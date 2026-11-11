//! F14 `data_run`, supervisor side (P5-bin-002; F14 Part 3 I1, I6-host; SPEC_INVARIANTS §H; PLAN-5 D13).
//!
//! Every `data-run` frame of a request goes through [`DataCtx::run`], in this order and nowhere else:
//!
//! 1. **decode** the guest's F10 `op` bytes completely ([`decode_op`]): total, depth-capped while decoding (a filter
//!    deeper than F4 `MAX_PRED_DEPTH` is refused before any deeper node is built), element counts bounded before
//!    allocation, no trailing bytes. A malformed op is a decode failure of the request (the caller kills the worker
//!    and charges the principal, F14 "Decoding"), never a panic and never a denial the module could probe with;
//! 2. **overwrite the tenant** with the route-bound tenant (the verified token's tenant caveat). The module's tenant
//!    field is a placeholder (F14 `monban.data_run`), so naming another tenant is not an effective-context switch;
//! 3. **authorize, check_schema, render** ([`Store::stage`]): F4 `authorize` against the route's `CapSet` (no `data`
//!    block = no capability, INV-NONEMPTY), F4 `check_schema` against the schema the engine introspected at boot,
//!    the op-budget pre-debit, and the engine's own renderer with its denylist scan. Nothing touches the engine yet;
//! 4. **audit** (F9, durable: sequenced, fsynced, checkpoint published) as `p2.data_run` with `actor.tenant` = the
//!    route-bound tenant: outcome `allow` before execution, or `deny` for a refused op. An `allow` event the log
//!    cannot take makes the op fail closed (no effect without its audit event, I6-host);
//! 5. **execute** in a transaction of its own (begin, execute within the reserved limits, commit) and answer the
//!    F10 `result`. Every refusal and every engine failure is the one uniform `[1, 1]` (W6: no existence oracle).
//!
//! An allow event is written before the effect, so it stays in the log when the request traps afterwards.
//!
//! The engine pairing lives in the native data plane ([`crate::native`], PLAN D15); a build without feature
//! `native` has no store, so every op is refused (and audited as refused).
#![forbid(unsafe_code)]

use std::sync::{Mutex, PoisonError};

use super::frame::{Dec, Enc};
use super::mutant::{self, Mutant};
use crate::audit::Auditor;

/// F4 `monban_data_ir::lower::MAX_PRED_DEPTH` (a leaf has depth 1; `and`/`or`/`not` add 1). Restated here because
/// a build without `native` does not link monban-data-ir; a `native` test pins the two equal.
pub const MAX_PRED_DEPTH: usize = 64;
/// Most `isIn` values, writes and returned columns one op may carry (the reference decoder's bounds).
const MAX_IN: u64 = 4096;
const MAX_WRITES: u64 = 256;
const MAX_RETURNING: u64 = 256;
/// The uniform F10 error code (W6).
pub const ERR_CODE: u64 = 1;

/// Text cells as both golden SQL engines return them (`None` = NULL).
pub type Rows = Vec<Vec<Option<String>>>;

/// An F10 `value`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PValue {
    Int(i64),
    Str(String),
}

/// An F10 `pred` (tt ff eq isIn range pfx and or not).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PPred {
    Tt,
    Ff,
    Eq(u32, PValue),
    IsIn(u32, Vec<PValue>),
    Range(u32, PValue, PValue),
    Pfx(u32, String),
    And(Box<PPred>, Box<PPred>),
    Or(Box<PPred>, Box<PPred>),
    Not(Box<PPred>),
}

/// A decoded F10 `op`. `kind` is the F10 code 0..=4 (select insert update delete upsert).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct POp {
    pub tenant: u64,
    pub collection: String,
    pub kind: u8,
    pub filter: PPred,
    pub writes: Vec<(u32, PValue)>,
    pub returning: Vec<u32>,
}

const KIND_NAMES: [&str; 5] = ["select", "insert", "update", "delete", "upsert"];

impl POp {
    pub fn kind_name(&self) -> &'static str {
        KIND_NAMES.get(usize::from(self.kind)).copied().unwrap_or("unknown")
    }
}

fn zigzag(n: u64) -> i64 {
    let half = i64::try_from(n >> 1).unwrap_or(i64::MAX); // n >> 1 < 2^63: always in range
    if n & 1 == 0 { half } else { -half - 1 }
}

fn field(d: &mut Dec<'_>) -> Option<u32> {
    u32::try_from(d.u()?).ok()
}

fn value(d: &mut Dec<'_>) -> Option<PValue> {
    match d.u()? {
        0 => Some(PValue::Int(zigzag(d.u()?))),
        1 => Some(PValue::Str(d.text()?.to_string())),
        _ => None,
    }
}

/// A count prefix, refused above `max` or above the bytes left (every element takes at least one byte), so no
/// allocation is sized by an attacker's count.
fn count(d: &mut Dec<'_>, max: u64) -> Option<usize> {
    let n = d.u()?;
    if n > max || n > u64::try_from(d.remaining()).unwrap_or(0) {
        return None;
    }
    usize::try_from(n).ok()
}

/// `budget` is the depth this node may still take (the root gets [`MAX_PRED_DEPTH`]); a node at budget 0 is
/// refused before it is read, so nothing deeper than the cap is ever constructed.
fn pred(d: &mut Dec<'_>, budget: usize) -> Option<PPred> {
    let next = budget.checked_sub(1)?;
    Some(match d.u()? {
        0 => PPred::Tt,
        1 => PPred::Ff,
        2 => PPred::Eq(field(d)?, value(d)?),
        3 => {
            let f = field(d)?;
            let n = count(d, MAX_IN)?;
            let mut vs = Vec::with_capacity(n);
            for _ in 0..n {
                vs.push(value(d)?);
            }
            PPred::IsIn(f, vs)
        }
        4 => PPred::Range(field(d)?, value(d)?, value(d)?),
        5 => PPred::Pfx(field(d)?, d.text()?.to_string()),
        6 => PPred::And(Box::new(pred(d, next)?), Box::new(pred(d, next)?)),
        7 => PPred::Or(Box::new(pred(d, next)?), Box::new(pred(d, next)?)),
        8 => PPred::Not(Box::new(pred(d, next)?)),
        _ => return None,
    })
}

/// Decodes one F10 `op` completely (`None`: malformed). Total: never panics, recursion bounded by
/// [`MAX_PRED_DEPTH`].
pub fn decode_op(b: &[u8]) -> Option<POp> {
    let mut d = Dec::new(b);
    let tenant = d.u()?;
    if tenant == 0 {
        return None; // F10: tenant uint .gt 0 (the placeholder convention is 1)
    }
    let collection = d.text()?.to_string();
    let kind = u8::try_from(d.u()?).ok().filter(|k| *k <= 4)?;
    let filter = pred(&mut d, MAX_PRED_DEPTH)?;
    let n = count(&mut d, MAX_WRITES)?;
    let mut writes = Vec::with_capacity(n);
    for _ in 0..n {
        writes.push((field(&mut d)?, value(&mut d)?));
    }
    let n = count(&mut d, MAX_RETURNING)?;
    let mut returning = Vec::with_capacity(n);
    for _ in 0..n {
        returning.push(field(&mut d)?);
    }
    d.done().then_some(POp { tenant, collection, kind, filter, writes, returning })
}

/// F10 `result = [0, rows]`; every cell a `tstr` (both golden engines return text cells) or `null`.
pub fn result_rows(rows: &Rows) -> Vec<u8> {
    let mut e = Enc::new().u(0).len_of(rows.len());
    for r in rows {
        e = e.len_of(r.len());
        for c in r {
            e = match c {
                None => e.u(0),
                Some(s) => e.u(1).u(1).bytes(s.as_bytes()),
            };
        }
    }
    e.finish()
}

/// F10 `result = [1, error-code]` with the uniform code.
pub fn result_err() -> Vec<u8> {
    Enc::new().u(1).u(ERR_CODE).finish()
}

/// What a staged op runs when called: begin, execute, commit (`None`: any engine failure, nothing committed).
pub type Exec<'a> = Box<dyn FnOnce() -> Option<Rows> + 'a>;

/// The route's data authority on one engine (implemented by the native data plane).
pub trait Store: Send + Sync {
    /// F4 authorize (skipped only by the `data-run-skips-authorize` negative control) → check_schema → op-budget
    /// pre-debit → render, for `op` exactly as given (its tenant already overwritten by the caller). `None`:
    /// refused; nothing reached the engine. Pure until the returned closure is called.
    fn stage<'a>(&'a self, op: &POp, skip_authorize: bool) -> Option<Exec<'a>>;
}

/// One allow event held back by the `no-audit-on-trap` negative control.
#[derive(Debug)]
struct Held {
    collection: String,
    kind: &'static str,
}

/// The data side of one P2 request.
pub struct DataCtx<'a> {
    /// The route-bound tenant (the verified token's tenant caveat).
    pub tenant: u64,
    pub store: Option<&'a dyn Store>,
    pub audit: Option<&'a Auditor>,
    pub module: &'a str,
    pub config_hash: [u8; 32],
    pub req_id: [u8; 16],
    held: Mutex<Vec<Held>>,
}

impl std::fmt::Debug for DataCtx<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataCtx").field("tenant", &self.tenant).field("module", &self.module).finish_non_exhaustive()
    }
}

impl<'a> DataCtx<'a> {
    pub fn new(
        tenant: u64,
        store: Option<&'a dyn Store>,
        audit: Option<&'a Auditor>,
        module: &'a str,
        config_hash: [u8; 32],
    ) -> Self {
        let req_id = audit.map_or([0u8; 16], Auditor::new_req_id);
        Self { tenant, store, audit, module, config_hash, req_id, held: Mutex::new(Vec::new()) }
    }

    /// A context without data authority (every op refused); unit tests and requests that never reach a store.
    #[cfg(test)]
    pub fn none() -> DataCtx<'static> {
        DataCtx {
            tenant: 1,
            store: None,
            audit: None,
            module: "",
            config_hash: [0; 32],
            req_id: [0; 16],
            held: Mutex::new(Vec::new()),
        }
    }

    fn record(&self, collection: &str, kind: &str, allow: bool) -> Result<(), String> {
        let audit = self.audit.ok_or("no audit log")?;
        audit.data_run(self.tenant, collection, kind, self.module, allow, self.req_id, self.config_hash)
    }

    /// One `data-run` (see the module docs). `Err(())`: the op does not decode (a decode failure of the request).
    pub fn run(&self, op_bytes: &[u8]) -> Result<Vec<u8>, ()> {
        let mut op = decode_op(op_bytes).ok_or(())?;
        if !mutant::is(Mutant::TenantNotOverwritten) {
            op.tenant = self.tenant; // the route-bound tenant replaces the module's placeholder (I1)
        }
        let kind = op.kind_name();
        let skip = mutant::is(Mutant::DataRunSkipsAuthorize);
        let Some(exec) = self.store.and_then(|s| s.stage(&op, skip)) else {
            // Refused (no capability, outside the CapSet, schema, budget or render): audited as refused. Nothing
            // was executed, so a failed append changes no outcome.
            if let Err(e) = self.record(&op.collection, kind, false) {
                super::log(&format!("audit of a refused data_run failed: {e}"));
            }
            return Ok(result_err());
        };
        if mutant::is(Mutant::AuditAfterEffect) {
            // NEGATIVE CONTROL: the effect runs before its audit event.
            let rows = exec();
            let _ = self.record(&op.collection, kind, true);
            return Ok(rows.as_ref().map_or_else(result_err, result_rows));
        }
        if mutant::is(Mutant::NoAuditOnTrap) {
            // NEGATIVE CONTROL: the allow event is written only if the request ends without a fault.
            self.held.lock().unwrap_or_else(PoisonError::into_inner).push(Held { collection: op.collection, kind });
            return Ok(exec().as_ref().map_or_else(result_err, result_rows));
        }
        if let Err(e) = self.record(&op.collection, kind, true) {
            super::log(&format!("audit append refused, data_run not executed (fail closed): {e}"));
            return Ok(result_err());
        }
        Ok(exec().as_ref().map_or_else(result_err, result_rows))
    }

    /// End of the request. Only the `no-audit-on-trap` negative control holds events back: they are written now if
    /// the request ended without a fault (`faulted` = trap, decode failure, death or timeout), and dropped otherwise.
    pub fn finish(&self, faulted: bool) {
        let held = std::mem::take(&mut *self.held.lock().unwrap_or_else(PoisonError::into_inner));
        if !faulted {
            for h in held {
                let _ = self.record(&h.collection, h.kind, true);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    fn zz(n: i64) -> u64 {
        ((n << 1) ^ (n >> 63)) as u64
    }
    fn s(e: Enc, t: &str) -> Enc {
        e.bytes(t.as_bytes())
    }

    /// The oracle's `f14.op(1, "notes", "insert", tt, [(1, "r"), (2, "b")], [])`.
    fn insert() -> Vec<u8> {
        let e = Enc::new().u(1);
        let e = s(e, "notes").u(1).u(0).u(2).u(1).u(1);
        let e = s(e, "r").u(2).u(1);
        s(e, "b").u(0).finish()
    }

    #[test]
    fn decodes_the_reference_encoding() {
        let op = decode_op(&insert()).unwrap();
        assert_eq!(op.tenant, 1);
        assert_eq!(op.collection, "notes");
        assert_eq!(op.kind_name(), "insert");
        assert_eq!(op.filter, PPred::Tt);
        assert_eq!(op.writes, vec![(1, PValue::Str("r".into())), (2, PValue::Str("b".into()))]);
        assert!(op.returning.is_empty());
        // select with every pred form and a negative int
        let e = s(Enc::new().u(7), "notes").u(0);
        let e = e.u(6).u(2).u(1).u(0).u(zz(-5)); // and(eq(1, -5),
        let e = e.u(7).u(8).u(1).u(3).u(2).u(2).u(0).u(zz(3)).u(1); //  or(not(ff), isIn(2, [3, "x"])))
        let e = s(e, "x").u(0).u(1).u(2).finish();
        let op = decode_op(&e).unwrap();
        assert_eq!(op.tenant, 7);
        assert_eq!(
            op.filter,
            PPred::And(
                Box::new(PPred::Eq(1, PValue::Int(-5))),
                Box::new(PPred::Or(
                    Box::new(PPred::Not(Box::new(PPred::Ff))),
                    Box::new(PPred::IsIn(2, vec![PValue::Int(3), PValue::Str("x".into())]))
                ))
            )
        );
        assert_eq!(op.returning, vec![2]);
    }

    #[test]
    fn malformed_ops_are_refused_totally() {
        let ok = insert();
        for i in 0..ok.len() {
            assert_eq!(decode_op(&ok[..i]), None, "prefix {i}");
        }
        let mut trailing = ok.clone();
        trailing.push(0);
        assert_eq!(decode_op(&trailing), None);
        assert_eq!(decode_op(&[0xff; 10]), None); // the oracle's malformed op
        assert_eq!(decode_op(&hex("ffffffffffffffffffff01")), None);
        let mut zero = ok.clone();
        zero[0] = 0; // tenant 0
        assert_eq!(decode_op(&zero), None);
        let bad_kind = s(Enc::new().u(1), "notes").u(5).u(0).u(0).u(0).finish();
        assert_eq!(decode_op(&bad_kind), None);
        let big_field = s(Enc::new().u(1), "notes").u(0).u(2).u(1 << 33).u(0).u(0).u(0).u(0).finish();
        assert_eq!(decode_op(&big_field), None);
        let huge_count = s(Enc::new().u(1), "notes").u(0).u(0).u(u64::MAX >> 1).finish();
        assert_eq!(decode_op(&huge_count), None);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn deep_not(n: usize) -> Vec<u8> {
        let mut e = s(Enc::new().u(1), "notes").u(0);
        for _ in 0..n {
            e = e.u(8);
        }
        e.u(0).u(0).u(1).u(1).finish()
    }

    #[test]
    fn filter_depth_is_capped_at_f4_max_pred_depth() {
        // MAX_PRED_DEPTH - 1 nots around a leaf = depth MAX_PRED_DEPTH: accepted; one more: refused.
        assert!(decode_op(&deep_not(MAX_PRED_DEPTH - 1)).is_some());
        assert_eq!(decode_op(&deep_not(MAX_PRED_DEPTH)), None);
        assert_eq!(decode_op(&deep_not(200)), None); // the oracle's h-i1-deep-filter
        assert_eq!(decode_op(&deep_not(100_000)), None); // no stack exhaustion
    }

    #[test]
    fn results_match_the_reference_encoding() {
        // f14.result_rows([["a", None]]) and f14.result_err(1)
        assert_eq!(result_rows(&vec![vec![Some("a".into()), None]]), vec![0, 1, 2, 1, 1, 1, b'a', 0]);
        assert_eq!(result_rows(&Vec::new()), vec![0, 0]);
        assert_eq!(result_err(), vec![1, 1]);
    }

    #[test]
    fn without_a_store_every_op_is_refused_and_malformed_ops_are_decode_failures() {
        let d = DataCtx::none();
        assert_eq!(d.run(&insert()), Ok(result_err()));
        assert_eq!(d.run(&[0xff; 10]), Err(()));
        d.finish(false);
    }

    struct Fake(std::sync::atomic::AtomicU64);
    impl Store for Fake {
        fn stage<'a>(&'a self, op: &POp, _skip: bool) -> Option<Exec<'a>> {
            self.0.store(op.tenant, std::sync::atomic::Ordering::SeqCst);
            (op.collection == "notes").then(|| -> Exec<'a> { Box::new(|| Some(vec![vec![Some("x".into())]])) })
        }
    }

    #[test]
    fn the_tenant_is_overwritten_and_an_allow_without_audit_log_fails_closed() {
        let f = Fake(std::sync::atomic::AtomicU64::new(0));
        let mut d = DataCtx::none();
        d.tenant = 42;
        d.store = Some(&f);
        // The op names tenant 1 (the placeholder); the store sees the route-bound tenant.
        // No audit log: the allow event cannot be written, so the op is not executed (uniform error).
        assert_eq!(d.run(&insert()), Ok(result_err()));
        if mutant::active().is_none() {
            assert_eq!(f.0.load(std::sync::atomic::Ordering::SeqCst), 42);
        }
    }
}
