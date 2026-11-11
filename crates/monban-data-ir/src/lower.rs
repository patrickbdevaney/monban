//! Engine-neutral lowering tree (P4-datair-001). One [`SqlExpr`] node per Lean node: `SqlExpr`, `lower` and `lowerQ`
//! in spec/AegisIR/Lowering.lean, evaluated by `sql3` (Kleene three-valued, NULL column ⇒ UNKNOWN). The structure
//! mirrors `lower`/`lowerQ` in oracles/lowering-read/lowir.py.
//!
//! No dialect text lives here. The SQLite, PostgreSQL and Redis renderers consume [`Lowered`] (from [`lower_op`]) and
//! turn each node into engine text; they own quoting, placeholders, collations and type guards. The renderer
//! obligations that make the tree exact are stated on each node (`Fidelity::Exact`, `rows_exact3`):
//!
//! * every atom ([`SqlExpr::CmpEq`], [`SqlExpr::InList`], [`SqlExpr::Between`], [`SqlExpr::Pfx`]) is UNKNOWN when its
//!   column is NULL, including `InList(f, [])`, which is FALSE on a present column and UNKNOWN on NULL
//!   (`sql3_inList_nil`); rendering it as constant FALSE is not exact under `Not`;
//! * comparisons are byte-wise/binary and class-strict (an `Int` never equals a `Str`);
//! * `And`/`Or` are always parenthesised; the tenant conjunct is the left child of the root `And` of every filter.
//!
//! [`eval3`] and [`sql3`] are the reference semantics (ThreeValued.lean `eval3`, Lowering.lean `sql3` with the exact
//! backend), for renderer differential tests.

use crate::ir::{Fidelity, Field, Op, OpKind, Pred, Schema, SchemaError, Value, check_schema, tenant_text};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use monban_types::TenantId;

/// Deepest IR filter [`lower`] accepts (a leaf has depth 1; `And`/`Or`/`Not` add 1). Deeper filters are refused, so
/// no recursive walk here or in a renderer can exhaust the stack on request-derived input.
pub const MAX_PRED_DEPTH: usize = 64;

/// Lean `SqlExpr`: the mini SQL WHERE language. Engine-neutral; renderers turn it into text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SqlExpr {
    /// `lit b` (TRUE / FALSE). From `tt` / `ff` only.
    Lit(bool),
    /// `column = value`, binary and class-strict; UNKNOWN on a NULL column.
    CmpEq(Field, Value),
    /// `(column = v1 OR column = v2 ...)`; the empty list is FALSE on a present column and UNKNOWN on NULL.
    InList(Field, Vec<Value>),
    /// `lo <= column AND column <= hi` (inclusive, Lean `refRange`: same storage class only, ints numerically,
    /// strings by code point = UTF-8 byte order); UNKNOWN on NULL.
    Between(Field, Value, Value),
    /// The column is a string whose code points start with the given string (`refPrefix`). Never LIKE/GLOB:
    /// renderers compare a byte prefix (UTF-8 is prefix-free); UNKNOWN on NULL.
    Pfx(Field, String),
    And(Box<SqlExpr>, Box<SqlExpr>),
    Or(Box<SqlExpr>, Box<SqlExpr>),
    Not(Box<SqlExpr>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LowerError {
    /// F4 `check_schema` refused the op (run first by [`lower_op`]).
    Schema(SchemaError),
    /// Filter deeper than [`MAX_PRED_DEPTH`].
    TooDeep,
    /// Insert and Upsert take no filter (`Pred::Tt` only): the row identity is the written key.
    FilterOnInsert,
    /// Select and Delete write nothing.
    WritesNotAllowed,
    /// Update with no column to set.
    EmptyWrites,
    /// The same column written twice in one op.
    DuplicateWrite(Field),
    /// Update (or Upsert's DO UPDATE) of an arbiter key column: it would move a row to another identity.
    KeyWritten(Field),
    /// Insert or Upsert that does not write every non-tenant key column.
    MissingKey(Field),
}

/// What a renderer turns into one statement. `filter` (where present) is always `lowerQ`: `And(CmpEq(tenant_field,
/// tenant), lower(op.filter))`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stmt {
    /// `SELECT <returning> FROM <collection> WHERE <filter>`.
    Select { filter: SqlExpr },
    /// `INSERT INTO <collection> (<row fields>) VALUES (<row values>)`. `row` starts with `(tenant_field, tenant)`
    /// from the host handle, followed by the op's writes in op order.
    Insert { row: Vec<(Field, Value)> },
    /// `UPDATE <collection> SET <set> WHERE <filter>`. `set` is non-empty and holds no tenant or key column.
    Update { set: Vec<(Field, Value)>, filter: SqlExpr },
    /// `DELETE FROM <collection> WHERE <filter>`.
    Delete { filter: SqlExpr },
    /// `INSERT ... ON CONFLICT (<arbiter>) <action>`. `row` as for Insert. `arbiter` is exactly the schema's sole
    /// unique index (tenant and key columns, ascending field order; W3), never a subset.
    Upsert { row: Vec<(Field, Value)>, arbiter: Vec<Field>, action: UpsertAction },
}

/// The conflict action of an upsert (W3 mandated forms; never the REPLACE family).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpsertAction {
    /// `DO NOTHING` (every written column is a key column).
    Nothing,
    /// `DO UPDATE SET c = excluded.c, ... WHERE <collection>.<guard> = excluded.<guard>` (binary comparison). `set`
    /// holds the written non-key columns in op order; `guard` is the tenant field, so a conflict on another tenant's
    /// row can never be updated even if the arbiter were wrong.
    Update { set: Vec<Field>, guard: Field },
}

/// A checked op lowered to the engine-neutral statement tree. This is the input of every SQL renderer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lowered {
    pub collection: String,
    pub kind: OpKind,
    pub tenant_field: Field,
    /// The tenant's engine value, `Value::Str(tenant_text(op.tenant))` (decision D4). Bound as a text parameter.
    pub tenant: Value,
    pub stmt: Stmt,
    /// `RETURNING` columns: the op's list in op order, duplicates dropped (each is permitted: W4, `check_schema`).
    pub returning: Vec<Field>,
}

fn depth(p: &Pred, budget: usize) -> Result<(), LowerError> {
    let next = budget.checked_sub(1).ok_or(LowerError::TooDeep)?;
    match p {
        Pred::And(a, b) | Pred::Or(a, b) => {
            depth(a, next)?;
            depth(b, next)
        }
        Pred::Not(a) => depth(a, next),
        _ => Ok(()),
    }
}

fn lower_rec(p: &Pred) -> SqlExpr {
    match p {
        Pred::Tt => SqlExpr::Lit(true),
        Pred::Ff => SqlExpr::Lit(false),
        Pred::Eq(f, v) => SqlExpr::CmpEq(*f, v.clone()),
        Pred::IsIn(f, vs) => SqlExpr::InList(*f, vs.clone()),
        Pred::Range(f, lo, hi) => SqlExpr::Between(*f, lo.clone(), hi.clone()),
        Pred::Pfx(f, s) => SqlExpr::Pfx(*f, s.clone()),
        Pred::And(a, b) => SqlExpr::And(Box::new(lower_rec(a)), Box::new(lower_rec(b))),
        Pred::Or(a, b) => SqlExpr::Or(Box::new(lower_rec(a)), Box::new(lower_rec(b))),
        Pred::Not(a) => SqlExpr::Not(Box::new(lower_rec(a))),
    }
}

/// Lean `lower`: structural, one node per node. Refuses filters deeper than [`MAX_PRED_DEPTH`].
pub fn lower(p: &Pred) -> Result<SqlExpr, LowerError> {
    depth(p, MAX_PRED_DEPTH)?;
    Ok(lower_rec(p))
}

/// Lean `lowerQ`: the mandatory tenant conjunct `And(CmpEq(tenant_field, tenant_text(t)), lower(p))`. The tenant
/// is the host-minted handle, never request bytes.
pub fn lower_q(tenant_field: Field, t: TenantId, p: &Pred) -> Result<SqlExpr, LowerError> {
    Ok(SqlExpr::And(Box::new(SqlExpr::CmpEq(tenant_field, Value::Str(tenant_text(t)))), Box::new(lower(p)?)))
}

fn no_dups(writes: &[(Field, Value)]) -> Result<(), LowerError> {
    let mut seen: Vec<Field> = Vec::with_capacity(writes.len());
    for (f, _) in writes {
        if seen.contains(f) {
            return Err(LowerError::DuplicateWrite(*f));
        }
        seen.push(*f);
    }
    Ok(())
}

/// Lower one op for a SQL engine. Order: `check_schema(op, schema, fidelity)` (so `Not` needs `Exact`, the tenant is
/// never written, RETURNING ⊆ permitted, and Upsert needs the sole (tenant, key) unique index), then the per-kind
/// shape rules on [`LowerError`], then `lowerQ`. Total: never panics. Run [`crate::authorize`] before this.
pub fn lower_op(op: &Op, schema: &Schema, fidelity: Fidelity) -> Result<Lowered, LowerError> {
    check_schema(op, schema, fidelity).map_err(LowerError::Schema)?;
    let tf = schema.tenant_field;
    let tenant = Value::Str(tenant_text(op.tenant));
    let mut keys: Vec<Field> = schema.columns.iter().filter(|c| c.key && c.field != tf).map(|c| c.field).collect();
    keys.sort_unstable();
    keys.dedup();
    no_dups(&op.writes)?;
    let mut returning: Vec<Field> = Vec::with_capacity(op.returning.len());
    for f in &op.returning {
        if !returning.contains(f) {
            returning.push(*f);
        }
    }
    let row = || {
        let mut r = Vec::with_capacity(op.writes.len().saturating_add(1));
        r.push((tf, tenant.clone()));
        r.extend(op.writes.iter().cloned());
        r
    };
    let need_keys = || match keys.iter().find(|k| !op.writes.iter().any(|(f, _)| f == *k)) {
        Some(k) => Err(LowerError::MissingKey(*k)),
        None => Ok(()),
    };
    let stmt = match op.kind {
        OpKind::Select | OpKind::Delete => {
            if !op.writes.is_empty() {
                return Err(LowerError::WritesNotAllowed);
            }
            let filter = lower_q(tf, op.tenant, &op.filter)?;
            if op.kind == OpKind::Select { Stmt::Select { filter } } else { Stmt::Delete { filter } }
        }
        OpKind::Update => {
            if op.writes.is_empty() {
                return Err(LowerError::EmptyWrites);
            }
            if let Some((f, _)) = op.writes.iter().find(|(f, _)| keys.contains(f)) {
                return Err(LowerError::KeyWritten(*f));
            }
            Stmt::Update { set: op.writes.clone(), filter: lower_q(tf, op.tenant, &op.filter)? }
        }
        OpKind::Insert | OpKind::Upsert => {
            if op.filter != Pred::Tt {
                return Err(LowerError::FilterOnInsert);
            }
            need_keys()?;
            if op.kind == OpKind::Insert {
                Stmt::Insert { row: row() }
            } else {
                let mut arbiter = keys.clone();
                arbiter.push(tf);
                arbiter.sort_unstable();
                let set: Vec<Field> = op.writes.iter().map(|(f, _)| *f).filter(|f| !keys.contains(f)).collect();
                let action =
                    if set.is_empty() { UpsertAction::Nothing } else { UpsertAction::Update { set, guard: tf } };
                Stmt::Upsert { row: row(), arbiter, action }
            }
        }
    };
    Ok(Lowered { collection: op.collection.clone(), kind: op.kind, tenant_field: tf, tenant, stmt, returning })
}

// ------------------------------------------------------------------------------------------- reference semantics

/// Lean `refLe`: same storage class only; ints numerically, strings by code point (= UTF-8 byte order).
fn ref_le(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => x <= y,
        (Value::Str(x), Value::Str(y)) => x.as_bytes().cmp(y.as_bytes()) != Ordering::Greater,
        _ => false,
    }
}

fn ref_range(lo: &Value, hi: &Value, x: &Value) -> bool {
    ref_le(lo, x) && ref_le(x, hi)
}

fn ref_prefix(s: &str, x: &Value) -> bool {
    matches!(x, Value::Str(v) if v.as_bytes().starts_with(s.as_bytes()))
}

fn k3and(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    match (a, b) {
        (Some(false), _) | (_, Some(false)) => Some(false),
        (Some(true), Some(true)) => Some(true),
        _ => None,
    }
}

fn k3or(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    match (a, b) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        _ => None,
    }
}

fn eval3_rec<'a>(
    row: &dyn Fn(Field) -> Option<&'a Value>,
    p: &Pred,
    budget: usize,
) -> Result<Option<bool>, LowerError> {
    let next = budget.checked_sub(1).ok_or(LowerError::TooDeep)?;
    Ok(match p {
        Pred::Tt => Some(true),
        Pred::Ff => Some(false),
        Pred::Eq(f, v) => row(*f).map(|x| x == v),
        Pred::IsIn(f, vs) => row(*f).map(|x| vs.contains(x)),
        Pred::Range(f, lo, hi) => row(*f).map(|x| ref_range(lo, hi, x)),
        Pred::Pfx(f, s) => row(*f).map(|x| ref_prefix(s, x)),
        Pred::And(a, b) => k3and(eval3_rec(row, a, next)?, eval3_rec(row, b, next)?),
        Pred::Or(a, b) => k3or(eval3_rec(row, a, next)?, eval3_rec(row, b, next)?),
        Pred::Not(a) => eval3_rec(row, a, next)?.map(|b| !b),
    })
}

/// ThreeValued.lean `eval3`: Kleene 3VL policy semantics; an absent (NULL) field makes the atom UNKNOWN (`None`).
/// `row(f)` is the stored value of field `f`, or `None` for NULL/absent. Refuses filters deeper than
/// [`MAX_PRED_DEPTH`] + 1 (one level for the tenant conjunct).
pub fn eval3<'a>(row: &dyn Fn(Field) -> Option<&'a Value>, p: &Pred) -> Result<Option<bool>, LowerError> {
    eval3_rec(row, p, MAX_PRED_DEPTH.saturating_add(1))
}

fn sql3_rec<'a>(
    row: &dyn Fn(Field) -> Option<&'a Value>,
    e: &SqlExpr,
    budget: usize,
) -> Result<Option<bool>, LowerError> {
    let next = budget.checked_sub(1).ok_or(LowerError::TooDeep)?;
    Ok(match e {
        SqlExpr::Lit(b) => Some(*b),
        SqlExpr::CmpEq(f, v) => row(*f).map(|x| x == v),
        SqlExpr::InList(f, vs) => row(*f).map(|x| vs.iter().any(|v| v == x)),
        SqlExpr::Between(f, lo, hi) => row(*f).map(|x| ref_range(lo, hi, x)),
        SqlExpr::Pfx(f, s) => row(*f).map(|x| ref_prefix(s, x)),
        SqlExpr::And(a, b) => k3and(sql3_rec(row, a, next)?, sql3_rec(row, b, next)?),
        SqlExpr::Or(a, b) => k3or(sql3_rec(row, a, next)?, sql3_rec(row, b, next)?),
        SqlExpr::Not(a) => sql3_rec(row, a, next)?.map(|b| !b),
    })
}

/// Lowering.lean `sql3` over the exact backend (`refBackend`): what a correct `Fidelity::Exact` renderer's WHERE
/// computes. A row is kept iff the result is `Some(true)` (`keeps`).
pub fn sql3<'a>(row: &dyn Fn(Field) -> Option<&'a Value>, e: &SqlExpr) -> Result<Option<bool>, LowerError> {
    sql3_rec(row, e, MAX_PRED_DEPTH.saturating_add(1))
}
