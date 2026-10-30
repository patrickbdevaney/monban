//! Op budgets with pre-debit (NC4, ARCHITECTURE §3.8): `rows ≤ 10k, bytes ≤ 8 MiB, ms ≤ 5000` per op.
//!
//! [`RequestBudget::pre_debit`] reserves one op's ceiling (bounded by what the scope has left) *before* the op is
//! rendered or sent. The returned [`Debit`] is settled with the measured usage, which refunds the unused part. A
//! debit that is dropped without being settled (cancellation, error, timeout) stays charged in full: cancels are
//! charged (NC4).

use std::cell::Cell;
use std::fmt;
use std::rc::Rc;

/// ARCHITECTURE §3.8 per-op ceilings.
pub const OP_MAX_ROWS: u64 = 10_000;
pub const OP_MAX_BYTES: u64 = 8 * 1024 * 1024;
pub const OP_MAX_MS: u64 = 5_000;
/// Default op count of one scope (request, step, message or job).
pub const DEFAULT_SCOPE_OPS: u64 = 64;

/// What one op may consume: the adapter must stop at these (row cap, byte cap, statement timeout).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpLimits {
    pub rows: u64,
    pub bytes: u64,
    pub ms: u64,
}

impl OpLimits {
    /// The §3.8 ceiling.
    pub const CEILING: OpLimits = OpLimits { rows: OP_MAX_ROWS, bytes: OP_MAX_BYTES, ms: OP_MAX_MS };
}

/// Measured consumption of one executed op.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub rows: u64,
    pub bytes: u64,
    pub ms: u64,
}

/// Remaining budget of one scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Remaining {
    pub ops: u64,
    pub rows: u64,
    pub bytes: u64,
    pub ms: u64,
}

impl Remaining {
    /// One scope: [`DEFAULT_SCOPE_OPS`] ops sharing one op ceiling of rows, bytes and milliseconds.
    pub const DEFAULT: Remaining =
        Remaining { ops: DEFAULT_SCOPE_OPS, rows: OP_MAX_ROWS, bytes: OP_MAX_BYTES, ms: OP_MAX_MS };
}

/// The budget is exhausted (or a dimension is zero): the op is refused before render.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exhausted;

impl fmt::Display for Exhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("op budget exhausted")
    }
}

/// The budget of one scope. Single-threaded by construction (one scope runs on one pool thread).
#[derive(Debug)]
pub struct RequestBudget {
    left: Rc<Cell<Remaining>>,
}

impl RequestBudget {
    pub fn new(r: Remaining) -> RequestBudget {
        RequestBudget { left: Rc::new(Cell::new(r)) }
    }

    pub fn remaining(&self) -> Remaining {
        self.left.get()
    }

    /// Reserve one op: one op count, and `min(ceiling, remaining)` of rows, bytes and ms. Refused when any of them
    /// is zero (fail closed).
    pub fn pre_debit(&self) -> Result<Debit, Exhausted> {
        let l = self.left.get();
        let c = OpLimits::CEILING;
        let limits = OpLimits { rows: c.rows.min(l.rows), bytes: c.bytes.min(l.bytes), ms: c.ms.min(l.ms) };
        if l.ops == 0 || limits.rows == 0 || limits.bytes == 0 || limits.ms == 0 {
            return Err(Exhausted);
        }
        self.left.set(Remaining {
            ops: l.ops - 1,
            rows: l.rows - limits.rows,
            bytes: l.bytes - limits.bytes,
            ms: l.ms - limits.ms,
        });
        Ok(Debit { left: Rc::clone(&self.left), limits })
    }
}

/// One reserved op. Settle it with the measured usage to refund the unused part; dropping it keeps the full
/// reservation charged (NC4: cancels are charged).
#[derive(Debug)]
#[must_use = "an unsettled debit stays charged in full"]
pub struct Debit {
    left: Rc<Cell<Remaining>>,
    limits: OpLimits,
}

impl Debit {
    pub fn limits(&self) -> OpLimits {
        self.limits
    }

    /// Refund `limits - used` per dimension. Usage above the reservation is not refunded (and the caller must treat
    /// it as an adapter fault: the limits are hard caps).
    pub fn settle(self, used: Usage) {
        let l = self.left.get();
        let back = |res: u64, u: u64| res.saturating_sub(u);
        self.left.set(Remaining {
            ops: l.ops,
            rows: l.rows.saturating_add(back(self.limits.rows, used.rows)),
            bytes: l.bytes.saturating_add(back(self.limits.bytes, used.bytes)),
            ms: l.ms.saturating_add(back(self.limits.ms, used.ms)),
        });
    }

    /// True iff `used` stays within this reservation.
    pub fn covers(&self, used: &Usage) -> bool {
        used.rows <= self.limits.rows && used.bytes <= self.limits.bytes && used.ms <= self.limits.ms
    }
}

/// Where NC4 charges against a principal go (quarantine time and discards of connections that a cancelled request
/// touched, reported by the PG pool's release path). The assembly debits its per-principal limiter here.
pub trait ChargeSink: Send + Sync + 'static {
    /// Debit `units` (op-budget units: milliseconds for PG sessions) from principal `who`
    /// (`session::principal_bytes`).
    fn charge(&self, who: &[u8], units: u64);
}

/// A simple in-memory [`ChargeSink`]: cumulative charges per principal.
#[derive(Debug, Default)]
pub struct PrincipalLedger {
    charged: std::sync::Mutex<std::collections::BTreeMap<Vec<u8>, u64>>,
}

impl PrincipalLedger {
    pub fn new() -> PrincipalLedger {
        PrincipalLedger::default()
    }
    /// Total charged to `who` so far.
    pub fn charged(&self, who: &[u8]) -> u64 {
        self.charged.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(who).copied().unwrap_or(0)
    }
}

impl ChargeSink for PrincipalLedger {
    fn charge(&self, who: &[u8], units: u64) {
        let mut m = self.charged.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let e = m.entry(who.to_vec()).or_insert(0);
        *e = e.saturating_add(units);
    }
}
