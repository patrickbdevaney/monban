//! Per-principal crash budget (PLAN-5 D7; SPEC_INVARIANTS INV-P2 P2-4; F8 `p2.crash_budget`; F14 Part 3 D7).
//!
//! A principal that causes `crashes` crash-attributable faults within `window` gets 429 for `penalty`, counted from
//! the crash that exhausted the budget. Crash-attributable = a trap, an abnormal fork-child exit, a cordon death or
//! an F14 decode failure caused by that principal's request ([`Failure::Crash`]). A healthy failure (Deny, a
//! client error, a refused request, anything not caused by the principal's module run) is reported as
//! [`Failure::Healthy`] and never counts. Other principals' faults never count: the state is keyed by principal.
//!
//! Pure logic: no clock read happens in this module. Every call takes `now`, a `CLOCK_MONOTONIC` instant
//! (`std::time::Instant`) that the caller read, so the windows are unit-testable. The key type is generic so the
//! tests can use plain values; monban-bin keys it by `monban_types::Principal` (the identity monban-token mints).
//!
//! When a penalty starts, the principal's crash records are cleared: after the penalty it starts from an empty
//! budget (F8 keeps `penalty_s` free of a window constraint; the p2-e2e oracle keeps `penalty_s > window_s`).
#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// F8 `p2.crash_budget.crashes` bounds and default.
pub const CRASHES_MIN: u32 = 1;
/// F8 maximum.
pub const CRASHES_MAX: u32 = 100;
/// F8 default (D7).
pub const CRASHES_DEFAULT: u32 = 3;
/// F8 `p2.crash_budget.window_s` bounds and default.
pub const WINDOW_S_MIN: u64 = 1;
/// F8 maximum.
pub const WINDOW_S_MAX: u64 = 3_600;
/// F8 default (D7).
pub const WINDOW_S_DEFAULT: u64 = 60;
/// F8 `p2.crash_budget.penalty_s` bounds and default.
pub const PENALTY_S_MIN: u64 = 1;
/// F8 maximum.
pub const PENALTY_S_MAX: u64 = 86_400;
/// F8 default (D7).
pub const PENALTY_S_DEFAULT: u64 = 600;

/// Below this many tracked principals the table is never pruned opportunistically.
const PRUNE_FLOOR: usize = 1_024;

/// A value outside the F8 bounds (refused, never clamped).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetError {
    /// `crashes` outside [`CRASHES_MIN`]..=[`CRASHES_MAX`].
    Crashes(u32),
    /// `window_s` outside [`WINDOW_S_MIN`]..=[`WINDOW_S_MAX`].
    WindowS(u64),
    /// `penalty_s` outside [`PENALTY_S_MIN`]..=[`PENALTY_S_MAX`].
    PenaltyS(u64),
}

impl fmt::Display for BudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crashes(v) => write!(f, "p2.crash_budget.crashes {v} outside {CRASHES_MIN}..={CRASHES_MAX}"),
            Self::WindowS(v) => write!(f, "p2.crash_budget.window_s {v} outside {WINDOW_S_MIN}..={WINDOW_S_MAX}"),
            Self::PenaltyS(v) => {
                write!(f, "p2.crash_budget.penalty_s {v} outside {PENALTY_S_MIN}..={PENALTY_S_MAX}")
            }
        }
    }
}

impl std::error::Error for BudgetError {}

/// The budget parameters (F8 `p2.crash_budget`, bounds-checked).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    crashes: u32,
    window: Duration,
    penalty: Duration,
}

impl Params {
    /// D7 defaults: 3 crashes in 60 s ⇒ 429 for 600 s.
    pub const DEFAULT: Self = Self {
        crashes: CRASHES_DEFAULT,
        window: Duration::from_secs(WINDOW_S_DEFAULT),
        penalty: Duration::from_secs(PENALTY_S_DEFAULT),
    };

    /// Bounds-checked constructor from the F8 values (seconds).
    pub fn new(crashes: u32, window_s: u64, penalty_s: u64) -> Result<Self, BudgetError> {
        if !(CRASHES_MIN..=CRASHES_MAX).contains(&crashes) {
            return Err(BudgetError::Crashes(crashes));
        }
        if !(WINDOW_S_MIN..=WINDOW_S_MAX).contains(&window_s) {
            return Err(BudgetError::WindowS(window_s));
        }
        if !(PENALTY_S_MIN..=PENALTY_S_MAX).contains(&penalty_s) {
            return Err(BudgetError::PenaltyS(penalty_s));
        }
        Ok(Self { crashes, window: Duration::from_secs(window_s), penalty: Duration::from_secs(penalty_s) })
    }

    /// Crashes that exhaust the budget.
    pub fn crashes(&self) -> u32 {
        self.crashes
    }
    /// The sliding window.
    pub fn window(&self) -> Duration {
        self.window
    }
    /// The penalty.
    pub fn penalty(&self) -> Duration {
        self.penalty
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Which crash-attributable fault happened (all count the same; kept for logs and metrics).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashKind {
    /// The request trapped (fuel, wall bound, memory, Wasm trap, handle fault, quota, ABI misuse, host fault).
    Trap,
    /// A fork+Wasm child ended without `resp-end` (signal, abnormal exit, wall-bound SIGALRM).
    AbnormalExit,
    /// The principal's cordon died (or was killed) while serving the principal's request.
    CordonDeath,
    /// A worker frame for the principal's request did not decode (the worker was killed).
    DecodeFailure,
}

/// How a failed P2 request is classified by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Caused by the principal's module run: counts against the budget.
    Crash(CrashKind),
    /// Not crash-attributable (Deny, client error, refused before the module ran, another principal's fault):
    /// never counts.
    Healthy,
}

/// What the supervisor does with the principal's next P2 request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Serve it.
    Serve,
    /// Answer 429: the principal is in penalty until `until` (`penalty` after `since`).
    Penalty {
        /// The crash instant that exhausted the budget.
        since: Instant,
        /// The end of the penalty, if representable.
        until: Option<Instant>,
    },
}

/// Whether a crash at `t` is inside the window ending at `now`. A record from the future (caller instants out of
/// order) is treated as inside.
fn in_window(p: &Params, t: Instant, now: Instant) -> bool {
    now.checked_duration_since(t).is_none_or(|age| age < p.window)
}

/// Whether a penalty that began at `since` still runs at `now`.
fn penalty_active(p: &Params, since: Instant, now: Instant) -> bool {
    now.checked_duration_since(since).is_none_or(|d| d < p.penalty)
}

#[derive(Debug)]
struct Entry {
    /// Crash instants within the window, oldest first; never longer than `crashes`.
    records: VecDeque<Instant>,
    /// Start of the current penalty.
    penalty_since: Option<Instant>,
}

/// Per-principal crash budgets.
#[derive(Debug)]
pub struct CrashBudget<K> {
    params: Params,
    entries: HashMap<K, Entry>,
    prune_mark: usize,
}

impl<K: Eq + Hash + Clone> CrashBudget<K> {
    /// An empty table.
    pub fn new(params: Params) -> Self {
        Self { params, entries: HashMap::new(), prune_mark: PRUNE_FLOOR }
    }

    /// The parameters.
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// Principals with live state (records within a window or a penalty not yet pruned).
    pub fn tracked(&self) -> usize {
        self.entries.len()
    }

    fn verdict_of(&self, e: &Entry, now: Instant) -> Verdict {
        match e.penalty_since {
            Some(since) if penalty_active(&self.params, since, now) => {
                Verdict::Penalty { since, until: since.checked_add(self.params.penalty) }
            }
            _ => Verdict::Serve,
        }
    }

    /// Whether `principal`'s next P2 request is served at `now`. Read-only.
    pub fn check(&self, principal: &K, now: Instant) -> Verdict {
        self.entries.get(principal).map_or(Verdict::Serve, |e| self.verdict_of(e, now))
    }

    /// Records the outcome of a failed request of `principal` at `now` and returns the verdict for its next
    /// request. [`Failure::Healthy`] changes nothing.
    pub fn record(&mut self, principal: &K, failure: Failure, now: Instant) -> Verdict {
        if failure == Failure::Healthy {
            return self.check(principal, now);
        }
        if self.entries.len() >= self.prune_mark {
            self.prune(now);
            self.prune_mark = self.entries.len().saturating_mul(2).max(PRUNE_FLOOR);
        }
        let params = self.params;
        let e = self
            .entries
            .entry(principal.clone())
            .or_insert_with(|| Entry { records: VecDeque::new(), penalty_since: None });
        // A crash reported while a penalty runs (a request admitted just before it began) does not extend it.
        if let Some(since) = e.penalty_since {
            if penalty_active(&params, since, now) {
                return Verdict::Penalty { since, until: since.checked_add(params.penalty) };
            }
            e.penalty_since = None;
        }
        while e.records.front().is_some_and(|&t| !in_window(&params, t, now)) {
            e.records.pop_front();
        }
        e.records.push_back(now);
        if e.records.len() >= usize::try_from(params.crashes).unwrap_or(usize::MAX) {
            e.records.clear();
            e.penalty_since = Some(now);
            return Verdict::Penalty { since: now, until: now.checked_add(params.penalty) };
        }
        Verdict::Serve
    }

    /// Drops every principal with no record inside the window and no running penalty (bounded memory).
    pub fn prune(&mut self, now: Instant) {
        let params = self.params;
        self.entries.retain(|_, e| {
            let penalized = e.penalty_since.is_some_and(|s| penalty_active(&params, s, now));
            e.records.retain(|&t| in_window(&params, t, now));
            penalized || !e.records.is_empty()
        });
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn s(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn bounds_are_refused_not_clamped() {
        assert_eq!(Params::new(0, 60, 600), Err(BudgetError::Crashes(0)));
        assert_eq!(Params::new(101, 60, 600), Err(BudgetError::Crashes(101)));
        assert_eq!(Params::new(3, 0, 600), Err(BudgetError::WindowS(0)));
        assert_eq!(Params::new(3, 3601, 600), Err(BudgetError::WindowS(3601)));
        assert_eq!(Params::new(3, 60, 0), Err(BudgetError::PenaltyS(0)));
        assert_eq!(Params::new(3, 60, 86_401), Err(BudgetError::PenaltyS(86_401)));
        assert_eq!(Params::new(3, 60, 600), Ok(Params::DEFAULT));
    }

    #[test]
    fn records_outside_the_window_are_forgotten() {
        let t0 = Instant::now();
        let mut b = CrashBudget::new(Params::DEFAULT);
        let c = Failure::Crash(CrashKind::Trap);
        assert_eq!(b.record(&1, c, t0), Verdict::Serve);
        assert_eq!(b.record(&1, c, t0 + s(30)), Verdict::Serve);
        // t0 is exactly 60 s old: out of the window.
        assert_eq!(b.record(&1, c, t0 + s(60)), Verdict::Serve);
        b.prune(t0 + s(200));
        assert_eq!(b.tracked(), 0);
    }
}
