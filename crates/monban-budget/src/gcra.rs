//! Integer GCRA (normative semantics 1 and 6 of the admission event protocol).

use core::cmp::{max, min};

/// I5: a post-hoc debit never pushes a TAT beyond `now + 10 min`.
pub const DEBIT_CAP_NS: u64 = 600 * crate::NS_PER_S;

/// Generic cell-rate limiter parameters: emission interval `t_ns` (ns per unit) and burst `burst` (units).
///
/// The tolerance is `τ = burst · t_ns`, computed in `u128` so it never overflows. The limiter state is just a
/// theoretical arrival time (`tat`, u64 ns) held by the caller, which keeps one `Gcra` shareable by many keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gcra {
    /// Emission interval in nanoseconds per unit.
    pub t_ns: u64,
    /// Burst in units.
    pub burst: u64,
}

impl Gcra {
    /// Builds a limiter from its emission interval and burst.
    #[must_use]
    pub const fn new(t_ns: u64, burst: u64) -> Self {
        Gcra { t_ns, burst }
    }

    /// Tolerance `τ = b · T` (exact, `u128`).
    #[must_use]
    pub const fn tau(&self) -> u128 {
        (self.burst as u128) * (self.t_ns as u128)
    }

    /// Conformance test: `new = max(tat, now) + cost·T` must fit in u64 and satisfy `new − now ≤ τ`.
    /// Returns the new TAT on conformance, `None` otherwise. Never mutates anything.
    #[must_use]
    pub fn conform(&self, tat: u64, now: u64, cost: u64) -> Option<u64> {
        let base = u128::from(max(tat, now));
        // u64·u64 + u64 < 2^128: the u128 sum cannot overflow.
        let raw = base + u128::from(cost) * u128::from(self.t_ns);
        let new = u64::try_from(raw).ok()?;
        let ahead = new.checked_sub(now)?;
        if u128::from(ahead) <= self.tau() { Some(new) } else { None }
    }

    /// Conformance test plus charge: on conformance `*tat` becomes the new TAT and `true` is returned; otherwise
    /// `*tat` is left untouched.
    pub fn charge(&self, tat: &mut u64, now: u64, cost: u64) -> bool {
        match self.conform(*tat, now, cost) {
            Some(n) => {
                *tat = n;
                true
            }
            None => false,
        }
    }

    /// TAT for a freshly inserted key that may spend at most `grant` units at `now` (semantics 2 / I4):
    /// `now + (b − min(b, grant)) · T`, saturating.
    #[must_use]
    pub fn initial_tat(&self, now: u64, grant: u64) -> u64 {
        let withheld = self.burst.saturating_sub(min(self.burst, grant));
        now.saturating_add(withheld.saturating_mul(self.t_ns))
    }

    /// Post-hoc debit of `extra` units observed at `now` (semantics 6 / I5):
    /// `min(sat(max(tat, now) + extra·T), now + 10 min)`.
    #[must_use]
    pub fn debit(&self, tat: u64, now: u64, extra: u64) -> u64 {
        let raised = max(tat, now).saturating_add(extra.saturating_mul(self.t_ns));
        min(raised, now.saturating_add(DEBIT_CAP_NS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testrng::Rng;

    #[test]
    fn burst_then_rate() {
        let g = Gcra::new(10, 5);
        let mut tat = 0;
        for _ in 0..5 {
            assert!(g.charge(&mut tat, 100, 1));
        }
        assert!(!g.charge(&mut tat, 100, 1));
        assert!(g.charge(&mut tat, 110, 1));
        assert!(!g.charge(&mut tat, 110, 1));
        // A single request larger than the burst never conforms (the new TAT is tested, not the old one).
        let mut t2 = 0;
        assert!(!g.charge(&mut t2, 1000, 6));
        assert!(g.charge(&mut t2, 1000, 5));
    }

    #[test]
    fn overflow_guards() {
        let g = Gcra::new(u64::MAX, u64::MAX);
        assert_eq!(g.conform(0, 0, 1), Some(u64::MAX));
        assert_eq!(g.conform(1, 0, 1), None);
        assert_eq!(g.conform(0, 0, 2), None);
        assert_eq!(g.conform(u64::MAX, u64::MAX, 0), Some(u64::MAX));
        let h = Gcra::new(3, 2);
        assert_eq!(h.conform(u64::MAX - 1, 0, 1), None);
        assert_eq!(h.debit(5, 10, u64::MAX), 10 + DEBIT_CAP_NS);
        assert_eq!(h.debit(5, u64::MAX - 2, u64::MAX), u64::MAX);
        assert_eq!(h.debit(5, 10, 1), 13);
        assert_eq!(Gcra::new(u64::MAX, 3).initial_tat(7, 1), u64::MAX);
        assert_eq!(Gcra::new(10, 30).initial_tat(7, 20), 107);
        assert_eq!(Gcra::new(10, 10).initial_tat(7, 20), 7);
    }

    /// I1 on random traces: from a TAT not ahead of the first instant, admitted cost in every window
    /// [ti, tj] satisfies Σcost·T ≤ b·T + (tj − ti).
    #[test]
    fn prop_window_bound() {
        let mut r = Rng::new(0xA11CE);
        for _ in 0..300 {
            let g = Gcra::new(1 + r.below(1000), 1 + r.below(20));
            let mut tat = 0u64;
            let mut now = r.below(1 << 40);
            let mut adm: alloc::vec::Vec<(u64, u64)> = alloc::vec::Vec::new();
            for _ in 0..60 {
                now = now.saturating_add(r.below(3 * g.t_ns));
                let cost = r.below(g.burst + 3);
                if g.charge(&mut tat, now, cost) {
                    adm.push((now, cost));
                }
            }
            for (i, &(ti, _)) in adm.iter().enumerate() {
                let mut sum: u128 = 0;
                for &(tj, c) in adm.iter().skip(i) {
                    sum += u128::from(c) * u128::from(g.t_ns);
                    assert!(sum <= g.tau() + u128::from(tj - ti));
                }
            }
        }
    }

    /// TAT is monotone under charge and debit stays within the cap; no input panics (TBI-9).
    #[test]
    fn prop_monotone_and_capped() {
        let mut r = Rng::new(42);
        for _ in 0..20_000 {
            let g = Gcra::new(r.next() >> r.below(64), r.next() >> r.below(64));
            let tat = r.next() >> r.below(64);
            let now = r.next() >> r.below(64);
            let cost = r.next() >> r.below(64);
            if let Some(n) = g.conform(tat, now, cost) {
                assert!(n >= tat && n >= now);
            }
            let d = g.debit(tat, now, cost);
            assert!(d <= now.saturating_add(DEBIT_CAP_NS));
        }
    }
}
