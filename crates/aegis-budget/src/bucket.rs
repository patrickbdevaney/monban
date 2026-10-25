//! Integer token bucket, used for the per-connection RST budget (TBI-5: burst 100, refill 33/s).

use core::cmp::min;

use crate::NS_PER_S;

/// TBI-5: RST bucket burst.
pub const RST_BURST: u64 = 100;
/// TBI-5: RST bucket refill rate, tokens per second.
pub const RST_REFILL_PER_S: u64 = 33;

/// Token bucket with integer state. The level is kept in "token·ns per second" units (one token =
/// `NS_PER_S` sub-units), so a refill of `r` tokens/s over `dt` ns adds exactly `dt · r` sub-units with no rounding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenBucket {
    cap_sub: u64,
    refill_per_s: u64,
    level_sub: u64,
    last_ns: u64,
}

impl TokenBucket {
    /// A full bucket of `capacity` tokens refilling at `refill_per_s` tokens/s, observed at `now`.
    #[must_use]
    pub fn new(capacity: u64, refill_per_s: u64, now: u64) -> Self {
        let cap_sub = capacity.saturating_mul(NS_PER_S);
        TokenBucket { cap_sub, refill_per_s, level_sub: cap_sub, last_ns: now }
    }

    /// The TBI-5 RST bucket (burst 100, refill 33/s), full at `now`.
    #[must_use]
    pub fn rst(now: u64) -> Self {
        Self::new(RST_BURST, RST_REFILL_PER_S, now)
    }

    fn refill(&mut self, now: u64) {
        // A clock that goes backwards adds nothing and never rewinds `last_ns`.
        let dt = now.saturating_sub(self.last_ns);
        if dt > 0 {
            self.last_ns = now;
            let add = dt.saturating_mul(self.refill_per_s);
            self.level_sub = min(self.level_sub.saturating_add(add), self.cap_sub);
        }
    }

    /// Takes one token at `now` if available. Returns `false` (and takes nothing) when empty.
    pub fn try_take(&mut self, now: u64) -> bool {
        self.refill(now);
        match self.level_sub.checked_sub(NS_PER_S) {
            Some(rest) => {
                self.level_sub = rest;
                true
            }
            None => false,
        }
    }

    /// Whole tokens available at `now` (refills first).
    pub fn available(&mut self, now: u64) -> u64 {
        self.refill(now);
        self.level_sub / NS_PER_S
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testrng::Rng;

    #[test]
    fn rst_burst_and_refill() {
        let mut b = TokenBucket::rst(5);
        for _ in 0..RST_BURST {
            assert!(b.try_take(5));
        }
        assert!(!b.try_take(5));
        // 33 tokens/s: one token every ~30.3 ms.
        assert!(!b.try_take(5 + 30_303_030));
        assert!(b.try_take(5 + 30_303_031));
        assert_eq!(b.available(5 + 30_303_031 + 10 * NS_PER_S), RST_BURST);
        // Time going backwards neither refills nor panics.
        assert_eq!(b.available(0), RST_BURST);
    }

    #[test]
    fn saturates() {
        let mut b = TokenBucket::new(u64::MAX, u64::MAX, 0);
        assert!(b.try_take(u64::MAX));
        assert!(b.available(u64::MAX) > 0);
    }

    /// Takes in any window [t0, t1] ≤ burst + refill·(t1 − t0) (rounded up).
    #[test]
    fn prop_window_bound() {
        let mut r = Rng::new(7);
        for _ in 0..200 {
            let mut b = TokenBucket::rst(0);
            let mut now = 0u64;
            let mut takes: std::vec::Vec<u64> = std::vec::Vec::new();
            for _ in 0..400 {
                now = now.saturating_add(r.below(40_000_000));
                if b.try_take(now) {
                    takes.push(now);
                }
            }
            for (i, &t0) in takes.iter().enumerate() {
                for (k, &t1) in takes.iter().skip(i).enumerate() {
                    let n = (k as u128) + 1;
                    let allowance = u128::from(RST_BURST)
                        + (u128::from(t1 - t0) * u128::from(RST_REFILL_PER_S)).div_ceil(u128::from(NS_PER_S));
                    assert!(n <= allowance);
                }
            }
        }
    }
}
