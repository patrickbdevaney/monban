// q2-013 representative Kani obligations (mirror F5 TBI-9 RST bucket and admission GCRA I1/I2).
// Pure counter structs only (R-FORMAL-2: Kani never gets async/Arc/slab state).
// Kani checks arithmetic overflow, so "no overflow" is discharged by every harness that reaches the code.

/// Fixed point: one token = SCALE token-nanoseconds, so refill is exact integer arithmetic on u64 ns time.
pub const SCALE: u64 = 1_000_000_000;
pub const BURST: u64 = 100; // tokens
pub const RATE: u64 = 33; // tokens per second
pub const CAP: u64 = BURST * SCALE; // 1e11 < 2^37

#[derive(Clone, Copy)]
pub struct RstBucket {
    tokens: u64, // token-ns, invariant tokens <= CAP
    last_ns: u64,
}

impl RstBucket {
    pub fn new(now: u64) -> Self { RstBucket { tokens: CAP, last_ns: now } }
    pub fn inv(&self) -> bool { self.tokens <= CAP }
    fn refill(&mut self, now: u64) {
        if now <= self.last_ns { return; } // non-monotone clock never mints tokens
        let dt = now - self.last_ns;
        // dt * RATE may overflow for dt > 5.6e17 ns (17.7 years): saturate, then clamp.
        let add = dt.saturating_mul(RATE);
        self.tokens = core::cmp::min(CAP, self.tokens.saturating_add(add));
        self.last_ns = now;
    }
    /// Called on each peer RST_STREAM; false => GOAWAY(ENHANCE_YOUR_CALM).
    pub fn on_rst(&mut self, now: u64) -> bool {
        self.refill(now);
        if self.tokens >= SCALE { self.tokens -= SCALE; true } else { false }
    }
}

/// GCRA (virtual scheduling). T = emission interval ns per cost unit, TAU = burst tolerance ns.
#[derive(Clone, Copy)]
pub struct Gcra { tat: u64 }
pub const MAX_COST: u64 = 64;
pub const MAX_T: u64 = 1_000_000_000; // >= 1 unit/s
pub const MAX_TAU: u64 = 3_600_000_000_000; // 1 h
pub const MAX_NOW: u64 = 1 << 62;

impl Gcra {
    /// Returns true and advances TAT iff admitted; on deny the state is unchanged.
    pub fn admit(&mut self, now: u64, cost: u64, t: u64, tau: u64) -> bool {
        let tat = if self.tat > now { self.tat } else { now };
        if tat - now > tau { return false; }
        let inc = match t.checked_mul(cost) { Some(v) => v, None => return false };
        let new_tat = match tat.checked_add(inc) { Some(v) => v, None => return false };
        self.tat = new_tat;
        true
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// TBI-9 inductive step: from ANY state satisfying inv, one on_rst at ANY time keeps inv,
    /// never overflows, and never mints more than RATE*dt (+ nothing on a backwards clock).
    #[kani::proof]
    fn rst_step_inductive() {
        let mut b = RstBucket { tokens: kani::any(), last_ns: kani::any() };
        kani::assume(b.inv());
        let before = b;
        let now: u64 = kani::any();
        let ok = b.on_rst(now);
        assert!(b.inv());
        if now <= before.last_ns {
            assert!(b.tokens <= before.tokens);
            assert!(b.last_ns == before.last_ns);
        } else {
            let minted = (now - before.last_ns) as u128 * RATE as u128;
            assert!((b.tokens as u128) + if ok { SCALE as u128 } else { 0 } <= before.tokens as u128 + minted);
        }
    }

    /// TBI-9 rate bound over a bounded trace: accepted RSTs over [t0, tn] <= BURST + RATE*(tn-t0)/1s.
    const N: usize = 6;
    #[kani::proof]
    #[kani::unwind(7)]
    fn rst_rate_bound_trace() {
        let t0: u64 = kani::any();
        let mut b = RstBucket::new(t0);
        let mut now = t0;
        let mut accepted: u128 = 0;
        for _ in 0..N {
            let dt: u64 = kani::any();
            kani::assume(dt <= 10 * SCALE); // steps of <= 10 s; clock monotone here
            now = match now.checked_add(dt) { Some(v) => v, None => return };
            if b.on_rst(now) { accepted += 1; }
            assert!(b.inv());
        }
        let elapsed = (now - t0) as u128;
        assert!(accepted * SCALE as u128 <= BURST as u128 * SCALE as u128 + RATE as u128 * elapsed);
    }

    /// GCRA I2 (per-key isolation is structural: admit takes &mut self of one key) + step facts.
    #[kani::proof]
    fn gcra_step() {
        let mut g = Gcra { tat: kani::any() };
        let (now, cost, t, tau): (u64, u64, u64, u64) = (kani::any(), kani::any(), kani::any(), kani::any());
        kani::assume(now <= MAX_NOW && g.tat <= MAX_NOW + MAX_TAU + MAX_T * MAX_COST);
        kani::assume(cost >= 1 && cost <= MAX_COST && t >= 1 && t <= MAX_T && tau <= MAX_TAU);
        let before = g;
        let ok = g.admit(now, cost, t, tau);
        if ok {
            assert!(g.tat >= now + t * cost);
            assert!(g.tat - now <= tau + t * cost);
            assert!(g.tat >= before.tat);
        } else {
            assert!(g.tat == before.tat);
        }
    }

    /// GCRA I1 over a bounded trace: T * sum(admitted cost) <= (t_last - t_first) + tau + T*MAX_COST.
    #[kani::proof]
    #[kani::unwind(7)]
    fn gcra_window_bound_trace() {
        let t: u64 = kani::any();
        let tau: u64 = kani::any();
        kani::assume(t >= 1 && t <= MAX_T && tau <= MAX_TAU);
        let t_first: u64 = kani::any();
        kani::assume(t_first <= MAX_NOW);
        let mut g = Gcra { tat: 0 };
        let mut now = t_first;
        let mut sum: u128 = 0;
        for _ in 0..N {
            let dt: u64 = kani::any();
            let cost: u64 = kani::any();
            kani::assume(dt <= 1_000_000_000_000 && cost >= 1 && cost <= MAX_COST);
            now += dt;
            if g.admit(now, cost, t, tau) { sum += cost as u128; }
        }
        assert!(t as u128 * sum <= (now - t_first) as u128 + tau as u128 + t as u128 * MAX_COST as u128);
    }
}
