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
    /// Same I1 bound with the emission interval fixed at a config constant (33/s), tau symbolic.
    /// Rate constants are per-call-site configuration, so this is the obligation the CI gate would carry.
    #[kani::proof]
    #[kani::unwind(7)]
    fn gcra_window_bound_trace_fixed_t() {
        const T: u64 = 30_303_030; // ns per unit, 33 units/s
        let tau: u64 = kani::any();
        kani::assume(tau <= MAX_TAU);
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
            if g.admit(now, cost, T, tau) { sum += cost as u128; }
        }
        assert!(T as u128 * sum <= (now - t_first) as u128 + tau as u128 + T as u128 * MAX_COST as u128);
    }
    /// GCRA I1 stated inductively (the form the CI gate should carry; the unrolled trace above blows up in
    /// solver time). Ghost (t_first, sum, last_now). J: t_first + T*sum <= max(tat, t_first).
    /// K: sum > 0 ==> tat <= last_now + tau + T*MAX_COST. J and K are preserved by one admit at any
    /// now >= last_now, and J /\ K imply T*sum <= (now - t_first) + tau + T*MAX_COST for every N.
    #[kani::proof]
    fn gcra_window_inductive() {
        let (t, tau): (u64, u64) = (kani::any(), kani::any());
        kani::assume(t >= 1 && t <= MAX_T && tau <= MAX_TAU);
        let (t_first, last_now, sum): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        let mut g = Gcra { tat: kani::any() };
        kani::assume(t_first <= last_now && last_now <= MAX_NOW && sum <= 1 << 40);
        kani::assume(g.tat <= MAX_NOW + MAX_TAU + MAX_T * MAX_COST);
        let j = |tat: u64, sum: u64| -> bool {
            t_first as u128 + t as u128 * sum as u128 <= core::cmp::max(tat, t_first) as u128
        };
        let k = |tat: u64, sum: u64, last: u64| -> bool {
            sum == 0 || tat as u128 <= last as u128 + tau as u128 + t as u128 * MAX_COST as u128
        };
        kani::assume(j(g.tat, sum) && k(g.tat, sum, last_now));
        // consequence: the window bound holds in any state satisfying J and K
        assert!(t as u128 * sum as u128 <= (last_now - t_first) as u128 + tau as u128 + t as u128 * MAX_COST as u128);
        // preservation by one step
        let now: u64 = kani::any();
        let cost: u64 = kani::any();
        kani::assume(now >= last_now && now <= MAX_NOW && cost >= 1 && cost <= MAX_COST);
        let sum2 = if g.admit(now, cost, t, tau) { sum + cost } else { sum };
        assert!(j(g.tat, sum2));
        assert!(k(g.tat, sum2, now));
    }
    /// Same inductive I1 with the emission interval fixed (config constant), tau symbolic.
    #[kani::proof]
    fn gcra_window_inductive_fixed_t() {
        let t: u64 = 30_303_030; // 33 units/s, a config constant at each call site
        let tau: u64 = kani::any();
        kani::assume(tau <= MAX_TAU);
        let (t_first, last_now, sum): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        let mut g = Gcra { tat: kani::any() };
        kani::assume(t_first <= last_now && last_now <= MAX_NOW && sum <= 1 << 40);
        kani::assume(g.tat <= MAX_NOW + MAX_TAU + MAX_T * MAX_COST);
        let j = |tat: u64, sum: u64| -> bool {
            t_first as u128 + t as u128 * sum as u128 <= core::cmp::max(tat, t_first) as u128
        };
        let k = |tat: u64, sum: u64, last: u64| -> bool {
            sum == 0 || tat as u128 <= last as u128 + tau as u128 + t as u128 * MAX_COST as u128
        };
        kani::assume(j(g.tat, sum) && k(g.tat, sum, last_now));
        // consequence: the window bound holds in any state satisfying J and K
        assert!(t as u128 * sum as u128 <= (last_now - t_first) as u128 + tau as u128 + t as u128 * MAX_COST as u128);
        // preservation by one step
        let now: u64 = kani::any();
        let cost: u64 = kani::any();
        kani::assume(now >= last_now && now <= MAX_NOW && cost >= 1 && cost <= MAX_COST);
        let sum2 = if g.admit(now, cost, t, tau) { sum + cost } else { sum };
        assert!(j(g.tat, sum2));
        assert!(k(g.tat, sum2, now));
    }
    /// I1 inductive, multiplication-free form: ghost `credit` = sum over admitted requests of T*cost_i
    /// (I1 in emission-time units). The variants above need T*(sum+c) = T*sum + T*c (distributivity), which
    /// bit-blasted SAT cannot prove in 15-25 min even on a 13k-variable instance; this one needs only adds.
    #[kani::proof]
    fn gcra_window_inductive_credit() {
        let (t, tau): (u64, u64) = (kani::any(), kani::any());
        kani::assume(t >= 1 && t <= MAX_T && tau <= MAX_TAU);
        let (t_first, last_now, credit): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        let mut g = Gcra { tat: kani::any() };
        kani::assume(t_first <= last_now && last_now <= MAX_NOW);
        kani::assume(g.tat <= MAX_NOW + MAX_TAU + MAX_T * MAX_COST);
        // J: t_first + credit <= max(tat, t_first);  K: credit > 0 ==> tat <= last_now + tau + T*MAX_COST
        let tat0 = g.tat;
        kani::assume(credit <= core::cmp::max(tat0, t_first) - t_first);
        kani::assume(credit == 0 || tat0 <= last_now + tau + t * MAX_COST);
        // consequence: the window bound (credit is T * sum(cost) of admitted requests)
        assert!(credit <= (last_now - t_first) + tau + t * MAX_COST);
        let now: u64 = kani::any();
        let cost: u64 = kani::any();
        kani::assume(now >= last_now && now <= MAX_NOW && cost >= 1 && cost <= MAX_COST);
        let credit2 = if g.admit(now, cost, t, tau) { credit + t * cost } else { credit };
        assert!(credit2 <= core::cmp::max(g.tat, t_first) - t_first);
        assert!(credit2 == 0 || g.tat <= now + tau + t * MAX_COST);
    }
}
