//! Kani harnesses for monban-budget (unit P2-kani-tbi-001; spec F1 TBI-5, TBI-9, Admission I1, I4, I5).
//!
//! These run against the real `TokenBucket`, `Gcra` and `LruStore`, not copies. They are compiled only under
//! `cfg(kani)` and run by `ci/kani.sh` on the prover box.
//!
//! The obligations follow the shape rule from spike q2-013. Each one is a single-step lemma over symbolic state.
//! Window bounds are stated in emission-time units (ghost `credit += T·cost`). There are no unrolled traces of
//! the GCRA. Kani's default checks (arithmetic overflow, panics, out-of-bounds) run on every line the harnesses
//! reach. So TBI-9, no counter overflow, is discharged for the production code on every path a harness covers.
//!
//! `TokenBucket`'s fields are private to `bucket.rs`, and this module may not change that file. So the RST
//! state cannot be havocked directly. `reachable_rst` builds it with public calls instead:
//! `rst(0)`, `a ≤ 100` takes at 0, a refill to `t1 = d < 1 s`, then `n ≤ 32` takes at `t1`.
//! Every take in the prefix is asserted to succeed. Alongside, it tracks the exact level as a ghost written from
//! the TBI-5 semantics, not from the code: one token is 1e9 sub-units, refill is `33·dt` and clamps at `cap`.
//!
//! Coverage: every level `L ≤ cap` is reached. Pick the unique `d < 1e9` with `33·d ≡ L (mod 1e9)`; 33 is
//! invertible mod 1e9. If `33·d ≤ L`, take `a = 100 − (L − 33·d)/1e9` and `n = 0`. Otherwise take `a = 100`
//! and `n = (33·d − L)/1e9 ≤ 32`. Neither refill reaches the clamp.
//! The construction starts at time 0 because a symbolic start time timed out (> 15 min). Each prefix take
//! then pays for a symbolic `t0 − t0` refill.
//! The step itself is over every `now: u64`: forward gaps up to 2^64 − 1 − last, which includes the saturation
//! of `dt·33`, and backward steps. The code reads time only as `now.saturating_sub(last_ns)` and stores `now`.
//! So the lemma covers every reachable level at any `last_ns`. That last step is translation invariance, and it
//! is argued from the code, not checked by Kani.
//!
//! The step checks compare against the ghost, not against `available()` floors before and after; that
//! version ran past 11 min. The decision of the step take must equal the ghost spec. The ghost level after the
//! step stays ≤ cap. A probe take on a clone at a non-refilling time must also match the ghost. That ties the
//! real post-state to the ghost at the whole-token boundary. One `available()` read gives the observable TBI-5
//! bound `tokens ≤ burst`.
//!
//! The negative control is compiled only with `--cfg monban_kani_negative`. It asserts a property that is false
//! of the real code: refill with no `min`. It must FAIL, which shows the harness setup can go red.

// `kani` (and `monban_kani_negative`) are not cfg names Cargo knows. The check-cfg lint is allowed for this
// module only, and lib.rs declares the module unconditionally: an allow on the item does not reach a `cfg` on
// that same item. In normal builds this module is empty.
#![allow(unexpected_cfgs)]

#[cfg(kani)]
mod harnesses {
    use crate::{DEBIT_CAP_NS, Gcra, LruStore, NS_PER_S, RST_BURST, RST_REFILL_PER_S, TokenBucket};

    /// Longest run of prefix takes at `t1` that the coverage argument needs (see the module docs).
    const MAX_N: u64 = 32;

    /// A symbolic RST bucket reached through the public API. Returns the bucket, its `last_ns`, and the exact
    /// ghost level in sub-units (see the module docs).
    fn reachable_rst() -> (TokenBucket, u64, u64) {
        let cap = RST_BURST * NS_PER_S;
        let mut b = TokenBucket::rst(0);
        let a: u64 = kani::any();
        kani::assume(a <= RST_BURST);
        for i in 0..RST_BURST {
            if i < a {
                assert!(b.try_take(0), "a full RST bucket holds RST_BURST tokens");
            }
        }
        let g0 = cap - a * NS_PER_S;
        let t1: u64 = kani::any();
        kani::assume(t1 < NS_PER_S);
        let _ = b.available(t1); // refill only; the quotient is unused
        let g1 = core::cmp::min(cap, g0 + t1 * RST_REFILL_PER_S);
        let n: u64 = kani::any();
        kani::assume(n <= MAX_N && n * NS_PER_S <= g1);
        for i in 0..MAX_N {
            if i < n {
                assert!(b.try_take(t1), "ghost says a token is there");
            }
        }
        (b, t1, g1 - n * NS_PER_S)
    }

    /// TBI-5 / TBI-9: one `try_take` at any `now`, from any reachable RST state. Nothing overflows. The decision
    /// equals the TBI-5 spec: refill `33·dt` only for an advancing clock, clamped at burst. Tokens stay ≤ burst
    /// afterwards. A clock that does not advance mints nothing. Once `33·dt ≥ 1 token` the take succeeds.
    #[kani::proof]
    #[kani::unwind(101)]
    fn rst_one_step() {
        let cap = RST_BURST * NS_PER_S;
        let (mut b, last, g) = reachable_rst();
        let now: u64 = kani::any();
        let ok = b.try_take(now);
        let refilled = if now > last {
            core::cmp::min(u128::from(cap), u128::from(g) + u128::from(now - last) * u128::from(RST_REFILL_PER_S))
        } else {
            u128::from(g) // a non-advancing clock mints nothing
        };
        let ns = u128::from(NS_PER_S);
        assert!(ok == (refilled >= ns), "take decision matches the TBI-5 spec");
        let g_after = if ok { refilled - ns } else { refilled };
        assert!(g_after <= u128::from(cap), "TBI-5: level <= burst");
        // the real post-state agrees with the ghost at the one-token boundary (no refill at max(now, last))
        let mut probe = b.clone();
        assert!(probe.try_take(core::cmp::max(now, last)) == (g_after >= ns), "post-state matches ghost");
        assert!(b.available(core::cmp::max(now, last)) <= RST_BURST, "TBI-5: tokens <= burst");
        kani::cover!(ok, "take succeeds");
        kani::cover!(!ok, "take refused");
        kani::cover!(now < last, "backwards clock");
        kani::cover!(g_after == u128::from(cap) - ns, "step from a full bucket");
    }

    /// TBI-9 for any `TokenBucket` parameters (full u64 width): build, take and read at arbitrary times with no
    /// overflow, panic or division fault (Kani's default checks). The level bound is proved for the RST
    /// parameters in `rst_one_step`. With symbolic capacity and rate the `avail ≤ cap` relation crosses a
    /// symbolic multiply and a divide, and it ran past 10 min, so it is not claimed here.
    #[kani::proof]
    fn bucket_any_params_no_overflow() {
        let (cap, rate, t0, t1, t2): (u64, u64, u64, u64, u64) =
            (kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
        let mut b = TokenBucket::new(cap, rate, t0);
        let took = b.try_take(t1);
        let _ = b.available(t2);
        kani::cover!(took, "take succeeds");
        kani::cover!(!took, "take refused");
    }

    /// GCRA single step, any parameters and state (full u64 width). Conformance gives `new ≥ max(tat, now)`
    /// and `new − now ≤ τ`. The new TAT is exactly `max(tat, now) + cost·T` with no wrap. `charge` writes
    /// exactly the conform result. On non-conformance the state is unchanged.
    #[kani::proof]
    fn gcra_conform_charge_step() {
        let g = Gcra::new(kani::any(), kani::any());
        let (tat, now, cost): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        let res = g.conform(tat, now, cost);
        let mut state = tat;
        let charged = g.charge(&mut state, now, cost);
        match res {
            Some(n) => {
                assert!(n >= tat && n >= now, "TAT monotone");
                assert!(u128::from(n - now) <= g.tau(), "conformance => new TAT - now <= tau");
                assert!(
                    u128::from(n) == u128::from(core::cmp::max(tat, now)) + u128::from(cost) * u128::from(g.t_ns),
                    "no wrap: new TAT is exact"
                );
                assert!(charged && state == n, "charge applies the conform result");
            }
            None => {
                assert!(!charged && state == tat, "non-conformance leaves state unchanged");
            }
        }
        kani::cover!(res.is_some() && cost > 0, "conforming charge");
        kani::cover!(res.is_none(), "refused charge");
    }

    /// Bounds for the I1 lemma (spike q2-013 shape rule: symbolic×symbolic products need one factor ≤ 8 bits;
    /// here that factor is `cost`).
    const MAX_COST: u64 = 64;
    const MAX_T: u64 = 1_000_000_000; // ≥ 1 unit/s
    const MAX_BURST: u64 = 255;
    const MAX_NOW: u64 = 1 << 62;

    /// Admission I1 (admitted cost in any window ≤ b + r·W), inductive form in emission-time units.
    ///
    /// Ghost state: window start `t_first`, last decision time `last`, and `credit` = Σ T·cost admitted since
    /// `t_first`. Invariant: J: `credit ≤ max(tat, t_first) − t_first`, and K: `credit > 0 ⇒ tat ≤ last + τ`.
    /// J ∧ K imply `credit ≤ (last − t_first) + τ`, which is I1 (divide by T). One `charge` at any `now ≥ last`
    /// preserves J ∧ K. Credit 0 satisfies J ∧ K for any TAT, so the bound holds for a window starting anywhere,
    /// for traces of any length.
    #[kani::proof]
    fn gcra_window_i1_inductive() {
        let g = Gcra::new(kani::any(), kani::any());
        kani::assume(g.t_ns >= 1 && g.t_ns <= MAX_T && g.burst <= MAX_BURST);
        let tau = g.tau();
        let (t_first, last, credit): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        let mut tat: u64 = kani::any();
        kani::assume(t_first <= last && last <= MAX_NOW);
        let base0 = core::cmp::max(tat, t_first);
        kani::assume(credit <= base0 - t_first);
        kani::assume(credit == 0 || u128::from(tat) <= u128::from(last) + tau);
        // consequence: the window bound
        assert!(u128::from(credit) <= u128::from(last - t_first) + tau, "I1 window bound");
        // preservation by one decision
        let now: u64 = kani::any();
        let cost: u64 = kani::any();
        kani::assume(now >= last && now <= MAX_NOW && cost <= MAX_COST);
        let admitted = g.charge(&mut tat, now, cost);
        let credit2 = if admitted { credit + cost * g.t_ns } else { credit };
        assert!(credit2 <= core::cmp::max(tat, t_first) - t_first, "J preserved");
        assert!(credit2 == 0 || u128::from(tat) <= u128::from(now) + tau, "K preserved");
        kani::cover!(admitted && cost > 0 && credit > 0, "admit with prior credit");
    }

    /// I5: a post-hoc debit, for any parameters and state, gives `TAT ≤ now + 10 min` (saturating). It never
    /// lowers the TAT below `min(max(tat, now), now + 10 min)` and never wraps.
    #[kani::proof]
    fn gcra_debit_cap_i5() {
        let g = Gcra::new(kani::any(), kani::any());
        let (tat, now, extra): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        let d = g.debit(tat, now, extra);
        let cap = now.saturating_add(DEBIT_CAP_NS);
        assert!(d <= cap, "I5: debit TAT <= now + 10 min");
        assert!(d >= core::cmp::min(core::cmp::max(tat, now), cap), "debit never refunds");
        kani::cover!(d == cap && cap < u64::MAX, "debit capped");
    }

    /// I4 (rate part), stated in emission-time units like I1. A fresh key's TAT is exactly
    /// `initial_tat(now, grant) = min(now + w·T, u64::MAX)` with `w = b − min(b, grant)` withheld units.
    /// `gcra_conform_charge_step` holds for every TAT, so for this one too. A charge of `cost` at `now`
    /// conforms only if `(tat − now) + cost·T ≤ τ = b·T` exactly. Unsaturated, that gives `w·T + cost·T ≤ b·T`,
    /// i.e. `cost ≤ min(b, grant)` for T ≥ 1. Saturated at `u64::MAX`, only `cost·T = 0` fits.
    /// The final division by T is arithmetic, not code.
    /// Proving the composed statement `conform ⇒ cost ≤ grant` in one harness did not finish in 15 min. That held
    /// even with T fixed or every value ≤ 8 bits, because it needs `w·T + c·T = (w + c)·T`; see the q2-013
    /// shape rule. Bound: `b ≤ 255` (the symbolic×symbolic rule: one factor ≤ 8 bits); T, now and grant are full
    /// u64.
    #[kani::proof]
    fn gcra_initial_tat_i4() {
        let g = Gcra::new(kani::any(), kani::any());
        kani::assume(g.burst <= MAX_BURST);
        let (now, grant): (u64, u64) = (kani::any(), kani::any());
        let tat0 = g.initial_tat(now, grant);
        let withheld = g.burst - core::cmp::min(g.burst, grant);
        let exact = u128::from(now) + u128::from(withheld) * u128::from(g.t_ns);
        assert!(u128::from(tat0) == core::cmp::min(exact, u128::from(u64::MAX)), "I4: fresh TAT withholds b - grant");
        kani::cover!(withheld > 0 && u128::from(tat0) == exact && g.t_ns > 0, "grant below burst");
    }

    /// I4 (memory part) on the real `LruStore`, limited to what Kani's symbolic execution of `BTreeMap` can
    /// finish. Capacity 0: every insert fails closed with `StoreFull` and the store stays empty. Capacity 1 or 2:
    /// the first insertion of any key starts at the anonymous TAT (the `init` value), and len ≤ capacity.
    /// Two or more operations on one store did not finish in 10 min, even with concrete keys: `BTreeMap`
    /// remove/insert unfolds node merge/split paths. So eviction and LRU order stay covered by the differential
    /// unit test `lru::tests::prop_matches_model`, not by Kani.
    #[kani::proof]
    #[kani::unwind(4)]
    fn lru_capacity_zero_fails_closed() {
        let mut store: LruStore<u8, u64> = LruStore::new(0);
        let key: u8 = kani::any();
        let res = store.get_or_insert_with(key, kani::any);
        assert!(res.is_err(), "capacity 0 fails closed");
        assert!(store.is_empty() && store.len() <= store.capacity(), "I4: capacity never exceeded");
    }

    /// See `lru_capacity_zero_fails_closed`.
    #[kani::proof]
    #[kani::unwind(4)]
    fn lru_first_insert_i4() {
        let cap: usize = kani::any();
        kani::assume(cap == 1 || cap == 2);
        let g = Gcra::new(kani::any(), kani::any());
        let (now, grant): (u64, u64) = (kani::any(), kani::any());
        let anon = g.initial_tat(now, grant);
        let mut store: LruStore<u8, u64> = LruStore::new(cap);
        let key: u8 = kani::any();
        match store.get_or_insert_with(key, || anon) {
            Ok((v, inserted)) => {
                assert!(inserted, "absent key is inserted");
                assert!(*v == anon, "I4: insertion starts at the anonymous burst");
            }
            Err(_) => assert!(false, "capacity >= 1 always has a slot"),
        }
        assert!(store.len() <= cap && store.contains(&key), "I4: capacity never exceeded");
    }

    /// NEGATIVE CONTROL (must FAIL). It claims the refill is unclamped, i.e. tokens = burst + 33·dt with no `min`.
    /// That is false of the real code: the clamp keeps tokens at burst.
    #[cfg(monban_kani_negative)]
    #[kani::proof]
    fn negative_control_unclamped_refill() {
        let t0: u64 = kani::any();
        let dt: u64 = kani::any();
        kani::assume(dt <= 1000 * NS_PER_S && t0 <= u64::MAX - dt);
        let mut b = TokenBucket::rst(t0);
        let got = b.available(t0 + dt);
        let unclamped = (RST_BURST * NS_PER_S + dt * RST_REFILL_PER_S) / NS_PER_S;
        assert!(got == unclamped, "NEGATIVE CONTROL: refill without min");
    }
}
