//! Per-principal crash budget (PLAN-5 D7; INV-P2 P2-4): 3 crash-attributable faults in 60 s ⇒ 429 for 600 s, per
//! principal, independent across principals, healthy failures never counted. All instants are caller-supplied.
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::time::{Duration, Instant};

use monban_iso::crash_budget::{CrashBudget, CrashKind, Failure, Params, Verdict};

fn s(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn penalized(v: Verdict) -> bool {
    matches!(v, Verdict::Penalty { .. })
}

const TRAP: Failure = Failure::Crash(CrashKind::Trap);

#[test]
fn three_crashes_in_sixty_seconds_give_429_for_six_hundred_seconds() {
    let t0 = Instant::now();
    let mut b = CrashBudget::new(Params::default());
    assert_eq!(b.params(), &Params::new(3, 60, 600).unwrap());
    assert_eq!(b.record(&"a", TRAP, t0), Verdict::Serve);
    assert_eq!(b.record(&"a", Failure::Crash(CrashKind::AbnormalExit), t0 + s(20)), Verdict::Serve);
    assert_eq!(b.check(&"a", t0 + s(40)), Verdict::Serve);
    let v = b.record(&"a", Failure::Crash(CrashKind::DecodeFailure), t0 + s(59));
    assert_eq!(v, Verdict::Penalty { since: t0 + s(59), until: Some(t0 + s(659)) });
    // 429 for the whole penalty, from the exhausting crash.
    for t in [59, 60, 300, 658] {
        assert!(penalized(b.check(&"a", t0 + s(t))), "t={t}");
    }
    let end = t0 + s(659);
    assert!(penalized(b.check(&"a", end - Duration::from_millis(1))));
    assert_eq!(b.check(&"a", end), Verdict::Serve);
    // After the penalty the budget starts empty: one more crash does not re-penalize.
    assert_eq!(b.record(&"a", TRAP, end + s(1)), Verdict::Serve);
}

#[test]
fn the_window_slides() {
    let t0 = Instant::now();
    let mut b = CrashBudget::new(Params::default());
    b.record(&"a", TRAP, t0);
    b.record(&"a", TRAP, t0 + s(30));
    // At t0+60 the first crash has left the window: two in the window, no penalty.
    assert_eq!(b.record(&"a", TRAP, t0 + s(60)), Verdict::Serve);
    // t0+30 and t0+60 are still in the window at t0+89: the third crash exhausts the budget.
    assert!(penalized(b.record(&"a", TRAP, t0 + s(89))));
}

#[test]
fn healthy_failures_never_count() {
    let t0 = Instant::now();
    let mut b = CrashBudget::new(Params::default());
    for i in 0..1_000 {
        assert_eq!(b.record(&"a", Failure::Healthy, t0 + Duration::from_millis(i)), Verdict::Serve);
    }
    assert_eq!(b.tracked(), 0);
    b.record(&"a", TRAP, t0 + s(2));
    b.record(&"a", Failure::Healthy, t0 + s(3));
    b.record(&"a", TRAP, t0 + s(4));
    b.record(&"a", Failure::Healthy, t0 + s(5));
    assert_eq!(b.check(&"a", t0 + s(6)), Verdict::Serve);
    assert!(penalized(b.record(&"a", Failure::Crash(CrashKind::CordonDeath), t0 + s(7))));
}

#[test]
fn principals_are_independent() {
    let t0 = Instant::now();
    let mut b = CrashBudget::new(Params::default());
    for i in 0..3 {
        b.record(&"a", TRAP, t0 + s(i));
    }
    assert!(penalized(b.check(&"a", t0 + s(3))));
    // b is served while a is in penalty, and a's crashes did not count for b.
    assert_eq!(b.check(&"b", t0 + s(3)), Verdict::Serve);
    assert_eq!(b.record(&"b", TRAP, t0 + s(4)), Verdict::Serve);
    assert_eq!(b.record(&"b", TRAP, t0 + s(5)), Verdict::Serve);
    assert_eq!(b.check(&"b", t0 + s(6)), Verdict::Serve);
    // b's crashes do not extend or change a's penalty.
    assert_eq!(b.check(&"a", t0 + s(6)), Verdict::Penalty { since: t0 + s(2), until: Some(t0 + s(602)) });
    // A crash reported for a during the penalty (a request admitted just before it) does not extend it.
    assert_eq!(b.record(&"a", TRAP, t0 + s(100)), Verdict::Penalty { since: t0 + s(2), until: Some(t0 + s(602)) });
    assert_eq!(b.check(&"a", t0 + s(602)), Verdict::Serve);
}

#[test]
fn scaled_knobs_and_pruning() {
    let t0 = Instant::now();
    // The p2-e2e scaled knobs: 3 crashes / 4 s window / 5 s penalty.
    let mut b = CrashBudget::new(Params::new(3, 4, 5).unwrap());
    b.record(&1u32, TRAP, t0);
    b.record(&1u32, TRAP, t0 + s(1));
    assert!(penalized(b.record(&1u32, TRAP, t0 + s(3))));
    assert_eq!(b.check(&1u32, t0 + s(8)), Verdict::Serve);
    b.record(&2u32, TRAP, t0 + s(3));
    b.prune(t0 + s(9));
    assert_eq!(b.tracked(), 0);
    // A single crash budget: the first crash exhausts it.
    let mut one = CrashBudget::new(Params::new(1, 60, 600).unwrap());
    assert!(penalized(one.record(&"x", TRAP, t0)));
}
