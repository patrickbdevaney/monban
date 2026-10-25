use super::*;
use aegis_budget::DEBIT_CAP_NS;
use std::string::ToString;

const S: u64 = 1_000_000_000;

fn cfg() -> Config {
    Config {
        s1: Gcra::new(S / 10, 50),
        s1_store: 16,
        s3_store: 16,
        anon: Gcra::new(S / 10, 60),
        session: Gcra::new(S / 20, 120),
        verified: Gcra::new(S / 40, 240),
        agg_f: Gcra::new(S / 300, 300),
        agg_e: Gcra::new(S / 400, 400),
        exp_cost: 20,
        stepup_cost: 100,
        stepup_bits: 16,
        limit: 10,
        max_conns: 8,
        prefix_cap: 4,
        fresh_age_ns: 60 * S,
    }
}

fn arrive(id: u64, t: u64, ip: &str, cred: Credential, cost: u64) -> Arrive {
    Arrive {
        id,
        t,
        ip: ip.to_string(),
        prefix: "p".to_string(),
        conn: ip.to_string(),
        newconn: false,
        cred,
        cost,
        pow: 0,
        lane: Lane::Std,
        fault: None,
    }
}

fn rej(stage: Stage, status: RejectStatus) -> Verdict {
    Verdict::Reject { stage, status }
}

#[test]
fn classify_rules() {
    let c = |minted, promoted| Credential::Cookie { id: "x".to_string(), minted, promoted };
    assert_eq!(classify(&Credential::None, 5, 1), Class::Anon);
    assert_eq!(classify(&Credential::Verified { id: "v".to_string() }, 5, 1), Class::Verified);
    assert_eq!(classify(&c(10, true), 5, 1), Class::Anon);
    assert_eq!(classify(&c(0, true), 5, 5), Class::Established);
    assert_eq!(classify(&c(0, false), 5, 5), Class::Fresh);
    assert_eq!(classify(&c(1, true), 5, 5), Class::Fresh);
}

#[test]
fn faults_reject_503_at_each_stage() {
    for st in [Stage::S0, Stage::S1, Stage::S2, Stage::S3, Stage::S3A, Stage::S4, Stage::S5, Stage::S6] {
        let mut a = Admission::new(cfg());
        let mut ev = arrive(1, S, "1.1.1.1", Credential::None, 1);
        ev.fault = Some(st);
        let want = if st == Stage::S3A { Stage::S3 } else { st };
        assert_eq!(a.arrive(&ev), rej(want, RejectStatus::Unavailable));
        assert_eq!(a.in_flight(), 0);
    }
}

#[test]
fn new_identity_gets_only_anon_burst_and_debit_is_capped() {
    let mut a = Admission::new(cfg());
    let v = Credential::Verified { id: "v1".to_string() };
    // Verified b=240 but a new entry gets min(240, b_anon=60) units at insertion (I4). Cost 19 avoids aggregates.
    let mut admitted = 0;
    for i in 0..10 {
        if a.arrive(&arrive(i, S, &std::format!("10.0.0.{i}"), v.clone(), 19)) == Verdict::Admit {
            admitted += 19;
        }
        a.done(&Done { id: i, t: S, actual_cost: 19, cancelled: false });
    }
    assert_eq!(admitted, 57);
    // Huge overrun: TAT capped at now + 10 min, never wraps.
    let ev = arrive(100, 1000 * S, "9.9.9.9", v.clone(), 1);
    assert_eq!(a.arrive(&ev), Verdict::Admit);
    a.done(&Done { id: 100, t: 1000 * S, actual_cost: u64::MAX, cancelled: false });
    let tat = a.s3.peek(&BucketKey::Verified("v1".to_string())).map(|e| e.tat);
    assert_eq!(tat, Some(1000 * S + DEBIT_CAP_NS));
    // τ = 6 s < 600 s, so the identity is locked out until the cap expires…
    assert_eq!(
        a.arrive(&arrive(101, 1001 * S, "9.9.9.8", v.clone(), 1)),
        rej(Stage::S3, RejectStatus::TooManyRequests)
    );
    // …and conforms again once now + τ reaches the capped TAT.
    assert_eq!(a.arrive(&arrive(102, 1000 * S + DEBIT_CAP_NS, "9.9.9.7", v, 1)), Verdict::Admit);
}

#[test]
fn aggregate_reject_leaves_identity_uncharged() {
    let mut c = cfg();
    c.agg_f = Gcra::new(S, 20);
    let mut a = Admission::new(c);
    let ck = |id: &str| Credential::Cookie { id: id.to_string(), minted: 0, promoted: false };
    assert_eq!(a.arrive(&arrive(1, S, "a", ck("s1"), 20)), Verdict::Admit);
    let before = a.s3.peek(&BucketKey::Session("s2".to_string())).map(|e| e.tat);
    assert_eq!(before, None);
    assert_eq!(a.arrive(&arrive(2, S, "b", ck("s2"), 20)), rej(Stage::S3A, RejectStatus::Unavailable));
    // Entry inserted (touched) at its initial TAT, not charged.
    let init = Gcra::new(S / 20, 120).initial_tat(S, 60);
    assert_eq!(a.s3.peek(&BucketKey::Session("s2".to_string())).map(|e| e.tat), Some(init));
}

#[test]
fn stepup_and_lanes() {
    let mut a = Admission::new(cfg());
    let mut ev = arrive(1, S, "a", Credential::None, 100);
    assert_eq!(a.arrive(&ev), rej(Stage::S3, RejectStatus::TooManyRequests)); // cost 100 > b_anon = 60
    let mut c = cfg();
    c.anon = Gcra::new(S / 10, 600);
    c.agg_f = Gcra::new(1, 10_000);
    let mut a = Admission::new(c);
    ev.id = 2;
    assert_eq!(a.arrive(&ev), rej(Stage::S4, RejectStatus::Unauthorized));
    ev.id = 3;
    ev.lane = Lane::Accessible;
    assert_eq!(a.arrive(&ev), Verdict::Admit);
    ev.id = 4;
    ev.lane = Lane::Std;
    ev.pow = 16;
    assert_eq!(a.arrive(&ev), Verdict::Admit);
}

#[test]
fn s0_caps_and_close() {
    let mut c = cfg();
    c.max_conns = 2;
    c.prefix_cap = 1;
    let mut a = Admission::new(c);
    let mut e1 = arrive(1, S, "a", Credential::None, 1);
    e1.newconn = true;
    assert_eq!(a.arrive(&e1), Verdict::Admit);
    let mut e2 = arrive(2, S, "b", Credential::None, 1);
    e2.newconn = true;
    assert_eq!(a.arrive(&e2), rej(Stage::S0, RejectStatus::Unavailable));
    e2.prefix = "q".to_string();
    assert_eq!(a.arrive(&e2), Verdict::Admit);
    let mut e3 = arrive(3, S, "c", Credential::None, 1);
    e3.newconn = true;
    e3.prefix = "r".to_string();
    assert_eq!(a.arrive(&e3), rej(Stage::S0, RejectStatus::Unavailable));
    a.close(&Close { conn: "a".to_string(), t: S });
    // Free the anon S5 reservation so only S0 is under test.
    a.done(&Done { id: 1, t: S, actual_cost: 1, cancelled: false });
    a.done(&Done { id: 2, t: S, actual_cost: 1, cancelled: false });
    assert_eq!(a.arrive(&e3), Verdict::Admit);
    assert_eq!(a.open_connections(), 2);
}

#[test]
fn s5_reservations_and_borrowing() {
    let mut c = cfg();
    c.limit = 10;
    let mut a = Admission::new(c);
    // anon reservation 2; others hold 3+4+1 = 8 in reserve, so anon may not borrow past 2.
    let mut ok = 0;
    for i in 0..5 {
        if a.arrive(&arrive(i, S, &std::format!("ip{i}"), Credential::None, 1)) == Verdict::Admit {
            ok += 1;
        }
    }
    assert_eq!(ok, 2);
    a.done(&Done { id: 0, t: S, actual_cost: 0, cancelled: true });
    assert_eq!(a.arrive(&arrive(9, S, "ipx", Credential::None, 1)), Verdict::Admit);
}

/// Small deterministic PRNG for property loops.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
}

/// I7 and boundedness on random traces: faults always reject, rejects carry 401/429/503, stores, in-flight and
/// connections stay within their caps, and nothing panics (including u64::MAX overruns).
#[test]
fn prop_random_traces() {
    let mut r = Rng(0x5EED_1234_ABCD_0001);
    for _ in 0..200 {
        let mut c = cfg();
        c.s3_store = 1 + r.below(6) as usize;
        c.s1_store = 1 + r.below(6) as usize;
        c.limit = 1 + r.below(40);
        let mut a = Admission::new(c.clone());
        let mut now = S;
        for id in 0..300u64 {
            now = now.saturating_add(r.below(S / 5));
            let who = r.below(5);
            let cred = match r.below(3) {
                0 => Credential::None,
                1 => Credential::Verified { id: std::format!("v{who}") },
                _ => Credential::Cookie { id: std::format!("c{who}"), minted: r.below(now), promoted: r.below(2) == 0 },
            };
            let mut ev = arrive(id, now, &std::format!("ip{who}"), cred, r.below(130));
            ev.newconn = r.below(3) == 0;
            ev.conn = std::format!("k{}", r.below(12));
            ev.pow = r.below(20);
            ev.fault = match r.below(20) {
                0 => Some(Stage::S0),
                1 => Some(Stage::S3),
                2 => Some(Stage::S6),
                _ => None,
            };
            let v = a.arrive(&ev);
            match v {
                Verdict::Admit => {
                    assert!(ev.fault.is_none());
                    assert_eq!(v.http_status(), 200);
                }
                Verdict::Reject { status, .. } => assert!(matches!(status.code(), 401 | 429 | 503)),
            }
            if r.below(2) == 0 {
                let actual = if r.below(10) == 0 { u64::MAX } else { r.below(200) };
                a.done(&Done { id: r.below(id + 1), t: now, actual_cost: actual, cancelled: false });
            }
            if r.below(5) == 0 {
                a.close(&Close { conn: std::format!("k{}", r.below(12)), t: now });
            }
            assert!(a.s1.len() <= c.s1_store && a.s3.len() <= c.s3_store);
            assert!(a.in_flight() <= c.limit);
            assert!(a.open_connections() as u64 <= c.max_conns);
        }
    }
}
