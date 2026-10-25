//! CFG-3 last-known-good, CFG-4 staged apply state machine, CFG-1 totality under random mutation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use aegis_config::{
    ConfigStore, ErrorKind, Generation, Health, MAX_CONFIG_BYTES, Phase, RolloutPolicy, StageError, parse_config,
};

const A: &str = r#"{"v":1,"listeners":[{"name":"web","bind":"0.0.0.0:443","profile":"P-PUBLIC-WEB","alpn":["h2"]}],
 "vhosts":[{"host":"example.com","routes":[{"id":1,"path":"/api/","to":{"upstream":"app","framing":"h2"},"authz":"api"},
 {"id":2,"path":"/s/","to":{"static":"/srv"}}]},{"host":"b.example","routes":[{"id":7,"path":"/","to":{"static":"x"}}]}],
 "admin":{"bind":"127.0.0.1:9000"},"limits":{"max_concurrent_streams":50,"stall_timeout_ms":2000},"canon":{"query":"typed"}}"#;
const B: &str = r#"{"v":1,"listeners":[{"name":"a","bind":"b","profile":"P-CNSA"}],
  "vhosts":[{"host":"a","routes":[{"id":1,"path":"/","to":{"static":"x"}}]}]}"#;
const C: &str = r#"{"v":1,"listeners":[{"name":"c","bind":"b","profile":"FIPS-CMVP"}],
  "vhosts":[{"host":"c","routes":[{"id":3,"path":"/c","to":{"upstream":"u"}}]}]}"#;

fn hash(s: &ConfigStore) -> Option<[u8; 32]> {
    s.config_hash()
}

fn policy() -> RolloutPolicy {
    RolloutPolicy { shadow_ms: 100, canary_permille: 10, bake_ms: 1000 }
}

#[test]
fn empty_store_serves_nothing() {
    let mut s = ConfigStore::new();
    assert!(s.current().is_none());
    assert!(s.apply(b"{}").is_err());
    assert!(s.current().is_none());
    assert_eq!(s.stage(B.as_bytes(), 0), Err(StageError::NoBaseline));
}

#[test]
fn lkg_on_err() {
    let mut s = ConfigStore::new();
    let g1 = s.apply(A.as_bytes()).unwrap();
    assert_eq!(g1, Generation(1));
    let h = hash(&s);
    let e = s.apply(b"{\"v\":2}").unwrap_err();
    assert_eq!(e.kind(), ErrorKind::MissingField);
    assert_eq!(hash(&s), h);
    assert_eq!(s.generation(), Some(g1));
    assert_eq!(s.last_error(), Some(&e));
    let g2 = s.apply(B.as_bytes()).unwrap();
    assert!(g2 > g1);
    assert!(s.last_error().is_none());
    assert_eq!(s.current().unwrap().listeners()[0].name, "a");
}

#[test]
fn oversize_three_times_cap_keeps_lkg() {
    let mut s = ConfigStore::new();
    s.apply(A.as_bytes()).unwrap();
    let h = hash(&s);
    let g = s.generation();
    // A valid document padded to 3x the cap.
    let mut big = A.to_string();
    big.push_str(&" ".repeat(3 * MAX_CONFIG_BYTES - big.len()));
    let e = s.apply(big.as_bytes()).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::TooLarge);
    assert_eq!((hash(&s), s.generation()), (h, g));
    // And as a staged candidate.
    assert!(matches!(s.stage(big.as_bytes(), 0), Err(StageError::Config(e)) if e.kind() == ErrorKind::TooLarge));
    assert_eq!((hash(&s), s.generation(), s.phase()), (h, g, None));
    // Pure garbage at 3x.
    assert_eq!(parse_config(&vec![b'['; 3 * MAX_CONFIG_BYTES]).unwrap_err().kind(), ErrorKind::TooLarge);
}

#[test]
fn rollout_happy_path() {
    let mut s = ConfigStore::with_policy(policy());
    let ga = s.apply(A.as_bytes()).unwrap();
    let ha = hash(&s);
    let gb = s.stage(B.as_bytes(), 1000).unwrap();
    assert_eq!(s.phase(), Some(Phase::Shadow));
    assert_eq!(s.stage(C.as_bytes(), 1000), Err(StageError::Busy));
    // Shadow never serves.
    assert!((0..1000).all(|b| s.config_for(b).unwrap().config_hash() == ha.unwrap()));
    assert_eq!(s.tick(1050, Health::Healthy), Ok(Phase::Shadow));
    assert_eq!(s.tick(1100, Health::Healthy), Ok(Phase::Canary));
    // Canary: exactly 10 of 1000 buckets see the candidate.
    let hb = s.candidate().unwrap().config_hash();
    let n = (0..1000u16).filter(|b| s.config_for(*b).unwrap().config_hash() == hb).count();
    assert_eq!(n, 10);
    assert_eq!(s.config_for(1005).unwrap().config_hash(), hb);
    assert_eq!(hash(&s), ha);
    assert_eq!(s.tick(2099, Health::Healthy), Ok(Phase::Canary));
    assert_eq!(s.tick(2100, Health::Healthy), Ok(Phase::Full));
    assert_eq!((s.generation(), hash(&s)), (Some(gb), Some(hb)));
    assert_eq!(s.phase(), None);
    assert_eq!(s.tick(3000, Health::Healthy), Err(StageError::NotStaging));
    // Rollback after Full restores the previous config, once.
    assert_eq!(s.rollback(), Ok(ga));
    assert_eq!(hash(&s), ha);
    assert_eq!(s.rollback(), Err(StageError::NothingToRollBack));
}

#[test]
fn rollout_unhealthy_rolls_back_in_each_phase() {
    for at_canary in [false, true] {
        let mut s = ConfigStore::with_policy(policy());
        let ga = s.apply(A.as_bytes()).unwrap();
        let ha = hash(&s);
        s.stage(B.as_bytes(), 0).unwrap();
        if at_canary {
            assert_eq!(s.tick(100, Health::Healthy), Ok(Phase::Canary));
        }
        assert_eq!(s.tick(150, Health::Unhealthy), Ok(Phase::RolledBack));
        assert_eq!((s.generation(), hash(&s), s.phase()), (Some(ga), ha, None));
        assert!((0..1000).all(|b| s.config_for(b).unwrap().config_hash() == ha.unwrap()));
    }
}

#[test]
fn rollout_manual_abort_and_clock_backwards() {
    let mut s = ConfigStore::with_policy(policy());
    let ga = s.apply(A.as_bytes()).unwrap();
    s.stage(B.as_bytes(), 5000).unwrap();
    // Clock going backwards counts as no elapsed time.
    assert_eq!(s.tick(0, Health::Healthy), Ok(Phase::Shadow));
    assert_eq!(s.rollback(), Ok(ga));
    assert_eq!(s.phase(), None);
    assert_eq!(s.current().unwrap().listeners()[0].name, "web");
}

#[test]
fn bad_candidate_does_not_start_rollout() {
    let mut s = ConfigStore::with_policy(policy());
    s.apply(A.as_bytes()).unwrap();
    let h = hash(&s);
    assert!(matches!(s.stage(b"{\"v\":1}", 0), Err(StageError::Config(_))));
    assert_eq!((s.phase(), hash(&s)), (None, h));
}

#[test]
fn apply_supersedes_rollout_but_failed_apply_does_not() {
    let mut s = ConfigStore::with_policy(policy());
    s.apply(A.as_bytes()).unwrap();
    s.stage(B.as_bytes(), 0).unwrap();
    assert!(s.apply(b"nope").is_err());
    assert_eq!(s.phase(), Some(Phase::Shadow));
    let gc = s.apply(C.as_bytes()).unwrap();
    assert_eq!((s.phase(), s.generation()), (None, Some(gc)));
}

// ------------------------------------------------------------------------------------------------ totality

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

const TOKENS: &[&[u8]] = &[
    b"0",
    b"1",
    b"-1",
    b"65535",
    b"1e3",
    b"1.5",
    b"9007199254740991",
    b"99999999999999999999",
    b"1e400",
    b"null",
    b"true",
    b"\"\"",
    b"\"x\"",
    b"\"h2\"",
    b"\"P-CNSA\"",
    b"\"opaque\"",
    b"\"typed\"",
    b"\"/\"",
    b"{}",
    b"[]",
    b"{",
    b"}",
    b"[",
    b"]",
    b",",
    b":",
    b"\"",
    b"\\",
    b"\\u0000",
    b"\\ud800",
    b"\"id\":1,",
    b"\"x\":0,",
    b"\"upstream\":\"u\",",
    b"\"static\":\"s\",",
    b"\"authz\":\"a\",",
    b"\xff",
    b"\xc3\xa9",
    b"\xef\xbb\xbf",
    b" ",
    b"\n",
    b"-0",
    b"0.0",
];

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..=rng.below(4) {
        match rng.below(7) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 => {
                let n = rng.below(v.len() + 1);
                v.truncate(n);
            }
            2 => {
                let i = rng.below(v.len() + 1);
                let t = TOKENS[rng.below(TOKENS.len())];
                v.splice(i..i, t.iter().copied());
            }
            3 if !v.is_empty() => {
                let i = rng.below(v.len());
                let n = rng.below(16).min(v.len() - i);
                v.drain(i..i + n);
            }
            4 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = rng.next() as u8;
            }
            5 if !v.is_empty() => {
                // Duplicate a span (repeats members / array items).
                let i = rng.below(v.len());
                let n = rng.below(64).min(v.len() - i);
                let span: Vec<u8> = v[i..i + n].to_vec();
                let j = rng.below(v.len() + 1);
                v.splice(j..j, span);
            }
            _ => {
                // Replace one digit run with another number token.
                if let Some(i) = (0..v.len()).map(|_| rng.below(v.len())).find(|&i| v[i].is_ascii_digit()) {
                    let mut j = i;
                    while j < v.len() && v[j].is_ascii_digit() {
                        j += 1;
                    }
                    let t = TOKENS[rng.below(8)];
                    v.splice(i..j, t.iter().copied());
                }
            }
        }
    }
    v
}

#[test]
fn totality_random_mutation() {
    let iters: u64 = std::env::var("AEGIS_CONFIG_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(if cfg!(debug_assertions) { 20_000 } else { 1_000_000 });
    let seeds: [&[u8]; 3] = [A.as_bytes(), B.as_bytes(), C.as_bytes()];
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut s = ConfigStore::with_policy(policy());
    s.apply(A.as_bytes()).unwrap();
    let (mut oks, mut errs) = (0u64, 0u64);
    let mut kinds = std::collections::HashSet::new();
    for i in 0..iters {
        let input = mutate(&mut rng, seeds[(i % 3) as usize]);
        let before = (s.config_hash(), s.generation());
        match s.apply(&input) {
            Ok(g) => {
                oks += 1;
                assert_eq!(s.generation(), Some(g));
                // A config that parses has an effective form that parses to the same hash.
                let c = s.current().unwrap();
                assert_eq!(parse_config(c.effective_json()).unwrap().config_hash(), c.config_hash());
            }
            Err(e) => {
                errs += 1;
                kinds.insert(e.kind());
                assert_eq!((s.config_hash(), s.generation()), before, "Err changed the served config");
                assert!(e.pointer().is_empty() || e.pointer().starts_with('/'));
            }
        }
        // Exercise the staged path too, on a slice of iterations.
        if i % 97 == 0 {
            let before = (s.config_hash(), s.generation());
            let staged = s.stage(&input, i);
            if staged.is_err() {
                assert_eq!((s.config_hash(), s.generation()), before, "failed stage changed the served config");
            }
            let _ = s.tick(i + 50, if rng.below(2) == 0 { Health::Healthy } else { Health::Unhealthy });
            let _ = s.rollback();
        }
    }
    println!("totality: {iters} inputs, {oks} accepted, {errs} rejected, kinds {kinds:?}");
    assert_eq!(oks + errs, iters);
    // The corpus must reach the schema layer, not only the JSON parser.
    assert!(kinds.len() >= 8, "mutations reached too few error kinds: {kinds:?}");
    assert!(oks > 0);
}
