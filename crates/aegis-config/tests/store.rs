//! CFG-3 last-known-good, CFG-4 staged apply state machine, CFG-1 totality under random mutation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use aegis_config::{
    Config, ConfigStore, CrashBudget, ErrorKind, Generation, Health, MAX_CONFIG_BYTES, P2Limits, Phase, RolloutPolicy,
    RouteTarget, StageError, parse_config,
};

const A: &str = r#"{"v":1,"listeners":[{"name":"web","bind":"0.0.0.0:443","profile":"P-PUBLIC-WEB","alpn":["h2"]}],
 "vhosts":[{"host":"example.com","routes":[{"id":1,"path":"/api/","to":{"upstream":"app","framing":"h2"},"authz":"api"},
 {"id":2,"path":"/s/","to":{"static":"/srv"}}]},{"host":"b.example","routes":[{"id":7,"path":"/","to":{"static":"x"}}]}],
 "admin":{"bind":"127.0.0.1:9000"},"limits":{"max_concurrent_streams":50,"stall_timeout_ms":2000},"canon":{"query":"typed"}}"#;
const B: &str = r#"{"v":1,"listeners":[{"name":"a","bind":"b","profile":"P-CNSA"}],
  "vhosts":[{"host":"a","routes":[{"id":1,"path":"/","to":{"static":"x"}}]}]}"#;
const C: &str = r#"{"v":1,"listeners":[{"name":"c","bind":"b","profile":"FIPS-CMVP"}],
  "vhosts":[{"host":"c","routes":[{"id":3,"path":"/c","to":{"upstream":"u"}}]}]}"#;
/// F8 `data` block (Phase 4): caps, the `unrestricted` literal, an absent endowment, all three dsn_ref forms.
const D: &str = r#"{"v":1,"listeners":[{"name":"d","bind":"b","profile":"P-PUBLIC-WEB"}],
  "vhosts":[{"host":"d","routes":[
    {"id":1,"path":"/n","to":{"upstream":"u"},"authz":"n","data":[{"backend":"pg","collection":"notes","ops":["select","insert"],"columns":["id","body"]},{"backend":"kv","collection":"s","ops":["upsert"],"columns":["k"]}]},
    {"id":2,"path":"/u","to":{"upstream":"u"},"data":"unrestricted"},
    {"id":3,"path":"/","to":{"static":"x"}}]}],
  "data":{"backends":[{"id":"pg","engine":"postgres","dsn_ref":"env:PG_DSN","pin":"pg18","max_conns":8},
    {"id":"kv","engine":"redis","dsn_ref":"cred:kv","pin":"redis","op_budget_ms":100},
    {"id":"lite","engine":"sqlite","dsn_ref":"path:/var/lib/a.db","pin":"sqlite"}]}}"#;
/// F8 `p2` block (Phase 5): wasm route targets, every p2 member set, module overrides and both tenancies.
const E: &str = r#"{"v":1,"listeners":[{"name":"e","bind":"b","profile":"P-PUBLIC-WEB"}],
  "vhosts":[{"host":"e","routes":[
    {"id":1,"path":"/m","to":{"wasm":"m"},"authz":"m"},
    {"id":2,"path":"/s","to":{"wasm":"s"},"authz":"s","data":"unrestricted"},
    {"id":3,"path":"/","to":{"upstream":"u"}}]}],
  "p2":{"worker":"/usr/libexec/aegis-p2","cache_dir":"/run/p2","isolation":"forkwasm","fuel":15000000,"wall_ms":100,
    "memory_mib":16,"max_host_calls":10000,"max_data_runs":64,"max_data_bytes":4194304,"max_resp_bytes":1048576,
    "max_log_bytes":65536,"frame_max_bytes":65536,"cordon_slots":64,"max_cordons":64,"cordon_idle_s":300,
    "crash_budget":{"crashes":3,"window_s":60,"penalty_s":600},"mpk":false,
    "modules":[{"id":"m","path":"/srv/m.wasm","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
      {"id":"s","path":"/srv/s.wasm","sha256":"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
       "tenancy":"single","fuel":20000,"wall_ms":50,"memory_mib":8}]}}"#;

/// F8 Phase-7 members (P7-spec-001): PROXY trusted prefixes, an L4 listener, the uring front and a `tls` block with
/// all three credential kinds.
const F: &str = r#"{"v":1,"listeners":[{"name":"f","bind":"b","profile":"P-PUBLIC-WEB","alpn":["h2"],
    "proxy_protocol":{"trusted":["10.0.0.0/8","2001:db8::/32"]},"front":"uring"},
   {"name":"g","bind":"c","profile":"P-PUBLIC-WEB","l4":[{"sni":"a.example","upstream":"10.0.0.2:443"},
    {"sni":"b.example","upstream":"[2001:db8::2]:8443"}]},
   {"name":"h","bind":"d","profile":"P-PQ-REQUIRED"}],
  "vhosts":[{"host":"f","routes":[{"id":1,"path":"/","to":{"upstream":"u"},"authz":"f"}]}],
  "admission":{"per_ip":{"rate_per_s":50000,"burst":100000},"per_ip_store":4096,"max_conns":1000,"per_prefix_conns":100,"concurrency":512},
  "tls":{"credentials":[{"id":"x","kind":"x509","chain":"cred:x.crt","key":"cred:x.key"},
    {"id":"m","kind":"mtc","trust_anchor_id":"32473.1","chain":"path:/etc/m.bin","key":"cred:m.key","listeners":["f"]},
    {"id":"q","kind":"mldsa","chain":"cred:q.crt","key":"cred:q.key","listeners":["h"]}]}}"#;

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
    // F8 p2 block (Phase 5).
    b"\"wasm\":\"m\",",
    b"{\"wasm\":\"m\"}",
    b"\"forkwasm\"",
    b"\"cordon\"",
    b"\"single\"",
    b"false",
    b"\"/x.wasm\"",
    b"\"cordon_key\":\"k\",",
    b"\"fuel\":1000000001,",
    b"\"crash_budget\":{},",
    // F8 Phase-7 members.
    b"\"front\":\"epoll\",",
    b"\"uring\"",
    b"\"10.0.0.1/8\"",
    b"\"0.0.0.0/0\"",
    b"\"::ffff:10.0.0.0/104\"",
    b"\"alpn\":[\"h2\"],",
    b"\"l4\":[{\"sni\":\"a.example\",\"upstream\":\"h:443\"}],",
    b"\"mldsa\"",
    b"\"mtc\"",
    b"\"trust_anchor_id\":\"1.2\",",
    b"\"listeners\":[\"f\"],",
    b"\"mariadb\"",
    b"\"burst\":1,",
    b"\"rate_per_s\":1000001,",
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
    let seeds: [&[u8]; 6] = [A.as_bytes(), B.as_bytes(), C.as_bytes(), D.as_bytes(), E.as_bytes(), F.as_bytes()];
    for seed in seeds {
        parse_config(seed).unwrap();
    }
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut s = ConfigStore::with_policy(policy());
    s.apply(A.as_bytes()).unwrap();
    let (mut oks, mut errs) = (0u64, 0u64);
    let (mut p2_oks, mut p2_errs) = (0u64, 0u64);
    let (mut p7_oks, mut p7_errs) = (0u64, 0u64);
    let mut kinds = std::collections::HashSet::new();
    for i in 0..iters {
        let input = mutate(&mut rng, seeds[(i % 6) as usize]);
        let before = (s.config_hash(), s.generation());
        match s.apply(&input) {
            Ok(g) => {
                oks += 1;
                assert_eq!(s.generation(), Some(g));
                // A config that parses has an effective form that parses to the same hash.
                let c = s.current().unwrap();
                assert_eq!(parse_config(c.effective_json()).unwrap().config_hash(), c.config_hash());
                if c.p2().is_some() {
                    p2_oks += 1;
                }
                if c.tls().is_some() || c.listeners().iter().any(|l| l.is_l4() || l.proxy_protocol.is_some()) {
                    p7_oks += 1;
                }
                p2_invariants(c);
                p7_invariants(c);
            }
            Err(e) => {
                errs += 1;
                kinds.insert(e.kind());
                if e.pointer().starts_with("/p2") || e.pointer().contains("/to/wasm") {
                    p2_errs += 1;
                }
                let ptr = e.pointer();
                if ptr.starts_with("/tls")
                    || ptr.starts_with("/admission")
                    || ptr.contains("/proxy_protocol")
                    || ptr.contains("/l4")
                    || ptr.ends_with("/front")
                    || e.kind() == ErrorKind::Forbidden
                {
                    p7_errs += 1;
                }
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
    println!(
        "totality: {iters} inputs, {oks} accepted ({p2_oks} with p2, {p7_oks} with phase-7 members), {errs} rejected \
         ({p2_errs} in p2, {p7_errs} in phase-7 members), kinds {kinds:?}"
    );
    assert_eq!(oks + errs, iters);
    // The corpus must reach the schema layer, not only the JSON parser.
    assert!(kinds.len() >= 8, "mutations reached too few error kinds: {kinds:?}");
    assert!(oks > 0);
    // The generator reaches the p2 block on both sides.
    assert!(p2_oks > 0 && p2_errs > 0, "p2 block not exercised: {p2_oks} accepted, {p2_errs} rejected");
    // ... and the Phase-7 members on both sides.
    assert!(p7_oks > 0 && p7_errs > 0, "phase-7 members not exercised: {p7_oks} accepted, {p7_errs} rejected");
}

/// What every accepted config guarantees about the Phase-7 members: an L4 listener carries no alpn and unique SNIs,
/// PROXY trust is non-empty and never /0, mtc credentials (and only they) carry a trust anchor, and no mldsa
/// credential is a candidate on a P-PUBLIC-WEB listener.
fn p7_invariants(c: &Config) {
    let a = c.admission();
    assert!(a.per_ip.rate_per_s >= 1 && a.per_ip.burst >= a.per_ip.rate_per_s && a.per_ip.burst <= 10_000_000);
    for ((n, lo, hi, _), v) in aegis_config::Admission::BOUNDS.iter().zip(a.values()) {
        assert!((*lo..=*hi).contains(&v), "admission.{n}={v}");
    }
    for l in c.listeners() {
        if let Some(r) = &l.l4 {
            assert!(l.alpn.is_none() && !r.is_empty());
            for (i, a) in r.iter().enumerate() {
                assert!(r.iter().skip(i + 1).all(|b| b.sni != a.sni));
                assert!(a.upstream_port >= 1);
            }
        }
        if let Some(pp) = &l.proxy_protocol {
            assert!(!pp.trusted().is_empty());
            assert!(pp.trusted().iter().all(|t| t.prefix() >= 1));
        }
    }
    let Some(t) = c.tls() else { return };
    assert!(!t.credentials().is_empty());
    for cr in t.credentials() {
        assert_eq!(cr.trust_anchor_id().is_some(), cr.kind() == aegis_config::CredentialKind::Mtc);
    }
    for l in c.listeners() {
        for cand in t.candidates(c, &l.name) {
            assert!(
                !(l.profile == aegis_config::Profile::PublicWeb && cand.kind() == aegis_config::CredentialKind::MlDsa)
            );
            assert!(!l.is_l4());
        }
    }
}

/// What every accepted config guarantees about P2: each wasm route names a declared module, and every effective
/// P2 limit (block, crash budget, per-module) is inside its F8 bounds.
fn p2_invariants(c: &Config) {
    for vh in c.vhosts() {
        for r in &vh.routes {
            if let RouteTarget::Wasm { module } = &r.to {
                assert!(c.p2().and_then(|b| b.module(module)).is_some(), "wasm route {module} without module");
            }
        }
    }
    let Some(b) = c.p2() else { return };
    for ((n, lo, hi, _), v) in P2Limits::BOUNDS.iter().zip(b.limits().values()) {
        assert!((*lo..=*hi).contains(&v), "{n}={v}");
    }
    for ((n, lo, hi, _), v) in CrashBudget::BOUNDS.iter().zip(b.crash_budget().values()) {
        assert!((*lo..=*hi).contains(&v), "{n}={v}");
    }
    assert!(!b.modules().is_empty());
    for m in b.modules() {
        assert!((P2Limits::FUEL_BOUNDS.0..=P2Limits::FUEL_BOUNDS.1).contains(&m.fuel()));
        assert!((P2Limits::WALL_MS_BOUNDS.0..=P2Limits::WALL_MS_BOUNDS.1).contains(&m.wall_ms()));
        assert!((P2Limits::MEMORY_MIB_BOUNDS.0..=P2Limits::MEMORY_MIB_BOUNDS.1).contains(&m.memory_mib()));
    }
}
