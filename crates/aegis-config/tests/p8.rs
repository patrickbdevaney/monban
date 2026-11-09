//! F8 Phase-8 additions (P8-spec-001, PLAN-8 Interfaces; gate config-totality): schema conformance against the frozen
//! schema file itself, "absent = today's behaviour" (same effective form and config_hash as a pre-Phase-8 config), and
//! an accept/reject corpus with the error kind and JSON pointer asserted for root `runtime` (R5), root `state` (R12)
//! and the load-time refusal of non-canonical route paths (R13).
//!
//! Mutant record (P8-spec-001, run on kamrui 2026-11-06 with both mutations applied together: 13 of 34 cases here
//! red, plus `totality_random_mutation` in store.rs and the two NotCanonical cases in schema.rs):
//! * drop the `is_canonical_route_path` check in `parse::route` -> every `path_*_refused` case and
//!   `every_accepted_route_path_is_a_canon_fixed_point` go red;
//! * widen `Runtime::BOUNDS` to 0..=1025 and `StateBlock::RETENTION_BOUNDS` to 59.. -> `runtime_and_state_mirror_f8`,
//!   `runtime_zero`, `runtime_over` and `retention_under` go red.
//!
//! Not run as a mutant: printing `runtime` when default or `state` when unset, which
//! `absent_blocks_keep_the_pre_phase8_hash` asserts against directly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use aegis_canon::{JsonValue, parse_json};
use aegis_config::ErrorKind as K;
use aegis_config::{Config, Runtime, StateBlock, parse_config};

const BASE: &str = r#"{"v":1,
 "listeners":[{"name":"web","bind":"0.0.0.0:443","profile":"P-PUBLIC-WEB","alpn":["h2","http/1.1"]}],
 "vhosts":[{"host":"example.com","routes":[{"id":1,"path":"/","to":{"upstream":"app","framing":"h2"},"authz":"api"}]}]}"#;

/// Append root members to BASE.
fn root(extra: &str) -> String {
    let b = BASE.strip_suffix('}').unwrap();
    format!("{b},{extra}}}")
}
fn rt(body: &str) -> String {
    root(&format!(r#""runtime":{{{body}}}"#))
}
fn st(body: &str) -> String {
    root(&format!(r#""state":{{{body}}}"#))
}
/// BASE with route 1's path replaced.
fn path(p: &str) -> String {
    assert!(BASE.contains(r#""path":"/""#));
    BASE.replacen(r#""path":"/""#, &format!(r#""path":"{p}""#), 1)
}

fn short(s: &str) -> &str {
    s.get(..s.len().min(600)).unwrap_or(s)
}
fn ok(s: &str) -> Config {
    match parse_config(s.as_bytes()) {
        Ok(c) => c,
        Err(e) => panic!("expected accept, got {e}\n{}", short(s)),
    }
}
fn rej(s: &str, kind: K, ptr: &str) {
    match parse_config(s.as_bytes()) {
        Ok(_) => panic!("expected reject {kind:?} at {ptr:?}\n{}", short(s)),
        Err(e) => assert_eq!((e.kind(), e.pointer()), (kind, ptr), "{e}\n{}", short(s)),
    }
}
fn eff(c: &Config) -> String {
    String::from_utf8(c.effective_json().to_vec()).unwrap()
}
/// Accepted, and the effective form re-parses to the same hash.
fn ok_rt(s: &str) -> Config {
    let c = ok(s);
    let again = parse_config(c.effective_json()).unwrap();
    assert_eq!(again.config_hash(), c.config_hash(), "effective form does not round-trip\n{}", eff(&c));
    assert_eq!(again.runtime(), c.runtime());
    assert_eq!(again.state(), c.state());
    c
}

macro_rules! accept {
    ($($name:ident: $doc:expr;)*) => { $( #[test] fn $name() { ok_rt(AsRef::<str>::as_ref(&$doc)); } )* };
}
macro_rules! reject {
    ($($name:ident: $doc:expr => $kind:ident @ $ptr:expr;)*) => {
        $( #[test] fn $name() { rej(AsRef::<str>::as_ref(&$doc), K::$kind, $ptr); } )*
    };
}

// ------------------------------------------------------------------------------------------------ schema mirror

fn schema() -> &'static JsonValue {
    static S: std::sync::OnceLock<JsonValue> = std::sync::OnceLock::new();
    S.get_or_init(|| parse_json(include_bytes!("../../../interfaces/F8-config.schema.json")).unwrap())
}
fn opt<'a>(v: &'a JsonValue, k: &str) -> Option<&'a JsonValue> {
    match v {
        JsonValue::Object(m) => m.iter().find(|(n, _)| n == k).map(|(_, v)| v),
        _ => panic!("not an object looking up {k}"),
    }
}
fn member<'a>(v: &'a JsonValue, k: &str) -> &'a JsonValue {
    opt(v, k).unwrap_or_else(|| panic!("no {k}"))
}
fn keys(v: &JsonValue) -> Vec<&str> {
    match v {
        JsonValue::Object(m) => m.iter().map(|(n, _)| n.as_str()).collect(),
        _ => panic!("not an object"),
    }
}
fn int(v: &JsonValue) -> u64 {
    match v {
        JsonValue::Int(n) => u64::try_from(*n).unwrap(),
        _ => panic!("not an integer"),
    }
}
fn def(name: &str) -> &'static JsonValue {
    member(member(schema(), "$defs"), name)
}

#[test]
fn runtime_and_state_mirror_f8() {
    let props = keys(member(schema(), "properties"));
    assert_eq!(props.iter().rev().take(2).collect::<Vec<_>>(), [&"state", &"runtime"]);
    for d in ["runtime", "state"] {
        assert_eq!(member(def(d), "additionalProperties"), &JsonValue::Bool(false), "{d} must be closed");
        assert!(opt(def(d), "required").is_none(), "{d} has no required member");
    }
    // runtime: every member bounded and defaulted, exactly Runtime::BOUNDS.
    let rp = member(def("runtime"), "properties");
    let names: Vec<&str> = Runtime::BOUNDS.iter().map(|(n, ..)| *n).collect();
    assert_eq!(keys(rp), names);
    for (n, lo, hi, d) in Runtime::BOUNDS {
        let m = member(rp, n);
        assert_eq!(member(m, "type"), &JsonValue::String("integer".into()));
        assert_eq!((int(member(m, "minimum")), int(member(m, "maximum")), int(member(m, "default"))), (*lo, *hi, *d));
    }
    assert_eq!(Runtime::default().values(), Runtime::BOUNDS.iter().map(|b| b.3).collect::<Vec<_>>());
    // state: bounded, and deliberately WITHOUT a default (absent = never expire).
    let sp = member(def("state"), "properties");
    assert_eq!(keys(sp), StateBlock::MEMBERS);
    let r = member(sp, "idempotency_retention_s");
    assert_eq!(member(r, "type"), &JsonValue::String("integer".into()));
    assert_eq!((int(member(r, "minimum")), int(member(r, "maximum"))), StateBlock::RETENTION_BOUNDS);
    assert!(opt(r, "default").is_none(), "idempotency_retention_s must have no default");
    // The route path member documents the canonical-path refusal (R13).
    let p = member(member(def("route"), "properties"), "path");
    let JsonValue::String(desc) = member(p, "description") else { panic!("path description") };
    assert!(desc.contains("canon_path") && desc.contains("NotCanonical"));
}

// ------------------------------------------------------------------------------------------------ absent = today

#[test]
fn absent_blocks_keep_the_pre_phase8_hash() {
    let base = ok(BASE);
    assert_eq!(base.runtime(), &Runtime { worker_threads: 2 });
    assert_eq!(base.state().idempotency_retention_s, None);
    let e = eff(&base);
    assert!(!e.contains("runtime") && !e.contains("state"), "{e}");
    // Explicit defaults and empty blocks mean (and hash) the same as absent.
    for doc in [rt(""), rt(r#""worker_threads":2"#), st(""), root(r#""runtime":{},"state":{}"#)] {
        let c = ok_rt(&doc);
        assert_eq!(c.config_hash(), base.config_hash(), "{doc}");
        assert_eq!(c.effective_json(), base.effective_json());
    }
    // A non-default value is a different config.
    let c = ok_rt(&rt(r#""worker_threads":12"#));
    assert_ne!(c.config_hash(), base.config_hash());
    assert!(eff(&c).contains(r#""runtime":{"worker_threads":12}"#), "{}", eff(&c));
    let c = ok_rt(&st(r#""idempotency_retention_s":86400"#));
    assert_ne!(c.config_hash(), base.config_hash());
    assert!(eff(&c).contains(r#""state":{"idempotency_retention_s":86400}"#), "{}", eff(&c));
    // The dump always shows the runtime block (operators see the effective worker count) but not unset state.
    let d = String::from_utf8(base.effective_dump(4)).unwrap();
    assert!(d.contains(r#""runtime":{"worker_threads":2}"#) && !d.contains("\"state\""), "{d}");
}

#[test]
fn typed_values() {
    assert_eq!(ok(&rt(r#""worker_threads":1"#)).runtime().worker_threads, 1);
    assert_eq!(ok(&rt(r#""worker_threads":1024"#)).runtime().worker_threads, 1024);
    assert_eq!(ok(&rt(r#""worker_threads":8.0"#)).runtime().worker_threads, 8);
    assert_eq!(ok(&st(r#""idempotency_retention_s":60"#)).state().idempotency_retention_s, Some(60));
    assert_eq!(ok(&st(r#""idempotency_retention_s":2592000"#)).state().idempotency_retention_s, Some(2_592_000));
}

accept! {
    runtime_min: rt(r#""worker_threads":1"#);
    runtime_max: rt(r#""worker_threads":1024"#);
    retention_min: st(r#""idempotency_retention_s":60"#);
    retention_max: st(r#""idempotency_retention_s":2592000"#);
    both_blocks: root(r#""runtime":{"worker_threads":4},"state":{"idempotency_retention_s":3600}"#);
    path_trailing_slash_kept: path("/a/b/");
    path_dots_inside_segments: path("/a.b/..c/c../.d/...");
    path_sub_delims: path("/ab=c/@x:y/~u_v-w!$&'()*+,");
}

reject! {
    // Oracle (unit spec): worker_threads 0 / 1025 refused; retention 59 refused.
    runtime_zero: rt(r#""worker_threads":0"#) => Minimum @ "/runtime/worker_threads";
    runtime_over: rt(r#""worker_threads":1025"#) => Maximum @ "/runtime/worker_threads";
    runtime_fraction: rt(r#""worker_threads":2.5"#) => Type @ "/runtime/worker_threads";
    runtime_string: rt(r#""worker_threads":"2""#) => Type @ "/runtime/worker_threads";
    runtime_negative: rt(r#""worker_threads":-1"#) => Minimum @ "/runtime/worker_threads";
    runtime_unknown: rt(r#""threads":2"#) => UnknownField @ "/runtime/threads";
    runtime_not_object: root(r#""runtime":2"#) => Type @ "/runtime";
    retention_under: st(r#""idempotency_retention_s":59"#) => Minimum @ "/state/idempotency_retention_s";
    retention_over: st(r#""idempotency_retention_s":2592001"#) => Maximum @ "/state/idempotency_retention_s";
    retention_zero: st(r#""idempotency_retention_s":0"#) => Minimum @ "/state/idempotency_retention_s";
    retention_null: st(r#""idempotency_retention_s":null"#) => Type @ "/state/idempotency_retention_s";
    state_unknown: st(r#""retention_s":60"#) => UnknownField @ "/state/retention_s";
    state_not_object: root(r#""state":[]"#) => Type @ "/state";
    // Oracle (unit spec): a route path '/a/../b' is refused at load (R13).
    path_dot_dot_refused: path("/a/../b") => NotCanonical @ "/vhosts/0/routes/0/path";
    path_dot_refused: path("/a/./b") => NotCanonical @ "/vhosts/0/routes/0/path";
    path_trailing_dot_dot_refused: path("/a/..") => NotCanonical @ "/vhosts/0/routes/0/path";
    path_lone_dot_refused: path("/.") => NotCanonical @ "/vhosts/0/routes/0/path";
    // ';' matches the F8 pattern, but CANON-2 forbids it literally in a path (no path parameters): dead route.
    path_semicolon_refused: path("/a;b") => NotCanonical @ "/vhosts/0/routes/0/path";
    path_empty_segment_refused: path("/a//b") => NotCanonical @ "/vhosts/0/routes/0/path";
    path_leading_double_slash_refused: path("//a") => NotCanonical @ "/vhosts/0/routes/0/path";
    // The pattern still answers first for characters it never allows.
    path_percent_is_pattern: path("/a%2e%2e/b") => Pattern @ "/vhosts/0/routes/0/path";
}

#[test]
fn path_over_canon_length_cap_refused() {
    // CANON-2 answers 414 above its path cap; such a route could never match either.
    let long = format!("/{}", "a".repeat(64 * 1024));
    rej(&path(&long), K::NotCanonical, "/vhosts/0/routes/0/path");
}

#[test]
fn every_accepted_route_path_is_a_canon_fixed_point() {
    // Exhaustive over short paths from a dot/slash-heavy alphabet: load accepts exactly the canon_path fixed points
    // among pattern-valid strings.
    let alpha = ['/', '.', 'a'];
    let mut frontier = vec![String::from("/")];
    let (mut accepted, mut refused) = (0, 0);
    for _ in 0..7 {
        let mut next = Vec::new();
        for p in &frontier {
            let fixed = matches!(aegis_canon::canon_path(p.as_bytes()), Ok(c) if c.as_bytes() == p.as_bytes());
            match parse_config(path(p).as_bytes()) {
                Ok(c) => {
                    assert!(fixed, "{p:?} accepted but not canonical");
                    assert_eq!(c.vhosts()[0].routes[0].path, *p);
                    accepted += 1;
                }
                Err(e) => {
                    assert!(!fixed, "{p:?} canonical but refused: {e}");
                    assert_eq!((e.kind(), e.pointer()), (K::NotCanonical, "/vhosts/0/routes/0/path"));
                    refused += 1;
                }
            }
            for c in alpha {
                next.push(format!("{p}{c}"));
            }
        }
        frontier = next;
    }
    assert!(accepted > 100 && refused > 100, "{accepted} accepted, {refused} refused");
}
