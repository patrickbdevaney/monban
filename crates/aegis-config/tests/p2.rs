//! F8 `p2` block and the `{"wasm": id}` route target (P5-config-001): schema conformance against the frozen
//! schema file itself (member sets, bounds, defaults, enums, required lists), every limit at its bounds and one
//! past them, the D1/D6/D7/D11 defaults, the cross-field checks (unique module ids, wasm routes name a declared
//! module) and "a cordon shared by principals is unrepresentable".
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use aegis_canon::{JsonValue, parse_json};
use aegis_config::ErrorKind as K;
use aegis_config::{
    Config, CrashBudget, Isolation, MAX_P2_MODULES, P2Block, P2Limits, P2Module, RouteTarget, Tenancy, parse_config,
};

const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const BASE: &str = r#"{"v":1,
 "listeners":[{"name":"web","bind":"127.0.0.1:8443","profile":"P-PUBLIC-WEB"}],
 "vhosts":[{"host":"localhost","routes":[
   {"id":1,"path":"/w","to":{"wasm":"hello"},"authz":"w"},
   {"id":2,"path":"/s","to":{"wasm":"solo"},"authz":"s"},
   {"id":3,"path":"/","to":{"static":"/srv"}}]}],
 "p2":{"worker":"/usr/libexec/aegis-p2","modules":[
   {"id":"hello","path":"/srv/p2/hello.wasm","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
   {"id":"solo","path":"/srv/p2/solo.wasm","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","tenancy":"single"}]}}"#;

const WORKER: &str = r#""worker":"/usr/libexec/aegis-p2""#;
const MOD0: &str = r#"{"id":"hello","path":"/srv/p2/hello.wasm","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#;
const TO0: &str = r#"{"wasm":"hello"}"#;
const ROUTE0: &str = r#"{"id":1,"path":"/w","to":{"wasm":"hello"},"authz":"w"}"#;

fn with(from: &str, to: &str) -> String {
    assert!(BASE.contains(from), "base lacks {from}");
    BASE.replacen(from, to, 1)
}
/// Add members to the `p2` object (after `worker`).
fn p2(extra: &str) -> String {
    with(WORKER, &format!("{WORKER},{extra}"))
}
/// Add members to the first module.
fn module(extra: &str) -> String {
    with(MOD0, &format!("{},{extra}}}", MOD0.strip_suffix('}').unwrap()))
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
fn block(c: &Config) -> &P2Block {
    c.p2().expect("p2 block")
}

macro_rules! reject {
    ($($name:ident: $doc:expr => $kind:ident @ $ptr:expr;)*) => {
        $( #[test] fn $name() { rej(AsRef::<str>::as_ref(&$doc), K::$kind, $ptr); } )*
    };
}

// ------------------------------------------------------------------------------------------------ schema mirror

fn schema() -> JsonValue {
    parse_json(include_bytes!("../../../interfaces/F8-config.schema.json")).unwrap()
}
fn member<'a>(v: &'a JsonValue, k: &str) -> &'a JsonValue {
    match v {
        JsonValue::Object(m) => m.iter().find(|(n, _)| n == k).map(|(_, v)| v).unwrap_or_else(|| panic!("no {k}")),
        _ => panic!("not an object looking up {k}"),
    }
}
fn opt<'a>(v: &'a JsonValue, k: &str) -> Option<&'a JsonValue> {
    match v {
        JsonValue::Object(m) => m.iter().find(|(n, _)| n == k).map(|(_, v)| v),
        _ => None,
    }
}
fn keys(v: &JsonValue) -> Vec<&str> {
    match v {
        JsonValue::Object(m) => m.iter().map(|(n, _)| n.as_str()).collect(),
        _ => panic!("not an object"),
    }
}
fn strs(v: &JsonValue) -> Vec<&str> {
    match v {
        JsonValue::Array(a) => a
            .iter()
            .map(|x| match x {
                JsonValue::String(s) => s.as_str(),
                _ => panic!("not a string"),
            })
            .collect(),
        _ => panic!("not an array"),
    }
}
fn int(v: &JsonValue) -> u64 {
    match v {
        JsonValue::Int(n) => u64::try_from(*n).unwrap(),
        _ => panic!("not an integer"),
    }
}
fn def(name: &str) -> &'static JsonValue {
    static S: std::sync::OnceLock<JsonValue> = std::sync::OnceLock::new();
    member(member(S.get_or_init(schema), "$defs"), name)
}
/// (name, minimum, maximum, default) of every integer property of a schema object, in schema order.
fn int_bounds(obj: &JsonValue) -> Vec<(String, u64, u64, Option<u64>)> {
    let props = member(obj, "properties");
    keys(props)
        .into_iter()
        .filter_map(|k| {
            let p = member(props, k);
            match opt(p, "type") {
                Some(JsonValue::String(t)) if t == "integer" => Some((
                    k.to_owned(),
                    int(member(p, "minimum")),
                    int(member(p, "maximum")),
                    opt(p, "default").map(int),
                )),
                _ => None,
            }
        })
        .collect()
}
fn table(b: &[(&str, u64, u64, u64)]) -> Vec<(String, u64, u64, Option<u64>)> {
    b.iter().map(|(n, lo, hi, d)| ((*n).to_owned(), *lo, *hi, Some(*d))).collect()
}

#[test]
fn p2_block_mirrors_f8_exactly() {
    let s = schema();
    assert_eq!(member(member(&s, "properties"), "p2"), &parse_json(br##"{"$ref":"#/$defs/p2"}"##).unwrap());
    let p2 = def("p2");
    assert_eq!(member(p2, "additionalProperties"), &JsonValue::Bool(false));
    assert_eq!(keys(member(p2, "properties")), P2Block::MEMBERS);
    assert_eq!(strs(member(p2, "required")), ["worker", "modules"]);
    assert_eq!(int_bounds(p2), table(P2Limits::BOUNDS));
    let props = member(p2, "properties");
    assert_eq!(strs(member(member(props, "isolation"), "enum")), ["forkwasm", "cordon"]);
    assert_eq!(member(member(props, "isolation"), "default"), &JsonValue::String("forkwasm".into()));
    assert_eq!(member(member(props, "mpk"), "default"), &JsonValue::Bool(false));
    assert_eq!(int(member(member(props, "modules"), "maxItems")), MAX_P2_MODULES as u64);
    assert_eq!(int(member(member(props, "modules"), "minItems")), 1);
    for k in ["worker", "cache_dir"] {
        assert_eq!(member(member(props, k), "pattern"), &JsonValue::String("^/[A-Za-z0-9._/-]{1,255}$".into()), "{k}");
    }

    let cb = def("p2_crash_budget");
    assert_eq!(member(cb, "additionalProperties"), &JsonValue::Bool(false));
    assert!(opt(cb, "required").is_none());
    assert_eq!(keys(member(cb, "properties")), ["crashes", "window_s", "penalty_s"]);
    assert_eq!(int_bounds(cb), table(CrashBudget::BOUNDS));

    let m = def("p2_module");
    assert_eq!(member(m, "additionalProperties"), &JsonValue::Bool(false));
    assert_eq!(keys(member(m, "properties")), P2Module::MEMBERS);
    assert_eq!(strs(member(m, "required")), ["id", "path", "sha256"]);
    let mp = member(m, "properties");
    assert_eq!(strs(member(member(mp, "tenancy"), "enum")), ["multi", "single"]);
    assert_eq!(member(member(mp, "tenancy"), "default"), &JsonValue::String("multi".into()));
    assert_eq!(member(member(mp, "id"), "pattern"), &JsonValue::String("^[a-z][a-z0-9-]{0,31}$".into()));
    assert_eq!(member(member(mp, "path"), "pattern"), &JsonValue::String("^/[A-Za-z0-9._/-]{1,250}\\.wasm$".into()));
    assert_eq!(member(member(mp, "sha256"), "pattern"), &JsonValue::String("^[0-9a-f]{64}$".into()));
    // Overrides: same bounds as the block, no default (absent = the block's value).
    let over = int_bounds(m);
    assert_eq!(
        over,
        vec![
            ("fuel".to_owned(), P2Limits::FUEL_BOUNDS.0, P2Limits::FUEL_BOUNDS.1, None),
            ("wall_ms".to_owned(), P2Limits::WALL_MS_BOUNDS.0, P2Limits::WALL_MS_BOUNDS.1, None),
            ("memory_mib".to_owned(), P2Limits::MEMORY_MIB_BOUNDS.0, P2Limits::MEMORY_MIB_BOUNDS.1, None),
        ]
    );
    for (n, lo, hi, _) in &over {
        let b = P2Limits::BOUNDS.iter().find(|(bn, ..)| bn == n).unwrap();
        assert_eq!((b.1, b.2), (*lo, *hi), "{n}: override bounds equal the block's");
    }

    // Route target: the third oneOf branch is exactly {"wasm": id}.
    let to = member(member(def("route"), "properties"), "to");
    let JsonValue::Array(branches) = member(to, "oneOf") else { panic!("oneOf") };
    assert_eq!(branches.len(), 3);
    let w = &branches[2];
    assert_eq!(member(w, "additionalProperties"), &JsonValue::Bool(false));
    assert_eq!(strs(member(w, "required")), ["wasm"]);
    assert_eq!(keys(member(w, "properties")), ["wasm"]);
    assert_eq!(
        member(member(member(w, "properties"), "wasm"), "pattern"),
        &JsonValue::String("^[a-z][a-z0-9-]{0,31}$".into())
    );
    // The root accepts `p2`.
    assert!(keys(member(&s, "properties")).contains(&"p2"));
}

// ------------------------------------------------------------------------------------------------ defaults

#[test]
fn defaults_d1_d6_d7_d11() {
    let c = ok(BASE);
    let b = block(&c);
    assert_eq!(b.worker(), "/usr/libexec/aegis-p2");
    assert_eq!(b.cache_dir(), None);
    assert_eq!(b.isolation(), Isolation::ForkWasm);
    assert_eq!(b.limits(), &P2Limits::default());
    assert_eq!(b.limits().fuel, 15_000_000);
    assert_eq!(b.limits().wall_ms, 100);
    assert_eq!(b.limits().memory_mib, 16);
    assert_eq!(b.limits().cordon_slots, 64);
    assert_eq!((b.crash_budget().crashes, b.crash_budget().window_s, b.crash_budget().penalty_s), (3, 60, 600));
    assert!(!b.mpk());
    let hello = b.module("hello").unwrap();
    assert_eq!(hello.tenancy(), Tenancy::Multi);
    assert_eq!((hello.fuel(), hello.wall_ms(), hello.memory_mib()), (15_000_000, 100, 16));
    assert_eq!(hello.sha256_hex(), SHA);
    assert_eq!(hello.sha256()[0], 0x01);
    assert_eq!(hello.path(), "/srv/p2/hello.wasm");
    // D1: multi-principal modules default to fork+Wasm; single-tenant always a per-principal cordon.
    assert_eq!(b.isolation_for(hello), Isolation::ForkWasm);
    let solo = b.module("solo").unwrap();
    assert_eq!(solo.tenancy(), Tenancy::Single);
    assert_eq!(b.isolation_for(solo), Isolation::Cordon);
    assert!(b.module("nope").is_none());
    assert_eq!(c.vhosts()[0].routes[0].to, RouteTarget::Wasm { module: "hello".into() });
}

#[test]
fn isolation_switch_is_a_config_change() {
    let a = ok(BASE);
    let c = ok(&p2(r#""isolation":"cordon""#));
    let b = block(&c);
    assert_eq!(b.isolation(), Isolation::Cordon);
    assert_eq!(b.isolation_for(b.module("hello").unwrap()), Isolation::Cordon);
    assert_eq!(b.isolation_for(b.module("solo").unwrap()), Isolation::Cordon);
    assert_ne!(a.config_hash(), c.config_hash());
    // Explicit default == absent.
    assert_eq!(a.config_hash(), ok(&p2(r#""isolation":"forkwasm""#)).config_hash());
}

#[test]
fn module_overrides_resolve_and_absent_equals_explicit_block_value() {
    let c = ok(&module(r#""fuel":20000,"wall_ms":5,"memory_mib":64"#));
    let m = block(&c).module("hello").unwrap();
    assert_eq!((m.fuel(), m.wall_ms(), m.memory_mib()), (20_000, 5, 64));
    // A block-level change flows to modules without an override.
    let c2 = ok(&p2(r#""fuel":30000,"wall_ms":7,"memory_mib":2"#));
    let m2 = block(&c2).module("hello").unwrap();
    assert_eq!((m2.fuel(), m2.wall_ms(), m2.memory_mib()), (30_000, 7, 2));
    // Absent override and an explicit override equal to the block value mean the same and hash the same.
    let a = ok(BASE);
    let b = ok(&module(r#""fuel":15000000,"wall_ms":100,"memory_mib":16,"tenancy":"multi""#));
    assert_eq!(a.config_hash(), b.config_hash());
}

#[test]
fn effective_json_prints_p2_with_every_default_and_round_trips() {
    let c = ok(BASE);
    let e = std::str::from_utf8(c.effective_json()).unwrap();
    assert_eq!(aegis_canon::canon_json(e.as_bytes()).unwrap().as_bytes(), c.effective_json());
    for needle in [
        r#""to":{"wasm":"hello"}"#,
        r#""crash_budget":{"crashes":3,"penalty_s":600,"window_s":60}"#,
        r#""fuel":15000000"#,
        r#""isolation":"forkwasm""#,
        r#""memory_mib":16"#,
        r#""mpk":false"#,
        r#""wall_ms":100"#,
        r#""tenancy":"single""#,
        r#""cordon_slots":64"#,
        r#""frame_max_bytes":65536"#,
    ] {
        assert!(e.contains(needle), "{needle} missing in {e}");
    }
    assert!(!e.contains("cache_dir"), "absent cache_dir has no default and is omitted");
    let again = ok(e);
    assert_eq!(again, c);
    assert_eq!(again.config_hash(), c.config_hash());
    // cache_dir round-trips when present.
    let d = ok(&p2(r#""cache_dir":"/run/aegis/p2""#));
    assert_eq!(block(&d).cache_dir(), Some("/run/aegis/p2"));
    assert_eq!(ok(std::str::from_utf8(d.effective_json()).unwrap()), d);
}

#[test]
fn absent_p2_is_omitted_and_wasm_free_configs_unchanged() {
    let doc = BASE
        .replace(r#""to":{"wasm":"hello"}"#, r#""to":{"upstream":"u"}"#)
        .replace(r#""to":{"wasm":"solo"}"#, r#""to":{"upstream":"u"}"#);
    let cut = doc.find(",\n \"p2\"").unwrap();
    let doc = format!("{}}}", &doc[..cut]);
    let c = ok(&doc);
    assert!(c.p2().is_none());
    assert!(!std::str::from_utf8(c.effective_json()).unwrap().contains("p2"));
}

// ------------------------------------------------------------------------------------------------ limits at bounds

#[test]
fn every_p2_limit_at_bounds_accepted_and_one_past_rejected() {
    for (n, lo, hi, d) in P2Limits::BOUNDS {
        assert!(lo <= d && d <= hi && *hi < u64::MAX, "{n} bounded with default inside");
        let get = |c: &Config| block(c).limits().values()[P2Limits::BOUNDS.iter().position(|b| b.0 == *n).unwrap()];
        assert_eq!(get(&ok(&p2(&format!(r#""{n}":{lo}"#)))), *lo, "{n} min");
        assert_eq!(get(&ok(&p2(&format!(r#""{n}":{hi}"#)))), *hi, "{n} max");
        rej(&p2(&format!(r#""{n}":{}"#, hi + 1)), K::Maximum, &format!("/p2/{n}"));
        if *lo > 0 {
            rej(&p2(&format!(r#""{n}":{}"#, lo - 1)), K::Minimum, &format!("/p2/{n}"));
        }
        rej(&p2(&format!(r#""{n}":-1"#)), K::Minimum, &format!("/p2/{n}"));
        rej(&p2(&format!(r#""{n}":"{d}""#)), K::Type, &format!("/p2/{n}"));
        rej(&p2(&format!(r#""{n}":null"#)), K::Type, &format!("/p2/{n}"));
        rej(&p2(&format!(r#""{n}":{lo}.5"#)), K::Type, &format!("/p2/{n}"));
        rej(&p2(&format!(r#""{n}":1e300"#)), K::Maximum, &format!("/p2/{n}"));
    }
}

#[test]
fn every_crash_budget_knob_at_bounds_accepted_and_one_past_rejected() {
    for (i, (n, lo, hi, _)) in CrashBudget::BOUNDS.iter().enumerate() {
        let doc = |v: &str| p2(&format!(r#""crash_budget":{{"{n}":{v}}}"#));
        assert_eq!(block(&ok(&doc(&lo.to_string()))).crash_budget().values()[i], *lo, "{n} min");
        assert_eq!(block(&ok(&doc(&hi.to_string()))).crash_budget().values()[i], *hi, "{n} max");
        rej(&doc(&(hi + 1).to_string()), K::Maximum, &format!("/p2/crash_budget/{n}"));
        rej(&doc(&(lo - 1).to_string()), K::Minimum, &format!("/p2/crash_budget/{n}"));
        rej(&doc("true"), K::Type, &format!("/p2/crash_budget/{n}"));
    }
    // Bounded minimums let a gate scale the window and penalty down (D7).
    let c = ok(&p2(r#""crash_budget":{"crashes":1,"window_s":1,"penalty_s":1}"#));
    assert_eq!(block(&c).crash_budget(), &CrashBudget { crashes: 1, window_s: 1, penalty_s: 1 });
}

#[test]
fn every_module_override_at_bounds_accepted_and_one_past_rejected() {
    for (n, (lo, hi)) in [
        ("fuel", P2Limits::FUEL_BOUNDS),
        ("wall_ms", P2Limits::WALL_MS_BOUNDS),
        ("memory_mib", P2Limits::MEMORY_MIB_BOUNDS),
    ] {
        ok(&module(&format!(r#""{n}":{lo}"#)));
        ok(&module(&format!(r#""{n}":{hi}"#)));
        rej(&module(&format!(r#""{n}":{}"#, hi + 1)), K::Maximum, &format!("/p2/modules/0/{n}"));
        rej(&module(&format!(r#""{n}":{}"#, lo - 1)), K::Minimum, &format!("/p2/modules/0/{n}"));
        rej(&module(&format!(r#""{n}":"1""#)), K::Type, &format!("/p2/modules/0/{n}"));
    }
}

// ------------------------------------------------------------------------------------------------ shared cordon

#[test]
fn shared_cordon_is_unrepresentable() {
    // No member of any p2 object can key, name, share or merge a cordon: the only members mentioning a cordon
    // are the three bounded integers (pool slots, live-cordon cap, idle reap), which count, never key.
    for k in P2Block::MEMBERS.iter().chain(P2Module::MEMBERS).chain(&["crashes", "window_s", "penalty_s"]) {
        let hit = ["cordon", "share", "principal", "tenant_key", "key", "group", "pool"].iter().any(|w| k.contains(w));
        if hit {
            assert!(
                ["cordon_slots", "max_cordons", "cordon_idle_s"].contains(k)
                    && P2Limits::BOUNDS.iter().any(|(n, ..)| n == k),
                "{k} could express a cordon identity"
            );
        }
    }
    // Every attempt to express one is an unknown field at the place it is written.
    let attempts = [
        r#""cordon":"shared""#,
        r#""cordon_key":"all""#,
        r#""cordon_id":1"#,
        r#""shared_cordon":true"#,
        r#""share_cordon":true"#,
        r#""cordons":[{"principals":["a","b"]}]"#,
        r#""principals":["a","b"]"#,
        r#""key":"route""#,
    ];
    for a in attempts {
        let k = a.split('"').nth(1).unwrap();
        rej(&p2(a), K::UnknownField, &format!("/p2/{k}"));
        rej(&module(a), K::UnknownField, &format!("/p2/modules/0/{k}"));
        rej(&p2(&format!(r#""crash_budget":{{{a}}}"#)), K::UnknownField, &format!("/p2/crash_budget/{k}"));
        rej(
            &with(ROUTE0, &format!(r#"{{"id":1,"path":"/w","to":{{"wasm":"hello"}},"authz":"w",{a}}}"#)),
            K::UnknownField,
            &format!("/vhosts/0/routes/0/{k}"),
        );
        // In the target object: no branch matches, and the object names `wasm` only, so the wasm branch's error.
        rej(&with(TO0, &format!(r#"{{"wasm":"hello",{a}}}"#)), K::UnknownField, &format!("/vhosts/0/routes/0/to/{k}"));
        rej(&with(r#"{"v":1,"#, &format!(r#"{{"v":1,{a},"#)), K::UnknownField, &format!("/{k}"));
    }
    // "single" tenancy is a per-principal cordon, never a shared one; there is no tenancy value that shares.
    rej(&module(r#""tenancy":"shared""#), K::Enum, "/p2/modules/0/tenancy");
    rej(&p2(r#""isolation":"shared-cordon""#), K::Enum, "/p2/isolation");
}

// ------------------------------------------------------------------------------------------------ cross-field

reject! {
    wasm_unknown_module: with(TO0, r#"{"wasm":"nope"}"#) => UnknownModule @ "/vhosts/0/routes/0/to/wasm";
    wasm_without_p2_block: {
        let d = BASE.to_owned();
        let cut = d.find(",\n \"p2\"").unwrap();
        format!("{}}}", &d[..cut])
    } => UnknownModule @ "/vhosts/0/routes/0/to/wasm";
    duplicate_module_id: with(r#""id":"solo""#, r#""id":"hello""#) => DuplicateModule @ "/p2/modules/1/id";
}

// ------------------------------------------------------------------------------------------------ schema rejects

reject! {
    p2_not_object: with(&BASE[BASE.find("{\"worker\"").unwrap()..BASE.len() - 1], "[]") => Type @ "/p2";
    p2_missing_worker: with(&format!("{WORKER},"), "") => MissingField @ "/p2/worker";
    p2_missing_modules: {
        let d = BASE.to_owned();
        let a = d.find(",\"modules\"").unwrap();
        format!("{}}}}}", &d[..a])
    } => MissingField @ "/p2/modules";
    p2_unknown_field: p2(r#""fuel_max":1"#) => UnknownField @ "/p2/fuel_max";
    worker_relative: with(WORKER, r#""worker":"aegis-p2""#) => Pattern @ "/p2/worker";
    worker_root_only: with(WORKER, r#""worker":"/""#) => Pattern @ "/p2/worker";
    worker_space: with(WORKER, r#""worker":"/usr/bin/aegis p2""#) => Pattern @ "/p2/worker";
    worker_too_long: with(WORKER, &format!(r#""worker":"/{}""#, "a".repeat(256))) => Pattern @ "/p2/worker";
    worker_not_string: with(WORKER, r#""worker":1"#) => Type @ "/p2/worker";
    cache_dir_relative: p2(r#""cache_dir":"run/p2""#) => Pattern @ "/p2/cache_dir";
    isolation_enum: p2(r#""isolation":"fork""#) => Enum @ "/p2/isolation";
    isolation_case: p2(r#""isolation":"ForkWasm""#) => Enum @ "/p2/isolation";
    mpk_string: p2(r#""mpk":"true""#) => Type @ "/p2/mpk";
    mpk_int: p2(r#""mpk":1"#) => Type @ "/p2/mpk";
    crash_budget_not_object: p2(r#""crash_budget":3"#) => Type @ "/p2/crash_budget";
    crash_budget_unknown: p2(r#""crash_budget":{"burst":3}"#) => UnknownField @ "/p2/crash_budget/burst";
    modules_empty: {
        let d = BASE.to_owned();
        let a = d.find("\"modules\":[").unwrap() + "\"modules\":[".len();
        format!("{}]}}}}", &d[..a])
    } => MinItems @ "/p2/modules";
    modules_not_array: {
        let d = BASE.to_owned();
        let a = d.find("\"modules\":[").unwrap() + "\"modules\":".len();
        format!("{}{{}}}}}}", &d[..a])
    } => Type @ "/p2/modules";
    module_unknown_field: module(r#""imports":[]"#) => UnknownField @ "/p2/modules/0/imports";
    module_missing_sha: with(&format!(r#","sha256":"{SHA}"}}"#), "}") => MissingField @ "/p2/modules/0/sha256";
    module_missing_path: with(r#""path":"/srv/p2/hello.wasm","#, "") => MissingField @ "/p2/modules/0/path";
    module_missing_id: with(r#""id":"hello","#, "") => MissingField @ "/p2/modules/0/id";
    module_id_pattern: with(r#""id":"hello""#, r#""id":"Hello""#) => Pattern @ "/p2/modules/0/id";
    module_id_too_long: with(r#""id":"hello""#, &format!(r#""id":"a{}""#, "b".repeat(32))) => Pattern @ "/p2/modules/0/id";
    module_path_not_wasm: with("/srv/p2/hello.wasm", "/srv/p2/hello.cwasm") => Pattern @ "/p2/modules/0/path";
    module_path_relative: with("/srv/p2/hello.wasm", "srv/hello.wasm") => Pattern @ "/p2/modules/0/path";
    module_path_bare_ext: with("/srv/p2/hello.wasm", "/.wasm") => Pattern @ "/p2/modules/0/path";
    module_path_space: with("/srv/p2/hello.wasm", "/srv/p2/he llo.wasm") => Pattern @ "/p2/modules/0/path";
    module_path_too_long: with("/srv/p2/hello.wasm", &format!("/{}.wasm", "a".repeat(251))) => Pattern @ "/p2/modules/0/path";
    module_sha_upper: with(&format!(r#""sha256":"{SHA}""#), &format!(r#""sha256":"{}""#, SHA.to_uppercase())) => Pattern @ "/p2/modules/0/sha256";
    module_sha_short: with(&format!(r#""sha256":"{SHA}""#), &format!(r#""sha256":"{}""#, &SHA[1..])) => Pattern @ "/p2/modules/0/sha256";
    module_sha_long: with(&format!(r#""sha256":"{SHA}""#), &format!(r#""sha256":"{SHA}0""#)) => Pattern @ "/p2/modules/0/sha256";
    module_sha_nonhex: with(&format!(r#""sha256":"{SHA}""#), &format!(r#""sha256":"g{}""#, &SHA[1..])) => Pattern @ "/p2/modules/0/sha256";
    module_tenancy_enum: module(r#""tenancy":"both""#) => Enum @ "/p2/modules/0/tenancy";
    target_wasm_pattern: with(TO0, r#"{"wasm":"Hello"}"#) => Pattern @ "/vhosts/0/routes/0/to/wasm";
    target_wasm_prefix_form: with(TO0, r#"{"wasm":"wasm:hello"}"#) => Pattern @ "/vhosts/0/routes/0/to/wasm";
    target_wasm_type: with(TO0, r#"{"wasm":1}"#) => Type @ "/vhosts/0/routes/0/to/wasm";
    target_wasm_and_upstream: with(TO0, r#"{"wasm":"hello","upstream":"u"}"#) => OneOf @ "/vhosts/0/routes/0/to";
    target_wasm_and_static: with(TO0, r#"{"wasm":"hello","static":"/s"}"#) => OneOf @ "/vhosts/0/routes/0/to";
    target_wasm_string_form: with(TO0, r#""wasm:hello""#) => OneOf @ "/vhosts/0/routes/0/to";
}

#[test]
fn module_path_at_length_bound_accepted() {
    let p = format!("/{}.wasm", "a".repeat(250));
    let c = ok(&with("/srv/p2/hello.wasm", &p));
    assert_eq!(block(&c).module("hello").unwrap().path(), p);
    ok(&with(WORKER, &format!(r#""worker":"/{}""#, "a".repeat(255))));
}

#[test]
fn modules_count_bounds() {
    let mods: Vec<String> =
        (0..MAX_P2_MODULES).map(|i| format!(r#"{{"id":"m{i}","path":"/m/{i}.wasm","sha256":"{SHA}"}}"#)).collect();
    let start = BASE.find("\"modules\":[").unwrap();
    let doc = |n: usize| format!("{}\"modules\":[{}]}}}}", &BASE[..start], mods[..n].join(","));
    // Routes name hello/solo: replace them with m0 for the count test.
    let fix = |s: String| {
        s.replace(r#"{"wasm":"hello"}"#, r#"{"wasm":"m0"}"#).replace(r#"{"wasm":"solo"}"#, r#"{"wasm":"m1"}"#)
    };
    let c = ok(&fix(doc(MAX_P2_MODULES)));
    assert_eq!(block(&c).modules().len(), MAX_P2_MODULES);
    let mut over = mods.clone();
    over.push(format!(r#"{{"id":"mx","path":"/m/x.wasm","sha256":"{SHA}"}}"#));
    let d = format!("{}\"modules\":[{}]}}}}", &BASE[..start], over.join(","));
    rej(&fix(d), K::MaxItems, "/p2/modules");
}

#[test]
fn wasm_route_may_hold_a_data_endowment_checked_like_any_route() {
    let r = r#"{"id":1,"path":"/w","to":{"wasm":"hello"},"authz":"w","data":[{"backend":"db","collection":"notes","ops":["select"],"columns":["id"]}]}"#;
    let doc = with(ROUTE0, r);
    rej(&doc, K::UnknownBackend, "/vhosts/0/routes/0/data/0/backend");
    let doc = doc.replacen(
        r#""p2":{"#,
        r#""data":{"backends":[{"id":"db","engine":"sqlite","dsn_ref":"path:/var/lib/a.db","pin":"sqlite"}]},"p2":{"#,
        1,
    );
    let c = ok(&doc);
    assert!(c.vhosts()[0].routes[0].data.is_some());
}

#[test]
fn route_authz_still_applies_to_wasm_routes() {
    let c = ok(&with(ROUTE0, r#"{"id":1,"path":"/w","to":{"wasm":"hello"}}"#));
    assert_eq!(c.vhosts()[0].routes[0].authz_requirement(), aegis_config::AuthzRequirement::Deny);
}
