//! F8 `data` block and `routes[].data` (P4-config-001): schema conformance, the cross-field checks the schema
//! cannot express (backend references, engine pins), INV-NONEMPTY (absent => no capability; `unrestricted` only
//! as the explicit literal; the built-in default never carries it) and the boot-time schema-provider seam.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use monban_config::ErrorKind as K;
use monban_config::{
    Backend, Config, DataOp, DsnRef, Engine, FieldId, ResolvedData, RouteData, SchemaProvider, Unresolved, engine_pin,
    engine_pins, parse_config,
};

const BASE: &str = r#"{"v":1,
 "listeners":[{"name":"web","bind":"127.0.0.1:8443","profile":"P-PUBLIC-WEB"}],
 "vhosts":[{"host":"localhost","routes":[
   {"id":1,"path":"/notes","to":{"upstream":"app"},"authz":"notes",
    "data":[{"backend":"main","collection":"notes","ops":["update","select"],"columns":["id","body","owner"]},
            {"backend":"cache","collection":"sessions","ops":["select"],"columns":["k"]}]},
   {"id":2,"path":"/","to":{"static":"/srv"}}]}],
 "data":{"backends":[
   {"id":"main","engine":"postgres","dsn_ref":"env:AEGIS_PG_DSN","pin":"pg18"},
   {"id":"cache","engine":"valkey","dsn_ref":"cred:valkey.dsn","pin":"valkey","max_conns":4,"op_budget_ms":250},
   {"id":"local","engine":"sqlite","dsn_ref":"path:/var/lib/monban/notes.db","pin":"sqlite"}]}}"#;

const CAP0: &str =
    r#"{"backend":"main","collection":"notes","ops":["update","select"],"columns":["id","body","owner"]}"#;
const DATA0: &str = r#""data":[{"backend":"main","collection":"notes","ops":["update","select"],"columns":["id","body","owner"]},
            {"backend":"cache","collection":"sessions","ops":["select"],"columns":["k"]}]"#;
const B0: &str = r#"{"id":"main","engine":"postgres","dsn_ref":"env:AEGIS_PG_DSN","pin":"pg18"}"#;
const DATA_BLOCK: &str = r#""data":{"backends":[
   {"id":"main","engine":"postgres","dsn_ref":"env:AEGIS_PG_DSN","pin":"pg18"},
   {"id":"cache","engine":"valkey","dsn_ref":"cred:valkey.dsn","pin":"valkey","max_conns":4,"op_budget_ms":250},
   {"id":"local","engine":"sqlite","dsn_ref":"path:/var/lib/monban/notes.db","pin":"sqlite"}]}"#;

const DEFAULT_BOOT: &str = include_str!("../../../ci/fixtures/unrestricted/default-boot.json");

fn with(from: &str, to: &str) -> String {
    assert!(BASE.contains(from), "base lacks {from}");
    BASE.replacen(from, to, 1)
}
fn cap(c: &str) -> String {
    with(CAP0, c)
}
fn rdata(d: &str) -> String {
    with(DATA0, &format!(r#""data":{d}"#))
}
fn backend(b: &str) -> String {
    with(B0, b)
}

fn ok(s: &str) -> Config {
    match parse_config(s.as_bytes()) {
        Ok(c) => c,
        Err(e) => panic!("expected accept, got {e}\n{s}"),
    }
}

fn rej(s: &str, kind: K, ptr: &str) {
    match parse_config(s.as_bytes()) {
        Ok(_) => panic!("expected reject {kind:?} at {ptr:?}\n{s}"),
        Err(e) => assert_eq!((e.kind(), e.pointer()), (kind, ptr), "{e}\n{s}"),
    }
}

/// Every occurrence of "unrestricted" (trimmed, case-folded) as a JSON string or key, as ci/unrestricted.py
/// counts them, by a plain scan of the canonical text.
fn unrestricted_count(effective: &[u8]) -> usize {
    let t = std::str::from_utf8(effective).unwrap().to_ascii_lowercase();
    t.matches("\"unrestricted\"").count()
}

macro_rules! accept {
    ($($name:ident: $doc:expr;)*) => { $( #[test] fn $name() { ok(AsRef::<str>::as_ref(&$doc)); } )* };
}
macro_rules! reject {
    ($($name:ident: $doc:expr => $kind:ident @ $ptr:expr;)*) => {
        $( #[test] fn $name() { rej(AsRef::<str>::as_ref(&$doc), K::$kind, $ptr); } )*
    };
}

// ------------------------------------------------------------------------------------------------ typed form

#[test]
fn base_typed_form_and_defaults() {
    let c = ok(BASE);
    let d = c.data().unwrap();
    assert_eq!(d.backends().len(), 3);
    let main = d.backend("main").unwrap();
    assert_eq!(main.engine, Engine::Postgres);
    assert_eq!(main.dsn_ref, DsnRef::Env("AEGIS_PG_DSN".into()));
    assert_eq!(main.pin, "pg18");
    assert_eq!((main.max_conns, main.op_budget_ms), (Backend::DEFAULT_MAX_CONNS, Backend::DEFAULT_OP_BUDGET_MS));
    let cache = d.backend("cache").unwrap();
    assert_eq!((cache.engine, cache.max_conns, cache.op_budget_ms), (Engine::Valkey, 4, 250));
    assert_eq!(cache.dsn_ref, DsnRef::Cred("valkey.dsn".into()));
    let local = d.backend("local").unwrap();
    assert_eq!(local.dsn_ref, DsnRef::Path("/var/lib/monban/notes.db".into()));

    let routes = &c.vhosts()[0].routes;
    let Some(RouteData::Caps(list)) = &routes[0].data else { panic!("route 1 must hold caps") };
    assert_eq!(list.len(), 2);
    assert!(!list.is_empty());
    let c0 = &list.as_slice()[0];
    assert_eq!((c0.backend(), c0.collection()), ("main", "notes"));
    assert_eq!(c0.ops(), vec![DataOp::Select, DataOp::Update]);
    assert_eq!(c0.ops_bits(), 1 | 4);
    assert!(c0.contains(DataOp::Update) && !c0.contains(DataOp::Delete));
    assert_eq!(c0.columns(), ["id", "body", "owner"]);
    // INV-NONEMPTY: absent data is no capability (None), never Unrestricted.
    assert_eq!(routes[1].data, None);
}

#[test]
fn op_bits_match_f4_opkind() {
    let want =
        [(DataOp::Select, 1u8), (DataOp::Insert, 2), (DataOp::Update, 4), (DataOp::Delete, 8), (DataOp::Upsert, 16)];
    for (o, b) in want {
        assert_eq!(o.bit(), b, "{o:?}");
    }
    assert_eq!(DataOp::ALL.map(|o| o.as_str()), ["select", "insert", "update", "delete", "upsert"]);
}

#[test]
fn effective_form_prints_data_block_with_defaults() {
    let c = ok(BASE);
    let e = std::str::from_utf8(c.effective_json()).unwrap();
    assert!(e.contains(r#""data":{"backends":[{"dsn_ref":"env:AEGIS_PG_DSN","engine":"postgres","id":"main","max_conns":16,"op_budget_ms":5000,"pin":"pg18"}"#), "{e}");
    assert!(e.contains(r#""data":[{"backend":"main","collection":"notes","columns":["id","body","owner"],"ops":["select","update"]}"#), "{e}");
    assert!(e.contains(r#""dsn_ref":"path:/var/lib/monban/notes.db""#), "{e}");
    assert!(!e.contains("null"));
    assert_eq!(monban_canon::canon_json(e.as_bytes()).unwrap().as_bytes(), c.effective_json());
    let again = ok(e);
    assert_eq!(again, c);
    assert_eq!(again.config_hash(), c.config_hash());
}

#[test]
fn hash_ignores_op_order_and_explicit_backend_defaults() {
    let a = ok(BASE);
    let b = ok(&with(r#""ops":["update","select"]"#, r#""ops":["select","update"]"#)
        .replace(B0, r#"{"id":"main","engine":"postgres","dsn_ref":"env:AEGIS_PG_DSN","pin":"pg18","max_conns":16,"op_budget_ms":5000.0}"#));
    assert_eq!(a.config_hash(), b.config_hash());
    let c = ok(&with(r#""ops":["update","select"]"#, r#""ops":["select"]"#));
    assert_ne!(a.config_hash(), c.config_hash());
}

// ------------------------------------------------------------------------------------------------ INV-NONEMPTY

#[test]
fn absent_data_is_omitted_never_null() {
    let doc = r#"{"v":1,"listeners":[{"name":"a","bind":"b","profile":"P-CNSA"}],
      "vhosts":[{"host":"a","routes":[{"id":1,"path":"/","to":{"static":"x"}}]}]}"#;
    let c = ok(doc);
    assert!(c.data().is_none());
    assert!(c.vhosts()[0].routes[0].data.is_none());
    let e = std::str::from_utf8(c.effective_json()).unwrap();
    assert!(!e.contains("\"data\""), "{e}");
    assert!(!e.contains("null"), "{e}");
    assert_eq!(unrestricted_count(c.effective_json()), 0);
}

#[test]
fn built_in_default_has_no_capability_and_no_unrestricted() {
    let c = ok(DEFAULT_BOOT);
    assert!(c.data().is_none());
    for vh in c.vhosts() {
        for r in &vh.routes {
            assert!(r.data.is_none(), "default route {} carries data", r.id);
        }
    }
    let e = std::str::from_utf8(c.effective_json()).unwrap();
    assert_eq!(unrestricted_count(c.effective_json()), 0, "{e}");
    assert!(!e.contains("null") && !e.contains("\"data\""), "{e}");
    assert!(c.resolve_data(&Fixed).unwrap().is_empty());
}

#[test]
fn unrestricted_only_from_the_explicit_literal_and_always_printed() {
    let c = ok(&rdata(r#""unrestricted""#));
    assert_eq!(c.vhosts()[0].routes[0].data, Some(RouteData::Unrestricted));
    assert_eq!(c.vhosts()[0].routes[1].data, None);
    // The printer shows it exactly once, at /vhosts/0/routes/0/data.
    assert_eq!(unrestricted_count(c.effective_json()), 1);
    let e = std::str::from_utf8(c.effective_json()).unwrap();
    assert!(e.contains(r#""data":"unrestricted""#), "{e}");
    // A cap list never becomes unrestricted, whatever it covers.
    assert_eq!(unrestricted_count(ok(BASE).effective_json()), 0);
    // Unrestricted needs no data block (it lifts the cap check only; there is still nothing to reach).
    let doc = r#"{"v":1,"listeners":[{"name":"a","bind":"b","profile":"P-CNSA"}],
      "vhosts":[{"host":"a","routes":[{"id":1,"path":"/","to":{"static":"x"},"data":"unrestricted"}]}]}"#;
    assert_eq!(ok(doc).vhosts()[0].routes[0].data, Some(RouteData::Unrestricted));
}

reject! {
    data_empty_list_is_not_all: rdata("[]") => MinItems @ "/vhosts/0/routes/0/data";
    data_null: rdata("null") => OneOf @ "/vhosts/0/routes/0/data";
    data_capitalised_literal: rdata(r#""Unrestricted""#) => OneOf @ "/vhosts/0/routes/0/data";
    data_padded_literal: rdata(r#"" unrestricted""#) => OneOf @ "/vhosts/0/routes/0/data";
    data_other_string: rdata(r#""all""#) => OneOf @ "/vhosts/0/routes/0/data";
    data_true: rdata("true") => OneOf @ "/vhosts/0/routes/0/data";
    data_object: rdata(r#"{"unrestricted":true}"#) => OneOf @ "/vhosts/0/routes/0/data";
    data_list_with_literal: rdata(r#"["unrestricted"]"#) => Type @ "/vhosts/0/routes/0/data/0";
    data_257_caps: rdata(&format!("[{}]", vec![CAP0; 257].join(","))) => MaxItems @ "/vhosts/0/routes/0/data";
}

accept! {
    data_256_caps: rdata(&format!("[{}]", vec![CAP0; 256].join(",")));
}

// ------------------------------------------------------------------------------------------------ caps

accept! {
    cap_all_ops: cap(r#"{"backend":"main","collection":"_t1","ops":["select","insert","update","delete","upsert"],"columns":["_a"]}"#);
    cap_256_columns: cap(&format!(r#"{{"backend":"main","collection":"t","ops":["select"],"columns":[{}]}}"#, (0..256).map(|i| format!("\"c{i}\"")).collect::<Vec<_>>().join(",")));
    cap_63_byte_names: cap(&format!(r#"{{"backend":"main","collection":"{0}","ops":["select"],"columns":["{0}"]}}"#, "a".repeat(63)));
}

reject! {
    cap_not_object: cap("1") => Type @ "/vhosts/0/routes/0/data/0";
    cap_unknown_field: cap(r#"{"backend":"main","collection":"notes","ops":["select"],"columns":["id"],"where":"1=1"}"#) => UnknownField @ "/vhosts/0/routes/0/data/0/where";
    cap_missing_backend: cap(r#"{"collection":"notes","ops":["select"],"columns":["id"]}"#) => MissingField @ "/vhosts/0/routes/0/data/0/backend";
    cap_missing_collection: cap(r#"{"backend":"main","ops":["select"],"columns":["id"]}"#) => MissingField @ "/vhosts/0/routes/0/data/0/collection";
    cap_missing_ops: cap(r#"{"backend":"main","collection":"notes","columns":["id"]}"#) => MissingField @ "/vhosts/0/routes/0/data/0/ops";
    cap_missing_columns: cap(r#"{"backend":"main","collection":"notes","ops":["select"]}"#) => MissingField @ "/vhosts/0/routes/0/data/0/columns";
    cap_backend_pattern: cap(r#"{"backend":"Main","collection":"notes","ops":["select"],"columns":["id"]}"#) => Pattern @ "/vhosts/0/routes/0/data/0/backend";
    cap_backend_not_string: cap(r#"{"backend":1,"collection":"notes","ops":["select"],"columns":["id"]}"#) => Type @ "/vhosts/0/routes/0/data/0/backend";
    cap_collection_pattern: cap(r#"{"backend":"main","collection":"no:tes","ops":["select"],"columns":["id"]}"#) => Pattern @ "/vhosts/0/routes/0/data/0/collection";
    cap_collection_glob: cap(r#"{"backend":"main","collection":"*","ops":["select"],"columns":["id"]}"#) => Pattern @ "/vhosts/0/routes/0/data/0/collection";
    cap_collection_64: cap(&format!(r#"{{"backend":"main","collection":"{}","ops":["select"],"columns":["id"]}}"#, "a".repeat(64))) => Pattern @ "/vhosts/0/routes/0/data/0/collection";
    cap_collection_digit_first: cap(r#"{"backend":"main","collection":"1t","ops":["select"],"columns":["id"]}"#) => Pattern @ "/vhosts/0/routes/0/data/0/collection";
    cap_ops_empty: cap(r#"{"backend":"main","collection":"notes","ops":[],"columns":["id"]}"#) => MinItems @ "/vhosts/0/routes/0/data/0/ops";
    cap_ops_six: cap(r#"{"backend":"main","collection":"notes","ops":["select","insert","update","delete","upsert","select"],"columns":["id"]}"#) => MaxItems @ "/vhosts/0/routes/0/data/0/ops";
    cap_ops_dup: cap(r#"{"backend":"main","collection":"notes","ops":["select","select"],"columns":["id"]}"#) => UniqueItems @ "/vhosts/0/routes/0/data/0/ops";
    cap_ops_enum: cap(r#"{"backend":"main","collection":"notes","ops":["truncate"],"columns":["id"]}"#) => Enum @ "/vhosts/0/routes/0/data/0/ops/0";
    cap_ops_star: cap(r#"{"backend":"main","collection":"notes","ops":["*"],"columns":["id"]}"#) => Enum @ "/vhosts/0/routes/0/data/0/ops/0";
    cap_ops_string: cap(r#"{"backend":"main","collection":"notes","ops":"select","columns":["id"]}"#) => Type @ "/vhosts/0/routes/0/data/0/ops";
    cap_columns_empty_is_not_all: cap(r#"{"backend":"main","collection":"notes","ops":["select"],"columns":[]}"#) => MinItems @ "/vhosts/0/routes/0/data/0/columns";
    cap_columns_dup: cap(r#"{"backend":"main","collection":"notes","ops":["select"],"columns":["id","id"]}"#) => UniqueItems @ "/vhosts/0/routes/0/data/0/columns";
    cap_columns_star: cap(r#"{"backend":"main","collection":"notes","ops":["select"],"columns":["*"]}"#) => Pattern @ "/vhosts/0/routes/0/data/0/columns/0";
    cap_columns_not_string: cap(r#"{"backend":"main","collection":"notes","ops":["select"],"columns":[null]}"#) => Type @ "/vhosts/0/routes/0/data/0/columns/0";
    cap_columns_257: cap(&format!(r#"{{"backend":"main","collection":"t","ops":["select"],"columns":[{}]}}"#, (0..257).map(|i| format!("\"c{i}\"")).collect::<Vec<_>>().join(","))) => MaxItems @ "/vhosts/0/routes/0/data/0/columns";
    cap_undeclared_backend: cap(r#"{"backend":"other","collection":"notes","ops":["select"],"columns":["id"]}"#) => UnknownBackend @ "/vhosts/0/routes/0/data/0/backend";
    cap_without_data_block: with(&format!(",\n {DATA_BLOCK}"), "") => UnknownBackend @ "/vhosts/0/routes/0/data/0/backend";
}

// ------------------------------------------------------------------------------------------------ backends

accept! {
    backend_bounds_min: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"env:_","pin":"pg17","max_conns":1,"op_budget_ms":10}"#);
    backend_bounds_max: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"env:AEGIS_PG_DSN","pin":"pg18","max_conns":256,"op_budget_ms":60000}"#);
    backend_redis: backend(r#"{"id":"main","engine":"redis","dsn_ref":"cred:r","pin":"redis"}"#);
    // Config selects a pin; a blocked major is refused at connect, not here (F8 backend.pin).
    backend_blocked_pin_selectable: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"env:X","pin":"pg19rc1"}"#);
    backend_64: with(DATA_BLOCK, &format!(r#""data":{{"backends":[{B0},{}]}}"#, (1..64).map(|i| format!(r#"{{"id":"{}","engine":"sqlite","dsn_ref":"path:/d/{i}.db","pin":"sqlite"}}"#, if i == 1 { "cache".to_string() } else { format!("b{i}") })).collect::<Vec<_>>().join(",")));
}

reject! {
    data_not_object: with(DATA_BLOCK, r#""data":[]"#) => Type @ "/data";
    data_null_block: with(DATA_BLOCK, r#""data":null"#) => Type @ "/data";
    data_unknown_field: with(r#""data":{"backends""#, r#""data":{"default":"unrestricted","backends""#) => UnknownField @ "/data/default";
    data_missing_backends: with(DATA_BLOCK, r#""data":{}"#) => MissingField @ "/data/backends";
    data_backends_empty: with(DATA_BLOCK, r#""data":{"backends":[]}"#) => MinItems @ "/data/backends";
    data_backends_65: with(DATA_BLOCK, &format!(r#""data":{{"backends":[{B0},{}]}}"#, (1..65).map(|i| format!(r#"{{"id":"b{i}","engine":"sqlite","dsn_ref":"path:/d/{i}.db","pin":"sqlite"}}"#)).collect::<Vec<_>>().join(","))) => MaxItems @ "/data/backends";
    backend_duplicate_id: with(r#"{"id":"local","#, r#"{"id":"main","#) => DuplicateBackend @ "/data/backends/2/id";
    backend_not_object: backend("\"main\"") => Type @ "/data/backends/0";
    backend_unknown_field: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"env:X","pin":"pg18","dsn":"postgres://u:p@h/db"}"#) => UnknownField @ "/data/backends/0/dsn";
    backend_missing_id: backend(r#"{"engine":"postgres","dsn_ref":"env:X","pin":"pg18"}"#) => MissingField @ "/data/backends/0/id";
    backend_missing_engine: backend(r#"{"id":"main","dsn_ref":"env:X","pin":"pg18"}"#) => MissingField @ "/data/backends/0/engine";
    backend_missing_dsn: backend(r#"{"id":"main","engine":"postgres","pin":"pg18"}"#) => MissingField @ "/data/backends/0/dsn_ref";
    backend_missing_pin: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"env:X"}"#) => MissingField @ "/data/backends/0/pin";
    backend_id_pattern: backend(r#"{"id":"1main","engine":"postgres","dsn_ref":"env:X","pin":"pg18"}"#) => Pattern @ "/data/backends/0/id";
    backend_id_33: backend(&format!(r#"{{"id":"m{}","engine":"postgres","dsn_ref":"env:X","pin":"pg18"}}"#, "a".repeat(32))) => Pattern @ "/data/backends/0/id";
    backend_engine_enum: backend(r#"{"id":"main","engine":"mysql","dsn_ref":"env:X","pin":"pg18"}"#) => Enum @ "/data/backends/0/engine";
    backend_engine_case: backend(r#"{"id":"main","engine":"Postgres","dsn_ref":"env:X","pin":"pg18"}"#) => Enum @ "/data/backends/0/engine";
    dsn_inline_url: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"postgres://u:p@h/db","pin":"pg18"}"#) => Pattern @ "/data/backends/0/dsn_ref";
    dsn_env_lowercase: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"env:pg","pin":"pg18"}"#) => Pattern @ "/data/backends/0/dsn_ref";
    dsn_env_empty: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"env:","pin":"pg18"}"#) => Pattern @ "/data/backends/0/dsn_ref";
    dsn_env_65: backend(&format!(r#"{{"id":"main","engine":"postgres","dsn_ref":"env:A{}","pin":"pg18"}}"#, "B".repeat(64))) => Pattern @ "/data/backends/0/dsn_ref";
    dsn_cred_empty: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"cred:","pin":"pg18"}"#) => Pattern @ "/data/backends/0/dsn_ref";
    dsn_cred_slash: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"cred:a/b","pin":"pg18"}"#) => Pattern @ "/data/backends/0/dsn_ref";
    dsn_cred_65: backend(&format!(r#"{{"id":"main","engine":"postgres","dsn_ref":"cred:{}","pin":"pg18"}}"#, "a".repeat(65))) => Pattern @ "/data/backends/0/dsn_ref";
    dsn_path_relative: with(r#""path:/var/lib/monban/notes.db""#, r#""path:notes.db""#) => Pattern @ "/data/backends/2/dsn_ref";
    dsn_path_root_only: with(r#""path:/var/lib/monban/notes.db""#, r#""path:/""#) => Pattern @ "/data/backends/2/dsn_ref";
    dsn_path_space: with(r#""path:/var/lib/monban/notes.db""#, r#""path:/a b""#) => Pattern @ "/data/backends/2/dsn_ref";
    dsn_path_too_long: with(r#""path:/var/lib/monban/notes.db""#, &format!(r#""path:/{}""#, "a".repeat(256))) => Pattern @ "/data/backends/2/dsn_ref";
    dsn_path_for_postgres: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"path:/x.db","pin":"pg18"}"#) => Pattern @ "/data/backends/0/dsn_ref";
    dsn_path_for_redis: backend(r#"{"id":"main","engine":"redis","dsn_ref":"path:/x","pin":"redis"}"#) => Pattern @ "/data/backends/0/dsn_ref";
    dsn_env_for_sqlite: with(r#""path:/var/lib/monban/notes.db""#, r#""env:SQLITE_PATH""#) => Pattern @ "/data/backends/2/dsn_ref";
    dsn_cred_for_sqlite: with(r#""path:/var/lib/monban/notes.db""#, r#""cred:db""#) => Pattern @ "/data/backends/2/dsn_ref";
    pin_pattern: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"env:X","pin":"pg-18"}"#) => Pattern @ "/data/backends/0/pin";
    pin_unknown: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"env:X","pin":"pg16"}"#) => UnknownPin @ "/data/backends/0/pin";
    pin_wrong_family: backend(r#"{"id":"main","engine":"redis","dsn_ref":"env:X","pin":"valkey"}"#) => PinEngineMismatch @ "/data/backends/0/pin";
    pin_pg_for_sqlite: with(r#""pin":"sqlite""#, r#""pin":"pg18""#) => PinEngineMismatch @ "/data/backends/2/pin";
    pin_sqlite_for_pg: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"env:X","pin":"sqlite"}"#) => PinEngineMismatch @ "/data/backends/0/pin";
    max_conns_zero: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"env:X","pin":"pg18","max_conns":0}"#) => Minimum @ "/data/backends/0/max_conns";
    max_conns_257: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"env:X","pin":"pg18","max_conns":257}"#) => Maximum @ "/data/backends/0/max_conns";
    max_conns_null: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"env:X","pin":"pg18","max_conns":null}"#) => Type @ "/data/backends/0/max_conns";
    op_budget_9: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"env:X","pin":"pg18","op_budget_ms":9}"#) => Minimum @ "/data/backends/0/op_budget_ms";
    op_budget_60001: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"env:X","pin":"pg18","op_budget_ms":60001}"#) => Maximum @ "/data/backends/0/op_budget_ms";
    op_budget_fraction: backend(r#"{"id":"main","engine":"postgres","dsn_ref":"env:X","pin":"pg18","op_budget_ms":10.5}"#) => Type @ "/data/backends/0/op_budget_ms";
}

// ------------------------------------------------------------------------------------------------ engine pins

#[test]
fn engine_pins_compiled_from_supply_chain() {
    let names: Vec<&str> = engine_pins().iter().map(|p| p.name.as_str()).collect();
    for want in ["sqlite", "pg17", "pg18", "pg19rc1", "valkey", "redis"] {
        assert!(names.contains(&want), "pin {want} missing from {names:?}");
    }
    assert_eq!(engine_pin("sqlite").map(|p| p.engine), Some(Engine::Sqlite));
    assert_eq!(engine_pin("pg18").map(|p| (p.engine, p.blocked)), Some((Engine::Postgres, false)));
    assert_eq!(engine_pin("pg19rc1").map(|p| (p.engine, p.blocked)), Some((Engine::Postgres, true)));
    assert_eq!(engine_pin("valkey").map(|p| p.engine), Some(Engine::Valkey));
    assert_eq!(engine_pin("redis").map(|p| p.engine), Some(Engine::Redis));
    assert!(engine_pin("pg16").is_none());
    assert!(engine_pin("").is_none());
}

// ------------------------------------------------------------------------------------------------ boot seam

/// Fixed introspected schema: main.notes {id 1, owner 2, body 3}, cache.sessions {k 0}; local unavailable.
struct Fixed;

impl SchemaProvider for Fixed {
    fn field(&self, backend: &Backend, collection: &str, column: &str) -> Result<FieldId, Unresolved> {
        let cols: &[(&str, FieldId)] = match (backend.id.as_str(), collection) {
            ("main", "notes") => &[("id", 1), ("owner", 2), ("body", 3)],
            ("cache", "sessions") => &[("k", 0)],
            ("local", _) => return Err(Unresolved::Unavailable),
            _ => return Err(Unresolved::NoCollection),
        };
        cols.iter().find(|(n, _)| *n == column).map(|(_, f)| *f).ok_or(Unresolved::NoColumn)
    }
}

/// A provider that must never be consulted.
struct Never;

impl SchemaProvider for Never {
    fn field(&self, _: &Backend, _: &str, _: &str) -> Result<FieldId, Unresolved> {
        panic!("provider consulted for a route without caps")
    }
}

fn boot_err(doc: &str, kind: K, ptr: &str) {
    let e = ok(doc).resolve_data(&Fixed).unwrap_err();
    assert_eq!((e.kind(), e.pointer()), (kind, ptr), "{e}");
}

#[test]
fn resolve_maps_names_to_sorted_fields() {
    let r = ok(BASE).resolve_data(&Fixed).unwrap();
    // Only route 1 holds data; route 2 (absent) is not listed, so it holds nothing.
    assert_eq!(r.len(), 1);
    assert_eq!((r[0].host.as_str(), r[0].route_id), ("localhost", 1));
    let ResolvedData::Caps(caps) = &r[0].data else { panic!("caps expected") };
    assert_eq!(caps.len(), 2);
    assert_eq!((caps[0].backend.as_str(), caps[0].collection.as_str(), caps[0].ops_bits), ("main", "notes", 5));
    assert_eq!(caps[0].fields, vec![1, 2, 3]);
    assert_eq!(caps[1].fields, vec![0]);
}

#[test]
fn resolve_unrestricted_and_absent_never_consult_the_provider() {
    let doc = r#"{"v":1,"listeners":[{"name":"a","bind":"b","profile":"P-CNSA"}],
      "vhosts":[{"host":"a","routes":[{"id":1,"path":"/","to":{"static":"x"},"data":"unrestricted"},
                                     {"id":2,"path":"/b","to":{"static":"x"}}]}]}"#;
    let r = ok(doc).resolve_data(&Never).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!((r[0].route_id, &r[0].data), (1, &ResolvedData::Unrestricted));
}

#[test]
fn resolve_unknown_column_fails_boot() {
    boot_err(
        &with(r#""columns":["id","body","owner"]"#, r#""columns":["id","secret"]"#),
        K::UnknownColumn,
        "/vhosts/0/routes/0/data/0/columns/1",
    );
}

#[test]
fn resolve_unknown_collection_fails_boot() {
    boot_err(
        &with(r#""collection":"sessions""#, r#""collection":"users""#),
        K::UnknownCollection,
        "/vhosts/0/routes/0/data/1/collection",
    );
}

#[test]
fn resolve_unavailable_schema_fails_boot() {
    boot_err(
        &with(r#""backend":"cache""#, r#""backend":"local""#),
        K::SchemaUnavailable,
        "/vhosts/0/routes/0/data/1/backend",
    );
}

#[test]
fn resolve_aliasing_columns_fail_boot() {
    struct Alias;
    impl SchemaProvider for Alias {
        fn field(&self, _: &Backend, _: &str, _: &str) -> Result<FieldId, Unresolved> {
            Ok(7)
        }
    }
    let e = ok(BASE).resolve_data(&Alias).unwrap_err();
    assert_eq!((e.kind(), e.pointer()), (K::UnknownColumn, "/vhosts/0/routes/0/data/0/columns"));
}
