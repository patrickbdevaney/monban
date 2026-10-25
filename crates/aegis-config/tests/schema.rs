//! F8 schema-conformance corpus: for every constraint of `interfaces/F8-config.schema.json`, at least one
//! accepted and one rejected document, with the error kind and JSON pointer asserted.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use aegis_config::ErrorKind as K;
use aegis_config::{
    Alpn, AuthzRequirement, Config, Framing, Limits, MAX_CONFIG_BYTES, Profile, QueryMode, RouteTarget, defaults_json,
    parse_config,
};

const BASE: &str = r#"{"v":1,
 "listeners":[{"name":"web","bind":"0.0.0.0:443","profile":"P-PUBLIC-WEB","alpn":["h2","http/1.1"]}],
 "vhosts":[{"host":"example.com","routes":[
   {"id":1,"path":"/api/","to":{"upstream":"app","framing":"h2"},"authz":"api"},
   {"id":2,"path":"/static/","to":{"static":"/srv/www"}}]}],
 "admin":{"bind":"127.0.0.1:9000"},
 "limits":{},
 "canon":{}}"#;

const L0: &str = r#"{"name":"web","bind":"0.0.0.0:443","profile":"P-PUBLIC-WEB","alpn":["h2","http/1.1"]}"#;
const R0: &str = r#"{"id":1,"path":"/api/","to":{"upstream":"app","framing":"h2"},"authz":"api"}"#;
const TO0: &str = r#"{"upstream":"app","framing":"h2"}"#;

fn with(from: &str, to: &str) -> String {
    assert!(BASE.contains(from), "base lacks {from}");
    BASE.replacen(from, to, 1)
}

fn listener(field: &str) -> String {
    with(L0, field)
}
fn route(r: &str) -> String {
    with(R0, r)
}
fn to(t: &str) -> String {
    with(TO0, t)
}
fn limit(name: &str, v: &str) -> String {
    with(r#""limits":{}"#, &format!(r#""limits":{{"{name}":{v}}}"#))
}
fn canon(body: &str) -> String {
    with(r#""canon":{}"#, &format!(r#""canon":{{{body}}}"#))
}

fn short(s: &str) -> &str {
    s.get(..s.len().min(400)).unwrap_or(s)
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
        Err(e) => {
            assert_eq!((e.kind(), e.pointer()), (kind, ptr), "{e}\n{}", short(s));
        }
    }
}

macro_rules! accept {
    ($($name:ident: $doc:expr;)*) => { $( #[test] fn $name() { ok(AsRef::<str>::as_ref(&$doc)); } )* };
}
macro_rules! reject {
    ($($name:ident: $doc:expr => $kind:ident @ $ptr:expr;)*) => {
        $( #[test] fn $name() { rej(AsRef::<str>::as_ref(&$doc), K::$kind, $ptr); } )*
    };
}

// ------------------------------------------------------------------------------------------------ root

#[test]
fn base_accepts_with_defaults() {
    let c = ok(BASE);
    assert_eq!(c.limits(), &Limits::default());
    assert_eq!(c.canon().query, QueryMode::Opaque);
    let l = &c.listeners()[0];
    assert_eq!((l.name.as_str(), l.profile), ("web", Profile::PublicWeb));
    assert_eq!(l.alpn.as_deref(), Some(&[Alpn::H2, Alpn::Http11][..]));
    let r = &c.vhosts()[0].routes;
    assert_eq!(r[0].to, RouteTarget::Upstream { upstream: "app".into(), framing: Some(Framing::H2) });
    assert_eq!(r[0].authz_requirement(), AuthzRequirement::Policy("api"));
    assert_eq!(r[1].to, RouteTarget::Static { root: "/srv/www".into() });
    assert_eq!(c.admin().and_then(|a| a.bind.as_deref()), Some("127.0.0.1:9000"));
}

const MINIMAL: &str = r#"{"v":1,"listeners":[{"name":"a","bind":"b","profile":"P-CNSA"}],
  "vhosts":[{"host":"a","routes":[{"id":1,"path":"/","to":{"static":"x"}}]}]}"#;

accept! {
    root_minimal: MINIMAL;
    root_v_const_float: with(r#""v":1"#, r#""v":1.0"#);
    root_no_admin_limits_canon: MINIMAL.to_string();
    listeners_max_64: with(&format!("[{L0}]"), &format!("[{}]", (0..64).map(|i| L0.replace("\"web\"", &format!("\"l{i}\""))).collect::<Vec<_>>().join(",")));
    vhosts_max_4096: with(r#"{"host":"example.com","routes":[
   {"id":1,"path":"/api/","to":{"upstream":"app","framing":"h2"},"authz":"api"},
   {"id":2,"path":"/static/","to":{"static":"/srv/www"}}]}"#, &(0..4096).map(|i| format!(r#"{{"host":"h{i}","routes":[{{"id":1,"path":"/","to":{{"static":"x"}}}}]}}"#)).collect::<Vec<_>>().join(","));
    admin_empty: with(r#""admin":{"bind":"127.0.0.1:9000"}"#, r#""admin":{}"#);
    admin_unix: with(r#""127.0.0.1:9000""#, r#""unix:/run/aegis/admin.sock""#);
}

reject! {
    root_not_object: "[]".to_string() => Type @ "";
    root_number: "1".to_string() => Type @ "";
    root_unknown_field: with(r#""v":1,"#, r#""v":1,"x":0,"#) => UnknownField @ "/x";
    root_unknown_field_escaped: with(r#""v":1,"#, r#""v":1,"a/b~":0,"#) => UnknownField @ "/a~1b~0";
    root_missing_v: with(r#""v":1,"#, "") => MissingField @ "/v";
    root_missing_listeners: MINIMAL.replace(r#""listeners":[{"name":"a","bind":"b","profile":"P-CNSA"}],"#, "") => MissingField @ "/listeners";
    root_missing_vhosts: r#"{"v":1,"listeners":[{"name":"a","bind":"b","profile":"P-CNSA"}]}"#.to_string() => MissingField @ "/vhosts";
    root_v_two: with(r#""v":1"#, r#""v":2"#) => Const @ "/v";
    root_v_string: with(r#""v":1"#, r#""v":"1""#) => Const @ "/v";
    root_v_float_frac: with(r#""v":1"#, r#""v":1.5"#) => Const @ "/v";
    listeners_not_array: with(&format!("[{L0}]"), L0) => Type @ "/listeners";
    listeners_empty: with(&format!("[{L0}]"), "[]") => MinItems @ "/listeners";
    listeners_65: with(&format!("[{L0}]"), &format!("[{}]", (0..65).map(|i| L0.replace("\"web\"", &format!("\"l{i}\""))).collect::<Vec<_>>().join(","))) => MaxItems @ "/listeners";
    vhosts_not_array: MINIMAL.replace(r#""vhosts":["#, r#""vhosts":{"a":["#).replace("}]}]}", "}]}]}}") => Type @ "/vhosts";
    vhosts_empty: r#"{"v":1,"listeners":[{"name":"a","bind":"b","profile":"P-CNSA"}],"vhosts":[]}"#.to_string() => MinItems @ "/vhosts";
    vhosts_4097: format!(r#"{{"v":1,"listeners":[{{"name":"a","bind":"b","profile":"P-CNSA"}}],"vhosts":[{}]}}"#, (0..4097).map(|i| format!(r#"{{"host":"h{i}","routes":[{{"id":1,"path":"/","to":{{"static":"x"}}}}]}}"#)).collect::<Vec<_>>().join(",")) => MaxItems @ "/vhosts";
    admin_not_object: with(r#""admin":{"bind":"127.0.0.1:9000"}"#, r#""admin":"127.0.0.1:9000""#) => Type @ "/admin";
    admin_unknown_field: with(r#""admin":{"#, r#""admin":{"port":1,"#) => UnknownField @ "/admin/port";
    admin_bind_not_string: with(r#""127.0.0.1:9000""#, "9000") => Type @ "/admin/bind";
    limits_not_object: with(r#""limits":{}"#, r#""limits":[]"#) => Type @ "/limits";
    limits_unknown_field: limit("max_connections", "1") => UnknownField @ "/limits/max_connections";
    canon_not_object: with(r#""canon":{}"#, r#""canon":"strict""#) => Type @ "/canon";
    canon_unknown_field: canon(r#""unicode":"nfc""#) => UnknownField @ "/canon/unicode";
}

// ------------------------------------------------------------------------------------------------ limits

macro_rules! limit_tests {
    ($($field:ident: $min:expr, $max:expr;)*) => { $(
        mod $field {
            use super::*;
            const N: &str = stringify!($field);
            #[test] fn accept_min() { assert_eq!(ok(&limit(N, &$min.to_string())).limits().$field, $min); }
            #[test] fn accept_max() { assert_eq!(ok(&limit(N, &$max.to_string())).limits().$field, $max); }
            #[test] fn accept_integral_float() {
                assert_eq!(ok(&limit(N, &format!("{}.0", $max))).limits().$field, $max);
            }
            #[test] fn default_applied() {
                let d = Limits::BOUNDS.iter().find(|b| b.0 == N).unwrap().3;
                assert_eq!(ok(BASE).limits().$field, d);
            }
            #[test] fn reject_below_min() {
                let below: i64 = $min as i64 - 1;
                rej(&limit(N, &below.to_string()), K::Minimum, &format!("/limits/{N}"));
            }
            #[test] fn reject_above_max() {
                rej(&limit(N, &($max as u64 + 1).to_string()), K::Maximum, &format!("/limits/{N}"));
            }
            #[test] fn reject_huge_float() {
                rej(&limit(N, "1e300"), K::Maximum, &format!("/limits/{N}"));
            }
            #[test] fn reject_string() { rej(&limit(N, "\"100\""), K::Type, &format!("/limits/{N}")); }
            #[test] fn reject_fraction() { rej(&limit(N, &format!("{}.5", $min)), K::Type, &format!("/limits/{N}")); }
            #[test] fn reject_null() { rej(&limit(N, "null"), K::Type, &format!("/limits/{N}")); }
        }
    )* };
}

limit_tests! {
    max_concurrent_streams: 1u64, 1000u64;
    max_header_list_size: 1024u64, 65536u64;
    max_header_fields: 8u64, 256u64;
    header_table_size: 0u64, 65536u64;
    rst_burst: 1u64, 1000u64;
    rst_refill_per_s: 1u64, 1000u64;
    max_streams_per_conn: 1u64, 100000u64;
    stream_window: 65535u64, 16777216u64;
    conn_window: 65535u64, 67108864u64;
    stall_timeout_ms: 100u64, 120000u64;
    idle_timeout_ms: 1000u64, 600000u64;
    max_body_bytes: 0u64, 1073741824u64;
    per_conn_memory_bytes: 65536u64, 268435456u64;
}

#[test]
fn limits_bounds_match_schema_table() {
    // Pinned copy of F8 limits (name, min, max, default); edits to either side must be deliberate.
    let want: &[(&str, u64, u64, u64)] = &[
        ("max_concurrent_streams", 1, 1000, 100),
        ("max_header_list_size", 1024, 65536, 16384),
        ("max_header_fields", 8, 256, 128),
        ("header_table_size", 0, 65536, 4096),
        ("rst_burst", 1, 1000, 100),
        ("rst_refill_per_s", 1, 1000, 33),
        ("max_streams_per_conn", 1, 100000, 10000),
        ("stream_window", 65535, 16777216, 262144),
        ("conn_window", 65535, 67108864, 1048576),
        ("stall_timeout_ms", 100, 120000, 10000),
        ("idle_timeout_ms", 1000, 600000, 30000),
        ("max_body_bytes", 0, 1073741824, 1048576),
        ("per_conn_memory_bytes", 65536, 268435456, 16777216),
    ];
    assert_eq!(Limits::BOUNDS, want);
}

#[test]
fn inv_nonempty_no_unbounded_limit() {
    // Every limit has a finite schema maximum and the default is within bounds.
    for (n, min, max, d) in Limits::BOUNDS {
        assert!(min <= d && d <= max && *max < u64::MAX, "{n}");
    }
}

// ------------------------------------------------------------------------------------------------ canon

accept! {
    canon_all_fixed: canon(r#""dot_segments":"reject","encoded_slash":"reject","non_ascii_host":"reject","encoded_non_ascii_path":"accept_opaque","empty_segments":"redirect_308","trailing_slash":"accept","query":"opaque""#);
}

reject! {
    canon_dot_segments: canon(r#""dot_segments":"accept""#) => Const @ "/canon/dot_segments";
    canon_encoded_slash: canon(r#""encoded_slash":"decode""#) => Const @ "/canon/encoded_slash";
    canon_non_ascii_host: canon(r#""non_ascii_host":"idna""#) => Const @ "/canon/non_ascii_host";
    canon_encoded_non_ascii_path: canon(r#""encoded_non_ascii_path":"reject""#) => Const @ "/canon/encoded_non_ascii_path";
    canon_empty_segments: canon(r#""empty_segments":"merge""#) => Const @ "/canon/empty_segments";
    canon_trailing_slash: canon(r#""trailing_slash":"strip""#) => Const @ "/canon/trailing_slash";
    canon_fixed_not_string: canon(r#""dot_segments":1"#) => Const @ "/canon/dot_segments";
    canon_query_enum: canon(r#""query":"split""#) => Enum @ "/canon/query";
    canon_query_case: canon(r#""query":"Opaque""#) => Enum @ "/canon/query";
    canon_query_not_string: canon(r#""query":true"#) => Enum @ "/canon/query";
}

#[test]
fn canon_query_typed() {
    assert_eq!(ok(&canon(r#""query":"typed""#)).canon().query, QueryMode::Typed);
    assert_eq!(ok(&canon(r#""query":"opaque""#)).canon().query, QueryMode::Opaque);
}

// ------------------------------------------------------------------------------------------------ listener

fn l(fields: &str) -> String {
    listener(&format!("{{{fields}}}"))
}

accept! {
    listener_no_alpn: l(r#""name":"web","bind":"x","profile":"P-PUBLIC-WEB""#);
    listener_name_one_char: l(r#""name":"a","bind":"x","profile":"P-PUBLIC-WEB""#);
    listener_name_32_chars: l(&format!(r#""name":"a{}","bind":"x","profile":"P-PUBLIC-WEB""#, "0-".repeat(15) + "z"));
    listener_alpn_single: l(r#""name":"web","bind":"x","profile":"P-PUBLIC-WEB","alpn":["http/1.1"]"#);
    listener_bind_any_string: l(r#""name":"web","bind":"","profile":"P-PUBLIC-WEB""#);
}

#[test]
fn listener_all_profiles() {
    for (s, p) in [
        ("P-PUBLIC-WEB", Profile::PublicWeb),
        ("P-PQ-REQUIRED", Profile::PqRequired),
        ("P-UNIVERSAL", Profile::Universal),
        ("P-BSI-ALT", Profile::BsiAlt),
        ("P-CNSA", Profile::Cnsa),
        ("FIPS-FLOOR", Profile::FipsFloor),
        ("FIPS-PQ-REQUIRED", Profile::FipsPqRequired),
        ("FIPS-CMVP", Profile::FipsCmvp),
    ] {
        let c = ok(&l(&format!(r#""name":"web","bind":"x","profile":"{s}""#)));
        assert_eq!(c.listeners()[0].profile, p);
        assert_eq!(p.as_str(), s);
    }
}

reject! {
    listener_not_object: listener("\"web\"") => Type @ "/listeners/0";
    listener_unknown_field: l(r#""name":"web","bind":"x","profile":"P-CNSA","port":443"#) => UnknownField @ "/listeners/0/port";
    listener_missing_name: l(r#""bind":"x","profile":"P-CNSA""#) => MissingField @ "/listeners/0/name";
    listener_missing_bind: l(r#""name":"web","profile":"P-CNSA""#) => MissingField @ "/listeners/0/bind";
    listener_missing_profile: l(r#""name":"web","bind":"x""#) => MissingField @ "/listeners/0/profile";
    listener_name_not_string: l(r#""name":1,"bind":"x","profile":"P-CNSA""#) => Type @ "/listeners/0/name";
    listener_name_empty: l(r#""name":"","bind":"x","profile":"P-CNSA""#) => Pattern @ "/listeners/0/name";
    listener_name_33_chars: l(&format!(r#""name":"a{}","bind":"x","profile":"P-CNSA""#, "b".repeat(32))) => Pattern @ "/listeners/0/name";
    listener_name_upper: l(r#""name":"Web","bind":"x","profile":"P-CNSA""#) => Pattern @ "/listeners/0/name";
    listener_name_leading_digit: l(r#""name":"1web","bind":"x","profile":"P-CNSA""#) => Pattern @ "/listeners/0/name";
    listener_name_leading_dash: l(r#""name":"-web","bind":"x","profile":"P-CNSA""#) => Pattern @ "/listeners/0/name";
    listener_name_underscore: l(r#""name":"web_1","bind":"x","profile":"P-CNSA""#) => Pattern @ "/listeners/0/name";
    listener_name_trailing_newline: l(r#""name":"web\n","bind":"x","profile":"P-CNSA""#) => Pattern @ "/listeners/0/name";
    listener_name_non_ascii: l(r#""name":"wéb","bind":"x","profile":"P-CNSA""#) => Pattern @ "/listeners/0/name";
    listener_bind_not_string: l(r#""name":"web","bind":443,"profile":"P-CNSA""#) => Type @ "/listeners/0/bind";
    listener_profile_enum: l(r#""name":"web","bind":"x","profile":"P-public-web""#) => Enum @ "/listeners/0/profile";
    listener_profile_not_string: l(r#""name":"web","bind":"x","profile":null"#) => Enum @ "/listeners/0/profile";
    listener_alpn_not_array: l(r#""name":"web","bind":"x","profile":"P-CNSA","alpn":"h2""#) => Type @ "/listeners/0/alpn";
    listener_alpn_empty: l(r#""name":"web","bind":"x","profile":"P-CNSA","alpn":[]"#) => MinItems @ "/listeners/0/alpn";
    listener_alpn_enum: l(r#""name":"web","bind":"x","profile":"P-CNSA","alpn":["h2","h3"]"#) => Enum @ "/listeners/0/alpn/1";
    listener_alpn_unique: l(r#""name":"web","bind":"x","profile":"P-CNSA","alpn":["h2","h2"]"#) => UniqueItems @ "/listeners/0/alpn";
    listener_duplicate_name: with(&format!("[{L0}]"), &format!("[{L0},{L0}]")) => DuplicateListener @ "/listeners/1/name";
}

// ------------------------------------------------------------------------------------------------ vhost

fn host(h: &str) -> String {
    with(r#""host":"example.com""#, &format!(r#""host":"{h}""#))
}

accept! {
    host_single_char: host("a");
    host_digits: host("1.2.3.4");
    host_dash_inside: host("a-b.c1");
    host_a_label: host("xn--bcher-kva.example");
    host_label_63: host(&format!("a{}b.com", "c".repeat(61)));
    host_many_labels: host(&vec!["a"; 200].join("."));
}

reject! {
    vhost_not_object: with(r#"{"host":"example.com","routes":["#, r#""x",{"host":"example.com","routes":["#) => Type @ "/vhosts/0";
    vhost_unknown_field: with(r#""host":"example.com","#, r#""host":"example.com","tls":{},"#) => UnknownField @ "/vhosts/0/tls";
    vhost_missing_host: with(r#""host":"example.com","#, "") => MissingField @ "/vhosts/0/host";
    vhost_missing_routes: MINIMAL.replace(r#","routes":[{"id":1,"path":"/","to":{"static":"x"}}]"#, "") => MissingField @ "/vhosts/0/routes";
    host_not_string: with(r#""host":"example.com""#, r#""host":["example.com"]"#) => Type @ "/vhosts/0/host";
    host_empty: host("") => Pattern @ "/vhosts/0/host";
    host_upper: host("Example.com") => Pattern @ "/vhosts/0/host";
    host_leading_dash: host("-a.com") => Pattern @ "/vhosts/0/host";
    host_trailing_dash: host("a-.com") => Pattern @ "/vhosts/0/host";
    host_empty_label: host("a..com") => Pattern @ "/vhosts/0/host";
    host_leading_dot: host(".a.com") => Pattern @ "/vhosts/0/host";
    host_trailing_dot: host("a.com.") => Pattern @ "/vhosts/0/host";
    host_label_64: host(&format!("a{}b.com", "c".repeat(62))) => Pattern @ "/vhosts/0/host";
    host_u_label: host("bücher.example") => Pattern @ "/vhosts/0/host";
    host_underscore: host("a_b.com") => Pattern @ "/vhosts/0/host";
    host_port: host("example.com:443") => Pattern @ "/vhosts/0/host";
    host_wildcard: host("*.example.com") => Pattern @ "/vhosts/0/host";
    routes_not_array: MINIMAL.replace(r#""routes":[{"id":1,"path":"/","to":{"static":"x"}}]"#, r#""routes":{"id":1}"#) => Type @ "/vhosts/0/routes";
    routes_empty: MINIMAL.replace(r#""routes":[{"id":1,"path":"/","to":{"static":"x"}}]"#, r#""routes":[]"#) => MinItems @ "/vhosts/0/routes";
    routes_4097: MINIMAL.replace(r#"[{"id":1,"path":"/","to":{"static":"x"}}]"#, &format!("[{}]", (1..=4097).map(|i| format!(r#"{{"id":{i},"path":"/","to":{{"static":"x"}}}}"#)).collect::<Vec<_>>().join(","))) => MaxItems @ "/vhosts/0/routes";
    vhost_duplicate_host: with(r#""vhosts":["#, r#""vhosts":[{"host":"example.com","routes":[{"id":1,"path":"/","to":{"static":"x"}}]},"#) => DuplicateHost @ "/vhosts/1/host";
}

accept! {
    routes_4096: MINIMAL.replace(r#"[{"id":1,"path":"/","to":{"static":"x"}}]"#, &format!("[{}]", (1..=4096).map(|i| format!(r#"{{"id":{i},"path":"/","to":{{"static":"x"}}}}"#)).collect::<Vec<_>>().join(",")));
}

// ------------------------------------------------------------------------------------------------ route

accept! {
    route_id_max_safe: route(r#"{"id":9007199254740991,"path":"/","to":{"static":"x"}}"#);
    route_id_float_integral: route(r#"{"id":3e0,"path":"/","to":{"static":"x"}}"#);
    route_path_root: route(r#"{"id":3,"path":"/","to":{"static":"x"}}"#);
    route_path_full_charset: route(r#"{"id":3,"path":"/AZaz09._~!$&'()*+,;=:@/-","to":{"static":"x"}}"#);
    route_same_id_other_vhost: with(r#""vhosts":["#, r#""vhosts":[{"host":"other.com","routes":[{"id":1,"path":"/","to":{"static":"x"}}]},"#);
    to_upstream_no_framing: to(r#"{"upstream":"app"}"#);
    to_framing_uds: to(r#"{"upstream":"app","framing":"uds"}"#);
    to_framing_h1: to(r#"{"upstream":"app","framing":"h1-regenerate"}"#);
}

reject! {
    route_not_object: route("1") => Type @ "/vhosts/0/routes/0";
    route_unknown_field: route(r#"{"id":3,"path":"/","to":{"static":"x"},"methods":["GET"]}"#) => UnknownField @ "/vhosts/0/routes/0/methods";
    route_missing_id: route(r#"{"path":"/","to":{"static":"x"}}"#) => MissingField @ "/vhosts/0/routes/0/id";
    route_missing_path: route(r#"{"id":3,"to":{"static":"x"}}"#) => MissingField @ "/vhosts/0/routes/0/path";
    route_missing_to: route(r#"{"id":3,"path":"/"}"#) => MissingField @ "/vhosts/0/routes/0/to";
    route_id_zero: route(r#"{"id":0,"path":"/","to":{"static":"x"}}"#) => Minimum @ "/vhosts/0/routes/0/id";
    route_id_negative: route(r#"{"id":-5,"path":"/","to":{"static":"x"}}"#) => Minimum @ "/vhosts/0/routes/0/id";
    route_id_beyond_safe: route(r#"{"id":9007199254740992.0,"path":"/","to":{"static":"x"}}"#) => Maximum @ "/vhosts/0/routes/0/id";
    route_id_string: route(r#"{"id":"1","path":"/","to":{"static":"x"}}"#) => Type @ "/vhosts/0/routes/0/id";
    route_id_fraction: route(r#"{"id":1.5,"path":"/","to":{"static":"x"}}"#) => Type @ "/vhosts/0/routes/0/id";
    route_path_not_string: route(r#"{"id":3,"path":1,"to":{"static":"x"}}"#) => Type @ "/vhosts/0/routes/0/path";
    route_path_empty: route(r#"{"id":3,"path":"","to":{"static":"x"}}"#) => Pattern @ "/vhosts/0/routes/0/path";
    route_path_relative: route(r#"{"id":3,"path":"api","to":{"static":"x"}}"#) => Pattern @ "/vhosts/0/routes/0/path";
    route_path_space: route(r#"{"id":3,"path":"/a b","to":{"static":"x"}}"#) => Pattern @ "/vhosts/0/routes/0/path";
    route_path_query: route(r#"{"id":3,"path":"/a?x","to":{"static":"x"}}"#) => Pattern @ "/vhosts/0/routes/0/path";
    route_path_percent: route(r#"{"id":3,"path":"/%41","to":{"static":"x"}}"#) => Pattern @ "/vhosts/0/routes/0/path";
    route_path_non_ascii: route(r#"{"id":3,"path":"/é","to":{"static":"x"}}"#) => Pattern @ "/vhosts/0/routes/0/path";
    route_path_trailing_newline: route(r#"{"id":3,"path":"/a\n","to":{"static":"x"}}"#) => Pattern @ "/vhosts/0/routes/0/path";
    route_authz_not_string: route(r#"{"id":3,"path":"/","to":{"static":"x"},"authz":true}"#) => Type @ "/vhosts/0/routes/0/authz";
    route_duplicate_id: route(r#"{"id":2,"path":"/","to":{"static":"x"}}"#) => DuplicateRouteId @ "/vhosts/0/routes/1/id";
    to_not_object: to(r#""app""#) => OneOf @ "/vhosts/0/routes/0/to";
    to_empty_object: to("{}") => OneOf @ "/vhosts/0/routes/0/to";
    to_both_branches: to(r#"{"upstream":"app","static":"/srv"}"#) => OneOf @ "/vhosts/0/routes/0/to";
    to_upstream_extra_field: to(r#"{"upstream":"app","weight":1}"#) => UnknownField @ "/vhosts/0/routes/0/to/weight";
    to_static_extra_field: to(r#"{"static":"/srv","index":"i.html"}"#) => UnknownField @ "/vhosts/0/routes/0/to/index";
    to_static_with_framing: to(r#"{"static":"/srv","framing":"h2"}"#) => UnknownField @ "/vhosts/0/routes/0/to/framing";
    to_upstream_not_string: to(r#"{"upstream":1}"#) => Type @ "/vhosts/0/routes/0/to/upstream";
    to_static_not_string: to(r#"{"static":null}"#) => Type @ "/vhosts/0/routes/0/to/static";
    to_framing_enum: to(r#"{"upstream":"app","framing":"h3"}"#) => Enum @ "/vhosts/0/routes/0/to/framing";
    to_framing_only: to(r#"{"framing":"h2"}"#) => OneOf @ "/vhosts/0/routes/0/to";
}

#[test]
fn inv_nonempty_route_without_authz_is_denied() {
    let c = ok(BASE);
    let r = &c.vhosts()[0].routes[1];
    assert_eq!(r.authz, None);
    assert_eq!(r.authz_requirement(), AuthzRequirement::Deny);
    let c = ok(&route(r#"{"id":3,"path":"/","to":{"static":"x"},"authz":""}"#));
    assert_eq!(c.vhosts()[0].routes[0].authz_requirement(), AuthzRequirement::Deny);
}

// ------------------------------------------------------------------------------------------------ syntax, size

reject! {
    syntax_duplicate_key: with(r#""v":1,"#, r#""v":1,"v":1,"#) => Syntax @ "";
    syntax_case_collision: with(r#""v":1,"#, r#""v":1,"V":1,"#) => Syntax @ "";
    syntax_trailing_comma: with(r#""canon":{}}"#, r#""canon":{},}"#) => Syntax @ "";
    syntax_invalid_utf8: String::from_utf8_lossy(b"{\"v\":1}").replace('1', "\u{FFFD}") => Syntax @ "";
    syntax_empty: String::new() => Syntax @ "";
    syntax_trailing_data: format!("{BASE} 1") => Syntax @ "";
}

#[test]
fn syntax_raw_invalid_utf8_bytes() {
    let e = parse_config(b"{\"v\":\xff}").unwrap_err();
    assert_eq!((e.kind(), e.pointer()), (K::Syntax, ""));
}

#[test]
fn size_cap_exact_and_over() {
    // Pad the base with whitespace to exactly the cap: accepted; one byte more: TooLarge before parsing.
    let mut s = BASE.to_string();
    s.push_str(&" ".repeat(MAX_CONFIG_BYTES - s.len()));
    assert_eq!(s.len(), MAX_CONFIG_BYTES);
    ok(&s);
    s.push(' ');
    rej(&s, K::TooLarge, "");
    // Over the cap even though the prefix is garbage: the cap is checked first.
    let junk = vec![0xffu8; MAX_CONFIG_BYTES + 1];
    assert_eq!(parse_config(&junk).unwrap_err().kind(), K::TooLarge);
}

#[test]
fn effective_form_held_to_cap() {
    // Integral floats expand when re-laid as integers (1e12 -> 1000000000000): an input under the cap whose
    // effective form exceeds it is rejected (CFG-2), never truncated.
    fn doc(slack: usize, id: impl Fn(usize) -> String) -> String {
        let head = r#"{"v":1,"listeners":[{"name":"a","bind":"b","profile":"P-CNSA"}],"vhosts":["#;
        let mut out = String::from(head);
        let (mut h, mut k) = (0usize, 0usize);
        out.push_str(&format!(r#"{{"host":"h{h}","routes":["#));
        loop {
            let r = format!(r#"{{"id":{},"path":"/","to":{{"static":"x"}}}}"#, id(k + 1));
            if out.len() + r.len() + slack > MAX_CONFIG_BYTES {
                break;
            }
            if k > 0 {
                out.push(',');
            }
            out.push_str(&r);
            k += 1;
            if k == 4096 {
                h += 1;
                k = 0;
                out.push_str(&format!(r#"]}},{{"host":"h{h}","routes":["#));
            }
        }
        if k == 0 {
            out.push_str(r#"{"id":1,"path":"/","to":{"static":"x"}}"#);
        }
        out.push_str("]}]}");
        out
    }
    // Defaults (limits + canon) add under 1 KiB to the effective form; a document that leaves that headroom
    // is accepted.
    let plain = doc(2048, |i| i.to_string());
    assert!(plain.len() <= MAX_CONFIG_BYTES);
    ok(&plain);
    let fat = doc(2048, |i| format!("{i}e12"));
    assert!(fat.len() <= MAX_CONFIG_BYTES);
    rej(&fat, K::TooLarge, "");
}

// ------------------------------------------------------------------------------------------------ effective / hash

#[test]
fn effective_json_is_canonical_and_complete() {
    let c = ok(MINIMAL);
    let e = std::str::from_utf8(c.effective_json()).unwrap();
    // Canonical: re-canonicalizing is the identity.
    assert_eq!(aegis_canon::canon_json(e.as_bytes()).unwrap().as_bytes(), c.effective_json());
    assert!(e.contains(r#""limits":{"conn_window":1048576,"#), "{e}");
    assert!(e.contains(r#""query":"opaque""#));
    assert!(e.contains(r#""dot_segments":"reject""#));
    // Effective JSON re-parses to the same config.
    let again = ok(e);
    assert_eq!(again, c);
    assert_eq!(again.config_hash(), c.config_hash());
    assert_eq!(c.config_hash(), aegis_config::sha256(c.effective_json()));
    assert_eq!(c.config_hash_hex().len(), 64);
}

#[test]
fn hash_ignores_layout_and_explicit_defaults() {
    let a = ok(MINIMAL);
    let b = ok(&MINIMAL
        .replace(r#"{"v":1,"#, r#"{ "limits":{"max_concurrent_streams":100.0}, "canon":{"query":"opaque"}, "v":1,"#));
    assert_eq!(a.config_hash(), b.config_hash());
    let c = ok(&MINIMAL.replace(r#"{"v":1,"#, r#"{"limits":{"max_concurrent_streams":101},"v":1,"#));
    assert_ne!(a.config_hash(), c.config_hash());
}

#[test]
fn defaults_document() {
    let d = defaults_json();
    assert_eq!(aegis_canon::canon_json(&d).unwrap().as_bytes(), &d[..]);
    let s = std::str::from_utf8(&d).unwrap();
    assert_eq!(
        s,
        concat!(
            r#"{"canon":{"dot_segments":"reject","empty_segments":"redirect_308","encoded_non_ascii_path":"accept_opaque","#,
            r#""encoded_slash":"reject","non_ascii_host":"reject","query":"opaque","trailing_slash":"accept"},"#,
            r#""limits":{"conn_window":1048576,"header_table_size":4096,"idle_timeout_ms":30000,"max_body_bytes":1048576,"#,
            r#""max_concurrent_streams":100,"max_header_fields":128,"max_header_list_size":16384,"#,
            r#""max_streams_per_conn":10000,"per_conn_memory_bytes":16777216,"rst_burst":100,"rst_refill_per_s":33,"#,
            r#""stall_timeout_ms":10000,"stream_window":262144}}"#
        )
    );
}
