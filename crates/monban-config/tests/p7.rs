//! F8 Phase-7 additions (P7-spec-001, PLAN-7 Interfaces): schema conformance against the frozen schema file itself
//! (member sets, enums, bounds, required lists), "absent = today's behaviour" (a pre-Phase-7 config has the same
//! effective form; the default front is not hashed), and an accept/reject corpus with the error kind and JSON
//! pointer asserted for `listeners[].proxy_protocol` (PROXY-1..3 inputs), `listeners[].l4` (L4-1/L4-2),
//! `listeners[].front` (FRONT-1), the root `tls` block (SEL-1..3) and the backend families mariadb/crdb.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::net::IpAddr;

use monban_canon::{JsonValue, parse_json};
use monban_config::ErrorKind as K;
use monban_config::{
    Admission, Cidr, Config, CredentialKind, Front, MAX_CREDENTIALS, MAX_L4_ROUTES, MAX_TRUSTED, Profile, RateLimit,
    SecretRef, TrustAnchorId, adapter_pins, parse_config,
};

const BASE: &str = r#"{"v":1,
 "listeners":[{"name":"web","bind":"0.0.0.0:443","profile":"P-PUBLIC-WEB","alpn":["h2","http/1.1"]},
   {"name":"priv","bind":"10.0.0.1:8443","profile":"P-PQ-REQUIRED"}],
 "vhosts":[{"host":"example.com","routes":[{"id":1,"path":"/","to":{"upstream":"app","framing":"h2"},"authz":"api"}]}]}"#;
const L0: &str = r#"{"name":"web","bind":"0.0.0.0:443","profile":"P-PUBLIC-WEB","alpn":["h2","http/1.1"]}"#;
const L1: &str = r#"{"name":"priv","bind":"10.0.0.1:8443","profile":"P-PQ-REQUIRED"}"#;

fn with(from: &str, to: &str) -> String {
    assert!(BASE.contains(from), "base lacks {from}");
    BASE.replacen(from, to, 1)
}
/// Add members to listener 0 (`web`, HTTP, P-PUBLIC-WEB).
fn l0(extra: &str) -> String {
    with(L0, &format!("{},{extra}}}", L0.strip_suffix('}').unwrap()))
}
/// Add members to listener 1 (`priv`, no alpn, P-PQ-REQUIRED).
fn l1(extra: &str) -> String {
    with(L1, &format!("{},{extra}}}", L1.strip_suffix('}').unwrap()))
}
fn proxy(items: &str) -> String {
    l0(&format!(r#""proxy_protocol":{{"trusted":[{items}]}}"#))
}
fn l4(items: &str) -> String {
    l1(&format!(r#""l4":[{items}]"#))
}
/// Append a root `tls` block with these credentials.
fn tls(creds: &str) -> String {
    let b = BASE.strip_suffix('}').unwrap();
    format!(r#"{b},"tls":{{"credentials":[{creds}]}}}}"#)
}
const X509: &str = r#"{"id":"web-x509","kind":"x509","chain":"cred:web.crt","key":"cred:web.key"}"#;
const MTC: &str = r#"{"id":"web-mtc","kind":"mtc","trust_anchor_id":"32473.1","chain":"path:/etc/monban/mtc.bin","key":"cred:mtc.key"}"#;
const MLDSA: &str = r#"{"id":"hop","kind":"mldsa","chain":"cred:hop.crt","key":"cred:hop.key","listeners":["priv"]}"#;

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
fn member<'a>(v: &'a JsonValue, k: &str) -> &'a JsonValue {
    match v {
        JsonValue::Object(m) => m.iter().find(|(n, _)| n == k).map(|(_, v)| v).unwrap_or_else(|| panic!("no {k}")),
        _ => panic!("not an object looking up {k}"),
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
    member(member(schema(), "$defs"), name)
}

#[test]
fn listener_members_mirror_f8() {
    let l = def("listener");
    assert_eq!(keys(member(l, "properties")), ["name", "bind", "profile", "alpn", "proxy_protocol", "l4", "front"]);
    assert_eq!(strs(member(l, "required")), ["name", "bind", "profile"]);
    let front = member(member(l, "properties"), "front");
    assert_eq!(strs(member(front, "enum")), [Front::Epoll.as_str(), Front::Uring.as_str()]);
    assert_eq!(member(front, "default"), &JsonValue::String(Front::default().as_str().into()));
    let l4 = member(member(l, "properties"), "l4");
    assert_eq!((int(member(l4, "minItems")), int(member(l4, "maxItems"))), (1, MAX_L4_ROUTES as u64));
    assert_eq!(keys(member(def("l4_route"), "properties")), ["sni", "upstream"]);
    assert_eq!(strs(member(def("l4_route"), "required")), ["sni", "upstream"]);
    // The vhost host grammar is reused for SNI (CANON-6).
    let host = member(member(member(def("vhost"), "properties"), "host"), "pattern");
    assert_eq!(member(member(member(def("l4_route"), "properties"), "sni"), "pattern"), host);
}

#[test]
fn proxy_protocol_mirrors_f8() {
    let p = def("proxy_protocol");
    assert_eq!(keys(member(p, "properties")), ["trusted"]);
    assert_eq!(strs(member(p, "required")), ["trusted"]);
    assert_eq!(member(p, "additionalProperties"), &JsonValue::Bool(false));
    let t = member(member(p, "properties"), "trusted");
    assert_eq!((int(member(t, "minItems")), int(member(t, "maxItems"))), (1, MAX_TRUSTED as u64));
    assert_eq!(member(t, "uniqueItems"), &JsonValue::Bool(true));
}

#[test]
fn tls_block_mirrors_f8() {
    assert!(keys(member(schema(), "properties")).contains(&"tls"));
    let t = def("tls");
    assert_eq!(keys(member(t, "properties")), ["credentials"]);
    let c = member(member(t, "properties"), "credentials");
    assert_eq!((int(member(c, "minItems")), int(member(c, "maxItems"))), (1, MAX_CREDENTIALS as u64));
    let cr = def("credential");
    assert_eq!(keys(member(cr, "properties")), ["id", "kind", "trust_anchor_id", "chain", "key", "listeners"]);
    assert_eq!(strs(member(cr, "required")), ["id", "kind", "chain", "key"]);
    let kinds = [CredentialKind::X509, CredentialKind::MlDsa, CredentialKind::Mtc].map(CredentialKind::as_str);
    assert_eq!(strs(member(member(member(cr, "properties"), "kind"), "enum")), kinds);
}

#[test]
fn engine_families_mirror_f8() {
    let e = member(member(member(def("backend"), "properties"), "engine"), "enum");
    assert_eq!(strs(e), ["sqlite", "postgres", "redis", "valkey", "mariadb", "crdb"]);
}

// ------------------------------------------------------------------------------------------------ absent = today

#[test]
fn absent_phase7_members_mean_the_pre_phase7_config() {
    let c = ok(BASE);
    let e = eff(&c);
    for k in ["\"front\"", "\"proxy_protocol\"", "\"l4\"", "\"tls\""] {
        assert!(!e.contains(k), "{k} printed for a pre-Phase-7 config: {e}");
    }
    let l = &c.listeners()[0];
    assert_eq!((l.proxy_protocol.as_ref(), l.l4.as_ref(), l.front, l.is_l4()), (None, None, Front::Epoll, false));
    assert!(c.tls().is_none());
    // An explicit default hashes like an absent one; a non-default front is part of the meaning.
    assert_eq!(ok(&l0(r#""front":"epoll""#)).config_hash(), c.config_hash());
    let u = ok_rt(&l0(r#""front":"uring""#));
    assert_ne!(u.config_hash(), c.config_hash());
    assert!(eff(&u).contains(r#""front":"uring""#));
    assert_eq!(u.listeners()[0].front, Front::Uring);
    // --print-effective shows the default front; the dump is not hashed.
    let dump = String::from_utf8(c.effective_dump(8)).unwrap();
    assert!(dump.contains(r#""front":"epoll""#), "{dump}");
}

// ------------------------------------------------------------------------------------------------ PROXY v2

accept! {
    proxy_v4_and_v6: proxy(r#""10.0.0.0/8","192.168.1.7/32","2001:db8::/32","fd00::1/128""#);
    proxy_on_l4_listener: l1(r#""proxy_protocol":{"trusted":["10.1.0.0/16"]},"l4":[{"sni":"a.example","upstream":"10.0.0.2:443"}]"#);
    proxy_max_items: proxy(&(0..MAX_TRUSTED).map(|i| format!("\"10.0.{i}.0/24\"")).collect::<Vec<_>>().join(","));
}

#[test]
fn proxy_admits_only_trusted_sources() {
    let c = ok(&proxy(r#""10.0.0.0/8","2001:db8::/32""#));
    let pp = c.listeners()[0].proxy_protocol.as_ref().unwrap();
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    assert!(pp.admits(ip("10.255.0.1")));
    assert!(pp.admits(ip("::ffff:10.1.2.3")), "an IPv4-mapped peer is matched as IPv4");
    assert!(pp.admits(ip("2001:db8:ffff::1")));
    assert!(!pp.admits(ip("11.0.0.1")));
    assert!(!pp.admits(ip("2001:db9::1")));
    assert!(!pp.admits(ip("::ffff:11.0.0.1")));
    assert!(!pp.admits(ip("::a00:1")), "an IPv4-compatible (not mapped) address is IPv6");
    // Listener 1 has no proxy_protocol: no source is ever admitted.
    assert!(c.listeners()[1].proxy_protocol.is_none());
    assert_eq!(pp.trusted().iter().map(Cidr::to_string).collect::<Vec<_>>(), ["10.0.0.0/8", "2001:db8::/32"]);
}

reject! {
    proxy_not_object: l0(r#""proxy_protocol":["10.0.0.0/8"]"#) => Type @ "/listeners/0/proxy_protocol";
    proxy_unknown_member: l0(r#""proxy_protocol":{"trusted":["10.0.0.0/8"],"v1":true}"#) => UnknownField @ "/listeners/0/proxy_protocol/v1";
    proxy_auto_detect_member: l0(r#""proxy_protocol":{"trusted":["10.0.0.0/8"],"auto":true}"#) => UnknownField @ "/listeners/0/proxy_protocol/auto";
    proxy_missing_trusted: l0(r#""proxy_protocol":{}"#) => MissingField @ "/listeners/0/proxy_protocol/trusted";
    proxy_empty: proxy("") => MinItems @ "/listeners/0/proxy_protocol/trusted";
    proxy_too_many: proxy(&(0..=MAX_TRUSTED).map(|i| format!("\"10.0.{i}.0/24\"")).collect::<Vec<_>>().join(",")) => MaxItems @ "/listeners/0/proxy_protocol/trusted";
    proxy_duplicate: proxy(r#""10.0.0.0/8","10.0.0.0/8""#) => UniqueItems @ "/listeners/0/proxy_protocol/trusted";
    proxy_v4_slash0: proxy(r#""0.0.0.0/0""#) => Pattern @ "/listeners/0/proxy_protocol/trusted/0";
    proxy_v6_slash0: proxy(r#""::/0""#) => Pattern @ "/listeners/0/proxy_protocol/trusted/0";
    proxy_host_bits_v4: proxy(r#""10.0.0.1/8""#) => Pattern @ "/listeners/0/proxy_protocol/trusted/0";
    proxy_host_bits_v6: proxy(r#""2001:db8::1/32""#) => Pattern @ "/listeners/0/proxy_protocol/trusted/0";
    proxy_v4_prefix_33: proxy(r#""10.0.0.0/33""#) => Pattern @ "/listeners/0/proxy_protocol/trusted/0";
    proxy_v6_prefix_129: proxy(r#""2001:db8::/129""#) => Pattern @ "/listeners/0/proxy_protocol/trusted/0";
    proxy_prefix_leading_zero: proxy(r#""10.0.0.0/08""#) => Pattern @ "/listeners/0/proxy_protocol/trusted/0";
    proxy_no_prefix: proxy(r#""10.0.0.1""#) => Pattern @ "/listeners/0/proxy_protocol/trusted/0";
    proxy_octet_leading_zero: proxy(r#""010.0.0.0/8""#) => Pattern @ "/listeners/0/proxy_protocol/trusted/0";
    proxy_v6_uppercase: proxy(r#""2001:DB8::/32""#) => Pattern @ "/listeners/0/proxy_protocol/trusted/0";
    proxy_v6_not_canonical: proxy(r#""2001:0db8::/32""#) => Pattern @ "/listeners/0/proxy_protocol/trusted/0";
    proxy_v6_mapped: proxy(r#""::ffff:10.0.0.0/104""#) => Pattern @ "/listeners/0/proxy_protocol/trusted/0";
    proxy_hostname: proxy(r#""lb.internal/32""#) => Pattern @ "/listeners/0/proxy_protocol/trusted/0";
    proxy_not_string: proxy("167772160") => Type @ "/listeners/0/proxy_protocol/trusted/0";
}

// ------------------------------------------------------------------------------------------------ L4

accept! {
    l4_two_routes: l4(r#"{"sni":"a.example","upstream":"10.0.0.2:443"},{"sni":"b.example","upstream":"backend.internal:8443"}"#);
    l4_v6_upstream: l4(r#"{"sni":"a.example","upstream":"[2001:db8::2]:443"}"#);
    l4_port_bounds: l4(r#"{"sni":"a.example","upstream":"h:1"},{"sni":"b.example","upstream":"h:65535"}"#);
    l4_front_uring: l1(r#""l4":[{"sni":"a.example","upstream":"h:443"}],"front":"uring""#);
    l4_max_routes: l4(&(0..MAX_L4_ROUTES).map(|i| format!(r#"{{"sni":"s{i}.example","upstream":"h:443"}}"#)).collect::<Vec<_>>().join(","));
}

#[test]
fn l4_listener_is_typed_and_has_no_default_upstream() {
    let c =
        ok(&l4(r#"{"sni":"a.example","upstream":"10.0.0.2:443"},{"sni":"b.example","upstream":"[2001:db8::2]:8443"}"#));
    let l = &c.listeners()[1];
    assert!(l.is_l4() && l.alpn.is_none());
    let r = l.l4.as_ref().unwrap();
    assert_eq!((r[0].sni.as_str(), r[0].upstream_host.as_str(), r[0].upstream_port), ("a.example", "10.0.0.2", 443));
    assert_eq!(r[1].upstream(), "[2001:db8::2]:8443");
    // The other listener is still HTTP.
    assert!(!c.listeners()[0].is_l4());
}

reject! {
    l4_with_alpn: l0(r#""l4":[{"sni":"a.example","upstream":"h:443"}]"#) => Forbidden @ "/listeners/0/alpn";
    l4_empty: l4("") => MinItems @ "/listeners/1/l4";
    l4_too_many: l4(&(0..=MAX_L4_ROUTES).map(|i| format!(r#"{{"sni":"s{i}.example","upstream":"h:443"}}"#)).collect::<Vec<_>>().join(",")) => MaxItems @ "/listeners/1/l4";
    l4_not_array: l1(r#""l4":{"sni":"a.example","upstream":"h:443"}"#) => Type @ "/listeners/1/l4";
    l4_duplicate_sni: l4(r#"{"sni":"a.example","upstream":"h:443"},{"sni":"a.example","upstream":"g:443"}"#) => DuplicateSni @ "/listeners/1/l4/1/sni";
    l4_wildcard_sni: l4(r#"{"sni":"*.example","upstream":"h:443"}"#) => Pattern @ "/listeners/1/l4/0/sni";
    l4_empty_sni: l4(r#"{"sni":"","upstream":"h:443"}"#) => Pattern @ "/listeners/1/l4/0/sni";
    l4_uppercase_sni: l4(r#"{"sni":"A.example","upstream":"h:443"}"#) => Pattern @ "/listeners/1/l4/0/sni";
    l4_default_member: l4(r#"{"sni":"a.example","upstream":"h:443","default":true}"#) => UnknownField @ "/listeners/1/l4/0/default";
    l4_missing_upstream: l4(r#"{"sni":"a.example"}"#) => MissingField @ "/listeners/1/l4/0/upstream";
    l4_missing_sni: l4(r#"{"upstream":"h:443"}"#) => MissingField @ "/listeners/1/l4/0/sni";
    l4_port_zero: l4(r#"{"sni":"a.example","upstream":"h:0"}"#) => Pattern @ "/listeners/1/l4/0/upstream";
    l4_port_65536: l4(r#"{"sni":"a.example","upstream":"h:65536"}"#) => Pattern @ "/listeners/1/l4/0/upstream";
    l4_port_leading_zero: l4(r#"{"sni":"a.example","upstream":"h:0443"}"#) => Pattern @ "/listeners/1/l4/0/upstream";
    l4_no_port: l4(r#"{"sni":"a.example","upstream":"h"}"#) => Pattern @ "/listeners/1/l4/0/upstream";
    l4_bare_v6: l4(r#"{"sni":"a.example","upstream":"2001:db8::2:443"}"#) => Pattern @ "/listeners/1/l4/0/upstream";
    l4_v6_not_canonical: l4(r#"{"sni":"a.example","upstream":"[2001:0db8::2]:443"}"#) => Pattern @ "/listeners/1/l4/0/upstream";
    l4_url_upstream: l4(r#"{"sni":"a.example","upstream":"https://h:443"}"#) => Pattern @ "/listeners/1/l4/0/upstream";
    front_unknown: l0(r#""front":"io_uring""#) => Enum @ "/listeners/0/front";
    front_not_string: l0(r#""front":1"#) => Enum @ "/listeners/0/front";
}

// ------------------------------------------------------------------------------------------------ tls

#[test]
fn tls_credentials_typed_and_scoped() {
    let c = ok_rt(&tls(&format!("{X509},{MTC},{MLDSA}")));
    let t = c.tls().unwrap();
    let m = t.credential("web-mtc").unwrap();
    assert_eq!(m.kind(), CredentialKind::Mtc);
    assert_eq!(m.trust_anchor_id().unwrap().to_string(), "32473.1");
    assert_eq!(m.chain(), &SecretRef::Path("/etc/monban/mtc.bin".into()));
    assert_eq!(t.credential("web-x509").unwrap().key(), &SecretRef::Cred("web.key".into()));
    // SEL-2: the mldsa credential is never a candidate on the P-PUBLIC-WEB listener; scope is respected.
    let ids = |l: &str| t.candidates(&c, l).iter().map(|c| c.id().to_owned()).collect::<Vec<_>>();
    assert_eq!(ids("web"), ["web-x509", "web-mtc"]);
    assert_eq!(ids("priv"), ["web-x509", "web-mtc", "hop"]);
    // SEL-3: an unknown listener has no candidates (never another listener's credential).
    assert!(ids("nope").is_empty());
}

#[test]
fn mldsa_without_scope_is_still_never_a_public_web_candidate() {
    let c = ok(&tls(r#"{"id":"hop","kind":"mldsa","chain":"cred:a","key":"cred:b"}"#));
    let t = c.tls().unwrap();
    assert!(t.candidates(&c, "web").is_empty());
    assert_eq!(t.candidates(&c, "priv").len(), 1);
    assert_eq!(c.listeners()[0].profile, Profile::PublicWeb);
}

#[test]
fn l4_listener_has_no_tls_candidates() {
    let doc = l4(r#"{"sni":"a.example","upstream":"h:443"}"#);
    let b = doc.strip_suffix('}').unwrap();
    let c = ok(&format!(r#"{b},"tls":{{"credentials":[{X509}]}}}}"#));
    assert!(c.tls().unwrap().candidates(&c, "priv").is_empty());
    assert_eq!(c.tls().unwrap().candidates(&c, "web").len(), 1);
}

#[test]
fn trust_anchor_id_wire_form() {
    let w = |s: &str| TrustAnchorId::parse(s).unwrap().wire();
    assert_eq!(w("32473.1"), [0x81, 0xFD, 0x59, 0x01]);
    assert_eq!(w("0"), [0x00]);
    assert_eq!(w("127.128"), [0x7F, 0x81, 0x00]);
    assert_eq!(w("4294967295"), [0x8F, 0xFF, 0xFF, 0xFF, 0x7F]);
    let max = vec!["4294967295"; 32].join(".");
    assert_eq!(w(&max).len(), 160);
    for bad in ["", ".", "1.", ".1", "01", "4294967296", "1..2", "-1", "1.a", &vec!["1"; 33].join(".")] {
        assert!(TrustAnchorId::parse(bad).is_none(), "{bad:?}");
    }
}

reject! {
    tls_not_object: format!("{},\"tls\":[]}}", BASE.strip_suffix('}').unwrap()) => Type @ "/tls";
    tls_unknown_member: format!("{},\"tls\":{{\"credentials\":[{X509}],\"default\":\"web-x509\"}}}}", BASE.strip_suffix('}').unwrap()) => UnknownField @ "/tls/default";
    tls_missing_credentials: format!("{},\"tls\":{{}}}}", BASE.strip_suffix('}').unwrap()) => MissingField @ "/tls/credentials";
    tls_empty: tls("") => MinItems @ "/tls/credentials";
    tls_too_many: tls(&(0..=MAX_CREDENTIALS).map(|i| format!(r#"{{"id":"c{i}","kind":"x509","chain":"cred:a","key":"cred:b"}}"#)).collect::<Vec<_>>().join(",")) => MaxItems @ "/tls/credentials";
    cred_unknown_member: tls(r#"{"id":"a","kind":"x509","chain":"cred:a","key":"cred:b","pem":"x"}"#) => UnknownField @ "/tls/credentials/0/pem";
    cred_missing_key: tls(r#"{"id":"a","kind":"x509","chain":"cred:a"}"#) => MissingField @ "/tls/credentials/0/key";
    cred_bad_id: tls(r#"{"id":"A","kind":"x509","chain":"cred:a","key":"cred:b"}"#) => Pattern @ "/tls/credentials/0/id";
    cred_bad_kind: tls(r#"{"id":"a","kind":"rsa","chain":"cred:a","key":"cred:b"}"#) => Enum @ "/tls/credentials/0/kind";
    cred_inline_key: tls(r#"{"id":"a","kind":"x509","chain":"cred:a","key":"-----BEGIN PRIVATE KEY-----"}"#) => Pattern @ "/tls/credentials/0/key";
    cred_env_ref: tls(r#"{"id":"a","kind":"x509","chain":"env:CHAIN","key":"cred:b"}"#) => Pattern @ "/tls/credentials/0/chain";
    cred_relative_path: tls(r#"{"id":"a","kind":"x509","chain":"path:etc/x.pem","key":"cred:b"}"#) => Pattern @ "/tls/credentials/0/chain";
    cred_duplicate_id: tls(&format!("{X509},{X509}")) => DuplicateCredential @ "/tls/credentials/1/id";
    // SEL-1: an mtc credential needs its trust anchor; no other kind may carry one.
    mtc_without_tai: tls(r#"{"id":"m","kind":"mtc","chain":"cred:a","key":"cred:b"}"#) => MissingField @ "/tls/credentials/0/trust_anchor_id";
    x509_with_tai: tls(r#"{"id":"a","kind":"x509","trust_anchor_id":"1.2","chain":"cred:a","key":"cred:b"}"#) => Forbidden @ "/tls/credentials/0/trust_anchor_id";
    mldsa_with_tai: tls(r#"{"id":"a","kind":"mldsa","trust_anchor_id":"1.2","chain":"cred:a","key":"cred:b","listeners":["priv"]}"#) => Forbidden @ "/tls/credentials/0/trust_anchor_id";
    tai_bad: tls(r#"{"id":"m","kind":"mtc","trust_anchor_id":"1.02","chain":"cred:a","key":"cred:b"}"#) => Pattern @ "/tls/credentials/0/trust_anchor_id";
    tai_overflow: tls(r#"{"id":"m","kind":"mtc","trust_anchor_id":"4294967296","chain":"cred:a","key":"cred:b"}"#) => Pattern @ "/tls/credentials/0/trust_anchor_id";
    tai_duplicate: tls(&format!("{MTC},{}", MTC.replace("web-mtc", "web-mtc2"))) => DuplicateTrustAnchor @ "/tls/credentials/1/trust_anchor_id";
    // SEL-2: never an mldsa credential scoped to a P-PUBLIC-WEB listener.
    mldsa_on_public_web: tls(r#"{"id":"hop","kind":"mldsa","chain":"cred:a","key":"cred:b","listeners":["priv","web"]}"#) => CredentialScope @ "/tls/credentials/0/listeners/1";
    // SEL-3: scope names declared HTTP listeners only.
    cred_unknown_listener: tls(r#"{"id":"a","kind":"x509","chain":"cred:a","key":"cred:b","listeners":["other"]}"#) => UnknownListener @ "/tls/credentials/0/listeners/0";
    cred_listeners_empty: tls(r#"{"id":"a","kind":"x509","chain":"cred:a","key":"cred:b","listeners":[]}"#) => MinItems @ "/tls/credentials/0/listeners";
    cred_listeners_dup: tls(r#"{"id":"a","kind":"x509","chain":"cred:a","key":"cred:b","listeners":["web","web"]}"#) => UniqueItems @ "/tls/credentials/0/listeners";
    cred_on_l4_listener: {
        let doc = l4(r#"{"sni":"a.example","upstream":"h:443"}"#);
        format!(r#"{},"tls":{{"credentials":[{{"id":"a","kind":"x509","chain":"cred:a","key":"cred:b","listeners":["priv"]}}]}}}}"#, doc.strip_suffix('}').unwrap())
    } => CredentialScope @ "/tls/credentials/0/listeners/0";
}

// ------------------------------------------------------------------------------------------------ adapter families

fn backend(engine: &str, pin: &str) -> String {
    let b = BASE.strip_suffix('}').unwrap();
    format!(r#"{b},"data":{{"backends":[{{"id":"m","engine":"{engine}","dsn_ref":"env:DSN","pin":"{pin}"}}]}}}}"#)
}

#[test]
fn adapter_families_are_accepted_by_the_schema_layer_and_need_their_own_pin() {
    // The embedded catalogue has no mariadb/crdb pin yet (P7-oracle-adapters-001 adds them): the family name is
    // accepted (the error is about the pin, not the enum) and a golden pin never stands in for it.
    if adapter_pins().is_empty() {
        rej(&backend("mariadb", "pg18"), K::PinEngineMismatch, "/data/backends/0/pin");
        rej(&backend("crdb", "pg18"), K::PinEngineMismatch, "/data/backends/0/pin");
        rej(&backend("crdb", "crdb254"), K::UnknownPin, "/data/backends/0/pin");
    } else {
        for p in adapter_pins() {
            let c = ok_rt(&backend(p.family.as_str(), &p.name));
            assert_eq!(c.data().unwrap().adapters()[0].family, p.family);
            assert!(c.data().unwrap().backends().is_empty());
        }
    }
    rej(&backend("mysql", "pg18"), K::Enum, "/data/backends/0/engine");
}

// ------------------------------------------------------------------------------------------------ everything

#[test]
fn full_phase7_config_round_trips() {
    let doc = format!(
        r#"{{"v":1,
 "listeners":[{{"name":"web","bind":"0.0.0.0:443","profile":"P-PUBLIC-WEB","alpn":["h2"],"proxy_protocol":{{"trusted":["10.0.0.0/8"]}},"front":"uring"}},
   {{"name":"edge","bind":"0.0.0.0:8443","profile":"P-PUBLIC-WEB","l4":[{{"sni":"a.example","upstream":"10.0.0.2:443"}}],"proxy_protocol":{{"trusted":["fd00::/8"]}}}},
   {{"name":"priv","bind":"10.0.0.1:9443","profile":"P-PQ-REQUIRED"}}],
 "vhosts":[{{"host":"example.com","routes":[{{"id":1,"path":"/","to":{{"upstream":"app"}},"authz":"api"}}]}}],
 "tls":{{"credentials":[{X509},{MTC},{MLDSA}]}}}}"#
    );
    let c = ok_rt(&doc);
    assert_eq!(c.listeners().len(), 3);
    let e = eff(&c);
    for k in ["\"proxy_protocol\"", "\"l4\"", "\"front\":\"uring\"", "\"tls\"", "\"trust_anchor_id\":\"32473.1\""] {
        assert!(e.contains(k), "{k} missing from {e}");
    }
}

// ------------------------------------------------------------------------------------------------ admission

fn adm(body: &str) -> String {
    let b = BASE.strip_suffix('}').unwrap();
    format!(r#"{b},"admission":{{{body}}}}}"#)
}

#[test]
fn admission_mirrors_f8_and_defaults_are_the_pre_phase7_constants() {
    let a = def("admission");
    assert_eq!(
        keys(member(a, "properties")),
        ["per_ip", "per_ip_store", "max_conns", "per_prefix_conns", "concurrency"]
    );
    let props = member(a, "properties");
    for (name, lo, hi, d) in Admission::BOUNDS {
        let p = member(props, name);
        assert_eq!(
            (int(member(p, "minimum")), int(member(p, "maximum")), int(member(p, "default"))),
            (*lo, *hi, *d),
            "{name}"
        );
    }
    let per_ip = member(member(props, "per_ip"), "properties");
    let r = member(per_ip, "rate_per_s");
    let b = member(per_ip, "burst");
    assert_eq!((int(member(r, "minimum")), int(member(r, "maximum"))), RateLimit::RATE_BOUNDS);
    assert_eq!((int(member(b, "minimum")), int(member(b, "maximum"))), RateLimit::BURST_BOUNDS);
    assert_eq!((int(member(r, "default")), int(member(b, "default"))), (1000, 2000));
    // The constants monban-bin `admission_config()` hard-coded before Phase 7: Gcra::new(1_000_000, 2_000), s1_store
    // 65_536, max_conns 16_384, prefix_cap 4096, limit 4096.
    let d = Admission::default();
    assert_eq!((d.per_ip.emission_interval_ns(), d.per_ip.burst), (1_000_000, 2000));
    assert_eq!((d.per_ip_store, d.max_conns, d.per_prefix_conns, d.concurrency), (65_536, 16_384, 4096, 4096));
    let c = ok(BASE);
    assert_eq!(c.admission(), &d);
    assert!(!eff(&c).contains("\"admission\""));
    // Explicit defaults hash like absent; the dump shows the block.
    assert_eq!(
        ok(&adm(r#""per_ip":{"rate_per_s":1000,"burst":2000},"max_conns":16384"#)).config_hash(),
        c.config_hash()
    );
    assert_eq!(ok(&adm("")).config_hash(), c.config_hash());
    assert!(String::from_utf8(c.effective_dump(8)).unwrap().contains("\"admission\""));
}

#[test]
fn admission_overrides_parse_and_round_trip() {
    let c = ok_rt(&adm(r#""per_ip":{"rate_per_s":200000,"burst":400000},"per_ip_store":1024,"concurrency":65536"#));
    let a = c.admission();
    assert_eq!((a.per_ip.rate_per_s, a.per_ip.burst, a.per_ip.emission_interval_ns()), (200_000, 400_000, 5000));
    assert_eq!((a.per_ip_store, a.concurrency, a.max_conns), (1024, 65_536, 16_384));
    assert_ne!(c.config_hash(), ok(BASE).config_hash());
    // Only the rate given: burst keeps its default when that is still >= rate.
    assert_eq!(ok(&adm(r#""per_ip":{"rate_per_s":2000}"#)).admission().per_ip.burst, 2000);
    assert_eq!(
        ok_rt(&adm(r#""per_ip":{"rate_per_s":1000000,"burst":1000000}"#)).admission().per_ip.emission_interval_ns(),
        1000
    );
    assert_eq!(
        ok_rt(&adm(r#""per_ip":{"rate_per_s":1,"burst":1}"#)).admission().per_ip.emission_interval_ns(),
        1_000_000_000
    );
}

reject! {
    adm_not_object: adm("").replace(r#""admission":{}"#, r#""admission":[]"#) => Type @ "/admission";
    adm_unknown: adm(r#""per_user":{}"#) => UnknownField @ "/admission/per_user";
    adm_per_ip_unknown: adm(r#""per_ip":{"rate":5}"#) => UnknownField @ "/admission/per_ip/rate";
    adm_rate_zero: adm(r#""per_ip":{"rate_per_s":0,"burst":10}"#) => Minimum @ "/admission/per_ip/rate_per_s";
    adm_rate_over: adm(r#""per_ip":{"rate_per_s":1000001,"burst":10000000}"#) => Maximum @ "/admission/per_ip/rate_per_s";
    adm_burst_zero: adm(r#""per_ip":{"rate_per_s":1,"burst":0}"#) => Minimum @ "/admission/per_ip/burst";
    adm_burst_over: adm(r#""per_ip":{"rate_per_s":1,"burst":10000001}"#) => Maximum @ "/admission/per_ip/burst";
    adm_burst_below_rate: adm(r#""per_ip":{"rate_per_s":500,"burst":499}"#) => BurstBelowRate @ "/admission/per_ip/burst";
    adm_rate_only_above_default_burst: adm(r#""per_ip":{"rate_per_s":5000}"#) => BurstBelowRate @ "/admission/per_ip/burst";
    adm_store_small: adm(r#""per_ip_store":1023"#) => Minimum @ "/admission/per_ip_store";
    adm_store_big: adm(r#""per_ip_store":1048577"#) => Maximum @ "/admission/per_ip_store";
    adm_conns_zero: adm(r#""max_conns":0"#) => Minimum @ "/admission/max_conns";
    adm_prefix_big: adm(r#""per_prefix_conns":1048577"#) => Maximum @ "/admission/per_prefix_conns";
    adm_concurrency_zero: adm(r#""concurrency":0"#) => Minimum @ "/admission/concurrency";
    adm_not_integer: adm(r#""max_conns":"10""#) => Type @ "/admission/max_conns";
}
