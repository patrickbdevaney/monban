//! MCP listener gate request classification (monban-agent `Gate::check` / `Gate::complete`), sans-I/O.
//!
//! The input is a script: an authorizer decision list, then up to 8 operations, each either a request (method, path,
//! authority, Origin / Sec-Fetch-Site / Cookie, Content-Type, a bearer JWT minted by the harness or arbitrary bytes,
//! a JSON-RPC body from a template, mutated or arbitrary, the MCP headers and a session id), the completion of the
//! oldest pending forward with scripted upstream replies, or a clock step. Requests go to three gates built from one
//! config: A and B with the same scripted `Authorizer`, and C with `DenyAll`. C sees a request only when A reached
//! its PDP, answered 503 or got a DELETE, because every other request stops at the same stateless checks on both
//! (this keeps the target fast). Properties (from gate.rs and its tests; nothing the code does not claim):
//! - INV-FAILCLOSED: a reject is a `Reply`, so it has no upstream call; a `Forward` only after exactly one
//!   authorizer call that answered Allow, with the PDP request built from the verified subject, the route path, the
//!   era, the method and the tool; an authorizer Deny/Error is always 403 / -32001; `DenyAll` never forwards, and
//!   answers 403 / -32001 to every stateless request A forwarded; a reject is never 200 (admission I7);
//! - the documented check order: no route 404, Host 421, Origin / ambient credential 403, metadata GET only,
//!   OPTIONS 204, other methods 405, Content-Type 415, bearer 401 (with the RFC 9728 challenge), empty body 400;
//! - a forward needs a token minted with the right key and `alg`, live (`exp`, `nbf`) and carrying the route's
//!   resource as audience (RFC 8707); forged, tampered, expired or wrong-audience tokens never forward;
//! - 2026-07-28 forwards have `Mcp-Method` = `method`, `Mcp-Name` = `params.name` for tools/call, `_meta`
//!   protocolVersion, no session id and a method of that era; 2025-11-25 forwards other than initialize carry a
//!   session id this gate issued for exactly (subject, route) and not deleted; a missing version header forwards
//!   only initialize; a DELETE succeeds only for such a session;
//! - forward plans: only the route's upstream URLs, the gate's own credential exactly once, no client
//!   Cookie / API key / session id, the era header, a canonical body (CANON-4); multiplexed tools/call strips a
//!   configured prefix, tools/list fans out to every upstream;
//! - `complete`: wrong reply count or a failed fetch is 502; 200 only for a valid JSON-RPC response to the same id;
//!   a session id is minted only by a successful 2025-11-25 initialize; merged tool lists are prefixed and
//!   case-fold unique; CORS only ever echoes an allowlisted Origin;
//! - counters, and determinism: A and B give identical verdicts, plans and replies (session ids compared by
//!   issue order, since the gate draws them from the DRBG).
#![no_main]

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};

use monban_agent::authz::pdp_request;
use monban_agent::gate::{FORBIDDEN, META_PV, PRM_PREFIX, V_LEGACY, V_MODERN};
use monban_agent::jwt::mint_hs256;
use monban_agent::{
    AgentConfig, Authorizer, DenyAll, Forward, Gate, HttpRequest, Method, Response, Target, UpstreamReply, Verdict,
    b64, emit,
};
use monban_authz::Decision;
use monban_authz::pdp::PdpRequest;
use monban_canon::{JsonValue, canon_json, canon_media_type, canon_origin, parse_json};
use monban_fuzz::{ALNUM, LOWER, Unstructured, byte, bytes, flag, selftest, string_from};
use libfuzzer_sys::fuzz_target;

const SECRET: &[u8] = b"monban-fuzz-mcp-gate-secret-NOT-FOR-PRODUCTION";
const ISS: &str = "https://issuer.fuzz.test";
const NOW: u64 = 1_800_000_000;
const CRED: &str = "Bearer gw";
const HOSTS: [&str; 2] = ["127.0.0.1:7000", "localhost:7000"];
const ORIGINS: [&str; 2] = ["http://127.0.0.1:7000", "http://localhost:7000"];
const PATHS: [&str; 3] = ["/mcp", "/mcp2", "/mcp-multi"];
const LEGACY_METHODS: &[&str] = &[
    "initialize",
    "notifications/initialized",
    "ping",
    "tools/list",
    "tools/call",
    "resources/list",
    "prompts/list",
    "notifications/cancelled",
];
const MODERN_METHODS: &[&str] =
    &["tools/list", "tools/call", "resources/list", "prompts/list", "notifications/cancelled"];
const CONFIG: &[u8] = br#"{"v":1,"listen":"127.0.0.1:7000","hosts":["127.0.0.1:7000","localhost:7000"],
 "origins":["http://127.0.0.1:7000","http://localhost:7000"],
 "auth":{"issuer":"https://issuer.fuzz.test","hs256_secret_file":"/dev/null"},
 "pdp":{"socket":"/nonexistent","deadline_ms":200},
 "sessions":{"max":6,"per_principal":2,"idle_ttl_s":60},
 "routes":[{"path":"/mcp","resource":"http://127.0.0.1:7000/mcp","upstreams":[{"prefix":"","url":"http://127.0.0.1:9/"}]},
  {"path":"/mcp2","resource":"http://127.0.0.1:7000/mcp2","upstreams":[{"prefix":"","url":"http://127.0.0.1:9/two"}]},
  {"path":"/mcp-multi","resource":"http://127.0.0.1:7000/mcp-multi","upstreams":[{"prefix":"a__","url":"http://127.0.0.1:9/a"},{"prefix":"b__","url":"http://127.0.0.1:9/b"}]}]}"#;

/// The config, parsed once (parsing is pure; every input still gets fresh gates with empty session tables).
fn config() -> &'static AgentConfig {
    static CFG: OnceLock<AgentConfig> = OnceLock::new();
    CFG.get_or_init(|| match AgentConfig::parse(CONFIG) {
        Ok(c) => c,
        Err(e) => panic!("harness config refused: {e}"),
    })
}

/// `mint_hs256` memoized (deterministic: same key, header and claims give the same token).
fn mint_cached(key: &[u8], header: &str, claims: &str) -> String {
    static CACHE: OnceLock<Mutex<HashMap<(Vec<u8>, String, String), String>>> = OnceLock::new();
    let k = (key.to_vec(), header.to_string(), claims.to_string());
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut m) = cache.lock() else { return mint_hs256(key, header, claims) };
    m.entry(k).or_insert_with(|| mint_hs256(key, header, claims)).clone()
}

fn resource(route: usize) -> String {
    format!("http://127.0.0.1:7000{}", PATHS.get(route).copied().unwrap_or("/mcp"))
}

fn upstreams(route: usize) -> &'static [(&'static str, &'static str)] {
    match route {
        0 => &[("", "http://127.0.0.1:9/")],
        1 => &[("", "http://127.0.0.1:9/two")],
        _ => &[("a__", "http://127.0.0.1:9/a"), ("b__", "http://127.0.0.1:9/b")],
    }
}

fn model_target(path: &[u8]) -> Option<Target> {
    PATHS.iter().enumerate().find_map(|(i, p)| {
        if p.as_bytes() == path {
            Some(Target::Mcp(i))
        } else if format!("{PRM_PREFIX}{p}").as_bytes() == path {
            Some(Target::Metadata(i))
        } else {
            None
        }
    })
}

// ---------------------------------------------------------------- scripted authorizer

#[derive(Default)]
struct AuthLog {
    script: Vec<Decision>,
    next: usize,
    calls: Vec<(PdpRequest, Decision)>,
}

struct Scripted(Arc<Mutex<AuthLog>>);

impl Authorizer for Scripted {
    fn decide(&self, r: &PdpRequest) -> Decision {
        let Ok(mut l) = self.0.lock() else { return Decision::Error };
        let d = match l.script.len() {
            0 => Decision::Allow,
            n => l.script.get(l.next % n).copied().unwrap_or(Decision::Error),
        };
        l.next += 1;
        l.calls.push((r.clone(), d));
        d
    }
}

fn log_len(l: &Arc<Mutex<AuthLog>>) -> usize {
    l.lock().map(|g| g.calls.len()).unwrap_or(0)
}

fn log_get(l: &Arc<Mutex<AuthLog>>, i: usize) -> Option<(PdpRequest, Decision)> {
    l.lock().ok().and_then(|g| g.calls.get(i).cloned())
}

// ---------------------------------------------------------------- per-gate session model

struct Issued {
    sid: String,
    sub: String,
    route: usize,
    deleted: bool,
}

struct Side {
    gate: Gate,
    log: Arc<Mutex<AuthLog>>,
    issued: Vec<Issued>,
}

impl Side {
    fn new(script: &[Decision]) -> Self {
        let log = Arc::new(Mutex::new(AuthLog { script: script.to_vec(), ..AuthLog::default() }));
        let Ok(gate) = Gate::new(config(), SECRET, Some(CRED.into()), Box::new(Scripted(log.clone()))) else {
            panic!("harness gate refused")
        };
        Self { gate, log, issued: Vec::new() }
    }

    /// A live (issued, not deleted) session with this id.
    fn live(&self, sid: &[u8]) -> Option<&Issued> {
        self.issued.iter().find(|s| s.sid.as_bytes() == sid && !s.deleted)
    }

    /// Replace session ids by their issue index (the DRBG makes the raw ids differ between gates).
    fn norm(&self, r: &Response) -> Response {
        let mut r = r.clone();
        for (k, v) in r.headers.iter_mut() {
            if k == "mcp-session-id" {
                let i = self.issued.iter().position(|s| s.sid == *v);
                *v = format!("#{i:?}");
            }
        }
        r
    }
}

// ---------------------------------------------------------------- request model

#[derive(Clone)]
enum SessRef {
    None,
    Issued(usize),
    Mangled(usize),
    Lit(Vec<u8>),
}

struct Tok {
    sub: &'static str,
    /// Minted with the right key, `alg` HS256, issuer and scheme (validity still depends on time and audience).
    well_formed: bool,
    auds: Vec<String>,
    exp: u64,
    nbf: Option<u64>,
}

impl Tok {
    fn valid_for(&self, route: usize, now: u64) -> bool {
        self.well_formed
            && self.exp > now
            && self.nbf.is_none_or(|n| n <= now)
            && self.auds.iter().any(|a| *a == resource(route))
    }
}

struct Req {
    method: Method,
    authority: Vec<u8>,
    path: Vec<u8>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    sess: SessRef,
    body: Vec<u8>,
    tok: Tok,
}

impl Req {
    fn headers_for(&self, side: &Side) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut h = self.headers.clone();
        let sid = match &self.sess {
            SessRef::None => None,
            SessRef::Issued(k) => Some(issued_sid(side, *k).into_bytes()),
            SessRef::Mangled(k) => {
                let mut s = issued_sid(side, *k).into_bytes();
                if let Some(c) = s.first_mut() {
                    *c = if *c == b'0' { b'1' } else { b'0' };
                }
                Some(s)
            }
            SessRef::Lit(v) => Some(v.clone()),
        };
        if let Some(s) = sid {
            h.push((b"mcp-session-id".to_vec(), s));
        }
        h
    }
}

fn issued_sid(side: &Side, k: usize) -> String {
    match side.issued.len() {
        0 => "0".repeat(32),
        n => side.issued.get(k % n).map(|s| s.sid.clone()).unwrap_or_default(),
    }
}

fn hdr<'a>(h: &'a [(Vec<u8>, Vec<u8>)], name: &[u8]) -> Option<&'a [u8]> {
    h.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_slice())
}

/// Header text with the MCP base64 sentinel decoded (`None` if it is not UTF-8 / a valid sentinel).
fn header_text(v: &[u8]) -> Option<String> {
    if let Some(inner) = v.strip_prefix(b"=?base64?").and_then(|r| r.strip_suffix(b"?=")) {
        return String::from_utf8(b64::decode_std(inner)?).ok();
    }
    String::from_utf8(v.to_vec()).ok()
}

fn sentinel(s: &str) -> Vec<u8> {
    format!("=?base64?{}?=", b64::encode_std(s.as_bytes())).into_bytes()
}

const METHODS: [Method; 12] = [
    Method::Post,
    Method::Post,
    Method::Post,
    Method::Post,
    Method::Post,
    Method::Options,
    Method::Delete,
    Method::Get,
    Method::Head,
    Method::Put,
    Method::Patch,
    Method::Other,
];

/// A JSON-RPC body from a template. Returns (body, method text for the MCP headers, tools/call name text).
fn template(u: &mut Unstructured<'_>) -> (String, String, String) {
    let meth = match byte(u) % 10 {
        0 => "tools/call".to_string(),
        1 => "tools/list".into(),
        2 => "initialize".into(),
        3 => "ping".into(),
        4 => "notifications/initialized".into(),
        5 => "notifications/cancelled".into(),
        6 => "resources/list".into(),
        7 => "prompts/list".into(),
        8 => "TOOLS/CALL".into(),
        _ => string_from(u, 16, b"abcdefghijklmnopqrstuvwxyz/"),
    };
    let id = match byte(u) % 6 {
        0 | 1 => Some(byte(u).to_string()),
        2 => Some("\"r1\"".into()),
        3 => None,
        4 => Some("1.5".into()),
        _ => Some("null".into()),
    };
    let (name, name_text) = match byte(u) % 8 {
        0 | 1 => (Some("\"echo\"".to_string()), "echo".to_string()),
        2 => (Some("\"a__echo\"".into()), "a__echo".into()),
        3 => (Some("\"b__echo\"".into()), "b__echo".into()),
        4 => (Some("\"c__echo\"".into()), "c__echo".into()),
        5 => (None, "echo".into()),
        6 => (Some("1".into()), "1".into()),
        _ => {
            let s = string_from(u, 12, ALNUM);
            (Some(format!("\"{s}\"")), s)
        }
    };
    let meta = match byte(u) % 7 {
        0 | 1 => None,
        2 | 3 => Some(format!("\"{V_MODERN}\"")),
        4 => Some(format!("\"{V_LEGACY}\"")),
        5 => Some("\"2099-01-01\"".into()),
        _ => Some("5".into()),
    };
    let pver = match byte(u) % 4 {
        0 => None,
        1 | 2 => Some(V_LEGACY),
        _ => Some("2024-11-05"),
    };
    let shape = byte(u) % 8;
    let pform = byte(u) % 6;
    let mut params: Vec<String> = Vec::new();
    if let Some(n) = &name {
        params.push(format!("\"name\":{n}"));
        params.push("\"arguments\":{\"x\":\"m\"}".into());
    }
    if let Some(p) = pver {
        params.push(format!("\"protocolVersion\":\"{p}\""));
    }
    if let Some(m) = meta {
        params.push(format!("\"_meta\":{{\"{META_PV}\":{m}}}"));
    }
    let mut members = vec![format!("\"jsonrpc\":\"{}\"", if shape == 6 { "1.0" } else { "2.0" })];
    if let Some(i) = id {
        members.push(format!("\"id\":{i}"));
    }
    members.push(format!("\"method\":\"{meth}\""));
    if pform == 5 {
        members.push("\"params\":[1]".into());
    } else if !params.is_empty() || pform == 4 {
        members.push(format!("\"params\":{{{}}}", params.join(",")));
    }
    if shape == 7 {
        members.push("\"Method\":\"x\"".into());
    }
    (format!("{{{}}}", members.join(",")), meth, name_text)
}

fn mint(u: &mut Unstructured<'_>, route_hint: usize) -> (Option<Vec<u8>>, Tok) {
    let kind = byte(u) % 14;
    let sub = ["alice", "bob", "carol"].get(usize::from(byte(u) % 3)).copied().unwrap_or("alice");
    let (auds, aud_json) = match byte(u) % 6 {
        0 | 1 => (vec![resource(route_hint)], format!("\"{}\"", resource(route_hint))),
        2 => (vec![resource(1)], format!("\"{}\"", resource(1))),
        3 => (vec!["x".to_string(), resource(route_hint)], format!("[\"x\",\"{}\"]", resource(route_hint))),
        4 => (vec!["http://other.example/mcp".into()], "\"http://other.example/mcp\"".into()),
        _ => (vec![resource(2)], format!("\"{}\"", resource(2))),
    };
    let exp = if kind == 4 { NOW - 1 } else { NOW + 3600 };
    let nbf = (kind == 5).then_some(NOW + 600);
    let mut claims = format!(r#"{{"sub":"{sub}","iss":"{ISS}","iat":{NOW},"exp":{exp},"aud":{aud_json}"#);
    if let Some(n) = nbf {
        claims.push_str(&format!(r#","nbf":{n}"#));
    }
    claims.push('}');
    let header = match kind {
        7 => r#"{"alg":"none","typ":"JWT"}"#,
        8 => r#"{"alg":"HS512","typ":"JWT"}"#,
        13 => r#"{"alg":"HS256","crit":["x"]}"#,
        _ => r#"{"alg":"HS256","typ":"JWT"}"#,
    };
    let key: &[u8] = if kind == 6 { b"not-the-key-not-the-key-not-the-key!!" } else { SECRET };
    let t = mint_cached(key, header, &claims);
    let value = match kind {
        9 => Some(format!("bearer {t}").into_bytes()),
        10 => {
            let mut t = t.into_bytes();
            if let Some(c) = t.last_mut() {
                *c = if *c == b'A' { b'B' } else { b'A' };
            }
            let mut v = b"Bearer ".to_vec();
            v.extend_from_slice(&t);
            Some(v)
        }
        11 => None,
        12 => Some(bytes(u, 64).to_vec()),
        _ => Some(format!("Bearer {t}").into_bytes()),
    };
    let well_formed = matches!(kind, 0..=5 | 9);
    (value, Tok { sub, well_formed, auds, exp, nbf })
}

fn parse_req(u: &mut Unstructured<'_>) -> Req {
    let method = METHODS.get(usize::from(byte(u) % 12)).copied().unwrap_or(Method::Post);
    let path: Vec<u8> = match byte(u) % 8 {
        0 => b"/mcp".to_vec(),
        1 => b"/mcp2".to_vec(),
        2 => b"/mcp-multi".to_vec(),
        3 => format!("{PRM_PREFIX}/mcp").into_bytes(),
        4 => format!("{PRM_PREFIX}/mcp-multi").into_bytes(),
        5 => b"/nope".to_vec(),
        6 => b"/MCP".to_vec(),
        _ => bytes(u, 24).to_vec(),
    };
    let authority: Vec<u8> = match byte(u) % 6 {
        0..=2 => HOSTS[0].as_bytes().to_vec(),
        3 => HOSTS[1].as_bytes().to_vec(),
        4 => b"evil.example".to_vec(),
        _ => bytes(u, 24).to_vec(),
    };
    let mut headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut push = |n: &str, v: Vec<u8>| headers.push((n.as_bytes().to_vec(), v));
    match byte(u) % 6 {
        0 | 1 => {}
        2 => push("origin", ORIGINS[1].as_bytes().to_vec()),
        3 => push("origin", ORIGINS[0].as_bytes().to_vec()),
        4 => push("origin", b"http://evil.example".to_vec()),
        _ => push("origin", bytes(u, 40).to_vec()),
    }
    match byte(u) % 5 {
        0 | 1 => {}
        2 => push("sec-fetch-site", b"cross-site".to_vec()),
        3 => push("sec-fetch-site", b"CROSS-SITE".to_vec()),
        _ => push("sec-fetch-site", b"same-origin".to_vec()),
    }
    if flag(u) {
        push("cookie", b"s=1".to_vec());
    }
    match byte(u) % 8 {
        0..=2 => push("content-type", b"application/json".to_vec()),
        3 => push("content-type", b"application/json; charset=utf-8".to_vec()),
        4 => push("content-type", b"text/plain".to_vec()),
        5 => {}
        6 => push("content-type", b"Application/JSON".to_vec()),
        _ => push("content-type", bytes(u, 40).to_vec()),
    }
    let route_hint = match model_target(&path) {
        Some(Target::Mcp(i) | Target::Metadata(i)) => i,
        None => 0,
    };
    let (auth, tok) = mint(u, route_hint);
    if let Some(a) = auth {
        push("authorization", a);
    }
    match byte(u) % 7 {
        0 => {}
        1 | 2 => push("mcp-protocol-version", V_MODERN.as_bytes().to_vec()),
        3 | 4 => push("mcp-protocol-version", V_LEGACY.as_bytes().to_vec()),
        5 => push("mcp-protocol-version", b"2099-01-01".to_vec()),
        _ => push("mcp-protocol-version", bytes(u, 16).to_vec()),
    }
    let (body, meth, name) = match byte(u) % 8 {
        6 => (bytes(u, 256).to_vec(), "tools/call".to_string(), "echo".to_string()),
        7 => {
            let (b, m, n) = template(u);
            let mut b = b.into_bytes();
            let (pos, x) = (usize::from(byte(u)), byte(u));
            let len = b.len();
            if let Some(c) = b.get_mut(pos % len.max(1)) {
                *c ^= x;
            }
            (b, m, n)
        }
        _ => {
            let (b, m, n) = template(u);
            (b.into_bytes(), m, n)
        }
    };
    match byte(u) % 7 {
        0 => {}
        1 | 2 => push("mcp-method", meth.as_bytes().to_vec()),
        3 => push("mcp-method", b"tools/list".to_vec()),
        4 => push("mcp-method", sentinel(&meth)),
        5 => push("mcp-method", bytes(u, 24).to_vec()),
        _ => push("mcp-method", b"=?base64?!!?=".to_vec()),
    }
    match byte(u) % 6 {
        0 => {}
        1 | 2 => push("mcp-name", name.as_bytes().to_vec()),
        3 => push("mcp-name", b"other".to_vec()),
        4 => push("mcp-name", sentinel(&name)),
        _ => push("mcp-name", bytes(u, 24).to_vec()),
    }
    let sess = match byte(u) % 7 {
        0 | 1 => SessRef::None,
        2 | 3 => SessRef::Issued(usize::from(byte(u))),
        4 => SessRef::Lit(string_from(u, 32, b"0123456789abcdef").into_bytes()),
        5 => SessRef::Mangled(usize::from(byte(u))),
        _ => SessRef::Lit(Vec::new()),
    };
    match byte(u) % 4 {
        0 | 1 => {}
        2 => push("x-api-key", b"client-key".to_vec()),
        _ => {
            let n = format!("x-{}", string_from(u, 8, LOWER));
            let v = bytes(u, 16).to_vec();
            push(&n, v);
        }
    }
    Req { method, authority, path, headers, sess, body, tok }
}

// ---------------------------------------------------------------- properties

fn verdict_norm(side: &Side, v: &Verdict) -> (Option<Response>, Option<Vec<monban_agent::UpstreamCall>>) {
    match v {
        Verdict::Reply(r) => (Some(side.norm(r)), None),
        Verdict::Forward(f) => (None, Some(f.calls().to_vec())),
    }
}

fn rpc_code(body: &[u8]) -> Option<i64> {
    let v = parse_json(body).ok()?;
    match emit::get(&v, "error").and_then(|e| emit::get(e, "code")) {
        Some(JsonValue::Int(c)) => Some(*c),
        _ => None,
    }
}

fn check_cors(r: &Response, h: &[(Vec<u8>, Vec<u8>)]) {
    for (k, v) in &r.headers {
        if k == "access-control-allow-origin" {
            assert!(ORIGINS.contains(&v.as_str()), "CORS echoed a non-allowlisted origin {v:?}");
            let o = hdr(h, b"origin").and_then(|o| canon_origin(o).ok());
            assert!(o.is_some_and(|o| o.as_bytes() == v.as_bytes()), "CORS origin is not the request's Origin");
        }
    }
}

/// The status the documented check order fixes before the JSON body is read (`None`: later stage decides).
fn early_status(q: &Req, h: &[(Vec<u8>, Vec<u8>)], now: u64) -> Option<u16> {
    let Some(t) = model_target(&q.path) else { return Some(404) };
    if !HOSTS.iter().any(|a| a.as_bytes() == q.authority.as_slice()) {
        return Some(421);
    }
    match hdr(h, b"origin") {
        Some(o) => match canon_origin(o) {
            Ok(c) if ORIGINS.iter().any(|x| x.as_bytes() == c.as_bytes()) => {}
            _ => return Some(403),
        },
        None => {
            if hdr(h, b"sec-fetch-site").is_some_and(|v| v.eq_ignore_ascii_case(b"cross-site")) {
                return Some(403);
            }
            if hdr(h, b"cookie").is_some() && hdr(h, b"authorization").is_none() {
                return Some(403);
            }
        }
    }
    let route = match t {
        Target::Metadata(_) => return Some(if matches!(q.method, Method::Get | Method::Head) { 200 } else { 405 }),
        Target::Mcp(i) => i,
    };
    match q.method {
        Method::Options => return Some(204),
        Method::Get | Method::Head | Method::Put | Method::Patch | Method::Other => return Some(405),
        Method::Delete => return if q.tok.valid_for(route, now) { None } else { Some(401) },
        Method::Post => {}
    }
    let ct_ok = hdr(h, b"content-type")
        .and_then(|c| canon_media_type(c).ok())
        .is_some_and(|c| matches!(c.as_bytes(), b"application/json" | b"application/json; charset=utf-8"));
    if !ct_ok {
        return Some(415);
    }
    if !q.tok.valid_for(route, now) {
        return Some(401);
    }
    if q.body.is_empty() {
        return Some(400);
    }
    None
}

/// Every property of one `check` on gate A.
fn check_a(a: &mut Side, q: &Req, h: &[(Vec<u8>, Vec<u8>)], v: &Verdict, log0: usize, now: u64) {
    let target = model_target(&q.path);
    assert_eq!(a.gate.target(&q.path), target, "Gate::target differs from the configured routes");
    let calls_now = log_len(&a.log) - log0;
    assert!(calls_now <= 1, "more than one authorizer call for one request");
    let pdp = (calls_now == 1).then(|| log_get(&a.log, log0)).flatten();
    let early = early_status(q, h, now);
    match v {
        Verdict::Reply(r) => {
            if let Some(s) = early {
                assert_eq!(r.status, s, "check order: expected {s}, got {}", r.status);
            }
            assert!(!r.headers.iter().any(|(k, _)| k == "mcp-session-id"), "check() reply carries a session id");
            check_cors(r, h);
            let local = matches!((r.status, target), (200, Some(Target::Metadata(_))) | (204, Some(Target::Mcp(_))));
            assert!(r.status >= 400 || local, "reply status {} outside a reject or a local answer", r.status);
            if r.status == 401 {
                let route = match target {
                    Some(Target::Mcp(i)) => i,
                    _ => panic!("401 outside an MCP route"),
                };
                let mut want = format!(
                    "Bearer resource_metadata=\"http://127.0.0.1:7000{PRM_PREFIX}{}\"",
                    PATHS.get(route).copied().unwrap_or("")
                );
                if hdr(h, b"authorization").is_some() {
                    want.push_str(", error=\"invalid_token\"");
                }
                assert!(
                    r.headers.iter().any(|(k, v)| k == "www-authenticate" && *v == want),
                    "401 without the RFC 9728 challenge"
                );
            }
            if r.status != 200 && !r.body.is_empty() {
                let b = parse_json(&r.body).ok();
                assert!(
                    b.as_ref().is_some_and(|b| emit::get_str(b, "jsonrpc") == Some("2.0"))
                        && rpc_code(&r.body).is_some(),
                    "reject body is not a JSON-RPC error"
                );
            }
            if r.status == 204 && q.method == Method::Delete {
                let Some(Target::Mcp(route)) = target else { panic!("DELETE 204 outside an MCP route") };
                assert!(q.tok.valid_for(route, now), "DELETE 204 without a valid token");
                let sid = hdr(h, b"mcp-session-id").unwrap_or(b"");
                let pos = a.issued.iter().position(|s| s.sid.as_bytes() == sid && !s.deleted);
                let Some(pos) = pos else { panic!("DELETE 204 for a session that is not live") };
                let s = a.issued.get_mut(pos).unwrap_or_else(|| panic!("index"));
                assert!(s.sub == q.tok.sub && s.route == route, "DELETE of a session bound to another pair");
                s.deleted = true;
            }
            if let Some((_, d)) = &pdp {
                if *d == Decision::Allow {
                    // Post-PDP refusals: unknown multiplexed prefix (404), canonicalization (400).
                    assert!(matches!(r.status, 400 | 404), "reply {} after an Allow", r.status);
                } else {
                    assert_eq!((r.status, rpc_code(&r.body)), (403, Some(FORBIDDEN)), "Deny/Error not 403/-32001");
                }
            }
        }
        Verdict::Forward(f) => {
            assert!(early.is_none(), "forwarded although the check order fixes {early:?}");
            assert_eq!(q.method, Method::Post, "forwarded a non-POST");
            let Some(Target::Mcp(route)) = target else { panic!("forwarded outside an MCP route") };
            assert!(q.tok.valid_for(route, now), "forwarded without a valid token for the route's audience");
            let Some((preq, d)) = pdp else { panic!("forwarded without an authorizer call") };
            assert_eq!(d, Decision::Allow, "forwarded although the authorizer said {d:?}");
            check_forward(a, q, h, f, &preq, route);
        }
    }
}

fn check_forward(a: &Side, q: &Req, h: &[(Vec<u8>, Vec<u8>)], f: &Forward, preq: &PdpRequest, route: usize) {
    let Ok(msg) = parse_json(&q.body) else { panic!("forwarded an unparseable body") };
    let meth = emit::get_str(&msg, "method").unwrap_or_else(|| panic!("forwarded without a string method"));
    let params = emit::get(&msg, "params");
    let name = params.and_then(|p| emit::get(p, "name"));
    let pv = hdr(h, b"mcp-protocol-version");
    let modern = pv == Some(V_MODERN.as_bytes());
    let era = if modern { V_MODERN } else { V_LEGACY };
    let tool = match name {
        Some(JsonValue::String(s)) if meth == "tools/call" => s.as_str(),
        _ => "",
    };
    let path = PATHS.get(route).copied().unwrap_or("");
    assert_eq!(*preq, pdp_request(q.tok.sub, path, era, meth, tool), "PDP request not bound to the verified request");
    let sid = hdr(h, b"mcp-session-id");
    if modern {
        let mm = hdr(h, b"mcp-method").and_then(header_text);
        assert_eq!(mm.as_deref(), Some(meth), "2026-07-28 forward with Mcp-Method != method");
        if meth == "tools/call" {
            let mn = hdr(h, b"mcp-name").and_then(header_text);
            assert!(matches!((mn, name), (Some(a), Some(JsonValue::String(b))) if a == *b), "Mcp-Name != params.name");
        }
        let meta = params.and_then(|p| emit::get(p, "_meta")).and_then(|m| emit::get_str(m, META_PV));
        assert_eq!(meta, Some(V_MODERN), "2026-07-28 forward without the _meta version");
        assert!(MODERN_METHODS.contains(&meth), "2026-07-28 forward of {meth:?}");
        assert!(sid.is_none(), "2026-07-28 forward with a session id");
    } else {
        assert!(LEGACY_METHODS.contains(&meth), "2025-11-25 forward of {meth:?}");
        if let Some(m) = hdr(h, b"mcp-method") {
            assert_eq!(header_text(m).as_deref(), Some(meth), "2025-11-25 forward with a disagreeing Mcp-Method");
        }
        if let Some(m) = hdr(h, b"mcp-name") {
            let ok = matches!((header_text(m), name), (Some(a), Some(JsonValue::String(b))) if a == *b);
            assert!(ok, "2025-11-25 forward with a disagreeing Mcp-Name");
        }
        assert!(pv == Some(V_LEGACY.as_bytes()) || (pv.is_none() && meth == "initialize"), "version header rule");
        if meth == "initialize" {
            assert!(sid.is_none(), "initialize inside a session");
            assert_eq!(params.and_then(|p| emit::get_str(p, "protocolVersion")), Some(V_LEGACY));
        } else {
            let s = sid.and_then(|s| a.live(s)).unwrap_or_else(|| panic!("2025-11-25 forward without a live session"));
            assert!(s.sub == q.tok.sub && s.route == route, "session used by another (subject, route)");
        }
    }
    if meth == "tools/call" {
        assert!(matches!(name, Some(JsonValue::String(_))), "tools/call forwarded without a string name");
    }
    // The plan.
    let ups = upstreams(route);
    let calls = f.calls();
    let merge = ups.len() > 1 && meth == "tools/list";
    assert_eq!(calls.len(), if merge { ups.len() } else { 1 }, "plan size");
    for (i, c) in calls.iter().enumerate() {
        assert!(ups.iter().any(|(_, u)| *u == c.url), "upstream URL {:?} not configured for the route", c.url);
        if merge {
            assert_eq!(Some(c.url.as_str()), ups.get(i).map(|(_, u)| *u), "fan-out order");
        }
        let n = |k: &str| c.headers.iter().filter(|(x, _)| x == k).count();
        assert_eq!(n("authorization"), 1, "upstream credential count");
        assert!(c.headers.iter().any(|(k, v)| k == "authorization" && v == CRED), "client credential forwarded");
        for k in ["cookie", "x-api-key", "mcp-session-id", "origin"] {
            assert_eq!(n(k), 0, "client {k} forwarded");
        }
        assert!(c.headers.iter().any(|(k, v)| k == "mcp-protocol-version" && v == era), "era header");
        let canon = canon_json(&c.body).ok();
        assert!(canon.is_some_and(|x| x.as_bytes() == c.body.as_slice()), "forwarded body not canonical");
        if ups.len() > 1 && meth == "tools/call" {
            let Some(JsonValue::String(full)) = name else { panic!("unreachable: checked above") };
            let (p, u) = ups.iter().find(|(p, _)| full.starts_with(p)).unwrap_or_else(|| panic!("no prefix matched"));
            assert_eq!(c.url, *u, "multiplexed tools/call to the wrong upstream");
            let local = full.strip_prefix(p).unwrap_or("");
            assert!(!local.is_empty(), "empty local tool name forwarded");
            let b = parse_json(&c.body).ok();
            let fwd_name = b.as_ref().and_then(|b| emit::get(b, "params")).and_then(|p| emit::get_str(p, "name"));
            assert_eq!(fwd_name, Some(local), "prefix not stripped");
        } else {
            let canon_in = canon_json(&q.body).ok();
            assert!(canon_in.is_some_and(|x| x.as_bytes() == c.body.as_slice()), "body is not the checked body");
        }
    }
}

struct Pending {
    fa: Box<Forward>,
    fb: Box<Forward>,
    rid: Option<JsonValue>,
    legacy_init: bool,
    merge: bool,
    sub: &'static str,
    route: usize,
    ncalls: usize,
}

fn reply_body(rid: &Option<JsonValue>, member: &str, value: JsonValue) -> Vec<u8> {
    let v = JsonValue::Object(vec![
        ("jsonrpc".into(), JsonValue::String("2.0".into())),
        ("id".into(), rid.clone().unwrap_or(JsonValue::Null)),
        (member.into(), value),
    ]);
    emit::canonical(&v).unwrap_or_default()
}

fn upstream_replies(u: &mut Unstructured<'_>, rid: &Option<JsonValue>, n: usize) -> Vec<Result<UpstreamReply, ()>> {
    let count = match byte(u) % 8 {
        7 => {
            if flag(u) {
                n + 1
            } else {
                0
            }
        }
        _ => n,
    };
    let names = ["echo", "Echo", "x", "X"];
    (0..count)
        .map(|_| {
            let tools: Vec<JsonValue> = (0..byte(u) % 3)
                .map(|_| {
                    let nm = names.get(usize::from(byte(u) % 4)).copied().unwrap_or("echo");
                    JsonValue::Object(vec![("name".into(), JsonValue::String(nm.into()))])
                })
                .collect();
            let result = JsonValue::Object(vec![("tools".into(), JsonValue::Array(tools))]);
            match byte(u) % 9 {
                0..=2 => Ok(UpstreamReply { status: 200, body: reply_body(rid, "result", result) }),
                3 => Ok(UpstreamReply {
                    status: 200,
                    body: reply_body(rid, "error", JsonValue::Object(vec![("code".into(), JsonValue::Int(-1))])),
                }),
                4 => Ok(UpstreamReply {
                    status: 200,
                    body: reply_body(&Some(JsonValue::Int(999_999)), "result", result),
                }),
                5 => Ok(UpstreamReply { status: 200, body: bytes(u, 32).to_vec() }),
                6 => Err(()),
                7 => Ok(UpstreamReply { status: 500, body: reply_body(rid, "result", result) }),
                _ => {
                    let mut b = reply_body(rid, "result", result);
                    b.pop();
                    b.extend_from_slice(b",\"error\":{}}");
                    Ok(UpstreamReply { status: 200, body: b })
                }
            }
        })
        .collect()
}

/// The upstream reply is a JSON-RPC 2.0 response to `rid` (same rule the gate documents).
fn valid_reply(rep: &UpstreamReply, rid: &Option<JsonValue>) -> Option<JsonValue> {
    let v = parse_json(&rep.body).ok()?;
    let JsonValue::Object(m) = &v else { return None };
    if m.iter().any(|(k, _)| !matches!(k.as_str(), "jsonrpc" | "id" | "result" | "error")) {
        return None;
    }
    if emit::get_str(&v, "jsonrpc") != Some("2.0") || emit::get(&v, "id") != rid.as_ref() {
        return None;
    }
    if emit::get(&v, "result").is_some() == emit::get(&v, "error").is_some() {
        return None;
    }
    Some(v)
}

fn complete(a: &mut Side, b: &mut Side, p: Pending, u: &mut Unstructured<'_>, now: u64) {
    let replies = upstream_replies(u, &p.rid, p.ncalls);
    let ra = a.gate.complete(*p.fa, replies.clone(), now);
    let rb = b.gate.complete(*p.fb, replies.clone(), now);
    for (side, r) in [(&mut *a, &ra), (&mut *b, &rb)] {
        if let Some((_, sid)) = r.headers.iter().find(|(k, _)| k == "mcp-session-id") {
            assert!(sid.len() == 32 && sid.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()), "sid");
            assert!(!side.issued.iter().any(|s| s.sid == *sid), "session id reused");
            side.issued.push(Issued { sid: sid.clone(), sub: p.sub.into(), route: p.route, deleted: false });
        }
    }
    assert_eq!(a.norm(&ra), b.norm(&rb), "complete() not deterministic");
    let r = ra;
    assert!(matches!(r.status, 200 | 202 | 502 | 503), "complete() status {}", r.status);
    if replies.len() != p.ncalls || replies.iter().any(Result::is_err) {
        assert_eq!(r.status, 502, "reply count / failed fetch not 502");
    }
    if !r.body.is_empty() {
        assert!(parse_json(&r.body).is_ok(), "complete() body is not JSON");
    }
    let has_sid = r.headers.iter().any(|(k, _)| k == "mcp-session-id");
    let first = replies.first().and_then(|x| x.as_ref().ok());
    let first_valid = first.and_then(|x| valid_reply(x, &p.rid));
    if has_sid {
        assert!(p.legacy_init && r.status == 200, "session minted outside a successful 2025-11-25 initialize");
        assert!(first_valid.as_ref().is_some_and(|v| emit::get(v, "result").is_some()), "session without a result");
    }
    if r.status == 202 {
        assert!(p.rid.is_none() && r.body.is_empty(), "202 for a request");
        assert!(first.is_some_and(|x| (200..300).contains(&x.status)), "202 although the upstream refused");
    }
    if r.status == 200 {
        assert!(replies.iter().all(|x| matches!(x, Ok(y) if y.status == 200)), "200 from a non-200 upstream");
        assert!(replies.iter().all(|x| x.as_ref().ok().and_then(|y| valid_reply(y, &p.rid)).is_some()), "bad reply");
        if p.merge {
            let v = parse_json(&r.body).ok();
            let tools = v.as_ref().and_then(|v| emit::get(v, "result")).and_then(|x| emit::get(x, "tools"));
            let Some(JsonValue::Array(ts)) = tools else { panic!("merged reply without tools") };
            let mut folded: Vec<String> = Vec::new();
            for t in ts {
                let n = emit::get_str(t, "name").unwrap_or_else(|| panic!("merged tool without a name"));
                assert!(upstreams(p.route).iter().any(|(pre, _)| n.starts_with(pre)), "unprefixed merged tool");
                folded.push(n.to_ascii_lowercase());
            }
            let n = folded.len();
            folded.sort();
            folded.dedup();
            assert_eq!(folded.len(), n, "merged tool names collide under case folding");
        } else if let Some(x) = first {
            let c = canon_json(&x.body).ok();
            assert!(c.is_some_and(|c| c.as_bytes() == r.body.as_slice()), "relayed body is not the canonical reply");
        }
        if p.legacy_init {
            assert!(has_sid || first_valid.is_some_and(|v| emit::get(&v, "result").is_none()), "initialize: no sid");
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let script: Vec<Decision> = bytes(&mut u, 8)
        .iter()
        .map(|b| match b % 3 {
            0 => Decision::Allow,
            1 => Decision::Deny,
            _ => Decision::Error,
        })
        .collect();
    let mut a = Side::new(&script);
    let mut b = Side::new(&script);
    let Ok(c) = Gate::new(config(), SECRET, Some(CRED.into()), Box::new(DenyAll)) else {
        panic!("harness gate refused")
    };
    let mut now = NOW;
    let mut pending: Vec<Pending> = Vec::new();
    let mut forwards = 0usize;
    for _ in 0..8 {
        if u.is_empty() {
            break;
        }
        match byte(&mut u) % 8 {
            5 => {
                if !pending.is_empty() {
                    let p = pending.remove(0);
                    complete(&mut a, &mut b, p, &mut u, now);
                }
            }
            6 => now += u64::from(byte(&mut u)) * 8,
            _ => {
                let q = parse_req(&mut u);
                let ha = q.headers_for(&a);
                let hb = q.headers_for(&b);
                let ra: Vec<(&[u8], &[u8])> = ha.iter().map(|(n, v)| (n.as_slice(), v.as_slice())).collect();
                let rb: Vec<(&[u8], &[u8])> = hb.iter().map(|(n, v)| (n.as_slice(), v.as_slice())).collect();
                let req_a = HttpRequest {
                    method: q.method,
                    authority: &q.authority,
                    path: &q.path,
                    headers: &ra,
                    body: &q.body,
                };
                let req_b = HttpRequest {
                    method: q.method,
                    authority: &q.authority,
                    path: &q.path,
                    headers: &rb,
                    body: &q.body,
                };
                let st = |s: &Side| {
                    let x = s.gate.stats();
                    (x.rejected.load(Ordering::Relaxed), x.forwarded.load(Ordering::Relaxed))
                };
                let (rej0, fwd0) = st(&a);
                let log0 = log_len(&a.log);
                let va = a.gate.check(&req_a, now);
                let vb = b.gate.check(&req_b, now);
                assert!(verdict_norm(&a, &va) == verdict_norm(&b, &vb), "check() not deterministic");
                check_a(&mut a, &q, &ha, &va, log0, now);
                // Keep B's session model in step with A's (a DELETE 204 ends the session in both).
                if let (Verdict::Reply(r), Method::Delete) = (&vb, q.method)
                    && r.status == 204
                {
                    let sid = hdr(&hb, b"mcp-session-id").unwrap_or(b"");
                    if let Some(s) = b.issued.iter_mut().find(|s| s.sid.as_bytes() == sid) {
                        s.deleted = true;
                    }
                }
                let (rej1, fwd1) = st(&a);
                match &va {
                    Verdict::Reply(r) => {
                        assert_eq!(fwd1, fwd0, "forwarded counter moved on a reply");
                        assert_eq!(rej1 - rej0, u64::from(r.status >= 400), "rejected counter");
                    }
                    Verdict::Forward(_) => {
                        assert_eq!((rej1, fwd1), (rej0, fwd0 + 1), "counters on a forward");
                    }
                }
                // DenyAll never forwards; every stateless request A forwarded is 403 / -32001 there. C has no
                // sessions, so it can only reach its PDP where A reached its own (or A's session table was full):
                // the other requests stop at the same stateless checks on both and are skipped for speed.
                let pdp_reached = log_len(&a.log) > log0;
                let full = matches!(&va, Verdict::Reply(r) if r.status == 503);
                let rc = if pdp_reached || full || q.method == Method::Delete {
                    let Verdict::Reply(rc) = c.check(&req_a, now) else { panic!("DenyAll gate forwarded") };
                    assert!(!(q.method == Method::Delete && rc.status == 204), "DenyAll gate deleted a session");
                    Some(rc)
                } else {
                    None
                };
                if let (Verdict::Forward(fa), Verdict::Forward(fb)) = (va, vb) {
                    forwards += 1;
                    let msg = parse_json(&q.body).ok();
                    let meth = msg.as_ref().and_then(|m| emit::get_str(m, "method")).unwrap_or("");
                    let legacy = hdr(&ha, b"mcp-protocol-version") != Some(V_MODERN.as_bytes());
                    if !legacy || meth == "initialize" {
                        let c403 = rc.as_ref().map(|r| (r.status, rpc_code(&r.body)));
                        assert_eq!(c403, Some((403, Some(FORBIDDEN))), "DenyAll did not refuse");
                    }
                    let route = match model_target(&q.path) {
                        Some(Target::Mcp(i)) => i,
                        _ => 0,
                    };
                    let ncalls = fa.calls().len();
                    pending.push(Pending {
                        rid: msg.as_ref().and_then(|m| emit::get(m, "id")).cloned(),
                        legacy_init: legacy && meth == "initialize",
                        merge: route == 2 && meth == "tools/list",
                        sub: q.tok.sub,
                        route,
                        ncalls,
                        fa,
                        fb,
                    });
                }
            }
        }
    }
    selftest!(forwards >= 4); // seeds: at most 3 forwards each
    let _ = forwards;
});
