#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Gate unit tests: one per rule family, each a reject that must not produce a forward plan, plus the accepted
//! paths in both eras. The black-box evidence is oracles/mcp-corpus against the shipped binary.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use aegis_authz::pdp::PdpRequest;
use aegis_types::Decision;

use crate::authz::Authorizer;
use crate::config::AgentConfig;
use crate::gate::*;
use crate::jwt::mint_hs256;

const SECRET: &[u8] = b"aegis-oracle-test-secret-NOT-FOR-PRODUCTION";
const ISS: &str = "https://issuer.oracle.test";
const URL: &str = "http://127.0.0.1:7000/mcp";
const NOW: u64 = 1_800_000_000;

struct Count(Arc<AtomicUsize>, Decision);
impl Authorizer for Count {
    fn decide(&self, _r: &PdpRequest) -> Decision {
        self.0.fetch_add(1, Ordering::SeqCst);
        self.1
    }
}

fn cfg() -> AgentConfig {
    AgentConfig::parse(
        br#"{"v":1,"listen":"127.0.0.1:7000","hosts":["127.0.0.1:7000","localhost:7000"],
        "origins":["http://127.0.0.1:7000","http://localhost:7000"],
        "auth":{"issuer":"https://issuer.oracle.test","hs256_secret_file":"/dev/null"},
        "pdp":{"socket":"/tmp/pdp.sock","deadline_ms":200},
        "sessions":{"max":100,"per_principal":4,"idle_ttl_s":60},
        "routes":[{"path":"/mcp","resource":"http://127.0.0.1:7000/mcp","upstreams":[{"prefix":"","url":"http://127.0.0.1:9/"}]},
                  {"path":"/mcp2","resource":"http://127.0.0.1:7000/mcp2","upstreams":[{"prefix":"","url":"http://127.0.0.1:9/"}]},
                  {"path":"/mcp-multi","resource":"http://127.0.0.1:7000/mcp-multi","upstreams":[{"prefix":"a__","url":"http://127.0.0.1:9/a"},{"prefix":"b__","url":"http://127.0.0.1:9/b"}]}]}"#,
    )
    .unwrap()
}

fn gate_with(d: Decision) -> (Gate, Arc<AtomicUsize>) {
    let n = Arc::new(AtomicUsize::new(0));
    let g = Gate::new(&cfg(), SECRET, Some("Bearer gw".into()), Box::new(Count(n.clone(), d))).unwrap();
    (g, n)
}

fn tok(sub: &str, aud: &str) -> String {
    let claims = format!(r#"{{"sub":"{sub}","iss":"{ISS}","iat":{NOW},"exp":{}, "aud":"{aud}"}}"#, NOW + 3600);
    mint_hs256(SECRET, r#"{"alg":"HS256","typ":"JWT"}"#, &claims)
}

struct Req {
    method: Method,
    authority: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Req {
    fn post(path: &str, body: &str) -> Self {
        Req {
            method: Method::Post,
            authority: "127.0.0.1:7000".into(),
            path: path.into(),
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
        }
    }
    fn h(mut self, n: &str, v: &str) -> Self {
        self.headers.retain(|(k, _)| k != n);
        self.headers.push((n.into(), v.into()));
        self
    }
    fn without(mut self, n: &str) -> Self {
        self.headers.retain(|(k, _)| k != n);
        self
    }
    fn bearer(self, sub: &str, aud: &str) -> Self {
        let t = tok(sub, aud);
        self.h("authorization", &format!("Bearer {t}"))
    }
    fn run(&self, g: &Gate) -> Verdict {
        let hs: Vec<(&[u8], &[u8])> = self.headers.iter().map(|(n, v)| (n.as_bytes(), v.as_bytes())).collect();
        g.check(
            &HttpRequest {
                method: self.method,
                authority: self.authority.as_bytes(),
                path: self.path.as_bytes(),
                headers: &hs,
                body: &self.body,
            },
            NOW,
        )
    }
}

fn modern_call(name: &str) -> Req {
    let b = format!(
        r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"{name}","arguments":{{"x":"m"}},"_meta":{{"{META_PV}":"{V_MODERN}"}}}}}}"#
    );
    Req::post("/mcp", &b)
        .h("mcp-protocol-version", V_MODERN)
        .h("mcp-method", "tools/call")
        .h("mcp-name", name)
        .bearer("alice", URL)
}

fn reply(v: Verdict) -> Response {
    match v {
        Verdict::Reply(r) => r,
        Verdict::Forward(f) => panic!("expected a reject, got a forward plan {f:?}"),
    }
}

fn forward(v: Verdict) -> Box<Forward> {
    match v {
        Verdict::Forward(f) => f,
        Verdict::Reply(r) => panic!("expected a forward, got {} {}", r.status, String::from_utf8_lossy(&r.body)),
    }
}

fn code(r: &Response) -> Option<i64> {
    let v = aegis_canon::parse_json(&r.body).ok()?;
    match crate::emit::get(&v, "error").and_then(|e| crate::emit::get(e, "code")) {
        Some(aegis_canon::JsonValue::Int(c)) => Some(*c),
        _ => None,
    }
}

fn assert_reject(g: &Gate, q: Req, status: u16, rpc: Option<i64>) {
    let r = reply(q.run(g));
    assert_eq!(r.status, status, "body {}", String::from_utf8_lossy(&r.body));
    if rpc.is_some() {
        assert_eq!(code(&r), rpc, "body {}", String::from_utf8_lossy(&r.body));
    }
}

#[test]
fn modern_accepts_and_forwards_canonical_body_with_own_credential() {
    let (g, n) = gate_with(Decision::Allow);
    let f = forward(modern_call("echo").h("cookie", "s=1").h("x-api-key", "k").run(&g));
    assert_eq!(n.load(Ordering::SeqCst), 1, "one PDP decision");
    let c = &f.calls()[0];
    assert_eq!(c.url, "http://127.0.0.1:9/");
    assert!(c.headers.contains(&("authorization".into(), "Bearer gw".into())));
    assert!(!c.headers.iter().any(|(k, _)| k == "cookie" || k == "x-api-key"));
    assert_eq!(aegis_canon::canon_json(&c.body).unwrap().as_bytes(), c.body.as_slice(), "canonical");
    let up = UpstreamReply { status: 200, body: br#"{"jsonrpc":"2.0","id":7,"result":{"content":[]}}"#.to_vec() };
    let r = g.complete(*f, vec![Ok(up)], NOW);
    assert_eq!(r.status, 200);
    assert!(!r.headers.iter().any(|(k, _)| k == "mcp-session-id"), "N05");
}

#[test]
fn header_body_consistency_and_versions() {
    let (g, n) = gate_with(Decision::Allow);
    assert_reject(&g, modern_call("echo").h("mcp-protocol-version", V_LEGACY), 400, Some(HEADER_MISMATCH));
    assert_reject(&g, modern_call("echo").without("mcp-method"), 400, Some(HEADER_MISMATCH));
    assert_reject(&g, modern_call("echo").h("mcp-name", "other"), 400, Some(HEADER_MISMATCH));
    let b = format!(
        r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"echo","_meta":{{"{META_PV}":"2099-01-01"}}}}}}"#
    );
    let q = Req::post("/mcp", &b)
        .h("mcp-protocol-version", "2099-01-01")
        .h("mcp-method", "tools/call")
        .h("mcp-name", "echo")
        .bearer("alice", URL);
    let r = reply(q.run(&g));
    assert_eq!((r.status, code(&r)), (400, Some(UNSUPPORTED_VERSION)));
    assert!(String::from_utf8_lossy(&r.body).contains(V_MODERN), "lists supported versions");
    // _meta missing under 2026-07-28.
    let b = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo"}}"#;
    let q = Req::post("/mcp", b)
        .h("mcp-protocol-version", V_MODERN)
        .h("mcp-method", "tools/call")
        .h("mcp-name", "echo")
        .bearer("alice", URL);
    assert_reject(&g, q, 400, Some(HEADER_MISMATCH));
    // Base64 sentinel in Mcp-Name decodes before comparison.
    let q = modern_call("echo").h("mcp-name", &format!("=?base64?{}?=", crate::b64::encode_std(b"echo")));
    forward(q.run(&g));
    assert_eq!(n.load(Ordering::SeqCst), 1, "only the accepted call reached the PDP");
}

#[test]
fn removed_methods_under_modern() {
    let (g, _) = gate_with(Decision::Allow);
    for m in ["ping", "initialize"] {
        let b =
            format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{m}","params":{{"_meta":{{"{META_PV}":"{V_MODERN}"}}}}}}"#);
        let q = Req::post("/mcp", &b).h("mcp-protocol-version", V_MODERN).h("mcp-method", m).bearer("alice", URL);
        let r = reply(q.run(&g));
        assert_eq!((r.status, code(&r)), (404, Some(METHOD_NOT_FOUND)));
        assert!(!r.headers.iter().any(|(k, _)| k == "mcp-session-id"));
    }
}

#[test]
fn tokens() {
    let (g, n) = gate_with(Decision::Allow);
    let base = || modern_call("echo");
    assert_reject(&g, base().without("authorization"), 401, None);
    assert_reject(&g, base().bearer("alice", "http://other.example/mcp"), 401, None);
    assert_reject(&g, base().bearer("alice", "http://127.0.0.1:7000/mcp2"), 401, None);
    let bad = |hdr: &str, claims: String, key: &[u8]| mint_hs256(key, hdr, &claims);
    let c = |extra: &str| format!(r#"{{"sub":"alice","iss":"{ISS}","aud":"{URL}"{extra}}}"#);
    let exp = format!(r#","exp":{}"#, NOW + 60);
    let cases = [
        bad(r#"{"alg":"HS256"}"#, c(&format!(r#","exp":{}"#, NOW - 1)), SECRET),
        bad(r#"{"alg":"HS256"}"#, c(""), SECRET),
        bad(r#"{"alg":"HS256"}"#, c(&format!(r#"{exp},"nbf":{}"#, NOW + 60)), SECRET),
        bad(r#"{"alg":"HS512"}"#, c(&exp), SECRET),
        bad(r#"{"alg":"none"}"#, c(&exp), SECRET),
        bad(r#"{"alg":"HS256"}"#, c(&exp), b"not-the-key-not-the-key-not-the-key!!"),
        bad(r#"{"alg":"HS256","crit":["x"]}"#, c(&exp), SECRET),
        bad(
            r#"{"alg":"HS256"}"#,
            format!(r#"{{"sub":"alice","iss":"http://evil.example","aud":"{URL}"{exp}}}"#),
            SECRET,
        ),
        bad(r#"{"alg":"HS256"}"#, format!(r#"{{"sub":"a","sub":"b","iss":"{ISS}","aud":"{URL}"{exp}}}"#), SECRET),
    ];
    for t in cases {
        assert_reject(&g, base().h("authorization", &format!("Bearer {t}")), 401, None);
    }
    let good = bad(r#"{"alg":"HS256"}"#, c(&exp), SECRET);
    let mut tampered = good.clone();
    tampered.pop();
    tampered.push(if good.ends_with('A') { 'B' } else { 'A' });
    assert_reject(&g, base().h("authorization", &format!("Bearer {tampered}")), 401, None);
    let aud_list =
        bad(r#"{"alg":"HS256"}"#, format!(r#"{{"sub":"alice","iss":"{ISS}","aud":["x","{URL}"]{exp}}}"#), SECRET);
    forward(base().h("authorization", &format!("Bearer {aud_list}")).run(&g));
    forward(base().h("authorization", &format!("Bearer {good}")).run(&g));
    assert_eq!(n.load(Ordering::SeqCst), 2);
    // The 401 carries the RFC 9728 challenge.
    let r = reply(base().without("authorization").run(&g));
    assert!(r.headers.iter().any(|(k, v)| k == "www-authenticate"
        && v == "Bearer resource_metadata=\"http://127.0.0.1:7000/.well-known/oauth-protected-resource/mcp\""));
}

#[test]
fn listener_rules() {
    let (g, _) = gate_with(Decision::Allow);
    assert_reject(&g, modern_call("echo").h("origin", "http://evil.example"), 403, None);
    assert_reject(&g, modern_call("echo").h("sec-fetch-site", "cross-site").h("cookie", "s=1"), 403, None);
    assert_reject(&g, modern_call("echo").without("authorization").h("cookie", "s=1"), 403, None);
    let mut q = modern_call("echo");
    q.authority = "evil.example".into();
    assert_reject(&g, q, 421, None);
    let mut q = modern_call("echo");
    q.path = "/nope".into();
    assert_reject(&g, q, 404, None);
    assert_reject(&g, modern_call("echo").h("content-type", "text/plain"), 415, None);
    assert_reject(&g, modern_call("echo").without("content-type"), 415, None);
    let mut q = modern_call("echo");
    q.method = Method::Get;
    assert_reject(&g, q, 405, None);
    // An allowed Origin is echoed (never "*").
    let f = forward(modern_call("echo").h("origin", "http://localhost:7000").run(&g));
    let up = UpstreamReply { status: 200, body: br#"{"jsonrpc":"2.0","id":7,"result":{}}"#.to_vec() };
    let r = g.complete(*f, vec![Ok(up)], NOW);
    assert!(r.headers.contains(&("access-control-allow-origin".into(), "http://localhost:7000".into())));
    // Metadata document.
    let mut q = Req::post("/.well-known/oauth-protected-resource/mcp", "");
    q.method = Method::Get;
    let r = reply(q.run(&g));
    assert_eq!(r.status, 200);
    assert!(String::from_utf8_lossy(&r.body).contains(URL));
}

#[test]
fn strict_json_and_shape() {
    let (g, n) = gate_with(Decision::Allow);
    let bodies: &[(&[u8], u16, i64)] = &[
        (b"\xef\xbb\xbf{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}", 400, PARSE_ERROR),
        (br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call"}"#, 400, PARSE_ERROR),
        (br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"na\u0000me":"echo"}}"#, 400, PARSE_ERROR),
        (br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":1e1000}}"#, 400, PARSE_ERROR),
        (br#"{"jsonrpc":"2.0","id":1,"Method":"tools/list"}"#, 400, INVALID_REQUEST),
        (br#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]"#, 400, INVALID_REQUEST),
        (br#"{"jsonrpc":"2.0","id":1.5,"method":"tools/list"}"#, 400, INVALID_REQUEST),
        (br#"{"jsonrpc":"1.0","id":1,"method":"tools/list"}"#, 400, INVALID_REQUEST),
        (br#"{"jsonrpc":"2.0","id":1,"method":"TOOLS/CALL","params":{}}"#, 404, METHOD_NOT_FOUND),
    ];
    let (sid, _) = legacy_session(&g, "alice", "/mcp", URL);
    for (b, st, c) in bodies {
        let mut q =
            Req::post("/mcp", "").h("mcp-protocol-version", V_LEGACY).h("mcp-session-id", &sid).bearer("alice", URL);
        q.body = b.to_vec();
        assert_reject(&g, q, *st, Some(*c));
    }
    let deep = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"echo","arguments":{{"x":{}{}}}}}}}"#,
        "[".repeat(200_000),
        "]".repeat(200_000)
    );
    let q = Req::post("/mcp", &deep).h("mcp-protocol-version", V_LEGACY).h("mcp-session-id", &sid).bearer("alice", URL);
    assert_reject(&g, q, 400, Some(PARSE_ERROR));
    assert_eq!(n.load(Ordering::SeqCst), 1, "only the initialize reached the PDP");
}

/// initialize + upstream success: returns the session id.
fn legacy_session(g: &Gate, sub: &str, path: &str, aud: &str) -> (String, Response) {
    let b = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"{V_LEGACY}","capabilities":{{}},"clientInfo":{{"name":"t","version":"1"}}}}}}"#
    );
    let f = forward(Req::post(path, &b).h("mcp-protocol-version", V_LEGACY).bearer(sub, aud).run(g));
    let up = UpstreamReply {
        status: 200,
        body: br#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}"#.to_vec(),
    };
    let r = g.complete(*f, vec![Ok(up)], NOW);
    let sid = r.headers.iter().find(|(k, _)| k == "mcp-session-id").map(|(_, v)| v.clone()).unwrap();
    (sid, r)
}

fn legacy_call(path: &str, sid: &str, sub: &str, aud: &str) -> Req {
    let b = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"x":"l"}}}"#;
    Req::post(path, b).h("mcp-protocol-version", V_LEGACY).h("mcp-session-id", sid).bearer(sub, aud)
}

#[test]
fn legacy_sessions_bound_to_principal_and_route() {
    let (g, _) = gate_with(Decision::Allow);
    let (sid, _) = legacy_session(&g, "alice", "/mcp", URL);
    forward(legacy_call("/mcp", &sid, "alice", URL).run(&g));
    assert_reject(&g, legacy_call("/mcp", &sid, "bob", URL), 404, None);
    assert_reject(&g, legacy_call("/mcp2", &sid, "alice", "http://127.0.0.1:7000/mcp2"), 404, None);
    assert_reject(&g, legacy_call("/mcp", "", "alice", URL).without("mcp-session-id"), 400, None);
    // DELETE by the owner ends it; reuse is 404.
    let mut d = Req::post("/mcp", "").h("mcp-session-id", &sid).bearer("bob", URL);
    d.method = Method::Delete;
    assert_eq!(reply(d.run(&g)).status, 404, "bob cannot delete alice's session");
    let mut d = Req::post("/mcp", "").h("mcp-session-id", &sid).bearer("alice", URL);
    d.method = Method::Delete;
    assert_eq!(reply(d.run(&g)).status, 204);
    assert_reject(&g, legacy_call("/mcp", &sid, "alice", URL), 404, None);
}

#[test]
fn pdp_deny_and_error_fail_closed() {
    for d in [Decision::Deny, Decision::Error] {
        let (g, n) = gate_with(d);
        assert_reject(&g, modern_call("echo"), 403, Some(FORBIDDEN));
        assert_eq!(n.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn multiplexed_namespacing() {
    let (g, _) = gate_with(Decision::Allow);
    let aud = "http://127.0.0.1:7000/mcp-multi";
    let b = format!(
        r#"{{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{{"_meta":{{"{META_PV}":"{V_MODERN}"}}}}}}"#
    );
    let q = Req::post("/mcp-multi", &b)
        .h("mcp-protocol-version", V_MODERN)
        .h("mcp-method", "tools/list")
        .bearer("alice", aud);
    let f = forward(q.run(&g));
    assert_eq!(f.calls().len(), 2);
    let tl = br#"{"jsonrpc":"2.0","id":4,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object"}}]}}"#;
    let r = g.complete(
        *f,
        vec![
            Ok(UpstreamReply { status: 200, body: tl.to_vec() }),
            Ok(UpstreamReply { status: 200, body: tl.to_vec() }),
        ],
        NOW,
    );
    let t = String::from_utf8_lossy(&r.body).to_string();
    assert!(r.status == 200 && t.contains("a__echo") && t.contains("b__echo"), "{t}");
    // Prefixes keep same-named tools apart; a case-fold collision (here inside one upstream) is refused.
    let up = |names: &str| {
        Ok(UpstreamReply {
            status: 200,
            body: format!(r#"{{"jsonrpc":"2.0","id":4,"result":{{"tools":[{names}]}}}}"#).into_bytes(),
        })
    };
    let f = forward(q.run(&g));
    assert_eq!(g.complete(*f, vec![up(r#"{"name":"X"}"#), up(r#"{"name":"x"}"#)], NOW).status, 200);
    let f = forward(q.run(&g));
    assert_eq!(g.complete(*f, vec![up(r#"{"name":"Echo"},{"name":"echo"}"#), up("")], NOW).status, 502);
    // tools/call routes by prefix and strips it.
    let b = format!(
        r#"{{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{{"name":"b__echo","arguments":{{}},"_meta":{{"{META_PV}":"{V_MODERN}"}}}}}}"#
    );
    let q = Req::post("/mcp-multi", &b)
        .h("mcp-protocol-version", V_MODERN)
        .h("mcp-method", "tools/call")
        .h("mcp-name", "b__echo")
        .bearer("alice", aud);
    let f = forward(q.run(&g));
    assert_eq!(f.calls()[0].url, "http://127.0.0.1:9/b");
    assert!(String::from_utf8_lossy(&f.calls()[0].body).contains(r#""name":"echo""#));
    let b = format!(
        r#"{{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{{"name":"c__echo","_meta":{{"{META_PV}":"{V_MODERN}"}}}}}}"#
    );
    let q = Req::post("/mcp-multi", &b)
        .h("mcp-protocol-version", V_MODERN)
        .h("mcp-method", "tools/call")
        .h("mcp-name", "c__echo")
        .bearer("alice", aud);
    assert_reject(&g, q, 404, None);
}

#[test]
fn upstream_replies_are_checked() {
    let (g, _) = gate_with(Decision::Allow);
    for body in [&b"not json"[..], br#"{"jsonrpc":"2.0","id":8,"result":{}}"#, br#"{"jsonrpc":"2.0","id":7}"#] {
        let f = forward(modern_call("echo").run(&g));
        let r = g.complete(*f, vec![Ok(UpstreamReply { status: 200, body: body.to_vec() })], NOW);
        assert_eq!(r.status, 502, "{}", String::from_utf8_lossy(body));
    }
    let f = forward(modern_call("echo").run(&g));
    assert_eq!(g.complete(*f, vec![Err(())], NOW).status, 502);
}

#[test]
fn config_refusals() {
    let ok = String::from_utf8(br#"{"v":1,"listen":"127.0.0.1:1","hosts":["127.0.0.1:1"],"origins":[],"auth":{"issuer":"i","hs256_secret_file":"f"},"pdp":{"socket":"s","deadline_ms":1},"routes":[{"path":"/m","resource":"http://127.0.0.1:1/m","upstreams":[{"prefix":"","url":"http://127.0.0.1:2/"}]}]}"#.to_vec()).unwrap();
    assert!(AgentConfig::parse(ok.as_bytes()).is_ok());
    for (from, to) in [
        (r#""routes":[{"#, r#""routes":[],"x":[{"#),
        (r#""path":"/m""#, r#""path":"/a/../m""#),
        (r#""hosts":["127.0.0.1:1"]"#, r#""hosts":["Example.COM:1"]"#),
        (r#""hosts":["127.0.0.1:1"]"#, r#""hosts":[]"#),
        (r#""prefix":"""#, r#""prefix":"a__""#),
        (r#""v":1"#, r#""v":2"#),
        (r#""deadline_ms":1"#, r#""deadline_ms":0"#),
        (r#""resource":"http://127.0.0.1:1/m""#, r#""resource":"http://127.0.0.1:1/other""#),
        (r#""listen""#, r#""unknown":1,"listen""#),
    ] {
        let bad = ok.replacen(from, to, 1);
        assert_ne!(bad, ok);
        assert!(AgentConfig::parse(bad.as_bytes()).is_err(), "accepted: {bad}");
    }
    let short = Gate::new(&cfg(), b"short", None, Box::new(crate::DenyAll));
    assert!(short.is_err(), "HS256 key below 32 bytes refused");
}
