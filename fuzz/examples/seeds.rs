//! Writes the initial seed corpus: `cargo run --example seeds -- <corpus dir>` (ci/fuzz.sh seed).
//! Seeds are produced through the crates' own public encoders, so they start inside each accepted language.
#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use monban_authz::Decision;
use monban_authz::pdp::{EntityData, PdpRequest, Uid, Value, encode_reply, encode_request};
use monban_token::{Caveat, KeyRing, MintParams, TokenL, attenuate, mint};

fn put(dir: &Path, target: &str, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let d = dir.join(target);
    fs::create_dir_all(&d)?;
    fs::write(d.join(name), bytes)
}

/// One mcp_gate request operation (byte layout of `parse_req` in fuzz_targets/mcp_gate.rs, no arbitrary fields):
/// op, method, path, authority, origin, sec-fetch-site, cookie, content-type, token kind, subject, audience,
/// MCP-Protocol-Version, body kind, template bytes, Mcp-Method, Mcp-Name, session (+ index), extra header.
#[allow(clippy::too_many_arguments)]
fn mcp_req(
    method: u8,
    path: u8,
    origin: u8,
    tok: u8,
    sub: u8,
    aud: u8,
    pv: u8,
    tmpl: &[u8],
    mm: u8,
    mn: u8,
    sess: &[u8],
) -> Vec<u8> {
    let mut v = vec![0, method, path, 0, origin, 0, 0, 0, tok, sub, aud, pv, 0];
    v.extend_from_slice(tmpl);
    v.extend_from_slice(&[mm, mn]);
    v.extend_from_slice(sess);
    v.push(0);
    v
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::args().nth(1).ok_or("usage: seeds <corpus dir>")?;
    let dir = Path::new(&dir);

    // h1_head: byte 0 = limits selector, byte 1 = split seed, then the stream.
    for (i, s) in [
        &b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"[..],
        b"POST /api/x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhelloGET /b HTTP/1.1\r\nHost: a\r\n\r\n",
        b"PUT /u HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n5;e=1\r\nhello\r\n0\r\nT: v\r\n\r\n",
        b"OPTIONS * HTTP/1.0\r\nCookie: a=1; b=2\r\n\r\n",
    ]
    .iter()
    .enumerate()
    {
        let mut v = vec![0u8, 7u8];
        v.extend_from_slice(s);
        put(dir, "h1_head", &format!("seed{i}"), &v)?;
    }

    // token: minted + attenuated Tier-L tokens under the harness key (k1 / [7; 32]).
    let mut keys = KeyRing::new();
    keys.insert(b"k1", [7u8; 32]).map_err(|e| format!("{e:?}"))?;
    let t = mint(
        &keys,
        MintParams { kid: b"k1", aud: "api", nonce: [1; 16], mint_time: 100, exp: 400, depth: 4, extra: vec![] },
    )
    .map_err(|e| format!("{e:?}"))?;
    let t2 = attenuate(&t, Caveat::Res(vec!["a".into(), "b".into()])).map_err(|e| format!("{e:?}"))?;
    let t3 = attenuate(&t2, Caveat::Tenant(1)).map_err(|e| format!("{e:?}"))?;
    for (i, tok) in [&t, &t2, &t3].iter().enumerate() {
        put(dir, "token", &format!("tierl{i}"), &tok.encode().map_err(|e| format!("{e:?}"))?)?;
    }
    put(dir, "token", "caveat", &Caveat::Ops(3).encode())?;
    let _ = TokenL::decode(&t.encode().map_err(|e| format!("{e:?}"))?);

    // canon_json
    for (i, s) in [
        "{\"b\":[1,2.5,{\"c\":null}],\"a\":\"x\\u00e9\\n\u{e9}\",\"d\":true}".as_bytes(),
        "[1e3,-0.5,\"\\ud83d\\ude00\u{1F600}\",{}]".as_bytes(),
        b"  \"str\"  ".as_slice(),
    ]
    .iter()
    .enumerate()
    {
        put(dir, "canon_json", &format!("seed{i}"), s)?;
    }

    // config (from crates/monban-config/tests/schema.rs BASE / MINIMAL)
    put(
        dir,
        "config",
        "base",
        br#"{"v":1,
 "listeners":[{"name":"web","bind":"0.0.0.0:443","profile":"P-PUBLIC-WEB","alpn":["h2","http/1.1"]}],
 "vhosts":[{"host":"example.com","routes":[
   {"id":1,"path":"/api/","to":{"upstream":"app","framing":"h2"},"authz":"api"},
   {"id":2,"path":"/static/","to":{"static":"/srv/www"}}]}],
 "admin":{"bind":"127.0.0.1:9000"},
 "limits":{},
 "canon":{}}"#,
    )?;
    put(
        dir,
        "config",
        "minimal",
        br#"{"v":1,"listeners":[{"name":"a","bind":"b","profile":"P-CNSA"}],
  "vhosts":[{"host":"a","routes":[{"id":1,"path":"/","to":{"static":"x"}}]}]}"#,
    )?;

    // pdp_wire: a canonical request frame and replies.
    let req = PdpRequest {
        principal: Uid::new("App::User", "alice"),
        action: Uid::new("App::Action", "read"),
        resource: Uid::new("App::Doc", "d1"),
        context: vec![("ip".into(), Value::Str("10.0.0.1".into())), ("n".into(), Value::Long(7))],
        entities: vec![EntityData {
            uid: Uid::new("App::User", "alice"),
            attrs: vec![("tags".into(), Value::Set(vec![Value::Str("a".into()), Value::Bool(true)]))],
            parents: vec![Uid::new("App::Group", "g")],
        }],
    };
    put(dir, "pdp_wire", "request", &encode_request(1, &req).map_err(|e| format!("{e:?}"))?)?;
    put(dir, "pdp_wire", "reply_allow", &encode_reply(1, Decision::Allow))?;
    put(dir, "pdp_wire", "reply_deny", &encode_reply(1, Decision::Deny))?;

    // combiner: decision list, then a script with exact echo replies.
    put(dir, "combiner", "seed0", &[3, 0, 0, 0, 3, 5, 0, 5, 0, 5, 1])?;
    put(dir, "combiner", "seed1", &[2, 0, 1, 2, 0, 1, 0, 3, 7, 0])?;

    // audit: structured bytes (any bytes are valid input).
    put(dir, "audit", "seed0", b"\x03\x05abcde\x10object \xc3\xa9\xe2\x80\x8b\x00\x02\x00\x03key\x00\x05hello")?;

    // egress: [len/2] "base ref" then the rest.
    let mut e = vec![30u8];
    e.extend_from_slice(b"https://example.org/a/b?x=1 ../c?y=2#f");
    e.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0]);
    e.extend_from_slice(b"\x10\x04\x08\x00HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
    put(dir, "egress", "seed0", &e)?;
    let mut e = vec![20u8];
    e.extend_from_slice(b"http://[2606:4700::1111]:8080/ //example.com/z");
    e.extend_from_slice(b"\x02HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n");
    put(dir, "egress", "seed1", &e)?;

    // mcp_gate: [script len, decisions...] then operations (0 = request, 5 = complete the oldest forward with
    // [count sel, per reply: tool count, tool names, kind], 6 = clock step). Template bytes: method (0 tools/call,
    // 1 tools/list, 2 initialize), id kind (0 + value byte = Int, 3 = none), name (0 echo, 5 none), _meta (0 none,
    // 2 2026-07-28), protocolVersion (0 none, 1 2025-11-25), shape, params form. pv: 1 = 2026-07-28, 3 = 2025-11-25.
    // At most 3 forwards per seed (the self-test plant needs 4).
    let call_modern: &[u8] = &[0, 0, 7, 0, 2, 0, 0, 0];
    let call_legacy: &[u8] = &[0, 0, 3, 0, 0, 0, 0, 0];
    let init: &[u8] = &[2, 0, 1, 5, 0, 1, 0, 0];
    let ok1: &[u8] = &[5, 0, 0, 0];
    // seed0: a 2026-07-28 tools/call, forwarded and completed.
    let mut m = vec![0u8];
    m.extend(mcp_req(0, 0, 0, 0, 0, 0, 1, call_modern, 1, 1, &[0]));
    m.extend_from_slice(ok1);
    put(dir, "mcp_gate", "modern_call", &m)?;
    // seed1: 2025-11-25 initialize -> session -> tools/call in that session.
    let mut m = vec![0u8];
    m.extend(mcp_req(0, 0, 0, 0, 0, 0, 0, init, 0, 0, &[0]));
    m.extend_from_slice(ok1);
    m.extend(mcp_req(0, 0, 0, 0, 0, 0, 3, call_legacy, 0, 0, &[2, 0]));
    m.extend_from_slice(ok1);
    put(dir, "mcp_gate", "legacy_session", &m)?;
    // seed2: multiplexed tools/list from an allowed Origin, merged from two upstreams.
    let mut m = vec![0u8];
    m.extend(mcp_req(0, 2, 2, 0, 0, 0, 1, &[1, 0, 4, 5, 2, 0, 0, 0], 1, 0, &[0]));
    m.extend_from_slice(&[5, 0, 1, 0, 0, 1, 1, 0]);
    put(dir, "mcp_gate", "multi_list", &m)?;
    // seed3: script Allow, Deny, Error: one forward, then a PDP Deny; metadata GET, OPTIONS, a wrong-audience
    // token and an evil Origin.
    let mut m = vec![3u8, 0, 1, 2];
    m.extend(mcp_req(0, 0, 0, 0, 0, 0, 1, call_modern, 1, 1, &[0]));
    m.extend(mcp_req(0, 0, 0, 0, 0, 0, 1, call_modern, 1, 1, &[0]));
    m.extend(mcp_req(7, 3, 0, 0, 0, 0, 0, call_modern, 0, 0, &[0]));
    m.extend(mcp_req(5, 0, 2, 0, 0, 0, 0, call_modern, 0, 0, &[0]));
    m.extend(mcp_req(0, 0, 0, 0, 0, 2, 1, call_modern, 1, 1, &[0]));
    m.extend(mcp_req(0, 0, 4, 0, 0, 0, 1, call_modern, 1, 1, &[0]));
    put(dir, "mcp_gate", "rejects", &m)?;
    // seed4: alice's session used by bob, deleted by alice, then reused; a clock step in between.
    let mut m = vec![0u8];
    m.extend(mcp_req(0, 0, 0, 0, 0, 0, 0, init, 0, 0, &[0]));
    m.extend_from_slice(ok1);
    m.extend(mcp_req(0, 0, 0, 0, 1, 0, 3, call_legacy, 0, 0, &[2, 0]));
    m.extend_from_slice(&[6, 2]);
    m.extend(mcp_req(6, 0, 0, 0, 0, 0, 3, call_legacy, 0, 0, &[2, 0]));
    m.extend(mcp_req(0, 0, 0, 0, 0, 0, 3, call_legacy, 0, 0, &[2, 0]));
    put(dir, "mcp_gate", "session_misuse", &m)?;
    Ok(())
}
