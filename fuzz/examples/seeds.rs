//! Writes the initial seed corpus: `cargo run --example seeds -- <corpus dir>` (ci/fuzz.sh seed).
//! Seeds are produced through the crates' own public encoders, so they start inside each accepted language.
#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

use aegis_authz::Decision;
use aegis_authz::pdp::{EntityData, PdpRequest, Uid, Value, encode_reply, encode_request};
use aegis_token::{Caveat, KeyRing, MintParams, TokenL, attenuate, mint};

fn put(dir: &Path, target: &str, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let d = dir.join(target);
    fs::create_dir_all(&d)?;
    fs::write(d.join(name), bytes)
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

    // config (from crates/aegis-config/tests/schema.rs BASE / MINIMAL)
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
    Ok(())
}
