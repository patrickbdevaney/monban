//! canon-subject: speaks the canon-diff line protocol (oracles/canon-diff/README.md) on stdin/stdout using only
//! monban-canon's public API.
//!
//! In:  `{"id": N, "kind": K, "input": X}` per line.
//! Out: `{"id": N, "accept": <canonical>}` or `{"id": N, "reject": "<status> <reason>"}` per line.
//! Kinds: path query query_typed host origin cookie ctype json tenant headers request. Lines that cannot be read
//! at all (no id) are skipped, which the oracle counts as a protocol error.
#![forbid(unsafe_code)]

mod proto;

use std::io::{BufRead, BufWriter, Write};

use monban_canon::{
    Proto, QueryMode, Reject, RequestIdentity, Scheme, Vhost, canon_cookie, canon_headers, canon_json,
    canon_media_type, canon_origin, canon_path, canon_query, canon_request, canon_sni, canon_tenant, header_fields,
};
use proto::{Pj, write_str};

/// A protocol value the reference would see as "not a string": mapped to bytes that every canonicalizer rejects
/// exactly as it rejects a non-string (non-ASCII, no '@', not empty).
const NOT_A_STRING: &[u8] = b"\xff";

enum Answer {
    Accept(String),
    Reject(String),
}

fn rejected(e: &Reject) -> Answer {
    Answer::Reject(e.to_string())
}

fn accept_str(b: &[u8]) -> Answer {
    let mut s = String::new();
    write_str(&mut s, b);
    Answer::Accept(s)
}

fn string_kind(kind: &str, x: &[u8]) -> Answer {
    let r = match kind {
        "path" => canon_path(x).map(|c| c.as_bytes().to_vec()),
        "query" => canon_query(x, QueryMode::Opaque).map(|c| c.as_bytes().to_vec()),
        "query_typed" => canon_query(x, QueryMode::Typed).map(|c| c.as_bytes().to_vec()),
        "host" => canon_sni(x).map(|c| c.as_bytes().to_vec()),
        "origin" => canon_origin(x).map(|c| c.as_bytes().to_vec()),
        "cookie" => canon_cookie(x).map(|c| c.as_bytes().to_vec()),
        "ctype" => canon_media_type(x).map(|c| c.as_bytes().to_vec()),
        "json" => canon_json(x).map(|c| c.as_bytes().to_vec()),
        "tenant" => canon_tenant(x).map(|c| c.as_bytes().to_vec()),
        _ => return Answer::Reject("400 unknown kind".to_string()),
    };
    match r {
        Ok(b) => accept_str(&b),
        Err(e) => rejected(&e),
    }
}

fn headers_kind(x: &Pj) -> Answer {
    let Pj::Arr(items) = x else {
        return Answer::Reject("400 headers: not a list of strings".to_string());
    };
    let mut lines: Vec<&[u8]> = Vec::with_capacity(items.len());
    for it in items {
        match it {
            Pj::Str(s) => lines.push(s),
            _ => return Answer::Reject("400 headers: not a list of strings".to_string()),
        }
    }
    match canon_headers(&lines) {
        Ok(c) => {
            let mut s = String::from("[");
            for (i, (n, v)) in header_fields(&c).enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push('[');
                write_str(&mut s, n);
                s.push(',');
                write_str(&mut s, v);
                s.push(']');
            }
            s.push(']');
            Answer::Accept(s)
        }
        Err(e) => rejected(&e),
    }
}

/// `None` when absent or JSON null; non-strings become [`NOT_A_STRING`].
fn opt_bytes(v: Option<&Pj>) -> Option<&[u8]> {
    match v {
        None | Some(Pj::Null) => None,
        Some(Pj::Str(s)) => Some(s),
        Some(_) => Some(NOT_A_STRING),
    }
}

fn request_kind(r: &Pj) -> Answer {
    let Pj::Obj(_) = r else {
        return Answer::Reject("400 request: not an object".to_string());
    };
    let str_of = |k: &str| match r.get(k) {
        Some(Pj::Str(s)) => s.as_slice(),
        _ => NOT_A_STRING,
    };
    let proto = Proto::parse(str_of("proto"));
    let scheme = Scheme::parse(str_of("scheme"));
    let hosts: Vec<&[u8]> = match r.get("host") {
        Some(v) if v.truthy() => match v {
            Pj::Arr(a) => a
                .iter()
                .map(|h| match h {
                    Pj::Str(s) => s.as_slice(),
                    _ => NOT_A_STRING,
                })
                .collect(),
            _ => return rejected(&Reject::bad_envelope()),
        },
        _ => Vec::new(),
    };
    let (proto, scheme) = match (proto, scheme) {
        (Ok(p), Ok(s)) => (p, s),
        (Err(e), _) | (_, Err(e)) => return rejected(&e),
    };
    let mut table: Vec<(&[u8], Vec<&[u8]>)> = Vec::new();
    if let Some(Pj::Obj(m)) = r.get("vhosts") {
        for (k, v) in m {
            let origins = match v {
                Pj::Arr(a) => a
                    .iter()
                    .filter_map(|o| match o {
                        Pj::Str(s) => Some(s.as_slice()),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            };
            table.push((k.as_slice(), origins));
        }
    }
    let vhosts: Vec<Vhost<'_>> = table.iter().map(|(a, o)| Vhost { authority: a, origins: o }).collect();
    let ident = RequestIdentity {
        proto,
        scheme,
        sni: opt_bytes(r.get("sni")),
        authority: opt_bytes(r.get("authority")),
        host: &hosts,
        origin: opt_bytes(r.get("origin")),
    };
    match canon_request(&ident, &vhosts) {
        Ok(a) => {
            let mut s = String::from("{\"vhost\":");
            write_str(&mut s, a.as_bytes());
            s.push('}');
            Answer::Accept(s)
        }
        Err(e) => rejected(&e),
    }
}

fn answer(kind: &str, input: Option<&Pj>) -> Answer {
    match (kind, input) {
        ("headers", Some(x)) => headers_kind(x),
        ("request", Some(x)) => request_kind(x),
        ("headers" | "request", None) => Answer::Reject(format!("400 {kind}: missing input")),
        (_, Some(Pj::Str(s))) => string_kind(kind, s),
        (_, _) => Answer::Reject(format!("400 {kind}: not a string")),
    }
}

fn main() {
    let stdin = std::io::stdin();
    let mut out = BufWriter::new(std::io::stdout().lock());
    for line in stdin.lock().split(b'\n') {
        let Ok(line) = line else { break };
        let Some(msg) = proto::parse(&line) else { continue };
        let Some(Pj::Num(id)) = msg.get("id") else { continue };
        let kind = match msg.get("kind") {
            Some(Pj::Str(k)) => String::from_utf8_lossy(k).into_owned(),
            _ => String::new(),
        };
        let mut s = format!("{{\"id\":{id},");
        match answer(&kind, msg.get("input")) {
            Answer::Accept(v) => {
                s.push_str("\"accept\":");
                s.push_str(&v);
            }
            Answer::Reject(r) => {
                s.push_str("\"reject\":");
                write_str(&mut s, r.as_bytes());
            }
        }
        s.push_str("}\n");
        if out.write_all(s.as_bytes()).is_err() {
            return;
        }
    }
    let _ = out.flush();
}
