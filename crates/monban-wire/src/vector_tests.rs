//! The proxy-l4 oracle's parser-level vectors (oracles/proxy-l4/README.md "Vector sets"), checked against
//! [`crate::proxy::parse_v2`] and [`crate::tls_peek::client_hello`]: every `ok` / `reject` / `incomplete` verdict and,
//! for `ok`, every field the reference compares. Reject classes are informational for Rust (README), so they are not
//! compared. The JSON is data, read with the minimal parser below (monban-wire has no dependencies).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::format;
use std::net::IpAddr;
use std::string::{String, ToString};
use std::vec::Vec;

use crate::proxy::{Addresses, Command, Family, ProxyError, Transport, parse_v2};
use crate::tls_peek::{PeekError, client_hello};

const PROXY_V2: &str = include_str!("../../../oracles/proxy-l4/vectors/proxy_v2.json");
const CLIENT_HELLO: &str = include_str!("../../../oracles/proxy-l4/vectors/client_hello.json");

// ------------------------------------------------------------------------------------------------ minimal JSON

#[derive(Clone, Debug, PartialEq)]
enum J {
    Null,
    Bool(bool),
    Num(i64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    fn get(&self, k: &str) -> &J {
        match self {
            J::Obj(m) => m.iter().find(|(n, _)| n == k).map(|(_, v)| v).unwrap_or(&J::Null),
            _ => &J::Null,
        }
    }
    fn s(&self) -> &str {
        match self {
            J::Str(s) => s,
            other => panic!("not a string: {other:?}"),
        }
    }
    fn n(&self) -> i64 {
        match self {
            J::Num(n) => *n,
            other => panic!("not a number: {other:?}"),
        }
    }
    fn arr(&self) -> &[J] {
        match self {
            J::Arr(a) => a,
            other => panic!("not an array: {other:?}"),
        }
    }
    fn opt_s(&self) -> Option<&str> {
        match self {
            J::Null => None,
            j => Some(j.s()),
        }
    }
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
}

impl P<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && self.b[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }
    fn eat(&mut self, c: u8) {
        self.ws();
        assert_eq!(self.b[self.i], c, "json: expected {:?} at {}", c as char, self.i);
        self.i += 1;
    }
    fn peek(&mut self) -> u8 {
        self.ws();
        self.b[self.i]
    }
    fn lit(&mut self, w: &str, v: J) -> J {
        assert!(self.b[self.i..].starts_with(w.as_bytes()), "json: bad literal at {}", self.i);
        self.i += w.len();
        v
    }
    fn string(&mut self) -> String {
        self.eat(b'"');
        let mut out = String::new();
        loop {
            let c = self.b[self.i];
            self.i += 1;
            match c {
                b'"' => return out,
                b'\\' => {
                    let e = self.b[self.i];
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'u' => {
                            let h = core::str::from_utf8(&self.b[self.i..self.i + 4]).unwrap();
                            out.push(char::from_u32(u32::from_str_radix(h, 16).unwrap()).unwrap());
                            self.i += 4;
                        }
                        _ => panic!("json: bad escape"),
                    }
                }
                _ => {
                    // Copy one UTF-8 sequence.
                    let start = self.i - 1;
                    let mut end = self.i;
                    while end < self.b.len() && (self.b[end] & 0xC0) == 0x80 {
                        end += 1;
                    }
                    out.push_str(core::str::from_utf8(&self.b[start..end]).unwrap());
                    self.i = end;
                }
            }
        }
    }
    fn value(&mut self) -> J {
        match self.peek() {
            b'{' => {
                self.eat(b'{');
                let mut m = Vec::new();
                if self.peek() == b'}' {
                    self.eat(b'}');
                    return J::Obj(m);
                }
                loop {
                    let k = self.string();
                    self.eat(b':');
                    m.push((k, self.value()));
                    if self.peek() == b',' {
                        self.eat(b',');
                    } else {
                        self.eat(b'}');
                        return J::Obj(m);
                    }
                }
            }
            b'[' => {
                self.eat(b'[');
                let mut a = Vec::new();
                if self.peek() == b']' {
                    self.eat(b']');
                    return J::Arr(a);
                }
                loop {
                    a.push(self.value());
                    if self.peek() == b',' {
                        self.eat(b',');
                    } else {
                        self.eat(b']');
                        return J::Arr(a);
                    }
                }
            }
            b'"' => J::Str(self.string()),
            b't' => self.lit("true", J::Bool(true)),
            b'f' => self.lit("false", J::Bool(false)),
            b'n' => self.lit("null", J::Null),
            _ => {
                let start = self.i;
                while self.i < self.b.len() && (self.b[self.i] == b'-' || self.b[self.i].is_ascii_digit()) {
                    self.i += 1;
                }
                J::Num(core::str::from_utf8(&self.b[start..self.i]).unwrap().parse().unwrap())
            }
        }
    }
}

fn json(s: &str) -> J {
    let mut p = P { b: s.as_bytes(), i: 0 };
    let v = p.value();
    p.ws();
    assert_eq!(p.i, s.len(), "json: trailing data");
    v
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn load(src: &str, want: usize) -> Vec<J> {
    let doc = json(src);
    assert_eq!(doc.get("count").n(), i64::try_from(want).unwrap());
    let v = doc.get("vectors").arr().to_vec();
    assert_eq!(v.len(), want, "vector count");
    v
}

// ------------------------------------------------------------------------------------------------ PROXY v2

fn proxy_divergence(v: &J) -> Option<String> {
    let buf = unhex(v.get("hex").s());
    let expect = v.get("expect").s();
    let got = parse_v2(&buf);
    let kind = match got {
        Ok(_) => "ok",
        Err(ProxyError::Incomplete) => "incomplete",
        Err(_) => "reject",
    };
    if kind != expect {
        return Some(format!("expected {expect}, got {got:?}"));
    }
    let Ok((h, consumed)) = got else { return None };
    let mut bad = Vec::new();
    if i64::try_from(consumed).unwrap() != v.get("consumed").n() {
        bad.push(format!("consumed {consumed}"));
    }
    let cmd = match h.command {
        Command::Local => "local",
        Command::Proxy => "proxy",
    };
    let fam = match h.family {
        Family::Unspec => "unspec",
        Family::Inet => "inet",
        Family::Inet6 => "inet6",
        Family::Unix => "unix",
    };
    let proto = match h.transport {
        Transport::Unspec => "unspec",
        Transport::Stream => "stream",
        Transport::Dgram => "dgram",
    };
    for (name, g) in [("command", cmd), ("family", fam), ("proto", proto)] {
        if v.get(name).s() != g {
            bad.push(format!("{name} {g}"));
        }
    }
    let ip = |j: &J| j.opt_s().map(|s| s.parse::<IpAddr>().unwrap());
    let port = |j: &J| match j {
        J::Null => None,
        j => Some(u16::try_from(j.n()).unwrap()),
    };
    match h.addresses {
        Addresses::Unspec => {
            for f in ["src", "dst", "src_port", "dst_port"] {
                if v.get(f) != &J::Null {
                    bad.push(format!("{f} missing"));
                }
            }
        }
        Addresses::Inet { src, dst } => {
            if ip(v.get("src")) != Some(src.ip()) || ip(v.get("dst")) != Some(dst.ip()) {
                bad.push(format!("addresses {src} {dst}"));
            }
            if port(v.get("src_port")) != Some(src.port()) || port(v.get("dst_port")) != Some(dst.port()) {
                bad.push(format!("ports {src} {dst}"));
            }
        }
        Addresses::Unix { src, dst } => {
            let strip = |b: &[u8]| {
                let end = b.iter().rposition(|&c| c != 0).map_or(0, |p| p + 1);
                hex(&b[..end])
            };
            if src.len() != 108 || dst.len() != 108 {
                bad.push("unix path field length".to_string());
            }
            if v.get("src").opt_s() != Some(strip(src).as_str()) || v.get("dst").opt_s() != Some(strip(dst).as_str()) {
                bad.push("unix paths".to_string());
            }
            if v.get("src_port") != &J::Null || v.get("dst_port") != &J::Null {
                bad.push("unix ports".to_string());
            }
        }
    }
    let peer = if h.source().is_some() { "src" } else { "transport" };
    if v.get("peer").s() != peer {
        bad.push(format!("peer {peer}"));
    }
    if let Some(s) = h.source()
        && (ip(v.get("src")) != Some(s.ip()) || port(v.get("src_port")) != Some(s.port()))
    {
        bad.push(format!("source {s}"));
    }
    if v.get("stream_accept") != &J::Bool(h.stream_accept()) {
        bad.push(format!("stream_accept {}", h.stream_accept()));
    }
    let tlvs: Vec<J> = h.tlvs().map(|t| J::Arr(std::vec![J::Num(i64::from(t.kind)), J::Str(hex(t.value))])).collect();
    if v.get("tlvs").arr() != tlvs.as_slice() {
        bad.push(format!("tlvs {tlvs:?}"));
    }
    // Every borrowed field lies inside the consumed header.
    let inside = |f: &[u8]| {
        let (d, s) = (buf.as_ptr() as usize, f.as_ptr() as usize);
        f.is_empty() || (s >= d && s + f.len() <= d + consumed)
    };
    if !h.tlvs().all(|t| inside(t.value)) {
        bad.push("tlv outside the header".to_string());
    }
    if bad.is_empty() { None } else { Some(bad.join(", ")) }
}

#[test]
fn proxy_v2_vectors() {
    let vectors = load(PROXY_V2, 242);
    let mut div = Vec::new();
    let mut counts = [0usize; 3];
    for v in &vectors {
        let i = ["ok", "reject", "incomplete"].iter().position(|e| *e == v.get("expect").s()).unwrap();
        counts[i] += 1;
        if let Some(d) = proxy_divergence(v) {
            div.push(format!("{}: {d}", v.get("id").s()));
        }
    }
    assert!(div.is_empty(), "{} PROXY divergence(s):\n{}", div.len(), div.join("\n"));
    assert_eq!(counts, [41, 189, 12], "ok/reject/incomplete counts");
}

// ------------------------------------------------------------------------------------------------ ClientHello

fn ch_divergence(v: &J) -> Option<String> {
    let buf = unhex(v.get("hex").s());
    let expect = v.get("expect").s();
    let got = client_hello(&buf);
    let kind = match got {
        Ok(_) => "ok",
        Err(PeekError::Incomplete) => "incomplete",
        Err(_) => "reject",
    };
    if kind != expect {
        return Some(format!("expected {expect}, got {got:?}"));
    }
    let Ok(p) = got else { return None };
    let mut bad = Vec::new();
    if i64::try_from(p.consumed).unwrap() != v.get("consumed").n() {
        bad.push(format!("consumed {}", p.consumed));
    }
    if v.get("sni").opt_s().map(str::as_bytes) != p.sni {
        bad.push(format!("sni {:?}", p.sni));
    }
    let alpn: Vec<J> = p.alpn_protocols().map(|a| J::Str(hex(a))).collect();
    if v.get("alpn").arr() != alpn.as_slice() {
        bad.push(format!("alpn {alpn:?}"));
    }
    for (name, list) in [
        ("versions", p.version_list().collect::<Vec<_>>()),
        ("sigalgs", p.sigalg_list().collect()),
        ("groups", p.group_list().collect()),
    ] {
        let want: Vec<u16> = v.get(name).arr().iter().map(|j| u16::try_from(j.n()).unwrap()).collect();
        if want != list {
            bad.push(format!("{name} {list:?}"));
        }
    }
    let ta = p.trust_anchors.map(|_| p.trust_anchor_ids().map(|i| J::Str(hex(i))).collect::<Vec<_>>());
    let want_ta = match v.get("trust_anchors") {
        J::Null => None,
        j => Some(j.arr().to_vec()),
    };
    if ta != want_ta {
        bad.push(format!("trust_anchors {ta:?}"));
    }
    let inside = |f: Option<&[u8]>| {
        f.is_none_or(|f| {
            let (d, s) = (buf.as_ptr() as usize, f.as_ptr() as usize);
            s >= d + 5 && s + f.len() <= d + p.consumed
        })
    };
    if ![p.sni, p.alpn, p.versions, p.sigalgs, p.groups, p.trust_anchors].into_iter().all(inside) {
        bad.push("field outside the record".to_string());
    }
    if bad.is_empty() { None } else { Some(bad.join(", ")) }
}

#[test]
fn client_hello_vectors() {
    let vectors = load(CLIENT_HELLO, 84);
    let mut div = Vec::new();
    let mut counts = [0usize; 3];
    for v in &vectors {
        let i = ["ok", "reject", "incomplete"].iter().position(|e| *e == v.get("expect").s()).unwrap();
        counts[i] += 1;
        if let Some(d) = ch_divergence(v) {
            div.push(format!("{}: {d}", v.get("id").s()));
        }
    }
    assert!(div.is_empty(), "{} ClientHello divergence(s):\n{}", div.len(), div.join("\n"));
    assert_eq!(counts, [23, 59, 2], "ok/reject/incomplete counts");
}

/// Every proper prefix of an accepted input is Incomplete (never Ok, never a reject the full input would not get):
/// a receiver that reads byte by byte reaches the same verdict as one that reads it all at once.
#[test]
fn prefixes_of_accepted_vectors_are_incomplete() {
    for v in load(PROXY_V2, 242).iter().filter(|v| v.get("expect").s() == "ok") {
        let buf = unhex(v.get("hex").s());
        let (_, consumed) = parse_v2(&buf).unwrap();
        for k in 0..consumed {
            assert_eq!(parse_v2(&buf[..k]), Err(ProxyError::Incomplete), "{} prefix {k}", v.get("id").s());
        }
    }
    for v in load(CLIENT_HELLO, 84).iter().filter(|v| v.get("expect").s() == "ok") {
        let buf = unhex(v.get("hex").s());
        let consumed = client_hello(&buf).unwrap().consumed;
        for k in 0..consumed {
            assert_eq!(client_hello(&buf[..k]), Err(PeekError::Incomplete), "{} prefix {k}", v.get("id").s());
        }
    }
}

/// Bytes after `consumed` never change the result (no read past the declared length).
#[test]
fn trailing_bytes_do_not_change_the_result() {
    for v in load(PROXY_V2, 242).iter().filter(|v| v.get("expect").s() == "ok") {
        let mut buf = unhex(v.get("hex").s());
        let first = parse_v2(&buf).unwrap();
        let first = (first.0.command, first.0.family, first.0.transport, first.0.source(), first.1);
        buf.extend_from_slice(b"\r\n\r\n\0\r\nQUIT\n\x21\x11\xff\xff garbage");
        let (h, c) = parse_v2(&buf).unwrap();
        assert_eq!((h.command, h.family, h.transport, h.source(), c), first, "{}", v.get("id").s());
    }
    for v in load(CLIENT_HELLO, 84).iter().filter(|v| v.get("expect").s() == "ok") {
        let mut buf = unhex(v.get("hex").s());
        let first = client_hello(&buf).unwrap().consumed;
        buf.extend_from_slice(&[0x16, 0x03, 0x01, 0xff, 0xff, 0x01]);
        assert_eq!(client_hello(&buf).unwrap().consumed, first, "{}", v.get("id").s());
    }
}

#[test]
fn v1_and_its_prefixes_are_refused() {
    for k in 1..=6 {
        assert_eq!(parse_v2(&b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n"[..k]), Err(ProxyError::V1Refused));
    }
    assert_eq!(parse_v2(b""), Err(ProxyError::Incomplete));
}
