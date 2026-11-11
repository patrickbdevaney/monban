//! Egress URL / address classification (monban-egress: `Url::parse`, `Url::join`, `classify`, `Prefix`,
//! `check_addr`, `vet`, `Policy`), plus the HTTP/1.1 response reader (`http1::exchange`) over an in-memory stream.
//!
//! Properties:
//! - URL parse is canonical: `parse(s) = Ok(u)` => `parse(u.to_string()) = Ok(u)`; the same for `join` results;
//!   a joined URL keeps the base origin unless the reference was absolute / scheme-relative;
//! - `classify` never calls a loopback, unspecified, multicast, private, link-local, unique-local, broadcast or
//!   documentation address (per std's predicates) `Public`; an embedded forbidden IPv4 (mapped, NAT64, 6to4) is
//!   never `Public`;
//! - `check_addr` admits only `Public` or a re-admittable class inside a configured prefix;
//! - `vet` (resolver answers from the input) returns only addresses that pass `check_addr`, on the URL's port, at
//!   most `MAX_ADDRS`, and rejects the hop if any answer is forbidden;
//! - the suffix allowlist never admits the bare suffix or a non-label-aligned match;
//! - `http1::exchange` is total on any response bytes and honours its body cap.
#![no_main]

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::{Pin, pin};
use std::task::{Context, Poll, Waker};

use monban_egress::fetch::MAX_ADDRS;
use monban_egress::http1::{Method, encode_head, exchange};
use monban_egress::{
    AddrClass, BoxFuture, EgressError, HostRule, Policy, Prefix, Resolver, Url, check_addr, classify, vet,
};
use monban_fuzz::{Unstructured, byte, bytes, flag, selftest};
use libfuzzer_sys::fuzz_target;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Poll a future that never actually waits (every I/O here is in memory) to completion, or give up.
fn run<F: Future>(f: F) -> Option<F::Output> {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..1000 {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return Some(v);
        }
    }
    None
}

struct FixedResolver(Vec<IpAddr>);

impl Resolver for FixedResolver {
    fn resolve<'a>(&'a self, _host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, EgressError>> {
        let v = self.0.clone();
        Box::pin(async move { Ok(v) })
    }
}

struct MemStream<'a> {
    input: &'a [u8],
    chunk: usize,
}

impl AsyncRead for MemStream<'_> {
    fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let n = self.chunk.min(self.input.len()).min(buf.remaining());
        let (now, later) = self.input.split_at(n);
        buf.put_slice(now);
        self.input = later;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MemStream<'_> {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn ip(u: &mut Unstructured<'_>) -> IpAddr {
    let mut b = [0u8; 16];
    for x in b.iter_mut() {
        *x = byte(u);
    }
    match byte(u) % 6 {
        0 | 1 => IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])),
        2 => IpAddr::V6(Ipv6Addr::from(b)),
        3 => IpAddr::V6(Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_ipv6_mapped()),
        4 => IpAddr::V6(Ipv6Addr::new(
            0x64,
            0xff9b,
            0,
            0,
            0,
            0,
            u16::from_be_bytes([b[0], b[1]]),
            u16::from_be_bytes([b[2], b[3]]),
        )),
        _ => IpAddr::V6(Ipv6Addr::new(
            0x2002,
            u16::from_be_bytes([b[0], b[1]]),
            u16::from_be_bytes([b[2], b[3]]),
            0,
            0,
            0,
            0,
            1,
        )),
    }
}

fn classify_props(a: IpAddr) {
    let c = classify(a);
    if c != AddrClass::Public {
        return;
    }
    match a {
        IpAddr::V4(v) => {
            let bad = v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || v.is_private()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_documentation();
            assert!(!bad, "{v} classified Public");
        }
        IpAddr::V6(v) => {
            let bad = v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || v.is_unique_local()
                || v.is_unicast_link_local();
            assert!(!bad, "{v} classified Public");
            assert!(v.to_ipv4_mapped().is_none(), "IPv4-mapped {v} classified Public");
            let s = v.segments();
            let embedded = if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                Some(Ipv4Addr::from((u32::from(s[6]) << 16) | u32::from(s[7])))
            } else if s[0] == 0x2002 {
                Some(Ipv4Addr::from((u32::from(s[1]) << 16) | u32::from(s[2])))
            } else {
                None
            };
            if let Some(e) = embedded {
                assert_eq!(classify(IpAddr::V4(e)), AddrClass::Public, "{v} embeds forbidden {e} but is Public");
            }
        }
    }
}

fn url_props(s: &str) -> Option<Url> {
    let u = Url::parse(s).ok()?;
    let again = Url::parse(&u.to_string());
    assert_eq!(again.as_ref(), Ok(&u), "URL does not round-trip through Display: {s:?} -> {u}");
    assert!(u.path().starts_with('/'), "path does not start with /");
    assert!(u.port() != 0, "port 0 accepted");
    Some(u)
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // URLs: split the head of the input into a base and a reference at the first space.
    let text_len = usize::from(byte(&mut u)) * 2;
    let text = String::from_utf8_lossy(bytes(&mut u, text_len)).into_owned();
    let (a, b) = text.split_once(' ').unwrap_or((text.as_str(), ""));
    let base = url_props(a);
    let _ = url_props(b);
    if let Some(base) = &base {
        if let Ok(j) = base.join(b) {
            let again = Url::parse(&j.to_string());
            assert_eq!(again.as_ref(), Ok(&j), "joined URL does not round-trip: {base} + {b:?} -> {j}");
            let absolute = b.starts_with("//") || b.split(['/', '?', '#']).next().is_some_and(|h| h.contains(':'));
            if !absolute {
                assert!(j.same_origin(base), "relative reference {b:?} changed the origin of {base}");
            }
            selftest!(!absolute && j.path().len() > base.path().len() + 4 && j.path().contains('?'));
        }
    }

    // Address classification.
    let addrs: Vec<IpAddr> = (0..1 + byte(&mut u) % 4).map(|_| ip(&mut u)).collect();
    for &a in &addrs {
        classify_props(a);
    }
    let readmit: Vec<Prefix> = (0..byte(&mut u) % 3)
        .filter_map(|_| {
            let a = ip(&mut u);
            Prefix::new(a, byte(&mut u) % 129)
        })
        .collect();
    let policy = Policy {
        allowed_hosts: vec![
            HostRule::Exact("example.com".into()),
            HostRule::Suffix("example.org".into()),
            HostRule::Exact("1.1.1.1".into()),
            HostRule::Exact("2606:4700::1111".into()),
            HostRule::Exact("10.0.0.1".into()),
        ],
        allowed_ports: if flag(&mut u) { Vec::new() } else { vec![443, 8080] },
        allow_plain_http: flag(&mut u),
        readmit: readmit.clone(),
        ..Policy::default()
    };
    for &a in &addrs {
        if check_addr(&policy, a).is_ok() {
            let c = classify(a);
            assert!(
                c == AddrClass::Public || (c.readmittable() && readmit.iter().any(|p| p.contains(a))),
                "check_addr admitted {a} ({c:?})"
            );
        }
    }
    if let Some(url) = &base {
        if policy.host_allowed(url) {
            let key = url.host().to_string();
            assert!(
                key == "example.com"
                    || key.ends_with(".example.org")
                    || key == "1.1.1.1"
                    || key == "[2606:4700::1111]"
                    || key == "10.0.0.1",
                "allowlist admitted {key}"
            );
        }
        let resolver = FixedResolver(addrs.clone());
        if let Some(Ok(vetted)) = run(vet(&policy, url, &resolver)) {
            assert!(!vetted.is_empty() && vetted.len() <= MAX_ADDRS);
            let answers: Vec<IpAddr> = match url.host().ip() {
                Some(lit) => vec![lit],
                None => addrs.clone(),
            };
            assert!(answers.iter().all(|&a| check_addr(&policy, a).is_ok()), "vet passed a forbidden answer");
            for v in vetted {
                let sa = v.get();
                assert_eq!(sa.port(), url.port(), "vetted address on another port");
                assert!(check_addr(&policy, sa.ip()).is_ok(), "vetted address fails check_addr");
            }
        }
    }

    // Response reader over the rest of the input.
    let max_body = usize::from(byte(&mut u)) * 16;
    let max_head = 64 + usize::from(byte(&mut u)) * 32;
    let chunk = 1 + usize::from(byte(&mut u) % 64);
    let head_req = flag(&mut u);
    let rest = u.take_rest();
    if let Ok(url) = Url::parse("http://example.com/x") {
        let head = encode_head(Method::Get, &url, &[], 0);
        let mut s = MemStream { input: rest, chunk };
        if let Some(Ok(r)) = run(exchange(&mut s, &head, &[], head_req, max_head, max_body)) {
            assert!((200..=599).contains(&r.status), "final status {} out of range", r.status);
            assert!(r.body.len() <= max_body, "body cap exceeded");
            assert!(r.headers.iter().all(|(n, _)| n.bytes().all(|c| !c.is_ascii_uppercase())), "header not lowercased");
            if head_req {
                assert!(r.body.is_empty(), "HEAD response with a body");
            }
        }
    }
});
