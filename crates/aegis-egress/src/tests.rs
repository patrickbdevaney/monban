//! Unit tests: classification, strict URL parsing, policy, vetting with an injected resolver, the redirect loop with
//! a scripted connector, the HTTP/1.1 reader, and real loopback fetches (Host header, caps, deadline).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::*;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn classify_table() {
    let cases: &[(&str, AddrClass)] = &[
        ("8.8.8.8", AddrClass::Public),
        ("1.1.1.1", AddrClass::Public),
        ("0.0.0.0", AddrClass::Unspecified),
        ("0.1.2.3", AddrClass::ThisNetwork),
        ("10.1.2.3", AddrClass::Private),
        ("172.16.0.1", AddrClass::Private),
        ("172.31.255.255", AddrClass::Private),
        ("172.32.0.1", AddrClass::Public),
        ("192.168.1.1", AddrClass::Private),
        ("100.64.0.1", AddrClass::SharedAddressSpace),
        ("100.100.100.200", AddrClass::Metadata),
        ("127.0.0.1", AddrClass::Loopback),
        ("127.255.255.254", AddrClass::Loopback),
        ("169.254.169.254", AddrClass::Metadata),
        ("169.254.170.2", AddrClass::Metadata),
        ("169.254.1.1", AddrClass::LinkLocal),
        ("192.0.0.8", AddrClass::Reserved),
        ("192.0.2.1", AddrClass::Documentation),
        ("198.51.100.1", AddrClass::Documentation),
        ("203.0.113.1", AddrClass::Documentation),
        ("198.18.0.1", AddrClass::Benchmarking),
        ("198.19.255.1", AddrClass::Benchmarking),
        ("192.88.99.1", AddrClass::Reserved),
        ("224.0.0.1", AddrClass::Multicast),
        ("239.255.255.250", AddrClass::Multicast),
        ("240.0.0.1", AddrClass::Reserved),
        ("255.255.255.255", AddrClass::Broadcast),
        ("::", AddrClass::Unspecified),
        ("::1", AddrClass::Loopback),
        ("::ffff:127.0.0.1", AddrClass::Ipv4Mapped),
        ("::ffff:8.8.8.8", AddrClass::Ipv4Mapped),
        ("::127.0.0.1", AddrClass::Ipv4Compatible),
        ("64:ff9b::7f00:1", AddrClass::Nat64),
        ("64:ff9b::a9fe:a9fe", AddrClass::Nat64),
        ("64:ff9b::808:808", AddrClass::Public),
        ("64:ff9b:1::808:808", AddrClass::Nat64LocalUse),
        ("2002:7f00:1::", AddrClass::SixToFour),
        ("2002:a00:1::1", AddrClass::SixToFour),
        ("2002:808:808::1", AddrClass::Public),
        ("2001:0:4136:e378:8000:63bf:3fff:fdd2", AddrClass::Teredo),
        ("2001:db8::1", AddrClass::Documentation),
        ("3fff::1", AddrClass::Documentation),
        ("2001:2::1", AddrClass::Benchmarking),
        ("2001:10::1", AddrClass::Reserved),
        ("100::1", AddrClass::Reserved),
        ("fc00::1", AddrClass::UniqueLocal),
        ("fd12:3456::1", AddrClass::UniqueLocal),
        ("fd00:ec2::254", AddrClass::Metadata),
        ("fe80::1", AddrClass::LinkLocal),
        ("fec0::1", AddrClass::SiteLocal),
        ("ff02::1", AddrClass::Multicast),
        ("5f00::1", AddrClass::Reserved),
        ("2606:4700:4700::1111", AddrClass::Public),
        ("2a00:1450::1", AddrClass::Public),
    ];
    for (a, c) in cases {
        assert_eq!(classify(ip(a)), *c, "{a}");
    }
}

#[test]
fn url_strict() {
    let ok: &[(&str, &str)] = &[
        ("https://example.com", "https://example.com/"),
        ("HTTPS://EXAMPLE.COM/A?b=c#frag", "https://example.com/A?b=c"),
        ("https://example.com:443/x", "https://example.com/x"),
        ("http://example.com:8080?q", "http://example.com:8080/?q"),
        ("https://93.184.216.34/", "https://93.184.216.34/"),
        ("https://[2606:4700::1111]:8443/", "https://[2606:4700::1111]:8443/"),
        ("https://xn--bcher-kva.example/", "https://xn--bcher-kva.example/"),
    ];
    for (i, o) in ok {
        assert_eq!(Url::parse(i).map(|u| u.to_string()), Ok(o.to_string()), "{i}");
    }
    let bad: &[(&str, &str)] = &[
        ("ftp://example.com/", "scheme"),
        ("file:///etc/passwd", "scheme"),
        ("https://user:pw@example.com/", "userinfo"),
        ("https://example.com@evil.com/", "userinfo"),
        ("https://example.com./", "trailing-dot"),
        ("http://0177.0.0.1/", "ipv4-noncanonical"),
        ("http://0x7f.0.0.1/", "ipv4-noncanonical"),
        ("http://2130706433/", "ipv4-noncanonical"),
        ("http://127.1/", "ipv4-noncanonical"),
        ("http://127.000.000.001/", "ipv4-noncanonical"),
        ("http://[fe80::1%25eth0]/", "zone-id"),
        ("http://[fe80::1%eth0]/", "zone-id"),
        ("http://example.com:0/", "port"),
        ("http://example.com:65536/", "port"),
        ("http://example.com:080/", "port"),
        ("http://example.com:/", "port"),
        ("http://example.com:80:443/", "port"),
        ("http://example.com:+80/", "port"),
        ("http://ex ample.com/", "bad-char"),
        ("http://example.com\\@evil.com/", "backslash"),
        ("http://exa%6dple.com/", "host-percent"),
        ("http://bücher.example/", "bad-char"),
        ("http://under_score.example/", "host"),
        ("http:///x", "empty-host"),
        ("http:/example.com/", "no-scheme"),
        ("http://example.com/a b", "bad-char"),
        ("http://example.com/%zz", "bad-percent"),
        ("http://[::1/", "ipv6"),
    ];
    for (i, r) in bad {
        assert_eq!(Url::parse(i), Err(EgressError::InvalidUrl(r)), "{i}");
    }
}

#[test]
fn url_join() {
    let base = Url::parse("https://a.example/dir/page?x=1").unwrap();
    let j = |l: &str| base.join(l).map(|u| u.to_string());
    assert_eq!(j("/root"), Ok("https://a.example/root".into()));
    assert_eq!(j("other"), Ok("https://a.example/dir/other".into()));
    assert_eq!(j("?y=2"), Ok("https://a.example/dir/page?y=2".into()));
    assert_eq!(j("//b.example/p"), Ok("https://b.example/p".into()));
    assert_eq!(j("http://c.example/"), Ok("http://c.example/".into()));
    assert_eq!(j("https:evil.example"), Err(EgressError::InvalidUrl("no-scheme")));
    assert_eq!(j("javascript:alert(1)"), Err(EgressError::InvalidUrl("no-scheme")));
    assert_eq!(j("gopher://x/"), Err(EgressError::InvalidUrl("scheme")));
    assert_eq!(j(""), Err(EgressError::BadRedirect("empty-location")));
}

#[test]
fn prefix_and_policy() {
    let p = Prefix::parse("127.0.0.1/32").unwrap();
    assert!(p.contains(ip("127.0.0.1")));
    assert!(!p.contains(ip("127.0.0.2")));
    assert!(!p.contains(ip("::ffff:127.0.0.1")));
    assert!(Prefix::parse("10.0.0.0/33").is_none());
    assert!(Prefix::parse("fd00::/8").unwrap().contains(ip("fd12::1")));

    let pol = Policy {
        allowed_hosts: vec![HostRule::Exact("a.example".into()), HostRule::Suffix("b.example".into())],
        ..Policy::default()
    };
    let u = |s: &str| Url::parse(s).unwrap();
    assert!(pol.host_allowed(&u("https://a.example/")));
    assert!(!pol.host_allowed(&u("https://x.a.example/")));
    assert!(pol.host_allowed(&u("https://x.b.example/")));
    assert!(!pol.host_allowed(&u("https://b.example/")));
    assert!(!pol.host_allowed(&u("https://xb.example/")));
    assert!(pol.port_allowed(&u("https://a.example/")));
    assert!(!pol.port_allowed(&u("https://a.example:8443/")));

    // Metadata is never re-admittable even if a prefix covers it.
    let pol = Policy { readmit: vec![Prefix::parse("0.0.0.0/0").unwrap()], ..Policy::default() };
    assert!(check_addr(&pol, ip("10.0.0.1")).is_ok());
    assert!(check_addr(&pol, ip("169.254.169.254")).is_err());
    assert!(check_addr(&pol, ip("169.254.1.1")).is_err());
    assert!(check_addr(&pol, ip("224.0.0.1")).is_err());
}

/// Scripted resolver: per host, the i-th query gets the i-th answer set (the last one repeats). Counts queries.
#[derive(Default)]
struct Script {
    answers: BTreeMap<String, Vec<Vec<IpAddr>>>,
    queries: Mutex<BTreeMap<String, usize>>,
}

impl Script {
    fn with(mut self, host: &str, sets: &[&[&str]]) -> Self {
        self.answers.insert(host.into(), sets.iter().map(|s| s.iter().map(|a| ip(a)).collect()).collect());
        self
    }
    fn count(&self, host: &str) -> usize {
        self.queries.lock().unwrap().get(host).copied().unwrap_or(0)
    }
}

impl Resolver for &Script {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<Vec<IpAddr>, EgressError>> {
        Box::pin(async move {
            let mut q = self.queries.lock().unwrap();
            let n = q.entry(host.to_string()).or_insert(0);
            let i = *n;
            *n += 1;
            let sets = self.answers.get(host).ok_or_else(|| EgressError::Resolve("nxdomain".into()))?;
            Ok(sets.get(i).or(sets.last()).cloned().unwrap_or_default())
        })
    }
}

/// Scripted connector: records peers, answers redirects from a table keyed by the hop URL.
#[derive(Default)]
struct Sim {
    redirects: BTreeMap<String, (u16, String)>,
    seen: Mutex<Vec<(SocketAddr, String, String)>>,
}

impl Connector for &Sim {
    fn exchange<'a>(&'a self, hop: Hop<'a>) -> BoxFuture<'a, Result<Exchanged, EgressError>> {
        Box::pin(async move {
            let peer = hop.addrs.first().ok_or(EgressError::Connect("none".into()))?.get();
            self.seen.lock().unwrap().push((peer, hop.url.to_string(), hop.url.host_header()));
            let response = match self.redirects.get(&hop.url.to_string()) {
                Some((s, l)) => {
                    RawResponse { status: *s, headers: vec![("location".into(), l.as_bytes().to_vec())], body: vec![] }
                }
                None => RawResponse { status: 200, headers: vec![], body: b"ok".to_vec() },
            };
            Ok(Exchanged { peer, response })
        })
    }
}

fn pol(hosts: &[&str]) -> Policy {
    Policy {
        allowed_hosts: hosts.iter().map(|h| HostRule::Exact((*h).into())).collect(),
        allow_plain_http: true,
        ..Policy::default()
    }
}

fn run_fetch(script: &Script, sim: &Sim, policy: &Policy, url: &str) -> Result<Response, EgressError> {
    let url = Url::parse(url)?;
    rt().block_on(Egress::new(script, sim).fetch(policy, Request::get(url)))
}

#[test]
fn vet_rejects_any_forbidden_answer() {
    let s = Script::default().with("a.example", &[&["93.184.216.34", "10.0.0.1"]]);
    let sim = Sim::default();
    let r = run_fetch(&s, &sim, &pol(&["a.example"]), "http://a.example/");
    assert!(matches!(r, Err(EgressError::ForbiddenAddress { .. })), "{r:?}");
    assert!(sim.seen.lock().unwrap().is_empty());
}

#[test]
fn rebinding_resolves_once_and_connects_to_vetted_ip() {
    let s = Script::default().with("a.example", &[&["93.184.216.34"], &["127.0.0.1"]]);
    let sim = Sim::default();
    let r = run_fetch(&s, &sim, &pol(&["a.example"]), "http://a.example/x").unwrap();
    assert_eq!(r.peers, vec!["93.184.216.34:80".parse::<SocketAddr>().unwrap()]);
    assert_eq!(s.count("a.example"), 1);
    let seen = sim.seen.lock().unwrap();
    assert_eq!(seen[0].2, "a.example"); // Host header from the original name
}

#[test]
fn redirect_policy() {
    let mk = |from: &str, to: &str| {
        let mut sim = Sim::default();
        sim.redirects.insert(from.into(), (302, to.into()));
        sim
    };
    let s = Script::default()
        .with("a.example", &[&["93.184.216.34"]])
        .with("b.example", &[&["93.184.216.35"]])
        .with("evil.example", &[&["169.254.169.254"]]);
    let both = pol(&["a.example", "b.example", "evil.example"]);
    let cross = Policy { cross_origin_redirects: true, ..both.clone() };

    // Same-origin redirect followed; each hop re-resolved once.
    let sim = mk("http://a.example/", "/next");
    let r = run_fetch(&s, &sim, &both, "http://a.example/").unwrap();
    assert_eq!(r.url.to_string(), "http://a.example/next");
    assert_eq!(r.peers.len(), 2);

    // Cross-origin refused unless allowed.
    let sim = mk("http://a.example/", "http://b.example/");
    assert_eq!(run_fetch(&s, &sim, &both, "http://a.example/").err(), Some(EgressError::CrossOriginRedirect));
    let sim = mk("http://a.example/", "http://b.example/");
    assert!(run_fetch(&s, &sim, &cross, "http://a.example/").is_ok());

    // Redirect to a metadata-resolving host: re-vetted and refused, never connected.
    let sim = mk("http://a.example/", "http://evil.example/");
    let r = run_fetch(&s, &sim, &cross, "http://a.example/");
    assert!(matches!(r, Err(EgressError::ForbiddenAddress { class: AddrClass::Metadata, .. })), "{r:?}");
    assert_eq!(sim.seen.lock().unwrap().len(), 1);

    // Redirect to a literal private address.
    let sim = mk("http://a.example/", "http://10.0.0.1/");
    let r = run_fetch(&s, &sim, &cross.clone_with_hosts(&["a.example", "10.0.0.1"]), "http://a.example/");
    assert!(matches!(r, Err(EgressError::ForbiddenAddress { .. })), "{r:?}");

    // Redirect to a non-allowlisted host.
    let sim = mk("http://a.example/", "http://c.example/");
    assert_eq!(run_fetch(&s, &sim, &cross, "http://a.example/").err(), Some(EgressError::HostNotAllowed));

    // Scheme downgrade.
    let sim = mk("https://a.example/", "http://a.example/");
    assert_eq!(run_fetch(&s, &sim, &cross, "https://a.example/").err(), Some(EgressError::SchemeDowngrade));

    // Hop limit.
    let sim = mk("http://a.example/", "/");
    let lim = Policy { max_redirects: 2, ..both.clone() };
    assert_eq!(run_fetch(&s, &sim, &lim, "http://a.example/").err(), Some(EgressError::TooManyRedirects));
    assert_eq!(sim.seen.lock().unwrap().len(), 3);
}

trait CloneWithHosts {
    fn clone_with_hosts(&self, h: &[&str]) -> Policy;
}
impl CloneWithHosts for Policy {
    fn clone_with_hosts(&self, h: &[&str]) -> Policy {
        Policy { allowed_hosts: h.iter().map(|x| HostRule::Exact((*x).into())).collect(), ..self.clone() }
    }
}

#[test]
fn scheme_host_port_gates() {
    let s = Script::default().with("a.example", &[&["93.184.216.34"]]);
    let sim = Sim::default();
    let https_only = Policy { allow_plain_http: false, ..pol(&["a.example"]) };
    assert_eq!(run_fetch(&s, &sim, &https_only, "http://a.example/").err(), Some(EgressError::SchemeNotAllowed));
    assert_eq!(run_fetch(&s, &sim, &pol(&["b.example"]), "http://a.example/").err(), Some(EgressError::HostNotAllowed));
    assert_eq!(
        run_fetch(&s, &sim, &pol(&["a.example"]), "http://a.example:22/").err(),
        Some(EgressError::PortNotAllowed)
    );
    assert_eq!(s.count("a.example"), 0);
    let r = run_fetch(&s, &sim, &pol(&["127.0.0.1"]), "http://127.0.0.1/");
    assert!(matches!(r, Err(EgressError::ForbiddenAddress { class: AddrClass::Loopback, .. })));
    let r = run_fetch(&s, &sim, &pol(&["::ffff:127.0.0.1"]), "http://[::ffff:127.0.0.1]/");
    assert!(matches!(r, Err(EgressError::ForbiddenAddress { class: AddrClass::Ipv4Mapped, .. })), "{r:?}");
}

#[test]
fn headers_validated() {
    let s = Script::default().with("a.example", &[&["93.184.216.34"]]);
    let sim = Sim::default();
    for h in [("Host", "evil"), ("X-A", "a\r\nInjected: 1"), ("Bad Name", "x"), ("Transfer-Encoding", "chunked")] {
        let req = Request {
            headers: vec![(h.0.into(), h.1.into())],
            ..Request::get(Url::parse("http://a.example/").unwrap())
        };
        let r = rt().block_on(Egress::new(&s, &sim).fetch(&pol(&["a.example"]), req));
        assert!(matches!(r, Err(EgressError::BadRequest(_))), "{h:?}");
    }
}

async fn read_response(raw: &[u8], max_body: usize) -> Result<RawResponse, EgressError> {
    let (mut a, mut b) = tokio::io::duplex(1 << 16);
    let raw = raw.to_vec();
    let srv = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let _ = b.read(&mut buf).await;
        let _ = b.write_all(&raw).await;
        drop(b);
    });
    let r = http1::exchange(&mut a, b"GET / HTTP/1.1\r\n\r\n", b"", false, 4096, max_body).await;
    srv.abort();
    r
}

#[test]
fn http1_reader() {
    let rt = rt();
    let r = rt.block_on(read_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", 100)).unwrap();
    assert_eq!((r.status, r.body.as_slice()), (200, &b"hello"[..]));
    let r = rt
        .block_on(read_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n",
            100,
        ))
        .unwrap();
    assert_eq!(r.body, b"abcde");
    let r = rt.block_on(read_response(b"HTTP/1.0 200 OK\r\n\r\nclose-delimited", 100)).unwrap();
    assert_eq!(r.body, b"close-delimited");
    let r = rt.block_on(read_response(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No\r\n\r\n", 100)).unwrap();
    assert_eq!(r.status, 204);
    let e = |raw: &[u8], max| rt.block_on(read_response(raw, max)).err();
    assert_eq!(e(b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n", 100), Some(EgressError::ResponseTooLarge));
    assert_eq!(e(b"HTTP/1.1 200 OK\r\n\r\n0123456789", 5), Some(EgressError::ResponseTooLarge));
    assert_eq!(
        e(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n0123456789abcdef\r\n0\r\n\r\n", 8),
        Some(EgressError::ResponseTooLarge)
    );
    assert_eq!(
        e(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n", 100),
        Some(EgressError::BadResponse("te-and-cl"))
    );
    assert_eq!(
        e(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab", 100),
        Some(EgressError::BadResponse("content-length"))
    );
    assert_eq!(e(b"HTTP/1.1 200 OK\r\n folded\r\n\r\n", 100), Some(EgressError::BadResponse("obs-fold")));
    assert_eq!(e(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc", 100), Some(EgressError::BadResponse("truncated")));
    assert_eq!(e(b"SSH-2.0-OpenSSH\r\n\r\n", 100), Some(EgressError::BadResponse("status-line")));
    let big = format!("HTTP/1.1 200 OK\r\nX: {}\r\n\r\n", "a".repeat(5000));
    assert_eq!(e(big.as_bytes(), 100), Some(EgressError::HeadersTooLarge));
}

/// Real loopback server: answers each connection with `reply`, after `delay`, and records the request head.
async fn serve(reply: Vec<u8>, delay: Duration) -> (u16, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = s.read(&mut buf).await.unwrap_or(0);
        let _ = tx.send(buf[..n].to_vec());
        tokio::time::sleep(delay).await;
        let _ = s.write_all(&reply).await;
    });
    (port, rx)
}

fn loop_policy(port: u16) -> Policy {
    Policy {
        allowed_hosts: vec![HostRule::Exact("svc.test".into())],
        allowed_ports: vec![port],
        allow_plain_http: true,
        readmit: vec![Prefix::parse("127.0.0.1/32").unwrap()],
        ..Policy::default()
    }
}

#[test]
fn loopback_fetch_host_header_caps_deadline() {
    let rt = rt();
    rt.block_on(async {
        let s = Script::default().with("svc.test", &[&["127.0.0.1"]]);
        let (port, head) = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(), Duration::ZERO).await;
        let url = Url::parse(&format!("http://svc.test:{port}/p?q=1")).unwrap();
        let r = Egress::new(&s, NetConnector::plain()).fetch(&loop_policy(port), Request::get(url)).await.unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"ok"[..]));
        let head = String::from_utf8(head.await.unwrap()).unwrap();
        assert!(head.starts_with("GET /p?q=1 HTTP/1.1\r\n"), "{head}");
        assert!(head.contains(&format!("\r\nHost: svc.test:{port}\r\n")), "{head}");

        // Without the readmit prefix the same fetch is refused before any connect.
        let (port, _h) = serve(Vec::new(), Duration::ZERO).await;
        let url = Url::parse(&format!("http://svc.test:{port}/")).unwrap();
        let p = Policy { readmit: vec![], ..loop_policy(port) };
        let r = Egress::new(&s, NetConnector::plain()).fetch(&p, Request::get(url)).await;
        assert!(matches!(r, Err(EgressError::ForbiddenAddress { .. })));

        // Body cap.
        let (port, _h) =
            serve(b"HTTP/1.1 200 OK\r\n\r\n".iter().chain(&[b'x'; 5000]).copied().collect(), Duration::ZERO).await;
        let url = Url::parse(&format!("http://svc.test:{port}/")).unwrap();
        let p = Policy { max_response_bytes: 1000, ..loop_policy(port) };
        let r = Egress::new(&s, NetConnector::plain()).fetch(&p, Request::get(url)).await;
        assert_eq!(r.err(), Some(EgressError::ResponseTooLarge));

        // Deadline.
        let (port, _h) = serve(b"HTTP/1.1 200 OK\r\n\r\n".to_vec(), Duration::from_secs(5)).await;
        let url = Url::parse(&format!("http://svc.test:{port}/")).unwrap();
        let p = Policy { deadline: Duration::from_millis(200), ..loop_policy(port) };
        let r = Egress::new(&s, NetConnector::plain()).fetch(&p, Request::get(url)).await;
        assert_eq!(r.err(), Some(EgressError::Timeout));
    });
}

#[test]
fn https_without_tls_feature_fails_closed() {
    let s = Script::default().with("a.example", &[&["93.184.216.34"]]);
    let p = Policy { allowed_hosts: vec![HostRule::Exact("a.example".into())], ..Policy::default() };
    let url = Url::parse("https://a.example/").unwrap();
    let r = rt().block_on(Egress::new(&s, NetConnector::plain()).fetch(&p, Request::get(url)));
    assert_eq!(r.err(), Some(EgressError::TlsUnavailable));
}

/// Test-only stand-in for the config aegis-tls builds (aegis-egress may not depend on aegis-tls, even as a
/// dev-dependency: same layer). The profile itself is tested in aegis-tls tests/client_profile.rs.
#[cfg(feature = "tls-client")]
fn injected_like_aegis_tls() -> rustls::ClientConfig {
    let mut c =
        rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
    c.resumption = rustls::client::Resumption::disabled();
    c.enable_early_data = false;
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    c
}

#[cfg(feature = "tls-client")]
#[test]
fn tls_client_accepts_conforming_injected_config() {
    let t = TlsClient::from_config(std::sync::Arc::new(injected_like_aegis_tls())).unwrap();
    assert!(tls::check_client_invariants(t.config()).is_ok());
}

#[cfg(feature = "tls-client")]
#[test]
fn tls_client_refuses_misbuilt_config() {
    use rustls::client::Resumption;
    let mutants: [fn(&mut rustls::ClientConfig); 6] = [
        |c| c.enable_early_data = true,
        |c| c.resumption = Resumption::default(),
        |c| c.resumption = Resumption::in_memory_sessions(8),
        |c| c.alpn_protocols = vec![b"h2".to_vec()],
        |c| c.alpn_protocols.push(b"h2".to_vec()),
        |c| c.alpn_protocols.clear(),
    ];
    for (i, m) in mutants.iter().enumerate() {
        let mut c = injected_like_aegis_tls();
        m(&mut c);
        assert!(
            matches!(TlsClient::from_config(std::sync::Arc::new(c)), Err(EgressError::Tls(_))),
            "mutant {i} accepted"
        );
    }
}

/// Totality: arbitrary bytes never panic the URL parser or join.
#[test]
fn url_parser_total() {
    let base = Url::parse("https://a.example/d/p").unwrap();
    let alphabet = b"htps:/[]@%.:0x7f1?#\\aZ-_~ \t\xff";
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..100_000 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let len = (x % 40) as usize;
        let mut s = Vec::with_capacity(len);
        let mut y = x;
        for _ in 0..len {
            y = y.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            s.push(alphabet[(y >> 33) as usize % alphabet.len()]);
        }
        let s = String::from_utf8_lossy(&s);
        let _ = Url::parse(&format!("http://{s}"));
        let _ = Url::parse(&s);
        let _ = base.join(&s);
    }
}
