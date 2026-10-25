//! End-to-end over in-memory pipes: h2 (prior knowledge) and HTTP/1.1 through `Server::serve_plain`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::sync::Arc;
use std::time::Duration;

use aegis_canon::kind::{Authority, RoutePath};
use aegis_canon::{Canon, Scheme};
use aegis_transport::exchange::{ExchangeBudget, FrontEnd, Head, HeadVerdict, MessageVerdict, Method, Mode};
use aegis_transport::{App, Reply, ReplyBody, Server, VhostTable, WrapperLimits};
use aegis_types::RouteId;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

struct TestApp;

const BUDGET: ExchangeBudget = ExchangeBudget {
    max_message_bytes: 65_536,
    max_frame_bytes: 16_384,
    max_messages: 1,
    max_total_bytes: 65_536,
    stall_ms: 120_000,
};

impl FrontEnd for TestApp {
    fn on_head(&self, _head: &Head<'_>) -> HeadVerdict {
        HeadVerdict::Accept(Mode::Unary, BUDGET)
    }
    fn on_message(&self, _head: &Head<'_>, _message: &[u8]) -> MessageVerdict {
        MessageVerdict::Continue
    }
}

impl App for TestApp {
    fn route(&self, _a: &Canon<Authority>, path: &Canon<RoutePath>, _m: Method) -> Option<RouteId> {
        match path.as_bytes() {
            b"/" => RouteId::new(1).ok(),
            b"/big" => RouteId::new(2).ok(),
            b"/echo" => RouteId::new(3).ok(),
            _ => None,
        }
    }
    fn respond(&self, head: &Head<'_>, message: &[u8]) -> Reply {
        match head.route.get() {
            2 => Reply::new(200, "application/octet-stream", ReplyBody::Fill { len: 4 << 20, byte: 0xA5 }),
            3 => Reply::new(200, "text/plain", ReplyBody::Owned(format!("{}", message.len()).into_bytes())),
            _ => Reply::new(200, "text/plain", ReplyBody::Static(b"ok\n")),
        }
    }
}

fn limits() -> WrapperLimits {
    let mut l = WrapperLimits::GOLDEN;
    l.set_f8("stall_timeout_ms", 300).unwrap();
    l.set_f8("idle_timeout_ms", 1000).unwrap();
    l
}

fn server() -> Arc<Server<TestApp>> {
    let mut v = VhostTable::new();
    v.add(b"aegis.test", &[]);
    Server::new(TestApp, v, limits()).unwrap()
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

fn pipe(srv: &Arc<Server<TestApp>>) -> (DuplexStream, tokio::task::JoinHandle<()>) {
    let (client, server_io) = tokio::io::duplex(1 << 20);
    let h = tokio::spawn(srv.clone().serve_plain(server_io));
    (client, h)
}

async fn h2_client(io: DuplexStream, window: u32) -> h2::client::SendRequest<hyper::body::Bytes> {
    let (send, conn) = h2::client::Builder::new().initial_window_size(window).handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    send.ready().await.unwrap()
}

fn get(uri: &str) -> http::Request<()> {
    http::Request::builder().method("GET").uri(uri).body(()).unwrap()
}

#[test]
fn h2_ok_421_host_mismatch_and_tbi1() {
    rt().block_on(async {
        let srv = server();
        let (io, _h) = pipe(&srv);
        let mut c = h2_client(io, 65_535).await;

        let (resp, _) = c.send_request(get("http://aegis.test/"), true).unwrap();
        let resp = resp.await.unwrap();
        assert_eq!(resp.status(), 200);
        let mut body = resp.into_body();
        let data = body.data().await.unwrap().unwrap();
        assert_eq!(&data[..], b"ok\n");

        // CANON-6: unknown vhost over h2 -> 421
        let mut c = c.ready().await.unwrap();
        let (resp, _) = c.send_request(get("http://other.test/"), true).unwrap();
        assert_eq!(resp.await.unwrap().status(), 421);

        // Host != :authority -> 400
        let mut c = c.ready().await.unwrap();
        let mut r = get("http://aegis.test/");
        r.headers_mut().insert("host", "other.test".parse().unwrap());
        let (resp, _) = c.send_request(r, true).unwrap();
        assert_eq!(resp.await.unwrap().status(), 400);

        // TBI-1: 129 cookie crumbs (small block) -> 431
        let mut c = c.ready().await.unwrap();
        let mut r = get("http://aegis.test/");
        for i in 0..129 {
            r.headers_mut().append("cookie", format!("c{i}=1").parse().unwrap());
        }
        let (resp, _) = c.send_request(r, true).unwrap();
        assert_eq!(resp.await.unwrap().status(), 431);

        // unknown route -> 404; dot segment -> 400
        let mut c = c.ready().await.unwrap();
        let (resp, _) = c.send_request(get("http://aegis.test/nope"), true).unwrap();
        assert_eq!(resp.await.unwrap().status(), 404);
        let mut c = c.ready().await.unwrap();
        let (resp, _) = c.send_request(get("http://aegis.test/a/../"), true).unwrap();
        assert_eq!(resp.await.unwrap().status(), 400);

        // POST body reaches the handler as the message
        let mut c = c.ready().await.unwrap();
        let r = http::Request::builder().method("POST").uri("http://aegis.test/echo").body(()).unwrap();
        let (resp, mut send) = c.send_request(r, false).unwrap();
        send.send_data(hyper::body::Bytes::from_static(b"12345"), true).unwrap();
        let resp = resp.await.unwrap();
        assert_eq!(resp.status(), 200);
        let data = resp.into_body().data().await.unwrap().unwrap();
        assert_eq!(&data[..], b"5");
        assert!(srv.counters().snapshot().contains(&("authority_rejects", 2)));
    });
}

/// TBI-8: a window-0 client never lets the body progress; the stream is reset at the stall deadline and the
/// connection is closed at the idle deadline.
#[test]
fn h2_window0_stall_reaped_then_idle_close() {
    rt().block_on(async {
        let srv = server();
        let (io, h) = pipe(&srv);
        let mut c = h2_client(io, 0).await;
        let t0 = std::time::Instant::now();
        let (resp, _) = c.send_request(get("http://aegis.test/big"), true).unwrap();
        let resp = resp.await.unwrap();
        assert_eq!(resp.status(), 200);
        let mut body = resp.into_body();
        let r = tokio::time::timeout(Duration::from_secs(5), body.data()).await.unwrap();
        let err = match r {
            Some(Err(e)) => e,
            other => panic!("expected reset, got {other:?}"),
        };
        assert_eq!(err.reason(), Some(h2::Reason::CANCEL));
        let reaped = t0.elapsed();
        assert!(reaped >= Duration::from_millis(250) && reaped < Duration::from_secs(3), "{reaped:?}");
        assert!(srv.counters().snapshot().contains(&("streams_stall_reaped", 1)));
        tokio::time::timeout(Duration::from_secs(5), h).await.unwrap().unwrap();
        assert!(t0.elapsed() < Duration::from_secs(4));
        assert!(srv.counters().snapshot().contains(&("conns_idle_closed", 1)));
    });
}

async fn h1_exchange(srv: &Arc<Server<TestApp>>, req: &[u8]) -> String {
    let (mut io, h) = pipe(srv);
    io.write_all(req).await.unwrap();
    io.shutdown().await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), io.read_to_end(&mut out)).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn h1_strict_framing_and_binding() {
    rt().block_on(async {
        let srv = server();
        let ok = h1_exchange(&srv, b"GET / HTTP/1.1\r\nHost: aegis.test\r\n\r\n").await;
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        assert!(ok.ends_with("ok\n"), "{ok}");

        let cases: &[(&[u8], &str)] = &[
            (b"POST /echo HTTP/1.1\r\nHost: aegis.test\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "HTTP/1.1 400"),
            (b"POST /echo HTTP/1.1\r\nHost: aegis.test\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nz", "HTTP/1.1 400"),
            (b"GET / HTTP/1.1\nHost: aegis.test\r\n\r\n", "HTTP/1.1 400"),
            (b"GET / HTTP/1.1\r\nHost: aegis.test\r\nX: a\r\n b\r\n\r\n", "HTTP/1.1 400"),
            (b"GET / HTTP/1.1\r\nHost: aegis.test\r\nExpect: 100-continue\r\n\r\n", "HTTP/1.1 400"),
            (b"POST /echo HTTP/1.1\r\nHost: aegis.test\r\nTransfer-Encoding: gzip\r\n\r\n", "HTTP/1.1 400"),
            (b"GET / HTTP/1.1\r\nHost: u@aegis.test\r\n\r\n", "HTTP/1.1 400"),
            (b"GET / HTTP/1.1\r\nHost: other.test\r\n\r\n", "HTTP/1.1 404"),
        ];
        for (req, want) in cases {
            let got = h1_exchange(&srv, req).await;
            assert!(got.starts_with(want), "{:?} -> {got:?}", String::from_utf8_lossy(req));
            assert!(!got.contains("200 OK"), "{got}");
        }
        // chunked request body is delivered to the handler intact
        let got = h1_exchange(
            &srv,
            b"POST /echo HTTP/1.1\r\nHost: aegis.test\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
        )
        .await;
        assert!(got.starts_with("HTTP/1.1 200") && got.ends_with("\r\n5"), "{got}");
        assert!(srv.counters().snapshot().iter().any(|(k, v)| *k == "h1_rejects" && *v >= 6));
    });
}

#[test]
fn limits_are_validated_at_construction() {
    let mut l = WrapperLimits::GOLDEN;
    l.ledger_bytes = 16 << 20;
    assert!(Server::new(TestApp, VhostTable::new(), l).is_err());
    let _ = Scheme::Https;
}
