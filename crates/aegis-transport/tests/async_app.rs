//! The async request handler (`App::handle`) over h1 and h2: canonical request object, admission hooks, reply
//! fields, handler deadline (504) and draining.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use aegis_canon::kind::{Authority, RoutePath};
use aegis_canon::{Canon, header_fields};
use aegis_transport::exchange::{ExchangeBudget, FrontEnd, Head, HeadVerdict, MessageVerdict, Method, Mode};
use aegis_transport::{App, ConnInfo, HandlerFuture, Reply, ReplyBody, Request, Server, VhostTable, WrapperLimits};
use aegis_types::RouteId;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

#[derive(Default)]
struct AsyncApp {
    arrived: AtomicU64,
    departed: AtomicU64,
    cancelled: AtomicU64,
    refused: AtomicU64,
    closed_admitted: AtomicU64,
}

const BUDGET: ExchangeBudget = ExchangeBudget {
    max_message_bytes: 65_536,
    max_frame_bytes: 16_384,
    max_messages: 1,
    max_total_bytes: 65_536,
    stall_ms: 300,
};

impl FrontEnd for AsyncApp {
    fn on_head(&self, head: &Head<'_>) -> HeadVerdict {
        if head.path.as_bytes() == b"/deny" {
            return HeadVerdict::Reject(403);
        }
        HeadVerdict::Accept(Mode::Unary, BUDGET)
    }
    fn on_message(&self, _head: &Head<'_>, _message: &[u8]) -> MessageVerdict {
        MessageVerdict::Continue
    }
}

impl App for AsyncApp {
    fn route(&self, _a: &Canon<Authority>, path: &Canon<RoutePath>, _m: Method) -> Option<RouteId> {
        match path.as_bytes() {
            b"/echo" | b"/deny" => RouteId::new(1).ok(),
            b"/slow" => RouteId::new(2).ok(),
            _ => None,
        }
    }

    fn handle(&self, req: Request) -> HandlerFuture<'_> {
        Box::pin(async move {
            if req.route.get() == 2 {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            let x =
                header_fields(&req.headers).find(|(n, _)| *n == b"x-a").map(|(_, v)| v.to_vec()).unwrap_or_default();
            let mut body = req.query.as_bytes().to_vec();
            body.push(b'|');
            body.extend_from_slice(&x);
            body.push(b'|');
            body.extend_from_slice(req.body.len().to_string().as_bytes());
            let mut r = Reply::new(200, "text/plain", ReplyBody::Owned(body));
            r.headers = vec![
                (b"x-from-handler".to_vec(), b"1".to_vec()),
                (b"connection".to_vec(), b"x-from-handler".to_vec()),
                (b"content-length".to_vec(), b"999".to_vec()),
            ];
            r
        })
    }

    fn arrive(&self, _conn: &ConnInfo, _first: bool) -> Result<u64, u16> {
        Ok(self.arrived.fetch_add(1, Ordering::Relaxed) + 1)
    }
    fn depart(&self, _ticket: u64, cancelled: bool) {
        self.departed.fetch_add(1, Ordering::Relaxed);
        if cancelled {
            self.cancelled.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn refused(&self, _status: u16) {
        self.refused.fetch_add(1, Ordering::Relaxed);
    }
    fn conn_closed(&self, _conn: &ConnInfo, admitted: bool) {
        if admitted {
            self.closed_admitted.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn server() -> Arc<Server<AsyncApp>> {
    let mut l = WrapperLimits::GOLDEN;
    l.set_f8("stall_timeout_ms", 300).unwrap();
    l.set_f8("idle_timeout_ms", 1000).unwrap();
    let mut v = VhostTable::new();
    v.add(b"aegis.test", &[]);
    Server::new(AsyncApp::default(), v, l).unwrap()
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

fn pipe(srv: &Arc<Server<AsyncApp>>) -> (DuplexStream, tokio::task::JoinHandle<()>) {
    let (client, server_io) = tokio::io::duplex(1 << 20);
    let h = tokio::spawn(srv.clone().serve_plain(server_io));
    (client, h)
}

async fn h1(srv: &Arc<Server<AsyncApp>>, req: &[u8]) -> String {
    let (mut io, h) = pipe(srv);
    io.write_all(req).await.unwrap();
    // No half-close: a client FIN while the handler runs cancels the request (INV-NOMUT-C NC1, tests/cancel.rs).
    // The connection ends at the idle deadline (1 s) after the reply.
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), io.read_to_end(&mut out)).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn h1_async_handler_sees_canonical_request() {
    rt().block_on(async {
        let srv = server();
        let got =
            h1(&srv, b"POST /echo?b=%7e1&a HTTP/1.1\r\nHost: aegis.test\r\nX-A:  v \r\nContent-Length: 3\r\n\r\nabc")
                .await;
        assert!(got.starts_with("HTTP/1.1 200"), "{got}");
        assert!(got.ends_with("b=~1&a|v|3"), "{got}");
        let lower = got.to_ascii_lowercase();
        assert!(lower.contains("x-from-handler: 1"), "{got}");
        assert!(lower.contains("content-length: 10\r\n") && !lower.contains("999"), "{got}");
        assert!(!lower.contains("connection: x-from-handler"), "{got}");
        // 308 carries the canonical query; refusals are reported; on_head rejects are not.
        let got = h1(&srv, b"GET //echo?q=%7e HTTP/1.1\r\nHost: aegis.test\r\n\r\n").await;
        assert!(got.starts_with("HTTP/1.1 308") && got.to_ascii_lowercase().contains("location: /echo?q=~"), "{got}");
        let got = h1(&srv, b"GET /deny HTTP/1.1\r\nHost: aegis.test\r\n\r\n").await;
        assert!(got.starts_with("HTTP/1.1 403"), "{got}");
        // duplicate singleton field: canonical header set rejects it
        let got =
            h1(&srv, b"GET /echo HTTP/1.1\r\nHost: aegis.test\r\nAuthorization: a\r\nAuthorization: b\r\n\r\n").await;
        assert!(got.starts_with("HTTP/1.1 400"), "{got}");
        let app = srv.app();
        assert_eq!(app.arrived.load(Ordering::Relaxed), 4);
        assert_eq!(app.departed.load(Ordering::Relaxed), 4);
        assert_eq!(app.cancelled.load(Ordering::Relaxed), 0);
        assert_eq!(app.refused.load(Ordering::Relaxed), 2);
        assert_eq!(app.closed_admitted.load(Ordering::Relaxed), 4);
    });
}

#[test]
fn handler_deadline_answers_504() {
    rt().block_on(async {
        let srv = server();
        let t0 = std::time::Instant::now();
        let got = h1(&srv, b"GET /slow HTTP/1.1\r\nHost: aegis.test\r\n\r\n").await;
        assert!(got.starts_with("HTTP/1.1 504"), "{got}");
        assert!(t0.elapsed() < Duration::from_secs(3));
    });
}

#[test]
fn h2_async_handler_and_drain() {
    rt().block_on(async {
        let srv = server();
        let (io, h) = pipe(&srv);
        let (send, conn) = h2::client::Builder::new().handshake::<_, hyper::body::Bytes>(io).await.unwrap();
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut c = send.ready().await.unwrap();
        let mut r = http::Request::builder().method("POST").uri("http://aegis.test/echo?z=1").body(()).unwrap();
        r.headers_mut().insert("x-a", "w".parse().unwrap());
        let (resp, mut body) = c.send_request(r, false).unwrap();
        body.send_data(hyper::body::Bytes::from_static(b"12345"), true).unwrap();
        let resp = resp.await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get("x-from-handler").unwrap(), "1");
        assert_eq!(resp.headers().get("content-length").unwrap(), "7");
        let data = resp.into_body().data().await.unwrap().unwrap();
        assert_eq!(&data[..], b"z=1|w|5");
        // drain: graceful GOAWAY, the connection ends without waiting for the idle deadline
        let t0 = std::time::Instant::now();
        srv.drain();
        tokio::time::timeout(Duration::from_secs(3), h).await.unwrap().unwrap();
        assert!(t0.elapsed() < Duration::from_millis(900));
        let _ = conn_task.await;
        assert_eq!(srv.app().closed_admitted.load(Ordering::Relaxed), 1);
    });
}
