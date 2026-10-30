//! INV-NOMUT-C NC1 at the transport: a peer termination before the reply (h2 RST_STREAM, h1 FIN or connection
//! drop) drops the handler future promptly, well inside the exchange stall deadline, so a handler holding a commit
//! gate observes the cancellation. Observed through a drop guard owned by the blocked handler future.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use aegis_canon::Canon;
use aegis_canon::kind::{Authority, RoutePath};
use aegis_transport::exchange::{ExchangeBudget, FrontEnd, Head, HeadVerdict, MessageVerdict, Method, Mode};
use aegis_transport::{App, ConnInfo, HandlerFuture, Reply, ReplyBody, Request, Server, VhostTable, WrapperLimits};
use aegis_types::RouteId;
use h2::Reason;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// Far above the bound the tests assert, so a drop seen in time is the peer termination, not the 504 deadline.
const STALL_MS: u32 = 20_000;
/// The promptness bound asserted for every drop.
const BOUND: Duration = Duration::from_millis(1_000);

#[derive(Default)]
struct BlockApp {
    started: AtomicU64,
    dropped: AtomicU64,
    completed: AtomicU64,
    departed_cancelled: AtomicU64,
    started_note: tokio::sync::Notify,
}

const BUDGET: ExchangeBudget = ExchangeBudget {
    max_message_bytes: 65_536,
    max_frame_bytes: 16_384,
    max_messages: 1,
    max_total_bytes: 65_536,
    stall_ms: STALL_MS,
};

impl FrontEnd for BlockApp {
    fn on_head(&self, _head: &Head<'_>) -> HeadVerdict {
        HeadVerdict::Accept(Mode::Unary, BUDGET)
    }
    fn on_message(&self, _head: &Head<'_>, _message: &[u8]) -> MessageVerdict {
        MessageVerdict::Continue
    }
}

/// Counts its own drop: a handler future that is dropped (not completed) drops it uncompleted.
struct DropGuard<'a>(&'a BlockApp);

impl Drop for DropGuard<'_> {
    fn drop(&mut self) {
        self.0.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

impl App for BlockApp {
    fn route(&self, _a: &Canon<Authority>, path: &Canon<RoutePath>, _m: Method) -> Option<RouteId> {
        match path.as_bytes() {
            b"/block" => RouteId::new(1).ok(),
            b"/short" => RouteId::new(2).ok(),
            _ => None,
        }
    }

    fn handle(&self, req: Request) -> HandlerFuture<'_> {
        Box::pin(async move {
            let guard = DropGuard(self);
            self.started.fetch_add(1, Ordering::SeqCst);
            self.started_note.notify_one();
            if req.route.get() == 1 {
                std::future::pending::<()>().await;
            } else {
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            std::mem::drop(guard);
            self.dropped.fetch_sub(1, Ordering::SeqCst);
            self.completed.fetch_add(1, Ordering::SeqCst);
            Reply::new(200, "text/plain", ReplyBody::Owned(b"done".to_vec()))
        })
    }

    fn arrive(&self, _conn: &ConnInfo, _first: bool) -> Result<u64, u16> {
        Ok(1)
    }
    fn depart(&self, _ticket: u64, cancelled: bool) {
        if cancelled {
            self.departed_cancelled.fetch_add(1, Ordering::SeqCst);
        }
    }
}

fn server() -> Arc<Server<BlockApp>> {
    let mut l = WrapperLimits::GOLDEN;
    l.set_f8("stall_timeout_ms", u64::from(STALL_MS)).unwrap();
    l.set_f8("idle_timeout_ms", 30_000).unwrap();
    let mut v = VhostTable::new();
    v.add(b"aegis.test", &[]);
    Server::new(BlockApp::default(), v, l).unwrap()
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

fn pipe(srv: &Arc<Server<BlockApp>>) -> (DuplexStream, tokio::task::JoinHandle<()>) {
    let (client, server_io) = tokio::io::duplex(1 << 20);
    let h = tokio::spawn(srv.clone().serve_plain(server_io));
    (client, h)
}

async fn wait_started(app: &BlockApp, n: u64) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while app.started.load(Ordering::SeqCst) < n {
            app.started_note.notified().await;
        }
    })
    .await
    .expect("handler started");
}

/// Wait (bounded) until the handler future has been dropped `n` times in total; returns the time it took.
async fn wait_dropped(app: &BlockApp, n: u64) -> Duration {
    let t0 = Instant::now();
    while app.dropped.load(Ordering::SeqCst) < n {
        assert!(t0.elapsed() < BOUND, "handler future not dropped within {BOUND:?}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    t0.elapsed()
}

fn counter(srv: &Server<BlockApp>, name: &str) -> u64 {
    srv.counters().snapshot().into_iter().find(|(k, _)| *k == name).map_or(0, |(_, v)| v)
}

#[test]
fn h2_rst_stream_drops_the_handler_future() {
    rt().block_on(async {
        let srv = server();
        let (io, _h) = pipe(&srv);
        let (send, conn) = h2::client::Builder::new().handshake::<_, hyper::body::Bytes>(io).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut c = send.ready().await.unwrap();
        let r = http::Request::builder().method("POST").uri("http://aegis.test/block").body(()).unwrap();
        let (_resp, mut body) = c.send_request(r, false).unwrap();
        body.send_data(hyper::body::Bytes::from_static(b"x"), true).unwrap();
        let app = srv.app();
        wait_started(app, 1).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(app.dropped.load(Ordering::SeqCst), 0, "the blocked handler is still alive before the reset");
        body.send_reset(Reason::CANCEL);
        let took = wait_dropped(app, 1).await;
        assert!(took < BOUND, "{took:?}");
        assert_eq!(app.completed.load(Ordering::SeqCst), 0);
        assert_eq!(app.departed_cancelled.load(Ordering::SeqCst), 1);
        assert_eq!(counter(&srv, "handlers_aborted"), 1);
        assert_eq!(counter(&srv, "peer_resets"), 1, "the reset is debited from the TBI-5 bucket once");

        // The connection survives the stream reset: a second stream is answered normally.
        let mut c = c.ready().await.unwrap();
        let r = http::Request::builder().method("GET").uri("http://aegis.test/short").body(()).unwrap();
        let (resp, _) = c.send_request(r, true).unwrap();
        let resp = tokio::time::timeout(Duration::from_secs(5), resp).await.unwrap().unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(app.completed.load(Ordering::SeqCst), 1);
        assert_eq!(app.dropped.load(Ordering::SeqCst), 1);
    });
}

const BLOCK_H1: &[u8] = b"POST /block HTTP/1.1\r\nHost: aegis.test\r\nContent-Length: 1\r\n\r\nx";

#[test]
fn h1_fin_drops_the_handler_future() {
    rt().block_on(async {
        let srv = server();
        let (mut io, h) = pipe(&srv);
        io.write_all(BLOCK_H1).await.unwrap();
        let app = srv.app();
        wait_started(app, 1).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(app.dropped.load(Ordering::SeqCst), 0, "the blocked handler is still alive before the FIN");
        io.shutdown().await.unwrap();
        let took = wait_dropped(app, 1).await;
        assert!(took < BOUND, "{took:?}");
        tokio::time::timeout(BOUND, h).await.unwrap().unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(BOUND, io.read_to_end(&mut out)).await;
        assert!(out.is_empty(), "no reply after a cancel: {:?}", String::from_utf8_lossy(&out));
        assert_eq!(app.completed.load(Ordering::SeqCst), 0);
        assert_eq!(app.departed_cancelled.load(Ordering::SeqCst), 1);
        assert_eq!(counter(&srv, "handlers_aborted"), 1);
    });
}

#[test]
fn h1_connection_drop_drops_the_handler_future() {
    rt().block_on(async {
        let srv = server();
        let (mut io, h) = pipe(&srv);
        io.write_all(BLOCK_H1).await.unwrap();
        let app = srv.app();
        wait_started(app, 1).await;
        drop(io);
        let took = wait_dropped(app, 1).await;
        assert!(took < BOUND, "{took:?}");
        tokio::time::timeout(BOUND, h).await.unwrap().unwrap();
        assert_eq!(app.completed.load(Ordering::SeqCst), 0);
        assert_eq!(app.departed_cancelled.load(Ordering::SeqCst), 1);
    });
}

/// Control: a client that stays connected gets the reply of a handler that takes a while, and bytes pipelined
/// while it runs are replayed to hyper (the probe reads ahead, it does not lose data).
#[test]
fn h1_open_client_gets_the_reply_and_pipelined_request() {
    rt().block_on(async {
        let srv = server();
        let (mut io, h) = pipe(&srv);
        io.write_all(b"GET /short HTTP/1.1\r\nHost: aegis.test\r\n\r\n").await.unwrap();
        let app = srv.app();
        wait_started(app, 1).await;
        io.write_all(b"GET /short HTTP/1.1\r\nHost: aegis.test\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), io.read_to_end(&mut out)).await.unwrap().unwrap();
        let got = String::from_utf8_lossy(&out);
        assert_eq!(got.matches("HTTP/1.1 200").count(), 2, "{got}");
        tokio::time::timeout(BOUND, h).await.unwrap().unwrap();
        assert_eq!(app.completed.load(Ordering::SeqCst), 2);
        assert_eq!(app.dropped.load(Ordering::SeqCst), 0);
        assert_eq!(counter(&srv, "handlers_aborted"), 0);
    });
}
