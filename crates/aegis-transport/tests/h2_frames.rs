//! Frame-level HTTP/2 regressions (P2-transport-002): the nine h2spec v2.6.0 cases from oracles/h2-conformance
//! replayed with a raw frame writer over an in-memory pipe, plus the early-421 path that masked them.
//!
//! Each test sends the frame sequence h2spec sends and asserts the RFC 9113 outcome h2spec expects. Requests are
//! addressed to `127.0.0.1:8443`, an IPv4-literal vhost, like h2spec's requests to the subject.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::sync::Arc;
use std::time::Duration;

use aegis_canon::Canon;
use aegis_canon::kind::{Authority, RoutePath};
use aegis_transport::exchange::{ExchangeBudget, FrontEnd, Head, HeadVerdict, MessageVerdict, Method, Mode};
use aegis_transport::{App, H2_PREFACE, Reply, ReplyBody, Server, VhostTable, WrapperLimits};
use aegis_types::RouteId;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::{Instant, timeout_at};

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
        (path.as_bytes() == b"/").then(|| RouteId::new(1).ok()).flatten()
    }
    fn respond(&self, _head: &Head<'_>, _message: &[u8]) -> Reply {
        Reply::new(200, "text/plain", ReplyBody::Static(b"ok\n"))
    }
}

const AUTHORITY: &str = "127.0.0.1:8443";

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const PRIORITY: u8 = 0x2;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;

const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;

const NO_ERROR: u32 = 0x0;
const PROTOCOL_ERROR: u32 = 0x1;
const FLOW_CONTROL_ERROR: u32 = 0x3;
const STREAM_CLOSED: u32 = 0x5;
const REFUSED_STREAM: u32 = 0x7;
const CANCEL: u32 = 0x8;

#[derive(Debug, Clone)]
struct Frame {
    ty: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

impl Frame {
    fn code(&self) -> Option<u32> {
        let at = match self.ty {
            RST_STREAM => 0,
            GOAWAY => 4,
            _ => return None,
        };
        self.payload.get(at..at + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

fn frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let n = u32::try_from(payload.len()).unwrap();
    let mut v = n.to_be_bytes()[1..].to_vec();
    v.extend([ty, flags]);
    v.extend(stream.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// HPACK literal header field without indexing, new name, no Huffman (RFC 7541 §6.2.2); lengths < 127.
fn hpack(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut v = Vec::new();
    for (n, val) in fields {
        v.push(0x00);
        v.push(u8::try_from(n.len()).unwrap());
        v.extend_from_slice(n.as_bytes());
        v.push(u8::try_from(val.len()).unwrap());
        v.extend_from_slice(val.as_bytes());
    }
    v
}

fn request(method: &str, authority: &str) -> Vec<u8> {
    hpack(&[(":method", method), (":scheme", "http"), (":path", "/"), (":authority", authority)])
}

fn get() -> Vec<u8> {
    request("GET", AUTHORITY)
}

fn rst(stream: u32, code: u32) -> Vec<u8> {
    frame(RST_STREAM, 0, stream, &code.to_be_bytes())
}

fn window_update(stream: u32, inc: u32) -> Vec<u8> {
    frame(WINDOW_UPDATE, 0, stream, &inc.to_be_bytes())
}

struct Peer {
    io: DuplexStream,
    buf: Vec<u8>,
    seen: Vec<Frame>,
    server_settings: Vec<(u16, u32)>,
    _srv: tokio::task::JoinHandle<()>,
}

impl Peer {
    /// Connect with the given client SETTINGS and finish the SETTINGS exchange.
    async fn connect(vhost: &[u8], settings: &[(u16, u32)]) -> Peer {
        let mut l = WrapperLimits::GOLDEN;
        l.set_f8("stall_timeout_ms", 2000).unwrap();
        l.set_f8("idle_timeout_ms", 5000).unwrap();
        let mut v = VhostTable::new();
        v.add(vhost, &[]);
        let srv = Server::new(TestApp, v, l).unwrap();
        let (io, server_io) = tokio::io::duplex(1 << 20);
        let h = tokio::spawn(Arc::clone(&srv).serve_plain(server_io));
        let mut p = Peer { io, buf: Vec::new(), seen: Vec::new(), server_settings: Vec::new(), _srv: h };
        let mut s = Vec::new();
        for (id, val) in settings {
            s.extend(id.to_be_bytes());
            s.extend(val.to_be_bytes());
        }
        let mut hello = H2_PREFACE.to_vec();
        hello.extend(frame(SETTINGS, 0, 0, &s));
        p.send(&hello).await;
        let f = p.next(Instant::now() + Duration::from_secs(5)).await.expect("server SETTINGS");
        assert!(f.ty == SETTINGS && f.flags & ACK == 0, "{f:?}");
        p.server_settings = f
            .payload
            .as_chunks::<6>()
            .0
            .iter()
            .map(|c| (u16::from_be_bytes([c[0], c[1]]), u32::from_be_bytes([c[2], c[3], c[4], c[5]])))
            .collect();
        p.send(&frame(SETTINGS, ACK, 0, &[])).await;
        p
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.io.write_all(bytes).await.unwrap();
        self.io.flush().await.unwrap();
    }

    /// Next frame, `None` on EOF or deadline. Every frame read is kept in `seen` for diagnostics.
    async fn next(&mut self, deadline: Instant) -> Option<Frame> {
        loop {
            if self.buf.len() >= 9 {
                let n = usize::try_from(u32::from_be_bytes([0, self.buf[0], self.buf[1], self.buf[2]])).unwrap();
                if self.buf.len() >= 9 + n {
                    let b: Vec<u8> = self.buf.drain(..9 + n).collect();
                    let f = Frame {
                        ty: b[3],
                        flags: b[4],
                        stream: u32::from_be_bytes([b[5], b[6], b[7], b[8]]) & 0x7fff_ffff,
                        payload: b[9..].to_vec(),
                    };
                    self.seen.push(f.clone());
                    return Some(f);
                }
            }
            let mut chunk = [0u8; 16_384];
            match timeout_at(deadline, self.io.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => self.buf.extend_from_slice(&chunk[..n]),
                _ => return None,
            }
        }
    }

    /// Read until `pred` matches a frame; panics with the frames seen if it never does.
    async fn expect(&mut self, what: &str, pred: impl Fn(&Frame) -> bool) -> Frame {
        let deadline = Instant::now() + Duration::from_secs(5);
        while let Some(f) = self.next(deadline).await {
            if f.ty == SETTINGS && f.flags & ACK == 0 {
                self.send(&frame(SETTINGS, ACK, 0, &[])).await;
            }
            if pred(&f) {
                return f;
            }
        }
        panic!("expected {what}; frames seen: {:?}", self.seen);
    }

    /// h2spec `VerifyStreamError`: RST_STREAM or GOAWAY carrying one of `codes`.
    async fn expect_error(&mut self, codes: &[u32]) -> Frame {
        self.expect(&format!("RST_STREAM/GOAWAY with {codes:?}"), |f| {
            f.code().is_some_and(|c| codes.contains(&c)) && (f.ty == GOAWAY || f.ty == RST_STREAM)
        })
        .await
    }

    /// The server closes the transport (EOF before the deadline, not a timeout).
    async fn expect_eof(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.next(deadline).await.is_some() {}
        assert!(Instant::now() < deadline, "connection not closed; frames seen: {:?}", self.seen);
    }

    /// The connection is still served: a PING is answered.
    async fn expect_alive(&mut self) {
        self.send(&frame(PING, 0, 0, b"aegis-01")).await;
        let f = self.expect("PING ack", |f| f.ty == PING || f.ty == GOAWAY).await;
        assert!(f.ty == PING && f.flags & ACK == ACK && f.payload == b"aegis-01", "{f:?}");
    }
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
}

async fn peer() -> Peer {
    Peer::connect(b"127.0.0.1:8443", &[]).await
}

/// h2spec http2/5.1/8, RFC 9113 §5.1 (closed): DATA after the client's RST_STREAM is a STREAM_CLOSED error.
#[test]
fn closed_data_after_rst_stream() {
    rt().block_on(async {
        let mut p = peer().await;
        let mut b = frame(HEADERS, END_HEADERS, 1, &get());
        b.extend(rst(1, CANCEL));
        b.extend(frame(DATA, END_STREAM, 1, b"test"));
        p.send(&b).await;
        p.expect_error(&[STREAM_CLOSED]).await;
    });
}

/// h2spec http2/5.1/9, RFC 9113 §5.1 (closed): HEADERS after the client's RST_STREAM must be an error. h2 0.4.20
/// escalates it to a connection error (GOAWAY PROTOCOL_ERROR, then close; §5.4.1 lets an endpoint treat a stream
/// error as a connection error), which h2spec accepts as "Connection closed". The STREAM_CLOSED code itself is not
/// reachable from the wrapper: see INFEASIBLE_REPORT.md and `strict_closed_headers_after_rst_stream_code`.
#[test]
fn closed_headers_after_rst_stream() {
    rt().block_on(async {
        let mut p = peer().await;
        let mut b = frame(HEADERS, END_HEADERS, 1, &get());
        b.extend(rst(1, CANCEL));
        b.extend(frame(HEADERS, END_HEADERS | END_STREAM, 1, &get()));
        p.send(&b).await;
        let f = p.expect_error(&[STREAM_CLOSED, PROTOCOL_ERROR]).await;
        if f.code() == Some(PROTOCOL_ERROR) {
            assert_eq!(f.ty, GOAWAY, "PROTOCOL_ERROR is only acceptable as a connection error: {f:?}");
            p.expect_eof().await;
        }
        assert!(!p.seen.iter().any(|f| f.ty == HEADERS && f.stream == 1), "responded on a reset stream: {:?}", p.seen);
    });
}

/// Strict form of 5.1/9 (exact STREAM_CLOSED code). Ignored: h2 0.4.20 limitation, INFEASIBLE_REPORT.md §1.
#[test]
#[ignore = "h2 0.4.20 answers GOAWAY(PROTOCOL_ERROR): INFEASIBLE_REPORT.md §1"]
fn strict_closed_headers_after_rst_stream_code() {
    rt().block_on(async {
        let mut p = peer().await;
        let mut b = frame(HEADERS, END_HEADERS, 1, &get());
        b.extend(rst(1, CANCEL));
        b.extend(frame(HEADERS, END_HEADERS | END_STREAM, 1, &get()));
        p.send(&b).await;
        p.expect_error(&[STREAM_CLOSED]).await;
    });
}

/// h2spec http2/8.1.2.1/3, RFC 9113 §8.1 / §8.3: a trailer block carrying a pseudo-header field, sent exactly as
/// h2spec sends it (POST, DATA, then the trailer HEADERS without END_STREAM), is a PROTOCOL_ERROR stream error.
#[test]
fn pseudo_header_in_trailers() {
    rt().block_on(async {
        let mut p = peer().await;
        let mut b = frame(HEADERS, END_HEADERS, 1, &request("POST", AUTHORITY));
        b.extend(frame(DATA, 0, 1, b"test"));
        b.extend(frame(HEADERS, END_HEADERS, 1, &hpack(&[(":method", "POST")])));
        p.send(&b).await;
        p.expect_error(&[PROTOCOL_ERROR]).await;
    });
}

/// The same trailer block with END_STREAM set. RFC 9113 §8.1: still malformed. Ignored: h2 0.4.20 drops the
/// pseudo-header fields of a trailer block without checking them (INFEASIBLE_REPORT.md §2).
#[test]
#[ignore = "h2 0.4.20 accepts pseudo-headers in EOS trailers: INFEASIBLE_REPORT.md §2"]
fn strict_pseudo_header_in_end_stream_trailers() {
    rt().block_on(async {
        let mut p = peer().await;
        let mut b = frame(HEADERS, END_HEADERS, 1, &request("POST", AUTHORITY));
        b.extend(frame(DATA, 0, 1, b"test"));
        b.extend(frame(HEADERS, END_HEADERS | END_STREAM, 1, &hpack(&[(":method", "POST")])));
        p.send(&b).await;
        p.expect_error(&[PROTOCOL_ERROR]).await;
    });
}

/// h2spec http2/8.1.2.6/1, RFC 9113 §8.1.1: content-length that differs from the DATA payload is malformed.
#[test]
fn content_length_differs_from_data() {
    rt().block_on(async {
        let mut p = peer().await;
        let mut h = request("POST", AUTHORITY);
        h.extend(hpack(&[("content-length", "1")]));
        let mut b = frame(HEADERS, END_HEADERS, 1, &h);
        b.extend(frame(DATA, END_STREAM, 1, b"test"));
        p.send(&b).await;
        p.expect_error(&[PROTOCOL_ERROR]).await;
    });
}

/// h2spec http2/2/3, RFC 9113 §5.1 (half-closed remote) / §6.3: PRIORITY is accepted; the response follows.
#[test]
fn priority_on_half_closed_remote() {
    rt().block_on(async {
        let mut p = peer().await;
        let mut b = frame(HEADERS, END_HEADERS | END_STREAM, 1, &get());
        b.extend(frame(PRIORITY, 0, 1, &[0, 0, 0, 0, 15]));
        p.send(&b).await;
        let f = p.expect("DATA on stream 1", |f| (f.ty == DATA && f.stream == 1) || f.code().is_some()).await;
        assert_eq!((f.ty, f.payload.as_slice()), (DATA, b"ok\n".as_slice()), "{:?}", p.seen);
    });
}

/// h2spec http2/8.1/1, RFC 9113 §8.1: a second HEADERS without END_STREAM (not trailers) is malformed.
#[test]
fn second_headers_without_end_stream() {
    rt().block_on(async {
        let mut p = peer().await;
        let mut b = frame(HEADERS, END_HEADERS, 1, &request("POST", AUTHORITY));
        b.extend(frame(DATA, 0, 1, b"test"));
        b.extend(frame(HEADERS, END_HEADERS, 1, &hpack(&[("x-trailer", "1")])));
        p.send(&b).await;
        p.expect_error(&[PROTOCOL_ERROR]).await;
    });
}

/// h2spec http2/2/2, RFC 9113 §5.1 (half-closed remote) / §6.9: WINDOW_UPDATE is accepted; the response follows.
#[test]
fn window_update_on_half_closed_remote() {
    rt().block_on(async {
        let mut p = peer().await;
        let mut b = frame(HEADERS, END_HEADERS | END_STREAM, 1, &get());
        b.extend(window_update(1, 1));
        p.send(&b).await;
        let f = p.expect("DATA on stream 1", |f| (f.ty == DATA && f.stream == 1) || f.code().is_some()).await;
        assert_eq!((f.ty, f.payload.as_slice()), (DATA, b"ok\n".as_slice()), "{:?}", p.seen);
    });
}

/// h2spec http2/5.1.2/1, RFC 9113 §5.1.2: the stream above SETTINGS_MAX_CONCURRENT_STREAMS is refused.
#[test]
fn exceeding_concurrent_stream_limit() {
    rt().block_on(async {
        let mut p = peer().await;
        let max = p.server_settings.iter().find(|(id, _)| *id == 0x3).map(|(_, v)| *v).expect("MAX_CONCURRENT");
        assert_eq!(max, 100);
        let mut b = Vec::new();
        for i in 0..=max {
            b.extend(frame(HEADERS, END_HEADERS, 1 + 2 * i, &request("POST", AUTHORITY)));
        }
        p.send(&b).await;
        let f = p.expect_error(&[REFUSED_STREAM, PROTOCOL_ERROR]).await;
        assert!(f.ty == GOAWAY || f.stream == 1 + 2 * max, "{f:?}");
    });
}

/// h2spec http2/6.9.1/3, RFC 9113 §6.9.1: a stream window above 2^31-1 is a FLOW_CONTROL_ERROR stream error.
#[test]
fn stream_window_above_max() {
    rt().block_on(async {
        // Window 0: the response stays queued, so the stream is still open when the WINDOW_UPDATEs arrive.
        let mut p = Peer::connect(b"127.0.0.1:8443", &[(0x4, 0)]).await;
        let mut b = frame(HEADERS, END_HEADERS | END_STREAM, 1, &get());
        b.extend(window_update(1, 0x7fff_ffff));
        b.extend(window_update(1, 0x7fff_ffff));
        p.send(&b).await;
        let f = p.expect_error(&[FLOW_CONTROL_ERROR]).await;
        assert_eq!((f.ty, f.stream), (RST_STREAM, 1));
        p.expect_alive().await;
    });
}

/// The path that masked the nine cases under h2spec: a request for an unknown authority gets a complete 421
/// before its request ends; the server then resets the stream with NO_ERROR (RFC 9113 §8.1) and ignores later
/// frames on it (§5.4.2). The connection stays usable.
#[test]
fn early_421_resets_no_error_and_ignores_later_frames() {
    rt().block_on(async {
        let mut p = peer().await;
        p.send(&frame(HEADERS, END_HEADERS, 1, &request("POST", "other.test"))).await;
        let f = p.expect("421 HEADERS", |f| f.ty == HEADERS && f.stream == 1).await;
        assert_eq!(f.flags & END_STREAM, END_STREAM);
        let f = p.expect("RST_STREAM", |f| f.code().is_some()).await;
        assert_eq!((f.ty, f.stream, f.code()), (RST_STREAM, 1, Some(NO_ERROR)));
        p.send(&frame(DATA, END_STREAM, 1, b"late")).await;
        p.expect_alive().await;
        assert!(!p.seen.iter().any(|f| f.ty == GOAWAY), "{:?}", p.seen);
    });
}
