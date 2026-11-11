# q2-009: window-0 / send-buffer stall harness (TBI-6/7/8)

**Verdict: keep.** The wrapper prototype holds peak per-connection memory at **12.5–13.2 MiB** (≤ 16 MiB, TBI-7) with the
golden stream cap of 100. It also reaps every stalled stream 10 s after its last progress and closes idle connections at
30 s (TBI-8). Without the ledger, the golden settings buffer **40.6 MiB per connection** (2.5× TBI-7) under a slow
reader, and the stream cap would have to drop to **37** (or the send buffer to ≤ ~130 KiB). The keep holds only if the
wrapper carries the exact send ledger described below. Grade B: laptop loopback, R1 executed.

## Method
- **Server**, `src/main.rs`, three implementations behind the same golden settings (ARCHITECTURE §3.1):
  max_concurrent_streams 100, stream/conn window 256 KiB / 1 MiB, max_frame 16384, send buffer 400 KiB,
  max_header_list 16384, max_pending_accept_reset_streams 20, plus hyper keepalive 20 s/20 s. Every request gets a
  64 MiB response sent in 16 KiB chunks. Each chunk is a fresh, non-zero heap allocation, so bytes buffered inside the
  stack show up in RSS. A zeroed `vec!` is calloc'd and never touched, which hid about 40% of the RSS in a first run.
  - `hyper-baseline`: hyper 1.12.0 http2 server, the stack we would actually ship.
  - `h2-baseline`: h2 0.4.20 used directly, with correct `reserve_capacity`/`capacity`/`poll_capacity` backpressure.
  - `h2-wrapper`: h2-baseline plus the wrapper prototype.
- **Exact buffered-bytes gauge.** A counting IO wraps the socket: `buffered(conn) = body bytes handed to the stack −
  bytes the stack wrote to the socket`. Server RSS comes from `/proc/<pid>/status` every 250 ms.
- **Hostile client**: hand-written HTTP/2 frames over cleartext TCP (preface, SETTINGS, HPACK-literal HEADERS,
  WINDOW_UPDATE, RST_STREAM, CONTINUATION; no h2 crate). Shapes:
  - `window0`: INITIAL_WINDOW_SIZE = 0, 100 streams, never sends WINDOW_UPDATE, holds 25 s.
  - `bigwin-noread`: stream window 16 MiB plus one connection WINDOW_UPDATE of +1 GiB, 100 streams, then never reads
    the socket. HTTP/2 flow control is not the limit, so TCP backpressure fills the send buffers.
  - `slowread`: like bigwin, but drains ~1 KiB/s and dribbles 256 B WINDOW_UPDATEs.
  - `rapidreset`: HEADERS+RST_STREAM ×100 (and ×1000) per connection; reads back GOAWAY.
  - `continuation`: HEADERS without END_HEADERS, then 64 × 15 KiB CONTINUATION frames; reads back GOAWAY.
- 1, 10 and 100 hostile connections for the window shapes; 10 for the others. Server and attacker share one host,
  under `ci/heavy.sh` (6 GB cgroup).
- Note on how the attack works: a peer that advertises window 0 cannot make the stack buffer. The memory attack is
  "large window, stop reading TCP", where the 400 KiB per-stream send buffer fills to the brim.

## Results (raw data in `raw/`, all rows in `results.json`)
"peak ΔRSS / conn" = (peak RSS − idle RSS) / connections. "max buffered / conn" = the exact gauge above.
Rows tagged `c100-wave2` / `c1-burst1000` come from `run_extra.sh`. The h2-baseline wave-2 run was **OOM-killed** at
5.5 GiB RSS when the second 100 connections arrived (journal: `oom-kill`), so its row is cut off at that point (the 56 MiB per-conn figure divides by 100 although 200 conns were live).

| run | conns | idle RSS | peak RSS | peak ΔRSS / conn | max buffered / conn (exact) | reaped | live streams @5/12/20 s |
|---|---:|---:|---:|---:|---:|---:|---|
| h2-baseline · bigwin-noread | 1 | 3.3 MiB | 44.2 MiB | 40.91 MiB | 39.06 MiB | 0 | 100/100/100 |
| h2-baseline · bigwin-noread | 10 | 3.3 MiB | 405.9 MiB | 40.27 MiB | 39.07 MiB | 0 | 1000/1000/1000 |
| h2-baseline · bigwin-noread (wave2) | 100 | 3.3 MiB | 5603.6 MiB | 56.0 MiB | 39.08 MiB | 0 | 10000/10000/- |
| h2-baseline · bigwin-noread | 100 | 3.3 MiB | 4015.6 MiB | 40.12 MiB | 39.08 MiB | 0 | 10000/10000/10000 |
| h2-baseline · continuation | 10 | 3.3 MiB | 4.1 MiB | 0.08 MiB | 0.0 MiB | 0 | 0/-/- |
| h2-baseline · rapidreset (burst1000) | 1 | 3.3 MiB | 3.7 MiB | 0.41 MiB | 0.0 MiB | 0 | 0/-/- |
| h2-baseline · rapidreset | 10 | 3.3 MiB | 4.0 MiB | 0.07 MiB | 0.0 MiB | 0 | 0/-/- |
| h2-baseline · slowread | 10 | 3.3 MiB | 406.1 MiB | 40.28 MiB | 39.07 MiB | 0 | 1000/1000/1000 |
| h2-baseline · window0 | 1 | 3.4 MiB | 3.8 MiB | 0.42 MiB | 0.0 MiB | 0 | 100/100/100 |
| h2-baseline · window0 | 10 | 3.4 MiB | 5.3 MiB | 0.19 MiB | 0.0 MiB | 0 | 1000/1000/1000 |
| h2-baseline · window0 | 100 | 3.3 MiB | 20.1 MiB | 0.17 MiB | 0.0 MiB | 0 | 10000/10000/10000 |
| h2-wrapper · bigwin-noread | 1 | 3.4 MiB | 16.6 MiB | 13.21 MiB | 12.05 MiB | 100 | 100/0/0 |
| h2-wrapper · bigwin-noread (long) | 10 | 3.4 MiB | 130.9 MiB | 12.75 MiB | 12.05 MiB | 1000 | 1000/0/0 |
| h2-wrapper · bigwin-noread | 10 | 3.3 MiB | 130.6 MiB | 12.73 MiB | 12.04 MiB | 1000 | 1000/0/0 |
| h2-wrapper · bigwin-noread (wave2) | 100 | 3.4 MiB | 1298.7 MiB | 12.95 MiB | 12.05 MiB | 20000 | 10000/9448/10000 |
| h2-wrapper · bigwin-noread | 100 | 3.3 MiB | 1255.9 MiB | 12.53 MiB | 12.05 MiB | 10000 | 10000/0/0 |
| h2-wrapper · continuation | 10 | 3.3 MiB | 4.1 MiB | 0.07 MiB | 0.0 MiB | 0 | 0/-/- |
| h2-wrapper · rapidreset (burst1000) | 1 | 3.2 MiB | 3.6 MiB | 0.42 MiB | 0.0 MiB | 0 | 0/-/- |
| h2-wrapper · rapidreset | 10 | 3.3 MiB | 3.9 MiB | 0.06 MiB | 0.0 MiB | 0 | 0/-/- |
| h2-wrapper · slowread | 10 | 3.3 MiB | 130.8 MiB | 12.74 MiB | 12.03 MiB | 1000 | 1000/0/0 |
| h2-wrapper · window0 | 1 | 3.3 MiB | 3.7 MiB | 0.44 MiB | 0.0 MiB | 100 | 100/0/0 |
| h2-wrapper · window0 | 10 | 3.4 MiB | 5.5 MiB | 0.21 MiB | 0.0 MiB | 1000 | 1000/0/0 |
| h2-wrapper · window0 | 100 | 3.4 MiB | 20.8 MiB | 0.17 MiB | 0.0 MiB | 10000 | 10000/0/0 |
| hyper-baseline · bigwin-noread | 1 | 3.3 MiB | 45.7 MiB | 42.38 MiB | 40.64 MiB | 0 | 100/100/100 |
| hyper-baseline · bigwin-noread | 10 | 3.3 MiB | 420.6 MiB | 41.72 MiB | 40.64 MiB | 0 | 1000/1000/1000 |
| hyper-baseline · bigwin-noread | 100 | 3.3 MiB | 4175.8 MiB | 41.72 MiB | 40.64 MiB | 0 | 10000/10000/10000 |
| hyper-baseline · continuation | 10 | 3.3 MiB | 4.1 MiB | 0.08 MiB | 0.0 MiB | 0 | 0/-/- |
| hyper-baseline · rapidreset (burst1000) | 1 | 3.3 MiB | 3.7 MiB | 0.35 MiB | 0.0 MiB | 0 | 0/-/- |
| hyper-baseline · rapidreset | 10 | 3.4 MiB | 4.1 MiB | 0.07 MiB | 0.0 MiB | 0 | 0/-/- |
| hyper-baseline · slowread | 10 | 3.4 MiB | 421.8 MiB | 41.84 MiB | 40.64 MiB | 0 | 1000/1000/1000 |
| hyper-baseline · window0 | 1 | 3.4 MiB | 5.4 MiB | 2.02 MiB | 1.56 MiB | 0 | 100/100/100 |
| hyper-baseline · window0 | 10 | 3.2 MiB | 20.8 MiB | 1.77 MiB | 1.56 MiB | 0 | 1000/1000/1000 |
| hyper-baseline · window0 | 100 | 3.3 MiB | 174.6 MiB | 1.71 MiB | 1.56 MiB | 0 | 10000/10000/10000 |

RSS curve (MiB, seconds since server start; attack starts at ~1 s, client holds until ~26 s):

| run | conns | 2s | 5s | 9s | 12s | 15s | 20s | 26s | 30s | 40s | 50s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| h2-baseline · bigwin-noread | 1 | 44.2 | 44.2 | 44.2 | 44.2 | 44.2 | 44.2 | 44.2 | 9.1 |  |  |
| h2-baseline · bigwin-noread | 10 | 405.9 | 405.9 | 405.9 | 405.9 | 405.9 | 405.9 | 405.9 | 67.0 |  |  |
| h2-baseline · bigwin-noread (wave2) | 100 | 4014.5 | 4014.5 | 4014.5 | 4014.5 |  |  |  |  |  |  |
| h2-baseline · bigwin-noread | 100 | 4015.6 | 4015.6 | 4015.6 | 4015.6 | 4015.6 | 4015.6 | 4015.6 | 2770.7 |  |  |
| h2-baseline · slowread | 10 | 406.0 | 406.0 | 406.0 | 406.0 | 406.0 | 406.0 | 406.1 | 151.7 |  |  |
| h2-baseline · window0 | 1 | 3.8 | 3.8 | 3.8 | 3.8 | 3.8 | 3.8 | 3.8 | 3.8 |  |  |
| h2-baseline · window0 | 10 | 5.3 | 5.3 | 5.3 | 5.3 | 5.3 | 5.3 | 5.3 | 5.3 |  |  |
| h2-baseline · window0 | 100 | 20.1 | 20.1 | 20.1 | 20.1 | 20.1 | 20.1 | 20.1 | 19.4 |  |  |
| h2-wrapper · bigwin-noread | 1 | 16.6 | 16.6 | 16.6 | 8.7 | 8.7 | 8.7 | 8.7 | 7.9 |  |  |
| h2-wrapper · bigwin-noread (long) | 10 | 130.9 | 130.9 | 130.8 | 100.8 | 100.8 | 100.8 | 100.8 | 100.8 | 19.7 | 19.7 |
| h2-wrapper · bigwin-noread | 10 | 130.6 | 130.6 | 130.6 | 71.7 | 71.7 | 71.7 | 71.7 | 30.0 |  |  |
| h2-wrapper · bigwin-noread (wave2) | 100 | 1258.6 | 1258.6 | 1258.6 | 1213.9 | 1298.7 | 1298.7 | 1245.8 |  |  |  |
| h2-wrapper · bigwin-noread | 100 | 1255.9 | 1255.9 | 1255.9 | 1208.6 | 1208.6 | 1208.6 | 1208.6 | 581.4 |  |  |
| h2-wrapper · slowread | 10 | 130.8 | 130.8 | 130.8 | 73.4 | 73.4 | 73.4 | 73.4 | 18.8 |  |  |
| h2-wrapper · window0 | 1 | 3.7 | 3.7 | 3.7 | 3.7 | 3.7 | 3.7 | 3.7 | 3.7 |  |  |
| h2-wrapper · window0 | 10 | 5.3 | 5.3 | 5.3 | 5.5 | 5.5 | 5.5 | 5.5 | 5.1 |  |  |
| h2-wrapper · window0 | 100 | 20.5 | 20.5 | 20.5 | 20.8 | 20.8 | 20.8 | 20.8 | 20.4 |  |  |
| hyper-baseline · bigwin-noread | 1 | 45.7 | 45.7 | 45.7 | 45.7 | 45.7 | 45.7 | 45.7 | 22.3 |  |  |
| hyper-baseline · bigwin-noread | 10 | 420.6 | 420.6 | 420.6 | 420.6 | 420.6 | 420.6 | 420.6 | 196.7 |  |  |
| hyper-baseline · bigwin-noread | 100 | 4175.8 | 4175.8 | 4175.8 | 4175.8 | 4175.8 | 4175.8 | 4175.8 | 3432.6 |  |  |
| hyper-baseline · slowread | 10 | 421.8 | 421.8 | 421.8 | 421.8 | 421.8 | 421.8 | 421.8 | 306.9 |  |  |
| hyper-baseline · window0 | 1 | 5.4 | 5.4 | 5.4 | 5.4 | 5.4 | 5.4 | 5.4 | 4.9 |  |  |
| hyper-baseline · window0 | 10 | 20.8 | 20.8 | 20.8 | 20.8 | 20.8 | 20.8 | 20.8 | 9.4 |  |  |
| hyper-baseline · window0 | 100 | 174.6 | 174.6 | 174.6 | 174.6 | 174.6 | 174.6 | 174.6 | 86.6 |  |  |

Frame-level outcomes (`raw/*rapidreset*.log`, `raw/*continuation*.log`):
- **Rapid reset**, burst 100/conn × 10 conns: GOAWAY ENHANCE_YOUR_CALM on 10/10 conns (hyper), 10/10 (h2-wrapper)
  and 7/10 (h2-baseline). Burst 1000: 1/1 for every implementation. h2's `max_pending_accept_reset_streams = 20`
  fires below the TBI-5 bucket burst of 100. Memory 0.06–0.08 MiB/conn.
- **CONTINUATION flood**: GOAWAY ENHANCE_YOUR_CALM on 10/10 conns for every implementation, 0.08 MiB/conn. The h2
  header-list cap holds. (A first run used frames larger than max_frame and only measured FRAME_SIZE_ERROR; it was rerun.)
- **Reaped memory is reused**: wrapper, 100 conns, then a second wave of 100 conns at t = 12 s. RSS peaks at 1258.6 MiB
  for wave 1 and 1298.7 MiB with both waves, not ~2.5 GiB. The RSS plateau after the reap is glibc retention, not live data.

## Reading against the invariants
- **TBI-7 (≤ 16 MiB/conn)**: baseline fails at 40.6 MiB/conn (hyper) under bigwin/slowread, which is
  100 streams × 400 KiB send buffer. The wrapper passes at 12.5–13.2 MiB/conn (12 MiB ledger + ~1 MiB fixed state).
- **TBI-8 (stall 10 s, idle 30 s)**: baseline never reaps; 10 000 streams stay live through the hold. The wrapper resets
  all stalled streams at t ≈ 11 s and closes idle connections at ≈ 31 s (`h2-wrapper__bigwin-noread__c10-long`).
- **TBI-6 (buffered ≤ advertised window)**: the bigwin attack satisfies TBI-6 (the peer advertised ~1 GiB) and still
  buffers 40 MiB, so TBI-6 does not imply TBI-7. The memory bound must be `min(peer window, local ledger)`. Under
  window 0, hyper holds one pre-polled frame per stream (1.56 MiB/conn), so a literal TBI-6 measured above hyper needs
  a slack of one max_frame per open stream.
- **Cap needed without the ledger**: 0.417–0.424 MiB/stream peak → ⌊16 / 0.424⌋ = **37** streams (40 by pure
  16 MiB / 400 KiB arithmetic). Keeping 100 streams instead needs max_send_buf ≤ ~130 KiB.

## Wrapper prototype (seed for monban-transport)
Rules: (1) hand a chunk to h2 only while `ledger + chunk ≤ budget` (budget 12 MiB = M_conn 16 MiB minus measured fixed
state), where the ledger is exact (bytes handed − bytes written to the socket); (2) a stream with no send progress for
10 s, for any reason (window, TCP backpressure, ledger exhaustion), gets RST_STREAM(ENHANCE_YOUR_CALM) and is dropped,
which frees its h2 buffer; (3) close a connection after 30 s without stream progress. Porting it to hyper (not done
here) needs the same counting IO plus a ledger-gated `Body` whose `poll_frame` returns `Pending` while the ledger is
full and `Err` at the stall deadline, so that hyper resets the stream. In monban-transport it also has to follow the
workspace lints (this harness uses indexing in the test client and `unwrap_or_default` on a builder).

```rust
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

// Wrapper sender (prototype of the Monban wrapper): per-connection memory ledger (TBI-6/7) + per-stream
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

```

## Reproduce
```
cd spikes/q2-009
CARGO_TARGET_DIR=$PWD/target ../../ci/heavy.sh cargo build --release --offline   # ~2 min cold, target/ 82 MB
HEAVY_TIMEOUT=2700 ../../ci/heavy.sh ./run.sh          # 28 runs, ~20 min, peak server RSS ~4.2 GB (hyper, 100 conns)
HEAVY_TIMEOUT=1200 ../../ci/heavy.sh ./run_extra.sh    # frame observation + second wave (h2-baseline wave 2 OOMs by design)
python3 -I summarize.py                                # -> results.md, results.json
rm -rf target
```
Single run: `./run_one.sh <hyper-baseline|h2-baseline|h2-wrapper> <window0|bigwin-noread|slowread|rapidreset|continuation> <conns> [streams] [hold_ms] [sample_ms] [ledger_mib] [tag]`.

## Limits (honest)
- Laptop loopback (i9-14900HX, Linux 6.17, glibc 2.39), with server and attacker on one host: grade B, provisional.
  Loopback has no RTT or loss.
- The wrapper was measured on h2 directly, not behind hyper. The hyper port is designed above but not measured.
- Kernel socket send buffers (tcp_wmem max 4 MiB) are outside RSS and outside the ledger. Production needs an explicit
  SO_SNDBUF cap, counted against the global budget (N·M_conn ≤ global).
- The ledger counts DATA payload only (9 B per frame of headers is excluded). Cleartext h2c, so TLS buffers are not counted.
- No per-stream fairness inside a saturated ledger. This only affects streams on the hostile connection itself.
- Crate ages come from `supply-chain/lock-targets.toml` (re-verified 2026-10-25). crates.io was unreachable from the
  sandbox. hyper-util 0.1.21, http 1.5.0, bytes 1.12.1 and http-body-util 0.1.5 came from the local registry cache;
  their age was not independently checked.
- TBI-8 timings come from the wall clock, one run per shape, not from DST.
