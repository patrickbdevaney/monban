# P7-uring-001 report (implementer, 2026-11-06, base 3a0a45d)

**Status: crate done; the gate (`front-equiv`) stays red until P7-bin-001 wires `--front` / `listeners[].front`.**
Write scope used: `crates/aegis-uring/src/**` and this report. No manifest, lock, oracle, gate or CI file was touched.
Nothing is infeasible, and no check or limit was weakened.

## Design

- **One driver thread per listener** (`aegis-uring`, same pid, no helper process). It is the only owner of the
  ring (io-uring 0.7.15), the listening socket, every connection fd and every buffer the kernel holds.
- **Accept, recv, send, shutdown, setsockopt(TCP_NODELAY) and close** all go through the ring. Neither the listener
  nor any connection socket is ever registered in an epoll instance. The tests build their tokio runtime without
  `enable_io`, so the test process has no epoll at all.
- **Waking the driver.** Callers send commands over a std channel, then write one byte to a socketpair. The driver
  keeps a recv armed on the other end, so it blocks only in `io_uring_enter`. When the listener and every stream are
  gone, the socketpair's write end closes and the armed recv sees EOF. The driver then closes what is left, reaps
  every CQE, and exits, which closes the listener.
- **Buffer ownership** is the argument behind the single unsafe site. Streams hand buffers to the driver by value
  (`Cmd::Recv` / `Cmd::Send`) and get them back by value after the CQE. Each buffer is a `Vec`, or a `Box` for the
  sockaddr, the i32 optval, the Timespec and the wake buffer, and it sits in the driver's op table from SQE until
  CQE. Moving an `Op` moves only the handle, never the heap memory the kernel holds. Nothing borrowed crosses an
  `.await`.
- **Drop of a stream with ops in flight:**
  1. its pending recv is cancelled (`ASYNC_CANCEL`) and reaped;
  2. a write it already accepted keeps draining, bounded by `linger` (default 30 s), then it is cancelled and reaped;
  3. only then is `CLOSE` issued on the fd.
- **Ring failure.** If `io_uring_enter` fails fatally, every waiter gets the error. The op table, the connection
  fds and the listener are leaked (`mem::forget`), not freed or closed.
- **EAGAIN** (a listener dup that someone set to O_NONBLOCK, for example the upgrade hand-off) is handled with a ring
  `POLL_ADD`, then a retry. The socket's flags are never changed.
- **Bounded.**
  - The SQ has `sq_entries` slots (1..=4096, default 256). If it fills, the driver submits and refills. On EBUSY it
    reaps first.
  - Per connection, at most one each of recv, send, shutdown, nodelay and linger is in flight. The listener has at
    most one accept, armed only while someone is polling `accept`, so connections are not pulled off the kernel
    backlog ahead of the server. The backlog of waiting SQEs is therefore bounded by the number of open connections.
  - `max_io` (1..=1 MiB, default 64 KiB) caps each recv and send. The ring needs `IORING_FEAT_NODROP`, so a CQ
    overflow never loses a completion.

## Public API (for P7-bin-001)

```rust
pub fn aegis_uring::uring_available() -> Result<(), UringError>;
    // ring setup + opcode probe (io_uring_register) + NODROP + one NOP through io_uring_enter.
    // Call it before binding anything for `--front uring`: Err => print `{e}`, exit != 0. Never fall back to epoll.

pub enum UringError { Unavailable(String), Start(String) }   // Display always contains "io_uring";
    // Unavailable(..) reads "io_uring unavailable: io_uring_setup failed: Operation not permitted (os error 1);
    // refusing to start (no epoll fallback)"

pub struct UringConfig { pub sq_entries: u32, pub max_io: usize, pub linger: Duration }  // Default: 256, 64 KiB, 30 s

impl UringListener {                          // Debug + Send + Sync
    pub fn bind(l: std::net::TcpListener) -> Result<Self, UringError>;
    pub fn bind_with(l: std::net::TcpListener, cfg: UringConfig) -> Result<Self, UringError>;
        // takes ownership; on Err the socket is closed and nothing was accepted
    pub async fn accept(&self) -> io::Result<(UringStream, SocketAddr)>;   // cancel-safe, one acceptor task
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(UringStream, SocketAddr)>>;
    pub fn local_addr(&self) -> SocketAddr;
    pub fn ring_fd(&self) -> RawFd;           // /proc evidence only
}
impl AsRawFd for UringListener                // the listening socket's fd, /proc evidence only
impl Drop for UringListener                   // cancels the pending accept; streams already handed out keep working

impl UringStream {                            // Debug, Send, Unpin, 'static
    pub fn peer_addr(&self) -> SocketAddr;
}
impl tokio::io::AsyncRead for UringStream
impl tokio::io::AsyncWrite for UringStream
impl AsRawFd for UringStream                  // /proc evidence only, never for I/O
```

### Wiring sketch

This mirrors `serve.rs::accept_tcp`. The `race(l.accept(), notified)` shape works unchanged, because `accept` is
cancel-safe.

```rust
// at start, when any listener resolves to front = uring (after the 64/78 argument and config checks):
if let Err(e) = aegis_uring::uring_available() { log(&e.to_string()); return ExitCode::from(EX_UNAVAILABLE /* != 0 */); }
// per uring listener, instead of TcpListener::from_std(mine):
let ul = aegis_uring::UringListener::bind(mine)?;   // `mine` = l.try_clone(); do NOT register it with tokio
loop { match race(ul.accept(), notified).await {
    Either::Left(Ok((sock, addr))) => { tokio::spawn(async move { srv.serve_tls_from(sock, acc, Some(addr)).await }); }
    Either::Left(Err(_)) => tokio::time::sleep(Duration::from_millis(20)).await,   // EMFILE etc.
    Either::Right(()) => break,
}}
drop(ul);  // the driver closes its listener fd once the last stream is gone
```

- `serve_tls_from` needs `IO: AsyncRead + AsyncWrite + Unpin + Send + 'static`. `UringStream` meets it, checked at
  compile time by `tests::stream_meets_transport_bounds`.
- `set_nodelay` is not needed: the driver sets TCP_NODELAY at accept, best effort.
- The admin listener may stay on epoll.
- Do not hand the uring listener's fd to `tokio::net::TcpListener::from_std`. That would put it in epoll, and the
  oracle's `uring.identity.conn-not-in-epoll` and listener checks would fail.

### Semantic differences from `TcpStream` (relevant to FRONT-1)

- **Write-behind.** `poll_write` copies up to `max_io` bytes and returns `Ready(n)` at once. A send error shows up on
  the next `poll_write`, `poll_flush` or `poll_shutdown`, and is sticky. `poll_flush` waits until the kernel has
  taken every accepted byte. This is the only correct option with owned buffers: returning `Pending` after
  submitting would break the AsyncWrite contract.
- **Drop without flush** delivers accepted bytes, the same way a kernel send buffer would, bounded by `linger`.
- **Reads** ask the kernel for at most `min(caller's buffer, max_io)`, so the kernel's view of unread bytes matches
  what epoll would see, up to one recv. The case where it can differ is the RST-on-close-with-unread-bytes case: up to
  one `max_io` of bytes that were already received but not consumed. The oracle already keeps its 431 cases within one
  TLS record to avoid that race.

## Unsafe sites (DEVIATIONS X-15; cap 6, used 1)

| # | where | what | lifetime argument |
|---|---|---|---|
| 1 | `crates/aegis-uring/src/driver.rs` `fn push` (`unsafe { sq.push(e) }`, `#[allow(unsafe_code)]` + `// SAFETY:`) | the single generic SQE push, used for every op and for the NOP probe | every pointer in the entry points into heap memory owned by the op table until its CQE is reaped. Streams never touch a listed buffer. Close is issued only after all of a connection's ops are reaped. On ring failure the table is leaked, not freed. |

`cargo xtask unsafe-sites`: `aegis-uring 1/6`, `UNSAFE-SITES: PASS`.

## Tests (crate level, `src/tests.rs`, 19)

| test | covers |
|---|---|
| `probe_reports_available` | `uring_available()` is Ok on the desktop |
| `echo_round_trip` | accept, recv, send, half-close and shutdown; the peer address is parsed from the accept sockaddr and equals the client's local address |
| `http_like_fragmented_keepalive` | request in 1-byte writes, read through a 7-byte buffer (partial reads), response in 3-byte writes (partial writes), two requests on one connection |
| `many_concurrent_connections` | 128 concurrent echo connections of about 16 KiB each, with `sq_entries = 16`, so the SQ overflows into the backlog |
| `big_body_both_directions` | 3 MiB + 17 bytes each way through `max_io = 4096`, compared byte for byte |
| `slow_reader_backpressure` | 8 MiB to a peer that waits 500 ms before reading (short sends, full socket buffer) |
| `peer_half_close_then_reply` | EOF after the data and EOF sticky, reply after the peer's FIN, write after shutdown fails |
| `peer_close_write_errors` | a peer that closes gives BrokenPipe or ConnectionReset, never a hang |
| `drop_with_read_in_flight` | drop with a recv in flight: cancel, reap, close; the peer sees EOF |
| `drop_after_write_delivers` | 1 MiB written, dropped without flush: all of it arrives, then EOF |
| `linger_bounds_a_stuck_write` | 64 MiB to a peer that never reads, dropped mid-write, `linger = 1 s`: aborted, fd closed, the peer's read ends |
| `accept_cancel_safe` | a dropped accept future does not lose the connection |
| `nonblocking_listener_accepts` | O_NONBLOCK listener dup: EAGAIN, then POLL_ADD, then retry |
| `proc_identity_not_in_epoll` | the ring fd is `anon_inode:[io_uring]`; its `CqTail` advances with one connection; neither the connection fd nor the listener fd appears as `tfd:` in any `/proc/self/fdinfo` |
| `eperm_fails_closed` | injected `io_uring_setup` returning EPERM gives `Unavailable`, a message with `io_uring`, `Operation not permitted` and `no epoll fallback`, a socket that is closed (ConnectionRefused), all in under 8 s |
| `config_bounds_refused` | out-of-range `sq_entries`, `max_io` or `linger` gives `Start` |
| `listener_drop_closes_socket` | the driver exits once its last handle is gone, and the port refuses |
| `sockaddr_parsing` | v4, v6, other address families |
| `stream_meets_transport_bounds` | the stream satisfies aegis-transport's IO bounds; `UringListener` is Send + Sync |

The EPERM path is injected through the crate-private `UringListener::bind_inner(.., setup)`, because a test cannot
change its own seccomp filter. The real seccomp path is `oracles/front-equiv` (`noring_exec.py`) once P7-bin-001
lands.

## Acceptance evidence (desktop, kernel 6.11, io_uring_disabled=0)

```
$ ci/remote.sh cargo test -p aegis-uring --locked
test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.30s
  (8 consecutive runs: 8 × 19 passed)
$ ci/remote.sh cargo clippy -p aegis-uring --locked --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s)
$ cargo xtask unsafe-sites
unsafe-sites: 54 packages, 335 source files; aegis-iso 16/20, aegis-wasm 1/1, aegis-uring 1/6
UNSAFE-SITES: PASS
$ cargo xtask layering
LAYERING: PASS
```

The second half of the unit's acceptance command, `oracles/front-equiv/run --binary-from-build`, cannot pass until
P7-bin-001 adds `--front`, `listeners[].front` and the wiring above. It was not run here.

## Notes and follow-ups

- **Rung.** These are tested behaviours (R1, crate tests). No proof covers this crate. The kernel io_uring surface,
  io-uring 0.7.15 (agent-audited, PREFLIGHT P5) and tokio are trusted, not verified.
- **Opcodes.** `IORING_OP_URING_CMD` setsockopt (TCP_NODELAY) needs kernel ≥ 6.7. On older kernels it fails and is
  ignored, and Nagle stays on. The probe requires ACCEPT, RECV, SEND, SHUTDOWN, CLOSE, ASYNC_CANCEL, POLL_ADD and
  TIMEOUT, plus NODROP.
- **One driver thread per listener.** A config with several public listeners on `--front uring` gets one ring per
  listener. This is fine for the oracle (it sums CqTail over the process's rings). A shared multi-listener driver
  would be a later optimisation.
