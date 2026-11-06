#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Crate-level tests. They need a kernel that permits io_uring (the desktop: io_uring_disabled=0, 6.11).
//! The tokio runtime is built without `enable_io`, so the process has no epoll instance of tokio's at all: every
//! byte below moves through the ring.

use std::future::{Future, poll_fn};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::mpsc;
use std::task::Poll;
use std::thread;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};

use crate::{UringConfig, UringError, UringListener, UringStream, uring_available};

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().build().unwrap()
}

/// Run `f` on its own thread; fail if it panics or takes longer than `secs`.
fn watchdog<F: FnOnce() + Send + 'static>(secs: u64, f: F) {
    let (tx, rx) = mpsc::channel();
    let h = thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(()) => h.join().unwrap(),
        Err(_) => match h.join() {
            Err(p) => std::panic::resume_unwind(p),
            Ok(()) => panic!("test exceeded {secs} s"),
        },
    }
}

fn listen_with(cfg: UringConfig) -> (UringListener, SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let u = UringListener::bind_with(l, cfg).unwrap();
    assert_eq!(u.local_addr(), addr);
    (u, addr)
}

fn listen() -> (UringListener, SocketAddr) {
    listen_with(UringConfig::default())
}

fn client(addr: SocketAddr) -> TcpStream {
    let c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    c.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
    c
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ ((i >> 8) as u8)).collect()
}

async fn echo(mut s: UringStream, chunk: usize) -> io::Result<u64> {
    let mut buf = vec![0u8; chunk];
    let mut total = 0u64;
    loop {
        let n = s.read(&mut buf).await?;
        if n == 0 {
            s.shutdown().await?;
            return Ok(total);
        }
        s.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}

#[test]
fn probe_reports_available() {
    uring_available().unwrap();
}

#[test]
fn echo_round_trip() {
    watchdog(30, || {
        let (l, addr) = listen();
        let c = thread::spawn(move || {
            let mut c = client(addr);
            let local = c.local_addr().unwrap();
            c.write_all(b"hello uring").unwrap();
            c.shutdown(Shutdown::Write).unwrap();
            let mut got = Vec::new();
            c.read_to_end(&mut got).unwrap();
            (got, local)
        });
        let (n, peer) = rt().block_on(async {
            let (s, peer) = l.accept().await.unwrap();
            assert_eq!(s.peer_addr(), peer);
            (echo(s, 4096).await.unwrap(), peer)
        });
        let (got, local) = c.join().unwrap();
        assert_eq!(got, b"hello uring");
        assert_eq!(n, 11);
        assert_eq!(peer, local, "peer address parsed from the accept sockaddr");
    });
}

/// HTTP-shaped exchange: the request arrives one byte per write, the server reads through a 7-byte buffer (many
/// partial reads), answers in 3-byte writes, and serves a second request on the same connection.
#[test]
fn http_like_fragmented_keepalive() {
    watchdog(30, || {
        let (l, addr) = listen();
        let req = b"GET /a HTTP/1.1\r\nhost: x\r\n\r\n";
        let resp: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello";
        let c = thread::spawn(move || {
            let mut c = client(addr);
            c.set_nodelay(true).unwrap();
            let mut out = Vec::new();
            for _ in 0..2 {
                for b in req.iter() {
                    c.write_all(&[*b]).unwrap();
                }
                let mut r = vec![0u8; resp.len()];
                c.read_exact(&mut r).unwrap();
                out.push(r);
            }
            out
        });
        rt().block_on(async move {
            let (mut s, _) = l.accept().await.unwrap();
            for _ in 0..2 {
                let mut head = Vec::new();
                let mut b7 = [0u8; 7];
                while !head.ends_with(b"\r\n\r\n") {
                    let n = s.read(&mut b7).await.unwrap();
                    assert!(n > 0 && n <= 7);
                    head.extend_from_slice(&b7[..n]);
                }
                assert_eq!(head, req);
                for part in resp.chunks(3) {
                    let mut p = part;
                    while !p.is_empty() {
                        let n = s.write(p).await.unwrap();
                        p = &p[n..];
                    }
                }
                s.flush().await.unwrap();
            }
        });
        for r in c.join().unwrap() {
            assert_eq!(r, resp);
        }
    });
}

#[test]
fn many_concurrent_connections() {
    const N: usize = 128;
    watchdog(60, || {
        let (l, addr) = listen_with(UringConfig { sq_entries: 16, ..UringConfig::default() });
        let clients: Vec<_> = (0..N)
            .map(|i| {
                thread::spawn(move || {
                    let data = pattern(16 * 1024 + i, i as u8);
                    let mut c = client(addr);
                    let mut r = c.try_clone().unwrap();
                    let w = {
                        let data = data.clone();
                        thread::spawn(move || {
                            c.write_all(&data).unwrap();
                            c.shutdown(Shutdown::Write).unwrap();
                        })
                    };
                    let mut got = Vec::new();
                    r.read_to_end(&mut got).unwrap();
                    w.join().unwrap();
                    assert_eq!(got, data, "client {i}");
                })
            })
            .collect();
        let total = rt().block_on(async move {
            let mut tasks = Vec::new();
            for _ in 0..N {
                let (s, _) = l.accept().await.unwrap();
                tasks.push(tokio::spawn(echo(s, 1500)));
            }
            let mut total = 0;
            for t in tasks {
                total += t.await.unwrap().unwrap();
            }
            total
        });
        for c in clients {
            c.join().unwrap();
        }
        let want: u64 = (0..N).map(|i| (16 * 1024 + i) as u64).sum();
        assert_eq!(total, want);
    });
}

/// 3 MiB each way through a 4 KiB max_io: hundreds of partial reads and writes, data checked byte for byte.
#[test]
fn big_body_both_directions() {
    watchdog(60, || {
        let (l, addr) = listen_with(UringConfig { max_io: 4096, ..UringConfig::default() });
        let data = pattern(3 * 1024 * 1024 + 17, 7);
        let expect = data.clone();
        let c = thread::spawn(move || {
            let mut c = client(addr);
            let mut r = c.try_clone().unwrap();
            let w = thread::spawn(move || {
                c.write_all(&data).unwrap();
                c.shutdown(Shutdown::Write).unwrap();
            });
            let mut got = Vec::new();
            r.read_to_end(&mut got).unwrap();
            w.join().unwrap();
            got
        });
        let n = rt().block_on(async move {
            let (s, _) = l.accept().await.unwrap();
            echo(s, 64 * 1024).await.unwrap()
        });
        let got = c.join().unwrap();
        assert_eq!(n as usize, expect.len());
        assert!(got == expect, "echoed body differs");
    });
}

/// The client does not read for a while, so the server's sends hit a full socket buffer (short sends, EAGAIN/poll).
#[test]
fn slow_reader_backpressure() {
    watchdog(60, || {
        let (l, addr) = listen();
        let data = pattern(8 * 1024 * 1024, 3);
        let expect = data.clone();
        let c = thread::spawn(move || {
            let mut c = client(addr);
            c.write_all(b"go").unwrap();
            thread::sleep(Duration::from_millis(500));
            let mut got = Vec::new();
            c.read_to_end(&mut got).unwrap();
            got
        });
        rt().block_on(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut go = [0u8; 2];
            s.read_exact(&mut go).await.unwrap();
            s.write_all(&data).await.unwrap();
            s.shutdown().await.unwrap();
        });
        let got = c.join().unwrap();
        assert!(got == expect, "body differs ({} of {} bytes)", got.len(), expect.len());
    });
}

/// Peer half-closes: the server sees the bytes then EOF (repeatedly), and can still answer.
#[test]
fn peer_half_close_then_reply() {
    watchdog(30, || {
        let (l, addr) = listen();
        let c = thread::spawn(move || {
            let mut c = client(addr);
            c.write_all(b"abc").unwrap();
            c.shutdown(Shutdown::Write).unwrap();
            let mut got = Vec::new();
            c.read_to_end(&mut got).unwrap();
            got
        });
        rt().block_on(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut got = Vec::new();
            s.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"abc");
            let mut one = [0u8; 1];
            assert_eq!(s.read(&mut one).await.unwrap(), 0, "EOF is sticky");
            s.write_all(b"bye").await.unwrap();
            s.shutdown().await.unwrap();
            assert!(s.write(b"x").await.is_err(), "write after shutdown fails");
        });
        assert_eq!(c.join().unwrap(), b"bye");
    });
}

/// Peer closes completely: writes start failing (EPIPE/ECONNRESET) instead of hanging.
#[test]
fn peer_close_write_errors() {
    watchdog(30, || {
        let (l, addr) = listen();
        let (tx, rx) = mpsc::channel::<()>();
        let c = thread::spawn(move || {
            let c = client(addr);
            rx.recv().unwrap();
            drop(c);
        });
        rt().block_on(async move {
            let (mut s, _) = l.accept().await.unwrap();
            tx.send(()).unwrap();
            c.join().unwrap();
            let chunk = vec![0u8; 64 * 1024];
            let mut err = None;
            for _ in 0..10_000 {
                if let Err(e) = s.write_all(&chunk).await {
                    err = Some(e);
                    break;
                }
                if let Err(e) = s.flush().await {
                    err = Some(e);
                    break;
                }
            }
            let e = err.expect("writes to a closed peer must fail");
            assert!(
                matches!(e.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset),
                "unexpected error {e:?}"
            );
            let mut one = [0u8; 1];
            let r = s.read(&mut one).await;
            assert!(matches!(r, Ok(0) | Err(_)), "read after reset: {r:?}");
        });
    });
}

/// Dropping a stream with a recv in flight: the recv is cancelled and reaped, then the fd is closed (peer sees EOF).
#[test]
fn drop_with_read_in_flight() {
    watchdog(30, || {
        let (l, addr) = listen();
        let c = thread::spawn(move || {
            let mut c = client(addr);
            let mut b = [0u8; 16];
            c.read(&mut b).unwrap()
        });
        rt().block_on(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut store = [0u8; 64];
            poll_fn(|cx| {
                let mut rb = ReadBuf::new(&mut store);
                assert!(Pin::new(&mut s).poll_read(cx, &mut rb).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(s);
        });
        assert_eq!(c.join().unwrap(), 0, "peer sees EOF after the drop");
    });
}

/// Bytes accepted by poll_write are delivered even if the stream is dropped without flush (like a kernel buffer).
#[test]
fn drop_after_write_delivers() {
    watchdog(30, || {
        let (l, addr) = listen();
        let data = pattern(1024 * 1024 + 5, 9);
        let expect = data.clone();
        let c = thread::spawn(move || {
            let mut c = client(addr);
            thread::sleep(Duration::from_millis(200));
            let mut got = Vec::new();
            c.read_to_end(&mut got).unwrap();
            got
        });
        rt().block_on(async move {
            let (mut s, _) = l.accept().await.unwrap();
            s.write_all(&data).await.unwrap();
            drop(s);
        });
        assert!(c.join().unwrap() == expect);
    });
}

/// Accept is cancel-safe: a dropped accept future does not lose the connection.
#[test]
fn accept_cancel_safe() {
    watchdog(30, || {
        let (l, addr) = listen();
        rt().block_on(async move {
            let mut fut = Box::pin(l.accept());
            poll_fn(|cx| {
                assert!(fut.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(fut);
            let c = thread::spawn(move || {
                let mut c = client(addr);
                c.write_all(b"z").unwrap();
                let mut b = [0u8; 1];
                c.read_exact(&mut b).unwrap();
                b
            });
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 1];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b).await.unwrap();
            s.flush().await.unwrap();
            assert_eq!(c.join().unwrap(), *b"z");
        });
    });
}

fn epoll_targets() -> Vec<i32> {
    let mut out = Vec::new();
    for e in std::fs::read_dir("/proc/self/fdinfo").unwrap().flatten() {
        let Ok(text) = std::fs::read_to_string(e.path()) else { continue };
        for line in text.lines() {
            if let Some(n) =
                line.strip_prefix("tfd:").and_then(|rest| rest.split_whitespace().next()).and_then(|t| t.parse().ok())
            {
                out.push(n);
            }
        }
    }
    out
}

fn ring_fds() -> Vec<String> {
    let mut out = Vec::new();
    for e in std::fs::read_dir("/proc/self/fd").unwrap().flatten() {
        if std::fs::read_link(e.path()).is_ok_and(|t| t.to_string_lossy() == "anon_inode:[io_uring]") {
            out.push(e.file_name().to_string_lossy().into_owned());
        }
    }
    out
}

fn cq_tail(ring_fd: i32) -> u64 {
    let t = std::fs::read_to_string(format!("/proc/self/fdinfo/{ring_fd}")).unwrap();
    t.lines().find_map(|l| l.strip_prefix("CqTail:").and_then(|v| v.trim().parse::<u64>().ok())).unwrap()
}

/// The /proc evidence the front-equiv oracle reads: a ring fd exists, its CqTail moves with traffic, and neither the
/// listener nor the connection socket is registered in any epoll instance.
#[test]
fn proc_identity_not_in_epoll() {
    watchdog(30, || {
        let (l, addr) = listen();
        assert!(ring_fds().contains(&l.ring_fd().to_string()), "ring fd is not anon_inode:[io_uring]");
        let before = cq_tail(l.ring_fd());
        let (tx, rx) = mpsc::channel::<()>();
        let c = thread::spawn(move || {
            let mut c = client(addr);
            c.write_all(b"ping").unwrap();
            let mut b = [0u8; 4];
            c.read_exact(&mut b).unwrap();
            rx.recv().unwrap();
            b
        });
        rt().block_on(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b).await.unwrap();
            s.flush().await.unwrap();
            let t = epoll_targets();
            assert!(!t.contains(&s.as_raw_fd()), "connection fd {} is in an epoll set", s.as_raw_fd());
            assert!(!t.contains(&l.as_raw_fd()), "listener fd {} is in an epoll set", l.as_raw_fd());
            assert!(cq_tail(l.ring_fd()) > before, "CqTail did not advance");
            tx.send(()).unwrap();
        });
        assert_eq!(c.join().unwrap(), *b"ping");
    });
}

/// Fail closed: io_uring_setup returning EPERM (what a seccomp filter or io_uring_disabled=2 gives) refuses to
/// start, names io_uring, closes the socket (nothing is ever accepted), and does so at once.
#[test]
fn eperm_fails_closed() {
    let t0 = Instant::now();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let r = UringListener::bind_inner(l, UringConfig::default(), &|_: u32| Err(io::Error::from_raw_os_error(1)));
    let e = r.expect_err("EPERM must refuse to start");
    assert!(matches!(e, UringError::Unavailable(_)), "{e:?}");
    let msg = e.to_string();
    assert!(msg.contains("io_uring"), "{msg}");
    assert!(msg.contains("Operation not permitted"), "{msg}");
    assert!(msg.contains("no epoll fallback"), "{msg}");
    let refused = TcpStream::connect(addr).map_err(|e| e.kind());
    assert_eq!(refused.err(), Some(io::ErrorKind::ConnectionRefused), "the listener must be closed");
    assert!(t0.elapsed() < Duration::from_secs(8));
}

#[test]
fn config_bounds_refused() {
    for cfg in [
        UringConfig { sq_entries: 0, ..UringConfig::default() },
        UringConfig { sq_entries: 8192, ..UringConfig::default() },
        UringConfig { max_io: 0, ..UringConfig::default() },
        UringConfig { max_io: 2 * 1024 * 1024, ..UringConfig::default() },
        UringConfig { linger: Duration::from_secs(301), ..UringConfig::default() },
    ] {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let e = UringListener::bind_with(l, cfg.clone()).expect_err("out-of-range config accepted");
        assert!(matches!(e, UringError::Start(_)), "{cfg:?}: {e:?}");
        assert!(e.to_string().contains("io_uring"));
    }
}

/// Dropping the listener (no streams left) stops the driver, which closes the listening socket.
#[test]
fn listener_drop_closes_socket() {
    watchdog(30, || {
        let (l, addr) = listen();
        drop(l);
        let t0 = Instant::now();
        loop {
            match TcpStream::connect(addr) {
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => break,
                _ if t0.elapsed() > Duration::from_secs(5) => panic!("listener still open after drop"),
                _ => thread::sleep(Duration::from_millis(20)),
            }
        }
    });
}

#[test]
fn sockaddr_parsing() {
    let mut v4 = [0u8; 128];
    v4[..2].copy_from_slice(&2u16.to_ne_bytes());
    v4[2..4].copy_from_slice(&8443u16.to_be_bytes());
    v4[4..8].copy_from_slice(&[10, 1, 2, 3]);
    assert_eq!(crate::driver::parse_for_test(v4), Some("10.1.2.3:8443".parse().unwrap()));
    let mut v6 = [0u8; 128];
    v6[..2].copy_from_slice(&10u16.to_ne_bytes());
    v6[2..4].copy_from_slice(&443u16.to_be_bytes());
    v6[8..24].copy_from_slice(&"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
    assert_eq!(crate::driver::parse_for_test(v6), Some("[2001:db8::1]:443".parse().unwrap()));
    let mut unix = [0u8; 128];
    unix[..2].copy_from_slice(&1u16.to_ne_bytes());
    assert_eq!(crate::driver::parse_for_test(unix), None);
}

/// Compile-time: the stream fits `aegis-transport`'s `IO: AsyncRead + AsyncWrite + Unpin + Send + 'static`.
#[test]
fn stream_meets_transport_bounds() {
    fn takes<IO: AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>() {}
    fn sync_send<T: Send + Sync>() {}
    takes::<UringStream>();
    sync_send::<UringListener>();
}

/// aegis-bin hands over a dup of a listener another holder may have set O_NONBLOCK on (the file status flag is
/// shared): accept must still work (EAGAIN -> ring poll -> retry), with no epoll.
#[test]
fn nonblocking_listener_accepts() {
    watchdog(30, || {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        let addr = l.local_addr().unwrap();
        let u = UringListener::bind(l).unwrap();
        let c = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            let mut c = client(addr);
            c.write_all(b"nb").unwrap();
            c.shutdown(Shutdown::Write).unwrap();
            let mut got = Vec::new();
            c.read_to_end(&mut got).unwrap();
            got
        });
        rt().block_on(async move {
            let (s, _) = u.accept().await.unwrap();
            echo(s, 1024).await.unwrap();
        });
        assert_eq!(c.join().unwrap(), b"nb");
    });
}

/// A dropped stream whose accepted write cannot drain (the peer never reads) is aborted after `linger`, and the fd
/// is then closed: the peer gets the bytes the kernel took, then end of stream, never a hang.
#[test]
fn linger_bounds_a_stuck_write() {
    watchdog(60, || {
        let (l, addr) = listen_with(UringConfig { linger: Duration::from_secs(1), ..UringConfig::default() });
        let total = 64 * 1024 * 1024;
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let c = thread::spawn(move || {
            let mut c = client(addr);
            go_rx.recv().unwrap(); // the server has dropped its stream with a send in flight
            thread::sleep(Duration::from_secs(2)); // past the 1 s linger
            let mut got = 0usize;
            let mut b = vec![0u8; 1 << 16];
            loop {
                match c.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got += n,
                }
            }
            got
        });
        rt().block_on(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(300));
                let _ = tx.send(());
            });
            let data = vec![7u8; total];
            let mut w = Box::pin(s.write_all(&data));
            let done = poll_fn(|cx| {
                if let Poll::Ready(r) = w.as_mut().poll(cx) {
                    return Poll::Ready(Some(r));
                }
                match Pin::new(&mut rx).poll(cx) {
                    Poll::Ready(_) => Poll::Ready(None),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await;
            assert!(done.is_none(), "64 MiB should not fit while the peer is not reading");
            drop(w);
            drop(s);
            go_tx.send(()).unwrap();
        });
        let got = c.join().unwrap();
        assert!(got < total, "peer got {got} of {total}");
    });
}
