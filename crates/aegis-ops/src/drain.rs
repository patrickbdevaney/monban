//! Accept loop with a stop flag and the two-phase drain (UP-1, UP-3 analogue for HTTP/1.1, UP-4).
//!
//! Phase 1 (GOAWAY analogue): [`ConnTracker::begin_drain`] flips `draining`; connection handlers finish the request
//! in flight, answer it with `Connection: close`, and close idle keep-alive connections. Phase 2: at the deadline
//! every connection still open is shut down and counted as a forced close. [`ConnTracker::drain`] returns no later
//! than the deadline plus one condvar wake-up.

use std::collections::HashMap;
use std::io;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

#[derive(Debug, Default)]
struct Inner {
    draining: AtomicBool,
    next: AtomicU64,
    conns: Mutex<HashMap<u64, TcpStream>>,
    cv: Condvar,
}

/// Tracks in-flight connections so the drain can wait for them and force-close stragglers.
#[derive(Debug, Clone, Default)]
pub struct ConnTracker {
    inner: Arc<Inner>,
}

/// Drop guard: unregisters the connection.
#[derive(Debug)]
pub struct ConnGuard {
    inner: Arc<Inner>,
    id: u64,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        lock(&self.inner.conns).remove(&self.id);
        self.inner.cv.notify_all();
    }
}

/// Result of a drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainReport {
    /// Connections force-closed at the deadline.
    pub forced: u64,
    /// Time the drain took.
    pub elapsed: Duration,
}

impl ConnTracker {
    /// New tracker.
    pub fn new() -> Self {
        Self::default()
    }
    /// Register a connection (keeps a clone of the socket for a forced shutdown).
    pub fn register(&self, s: &TcpStream) -> io::Result<ConnGuard> {
        let clone = s.try_clone()?;
        let id = self.inner.next.fetch_add(1, Ordering::Relaxed);
        lock(&self.inner.conns).insert(id, clone);
        Ok(ConnGuard { inner: self.inner.clone(), id })
    }
    /// Phase 1 started?
    pub fn is_draining(&self) -> bool {
        self.inner.draining.load(Ordering::Acquire)
    }
    /// Start phase 1 without waiting.
    pub fn begin_drain(&self) {
        self.inner.draining.store(true, Ordering::Release);
    }
    /// Connections currently open.
    pub fn in_flight(&self) -> usize {
        lock(&self.inner.conns).len()
    }
    /// Two-phase drain: phase 1 now, wait until no connection is open or `deadline` passes, then phase 2 (shut down
    /// and count the rest). UP-4: returns ≤ deadline (+ scheduling slack).
    pub fn drain(&self, deadline: Duration) -> DrainReport {
        let start = Instant::now();
        self.begin_drain();
        let mut g = lock(&self.inner.conns);
        loop {
            if g.is_empty() {
                return DrainReport { forced: 0, elapsed: start.elapsed() };
            }
            let left = deadline.saturating_sub(start.elapsed());
            if left.is_zero() {
                break;
            }
            g = match self.inner.cv.wait_timeout(g, left) {
                Ok((g, _)) => g,
                Err(p) => p.into_inner().0,
            };
        }
        let mut forced = 0u64;
        for s in g.values() {
            let _ = s.shutdown(Shutdown::Both);
            forced += 1;
        }
        g.clear();
        DrainReport { forced, elapsed: start.elapsed() }
    }
}

/// Accept connections from `listener` until `stop` is set, then drop (close) this process's fd for it.
///
/// The listener is put in non-blocking mode and polled every `tick`, so `stop` is honoured promptly. Note that
/// O_NONBLOCK lives on the shared open file description: parent and child both use this loop, so both expect it.
/// Closing this fd never closes the socket while another process (the upgraded child) holds it, which is what makes
/// the handover lossless (UP-1). Accepted sockets are returned in blocking mode.
pub fn accept_loop(
    listener: TcpListener,
    stop: &AtomicBool,
    tick: Duration,
    mut on_conn: impl FnMut(TcpStream),
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let timeout =
        Timespec { tv_sec: i64::try_from(tick.as_secs()).unwrap_or(i64::MAX), tv_nsec: tick.subsec_nanos().into() };
    loop {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut fds = [PollFd::new(&listener, PollFlags::IN)];
        match poll(&mut fds, Some(&timeout)) {
            Ok(0) => continue,
            Ok(_) => {}
            Err(Errno::INTR) => continue,
            Err(e) => return Err(io::Error::from(e)),
        }
        loop {
            if stop.load(Ordering::Acquire) {
                return Ok(());
            }
            match listener.accept() {
                Ok((s, _)) => {
                    if s.set_nonblocking(false).is_ok() {
                        on_conn(s);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                // ECONNABORTED and resource errors: the queue entry is gone or will be retried; keep serving.
                Err(_) => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn drain_waits_then_forces() {
        let Ok(l) = TcpListener::bind("127.0.0.1:0") else { return };
        let Ok(addr) = l.local_addr() else { return };
        let t = ConnTracker::new();
        let Ok(_c1) = TcpStream::connect(addr) else { return };
        let Ok((s1, _)) = l.accept() else { return };
        let g1 = t.register(&s1).ok();
        assert_eq!(t.in_flight(), 1);
        // A connection that finishes within the deadline is not forced.
        let t2 = t.clone();
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            drop(g1);
            drop(t2);
        });
        let r = t.drain(Duration::from_millis(2000));
        let _ = h.join();
        assert_eq!(r.forced, 0);
        assert!(t.is_draining());
        // A straggler is forced at the deadline and the drain returns on time.
        let Ok(mut c2) = TcpStream::connect(addr) else { return };
        let Ok((s2, _)) = l.accept() else { return };
        let _g2 = t.register(&s2);
        let r = t.drain(Duration::from_millis(100));
        assert_eq!(r.forced, 1);
        assert!(r.elapsed < Duration::from_millis(1000));
        let mut b = [0u8; 1];
        assert_eq!(c2.read(&mut b).unwrap_or(1), 0, "peer sees EOF after the forced close");
        let _ = c2.write(b"x");
    }

    #[test]
    fn accept_loop_stops_and_serves() {
        let Ok(l) = TcpListener::bind("127.0.0.1:0") else { return };
        let Ok(addr) = l.local_addr() else { return };
        let stop = Arc::new(AtomicBool::new(false));
        let st = stop.clone();
        let n = Arc::new(AtomicU64::new(0));
        let n2 = n.clone();
        let h = std::thread::spawn(move || {
            accept_loop(l, &st, Duration::from_millis(10), |_s| {
                n2.fetch_add(1, Ordering::Relaxed);
            })
        });
        for _ in 0..5 {
            let _ = TcpStream::connect(addr);
        }
        let t0 = Instant::now();
        while n.load(Ordering::Relaxed) < 5 && t0.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(5));
        }
        stop.store(true, Ordering::Release);
        assert!(matches!(h.join(), Ok(Ok(()))));
        assert_eq!(n.load(Ordering::Relaxed), 5);
        // Listener closed with no other holder: new connections are refused.
        assert!(TcpStream::connect(addr).is_err());
    }
}
