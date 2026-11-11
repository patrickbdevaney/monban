//! Per-connection resource ledgers (TBI-4, TBI-5, TBI-6/7, TBI-9).
//!
//! [`Ledger`] is the pure model: `in_use = recv_held + send_outstanding ≤ cap` holds after every operation,
//! because bytes are only admitted by `try_reserve_*` when they fit, and every other operation only lowers a
//! term (saturating, TBI-9). [`ConnLedger`] puts it behind a mutex with a wake-up for waiters.

use std::pin::pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use monban_budget::TokenBucket;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, timeout_at};

/// Pure per-connection byte ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ledger {
    cap: u64,
    recv_held: u64,
    send_outstanding: u64,
    peak: u64,
}

impl Ledger {
    pub const fn new(cap: u64) -> Self {
        Self { cap, recv_held: 0, send_outstanding: 0, peak: 0 }
    }

    /// Bytes currently accounted.
    pub const fn in_use(&self) -> u64 {
        self.recv_held.saturating_add(self.send_outstanding)
    }

    pub const fn cap(&self) -> u64 {
        self.cap
    }

    /// Highest `in_use` ever observed.
    pub const fn peak(&self) -> u64 {
        self.peak
    }

    fn fits(&self, n: u64) -> bool {
        self.in_use().checked_add(n).is_some_and(|t| t <= self.cap)
    }

    fn note_peak(&mut self) {
        self.peak = self.peak.max(self.in_use());
    }

    /// Admit `n` received / decoded bytes the wrapper will hold. `false` (nothing changes) if they do not fit.
    pub fn try_reserve_recv(&mut self, n: u64) -> bool {
        if !self.fits(n) {
            return false;
        }
        self.recv_held = self.recv_held.saturating_add(n);
        self.note_peak();
        true
    }

    pub fn release_recv(&mut self, n: u64) {
        self.recv_held = self.recv_held.saturating_sub(n);
    }

    /// Admit `n` response bytes about to be handed to the protocol stack.
    pub fn try_reserve_send(&mut self, n: u64) -> bool {
        if !self.fits(n) {
            return false;
        }
        self.send_outstanding = self.send_outstanding.saturating_add(n);
        self.note_peak();
        true
    }

    /// `n` bytes reached the socket. Frame headers and control frames are written too, so this may release more
    /// than was reserved for DATA; it saturates at zero (the error is bounded by non-DATA bytes written).
    pub fn written(&mut self, n: u64) {
        self.send_outstanding = self.send_outstanding.saturating_sub(n);
    }

    /// The stack is known to hold no unwritten response bytes (no live stream and the last I/O was a completed
    /// flush): drop bytes that were handed for streams the peer reset, which the stack discarded unwritten.
    pub fn reset_send(&mut self) {
        self.send_outstanding = 0;
    }
}

/// Which side of the ledger a reservation debits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Side {
    Recv,
    Send,
}

/// Shared per-connection ledger with wake-ups.
#[derive(Debug)]
pub(crate) struct ConnLedger {
    inner: Mutex<Ledger>,
    notify: Notify,
    /// Set when no unwritten response bytes can remain in the stack (see [`Ledger::reset_send`]).
    flushed_idle: AtomicU64,
}

impl ConnLedger {
    pub(crate) fn new(cap: u64) -> Self {
        Self { inner: Mutex::new(Ledger::new(cap)), notify: Notify::new(), flushed_idle: AtomicU64::new(0) }
    }

    fn lock(&self) -> MutexGuard<'_, Ledger> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn snapshot(&self) -> Ledger {
        *self.lock()
    }

    pub(crate) fn try_reserve(&self, side: Side, n: u64) -> bool {
        let mut l = self.lock();
        match side {
            Side::Recv => l.try_reserve_recv(n),
            Side::Send => l.try_reserve_send(n),
        }
    }

    /// Reserve, waiting for releases until `deadline`. `false` on deadline (or if `n` can never fit).
    pub(crate) async fn reserve(&self, side: Side, n: u64, deadline: Instant) -> bool {
        if n > self.lock().cap() {
            return false;
        }
        loop {
            let mut notified = pin!(self.notify.notified());
            notified.as_mut().enable();
            if self.try_reserve(side, n) {
                return true;
            }
            if timeout_at(deadline, notified).await.is_err() {
                return false;
            }
        }
    }

    pub(crate) fn release_recv(&self, n: u64) {
        self.lock().release_recv(n);
        self.notify.notify_waiters();
    }

    pub(crate) fn written(&self, n: u64) {
        if n == 0 {
            return;
        }
        self.flushed_idle.store(0, Ordering::Relaxed);
        self.lock().written(n);
        self.notify.notify_waiters();
    }

    /// I/O layer: a flush completed (1) or a write was attempted (0).
    pub(crate) fn note_flushed(&self, done: bool) {
        self.flushed_idle.store(u64::from(done), Ordering::Relaxed);
    }

    /// Connection loop: with no live stream, a completed flush means the stack holds no response bytes.
    pub(crate) fn reconcile_if_idle(&self, live_streams: usize) {
        if live_streams == 0 && self.flushed_idle.load(Ordering::Relaxed) == 1 {
            self.lock().reset_send();
            self.notify.notify_waiters();
        }
    }
}

/// RAII hold on the receive side; released on drop.
#[derive(Debug)]
pub(crate) struct RecvHold {
    ledger: Arc<ConnLedger>,
    n: u64,
}

impl RecvHold {
    pub(crate) fn empty(ledger: Arc<ConnLedger>) -> Self {
        Self { ledger, n: 0 }
    }

    /// Record `n` more bytes already reserved on the receive side.
    pub(crate) fn grow(&mut self, n: u64) {
        self.n = self.n.saturating_add(n);
    }
}

impl Drop for RecvHold {
    fn drop(&mut self) {
        self.ledger.release_recv(self.n);
    }
}

/// TBI-4 handler gate: at most `live` handlers run per connection and at most `queue` wait for a permit. A permit
/// is moved into the stream task and held for its whole lifetime.
#[derive(Debug)]
pub(crate) struct HandlerGate {
    sem: Arc<Semaphore>,
    queued: AtomicU64,
    max_queue: u64,
}

/// Outcome of asking the gate.
#[derive(Debug)]
pub(crate) enum Admit {
    Permit(OwnedSemaphorePermit),
    /// More than `queue` tasks waiting: the connection gets GOAWAY ENHANCE_YOUR_CALM.
    QueueFull,
    /// No permit before the stall deadline.
    Timeout,
}

impl HandlerGate {
    pub(crate) fn new(live: usize, max_queue: u64) -> Self {
        Self { sem: Arc::new(Semaphore::new(live)), queued: AtomicU64::new(0), max_queue }
    }

    pub(crate) async fn admit(&self, deadline: Instant) -> Admit {
        if let Ok(p) = self.sem.clone().try_acquire_owned() {
            return Admit::Permit(p);
        }
        let entered = self
            .queued
            .try_update(Ordering::AcqRel, Ordering::Acquire, |q| if q < self.max_queue { Some(q + 1) } else { None })
            .is_ok();
        if !entered {
            return Admit::QueueFull;
        }
        let r = timeout_at(deadline, self.sem.clone().acquire_owned()).await;
        crate::counters::dec(&self.queued);
        match r {
            Ok(Ok(p)) => Admit::Permit(p),
            _ => Admit::Timeout,
        }
    }

    #[cfg(test)]
    pub(crate) fn queued(&self) -> u64 {
        self.queued.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn live(&self, total: usize) -> usize {
        total.saturating_sub(self.sem.available_permits())
    }
}

/// TBI-5 per-connection reset accounting.
#[derive(Debug)]
pub(crate) struct ResetBudget {
    bucket: Mutex<TokenBucket>,
    server_resets: AtomicU64,
    max_server_resets: u64,
}

impl ResetBudget {
    pub(crate) fn new(burst: u64, refill_per_s: u64, max_server_resets: u64, now_ns: u64) -> Self {
        Self {
            bucket: Mutex::new(TokenBucket::new(burst, refill_per_s, now_ns)),
            server_resets: AtomicU64::new(0),
            max_server_resets,
        }
    }

    /// Debit one peer reset; `false` once the bucket is empty.
    pub(crate) fn peer_reset(&self, now_ns: u64) -> bool {
        self.bucket.lock().unwrap_or_else(std::sync::PoisonError::into_inner).try_take(now_ns)
    }

    /// Count one reset we send; `false` once the cap is exceeded.
    pub(crate) fn server_reset(&self) -> bool {
        crate::counters::bump(&self.server_resets);
        self.server_resets.load(Ordering::Relaxed) <= self.max_server_resets
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    use super::*;

    /// TBI-6/7 ledger invariant under random operation sequences (xorshift, deterministic).
    #[test]
    fn ledger_never_exceeds_cap() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for cap in [0u64, 1, 4096, 12 << 20, u64::MAX] {
            let mut l = Ledger::new(cap);
            for _ in 0..20_000 {
                let n = match next() % 4 {
                    0 => next(),
                    1 => next() % 70_000,
                    _ => next() % 17_000,
                };
                match next() % 6 {
                    0 => {
                        let before = l;
                        if !l.try_reserve_recv(n) {
                            assert_eq!(l, before);
                        }
                    }
                    1 => {
                        let _ = l.try_reserve_send(n);
                    }
                    2 => l.release_recv(n),
                    3 => l.written(n),
                    4 => l.reset_send(),
                    _ => {}
                }
                assert!(l.in_use() <= cap, "in_use {} > cap {cap}", l.in_use());
                assert!(l.peak() <= cap);
            }
        }
    }

    #[test]
    fn reserve_waits_for_release_and_times_out() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        rt.block_on(async {
            let l = Arc::new(ConnLedger::new(100));
            assert!(l.try_reserve(Side::Send, 80));
            let soon = Instant::now() + std::time::Duration::from_millis(50);
            assert!(!l.reserve(Side::Recv, 30, soon).await);
            let l2 = l.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                l2.written(80);
            });
            let later = Instant::now() + std::time::Duration::from_secs(2);
            assert!(l.reserve(Side::Recv, 30, later).await);
            assert!(!l.reserve(Side::Recv, 101, later).await);
            assert_eq!(l.snapshot().in_use(), 30);
        });
    }

    #[test]
    fn gate_bounds_live_and_queue() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        rt.block_on(async {
            let g = Arc::new(HandlerGate::new(2, 1));
            let far = Instant::now() + std::time::Duration::from_secs(5);
            let Admit::Permit(p1) = g.admit(far).await else { panic!() };
            let Admit::Permit(_p2) = g.admit(far).await else { panic!() };
            let g2 = g.clone();
            let waiter = tokio::spawn(async move { matches!(g2.admit(far).await, Admit::Permit(_)) });
            tokio::task::yield_now().await;
            assert_eq!(g.queued(), 1);
            assert!(matches!(g.admit(far).await, Admit::QueueFull));
            assert_eq!(g.live(2), 2);
            drop(p1);
            assert!(waiter.await.unwrap());
            let Admit::Permit(_p3) = g.admit(far).await else { panic!() };
            let soon = Instant::now() + std::time::Duration::from_millis(20);
            assert!(matches!(g.admit(soon).await, Admit::Timeout));
        });
    }

    #[test]
    fn reset_budget_tbi5() {
        let r = ResetBudget::new(100, 33, 256, 0);
        let taken = (0..1000).filter(|_| r.peer_reset(0)).count();
        assert_eq!(taken, 100);
        assert!(r.peer_reset(1_000_000_000 / 33 + 1));
        assert!((0..256).all(|_| r.server_reset()));
        assert!(!r.server_reset());
    }
}
