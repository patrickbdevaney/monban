//! Per-principal cordons (PLAN-5 D1, D8; SPEC_INVARIANTS INV-P2 P2-1..P2-3; ARCHITECTURE §3.6 single-tenant row as
//! amended by q4-006; F8 `p2.cordon_slots`, `p2.max_cordons`, `p2.cordon_idle_s`).
//!
//! A cordon is one exec-spawned monban-p2 process that serves the requests of exactly one principal: a fresh Wasm
//! instance per request from a pool of `cordon_slots`, fuel per route and an epoch wall bound. Two halves:
//!
//! - Supervisor side, [`Registry`]: the cordon table of monban-bin. Its key is the principal, so the only way to
//!   reach a cordon is through the principal that owns it; there is no API that puts a second principal on a
//!   cordon, and every id-based call ([`Registry::get`], [`Registry::release`], [`Registry::remove`]) refuses a
//!   principal other than the owner ([`RegistryError::ForeignPrincipal`]). The table is bounded (`max_cordons`): at
//!   the cap the least-recently-used idle cordon is evicted, and when none is idle the request is refused
//!   ([`RegistryError::AtCapacity`], 503), never routed to another principal's cordon. Idle cordons are reaped after
//!   `cordon_idle_s` ([`Registry::reap_idle`]). The table never spawns or kills anything itself: the caller spawns
//!   by execve (`crate::supervisor`, D8: never a fork of a template) and shuts down what the table hands back.
//! - Worker side, [`serve`]: the cordon's serving loop. The cordon process installs
//!   [`crate::sandbox::Profile::cordon`] while it is still single-threaded (Landlock and the seccomp filter bind
//!   the calling thread and are inherited by every thread created afterwards; the cordon layout allows only
//!   `CLONE_THREAD` clones, so a cordon can never fork), then calls [`serve`], which starts the serving threads.
//!   Each thread accepts on the supervisor-held listening socket (fd 3) and runs the handler on the connection.
//!
//! A cordon accepts damage local to its own principal (a host-level fault in a cordon affects only that principal's
//! later requests; spikes/q4-006). That is why cordons are never shared (D1), and why hostabort/hostpoison are
//! reported, not gated, for the cordon path of oracles/isolation-fi.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rustix::net::SocketFlags;

/// F8 `p2.max_cordons` bounds and default.
pub const MAX_CORDONS_MIN: usize = 1;
/// F8 maximum.
pub const MAX_CORDONS_MAX: usize = 4_096;
/// F8 default.
pub const MAX_CORDONS_DEFAULT: usize = 64;
/// F8 `p2.cordon_idle_s` bounds and default.
pub const IDLE_S_MIN: u64 = 1;
/// F8 maximum.
pub const IDLE_S_MAX: u64 = 86_400;
/// F8 default.
pub const IDLE_S_DEFAULT: u64 = 300;
/// Upper bound on serving threads in one cordon (F8 `p2.cordon_slots` maximum).
pub const MAX_THREADS: usize = 1_024;

// ------------------------------------------------------------------------------------------------ registry

/// Identity of one cordon process generation in a [`Registry`]. Only the registry makes one; a respawned or
/// re-created cordon gets a new id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CordonId(u64);

impl CordonId {
    /// The numeric value (logs only).
    pub fn get(self) -> u64 {
        self.0
    }
}

/// Why the registry refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryError {
    /// `max_cordons` or `idle_s` outside the F8 bounds.
    Bounds,
    /// The cordon belongs to another principal: a cordon never serves a second principal (D1, P2-2).
    ForeignPrincipal(CordonId),
    /// No such cordon (reaped, removed or never created).
    Unknown(CordonId),
    /// The table is full and no cordon is idle: refuse (503), never share.
    AtCapacity,
    /// More than `u32::MAX` requests in flight on one cordon.
    Busy(CordonId),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bounds => write!(f, "cordon registry: max_cordons or cordon_idle_s outside the F8 bounds"),
            Self::ForeignPrincipal(id) => {
                write!(f, "cordon {} belongs to another principal; a cordon never serves a second one", id.0)
            }
            Self::Unknown(id) => write!(f, "cordon {} is not in the registry", id.0),
            Self::AtCapacity => write!(f, "cordon registry at max_cordons with no idle cordon; refused"),
            Self::Busy(id) => write!(f, "cordon {}: in-flight counter overflow", id.0),
        }
    }
}

impl std::error::Error for RegistryError {}

#[derive(Debug)]
struct Slot<C> {
    id: CordonId,
    cordon: C,
    last_used: Instant,
    in_flight: u32,
}

/// What [`Registry::acquire`] did.
#[derive(Debug)]
pub struct Acquired<K, C> {
    /// The principal's cordon (now holding one more in-flight request).
    pub id: CordonId,
    /// Whether `spawn` ran (a new cordon for this principal).
    pub spawned: bool,
    /// A least-recently-used idle cordon evicted to make room: the caller shuts it down.
    pub evicted: Option<(K, CordonId, C)>,
}

/// The supervisor's cordon table, keyed by principal (see the module docs). `K` is the principal type
/// (`monban_types::Principal` in monban-bin); `C` is the cordon handle (`crate::supervisor::Supervised`).
#[derive(Debug)]
pub struct Registry<K, C> {
    max: usize,
    idle: Duration,
    next_id: u64,
    slots: HashMap<K, Slot<C>>,
}

impl<K: Eq + Hash + Clone, C> Registry<K, C> {
    /// An empty table with the F8 `max_cordons` and `cordon_idle_s` (bounds-checked, never clamped).
    pub fn new(max_cordons: usize, idle_s: u64) -> Result<Self, RegistryError> {
        if !(MAX_CORDONS_MIN..=MAX_CORDONS_MAX).contains(&max_cordons) || !(IDLE_S_MIN..=IDLE_S_MAX).contains(&idle_s) {
            return Err(RegistryError::Bounds);
        }
        Ok(Self { max: max_cordons, idle: Duration::from_secs(idle_s), next_id: 1, slots: HashMap::new() })
    }

    /// Live cordons.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether no cordon is live.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// `principal`'s cordon id, if it has one.
    pub fn id_of(&self, principal: &K) -> Option<CordonId> {
        self.slots.get(principal).map(|s| s.id)
    }

    /// The cordon for one request of `principal` at `now`: its existing cordon, or a new one made by `spawn` (called
    /// at most once, with the new id; the caller execs the worker). At the cap the least-recently-used idle cordon
    /// of another principal is evicted and handed back; with no idle cordon the request is refused. On success the
    /// cordon's in-flight count is raised; pair every success with [`Registry::release`].
    pub fn acquire<E>(
        &mut self,
        principal: &K,
        now: Instant,
        spawn: impl FnOnce(CordonId) -> Result<C, E>,
    ) -> Result<Result<Acquired<K, C>, E>, RegistryError> {
        if let Some(s) = self.slots.get_mut(principal) {
            s.in_flight = s.in_flight.checked_add(1).ok_or(RegistryError::Busy(s.id))?;
            s.last_used = now;
            return Ok(Ok(Acquired { id: s.id, spawned: false, evicted: None }));
        }
        let mut evicted = None;
        if self.slots.len() >= self.max {
            let victim = self
                .slots
                .iter()
                .filter(|(_, s)| s.in_flight == 0)
                .min_by_key(|(_, s)| (s.last_used, s.id))
                .map(|(k, _)| k.clone())
                .ok_or(RegistryError::AtCapacity)?;
            evicted = self.slots.remove(&victim).map(|s| (victim, s.id, s.cordon));
        }
        let id = CordonId(self.next_id);
        let cordon = match spawn(id) {
            Ok(c) => c,
            Err(e) => return Ok(Err(e)),
        };
        self.next_id = self.next_id.saturating_add(1);
        self.slots.insert(principal.clone(), Slot { id, cordon, last_used: now, in_flight: 1 });
        Ok(Ok(Acquired { id, spawned: true, evicted }))
    }

    fn owned(&mut self, id: CordonId, principal: &K) -> Result<&mut Slot<C>, RegistryError> {
        if self.slots.get(principal).is_none_or(|s| s.id != id) {
            return Err(if self.slots.values().any(|s| s.id == id) {
                RegistryError::ForeignPrincipal(id)
            } else {
                RegistryError::Unknown(id)
            });
        }
        self.slots.get_mut(principal).ok_or(RegistryError::Unknown(id))
    }

    /// The cordon `id` for a request of `principal`: refused unless `principal` owns it.
    pub fn get(&mut self, id: CordonId, principal: &K) -> Result<&mut C, RegistryError> {
        self.owned(id, principal).map(|s| &mut s.cordon)
    }

    /// Ends one in-flight request of `principal` on cordon `id` at `now` (refused unless `principal` owns it).
    pub fn release(&mut self, id: CordonId, principal: &K, now: Instant) -> Result<(), RegistryError> {
        let s = self.owned(id, principal)?;
        s.in_flight = s.in_flight.saturating_sub(1);
        s.last_used = now;
        Ok(())
    }

    /// Removes `principal`'s cordon `id` (e.g. after its death; refused unless `principal` owns it) and hands the
    /// handle back for shutdown.
    pub fn remove(&mut self, id: CordonId, principal: &K) -> Result<C, RegistryError> {
        self.owned(id, principal)?;
        self.slots.remove(principal).map(|s| s.cordon).ok_or(RegistryError::Unknown(id))
    }

    /// Removes every cordon with no request in flight that has been idle for at least `cordon_idle_s` at `now`, and
    /// hands them back for shutdown.
    pub fn reap_idle(&mut self, now: Instant) -> Vec<(K, CordonId, C)> {
        let idle = self.idle;
        let stale: Vec<K> = self
            .slots
            .iter()
            .filter(|(_, s)| s.in_flight == 0 && now.checked_duration_since(s.last_used).is_some_and(|d| d >= idle))
            .map(|(k, _)| k.clone())
            .collect();
        stale.into_iter().filter_map(|k| self.slots.remove(&k).map(|s| (k, s.id, s.cordon))).collect()
    }

    /// Every live cordon handle, for a periodic liveness check (`Supervised::check` respawns by execve).
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&K, CordonId, &mut C)> {
        self.slots.iter_mut().map(|(k, s)| (k, s.id, &mut s.cordon))
    }
}

// ------------------------------------------------------------------------------------------------ worker side

/// Accept errors after which a serving thread keeps going (transient or per-connection).
fn transient(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(
            libc::EINTR
                | libc::ECONNABORTED
                | libc::EAGAIN
                | libc::EMFILE
                | libc::ENFILE
                | libc::ENOBUFS
                | libc::ENOMEM
                | libc::EPROTO
        )
    )
}

/// Serving threads started before the first connection.
const INITIAL_THREADS: usize = 2;

/// State shared by the serving threads.
struct Pool<H> {
    listener: OwnedFd,
    handler: H,
    /// Threads blocked in (or about to enter) accept.
    idle: AtomicUsize,
    /// Threads started.
    total: AtomicUsize,
    max: usize,
    fatal: mpsc::Sender<io::Error>,
}

/// Starts one more serving thread if fewer than `max` exist. Returns false at the cap or if the thread could not be
/// started (the cordon keeps serving with the threads it has).
fn grow<H>(pool: &Arc<Pool<H>>) -> bool
where
    H: Fn(OwnedFd) + Send + Sync + 'static,
{
    let reserved = pool.total.try_update(Ordering::AcqRel, Ordering::Acquire, |t| (t < pool.max).then_some(t + 1));
    let Ok(n) = reserved else { return false };
    pool.idle.fetch_add(1, Ordering::AcqRel);
    let p = Arc::clone(pool);
    let started = std::thread::Builder::new().name(format!("monban-cordon-{n}")).spawn(move || run(&p));
    if started.is_err() {
        pool.idle.fetch_sub(1, Ordering::AcqRel);
        pool.total.fetch_sub(1, Ordering::AcqRel);
        return false;
    }
    true
}

/// One serving thread: accept, keep one idle thread in reserve (start one when this was the last idle thread),
/// handle the connection to completion, repeat.
fn run<H>(pool: &Arc<Pool<H>>)
where
    H: Fn(OwnedFd) + Send + Sync + 'static,
{
    loop {
        match rustix::net::accept_with(pool.listener.as_fd(), SocketFlags::CLOEXEC).map_err(io::Error::from) {
            Ok(conn) => {
                if pool.idle.fetch_sub(1, Ordering::AcqRel) == 1 {
                    grow(pool);
                }
                (pool.handler)(conn);
                pool.idle.fetch_add(1, Ordering::AcqRel);
            }
            Err(e) if transient(&e) => std::thread::sleep(Duration::from_millis(1)),
            Err(e) => {
                let _ = pool.fatal.send(e);
                return;
            }
        }
    }
}

/// Serves connections on `listener` with up to `threads` serving threads (1..=[`MAX_THREADS`], the cordon's
/// concurrent requests); each thread accepts one connection at a time and runs `handler` on it to completion.
/// Returns only when the listening socket fails (a non-transient accept error in any thread) or no serving thread
/// can be started; the caller exits and the supervisor respawns the cordon by execve.
///
/// Threads are started on demand: whenever the last idle thread takes a connection it starts one more, up to
/// `threads`, and threads never exit. So the cordon holds about its peak concurrency plus one thread instead of
/// `threads` idle accept waiters. Measured reason (P5-iso-003, laptop, one pinned core): with 64 threads parked in
/// accept for 16 concurrent clients, the constant wake-up of long-idle threads starved running requests for
/// 100+ ms (the 100 ms epoch deadline then trapped healthy requests after ~22 fuel units); with as many threads
/// as clients the stalls did not occur.
///
/// The caller must have installed [`crate::sandbox::Profile::cordon`] while single-threaded, before this call:
/// every serving thread inherits the Landlock domain and the seccomp filter of the calling thread.
pub fn serve<H>(listener: OwnedFd, threads: usize, handler: H) -> io::Error
where
    H: Fn(OwnedFd) + Send + Sync + 'static,
{
    if !(1..=MAX_THREADS).contains(&threads) {
        return io::Error::from_raw_os_error(libc::EINVAL);
    }
    let (fatal, rx) = mpsc::channel::<io::Error>();
    let pool = Arc::new(Pool {
        listener,
        handler,
        idle: AtomicUsize::new(0),
        total: AtomicUsize::new(0),
        max: threads,
        fatal,
    });
    let mut started = 0;
    for _ in 0..INITIAL_THREADS.min(threads) {
        started += usize::from(grow(&pool));
    }
    if started == 0 {
        return io::Error::from_raw_os_error(libc::EAGAIN);
    }
    // Only the serving threads hold the pool (and its Sender) from here on: if every one of them ends, recv fails.
    drop(pool);
    rx.recv().unwrap_or_else(|_| io::Error::from_raw_os_error(libc::EPIPE))
}
