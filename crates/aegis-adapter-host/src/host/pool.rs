//! The bounded blocking pool for synchronous F7 handlers (DEVIATIONS X-11).
//!
//! A fixed set of worker threads, each running at most one task. Admission hands a task to an idle worker or
//! refuses it at once with [`Rejected`]: the pool never queues a task behind a busy worker and never runs one on
//! the caller's thread. A worker returns itself to the idle list *before* it delivers the task's result, so a
//! caller that has seen a result can be admitted again immediately.
//!
//! Results come back through a [`Ticket`]: `.await` it from async code (tokio oneshot) or [`Ticket::wait`] from a
//! plain thread.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::thread;

use tokio::sync::oneshot;

/// Largest pool accepted by [`BlockingPool::new`].
pub const MAX_POOL: usize = 4096;

type Deliver = Box<dyn FnOnce() + Send>;
type Task = Box<dyn FnOnce() -> Deliver + Send>;

/// The pool had no idle worker: the call was not made (X-11 admission rejection).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rejected;

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("blocking pool full")
    }
}

/// The task's result never arrived (its worker died; with `panic = "abort"` this does not happen in a live process).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lost;

#[derive(Debug)]
pub enum PoolError {
    /// Capacity outside `1..=MAX_POOL`.
    Capacity,
    Spawn(std::io::Error),
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoolError::Capacity => write!(f, "pool capacity must be 1..={MAX_POOL}"),
            PoolError::Spawn(e) => write!(f, "spawning a pool worker: {e}"),
        }
    }
}

impl std::error::Error for PoolError {}

/// Self-test mutations for `oracles/sdk-host` (POOL clause). Production uses [`PoolMutations::NONE`].
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolMutations {
    /// Admission never refuses (an extra thread runs the task).
    pub unbounded: bool,
    /// Tasks run on the caller's thread, bypassing the pool.
    pub inline: bool,
    /// Admission waits for a free worker (a `spawn_blocking`-style queue).
    pub queueing: bool,
}

impl PoolMutations {
    pub const NONE: PoolMutations = PoolMutations { unbounded: false, inline: false, queueing: false };
}

struct Shared {
    idle: Mutex<Vec<mpsc::Sender<Option<Task>>>>,
    freed: Condvar,
    shutdown: AtomicBool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned lock only means a worker died while holding it (impossible under panic = "abort"); the idle list is
    // still a valid list of senders.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Fixed-capacity blocking pool. Dropping it stops idle workers; busy workers stop after their task.
pub struct BlockingPool {
    shared: Arc<Shared>,
    capacity: usize,
    muts: PoolMutations,
}

impl fmt::Debug for BlockingPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlockingPool").field("capacity", &self.capacity).field("idle", &self.idle()).finish()
    }
}

impl BlockingPool {
    /// Spawn `capacity` workers.
    pub fn new(capacity: usize) -> Result<BlockingPool, PoolError> {
        BlockingPool::with_mutations(capacity, PoolMutations::NONE)
    }

    #[doc(hidden)]
    pub fn with_mutations(capacity: usize, muts: PoolMutations) -> Result<BlockingPool, PoolError> {
        if capacity == 0 || capacity > MAX_POOL {
            return Err(PoolError::Capacity);
        }
        let shared = Arc::new(Shared {
            idle: Mutex::new(Vec::with_capacity(capacity)),
            freed: Condvar::new(),
            shutdown: AtomicBool::new(false),
        });
        for i in 0..capacity {
            let tx = spawn_worker(&shared, i).map_err(PoolError::Spawn)?;
            lock(&shared.idle).push(tx);
        }
        Ok(BlockingPool { shared, capacity, muts })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Idle workers right now (diagnostics only; admission is decided under the lock in [`BlockingPool::try_run`]).
    pub fn idle(&self) -> usize {
        lock(&self.shared.idle).len()
    }

    /// Take an idle worker, or refuse at once. The returned [`Slot`] runs exactly one task; dropping it unused
    /// returns the worker.
    pub fn reserve(&self) -> Result<Slot<'_>, Rejected> {
        if self.muts.inline {
            return Ok(Slot { pool: self, kind: SlotKind::Inline }); // MUTATION (self-test only)
        }
        let mut idle = lock(&self.shared.idle);
        loop {
            if let Some(w) = idle.pop() {
                return Ok(Slot { pool: self, kind: SlotKind::Worker(Some(w)) });
            }
            if self.muts.unbounded {
                return Ok(Slot { pool: self, kind: SlotKind::Extra }); // MUTATION (self-test only)
            }
            if !self.muts.queueing {
                return Err(Rejected);
            }
            // MUTATION (self-test only): wait for a free worker instead of refusing.
            idle = self.shared.freed.wait(idle).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Run `f` on an idle worker, or refuse at once (`f` is then dropped unrun).
    pub fn try_run<T, F>(&self, f: F) -> Result<Ticket<T>, Rejected>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        Ok(self.reserve()?.run(f))
    }
}

#[derive(Debug)]
enum SlotKind {
    Worker(Option<mpsc::Sender<Option<Task>>>),
    Extra,
    Inline,
}

/// One admitted pool slot (see [`BlockingPool::reserve`]).
#[derive(Debug)]
pub struct Slot<'p> {
    pool: &'p BlockingPool,
    kind: SlotKind,
}

impl Slot<'_> {
    /// Run `f` on this slot's worker. If the worker has died the task is dropped and the ticket yields [`Lost`].
    pub fn run<T, F>(mut self, f: F) -> Ticket<T>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        let task: Task = Box::new(move || {
            let v = f();
            Box::new(move || {
                let _ = tx.send(v); // the receiver may be gone (caller cancelled): the result is dropped
            })
        });
        match &mut self.kind {
            SlotKind::Worker(w) => {
                if let Some(w) = w.take() {
                    let _ = w.send(Some(task));
                }
            }
            // MUTATION (self-test only): an extra thread beyond capacity.
            SlotKind::Extra => {
                let _ = thread::Builder::new().spawn(move || task()());
            }
            // MUTATION (self-test only): the caller's thread.
            SlotKind::Inline => task()(),
        }
        Ticket(rx)
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        if let SlotKind::Worker(Some(w)) = &mut self.kind {
            let w = w.clone();
            lock(&self.pool.shared.idle).push(w);
            self.pool.shared.freed.notify_one();
        }
    }
}

fn spawn_worker(shared: &Arc<Shared>, i: usize) -> std::io::Result<mpsc::Sender<Option<Task>>> {
    let (tx, rx) = mpsc::channel::<Option<Task>>();
    let me = tx.clone();
    let sh = Arc::clone(shared);
    thread::Builder::new().name(format!("aegis-blk-{i}")).spawn(move || {
        while let Ok(Some(task)) = rx.recv() {
            let deliver = task();
            {
                // Back to idle before delivering (under the lock that Drop also takes, so a worker either rejoins
                // a live pool or exits; it never rejoins after shutdown drained the list).
                let mut idle = lock(&sh.idle);
                if sh.shutdown.load(Ordering::SeqCst) {
                    drop(idle);
                    deliver();
                    return;
                }
                idle.push(me.clone());
            }
            sh.freed.notify_one();
            deliver();
        }
    })?;
    Ok(tx)
}

impl Drop for BlockingPool {
    fn drop(&mut self) {
        let idle: Vec<_> = {
            let mut g = lock(&self.shared.idle);
            self.shared.shutdown.store(true, Ordering::SeqCst);
            g.drain(..).collect()
        };
        for w in idle {
            let _ = w.send(None);
        }
        self.shared.freed.notify_all();
    }
}

/// The pending result of one pool task.
#[derive(Debug)]
pub struct Ticket<T>(oneshot::Receiver<T>);

impl<T> Ticket<T> {
    /// Block the calling thread until the task finished. Must not be called from inside an async runtime (use
    /// `.await` there).
    pub fn wait(self) -> Result<T, Lost> {
        self.0.blocking_recv().map_err(|_| Lost)
    }
}

impl<T> Future for Ticket<T> {
    type Output = Result<T, Lost>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map(|r| r.map_err(|_| Lost))
    }
}
