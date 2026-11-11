//! Idempotency leases that always end (INV-IDEMP on monban-state, P4-state-002 finding).
//!
//! An `monban_state::Lease` that is dropped keeps its key `InFlight` until restart. [`LeaseGuard`] owns the lease
//! and ends it in exactly one [`LeaseGuard::commit`] or [`LeaseGuard::abort`]; on every other path (an error
//! return, a cancelled future that owned the guard, a pool rejection that dropped the task holding it, a timeout
//! that dropped the request) its `Drop` aborts the lease, so the key is free again. (`panic = "abort"` aside: then
//! the process dies and in-memory leases die with it.)
//!
//! [`Host::call_idempotent`](super::Host::call_idempotent) moves the guard into the pool task, so the lease ends
//! where the handler ends: committed with the reply when the handler succeeded, aborted otherwise, and aborted by
//! `Drop` when the pool rejected the task.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use monban_state::{Begin, IdemKey, Lease, Outcome, Reply, State, StateError};

fn lock(m: &Mutex<State>) -> MutexGuard<'_, State> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Shared idempotency state (the single-writer `State` behind a mutex).
#[derive(Clone)]
pub struct Idem {
    state: Arc<Mutex<State>>,
}

impl fmt::Debug for Idem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Idem").field("held", &self.held_count()).finish()
    }
}

/// Answer of [`Idem::begin`].
#[derive(Debug)]
pub enum Admission {
    /// Key free: run the request; the guard ends the lease.
    Run(LeaseGuard),
    /// Completed with the same digest: serve the stored outcome, run nothing.
    Replay(Outcome),
    /// Completed or held with a different digest (422-class).
    Conflict,
    /// Held by an open request with the same digest (409-class).
    InFlight,
}

impl Idem {
    pub fn new(state: State) -> Idem {
        Idem { state: Arc::new(Mutex::new(state)) }
    }

    pub fn begin(&self, key: &IdemKey, digest: &[u8]) -> Result<Admission, StateError> {
        Ok(match lock(&self.state).begin(key, digest)? {
            Begin::New(lease) => Admission::Run(LeaseGuard { lease: Some(lease), state: Arc::clone(&self.state) }),
            Begin::Replay(o) => Admission::Replay(o),
            Begin::Conflict => Admission::Conflict,
            Begin::InFlight => Admission::InFlight,
        })
    }

    /// Keys currently held by open leases.
    pub fn held_count(&self) -> usize {
        lock(&self.state).held_count()
    }

    /// The durable outcome of a completed key (retrieval after a 202).
    pub fn outcome(&self, key: &IdemKey) -> Result<Option<monban_state::Record>, StateError> {
        lock(&self.state).outcome(key)
    }
}

/// An open request's lease. Ends in exactly one commit or abort; `Drop` aborts.
pub struct LeaseGuard {
    lease: Option<Lease>,
    state: Arc<Mutex<State>>,
}

impl fmt::Debug for LeaseGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeaseGuard").field("held", &self.lease.is_some()).finish()
    }
}

impl LeaseGuard {
    /// The lease, to buffer user-row writes and outbox effects before the commit point.
    pub fn lease_mut(&mut self) -> Option<&mut Lease> {
        self.lease.as_mut()
    }

    pub fn key(&self) -> Option<&IdemKey> {
        self.lease.as_ref().map(Lease::key)
    }

    /// The commit point (NC2): rows, outcome record and outbox rows durably, then the latched reply. The key is
    /// released whatever the result.
    pub fn commit(mut self, outcome: Outcome, timer_fired_after_cp: bool) -> Result<Reply, StateError> {
        let lease = self.lease.take().ok_or(StateError::Invalid("lease already ended"))?;
        lock(&self.state).commit(lease, outcome, timer_fired_after_cp)
    }

    /// End before the commit point (NC1): nothing becomes durable and the key is free again.
    pub fn abort(mut self) {
        self.end();
    }

    fn end(&mut self) {
        if let Some(lease) = self.lease.take() {
            lock(&self.state).abort(lease);
        }
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        self.end();
    }
}
