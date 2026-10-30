//! The F7/F7b SDK host (decision D2(b)): drives `aegis_sdk::host` on the bounded blocking pool (X-11).
//!
//! * [`pool`]: fixed-capacity blocking pool; rejects at once when full, never queues, never runs inline.
//! * [`session`]: [`SessionHandle`], the live `aegis_sdk::host::Session` (endowment ∩ token, minus revocation).
//! * [`runtime`]: [`Host`], one SDK scope per call/open/step/message/job, job queue, stream budgets in ticks.
//! * [`reply`]: fixed content types + nosniff for handler values (sdk-trybuild M4).
//! * [`lease`]: idempotency leases that end in exactly one commit/abort on every path.
//! * [`endow`]: route endowment → F4 `CapSet` (INV-NONEMPTY at the boot seam).
//! * [`budget`]: per-op budgets with pre-debit (NC4).
//! * [`oop`]: F10 request frames for out-of-process modules.

pub mod budget;
pub mod endow;
pub mod lease;
pub mod oop;
pub mod pool;
pub mod reply;
pub mod runtime;
pub mod session;

use std::sync::Arc;

use aegis_sdk::ScopedHandler;
use aegis_state::{Outcome, Reply, StateError};

pub use pool::{BlockingPool, CancelToken, PoolError, Rejected, Ticket};
pub use reply::{HttpReply, Respond, reply};
pub use runtime::{
    Backends, CloseReason, GenStream, Host, HostMutations, Outcome as ScopeOutcome, QueuedJob, StepOutcome,
    StepRefused, StreamBudget, WsStream,
};
pub use session::SessionHandle;

/// Result of [`Host::call_idempotent`].
#[derive(Debug)]
pub struct IdemReply {
    /// The serialized reply (fixed content type, nosniff).
    pub reply: HttpReply,
    /// `Some` when the lease was committed (the handler succeeded): the latched reply, or the commit error (then
    /// nothing may be acknowledged). `None` when the lease was aborted (the handler failed; the key is free).
    pub latched: Option<Result<Reply, StateError>>,
    pub jobs_queued: usize,
}

impl<F: Backends> Host<F> {
    /// [`Host::call`] under an idempotency lease. The guard moves into the pool task and ends there: committed
    /// with the serialized reply when the handler returned `Ok`, aborted when it returned `Err`. If the pool
    /// rejects the call, the task (and the guard in it) is dropped unrun and `Drop` aborts the lease, so the key is
    /// reusable at once. Dropping the returned ticket (a cancelled request) does not stop the task: the handler
    /// finishes at its next host-call boundary (X-11) and the lease still ends in exactly one commit or abort.
    pub fn call_idempotent<H>(
        &self,
        h: Arc<H>,
        session: &SessionHandle,
        guard: lease::LeaseGuard,
    ) -> Result<Ticket<IdemReply>, Rejected>
    where
        H: ScopedHandler + Send + Sync + 'static,
        H::Response: Respond + Send + 'static,
    {
        let slot = self.pool().reserve()?; // on Err the guard is dropped here: lease aborted
        let host = self.clone();
        let s = session.clone();
        Ok(slot.run_cancellable(move |c| {
            let o = host.scope_now(&s, &c, |req| aegis_sdk::host::drive(&*h, req));
            let ok = o.result.is_ok();
            let reply = reply::reply(o.result);
            let latched = if ok {
                Some(guard.commit(Outcome { status: reply.status, body: reply.body.clone() }, false))
            } else {
                guard.abort();
                None
            };
            IdemReply { reply, latched, jobs_queued: o.jobs_queued }
        }))
    }
}
