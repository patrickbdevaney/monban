//! Design 2: HOST-OWNED stream capability.
//!
//! The handler's `open` returns a `'static` generator/session value (plain data: cursors, counters, ids). The
//! host owns and drives it, and for EVERY step/message it re-derives the principal, re-checks the session, mints a
//! fresh `Ctx<'m>` + db view scoped to that one step, and passes them in. `'m` is higher-ranked (a method generic),
//! so the generator can never store them; the `'static` bound on the generator is a guard, not a leak.
//! Detached jobs use the same idea: `Ctx::detach` takes a `'static` job value, only with a `Tx<'r, Committed>`
//! proof, and the host later runs it with a freshly minted job-scoped `Ctx<'j>`.
//! Every signature here is synchronous and uses only core/alloc types (F7 stays no_std, app crates stay tokio-free).

use crate::host::HostDb;
use crate::surface::{Committed, Ctx, Db, Endowment, SdkError, Tx};
use std::sync::{Arc, Mutex};

pub use crate::d1::{Chunk, Event};

/// One pull of a host-driven stream.
#[derive(Debug, PartialEq, Eq)]
pub enum Step<T> {
    /// Emit one item now.
    Item(T),
    /// Nothing to emit now; the host re-polls on its next wake (timer or tenant change-feed).
    Idle,
    /// Stream finished; the host ends the body / SSE stream.
    Done,
}

/// A host-driven generator. `'static` + `Send` so the host may park it, move it across threads or resume it.
pub trait StreamGen: Send + 'static {
    type Item: Send + 'static;
    fn next<'m, D: Db<'m>>(&mut self, ctx: Ctx<'m>, db: &D) -> Result<Step<Self::Item>, SdkError>;
}

/// (a) streamed response body: `open` validates the request (request-scoped) and returns the generator.
pub trait BodyHandler: Send + Sync + 'static {
    type Gen: StreamGen<Item = Chunk>;
    fn open<'r, D: Db<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<Self::Gen, SdkError>;
}

/// (b) server-sent events; `last_event_id` lets the host resume a reconnecting client.
pub trait SseHandler: Send + Sync + 'static {
    type Gen: StreamGen<Item = Event>;
    fn open<'r, D: Db<'r>>(&self, ctx: Ctx<'r>, db: &D, last_event_id: Option<u64>) -> Result<Self::Gen, SdkError>;
}

/// Reply to one inbound WebSocket message.
#[derive(Debug, PartialEq, Eq)]
pub enum WsReply {
    Send(Vec<String>),
    Close,
}

/// (c) WebSocket session state, host-owned; called once per inbound message with a fresh per-message `Ctx<'m>`.
pub trait WsSessionGen: Send + 'static {
    fn on_message<'m, D: Db<'m>>(&mut self, ctx: Ctx<'m>, db: &D, msg: &str) -> Result<WsReply, SdkError>;
}

pub trait WsHandler: Send + Sync + 'static {
    type Session: WsSessionGen;
    fn open<'r, D: Db<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<Self::Session, SdkError>;
}

/// (d) detached job: a `'static` value the host runs later with a freshly minted job-scoped `Ctx<'j>`.
pub trait Job: Send + 'static {
    fn run<'j, D: Db<'j>>(self, ctx: Ctx<'j>, db: &D) -> Result<(), SdkError>;
}

// ---- host side of `detach` (erasure to the host's concrete db type; not visible to handlers as an API) ----
pub(crate) trait ErasedJob: Send {
    fn run_boxed(self: Box<Self>, ctx: Ctx<'_>, db: &HostDb<'_>) -> Result<(), SdkError>;
}
impl<J: Job> ErasedJob for J {
    fn run_boxed(self: Box<Self>, ctx: Ctx<'_>, db: &HostDb<'_>) -> Result<(), SdkError> {
        (*self).run(ctx, db)
    }
}

pub(crate) struct QueuedJob {
    pub(crate) user: u64,
    pub(crate) tenant: u64,
    pub(crate) endow: Arc<Endowment>, // host-held: originating session's live policy, re-checked at run time
    pub(crate) job: Box<dyn ErasedJob>,
}

/// Host-owned, per-connection link to the host's detached-job queue.
pub struct JobQueue {
    pub(crate) sink: Arc<Mutex<Vec<QueuedJob>>>,
    pub(crate) endow: Arc<Endowment>,
}

impl core::fmt::Debug for JobQueue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("JobQueue")
    }
}

impl<'r> Ctx<'r> {
    /// Enqueue a detached job. Requires proof that the request's transaction committed (no effect before commit).
    pub fn detach<J: Job>(&self, _after: &Tx<'r, Committed>, job: J) -> Result<(), SdkError> {
        let p = self.principal();
        let q = QueuedJob { user: p.user(), tenant: p.tenant(), endow: self.jobs.endow.clone(), job: Box::new(job) };
        self.jobs.sink.lock().map_err(|_| SdkError::Unavailable)?.push(q);
        Ok(())
    }
}
