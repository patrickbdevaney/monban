//! The SDK host: every F7/F7b entry point (`drive`, `open_*`, `step`, `on_ws_message`, `run_job`) runs on the
//! bounded blocking pool, with a fresh `Session` view and a fresh per-scope backend per call.
//!
//! Host obligations met here (oracles/sdk-host):
//! * **MINT / GRANT-FRESH**: one SDK call per step or message; the `Session` handed to the SDK reads the live
//!   [`SessionHandle`] at the moment of each call.
//! * **REVOKE**: a step or message on a revoked session is `Unavailable` (generator not called) and closes the
//!   stream with [`CloseReason::Revoked`]; an open on a revoked session is `Denied`.
//! * **JOB-REVOKE / JOB-KEEP**: `Driven.jobs` is queued even when `Driven.result` is an error (a job exists only
//!   after a commit); each queued job runs once through `run_job` with its session as it is *then*.
//! * **IDLE-BUDGET / STEP-BUDGET**: per stream, in ticks (one host poll = one tick).
//! * **POOL**: every SDK call goes through [`BlockingPool::reserve`] (X-11): rejected at once when full.

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use aegis_sdk::host::{self as sdk, Backend, Driven, PendingJob, Request};
use aegis_sdk::{
    BodyHandler, Ctx, ScopedHandler, SdkError, SseHandler, Step, StreamGen, TenantDb, WsHandler, WsMsg, WsReply,
    WsSession,
};

use super::pool::{BlockingPool, CancelToken, Rejected, Ticket};
use super::session::{Frozen, SessionHandle, View};

/// Produces the per-scope `Backend` for a session. Called on the pool thread, once per SDK scope, so a backend
/// never crosses threads. Implementations should acquire connections lazily (at `Backend::begin`).
pub trait Backends: Send + Sync + 'static {
    type Backend: Backend;
    /// `cancel` is the scope's cancellation token (the caller dropped its ticket, or a deadline cancelled it);
    /// backends check it at their cancellation points and release resources as cancelled (NC1/NC3).
    fn open(&self, session: &SessionHandle, cancel: &CancelToken) -> Result<Self::Backend, SdkError>;
}

/// Self-test mutations for `oracles/sdk-host` (`host-subject sdk-host --mutate`). Production uses
/// [`HostMutations::NONE`].
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostMutations {
    /// Streams use the liveness and grants captured at open.
    pub mint_once_per_session: bool,
    /// Streams use the liveness captured at open (grants live).
    pub revoked_stream_keeps_serving: bool,
    /// A stream answered `Idle` is pulled again at once.
    pub step_retry_double_mint: bool,
    /// Jobs run with the liveness and grants captured when they were queued.
    pub job_ignores_revocation: bool,
    /// `Driven.jobs` is discarded when `Driven.result` is an error.
    pub drop_jobs_on_error: bool,
    /// Idle streams are never closed.
    pub no_idle_budget: bool,
    /// The step budget is not enforced.
    pub no_step_budget: bool,
}

impl HostMutations {
    pub const NONE: HostMutations = HostMutations {
        mint_once_per_session: false,
        revoked_stream_keeps_serving: false,
        step_retry_double_mint: false,
        job_ignores_revocation: false,
        drop_jobs_on_error: false,
        no_idle_budget: false,
        no_step_budget: false,
    };
}

/// Per-stream budgets in ticks. Both are at least 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamBudget {
    idle: u32,
    steps: u32,
}

impl StreamBudget {
    /// `idle`: consecutive idle polls before the stream is closed; `steps`: SDK steps before it is closed.
    pub fn new(idle: u32, steps: u32) -> Option<StreamBudget> {
        (idle >= 1 && steps >= 1).then_some(StreamBudget { idle, steps })
    }
    pub fn idle(&self) -> u32 {
        self.idle
    }
    pub fn steps(&self) -> u32 {
        self.steps
    }
}

/// Why the host closed a stream. A closed stream is dropped and never pulled again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// The callback returned an error.
    Error,
    /// The generator answered `Done` or the WebSocket session `Close`.
    Done,
    IdleBudget,
    StepBudget,
    /// The session was revoked (the SDK did not call the stream).
    Revoked,
}

impl CloseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            CloseReason::Error => "error",
            CloseReason::Done => "done",
            CloseReason::IdleBudget => "idle_budget",
            CloseReason::StepBudget => "step_budget",
            CloseReason::Revoked => "revoked",
        }
    }
}

/// Result of one SDK scope, after the host queued its jobs.
#[derive(Debug)]
pub struct Outcome<T> {
    pub result: Result<T, SdkError>,
    /// Jobs of this scope now in the host queue.
    pub jobs_queued: usize,
}

/// Result of one stream step, message or tick.
#[derive(Debug)]
pub struct StepOutcome<S, T> {
    /// The stream, unless this step closed it.
    pub stream: Option<S>,
    pub result: Result<T, SdkError>,
    pub jobs_queued: usize,
    pub closed: Option<CloseReason>,
}

/// Why a step was not made.
#[derive(Debug)]
pub enum StepRefused<S> {
    /// The pool is full; the stream is handed back unchanged.
    Rejected(S),
}

#[derive(Debug)]
struct Counters {
    budget: StreamBudget,
    steps: u32,
    idle: u32,
}

impl Counters {
    fn new(budget: StreamBudget) -> Self {
        Counters { budget, steps: 0, idle: 0 }
    }

    /// Account one callback that ran: `idle` / `done` / `err` classify its answer.
    fn account(&mut self, err: bool, done: bool, idle: bool, m: &HostMutations) -> Option<CloseReason> {
        self.steps = self.steps.saturating_add(1);
        let mut closed = if err {
            Some(CloseReason::Error)
        } else if done {
            Some(CloseReason::Done)
        } else if idle {
            self.idle = self.idle.saturating_add(1);
            (!m.no_idle_budget && self.idle >= self.budget.idle).then_some(CloseReason::IdleBudget)
        } else {
            self.idle = 0;
            None
        };
        if closed.is_none() && !m.no_step_budget && self.steps >= self.budget.steps {
            closed = Some(CloseReason::StepBudget);
        }
        closed
    }
}

/// A host-driven body or SSE stream: the generator plus its session and budget counters.
pub struct GenStream<G> {
    generator: G,
    session: SessionHandle,
    counters: Counters,
    frozen: Frozen,
}

impl<G> fmt::Debug for GenStream<G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenStream").field("session", &self.session).field("counters", &self.counters).finish()
    }
}

/// A host-driven WebSocket session.
pub struct WsStream<W> {
    ws: W,
    session: SessionHandle,
    counters: Counters,
    frozen: Frozen,
}

impl<W> fmt::Debug for WsStream<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WsStream").field("session", &self.session).field("counters", &self.counters).finish()
    }
}

impl<W> WsStream<W> {
    /// One idle poll with no inbound message: no SDK call, no pool. `Err(reason)` closes (and drops) the stream.
    pub fn tick(mut self, m_no_idle_budget: bool) -> Result<WsStream<W>, CloseReason> {
        self.counters.idle = self.counters.idle.saturating_add(1);
        if !m_no_idle_budget && self.counters.idle >= self.counters.budget.idle {
            return Err(CloseReason::IdleBudget);
        }
        Ok(self)
    }
}

/// A queued detached job and the session it runs under.
pub struct QueuedJob<B: Backend> {
    job: PendingJob<B>,
    session: SessionHandle,
    frozen: Frozen,
}

impl<B: Backend> fmt::Debug for QueuedJob<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueuedJob").field("session", &self.session).finish_non_exhaustive()
    }
}

struct Inner<F: Backends> {
    pool: BlockingPool,
    backends: F,
    jobs: Mutex<VecDeque<QueuedJob<F::Backend>>>,
    muts: HostMutations,
}

/// The SDK host for one backend family. Clone-cheap (`Arc` inside).
pub struct Host<F: Backends> {
    inner: Arc<Inner<F>>,
}

impl<F: Backends> Clone for Host<F> {
    fn clone(&self) -> Self {
        Host { inner: Arc::clone(&self.inner) }
    }
}

impl<F: Backends> fmt::Debug for Host<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Host").field("pool", &self.inner.pool).field("jobs", &self.queued_jobs()).finish()
    }
}

/// Probe around a stream value: records whether the SDK actually called it (it does not on a revoked session).
struct Probe<G> {
    g: G,
    called: bool,
}

impl<G: StreamGen> StreamGen for Probe<G> {
    type Item = G::Item;
    fn next<'m, D: TenantDb<'m>>(&mut self, ctx: Ctx<'m>, db: &D) -> Result<Step<Self::Item>, SdkError> {
        self.called = true;
        self.g.next(ctx, db)
    }
}

impl<W: WsSession> WsSession for Probe<W> {
    fn on_message<'m, D: TenantDb<'m>>(&mut self, ctx: Ctx<'m>, db: &D, msg: &WsMsg) -> Result<WsReply, SdkError> {
        self.called = true;
        self.g.on_message(ctx, db, msg)
    }
}

impl<F: Backends> Inner<F> {
    /// One SDK scope on the current (pool) thread: fresh backend, fresh session view, jobs queued.
    fn scope<T>(
        &self,
        session: &SessionHandle,
        frozen: Frozen,
        cancel: &CancelToken,
        f: impl FnOnce(&Request<'_, F::Backend, View<'_>>) -> Driven<T, F::Backend>,
    ) -> Outcome<T> {
        let backend = match self.backends.open(session, cancel) {
            Ok(b) => b,
            Err(e) => return Outcome { result: Err(e), jobs_queued: 0 },
        };
        let view = View { s: session, frozen };
        let req = Request { principal: session.principal(), route: session.route(), backend: &backend, session: &view };
        let d = f(&req);
        let jobs_queued = self.enqueue(d.jobs, session, d.result.is_err());
        Outcome { result: d.result, jobs_queued }
    }

    fn enqueue(&self, jobs: Vec<PendingJob<F::Backend>>, session: &SessionHandle, errored: bool) -> usize {
        if errored && self.muts.drop_jobs_on_error {
            return 0; // MUTATION (self-test only)
        }
        let frozen = if self.muts.job_ignores_revocation {
            Frozen { live: Some(session.live()), ops: Some(session.ops_now()) } // MUTATION (self-test only)
        } else {
            Frozen::NONE
        };
        let n = jobs.len();
        let mut q = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        q.extend(jobs.into_iter().map(|job| QueuedJob { job, session: session.clone(), frozen }));
        n
    }

    fn stream_frozen(&self, session: &SessionHandle) -> Frozen {
        if self.muts.mint_once_per_session {
            Frozen { live: Some(session.live()), ops: Some(session.ops_now()) } // MUTATION (self-test only)
        } else if self.muts.revoked_stream_keeps_serving {
            Frozen { live: Some(session.live()), ops: None } // MUTATION (self-test only)
        } else {
            Frozen::NONE
        }
    }
}

impl<F: Backends> Host<F> {
    pub fn new(pool: BlockingPool, backends: F) -> Host<F> {
        Host::with_mutations(pool, backends, HostMutations::NONE)
    }

    #[doc(hidden)]
    pub fn with_mutations(pool: BlockingPool, backends: F, muts: HostMutations) -> Host<F> {
        Host { inner: Arc::new(Inner { pool, backends, jobs: Mutex::new(VecDeque::new()), muts }) }
    }

    pub fn pool(&self) -> &BlockingPool {
        &self.inner.pool
    }

    pub fn mutations(&self) -> HostMutations {
        self.inner.muts
    }

    /// One SDK scope on the current thread (used inside pool tasks only).
    pub(crate) fn scope_now<T>(
        &self,
        session: &SessionHandle,
        cancel: &CancelToken,
        f: impl FnOnce(&Request<'_, F::Backend, View<'_>>) -> Driven<T, F::Backend>,
    ) -> Outcome<T> {
        self.inner.scope(session, Frozen::NONE, cancel, f)
    }

    /// `host::drive` of a request-scoped handler on the pool.
    pub fn call<H>(&self, h: Arc<H>, session: &SessionHandle) -> Result<Ticket<Outcome<H::Response>>, Rejected>
    where
        H: ScopedHandler + Send + Sync + 'static,
        H::Response: Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        let s = session.clone();
        Ok(self
            .inner
            .pool
            .reserve()?
            .run_cancellable(move |c| inner.scope(&s, Frozen::NONE, &c, |req| sdk::drive(&*h, req))))
    }

    /// `host::open_body` on the pool; on success the stream carries `budget`.
    pub fn open_body<H: BodyHandler>(
        &self,
        h: Arc<H>,
        session: &SessionHandle,
        budget: StreamBudget,
    ) -> Result<Ticket<Outcome<GenStream<H::Gen>>>, Rejected> {
        let inner = Arc::clone(&self.inner);
        let s = session.clone();
        Ok(self.inner.pool.reserve()?.run_cancellable(move |c| {
            let o = inner.scope(&s, Frozen::NONE, &c, |req| sdk::open_body(&*h, req));
            inner.gen_stream(o, s, budget)
        }))
    }

    /// `host::open_sse` on the pool.
    pub fn open_sse<H: SseHandler>(
        &self,
        h: Arc<H>,
        session: &SessionHandle,
        last_event_id: Option<u64>,
        budget: StreamBudget,
    ) -> Result<Ticket<Outcome<GenStream<H::Gen>>>, Rejected> {
        let inner = Arc::clone(&self.inner);
        let s = session.clone();
        Ok(self.inner.pool.reserve()?.run_cancellable(move |c| {
            let o = inner.scope(&s, Frozen::NONE, &c, |req| sdk::open_sse(&*h, req, last_event_id));
            inner.gen_stream(o, s, budget)
        }))
    }

    /// `host::open_ws` on the pool.
    pub fn open_ws<H: WsHandler>(
        &self,
        h: Arc<H>,
        session: &SessionHandle,
        budget: StreamBudget,
    ) -> Result<Ticket<Outcome<WsStream<H::Session>>>, Rejected> {
        let inner = Arc::clone(&self.inner);
        let s = session.clone();
        Ok(self.inner.pool.reserve()?.run_cancellable(move |c| {
            let o = inner.scope(&s, Frozen::NONE, &c, |req| sdk::open_ws(&*h, req));
            let frozen = inner.stream_frozen(&s);
            Outcome {
                result: o.result.map(|ws| WsStream { ws, session: s, counters: Counters::new(budget), frozen }),
                jobs_queued: o.jobs_queued,
            }
        }))
    }

    /// One `host::step` of a generator stream on the pool (a fresh context per step).
    #[allow(clippy::type_complexity)]
    pub fn step<G: StreamGen>(
        &self,
        st: GenStream<G>,
    ) -> Result<Ticket<StepOutcome<GenStream<G>, Step<G::Item>>>, StepRefused<GenStream<G>>> {
        let Ok(slot) = self.inner.pool.reserve() else { return Err(StepRefused::Rejected(st)) };
        let inner = Arc::clone(&self.inner);
        Ok(slot.run_cancellable(move |c| inner.step_gen(st, &c)))
    }

    /// One inbound WebSocket message (`host::on_ws_message`) on the pool.
    #[allow(clippy::type_complexity)]
    pub fn message<W: WsSession>(
        &self,
        st: WsStream<W>,
        msg: WsMsg,
    ) -> Result<Ticket<StepOutcome<WsStream<W>, WsReply>>, StepRefused<WsStream<W>>> {
        let Ok(slot) = self.inner.pool.reserve() else { return Err(StepRefused::Rejected(st)) };
        let inner = Arc::clone(&self.inner);
        Ok(slot.run_cancellable(move |c| inner.step_ws(st, &msg, &c)))
    }

    /// A WebSocket idle tick (no inbound message): no SDK call, no pool.
    pub fn tick<W>(&self, st: WsStream<W>) -> Result<WsStream<W>, CloseReason> {
        st.tick(self.inner.muts.no_idle_budget)
    }

    /// Jobs waiting in the queue.
    pub fn queued_jobs(&self) -> usize {
        self.inner.jobs.lock().unwrap_or_else(PoisonError::into_inner).len()
    }

    /// The oldest queued job (FIFO in queueing order).
    pub fn take_job(&self) -> Option<QueuedJob<F::Backend>> {
        self.inner.jobs.lock().unwrap_or_else(PoisonError::into_inner).pop_front()
    }

    /// Put a job back at the head of the queue (after a pool rejection).
    pub fn requeue_front(&self, job: QueuedJob<F::Backend>) {
        self.inner.jobs.lock().unwrap_or_else(PoisonError::into_inner).push_front(job);
    }

    /// `host::run_job` on the pool, with the job's session as it is now: a revoked session's job is `Denied` and
    /// never runs.
    #[allow(clippy::type_complexity)]
    pub fn run_job(&self, job: QueuedJob<F::Backend>) -> Result<Ticket<Outcome<()>>, (QueuedJob<F::Backend>, Rejected)>
    where
        F::Backend: 'static,
    {
        let Ok(slot) = self.inner.pool.reserve() else { return Err((job, Rejected)) };
        let inner = Arc::clone(&self.inner);
        let QueuedJob { job, session, frozen } = job;
        Ok(slot.run_cancellable(move |c| inner.scope(&session, frozen, &c, |req| sdk::run_job(job, req))))
    }
}

impl<F: Backends> Inner<F> {
    fn gen_stream<G>(&self, o: Outcome<G>, s: SessionHandle, budget: StreamBudget) -> Outcome<GenStream<G>> {
        let frozen = self.stream_frozen(&s);
        Outcome {
            result: o.result.map(|generator| GenStream {
                generator,
                session: s,
                counters: Counters::new(budget),
                frozen,
            }),
            jobs_queued: o.jobs_queued,
        }
    }

    fn step_gen<G: StreamGen>(
        &self,
        st: GenStream<G>,
        cancel: &CancelToken,
    ) -> StepOutcome<GenStream<G>, Step<G::Item>> {
        let GenStream { generator, session, mut counters, frozen } = st;
        let mut probe = Probe { g: generator, called: false };
        let mut o = self.scope(&session, frozen, cancel, |req| sdk::step(&mut probe, req));
        let mut queued = o.jobs_queued;
        if self.muts.step_retry_double_mint && matches!(o.result, Ok(Step::Idle)) {
            o = self.scope(&session, frozen, cancel, |req| sdk::step(&mut probe, req)); // MUTATION (self-test only)
            queued = queued.saturating_add(o.jobs_queued);
        }
        let closed = if probe.called {
            let (err, done, idle) = match &o.result {
                Err(_) => (true, false, false),
                Ok(Step::Done) => (false, true, false),
                Ok(Step::Idle) => (false, false, true),
                Ok(Step::Item(_)) => (false, false, false),
            };
            counters.account(err, done, idle, &self.muts)
        } else {
            Some(CloseReason::Revoked) // the SDK refused the scope: session not live; counters unchanged
        };
        let stream = match closed {
            Some(_) => None,
            None => Some(GenStream { generator: probe.g, session, counters, frozen }),
        };
        StepOutcome { stream, result: o.result, jobs_queued: queued, closed }
    }

    fn step_ws<W: WsSession>(
        &self,
        st: WsStream<W>,
        msg: &WsMsg,
        cancel: &CancelToken,
    ) -> StepOutcome<WsStream<W>, WsReply> {
        let WsStream { ws, session, mut counters, frozen } = st;
        let mut probe = Probe { g: ws, called: false };
        let o = self.scope(&session, frozen, cancel, |req| sdk::on_ws_message(&mut probe, req, msg));
        let closed = if probe.called {
            let (err, done) = match &o.result {
                Err(_) => (true, false),
                Ok(WsReply::Close) => (false, true),
                Ok(WsReply::Send(_)) => (false, false),
            };
            counters.account(err, done, false, &self.muts)
        } else {
            Some(CloseReason::Revoked)
        };
        let stream = match closed {
            Some(_) => None,
            None => Some(WsStream { ws: probe.g, session, counters, frozen }),
        };
        StepOutcome { stream, result: o.result, jobs_queued: o.jobs_queued, closed }
    }
}
