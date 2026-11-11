//! Host seam (decision D2(b), cargo feature `host`). The host driving loop lives here, inside the SDK, so the
//! constructors of `Ctx`, `Granted` and `Tx` stay `pub(crate)`. The only effect seam is the [`Backend`] trait,
//! implemented by monban-adapter-host; [`Session`] is its live grant check. core/alloc only: no IO, no tokio.
//!
//! Only monban-adapter-host may enable feature `host` or name `monban_sdk::host` (`cargo xtask layering`, OWNERS).
//! Outside the workspace that rule is not enforced, but nothing here lets a caller mint a capability for a db view it
//! does not supply itself: every `Ctx` and `Granted` is minted inside one call below, is tied to that call's scope,
//! and can only be spent on the SDK-owned db view of the same call.
//!
//! Host obligations that stay outside the SDK (checked by the adapter-host oracle): call [`step`] /
//! [`on_ws_message`] once per step or message (each call mints a fresh context; never cache across calls), keep an
//! idle/step budget per stream, run returned [`PendingJob`]s only through [`run_job`], and run handlers on the bounded
//! blocking pool (DEVIATIONS X-11).

use crate::surface::Grants;
use crate::{
    BodyHandler, Committed, Ctx, DataCap, Granted, Job, JobQueue, Open, ScopedHandler, SdkError, SseHandler, Step,
    StreamGen, TenantDb, Tx, WsHandler, WsMsg, WsReply, WsSession, op_code,
};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::fmt;
use monban_data_ir::Op;
use monban_types::{Principal, RouteId, TenantId};

/// The data effect seam. One value per request, step, message or job, bound to the principal's tenant by the host.
/// The SDK calls it only from its own db view, after checking the capability proof and overwriting `Op::tenant`.
/// `'static` because detached jobs are stored beyond the request.
pub trait Backend: 'static {
    type Rows;
    /// Opens the (single) transaction of this scope.
    fn begin(&self) -> Result<(), SdkError>;
    /// Runs one operation inside the open transaction. `op.kind` matches the granted capability and `op.tenant` is
    /// the principal's tenant (both enforced by the SDK before this call).
    fn run(&self, op: Op) -> Result<Self::Rows, SdkError>;
    /// Makes the open transaction durable. On `Err` the SDK calls `rollback` and the handler sees the error.
    fn commit(&self) -> Result<(), SdkError>;
    /// Discards the open transaction: called when a scope ends with it still open, or after a failed commit.
    fn rollback(&self);
}

/// The live grant state of one session: the route's static endowment intersected with the verified token, minus
/// revocations. Consulted on every `Ctx::grant` and before every step, message and job.
pub trait Session {
    /// True iff data capability `op_code` (one of `op_code(OpKind::*)`) is granted now.
    fn permits(&self, op_code: u8) -> bool;
    /// False once the session or token is revoked or expired.
    fn live(&self) -> bool;
}

/// What the host hands the SDK for one scope.
pub struct Request<'a, B: Backend, S: Session> {
    pub principal: &'a Principal,
    pub route: RouteId,
    pub backend: &'a B,
    pub session: &'a S,
}

impl<B: Backend, S: Session> fmt::Debug for Request<'_, B, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request").field("principal", self.principal).field("route", &self.route).finish_non_exhaustive()
    }
}

type JobFn<B> = Box<dyn for<'j> FnOnce(Ctx<'j>, &HostDb<'j, B>) -> Result<(), SdkError> + Send>;

/// A job queued by `detach` after a commit. Opaque: the host stores it and later runs it with [`run_job`], which mints
/// a fresh job-scoped context (or denies it if the session is no longer live).
pub struct PendingJob<B: Backend> {
    run: JobFn<B>,
}

impl<B: Backend> fmt::Debug for PendingJob<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingJob")
    }
}

/// Result of one driven scope plus the jobs it queued (only possible after a commit, so they are kept even when the
/// handler later returned an error).
pub struct Driven<T, B: Backend> {
    pub result: Result<T, SdkError>,
    pub jobs: Vec<PendingJob<B>>,
}

impl<T, B: Backend> fmt::Debug for Driven<T, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Driven")
            .field("result", &self.result.as_ref().map(|_| ()))
            .field("jobs", &self.jobs.len())
            .finish()
    }
}

/// Request-scoped handler (`ScopedHandler`). Denied when the session is not live.
pub fn drive<B: Backend, S: Session, H: ScopedHandler>(h: &H, req: &Request<'_, B, S>) -> Driven<H::Response, B> {
    scope(req, SdkError::Denied, |ctx, db| h.handle(ctx, db))
}

/// Opens a host-driven response body. Denied when the session is not live.
pub fn open_body<B: Backend, S: Session, H: BodyHandler>(h: &H, req: &Request<'_, B, S>) -> Driven<H::Gen, B> {
    scope(req, SdkError::Denied, |ctx, db| h.open(ctx, db))
}

/// Opens a server-sent-event stream. Denied when the session is not live.
pub fn open_sse<B: Backend, S: Session, H: SseHandler>(
    h: &H,
    req: &Request<'_, B, S>,
    last_event_id: Option<u64>,
) -> Driven<H::Gen, B> {
    scope(req, SdkError::Denied, |ctx, db| h.open(ctx, db, last_event_id))
}

/// Opens a WebSocket session. Denied when the session is not live.
pub fn open_ws<B: Backend, S: Session, H: WsHandler>(h: &H, req: &Request<'_, B, S>) -> Driven<H::Session, B> {
    scope(req, SdkError::Denied, |ctx, db| h.open(ctx, db))
}

/// One pull of a stream generator with a freshly minted context. `Unavailable` (generator not called) when the
/// session is not live.
pub fn step<B: Backend, S: Session, G: StreamGen>(g: &mut G, req: &Request<'_, B, S>) -> Driven<Step<G::Item>, B> {
    scope(req, SdkError::Unavailable, |ctx, db| g.next(ctx, db))
}

/// One inbound WebSocket message with a freshly minted context. `Unavailable` (session not called) when the session
/// is not live.
pub fn on_ws_message<B: Backend, S: Session, W: WsSession>(
    w: &mut W,
    req: &Request<'_, B, S>,
    msg: &WsMsg,
) -> Driven<WsReply, B> {
    scope(req, SdkError::Unavailable, |ctx, db| w.on_message(ctx, db, msg))
}

/// Runs a detached job with a freshly minted job-scoped context. Denied (job dropped, not run) when the session is
/// not live.
pub fn run_job<B: Backend, S: Session>(job: PendingJob<B>, req: &Request<'_, B, S>) -> Driven<(), B> {
    scope(req, SdkError::Denied, |ctx, db| (job.run)(ctx, db))
}

/// Mints one scope: liveness gate, fresh `Ctx` and db view, rollback of a transaction left open, job collection.
fn scope<B, S, T, F>(req: &Request<'_, B, S>, not_live: SdkError, f: F) -> Driven<T, B>
where
    B: Backend,
    S: Session,
    F: for<'r> FnOnce(Ctx<'r>, &HostDb<'r, B>) -> Result<T, SdkError>,
{
    if !req.session.live() {
        return Driven { result: Err(not_live), jobs: Vec::new() };
    }
    let grants = Live(req.session);
    let db = HostDb {
        backend: req.backend,
        tenant: req.principal.tenant(),
        open: Cell::new(false),
        jobs: RefCell::new(Vec::new()),
    };
    let result = f(Ctx::mint(req.principal, req.route, &grants), &db);
    if db.open.replace(false) {
        req.backend.rollback();
    }
    Driven { result, jobs: db.jobs.into_inner() }
}

/// `Grants` over a host `Session`: only the five single-kind op codes can ever be granted, and only while live.
struct Live<'a, S: Session>(&'a S);

impl<S: Session> fmt::Debug for Live<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Live")
    }
}

impl<S: Session> Grants for Live<'_, S> {
    fn permits(&self, k: u8) -> bool {
        matches!(k, 1 | 2 | 4 | 8 | 16) && self.0.live() && self.0.permits(k)
    }
}

/// The SDK-owned tenant-bound db view handed to handlers. At most one open transaction per scope.
pub(crate) struct HostDb<'r, B: Backend> {
    backend: &'r B,
    tenant: TenantId,
    open: Cell<bool>,
    jobs: RefCell<Vec<PendingJob<B>>>,
}

fn erase<B: Backend, F>(f: F) -> JobFn<B>
where
    F: for<'j> FnOnce(Ctx<'j>, &HostDb<'j, B>) -> Result<(), SdkError> + Send + 'static,
{
    Box::new(f)
}

impl<'r, B: Backend> JobQueue<'r> for HostDb<'r, B> {
    fn detach<J: Job>(&self, _after: &Tx<'r, Committed>, job: J) -> Result<(), SdkError> {
        let mut q = self.jobs.try_borrow_mut().map_err(|_| SdkError::Unavailable)?;
        q.push(PendingJob { run: erase(move |ctx, db| job.run(ctx, db)) });
        Ok(())
    }
}

impl<'r, B: Backend> TenantDb<'r> for HostDb<'r, B> {
    type Rows = B::Rows;

    fn begin(&self) -> Result<Tx<'r, Open>, SdkError> {
        if self.open.get() {
            return Err(SdkError::Conflict);
        }
        self.backend.begin()?;
        self.open.set(true);
        Ok(Tx::mint())
    }

    fn run<const K: u8>(
        &self,
        _tx: &mut Tx<'r, Open>,
        _cap: &Granted<'r, DataCap<K>>,
        mut op: Op,
    ) -> Result<Self::Rows, SdkError> {
        if !self.open.get() || op_code(op.kind) != K {
            return Err(SdkError::Denied);
        }
        op.tenant = self.tenant;
        self.backend.run(op)
    }

    fn commit(&self, _tx: Tx<'r, Open>) -> Result<Tx<'r, Committed>, SdkError> {
        if !self.open.replace(false) {
            return Err(SdkError::Denied);
        }
        match self.backend.commit() {
            Ok(()) => Ok(Tx::mint()),
            Err(e) => {
                self.backend.rollback();
                Err(e)
            }
        }
    }
}
