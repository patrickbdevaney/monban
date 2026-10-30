//! Golden dispatch: the host order every data op takes before it reaches an engine.
//!
//! ```text
//! authorize(CapSet) → check_schema(introspected) → allowlist lock → budget pre-debit (NC4) → render → execute
//! ```
//!
//! * **authorize** is F4 [`aegis_data_ir::authorize`] on the route's endowment. A route without a data block holds
//!   no `CapSet` (`None`) and is denied (INV-NONEMPTY); `Unrestricted` exists only from the explicit literal.
//! * **check_schema** runs on the schema the engine introspected at boot. An unknown collection is refused as
//!   `Denied`, after authorization, so the answer reveals nothing a caller without a covering capability could not
//!   already see (W6). A deny is decided before anything else, so render is never reached on a deny.
//! * **allowlist lock**: when the engine carries a verified [`Allowlist`], an op whose shape is not a lock line is
//!   refused.
//! * **pre-debit** reserves the op's budget before render ([`RequestBudget::pre_debit`]).
//! * **render** is the engine's adapter (SQLite/PG renderers, `kv_plan` on Redis/Valkey, the F10 frame for an
//!   out-of-process module), then **execute** through the engine's [`Executor`].
//!
//! [`prepare`] is the pipeline up to render (what `oracles/nonempty-props` judges through host-subject); [`run`]
//! adds execution. [`ScopeBackend`] is the `aegis_sdk::host::Backend` that drives [`run`] for one SDK scope.
//!
//! Seams: an engine is a [`Renderer`] (adapter crate) paired with an [`Executor`] (connection or pool). The PG pool
//! (P4-pg-003) slots in as an `Executor<aegis_adapter_pg::Rendered>`; nothing here depends on how connections are
//! pooled, checked in or discarded (NC3 stays in the pool).

use std::cell::RefCell;
use std::fmt;
use std::sync::Arc;

use aegis_data_ir::{Allowlist, CapSet, Denied, Fidelity, Op, Schema, SchemaError, authorize, check_schema};
use aegis_sdk::SdkError;
use aegis_types::{Principal, TenantId};

use crate::host::budget::{Exhausted, OpLimits, Remaining, RequestBudget, Usage};
use crate::host::pool::CancelToken;

/// Why an engine refused or failed. Coarse on purpose: nothing engine-specific reaches the handler (W6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineError {
    /// The renderer refused the op (shape, W-rule, denylist, value class).
    Refused(String),
    /// The engine cannot run this kind of op (e.g. KV listing under per-tenant ACL users, PLAN D11).
    Unsupported,
    /// A write lost a race or hit a constraint.
    Conflict,
    /// Connection, timeout, limit or protocol failure (the resource is the executor's to quarantine, NC3).
    Unavailable(String),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::Refused(s) => write!(f, "refused: {s}"),
            EngineError::Unsupported => f.write_str("unsupported"),
            EngineError::Conflict => f.write_str("conflict"),
            EngineError::Unavailable(s) => write!(f, "unavailable: {s}"),
        }
    }
}

/// The adapter half of an engine: identity, fidelity, introspected schemas and the renderer. Pure.
pub trait Renderer: Send + Sync + 'static {
    type Rendered: Send + 'static;
    /// The backend id capabilities name (F8 `backend.id`).
    fn backend_id(&self) -> &str;
    fn fidelity(&self) -> Fidelity;
    /// The schema of `collection` as introspected and gated at boot; `None` if the engine has no such collection.
    fn schema(&self, collection: &str) -> Option<&Schema>;
    /// The verified allowlist lock of this engine, if one is configured.
    fn allowlist(&self) -> Option<&Allowlist> {
        None
    }
    /// Render one authorized, schema-checked op.
    fn render(&self, op: &Op, schema: &Schema) -> Result<Self::Rendered, EngineError>;
}

/// Who a scope runs as, for executors: the principal (pool keys never mix principals, CRS C2), its tenant, and the
/// scope's cancellation token. An executor checks the token at its cancellation points and releases its resources
/// as cancelled when the scope was cancelled before its commit point (NC1/NC3).
#[derive(Debug)]
pub struct ScopeInfo<'a> {
    pub principal: &'a Principal,
    pub tenant: TenantId,
    pub cancel: &'a CancelToken,
}

/// The effect half of an engine: one transaction (or connection lease) per SDK scope.
pub trait Executor<R>: Send + Sync + 'static {
    /// Per-scope transaction state (a pooled connection inside BEGIN with the tenant bound, a buffered KV batch...).
    /// Dropping it must release its resources (an executor implements `Drop` for that), because a scope can end
    /// without commit or rollback reaching it.
    type Tx: Send + 'static;
    type Rows: 'static;
    fn begin(&self, scope: &ScopeInfo<'_>) -> Result<Self::Tx, EngineError>;
    /// Execute one rendered op within `limits` (row cap, byte cap, statement timeout) and report what it used.
    fn execute(&self, tx: &mut Self::Tx, rendered: R, limits: OpLimits) -> Result<(Self::Rows, Usage), EngineError>;
    fn commit(&self, tx: Self::Tx) -> Result<(), EngineError>;
    fn rollback(&self, tx: Self::Tx);
}

/// A renderer paired with an executor.
#[derive(Debug)]
pub struct Engine<Rn, Ex> {
    pub renderer: Rn,
    pub executor: Ex,
}

/// Why [`prepare`] stopped. Only [`Refusal::Render`] means the render step was reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The authorization stage refused: no capability covers the op, or the route has no data block.
    Denied,
    /// Authorized, but the engine has no such collection. Handlers see the same `Denied` as above (W6).
    NoSuchCollection,
    /// The op fails F4 `check_schema` against the introspected schema.
    Schema(SchemaError),
    /// The op's shape is not in the engine's allowlist lock.
    NotInLock,
    /// The scope's budget is exhausted (NC4).
    Budget,
    /// The renderer refused the op.
    Render(EngineError),
}

impl Refusal {
    /// True iff the pipeline reached the render step.
    pub fn rendered(&self) -> bool {
        matches!(self, Refusal::Render(_))
    }
}

impl From<Denied> for Refusal {
    fn from(_: Denied) -> Refusal {
        Refusal::Denied
    }
}

impl From<Exhausted> for Refusal {
    fn from(_: Exhausted) -> Refusal {
        Refusal::Budget
    }
}

/// Self-test mutations for `oracles/nonempty-props` (`host-subject nonempty --mutate`). Production uses
/// [`DispatchMutations::NONE`]; each field breaks INV-NONEMPTY or the pipeline order on purpose.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DispatchMutations {
    /// `[]` grants everything.
    pub empty_means_all: bool,
    /// An absent or failed (null) endowment grants everything.
    pub missing_means_all: bool,
    /// An absent data block is read as `Unrestricted`.
    pub unrestricted_implicit: bool,
    /// Authorization never allows.
    pub deny_everything: bool,
    /// Render runs before authorization.
    pub render_on_deny: bool,
}

impl DispatchMutations {
    pub const NONE: DispatchMutations = DispatchMutations {
        empty_means_all: false,
        missing_means_all: false,
        unrestricted_implicit: false,
        deny_everything: false,
        render_on_deny: false,
    };
}

/// An op that passed every check and was rendered, with its budget reservation.
#[derive(Debug)]
pub struct Prepared<R> {
    pub rendered: R,
    pub debit: crate::host::budget::Debit,
}

/// The host pipeline up to render. `caps` is the route's endowment (`None` = no data block).
pub fn prepare<Rn: Renderer>(
    caps: Option<&CapSet>,
    renderer: &Rn,
    op: &Op,
    budget: &RequestBudget,
) -> Result<Prepared<Rn::Rendered>, Refusal> {
    prepare_with(caps, renderer, op, budget, DispatchMutations::NONE).map_err(|(r, _)| r)
}

/// [`prepare`] with self-test mutations. On refusal also returns whether render was reached (only differs from
/// [`Refusal::rendered`] under `render_on_deny`).
#[doc(hidden)]
pub fn prepare_with<Rn: Renderer>(
    caps: Option<&CapSet>,
    renderer: &Rn,
    op: &Op,
    budget: &RequestBudget,
    muts: DispatchMutations,
) -> Result<Prepared<Rn::Rendered>, (Refusal, bool)> {
    let mut early = None;
    if muts.render_on_deny {
        // MUTATION (self-test only): render before the capability check.
        if let Some(s) = renderer.schema(&op.collection) {
            early = Some(renderer.render(op, s));
        }
    }
    let reached = early.is_some();
    let fail = |r: Refusal| {
        let rendered = reached || r.rendered();
        (r, rendered)
    };
    // 1. Capability (INV-NONEMPTY): no data block, no capability.
    let caps = caps.ok_or(Refusal::Denied).map_err(fail)?;
    if muts.deny_everything {
        return Err(fail(Refusal::Denied)); // MUTATION (self-test only)
    }
    authorize(caps, renderer.backend_id(), op).map_err(|d| fail(d.into()))?;
    // 2. Static schema check against the introspected schema; an unknown collection is a uniform deny (W6).
    let schema = renderer.schema(&op.collection).ok_or(Refusal::NoSuchCollection).map_err(fail)?;
    check_schema(op, schema, renderer.fidelity()).map_err(|e| fail(Refusal::Schema(e)))?;
    // 3. Allowlist lock.
    if let Some(lock) = renderer.allowlist()
        && !lock.permits(op)
    {
        return Err(fail(Refusal::NotInLock));
    }
    // 4. Budget pre-debit (NC4), before any rendering or engine work.
    let debit = budget.pre_debit().map_err(|e| fail(e.into()))?;
    // 5. Render.
    let rendered = match early {
        Some(r) => r,
        None => renderer.render(op, schema),
    }
    .map_err(|e| fail(Refusal::Render(e)))?;
    Ok(Prepared { rendered, debit })
}

/// Failure of [`run`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DispatchError {
    Refused(Refusal),
    Engine(EngineError),
    /// The engine reported usage above the reservation (an adapter fault; fail closed).
    Overrun,
}

impl DispatchError {
    /// The uniform handler-facing error (W6: authorization and existence look the same).
    pub fn to_sdk(&self) -> SdkError {
        match self {
            DispatchError::Refused(Refusal::Budget) => SdkError::Unavailable,
            DispatchError::Refused(_) => SdkError::Denied,
            DispatchError::Engine(EngineError::Conflict) => SdkError::Conflict,
            DispatchError::Engine(EngineError::Refused(_) | EngineError::Unsupported) => SdkError::Denied,
            DispatchError::Engine(EngineError::Unavailable(_)) | DispatchError::Overrun => SdkError::Unavailable,
        }
    }
}

/// The full pipeline: [`prepare`], then execute inside `tx` within the reserved limits, then settle the debit.
pub fn run<Rn: Renderer, Ex: Executor<Rn::Rendered>>(
    caps: Option<&CapSet>,
    engine: &Engine<Rn, Ex>,
    op: &Op,
    budget: &RequestBudget,
    tx: &mut Ex::Tx,
) -> Result<Ex::Rows, DispatchError> {
    let p = prepare(caps, &engine.renderer, op, budget).map_err(DispatchError::Refused)?;
    let (rows, used) = engine.executor.execute(tx, p.rendered, p.debit.limits()).map_err(DispatchError::Engine)?;
    if !p.debit.covers(&used) {
        return Err(DispatchError::Overrun); // the debit drops unsettled: charged in full
    }
    p.debit.settle(used);
    Ok(rows)
}

/// The `aegis_sdk::host::Backend` of one SDK scope: tenant-bound, one transaction at most, every op through [`run`]
/// with the session's endowment and a fresh scope budget. The transaction is opened lazily at `begin`, so a scope
/// that never begins holds no connection.
pub struct ScopeBackend<Rn: Renderer, Ex: Executor<Rn::Rendered>> {
    engine: Arc<Engine<Rn, Ex>>,
    caps: Option<Arc<CapSet>>,
    principal: Principal,
    tenant: TenantId,
    cancel: CancelToken,
    budget: RequestBudget,
    tx: RefCell<Option<Ex::Tx>>,
}

impl<Rn: Renderer, Ex: Executor<Rn::Rendered>> fmt::Debug for ScopeBackend<Rn, Ex> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopeBackend")
            .field("tenant", &self.tenant)
            .field("open", &self.tx.try_borrow().map(|t| t.is_some()).unwrap_or(true))
            .finish_non_exhaustive()
    }
}

impl<Rn: Renderer, Ex: Executor<Rn::Rendered>> ScopeBackend<Rn, Ex> {
    /// Every op of the scope is bound to `principal`'s tenant.
    pub fn new(
        engine: Arc<Engine<Rn, Ex>>,
        caps: Option<Arc<CapSet>>,
        principal: Principal,
        cancel: CancelToken,
        budget: Remaining,
    ) -> Self {
        let tenant = principal.tenant();
        ScopeBackend {
            engine,
            caps,
            principal,
            tenant,
            cancel,
            budget: RequestBudget::new(budget),
            tx: RefCell::new(None),
        }
    }

    pub fn remaining(&self) -> Remaining {
        self.budget.remaining()
    }
}

impl<Rn: Renderer, Ex: Executor<Rn::Rendered>> aegis_sdk::host::Backend for ScopeBackend<Rn, Ex> {
    type Rows = Ex::Rows;

    fn begin(&self) -> Result<(), SdkError> {
        let mut slot = self.tx.try_borrow_mut().map_err(|_| SdkError::Conflict)?;
        if slot.is_some() {
            return Err(SdkError::Conflict);
        }
        let info = ScopeInfo { principal: &self.principal, tenant: self.tenant, cancel: &self.cancel };
        *slot = Some(self.engine.executor.begin(&info).map_err(|e| DispatchError::Engine(e).to_sdk())?);
        Ok(())
    }

    fn run(&self, op: Op) -> Result<Self::Rows, SdkError> {
        // The SDK already overwrote op.tenant with the principal's tenant; re-check (defence in depth).
        if op.tenant != self.tenant {
            return Err(SdkError::Denied);
        }
        let mut slot = self.tx.try_borrow_mut().map_err(|_| SdkError::Conflict)?;
        let tx = slot.as_mut().ok_or(SdkError::Denied)?;
        run(self.caps.as_deref(), &self.engine, &op, &self.budget, tx).map_err(|e| e.to_sdk())
    }

    fn commit(&self) -> Result<(), SdkError> {
        let tx = self.tx.try_borrow_mut().map_err(|_| SdkError::Conflict)?.take().ok_or(SdkError::Denied)?;
        self.engine.executor.commit(tx).map_err(|e| DispatchError::Engine(e).to_sdk())
    }

    fn rollback(&self) {
        if let Ok(mut slot) = self.tx.try_borrow_mut()
            && let Some(tx) = slot.take()
        {
            self.engine.executor.rollback(tx);
        }
    }
}

impl<Rn: Renderer, Ex: Executor<Rn::Rendered>> Drop for ScopeBackend<Rn, Ex> {
    /// A scope that ends with its transaction still open rolls it back (the SDK does this too; this covers host
    /// paths that drop a backend without an SDK scope, e.g. a backend opened for a revoked session).
    fn drop(&mut self) {
        if let Some(tx) = self.tx.get_mut().take() {
            self.engine.executor.rollback(tx);
        }
    }
}

/// [`crate::host::Backends`] over one engine: each scope gets a [`ScopeBackend`] bound to the session principal's
/// tenant and the session's route endowment, with a fresh budget.
pub struct EngineBackends<Rn: Renderer, Ex: Executor<Rn::Rendered>> {
    engine: Arc<Engine<Rn, Ex>>,
    budget: Remaining,
}

impl<Rn: Renderer, Ex: Executor<Rn::Rendered>> fmt::Debug for EngineBackends<Rn, Ex> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineBackends").field("budget", &self.budget).finish_non_exhaustive()
    }
}

impl<Rn: Renderer, Ex: Executor<Rn::Rendered>> EngineBackends<Rn, Ex> {
    pub fn new(engine: Arc<Engine<Rn, Ex>>, budget: Remaining) -> Self {
        EngineBackends { engine, budget }
    }
}

impl<Rn: Renderer, Ex: Executor<Rn::Rendered>> crate::host::Backends for EngineBackends<Rn, Ex> {
    type Backend = ScopeBackend<Rn, Ex>;

    fn open(&self, session: &crate::host::SessionHandle, cancel: &CancelToken) -> Result<Self::Backend, SdkError> {
        Ok(ScopeBackend::new(
            Arc::clone(&self.engine),
            session.endowment(),
            session.principal().clone(),
            cancel.clone(),
            self.budget,
        ))
    }
}
