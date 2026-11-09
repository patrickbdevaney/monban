//! Request context for the golden dispatch: the assembly's renderer/executor wrappers and the commit gate.
//!
//! aegis-adapter-host drives every SDK scope through its own `dispatch::ScopeBackend` (`EngineBackends`): the
//! assembly cannot implement an SDK backend (only aegis-adapter-host and apps may depend on aegis-sdk; D2(b)), so
//! what the assembly adds lives behind the two seams it owns (PLAN D15), [`CtxRenderer`] and [`CtxExec`]. Those
//! seams see only `(principal, tenant, cancel)` and the op, so a request's context ([`ReqCtx`]) is registered under
//! its (backend, tenant) slot and requests of one tenant on one backend run one at a time ([`Registry`]); the
//! slot is held until the pool task has ended, not merely until the client was answered.
//!
//! What the wrappers add to the dispatch pipeline (authorize → check_schema → allowlist lock → pre-debit → render
//! → execute, unchanged):
//! * **Commit point (NC1/NC2).** [`Gate`] makes the commit point and a cancellation mutually exclusive: a cancel
//!   (deadline, client gone, request dropped) that wins makes the commit refuse and roll back; a commit that won
//!   runs to completion, and the request is answered 202 if its deadline fired meanwhile.
//! * **Idempotency outcome in the same transaction (PLAN D14).** For a mutation with an `Idempotency-Key`, the
//!   reply the app commits to ([`ReqCtx::idem`]) is inserted into the backend's `aegis_idem` table inside the
//!   scope's own transaction, right before COMMIT: rows and outcome are durable together or not at all.
//! * **Existence is uniform (W6).** A point op (filter `Eq` on a key column) that matches no row is refused like a
//!   missing capability (`Denied`): handlers cannot tell "absent" from "not yours".
//! * **Row rendering.** F7 handlers never read row bytes; the rows of the scope's last select are kept for the host.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use aegis_adapter_host::dispatch::{EngineBackends, EngineError, Executor, Renderer, ScopeInfo};
use aegis_adapter_host::host::budget::{OpLimits, Usage};
use aegis_adapter_host::host::{CancelToken, Host};
use aegis_adapter_pg::PgConn;
use aegis_data_ir::{Allowlist, Fidelity, Op, OpKind, Pred, Schema, tenant_text};
use aegis_types::TenantId;
use tokio::sync::Notify;

use super::engines::{PgRenderer, SqliteRenderer};
use super::pg::{PgExecutor, PgTx};
use super::sqlite::{Rows, SqliteExec, SqliteTx};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Where the request stands with respect to its commit point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Before the commit point.
    Open,
    /// Cancelled before the commit point: the commit will refuse and roll back.
    Cancelled,
    /// The commit point was passed; COMMIT is running.
    Committing,
    Committed,
    /// COMMIT (or the outcome record) failed: nothing is durable.
    Failed,
}

/// Interrupts the statement a scope is running on its engine (PG/crdb: a CancelRequest with the session's
/// BackendKeyData over a separate connection). Blocking; run off the async workers.
pub type Interrupt = Box<dyn FnOnce() + Send>;

/// The armed interrupt of the scope's open transaction, and the interrupt in flight.
#[derive(Default)]
struct Interrupts {
    armed: Option<Interrupt>,
    sending: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for Interrupts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interrupts")
            .field("armed", &self.armed.is_some())
            .field("sending", &self.sending.is_some())
            .finish()
    }
}

/// The commit point / cancellation latch of one request (NC1/NC2).
///
/// A cancel that wins also fires the scope's armed [`Interrupt`] (R8: at the request deadline the running statement
/// is stopped on the server, not left to run to its statement_timeout). The interrupt is disarmed, and an interrupt
/// in flight is joined, before the scope's connection is released ([`Gate::disarm`]), so a CancelRequest never
/// reaches a backend after its connection went back to the pool.
#[derive(Debug)]
pub struct Gate {
    phase: Mutex<Phase>,
    interrupts: Mutex<Interrupts>,
    /// The executor's cancellation token: set only by this gate, so a cancel that lost the race to the commit point
    /// never interrupts COMMIT.
    exec: CancelToken,
    /// NEGATIVE CONTROL `commit-despite-cancel` (feature `e2e-mutants` only): cancellations are ignored.
    ignore_cancel: bool,
}

impl Gate {
    pub fn new(ignore_cancel: bool) -> Gate {
        Gate {
            phase: Mutex::new(Phase::Open),
            interrupts: Mutex::new(Interrupts::default()),
            exec: CancelToken::new(),
            ignore_cancel,
        }
    }

    pub fn phase(&self) -> Phase {
        *lock(&self.phase)
    }

    /// Cancel before the commit point, if it was not passed yet. Returns the phase after the call.
    pub fn cancel(&self) -> Phase {
        let mut p = lock(&self.phase);
        if *p == Phase::Open && !self.ignore_cancel {
            *p = Phase::Cancelled;
            self.exec.cancel();
            let mut i = lock(&self.interrupts);
            if let Some(f) = i.armed.take() {
                i.sending = std::thread::Builder::new().name("aegis-db-cancel".into()).spawn(f).ok();
            }
        }
        *p
    }

    /// Arm `f` for the scope's open transaction (replacing an earlier one). Not armed once the gate left `Open`
    /// (the executor's next cancellation point refuses anyway).
    pub fn arm(&self, f: Interrupt) {
        let p = lock(&self.phase);
        if *p == Phase::Open {
            lock(&self.interrupts).armed = Some(f);
        }
    }

    /// Drop the armed interrupt and wait for one in flight. Called before the scope's connection is released.
    pub fn disarm(&self) {
        let sending = {
            let mut i = lock(&self.interrupts);
            i.armed = None;
            i.sending.take()
        };
        if let Some(h) = sending {
            let _ = h.join();
        }
    }

    /// The commit point. `false`: cancelled first.
    fn enter_commit(&self) -> bool {
        let mut p = lock(&self.phase);
        if *p != Phase::Open {
            self.exec.cancel();
            return false;
        }
        *p = Phase::Committing;
        true
    }

    fn finish(&self, ok: bool) {
        *lock(&self.phase) = if ok { Phase::Committed } else { Phase::Failed };
    }
}

/// The outcome record of an idempotent mutation (PLAN D14).
#[derive(Clone, Debug)]
pub struct Idem {
    /// `principal_bytes` of the principal, hex.
    pub principal: String,
    pub key: String,
    pub status: u16,
    pub body: String,
}

/// An in-memory claim on (principal, key) while a request holds it; released on drop.
#[derive(Debug)]
pub struct Claim {
    set: Arc<Mutex<std::collections::HashSet<(String, String)>>>,
    k: (String, String),
}

impl Claim {
    pub fn take(
        set: &Arc<Mutex<std::collections::HashSet<(String, String)>>>,
        principal: &str,
        key: &str,
    ) -> Option<Claim> {
        let k = (principal.to_string(), key.to_string());
        lock(set).insert(k.clone()).then(|| Claim { set: Arc::clone(set), k })
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        lock(&self.set).remove(&self.k);
    }
}

/// The op being executed, as the renderer saw it (render and execute are sequential within a scope).
#[derive(Clone, Debug, Default)]
struct CurOp {
    select: bool,
    write: bool,
    point: bool,
    names: Vec<String>,
}

/// Everything one request's scope needs beyond the session.
#[derive(Debug)]
pub struct ReqCtx {
    /// `false` when the route holds no data capability: the executor refuses to begin (INV-NONEMPTY).
    pub reach: bool,
    /// The tenant every op is bound to: the principal's (the token's tenant caveat).
    pub data_tenant: TenantId,
    pub idem: Option<Idem>,
    pub gate: Gate,
    /// Field names and rows of the scope's last select.
    pub rows: Mutex<Option<(Vec<String>, Rows)>>,
    cur: Mutex<CurOp>,
    /// NEGATIVE CONTROL `body-before-cp`: set after the first successful write, before the commit point.
    pub early: AtomicBool,
    pub body_before_cp: bool,
    /// Held for its `Drop`: the (principal, key) claim ends with the request context.
    _claim: Option<Claim>,
}

impl ReqCtx {
    pub fn new(
        reach: bool,
        data_tenant: TenantId,
        idem: Option<Idem>,
        claim: Option<Claim>,
        m: &crate::shared::Mutants,
    ) -> Self {
        ReqCtx {
            reach,
            data_tenant,
            idem,
            gate: Gate::new(m.commit_despite_cancel),
            rows: Mutex::new(None),
            cur: Mutex::new(CurOp::default()),
            early: AtomicBool::new(false),
            body_before_cp: m.body_before_cp,
            _claim: claim,
        }
    }
}

/// Slot key: (backend index, principal tenant).
pub type Slot = (usize, TenantId);

/// Request contexts by slot. A slot is held from admission until the request's pool task ended.
#[derive(Debug, Default)]
pub struct Registry {
    map: Mutex<HashMap<Slot, Option<Arc<ReqCtx>>>>,
    freed: Notify,
}

impl Registry {
    /// Take a free slot (with no context yet). `false`: held by another request.
    pub fn try_take(&self, slot: Slot) -> bool {
        let mut m = lock(&self.map);
        if m.contains_key(&slot) {
            return false;
        }
        m.insert(slot, None);
        true
    }
    /// Wait until some slot is released.
    pub fn freed(&self) -> tokio::sync::futures::Notified<'_> {
        self.freed.notified()
    }
    pub fn set(&self, slot: Slot, ctx: Arc<ReqCtx>) {
        if let Some(v) = lock(&self.map).get_mut(&slot) {
            *v = Some(ctx);
        }
    }
    pub fn release(&self, slot: Slot) {
        lock(&self.map).remove(&slot);
        self.freed.notify_waiters();
    }
    fn get(&self, slot: Slot) -> Option<Arc<ReqCtx>> {
        lock(&self.map).get(&slot).cloned().flatten()
    }
    /// Requests holding a slot (the drain waits for zero).
    pub fn active(&self) -> usize {
        lock(&self.map).len()
    }
}

// ------------------------------------------------------------------------------------------------ renderer wrapper

/// The engine's renderer, plus: the op is rendered for the request's data tenant, and its shape is noted for the
/// executor (point op, select column names).
#[derive(Debug)]
pub struct CtxRenderer<R> {
    pub inner: R,
    reg: Arc<Registry>,
    backend: usize,
}

impl<R: Renderer> Renderer for CtxRenderer<R> {
    type Rendered = R::Rendered;
    fn backend_id(&self) -> &str {
        self.inner.backend_id()
    }
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }
    fn schema(&self, collection: &str) -> Option<&Schema> {
        self.inner.schema(collection)
    }
    fn allowlist(&self) -> Option<&Allowlist> {
        self.inner.allowlist()
    }
    fn render(&self, op: &Op, schema: &Schema) -> Result<Self::Rendered, EngineError> {
        let ctx = self.reg.get((self.backend, op.tenant)).ok_or(EngineError::Unsupported)?;
        let mut op = op.clone();
        op.tenant = ctx.data_tenant; // equal to op.tenant, except under the tenant-from-path negative control
        let point = match &op.filter {
            Pred::Eq(f, _) => schema.columns.iter().any(|c| c.field == *f && c.key),
            _ => false,
        };
        let names = op
            .returning
            .iter()
            .map(|f| schema.columns.iter().find(|c| c.field == *f).map(|c| c.name.clone()).unwrap_or_default())
            .collect();
        *lock(&ctx.cur) = CurOp {
            select: op.kind == OpKind::Select,
            write: op.kind != OpKind::Select,
            point: point && matches!(op.kind, OpKind::Select | OpKind::Update | OpKind::Delete),
            names,
        };
        self.inner.render(&op, schema)
    }
}

// ------------------------------------------------------------------------------------------------ executor wrapper

/// Host-owned statements an engine runs inside a scope's transaction.
pub trait HostSql<R>: Executor<R, Rows = Rows> {
    fn write_idem(&self, tx: &mut Self::Tx, tenant: &str, idem: &Idem) -> Result<(), EngineError>;
    /// How to interrupt the statement `tx` is running from another thread (`None`: the engine has no such path;
    /// a cancel then takes effect at the next cancellation point).
    fn interrupt(&self, _tx: &Self::Tx) -> Option<Interrupt> {
        None
    }
}

impl HostSql<aegis_adapter_sqlite::Rendered> for SqliteExec {
    fn write_idem(&self, tx: &mut SqliteTx, _tenant: &str, idem: &Idem) -> Result<(), EngineError> {
        let status = idem.status.to_string();
        if !self.stamped() {
            return self
                .raw(
                    tx,
                    "INSERT INTO aegis_idem (principal, k, status, body) VALUES (?1, ?2, ?3, ?4)",
                    &[idem.principal.as_str(), idem.key.as_str(), status.as_str(), idem.body.as_str()],
                )
                .map(|_| ());
        }
        // IDEMP-R (super::retention): the lookup forgot an expired row of this key, so the new outcome replaces it
        // here, in the same transaction; a row inside the window is never deleted (the insert then conflicts).
        let now = super::retention::now_s();
        if let Some(cut) = self.retention().and_then(|r| super::retention::cutoff(now, r)) {
            let cut = cut.to_string();
            self.raw(
                tx,
                "DELETE FROM aegis_idem WHERE principal = ?1 AND k = ?2 AND committed_at IS NOT NULL \
                 AND committed_at <= CAST(?3 AS INTEGER)",
                &[idem.principal.as_str(), idem.key.as_str(), cut.as_str()],
            )?;
        }
        let now = now.to_string();
        self.raw(
            tx,
            "INSERT INTO aegis_idem (principal, k, status, body, committed_at) \
             VALUES (?1, ?2, ?3, ?4, CAST(?5 AS INTEGER))",
            &[idem.principal.as_str(), idem.key.as_str(), status.as_str(), idem.body.as_str(), now.as_str()],
        )
        .map(|_| ())
    }
}

impl HostSql<aegis_adapter_pg::Rendered> for PgExecutor<PgConn> {
    fn write_idem(&self, tx: &mut PgTx<PgConn>, tenant: &str, idem: &Idem) -> Result<(), EngineError> {
        let status = idem.status.to_string();
        self.raw(
            tx,
            "INSERT INTO aegis_idem (tenant, principal, k, status, body) VALUES ($1, $2, $3, $4::integer, $5)",
            &[
                Some(tenant),
                Some(idem.principal.as_str()),
                Some(idem.key.as_str()),
                Some(status.as_str()),
                Some(idem.body.as_str()),
            ],
            1,
        )
        .map(|_| ())
    }

    /// PG/crdb CancelRequest with the session's BackendKeyData (R8).
    fn interrupt(&self, tx: &PgTx<PgConn>) -> Option<Interrupt> {
        tx.interrupt()
    }
}

/// One scope's transaction with its request context. Field order matters: `_disarm` drops (joins any interrupt in
/// flight) before `inner` releases the connection.
pub struct CtxTx<T> {
    _disarm: Disarm,
    inner: T,
    ctx: Arc<ReqCtx>,
}

/// Disarms the request's gate on drop (a scope that ends without commit or rollback reaching the executor).
pub struct Disarm(Arc<ReqCtx>);

impl Drop for Disarm {
    fn drop(&mut self) {
        self.0.gate.disarm();
    }
}

/// The engine's executor behind the request's commit gate.
#[derive(Debug)]
pub struct CtxExec<E> {
    pub inner: E,
    reg: Arc<Registry>,
    backend: usize,
}

impl<R: Send + 'static, E: HostSql<R>> Executor<R> for CtxExec<E> {
    type Tx = CtxTx<E::Tx>;
    type Rows = Rows;

    fn begin(&self, scope: &ScopeInfo<'_>) -> Result<Self::Tx, EngineError> {
        // Fail closed: an executor call without a registered request context never reaches the engine.
        let ctx = self.reg.get((self.backend, scope.tenant)).ok_or(EngineError::Unsupported)?;
        if !ctx.reach {
            return Err(EngineError::Refused("route holds no data capability".into()));
        }
        if ctx.gate.phase() != Phase::Open {
            return Err(EngineError::Unavailable("cancelled before begin".into()));
        }
        let info = ScopeInfo { principal: scope.principal, tenant: ctx.data_tenant, cancel: &ctx.gate.exec };
        let inner = self.inner.begin(&info)?;
        if let Some(f) = self.inner.interrupt(&inner) {
            ctx.gate.arm(f);
        }
        Ok(CtxTx { _disarm: Disarm(Arc::clone(&ctx)), inner, ctx })
    }

    fn execute(&self, tx: &mut Self::Tx, r: R, l: OpLimits) -> Result<(Rows, Usage), EngineError> {
        let cur = lock(&tx.ctx.cur).clone();
        let (rows, used) = self.inner.execute(&mut tx.inner, r, l)?;
        if cur.point && rows.is_empty() {
            return Err(EngineError::Refused("no such row".into())); // W6: answered as Denied
        }
        if cur.select {
            *lock(&tx.ctx.rows) = Some((cur.names, rows.clone()));
        } else if cur.write && tx.ctx.body_before_cp {
            tx.ctx.early.store(true, Ordering::Release); // NEGATIVE CONTROL (e2e-mutants only)
        }
        Ok((rows, used))
    }

    fn commit(&self, mut tx: Self::Tx) -> Result<(), EngineError> {
        let ctx = Arc::clone(&tx.ctx);
        if !ctx.gate.enter_commit() {
            ctx.gate.disarm();
            self.inner.rollback(tx.inner);
            return Err(EngineError::Unavailable("cancelled before the commit point".into()));
        }
        ctx.gate.disarm(); // past the commit point: no cancel fires any more
        if let Some(idem) = &ctx.idem
            && let Err(e) = self.inner.write_idem(&mut tx.inner, &tenant_text(ctx.data_tenant), idem)
        {
            // A unique violation here means a concurrent request latched the key first: nothing commits.
            self.inner.rollback(tx.inner);
            ctx.gate.finish(false);
            return Err(e);
        }
        let r = self.inner.commit(tx.inner);
        ctx.gate.finish(r.is_ok());
        r
    }

    fn rollback(&self, tx: Self::Tx) {
        tx.ctx.gate.disarm();
        self.inner.rollback(tx.inner);
    }
}

// ------------------------------------------------------------------------------------------------ engines

pub type SqliteEngine = aegis_adapter_host::dispatch::Engine<CtxRenderer<SqliteRenderer>, CtxExec<SqliteExec>>;
pub type PgEngine = aegis_adapter_host::dispatch::Engine<CtxRenderer<PgRenderer>, CtxExec<PgExecutor<PgConn>>>;
pub type SqliteHost = Host<EngineBackends<CtxRenderer<SqliteRenderer>, CtxExec<SqliteExec>>>;
pub type PgHost = Host<EngineBackends<CtxRenderer<PgRenderer>, CtxExec<PgExecutor<PgConn>>>>;
#[cfg(feature = "adapter-crdb")]
pub type CrdbEngine =
    aegis_adapter_host::dispatch::Engine<CtxRenderer<super::engines::CrdbRenderer>, CtxExec<PgExecutor<PgConn>>>;
#[cfg(feature = "adapter-crdb")]
pub type CrdbHost = Host<EngineBackends<CtxRenderer<super::engines::CrdbRenderer>, CtxExec<PgExecutor<PgConn>>>>;
#[cfg(feature = "adapter-mariadb")]
pub type MariadbEngine = aegis_adapter_host::dispatch::Engine<
    CtxRenderer<super::engines::MariadbRenderer>,
    CtxExec<super::mariadb::MariadbExec>,
>;
#[cfg(feature = "adapter-mariadb")]
pub type MariadbHost =
    Host<EngineBackends<CtxRenderer<super::engines::MariadbRenderer>, CtxExec<super::mariadb::MariadbExec>>>;

/// One configured backend's engine and its SDK host (one blocking pool per backend).
pub enum EngineHandle {
    Sqlite {
        engine: Arc<SqliteEngine>,
        host: SqliteHost,
    },
    Pg {
        engine: Arc<PgEngine>,
        host: PgHost,
    },
    /// CockroachDB (feature `adapter-crdb`): the PG wire and pool, crdb dialect, no RLS.
    #[cfg(feature = "adapter-crdb")]
    Crdb {
        engine: Arc<CrdbEngine>,
        host: CrdbHost,
    },
    /// MariaDB (feature `adapter-mariadb`): the MySQL wire, one connection per scope, no RLS.
    #[cfg(feature = "adapter-mariadb")]
    Mariadb {
        engine: Arc<MariadbEngine>,
        host: MariadbHost,
    },
}

impl std::fmt::Debug for EngineHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineHandle::Sqlite { .. } => f.write_str("Sqlite"),
            EngineHandle::Pg { .. } => f.write_str("Pg"),
            #[cfg(feature = "adapter-crdb")]
            EngineHandle::Crdb { .. } => f.write_str("Crdb"),
            #[cfg(feature = "adapter-mariadb")]
            EngineHandle::Mariadb { .. } => f.write_str("Mariadb"),
        }
    }
}

/// The pending result of one app call.
pub type AppTicket = aegis_adapter_host::host::Ticket<aegis_adapter_host::host::ScopeOutcome<notes::Out>>;

impl EngineHandle {
    /// Drive the app handler on this backend's pool (`Host::call`: one SDK scope, rejected at once when full).
    pub fn call(
        &self,
        app: Arc<notes::Notes>,
        session: &aegis_adapter_host::host::SessionHandle,
    ) -> Result<AppTicket, aegis_adapter_host::host::Rejected> {
        match self {
            EngineHandle::Sqlite { host, .. } => host.call(app, session),
            EngineHandle::Pg { host, .. } => host.call(app, session),
            #[cfg(feature = "adapter-crdb")]
            EngineHandle::Crdb { host, .. } => host.call(app, session),
            #[cfg(feature = "adapter-mariadb")]
            EngineHandle::Mariadb { host, .. } => host.call(app, session),
        }
    }

    pub fn pool(&self) -> &aegis_adapter_host::host::BlockingPool {
        match self {
            EngineHandle::Sqlite { host, .. } => host.pool(),
            EngineHandle::Pg { host, .. } => host.pool(),
            #[cfg(feature = "adapter-crdb")]
            EngineHandle::Crdb { host, .. } => host.pool(),
            #[cfg(feature = "adapter-mariadb")]
            EngineHandle::Mariadb { host, .. } => host.pool(),
        }
    }
}

pub fn wrap<R, E>(
    renderer: R,
    executor: E,
    reg: &Arc<Registry>,
    backend: usize,
) -> aegis_adapter_host::dispatch::Engine<CtxRenderer<R>, CtxExec<E>> {
    aegis_adapter_host::dispatch::Engine {
        renderer: CtxRenderer { inner: renderer, reg: Arc::clone(reg), backend },
        executor: CtxExec { inner: executor, reg: Arc::clone(reg), backend },
    }
}
