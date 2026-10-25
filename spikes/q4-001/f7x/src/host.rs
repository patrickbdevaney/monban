//! Mock host: owns the store, mints principals/endowments/contexts, and drives handlers of all three designs.
//! Every driver returns a `Send + 'static` future that OWNS the request scope, so the test harness can
//! `tokio::spawn` it: that is how a host runs `'r`-scoped handlers on a `'static` executor without leaking.

use crate::d2::{JobQueue, QueuedJob, Step, StreamGen, WsReply, WsSessionGen};
use crate::surface::{
    op_code, Committed, Ctx, DataCap, Endowment, Granted, Op, OpKind, Open, Principal, RouteId, SdkError, TenantDb, Tx,
};
use crate::{d1, d2, d3};
use core::future::Future;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct Store {
    rows: Mutex<Vec<(u64, u64, String)>>,
    commits: AtomicUsize,
}

impl Store {
    pub(crate) fn select(&self, tenant: u64, key: u64) -> Result<Vec<(u64, String)>, SdkError> {
        let rows = self.rows.lock().map_err(|_| SdkError::Unavailable)?;
        Ok(rows
            .iter()
            .filter(|(t, k, _)| *t == tenant && (key == 0 || *k == key))
            .map(|(_, k, v)| (*k, v.clone()))
            .collect())
    }
    pub(crate) fn apply(&self, tenant: u64, ops: Vec<Op>) -> Result<(), SdkError> {
        let mut rows = self.rows.lock().map_err(|_| SdkError::Unavailable)?;
        for op in ops {
            rows.push((tenant, op.key, op.val));
        }
        self.commits.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// The host's tenant-bound db view (implements frozen `TenantDb<'r>`).
#[derive(Debug)]
pub struct HostDb<'r> {
    store: &'r Store,
    tenant: u64,
}

impl<'r> TenantDb<'r> for HostDb<'r> {
    type Rows = Vec<(u64, String)>;
    fn begin(&self) -> Result<Tx<'r, Open>, SdkError> {
        Ok(Tx::new())
    }
    fn run<const K: u8>(
        &self,
        tx: &mut Tx<'r, Open>,
        _cap: &Granted<'r, DataCap<K>>,
        op: Op,
    ) -> Result<Self::Rows, SdkError> {
        if op_code(op.kind) != K {
            return Err(SdkError::Denied);
        }
        if op.kind == OpKind::Select {
            self.store.select(self.tenant, op.key)
        } else {
            tx.pending.push(op);
            Ok(Vec::new())
        }
    }
    fn commit(&self, tx: Tx<'r, Open>) -> Result<Tx<'r, Committed>, SdkError> {
        self.store.apply(self.tenant, tx.pending)?;
        Ok(Tx::new())
    }
}

type JobSink = Arc<Mutex<Vec<QueuedJob>>>;

#[derive(Debug, Default)]
pub struct Host {
    store: Arc<Store>,
    jobs: JobSink,
}

/// One authenticated connection (what the transport hands the dispatcher). Owned, `'static`, host-only.
#[derive(Debug)]
pub struct Conn {
    principal: Principal,
    route: RouteId,
    endow: Arc<Endowment>,
    store: Arc<Store>,
    jobs: JobSink,
}

impl core::fmt::Debug for QueuedJob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "QueuedJob(user={}, tenant={})", self.user, self.tenant)
    }
}

/// Max host polls of one D2 generator in these tests (stands in for idle timeouts).
const MAX_STEPS: usize = 64;

impl Host {
    pub fn new() -> Self {
        Host::default()
    }
    pub fn seed(&self, tenant: u64, key: u64, val: &str) -> Result<(), SdkError> {
        self.store.apply(tenant, vec![Op::insert(key, val)])
    }
    pub fn rows(&self, tenant: u64) -> Result<Vec<(u64, String)>, SdkError> {
        self.store.select(tenant, 0)
    }
    pub fn commits(&self) -> usize {
        self.store.commits.load(Ordering::SeqCst)
    }
    pub fn queued_jobs(&self) -> usize {
        self.jobs.lock().map(|q| q.len()).unwrap_or(usize::MAX)
    }
    /// Authenticate a connection; returns it plus the control-plane handle used to revoke.
    pub fn connect(&self, user: u64, tenant: u64, allowed: u8) -> (Conn, Arc<Endowment>) {
        let endow = Arc::new(Endowment::new(allowed));
        let conn = Conn {
            principal: Principal::new(user, tenant),
            route: RouteId(1),
            endow: endow.clone(),
            store: self.store.clone(),
            jobs: self.jobs.clone(),
        };
        (conn, endow)
    }
    /// Run queued detached jobs, each with a freshly minted job-scoped context (re-derived principal, live policy).
    pub fn run_jobs(&self) -> Vec<Result<(), SdkError>> {
        let drained: Vec<QueuedJob> = match self.jobs.lock() {
            Ok(mut q) => q.drain(..).collect(),
            Err(_) => return vec![Err(SdkError::Unavailable)],
        };
        drained
            .into_iter()
            .map(|j| {
                if !j.endow.session_live() {
                    return Err(SdkError::Denied);
                }
                let principal = Principal::new(j.user, j.tenant);
                let jq = JobQueue { sink: self.jobs.clone(), endow: j.endow.clone() };
                let ctx = Ctx::new(&principal, RouteId(0), &j.endow, &jq);
                let db = HostDb { store: &self.store, tenant: principal.tenant() };
                j.job.run_boxed(ctx, &db)
            })
            .collect()
    }
}

/// Frozen F7 request-scoped handler (used by D2's detached baseline).
pub fn scoped<H: crate::surface::ScopedHandler>(conn: Conn, h: &H) -> Result<H::Response, SdkError> {
    let jq = JobQueue { sink: conn.jobs.clone(), endow: conn.endow.clone() };
    let ctx = Ctx::new(&conn.principal, conn.route, &conn.endow, &jq);
    let db = HostDb { store: &conn.store, tenant: conn.principal.tenant() };
    h.handle(ctx, &db)
}

// ------------------------------------------------------------------ D1 drivers (borrowing, host-driven)
pub fn d1_body<H: d1::BodyHandler>(
    conn: Conn,
    h: Arc<H>,
) -> impl Future<Output = (Vec<d1::Chunk>, Result<(), SdkError>)> + Send + 'static {
    async move {
        let jq = JobQueue { sink: conn.jobs.clone(), endow: conn.endow.clone() };
        let ctx = Ctx::new(&conn.principal, conn.route, &conn.endow, &jq);
        let db = HostDb { store: &conn.store, tenant: conn.principal.tenant() };
        let mut out = Vec::new();
        let r = h.stream(ctx, &db, d1::Sink::new(&mut out, &conn.endow)).await;
        (out, r)
    }
}

pub fn d1_sse<H: d1::SseHandler>(
    conn: Conn,
    h: Arc<H>,
) -> impl Future<Output = (Vec<d1::Event>, Result<(), SdkError>)> + Send + 'static {
    async move {
        let jq = JobQueue { sink: conn.jobs.clone(), endow: conn.endow.clone() };
        let ctx = Ctx::new(&conn.principal, conn.route, &conn.endow, &jq);
        let db = HostDb { store: &conn.store, tenant: conn.principal.tenant() };
        let mut out = Vec::new();
        let r = h.events(ctx, &db, d1::Sink::new(&mut out, &conn.endow)).await;
        (out, r)
    }
}

/// `before(i)` is called by the host before delivering inbound message i (used to revoke mid-session).
pub fn d1_ws<H: d1::WsHandler, F: Fn(usize) + Send + Sync + 'static>(
    conn: Conn,
    h: Arc<H>,
    inbox: Vec<String>,
    before: F,
) -> impl Future<Output = (Vec<String>, Result<(), SdkError>)> + Send + 'static {
    async move {
        let jq = JobQueue { sink: conn.jobs.clone(), endow: conn.endow.clone() };
        let ctx = Ctx::new(&conn.principal, conn.route, &conn.endow, &jq);
        let db = HostDb { store: &conn.store, tenant: conn.principal.tenant() };
        let mut out = Vec::new();
        let mut inbox: VecDeque<String> = inbox.into();
        let ws = d1::WsSession::new(&mut inbox, d1::Sink::new(&mut out, &conn.endow), &before);
        let r = h.session(ctx, &db, ws).await;
        (out, r)
    }
}

// ------------------------------------------------------------------ D2 drivers (host-owned stream capability)
/// One D2 step: re-check the session, re-mint principal + Ctx<'m> + db view for this step only.
fn d2_step<G: StreamGen>(conn: &Conn, gen: &mut G) -> Result<Step<G::Item>, SdkError> {
    if !conn.endow.session_live() {
        return Err(SdkError::Unavailable);
    }
    let principal = Principal::new(conn.principal.user(), conn.principal.tenant()); // re-derived per step
    let jq = JobQueue { sink: conn.jobs.clone(), endow: conn.endow.clone() };
    let ctx = Ctx::new(&principal, conn.route, &conn.endow, &jq);
    let db = HostDb { store: &conn.store, tenant: principal.tenant() };
    gen.next(ctx, &db)
}

async fn d2_drive<G: StreamGen>(conn: &Conn, mut gen: G) -> (Vec<G::Item>, Result<(), SdkError>) {
    let mut out = Vec::new();
    for _ in 0..MAX_STEPS {
        match d2_step(conn, &mut gen) {
            Ok(Step::Item(x)) => out.push(x),
            Ok(Step::Idle) => {}
            Ok(Step::Done) => return (out, Ok(())),
            Err(e) => return (out, Err(e)),
        }
        crate::YieldNow::default().await;
    }
    (out, Err(SdkError::Unavailable))
}

pub fn d2_body<H: d2::BodyHandler>(
    conn: Conn,
    h: Arc<H>,
) -> impl Future<Output = (Vec<d2::Chunk>, Result<(), SdkError>)> + Send + 'static {
    async move {
        let gen = {
            let jq = JobQueue { sink: conn.jobs.clone(), endow: conn.endow.clone() };
            let ctx = Ctx::new(&conn.principal, conn.route, &conn.endow, &jq);
            let db = HostDb { store: &conn.store, tenant: conn.principal.tenant() };
            h.open(ctx, &db)
        };
        match gen {
            Ok(g) => d2_drive(&conn, g).await,
            Err(e) => (Vec::new(), Err(e)),
        }
    }
}

pub fn d2_sse<H: d2::SseHandler>(
    conn: Conn,
    h: Arc<H>,
    last_event_id: Option<u64>,
) -> impl Future<Output = (Vec<d2::Event>, Result<(), SdkError>)> + Send + 'static {
    async move {
        let gen = {
            let jq = JobQueue { sink: conn.jobs.clone(), endow: conn.endow.clone() };
            let ctx = Ctx::new(&conn.principal, conn.route, &conn.endow, &jq);
            let db = HostDb { store: &conn.store, tenant: conn.principal.tenant() };
            h.open(ctx, &db, last_event_id)
        };
        match gen {
            Ok(g) => d2_drive(&conn, g).await,
            Err(e) => (Vec::new(), Err(e)),
        }
    }
}

/// `before(i)` is called by the host before delivering inbound message i (used to revoke mid-session).
pub fn d2_ws<H: d2::WsHandler, F: Fn(usize) + Send + 'static>(
    conn: Conn,
    h: Arc<H>,
    inbox: Vec<String>,
    before: F,
) -> impl Future<Output = (Vec<String>, Result<(), SdkError>)> + Send + 'static {
    async move {
        let session = {
            let jq = JobQueue { sink: conn.jobs.clone(), endow: conn.endow.clone() };
            let ctx = Ctx::new(&conn.principal, conn.route, &conn.endow, &jq);
            let db = HostDb { store: &conn.store, tenant: conn.principal.tenant() };
            h.open(ctx, &db)
        };
        let mut s = match session {
            Ok(s) => s,
            Err(e) => return (Vec::new(), Err(e)),
        };
        let mut out = Vec::new();
        for (i, msg) in inbox.iter().enumerate() {
            before(i);
            if !conn.endow.session_live() {
                return (out, Err(SdkError::Unavailable));
            }
            let principal = Principal::new(conn.principal.user(), conn.principal.tenant());
            let jq = JobQueue { sink: conn.jobs.clone(), endow: conn.endow.clone() };
            let ctx = Ctx::new(&principal, conn.route, &conn.endow, &jq);
            let db = HostDb { store: &conn.store, tenant: principal.tenant() };
            match s.on_message(ctx, &db, msg) {
                Ok(WsReply::Send(v)) => out.extend(v),
                Ok(WsReply::Close) => return (out, Ok(())),
                Err(e) => return (out, Err(e)),
            }
            crate::YieldNow::default().await;
        }
        (out, Ok(()))
    }
}

// ------------------------------------------------------------------ D3 drivers (leaky 'static, handler spawns)
fn d3_parts(conn: &Conn) -> (d3::OwnedCtx, d3::OwnedDb) {
    let p = Arc::new(Principal::new(conn.principal.user(), conn.principal.tenant()));
    (d3::OwnedCtx::new(p, conn.endow.clone()), d3::OwnedDb::new(conn.store.clone(), conn.principal.tenant()))
}

async fn collect<T>(mut rx: tokio::sync::mpsc::Receiver<T>) -> Vec<T> {
    let mut v = Vec::new();
    while let Some(x) = rx.recv().await {
        v.push(x);
    }
    v
}

pub fn d3_body<H: d3::BodyHandler>(
    conn: Conn,
    h: Arc<H>,
) -> impl Future<Output = (Vec<d3::Chunk>, Result<(), SdkError>)> + Send + 'static {
    async move {
        let (ctx, db) = d3_parts(&conn);
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let r = h.stream(ctx, db, d3::BodyTx::new(tx, conn.endow.clone()));
        (collect(rx).await, r)
    }
}

pub fn d3_sse<H: d3::SseHandler>(
    conn: Conn,
    h: Arc<H>,
) -> impl Future<Output = (Vec<d3::Event>, Result<(), SdkError>)> + Send + 'static {
    async move {
        let (ctx, db) = d3_parts(&conn);
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let r = h.events(ctx, db, d3::BodyTx::new(tx, conn.endow.clone()));
        (collect(rx).await, r)
    }
}

pub fn d3_ws<H: d3::WsHandler>(
    conn: Conn,
    h: Arc<H>,
    inbox: Vec<String>,
) -> impl Future<Output = (Vec<String>, Result<(), SdkError>)> + Send + 'static {
    async move {
        let (ctx, db) = d3_parts(&conn);
        let (itx, irx) = tokio::sync::mpsc::channel(8);
        for m in inbox {
            let _ = itx.try_send(m);
        }
        drop(itx);
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let r = h.session(ctx, db, irx, d3::BodyTx::new(tx, conn.endow.clone()));
        (collect(rx).await, r)
    }
}

pub fn d3_job<H: d3::JobHandler>(conn: Conn, h: &H) -> Result<(), SdkError> {
    let (ctx, db) = d3_parts(&conn);
    h.handle(ctx, db)
}
