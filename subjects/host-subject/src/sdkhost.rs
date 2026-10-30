//! `host-subject sdk-host`: oracles/sdk-host subject protocol (README "Subject protocol").
//!
//! The host is `aegis_adapter_host::host::Host`: every open, step, message, call, hold and job goes through its
//! bounded pool and its `aegis_sdk::host` driving loop; streams are its `GenStream`/`WsStream` (budgets and close
//! reasons are decided there); jobs are its queue (kept on error, run with the session as it is now); sessions are
//! its `SessionHandle`. This file is the scripted test application, the instrumented `Backend`, and the protocol
//! plumbing (printing what the host decided). Principals are minted through aegis-token's Tier-0 path.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};

use aegis_adapter_host::host::pool::PoolMutations;
use aegis_adapter_host::host::{
    Backends, BlockingPool, CloseReason, GenStream, Host, HostMutations, ScopeOutcome, SessionHandle, StepRefused,
    StreamBudget, Ticket, WsStream,
};
use aegis_data_ir::{CapSet, Caps, DataCap, OpMask, Pred, tenant_text};
use aegis_sdk::query::{Op, OpKind};
use aegis_sdk::{
    BodyHandler, Chunk, Committed, Ctx, DataCap as Cap, Event, Granted, Job, Open, ScopedHandler, SdkError, SseHandler,
    Step, StreamGen, TenantDb, Tx, WsHandler, WsMsg, WsReply, WsSession,
};
use aegis_types::RouteId;

use crate::json::{self, Json};

/// Mutations this subject implements (every required one; `detach-before-commit` is inexpressible: `detach` needs
/// a `&Tx<Committed>`).
pub const MUTATIONS: &[&str] = &[
    "mint-once-per-session",
    "revoked-stream-keeps-serving",
    "step-retry-double-mint",
    "job-ignores-revocation",
    "drop-jobs-on-error",
    "no-idle-budget",
    "no-step-budget",
    "unbounded-pool",
    "inline-handler",
    "queueing-pool",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct Muts {
    host: HostMutations,
    pool: PoolMutations,
}

pub fn mutations(name: &str) -> Option<Muts> {
    let mut m = Muts::default();
    match name {
        "mint-once-per-session" => m.host.mint_once_per_session = true,
        "revoked-stream-keeps-serving" => m.host.revoked_stream_keeps_serving = true,
        "step-retry-double-mint" => m.host.step_retry_double_mint = true,
        "job-ignores-revocation" => m.host.job_ignores_revocation = true,
        "drop-jobs-on-error" => m.host.drop_jobs_on_error = true,
        "no-idle-budget" => m.host.no_idle_budget = true,
        "no-step-budget" => m.host.no_step_budget = true,
        "unbounded-pool" => m.pool.unbounded = true,
        "inline-handler" => m.pool.inline = true,
        "queueing-pool" => m.pool.queueing = true,
        _ => return None,
    }
    Some(m)
}

// ------------------------------------------------------------------------------------------------ output

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// One JSON object per line on stdout, flushed per line (events come from pool threads and the main thread, but
/// never concurrently within one op: the main thread prints only after the pool task finished).
#[derive(Clone, Debug)]
struct Out(Arc<Mutex<std::io::Stdout>>);

impl Out {
    fn line(&self, s: &str) {
        let g = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let mut l = g.lock();
        let _ = writeln!(l, "{s}");
        let _ = l.flush();
    }
    fn ev(&self, fields: &[(&str, String)]) {
        let body: Vec<String> = fields.iter().map(|(k, v)| format!("{}:{v}", esc(k))).collect();
        self.line(&format!("{{{}}}", body.join(",")));
    }
    fn result_ok(&self, v: &str) {
        self.ev(&[("ev", esc("result")), ("ok", esc(v))]);
    }
    fn result_err(&self, e: &str) {
        self.ev(&[("ev", esc("result")), ("err", esc(e))]);
    }
    fn closed(&self, stream: &str, r: CloseReason) {
        self.ev(&[("ev", esc("closed")), ("stream", esc(stream)), ("reason", esc(r.as_str()))]);
    }
    fn rejected(&self) {
        self.ev(&[("ev", esc("rejected")), ("reason", esc("pool_full"))]);
    }
    fn error(&self, msg: &str) {
        self.ev(&[("ev", esc("error")), ("msg", esc(msg))]);
    }
}

fn err_name(e: SdkError) -> &'static str {
    match e {
        SdkError::Denied => "denied",
        SdkError::Conflict => "conflict",
        SdkError::Unavailable => "unavailable",
    }
}

fn err_of(s: &str) -> SdkError {
    match s {
        "conflict" => SdkError::Conflict,
        "unavailable" => SdkError::Unavailable,
        _ => SdkError::Denied,
    }
}

// ------------------------------------------------------------------------------------------------ backend

/// Instrumented `Backend`: prints every call; `commit` fails once after `fail_commit` on its session.
struct SubjBackend {
    out: Out,
    fail: Arc<AtomicBool>,
}

impl aegis_sdk::host::Backend for SubjBackend {
    type Rows = ();
    fn begin(&self) -> Result<(), SdkError> {
        self.out.ev(&[("ev", esc("backend")), ("call", esc("begin"))]);
        Ok(())
    }
    fn run(&self, op: Op) -> Result<(), SdkError> {
        self.out.ev(&[
            ("ev", esc("backend")),
            ("call", esc("run")),
            ("kind", esc(op.kind.name())),
            ("tenant", esc(&tenant_text(op.tenant))),
        ]);
        Ok(())
    }
    fn commit(&self) -> Result<(), SdkError> {
        let fail = self.fail.swap(false, Ordering::SeqCst);
        self.out.ev(&[("ev", esc("backend")), ("call", esc("commit")), ("ok", (!fail).to_string())]);
        if fail { Err(SdkError::Unavailable) } else { Ok(()) }
    }
    fn rollback(&self) {
        self.out.ev(&[("ev", esc("backend")), ("call", esc("rollback"))]);
    }
}

struct SubjBackends {
    out: Out,
    fail: Arc<Mutex<HashMap<u64, Arc<AtomicBool>>>>,
}

impl Backends for SubjBackends {
    type Backend = SubjBackend;
    fn open(&self, session: &SessionHandle) -> Result<SubjBackend, SdkError> {
        let fail = self
            .fail
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&session.id())
            .cloned()
            .ok_or(SdkError::Unavailable)?;
        Ok(SubjBackend { out: self.out.clone(), fail })
    }
}

// ------------------------------------------------------------------------------------------------ the app

type JobDefs = Arc<BTreeMap<String, Vec<String>>>;

/// One callback's script plus what it reports back to the protocol layer.
#[derive(Default)]
struct Scope {
    actions: Vec<String>,
    jobs: JobDefs,
    /// Jobs whose `detach` was accepted, in order, with their "ran" flag.
    accepted: Vec<(String, Arc<AtomicBool>)>,
    /// The terminal the callback returned `Ok` with (or "ok" at end of script).
    terminal: Option<String>,
}

type ScopeCell = Arc<Mutex<Scope>>;

fn take_spec(c: &ScopeCell) -> (Vec<String>, JobDefs) {
    let g = c.lock().unwrap_or_else(PoisonError::into_inner);
    (g.actions.clone(), Arc::clone(&g.jobs))
}

struct AppJob {
    name: String,
    actions: Vec<String>,
    out: Out,
    ran: Arc<AtomicBool>,
}

impl Job for AppJob {
    fn run<'j, D: TenantDb<'j>>(self, ctx: Ctx<'j>, db: &D) -> Result<(), SdkError> {
        self.ran.store(true, Ordering::SeqCst);
        let mut sink = Vec::new();
        let _ = &self.name;
        interp("job", ctx, db, &self.actions, &Arc::new(BTreeMap::new()), &self.out, &mut sink).map(|_| ())
    }
}

#[derive(Default)]
struct Proofs<'r> {
    p1: Option<Granted<'r, Cap<1>>>,
    p2: Option<Granted<'r, Cap<2>>>,
    p4: Option<Granted<'r, Cap<4>>>,
    p8: Option<Granted<'r, Cap<8>>>,
    p16: Option<Granted<'r, Cap<16>>>,
}

fn op_of(ctx: &Ctx<'_>, kind: OpKind) -> Op {
    Op {
        tenant: ctx.principal().tenant(),
        collection: "c".into(),
        kind,
        filter: Pred::Tt,
        writes: Vec::new(),
        returning: Vec::new(),
    }
}

fn run_k<'r, D: TenantDb<'r>>(
    ctx: &Ctx<'r>,
    db: &D,
    tx: &mut Tx<'r, Open>,
    p: &Proofs<'r>,
    kind: OpKind,
) -> Option<Result<D::Rows, SdkError>> {
    let op = op_of(ctx, kind);
    Some(match kind {
        OpKind::Select => db.run(tx, p.p1.as_ref()?, op),
        OpKind::Insert => db.run(tx, p.p2.as_ref()?, op),
        OpKind::Update => db.run(tx, p.p4.as_ref()?, op),
        OpKind::Delete => db.run(tx, p.p8.as_ref()?, op),
        OpKind::Upsert => db.run(tx, p.p16.as_ref()?, op),
    })
}

fn grant_k<'r>(ctx: &Ctx<'r>, p: &mut Proofs<'r>, kind: OpKind) -> bool {
    match kind {
        OpKind::Select => ctx.grant::<1>().map(|g| p.p1 = Some(g)).is_ok(),
        OpKind::Insert => ctx.grant::<2>().map(|g| p.p2 = Some(g)).is_ok(),
        OpKind::Update => ctx.grant::<4>().map(|g| p.p4 = Some(g)).is_ok(),
        OpKind::Delete => ctx.grant::<8>().map(|g| p.p8 = Some(g)).is_ok(),
        OpKind::Upsert => ctx.grant::<16>().map(|g| p.p16 = Some(g)).is_ok(),
    }
}

/// README "App semantics": one callback with a freshly minted `Ctx`.
fn interp<'r, D: TenantDb<'r>>(
    call: &str,
    ctx: Ctx<'r>,
    db: &D,
    actions: &[String],
    jobs: &JobDefs,
    out: &Out,
    accepted: &mut Vec<(String, Arc<AtomicBool>)>,
) -> Result<String, SdkError> {
    out.ev(&[("ev", esc("minted")), ("call", esc(call)), ("tenant", esc(&tenant_text(ctx.principal().tenant())))]);
    let mut proofs = Proofs::default();
    let mut open: Option<Tx<'r, Open>> = None;
    let mut committed: Option<Tx<'r, Committed>> = None;
    for a in actions {
        if let Some(k) = a.strip_prefix("grant:") {
            let kind = OpKind::from_name(k).ok_or(SdkError::Denied)?;
            let ok = grant_k(&ctx, &mut proofs, kind);
            out.ev(&[("ev", esc("decision")), ("cap", esc(k)), ("result", esc(if ok { "granted" } else { "denied" }))]);
        } else if a == "begin" {
            open = Some(db.begin()?);
        } else if let Some(k) = a.strip_prefix("run:") {
            let kind = OpKind::from_name(k).ok_or(SdkError::Denied)?;
            let tx = open.as_mut().ok_or(SdkError::Denied)?;
            run_k(&ctx, db, tx, &proofs, kind).ok_or(SdkError::Denied)??;
        } else if a == "commit" {
            let tx = open.take().ok_or(SdkError::Denied)?;
            committed = Some(db.commit(tx)?);
        } else if let Some(j) = a.strip_prefix("detach:") {
            let ok = match &committed {
                Some(c) => {
                    let ran = Arc::new(AtomicBool::new(false));
                    let job = AppJob {
                        name: j.to_string(),
                        actions: jobs.get(j).cloned().unwrap_or_else(|| vec!["ok".into()]),
                        out: out.clone(),
                        ran: Arc::clone(&ran),
                    };
                    let r = db.detach(c, job).is_ok();
                    if r {
                        accepted.push((j.to_string(), ran));
                    }
                    r
                }
                None => false,
            };
            out.ev(&[("ev", esc("detach")), ("job", esc(j)), ("result", esc(if ok { "accepted" } else { "refused" }))]);
        } else if let Some(e) = a.strip_prefix("err:") {
            return Err(err_of(e));
        } else {
            return Ok(a.clone());
        }
    }
    Ok("ok".into())
}

/// Run `interp` for `cell`'s script and store what it reported.
fn interp_cell<'r, D: TenantDb<'r>>(
    call: &str,
    ctx: Ctx<'r>,
    db: &D,
    cell: &ScopeCell,
    out: &Out,
) -> Result<String, SdkError> {
    let (actions, jobs) = take_spec(cell);
    let mut acc = Vec::new();
    let r = interp(call, ctx, db, &actions, &jobs, out, &mut acc);
    let mut g = cell.lock().unwrap_or_else(PoisonError::into_inner);
    g.accepted = acc;
    if let Ok(t) = &r {
        g.terminal = Some(t.clone());
    }
    r
}

struct CallApp {
    cell: ScopeCell,
    out: Out,
}

impl ScopedHandler for CallApp {
    type Response = String;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<String, SdkError> {
        interp_cell("call", ctx, db, &self.cell, &self.out)
    }
}

struct HoldApp {
    out: Out,
    running: Mutex<mpsc::Sender<()>>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl ScopedHandler for HoldApp {
    type Response = String;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, _db: &D) -> Result<String, SdkError> {
        self.out.ev(&[
            ("ev", esc("minted")),
            ("call", esc("hold")),
            ("tenant", esc(&tenant_text(ctx.principal().tenant()))),
        ]);
        let _ = self.running.lock().unwrap_or_else(PoisonError::into_inner).send(());
        let _ = self.release.lock().unwrap_or_else(PoisonError::into_inner).recv();
        Ok("ok".into())
    }
}

/// Stream generators read their per-step script from the stream's cell (filled before each `step`).
struct AppGen<I> {
    cell: ScopeCell,
    out: Out,
    n: u64,
    _i: std::marker::PhantomData<fn() -> I>,
}

trait MakeItem: Send + 'static {
    type Item: Send + 'static;
    fn make(n: u64) -> Self::Item;
}

struct SseItem;
impl MakeItem for SseItem {
    type Item = Event;
    fn make(n: u64) -> Event {
        Event { id: n, data: Box::from(&b"e"[..]) }
    }
}

struct BodyItem;
impl MakeItem for BodyItem {
    type Item = Chunk;
    fn make(_n: u64) -> Chunk {
        Chunk(Box::from(&b"c"[..]))
    }
}

impl<I: MakeItem> StreamGen for AppGen<I> {
    type Item = I::Item;
    fn next<'m, D: TenantDb<'m>>(&mut self, ctx: Ctx<'m>, db: &D) -> Result<Step<I::Item>, SdkError> {
        let t = interp_cell("step", ctx, db, &self.cell, &self.out)?;
        self.n = self.n.saturating_add(1);
        Ok(match t.as_str() {
            "idle" => Step::Idle,
            "done" => Step::Done,
            _ => Step::Item(I::make(self.n)),
        })
    }
}

struct OpenApp {
    cell: ScopeCell,
    out: Out,
}

impl OpenApp {
    fn make_gen<'r, D: TenantDb<'r>, I: MakeItem>(&self, ctx: Ctx<'r>, db: &D) -> Result<AppGen<I>, SdkError> {
        interp_cell("open", ctx, db, &self.cell, &self.out)?;
        Ok(AppGen { cell: Arc::clone(&self.cell), out: self.out.clone(), n: 0, _i: std::marker::PhantomData })
    }
}

impl SseHandler for OpenApp {
    type Gen = AppGen<SseItem>;
    fn open<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D, _last: Option<u64>) -> Result<Self::Gen, SdkError> {
        self.make_gen(ctx, db)
    }
}

impl BodyHandler for OpenApp {
    type Gen = AppGen<BodyItem>;
    fn open<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<Self::Gen, SdkError> {
        self.make_gen(ctx, db)
    }
}

struct AppWs {
    cell: ScopeCell,
    out: Out,
}

impl WsSession for AppWs {
    fn on_message<'m, D: TenantDb<'m>>(&mut self, ctx: Ctx<'m>, db: &D, _msg: &WsMsg) -> Result<WsReply, SdkError> {
        let t = interp_cell("msg", ctx, db, &self.cell, &self.out)?;
        Ok(if t == "close" { WsReply::Close } else { WsReply::Send(vec![WsMsg::Text(Box::from("r"))]) })
    }
}

impl WsHandler for OpenApp {
    type Session = AppWs;
    fn open<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<AppWs, SdkError> {
        interp_cell("open", ctx, db, &self.cell, &self.out)?;
        Ok(AppWs { cell: Arc::clone(&self.cell), out: self.out.clone() })
    }
}

// ------------------------------------------------------------------------------------------------ protocol state

enum StreamSt {
    Sse(GenStream<AppGen<SseItem>>),
    Body(GenStream<AppGen<BodyItem>>),
    Ws(WsStream<AppWs>),
}

struct Entry {
    st: StreamSt,
    cell: ScopeCell,
}

struct Sess {
    handle: SessionHandle,
}

struct Subject {
    out: Out,
    muts: Muts,
    host: Option<Host<SubjBackends>>,
    backends_fail: Arc<Mutex<HashMap<u64, Arc<AtomicBool>>>>,
    sessions: HashMap<String, Sess>,
    streams: HashMap<String, Entry>,
    /// Names (and ran flags) of queued jobs, parallel to the host queue.
    names: VecDeque<(String, Arc<AtomicBool>)>,
    holds: HashMap<String, (mpsc::Sender<()>, Ticket<ScopeOutcome<String>>)>,
}

fn s_of<'a>(req: &'a Json, k: &str) -> Result<&'a str, String> {
    req.get(k).and_then(Json::str).ok_or_else(|| format!("missing {k}"))
}

fn u32_of(req: &Json, k: &str) -> Result<u32, String> {
    match req.get(k) {
        Some(Json::Num(t)) => t.parse().map_err(|_| format!("bad {k}")),
        _ => Err(format!("missing {k}")),
    }
}

fn strings(j: Option<&Json>) -> Result<Vec<String>, String> {
    match j {
        Some(Json::Arr(v)) => {
            v.iter().map(|x| x.str().map(String::from).ok_or_else(|| "non-string".to_string())).collect()
        }
        None => Ok(Vec::new()),
        _ => Err("expected a list".into()),
    }
}

fn jobs_of(req: &Json) -> Result<JobDefs, String> {
    let mut m = BTreeMap::new();
    if let Some(Json::Obj(o)) = req.get("jobs") {
        for (k, v) in o {
            m.insert(k.clone(), strings(Some(v))?);
        }
    }
    Ok(Arc::new(m))
}

fn ops_mask(names: &[String]) -> Result<u8, String> {
    names.iter().try_fold(0u8, |m, n| OpKind::from_name(n).map(|k| m | k.bit()).ok_or_else(|| format!("kind {n}")))
}

fn cell_of(req: &Json) -> Result<ScopeCell, String> {
    Ok(Arc::new(Mutex::new(Scope {
        actions: strings(req.get("script"))?,
        jobs: jobs_of(req)?,
        accepted: Vec::new(),
        terminal: None,
    })))
}

impl Subject {
    fn host(&self) -> Result<&Host<SubjBackends>, String> {
        self.host.as_ref().ok_or_else(|| "no config op yet".to_string())
    }

    fn session(&self, req: &Json) -> Result<SessionHandle, String> {
        let name = s_of(req, "session")?;
        self.sessions.get(name).map(|s| s.handle.clone()).ok_or_else(|| format!("unknown session {name}"))
    }

    /// After a scope: queue the names of the jobs the host reports it queued (the app's accepted detaches, in
    /// order). The keep/drop decision is the host's (`jobs_queued`).
    fn queue_names(&mut self, cell: &ScopeCell, jobs_queued: usize) -> Result<(), String> {
        let acc = std::mem::take(&mut cell.lock().unwrap_or_else(PoisonError::into_inner).accepted);
        if jobs_queued == acc.len() {
            self.names.extend(acc);
            Ok(())
        } else if jobs_queued == 0 {
            Ok(())
        } else {
            Err(format!("host queued {jobs_queued} jobs, app detached {}", acc.len()))
        }
    }

    fn terminal(cell: &ScopeCell) -> String {
        cell.lock().unwrap_or_else(PoisonError::into_inner).terminal.clone().unwrap_or_else(|| "ok".into())
    }

    fn op(&mut self, req: &Json) -> Result<(), String> {
        match s_of(req, "op")? {
            "config" => {
                let cap = u32_of(req, "pool")? as usize;
                let pool = BlockingPool::with_mutations(cap, self.muts.pool).map_err(|e| e.to_string())?;
                let backends = SubjBackends { out: self.out.clone(), fail: Arc::clone(&self.backends_fail) };
                self.host = Some(Host::with_mutations(pool, backends, self.muts.host));
                Ok(())
            }
            "session" => {
                let name = s_of(req, "session")?.to_string();
                let tenant = aegis_data_ir::parse_tenant_text(s_of(req, "tenant")?).ok_or("bad tenant")?;
                let permits = ops_mask(&strings(req.get("permits"))?)?;
                let principal = crate::token::principal(tenant)?;
                let handle = SessionHandle::new(principal, route(), Some(endowment()?), permits);
                self.register(&handle);
                self.sessions.insert(name, Sess { handle });
                Ok(())
            }
            "revoke" => {
                self.session(req)?.revoke();
                Ok(())
            }
            "bump_epoch" => {
                let ops = ops_mask(&strings(req.get("permits"))?)?;
                self.session(req)?.set_token_ops(ops);
                Ok(())
            }
            "fail_commit" => {
                let s = self.session(req)?;
                self.flag(&s).store(true, Ordering::SeqCst);
                Ok(())
            }
            "open" => self.open(req),
            "step" => self.step(req),
            "call" => self.call(req),
            "run_jobs" => self.run_jobs(),
            "hold" => self.hold(req),
            "release" => self.release(req),
            other => Err(format!("unknown op {other}")),
        }
    }

    /// The fail-commit flag map is shared with the host's backend factory (`SubjBackends::fail`).
    fn register(&mut self, s: &SessionHandle) {
        self.backends_fail
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(s.id(), Arc::new(AtomicBool::new(false)));
    }

    fn flag(&self, s: &SessionHandle) -> Arc<AtomicBool> {
        self.backends_fail
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&s.id())
            .cloned()
            .unwrap_or_else(|| Arc::new(AtomicBool::new(false)))
    }

    fn open(&mut self, req: &Json) -> Result<(), String> {
        let name = s_of(req, "stream")?.to_string();
        let kind = s_of(req, "kind")?;
        let session = self.session(req)?;
        let budget = StreamBudget::new(u32_of(req, "idle_budget")?, u32_of(req, "step_budget")?).ok_or("bad budget")?;
        let cell = cell_of(req)?;
        let app = Arc::new(OpenApp { cell: Arc::clone(&cell), out: self.out.clone() });
        let host = self.host()?.clone();
        let (result, queued): (Result<StreamSt, SdkError>, usize) = match kind {
            "sse" => match host.open_sse(app, &session, None, budget) {
                Err(_) => return self.reject(),
                Ok(t) => {
                    let o = t.wait().map_err(|_| "lost")?;
                    (o.result.map(StreamSt::Sse), o.jobs_queued)
                }
            },
            "body" => match host.open_body(app, &session, budget) {
                Err(_) => return self.reject(),
                Ok(t) => {
                    let o = t.wait().map_err(|_| "lost")?;
                    (o.result.map(StreamSt::Body), o.jobs_queued)
                }
            },
            "ws" => match host.open_ws(app, &session, budget) {
                Err(_) => return self.reject(),
                Ok(t) => {
                    let o = t.wait().map_err(|_| "lost")?;
                    (o.result.map(StreamSt::Ws), o.jobs_queued)
                }
            },
            other => return Err(format!("stream kind {other}")),
        };
        match result {
            Ok(st) => {
                self.out.result_ok(&Self::terminal(&cell));
                self.queue_names(&cell, queued)?;
                self.streams.insert(name, Entry { st, cell });
            }
            Err(e) => {
                self.out.result_err(err_name(e));
                self.queue_names(&cell, queued)?;
            }
        }
        Ok(())
    }

    fn reject(&self) -> Result<(), String> {
        self.out.rejected();
        Ok(())
    }

    fn step(&mut self, req: &Json) -> Result<(), String> {
        let name = s_of(req, "stream")?.to_string();
        let Some(entry) = self.streams.remove(&name) else {
            self.out.result_err("closed");
            return Ok(());
        };
        let Entry { st, cell } = entry;
        let host = self.host()?.clone();
        let is_tick = req.get("script").is_none() && req.get("msg").is_none();
        if let StreamSt::Ws(ws) = st {
            if is_tick {
                match host.tick(ws) {
                    Ok(ws) => {
                        self.streams.insert(name, Entry { st: StreamSt::Ws(ws), cell });
                    }
                    Err(r) => self.out.closed(&name, r),
                }
                return Ok(());
            }
            self.refill(&cell, req)?;
            let msg = WsMsg::Text(Box::from(s_of(req, "msg").unwrap_or("")));
            match host.message(ws, msg) {
                Err(StepRefused::Rejected(ws)) => {
                    self.streams.insert(name, Entry { st: StreamSt::Ws(ws), cell });
                    return self.reject();
                }
                Ok(t) => {
                    let o = t.wait().map_err(|_| "lost")?;
                    match &o.result {
                        Ok(WsReply::Close) => self.out.result_ok("close"),
                        Ok(WsReply::Send(_)) => self.out.result_ok("send"),
                        Err(e) => self.out.result_err(err_name(*e)),
                    }
                    self.after_step(&name, &cell, o.closed, o.jobs_queued)?;
                    if let Some(ws) = o.stream {
                        self.streams.insert(name, Entry { st: StreamSt::Ws(ws), cell });
                    }
                }
            }
            return Ok(());
        }
        self.refill(&cell, req)?;
        match st {
            StreamSt::Sse(g) => match host.step(g) {
                Err(StepRefused::Rejected(g)) => {
                    self.streams.insert(name, Entry { st: StreamSt::Sse(g), cell });
                    self.reject()
                }
                Ok(t) => {
                    let o = t.wait().map_err(|_| "lost")?;
                    self.print_step(&o.result);
                    self.after_step(&name, &cell, o.closed, o.jobs_queued)?;
                    if let Some(g) = o.stream {
                        self.streams.insert(name, Entry { st: StreamSt::Sse(g), cell });
                    }
                    Ok(())
                }
            },
            StreamSt::Body(g) => match host.step(g) {
                Err(StepRefused::Rejected(g)) => {
                    self.streams.insert(name, Entry { st: StreamSt::Body(g), cell });
                    self.reject()
                }
                Ok(t) => {
                    let o = t.wait().map_err(|_| "lost")?;
                    self.print_step(&o.result);
                    self.after_step(&name, &cell, o.closed, o.jobs_queued)?;
                    if let Some(g) = o.stream {
                        self.streams.insert(name, Entry { st: StreamSt::Body(g), cell });
                    }
                    Ok(())
                }
            },
            StreamSt::Ws(_) => Err("unreachable ws".into()),
        }
    }

    fn print_step<T>(&self, r: &Result<Step<T>, SdkError>) {
        match r {
            Ok(Step::Item(_)) => self.out.result_ok("item"),
            Ok(Step::Idle) => self.out.result_ok("idle"),
            Ok(Step::Done) => self.out.result_ok("done"),
            Err(e) => self.out.result_err(err_name(*e)),
        }
    }

    fn after_step(
        &mut self,
        name: &str,
        cell: &ScopeCell,
        closed: Option<CloseReason>,
        queued: usize,
    ) -> Result<(), String> {
        if let Some(r) = closed {
            self.out.closed(name, r);
        }
        self.queue_names(cell, queued)
    }

    fn refill(&self, cell: &ScopeCell, req: &Json) -> Result<(), String> {
        let mut g = cell.lock().unwrap_or_else(PoisonError::into_inner);
        g.actions = strings(req.get("script"))?;
        g.jobs = jobs_of(req)?;
        g.accepted.clear();
        g.terminal = None;
        Ok(())
    }

    fn call(&mut self, req: &Json) -> Result<(), String> {
        let session = self.session(req)?;
        let cell = cell_of(req)?;
        let app = Arc::new(CallApp { cell: Arc::clone(&cell), out: self.out.clone() });
        let Ok(t) = self.host()?.call(app, &session) else { return self.reject() };
        let o = t.wait().map_err(|_| "lost")?;
        match &o.result {
            Ok(v) => self.out.result_ok(v),
            Err(e) => self.out.result_err(err_name(*e)),
        }
        self.queue_names(&cell, o.jobs_queued)
    }

    fn run_jobs(&mut self) -> Result<(), String> {
        let host = self.host()?.clone();
        while let Some(job) = host.take_job() {
            let (name, ran) = self.names.pop_front().ok_or("job queue and name queue out of step")?;
            let t = match host.run_job(job) {
                Ok(t) => t,
                Err((job, _)) => {
                    host.requeue_front(job);
                    self.names.push_front((name, ran));
                    return Err("pool full during run_jobs".into());
                }
            };
            let o = t.wait().map_err(|_| "lost")?;
            match o.result {
                Ok(()) => self.out.result_ok("ok"),
                Err(e) => self.out.result_err(err_name(e)),
            }
            let verdict = if ran.load(Ordering::SeqCst) { "ran" } else { "denied" };
            self.out.ev(&[("ev", esc("job")), ("job", esc(&name)), ("result", esc(verdict))]);
        }
        if !self.names.is_empty() {
            return Err("name queue longer than the host queue".into());
        }
        Ok(())
    }

    fn hold(&mut self, req: &Json) -> Result<(), String> {
        let c = s_of(req, "call")?.to_string();
        let session = self.session(req)?;
        let (run_tx, run_rx) = mpsc::channel();
        let (rel_tx, rel_rx) = mpsc::channel();
        let app = Arc::new(HoldApp { out: self.out.clone(), running: Mutex::new(run_tx), release: Mutex::new(rel_rx) });
        let Ok(t) = self.host()?.call(app, &session) else { return self.reject() };
        run_rx.recv().map_err(|_| "hold handler did not start")?;
        self.out.ev(&[("ev", esc("held")), ("call", esc(&c))]);
        self.holds.insert(c, (rel_tx, t));
        Ok(())
    }

    fn release(&mut self, req: &Json) -> Result<(), String> {
        let c = s_of(req, "call")?;
        let (tx, t) = self.holds.remove(c).ok_or_else(|| format!("unknown hold {c}"))?;
        let _ = tx.send(());
        let o = t.wait().map_err(|_| "lost")?;
        match &o.result {
            Ok(v) => self.out.result_ok(v),
            Err(e) => self.out.result_err(err_name(*e)),
        }
        Ok(())
    }
}

fn route() -> RouteId {
    // RouteId 1 is non-zero by construction.
    RouteId::new(1).unwrap_or_else(|_| std::process::abort())
}

/// The route endowment of every test session: one capability holding all five kinds, so the session's grants are
/// exactly the token op mask the oracle sets (`session` / `bump_epoch`).
fn endowment() -> Result<Arc<CapSet>, String> {
    let all = OpMask::from_bits(0x1f).map_err(|e| format!("{e:?}"))?;
    let cap = DataCap::new("app", "c", all, vec![1]).map_err(|e| format!("{e:?}"))?;
    Ok(Arc::new(CapSet::Caps(Caps::new(vec![cap]).map_err(|e| format!("{e:?}"))?)))
}

pub fn serve(muts: Muts) -> Result<(), String> {
    let out = Out(Arc::new(Mutex::new(std::io::stdout())));
    let list: Vec<String> = MUTATIONS.iter().map(|m| esc(m)).collect();
    out.line(&format!("{{\"ready\":true,\"mutations\":[{}]}}", list.join(",")));
    let mut s = Subject {
        out: out.clone(),
        muts,
        host: None,
        backends_fail: Arc::new(Mutex::new(HashMap::new())),
        sessions: HashMap::new(),
        streams: HashMap::new(),
        names: VecDeque::new(),
        holds: HashMap::new(),
    };
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let req = json::parse(&line)?;
        if s_of(&req, "op") == Ok("quit") {
            break;
        }
        let seq = match req.get("seq") {
            Some(Json::Num(t)) => t.clone(),
            _ => "0".into(),
        };
        if let Err(e) = s.op(&req) {
            out.error(&e);
        }
        out.line(&format!("{{\"ev\":\"end\",\"seq\":{seq}}}"));
    }
    // Unblock held handlers so the pool can wind down.
    for (_, (tx, _)) in s.holds.drain() {
        let _ = tx.send(());
    }
    Ok(())
}
