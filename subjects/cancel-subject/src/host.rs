//! DST shell: a synchronous host (DEVIATIONS X-11) around the adapter's pool and NC3 release path.
//!
//! The handler is plain synchronous code on its own worker thread. It holds no host state, only a capability
//! handle: every host call is a message to the host thread, which owns the pools, the connections and the
//! accounting. Cancellation points are host-call boundaries (README "Synchronous host"):
//!
//! * a driver round trip writes its message first, then checks the token before reading the reply (`db.<MSG>`), so a
//!   cancelled request can leave a reply outstanding (the send-before-yield hazard);
//! * every other host call (limiter debit, each `authz.<stage>`, `pool.acquire`, `stmtcache.insert`,
//!   `session.ready`, `upstream.acquire`, `upstream.response`) checks the token at its boundary, before its effect;
//! * the C8 recycle reset in `pool.acquire` is itself a round trip (`db.DISCARD`).
//!
//! `CancelAt<N>` fires at the N-th point: that call returns `Stop` with no effect, the handler's capabilities are
//! revoked (every later call returns `Stop` with no effect and no event), and host-owned cleanup runs right there
//! on the host thread: NC3 release of the held connection as `Cancelled`, upstream close, the NC4 cancel debit,
//! Failed / 408. From the commit point on the token is ignored (NC2 latch): later points are reported detached and
//! the request completes; a timer after CP answers 202. `crash` kills the host (pools gone, backends roll back).
//!
//! Handlers run one at a time (the sweep is sequential), so the run is deterministic: the host thread serves the
//! handler thread's calls in order over a rendezvous channel.

use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread;

use aegis_adapter_pg::pool::PoolMutations;
use aegis_adapter_pg::{
    Charge, Checkout, ConnId, Epoch, Nc3Observer, PlainReuse, Pool, PoolConfig, PoolKey, Pooled, Release, TenantId,
};

use crate::fake::{FakeSession, Msg, Reply, Shared, World, n, s};
use crate::json::Json;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Drop,
    Rst,
    Timeout,
    StageTimeout,
    Crash,
}

impl Mode {
    pub fn parse(v: &str) -> Option<Mode> {
        Some(match v {
            "drop" => Mode::Drop,
            "rst" => Mode::Rst,
            "timeout" => Mode::Timeout,
            "stage_timeout" => Mode::StageTimeout,
            "crash" => Mode::Crash,
            _ => return None,
        })
    }
    fn name(self) -> &'static str {
        match self {
            Mode::Drop => "drop",
            Mode::Rst => "rst",
            Mode::Timeout => "timeout",
            Mode::StageTimeout => "stage_timeout",
            Mode::Crash => "crash",
        }
    }
    fn timer(self) -> bool {
        matches!(self, Mode::Timeout | Mode::StageTimeout)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    Read(Vec<String>),
    Write(String, String),
    Prepared(String, String, String),
    Savepoint(String, String, String),
    Upstream,
    Show,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Abort {
    BeforeBegin,
    InTxn,
}

#[derive(Clone, Debug)]
pub struct Req {
    pub id: String,
    pub principal: String,
    pub idem_key: String,
    pub cost: u64,
    pub authority: String,
    pub authz: Vec<String>,
    pub pre_prepare: bool,
    pub session_set: bool,
    pub op_budget: u64,
    pub stmt_ticks: u64,
    pub steps: Vec<Step>,
    pub abort: Option<Abort>,
}

/// Subject-side self-test mutations: the adapter's (pool / NC3) and the shell's own.
#[derive(Clone, Copy, Debug, Default)]
pub struct Muts {
    pub pool: PoolMutations,
    pub no_cp_latch: bool,
    pub authz_fail_open: bool,
    pub debit_after_work: bool,
}

impl Muts {
    pub fn apply(&mut self, name: &str) -> bool {
        match name {
            "always-reusable" => self.pool.always_reusable = true,
            "checkin-ignores-txn" => self.pool.checkin_ignores_txn = true,
            "checkin-ignores-objects" => self.pool.checkin_ignores_objects = true,
            "pool-key-no-epoch" => self.pool.pool_key_no_epoch = true,
            "reuse-after-cancelrequest" => self.pool.reuse_after_cancelrequest = true,
            "recovery-no-discard-all" => self.pool.recovery_no_discard_all = true,
            "quarantine-not-charged" => self.pool.quarantine_not_charged = true,
            "cancelled-session-no-discard" => self.pool.cancelled_session_no_discard = true,
            "no-cp-latch" => self.no_cp_latch = true,
            "authz-fail-open" => self.authz_fail_open = true,
            "debit-after-work" => self.debit_after_work = true,
            _ => return false,
        }
        true
    }
}

// ------------------------------------------------------------------------------------------------ capability seam

/// A host call made by the handler.
#[derive(Debug)]
enum Call {
    Debit,
    Authz(String),
    Acquire,
    Db(Msg),
    StmtCacheInsert,
    SessionReady,
    UpAcquire,
    UpResponse,
    Commit,
    Fail(&'static str),
    Done,
}

#[derive(Debug)]
enum Ret {
    Go,
    Stop,
}

/// The handler stops (cancelled, denied, failed, or its capabilities were revoked).
#[derive(Debug)]
struct Stop;

struct Handle {
    tx: Sender<Call>,
    rx: Receiver<Ret>,
}

impl Handle {
    fn call(&mut self, c: Call) -> Result<(), Stop> {
        self.tx.send(c).map_err(|_| Stop)?;
        match self.rx.recv() {
            Ok(Ret::Go) => Ok(()),
            Ok(Ret::Stop) | Err(_) => Err(Stop),
        }
    }
    fn db(&mut self, m: Msg) -> Result<(), Stop> {
        self.call(Call::Db(m))
    }
}

/// The application handler (the cancel-sweep request shape): synchronous, host calls only.
fn handler(h: &mut Handle, r: &Req) -> Result<(), Stop> {
    h.call(Call::Debit)?;
    for stage in &r.authz {
        h.call(Call::Authz(stage.clone()))?;
    }
    h.call(Call::Acquire)?;
    if r.pre_prepare {
        // session-level named statement before the txn (statement-cache shape, tokio-postgres #1374)
        h.db(Msg::Parse("cached".into()))?;
        h.call(Call::StmtCacheInsert)?;
    }
    if r.abort == Some(Abort::BeforeBegin) {
        return h.call(Call::Fail("handler error after the statement-cache insert (txn I, server object open)"));
    }
    if r.session_set {
        h.db(Msg::Set("app.principal".into(), r.principal.clone()))?;
        h.call(Call::SessionReady)?;
    }
    h.db(Msg::Begin)?;
    let idem = format!("idem:{}:{}", r.principal, r.idem_key);
    h.db(Msg::Exec(idem.clone(), "in_flight".into()))?;
    for st in &r.steps {
        match st {
            Step::Read(keys) => h.db(Msg::Select(keys.clone()))?,
            Step::Write(k, v) => h.db(Msg::Exec(k.clone(), v.clone()))?,
            Step::Prepared(name, k, v) => {
                h.db(Msg::Parse(name.clone()))?;
                h.db(Msg::Bind(name.clone()))?;
                h.db(Msg::ExecP(name.clone(), k.clone(), v.clone()))?;
                h.db(Msg::Close(name.clone()))?;
            }
            Step::Savepoint(name, k, v) => {
                h.db(Msg::Savepoint(name.clone()))?;
                h.db(Msg::Exec(k.clone(), v.clone()))?;
                h.db(Msg::Release(name.clone()))?;
            }
            Step::Show => h.db(Msg::Show)?,
            Step::Upstream => {
                h.call(Call::UpAcquire)?;
                h.call(Call::UpResponse)?;
            }
        }
    }
    if r.abort == Some(Abort::InTxn) {
        return h.call(Call::Fail("handler error inside the txn (txn T, nothing outstanding)"));
    }
    h.db(Msg::Exec(idem, "done:200".into()))?; // outcome record inside the txn (NC2)
    h.call(Call::Commit)?;
    if r.pre_prepare {
        h.db(Msg::Close("cached".into()))?;
    }
    if r.session_set {
        h.db(Msg::Reset)?;
    }
    h.call(Call::Done)
}

// ------------------------------------------------------------------------------------------------ host

/// Upstream connection (no protocol state in this model).
#[derive(Debug)]
struct UpConn {
    name: String,
}

impl Pooled for UpConn {
    fn close(self) {}
}

impl PlainReuse for UpConn {}

const DB_POOL: PoolConfig =
    PoolConfig { max_open: 16, max_idle_per_key: 1, acquire_timeout: std::time::Duration::from_millis(0) };
const UP_POOL: PoolConfig =
    PoolConfig { max_open: 64, max_idle_per_key: 8, acquire_timeout: std::time::Duration::from_millis(0) };

struct Ctx {
    req: Req,
    tenant: TenantId,
    cancel_at: Option<u64>,
    mode: Mode,
    n: u64,
    revoked: bool,
    finished: bool,
    cp: bool,
    latched: bool,
    stage_timeout: bool,
    commit_ok: bool,
    post_cp_error: bool,
    conn: Option<Checkout<FakeSession>>,
    ups: Vec<Checkout<UpConn>>,
}

/// NC3 observer: turns the adapter's release hooks into protocol events and NC4 debits.
struct Obs<'a> {
    world: &'a Shared,
    principal: &'a str,
    names: &'a BTreeMap<ConnId, (String, u64)>,
}

impl Obs<'_> {
    fn name(&self, id: ConnId) -> (String, u64) {
        self.names.get(&id).cloned().unwrap_or_else(|| (format!("conn{id}"), 0))
    }
}

impl Nc3Observer<FakeSession> for Obs<'_> {
    fn quarantine(&mut self, id: ConnId) {
        let (c, sid) = self.name(id);
        let mut w = self.world.borrow_mut();
        w.set_draining(sid, true);
        w.out.ev("quarantine", true, vec![("conn", s(&c))]);
    }
    fn cancel_request(&mut self, id: ConnId) {
        let (c, _) = self.name(id);
        self.world.borrow_mut().out.ev("cancel_request", true, vec![("conn", s(&c))]);
    }
    fn gen_bump(&mut self, id: ConnId, generation: u64) {
        let (c, _) = self.name(id);
        self.world.borrow_mut().out.ev("gen_bump", true, vec![("conn", s(&c)), ("gen", n(generation))]);
    }
    fn charge(&mut self, cost: u64, why: Charge) {
        let reason = match why {
            Charge::Quarantine => "quarantine",
            Charge::Discard => "discard",
        };
        self.world.borrow_mut().out.ev(
            "debit",
            true,
            vec![("principal", s(self.principal)), ("cost", n(cost)), ("reason", s(reason))],
        );
    }
    fn recover(&mut self, id: ConnId, ticks: u64, completed: bool) {
        let (c, sid) = self.name(id);
        let mut w = self.world.borrow_mut();
        w.set_draining(sid, false);
        w.out.ev("recover", true, vec![("conn", s(&c)), ("ticks", n(ticks)), ("completed", Json::Bool(completed))]);
    }
    fn checkin(&mut self, id: ConnId, conn: &FakeSession) {
        let (c, _) = self.name(id);
        let mut w = self.world.borrow_mut();
        let truth = w.truth(conn.sid);
        w.out.ev("checkin", true, vec![("conn", s(&c)), ("truth", truth)]);
    }
    fn discard(&mut self, id: ConnId) {
        let (c, _) = self.name(id);
        self.world.borrow_mut().out.ev("discard", true, vec![("conn", s(&c))]);
    }
}

pub struct Host {
    world: Shared,
    pool: Pool<FakeSession>,
    up: Pool<UpConn>,
    up_n: u64,
    up_names: BTreeMap<ConnId, String>,
    names: BTreeMap<ConnId, (String, u64)>,
    epoch: Epoch,
    muts: Muts,
    tenants: BTreeMap<String, TenantId>,
    ctx: Option<Ctx>,
}

type Step2 = Result<(), ()>;

impl Host {
    pub fn new(world: World, muts: Muts, tenants: BTreeMap<String, TenantId>) -> Host {
        Host {
            world: Rc::new(std::cell::RefCell::new(world)),
            pool: Pool::new_with(DB_POOL, muts.pool),
            up: Pool::new_with(UP_POOL, muts.pool),
            up_n: 0,
            up_names: BTreeMap::new(),
            names: BTreeMap::new(),
            epoch: 0,
            muts,
            tenants,
            ctx: None,
        }
    }

    pub fn world(&self) -> &Shared {
        &self.world
    }

    fn ev(&self, name: &str, fields: Vec<(&str, Json)>) {
        self.world.borrow_mut().out.ev(name, true, fields);
    }

    fn debit(&self, principal: &str, cost: u64, reason: &str) {
        self.ev("debit", vec![("principal", s(principal)), ("cost", n(cost)), ("reason", s(reason))]);
    }

    /// Auth/config change (CRS C5): bump the epoch and retire older pool entries.
    pub fn bump(&mut self) {
        self.epoch = self.epoch.saturating_add(1);
        self.world.borrow_mut().out.ev("epoch_bump", false, vec![("epoch", n(self.epoch))]);
        let _ = self.pool.retire_before(self.epoch);
        for id in self.up.retire_before(self.epoch) {
            if let Some(name) = self.up_names.get(&id) {
                self.world.borrow_mut().out.ev("upstream_close", false, vec![("conn", s(name))]);
            }
        }
    }

    /// Execute one request; `cancel_at` / `mode` only for the target.
    pub fn run(&mut self, r: &Req, cancel_at: Option<u64>, mode: Option<Mode>) -> Result<(), String> {
        let tenant = *self.tenants.get(&r.principal).ok_or_else(|| format!("no tenant for {}", r.principal))?;
        self.world.borrow_mut().out.req = Some(r.id.clone());
        self.ctx = Some(Ctx {
            req: r.clone(),
            tenant,
            cancel_at,
            mode: mode.unwrap_or(Mode::Drop),
            n: 0,
            revoked: false,
            finished: false,
            cp: false,
            latched: false,
            stage_timeout: false,
            commit_ok: false,
            post_cp_error: false,
            conn: None,
            ups: Vec::new(),
        });
        let (call_tx, call_rx) = channel::<Call>();
        let (ret_tx, ret_rx) = channel::<Ret>();
        let req = r.clone();
        thread::scope(|sc| {
            sc.spawn(move || {
                let mut h = Handle { tx: call_tx, rx: ret_rx };
                let _ = handler(&mut h, &req);
            });
            for call in call_rx.iter() {
                let ret = self.serve(call);
                if ret_tx.send(ret).is_err() {
                    break;
                }
            }
        });
        // Fail closed: a handler that returned without a result is a handler error.
        let open = self.ctx.as_ref().is_some_and(|c| !c.finished && !c.revoked);
        if open {
            self.fail("handler returned without a result");
        }
        self.ctx = None;
        self.world.borrow_mut().out.req = None;
        Ok(())
    }

    fn c(&mut self) -> Option<&mut Ctx> {
        self.ctx.as_mut()
    }

    fn serve(&mut self, call: Call) -> Ret {
        if self.ctx.as_ref().is_none_or(|c| c.revoked || c.finished) {
            return Ret::Stop;
        }
        let r = match call {
            Call::Debit => self.call_debit(),
            Call::Authz(stage) => return self.call_authz(&stage),
            Call::Acquire => self.call_acquire(),
            Call::Db(m) => self.call_db(m),
            Call::StmtCacheInsert => self.point("stmtcache.insert"),
            Call::SessionReady => self.point("session.ready"),
            Call::UpAcquire => self.call_up_acquire(),
            Call::UpResponse => self.call_up_response(),
            Call::Commit => self.call_commit(),
            Call::Fail(why) => {
                self.fail(why);
                Err(())
            }
            Call::Done => {
                self.done();
                Ok(())
            }
        };
        match r {
            Ok(()) => Ret::Go,
            Err(()) => Ret::Stop,
        }
    }

    /// One cancellation point (host-call boundary).
    fn point(&mut self, site: &str) -> Step2 {
        let no_cp_latch = self.muts.no_cp_latch;
        let Some(c) = self.ctx.as_mut() else { return Err(()) };
        if c.latched {
            self.world.borrow_mut().out.ev(
                "await",
                true,
                vec![("n", Json::Null), ("site", s(site)), ("detached", Json::Bool(true))],
            );
            return Ok(());
        }
        let at = c.n;
        c.n = c.n.saturating_add(1);
        let fire = c.cancel_at == Some(at);
        let mode = c.mode;
        let cp = c.cp;
        self.world.borrow_mut().out.ev("await", true, vec![("n", n(at)), ("site", s(site))]);
        if !fire {
            return Ok(());
        }
        self.ev("cancel", vec![("n", n(at)), ("site", s(site)), ("mode", s(mode.name()))]);
        if mode == Mode::Crash {
            self.ev("crash", vec![]);
            self.crash();
            return Err(());
        }
        if cp && !no_cp_latch {
            self.ev("latched", vec![]);
            if let Some(c) = self.c() {
                c.latched = true;
            }
            return Ok(());
        }
        if mode == Mode::StageTimeout && site.starts_with("authz.") {
            if let Some(c) = self.c() {
                c.stage_timeout = true;
            }
            return Ok(());
        }
        self.cancel_cleanup(site);
        Err(())
    }

    /// Host-owned cleanup at the cancellation point (before CP).
    fn cancel_cleanup(&mut self, site: &str) {
        if let Some(stage) = site.strip_prefix("authz.") {
            self.ev("authz", vec![("stage", s(stage)), ("decision", s("deny")), ("cancelled", Json::Bool(true))]);
        }
        let Some(mut c) = self.ctx.take() else { return };
        c.revoked = true;
        if let Some(co) = c.conn.take() {
            self.release(co, Release::Cancelled, &c);
        }
        for u in c.ups.drain(..) {
            self.ev("upstream_close", vec![("conn", s(&u.peek().name))]);
            drop(u); // closes it; never back to the pool with an unread response
        }
        self.debit(&c.req.principal, 1, "cancel");
        self.ev("outcome", vec![("outcome", s("Failed"))]);
        if c.mode.timer() {
            self.ev("response", vec![("status", n(408))]);
        }
        c.finished = true;
        self.ctx = Some(c);
    }

    fn release(&self, co: Checkout<FakeSession>, how: Release, c: &Ctx) {
        let mut obs = Obs { world: &self.world, principal: &c.req.principal, names: &self.names };
        let _ = self.pool.release(co, how, c.req.op_budget, &mut obs);
    }

    fn crash(&mut self) {
        self.world.borrow_mut().crash();
        if let Some(c) = self.ctx.as_mut() {
            c.revoked = true;
            c.finished = true;
            c.conn = None; // the process is gone: nothing is released, the backend already rolled back
            c.ups.clear();
        }
        self.pool = Pool::new_with(DB_POOL, self.muts.pool);
        self.up = Pool::new_with(UP_POOL, self.muts.pool);
    }

    /// Handler error or failed statement before CP: Failed / 500, NC3 "left mid-protocol" decided by the predicate.
    fn fail(&mut self, why: &str) {
        let Some(mut c) = self.ctx.take() else { return };
        if let Some(co) = c.conn.take() {
            self.release(co, Release::HandlerError, &c);
        }
        for u in c.ups.drain(..) {
            self.ev("upstream_close", vec![("conn", s(&u.peek().name))]);
            drop(u);
        }
        self.ev("outcome", vec![("outcome", s("Failed")), ("error", s(why))]);
        self.ev("response", vec![("status", n(500))]);
        c.finished = true;
        self.ctx = Some(c);
    }

    fn done(&mut self) {
        let Some(mut c) = self.ctx.take() else { return };
        if let Some(co) = c.conn.take() {
            let how = if c.post_cp_error { Release::HandlerError } else { Release::Completed };
            self.release(co, how, &c);
        }
        if self.muts.debit_after_work {
            self.debit(&c.req.principal, c.req.cost, "admission");
        }
        self.ev("outcome", vec![("outcome", s(if c.commit_ok { "Committed" } else { "Failed" }))]);
        if !c.latched {
            self.ev("response", vec![("status", n(if c.commit_ok { 200 } else { 500 }))]);
        } else if c.mode.timer() {
            self.ev("response", vec![("status", n(202)), ("note", s("pending; retrieve by idempotency key"))]);
        }
        c.finished = true;
        self.ctx = Some(c);
    }

    fn call_debit(&mut self) -> Step2 {
        self.point("limiter.debit")?;
        if !self.muts.debit_after_work
            && let Some(c) = self.ctx.as_ref()
        {
            self.debit(&c.req.principal, c.req.cost, "admission");
        }
        Ok(())
    }

    fn call_authz(&mut self, stage: &str) -> Ret {
        if let Some(c) = self.c() {
            c.stage_timeout = false;
        }
        if self.point(&format!("authz.{stage}")).is_err() {
            return Ret::Stop;
        }
        let timed_out = self.ctx.as_ref().is_some_and(|c| c.stage_timeout);
        if !timed_out {
            self.ev("authz", vec![("stage", s(stage)), ("decision", s("allow")), ("cancelled", Json::Bool(false))]);
            return Ret::Go;
        }
        if self.muts.authz_fail_open {
            self.ev("authz", vec![("stage", s(stage)), ("decision", s("allow")), ("cancelled", Json::Bool(true))]);
            return Ret::Go;
        }
        // NC5: a timed-out stage evaluates to Error => Deny.
        self.ev("authz", vec![("stage", s(stage)), ("decision", s("deny")), ("cancelled", Json::Bool(true))]);
        if let Some(c) = self.ctx.as_ref() {
            self.debit(&c.req.principal, 1, "cancel");
        }
        self.ev("outcome", vec![("outcome", s("Failed"))]);
        self.ev("response", vec![("status", n(403))]);
        if let Some(c) = self.c() {
            c.finished = true;
        }
        Ret::Stop
    }

    fn call_acquire(&mut self) -> Step2 {
        self.point("pool.acquire")?;
        let (principal, tenant, ticks, budget) = match self.ctx.as_ref() {
            Some(c) => (c.req.principal.clone(), c.tenant, c.req.stmt_ticks, c.req.op_budget),
            None => return Err(()),
        };
        let role = format!("t_{:016x}", tenant.get());
        let Ok(key) = PoolKey::new(principal.as_bytes(), tenant, &role, self.epoch) else {
            self.fail("pool key refused");
            return Err(());
        };
        let world = Rc::clone(&self.world);
        let mut co = match self.pool.acquire(&key, |_| Ok::<_, ()>(FakeSession::connect(&world))) {
            Ok(co) => co,
            Err(_) => {
                self.fail("pool acquire failed");
                return Err(());
            }
        };
        let name = co.peek().name.clone();
        let sid = co.peek().sid;
        self.names.insert(co.id(), (name.clone(), sid));
        self.ev("conn_acquire", vec![("conn", s(&name)), ("reused", Json::Bool(co.reused()))]);
        self.world.borrow_mut().set_ticks(sid, ticks);
        let sent = co.reset_send(budget);
        if let Some(c) = self.c() {
            c.conn = Some(co);
        }
        match sent {
            Ok(false) => Ok(()),
            Ok(true) => {
                // C8 reset on recycle: DISCARD ALL is a round trip, so a cancellation point.
                self.point("db.DISCARD")?;
                let res = match self.c().and_then(|c| c.conn.as_mut()) {
                    Some(co) => co.reset_finish(budget),
                    None => return Err(()),
                };
                match res {
                    Ok(generation) => {
                        self.ev("gen_bump", vec![("conn", s(&name)), ("gen", n(generation))]);
                        Ok(())
                    }
                    Err(_) => {
                        self.fail("recycle reset failed");
                        Err(())
                    }
                }
            }
            Err(_) => {
                self.fail("recycle reset failed");
                Err(())
            }
        }
    }

    fn call_db(&mut self, m: Msg) -> Step2 {
        let sent = matches!(
            self.c().and_then(|c| c.conn.as_mut()).map(|co| co.session().map(|x| x.send(&m))),
            Some(Ok(Ok(())))
        );
        if !sent {
            self.fail("no usable connection");
            return Err(());
        }
        self.point(&format!("db.{}", m.label()))?;
        self.read_reply(&m).map(|_| ())
    }

    fn read_reply(&mut self, m: &Msg) -> Result<Reply, ()> {
        let rep = match self.c().and_then(|c| c.conn.as_mut()).map(|co| co.session().map(|x| x.recv())) {
            Some(Ok(Ok(rep))) => rep,
            _ => {
                self.fail("connection lost");
                return Err(());
            }
        };
        if rep.label == "ERROR" {
            let cp = self.ctx.as_ref().is_some_and(|c| c.cp);
            if cp {
                if let Some(c) = self.c() {
                    c.post_cp_error = true; // latched: the outcome is the commit's; release decides the rest
                }
                return Ok(rep);
            }
            self.fail(&format!("{}: server error", m.label()));
            return Err(());
        }
        let rows =
            Json::Obj(rep.rows.iter().map(|(k, v)| (k.clone(), v.as_ref().map_or(Json::Null, |x| s(x)))).collect());
        match m {
            Msg::Select(_) => self.ev("result", vec![("rows", rows)]),
            Msg::Show => self.ev("result", vec![("rows", rows), ("kind", s("session"))]),
            _ => {}
        }
        Ok(rep)
    }

    fn call_commit(&mut self) -> Step2 {
        let sent = matches!(
            self.c().and_then(|c| c.conn.as_mut()).map(|co| co.session().map(|x| x.send(&Msg::Commit))),
            Some(Ok(Ok(())))
        );
        if !sent {
            self.fail("no usable connection");
            return Err(());
        }
        // Commit point: COMMIT is on the wire; from here the token is ignored (NC2).
        if let Some(c) = self.c() {
            c.cp = true;
        }
        self.ev("cp", vec![]);
        self.point("db.COMMIT")?;
        let rep = self.read_reply(&Msg::Commit)?;
        if let Some(c) = self.c() {
            c.commit_ok = rep.label == "COMMIT";
        }
        Ok(())
    }

    fn call_up_acquire(&mut self) -> Step2 {
        self.point("upstream.acquire")?;
        let (principal, tenant, authority) = match self.ctx.as_ref() {
            Some(c) => (c.req.principal.clone(), c.tenant, c.req.authority.clone()),
            None => return Err(()),
        };
        // Upstream pool key = the whole connection config: authority, principal, auth ctx, tenant, epoch (C3/C5).
        let Ok(key) = PoolKey::new(principal.as_bytes(), tenant, &format!("{authority}/bearer"), self.epoch) else {
            self.fail("upstream key refused");
            return Err(());
        };
        let mut next = self.up_n;
        let mut created = false;
        let res = self.up.acquire(&key, |_| {
            next = next.saturating_add(1);
            created = true;
            Ok::<_, ()>(UpConn { name: format!("up{next}") })
        });
        self.up_n = next;
        let Ok(co) = res else {
            self.fail("upstream pool exhausted");
            return Err(());
        };
        let name = co.peek().name.clone();
        self.up_names.insert(co.id(), name.clone());
        if created {
            self.ev("upstream_connect", vec![("conn", s(&name))]);
        }
        self.ev("upstream_acquire", vec![("conn", s(&name)), ("reused", Json::Bool(co.reused()))]);
        if let Some(c) = self.c() {
            c.ups.push(co);
        }
        Ok(())
    }

    fn call_up_response(&mut self) -> Step2 {
        self.point("upstream.response")?;
        let Some(co) = self.c().and_then(|c| c.ups.pop()) else {
            self.fail("no upstream connection");
            return Err(());
        };
        let name = co.peek().name.clone();
        match self.up.put_back(co) {
            aegis_adapter_pg::Idled::Kept => self.ev("upstream_release", vec![("conn", s(&name))]),
            aegis_adapter_pg::Idled::Closed => self.ev("upstream_close", vec![("conn", s(&name))]),
        }
        Ok(())
    }
}
