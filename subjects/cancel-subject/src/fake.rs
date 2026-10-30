//! Harness pgwire fake (trusted test code, not the unit under test) and the event sink.
//!
//! The server side executes a frontend message group on arrival and queues its backend messages (real
//! `aegis_adapter_pg::wire::Backend` values); the client side is the adapter's own protocol mirror (`ProtoState`,
//! driven through the `checkin::sim` seam), so the NC3 predicate, drain and recovery run on the production code.
//! Semantics follow PostgreSQL where the cancel-sweep model needs them: txn status I/T/E, autocommit outside a
//! transaction, named statements until Close / DISCARD ALL, named portals until the end of the (implicit or explicit)
//! transaction, savepoints inside a transaction, session GUCs (SET / RESET ALL / SHOW) cleared by DISCARD ALL,
//! DISCARD ALL inside a transaction block = 25001, any statement in a failed transaction = 25P02, COMMIT of a failed
//! transaction answers ROLLBACK, and a close that rolls back. A CancelRequest is not statement-bound and is
//! delivered late: it cancels the first message executed on that backend on behalf of a *different* request
//! (SQLSTATE 57014), the q3-008 worst case.
//!
//! `durable` snapshots and `checkin.truth` are read from this server state, never from the client's view.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;

use aegis_adapter_pg::checkin::sim::SimProto;
use aegis_adapter_pg::wire::{self, Backend, DbError, Event, Expect, ProtoState, TxnStatus, Unrecoverable};
use aegis_adapter_pg::{PgSession, Pooled};

use crate::json::{Json, emit};

/// Event sink: JSON lines of the cancel-sweep protocol, tagged with the current request.
#[derive(Debug, Default)]
pub struct Out {
    pub req: Option<String>,
    pub lines: Vec<String>,
}

pub fn s(v: &str) -> Json {
    Json::Str(v.to_owned())
}

pub fn n(v: u64) -> Json {
    Json::Num(v.to_string())
}

impl Out {
    /// Emit `{"ev":name, ["req":<current>], fields...}`.
    pub fn ev(&mut self, name: &str, with_req: bool, fields: Vec<(&str, Json)>) {
        let mut m = BTreeMap::new();
        m.insert("ev".to_owned(), s(name));
        if with_req && let Some(r) = &self.req {
            m.insert("req".to_owned(), s(r));
        }
        for (k, v) in fields {
            m.insert(k.to_owned(), v);
        }
        self.lines.push(emit(&Json::Obj(m)));
    }
}

/// A frontend message group (one model message = one group ending in ReadyForQuery).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
    Begin,
    Commit,
    Rollback,
    Exec(String, String),
    Select(Vec<String>),
    Parse(String),
    Bind(String),
    ExecP(String, String, String),
    Close(String),
    /// Recovery: Close of one named statement (`b'S'`) or portal (`b'P'`) + Sync.
    CloseOne(u8, String),
    Savepoint(String),
    Release(String),
    Set(String, String),
    Reset,
    Show,
    Discard,
}

impl Msg {
    /// The protocol message name (`wire` events, `db.<MSG>` sites).
    pub fn label(&self) -> &'static str {
        match self {
            Msg::Begin => "BEGIN",
            Msg::Commit => "COMMIT",
            Msg::Rollback => "ROLLBACK",
            Msg::Exec(..) => "EXEC",
            Msg::Select(_) => "SELECT",
            Msg::Parse(_) => "PARSE",
            Msg::Bind(_) => "BIND",
            Msg::ExecP(..) => "EXECP",
            Msg::Close(_) | Msg::CloseOne(..) => "CLOSE",
            Msg::Savepoint(_) => "SAVEPOINT",
            Msg::Release(_) => "RELEASE",
            Msg::Set(..) => "SET",
            Msg::Reset => "RESET",
            Msg::Show => "SHOW",
            Msg::Discard => "DISCARD",
        }
    }
    /// What the client expects back (recorded in the protocol mirror before the write).
    fn expects(&self) -> Vec<Expect> {
        match self {
            Msg::Parse(name) => vec![Expect::Parse(name.clone()), Expect::Sync],
            Msg::Bind(name) => vec![Expect::Bind(name.clone()), Expect::Sync],
            Msg::ExecP(..) => vec![Expect::Execute, Expect::Sync],
            Msg::CloseOne(kind, name) => vec![Expect::Close(*kind, name.clone()), Expect::Sync],
            Msg::Close(name) => {
                vec![Expect::Close(b'S', name.clone()), Expect::Close(b'P', name.clone()), Expect::Sync]
            }
            _ => vec![Expect::Query],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Txn {
    I,
    T,
    E,
}

impl Txn {
    fn status(self) -> TxnStatus {
        match self {
            Txn::I => TxnStatus::Idle,
            Txn::T => TxnStatus::InTransaction,
            Txn::E => TxnStatus::Failed,
        }
    }
    fn letter(self) -> &'static str {
        match self {
            Txn::I => "I",
            Txn::T => "T",
            Txn::E => "E",
        }
    }
}

/// One queued backend message, with its server time (op-budget ticks) and, on the ReadyForQuery that ends a group,
/// the group's reply label.
#[derive(Debug)]
struct Queued {
    msg: Backend,
    cost: u64,
    label: Option<String>,
}

#[derive(Debug)]
struct Backendside {
    txn: Txn,
    writes: BTreeMap<String, String>,
    statements: BTreeSet<String>,
    portals: BTreeSet<String>,
    savepoints: BTreeSet<String>,
    session: BTreeMap<String, String>,
    queue: VecDeque<Queued>,
    /// A CancelRequest in flight, sent on behalf of this request (None = sent outside any request).
    stray: Option<Option<String>>,
    closed: bool,
    stmt_ticks: u64,
}

impl Backendside {
    fn new() -> Backendside {
        Backendside {
            txn: Txn::I,
            writes: BTreeMap::new(),
            statements: BTreeSet::new(),
            portals: BTreeSet::new(),
            savepoints: BTreeSet::new(),
            session: BTreeMap::new(),
            queue: VecDeque::new(),
            stray: None,
            closed: false,
            stmt_ticks: 1,
        }
    }
    fn end_txn(&mut self) {
        self.writes.clear();
        self.savepoints.clear();
        self.portals.clear();
        self.txn = Txn::I;
    }
    fn close(&mut self) {
        self.end_txn();
        self.statements.clear();
        self.session.clear();
        self.queue.clear();
        self.stray = None;
        self.closed = true;
    }
}

/// The fake server plus the event sink (shared by the host shell and every fake session on the host thread).
#[derive(Debug, Default)]
pub struct World {
    pub rows: BTreeMap<String, String>,
    backends: BTreeMap<u64, Backendside>,
    next: u64,
    pub out: Out,
    draining: BTreeSet<u64>,
}

pub type Shared = Rc<RefCell<World>>;

fn err(code: &str, message: &str) -> Backend {
    Backend::ErrorResponse(DbError {
        severity: "ERROR".into(),
        code: code.into(),
        message: message.into(),
        detail: None,
        constraint: None,
    })
}

fn row(k: &str, v: Option<&String>) -> Backend {
    Backend::DataRow(vec![Some(k.as_bytes().to_vec()), v.map(|x| x.as_bytes().to_vec())])
}

impl World {
    pub fn new(rows: BTreeMap<String, String>) -> World {
        World { rows, ..World::default() }
    }

    pub fn durable(&mut self, at: &str) {
        let rows = Json::Obj(self.rows.iter().map(|(k, v)| (k.clone(), s(v))).collect());
        self.out.ev("durable", false, vec![("at", s(at)), ("rows", rows)]);
    }

    /// Server truth of one backend for `checkin` events.
    pub fn truth(&self, sid: u64) -> Json {
        let mut m = BTreeMap::new();
        match self.backends.get(&sid) {
            Some(b) => {
                let groups = b.queue.iter().filter(|q| q.label.is_some()).count();
                let mut objs: Vec<String> = b.statements.iter().map(|x| format!("stmt:{x}")).collect();
                objs.extend(b.portals.iter().map(|x| format!("portal:{x}")));
                objs.extend(b.savepoints.iter().map(|x| format!("sp:{x}")));
                objs.sort();
                m.insert("txn".to_owned(), s(b.txn.letter()));
                m.insert("queued".to_owned(), n(groups as u64));
                m.insert("objects".to_owned(), Json::Arr(objs.iter().map(|o| s(o)).collect()));
                m.insert("session".to_owned(), Json::Obj(b.session.iter().map(|(k, v)| (k.clone(), s(v))).collect()));
            }
            None => {
                m.insert("txn".to_owned(), s("?"));
            }
        }
        Json::Obj(m)
    }

    /// kill -9 of the host: every backend sees its client vanish and rolls back.
    pub fn crash(&mut self) {
        for b in self.backends.values_mut() {
            b.close();
        }
        self.draining.clear();
    }

    pub fn set_draining(&mut self, sid: u64, on: bool) {
        if on {
            self.draining.insert(sid);
        } else {
            self.draining.remove(&sid);
        }
    }

    fn connect(&mut self) -> u64 {
        self.next = self.next.saturating_add(1);
        self.backends.insert(self.next, Backendside::new());
        self.next
    }

    /// Execute one message group on backend `sid` and queue its replies.
    fn exec(&mut self, sid: u64, m: &Msg) {
        let req = self.out.req.clone();
        let rows = &mut self.rows;
        let Some(b) = self.backends.get_mut(&sid) else { return };
        if b.closed {
            return;
        }
        let ticks = b.stmt_ticks;
        let mut q: Vec<Backend> = Vec::new();
        let mut cost = 0u64;
        let mut label = m.label().to_owned();
        let failed = |b: &mut Backendside| {
            if b.txn == Txn::T {
                b.txn = Txn::E;
            }
        };
        // The late CancelRequest lands on the first message executed for a different request.
        let stray_hits = matches!(&b.stray, Some(from) if *from != req);
        if stray_hits {
            b.stray = None;
            failed(b);
            q.push(err("57014", "canceling statement due to user request"));
            label = "ERROR".into();
        } else if b.txn == Txn::E && !matches!(m, Msg::Rollback | Msg::Commit) {
            q.push(err("25P02", "current transaction is aborted"));
            label = "ERROR".into();
        } else {
            match m {
                Msg::Begin => {
                    if b.txn == Txn::I {
                        b.txn = Txn::T;
                    }
                    q.push(Backend::CommandComplete("BEGIN".into()));
                }
                Msg::Commit => {
                    let tag = if b.txn == Txn::E { "ROLLBACK" } else { "COMMIT" };
                    if b.txn == Txn::T {
                        let w = std::mem::take(&mut b.writes);
                        rows.extend(w);
                    }
                    b.end_txn();
                    label = tag.into();
                    q.push(Backend::CommandComplete(tag.into()));
                }
                Msg::Rollback => {
                    b.end_txn();
                    cost = 1;
                    q.push(Backend::CommandComplete("ROLLBACK".into()));
                }
                Msg::Exec(k, v) => {
                    if b.txn == Txn::T {
                        b.writes.insert(k.clone(), v.clone());
                    } else {
                        rows.insert(k.clone(), v.clone());
                    }
                    cost = ticks;
                    q.push(Backend::CommandComplete("UPDATE 1".into()));
                }
                Msg::Select(keys) => {
                    for k in keys {
                        q.push(row(k, b.writes.get(k).or_else(|| rows.get(k))));
                    }
                    cost = ticks;
                    label = "ROWS".into();
                    q.push(Backend::CommandComplete(format!("SELECT {}", keys.len())));
                }
                Msg::Parse(name) => {
                    b.statements.insert(name.clone());
                    q.push(Backend::ParseComplete);
                }
                Msg::Bind(name) => {
                    if b.statements.contains(name) {
                        b.portals.insert(name.clone());
                        q.push(Backend::BindComplete);
                    } else {
                        failed(b);
                        label = "ERROR".into();
                        q.push(err("26000", "prepared statement does not exist"));
                    }
                }
                Msg::ExecP(name, k, v) => {
                    if b.portals.contains(name) {
                        if b.txn == Txn::T {
                            b.writes.insert(k.clone(), v.clone());
                        } else {
                            rows.insert(k.clone(), v.clone());
                        }
                        cost = ticks;
                        q.push(Backend::CommandComplete("INSERT 0 1".into()));
                    } else {
                        failed(b);
                        label = "ERROR".into();
                        q.push(err("34000", "portal does not exist"));
                    }
                }
                Msg::Close(name) => {
                    b.statements.remove(name);
                    b.portals.remove(name);
                    q.push(Backend::CloseComplete);
                    q.push(Backend::CloseComplete);
                }
                Msg::CloseOne(kind, name) => {
                    if *kind == b'S' {
                        b.statements.remove(name);
                    } else {
                        b.portals.remove(name);
                    }
                    q.push(Backend::CloseComplete);
                }
                Msg::Savepoint(name) => {
                    if b.txn == Txn::T {
                        b.savepoints.insert(name.clone());
                        q.push(Backend::CommandComplete("SAVEPOINT".into()));
                    } else {
                        label = "ERROR".into();
                        q.push(err("25P01", "SAVEPOINT can only be used in transaction blocks"));
                    }
                }
                Msg::Release(name) => {
                    if b.savepoints.remove(name) {
                        q.push(Backend::CommandComplete("RELEASE".into()));
                    } else {
                        failed(b);
                        label = "ERROR".into();
                        q.push(err("3B001", "savepoint does not exist"));
                    }
                }
                Msg::Set(k, v) => {
                    b.session.insert(k.clone(), v.clone());
                    q.push(Backend::CommandComplete("SET".into()));
                }
                Msg::Reset => {
                    b.session.clear();
                    q.push(Backend::CommandComplete("RESET".into()));
                }
                Msg::Show => {
                    for (k, v) in &b.session {
                        q.push(row(k, Some(v)));
                    }
                    label = "ROWS".into();
                    q.push(Backend::CommandComplete("SHOW".into()));
                }
                Msg::Discard => {
                    cost = 1;
                    if b.txn == Txn::I {
                        b.statements.clear();
                        b.portals.clear();
                        b.session.clear();
                        q.push(Backend::CommandComplete("DISCARD ALL".into()));
                    } else {
                        b.txn = Txn::E;
                        label = "ERROR".into();
                        q.push(err("25001", "DISCARD ALL cannot run inside a transaction block"));
                    }
                }
            }
        }
        // End of the group: an implicit transaction ends at Sync (its portals with it).
        if b.txn == Txn::I {
            b.portals.clear();
        }
        for msg in q {
            b.queue.push_back(Queued { msg, cost: 0, label: None });
        }
        b.queue.push_back(Queued { msg: Backend::ReadyForQuery(b.txn.status()), cost, label: Some(label) });
    }

    fn send_cancel(&mut self, sid: u64) {
        let req = self.out.req.clone();
        if let Some(b) = self.backends.get_mut(&sid)
            && !b.closed
        {
            b.stray = Some(req);
        }
    }

    fn close(&mut self, sid: u64) {
        if let Some(b) = self.backends.get_mut(&sid) {
            b.close();
        }
        self.draining.remove(&sid);
    }

    fn pop(&mut self, sid: u64) -> Option<Queued> {
        self.backends.get_mut(&sid).and_then(|b| b.queue.pop_front())
    }

    pub fn set_ticks(&mut self, sid: u64, t: u64) {
        if let Some(b) = self.backends.get_mut(&sid) {
            b.stmt_ticks = t;
        }
    }
}

/// What one message group answered.
#[derive(Debug, Default)]
pub struct Reply {
    pub label: String,
    pub rows: Vec<(String, Option<String>)>,
}

/// Client handle on one fake backend: the adapter's protocol mirror plus the driver cache generation.
#[derive(Debug)]
pub struct FakeSession {
    pub sid: u64,
    pub name: String,
    world: Shared,
    proto: SimProto,
    generation: u64,
    /// DataRows of the group being read.
    rows: Vec<(String, Option<String>)>,
}

impl FakeSession {
    pub fn connect(world: &Shared) -> FakeSession {
        let sid = world.borrow_mut().connect();
        FakeSession {
            sid,
            name: format!("db{sid}"),
            world: Rc::clone(world),
            proto: SimProto::started(TxnStatus::Idle),
            generation: 0,
            rows: Vec::new(),
        }
    }

    /// Write one message group (`wire` event); the server executes it on arrival.
    pub fn send(&mut self, m: &Msg) -> Result<(), wire::Error> {
        if let Some(u) = self.proto.state().unrecoverable() {
            return Err(wire::Error::Unrecoverable(u.clone()));
        }
        for e in m.expects() {
            self.proto.sent(e);
        }
        let mut w = self.world.borrow_mut();
        w.draining.remove(&self.sid); // a new message ends the drain of outstanding replies
        w.out.ev("wire", true, vec![("conn", s(&self.name)), ("msg", s(m.label()))]);
        w.exec(self.sid, m);
        Ok(())
    }

    /// Read one backend message into the protocol mirror. Returns its cost and, at the end of a group, the reply.
    fn read_msg(&mut self) -> Result<(u64, Option<Reply>), wire::Error> {
        let q = self.world.borrow_mut().pop(self.sid);
        let Some(q) = q else {
            return Err(wire::Error::Unrecoverable(Unrecoverable::Desync("fake: no reply queued".into())));
        };
        let ev = self.proto.on_backend(&q.msg).map_err(wire::Error::Unrecoverable)?;
        if let Backend::DataRow(vals) = &q.msg {
            let mut it = vals.iter();
            let k = it.next().cloned().flatten().map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
            let v = it.next().cloned().flatten().map(|b| String::from_utf8_lossy(&b).into_owned());
            self.rows.push((k, v));
        }
        match (ev, q.label) {
            (Event::Ready(_), Some(label)) => {
                let mut w = self.world.borrow_mut();
                let mut f = vec![("conn", s(&self.name)), ("msg", s(&label))];
                if w.draining.contains(&self.sid) {
                    f.push(("drain", Json::Bool(true)));
                }
                w.out.ev("reply", true, f);
                Ok((q.cost, Some(Reply { label, rows: std::mem::take(&mut self.rows) })))
            }
            _ => Ok((q.cost, None)),
        }
    }

    /// Read through the next ReadyForQuery (`reply` event).
    pub fn recv(&mut self) -> Result<Reply, wire::Error> {
        loop {
            if let (_, Some(r)) = self.read_msg()? {
                return Ok(r);
            }
        }
    }
}

impl Pooled for FakeSession {
    fn close(mut self) {
        self.proto.closed();
        self.world.borrow_mut().close(self.sid);
    }
}

impl PgSession for FakeSession {
    fn proto(&self) -> &ProtoState {
        self.proto.state()
    }
    fn read_one(&mut self, _left: u64) -> Result<u64, wire::Error> {
        // DST: the cost is the server time the fake reports; the caller compares the total with the budget.
        self.read_msg().map(|(c, _)| c)
    }
    fn send_sync(&mut self, _left: u64) -> Result<u64, wire::Error> {
        self.proto.sent(Expect::Sync);
        let mut w = self.world.borrow_mut();
        if let Some(b) = w.backends.get_mut(&self.sid) {
            let st = b.txn.status();
            b.queue.push_back(Queued { msg: Backend::ReadyForQuery(st), cost: 0, label: Some("SYNC".into()) });
        }
        Ok(0)
    }
    fn send_simple(&mut self, sql: &str, _left: u64) -> Result<u64, wire::Error> {
        let m = match sql {
            "ROLLBACK" => Msg::Rollback,
            "DISCARD ALL" => Msg::Discard,
            other => return Err(wire::Error::Usage(format!("fake: unsupported recovery statement {other}"))),
        };
        self.send(&m).map(|()| 0)
    }
    fn send_close(&mut self, kind: u8, name: &str, _left: u64) -> Result<u64, wire::Error> {
        self.send(&Msg::CloseOne(kind, name.to_owned())).map(|()| 0)
    }
    fn cancel_request(&mut self) -> Result<(), wire::Error> {
        self.world.borrow_mut().send_cancel(self.sid);
        Ok(())
    }
    fn generation(&self) -> u64 {
        self.generation
    }
    fn bump_generation(&mut self) -> u64 {
        self.generation = self.generation.saturating_add(1);
        self.generation
    }
}
