"""sdk-trybuild corpus: the 32 research B2 mutants and the 19 q4-001 F7b mutants, re-expressed against the real F7
(sync, axum-free, `Ctx::grant`, `TenantDb: JobQueue`). Imported by oracle.py; stdlib only.

Every mutant is ONE edit of a baseline that compiles lint-clean (the baselines are controls), so a rejection cannot
come from an unrelated typo. Each case carries:
  why   the mechanism that should reject it: "type: ..." (an F7 type rule), "absent: ..." (the construct has no F7
        analogue; the closest attempt names a dependency or SDK surface an F7 app does not have, decision D5),
        "lint: ..." (forbid(unsafe_code), clippy ban list, owner scan), "runtime: ..." (compiles; the harness decides)
  must  codes of which at least one must appear among the rejection codes (the intended mechanism). Codes are rustc
        E-codes, LT (uncoded "lifetime may not live long enough"), lint:<name>, owner:host.
Research provenance: research/state/raw/round-004/05-work/mutants.py (shape b2nd), spikes/q4-001/gen_mutants.py (D2).
"""

# ---------------------------------------------------------------------------------------------------------------------
# B2 baseline: the research notes app on F7. Request input is modelled as plain data on the handler value (`Raw`):
# F7 gives a handler only `Ctx` and a db view; the bearer token never reaches the app.
B2_BASE = r'''use monban_data_ir::{Op, OpKind, Pred, Value};
use monban_sdk::*;
use monban_types::{Principal, Subject};

pub const SELECT: u8 = op_code(OpKind::Select);
pub const INSERT: u8 = op_code(OpKind::Insert);
pub const DELETE: u8 = op_code(OpKind::Delete);
pub const ID: u32 = 0;
pub const OWNER: u32 = 2;
pub const BODY: u32 = 3;
pub const ARCHIVED: u32 = 4;

/// Untrusted request data, already parsed by the host (no token: F7 never hands it to the app).
#[derive(Clone, Debug, Default)]
pub struct Raw {
    pub param: String,
    pub path_tenant: u64,
    pub header_tenant: Option<u64>,
}

pub fn owner(p: &Principal) -> Value {
    match p.subject() {
        Subject::Authenticated(b) => Value::Str(b.iter().map(|x| format!("{x:02x}")).collect()),
        Subject::Public => Value::Str(String::new()),
    }
}

pub fn op(ctx: &Ctx<'_>, kind: OpKind, filter: Pred, writes: Vec<(u32, Value)>) -> Op {
    Op { tenant: ctx.principal().tenant(), collection: String::from("notes"), kind, filter, writes, returning: vec![ID, BODY] }
}

#[derive(Debug)]
pub struct Email {
    pub to: Value,
}
impl Job for Email {
    fn run<'j, D: TenantDb<'j>>(self, _ctx: Ctx<'j>, _db: &D) -> Result<(), SdkError> {
        let _ = self.to;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ListNotes {
    pub raw: Raw,
}
impl ScopedHandler for ListNotes {
    type Response = String;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<String, SdkError> {
        let read = ctx.grant::<SELECT>()?;
        let mut tx = db.begin()?;
        let filter = Pred::and_n(vec![Pred::Eq(ARCHIVED, Value::Int(0)), Pred::Pfx(BODY, self.raw.param.clone())]);
        let _rows = db.run(&mut tx, &read, op(&ctx, OpKind::Select, filter, Vec::new()))?;
        let _done = db.commit(tx)?;
        Ok(String::from("listed"))
    }
}

#[derive(Debug)]
pub struct CreateNote {
    pub raw: Raw,
}
impl ScopedHandler for CreateNote {
    type Response = String;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<String, SdkError> {
        let write = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        let row = vec![(OWNER, owner(ctx.principal())), (BODY, Value::Str(self.raw.param.clone()))];
        db.run(&mut tx, &write, op(&ctx, OpKind::Insert, Pred::Tt, row))?;
        let done = db.commit(tx)?;
        db.detach(&done, Email { to: owner(ctx.principal()) })?;
        Ok(String::from("ok"))
    }
}

#[derive(Debug)]
pub struct TouchNote;
impl ScopedHandler for TouchNote {
    type Response = String;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<String, SdkError> {
        let write = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &write, op(&ctx, OpKind::Insert, Pred::Tt, vec![(BODY, Value::Str(String::from("touched")))]))?;
        let _done = db.commit(tx)?;
        Ok(String::from("touched"))
    }
}

#[derive(Debug)]
pub struct DeleteNote {
    pub id: i64,
}
impl ScopedHandler for DeleteNote {
    type Response = String;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<String, SdkError> {
        let del = ctx.grant::<DELETE>()?;
        let mut tx = db.begin()?;
        let mine = Pred::and_n(vec![Pred::Eq(ID, Value::Int(self.id)), Pred::Eq(OWNER, owner(ctx.principal()))]);
        db.run(&mut tx, &del, op(&ctx, OpKind::Delete, mine, Vec::new()))?;
        let _done = db.commit(tx)?;
        Ok(String::from("deleted"))
    }
}
'''

LIST_RUN = "        let _rows = db.run(&mut tx, &read, op(&ctx, OpKind::Select, filter, Vec::new()))?;\n"
LIST_END = '        Ok(String::from("listed"))\n'
CREATE_COMMIT = ("        let done = db.commit(tx)?;\n"
                 "        db.detach(&done, Email { to: owner(ctx.principal()) })?;\n")
CREATE_OWNER = "(OWNER, owner(ctx.principal())), (BODY"
LIST_ITEM = "#[derive(Debug)]\npub struct ListNotes {"


def at_list_end(code):
    return [(LIST_END, code + "\n" + LIST_END)]


B2 = {}  # id -> dict(cls, edits, why, must)


def b2(i, cls, edits, why, must):
    B2[i] = dict(cls=cls, edits=edits, why=why, must=must)


LIFETIME = ["LT", "E0521", "E0597", "E0373", "E0310", "E0716"]
NOT_THREAD = ["E0277"]

b2("M1", "missing tenant filter", [(LIST_RUN, '        let _rows = db.query("select * from notes")?;\n')],
   "absent: F7 has no unscoped/raw query; the only data call takes a Granted proof and the host binds the tenant",
   ["E0599"])
b2("M2", "default principal", [(CREATE_OWNER, "(OWNER, owner(&Principal::default())), (BODY")],
   "type: Principal has no Default and no public constructor (F2)", ["E0599"])
b2("M3", "cross-tenant cache key",
   [(LIST_ITEM, "static CACHE: std::sync::Mutex<Vec<(String, String)>> = std::sync::Mutex::new(Vec::new());\n" + LIST_ITEM)]
   + at_list_end('        if let Ok(mut c) = CACHE.lock() { c.push((format!("notes:{}", self.raw.param), String::from("listed"))); }'),
   "lint: F7 has no cache API; an app-built cross-request cache needs process-global state (ban list: std Mutex)",
   ["lint:clippy::disallowed_types"])
b2("M4", "unescaped HTML", [(LIST_END, '        Ok(Resp::html(format!("<li>{}</li>", self.raw.param)))\n')],
   "absent: F7 has no HTML/response builder (Resp::html); the handler's Response is serialized by the host, so "
   "escaping is a host obligation (see probe M4s, which compiles)", ["E0433"])
b2("M5", "effect before commit",
   [(CREATE_COMMIT, "        db.detach(&tx, Email { to: owner(ctx.principal()) })?;\n        let done = db.commit(tx)?;\n")],
   "type: JobQueue::detach requires &Tx<'r, Committed>", ["E0308"])
b2("M6", "write in read-only (GET) handler",
   [(LIST_END, "        let w = ctx.grant::<INSERT>()?;\n        let mut t2 = db.begin()?;\n"
     "        db.run(&mut t2, &w, op(&ctx, OpKind::Insert, Pred::Tt, vec![(BODY, Value::Str(String::from(\"audit\")))]))?;\n"
     "        let _d2 = db.commit(t2)?;\n" + LIST_END)],
   "runtime: F7 has no static read/write handler split; Ctx::grant::<INSERT> is checked against the route endowment "
   "at run time and fails closed", [])
b2("M7", "forge principal from request header",
   [(CREATE_OWNER, "(OWNER, owner(&Principal { tenant: monban_types::TenantId::new(self.raw.header_tenant.unwrap_or(1))"
     ".map_err(|_| SdkError::Denied)?, subject: Subject::Public })), (BODY")],
   "type: Principal fields are private (F2)", ["E0451"])
b2("M8", "tenant from request path (IDOR)",
   [(LIST_RUN, "        let mut q = op(&ctx, OpKind::Select, filter, Vec::new());\n"
     "        q.tenant = monban_types::TenantId::new(self.raw.path_tenant).map_err(|_| SdkError::Denied)?;\n"
     "        let _rows = db.run(&mut tx, &read, q)?;\n")],
   "runtime: Op::tenant is a public field, but the SDK host overwrites it with the principal's tenant", [])
b2("M9", "SQL string concatenation of user input",
   [(LIST_RUN, "        let sql = format!(\"select * from notes where body like '{}%'\", self.raw.param);\n"
     "        let _rows = db.query(&sql)?;\n")],
   "absent: F7 has no raw-SQL surface; operations are structured Op values", ["E0599"])
b2("M10", "missing authz check on delete", [("        let del = ctx.grant::<DELETE>()?;\n", "")],
   "type: TenantDb::run needs a &Granted<'r, DataCap<K>> proof; without the grant there is nothing to pass",
   ["E0425"])
b2("M11", "handle escapes request (stashed in static Mutex<Vec>)",
   [(LIST_ITEM, "static STASH: std::sync::Mutex<Vec<Ctx<'static>>> = std::sync::Mutex::new(Vec::new());\n" + LIST_ITEM)]
   + at_list_end("        if let Ok(mut s) = STASH.lock() { s.push(ctx); }"),
   "type: Ctx<'r> cannot become 'static and is not Send (the db view is a generic &D that a static cannot name)",
   LIFETIME + NOT_THREAD)
b2("M12", "SSRF: unvalidated URL fetched",
   at_list_end("        let _ = std::net::TcpStream::connect(self.raw.param.as_str());"),
   "lint: F7 has no egress capability; any fetch is ambient std::net (ban list)", ["lint:clippy::disallowed_methods"])
b2("M13", "bearer token written to log",
   at_list_end('        eprintln!("list ok tenant={:?} token={}", ctx.principal().tenant(), ctx.token());'),
   "absent: F7 never hands the bearer token to a handler (Ctx has principal and route only)", ["E0599"])
b2("M14", "use transaction after commit",
   [(CREATE_COMMIT, CREATE_COMMIT + "        db.run(&mut tx, &write, op(&ctx, OpKind::Insert, Pred::Tt, "
     "vec![(BODY, Value::Str(String::from(\"dup\")))]))?;\n")],
   "type: commit consumes Tx<'r, Open>", ["E0382"])
b2("M15", "semantic: skip same-tenant ownership check on delete",
   [(", Pred::Eq(OWNER, owner(ctx.principal()))])", "])")],
   "runtime: semantic, expected residual (Cedar + oracle tests)", [])
b2("M16", "semantic: archived rows leaked into listing",
   [("Pred::Eq(ARCHIVED, Value::Int(0)), ", "")],
   "runtime: semantic, expected residual (Cedar + oracle tests)", [])
# ---- async-specific (research N-class); tokio::spawn becomes std::thread::spawn, the same 'static + Send demand.
b2("N1", "handle MOVED into a spawned thread",
   at_list_end("        let h = db;\n        std::thread::spawn(move || { let _ = h.begin(); });"),
   "type: &D is neither 'static nor Send", LIFETIME + NOT_THREAD)
b2("N1b", "handle BORROWED into a spawned thread (no move)",
   at_list_end("        std::thread::spawn(|| { let _ = db.begin(); });"),
   "type: closure borrows the request-scoped db view", LIFETIME + NOT_THREAD)
b2("N2", "handle stored in static OnceLock",
   [(LIST_ITEM, "static CELL: std::sync::OnceLock<Ctx<'static>> = std::sync::OnceLock::new();\n" + LIST_ITEM)]
   + at_list_end("        let _ = CELL.set(ctx);"),
   "type: Ctx<'r> is not 'static and not Sync", LIFETIME + NOT_THREAD)
b2("N3", "whole Ctx moved into a background thread after the response",
   at_list_end("        std::thread::spawn(move || { let c = ctx; let _ = c.grant::<SELECT>(); });"),
   "type: Ctx<'r> is not 'static and not Send", LIFETIME + NOT_THREAD)
b2("N4", "handle smuggled through Arc<Mutex<>> shared state on the handler value",
   [(LIST_ITEM, "#[derive(Clone, Debug, Default)]\npub struct Shared(pub std::sync::Arc<std::sync::Mutex<Vec<Ctx<'static>>>>);\n"
     "impl ScopedHandler for Shared {\n    type Response = ();\n"
     "    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, _db: &D) -> Result<(), SdkError> {\n"
     "        if let Ok(mut v) = self.0.lock() { v.push(ctx); }\n        Ok(())\n    }\n}\n" + LIST_ITEM)],
   "type: Ctx<'r> cannot be stored as Ctx<'static>", LIFETIME + NOT_THREAD)
b2("N5", "tower middleware bypassing the extractor",
   [(LIST_ITEM, "pub async fn mw(req: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response "
     "{ next.run(req).await }\n" + LIST_ITEM)],
   "absent: app crates have no axum dependency (D5: dependency absence)", ["E0433"])
b2("N6", "handler registered without the capability extractor (raw axum handler)",
   [(LIST_ITEM, "pub fn dump_routes() -> axum::Router { axum::Router::new().route(\"/t/{tenant}/dump\", "
     "axum::routing::get(|| async { \"x\" })) }\n" + LIST_ITEM)],
   "absent: app crates have no axum dependency (D5: dependency absence)", ["E0433"])
b2("N7", "tokio::time::timeout cancels the commit (Tx dropped mid-flight)",
   [(CREATE_COMMIT, "        let _ = tokio::runtime::Handle::current().block_on(tokio::time::timeout("
     "std::time::Duration::from_millis(5), async move { db.commit(tx) }));\n")],
   "absent: app crates have no tokio dependency and F7 handlers are synchronous (D5: dependency absence)", ["E0433"])
b2("N8", "tokio::select! race drops the commit branch",
   [(CREATE_COMMIT, "        tokio::select! { _ = tokio::time::sleep(std::time::Duration::from_millis(5)) => {}, "
     "_ = async move { db.commit(tx) } => {} }\n")],
   "absent: app crates have no tokio dependency (D5: dependency absence)", ["E0433"])
b2("N9", "std::mem::forget(tx) leaves the transaction open",
   [(CREATE_COMMIT, "        std::mem::forget(tx);\n")],
   "lint: ban list std::mem::forget (at run time the SDK host also rolls back a transaction left open)",
   ["lint:clippy::disallowed_methods", "lint:clippy::mem_forget"])
b2("N10", "std MutexGuard held across .await in a handler",
   [(LIST_RUN, "        let m = std::sync::Mutex::new(0u8);\n        let g = m.lock();\n"
     "        tokio::task::yield_now().await;\n        drop(g);\n" + LIST_RUN)],
   "absent: F7 is synchronous (no await point) and apps have no tokio (D5: dependency absence)", ["E0433", "E0728"])
b2("N11", "state-changing handler registered on a GET route",
   [(LIST_ITEM, "pub fn touch_routes() -> axum::Router { axum::Router::new().route(\"/t/{tenant}/touch\", "
     "axum::routing::get(|| async { \"touched\" })) }\n" + LIST_ITEM)],
   "absent: F7 apps register no routes (verb and data endowment are F8 config) and have no axum; at run time a write "
   "under a read endowment fails closed in Ctx::grant (the M6 runtime check)", ["E0433"])
b2("N12", "Box::leak(handle) to 'static, then spawn",
   at_list_end("        let c: &'static Ctx<'_> = Box::leak(Box::new(ctx));\n"
               "        std::thread::spawn(move || { let _ = c.grant::<SELECT>(); });"),
   "type: Ctx<'r> is not 'static and not Sync", LIFETIME + NOT_THREAD)
b2("N13", "handle sent over an mpsc channel as Box<dyn Any + Send>",
   at_list_end("        { let (chan, _rx) = std::sync::mpsc::channel::<Box<dyn std::any::Any + Send>>(); "
               "let _ = chan.send(Box::new(ctx)); }"),
   "type: Any needs 'static and Send", LIFETIME + NOT_THREAD)
b2("N14", "unsafe transmute of the handle's lifetime to 'static, then spawn",
   at_list_end("        let h: &'static D = unsafe { std::mem::transmute::<&D, &'static D>(db) };\n"
               "        std::thread::spawn(move || { let _ = h.begin(); });"),
   "lint: forbid(unsafe_code) (workspace lints); D is also not Send/Sync, so rustc may reject it first",
   ["lint:unsafe_code"] + LIFETIME + NOT_THREAD)
b2("N15", "Tx moved into a spawned thread (commit after the response)",
   [(CREATE_COMMIT, "        std::thread::spawn(move || { let _ = db.commit(tx); });\n")],
   "type: Tx<'r, Open> and &D are request-scoped and not Send", LIFETIME + NOT_THREAD)

B2_PROBES = {
    "H1": dict(cls="host seam: app drives monban_sdk::host itself (compiles with feature host; only layering catches it)",
               edits=[(LIST_ITEM, "pub fn sneak<B: monban_sdk::host::Backend, S: monban_sdk::host::Session>("
                       "req: &monban_sdk::host::Request<'_, B, S>) {\n"
                       "    let _ = monban_sdk::host::drive(&ListNotes { raw: Raw::default() }, req);\n}\n" + LIST_ITEM)],
               why="lint: in-oracle owner scan (cargo xtask layering equivalent: only monban-adapter-host names host)",
               must=["owner:host"]),
    "M4s": dict(cls="markup returned as a String Response (M4 written without the research Resp::html)",
                edits=[(LIST_END, '        Ok(format!("<li>{}</li>", self.raw.param))\n')],
                why="runtime: compiles; escaping is the host's Response serialization obligation (P4-host-001), "
                    "outside the SDK; no runtime check here", must=[]),
}

# ---------------------------------------------------------------------------------------------------------------------
# F7b (q4-001 design D2) on the real SDK. tokio::spawn -> std::thread::spawn, tokio mpsc -> std mpsc,
# ctx.detach -> db.detach (JobQueue is TenantDb's supertrait), f7x::Db -> TenantDb, string WS messages -> WsMsg.
F7B_PRE = r'''use monban_data_ir::{Op, OpKind, Pred, Value};
use monban_sdk::*;
use monban_types::{Principal, TenantId};
use core::marker::PhantomData;

pub const SELECT: u8 = op_code(OpKind::Select);
pub const INSERT: u8 = op_code(OpKind::Insert);

pub fn sel(t: TenantId) -> Op {
    Op { tenant: t, collection: String::from("notes"), kind: OpKind::Select, filter: Pred::Tt, writes: Vec::new(), returning: Vec::new() }
}
pub fn ins(t: TenantId, id: i64, body: &str) -> Op {
    let writes = vec![(0, Value::Int(id)), (3, Value::Str(String::from(body)))];
    Op { tenant: t, collection: String::from("notes"), kind: OpKind::Insert, filter: Pred::Tt, writes, returning: Vec::new() }
}
'''

F7B_T = {
    "body": F7B_PRE + r'''{X}
pub struct H;
pub struct G { {S} }
impl BodyHandler for H {
    type Gen = G;
    fn open<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<G, SdkError> {
{O}
    }
}
impl StreamGen for G {
    type Item = Chunk;
    fn next<'m, D: TenantDb<'m>>(&mut self, ctx: Ctx<'m>, db: &D) -> Result<Step<Chunk>, SdkError> {
{B}
    }
}
''',
    "sse": F7B_PRE + r'''{X}
pub struct H;
pub struct G { {S} }
impl SseHandler for H {
    type Gen = G;
    fn open<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D, last: Option<u64>) -> Result<G, SdkError> {
{O}
    }
}
impl StreamGen for G {
    type Item = Event;
    fn next<'m, D: TenantDb<'m>>(&mut self, ctx: Ctx<'m>, db: &D) -> Result<Step<Event>, SdkError> {
{B}
    }
}
''',
    "ws": F7B_PRE + r'''{X}
pub struct H;
pub struct G { {S} }
impl WsHandler for H {
    type Session = G;
    fn open<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<G, SdkError> {
{O}
    }
}
impl WsSession for G {
    fn on_message<'m, D: TenantDb<'m>>(&mut self, ctx: Ctx<'m>, db: &D, msg: &WsMsg) -> Result<WsReply, SdkError> {
{B}
    }
}
''',
    "job": F7B_PRE + r'''pub struct H;
pub struct AuditJob { pub key: u64 }
impl Job for AuditJob {
    fn run<'j, D: TenantDb<'j>>(self, ctx: Ctx<'j>, db: &D) -> Result<(), SdkError> { Ok(()) }
}
{X}
impl ScopedHandler for H {
    type Response = &'static str;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<&'static str, SdkError> {
{B}
    }
}
''',
}
DEF_S = "n: u64"
DEF_O = "        Ok(G { n: 0 })"
DEF_NEXT = "        Ok(Step::Done)"
DEF_WS = "        Ok(WsReply::Close)"
DEF_JOB = '''        let t = ctx.principal().tenant();
        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, ins(t, 7, "created"))?;
        let done = db.commit(tx)?;
        db.detach(&done, AuditJob { key: 7 })?;
        Ok("created")'''


def f7b(feature, x="", s=None, o=None, b=None):
    if feature == "job":
        return F7B_T["job"].replace("{X}", x).replace("{B}", b or DEF_JOB)
    dn = DEF_WS if feature == "ws" else DEF_NEXT
    return (F7B_T[feature].replace("{X}", x).replace("{S}", s or DEF_S).replace("{O}", o or DEF_O)
            .replace("{B}", b or dn))


F7B = {}  # id -> dict(cls, src, why, must)


def e(i, cls, src, why, must):
    F7B[i] = dict(cls=cls, src=src, why=why, must=must)


SPAWN = "std::thread::spawn"
e("E1", "Granted moved into a spawned thread",
  f7b("body", b=f"        let g = ctx.grant::<SELECT>()?;\n        {SPAWN}(move || {{ drop(g); }});\n        Ok(Step::Done)"),
  "type: Granted<'m> is not 'static", LIFETIME)
e("E2", "whole Ctx moved into a spawned thread",
  f7b("body", b=f"        {SPAWN}(move || {{ let c = ctx; let _ = c.grant::<SELECT>(); }});\n        Ok(Step::Done)"),
  "type: Ctx<'m> is not 'static and not Send", LIFETIME + NOT_THREAD)
e("E3", "SSE producer thread: tenant db handle + grant moved into spawn",
  f7b("sse", b="        let t = ctx.principal().tenant();\n        let g = ctx.grant::<SELECT>()?;\n"
      f"        {SPAWN}(move || {{ if let Ok(mut tx) = db.begin() {{ let _ = db.run(&mut tx, &g, sel(t)); }} }});\n"
      "        Ok(Step::Done)"),
  "type: &D and Granted<'m> are request-scoped", LIFETIME + NOT_THREAD)
e("E4", "Ctx cloned, clone moved into spawn, original keeps serving",
  f7b("body", b=f"        let c2 = ctx.clone();\n        {SPAWN}(move || {{ let _ = c2.grant::<SELECT>(); }});\n"
      "        let _ = ctx.grant::<SELECT>()?;\n        Ok(Step::Done)"),
  "type: Ctx is not Clone", ["E0599"])
e("E5", "Granted stored in static OnceLock",
  f7b("body", x="static CELL: std::sync::OnceLock<Granted<'static, DataCap<SELECT>>> = std::sync::OnceLock::new();",
      b="        let _ = CELL.set(ctx.grant::<SELECT>()?);\n        Ok(Step::Done)"),
  "type: Granted<'m> is not 'static", LIFETIME)
e("E6", "Ctx stashed in a thread_local RefCell (no Sync needed)",
  f7b("body", x="thread_local! { static STASH: std::cell::RefCell<Option<Ctx<'static>>> = std::cell::RefCell::new(None); }",
      b="        STASH.with(|s| *s.borrow_mut() = Some(ctx));\n        Ok(Step::Done)"),
  "type: Ctx<'m> is not 'static", LIFETIME)
e("E7", "Granted sent over a typed channel to a long-lived consumer (static Sender)",
  f7b("body", x="static TX: std::sync::OnceLock<std::sync::Mutex<std::sync::mpsc::Sender<Granted<'static, DataCap<SELECT>>>>> "
      "= std::sync::OnceLock::new();",
      b="        let g = ctx.grant::<SELECT>()?;\n"
        "        if let Some(t) = TX.get() { if let Ok(t) = t.lock() { let _ = t.send(g); } }\n        Ok(Step::Done)"),
  "type: Granted<'m> is not 'static", LIFETIME)
e("E8", "Ctx sent over a channel as Box<dyn Any + Send>",
  f7b("body", b="        let (tx, _rx) = std::sync::mpsc::channel::<Box<dyn std::any::Any + Send>>(); "
      "let _ = tx.send(Box::new(ctx));\n        Ok(Step::Done)"),
  "type: Any needs 'static; Ctx is not Send", LIFETIME + NOT_THREAD)
e("E9", "Granted wrapped in Arc, Arc clone moved into spawn",
  f7b("body", b=f"        let g = std::sync::Arc::new(ctx.grant::<SELECT>()?); let g2 = g.clone(); "
      f"{SPAWN}(move || {{ drop(g2); }});\n        Ok(Step::Done)"),
  "type: Granted<'m> is not 'static", LIFETIME)
e("E10", "Box::leak(Granted) to &'static, then spawn",
  f7b("body", b=f"        let g: &'static Granted<'_, DataCap<SELECT>> = Box::leak(Box::new(ctx.grant::<SELECT>()?)); "
      f"{SPAWN}(move || {{ let _ = g; }});\n        Ok(Step::Done)"),
  "type: Granted<'m> is not 'static", LIFETIME)
e("E11", "detached job keeps the request's Granted (instead of re-deriving at run time)",
  f7b("job", x="""pub struct KeepCap { g: Granted<'static, DataCap<INSERT>> }
impl Job for KeepCap {
    fn run<'j, D: TenantDb<'j>>(self, ctx: Ctx<'j>, db: &D) -> Result<(), SdkError> { let _ = self.g; Ok(()) }
}""", b='''        let t = ctx.principal().tenant();
        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, ins(t, 7, "created"))?;
        let done = db.commit(tx)?;
        db.detach(&done, KeepCap { g: ctx.grant::<INSERT>()? })?;
        Ok("created")'''),
  "type: Job: 'static, Granted<'r> is not", LIFETIME)
e("E12", "detached job keeps the request's tenant db handle",
  f7b("job", x="""pub struct KeepDb<T: Send + Sync + 'static> { db: &'static T }
impl<T: Send + Sync + 'static> Job for KeepDb<T> {
    fn run<'j, D: TenantDb<'j>>(self, ctx: Ctx<'j>, db: &D) -> Result<(), SdkError> { let _ = self.db; Ok(()) }
}""", b='''        let t = ctx.principal().tenant();
        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, ins(t, 7, "created"))?;
        let done = db.commit(tx)?;
        db.detach(&done, KeepDb { db })?;
        Ok("created")'''),
  "type: D is not Send/Sync/'static (masks the lifetime; E12b isolates it)", NOT_THREAD + LIFETIME)
e("E12b", "detached job keeps the request's &Principal (Sync, so only the lifetime can stop it)",
  f7b("job", x="""pub struct KeepPrincipal { p: &'static Principal }
impl Job for KeepPrincipal {
    fn run<'j, D: TenantDb<'j>>(self, ctx: Ctx<'j>, db: &D) -> Result<(), SdkError> { let _ = self.p.tenant(); Ok(()) }
}""", b='''        let t = ctx.principal().tenant();
        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, ins(t, 7, "created"))?;
        let done = db.commit(tx)?;
        db.detach(&done, KeepPrincipal { p: ctx.principal() })?;
        Ok("created")'''),
  "type: &'r Principal is not 'static", LIFETIME)
e("E13", "detached job enqueued before the transaction commits (effect before commit)",
  f7b("job", b='''        let t = ctx.principal().tenant();
        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, ins(t, 7, "created"))?;
        db.detach(&tx, AuditJob { key: 7 })?;
        let done = db.commit(tx)?;
        Ok("created")'''),
  "type: detach requires &Tx<'r, Committed>", ["E0308"])
e("E14", "WS session reuses the first message's Granted for every later message",
  f7b("ws", s="g: Granted<'static, DataCap<SELECT>>", o="        Ok(G { g: ctx.grant::<SELECT>()? })",
      b="        let t = ctx.principal().tenant();\n        let mut tx = db.begin()?;\n"
        "        let _rows = db.run(&mut tx, &self.g, sel(t))?;\n        Ok(WsReply::Close)"),
  "type: the session is 'static, Granted<'r> is not", LIFETIME)
e("E15", "open Tx<Open> held across streamed chunks (writes after the response head)",
  f7b("body", s="tx: Tx<'static, Open>", o="        Ok(G { tx: db.begin()? })"),
  "type: the generator is 'static, Tx<'r, Open> is not", LIFETIME)
e("E16", "Tx used after commit",
  f7b("job", b='''        let t = ctx.principal().tenant();
        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, ins(t, 1, "a"))?;
        let done = db.commit(tx)?;
        db.run(&mut tx, &g, ins(t, 2, "dup"))?;
        Ok("x")'''),
  "type: commit consumes Tx<'r, Open>", ["E0382"])
e("E17", "handler forges a Granted (struct literal) instead of asking the host",
  f7b("body", b="        let g: Granted<'_, DataCap<INSERT>> = Granted { _c: PhantomData, _r: PhantomData };\n"
      "        Ok(Step::Done)"),
  "type: Granted fields are private", ["E0451"])
e("E18", "unsafe transmute of Granted<'r> to Granted<'static>, then spawn",
  f7b("body", b="        let g: Granted<'static, DataCap<SELECT>> = unsafe { core::mem::transmute(ctx.grant::<SELECT>()?) }; "
      f"{SPAWN}(move || {{ drop(g); }});\n        Ok(Step::Done)"),
  "lint: forbid(unsafe_code); Granted is Send, so only the lint tier can stop it", ["lint:unsafe_code"])

# ---------------------------------------------------------------------------------------------------------------------
# Controls: legitimate patterns that MUST compile lint-clean (guard against over-rejection and against a broken
# baseline). BASE also runs through the runtime harness and must show no violation.
CONTROLS = {
    "BASE": dict(cls="B2 baseline notes app (every B2 mutant is one edit of this)", src=B2_BASE),
    "C1": dict(cls="std::thread::scope borrowing a Granted (joined before the scope ends)",
               src=f7b("body", b="        let g = ctx.grant::<SELECT>()?; std::thread::scope(|s| { s.spawn(|| { let _ = &g; }); });\n"
                       "        Ok(Step::Done)")),
    "C2": dict(cls="plain data (tenant id) moved into a spawned thread",
               src=f7b("body", b=f"        let tenant = ctx.principal().tenant(); {SPAWN}(move || {{ let _ = tenant; }});\n"
                       "        Ok(Step::Done)")),
    "F7B_BODY": dict(cls="F7b body baseline", src=f7b("body")),
    "F7B_SSE": dict(cls="F7b SSE baseline", src=f7b("sse")),
    "F7B_WS": dict(cls="F7b WebSocket baseline", src=f7b("ws")),
    "F7B_JOB": dict(cls="F7b detached-job baseline (grant, insert, commit, detach)", src=f7b("job")),
}


def apply(base, edits, ident):
    src = base
    for old, new in edits:
        n = src.count(old)
        if n != 1:
            raise ValueError(f"{ident}: edit anchor occurs {n} times: {old[:60]!r}")
        src = src.replace(old, new, 1)
    return src


def cases():
    """[(id, group, cls, src, why, must)] in a stable order."""
    out = [(i, "control", c["cls"], c["src"], "control: must compile lint-clean", []) for i, c in CONTROLS.items()]
    for i, m in B2.items():
        out.append((i, "b2", m["cls"], apply(B2_BASE, m["edits"], i), m["why"], m["must"]))
    for i, m in F7B.items():
        out.append((i, "f7b", m["cls"], m["src"], m["why"], m["must"]))
    for i, m in B2_PROBES.items():
        out.append((i, "probe", m["cls"], apply(B2_BASE, m["edits"], i), m["why"], m["must"]))
    return out
