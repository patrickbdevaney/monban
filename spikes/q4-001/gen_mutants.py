#!/usr/bin/env python3
"""Generate the q4-001 trybuild corpus: one file per (mutant, design). Run: python3 -I gen_mutants.py
Each file is a standalone crate root compiled by trybuild against f7x + tokio (deps present = worst case).
Mutant = the design's baseline handler with ONE smuggling edit. Files are written to corpus/mutants/."""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "corpus", "mutants")

PRE = "#![forbid(unsafe_code)]\n#![allow(unused)]\nuse core::future::Future;\nuse core::marker::PhantomData;\nuse f7x::*;\n"
MAIN = "\nfn main() {}\n"

# ---------------- design headers ({B} = mutated body). Each mirrors the baseline in corpus/src/lib.rs.
D1 = {
    "body": PRE + """use f7x::d1::*;
struct H;
impl BodyHandler for H {
    fn stream<'r, D: Db<'r>>(&'r self, ctx: Ctx<'r>, db: &'r D, mut out: Sink<'r, Chunk>)
        -> impl Future<Output = Result<(), SdkError>> + Send + 'r {
        async move {
{B}
            Ok(())
        }
    }
}
""" + MAIN,
    "sse": PRE + """use f7x::d1::*;
struct H;
impl SseHandler for H {
    fn events<'r, D: Db<'r>>(&'r self, ctx: Ctx<'r>, db: &'r D, mut out: Sink<'r, Event>)
        -> impl Future<Output = Result<(), SdkError>> + Send + 'r {
        async move {
{B}
            Ok(())
        }
    }
}
""" + MAIN,
    "ws": PRE + """use f7x::d1::*;
struct H;
impl WsHandler for H {
    fn session<'r, D: Db<'r>>(&'r self, ctx: Ctx<'r>, db: &'r D, mut ws: WsSession<'r>)
        -> impl Future<Output = Result<(), SdkError>> + Send + 'r {
        async move {
{B}
            Ok(())
        }
    }
}
""" + MAIN,
}

D2 = {
    # {S}=generator state fields, {O}=open body (must return Ok(G{..})), {B}=next body (must return)
    "body": PRE + """use f7x::d2::*;
struct H;
struct G { {S} }
impl BodyHandler for H {
    type Gen = G;
    fn open<'r, D: Db<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<G, SdkError> {
{O}
    }
}
impl StreamGen for G {
    type Item = Chunk;
    fn next<'m, D: Db<'m>>(&mut self, ctx: Ctx<'m>, db: &D) -> Result<Step<Chunk>, SdkError> {
{B}
    }
}
""" + MAIN,
    "sse": PRE + """use f7x::d2::*;
struct H;
struct G { {S} }
impl SseHandler for H {
    type Gen = G;
    fn open<'r, D: Db<'r>>(&self, ctx: Ctx<'r>, db: &D, last: Option<u64>) -> Result<G, SdkError> {
{O}
    }
}
impl StreamGen for G {
    type Item = Event;
    fn next<'m, D: Db<'m>>(&mut self, ctx: Ctx<'m>, db: &D) -> Result<Step<Event>, SdkError> {
{B}
    }
}
""" + MAIN,
    "ws": PRE + """use f7x::d2::*;
struct H;
struct G { {S} }
impl WsHandler for H {
    type Session = G;
    fn open<'r, D: Db<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<G, SdkError> {
{O}
    }
}
impl WsSessionGen for G {
    fn on_message<'m, D: Db<'m>>(&mut self, ctx: Ctx<'m>, db: &D, msg: &str) -> Result<WsReply, SdkError> {
{B}
    }
}
""" + MAIN,
    # {J}=extra items (job types), {B}=handle body (must return Ok("..."))
    "job": PRE + """use f7x::d2::*;
struct H;
struct AuditJob { key: u64 }
impl Job for AuditJob {
    fn run<'j, D: Db<'j>>(self, ctx: Ctx<'j>, db: &D) -> Result<(), SdkError> { Ok(()) }
}
{J}
impl ScopedHandler for H {
    type Response = &'static str;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<&'static str, SdkError> {
{B}
    }
}
""" + MAIN,
}

D3 = {
    "body": PRE + """use f7x::d3::*;
struct H;
impl BodyHandler for H {
    fn stream(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Chunk>) -> Result<(), SdkError> {
{B}
        Ok(())
    }
}
""" + MAIN,
    "sse": PRE + """use f7x::d3::*;
struct H;
impl SseHandler for H {
    fn events(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Event>) -> Result<(), SdkError> {
{B}
        Ok(())
    }
}
""" + MAIN,
    "ws": PRE + """use f7x::d3::*;
struct H;
impl WsHandler for H {
    fn session(&self, ctx: OwnedCtx, db: OwnedDb, mut inbox: tokio::sync::mpsc::Receiver<String>, out: BodyTx<String>)
        -> Result<(), SdkError> {
{B}
        Ok(())
    }
}
""" + MAIN,
    "job": PRE + """use f7x::d3::*;
struct H;
{J}
impl JobHandler for H {
    fn handle(&self, ctx: OwnedCtx, db: OwnedDb) -> Result<(), SdkError> {
{B}
        Ok(())
    }
}
""" + MAIN,
}

D2_DEFAULT_S = "n: u64"
D2_OPEN_OK = "        Ok(G { n: 0 })"
D2_NEXT_DONE = "        Ok(Step::Done)"
D2_WS_OK = "        Ok(WsReply::Close)"


def hoist(src):
    """Move item-level prefixes (statics, thread_local!) below the crate-level inner attributes."""
    i = src.index("#![forbid(unsafe_code)]")
    return src[i:].replace("use f7x::*;\n", "use f7x::*;\n" + src[:i], 1) if i else src


def d1(feature, body):
    return D1[feature].replace("{B}", body)


def d2(feature, open_=None, next_=None, state=None, extra="", job_body=None):
    if feature == "job":
        return D2["job"].replace("{J}", extra).replace("{B}", job_body)
    dn = D2_WS_OK if feature == "ws" else D2_NEXT_DONE
    return (D2[feature].replace("{S}", state or D2_DEFAULT_S).replace("{O}", open_ or D2_OPEN_OK)
            .replace("{B}", next_ or dn))


def d3(feature, body, extra=""):
    return D3[feature].replace("{J}", extra).replace("{B}", body)


M = {}  # id -> dict(cls=..., d1=src|("NA",why), d2=..., d3=...)


def add(i, cls, **kw):
    M[i] = dict(cls=cls, **kw)


SLEEP = "tokio::time::sleep(std::time::Duration::from_millis(5)).await;"

add("E1", "Granted moved into tokio::spawn",
    d1=d1("body", f"            let g = ctx.grant::<SELECT>()?;\n            tokio::spawn(async move {{ {SLEEP} drop(g); }});"),
    d2=d2("body", next_=f"        let g = ctx.grant::<SELECT>()?;\n        tokio::spawn(async move {{ {SLEEP} drop(g); }});\n        Ok(Step::Done)"),
    d3=d3("body", f"        let g = ctx.grant::<SELECT>()?;\n        tokio::spawn(async move {{ {SLEEP} drop(g); }});"))

add("E2", "whole Ctx moved into tokio::spawn",
    d1=d1("body", f"            tokio::spawn(async move {{ let c = ctx; {SLEEP} let _ = c.grant::<SELECT>(); }});"),
    d2=d2("body", next_=f"        tokio::spawn(async move {{ let c = ctx; {SLEEP} let _ = c.grant::<SELECT>(); }});\n        Ok(Step::Done)"),
    d3=d3("body", f"        tokio::spawn(async move {{ let c = ctx; {SLEEP} let _ = c.grant::<SELECT>(); }});"))

SSE_PRODUCER_D = (f"tokio::spawn(async move {{ {SLEEP} if let Ok(mut tx) = db.begin() {{ let _ = db.run(&mut tx, &g, Op::select(0)); }} }});")
add("E3", "SSE producer task: tenant db handle + grant moved into tokio::spawn",
    d1=d1("sse", "            let g = ctx.grant::<SELECT>()?;\n            " + SSE_PRODUCER_D),
    d2=d2("sse", next_="        let g = ctx.grant::<SELECT>()?;\n        " + SSE_PRODUCER_D + "\n        Ok(Step::Done)"),
    d3=d3("sse", "        let g = ctx.grant::<SELECT>()?;\n        " + SSE_PRODUCER_D))

add("E4", "Ctx cloned, clone moved into tokio::spawn, original keeps serving",
    d1=d1("body", f"            let c2 = ctx.clone();\n            tokio::spawn(async move {{ {SLEEP} let _ = c2.grant::<SELECT>(); }});\n            let _ = ctx.grant::<SELECT>()?;"),
    d2=d2("body", next_=f"        let c2 = ctx.clone();\n        tokio::spawn(async move {{ {SLEEP} let _ = c2.grant::<SELECT>(); }});\n        let _ = ctx.grant::<SELECT>()?;\n        Ok(Step::Done)"),
    d3=d3("body", f"        let c2 = ctx.clone();\n        tokio::spawn(async move {{ {SLEEP} let _ = c2.grant::<SELECT>(); }});\n        let _ = ctx.grant::<SELECT>()?;"))

ONCE = "static CELL: std::sync::OnceLock<Granted<'static, DataCap<SELECT>>> = std::sync::OnceLock::new();\n"
ONCE3 = "static CELL: std::sync::OnceLock<OwnedGranted<SELECT>> = std::sync::OnceLock::new();\n"
add("E5", "Granted stored in static OnceLock",
    d1=ONCE + d1("body", "            let _ = CELL.set(ctx.grant::<SELECT>()?);"),
    d2=ONCE + d2("body", next_="        let _ = CELL.set(ctx.grant::<SELECT>()?);\n        Ok(Step::Done)"),
    d3=ONCE3 + d3("body", "        let _ = CELL.set(ctx.grant::<SELECT>()?);"))

TL = "thread_local! { static STASH: std::cell::RefCell<Option<Ctx<'static>>> = std::cell::RefCell::new(None); }\n"
TL3 = "thread_local! { static STASH: std::cell::RefCell<Option<OwnedCtx>> = std::cell::RefCell::new(None); }\n"
add("E6", "Ctx stashed in thread_local RefCell (no Sync needed)",
    d1=TL + d1("body", "            STASH.with(|s| *s.borrow_mut() = Some(ctx));"),
    d2=TL + d2("body", next_="        STASH.with(|s| *s.borrow_mut() = Some(ctx));\n        Ok(Step::Done)"),
    d3=TL3 + d3("body", "        STASH.with(|s| *s.borrow_mut() = Some(ctx));"))

CH = "static TX: std::sync::OnceLock<std::sync::Mutex<std::sync::mpsc::Sender<Granted<'static, DataCap<SELECT>>>>> = std::sync::OnceLock::new();\n"
CH3 = "static TX: std::sync::OnceLock<std::sync::Mutex<std::sync::mpsc::Sender<OwnedGranted<SELECT>>>> = std::sync::OnceLock::new();\n"
SEND = "if let Some(t) = TX.get() { if let Ok(t) = t.lock() { let _ = t.send(g); } }"
add("E7", "Granted sent over a typed channel to a long-lived consumer (static Sender)",
    d1=CH + d1("body", "            let g = ctx.grant::<SELECT>()?;\n            " + SEND),
    d2=CH + d2("body", next_="        let g = ctx.grant::<SELECT>()?;\n        " + SEND + "\n        Ok(Step::Done)"),
    d3=CH3 + d3("body", "        let g = ctx.grant::<SELECT>()?;\n        " + SEND))

ANY = "let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<Box<dyn std::any::Any + Send>>(); let _ = tx.send(Box::new(ctx));"
add("E8", "Ctx sent over a channel as Box<dyn Any + Send>",
    d1=d1("body", "            " + ANY),
    d2=d2("body", next_="        " + ANY + "\n        Ok(Step::Done)"),
    d3=d3("body", "        " + ANY))

ARC = f"let g = std::sync::Arc::new(ctx.grant::<SELECT>()?); let g2 = g.clone(); tokio::spawn(async move {{ {SLEEP} drop(g2); }});"
add("E9", "Granted wrapped in Arc, Arc clone moved into tokio::spawn",
    d1=d1("body", "            " + ARC),
    d2=d2("body", next_="        " + ARC + "\n        Ok(Step::Done)"),
    d3=d3("body", "        " + ARC))

LEAK = f"let g: &'static Granted<'_, DataCap<SELECT>> = Box::leak(Box::new(ctx.grant::<SELECT>()?)); tokio::spawn(async move {{ {SLEEP} let _ = g; }});"
LEAK3 = f"let g: &'static OwnedGranted<SELECT> = Box::leak(Box::new(ctx.grant::<SELECT>()?)); tokio::spawn(async move {{ {SLEEP} let _ = g; }});"
add("E10", "Box::leak(Granted) to &'static, then tokio::spawn",
    d1=d1("body", "            " + LEAK),
    d2=d2("body", next_="        " + LEAK + "\n        Ok(Step::Done)"),
    d3=d3("body", "        " + LEAK3))

NA_DETACH = ("NA", "D1 has no detached-job API: nothing borrowed from 'r can outlive the connection; every attempt reduces to E1/E3 (rejected)")
J11 = """struct KeepCap { g: Granted<'static, DataCap<INSERT>> }
impl Job for KeepCap {
    fn run<'j, D: Db<'j>>(self, ctx: Ctx<'j>, db: &D) -> Result<(), SdkError> { let _ = self.g; Ok(()) }
}"""
add("E11", "detached job keeps the request's Granted (instead of re-deriving at run time)",
    d1=NA_DETACH,
    d2=d2("job", extra=J11, job_body="""        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, Op::insert(7, "created"))?;
        let done = db.commit(tx)?;
        ctx.detach(&done, KeepCap { g: ctx.grant::<INSERT>()? })?;
        Ok("created")"""),
    d3=d3("job", f"""        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, Op::insert(7, "created"))?;
        db.commit(tx)?;
        tokio::spawn(async move {{ {SLEEP} let Ok(mut tx) = db.begin() else {{ return }}; let _ = db.run(&mut tx, &g, Op::insert(7, "late")); let _ = db.commit(tx); }});"""))

J12 = """struct KeepDb<T: Send + Sync + 'static> { db: &'static T }
impl<T: Send + Sync + 'static> Job for KeepDb<T> {
    fn run<'j, D: Db<'j>>(self, ctx: Ctx<'j>, db: &D) -> Result<(), SdkError> { let _ = self.db; Ok(()) }
}"""
add("E12", "detached job keeps the request's tenant db handle",
    d1=NA_DETACH,
    d2=d2("job", extra=J12, job_body="""        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, Op::insert(7, "created"))?;
        let done = db.commit(tx)?;
        ctx.detach(&done, KeepDb { db })?;
        Ok("created")"""),
    d3=d3("job", f"""        let db2 = db.clone();
        tokio::spawn(async move {{ {SLEEP} let Ok(g) = ctx.grant::<INSERT>() else {{ return }}; let Ok(mut tx) = db2.begin() else {{ return }}; let _ = db2.run(&mut tx, &g, Op::insert(9, "x")); let _ = db2.commit(tx); }});"""))

J12B = """struct KeepPrincipal { p: &'static Principal }
impl Job for KeepPrincipal {
    fn run<'j, D: Db<'j>>(self, ctx: Ctx<'j>, db: &D) -> Result<(), SdkError> { let _ = self.p.tenant(); Ok(()) }
}"""
add("E12b", "detached job keeps the request's &Principal (Sync, so only the lifetime can stop it)",
    d1=NA_DETACH,
    d2=d2("job", extra=J12B, job_body="""        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, Op::insert(7, "created"))?;
        let done = db.commit(tx)?;
        ctx.detach(&done, KeepPrincipal { p: ctx.principal() })?;
        Ok("created")"""),
    d3=d3("job", f"""        let p = ctx.clone();
        tokio::spawn(async move {{ {SLEEP} let _ = p.principal().tenant(); }});"""))

add("E13", "detached job enqueued before the transaction commits (effect before commit)",
    d1=NA_DETACH,
    d2=d2("job", job_body="""        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, Op::insert(7, "created"))?;
        ctx.detach(&tx, AuditJob { key: 7 })?;
        let done = db.commit(tx)?;
        Ok("created")"""),
    d3=d3("job", f"""        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, Op::insert(7, "created"))?;
        let (c2, d2) = (ctx.clone(), db.clone());
        tokio::spawn(async move {{ let Ok(g) = c2.grant::<INSERT>() else {{ return }}; let Ok(mut t) = d2.begin() else {{ return }}; let _ = d2.run(&mut t, &g, Op::insert(7, "audited")); let _ = d2.commit(t); }});
        db.commit(tx)?;"""))

add("E14", "WS session reuses the first message's Granted for every later message (no per-message re-derivation)",
    d1=d1("ws", """            let g = ctx.grant::<SELECT>()?;
            while let Some(m) = ws.recv().await {
                let line = { let mut tx = db.begin()?; db.run(&mut tx, &g, Op::select(1))?.len().to_string() };
                ws.send(line).await?;
            }"""),
    d2=d2("ws", state="g: Granted<'static, DataCap<SELECT>>", open_="        Ok(G { g: ctx.grant::<SELECT>()? })",
          next_="        let mut tx = db.begin()?;\n        let n = db.run(&mut tx, &self.g, Op::select(1))?.len();\n        Ok(WsReply::Send(vec![n.to_string()]))"),
    d3=d3("ws", """        let g = ctx.grant::<SELECT>()?;
        tokio::spawn(async move {
            while let Some(m) = inbox.recv().await {
                let Ok(mut tx) = db.begin() else { return };
                let n = db.run(&mut tx, &g, Op::select(1)).map(|r| r.len()).unwrap_or(0);
                if out.send(n.to_string()).await.is_err() { return }
            }
        });"""))

add("E15", "open Tx<Open> held across streamed chunks (writes after the response head is committed)",
    d1=d1("body", """            let g = ctx.grant::<INSERT>()?;
            let mut tx = db.begin()?;
            for i in 0..3u64 {
                out.send(i.to_string()).await?;
                db.run(&mut tx, &g, Op::insert(100 + i, "late"))?;
            }
            db.commit(tx)?;"""),
    d2=d2("body", state="tx: Tx<'static, Open>", open_="        Ok(G { tx: db.begin()? })"),
    d3=d3("body", """        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        tokio::spawn(async move {
            for i in 0..3u64 {
                if out.send(i.to_string()).await.is_err() { return }
                let _ = db.run(&mut tx, &g, Op::insert(100 + i, "late"));
            }
            let _ = db.commit(tx);
        });"""))

UAC = """let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, Op::insert(1, "a"))?;
        let done = db.commit(tx)?;
        db.run(&mut tx, &g, Op::insert(2, "dup"))?;"""
add("E16", "Tx used after commit",
    d1=d1("body", "            " + UAC.replace("\n        ", "\n            ")),
    d2=d2("job", job_body="        " + UAC + "\n        Ok(\"x\")"),
    d3=d3("job", "        " + UAC))

add("E17", "handler forges a Granted (struct literal) instead of asking the host",
    d1=d1("body", "            let g: Granted<'_, DataCap<INSERT>> = Granted { _c: PhantomData, _r: PhantomData };"),
    d2=d2("body", next_="        let g: Granted<'_, DataCap<INSERT>> = Granted { _c: PhantomData, _r: PhantomData };\n        Ok(Step::Done)"),
    d3=d3("body", "        let g = OwnedGranted::<INSERT>(PhantomData);"))

TM = f"let g: Granted<'static, DataCap<SELECT>> = unsafe {{ core::mem::transmute(ctx.grant::<SELECT>()?) }}; tokio::spawn(async move {{ {SLEEP} drop(g); }});"
add("E18", "unsafe transmute of Granted<'r> to Granted<'static>, then spawn",
    d1=d1("body", "            " + TM),
    d2=d2("body", next_="        " + TM + "\n        Ok(Step::Done)"),
    d3=d3("body", "        let c: OwnedCtx = unsafe { core::mem::transmute::<OwnedCtx, OwnedCtx>(ctx) };"))

add("E19", "WS outbound half moved into a spawned task that keeps writing with the session's capabilities",
    d1=d1("ws", f"            tokio::spawn(async move {{ {SLEEP} let _ = ws.send(\"late\".to_string()).await; }});"),
    d2=("NA", "D2 exposes no outbound handle to move: replies are return values of on_message; the nearest attempt is E2/E3 (rejected)"),
    d3=d3("ws", f"""        let (c2, o2) = (ctx.clone(), out.clone());
        tokio::spawn(async move {{ loop {{ {SLEEP} if c2.grant::<SELECT>().is_err() || o2.send("push".to_string()).await.is_err() {{ return }} }} }});"""))

# ---------------- controls: legitimate patterns that MUST compile (guards against over-rejection)
SCOPE = "let g = ctx.grant::<SELECT>()?; std::thread::scope(|s| { s.spawn(|| { let _ = &g; }); });"
add("C1", "CONTROL: std::thread::scope borrowing a Granted (joined before the scope ends)",
    d1=d1("body", "            " + SCOPE),
    d2=d2("body", next_="        " + SCOPE + "\n        Ok(Step::Done)"),
    d3=d3("body", "        " + SCOPE))
add("C2", "CONTROL: plain data (ids, strings) moved into tokio::spawn",
    d1=d1("body", f"            let tenant = ctx.principal().tenant(); tokio::spawn(async move {{ {SLEEP} let _ = tenant; }});"),
    d2=d2("body", next_=f"        let tenant = ctx.principal().tenant(); tokio::spawn(async move {{ {SLEEP} let _ = tenant; }});\n        Ok(Step::Done)"),
    d3=d3("body", f"        let tenant = ctx.principal().tenant(); tokio::spawn(async move {{ {SLEEP} let _ = tenant; }});"))

# ---------------- D3-strict: the naive spawn idiom written against F7's request-scoped types (no hatch)
STRICT = {
    "S1": ("naive spawn producer for a streamed body using F7 Ctx<'r>/&D", """struct H;
impl ScopedHandler for H {
    type Response = tokio::sync::mpsc::Receiver<String>;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<Self::Response, SdkError> {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            let Ok(g) = ctx.grant::<SELECT>() else { return };
            let Ok(mut t) = db.begin() else { return };
            if db.run(&mut t, &g, Op::select(0)).is_ok() { let _ = tx.send("row".to_string()).await; }
        });
        Ok(rx)
    }
}"""),
    "S2": ("naive SSE ticker task holding only the Granted", """struct H;
impl ScopedHandler for H {
    type Response = tokio::sync::mpsc::Receiver<String>;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<Self::Response, SdkError> {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let g = ctx.grant::<SELECT>()?;
        tokio::spawn(async move { let _g = g; let _ = tx.send("tick".to_string()).await; });
        Ok(rx)
    }
}"""),
    "S3": ("naive WS task holding Ctx for the session", """struct H;
impl ScopedHandler for H {
    type Response = tokio::sync::mpsc::Sender<String>;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<Self::Response, SdkError> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(8);
        tokio::spawn(async move { while let Some(_m) = rx.recv().await { let _ = ctx.grant::<SELECT>(); } });
        Ok(tx)
    }
}"""),
    "S4": ("naive detached audit task after commit using F7 Ctx<'r>", """struct H;
impl ScopedHandler for H {
    type Response = &'static str;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<&'static str, SdkError> {
        let g = ctx.grant::<INSERT>()?;
        let mut tx = db.begin()?;
        db.run(&mut tx, &g, Op::insert(7, "created"))?;
        db.commit(tx)?;
        tokio::spawn(async move { let Ok(g) = ctx.grant::<INSERT>() else { return }; let _ = g; });
        Ok("created")
    }
}"""),
}


def main():
    os.makedirs(OUT, exist_ok=True)
    for f in os.listdir(OUT):
        if f.endswith(".rs"):
            os.remove(os.path.join(OUT, f))
    table = {"mutants": {}, "strict": {}}
    for i, m in M.items():
        row = {"class": m["cls"], "cases": {}}
        for d in ("d1", "d2", "d3"):
            v = m[d]
            if isinstance(v, tuple):
                row["cases"][d] = {"na": v[1]}
                continue
            name = f"{d}_{i}"
            with open(os.path.join(OUT, name + ".rs"), "w") as fh:
                fh.write(f"// {i} [{d}] {m['cls']}\n" + hoist(v))
            row["cases"][d] = {"file": f"mutants/{name}.rs"}
        table["mutants"][i] = row
    for i, (cls, src) in STRICT.items():
        name = f"d3strict_{i}"
        with open(os.path.join(OUT, name + ".rs"), "w") as fh:
            fh.write(f"// {i} [d3-strict] {cls}\n" + PRE + src + MAIN)
        table["strict"][i] = {"class": cls, "file": f"mutants/{name}.rs"}
    with open(os.path.join(HERE, "results", "corpus.json"), "w") as fh:
        json.dump(table, fh, indent=1)
    n = sum(1 for f in os.listdir(OUT) if f.endswith(".rs"))
    print(f"wrote {n} case files")


if __name__ == "__main__":
    main()
