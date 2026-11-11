//! monban-adapter-host's Host API with real principals (monban-token Tier-0 path): M4 end to end, leases on the
//! cancellation / rejection / error / success paths, and the monban-config → endowment → CapSet boot conversion.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use monban_adapter_host::host::endow::{CapParts, Endowment, capset};
use monban_adapter_host::host::lease::{Admission, Idem};
use monban_adapter_host::host::{Backends, BlockingPool, CancelToken, Host, SessionHandle, reply};
use monban_config::{
    Backend as CfgBackend, FieldId, ResolvedData, ResolvedRoute, SchemaProvider, Unresolved, parse_config,
};
use monban_data_ir::{CapSet, Op};
use monban_sdk::{Ctx, ScopedHandler, SdkError, TenantDb};
use monban_state::{IdemKey, State};
use monban_token::{Caveat, Req, Tier0Table};
use monban_types::{Principal, RouteId, TenantId};

fn principal(t: u64) -> Result<Principal, String> {
    let tenant = TenantId::new(t).map_err(|_| "tenant")?;
    let mut table = Tier0Table::new();
    let h = table.insert(tenant, b"test", vec![Caveat::Tenant(t)]).map_err(|e| format!("{e:?}"))?;
    let req = Req {
        aud: String::new(),
        ops: 0,
        res: vec![],
        tenant: t,
        holder: vec![],
        tool: String::new(),
        args: vec![],
        now: 0,
    };
    table.lookup(h.as_bytes(), &req).map_err(|e| format!("{e:?}"))
}

fn session(t: u64) -> Result<SessionHandle, String> {
    Ok(SessionHandle::new(
        principal(t)?,
        RouteId::new(1).map_err(|_| "route")?,
        Some(Arc::new(CapSet::Unrestricted)),
        0x1f,
    ))
}

struct NoopBackend;
impl monban_sdk::host::Backend for NoopBackend {
    type Rows = ();
    fn begin(&self) -> Result<(), SdkError> {
        Ok(())
    }
    fn run(&self, _op: Op) -> Result<(), SdkError> {
        Ok(())
    }
    fn commit(&self) -> Result<(), SdkError> {
        Ok(())
    }
    fn rollback(&self) {}
}

struct Noop;
impl Backends for Noop {
    type Backend = NoopBackend;
    fn open(&self, _s: &SessionHandle, _c: &CancelToken) -> Result<NoopBackend, SdkError> {
        Ok(NoopBackend)
    }
}

type Gate = (Mutex<mpsc::Sender<()>>, Mutex<mpsc::Receiver<()>>);

/// Returns markup, or an error, and can block until released.
struct App {
    body: Result<String, SdkError>,
    gate: Option<Gate>,
    calls: Arc<AtomicUsize>,
}

impl ScopedHandler for App {
    type Response = String;
    fn handle<'r, D: TenantDb<'r>>(&self, _ctx: Ctx<'r>, db: &D) -> Result<String, SdkError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some((started, release)) = &self.gate {
            let _ = started.lock().map(|s| s.send(()));
            let _ = release.lock().map(|r| r.recv());
        }
        let tx = db.begin()?;
        db.commit(tx)?;
        self.body.clone()
    }
}

fn app(body: Result<String, SdkError>) -> (Arc<App>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    (Arc::new(App { body, gate: None, calls: Arc::clone(&calls) }), calls)
}

fn idem(tag: &str) -> Result<(std::path::PathBuf, Idem), String> {
    let dir = std::env::temp_dir().join(format!("host-subject-api-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok((dir.clone(), Idem::new(State::open(&dir).map_err(|e| e.to_string())?)))
}

#[test]
fn m4_markup_from_a_handler_is_served_as_text_plain_with_nosniff() -> Result<(), String> {
    let host = Host::new(BlockingPool::new(2).map_err(|e| e.to_string())?, Noop);
    let s = session(7)?;
    let (a, _) = app(Ok("<script>alert(1)</script>".into()));
    let o = host.call(a, &s).map_err(|e| e.to_string())?.wait().map_err(|_| "lost")?;
    let r = reply::reply(o.result);
    assert_eq!(r.content_type(), "text/plain; charset=utf-8");
    assert!(r.headers().contains(&("x-content-type-options", "nosniff")));
    assert_eq!(r.body, b"<script>alert(1)</script>");
    // Through the idempotent path too (the latched outcome is the same body; the content type is the host's).
    let (dir, idem) = idem("m4")?;
    let key = IdemKey::new(b"p7", b"k").map_err(|e| e.to_string())?;
    let Admission::Run(g) = idem.begin(&key, b"d").map_err(|e| e.to_string())? else { return Err("new".into()) };
    let (a, _) = app(Ok("<b>x</b>".into()));
    let ir = host.call_idempotent(a, &s, g).map_err(|e| e.to_string())?.wait().map_err(|_| "lost")?;
    assert_eq!(ir.reply.content_type(), "text/plain; charset=utf-8");
    assert!(ir.reply.headers().contains(&("x-content-type-options", "nosniff")));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn idempotent_calls_end_their_lease_on_every_path() -> Result<(), String> {
    let (dir, idem) = idem("paths")?;
    let host = Host::new(BlockingPool::new(1).map_err(|e| e.to_string())?, Noop);
    let s = session(9)?;
    let key = IdemKey::new(b"p9", b"key").map_err(|e| e.to_string())?;

    // 1. Handler error: aborted, key free.
    let Admission::Run(g) = idem.begin(&key, b"d").map_err(|e| e.to_string())? else { return Err("new".into()) };
    let (a, _) = app(Err(SdkError::Conflict));
    let ir = host.call_idempotent(a, &s, g).map_err(|e| e.to_string())?.wait().map_err(|_| "lost")?;
    assert!(ir.latched.is_none());
    assert_eq!(ir.reply.status, 409);
    assert_eq!(idem.held_count(), 0);

    // 2. Cancelled request: the caller drops the ticket while the handler runs. The handler finishes at its next
    //    host-call boundary and the lease ends; the key is not left InFlight.
    let Admission::Run(g) = idem.begin(&key, b"d").map_err(|e| e.to_string())? else { return Err("reuse".into()) };
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let gated = Arc::new(App {
        body: Err(SdkError::Unavailable),
        gate: Some((Mutex::new(started_tx), Mutex::new(release_rx))),
        calls: Arc::clone(&calls),
    });
    let ticket = host.call_idempotent(gated, &s, g).map_err(|e| e.to_string())?;
    started_rx.recv().map_err(|e| e.to_string())?;
    drop(ticket); // cancellation
    assert!(matches!(idem.begin(&key, b"d"), Ok(Admission::InFlight)));
    // 3. Pool rejection while that request holds the only worker: the second guard is dropped unrun -> aborted.
    let other = IdemKey::new(b"p9", b"other").map_err(|e| e.to_string())?;
    let Admission::Run(g2) = idem.begin(&other, b"d").map_err(|e| e.to_string())? else { return Err("new".into()) };
    let (a, never) = app(Ok("x".into()));
    assert!(host.call_idempotent(a, &s, g2).is_err());
    assert_eq!(never.load(Ordering::SeqCst), 0);
    assert!(matches!(idem.begin(&other, b"d"), Ok(Admission::Run(_))), "rejected request's key must be free");
    let _ = release_tx.send(());
    // Wait until the cancelled handler's task has ended its lease (the pool worker is free again).
    let mut freed = false;
    for _ in 0..500 {
        if let Ok(t) = host.pool().try_run(|| ()) {
            let _ = t.wait();
            freed = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    assert!(freed);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(idem.held_count(), 0);
    // The cancelled request's key is reusable afterwards.
    let Admission::Run(g) = idem.begin(&key, b"d").map_err(|e| e.to_string())? else { return Err("reusable".into()) };

    // 4. Success: committed, then replayed without running again.
    let (a, ran) = app(Ok("done".into()));
    let ir = host.call_idempotent(a, &s, g).map_err(|e| e.to_string())?.wait().map_err(|_| "lost")?;
    assert!(matches!(ir.latched, Some(Ok(_))));
    match idem.begin(&key, b"d").map_err(|e| e.to_string())? {
        Admission::Replay(o) => assert_eq!((o.status, o.body), (200, b"done".to_vec())),
        other => return Err(format!("expected replay, got {other:?}")),
    }
    assert_eq!(ran.load(Ordering::SeqCst), 1);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn revoked_session_is_denied() -> Result<(), String> {
    let host = Host::new(BlockingPool::new(1).map_err(|e| e.to_string())?, Noop);
    let s = session(11)?;
    s.revoke();
    let (a, calls) = app(Ok("x".into()));
    let o = host.call(a, &s).map_err(|e| e.to_string())?.wait().map_err(|_| "lost")?;
    assert_eq!(o.result, Err(SdkError::Denied));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

// ------------------------------------------------------------------------------------------------ config

const DOC: &str = r#"{"v":1,
 "listeners":[{"name":"web","bind":"127.0.0.1:8443","profile":"P-PUBLIC-WEB"}],
 "vhosts":[{"host":"localhost","routes":[
   {"id":1,"path":"/notes","to":{"upstream":"app"},"authz":"notes",
    "data":[{"backend":"main","collection":"notes","ops":["update","select"],"columns":["id","body","owner"]},
            {"backend":"cache","collection":"sessions","ops":["select"],"columns":["k"]}]},
   {"id":2,"path":"/","to":{"static":"/srv"}},
   {"id":3,"path":"/admin","to":{"static":"/srv"},"data":"unrestricted"}]}],
 "data":{"backends":[
   {"id":"main","engine":"postgres","dsn_ref":"env:AEGIS_PG_DSN","pin":"pg18"},
   {"id":"cache","engine":"valkey","dsn_ref":"cred:valkey.dsn","pin":"valkey"}]}}"#;

struct Fixed;
impl SchemaProvider for Fixed {
    fn field(&self, _b: &CfgBackend, _c: &str, column: &str) -> Result<FieldId, Unresolved> {
        match column {
            "k" => Ok(0),
            "id" => Ok(1),
            "body" => Ok(2),
            "owner" => Ok(3),
            _ => Err(Unresolved::NoColumn),
        }
    }
}

/// The assembly's mapping (field for field): monban-config `ResolvedData` of a route → host `Endowment`. A route
/// that is not listed has no data block.
fn endowment_of(routes: &[ResolvedRoute], host: &str, id: u64) -> Endowment {
    match routes.iter().find(|r| r.host == host && r.route_id == id).map(|r| &r.data) {
        None => Endowment::Absent,
        Some(ResolvedData::Unrestricted) => Endowment::Unrestricted,
        Some(ResolvedData::Caps(v)) => Endowment::Caps(
            v.iter()
                .map(|c| CapParts {
                    backend: c.backend.clone(),
                    collection: c.collection.clone(),
                    ops_bits: c.ops_bits,
                    fields: c.fields.clone(),
                })
                .collect(),
        ),
    }
}

#[test]
fn config_resolved_routes_convert_to_capsets() -> Result<(), String> {
    let cfg = parse_config(DOC.as_bytes()).map_err(|e| e.to_string())?;
    let routes = cfg.resolve_data(&Fixed).map_err(|e| e.to_string())?;
    // Route 1: two caps, exactly as configured.
    let c1 = capset(&endowment_of(&routes, "localhost", 1));
    assert!(c1.boot_ok());
    let Some(CapSet::Caps(caps)) = &c1.caps else { return Err(format!("caps expected: {c1:?}")) };
    let got: Vec<(String, String, u8, Vec<u32>)> = caps
        .as_slice()
        .iter()
        .map(|d| (d.backend().to_string(), d.collection().to_string(), d.ops().bits(), d.columns().to_vec()))
        .collect();
    assert_eq!(
        got,
        vec![
            ("main".to_string(), "notes".to_string(), 0b101, vec![1, 2, 3]),
            ("cache".to_string(), "sessions".to_string(), 0b1, vec![0]),
        ]
    );
    // Route 2: no data block -> no CapSet (deny), never unrestricted.
    let c2 = capset(&endowment_of(&routes, "localhost", 2));
    assert_eq!(c2.caps, None);
    // Route 3: only the explicit literal gives Unrestricted.
    assert_eq!(capset(&endowment_of(&routes, "localhost", 3)).caps, Some(CapSet::Unrestricted));
    Ok(())
}
