//! Host building blocks without a principal: the blocking pool (X-11), reply serialization (sdk-trybuild M4),
//! endowment conversion (INV-NONEMPTY), idempotency leases (P4-state-002 finding) and F10 frames.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use aegis_adapter_host::host::endow::{CapParts, Endowment, capset};
use aegis_adapter_host::host::lease::{Admission, Idem};
use aegis_adapter_host::host::oop::{MAX_FRAME, encode_request};
use aegis_adapter_host::host::pool::{BlockingPool, Rejected};
use aegis_adapter_host::host::reply::{self, FIXED_HEADERS, Json, TEXT_PLAIN};
use aegis_adapter_host::host::session::endowment_ops;
use aegis_data_ir::{CapSet, Op, OpKind, Pred, Value};
use aegis_sdk::SdkError;
use aegis_state::{IdemKey, Outcome, State};
use aegis_types::TenantId;

// ------------------------------------------------------------------------------------------------ pool

#[test]
fn pool_rejects_at_once_when_full_and_never_runs_inline() -> Result<(), String> {
    let pool = BlockingPool::new(2).map_err(|e| e.to_string())?;
    let me = std::thread::current().id();
    let (go1, wait1) = mpsc::channel::<()>();
    let (go2, wait2) = mpsc::channel::<()>();
    let t1 = pool.try_run(move || (wait1.recv().is_ok(), std::thread::current().id())).map_err(|e| e.to_string())?;
    let t2 = pool.try_run(move || (wait2.recv().is_ok(), std::thread::current().id())).map_err(|e| e.to_string())?;
    // Full: refused immediately (never queued), and the refused closure never runs.
    let start = Instant::now();
    let (ran_tx, ran_rx) = mpsc::channel::<()>();
    assert_eq!(pool.try_run(move || ran_tx.send(())).err(), Some(Rejected));
    assert!(start.elapsed() < Duration::from_millis(500));
    assert!(ran_rx.recv_timeout(Duration::from_millis(50)).is_err());
    let _ = go1.send(());
    let (ok, tid) = t1.wait().map_err(|_| "lost")?;
    assert!(ok);
    assert_ne!(tid, me, "pool task ran on the caller's thread");
    // A result seen means its worker is idle again: admission succeeds at once.
    let t3 = pool.try_run(|| 7).map_err(|e| e.to_string())?;
    assert_eq!(t3.wait().map_err(|_| "lost")?, 7);
    let _ = go2.send(());
    assert!(t2.wait().map_err(|_| "lost")?.0);
    assert!(BlockingPool::new(0).is_err());
    Ok(())
}

#[test]
fn reserved_slot_dropped_unused_returns_the_worker() -> Result<(), String> {
    let pool = BlockingPool::new(1).map_err(|e| e.to_string())?;
    {
        let _slot = pool.reserve().map_err(|e| e.to_string())?;
        assert_eq!(pool.try_run(|| ()).err(), Some(Rejected));
    }
    assert_eq!(pool.try_run(|| 1).map_err(|e| e.to_string())?.wait().map_err(|_| "lost")?, 1);
    Ok(())
}

// ------------------------------------------------------------------------------------------------ M4

#[test]
fn handler_markup_string_is_never_served_as_html() {
    let markup = String::from("<!doctype html><script>alert(document.cookie)</script>");
    let r = reply::reply::<String>(Ok(markup.clone()));
    assert_eq!(r.status, 200);
    assert_eq!(r.content_type(), TEXT_PLAIN);
    assert!(!r.content_type().contains("html"));
    assert_eq!(r.body, markup.as_bytes());
    let h = r.headers();
    assert!(h.contains(&("content-type", "text/plain; charset=utf-8")));
    assert!(h.contains(&("x-content-type-options", "nosniff")));
    assert!(FIXED_HEADERS.iter().all(|f| h.contains(f)));
    // Every serializable response type has a fixed, non-HTML type and nosniff.
    for r in [
        reply::reply::<&'static str>(Ok("<b>x</b>")),
        reply::reply::<Vec<u8>>(Ok(b"<html>".to_vec())),
        reply::reply::<Json>(Ok(Json("\"<script>\"".into()))),
        reply::reply::<()>(Ok(())),
        reply::reply::<String>(Err(SdkError::Denied)),
    ] {
        assert!(!r.content_type().contains("html"), "{r:?}");
        assert!(r.headers().contains(&("x-content-type-options", "nosniff")));
    }
    // W6: denied is uniform.
    assert_eq!(reply::reply::<String>(Err(SdkError::Denied)).status, 404);
}

// ------------------------------------------------------------------------------------------------ endowment

fn part(backend: &str, collection: &str, ops: u8, fields: Vec<u32>) -> CapParts {
    CapParts { backend: backend.into(), collection: collection.into(), ops_bits: ops, fields }
}

#[test]
fn endowment_conversion_never_widens() {
    // Absent, failed and empty: no CapSet (deny), never Unrestricted.
    for e in [Endowment::Absent, Endowment::Failed, Endowment::Caps(vec![])] {
        let c = capset(&e);
        assert_eq!(c.caps, None, "{e:?}");
        assert_eq!(endowment_ops(c.caps.as_ref()), 0);
    }
    assert!(!capset(&Endowment::Caps(vec![])).boot_ok());
    // Unrestricted only from the explicit variant.
    assert_eq!(capset(&Endowment::Unrestricted).caps, Some(CapSet::Unrestricted));
    // Field for field (aegis-config ResolvedCap) into DataCap.
    let c = capset(&Endowment::Caps(vec![part("main", "notes", 0b101, vec![3, 1, 2])]));
    assert!(c.boot_ok());
    let Some(CapSet::Caps(caps)) = &c.caps else { unreachable!("caps expected: {c:?}") };
    let d = caps.as_slice();
    assert_eq!(d.len(), 1);
    assert!(d.iter().all(|x| x.backend() == "main" && x.collection() == "notes" && x.ops().bits() == 5));
    assert!(d.iter().all(|x| x.columns() == [1, 2, 3]));
    assert_eq!(endowment_ops(c.caps.as_ref()), 0b101);
    // Unrepresentable parts grant nothing and fail the boot check; they never become "all".
    for bad in [
        part("main", "notes", 0, vec![1]),
        part("main", "notes", 1, vec![]),
        part("*", "notes", 1, vec![1]),
        part("main", "", 1, vec![1]),
        part("MAIN", "notes", 1, vec![1]),
    ] {
        let c = capset(&Endowment::Caps(vec![bad.clone()]));
        assert_eq!(c.caps, None, "{bad:?}");
        assert_eq!(c.inert, 1);
        assert!(!c.boot_ok());
        let mixed = capset(&Endowment::Caps(vec![bad, part("main", "notes", 1, vec![1])]));
        assert_eq!(mixed.inert, 1);
        assert!(!mixed.boot_ok());
        let Some(CapSet::Caps(m)) = &mixed.caps else { unreachable!("caps expected") };
        assert_eq!(m.as_slice().len(), 1);
    }
}

// ------------------------------------------------------------------------------------------------ leases

fn temp_state(tag: &str) -> Result<(std::path::PathBuf, State), String> {
    let dir = std::env::temp_dir().join(format!("aegis-host-lease-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let st = State::open(&dir).map_err(|e| e.to_string())?;
    Ok((dir, st))
}

#[test]
fn every_lease_ends_on_every_path() -> Result<(), String> {
    let (dir, st) = temp_state("paths")?;
    let idem = Idem::new(st);
    let key = IdemKey::new(b"principal-1", b"key-1").map_err(|e| e.to_string())?;
    let digest = b"d1";

    // Cancellation: the guard is dropped without commit/abort (a dropped future, a pool rejection, a timeout).
    let Admission::Run(g) = idem.begin(&key, digest).map_err(|e| e.to_string())? else { return Err("new".into()) };
    assert!(matches!(idem.begin(&key, digest), Ok(Admission::InFlight)));
    drop(g);
    assert_eq!(idem.held_count(), 0);
    // The cancelled request's key is reusable afterwards.
    let Admission::Run(g) = idem.begin(&key, digest).map_err(|e| e.to_string())? else { return Err("reusable".into()) };
    // Explicit abort (handler error).
    g.abort();
    assert_eq!(idem.held_count(), 0);
    // Commit: latched; a replay serves the stored outcome and runs nothing.
    let Admission::Run(g) = idem.begin(&key, digest).map_err(|e| e.to_string())? else { return Err("new2".into()) };
    let out = Outcome { status: 200, body: b"done".to_vec() };
    g.commit(out.clone(), false).map_err(|e| e.to_string())?;
    assert_eq!(idem.held_count(), 0);
    match idem.begin(&key, digest).map_err(|e| e.to_string())? {
        Admission::Replay(o) => assert_eq!(o, out),
        other => return Err(format!("expected replay, got {other:?}")),
    }
    assert!(matches!(idem.begin(&key, b"other"), Ok(Admission::Conflict)));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn lease_in_a_rejected_pool_task_is_aborted() -> Result<(), String> {
    let (dir, st) = temp_state("pool")?;
    let idem = Idem::new(st);
    let key = IdemKey::new(b"p", b"k").map_err(|e| e.to_string())?;
    let pool = BlockingPool::new(1).map_err(|e| e.to_string())?;
    let (go, wait) = mpsc::channel::<()>();
    let busy = pool.try_run(move || wait.recv().is_ok()).map_err(|e| e.to_string())?;
    let Admission::Run(g) = idem.begin(&key, b"d").map_err(|e| e.to_string())? else { return Err("new".into()) };
    // The task owning the guard is refused: dropped unrun, so the lease is aborted.
    assert_eq!(pool.try_run(move || g.abort()).err(), Some(Rejected));
    assert_eq!(idem.held_count(), 0);
    assert!(matches!(idem.begin(&key, b"d"), Ok(Admission::Run(_))));
    let _ = go.send(());
    assert!(busy.wait().map_err(|_| "lost")?);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

// ------------------------------------------------------------------------------------------------ F10

#[test]
fn f10_request_frame_is_positional_and_capped() -> Result<(), String> {
    let op = Op {
        tenant: TenantId::new(300).map_err(|_| "t")?,
        collection: "ab".into(),
        kind: OpKind::Update,
        filter: Pred::Eq(1, Value::Int(-1)),
        writes: vec![(2, Value::Str("x".into()))],
        returning: vec![],
    };
    let f = encode_request(5, &op).map_err(|e| format!("{e:?}"))?;
    // [0=request, req 5, tenant 300 = ac 02, "ab", kind 2, eq(2) f1 int(0) zigzag(-1)=1, writes [ (2, str(1) "x") ], []]
    assert_eq!(f, vec![0, 5, 0xac, 0x02, 2, b'a', b'b', 2, 2, 1, 0, 1, 1, 2, 1, 1, b'x', 0]);
    let big = Op { writes: vec![(2, Value::Str("y".repeat(MAX_FRAME)))], ..op };
    assert!(encode_request(1, &big).is_err());
    Ok(())
}
