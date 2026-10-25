//! Runtime oracle on tokio current-thread. Every host driver future OWNS its request scope and is run through
//! `tokio::spawn` (requires `Send + 'static`), proving the host can run `'r`-scoped handlers on a `'static`
//! executor without leaking any capability. Also measures the semantic difference that matters for long-lived
//! sessions: whether a capability revoked mid-session stops being usable.
#![forbid(unsafe_code)]

use corpus::{d1app, d2app, d3app};
use core::future::Future;
use f7x::host::{self, Host};
use f7x::{Ctx, Db, Op, SdkError, INSERT, SELECT};
use std::sync::Arc;

const ALL: u8 = SELECT | INSERT;

fn host3() -> Host {
    let h = Host::new();
    for (k, v) in [(1, "a"), (2, "b"), (3, "c")] {
        assert_eq!(h.seed(10, k, v), Ok(()));
    }
    assert_eq!(h.seed(20, 1, "OTHER-TENANT"), Ok(()));
    h
}

async fn spawned<T: Send + 'static>(f: impl Future<Output = T> + Send + 'static) -> T {
    match tokio::spawn(f).await {
        Ok(v) => v,
        Err(e) => panic!("task failed: {e}"),
    }
}

fn ws_in() -> Vec<String> {
    ["get:1", "put:9:z", "get:9"].iter().map(|s| s.to_string()).collect()
}

#[tokio::test(flavor = "current_thread")]
async fn d1_body_sse_ws_run_in_static_task_without_leak() {
    let h = host3();
    let (c, _) = h.connect(1, 10, ALL);
    assert_eq!(spawned(host::d1_body(c, Arc::new(d1app::ListBody))).await, (vec!["a".into(), "b".into(), "c".into()], Ok(())));
    let (c, _) = h.connect(1, 10, ALL);
    let (ev, r) = spawned(host::d1_sse(c, Arc::new(d1app::RowEvents))).await;
    assert_eq!((ev.iter().map(|e| e.id).collect::<Vec<_>>(), r), (vec![1, 2, 3], Ok(())));
    let (c, _) = h.connect(1, 10, ALL);
    let (out, r) = spawned(host::d1_ws(c, Arc::new(d1app::KvSocket), ws_in(), |_| {})).await;
    assert_eq!((out, r), (vec!["a".to_string(), "ok".into(), "z".into()], Ok(())));
}

#[tokio::test(flavor = "current_thread")]
async fn d2_all_four_features_with_per_step_ctx() {
    let h = host3();
    let (c, _) = h.connect(1, 10, ALL);
    assert_eq!(spawned(host::d2_body(c, Arc::new(d2app::ListBody))).await, (vec!["a".into(), "b".into(), "c".into()], Ok(())));
    // SSE with resume after id 1
    let (c, _) = h.connect(1, 10, ALL);
    let (ev, r) = spawned(host::d2_sse(c, Arc::new(d2app::RowEvents), Some(1))).await;
    assert_eq!((ev.iter().map(|e| e.id).collect::<Vec<_>>(), r), (vec![2, 3], Ok(())));
    let (c, _) = h.connect(1, 10, ALL);
    let (out, r) = spawned(host::d2_ws(c, Arc::new(d2app::KvSocket), ws_in(), |_| {})).await;
    assert_eq!((out, r), (vec!["a".to_string(), "ok".into(), "z".into()], Ok(())));
    // detached: enqueued only after commit, run later by the host with a fresh Ctx
    let (c, _) = h.connect(1, 10, ALL);
    assert_eq!(host::scoped(c, &d2app::CreateThenAudit), Ok("created"));
    assert_eq!(h.queued_jobs(), 1);
    assert_eq!(h.run_jobs(), vec![Ok(())]);
    let rows = h.rows(10).unwrap_or_default();
    assert!(rows.contains(&(7, "created".into())) && rows.contains(&(7, "audited".into())));
}

#[tokio::test(flavor = "current_thread")]
async fn d3_all_four_features_via_handler_spawn() {
    let h = host3();
    let (c, _) = h.connect(1, 10, ALL);
    assert_eq!(spawned(host::d3_body(c, Arc::new(d3app::ListBody))).await, (vec!["a".into(), "b".into(), "c".into()], Ok(())));
    let (c, _) = h.connect(1, 10, ALL);
    let (ev, _) = spawned(host::d3_sse(c, Arc::new(d3app::RowEvents))).await;
    assert_eq!(ev.iter().map(|e| e.id).collect::<Vec<_>>(), vec![1, 2, 3]);
    let (c, _) = h.connect(1, 10, ALL);
    let (out, _) = spawned(host::d3_ws(c, Arc::new(d3app::KvSocket), vec!["get:2".into()])).await;
    assert_eq!(out, vec!["b".to_string()]);
    let (c, _) = h.connect(1, 10, ALL);
    assert_eq!(host::d3_job(c, &d3app::CreateThenAudit), Ok(()));
    tokio::task::yield_now().await;
    assert!(h.rows(10).unwrap_or_default().contains(&(7, "audited".into())));
}

// ---------------- revocation of ONE capability mid-session (session itself stays valid)

/// The accepted D1 mutant E14: grant once, reuse for every message.
struct D1Stale;
impl f7x::d1::WsHandler for D1Stale {
    fn session<'r, D: Db<'r>>(
        &'r self,
        ctx: Ctx<'r>,
        db: &'r D,
        mut ws: f7x::d1::WsSession<'r>,
    ) -> impl Future<Output = Result<(), SdkError>> + Send + 'r {
        async move {
            let g = ctx.grant::<SELECT>()?;
            while let Some(_m) = ws.recv().await {
                let line = {
                    let mut tx = db.begin()?;
                    db.run(&mut tx, &g, Op::select(1))?.into_iter().map(|(_, v)| v).collect::<String>()
                };
                ws.send(line).await?;
            }
            Ok(())
        }
    }
}

fn gets() -> Vec<String> {
    vec!["get:1".into(), "get:1".into(), "get:1".into()]
}

#[tokio::test(flavor = "current_thread")]
async fn cap_revoked_mid_ws_session() {
    let h = host3();
    // D1 baseline (re-grants per message, by convention): stops after revocation.
    let (c, e) = h.connect(1, 10, ALL);
    let (out, _) = spawned(host::d1_ws(c, Arc::new(d1app::KvSocket), gets(), move |i| if i == 1 { e.revoke_cap(SELECT) })).await;
    assert_eq!(out, vec!["a".to_string(), "err:Denied".into(), "err:Denied".into()]);
    // D1 stale holder (E14, compiles): keeps reading after revocation.
    let (c, e) = h.connect(1, 10, ALL);
    let (out, _) = spawned(host::d1_ws(c, Arc::new(D1Stale), gets(), move |i| if i == 1 { e.revoke_cap(SELECT) })).await;
    assert_eq!(out, vec!["a".to_string(), "a".into(), "a".into()], "D1 E14: stale grant still usable");
    // D2 (holding is impossible by construction): stops after revocation.
    let (c, e) = h.connect(1, 10, ALL);
    let (out, _) = spawned(host::d2_ws(c, Arc::new(d2app::KvSocket), gets(), move |i| if i == 1 { e.revoke_cap(SELECT) })).await;
    assert_eq!(out, vec!["a".to_string(), "err:Denied".into(), "err:Denied".into()]);
}

#[tokio::test(flavor = "current_thread")]
async fn session_revoked_mid_stream_fails_closed_in_d1_and_d2() {
    let h = host3();
    let (c, e) = h.connect(1, 10, ALL);
    let (out, r) = spawned(host::d1_ws(c, Arc::new(d1app::KvSocket), gets(), move |i| if i == 1 { e.revoke_session() })).await;
    assert_eq!((out.len(), r), (1, Err(SdkError::Unavailable)));
    let (c, e) = h.connect(1, 10, ALL);
    let (out, r) = spawned(host::d2_ws(c, Arc::new(d2app::KvSocket), gets(), move |i| if i == 1 { e.revoke_session() })).await;
    assert_eq!((out.len(), r), (1, Err(SdkError::Unavailable)));
}

/// The accepted D3 mutant E11: detached task holds the request's grant.
struct D3KeepCap;
impl f7x::d3::JobHandler for D3KeepCap {
    fn handle(&self, ctx: f7x::d3::OwnedCtx, db: f7x::d3::OwnedDb) -> Result<(), SdkError> {
        let g = ctx.grant::<INSERT>()?;
        tokio::spawn(async move {
            let Ok(mut tx) = db.begin() else { return };
            let _ = db.run(&mut tx, &g, Op::insert(8, "late-write"));
            let _ = db.commit(tx);
        });
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn detached_job_after_session_revocation() {
    // D2: job runs with a re-derived ctx; a revoked session denies it.
    let h = host3();
    let (c, e) = h.connect(1, 10, ALL);
    assert_eq!(host::scoped(c, &d2app::CreateThenAudit), Ok("created"));
    e.revoke_session();
    assert_eq!(h.run_jobs(), vec![Err(SdkError::Denied)]);
    assert!(!h.rows(10).unwrap_or_default().contains(&(7, "audited".into())));
    // D3 E11: the held grant outlives the revoked session and the write lands.
    let h = host3();
    let (c, e) = h.connect(1, 10, ALL);
    assert_eq!(host::d3_job(c, &D3KeepCap), Ok(()));
    e.revoke_session();
    tokio::task::yield_now().await;
    assert!(h.rows(10).unwrap_or_default().contains(&(8, "late-write".into())), "D3 E11: write after revocation");
}

#[tokio::test(flavor = "current_thread")]
async fn tenant_binding_holds_in_all_designs() {
    let h = host3();
    let (c, _) = h.connect(2, 20, ALL);
    assert_eq!(spawned(host::d1_body(c, Arc::new(d1app::ListBody))).await.0, vec!["OTHER-TENANT".to_string()]);
    let (c, _) = h.connect(2, 20, ALL);
    assert_eq!(spawned(host::d2_body(c, Arc::new(d2app::ListBody))).await.0, vec!["OTHER-TENANT".to_string()]);
    let (c, _) = h.connect(2, 20, ALL);
    assert_eq!(spawned(host::d3_body(c, Arc::new(d3app::ListBody))).await.0, vec!["OTHER-TENANT".to_string()]);
}
