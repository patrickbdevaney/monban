//! IDEMP-R through the assembly (P8-bin-002, PREFLIGHT R12): F8 `state.idempotency_retention_s` read by
//! [`super::boot`] and applied to the in-band SQLite `monban_idem` (lookup, outcome write, boot purge, periodic purge).
//! Every case here fails if `boot` stops passing the retention on (the lookup then replays an expired outcome and the
//! purge deletes nothing).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};

use monban_adapter_host::dispatch::{EngineError, Executor, ScopeInfo};
use monban_adapter_host::host::CancelToken;
use monban_types::TenantId;

use super::retention::now_s;
use super::scope::{EngineHandle, HostSql, Idem};
use super::{DataPlane, boot, spawn_purge};
use crate::shared::Mutants;

struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp(name: &str) -> Tmp {
    let p = std::env::temp_dir().join(format!("monban-bin-idemp-r-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    Tmp(p)
}

fn keyring(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join("keyring.json");
    std::fs::write(&p, format!("{{\"keys\":[{{\"kid\":\"01\",\"key\":\"{}\"}}]}}", "ab".repeat(32))).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

/// The native-e2e SQLite provisioning (notes in WAL), plus an `monban_idem` already carrying the stamp when asked.
fn db(dir: &Path, stamped: bool) -> PathBuf {
    let p = dir.join("notes.db");
    let c = rusqlite::Connection::open(&p).unwrap();
    c.execute_batch(
        "PRAGMA journal_mode=WAL; CREATE TABLE notes(tenant TEXT NOT NULL COLLATE BINARY, id TEXT NOT NULL COLLATE \
         BINARY, body TEXT NOT NULL, PRIMARY KEY(tenant, id)) WITHOUT ROWID;",
    )
    .unwrap();
    if stamped {
        c.execute_batch(
            "CREATE TABLE monban_idem (principal TEXT NOT NULL COLLATE BINARY, k TEXT NOT NULL COLLATE BINARY, \
             status INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY (principal, k)) WITHOUT ROWID; \
             ALTER TABLE monban_idem ADD COLUMN committed_at INTEGER;",
        )
        .unwrap();
    }
    p
}

fn config(backend: &str, state: Option<u64>) -> monban_config::Config {
    let state = state.map(|r| format!(",\"state\":{{\"idempotency_retention_s\":{r}}}")).unwrap_or_default();
    let doc = format!(
        "{{\"v\":1,\"listeners\":[{{\"name\":\"pub\",\"bind\":\"127.0.0.1:1\",\"profile\":\"P-PUBLIC-WEB\",\
         \"alpn\":[\"h2\",\"http/1.1\"]}}],\"admin\":{{\"bind\":\"127.0.0.1:2\"}},\"data\":{{\"backends\":[{backend}]}},\
         \"vhosts\":[{{\"host\":\"notes.test\",\"routes\":[{{\"id\":1,\"path\":\"/sq/\",\"to\":{{\"upstream\":\
         \"app:notes\"}},\"authz\":\"allow-all\",\"data\":[{{\"backend\":\"sq\",\"collection\":\"notes\",\"ops\":\
         [\"select\",\"insert\"],\"columns\":[\"id\",\"body\"]}}]}}]}}]{state}}}"
    );
    monban_config::parse_config(doc.as_bytes()).unwrap()
}

fn sqlite_backend(p: &Path) -> String {
    format!(
        "{{\"id\":\"sq\",\"engine\":\"sqlite\",\"dsn_ref\":\"path:{}\",\"pin\":\"sqlite\",\"op_budget_ms\":5000}}",
        p.display()
    )
}

fn put(p: &Path, ph: &str, k: &str, at: Option<u64>) {
    let c = rusqlite::Connection::open(p).unwrap();
    c.execute(
        "INSERT INTO monban_idem (principal, k, status, body, committed_at) VALUES (?1, ?2, 201, ?3, ?4)",
        rusqlite::params![ph, k, format!("{{\"k\":\"{k}\"}}"), at.map(|t| i64::try_from(t).unwrap())],
    )
    .unwrap();
}

fn columns(p: &Path) -> Vec<String> {
    let c = rusqlite::Connection::open(p).unwrap();
    let mut st = c.prepare("SELECT name FROM pragma_table_info('monban_idem') ORDER BY cid").unwrap();
    st.query_map([], |r| r.get::<_, String>(0)).unwrap().map(Result::unwrap).collect()
}

/// Write an outcome through the backend's own transaction path (the scope's `write_idem`, then COMMIT).
fn write(dp: &DataPlane, p: &monban_types::Principal, k: &str, body: &str) -> Result<(), EngineError> {
    let EngineHandle::Sqlite { engine, .. } = &dp.engines[0].engine else { panic!("sqlite") };
    let x = &engine.executor.inner;
    let cancel = CancelToken::new();
    let mut tx = x.begin(&ScopeInfo { principal: p, tenant: p.tenant(), cancel: &cancel })?;
    let idem = Idem { principal: DataPlane::principal_hex(p), key: k.into(), status: 200, body: body.into() };
    x.write_idem(&mut tx, "", &idem)?;
    x.commit(tx)
}

#[test]
fn a_set_retention_expires_replaces_and_purges() {
    let t = tmp("set");
    let path = db(&t.0, true);
    let p = crate::native::testutil::principal(TenantId::new(7).unwrap()).unwrap();
    let ph = DataPlane::principal_hex(&p);
    let now = now_s();
    put(&path, &ph, "old", Some(now - 600)); // expired before boot
    put(&path, &ph, "fresh", Some(now - 10)); // inside the window
    put(&path, &ph, "legacy", None); // pre-Phase-8 row: never expires
    put(&path, &ph, "future", Some(now + 3600)); // the clock went back: kept

    let dp =
        boot(&config(&sqlite_backend(&path), Some(60)), Some(&keyring(&t.0)), Mutants::default()).unwrap().unwrap();
    assert_eq!(dp.retention(), Some(60));
    assert_eq!(dp.lookup(0, &p, "old").unwrap(), None, "boot purge removed the expired outcome");
    assert!(dp.lookup(0, &p, "fresh").unwrap().is_some(), "INV-IDEMP inside the window");
    assert!(dp.lookup(0, &p, "legacy").unwrap().is_some(), "unstamped rows never expire");
    assert!(dp.lookup(0, &p, "future").unwrap().is_some(), "a stamp from the future is kept");

    // Expired after boot: forgotten by the lookup at once, deleted by the purge.
    put(&path, &ph, "late", Some(now - 120));
    assert_eq!(dp.lookup(0, &p, "late").unwrap(), None, "an expired outcome is not replayed");
    assert_eq!(dp.purge_expired(now_s()).unwrap(), 1);
    assert_eq!(dp.purge_expired(now_s()).unwrap(), 0);

    // The request then runs as new and its outcome replaces the expired row in its own transaction.
    put(&path, &ph, "again", Some(now - 120));
    write(&dp, &p, "again", "{\"n\":2}").unwrap();
    assert_eq!(dp.lookup(0, &p, "again").unwrap(), Some((200, "{\"n\":2}".into())));
    // Inside the window nothing is replaced: the outcome row conflicts (INV-IDEMP: the stored outcome stands).
    assert!(matches!(write(&dp, &p, "fresh", "{\"n\":3}"), Err(EngineError::Conflict)));
    assert_eq!(dp.lookup(0, &p, "fresh").unwrap(), Some((201, "{\"k\":\"fresh\"}".into())));

    // The periodic purge runs while the data plane lives.
    assert!(spawn_purge(&dp, |_| {}).is_some());
}

#[test]
fn a_set_retention_adds_the_stamp_to_an_old_table() {
    let t = tmp("alter");
    let path = db(&t.0, false);
    let kr = keyring(&t.0);
    // Absent: the pre-Phase-8 table, unchanged, and no purge thread.
    let dp = boot(&config(&sqlite_backend(&path), None), Some(&kr), Mutants::default()).unwrap().unwrap();
    assert_eq!(columns(&path), ["principal", "k", "status", "body"]);
    assert!(spawn_purge(&dp, |_| {}).is_none());
    let p = crate::native::testutil::principal(TenantId::new(7).unwrap()).unwrap();
    write(&dp, &p, "pre", "{}").unwrap();
    drop(dp);
    // Set: the additive stamp column; the row written before it never expires.
    let dp = boot(&config(&sqlite_backend(&path), Some(60)), Some(&kr), Mutants::default()).unwrap().unwrap();
    assert_eq!(columns(&path), ["principal", "k", "status", "body", "committed_at"]);
    assert!(dp.lookup(0, &p, "pre").unwrap().is_some());
    write(&dp, &p, "post", "{}").unwrap();
    let c = rusqlite::Connection::open(&path).unwrap();
    let at: Option<i64> =
        c.query_row("SELECT committed_at FROM monban_idem WHERE k = 'post'", [], |r| r.get(0)).unwrap();
    assert!(at.is_some_and(|a| a > 0), "the outcome carries its commit second");
}

#[test]
fn absent_retention_never_expires() {
    let t = tmp("absent");
    let path = db(&t.0, true);
    let p = crate::native::testutil::principal(TenantId::new(7).unwrap()).unwrap();
    put(&path, &DataPlane::principal_hex(&p), "old", Some(now_s() - 10_000_000));
    let dp = boot(&config(&sqlite_backend(&path), None), Some(&keyring(&t.0)), Mutants::default()).unwrap().unwrap();
    assert_eq!(dp.retention(), None);
    assert!(dp.lookup(0, &p, "old").unwrap().is_some(), "absent = never expire");
    assert_eq!(dp.purge_expired(now_s()).unwrap(), 0);
}

#[test]
fn retention_is_refused_where_it_cannot_apply_and_on_reload() {
    let t = tmp("refuse");
    let kr = keyring(&t.0);
    let pg = "{\"id\":\"sq\",\"engine\":\"postgres\",\"dsn_ref\":\"env:AEGIS_TEST_NO_SUCH_DSN\",\"pin\":\"pg17\",\
              \"op_budget_ms\":5000}";
    let e = boot(&config(pg, Some(60)), Some(&kr), Mutants::default()).unwrap_err();
    assert!(e.contains("idempotency_retention_s"), "{e}");
    // A reload cannot change the retention the data plane booted with.
    let path = db(&t.0, false);
    let dp = boot(&config(&sqlite_backend(&path), None), Some(&kr), Mutants::default()).unwrap().unwrap();
    let e = dp.bind(&config(&sqlite_backend(&path), Some(60))).unwrap_err();
    assert!(e.contains("idempotency_retention_s"), "{e}");
}
