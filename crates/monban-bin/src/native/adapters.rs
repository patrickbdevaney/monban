//! Phase-7 adapter families on the native data plane (D-P7.8; features `adapter-crdb`, `adapter-mariadb`). Both are
//! non-golden until the integrator records their gates (crdb-live, native-e2e-mariadb), and every boot check fails
//! closed (exit 78 before any listener exists).
//!
//! **CockroachDB** (`adapter-crdb`) rides the PG wire, pool and executor ([`super::pg::PgExecutor`] with `crdb`):
//! * boot: `monban_adapter_pg::crdb::connect_admitted` (the crdb version gate: `SELECT version()` against the crdb
//!   floors of engine-pins.toml; the PG gate would refuse CockroachDB's `server_version` 13.0.0), then
//!   `check_live_schema_dialect(.., Dialect::Crdb)` for the app's collection, then [`ensure_crdb_idem`];
//! * pool connects re-run `crdb::connect_admitted` with the admitted version pinned (R-DB-1 recheck);
//! * per scope: `BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE` + the transaction-local `statement_timeout`; no role
//!   switch and no tenant GUC: CockroachDB has no RLS here (P7-oracle-adapters-001), so tenant isolation is the
//!   rendered tenant conjunct, the crdb upsert guard and the schema gate; the idempotency lookup carries the tenant
//!   predicate itself;
//! * the C8/NC3 reset statements the pool sends on recycle and recovery (ROLLBACK, Close, DISCARD ALL) and
//!   CancelRequest are exercised against a live CockroachDB by the `crdb_live` test below;
//! * at the request deadline (or client gone) before the commit point the running statement is stopped with a
//!   CancelRequest (the session's BackendKeyData; `PgTx::interrupt`, armed by scope.rs `Gate`), and the checkout is
//!   released `Cancelled`: recovered (ROLLBACK, Close, DISCARD ALL) or discarded, never pooled with an open
//!   transaction (R8, gate crdb-live);
//! * 40001 (serialization failure) surfaces as `EngineError::Conflict`: the scope's transaction is driven step by step
//!   by the SDK host, and a whole-transaction retry (`crdb::run_serializable`) would have to re-run the app handler,
//!   which this seam cannot do. `run_serializable` is used for the host-owned boot statements instead.
//!
//! **MariaDB** (`adapter-mariadb`; PREFLIGHT R4, gate native-e2e-mariadb, contract oracles/native-e2e/README.md
//! "MariaDB backend"):
//! * boot: the backend is connected (loopback, mysql_native_password, the version gate of engine-pins.toml before
//!   any credential), its session pinned (strict `sql_mode`, utf8mb4), the app's collection put through
//!   `monban_adapter_mysql::check_live_schema` (InnoDB, byte-equality NO PAD collations, `(tenant, id)` the only
//!   unique key, no trigger), and the operator-provisioned `monban_idem` through [`ensure_mariadb_idem`]; the app's
//!   allowlist lock is `notes::ALLOWLIST_MARIADB` (family `mariadb`);
//! * renderer: [`super::engines::MariadbRenderer`] (`monban_adapter_mysql::render_op` + the F4 MariaDB denylist scan,
//!   DENY-M);
//! * executor: [`super::mariadb::MariadbExec`]: `START TRANSACTION` .. `COMMIT` per scope on a connection the scope
//!   holds exclusively; pooled again only if `is_reusable()`; a cancelled or deadline-hit scope never returns its
//!   connection;
//! * idempotency in band (PLAN D14): the outcome row is inserted into `monban_idem` inside the scope's transaction,
//!   and every lookup carries the tenant predicate (no RLS on MariaDB).

use std::sync::Arc;
#[cfg(feature = "adapter-crdb")]
use std::time::{Duration, Instant};

use monban_config::{AdapterBackend, AdapterFamily};

use super::scope::{EngineHandle, Registry};
#[cfg(feature = "adapter-crdb")]
use super::{BOOT_TIMEOUT, PG_NAMESPACE, dsn, engines, notes_schema, pool};

/// Boot one adapter-family backend at index `idx` of the data plane.
pub fn boot(a: &AdapterBackend, reg: &Arc<Registry>, idx: usize) -> Result<EngineHandle, String> {
    match a.family {
        #[cfg(feature = "adapter-crdb")]
        AdapterFamily::Crdb => boot_crdb(a, reg, idx),
        #[cfg(feature = "adapter-mariadb")]
        AdapterFamily::Mariadb => boot_mariadb(a, reg, idx),
        #[allow(unreachable_patterns)]
        other => {
            let _ = (reg, idx);
            Err(format!("engine {} is not built into this binary (fail closed)", other.as_str()))
        }
    }
}

/// The host-owned rows of a crdb query, as text cells.
#[cfg(feature = "adapter-crdb")]
fn q(c: &mut monban_adapter_pg::Connection, sql: &str, params: &[&str]) -> Result<Vec<Vec<String>>, String> {
    let p: Vec<Option<&str>> = params.iter().map(|s| Some(*s)).collect();
    c.query(sql, &p, Instant::now() + BOOT_TIMEOUT)
        .map(|r| r.rows.into_iter().map(|row| row.into_iter().map(Option::unwrap_or_default).collect()).collect())
        .map_err(|e| e.to_string())
}

/// The provisioning DDL `public.monban_idem` must match on CockroachDB (PLAN D14; no RLS, so every lookup carries the
/// tenant predicate).
#[cfg(feature = "adapter-crdb")]
pub const CRDB_IDEM_DDL: &str = "CREATE TABLE public.monban_idem (tenant STRING NOT NULL, principal STRING NOT NULL, \
     k STRING NOT NULL, status INT8 NOT NULL, body STRING NOT NULL, PRIMARY KEY (principal, k))";

/// PLAN D14 on CockroachDB: the operator-provisioned `public.monban_idem` is accepted only in exactly the shape of
/// [`CRDB_IDEM_DDL`] (byte-order strings, `(principal, k)` its only unique index, no trigger), with SELECT and
/// INSERT for the login role. Missing or different: refused, never created or altered.
#[cfg(feature = "adapter-crdb")]
fn ensure_crdb_idem(c: &mut monban_adapter_pg::Connection) -> Result<(), String> {
    let refuse = |why: &str| Err(format!("public.monban_idem {why} (provision it as: {CRDB_IDEM_DDL})"));
    let cols = q(
        c,
        "SELECT column_name, data_type, is_nullable, COALESCE(collation_name, '') FROM information_schema.columns \
         WHERE table_schema = $1 AND table_name = 'monban_idem' ORDER BY ordinal_position",
        &[PG_NAMESPACE],
    )?;
    if cols.is_empty() {
        return refuse("does not exist");
    }
    let want: [(&str, &[&str]); 5] = [
        ("tenant", &["text"]),
        ("principal", &["text"]),
        ("k", &["text"]),
        ("status", &["bigint", "integer"]),
        ("body", &["text"]),
    ];
    let cols_ok = cols.len() == want.len()
        && cols.iter().zip(want.iter()).all(|(got, (n, types))| {
            got.first().map(String::as_str) == Some(*n)
                && got.get(1).is_some_and(|t| types.contains(&t.as_str()))
                && got.get(2).map(String::as_str) == Some("NO")
                && got.get(3).is_some_and(|c| c.is_empty() || c == "default" || c == "C")
        });
    if !cols_ok {
        return refuse("does not have the expected columns (byte-order strings, NOT NULL)");
    }
    let uniq = q(
        c,
        "SELECT i.indisprimary::text, pg_catalog.array_to_string(ARRAY(SELECT a.attname FROM pg_catalog.pg_attribute \
         a WHERE a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey::INT2[]) ORDER BY \
         pg_catalog.array_position(i.indkey::INT2[], a.attnum)), ',') FROM pg_catalog.pg_index i \
         JOIN pg_catalog.pg_class t ON t.oid = i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace \
         WHERE n.nspname = $1 AND t.relname = 'monban_idem' AND i.indisunique",
        &[PG_NAMESPACE],
    )?;
    if uniq != [vec!["true".to_string(), "principal,k".to_string()]] {
        return refuse("must have (principal, k) as its only unique index (the primary key)");
    }
    let other = q(
        c,
        "SELECT (SELECT count(*) FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class t ON t.oid = g.tgrelid \
         JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace WHERE n.nspname = $1 AND t.relname = 'monban_idem')\
         ::text, pg_catalog.has_table_privilege('public.monban_idem', 'SELECT')::text, \
         pg_catalog.has_table_privilege('public.monban_idem', 'INSERT')::text",
        &[PG_NAMESPACE],
    )?;
    match other.as_slice() {
        [r] if r.as_slice() == ["0", "true", "true"] => Ok(()),
        [r] if r.first().map(String::as_str) != Some("0") => refuse("has a trigger"),
        _ => refuse("lacks SELECT and INSERT for the login role"),
    }
}

#[cfg(feature = "adapter-crdb")]
fn boot_crdb(a: &AdapterBackend, reg: &Arc<Registry>, idx: usize) -> Result<EngineHandle, String> {
    use monban_adapter_host::dispatch::EngineBackends;
    use monban_adapter_host::host::Host;
    use monban_adapter_host::host::budget::{PrincipalLedger, Remaining};
    use monban_adapter_pg::crdb::{self, CrdbConnectError};
    use monban_adapter_pg::{Dialect, PgConn, PoolConfig};
    use monban_data_ir::EngineFamily;

    let mut cc = monban_adapter_pg::ConnectConfig::from_dsn(&dsn(&a.dsn_ref)?).map_err(|e| format!("dsn: {e}"))?;
    cc.connect_timeout = cc.connect_timeout.min(Duration::from_millis(a.op_budget_ms.max(1000)));
    let (mut conn, admitted) = crdb::connect_admitted(&cc, None).map_err(|e| e.to_string())?;
    let live = monban_adapter_pg::check_live_schema_dialect(
        &mut conn,
        PG_NAMESPACE,
        &notes_schema(),
        Instant::now() + BOOT_TIMEOUT,
        Dialect::Crdb,
    )
    .map_err(|e| format!("schema gate: {e}"));
    let idem = live.as_ref().map_err(String::clone).and_then(|_| ensure_crdb_idem(&mut conn));
    conn.terminate(Duration::from_millis(200));
    let live = live?;
    idem?;
    let lock = engines::allowlist(notes::ALLOWLIST_PG, EngineFamily::Postgres)?;
    let login_role = cc.user.clone();
    let connect = move |_k: &monban_adapter_pg::PoolKey| -> Result<PgConn, monban_adapter_pg::wire::Error> {
        match crdb::connect_admitted(&cc, Some(&admitted)) {
            Ok((c, _)) => Ok(PgConn::new(c)),
            Err(CrdbConnectError::Wire(e)) => Err(e),
            Err(CrdbConnectError::Refused(r)) => Err(monban_adapter_pg::wire::Error::Auth(r.to_string())),
        }
    };
    let exec = super::pg::PgExecutor::new(super::pg::PgExecConfig {
        pool: PoolConfig {
            max_open: usize::try_from(a.max_conns).unwrap_or(16).max(1),
            max_idle_per_key: 1,
            acquire_timeout: Duration::from_millis(a.op_budget_ms),
        },
        connect: Box::new(connect),
        login_role,
        rls_role: super::PG_RLS_ROLE.into(),
        setting: super::PG_TENANT_SETTING.into(),
        epoch: 1,
        op_budget_ms: a.op_budget_ms,
        charges: Arc::new(PrincipalLedger::new()),
        crdb: true,
    });
    let renderer = engines::CrdbRenderer(engines::PgRenderer::new(&a.id, vec![live], lock));
    let engine = Arc::new(super::scope::wrap(renderer, exec, reg, idx));
    let host = Host::new(pool()?, EngineBackends::new(Arc::clone(&engine), Remaining::DEFAULT));
    Ok(EngineHandle::Crdb { engine, host })
}

/// The provisioning DDL `monban_idem` must match on MariaDB (PLAN D14; oracles/native-e2e `my_provision`). The login
/// user needs SELECT and INSERT on it and never DDL.
#[cfg(feature = "adapter-mariadb")]
pub const MARIADB_IDEM_DDL: &str = "CREATE TABLE monban_idem (tenant VARCHAR(16) CHARACTER SET utf8mb4 COLLATE \
     utf8mb4_nopad_bin NOT NULL, principal VARCHAR(255) .. NOT NULL, k VARCHAR(64) .. NOT NULL, status INT NOT NULL, \
     body MEDIUMTEXT .. NOT NULL, PRIMARY KEY (principal, k)) ENGINE=InnoDB";

/// PLAN D14 on MariaDB: the operator-provisioned `monban_idem` (in the DSN's database) is accepted only in the shape
/// of [`MARIADB_IDEM_DDL`]: those columns in that order, NOT NULL, strings in a byte-equality NO PAD collation (F4
/// `Collation::Binary` by `my_collation`), `(principal, k)` its only unique index (the primary key), InnoDB, no
/// trigger. Missing or different: refused, never created or altered.
#[cfg(feature = "adapter-mariadb")]
fn ensure_mariadb_idem(c: &mut monban_adapter_mysql::Connection, db: &str) -> Result<(), String> {
    use monban_adapter_mysql::Param;
    let refuse = |why: &str| Err(format!("monban_idem {why} (provision it as: {MARIADB_IDEM_DDL})"));
    let deadline = std::time::Instant::now() + super::BOOT_TIMEOUT;
    let mut q = |sql: &str| -> Result<Vec<Vec<String>>, String> {
        let r = c
            .execute_until(sql, &[Param::Text(db.into()), Param::Text("monban_idem".into())], deadline)
            .map_err(|e| e.to_string())?;
        Ok(r.rows
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .map(|cell| match cell {
                        monban_adapter_mysql::Cell::Int(i) => i.to_string(),
                        monban_adapter_mysql::Cell::UInt(u) => u.to_string(),
                        other => other.as_str().unwrap_or_default().to_string(),
                    })
                    .collect()
            })
            .collect())
    };
    let t = q("SELECT TABLE_TYPE, ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?")?;
    match t.as_slice() {
        [] => return refuse("does not exist"),
        [r] if r.first().map(String::as_str) == Some("BASE TABLE")
            && r.get(1).is_some_and(|e| e.eq_ignore_ascii_case("InnoDB")) => {}
        _ => return refuse("is not an InnoDB base table"),
    }
    let cols = q("SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COALESCE(COLLATION_NAME, ''), IS_GENERATED \
         FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION")?;
    let want: [(&str, &[&str]); 5] = [
        ("tenant", &["varchar", "char"]),
        ("principal", &["varchar"]),
        ("k", &["varchar"]),
        ("status", &["int", "bigint"]),
        ("body", &["text", "mediumtext", "longtext"]),
    ];
    let cols_ok = cols.len() == want.len()
        && cols.iter().zip(want.iter()).all(|(got, (n, types))| {
            let ty = got.get(1).map(|t| t.to_ascii_lowercase()).unwrap_or_default();
            let coll = got.get(3).map(String::as_str).filter(|s| !s.is_empty());
            let string = ty != "int" && ty != "bigint";
            got.first().map(String::as_str) == Some(*n)
                && types.contains(&ty.as_str())
                && got.get(2).map(String::as_str) == Some("NO")
                && got.get(4).map(String::as_str) == Some("NEVER")
                && (!string
                    || monban_adapter_mysql::schema::my_collation(&ty, coll) == monban_data_ir::Collation::Binary)
        });
    if !cols_ok {
        return refuse("does not have the expected columns (NOT NULL, byte-equality NO PAD collations)");
    }
    let uniq = q("SELECT INDEX_NAME, GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX SEPARATOR ',') FROM \
         information_schema.STATISTICS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND NON_UNIQUE = 0 \
         GROUP BY INDEX_NAME")?;
    if uniq != [vec!["PRIMARY".to_string(), "principal,k".to_string()]] {
        return refuse("must have (principal, k) as its only unique index (the primary key)");
    }
    let trig = q("SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE EVENT_OBJECT_SCHEMA = ? AND \
         EVENT_OBJECT_TABLE = ?")?;
    if trig != [vec!["0".to_string()]] {
        return refuse("has a trigger");
    }
    Ok(())
}

/// MariaDB: connect, version gate, live schema gate, `monban_idem` shape, lock; then the engine (module docs).
#[cfg(feature = "adapter-mariadb")]
fn boot_mariadb(a: &AdapterBackend, reg: &Arc<Registry>, idx: usize) -> Result<EngineHandle, String> {
    use monban_adapter_host::dispatch::EngineBackends;
    use monban_adapter_host::host::Host;
    use monban_adapter_host::host::budget::Remaining;
    use monban_data_ir::EngineFamily;
    let dsn = match &a.dsn_ref {
        monban_config::DsnRef::Env(_) | monban_config::DsnRef::Cred(_) => super::dsn(&a.dsn_ref)?,
        monban_config::DsnRef::Path(_) => return Err("a network engine needs env: or cred:".into()),
    };
    let mut cc = monban_adapter_mysql::ConnectConfig::from_dsn(&dsn).map_err(|e| format!("dsn: {e}"))?;
    cc.connect_timeout = cc.connect_timeout.min(std::time::Duration::from_millis(a.op_budget_ms.max(1000)));
    let db = cc.database.clone();
    if db.is_empty() {
        return Err("the DSN names no database (the collection's namespace)".into());
    }
    let mut conn = monban_adapter_mysql::connect(&cc).map_err(|e| e.to_string())?;
    let deadline = std::time::Instant::now() + super::BOOT_TIMEOUT;
    let live = monban_adapter_mysql::check_live_schema(&mut conn, &db, &super::notes_schema(), deadline)
        .map_err(|e| format!("schema gate: {e}"));
    let idem = live.as_ref().map_err(String::clone).and_then(|_| ensure_mariadb_idem(&mut conn, &db));
    conn.terminate(std::time::Duration::from_millis(200));
    let live = live?;
    idem?;
    let lock = super::engines::allowlist(notes::ALLOWLIST_MARIADB, EngineFamily::Mariadb)?;
    let max_open = usize::try_from(a.max_conns).unwrap_or(16).max(1);
    let exec = super::mariadb::MariadbExec::new(cc, max_open, a.op_budget_ms);
    let renderer = super::engines::MariadbRenderer::new(&a.id, vec![live], lock);
    let engine = Arc::new(super::scope::wrap(renderer, exec, reg, idx));
    let host = Host::new(super::pool()?, EngineBackends::new(Arc::clone(&engine), Remaining::DEFAULT));
    Ok(EngineHandle::Mariadb { engine, host })
}

#[cfg(all(test, feature = "adapter-crdb"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
    //! `crdb_live` needs a throwaway CockroachDB: `ci/engines.sh with crdb -- env AEGIS_TEST_CRDB_DSN=@crdb cargo test
    //! -p monban-bin --features adapter-crdb native::adapters` (kamrui). Without the variable it does nothing.

    use super::*;
    use monban_adapter_host::dispatch::{EngineError, Executor, ScopeInfo};
    use monban_adapter_host::host::CancelToken;
    use monban_adapter_host::host::budget::OpLimits;
    use monban_types::TenantId;

    fn setup(dsn: &str) -> monban_adapter_pg::Connection {
        let cc = monban_adapter_pg::ConnectConfig::from_dsn(dsn).unwrap();
        let (mut c, _) = monban_adapter_pg::crdb::connect_admitted(&cc, None).unwrap();
        for s in [
            "DROP TABLE IF EXISTS public.notes",
            "DROP TABLE IF EXISTS public.monban_idem",
            "CREATE TABLE public.notes (tenant STRING NOT NULL, id STRING NOT NULL, body STRING NOT NULL, \
             PRIMARY KEY (tenant, id))",
            CRDB_IDEM_DDL,
        ] {
            c.query(s, &[], Instant::now() + Duration::from_secs(20)).unwrap();
        }
        c
    }

    fn backend(env: &str) -> AdapterBackend {
        let doc = format!(
            r#"{{"v":1,"listeners":[{{"name":"pub","bind":"127.0.0.1:8443","profile":"P-PUBLIC-WEB"}}],
               "data":{{"backends":[{{"id":"cr","engine":"crdb","dsn_ref":"env:{env}","pin":"crdb"}}]}},
               "vhosts":[{{"host":"monban.test","routes":[{{"id":1,"path":"/","to":{{"upstream":"127.0.0.1:9"}},"authz":"allow-all"}}]}}]}}"#
        );
        let cfg = monban_config::parse_config(doc.as_bytes()).unwrap();
        cfg.data().unwrap().adapters()[0].clone()
    }

    /// The C8/NC3 statements the pool sends (recycle reset DISCARD ALL, recovery ROLLBACK + Close + DISCARD ALL),
    /// CancelRequest, and the executor's per-scope statements are accepted by a live CockroachDB; the boot path
    /// (version gate, crdb schema gate, monban_idem shape) admits the provisioned schema and refuses a wrong one.
    #[test]
    fn crdb_live() {
        let Ok(dsn) = std::env::var("AEGIS_TEST_CRDB_DSN") else {
            eprintln!("crdb_live: AEGIS_TEST_CRDB_DSN not set; skipped");
            return;
        };
        let mut c = setup(&dsn);
        // The reset statements, one by one, as the pool sends them (simple protocol).
        for s in [monban_adapter_pg::checkin::ROLLBACK, monban_adapter_pg::checkin::DISCARD_ALL] {
            c.query(s, &[], Instant::now() + Duration::from_secs(10)).unwrap_or_else(|e| panic!("{s}: {e}"));
        }
        c.terminate(Duration::from_millis(200));

        // The boot path, then scopes through the real pool: commit, recycle (DISCARD ALL), handler error
        // (ROLLBACK), cancel (recovery), and a second key.
        let a = backend("AEGIS_TEST_CRDB_DSN");
        let reg = Arc::new(Registry::default());
        let EngineHandle::Crdb { engine, .. } = boot(&a, &reg, 0).unwrap() else { panic!("not crdb") };
        let x = &engine.executor.inner;
        let t = TenantId::new(7).unwrap();
        let p = crate::native::testutil::principal(t).unwrap();
        let cancel = CancelToken::new();
        let info = ScopeInfo { principal: &p, tenant: t, cancel: &cancel };
        let tenant = monban_data_ir::tenant_text(t);
        let ins = monban_adapter_pg::Rendered {
            sql: "INSERT INTO public.notes (tenant, id, body) VALUES ($1, $2, $3) RETURNING id".into(),
            params: vec![
                monban_adapter_pg::Param::Text(tenant.clone()),
                monban_adapter_pg::Param::Text("n1".into()),
                monban_adapter_pg::Param::Text("b".into()),
            ],
        };
        let lim = OpLimits { rows: 10, bytes: 1 << 16, ms: 5000 };
        let mut tx = x.begin(&info).unwrap();
        let (rows, _) = x.execute(&mut tx, ins.clone(), lim).unwrap();
        assert_eq!(rows, vec![vec![Some("n1".to_string())]]);
        x.commit(tx).unwrap();
        // Recycled connection: the checkout runs DISCARD ALL first.
        let mut tx = x.begin(&info).unwrap();
        let dup = x.execute(&mut tx, ins.clone(), lim);
        assert!(matches!(dup, Err(EngineError::Conflict)), "duplicate key is a conflict: {dup:?}");
        x.rollback(tx);
        let mut tx = x.begin(&info).unwrap();
        let r = x.raw(&mut tx, "SELECT count(*)::text FROM public.notes WHERE tenant = $1", &[Some(&tenant)], 1);
        assert_eq!(r.unwrap().rows, vec![vec![Some("1".to_string())]]);
        x.rollback(tx);
        // A cancelled scope is released as Cancelled: the pool's recovery (ROLLBACK, Close, DISCARD ALL) runs.
        let cancel2 = CancelToken::new();
        let info2 = ScopeInfo { principal: &p, tenant: t, cancel: &cancel2 };
        let tx = x.begin(&info2).unwrap();
        cancel2.cancel();
        x.rollback(tx);
        let mut tx = x.begin(&info).unwrap();
        let r = x.raw(&mut tx, "SELECT 1::text", &[], 1);
        assert_eq!(r.unwrap().rows, vec![vec![Some("1".to_string())]]);
        x.commit(tx).unwrap();
        // A wrong monban_idem shape is refused at boot.
        let mut c = setup(&dsn);
        c.query(
            "ALTER TABLE public.monban_idem ADD COLUMN extra STRING",
            &[],
            Instant::now() + Duration::from_secs(20),
        )
        .unwrap();
        c.terminate(Duration::from_millis(200));
        let err = boot(&a, &reg, 0).err().unwrap_or_default();
        assert!(err.contains("monban_idem"), "{err}");
    }
}
