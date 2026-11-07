//! Native data plane, modes A/D (IMPLEMENTATION_PLAN §7): routes with `to.upstream = "app:<name>"` are served by a
//! linked application (`apps/notes`) through the F7 SDK host, over the golden engines (SQLite, PostgreSQL).
//!
//! Boot (fail closed, exit 78 before any listener exists; [`boot`]):
//! * the Tier-L key ring (`--token-keyring`, mode 0600) is required as soon as one app route exists;
//! * every F8 backend is opened and its schema introspected: SQLite `SqliteDb::check_schema` (R-DB-7, D7), PG
//!   `connect_admitted` (version gate, R-DB-1/R-DB-8) then `check_live_schema` (FORCE RLS, collations, triggers,
//!   FKs: D8/D9/D10); the Phase-7 adapter families (CockroachDB, MariaDB; features `adapter-crdb`,
//!   `adapter-mariadb`) in [`adapters`]. An app's declared collection that the engine does not have, or has in a refused shape, fails
//!   the boot. Redis/Valkey backends are refused (PLAN D18, deferred: the KV commit needs MULTI/EXEC);
//! * the backend's `aegis_idem` table (PLAN D14) is created if missing (PG: under FORCE RLS for the RLS role);
//! * every route's `data` block is resolved against the introspected schemas (aegis-config `resolve_data`; an
//!   unknown collection or column fails the boot) and converted to an F4 `CapSet` (aegis-adapter-host
//!   `endow::capset`; anything inert or refused fails the boot). A route without `data` holds no capability.
//!
//! The data plane also boots for a config whose only data endowments are on `{"wasm": id}` routes (feature `p2`):
//! those endowments resolve the same way, and P2 `data_run`s reach the engines through [`p2data`] (P5-bin-002).
//!
//! Requests: [`http`]. Per-scope backend, commit gate and outcome record: [`scope`]. Renderers: [`engines`].

#[cfg(any(feature = "adapter-crdb", feature = "adapter-mariadb"))]
pub mod adapters;
#[cfg(not(any(feature = "adapter-crdb", feature = "adapter-mariadb")))]
mod adapters {
    //! No adapter family is built: plan() already refused any adapter backend (exit 78).
    pub fn boot(
        a: &aegis_config::AdapterBackend,
        _reg: &std::sync::Arc<super::scope::Registry>,
        _idx: usize,
    ) -> Result<super::scope::EngineHandle, String> {
        Err(format!("engine {} is not built into this binary (fail closed)", a.family.as_str()))
    }
}
pub mod engines;
pub mod http;
#[cfg(feature = "adapter-mariadb")]
pub mod mariadb;
#[cfg(feature = "p2")]
pub mod p2data;
pub mod pg;
pub mod scope;
pub mod sqlite;
#[cfg(test)]
pub mod testutil;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_adapter_host::dispatch::{EngineBackends, Executor, Renderer, ScopeInfo};
use aegis_adapter_host::host::budget::{PrincipalLedger, Remaining};
use aegis_adapter_host::host::endow::{CapParts, Endowment, capset};
use aegis_adapter_host::host::session::principal_bytes;
use aegis_adapter_host::host::{BlockingPool, CancelToken, Host};
use aegis_adapter_pg::{PgConn, PoolConfig};
use aegis_config::{
    Config, DsnRef, Engine as CfgEngine, FieldId, ResolvedData, RouteTarget, SchemaProvider, Unresolved,
};
use aegis_data_ir::{CapSet, Collation, Column, EngineFamily, Schema, UniqueIndex};
use aegis_token::KeyRing;
use aegis_types::Principal;

use crate::shared::Mutants;
use scope::{EngineHandle, Registry, wrap};

/// The prefix of an app route target (F8 `upstream` is a free string; PLAN D16).
pub const APP_PREFIX: &str = "app:";
/// The apps linked into this binary.
pub const APPS: &[&str] = &[notes::NAME];
/// PG role the transaction switches to (`SET LOCAL ROLE`, the role the FORCE RLS policy applies to) and the
/// transaction-local setting carrying the tenant. F8 has no field for either; these are the provisioning names.
pub const PG_RLS_ROLE: &str = "aegis_app";
pub const PG_TENANT_SETTING: &str = "aegis.tenant";
const PG_NAMESPACE: &str = "public";
/// Blocking pool for handlers, per backend (X-11): rejects at once when full.
const POOL_THREADS: usize = 32;
const BOOT_TIMEOUT: Duration = Duration::from_secs(10);

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The notes collection as the app declares it (names, field ids, tenant/key roles, permitted columns). Collations,
/// NULL-ability and unique keys are taken from the live catalog by the schema gates, never from here.
pub fn notes_schema() -> Schema {
    Schema {
        collection: notes::COLLECTION.into(),
        tenant_field: notes::TENANT_FIELD,
        columns: notes::COLUMNS
            .iter()
            .map(|(field, name, key)| Column {
                field: *field,
                name: (*name).into(),
                nullable: false,
                collation: Collation::Binary,
                key: *key,
            })
            .collect(),
        permitted: notes::PERMITTED.to_vec(),
        unique_indexes: vec![UniqueIndex { fields: vec![notes::TENANT_FIELD, notes::ID], prefix: false }],
    }
}

/// The Tier-L key ring loader (shared with the P2 routes, feature `p2`).
pub use crate::keyring::load as load_keyring;

#[cfg(feature = "p2")]
pub use p2data::p2_store;

/// One app route (or a `wasm:` route with a data block, feature `p2`) as served.
#[derive(Clone, Debug)]
pub struct AppRoute {
    /// The vhost host (token audience).
    pub host: String,
    /// Canonical route path (prefix).
    pub path: String,
    /// Index into [`DataPlane::engines`]; `None`: no data capability, no backend.
    pub backend: Option<usize>,
    /// The route's F4 endowment; `None` denies every op (INV-NONEMPTY).
    pub caps: Option<Arc<CapSet>>,
}

/// App routes and data-endowed wasm routes of one config generation, by (vhost host, route id).
#[derive(Debug, Default)]
pub struct Bindings {
    routes: HashMap<(String, u64), AppRoute>,
}

impl Bindings {
    pub fn get(&self, host: &str, id: u64) -> Option<&AppRoute> {
        self.routes.get(&(host.to_string(), id))
    }
}

/// One configured backend.
#[derive(Debug)]
pub struct Backend {
    pub id: String,
    pub engine: EngineHandle,
    pub budget_ms: u64,
}

/// The booted data plane.
pub struct DataPlane {
    pub reg: Arc<Registry>,
    pub engines: Vec<Backend>,
    pub keyring: KeyRing,
    pub claims: Arc<Mutex<HashSet<(String, String)>>>,
    /// NEGATIVE CONTROL `ack-then-drop` (feature `e2e-mutants`): set on SIGTERM.
    pub dropping: AtomicBool,
    pub mutants: Mutants,
    data: Option<aegis_config::DataBlock>,
}

impl std::fmt::Debug for DataPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataPlane").field("engines", &self.engines).field("active", &self.reg.active()).finish()
    }
}

/// True iff the config binds at least one route to an app.
pub fn has_app_routes(cfg: &Config) -> bool {
    cfg.vhosts()
        .iter()
        .flat_map(|v| v.routes.iter())
        .any(|r| matches!(&r.to, RouteTarget::Upstream { upstream, .. } if upstream.starts_with(APP_PREFIX)))
}

/// True iff some `{"wasm": id}` route carries a data block (its endowment is resolved by this data plane).
pub fn has_data_wasm_routes(cfg: &Config) -> bool {
    cfg.vhosts()
        .iter()
        .flat_map(|v| v.routes.iter())
        .any(|r| matches!(r.to, RouteTarget::Wasm { .. }) && r.data.is_some())
}

fn dsn(r: &DsnRef) -> Result<String, String> {
    match r {
        DsnRef::Env(n) => std::env::var(n).map_err(|_| format!("dsn_ref env:{n} is not set")),
        DsnRef::Cred(n) => {
            let d = std::env::var_os("CREDENTIALS_DIRECTORY").ok_or("dsn_ref cred: needs $CREDENTIALS_DIRECTORY")?;
            let s = std::fs::read_to_string(PathBuf::from(d).join(n)).map_err(|e| format!("dsn_ref cred:{n}: {e}"))?;
            Ok(s.trim_end().to_string())
        }
        DsnRef::Path(_) => Err("a network engine needs env: or cred:".into()),
    }
}

fn pool() -> Result<BlockingPool, String> {
    BlockingPool::new(POOL_THREADS).map_err(|e| e.to_string())
}

fn boot_sqlite(b: &aegis_config::Backend, reg: &Arc<Registry>, idx: usize) -> Result<EngineHandle, String> {
    let DsnRef::Path(path) = &b.dsn_ref else { return Err("sqlite needs dsn_ref path:".into()) };
    let path = PathBuf::from(path);
    let db = sqlite::open(&path, b.op_budget_ms).map_err(|e| e.to_string())?;
    let table = db.check_schema(&notes_schema(), &|_| None).map_err(|e| format!("schema gate: {e:?}"))?;
    sqlite::query(
        &db,
        "CREATE TABLE IF NOT EXISTS aegis_idem (principal TEXT NOT NULL COLLATE BINARY, k TEXT NOT NULL COLLATE BINARY, \
         status INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY (principal, k)) WITHOUT ROWID",
        &[],
    )
    .map_err(|e| format!("aegis_idem: {e}"))?;
    // A pre-existing table must have exactly that shape (an existing different one is refused, never altered).
    let shape =
        sqlite::query(&db, "SELECT name, pk, \"notnull\" FROM pragma_table_info('aegis_idem') ORDER BY cid", &[])
            .map_err(|e| format!("aegis_idem: {e}"))?;
    let want = [["principal", "1", "1"], ["k", "2", "1"], ["status", "0", "1"], ["body", "0", "1"]];
    let ok = shape.len() == want.len()
        && shape
            .iter()
            .zip(want.iter())
            .all(|(r, w)| r.iter().map(|c| c.as_deref().unwrap_or("")).eq(w.iter().copied()));
    if !ok {
        return Err(
            "aegis_idem exists with a different shape (expected principal, k, status, body; PK (principal, k))".into(),
        );
    }
    let lock = engines::allowlist(notes::ALLOWLIST_SQLITE, EngineFamily::Sqlite)?;
    let engine = Arc::new(wrap(
        engines::SqliteRenderer::new(&b.id, vec![table], lock),
        sqlite::SqliteExec::new(path, b.op_budget_ms),
        reg,
        idx,
    ));
    let host = Host::new(pool()?, EngineBackends::new(Arc::clone(&engine), Remaining::DEFAULT));
    Ok(EngineHandle::Sqlite { engine, host })
}

fn pg_q(c: &mut aegis_adapter_pg::Connection, sql: &str, params: &[&str]) -> Result<Vec<Vec<Option<String>>>, String> {
    let p: Vec<Option<&str>> = params.iter().map(|s| Some(*s)).collect();
    c.query(sql, &p, Instant::now() + BOOT_TIMEOUT).map(|r| r.rows).map_err(|e| e.to_string())
}

/// The provisioning DDL `aegis_idem` must match (documented for operators; aegis-bin never runs it: the RLS role
/// has no CREATE and must own nothing).
pub const PG_IDEM_DDL: &str = "CREATE TABLE public.aegis_idem (tenant text COLLATE \"C\" NOT NULL, principal text \
     COLLATE \"C\" NOT NULL, k text COLLATE \"C\" NOT NULL, status integer NOT NULL, body text NOT NULL, PRIMARY KEY \
     (principal, k)) + aegis_adapter_pg::rls_policy(public, aegis_idem, tenant, aegis_app, aegis.tenant) + GRANT \
     SELECT, INSERT TO aegis_app";

fn cells(rows: &[Vec<Option<String>>]) -> Vec<Vec<&str>> {
    rows.iter().map(|r| r.iter().map(|c| c.as_deref().unwrap_or("")).collect()).collect()
}

/// PLAN D14 on PG: the operator-provisioned `public.aegis_idem` is accepted only in exactly the shape above: the
/// columns, `(principal, k)` its only unique index, ENABLE + FORCE ROW LEVEL SECURITY, every policy a permissive
/// FOR ALL tenant guard (USING and WITH CHECK) with at least one applying to the RLS role, no user trigger or rule,
/// SELECT and INSERT granted, not owned by the RLS role (an owner could turn FORCE off). Missing or different:
/// refused (fail closed), never created or altered.
fn ensure_pg_idem(c: &mut aegis_adapter_pg::Connection) -> Result<(), String> {
    let refuse = |why: &str| Err(format!("public.aegis_idem {why} (provision it as: {PG_IDEM_DDL})"));
    if pg_q(c, "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1", &[PG_RLS_ROLE])?.is_empty() {
        return Err(format!("role {PG_RLS_ROLE:?} does not exist (provision it and the collections' RLS policies)"));
    }
    let rel = pg_q(
        c,
        "SELECT c.relkind::text, c.relrowsecurity, c.relforcerowsecurity, \
         (pg_catalog.pg_get_userbyid(c.relowner) = $1) FROM pg_catalog.pg_class c \
         WHERE c.oid = pg_catalog.to_regclass('public.aegis_idem')",
        &[PG_RLS_ROLE],
    )?;
    match cells(&rel).as_slice() {
        [] => return refuse("does not exist"),
        [r] if r.as_slice() == ["r", "t", "t", "f"] => {}
        [r] if r.get(3) == Some(&"t") => return refuse("is owned by the RLS role"),
        _ => return refuse("is not an ordinary table under ENABLE + FORCE ROW LEVEL SECURITY"),
    }
    let cols = pg_q(
        c,
        "SELECT a.attname::text, pg_catalog.format_type(a.atttypid, a.atttypmod), a.attnotnull, \
         COALESCE(co.collname::text, '') FROM pg_catalog.pg_attribute a \
         LEFT JOIN pg_catalog.pg_collation co ON co.oid = a.attcollation \
         WHERE a.attrelid = 'public.aegis_idem'::regclass AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum",
        &[],
    )?;
    let cols = cells(&cols);
    let want: [(&str, &str, Option<&str>); 5] = [
        ("tenant", "text", Some("C")),
        ("principal", "text", Some("C")),
        ("k", "text", Some("C")),
        ("status", "integer", None),
        ("body", "text", None),
    ];
    let cols_ok = cols.len() == want.len()
        && cols.iter().zip(want.iter()).all(|(got, (n, t, coll))| {
            got.first() == Some(n)
                && got.get(1) == Some(t)
                && got.get(2) == Some(&"t")
                && coll.is_none_or(|w| got.get(3) == Some(&w))
        });
    if !cols_ok {
        return refuse("does not have the expected columns");
    }
    let uniq = pg_q(
        c,
        "SELECT pg_catalog.array_to_string(ARRAY(SELECT a.attname::text FROM \
         unnest(i.indkey::int2[]) WITH ORDINALITY AS k(n, o) JOIN pg_catalog.pg_attribute a \
         ON a.attrelid = i.indrelid AND a.attnum = k.n ORDER BY k.o), ','), i.indisprimary, \
         (i.indpred IS NULL AND i.indexprs IS NULL) FROM pg_catalog.pg_index i \
         WHERE i.indrelid = 'public.aegis_idem'::regclass AND i.indisunique",
        &[],
    )?;
    if cells(&uniq).as_slice() != [vec!["principal,k", "t", "t"]] {
        return refuse("must have (principal, k) as its only unique index (the primary key)");
    }
    let pols = pg_q(
        c,
        "SELECT p.polcmd::text, p.polpermissive, COALESCE(pg_catalog.pg_get_expr(p.polqual, p.polrelid), ''), \
         COALESCE(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), ''), \
         (0::oid = ANY(p.polroles) OR (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1) = ANY(p.polroles)) \
         FROM pg_catalog.pg_policy p WHERE p.polrelid = 'public.aegis_idem'::regclass",
        &[PG_RLS_ROLE],
    )?;
    let pols = cells(&pols);
    let guard = |e: Option<&&str>| e.is_some_and(|e| aegis_adapter_pg::lower::is_tenant_guard(e, "tenant"));
    let all_guards =
        pols.iter().all(|p| p.first() == Some(&"*") && p.get(1) == Some(&"t") && guard(p.get(2)) && guard(p.get(3)));
    if pols.is_empty() || !all_guards || !pols.iter().any(|p| p.get(4) == Some(&"t")) {
        return refuse("policies are not permissive FOR ALL tenant guards (USING and WITH CHECK) for the RLS role");
    }
    let other = pg_q(
        c,
        "SELECT (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgrelid = 'public.aegis_idem'::regclass \
         AND NOT tgisinternal) + (SELECT count(*) FROM pg_catalog.pg_rewrite WHERE ev_class = \
         'public.aegis_idem'::regclass AND rulename <> '_RETURN'), \
         pg_catalog.has_table_privilege($1, 'public.aegis_idem', 'SELECT'), \
         pg_catalog.has_table_privilege($1, 'public.aegis_idem', 'INSERT')",
        &[PG_RLS_ROLE],
    )?;
    match cells(&other).as_slice() {
        [r] if r.as_slice() == ["0", "t", "t"] => Ok(()),
        [r] if r.first() != Some(&"0") => refuse("has a user trigger or rule"),
        _ => refuse("lacks SELECT and INSERT for the RLS role"),
    }
}

fn boot_pg(b: &aegis_config::Backend, reg: &Arc<Registry>, idx: usize) -> Result<EngineHandle, String> {
    let mut cc = aegis_adapter_pg::ConnectConfig::from_dsn(&dsn(&b.dsn_ref)?).map_err(|e| format!("dsn: {e}"))?;
    cc.connect_timeout = cc.connect_timeout.min(Duration::from_millis(b.op_budget_ms.max(1000)));
    let (mut conn, admitted) = aegis_adapter_pg::connect_admitted(&cc, None).map_err(|e| e.to_string())?;
    let live =
        aegis_adapter_pg::check_live_schema(&mut conn, PG_NAMESPACE, &notes_schema(), Instant::now() + BOOT_TIMEOUT)
            .map_err(|e| format!("schema gate: {e}"));
    let idem = live.as_ref().map_err(String::clone).and_then(|_| ensure_pg_idem(&mut conn));
    conn.terminate(Duration::from_millis(200));
    let live = live?;
    idem?;
    let lock = engines::allowlist(notes::ALLOWLIST_PG, EngineFamily::Postgres)?;
    let login_role = cc.user.clone();
    let connect = move |_k: &aegis_adapter_pg::PoolKey| -> Result<PgConn, aegis_adapter_pg::wire::Error> {
        match aegis_adapter_pg::connect_admitted(&cc, Some(&admitted)) {
            Ok((c, _)) => Ok(PgConn::new(c)),
            Err(aegis_adapter_pg::ConnectError::Wire(e)) => Err(e),
            Err(aegis_adapter_pg::ConnectError::Refused(r)) => Err(aegis_adapter_pg::wire::Error::Auth(r.to_string())),
        }
    };
    let exec = pg::PgExecutor::new(pg::PgExecConfig {
        pool: PoolConfig {
            max_open: usize::try_from(b.max_conns).unwrap_or(16).max(1),
            max_idle_per_key: 1,
            acquire_timeout: Duration::from_millis(b.op_budget_ms),
        },
        connect: Box::new(connect),
        login_role,
        rls_role: PG_RLS_ROLE.into(),
        setting: PG_TENANT_SETTING.into(),
        epoch: 1,
        op_budget_ms: b.op_budget_ms,
        charges: Arc::new(PrincipalLedger::new()),
        #[cfg(feature = "adapter-crdb")]
        crdb: false,
    });
    let engine = Arc::new(wrap(engines::PgRenderer::new(&b.id, vec![live], lock), exec, reg, idx));
    let host = Host::new(pool()?, EngineBackends::new(Arc::clone(&engine), Remaining::DEFAULT));
    Ok(EngineHandle::Pg { engine, host })
}

/// Boot the data plane, or `Ok(None)` when no route is bound to an app and no wasm route holds a data block. Every
/// error must fail the boot.
pub fn boot(cfg: &Config, keyring: Option<&Path>, mutants: Mutants) -> Result<Option<Arc<DataPlane>>, String> {
    if !has_app_routes(cfg) && !has_data_wasm_routes(cfg) {
        return Ok(None);
    }
    let keyring = load_keyring(keyring.ok_or("app and data routes need --token-keyring (F5 Tier-L key ring)")?)?;
    let reg = Arc::new(Registry::default());
    let mut engines = Vec::new();
    for (idx, b) in cfg.data().map(aegis_config::DataBlock::backends).unwrap_or(&[]).iter().enumerate() {
        let e = match b.engine {
            CfgEngine::Sqlite => boot_sqlite(b, &reg, idx),
            CfgEngine::Postgres => boot_pg(b, &reg, idx),
            CfgEngine::Redis | CfgEngine::Valkey => Err("Redis/Valkey data plane is not available in this build: the \
                 buffered commit needs MULTI/EXEC, which aegis-adapter-redis (GET/SET/DEL allowlist, per-tenant ACL) \
                 cannot send yet (PLAN D18, deferred)"
                .into()),
        }
        .map_err(|e| format!("data backend {:?} ({}): {e}", b.id, b.engine.as_str()))?;
        engines.push(Backend { id: b.id.clone(), engine: e, budget_ms: b.op_budget_ms });
    }
    // Phase-7 adapter families (features `adapter-crdb`, `adapter-mariadb`; plan() refused any family not built).
    for a in cfg.data().map(aegis_config::DataBlock::adapters).unwrap_or(&[]) {
        let idx = engines.len();
        let e = adapters::boot(a, &reg, idx)
            .map_err(|e| format!("data backend {:?} ({}): {e}", a.id, a.family.as_str()))?;
        engines.push(Backend { id: a.id.clone(), engine: e, budget_ms: a.op_budget_ms });
    }
    let dp = DataPlane {
        reg,
        engines,
        keyring,
        claims: Arc::new(Mutex::new(HashSet::new())),
        dropping: AtomicBool::new(false),
        mutants,
        data: cfg.data().cloned(),
    };
    dp.bind(cfg)?; // every route endowment must resolve at boot
    Ok(Some(Arc::new(dp)))
}

struct Provider<'a>(&'a DataPlane);

impl SchemaProvider for Provider<'_> {
    fn field(&self, backend: &aegis_config::Backend, collection: &str, column: &str) -> Result<FieldId, Unresolved> {
        let b = self.0.engines.iter().find(|e| e.id == backend.id).ok_or(Unresolved::Unavailable)?;
        let s = match &b.engine {
            EngineHandle::Sqlite { engine, .. } => engine.renderer.schema(collection),
            EngineHandle::Pg { engine, .. } => engine.renderer.schema(collection),
            #[cfg(feature = "adapter-crdb")]
            EngineHandle::Crdb { .. } => return Err(Unresolved::Unavailable), // never a golden backend id
            #[cfg(feature = "adapter-mariadb")]
            EngineHandle::Mariadb { .. } => return Err(Unresolved::Unavailable), // never a golden backend id
        }
        .ok_or(Unresolved::NoCollection)?;
        s.columns.iter().find(|c| c.name == column).map(|c| c.field).ok_or(Unresolved::NoColumn)
    }

    /// The Phase-7 adapter families this build serves (P7-spec-001: the default refuses every family). Only a
    /// backend booted as that family resolves (a crdb id never resolves against a golden engine, and vice versa).
    #[cfg(any(feature = "adapter-crdb", feature = "adapter-mariadb"))]
    fn adapter_field(
        &self,
        backend: &aegis_config::AdapterBackend,
        collection: &str,
        column: &str,
    ) -> Result<FieldId, Unresolved> {
        let b = self.0.engines.iter().find(|e| e.id == backend.id).ok_or(Unresolved::Unavailable)?;
        let s = match (&b.engine, backend.family) {
            #[cfg(feature = "adapter-crdb")]
            (EngineHandle::Crdb { engine, .. }, aegis_config::AdapterFamily::Crdb) => {
                engine.renderer.schema(collection)
            }
            #[cfg(feature = "adapter-mariadb")]
            (EngineHandle::Mariadb { engine, .. }, aegis_config::AdapterFamily::Mariadb) => {
                engine.renderer.schema(collection)
            }
            _ => return Err(Unresolved::Unavailable),
        }
        .ok_or(Unresolved::NoCollection)?;
        s.columns.iter().find(|c| c.name == column).map(|c| c.field).ok_or(Unresolved::NoColumn)
    }
}

impl DataPlane {
    /// Resolve and convert every app route of `cfg` (boot and reload). A reload may not change the data block.
    pub fn bind(&self, cfg: &Config) -> Result<Bindings, String> {
        if cfg.data() != self.data.as_ref() {
            return Err("the data block changed: backends are opened at boot (restart or upgrade to apply)".into());
        }
        let resolved = cfg.resolve_data(&Provider(self)).map_err(|e| e.to_string())?;
        let mut out = Bindings::default();
        for (vi, v) in cfg.vhosts().iter().enumerate() {
            for (ri, r) in v.routes.iter().enumerate() {
                let at = format!("/vhosts/{vi}/routes/{ri}");
                let app_route = match &r.to {
                    RouteTarget::Upstream { upstream, .. } => {
                        let Some(app) = upstream.strip_prefix(APP_PREFIX) else { continue };
                        if !APPS.contains(&app) {
                            return Err(format!("{at}/to: unknown app {app:?}"));
                        }
                        true
                    }
                    // A wasm route without a data block holds no capability: no binding (every data_run refused).
                    RouteTarget::Wasm { .. } if r.data.is_some() => false,
                    _ => continue,
                };
                let res = resolved.iter().find(|x| x.host == v.host && x.route_id == r.id).map(|x| &x.data);
                let (caps, backend) = match res {
                    None if app_route && self.mutants.empty_caps_means_all && !self.engines.is_empty() => {
                        // NEGATIVE CONTROL (e2e-mutants only): no data block read as "all ops on a backend".
                        (Some(Arc::new(CapSet::Unrestricted)), Some(0))
                    }
                    None => (None, None),
                    Some(ResolvedData::Unrestricted) => {
                        if self.engines.len() != 1 {
                            return Err(format!("{at}/data: \"unrestricted\" names no backend; declare exactly one"));
                        }
                        (Some(Arc::new(CapSet::Unrestricted)), Some(0))
                    }
                    Some(ResolvedData::Caps(list)) => {
                        let parts: Vec<CapParts> = list
                            .iter()
                            .map(|c| CapParts {
                                backend: c.backend.clone(),
                                collection: c.collection.clone(),
                                ops_bits: c.ops_bits,
                                fields: c.fields.clone(),
                            })
                            .collect();
                        let conv = capset(&Endowment::Caps(parts));
                        if !conv.boot_ok() {
                            return Err(format!("{at}/data: endowment not representable ({:?})", conv.refused));
                        }
                        let mut ids: Vec<&str> = list.iter().map(|c| c.backend.as_str()).collect();
                        ids.sort_unstable();
                        ids.dedup();
                        let [id] = ids.as_slice() else {
                            return Err(format!("{at}/data: a route's caps must name exactly one backend"));
                        };
                        let idx = self.engines.iter().position(|e| e.id == *id).ok_or(format!("{at}/data: backend"))?;
                        (conv.caps.map(Arc::new), Some(idx))
                    }
                };
                out.routes.insert(
                    (v.host.clone(), r.id),
                    AppRoute { host: v.host.clone(), path: r.path.clone(), backend, caps },
                );
            }
        }
        Ok(out)
    }

    /// CRS C5: a new config epoch retires pooled PG connections of older epochs.
    pub fn bump_epoch(&self, epoch: u64) {
        for e in &self.engines {
            match &e.engine {
                EngineHandle::Pg { engine, .. } => engine.executor.inner.bump_epoch(epoch),
                #[cfg(feature = "adapter-crdb")]
                EngineHandle::Crdb { engine, .. } => engine.executor.inner.bump_epoch(epoch),
                // MariaDB: no session binding to retire (no RLS role, no tenant GUC; the pool keys on nothing).
                #[cfg(feature = "adapter-mariadb")]
                EngineHandle::Mariadb { .. } => {}
                EngineHandle::Sqlite { .. } => {}
            }
        }
    }

    pub fn active(&self) -> usize {
        self.reg.active()
    }

    /// NEGATIVE CONTROL `ack-then-drop` (e2e-mutants only): in-flight requests answer a fabricated success.
    pub fn start_dropping(&self) {
        self.dropping.store(true, Ordering::Release);
    }

    pub fn is_dropping(&self) -> bool {
        self.dropping.load(Ordering::Acquire)
    }

    /// The stored outcome of (principal, key) in backend `idx`'s `aegis_idem`, read in a tenant-bound transaction.
    /// Blocking: call on the pool.
    pub fn lookup(&self, idx: usize, principal: &Principal, key: &str) -> Result<Option<(u16, String)>, String> {
        let b = self.engines.get(idx).ok_or("no such backend")?;
        let ph = hex(&principal_bytes(principal));
        let rows = match &b.engine {
            EngineHandle::Sqlite { engine, .. } => {
                let x = &engine.executor.inner;
                let db = sqlite::open(x.path(), x.budget_ms()).map_err(|e| e.to_string())?;
                sqlite::query(&db, "SELECT status, body FROM aegis_idem WHERE principal = ?1 AND k = ?2", &[&ph, key])
                    .map_err(|e| e.to_string())?
            }
            EngineHandle::Pg { engine, .. } => {
                let x = &engine.executor.inner;
                let cancel = CancelToken::new();
                let info = ScopeInfo { principal, tenant: principal.tenant(), cancel: &cancel };
                let mut tx = x.begin(&info).map_err(|e| e.to_string())?;
                let r = x.raw(
                    &mut tx,
                    "SELECT status::text, body FROM aegis_idem WHERE principal = $1 AND k = $2",
                    &[Some(ph.as_str()), Some(key)],
                    1,
                );
                x.rollback(tx);
                r.map_err(|e| e.to_string())?.rows
            }
            #[cfg(feature = "adapter-crdb")]
            EngineHandle::Crdb { engine, .. } => {
                // No RLS on CockroachDB: the tenant predicate is the guard (the table's rows carry the tenant).
                let x = &engine.executor.inner;
                let cancel = CancelToken::new();
                let info = ScopeInfo { principal, tenant: principal.tenant(), cancel: &cancel };
                let tenant = aegis_data_ir::tenant_text(principal.tenant());
                let mut tx = x.begin(&info).map_err(|e| e.to_string())?;
                let r = x.raw(
                    &mut tx,
                    "SELECT status::text, body FROM aegis_idem WHERE tenant = $1 AND principal = $2 AND k = $3",
                    &[Some(tenant.as_str()), Some(ph.as_str()), Some(key)],
                    1,
                );
                x.rollback(tx);
                r.map_err(|e| e.to_string())?.rows
            }
            #[cfg(feature = "adapter-mariadb")]
            EngineHandle::Mariadb { engine, .. } => {
                // No RLS on MariaDB: the tenant predicate is the guard (the table's rows carry the tenant).
                use aegis_adapter_mysql::Param;
                let x = &engine.executor.inner;
                let cancel = CancelToken::new();
                let info = ScopeInfo { principal, tenant: principal.tenant(), cancel: &cancel };
                let tenant = aegis_data_ir::tenant_text(principal.tenant());
                let mut tx = x.begin(&info).map_err(|e| e.to_string())?;
                let r = x.raw(
                    &mut tx,
                    "SELECT CAST(status AS CHAR), body FROM aegis_idem WHERE tenant = ? AND principal = ? AND k = ?",
                    &[Param::Text(tenant), Param::Text(ph.clone()), Param::Text(key.into())],
                );
                x.rollback(tx);
                r.map_err(|e| e.to_string())?
            }
        };
        let Some(row) = rows.into_iter().next() else { return Ok(None) };
        let mut it = row.into_iter();
        let status = it.next().flatten().and_then(|s| s.parse::<u16>().ok()).ok_or("aegis_idem: bad status")?;
        let body = it.next().flatten().ok_or("aegis_idem: bad body")?;
        Ok(Some((status, body)))
    }

    pub fn principal_hex(p: &Principal) -> String {
        hex(&principal_bytes(p))
    }
}
