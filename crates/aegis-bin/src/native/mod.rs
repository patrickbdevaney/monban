//! Native data plane, modes A/D (IMPLEMENTATION_PLAN §7): routes with `to.upstream = "app:<name>"` are served by a
//! linked application (`apps/notes`) through the F7 SDK host, over the golden engines (SQLite, PostgreSQL).
//!
//! Boot (fail closed, exit 78 before any listener exists; [`boot`]):
//! * the Tier-L key ring (`--token-keyring`, mode 0600) is required as soon as one app route exists;
//! * every F8 backend is opened and its schema introspected: SQLite `SqliteDb::check_schema` (R-DB-7, D7), PG
//!   `connect_admitted` (version gate, R-DB-1/R-DB-8) then `check_live_schema` (FORCE RLS, collations, triggers,
//!   FKs: D8/D9/D10). An app's declared collection that the engine does not have, or has in a refused shape, fails
//!   the boot. Redis/Valkey backends are refused (see INFEASIBLE_REPORT.md: the KV commit needs MULTI/EXEC);
//! * the backend's `aegis_idem` table (PLAN D14) is created if missing (PG: under FORCE RLS for the RLS role);
//! * every route's `data` block is resolved against the introspected schemas (aegis-config `resolve_data`; an
//!   unknown collection or column fails the boot) and converted to an F4 `CapSet` (aegis-adapter-host
//!   `endow::capset`; anything inert or refused fails the boot). A route without `data` holds no capability.
//!
//! Requests: [`http`]. Per-scope backend, commit gate and outcome record: [`scope`]. Renderers: [`engines`].

pub mod engines;
pub mod http;
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

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|c| {
            let h = char::from(*c.first()?).to_digit(16)?;
            let l = char::from(*c.get(1)?).to_digit(16)?;
            u8::try_from(h * 16 + l).ok()
        })
        .collect()
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

/// Load the Tier-L key ring: `{"keys":[{"kid":"<hex>","key":"<64 hex>"}]}`, a regular file not readable by group or
/// others.
pub fn load_keyring(p: &Path) -> Result<KeyRing, String> {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    let f = std::fs::File::open(p).map_err(|e| format!("token keyring {}: {e}", p.display()))?;
    let md = f.metadata().map_err(|e| format!("token keyring {}: {e}", p.display()))?;
    if !md.is_file() || md.permissions().mode() & 0o077 != 0 {
        return Err(format!("token keyring {}: must be a regular file with mode 0600", p.display()));
    }
    let mut b = Vec::new();
    f.take(1 << 20).read_to_end(&mut b).map_err(|e| format!("token keyring {}: {e}", p.display()))?;
    let bad = |w: &str| format!("token keyring {}: {w}", p.display());
    let doc = aegis_canon::parse_json(&b).map_err(|_| bad("not JSON"))?;
    let aegis_canon::JsonValue::Object(top) = doc else { return Err(bad("not an object")) };
    let Some((_, aegis_canon::JsonValue::Array(keys))) = top.iter().find(|(k, _)| k == "keys") else {
        return Err(bad("no keys array"));
    };
    let mut ring = KeyRing::new();
    for k in keys {
        let aegis_canon::JsonValue::Object(m) = k else { return Err(bad("key entry not an object")) };
        let field = |n: &str| match m.iter().find(|(k, _)| k == n) {
            Some((_, aegis_canon::JsonValue::String(s))) => unhex(s),
            _ => None,
        };
        let kid = field("kid").ok_or_else(|| bad("kid"))?;
        let key: [u8; 32] = field("key").and_then(|v| v.try_into().ok()).ok_or_else(|| bad("key (32 bytes hex)"))?;
        ring.insert(&kid, key).map_err(|e| bad(&format!("kid: {e:?}")))?;
    }
    if keys.is_empty() {
        return Err(bad("no keys"));
    }
    Ok(ring)
}

/// One app route as served.
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

/// App routes of one config generation, by (vhost host, route id).
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

/// `aegis_idem` under FORCE RLS for the RLS role, created once by the boot connection (the table owner).
fn ensure_pg_idem(c: &mut aegis_adapter_pg::Connection) -> Result<(), String> {
    if pg_q(c, "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1", &[PG_RLS_ROLE])?.is_empty() {
        return Err(format!("role {PG_RLS_ROLE:?} does not exist (provision it and the collections' RLS policies)"));
    }
    let exists = pg_q(c, "SELECT pg_catalog.to_regclass('public.aegis_idem') IS NOT NULL", &[])?;
    if exists.first().and_then(|r| r.first()).and_then(|v| v.as_deref()) == Some("t") {
        return Ok(());
    }
    let mut stmts = vec![
        "BEGIN".to_string(),
        "CREATE TABLE public.aegis_idem (tenant text COLLATE \"C\" NOT NULL, principal text COLLATE \"C\" NOT NULL, \
         k text COLLATE \"C\" NOT NULL, status integer NOT NULL, body text NOT NULL, PRIMARY KEY (principal, k))"
            .to_string(),
    ];
    stmts.extend(
        aegis_adapter_pg::rls_policy(Some(PG_NAMESPACE), "aegis_idem", "tenant", PG_RLS_ROLE, PG_TENANT_SETTING)
            .map_err(|e| e.to_string())?,
    );
    stmts.push(format!("GRANT SELECT, INSERT ON public.aegis_idem TO \"{PG_RLS_ROLE}\""));
    stmts.push("COMMIT".to_string());
    for s in &stmts {
        if let Err(e) = c.simple_query(s, Instant::now() + BOOT_TIMEOUT) {
            let _ = c.simple_query("ROLLBACK", Instant::now() + BOOT_TIMEOUT);
            return Err(format!("creating aegis_idem: {e}"));
        }
    }
    Ok(())
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
    });
    let engine = Arc::new(wrap(engines::PgRenderer::new(&b.id, vec![live], lock), exec, reg, idx));
    let host = Host::new(pool()?, EngineBackends::new(Arc::clone(&engine), Remaining::DEFAULT));
    Ok(EngineHandle::Pg { engine, host })
}

/// Boot the data plane, or `Ok(None)` when no route is bound to an app. Every error must fail the boot.
pub fn boot(cfg: &Config, keyring: Option<&Path>, mutants: Mutants) -> Result<Option<Arc<DataPlane>>, String> {
    if !has_app_routes(cfg) {
        return Ok(None);
    }
    let keyring = load_keyring(keyring.ok_or("app routes need --token-keyring (F5 Tier-L key ring)")?)?;
    let reg = Arc::new(Registry::default());
    let mut engines = Vec::new();
    for (idx, b) in cfg.data().map(aegis_config::DataBlock::backends).unwrap_or(&[]).iter().enumerate() {
        let e = match b.engine {
            CfgEngine::Sqlite => boot_sqlite(b, &reg, idx),
            CfgEngine::Postgres => boot_pg(b, &reg, idx),
            CfgEngine::Redis | CfgEngine::Valkey => Err("Redis/Valkey data plane is not available in this build: the \
                 buffered commit needs MULTI/EXEC, which aegis-adapter-redis (GET/SET/DEL allowlist, per-tenant ACL) \
                 cannot send (INFEASIBLE_REPORT.md)"
                .into()),
        }
        .map_err(|e| format!("data backend {:?} ({}): {e}", b.id, b.engine.as_str()))?;
        engines.push(Backend { id: b.id.clone(), engine: e, budget_ms: b.op_budget_ms });
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
                let RouteTarget::Upstream { upstream, .. } = &r.to else { continue };
                let Some(app) = upstream.strip_prefix(APP_PREFIX) else { continue };
                if !APPS.contains(&app) {
                    return Err(format!("{at}/to: unknown app {app:?}"));
                }
                let res = resolved.iter().find(|x| x.host == v.host && x.route_id == r.id).map(|x| &x.data);
                let (caps, backend) = match res {
                    None if self.mutants.empty_caps_means_all && !self.engines.is_empty() => {
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
                            return Err(format!("{at}/data: an app route's caps must name exactly one backend"));
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
            if let EngineHandle::Pg { engine, .. } = &e.engine {
                engine.executor.inner.bump_epoch(epoch);
            }
        }
    }

    pub fn active(&self) -> usize {
        self.reg.active()
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
