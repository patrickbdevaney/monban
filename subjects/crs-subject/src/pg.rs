//! The PG half of `do sql`: per-tenant login roles, the scope-keyed pool, the C8 reset, `rls_bind`, observations.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use monban_adapter_pg::data_ir::tenant_text;
use monban_adapter_pg::{
    AdmittedVersion, Checkout, ConnectConfig, Connection, NoObserver, PgConn, PgSession, Pool, PoolConfig, Release,
    TenantId, connect_admitted, pool::PoolMutations, rls_bind,
};

use crate::{Mutants, Scope, pool_key, random_hex};

/// Op budget of one request (ms): reset, statements and NC3 recovery.
const BUDGET_MS: u64 = 5_000;
const TERMINATE: Duration = Duration::from_millis(200);
/// The tenant GUC `rls_bind` sets (transaction-local) and RLS policies read.
pub const TENANT_GUC: &str = "monban.tenant";
/// A session-level GUC the request leaves behind (a per-connection residual the C8 reset must clear).
const RESIDUAL_GUC: &str = "monban.crs_residual";

/// Residual per-connection state at acquire time: any temp relation, any prepared statement, or a non-empty
/// session-level residual or tenant GUC.
const PROBE: &str = "SELECT pg_catalog.pg_backend_pid()::text, (\
     EXISTS (SELECT 1 FROM pg_catalog.pg_class WHERE relnamespace = pg_catalog.pg_my_temp_schema()) \
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_prepared_statements) \
     OR COALESCE(pg_catalog.current_setting('monban.crs_residual', true), '') <> '' \
     OR COALESCE(pg_catalog.current_setting('monban.tenant', true), '') <> '')::text";

pub struct SqlObs {
    pub conn: String,
    pub guc: Option<String>,
    pub residual: bool,
    pub cache: String,
}

struct Role {
    name: String,
    password: String,
}

pub struct Pg {
    admin_cfg: ConnectConfig,
    admin: Connection,
    version: AdmittedVersion,
    roles: HashMap<TenantId, Role>,
    pool: Pool<PgConn>,
    shared_tenant: TenantId,
    seq: u64,
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_millis(BUDGET_MS)
}

fn cell(r: &monban_adapter_pg::wire::QueryResult, col: usize) -> Option<String> {
    r.rows.first().and_then(|row| row.get(col)).cloned().flatten()
}

impl Pg {
    pub fn open(dsn: &str, m: Mutants) -> Result<Pg, String> {
        let admin_cfg = ConnectConfig::from_dsn(dsn).map_err(|e| format!("--pg: {e}"))?;
        if admin_cfg.password.is_none() {
            return Err("--pg DSN must carry the admin password".into());
        }
        let (admin, version) = connect_admitted(&admin_cfg, None).map_err(|e| format!("pg admin connect: {e}"))?;
        let muts =
            PoolMutations { pool_key_no_epoch: m.key_no_epoch, recycle_no_reset: m.no_reset, ..PoolMutations::NONE };
        let pool = Pool::new_with(PoolConfig::default(), muts);
        let shared_tenant = TenantId::new(u64::MAX).map_err(|_| "shared tenant id".to_string())?;
        Ok(Pg { admin_cfg, admin, version, roles: HashMap::new(), pool, shared_tenant, seq: 0 })
    }

    /// The Valkey admin password of this run: derived from the run's random PG admin password, so every subject
    /// process of one oracle run (same engines, same argv) logs in as the same admin.
    pub fn kv_admin_password(&self) -> Result<String, String> {
        let p = self.admin_cfg.password.as_deref().ok_or("no PG admin password")?;
        Ok(format!("crs-admin-{p}"))
    }

    /// Create (or re-password) the tenant's login role: LOGIN, no superuser, no BYPASSRLS, SCRAM password.
    fn ensure_role(&mut self, t: TenantId) -> Result<(String, String), String> {
        if let Some(r) = self.roles.get(&t) {
            return Ok((r.name.clone(), r.password.clone()));
        }
        let name = format!("monban_crs_t_{}", tenant_text(t));
        let password = random_hex(24)?;
        let sql = format!(
            "DO $$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{name}') THEN \
             CREATE ROLE {name}; END IF; END$$; \
             ALTER ROLE {name} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT PASSWORD '{password}'"
        );
        self.admin.simple_query(&sql, deadline()).map_err(|e| format!("provision PG role {name}: {e}"))?;
        self.roles.insert(t, Role { name: name.clone(), password: password.clone() });
        Ok((name, password))
    }

    pub fn request(&mut self, m: Mutants, s: &Scope) -> Result<SqlObs, String> {
        let (role, password) = self.ensure_role(s.tenant)?;
        let (key, shared) =
            pool_key(m, s, &role, &self.admin_cfg.user, self.shared_tenant).map_err(|e| format!("pool key: {e}"))?;
        let cfg = if shared {
            self.admin_cfg.clone()
        } else {
            ConnectConfig { user: role.clone(), password: Some(password), ..self.admin_cfg.clone() }
        };
        let ver = &self.version;
        let mut co = self
            .pool
            .acquire(&key, |_| connect_admitted(&cfg, Some(ver)).map(|(c, _)| PgConn::new(c)))
            .map_err(|e| format!("pg acquire: {e}"))?;
        self.seq = self.seq.saturating_add(1);
        let out = Self::work(&mut co, s.tenant, &role, self.seq);
        let how = if out.is_ok() { Release::Completed } else { Release::HandlerError };
        self.pool.release(co, how, BUDGET_MS, &mut NoObserver);
        out
    }

    /// One request on a checked-out backend: C8 reset if recycled, observe, bind, dirty.
    fn work(co: &mut Checkout<PgConn>, tenant: TenantId, role: &str, seq: u64) -> Result<SqlObs, String> {
        if co.reset_send(BUDGET_MS).map_err(|e| e.to_string())? {
            co.reset_finish(BUDGET_MS).map_err(|e| e.to_string())?;
        }
        let cache = format!("{}:{}", co.id(), co.peek().generation());
        let conn = co.session().map_err(|e| e.to_string())?.connection();
        let probe = conn.query(PROBE, &[], deadline()).map_err(|e| format!("probe: {e}"))?;
        let pid = cell(&probe, 0).ok_or("probe: no backend pid")?;
        let residual = match cell(&probe, 1).as_deref() {
            Some("false") => false,
            Some("true") => true,
            other => return Err(format!("probe: unreadable residual flag {other:?}")),
        };
        conn.simple_query("BEGIN", deadline()).map_err(|e| format!("BEGIN: {e}"))?;
        for r in rls_bind(tenant, role, TENANT_GUC).map_err(|e| format!("rls_bind: {e}"))? {
            let params: Vec<String> = r.params.iter().map(|p| p.text()).collect();
            let refs: Vec<Option<&str>> = params.iter().map(|p| Some(p.as_str())).collect();
            conn.query(&r.sql, &refs, deadline()).map_err(|e| format!("rls_bind statement: {e}"))?;
        }
        let g = conn
            .query("SELECT pg_catalog.current_setting($1, true)", &[Some(TENANT_GUC)], deadline())
            .map_err(|e| format!("read tenant GUC: {e}"))?;
        let guc = cell(&g, 0);
        // The request's own work leaves per-connection state behind: a temp relation and a prepared statement
        // (created under the tenant role), then a session-level GUC after COMMIT.
        let dirty = format!(
            "CREATE TEMP TABLE IF NOT EXISTS crs_scratch (v text); INSERT INTO crs_scratch VALUES ('x'); \
             PREPARE crs_stale_{seq} AS SELECT 1"
        );
        conn.simple_query(&dirty, deadline()).map_err(|e| format!("request work: {e}"))?;
        conn.simple_query("COMMIT", deadline()).map_err(|e| format!("COMMIT: {e}"))?;
        conn.query("SELECT pg_catalog.set_config($1, 'dirty', false)", &[Some(RESIDUAL_GUC)], deadline())
            .map_err(|e| format!("session GUC: {e}"))?;
        Ok(SqlObs { conn: pid, guc, residual, cache })
    }

    pub fn close(self) {
        self.pool.close_idle();
        self.admin.terminate(TERMINATE);
    }
}
