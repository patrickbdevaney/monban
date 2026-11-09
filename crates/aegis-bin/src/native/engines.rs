//! The render half of each golden engine, as `aegis_adapter_host::dispatch::Renderer`s (PLAN D15: the pairings live
//! in the assembly, because aegis-adapter-host has no edge to the adapters). Lifted from subjects/host-subject.
//!
//! Each `render` is exactly the adapter's production entry point (`aegis_adapter_sqlite::render`,
//! `aegis_adapter_pg::render_op`, `aegis_adapter_mysql::render_op` = `lower_op` + `lower::render`), followed by the
//! F4 denylist scan of the rendered SQL (MariaDB: its own dialect scanner, `EngineFamily::Mariadb`, DENY-M). Each renderer carries the
//! app's verified allowlist lock, so dispatch refuses any op shape that is not a lock line.

use std::collections::BTreeMap;

use aegis_adapter_host::dispatch::{EngineError, Renderer};
use aegis_adapter_sqlite::Table;
use aegis_data_ir::{Allowlist, EngineFamily, Fidelity, Op, Schema, denied_in_sql};

fn deny_scan(family: EngineFamily, sql: &str) -> Result<(), EngineError> {
    match denied_in_sql(family, sql) {
        Ok(None) => Ok(()),
        Ok(Some(d)) => Err(EngineError::Refused(format!("denylisted: {}", d.item))),
        Err(_) => Err(EngineError::Refused("unterminated SQL text".into())),
    }
}

/// Parse an allowlist lock and require its family.
pub fn allowlist(text: &str, family: EngineFamily) -> Result<Allowlist, String> {
    let a = Allowlist::parse(text).map_err(|e| format!("allowlist lock: {e:?}"))?;
    if a.family() != family {
        return Err(format!("allowlist lock {} is for {:?}, not {family:?}", a.adapter(), a.family()));
    }
    Ok(a)
}

/// SQLite (golden, `Exact`). `tables` are the introspected tables (`SqliteDb::check_schema` at boot).
#[derive(Debug)]
pub struct SqliteRenderer {
    backend: String,
    tables: BTreeMap<String, Table>,
    lock: Allowlist,
}

impl SqliteRenderer {
    pub fn new(backend: &str, tables: Vec<Table>, lock: Allowlist) -> SqliteRenderer {
        SqliteRenderer {
            backend: backend.into(),
            tables: tables.into_iter().map(|t| (t.schema.collection.clone(), t)).collect(),
            lock,
        }
    }
}

impl Renderer for SqliteRenderer {
    type Rendered = aegis_adapter_sqlite::Rendered;
    fn backend_id(&self) -> &str {
        &self.backend
    }
    fn fidelity(&self) -> Fidelity {
        Fidelity::Exact
    }
    fn schema(&self, collection: &str) -> Option<&Schema> {
        self.tables.get(collection).map(|t| &t.schema)
    }
    fn allowlist(&self) -> Option<&Allowlist> {
        Some(&self.lock)
    }
    fn render(&self, op: &Op, _schema: &Schema) -> Result<Self::Rendered, EngineError> {
        let table = self.tables.get(&op.collection).ok_or_else(|| EngineError::Refused("no table".into()))?;
        let r = aegis_adapter_sqlite::render(op, table).map_err(|e| EngineError::Refused(format!("{e:?}")))?;
        deny_scan(EngineFamily::Sqlite, &r.sql)?;
        Ok(r)
    }
}

/// PostgreSQL (golden, `Exact`). `tables` are `check_live_schema` results (schema + renderer table).
#[derive(Debug)]
pub struct PgRenderer {
    backend: String,
    tables: BTreeMap<String, aegis_adapter_pg::LiveTable>,
    lock: Allowlist,
}

impl PgRenderer {
    pub fn new(backend: &str, tables: Vec<aegis_adapter_pg::LiveTable>, lock: Allowlist) -> PgRenderer {
        PgRenderer {
            backend: backend.into(),
            tables: tables.into_iter().map(|t| (t.schema.collection.clone(), t)).collect(),
            lock,
        }
    }
}

impl Renderer for PgRenderer {
    type Rendered = aegis_adapter_pg::Rendered;
    fn backend_id(&self) -> &str {
        &self.backend
    }
    fn fidelity(&self) -> Fidelity {
        Fidelity::Exact
    }
    fn schema(&self, collection: &str) -> Option<&Schema> {
        self.tables.get(collection).map(|t| &t.schema)
    }
    fn allowlist(&self) -> Option<&Allowlist> {
        Some(&self.lock)
    }
    fn render(&self, op: &Op, schema: &Schema) -> Result<Self::Rendered, EngineError> {
        let lt = self.tables.get(&op.collection).ok_or_else(|| EngineError::Refused("no table".into()))?;
        let r = aegis_adapter_pg::render_op(op, schema, &lt.table).map_err(|e| EngineError::Refused(e.to_string()))?;
        deny_scan(EngineFamily::Postgres, &r.sql)?;
        Ok(r)
    }
}

/// CockroachDB (feature `adapter-crdb`, non-golden until its gates are recorded; D-P7.8): the PG renderer in the
/// crdb dialect (`render_op_dialect(.., Dialect::Crdb)`: the q4-005 upsert guard), over `check_live_schema_dialect`
/// tables. CockroachDB speaks the PostgreSQL dialect, so the F4 denylist scan and the allowlist lock are the
/// PostgreSQL ones (the lock's family is `postgres`; its op lines are IR shapes, not engine text).
#[cfg(feature = "adapter-crdb")]
#[derive(Debug)]
pub struct CrdbRenderer(pub PgRenderer);

#[cfg(feature = "adapter-crdb")]
impl Renderer for CrdbRenderer {
    type Rendered = aegis_adapter_pg::Rendered;
    fn backend_id(&self) -> &str {
        self.0.backend_id()
    }
    fn fidelity(&self) -> Fidelity {
        Fidelity::Exact
    }
    fn schema(&self, collection: &str) -> Option<&Schema> {
        self.0.schema(collection)
    }
    fn allowlist(&self) -> Option<&Allowlist> {
        self.0.allowlist()
    }
    fn render(&self, op: &Op, schema: &Schema) -> Result<Self::Rendered, EngineError> {
        let lt = self.0.tables.get(&op.collection).ok_or_else(|| EngineError::Refused("no table".into()))?;
        let r = aegis_adapter_pg::render_op_dialect(op, schema, &lt.table, aegis_adapter_pg::Dialect::Crdb)
            .map_err(|e| EngineError::Refused(e.to_string()))?;
        deny_scan(EngineFamily::Postgres, &r.sql)?;
        Ok(r)
    }
}

/// MariaDB (feature `adapter-mariadb`, non-golden until `native-e2e-mariadb` is recorded; PREFLIGHT R4): the
/// adapter's renderer (`aegis_adapter_mysql::render_op`: `lower_op(.., Exact)` then `lower::render`, the q4-005
/// mandated MariaDB forms) over `aegis_adapter_mysql::check_live_schema` tables, then the F4 MariaDB denylist scan
/// (`EngineFamily::Mariadb`, DENY-M) of every statement it emits, the `returning_select` of an UPDATE included. The
/// allowlist lock is `notes-mariadb` (family `mariadb`).
#[cfg(feature = "adapter-mariadb")]
#[derive(Debug)]
pub struct MariadbRenderer {
    backend: String,
    tables: BTreeMap<String, aegis_adapter_mysql::LiveTable>,
    lock: Allowlist,
}

#[cfg(feature = "adapter-mariadb")]
impl MariadbRenderer {
    pub fn new(backend: &str, tables: Vec<aegis_adapter_mysql::LiveTable>, lock: Allowlist) -> MariadbRenderer {
        MariadbRenderer {
            backend: backend.into(),
            tables: tables.into_iter().map(|t| (t.schema.collection.clone(), t)).collect(),
            lock,
        }
    }
}

#[cfg(feature = "adapter-mariadb")]
impl Renderer for MariadbRenderer {
    type Rendered = aegis_adapter_mysql::Rendered;
    fn backend_id(&self) -> &str {
        &self.backend
    }
    fn fidelity(&self) -> Fidelity {
        Fidelity::Exact
    }
    fn schema(&self, collection: &str) -> Option<&Schema> {
        self.tables.get(collection).map(|t| &t.schema)
    }
    fn allowlist(&self) -> Option<&Allowlist> {
        Some(&self.lock)
    }
    fn render(&self, op: &Op, schema: &Schema) -> Result<Self::Rendered, EngineError> {
        let lt = self.tables.get(&op.collection).ok_or_else(|| EngineError::Refused("no table".into()))?;
        let r =
            aegis_adapter_mysql::render_op(op, schema, &lt.table).map_err(|e| EngineError::Refused(e.to_string()))?;
        deny_scan(EngineFamily::Mariadb, &r.stmt.sql)?;
        if let Some(rs) = &r.returning_select {
            deny_scan(EngineFamily::Mariadb, &rs.sql)?;
        }
        Ok(r)
    }
}
