//! The render step of the golden dispatch for each adapter, as `aegis_adapter_host::dispatch::Renderer`s.
//!
//! aegis-adapter-host cannot link the SQLite/PG/Redis adapters (same layer, no dependency edge), so the pairing of
//! a renderer with the host's pipeline happens in the assembly. These are the thin pairings host-subject drives:
//! each `render` is exactly the adapter's production entry point (`aegis_adapter_sqlite::render`,
//! `aegis_adapter_pg::render_op`, `aegis_data_ir::kv_plan` + `aegis_adapter_redis::command_args`), followed by the
//! F4 denylist scan of the rendered SQL. The out-of-process renderer is aegis-adapter-host's own
//! (`host::oop::OopRenderer`).

use std::collections::BTreeMap;

use aegis_adapter_host::dispatch::{EngineError, Renderer};
use aegis_adapter_pg::{PgClass, PgColumn, PgTable};
use aegis_adapter_sqlite::Table;
use aegis_data_ir::{EngineFamily, Fidelity, Op, Schema, denied_in_sql, kv_plan};

fn deny_scan(family: EngineFamily, sql: &str) -> Result<(), EngineError> {
    match denied_in_sql(family, sql) {
        Ok(None) => Ok(()),
        Ok(Some(d)) => Err(EngineError::Refused(format!("denylisted: {}", d.item))),
        Err(_) => Err(EngineError::Refused("unterminated SQL text".into())),
    }
}

/// SQLite (golden, `Exact`). `tables` are the introspected tables (`SqliteDb::check_schema` at boot).
#[derive(Debug)]
pub struct SqliteRenderer {
    backend: String,
    tables: BTreeMap<String, Table>,
}

impl SqliteRenderer {
    pub fn new(backend: &str, tables: Vec<Table>) -> SqliteRenderer {
        SqliteRenderer {
            backend: backend.into(),
            tables: tables.into_iter().map(|t| (t.schema.collection.clone(), t)).collect(),
        }
    }

    /// A table with no foreign keys, from a schema the caller states is the introspected one.
    pub fn table_of(schema: Schema) -> Table {
        Table { schema, fks_out: Vec::new(), fks_in: Vec::new() }
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
}

impl PgRenderer {
    pub fn new(backend: &str, tables: Vec<aegis_adapter_pg::LiveTable>) -> PgRenderer {
        PgRenderer {
            backend: backend.into(),
            tables: tables.into_iter().map(|t| (t.schema.collection.clone(), t)).collect(),
        }
    }

    /// The renderer table for a schema the caller states is the introspected one: every column text, unique keys
    /// from the schema's unique indexes, no foreign keys, unqualified name.
    pub fn live_of(schema: Schema) -> aegis_adapter_pg::LiveTable {
        let table = PgTable {
            namespace: None,
            name: schema.collection.clone(),
            columns: schema
                .columns
                .iter()
                .map(|c| PgColumn { field: c.field, name: c.name.clone(), class: PgClass::Text })
                .collect(),
            unique: schema.unique_indexes.iter().filter(|u| !u.prefix).map(|u| u.fields.clone()).collect(),
            fks: Vec::new(),
        };
        aegis_adapter_pg::LiveTable { schema, table }
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
    fn render(&self, op: &Op, schema: &Schema) -> Result<Self::Rendered, EngineError> {
        let lt = self.tables.get(&op.collection).ok_or_else(|| EngineError::Refused("no table".into()))?;
        let r = aegis_adapter_pg::render_op(op, schema, &lt.table).map_err(|e| EngineError::Refused(e.to_string()))?;
        deny_scan(EngineFamily::Postgres, &r.sql)?;
        Ok(r)
    }
}

/// Redis/Valkey (golden, `Refines`): `kv_plan` → RESP arguments. Listing (`Scan`) renders but the executor
/// refuses it (PLAN D11).
#[derive(Debug)]
pub struct KvRenderer {
    backend: String,
    schemas: BTreeMap<String, Schema>,
}

impl KvRenderer {
    pub fn new(backend: &str, schemas: Vec<Schema>) -> KvRenderer {
        KvRenderer {
            backend: backend.into(),
            schemas: schemas.into_iter().map(|s| (s.collection.clone(), s)).collect(),
        }
    }
}

impl Renderer for KvRenderer {
    type Rendered = Vec<Vec<u8>>;
    fn backend_id(&self) -> &str {
        &self.backend
    }
    fn fidelity(&self) -> Fidelity {
        Fidelity::Refines
    }
    fn schema(&self, collection: &str) -> Option<&Schema> {
        self.schemas.get(collection)
    }
    fn render(&self, op: &Op, schema: &Schema) -> Result<Self::Rendered, EngineError> {
        let c = kv_plan(op, schema).map_err(|e| EngineError::Refused(format!("{e:?}")))?;
        Ok(aegis_adapter_redis::command_args(&c))
    }
}

#[cfg(test)]
mod tests {
    //! The full `dispatch::run` path (authorize → check_schema → pre-debit → render → execute) against a real
    //! SQLite database through `aegis_adapter_sqlite::SqliteDb`, with a minimal executor.
    use super::*;
    use aegis_adapter_host::dispatch::{self, Engine, Executor, Refusal, ScopeInfo};
    use aegis_adapter_host::host::CancelToken;
    use aegis_adapter_host::host::budget::{OpLimits, Remaining, RequestBudget, Usage};
    use aegis_adapter_sqlite::{OpenMode, SqliteDb};
    use aegis_data_ir::{CapSet, Caps, Collation, Column, DataCap, OpKind, OpMask, Pred, UniqueIndex, Value};
    use aegis_types::TenantId;
    use std::path::PathBuf;

    struct SqliteExec(PathBuf);

    impl Executor<aegis_adapter_sqlite::Rendered> for SqliteExec {
        type Tx = SqliteDb;
        type Rows = usize;
        fn begin(&self, _s: &ScopeInfo<'_>) -> Result<SqliteDb, EngineError> {
            let db =
                SqliteDb::open(&self.0, OpenMode::ReadWrite).map_err(|e| EngineError::Unavailable(format!("{e:?}")))?;
            db.connection().execute_batch("BEGIN IMMEDIATE").map_err(|e| EngineError::Unavailable(e.to_string()))?;
            Ok(db)
        }
        fn execute(
            &self,
            tx: &mut SqliteDb,
            r: aegis_adapter_sqlite::Rendered,
            l: OpLimits,
        ) -> Result<(usize, Usage), EngineError> {
            let rows = tx.run(&r).map_err(|e| EngineError::Unavailable(e.to_string()))?;
            let n = rows.len() as u64;
            if n > l.rows {
                return Err(EngineError::Unavailable("row cap".into()));
            }
            Ok((rows.len(), Usage { rows: n, bytes: 0, ms: 1 }))
        }
        fn commit(&self, tx: SqliteDb) -> Result<(), EngineError> {
            tx.connection().execute_batch("COMMIT").map_err(|e| EngineError::Unavailable(e.to_string()))
        }
        fn rollback(&self, tx: SqliteDb) {
            let _ = tx.connection().execute_batch("ROLLBACK");
        }
    }

    fn schema() -> Schema {
        let col = |field, name: &str, key| Column {
            field,
            name: name.into(),
            nullable: false,
            collation: Collation::Binary,
            key,
        };
        Schema {
            collection: "notes".into(),
            tenant_field: 0,
            columns: vec![col(0, "tenant", false), col(1, "k", true), col(2, "body", false)],
            permitted: vec![1, 2],
            unique_indexes: vec![UniqueIndex { fields: vec![0, 1], prefix: false }],
        }
    }

    fn op(kind: OpKind, t: TenantId, filter: Pred, writes: Vec<(u32, Value)>, ret: Vec<u32>) -> Op {
        Op { tenant: t, collection: "notes".into(), kind, filter, writes, returning: ret }
    }

    #[test]
    fn run_executes_only_after_every_check() -> Result<(), String> {
        let dir = std::env::temp_dir().join(format!("host-subject-sqlite-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let path = dir.join("db.sqlite");
        std::fs::write(&path, b"").map_err(|e| e.to_string())?; // an empty file is an empty SQLite database
        {
            let db = SqliteDb::open(&path, OpenMode::ReadWrite).map_err(|e| format!("{e:?}"))?;
            db.connection()
                .execute_batch(
                    "CREATE TABLE notes (tenant TEXT NOT NULL COLLATE BINARY, k TEXT NOT NULL COLLATE BINARY, \
                     body TEXT NOT NULL, PRIMARY KEY (tenant, k)) STRICT",
                )
                .map_err(|e| e.to_string())?;
            let table = db.check_schema(&schema(), &|_| None).map_err(|e| format!("{e:?}"))?;
            assert_eq!(table.schema.collection, "notes");
        }
        let db = SqliteDb::open(&path, OpenMode::ReadOnly).map_err(|e| format!("{e:?}"))?;
        let table = db.check_schema(&schema(), &|_| None).map_err(|e| format!("{e:?}"))?;
        let engine = Engine { renderer: SqliteRenderer::new("main", vec![table]), executor: SqliteExec(path.clone()) };
        let t = TenantId::new(7).map_err(|_| "tenant")?;
        let principal = crate::token::principal(t)?;
        let cancel = CancelToken::new();
        let info = ScopeInfo { principal: &principal, tenant: t, cancel: &cancel };
        let all = OpMask::from_bits(0x1f).map_err(|e| format!("{e:?}"))?;
        let cap = DataCap::new("main", "notes", all, vec![1, 2]).map_err(|e| format!("{e:?}"))?;
        let caps = CapSet::Caps(Caps::new(vec![cap]).map_err(|e| format!("{e:?}"))?);
        let budget = RequestBudget::new(Remaining::DEFAULT);

        let ins =
            op(OpKind::Insert, t, Pred::Tt, vec![(1, Value::Str("a".into())), (2, Value::Str("x".into()))], vec![]);
        let mut tx = engine.executor.begin(&info).map_err(|e| e.to_string())?;
        dispatch::run(Some(&caps), &engine, &ins, &budget, &mut tx).map_err(|e| format!("{e:?}"))?;
        engine.executor.commit(tx).map_err(|e| e.to_string())?;

        let sel = op(OpKind::Select, t, Pred::Eq(1, Value::Str("a".into())), vec![], vec![2]);
        let mut tx = engine.executor.begin(&info).map_err(|e| e.to_string())?;
        let n = dispatch::run(Some(&caps), &engine, &sel, &budget, &mut tx).map_err(|e| format!("{e:?}"))?;
        assert_eq!(n, 1);
        // Another tenant sees nothing (tenant conjunct from the bound op).
        let other = TenantId::new(8).map_err(|_| "tenant")?;
        let sel2 = op(OpKind::Select, other, Pred::Eq(1, Value::Str("a".into())), vec![], vec![2]);
        assert_eq!(dispatch::run(Some(&caps), &engine, &sel2, &budget, &mut tx), Ok(0));
        // No data block: denied before anything runs.
        assert_eq!(
            dispatch::run(None, &engine, &sel, &budget, &mut tx),
            Err(dispatch::DispatchError::Refused(Refusal::Denied))
        );
        engine.executor.rollback(tx);
        // The settled debits refunded unused rows/ms; each op consumed one op count.
        assert_eq!(budget.remaining().ops, Remaining::DEFAULT.ops - 3);
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
