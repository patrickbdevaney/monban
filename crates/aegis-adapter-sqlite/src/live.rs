//! Connection (fixed configuration, version floor) and live schema introspection (R-DB-7) for schema `main`.

use crate::render::{ForeignKey, Rendered, Table};
use crate::{engine_pin, linked_version};
use aegis_data_ir::{
    Collation, Column, EngineVersion, Fidelity, Field, Op, OpKind, PinError, Pred, Schema, SchemaError, UniqueIndex,
    Value, check_schema, valid_collection,
};
use aegis_types::TenantId;
use rusqlite::config::DbConfig;
use rusqlite::types::{Value as SqlValue, ValueRef};
use rusqlite::{Connection, OpenFlags, params_from_iter};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenMode {
    /// `SQLITE_OPEN_READ_ONLY` (schema gate, read-only routes).
    ReadOnly,
    /// `SQLITE_OPEN_READ_WRITE`, never CREATE: collections must already exist.
    ReadWrite,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// `sqlite3_libversion_number` did not decode.
    UnknownVersion,
    /// The linked SQLite fails the pin (major other than 3, or below [`crate::SQLITE_FLOOR`]).
    Version(PinError, EngineVersion),
    /// The database text encoding is not UTF-8 (BINARY order and byte prefixes assume UTF-8).
    Encoding(String),
    /// A connection setting did not take the fixed value.
    Config(&'static str),
    Sqlite(String),
}

/// Why [`SqliteDb::check_schema`] refused a collection. `Schema` wraps F4; the others are the live-only classes of
/// PLAN D9 (adapter error types, F4 not re-frozen). `Debug` of a variant is the schema-gate refusal class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LiveError {
    Schema(SchemaError),
    /// Tenant column without TEXT affinity (non-STRICT) or not TEXT (STRICT). Under INTEGER affinity
    /// `'00000000000001e5'` and `'0000000000100000'` both store as 100000 (PLAN finding).
    TenantNotText,
    /// Tenant is a generated column: its post-image is not the bound tenant (W2).
    GeneratedTenant,
    /// A trigger on the collection (W5, D8).
    TriggerOnCollection,
    /// An FK from or into the collection with an ON DELETE/UPDATE action other than NO ACTION/RESTRICT (W5, D8).
    ForeignKeyAction,
    /// Missing, a view, or a virtual table (module registration is per connection, D7).
    NotATable,
    /// The declared collection name fails `valid_collection`.
    BadCollection,
    /// The catalog could not be read; refused (fail closed).
    Introspection(String),
}

/// Fixed connection configuration (D7: set once at open, never per request).
const CONFIG: &[(DbConfig, bool, &str)] = &[
    (DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY, true, "foreign_keys on"),
    (DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false, "triggers off (W5, D8)"),
    (DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false, "views off"),
    (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true, "defensive on"),
    (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false, "trusted_schema off"),
    (DbConfig::SQLITE_DBCONFIG_DQS_DML, false, "no double-quoted string literals (DML)"),
    (DbConfig::SQLITE_DBCONFIG_DQS_DDL, false, "no double-quoted string literals (DDL)"),
    (DbConfig::SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER, false, "fts3_tokenizer off"),
    (DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE, false, "ATTACH cannot create"),
    (DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE, false, "ATTACH cannot write"),
];

/// One adapter connection. Holds no per-request state.
#[derive(Debug)]
pub struct SqliteDb {
    conn: Connection,
}

fn sq(e: rusqlite::Error) -> OpenError {
    OpenError::Sqlite(e.to_string())
}

fn intro(e: rusqlite::Error) -> LiveError {
    LiveError::Introspection(e.to_string())
}

fn qi(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// SQLite datatype affinity (https://sqlite.org/datatype3.html §3.1), rules applied in order.
fn affinity(decl: &str) -> &'static str {
    let t = decl.to_ascii_uppercase();
    if t.contains("INT") {
        "INTEGER"
    } else if t.contains("CHAR") || t.contains("CLOB") || t.contains("TEXT") {
        "TEXT"
    } else if t.contains("BLOB") || t.is_empty() {
        "BLOB"
    } else if t.contains("REAL") || t.contains("FLOA") || t.contains("DOUB") {
        "REAL"
    } else {
        "NUMERIC"
    }
}

/// A field that names no declared column (an undeclared index column or FK column never matches (tenant, key)).
const FOREIGN_FIELD: Field = Field::MAX;

/// One `pragma_table_xinfo` row.
struct XCol {
    name: String,
    decl: String,
    notnull: bool,
    pk: i64,
    hidden: i64,
}

/// One `pragma_foreign_key_list` row.
struct FkRow {
    id: i64,
    table: String,
    from: String,
    to: Option<String>,
    on_update: String,
    on_delete: String,
}

impl SqliteDb {
    /// Open an existing database. Asserts the SQLite floor, fixes the connection configuration ([`CONFIG`]) and
    /// checks the encoding is UTF-8.
    pub fn open(path: &Path, mode: OpenMode) -> Result<SqliteDb, OpenError> {
        let v = linked_version().ok_or(OpenError::UnknownVersion)?;
        engine_pin().admit(v).map_err(|e| OpenError::Version(e, v))?;
        let rw = match mode {
            OpenMode::ReadOnly => OpenFlags::SQLITE_OPEN_READ_ONLY,
            OpenMode::ReadWrite => OpenFlags::SQLITE_OPEN_READ_WRITE,
        };
        let conn = Connection::open_with_flags(path, rw | OpenFlags::SQLITE_OPEN_NO_MUTEX).map_err(sq)?;
        for (cfg, want, what) in CONFIG {
            if conn.set_db_config(*cfg, *want).map_err(sq)? != *want {
                return Err(OpenError::Config(what));
            }
        }
        let enc: String = conn.query_row("PRAGMA main.encoding", [], |r| r.get(0)).map_err(sq)?;
        if enc != "UTF-8" {
            return Err(OpenError::Encoding(enc));
        }
        Ok(SqliteDb { conn })
    }

    /// Execute one rendered statement and return its rows (RETURNING / SELECT columns). Values are bound exactly as
    /// rendered: `Int` as INTEGER, `Str` as TEXT. One statement only: trailing SQL is an error.
    pub fn run(&self, r: &Rendered) -> Result<Vec<Vec<SqlValue>>, rusqlite::Error> {
        let mut st = self.conn.prepare(&r.sql)?;
        let ps = r.params.iter().map(|v| match v {
            Value::Int(i) => SqlValue::Integer(*i),
            Value::Str(s) => SqlValue::Text(s.clone()),
        });
        let n = st.column_count();
        let mut rows = st.query(params_from_iter(ps))?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let mut v = Vec::with_capacity(n);
            for i in 0..n {
                v.push(row.get::<_, SqlValue>(i)?);
            }
            out.push(v);
        }
        Ok(out)
    }

    /// The underlying connection, for transaction control by the host (BEGIN/COMMIT/ROLLBACK) and tests.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Effective collation of `col` in `table`: read from the compiled comparison `col = ?1` (P4 of the Eq opcode), so
    /// it reflects the column's COLLATE clause without parsing CREATE TABLE text. An application-defined collation
    /// is not registered on this connection (D7), so preparation fails: `None`.
    fn column_collation(&self, table: &str, col: &str) -> Option<String> {
        let sql = format!("EXPLAIN SELECT {} = ?1 FROM main.{}", qi(col), qi(table));
        let mut st = self.conn.prepare(&sql).ok()?;
        let mut rows = st.query(["x"]).ok()?;
        while let Ok(Some(r)) = rows.next() {
            let op: String = r.get(1).ok()?;
            if op == "Eq" || op == "Ne" {
                return Some(match r.get_ref(5).ok()? {
                    ValueRef::Text(t) => {
                        let s = String::from_utf8_lossy(t).into_owned();
                        match s.rsplit_once('-') {
                            Some((name, _enc)) => name.to_string(),
                            None => s,
                        }
                    }
                    // A rowid alias compares as an integer, with no collating sequence.
                    _ => String::from("BINARY"),
                });
            }
        }
        None
    }

    fn xinfo(&self, table: &str) -> Result<Vec<XCol>, LiveError> {
        let mut st = self
            .conn
            .prepare("SELECT name, coalesce(type, ''), \"notnull\", pk, hidden FROM pragma_table_xinfo(?1, 'main')")
            .map_err(intro)?;
        let rows = st
            .query_map([table], |r| {
                Ok(XCol {
                    name: r.get(0)?,
                    decl: r.get(1)?,
                    notnull: r.get::<_, i64>(2)? != 0,
                    pk: r.get(3)?,
                    hidden: r.get(4)?,
                })
            })
            .map_err(intro)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(intro)
    }

    fn fk_rows(&self, table: &str) -> Result<Vec<FkRow>, LiveError> {
        let mut st = self
            .conn
            .prepare(
                "SELECT id, \"table\", \"from\", \"to\", on_update, on_delete FROM pragma_foreign_key_list(?1, 'main') \
                 ORDER BY id, seq",
            )
            .map_err(intro)?;
        let rows = st
            .query_map([table], |r| {
                Ok(FkRow {
                    id: r.get(0)?,
                    table: r.get(1)?,
                    from: r.get(2)?,
                    to: r.get(3)?,
                    on_update: r.get(4)?,
                    on_delete: r.get(5)?,
                })
            })
            .map_err(intro)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(intro)
    }

    /// Primary-key columns of `table` in key order (for an FK that names no referenced columns).
    fn pk_columns(&self, table: &str) -> Result<Vec<String>, LiveError> {
        let mut cols: Vec<(i64, String)> =
            self.xinfo(table)?.into_iter().filter(|c| c.pk > 0).map(|c| (c.pk, c.name)).collect();
        cols.sort();
        Ok(cols.into_iter().map(|(_, n)| n).collect())
    }

    /// Live R-DB-7 check of one collection in schema `main`. `declared` supplies only what config states (column
    /// names, which field is the tenant, which are keys, the permitted columns); collations, NULL-ability, unique
    /// keys, types, triggers and foreign keys come from the catalog. `remote_tenant(table)` names the tenant column of
    /// another collection (for foreign keys; `None` = not a tenant-scoped collection, so writes across that key are
    /// refused at render). Returns the introspected [`Table`] the renderer uses.
    pub fn check_schema(
        &self,
        declared: &Schema,
        remote_tenant: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Table, LiveError> {
        let coll = declared.collection.as_str();
        if !valid_collection(coll) {
            return Err(LiveError::BadCollection);
        }
        let row: Option<(String, Option<String>)> = {
            let mut st = self
                .conn
                .prepare("SELECT type, sql FROM main.sqlite_schema WHERE name = ?1 AND type IN ('table', 'view')")
                .map_err(intro)?;
            let mut rows = st.query([coll]).map_err(intro)?;
            match rows.next().map_err(intro)? {
                Some(r) => Some((r.get(0).map_err(intro)?, r.get(1).map_err(intro)?)),
                None => None,
            }
        };
        let Some((kind, sql)) = row else { return Err(LiveError::NotATable) };
        let virt = sql.as_deref().is_some_and(|s| {
            let w: Vec<String> = s.split_whitespace().take(2).map(str::to_ascii_uppercase).collect();
            w.get(1).map(String::as_str) == Some("VIRTUAL")
        });
        if kind != "table" || virt {
            return Err(LiveError::NotATable);
        }
        let (strict, without_rowid): (bool, bool) = self
            .conn
            .query_row(
                "SELECT \"strict\", wr FROM pragma_table_list WHERE schema = 'main' AND name = ?1",
                [coll],
                |r| Ok((r.get::<_, i64>(0)? != 0, r.get::<_, i64>(1)? != 0)),
            )
            .map_err(intro)?;
        let info = self.xinfo(coll)?;
        let tf = declared.tenant_field;
        let field_of = |name: &str| declared.columns.iter().find(|c| c.name == name).map(|c| c.field);
        let governs = |f: Field| f == tf || declared.columns.iter().any(|c| c.key && c.field == f);

        let mut columns = Vec::with_capacity(declared.columns.len());
        for c in &declared.columns {
            let Some(x) = info.iter().find(|x| x.name == c.name) else {
                return Err(LiveError::Schema(SchemaError::UnknownField(c.field)));
            };
            let collation = match self.column_collation(coll, &c.name).as_deref() {
                Some("BINARY") => Collation::Binary,
                Some("RTRIM") => Collation::PadSpace,
                Some("NOCASE") => Collation::CaseInsensitive,
                _ => Collation::Nondeterministic,
            };
            columns.push(Column { field: c.field, name: c.name.clone(), nullable: !x.notnull, collation, key: c.key });
        }
        let tname = declared.columns.iter().find(|c| c.field == tf).map(|c| c.name.clone());
        let Some(tx) = tname.as_deref().and_then(|n| info.iter().find(|x| x.name == n)) else {
            return Err(LiveError::Schema(SchemaError::UnknownField(tf)));
        };

        // Unique keys: every unique index (PK autoindex, WITHOUT ROWID PK, UNIQUE constraints, CREATE UNIQUE INDEX)
        // plus the rowid alias (`INTEGER PRIMARY KEY` in a rowid table is a unique key with no index).
        let mut unique_indexes = Vec::new();
        let idx: Vec<(String, bool, bool)> = {
            let mut st = self
                .conn
                .prepare("SELECT name, \"unique\", partial FROM pragma_index_list(?1, 'main')")
                .map_err(intro)?;
            let rows = st
                .query_map([coll], |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0, r.get::<_, i64>(2)? != 0)))
                .map_err(intro)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(intro)?
        };
        for (iname, unique, partial) in idx {
            if !unique {
                continue;
            }
            let parts: Vec<(i64, Option<String>, Option<String>, bool)> = {
                let mut st = self
                    .conn
                    .prepare("SELECT cid, name, coll, key FROM pragma_index_xinfo(?1, 'main') ORDER BY seqno")
                    .map_err(intro)?;
                let rows = st
                    .query_map([&iname], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, i64>(3)? != 0)))
                    .map_err(intro)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(intro)?
            };
            let mut fields = Vec::new();
            let mut prefix = partial;
            for (cid, cname, icoll, key) in parts {
                if !key {
                    continue;
                }
                if cid == -2 {
                    prefix = true; // expression key part
                    continue;
                }
                match cname.as_deref().and_then(field_of) {
                    Some(f) => {
                        if governs(f) && !icoll.as_deref().is_some_and(|k| k.eq_ignore_ascii_case("BINARY")) {
                            return Err(LiveError::Schema(SchemaError::NonBinaryCollation(f)));
                        }
                        fields.push(f);
                    }
                    None => fields.push(FOREIGN_FIELD),
                }
            }
            unique_indexes.push(UniqueIndex { fields, prefix });
        }
        let pk: Vec<&XCol> = info.iter().filter(|x| x.pk > 0).collect();
        if let [only] = pk.as_slice()
            && !without_rowid
            && only.decl.eq_ignore_ascii_case("INTEGER")
        {
            unique_indexes
                .push(UniqueIndex { fields: vec![field_of(&only.name).unwrap_or(FOREIGN_FIELD)], prefix: false });
        }

        let schema = Schema {
            collection: declared.collection.clone(),
            tenant_field: tf,
            columns,
            permitted: declared.permitted.clone(),
            unique_indexes,
        };
        // Admission probe: an Upsert with no writes, so the table is fit to host every OpKind (an F8 endowment can
        // grant Upsert). Any non-zero TenantId does; only the schema is under test.
        let tenant = TenantId::new(1).map_err(|_| LiveError::Introspection(String::from("tenant id")))?;
        let probe = Op {
            tenant,
            collection: schema.collection.clone(),
            kind: OpKind::Upsert,
            filter: Pred::Tt,
            writes: Vec::new(),
            returning: Vec::new(),
        };
        check_schema(&probe, &schema, Fidelity::Exact).map_err(LiveError::Schema)?;

        // Live-only classes (PLAN D9).
        if tx.hidden == 2 || tx.hidden == 3 {
            return Err(LiveError::GeneratedTenant);
        }
        let text = if strict { tx.decl.eq_ignore_ascii_case("TEXT") } else { affinity(&tx.decl) == "TEXT" };
        if !text {
            return Err(LiveError::TenantNotText);
        }
        let triggers: i64 = self
            .conn
            .query_row(
                "SELECT count(*) FROM main.sqlite_schema WHERE type = 'trigger' AND tbl_name = ?1 COLLATE NOCASE",
                [coll],
                |r| r.get(0),
            )
            .map_err(intro)?;
        if triggers != 0 {
            return Err(LiveError::TriggerOnCollection);
        }
        let safe = |a: &str| a.eq_ignore_ascii_case("NO ACTION") || a.eq_ignore_ascii_case("RESTRICT");

        let mut fks_out = Vec::new();
        let out_rows = self.fk_rows(coll)?;
        if out_rows.iter().any(|r| !safe(&r.on_update) || !safe(&r.on_delete)) {
            return Err(LiveError::ForeignKeyAction);
        }
        for group in group_fks(out_rows.iter()) {
            let Some(first) = group.first() else { continue };
            let remote: Vec<String> = if group.iter().all(|r| r.to.is_some()) {
                group.iter().filter_map(|r| r.to.clone()).collect()
            } else {
                self.pk_columns(&first.table).unwrap_or_default()
            };
            fks_out.push(ForeignKey {
                local: group.iter().map(|r| field_of(&r.from).unwrap_or(FOREIGN_FIELD)).collect(),
                remote_table: first.table.clone(),
                remote,
                remote_tenant: remote_tenant(&first.table),
            });
        }

        let mut fks_in = Vec::new();
        let tables: Vec<String> = {
            let mut st =
                self.conn.prepare("SELECT name FROM main.sqlite_schema WHERE type = 'table'").map_err(intro)?;
            let rows = st.query_map([], |r| r.get(0)).map_err(intro)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(intro)?
        };
        for other in &tables {
            let rows = self.fk_rows(other)?;
            let into = || rows.iter().filter(|r| r.table.eq_ignore_ascii_case(coll));
            if into().any(|r| !safe(&r.on_update) || !safe(&r.on_delete)) {
                return Err(LiveError::ForeignKeyAction);
            }
            for group in group_fks(into()) {
                let local: Vec<Field> = if group.iter().all(|r| r.to.is_some()) {
                    group.iter().map(|r| r.to.as_deref().and_then(field_of).unwrap_or(FOREIGN_FIELD)).collect()
                } else {
                    self.pk_columns(coll)?.iter().map(|n| field_of(n).unwrap_or(FOREIGN_FIELD)).collect()
                };
                fks_in.push(ForeignKey {
                    local,
                    remote_table: other.clone(),
                    remote: group.iter().map(|r| r.from.clone()).collect(),
                    remote_tenant: remote_tenant(other),
                });
            }
        }
        Ok(Table { schema, fks_out, fks_in })
    }
}

/// Rows of one `pragma_foreign_key_list` grouped by constraint id (rows arrive ordered by id, seq).
fn group_fks<'a>(rows: impl Iterator<Item = &'a FkRow>) -> Vec<Vec<&'a FkRow>> {
    let mut out: Vec<Vec<&'a FkRow>> = Vec::new();
    for r in rows {
        match out.last_mut() {
            Some(g) if g.first().is_some_and(|f| f.id == r.id) => g.push(r),
            _ => out.push(vec![r]),
        }
    }
    out
}
