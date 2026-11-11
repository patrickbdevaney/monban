//! Live schema introspection and gate for MariaDB (R-DB-7 `check_schema()`, W3 amendment of q4-005).
//!
//! [`check_live_schema`] reads `information_schema` for one collection (prepared statements, bound parameters),
//! never trusting the declared F4 [`Schema`] for anything but the column names, field numbers, tenant/key roles and
//! the permitted projection. It fills an F4 `Schema` from the catalog and runs F4 `check_schema` on the admission
//! probe (an Upsert with no writes: a collection must be fit for every OpKind), then the live-only checks. The
//! order is that of oracles/schema-gate/refsubject.py (`_my_check`), so each counterexample reports its class:
//!
//! 1. the collection is a `BASE TABLE` (else `NotATable`; views are refused);
//! 2. every declared column exists (else `UnknownField(f)`);
//! 3. collations (W3 amendment): `Binary` only for VARBINARY, integer types and `*_nopad_bin`; `CHAR` / `BINARY`
//!    (padded) and `*_bin` (PAD SPACE) are `PadSpace`; `*_ci` (incl. the 11.8 default `uca1400_ai_ci`) is
//!    `CaseInsensitive`; anything else `Nondeterministic`;
//! 4. unique keys: PRIMARY and every UNIQUE index; a key part with `SUB_PART` (prefix) or a non-BTREE (long unique
//!    HASH) index is a prefix index, never the exact (tenant, key) arbiter. ODKU arbitrates on ANY unique key, so
//!    F4 requires the (tenant, key) index to be the only one;
//! 5. tenant column not generated (`GeneratedTenant`), of type VARCHAR or VARBINARY (`TenantNotText`);
//! 6. no trigger on the collection (`TriggerOnCollection`), no FK from or into it with an action other than
//!    RESTRICT / NO ACTION (`ForeignKeyAction`) (W5, D8);
//! 7. storage engine InnoDB (`NonTransactionalEngine`): MyISAM / MEMORY / Aria ignore transactions and row locks,
//!    and the UPDATE RETURNING emulation (`SELECT .. FOR UPDATE` + `UPDATE` in one transaction) depends on both;
//! 8. (adapter addition, after every oracle class) each declared string column is in utf8mb4 or a binary string
//!    (`NonUtf8Charset(f)`): the prefix test's byte length is the UTF-8 length.
//!
//! On success the result also carries the renderer's [`MyTable`] (column classes, unique keys, foreign keys) built
//! from the same catalog reads.

use std::fmt;
use std::time::Instant;

use monban_data_ir::{
    Collation, Column, Fidelity, Field, Op, OpKind, Pred, Schema, SchemaError, UniqueIndex, check_schema,
};
use monban_types::TenantId;

use crate::MysqlError;
use crate::conn::{Connection, Param};
use crate::lower::{MyClass, MyColumn, MyForeignKey, MyTable};
use crate::packet::Cell;

/// Why a collection is not admitted (or could not be inspected).
#[derive(Debug, PartialEq)]
pub enum LiveSchemaError {
    /// F4 `check_schema` refused the introspected schema (Debug prints e.g. `NonBinaryCollation(1)`).
    Schema(SchemaError),
    NotATable,
    TenantNotText,
    GeneratedTenant,
    TriggerOnCollection,
    ForeignKeyAction,
    NonTransactionalEngine,
    NonUtf8Charset(Field),
    /// A catalog row had an unexpected shape (not a refusal class: inspection failed).
    Catalog(String),
    Wire(MysqlError),
}

impl LiveSchemaError {
    /// The refusal class name (the schema-gate protocol vocabulary), or `None` if inspection itself failed.
    pub fn class(&self) -> Option<String> {
        Some(match self {
            LiveSchemaError::Schema(e) => format!("{e:?}"),
            LiveSchemaError::NotATable => "NotATable".into(),
            LiveSchemaError::TenantNotText => "TenantNotText".into(),
            LiveSchemaError::GeneratedTenant => "GeneratedTenant".into(),
            LiveSchemaError::TriggerOnCollection => "TriggerOnCollection".into(),
            LiveSchemaError::ForeignKeyAction => "ForeignKeyAction".into(),
            LiveSchemaError::NonTransactionalEngine => "NonTransactionalEngine".into(),
            LiveSchemaError::NonUtf8Charset(f) => format!("NonUtf8Charset({f})"),
            LiveSchemaError::Catalog(_) | LiveSchemaError::Wire(_) => return None,
        })
    }
}

impl fmt::Display for LiveSchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LiveSchemaError::Catalog(e) => write!(f, "catalog: {e}"),
            LiveSchemaError::Wire(e) => write!(f, "{e}"),
            other => write!(f, "{}", other.class().unwrap_or_default()),
        }
    }
}

impl std::error::Error for LiveSchemaError {}

impl From<MysqlError> for LiveSchemaError {
    fn from(e: MysqlError) -> Self {
        LiveSchemaError::Wire(e)
    }
}

impl From<SchemaError> for LiveSchemaError {
    fn from(e: SchemaError) -> Self {
        LiveSchemaError::Schema(e)
    }
}

/// An admitted collection: the F4 schema as introspected and the renderer's table description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveTable {
    pub schema: Schema,
    pub table: MyTable,
}

/// F4 collation of a MariaDB column from `DATA_TYPE` and `COLLATION_NAME` (module docs, point 3).
pub fn my_collation(data_type: &str, collation: Option<&str>) -> Collation {
    let d = data_type.to_ascii_lowercase();
    if d == "char" || d == "binary" {
        return Collation::PadSpace;
    }
    let Some(c) = collation else {
        return match d.as_str() {
            "tinyint" | "smallint" | "mediumint" | "int" | "bigint" | "varbinary" => Collation::Binary,
            _ => Collation::Nondeterministic,
        };
    };
    let c = c.to_ascii_lowercase();
    if c.ends_with("_nopad_bin") {
        Collation::Binary
    } else if c.ends_with("_bin") {
        Collation::PadSpace
    } else if c.ends_with("_ci") {
        Collation::CaseInsensitive
    } else {
        Collation::Nondeterministic
    }
}

type Rows = Vec<Vec<Cell>>;

fn q(conn: &mut Connection, sql: &str, params: &[&str], deadline: Instant) -> Result<Rows, LiveSchemaError> {
    let p: Vec<Param> = params.iter().map(|s| Param::Text((*s).to_owned())).collect();
    Ok(conn.execute_until(sql, &p, deadline)?.rows)
}

fn text(row: &[Cell], i: usize) -> Result<Option<String>, LiveSchemaError> {
    match row.get(i) {
        Some(Cell::Null) => Ok(None),
        Some(c) => c
            .as_str()
            .map(|s| Some(s.to_owned()))
            .ok_or_else(|| LiveSchemaError::Catalog(format!("column {i} is not text: {c:?}"))),
        None => Err(LiveSchemaError::Catalog(format!("missing column {i}"))),
    }
}

fn req_text(row: &[Cell], i: usize) -> Result<String, LiveSchemaError> {
    text(row, i)?.ok_or_else(|| LiveSchemaError::Catalog(format!("unexpected NULL in column {i}")))
}

fn count(rows: &Rows) -> Result<i64, LiveSchemaError> {
    rows.first()
        .and_then(|r| r.first())
        .and_then(Cell::as_i64)
        .ok_or_else(|| LiveSchemaError::Catalog("count(*) without an integer".into()))
}

struct LiveCol {
    nullable: bool,
    data_type: String,
    collation: Option<String>,
    generated: String,
    charset: Option<String>,
}

/// Introspect `namespace`.`declared.collection` and gate it (module docs). `Ok` means admitted.
pub fn check_live_schema(
    conn: &mut Connection,
    namespace: &str,
    declared: &Schema,
    deadline: Instant,
) -> Result<LiveTable, LiveSchemaError> {
    let coll = declared.collection.as_str();
    // 1. a base table, and its storage engine
    let t = q(
        conn,
        "SELECT TABLE_TYPE, ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?",
        &[namespace, coll],
        deadline,
    )?;
    let Some(trow) = t.first() else { return Err(LiveSchemaError::NotATable) };
    if text(trow, 0)?.as_deref() != Some("BASE TABLE") {
        return Err(LiveSchemaError::NotATable);
    }
    let engine = text(trow, 1)?.unwrap_or_default();
    // 2. columns
    let crows = q(
        conn,
        "SELECT COLUMN_NAME, IS_NULLABLE, DATA_TYPE, COLLATION_NAME, IS_GENERATED, CHARACTER_SET_NAME \
         FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?",
        &[namespace, coll],
        deadline,
    )?;
    let mut live: Vec<(String, LiveCol)> = Vec::with_capacity(crows.len());
    for r in &crows {
        live.push((
            req_text(r, 0)?,
            LiveCol {
                nullable: req_text(r, 1)? == "YES",
                data_type: req_text(r, 2)?.to_ascii_lowercase(),
                collation: text(r, 3)?,
                generated: text(r, 4)?.unwrap_or_else(|| "NEVER".into()),
                charset: text(r, 5)?,
            },
        ));
    }
    let find = |name: &str| live.iter().find(|(n, _)| n == name).map(|(_, c)| c);
    let mut columns = Vec::with_capacity(declared.columns.len());
    let mut my_columns = Vec::with_capacity(declared.columns.len());
    let mut tenant: Option<(&str, &LiveCol)> = None;
    for c in &declared.columns {
        let Some(l) = find(&c.name) else { return Err(SchemaError::UnknownField(c.field).into()) };
        if c.field == declared.tenant_field {
            tenant = Some((c.name.as_str(), l));
        }
        columns.push(Column {
            field: c.field,
            name: c.name.clone(),
            nullable: l.nullable,
            collation: my_collation(&l.data_type, l.collation.as_deref()),
            key: c.key,
        });
        my_columns.push(MyColumn { field: c.field, name: c.name.clone(), class: MyClass::of_type_name(&l.data_type) });
    }
    let field_of = |name: &str, k: usize| -> Field {
        declared
            .columns
            .iter()
            .find(|c| c.name == name)
            .map(|c| c.field)
            .unwrap_or_else(|| u32::MAX.saturating_sub(u32::try_from(k).unwrap_or(0)))
    };
    // 4. unique keys
    let irows = q(
        conn,
        "SELECT INDEX_NAME, COLUMN_NAME, SUB_PART, INDEX_TYPE FROM information_schema.STATISTICS \
         WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND NON_UNIQUE = 0 ORDER BY INDEX_NAME, SEQ_IN_INDEX",
        &[namespace, coll],
        deadline,
    )?;
    let mut idx: Vec<(String, UniqueIndex)> = Vec::new();
    for r in &irows {
        let name = req_text(r, 0)?;
        let col = req_text(r, 1)?;
        let sub = r.get(2).is_some_and(|c| !c.is_null());
        let itype = text(r, 3)?.unwrap_or_default();
        let pos = match idx.iter().position(|(n, _)| *n == name) {
            Some(p) => p,
            None => {
                idx.push((name, UniqueIndex { fields: Vec::new(), prefix: false }));
                idx.len().saturating_sub(1)
            }
        };
        if let Some((_, u)) = idx.get_mut(pos) {
            let k = u.fields.len();
            u.fields.push(field_of(&col, k));
            if sub || !itype.eq_ignore_ascii_case("BTREE") {
                u.prefix = true;
            }
        }
    }
    let schema = Schema {
        collection: coll.to_owned(),
        tenant_field: declared.tenant_field,
        columns,
        permitted: declared.permitted.clone(),
        unique_indexes: idx.iter().map(|(_, u)| u.clone()).collect(),
    };
    // 3 + 4: F4 on the admission probe
    let probe_tenant = TenantId::new(1).map_err(|_| LiveSchemaError::Catalog("probe tenant".into()))?;
    let probe = Op {
        tenant: probe_tenant,
        collection: coll.to_owned(),
        kind: OpKind::Upsert,
        filter: Pred::Tt,
        writes: Vec::new(),
        returning: Vec::new(),
    };
    check_schema(&probe, &schema, Fidelity::Exact)?;
    // 5. tenant column
    let Some((tname, tl)) = tenant else {
        return Err(SchemaError::UnknownField(declared.tenant_field).into());
    };
    if tl.generated != "NEVER" {
        return Err(LiveSchemaError::GeneratedTenant);
    }
    if tl.data_type != "varchar" && tl.data_type != "varbinary" {
        return Err(LiveSchemaError::TenantNotText);
    }
    // 6. triggers, FK actions
    let n = count(&q(
        conn,
        "SELECT count(*) FROM information_schema.TRIGGERS WHERE EVENT_OBJECT_SCHEMA = ? AND EVENT_OBJECT_TABLE = ?",
        &[namespace, coll],
        deadline,
    )?)?;
    if n != 0 {
        return Err(LiveSchemaError::TriggerOnCollection);
    }
    let n = count(&q(
        conn,
        "SELECT count(*) FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA = ? AND \
         (TABLE_NAME = ? OR REFERENCED_TABLE_NAME = ?) AND (UPDATE_RULE NOT IN ('RESTRICT', 'NO ACTION') OR \
         DELETE_RULE NOT IN ('RESTRICT', 'NO ACTION'))",
        &[namespace, coll, coll],
        deadline,
    )?)?;
    if n != 0 {
        return Err(LiveSchemaError::ForeignKeyAction);
    }
    // 7. storage engine
    if !engine.eq_ignore_ascii_case("InnoDB") {
        return Err(LiveSchemaError::NonTransactionalEngine);
    }
    // 8. string columns are utf8mb4 (or binary strings)
    for c in &declared.columns {
        if let Some(l) = find(&c.name)
            && MyClass::of_type_name(&l.data_type) == MyClass::Text
        {
            match l.charset.as_deref() {
                None | Some("utf8mb4") | Some("binary") => {}
                Some(_) => return Err(LiveSchemaError::NonUtf8Charset(c.field)),
            }
        }
    }
    // Renderer description: foreign keys out of the collection.
    let frows = q(
        conn,
        "SELECT CONSTRAINT_NAME, COLUMN_NAME, REFERENCED_TABLE_NAME, REFERENCED_COLUMN_NAME \
         FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND \
         REFERENCED_TABLE_NAME IS NOT NULL ORDER BY CONSTRAINT_NAME, ORDINAL_POSITION",
        &[namespace, coll],
        deadline,
    )?;
    let mut fks: Vec<(String, MyForeignKey)> = Vec::new();
    for r in &frows {
        let name = req_text(r, 0)?;
        let col = req_text(r, 1)?;
        let rt = req_text(r, 2)?;
        let rc = req_text(r, 3)?;
        let pos = match fks.iter().position(|(n, _)| *n == name) {
            Some(p) => p,
            None => {
                fks.push((
                    name,
                    MyForeignKey {
                        columns: Vec::new(),
                        ref_table: rt,
                        ref_columns: Vec::new(),
                        ref_tenant_column: Some(tname.to_owned()),
                    },
                ));
                fks.len().saturating_sub(1)
            }
        };
        if let Some((_, fk)) = fks.get_mut(pos) {
            let k = fk.columns.len();
            fk.columns.push(field_of(&col, k));
            fk.ref_columns.push(rc);
        }
    }
    let table = MyTable {
        namespace: Some(namespace.to_owned()),
        name: coll.to_owned(),
        columns: my_columns,
        unique: schema.unique_indexes.iter().map(|u| u.fields.clone()).collect(),
        fks: fks.into_iter().map(|(_, f)| f).collect(),
    };
    Ok(LiveTable { schema, table })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn collation_mapping() {
        assert_eq!(my_collation("varchar", Some("utf8mb4_nopad_bin")), Collation::Binary);
        assert_eq!(my_collation("varbinary", None), Collation::Binary);
        assert_eq!(my_collation("int", None), Collation::Binary);
        assert_eq!(my_collation("varchar", Some("utf8mb4_bin")), Collation::PadSpace);
        assert_eq!(my_collation("char", Some("utf8mb4_nopad_bin")), Collation::PadSpace);
        assert_eq!(my_collation("binary", None), Collation::PadSpace);
        assert_eq!(my_collation("varchar", Some("utf8mb4_uca1400_ai_ci")), Collation::CaseInsensitive);
        assert_eq!(my_collation("varchar", Some("utf8mb4_general_ci")), Collation::CaseInsensitive);
        assert_eq!(my_collation("varchar", Some("utf8mb4_uca1400_as_cs")), Collation::Nondeterministic);
        assert_eq!(my_collation("decimal", None), Collation::Nondeterministic);
    }
}
