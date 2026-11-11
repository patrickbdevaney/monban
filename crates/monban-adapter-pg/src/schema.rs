//! Live schema introspection and gate (R-DB-7 `check_schema()`, P4-pg-002).
//!
//! [`check_live_schema`] reads the PG catalog for one collection, never trusting the declared F4 [`Schema`] for
//! anything but the column names, field numbers, tenant/key roles and the permitted projection. It fills an F4
//! `Schema` from the catalog (NULL-ability, collations, every unique index and exclusion constraint), runs F4
//! `check_schema` on the admission probe (an Upsert with no writes: a collection must be fit for every OpKind,
//! because an F8 endowment may grant Upsert), then the live-only checks of PLAN D8/D9/D10:
//!
//! * collations: only `C`/`POSIX` (libc or default provider) count as binary; `default` only when the database's
//!   default collation is C/POSIX with the libc provider; citext is CaseInsensitive, bpchar PadSpace (D10);
//! * tenant column: not generated, type text or varchar (D4);
//! * no user trigger, no rewrite rule other than `_RETURN`, no FK with an action other than NO ACTION / RESTRICT,
//!   from or into the collection or any partition (W5, D8);
//! * a partitioned collection's key uses the column type's default opclass and the column's collation, no
//!   expression (R-DB-7);
//! * ENABLE + FORCE ROW LEVEL SECURITY with at least one policy; every ALL/INSERT/UPDATE policy has an explicit
//!   WITH CHECK; every permissive policy expression is exactly a tenant guard ([`crate::lower::is_tenant_guard`]).
//!
//! The order of the checks is that of oracles/schema-gate/refsubject.py, so each counterexample reports its class.
//! The live-only classes are [`LiveSchemaError`] variants next to the wrapped F4 [`SchemaError`] (PLAN D9).
//! On success the result also carries the renderer's [`PgTable`] built from the same catalog reads.

use std::fmt;
use std::time::Instant;

use monban_data_ir::{
    Collation, Column, Fidelity, Field, Op, OpKind, Pred, Schema, SchemaError, UniqueIndex, check_schema,
};
use monban_types::TenantId;

use crate::lower::{Dialect, PgClass, PgColumn, PgForeignKey, PgTable, is_tenant_guard};
use crate::wire::{Connection, Error as WireError};

/// Why a collection is not admitted (or could not be inspected).
#[derive(Debug)]
pub enum LiveSchemaError {
    /// F4 `check_schema` refused the introspected schema (Debug prints e.g. `NonBinaryCollation(0)`).
    Schema(SchemaError),
    TenantNotText,
    GeneratedTenant,
    TriggerOnCollection,
    RuleOnCollection,
    ForeignKeyAction,
    PartitionKeyMismatch,
    RlsNotForced,
    RlsPolicyWithoutCheck,
    RlsPolicyNotTenantScoped,
    NotATable,
    /// The server does not use UTF8 (the renderer's prefix/range exactness depends on it).
    ServerEncoding(String),
    /// A catalog row had an unexpected shape (not a refusal class: inspection failed).
    Catalog(String),
    Wire(WireError),
}

impl LiveSchemaError {
    /// The refusal class name (the schema-gate protocol vocabulary), or `None` if inspection itself failed.
    pub fn class(&self) -> Option<String> {
        Some(match self {
            LiveSchemaError::Schema(e) => format!("{e:?}"),
            LiveSchemaError::TenantNotText => "TenantNotText".into(),
            LiveSchemaError::GeneratedTenant => "GeneratedTenant".into(),
            LiveSchemaError::TriggerOnCollection => "TriggerOnCollection".into(),
            LiveSchemaError::RuleOnCollection => "RuleOnCollection".into(),
            LiveSchemaError::ForeignKeyAction => "ForeignKeyAction".into(),
            LiveSchemaError::PartitionKeyMismatch => "PartitionKeyMismatch".into(),
            LiveSchemaError::RlsNotForced => "RlsNotForced".into(),
            LiveSchemaError::RlsPolicyWithoutCheck => "RlsPolicyWithoutCheck".into(),
            LiveSchemaError::RlsPolicyNotTenantScoped => "RlsPolicyNotTenantScoped".into(),
            LiveSchemaError::NotATable => "NotATable".into(),
            LiveSchemaError::ServerEncoding(_) | LiveSchemaError::Catalog(_) | LiveSchemaError::Wire(_) => {
                return None;
            }
        })
    }
}

impl fmt::Display for LiveSchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LiveSchemaError::ServerEncoding(e) => write!(f, "server_encoding {e:?} is not UTF8"),
            LiveSchemaError::Catalog(e) => write!(f, "catalog: {e}"),
            LiveSchemaError::Wire(e) => write!(f, "{e}"),
            other => write!(f, "{}", other.class().unwrap_or_default()),
        }
    }
}

impl std::error::Error for LiveSchemaError {}

impl From<WireError> for LiveSchemaError {
    fn from(e: WireError) -> Self {
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
    pub table: PgTable,
}

type Rows = Vec<Vec<Option<String>>>;

fn q(conn: &mut Connection, sql: &str, params: &[&str], deadline: Instant) -> Result<Rows, LiveSchemaError> {
    let p: Vec<Option<&str>> = params.iter().map(|s| Some(*s)).collect();
    Ok(conn.query(sql, &p, deadline)?.rows)
}

fn cell(row: &[Option<String>], i: usize) -> Result<&str, LiveSchemaError> {
    match row.get(i) {
        Some(Some(s)) => Ok(s.as_str()),
        Some(None) => Err(LiveSchemaError::Catalog(format!("unexpected NULL in column {i}"))),
        None => Err(LiveSchemaError::Catalog(format!("missing column {i}"))),
    }
}

fn opt_cell(row: &[Option<String>], i: usize) -> Result<Option<&str>, LiveSchemaError> {
    match row.get(i) {
        Some(c) => Ok(c.as_deref()),
        None => Err(LiveSchemaError::Catalog(format!("missing column {i}"))),
    }
}

fn int(row: &[Option<String>], i: usize) -> Result<i64, LiveSchemaError> {
    let s = cell(row, i)?;
    s.parse().map_err(|_| LiveSchemaError::Catalog(format!("not an integer: {s:?}")))
}

fn boolean(row: &[Option<String>], i: usize) -> Result<bool, LiveSchemaError> {
    match cell(row, i)? {
        "t" => Ok(true),
        "f" => Ok(false),
        s => Err(LiveSchemaError::Catalog(format!("not a boolean: {s:?}"))),
    }
}

/// `int2vector` / `oidvector` text ("1 2") or an array ("{1,2}") as integers.
fn ints(s: &str) -> Result<Vec<i64>, LiveSchemaError> {
    s.trim_matches(|c| c == '{' || c == '}')
        .split([' ', ','])
        .filter(|t| !t.is_empty())
        .map(|t| t.parse().map_err(|_| LiveSchemaError::Catalog(format!("not an integer list: {s:?}"))))
        .collect()
}

struct Attr {
    num: i64,
    name: String,
    notnull: bool,
    generated: bool,
    typname: String,
    typoid: i64,
    coll: i64,
    collname: String,
    collprovider: String,
}

/// Inspect and gate `namespace`.`declared.collection` on `conn`. `declared` supplies only names, field numbers,
/// the tenant field, key flags and `permitted`; everything else is read from the catalog. Foreign keys out of the
/// collection are recorded for the renderer with the convention that the referenced table's tenant column has the
/// same name as this collection's.
pub fn check_live_schema(
    conn: &mut Connection,
    namespace: &str,
    declared: &Schema,
    deadline: Instant,
) -> Result<LiveTable, LiveSchemaError> {
    check_live_schema_dialect(conn, namespace, declared, deadline, Dialect::Postgres)
}

/// [`check_live_schema`] for `dialect`. `Postgres` is the gate described above, unchanged.
///
/// `Crdb` (feature `crdb`; oracles/schema-gate README "MariaDB and CockroachDB modes"): the same pg_catalog reads,
/// with CockroachDB's catalog semantics. A plain STRING has collation `default`, which is byte order (binary, NO PAD)
/// on CockroachDB whatever the database locale, so no pg_database lookup; a COLLATE'd STRING has a collation oid with
/// no pg_collation row, so it is never binary. CockroachDB has no rewrite rules, exclusion constraints, PG
/// partitioning or `pg_partition_tree`, so those reads are skipped (the trigger and FK-action checks cover the
/// collection itself). RLS is not part of the crdb dialect (no `rls_policy` / `rls_bind`, PREFLIGHT D-P7.8), so
/// FORCE RLS is not required: tenant scoping on crdb rests on the rendered tenant conjunct and the upsert guard
/// alone. Referenced table names for the renderer's FK check come from a pg_class join instead of `::regclass`.
pub fn check_live_schema_dialect(
    conn: &mut Connection,
    namespace: &str,
    declared: &Schema,
    deadline: Instant,
    dialect: Dialect,
) -> Result<LiveTable, LiveSchemaError> {
    let crdb = dialect.is_crdb();
    if let Some(enc) = conn.parameter("server_encoding")
        && enc != "UTF8"
    {
        return Err(LiveSchemaError::ServerEncoding(enc.to_owned()));
    }
    let coll = declared.collection.as_str();
    let rel = q(
        conn,
        "SELECT c.oid::int8::text, c.relkind::text, c.relrowsecurity, c.relforcerowsecurity \
         FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = $1 AND c.relname = $2",
        &[namespace, coll],
        deadline,
    )?;
    let Some(r) = rel.first() else { return Err(LiveSchemaError::NotATable) };
    let oid = int(r, 0)?;
    let relkind = cell(r, 1)?.to_owned();
    // CockroachDB leaves relrowsecurity / relforcerowsecurity NULL; RLS is not read for the crdb dialect at all.
    let (rls, force) = if crdb { (false, false) } else { (boolean(r, 2)?, boolean(r, 3)?) };
    if relkind != "r" && relkind != "p" {
        return Err(LiveSchemaError::NotATable);
    }
    let oid_s = oid.to_string();

    let db_default_c = if crdb {
        true
    } else {
        let db = q(
            conn,
            "SELECT datcollate::text, datlocprovider::text FROM pg_catalog.pg_database WHERE datname = current_database()",
            &[],
            deadline,
        )?;
        let Some(d) = db.first() else { return Err(LiveSchemaError::Catalog("no pg_database row".into())) };
        matches!(cell(d, 0)?, "C" | "POSIX") && cell(d, 1)? == "c"
    };
    let binary_coll = |name: &str, provider: &str| {
        (matches!(name, "C" | "POSIX") && matches!(provider, "c" | "d")) || (name == "default" && db_default_c)
    };

    let attrs: Vec<Attr> = q(
        conn,
        "SELECT a.attnum::int8::text, a.attname::text, a.attnotnull, a.attgenerated::text, t.typname::text, \
         a.atttypid::int8::text, a.attcollation::int8::text, coalesce(co.collname::text, ''), \
         coalesce(co.collprovider::text, '') \
         FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_type t ON t.oid = a.atttypid \
         LEFT JOIN pg_catalog.pg_collation co ON co.oid = a.attcollation \
         WHERE a.attrelid = $1::oid AND a.attnum > 0 AND NOT a.attisdropped",
        &[&oid_s],
        deadline,
    )?
    .iter()
    .map(|r| {
        Ok(Attr {
            num: int(r, 0)?,
            name: cell(r, 1)?.to_owned(),
            notnull: boolean(r, 2)?,
            generated: !opt_cell(r, 3)?.unwrap_or("").is_empty(),
            typname: cell(r, 4)?.to_owned(),
            typoid: int(r, 5)?,
            coll: int(r, 6)?,
            collname: cell(r, 7)?.to_owned(),
            collprovider: cell(r, 8)?.to_owned(),
        })
    })
    .collect::<Result<_, LiveSchemaError>>()?;
    let by_name = |n: &str| attrs.iter().find(|a| a.name == n);
    let by_num = |k: i64| attrs.iter().find(|a| a.num == k);
    let field_of = |n: &str| declared.columns.iter().find(|c| c.name == n).map(|c| c.field);

    let tf = declared.tenant_field;
    let mut columns = Vec::with_capacity(declared.columns.len());
    let mut pg_columns = Vec::with_capacity(declared.columns.len());
    let mut tenant_attr: Option<&Attr> = None;
    for c in &declared.columns {
        let a = by_name(&c.name).ok_or(SchemaError::UnknownField(c.field))?;
        let collation = if a.typname == "citext" {
            Collation::CaseInsensitive
        } else if a.typname == "bpchar" {
            Collation::PadSpace
        } else if a.coll == 0 || binary_coll(&a.collname, &a.collprovider) {
            // a.coll == 0: non-collatable type (int, bigint, uuid, bytea): byte-exact equality.
            Collation::Binary
        } else {
            Collation::Nondeterministic
        };
        if c.field == tf {
            tenant_attr = Some(a);
        }
        columns.push(Column { field: c.field, name: c.name.clone(), nullable: !a.notnull, collation, key: c.key });
        pg_columns.push(PgColumn { field: c.field, name: c.name.clone(), class: PgClass::of_type_name(&a.typname) });
    }
    let tenant_attr = tenant_attr.ok_or(SchemaError::UnknownField(tf))?;
    let governs = |f: Field| f == tf || columns.iter().any(|c| c.key && c.field == f);

    // Every unique index (incl. the primary key); expression / partial parts make it a "prefix" index.
    // CockroachDB leaves collprovider NULL (so its `C` / `POSIX` rows never count as binary, as in the reference;
    // only `default` does, via `db_default_c`).
    let colls: Vec<(i64, String, String)> = q(
        conn,
        if crdb {
            "SELECT oid::int8::text, collname::text, coalesce(collprovider::text, '') FROM pg_catalog.pg_collation"
        } else {
            "SELECT oid::int8::text, collname::text, collprovider::text FROM pg_catalog.pg_collation"
        },
        &[],
        deadline,
    )?
    .iter()
    .map(|r| Ok((int(r, 0)?, cell(r, 1)?.to_owned(), cell(r, 2)?.to_owned())))
    .collect::<Result<_, LiveSchemaError>>()?;
    let idx = q(
        conn,
        "SELECT i.indkey::text, i.indexprs IS NOT NULL, i.indpred IS NOT NULL, i.indcollation::text, \
         i.indnkeyatts::int8::text FROM pg_catalog.pg_index i WHERE i.indrelid = $1::oid AND i.indisunique",
        &[&oid_s],
        deadline,
    )?;
    let mut unique_indexes = Vec::with_capacity(idx.len());
    let mut pg_unique = Vec::with_capacity(idx.len());
    for r in &idx {
        let nkey = usize::try_from(int(r, 4)?).map_err(|_| LiveSchemaError::Catalog("indnkeyatts".into()))?;
        let keys = ints(cell(r, 0)?)?;
        let icolls = ints(cell(r, 3)?)?;
        let mut prefix = boolean(r, 1)? || boolean(r, 2)?;
        let mut fields = Vec::new();
        let mut plain = Vec::new();
        for (k, co) in keys.iter().zip(icolls.iter()).take(nkey) {
            if *k == 0 {
                prefix = true;
                continue;
            }
            match by_num(*k).and_then(|a| field_of(&a.name)) {
                None => {
                    // An undeclared column: can never match (tenant, key). Encoded out of the declared range.
                    fields.push(u32::MAX);
                }
                Some(f) => {
                    fields.push(f);
                    plain.push(f);
                    if governs(f) && *co != 0 {
                        let ok = colls.iter().any(|(o, n, p)| o == co && binary_coll(n, p));
                        if !ok {
                            return Err(SchemaError::NonBinaryCollation(f).into());
                        }
                    }
                }
            }
        }
        unique_indexes.push(UniqueIndex { fields, prefix });
        pg_unique.push(plain);
    }
    let n_excl = if crdb {
        0
    } else {
        let excl = q(
            conn,
            "SELECT count(*)::int8::text FROM pg_catalog.pg_constraint WHERE conrelid = $1::oid AND contype = 'x'",
            &[&oid_s],
            deadline,
        )?;
        excl.first().map(|r| int(r, 0)).transpose()?.unwrap_or(0)
    };
    for _ in 0..n_excl {
        unique_indexes.push(UniqueIndex { fields: Vec::new(), prefix: true });
        pg_unique.push(Vec::new());
    }

    let schema = Schema {
        collection: declared.collection.clone(),
        tenant_field: tf,
        columns,
        permitted: declared.permitted.clone(),
        unique_indexes,
    };
    let probe_tenant = TenantId::new(1).map_err(|_| LiveSchemaError::Catalog("probe tenant".into()))?;
    let probe = Op {
        tenant: probe_tenant,
        collection: declared.collection.clone(),
        kind: OpKind::Upsert,
        filter: Pred::Tt,
        writes: Vec::new(),
        returning: Vec::new(),
    };
    check_schema(&probe, &schema, Fidelity::Exact)?;

    if tenant_attr.generated {
        return Err(LiveSchemaError::GeneratedTenant);
    }
    if !matches!(tenant_attr.typname.as_str(), "text" | "varchar") {
        return Err(LiveSchemaError::TenantNotText);
    }
    // The collection plus every partition (pg_partition_tree is empty for an ordinary table).
    let tree = if crdb {
        "($1::oid)"
    } else {
        "(SELECT $1::oid UNION SELECT relid FROM pg_catalog.pg_partition_tree($1::oid::regclass))"
    };
    let count = |conn: &mut Connection, sql: String| -> Result<i64, LiveSchemaError> {
        let r = q(conn, &sql, &[&oid_s], deadline)?;
        r.first().map(|r| int(r, 0)).transpose().map(|n| n.unwrap_or(0))
    };
    if count(
        conn,
        format!("SELECT count(*)::int8::text FROM pg_catalog.pg_trigger WHERE tgrelid IN {tree} AND NOT tgisinternal"),
    )? > 0
    {
        return Err(LiveSchemaError::TriggerOnCollection);
    }
    if !crdb
        && count(
            conn,
            format!(
                "SELECT count(*)::int8::text FROM pg_catalog.pg_rewrite WHERE ev_class IN {tree} AND rulename <> '_RETURN'"
            ),
        )? > 0
    {
        return Err(LiveSchemaError::RuleOnCollection);
    }
    if count(
        conn,
        format!(
            "SELECT count(*)::int8::text FROM pg_catalog.pg_constraint WHERE contype = 'f' AND (conrelid IN {tree} \
             OR confrelid IN {tree}) AND (confupdtype NOT IN ('a','r') OR confdeltype NOT IN ('a','r'))"
        ),
    )? > 0
    {
        return Err(LiveSchemaError::ForeignKeyAction);
    }
    if relkind == "p" && !crdb {
        let pr = q(
            conn,
            "SELECT partstrat::text, partattrs::text, partclass::text, partcollation::text, partexprs IS NOT NULL \
             FROM pg_catalog.pg_partitioned_table WHERE partrelid = $1::oid",
            &[&oid_s],
            deadline,
        )?;
        let Some(p) = pr.first() else { return Err(LiveSchemaError::PartitionKeyMismatch) };
        if boolean(p, 4)? {
            return Err(LiveSchemaError::PartitionKeyMismatch);
        }
        let am = if cell(p, 0)? == "h" { "hash" } else { "btree" };
        let pattrs = ints(cell(p, 1)?)?;
        let pclass = ints(cell(p, 2)?)?;
        let pcoll = ints(cell(p, 3)?)?;
        if pattrs.len() != pclass.len() || pattrs.len() != pcoll.len() {
            return Err(LiveSchemaError::PartitionKeyMismatch);
        }
        for ((a, cl), pc) in pattrs.iter().zip(pclass.iter()).zip(pcoll.iter()) {
            let Some(at) = by_num(*a) else { return Err(LiveSchemaError::PartitionKeyMismatch) };
            let typ = at.typoid.to_string();
            let d = q(
                conn,
                "SELECT opc.oid::int8::text FROM pg_catalog.pg_opclass opc JOIN pg_catalog.pg_am am \
                 ON am.oid = opc.opcmethod WHERE opc.opcintype = $1::oid AND opc.opcdefault AND am.amname = $2",
                &[&typ, am],
                deadline,
            )?;
            let default_ok = match d.first() {
                Some(r) => int(r, 0)? == *cl,
                None => false,
            };
            if !default_ok || *pc != at.coll {
                return Err(LiveSchemaError::PartitionKeyMismatch);
            }
        }
    }
    let tname = tenant_attr.name.as_str();
    if !crdb {
        if !(rls && force) {
            return Err(LiveSchemaError::RlsNotForced);
        }
        let pols = q(
            conn,
            "SELECT polcmd::text, polpermissive, pg_catalog.pg_get_expr(polqual, polrelid), \
             pg_catalog.pg_get_expr(polwithcheck, polrelid) FROM pg_catalog.pg_policy WHERE polrelid = $1::oid",
            &[&oid_s],
            deadline,
        )?;
        if pols.is_empty() {
            return Err(LiveSchemaError::RlsNotForced);
        }
        for p in &pols {
            let cmd = cell(p, 0)?;
            let qual = opt_cell(p, 2)?;
            let check = opt_cell(p, 3)?;
            if matches!(cmd, "*" | "a" | "w") && check.is_none() {
                return Err(LiveSchemaError::RlsPolicyWithoutCheck);
            }
            if boolean(p, 1)? && [qual, check].iter().flatten().any(|e| !is_tenant_guard(e, tname)) {
                return Err(LiveSchemaError::RlsPolicyNotTenantScoped);
            }
        }
    }

    // Foreign keys out of the collection, for the renderer's W6 check.
    let fk_sql = if crdb {
        "SELECT con.conkey::text, con.confkey::text, con.confrelid::int8::text, r.relname::text \
         FROM pg_catalog.pg_constraint con JOIN pg_catalog.pg_class r ON r.oid = con.confrelid \
         WHERE con.conrelid = $1::oid AND con.contype = 'f'"
    } else {
        "SELECT con.conkey::text, con.confkey::text, con.confrelid::int8::text, con.confrelid::regclass::text \
         FROM pg_catalog.pg_constraint con WHERE con.conrelid = $1::oid AND con.contype = 'f'"
    };
    let fk_rows = q(conn, fk_sql, &[&oid_s], deadline)?;
    let mut fks = Vec::with_capacity(fk_rows.len());
    for r in &fk_rows {
        let local = ints(cell(r, 0)?)?;
        let remote = ints(cell(r, 1)?)?;
        let ref_oid = cell(r, 2)?.to_owned();
        let ref_attrs = q(
            conn,
            "SELECT attnum::int8::text, attname::text FROM pg_catalog.pg_attribute \
             WHERE attrelid = $1::oid AND attnum > 0 AND NOT attisdropped",
            &[&ref_oid],
            deadline,
        )?;
        let mut columns = Vec::with_capacity(local.len());
        for k in &local {
            // An undeclared local column cannot be the tenant: out-of-range field.
            columns.push(by_num(*k).and_then(|a| field_of(&a.name)).unwrap_or(u32::MAX));
        }
        let mut ref_columns = Vec::with_capacity(remote.len());
        for k in &remote {
            let mut name = None;
            for a in &ref_attrs {
                if int(a, 0)? == *k {
                    name = Some(cell(a, 1)?.to_owned());
                }
            }
            ref_columns.push(name.ok_or_else(|| LiveSchemaError::Catalog("fk column".into()))?);
        }
        fks.push(PgForeignKey {
            columns,
            ref_table: cell(r, 3)?.to_owned(),
            ref_columns,
            ref_tenant_column: Some(tname.to_owned()),
        });
    }
    let table = PgTable {
        namespace: Some(namespace.to_owned()),
        name: declared.collection.clone(),
        columns: pg_columns,
        unique: pg_unique,
        fks,
    };
    Ok(LiveTable { schema, table })
}
