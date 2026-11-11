//! PostgreSQL renderer (P4-pg-002): turns the engine-neutral [`Lowered`] tree of `monban_data_ir::lower_op` into one
//! PG statement with `$n` text parameters, plus the RLS defence-in-depth statements (R-DB-1).
//!
//! Exactness (SPEC §E, `Fidelity::Exact`, the renderer obligations stated in monban-data-ir `lower.rs`):
//!
//! * every atom is `(CASE WHEN col IS NULL THEN NULL ELSE <test> END)`, so a NULL column is UNKNOWN exactly as in
//!   Lean `sql3`, including `InList(f, [])` (FALSE on a present column, UNKNOWN on NULL; never constant FALSE);
//! * text tests are `col::text = $n::text COLLATE "C"` (ranges with `>=`/`<=` under `COLLATE "C"`, prefixes as
//!   `left(col::text, $n::int) = $m::text COLLATE "C"`): byte-wise whatever the column collation, and C ordering of
//!   UTF-8 is code-point order (`refLe`). Never LIKE. The server encoding must be UTF8 ([`crate::schema`] checks it);
//! * integer tests are `col = $n::bigint` on integer columns only;
//! * class-strict: a value whose class differs from the column's PG type class can never be equal, so the test is
//!   the constant `false` (still wrapped, so NULL stays UNKNOWN). A column whose type is neither integer nor text is
//!   refused ([`RenderError::ColumnType`]), never guessed;
//! * PG text cannot hold NUL, so an equality / prefix test with a NUL-bearing literal is `false`; a range bound with
//!   NUL is refused (no exact NUL-free rendering of that bound is attempted);
//! * `And`/`Or` are parenthesised; the tenant conjunct stays the left child of the root `And`.
//!
//! Mandated write forms (SPEC §E W1-W7): one statement, verb first, never MERGE / WITH / REPLACE / `;`; the upsert is
//! `INSERT .. ON CONFLICT (<the sole (tenant, key) unique index>) DO NOTHING | DO UPDATE SET c = excluded.c ..
//! WHERE (<table>.<tenant>::text COLLATE "C") = (excluded.<tenant>::text COLLATE "C")` (no user expression in the
//! upsert WHERE, binary text both sides). Writes into a table whose unique keys (Insert/Upsert) or foreign keys (any
//! write) do not carry the tenant are refused (W6 existence oracle, W3).
#![allow(clippy::module_name_repetitions)]

use std::fmt;

use monban_data_ir::{
    Fidelity, Field, LowerError, Lowered, MAX_PRED_DEPTH, Op, OpKind, Schema, SqlExpr, Stmt, UpsertAction, Value,
    lower_op, tenant_text,
};
use monban_types::TenantId;

/// PostgreSQL silently truncates identifiers longer than this (NAMEDATALEN - 1); longer names are refused.
pub const MAX_IDENT_BYTES: usize = 63;
/// Most parameters one extended-protocol statement can carry (Bind's Int16 count).
pub const MAX_PARAMS: usize = 65_535;

/// IR storage class of a PG column type. Only `Int` (int2/int4/int8) and `Text` (text, varchar, citext) columns
/// are rendered; anything else (bpchar, numeric, uuid, ...) is `Other` and refused when an op touches it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PgClass {
    Int,
    Text,
    Other,
}

impl PgClass {
    /// Class of a PG type name (`pg_type.typname`, or a declared type such as `bigint`, `character varying(16)`).
    pub fn of_type_name(name: &str) -> PgClass {
        let n = name.trim().to_ascii_lowercase();
        let base = n.split('(').next().unwrap_or("").trim();
        match base {
            "int2" | "int4" | "int8" | "smallint" | "int" | "integer" | "bigint" => PgClass::Int,
            "text" | "varchar" | "character varying" | "citext" => PgClass::Text,
            _ => PgClass::Other,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PgColumn {
    pub field: Field,
    pub name: String,
    pub class: PgClass,
}

/// A foreign key out of the collection. It carries the tenant iff the tenant column is one of `columns` and the
/// referenced column at the same position is `ref_tenant_column` (the referenced table's tenant column).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PgForeignKey {
    pub columns: Vec<Field>,
    pub ref_table: String,
    pub ref_columns: Vec<String>,
    /// `None` = unknown: the key is treated as not tenant-carrying, so writes are refused.
    pub ref_tenant_column: Option<String>,
}

/// What the renderer knows about one collection (filled by [`crate::schema::check_live_schema`] from the live
/// catalog, or by a test/oracle subject from its declaration).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PgTable {
    /// Schema (namespace) qualifier; `None` renders the bare name (resolved through the connection's search_path).
    pub namespace: Option<String>,
    pub name: String,
    pub columns: Vec<PgColumn>,
    /// Every unique key (primary key, unique index or constraint) as its plain-column fields; expression parts are
    /// left out, so an expression over the tenant does not count as carrying it.
    pub unique: Vec<Vec<Field>>,
    pub fks: Vec<PgForeignKey>,
}

impl PgTable {
    fn column(&self, f: Field) -> Result<&PgColumn, RenderError> {
        self.columns.iter().find(|c| c.field == f).ok_or(RenderError::UnknownField(f))
    }
}

/// A bound parameter. Sent as text over the wire ([`Param::text`]); the SQL casts it (`::bigint` / `::text`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Param {
    Int(i64),
    Text(String),
}

impl Param {
    pub fn text(&self) -> String {
        match self {
            Param::Int(i) => i.to_string(),
            Param::Text(s) => s.clone(),
        }
    }
}

/// One rendered statement (or WHERE body for [`render_filter`]) and its parameters, `$1..` in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    pub sql: String,
    pub params: Vec<Param>,
}

impl Rendered {
    /// The parameters as wire text, for [`crate::wire::Connection::query`] (`params_as_wire(&texts)`).
    pub fn param_texts(&self) -> Vec<String> {
        self.params.iter().map(Param::text).collect()
    }
}

/// Borrow [`Rendered::param_texts`] as the `&[Option<&str>]` the wire client takes.
pub fn params_as_wire(texts: &[String]) -> Vec<Option<&str>> {
    texts.iter().map(|s| Some(s.as_str())).collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenderError {
    /// `lower_op` refused the op (F4 `check_schema` or a shape rule).
    Lower(LowerError),
    /// The op's collection is not this table.
    CollectionMismatch,
    UnknownField(Field),
    /// The column's PG type is neither integer nor text (or the tenant column is not text).
    ColumnType(Field),
    /// A written value's class differs from the column's (it would be coerced by PG, changing its IR value).
    ValueClass(Field),
    /// A range bound or written text containing NUL (PG text cannot hold it).
    NulInText(Field),
    /// Insert/Upsert on a table with a unique key that lacks the tenant column (W6 existence oracle, W3).
    UniqueKeyWithoutTenant,
    /// Upsert whose arbiter is not exactly the table's sole unique key (W3).
    ArbiterNotSoleUniqueKey,
    /// A write on a table with a foreign key that does not map the tenant to the referenced tenant (W6).
    ForeignKeyWithoutTenant,
    /// Empty, NUL-bearing or over-long identifier.
    BadIdentifier,
    /// RLS role or GUC setting name outside the accepted grammar.
    BadRlsName,
    /// More than [`MAX_PARAMS`] parameters.
    TooManyParams,
    /// Filter deeper than `MAX_PRED_DEPTH + 1`.
    TooDeep,
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RenderError {}

impl From<LowerError> for RenderError {
    fn from(e: LowerError) -> Self {
        RenderError::Lower(e)
    }
}

/// `"name"` with `"` doubled. Refuses empty, NUL-bearing and over-long names.
pub fn quote_ident(name: &str) -> Result<String, RenderError> {
    if name.is_empty() || name.len() > MAX_IDENT_BYTES || name.contains('\0') {
        return Err(RenderError::BadIdentifier);
    }
    Ok(format!("\"{}\"", name.replace('"', "\"\"")))
}

fn quote_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn table_ref(ns: Option<&str>, name: &str) -> Result<String, RenderError> {
    Ok(match ns {
        Some(n) => format!("{}.{}", quote_ident(n)?, quote_ident(name)?),
        None => quote_ident(name)?,
    })
}

struct W<'a> {
    table: &'a PgTable,
    alias: Option<String>,
    offset: usize,
    params: Vec<Param>,
}

impl W<'_> {
    fn ph(&mut self, p: Param) -> Result<String, RenderError> {
        self.params.push(p);
        let n = self.offset.checked_add(self.params.len()).ok_or(RenderError::TooManyParams)?;
        if n > MAX_PARAMS {
            return Err(RenderError::TooManyParams);
        }
        Ok(format!("${n}"))
    }

    fn col(&self, f: Field) -> Result<(String, PgClass), RenderError> {
        let c = self.table.column(f)?;
        let q = quote_ident(&c.name)?;
        Ok(match &self.alias {
            Some(a) => (format!("{a}.{q}"), c.class),
            None => (q, c.class),
        })
    }

    fn eq_test(&mut self, f: Field, c: &str, class: PgClass, v: &Value) -> Result<String, RenderError> {
        Ok(match (class, v) {
            (PgClass::Other, _) => return Err(RenderError::ColumnType(f)),
            (PgClass::Int, Value::Int(i)) => format!("({c} = {}::bigint)", self.ph(Param::Int(*i))?),
            (PgClass::Text, Value::Str(s)) if s.contains('\0') => "false".into(),
            (PgClass::Text, Value::Str(s)) => {
                format!("({c}::text = {}::text COLLATE \"C\")", self.ph(Param::Text(s.clone()))?)
            }
            _ => "false".into(),
        })
    }

    fn range_test(&mut self, f: Field, c: &str, class: PgClass, lo: &Value, hi: &Value) -> Result<String, RenderError> {
        Ok(match (class, lo, hi) {
            (PgClass::Other, _, _) => return Err(RenderError::ColumnType(f)),
            (PgClass::Int, Value::Int(a), Value::Int(b)) => {
                let pa = self.ph(Param::Int(*a))?;
                let pb = self.ph(Param::Int(*b))?;
                format!("({c} >= {pa}::bigint AND {c} <= {pb}::bigint)")
            }
            (PgClass::Text, Value::Str(a), Value::Str(b)) => {
                if a.contains('\0') || b.contains('\0') {
                    return Err(RenderError::NulInText(f));
                }
                let pa = self.ph(Param::Text(a.clone()))?;
                let pb = self.ph(Param::Text(b.clone()))?;
                format!("({c}::text >= {pa}::text COLLATE \"C\" AND {c}::text <= {pb}::text COLLATE \"C\")")
            }
            _ => "false".into(),
        })
    }

    fn pfx_test(&mut self, f: Field, c: &str, class: PgClass, s: &str) -> Result<String, RenderError> {
        Ok(match class {
            PgClass::Other => return Err(RenderError::ColumnType(f)),
            PgClass::Int => "false".into(),
            PgClass::Text if s.contains('\0') => "false".into(),
            PgClass::Text => {
                let n = i64::try_from(s.chars().count()).map_err(|_| RenderError::TooManyParams)?;
                let pn = self.ph(Param::Int(n))?;
                let ps = self.ph(Param::Text(s.to_owned()))?;
                format!("(left({c}::text, {pn}::int) = {ps}::text COLLATE \"C\")")
            }
        })
    }

    fn expr(&mut self, e: &SqlExpr, budget: usize) -> Result<String, RenderError> {
        let next = budget.checked_sub(1).ok_or(RenderError::TooDeep)?;
        let atom = |c: &str, test: String| format!("(CASE WHEN {c} IS NULL THEN NULL ELSE {test} END)");
        Ok(match e {
            SqlExpr::Lit(true) => "true".into(),
            SqlExpr::Lit(false) => "false".into(),
            SqlExpr::CmpEq(f, v) => {
                let (c, class) = self.col(*f)?;
                let t = self.eq_test(*f, &c, class, v)?;
                atom(&c, t)
            }
            SqlExpr::InList(f, vs) => {
                let (c, class) = self.col(*f)?;
                if class == PgClass::Other {
                    return Err(RenderError::ColumnType(*f));
                }
                if vs.is_empty() {
                    atom(&c, "false".into())
                } else {
                    let mut tests = Vec::with_capacity(vs.len());
                    for v in vs {
                        tests.push(self.eq_test(*f, &c, class, v)?);
                    }
                    atom(&c, format!("({})", tests.join(" OR ")))
                }
            }
            SqlExpr::Between(f, lo, hi) => {
                let (c, class) = self.col(*f)?;
                let t = self.range_test(*f, &c, class, lo, hi)?;
                atom(&c, t)
            }
            SqlExpr::Pfx(f, s) => {
                let (c, class) = self.col(*f)?;
                let t = self.pfx_test(*f, &c, class, s)?;
                atom(&c, t)
            }
            SqlExpr::And(a, b) => format!("({} AND {})", self.expr(a, next)?, self.expr(b, next)?),
            SqlExpr::Or(a, b) => format!("({} OR {})", self.expr(a, next)?, self.expr(b, next)?),
            SqlExpr::Not(a) => format!("(NOT {})", self.expr(a, next)?),
        })
    }

    fn value(&mut self, f: Field, v: &Value) -> Result<String, RenderError> {
        let class = self.table.column(f)?.class;
        match (class, v) {
            (PgClass::Int, Value::Int(i)) => Ok(format!("{}::bigint", self.ph(Param::Int(*i))?)),
            (PgClass::Text, Value::Str(s)) => {
                if s.contains('\0') {
                    return Err(RenderError::NulInText(f));
                }
                Ok(format!("{}::text", self.ph(Param::Text(s.clone()))?))
            }
            (PgClass::Other, _) => Err(RenderError::ColumnType(f)),
            _ => Err(RenderError::ValueClass(f)),
        }
    }
}

/// Filter budget: `lower_q` adds one level above `MAX_PRED_DEPTH`.
const EXPR_BUDGET: usize = MAX_PRED_DEPTH + 1;

/// Render a filter (a `lowerQ` tree) as a PG boolean expression, the WHERE body. `alias` qualifies every column
/// (self-joins); placeholders start at `$param_offset + 1`.
pub fn render_filter(
    e: &SqlExpr,
    table: &PgTable,
    alias: Option<&str>,
    param_offset: usize,
) -> Result<Rendered, RenderError> {
    let alias = alias.map(quote_ident).transpose()?;
    let mut w = W { table, alias, offset: param_offset, params: Vec::new() };
    let sql = w.expr(e, EXPR_BUDGET)?;
    Ok(Rendered { sql, params: w.params })
}

fn tenant_carried(table: &PgTable, tf: Field) -> Result<(), RenderError> {
    for fk in &table.fks {
        let pos = fk.columns.iter().position(|f| *f == tf).ok_or(RenderError::ForeignKeyWithoutTenant)?;
        let ok = fk.columns.len() == fk.ref_columns.len()
            && match (&fk.ref_tenant_column, fk.ref_columns.get(pos)) {
                (Some(want), Some(got)) => want == got,
                _ => false,
            };
        if !ok {
            return Err(RenderError::ForeignKeyWithoutTenant);
        }
    }
    Ok(())
}

/// The SQL dialect a statement is rendered for. Every dialect speaks the PostgreSQL forms above; they differ only
/// where an engine evaluates one of those forms differently.
///
/// * `Postgres`: the golden PG forms (default).
/// * `Crdb` (feature `crdb`, PREFLIGHT D-P7.8, spikes/q4-005): CockroachDB over the PG wire. The upsert guard is
///   `WHERE <table>.<tenant>::text = excluded.<tenant>::text COLLATE "C"`: CockroachDB evaluates
///   `t.tenant = excluded.tenant COLLATE "C"` under the LEFT operand's collation, so on a collated tenant column
///   tenant `'ACME'` would update tenant `'acme'` (q4-005 finding 2); the casts drop the locale on both sides. The
///   `UPSERT` statement (primary-key arbiter, no guard) is never rendered. Text atoms already cast with `::text`,
///   which drops a collated string's locale on CockroachDB, so they are unchanged.
///
/// `#[non_exhaustive]`: matches outside this crate need a wildcard arm, so enabling `crdb` through feature
/// unification never breaks a crate that only knows `Postgres`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Dialect {
    #[default]
    Postgres,
    #[cfg(feature = "crdb")]
    Crdb,
}

impl Dialect {
    /// Whether this is the CockroachDB dialect (always false without feature `crdb`).
    pub const fn is_crdb(self) -> bool {
        match self {
            Dialect::Postgres => false,
            #[cfg(feature = "crdb")]
            Dialect::Crdb => true,
        }
    }
}

/// The DO UPDATE guard of the upsert for `dialect` (`tname`, `g` already quoted).
fn upsert_guard(dialect: Dialect, tname: &str, g: &str) -> String {
    if dialect.is_crdb() {
        format!("{tname}.{g}::text = excluded.{g}::text COLLATE \"C\"")
    } else {
        format!("({tname}.{g}::text COLLATE \"C\") = (excluded.{g}::text COLLATE \"C\")")
    }
}

/// Render one lowered op as a single PG statement. The tenant column must be a text column of `table`.
pub fn render(l: &Lowered, table: &PgTable) -> Result<Rendered, RenderError> {
    render_dialect(l, table, Dialect::Postgres)
}

/// [`render`] for `dialect`. Only the upsert guard differs between dialects (see [`Dialect`]).
pub fn render_dialect(l: &Lowered, table: &PgTable, dialect: Dialect) -> Result<Rendered, RenderError> {
    if l.collection != table.name {
        return Err(RenderError::CollectionMismatch);
    }
    let tf = l.tenant_field;
    if table.column(tf)?.class != PgClass::Text {
        return Err(RenderError::ColumnType(tf));
    }
    let tbl = table_ref(table.namespace.as_deref(), &table.name)?;
    let mut w = W { table, alias: None, offset: 0, params: Vec::new() };
    let mut ret = String::new();
    if !l.returning.is_empty() {
        let mut cols = Vec::with_capacity(l.returning.len());
        for f in &l.returning {
            cols.push(w.col(*f)?.0);
        }
        ret = format!(" RETURNING {}", cols.join(", "));
    }
    if l.kind != OpKind::Select {
        tenant_carried(table, tf)?;
    }
    let sql = match &l.stmt {
        Stmt::Select { filter } => {
            let mut cols = Vec::with_capacity(l.returning.len());
            for f in &l.returning {
                cols.push(w.col(*f)?.0);
            }
            let wh = w.expr(filter, EXPR_BUDGET)?;
            format!("SELECT {} FROM {tbl} WHERE {wh}", cols.join(", "))
        }
        Stmt::Delete { filter } => {
            let wh = w.expr(filter, EXPR_BUDGET)?;
            format!("DELETE FROM {tbl} WHERE {wh}{ret}")
        }
        Stmt::Update { set, filter } => {
            let mut parts = Vec::with_capacity(set.len());
            for (f, v) in set {
                let c = w.col(*f)?.0;
                parts.push(format!("{c} = {}", w.value(*f, v)?));
            }
            let wh = w.expr(filter, EXPR_BUDGET)?;
            format!("UPDATE {tbl} SET {} WHERE {wh}{ret}", parts.join(", "))
        }
        Stmt::Insert { row } | Stmt::Upsert { row, .. } => {
            if table.unique.iter().any(|u| !u.contains(&tf)) {
                return Err(RenderError::UniqueKeyWithoutTenant);
            }
            let mut names = Vec::with_capacity(row.len());
            let mut vals = Vec::with_capacity(row.len());
            for (f, v) in row {
                names.push(w.col(*f)?.0);
                vals.push(w.value(*f, v)?);
            }
            let ins = format!("INSERT INTO {tbl} ({}) VALUES ({})", names.join(", "), vals.join(", "));
            match &l.stmt {
                Stmt::Upsert { arbiter, action, .. } => {
                    let mut want = arbiter.clone();
                    want.sort_unstable();
                    let sole = match table.unique.as_slice() {
                        [only] => {
                            let mut got = only.clone();
                            got.sort_unstable();
                            got == want
                        }
                        _ => false,
                    };
                    if !sole || !arbiter.contains(&tf) {
                        return Err(RenderError::ArbiterNotSoleUniqueKey);
                    }
                    let mut arb = Vec::with_capacity(arbiter.len());
                    for f in arbiter {
                        arb.push(w.col(*f)?.0);
                    }
                    let act = match action {
                        UpsertAction::Nothing => "DO NOTHING".to_owned(),
                        UpsertAction::Update { set, guard } => {
                            let mut parts = Vec::with_capacity(set.len());
                            for f in set {
                                let c = w.col(*f)?.0;
                                parts.push(format!("{c} = excluded.{c}"));
                            }
                            let g = w.col(*guard)?.0;
                            let tname = quote_ident(&table.name)?;
                            format!("DO UPDATE SET {} WHERE {}", parts.join(", "), upsert_guard(dialect, &tname, &g))
                        }
                    };
                    format!("{ins} ON CONFLICT ({}) {act}{ret}", arb.join(", "))
                }
                _ => format!("{ins}{ret}"),
            }
        }
    };
    Ok(Rendered { sql, params: w.params })
}

/// `lower_op(op, schema, Exact)` then [`render`]. Run `monban_data_ir::authorize` before this.
pub fn render_op(op: &Op, schema: &Schema, table: &PgTable) -> Result<Rendered, RenderError> {
    let l = lower_op(op, schema, Fidelity::Exact)?;
    render(&l, table)
}

/// [`render_op`] for `dialect`.
pub fn render_op_dialect(op: &Op, schema: &Schema, table: &PgTable, dialect: Dialect) -> Result<Rendered, RenderError> {
    let l = lower_op(op, schema, Fidelity::Exact)?;
    render_dialect(&l, table, dialect)
}

// ------------------------------------------------------------------------------------------- RLS (R-DB-1, W-forms)

/// Name of the policy [`rls_policy`] creates.
pub const RLS_POLICY_NAME: &str = "monban_tenant";

fn valid_setting(s: &str) -> bool {
    let part = |p: &str| {
        let mut b = p.bytes();
        matches!(b.next(), Some(c) if c == b'_' || c.is_ascii_lowercase())
            && b.all(|c| c == b'_' || c.is_ascii_lowercase() || c.is_ascii_digit())
    };
    if s.len() > MAX_IDENT_BYTES {
        return false;
    }
    match s.split_once('.') {
        Some((a, b)) => part(a) && part(b),
        None => part(s),
    }
}

/// The tenant guard of the policy: `("<tenant>" = current_setting('<setting>', true) COLLATE "C")`. An unset
/// setting yields NULL, so nothing is visible or writable (fail closed).
fn rls_guard(tenant_column: &str, setting: &str) -> Result<String, RenderError> {
    if !valid_setting(setting) {
        return Err(RenderError::BadRlsName);
    }
    Ok(format!("({} = current_setting({}, true) COLLATE \"C\")", quote_ident(tenant_column)?, quote_literal(setting)))
}

/// DDL that puts a collection under FORCE ROW LEVEL SECURITY with one permissive FOR ALL policy for `role` whose
/// USING and explicit WITH CHECK both compare the tenant column with the transaction-local GUC `setting` (W-forms
/// "FORCE RLS + WITH CHECK"). Run once at provisioning, by the table owner.
pub fn rls_policy(
    namespace: Option<&str>,
    table: &str,
    tenant_column: &str,
    role: &str,
    setting: &str,
) -> Result<Vec<String>, RenderError> {
    let t = table_ref(namespace, table)?;
    let r = quote_ident(role).map_err(|_| RenderError::BadRlsName)?;
    let g = rls_guard(tenant_column, setting)?;
    Ok(vec![
        format!("ALTER TABLE {t} ENABLE ROW LEVEL SECURITY"),
        format!("ALTER TABLE {t} FORCE ROW LEVEL SECURITY"),
        format!("CREATE POLICY {RLS_POLICY_NAME} ON {t} AS PERMISSIVE FOR ALL TO {r} USING {g} WITH CHECK {g}"),
    ])
}

/// Per-transaction tenant binding (R-DB-1): `SET LOCAL ROLE <role>` and `set_config(<setting>, <tenant>, true)`
/// (is_local), both ending with the transaction. Run inside BEGIN, before the op's statement.
pub fn rls_bind(tenant: TenantId, role: &str, setting: &str) -> Result<Vec<Rendered>, RenderError> {
    let r = quote_ident(role).map_err(|_| RenderError::BadRlsName)?;
    if !valid_setting(setting) {
        return Err(RenderError::BadRlsName);
    }
    Ok(vec![
        Rendered { sql: format!("SET LOCAL ROLE {r}"), params: Vec::new() },
        Rendered {
            sql: "SELECT pg_catalog.set_config($1, $2, true)".into(),
            params: vec![Param::Text(setting.to_owned()), Param::Text(tenant_text(tenant))],
        },
    ])
}

/// Whether a policy expression (as `pg_get_expr` prints it) has exactly the shape of a tenant guard: the tenant
/// column compared for equality with `current_setting('<setting>'[, true])`, optionally under `COLLATE "C"` and
/// `::text` casts, and nothing else (no AND/OR/NOT, no constant, no other function). Used by the live schema gate.
/// Limit (PLAN D10): which setting is meant, and who may set it, is not judged here.
pub fn is_tenant_guard(expr: &str, tenant_column: &str) -> bool {
    let e: String = expr.chars().filter(|c| !c.is_whitespace() && *c != '(' && *c != ')').collect();
    let e = e.replace("::text", "");
    // The column, quoted, or bare when it is a plain lower-case identifier (pg_get_expr's choice).
    let quoted = format!("\"{}\"", tenant_column.replace('"', "\"\""));
    let plain = tenant_column.bytes().all(|c| c == b'_' || c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest = match e.strip_prefix(&quoted) {
        Some(r) => r,
        None if plain => match e.strip_prefix(tenant_column) {
            Some(r) => r,
            None => return false,
        },
        None => return false,
    };
    let rest = rest.strip_prefix("COLLATE\"C\"").unwrap_or(rest);
    let Some(rest) = rest.strip_prefix("=current_setting'") else { return false };
    let Some((setting, tail)) = rest.split_once('\'') else { return false };
    if !valid_setting(setting) {
        return false;
    }
    let tail = tail.strip_prefix(",true").unwrap_or(tail);
    matches!(tail, "" | "COLLATE\"C\"")
}
