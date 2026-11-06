//! MariaDB renderer: turns the engine-neutral [`Lowered`] tree of `aegis_data_ir::lower_op` into one MariaDB
//! statement with `?` placeholders (bound by the binary protocol, never interpolated), in the q4-005 mandated forms.
//!
//! Exactness (SPEC §E, `Fidelity::Exact`, the renderer obligations stated in aegis-data-ir `lower.rs`):
//!
//! * every atom is `(CASE WHEN c IS NULL THEN NULL ELSE <test> END)`, so a NULL column is UNKNOWN exactly as in Lean
//!   `sql3`, including `InList(f, [])`;
//! * string tests compare bytes, whatever the column collation (the 11.8 default `uca1400_ai_ci` is case- and
//!   accent-insensitive and PAD SPACE; `utf8mb4_bin` is PAD SPACE): `CAST(c AS BINARY) <op> CAST(? AS BINARY)`.
//!   Binary-string comparison is byte order with no padding, and byte order of UTF-8 is code-point order
//!   (`refLe`). The connection character set is utf8mb4 ([`crate::conn`] checks it);
//! * prefixes are `LEFT(CAST(c AS BINARY), ?) = CAST(? AS BINARY)` with the literal's UTF-8 **byte** length (UTF-8
//!   is prefix-free, so a byte prefix is a code-point prefix). Never LIKE;
//! * integer tests are `c = ?` (LONGLONG parameter) on integer columns only;
//! * class-strict: a value whose class differs from the column's can never be equal, so the test is `FALSE` (still
//!   wrapped, so NULL stays UNKNOWN); a column that is neither integer nor string is refused;
//! * `And`/`Or` are parenthesised; the tenant conjunct stays the left child of the root `And`.
//!
//! Mandated write forms (q4-005; SPEC §E W1-W7), one statement, verb first, never REPLACE / IGNORE / MERGE / WITH /
//! ON CONFLICT / `;`:
//!
//! * `UPDATE t SET c = ? .. WHERE lowerQ`. MariaDB has no `UPDATE .. RETURNING`: a requested RETURNING becomes
//!   [`Rendered::returning_select`] = `SELECT <post-image projection> FROM t WHERE <same lowerQ> FOR UPDATE`, which
//!   the host runs immediately before the UPDATE in the same transaction ([`crate::Connection::run`]);
//! * `DELETE FROM t WHERE lowerQ RETURNING ..`, `INSERT INTO t (..) VALUES (..) RETURNING ..`;
//! * upsert with update columns: `INSERT .. VALUES .. ON DUPLICATE KEY UPDATE c = IF(CAST(t AS BINARY) =
//!   CAST(VALUES(t) AS BINARY), VALUES(c), c) [, ..] RETURNING ..`. ODKU's arbiter is ANY unique key, so this is
//!   only sound behind the W3 schema gate (the sole unique index is (tenant, key)): enforced here from the table
//!   description and by F4 `check_schema`;
//! * upsert without update columns: `INSERT INTO t (..) SELECT ?, .. FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM t
//!   WHERE <binary own key>) RETURNING ..` (never INSERT IGNORE, which downgrades errors and truncates: W2).
//!
//! Writes into a table whose unique keys (Insert/Upsert) or foreign keys (any write) do not carry the tenant are
//! refused (W6 existence oracle, W3).

use std::fmt;

use aegis_data_ir::{
    Fidelity, Field, LowerError, Lowered, MAX_PRED_DEPTH, Op, OpKind, Schema, SqlExpr, Stmt, UpsertAction, Value,
    lower_op,
};

use crate::conn::MAX_PARAMS;
pub use crate::conn::Param;

/// MariaDB identifiers are at most 64 characters; longer (in bytes) or NUL-bearing names are refused.
pub const MAX_IDENT_BYTES: usize = 64;

/// IR storage class of a MariaDB column type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MyClass {
    Int,
    Text,
    Other,
}

impl MyClass {
    /// Class of a MariaDB `DATA_TYPE` (or a declared type such as `bigint`, `varchar(32)`, or the IR names `int`
    /// / `text`). Integer types are `Int`; character and binary strings are `Text`; anything else (decimal, float,
    /// date, json, enum, ...) is `Other` and refused when an op touches it.
    pub fn of_type_name(name: &str) -> MyClass {
        let n = name.trim().to_ascii_lowercase();
        let base = n.split(['(', ' ']).next().unwrap_or("").trim();
        match base {
            "tinyint" | "smallint" | "mediumint" | "int" | "integer" | "bigint" => MyClass::Int,
            "varchar" | "char" | "text" | "tinytext" | "mediumtext" | "longtext" | "varbinary" | "binary" | "blob"
            | "tinyblob" | "mediumblob" | "longblob" => MyClass::Text,
            _ => MyClass::Other,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MyColumn {
    pub field: Field,
    pub name: String,
    pub class: MyClass,
}

/// A foreign key out of the collection. It carries the tenant iff the tenant column is one of `columns` and the
/// referenced column at the same position is `ref_tenant_column`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MyForeignKey {
    pub columns: Vec<Field>,
    pub ref_table: String,
    pub ref_columns: Vec<String>,
    /// `None` = unknown: the key is treated as not tenant-carrying, so writes are refused.
    pub ref_tenant_column: Option<String>,
}

/// What the renderer knows about one collection (from [`crate::schema::check_live_schema`], or a declaration).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MyTable {
    /// Database qualifier; `None` renders the bare name (the connection's default database).
    pub namespace: Option<String>,
    pub name: String,
    pub columns: Vec<MyColumn>,
    /// Every unique key (PRIMARY and UNIQUE indexes) as its column fields.
    pub unique: Vec<Vec<Field>>,
    pub fks: Vec<MyForeignKey>,
}

impl MyTable {
    fn column(&self, f: Field) -> Result<&MyColumn, RenderError> {
        self.columns.iter().find(|c| c.field == f).ok_or(RenderError::UnknownField(f))
    }
}

/// One SQL text and its parameters, in `?` order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    pub sql: String,
    pub params: Vec<Param>,
}

/// A rendered op: the statement, plus (UPDATE with RETURNING only) the post-image select that runs before it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    pub stmt: Statement,
    pub returning_select: Option<Statement>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenderError {
    /// `lower_op` refused the op (F4 `check_schema` or a shape rule).
    Lower(LowerError),
    CollectionMismatch,
    UnknownField(Field),
    /// The column's type is neither integer nor string (or the tenant column is not a string).
    ColumnType(Field),
    /// A written value's class differs from the column's (MariaDB would coerce it, changing its IR value).
    ValueClass(Field),
    /// Insert/Upsert on a table with a unique key that lacks the tenant column (W6 existence oracle, W3).
    UniqueKeyWithoutTenant,
    /// Upsert whose arbiter is not exactly the table's sole unique key (W3: ODKU arbitrates on any unique key).
    ArbiterNotSoleUniqueKey,
    /// A write on a table with a foreign key that does not map the tenant to the referenced tenant (W6).
    ForeignKeyWithoutTenant,
    BadIdentifier,
    TooManyParams,
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

/// `` `name` `` with backticks doubled. Refuses empty, NUL-bearing and over-long names.
pub fn quote_ident(name: &str) -> Result<String, RenderError> {
    if name.is_empty() || name.len() > MAX_IDENT_BYTES || name.contains('\0') {
        return Err(RenderError::BadIdentifier);
    }
    Ok(format!("`{}`", name.replace('`', "``")))
}

fn table_ref(ns: Option<&str>, name: &str) -> Result<String, RenderError> {
    Ok(match ns {
        Some(n) => format!("{}.{}", quote_ident(n)?, quote_ident(name)?),
        None => quote_ident(name)?,
    })
}

fn bin(e: &str) -> String {
    format!("CAST({e} AS BINARY)")
}

struct W<'a> {
    table: &'a MyTable,
    alias: Option<String>,
    params: Vec<Param>,
}

impl W<'_> {
    fn ph(&mut self, p: Param) -> Result<&'static str, RenderError> {
        if self.params.len() >= MAX_PARAMS {
            return Err(RenderError::TooManyParams);
        }
        self.params.push(p);
        Ok("?")
    }

    fn col(&self, f: Field) -> Result<(String, MyClass), RenderError> {
        let c = self.table.column(f)?;
        let q = quote_ident(&c.name)?;
        Ok(match &self.alias {
            Some(a) => (format!("{a}.{q}"), c.class),
            None => (q, c.class),
        })
    }

    fn eq_test(&mut self, f: Field, c: &str, class: MyClass, v: &Value) -> Result<String, RenderError> {
        Ok(match (class, v) {
            (MyClass::Other, _) => return Err(RenderError::ColumnType(f)),
            (MyClass::Int, Value::Int(i)) => format!("({c} = {})", self.ph(Param::Int(*i))?),
            (MyClass::Text, Value::Str(s)) => format!("({} = {})", bin(c), bin(self.ph(Param::Text(s.clone()))?)),
            _ => "FALSE".into(),
        })
    }

    fn range_test(&mut self, f: Field, c: &str, class: MyClass, lo: &Value, hi: &Value) -> Result<String, RenderError> {
        Ok(match (class, lo, hi) {
            (MyClass::Other, _, _) => return Err(RenderError::ColumnType(f)),
            (MyClass::Int, Value::Int(a), Value::Int(b)) => {
                let pa = self.ph(Param::Int(*a))?;
                let pb = self.ph(Param::Int(*b))?;
                format!("({c} >= {pa} AND {c} <= {pb})")
            }
            (MyClass::Text, Value::Str(a), Value::Str(b)) => {
                let pa = bin(self.ph(Param::Text(a.clone()))?);
                let pb = bin(self.ph(Param::Text(b.clone()))?);
                let bc = bin(c);
                format!("({bc} >= {pa} AND {bc} <= {pb})")
            }
            _ => "FALSE".into(),
        })
    }

    fn pfx_test(&mut self, f: Field, c: &str, class: MyClass, s: &str) -> Result<String, RenderError> {
        Ok(match class {
            MyClass::Other => return Err(RenderError::ColumnType(f)),
            MyClass::Int => "FALSE".into(),
            MyClass::Text => {
                let n = i64::try_from(s.len()).map_err(|_| RenderError::TooManyParams)?;
                let pn = self.ph(Param::Int(n))?;
                let ps = bin(self.ph(Param::Text(s.to_owned()))?);
                format!("(LEFT({}, {pn}) = {ps})", bin(c))
            }
        })
    }

    fn expr(&mut self, e: &SqlExpr, budget: usize) -> Result<String, RenderError> {
        let next = budget.checked_sub(1).ok_or(RenderError::TooDeep)?;
        let atom = |c: &str, test: String| format!("(CASE WHEN {c} IS NULL THEN NULL ELSE {test} END)");
        Ok(match e {
            SqlExpr::Lit(true) => "TRUE".into(),
            SqlExpr::Lit(false) => "FALSE".into(),
            SqlExpr::CmpEq(f, v) => {
                let (c, class) = self.col(*f)?;
                let t = self.eq_test(*f, &c, class, v)?;
                atom(&c, t)
            }
            SqlExpr::InList(f, vs) => {
                let (c, class) = self.col(*f)?;
                if class == MyClass::Other {
                    return Err(RenderError::ColumnType(*f));
                }
                if vs.is_empty() {
                    atom(&c, "FALSE".into())
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

    /// A written value: `?`, class-checked against the column.
    fn value(&mut self, f: Field, v: &Value) -> Result<&'static str, RenderError> {
        match (self.table.column(f)?.class, v) {
            (MyClass::Int, Value::Int(i)) => self.ph(Param::Int(*i)),
            (MyClass::Text, Value::Str(s)) => self.ph(Param::Text(s.clone())),
            (MyClass::Other, _) => Err(RenderError::ColumnType(f)),
            _ => Err(RenderError::ValueClass(f)),
        }
    }
}

/// Filter budget: `lower_q` adds one level above `MAX_PRED_DEPTH`.
const EXPR_BUDGET: usize = MAX_PRED_DEPTH + 1;

/// Render a filter (a `lowerQ` tree) as a MariaDB boolean expression, the WHERE body. `alias` qualifies every
/// column (self-joins). Placeholders are positional `?`, so a caller joining two filters concatenates the params.
pub fn render_filter(e: &SqlExpr, table: &MyTable, alias: Option<&str>) -> Result<Statement, RenderError> {
    let alias = alias.map(quote_ident).transpose()?;
    let mut w = W { table, alias, params: Vec::new() };
    let sql = w.expr(e, EXPR_BUDGET)?;
    Ok(Statement { sql, params: w.params })
}

fn tenant_carried(table: &MyTable, tf: Field) -> Result<(), RenderError> {
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

fn returning_list(w: &W<'_>, l: &Lowered) -> Result<String, RenderError> {
    if l.returning.is_empty() {
        return Ok(String::new());
    }
    let mut cols = Vec::with_capacity(l.returning.len());
    for f in &l.returning {
        cols.push(w.col(*f)?.0);
    }
    Ok(format!(" RETURNING {}", cols.join(", ")))
}

/// Render one lowered op as a single MariaDB statement (plus the UPDATE RETURNING emulation). The tenant column
/// must be a string column of `table`.
pub fn render(l: &Lowered, table: &MyTable) -> Result<Rendered, RenderError> {
    if l.collection != table.name {
        return Err(RenderError::CollectionMismatch);
    }
    let tf = l.tenant_field;
    if table.column(tf)?.class != MyClass::Text {
        return Err(RenderError::ColumnType(tf));
    }
    let tbl = table_ref(table.namespace.as_deref(), &table.name)?;
    let mut w = W { table, alias: None, params: Vec::new() };
    if l.kind != OpKind::Select {
        tenant_carried(table, tf)?;
    }
    let mut returning_select = None;
    let sql = match &l.stmt {
        Stmt::Select { filter } => {
            let mut cols = Vec::with_capacity(l.returning.len());
            for f in &l.returning {
                cols.push(w.col(*f)?.0);
            }
            let cols = if cols.is_empty() { "1".to_owned() } else { cols.join(", ") };
            let wh = w.expr(filter, EXPR_BUDGET)?;
            format!("SELECT {cols} FROM {tbl} WHERE {wh}")
        }
        Stmt::Delete { filter } => {
            let ret = returning_list(&w, l)?;
            let wh = w.expr(filter, EXPR_BUDGET)?;
            format!("DELETE FROM {tbl} WHERE {wh}{ret}")
        }
        Stmt::Update { set, filter } => {
            if !l.returning.is_empty() {
                // Post-image projection: a SET column returns its new value, any other its current value.
                let mut sw = W { table, alias: None, params: Vec::new() };
                let mut proj = Vec::with_capacity(l.returning.len());
                for f in &l.returning {
                    let c = sw.col(*f)?.0;
                    match set.iter().find(|(g, _)| g == f) {
                        Some((g, v)) => {
                            let p = sw.value(*g, v)?;
                            proj.push(format!("{p} AS {c}"));
                        }
                        None => proj.push(c),
                    }
                }
                let wh = sw.expr(filter, EXPR_BUDGET)?;
                returning_select = Some(Statement {
                    sql: format!("SELECT {} FROM {tbl} WHERE {wh} FOR UPDATE", proj.join(", ")),
                    params: sw.params,
                });
            }
            let mut parts = Vec::with_capacity(set.len());
            for (f, v) in set {
                let c = w.col(*f)?.0;
                parts.push(format!("{c} = {}", w.value(*f, v)?));
            }
            let wh = w.expr(filter, EXPR_BUDGET)?;
            format!("UPDATE {tbl} SET {} WHERE {wh}", parts.join(", "))
        }
        Stmt::Insert { row } | Stmt::Upsert { row, .. } => {
            if table.unique.iter().any(|u| !u.contains(&tf)) {
                return Err(RenderError::UniqueKeyWithoutTenant);
            }
            let ret = returning_list(&w, l)?;
            let mut names = Vec::with_capacity(row.len());
            for (f, _) in row {
                names.push(w.col(*f)?.0);
            }
            let names = names.join(", ");
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
                    match action {
                        UpsertAction::Update { set, guard } => {
                            let mut vals = Vec::with_capacity(row.len());
                            for (f, v) in row {
                                vals.push(w.value(*f, v)?);
                            }
                            let g = w.col(*guard)?.0;
                            let cond = format!("{} = {}", bin(&g), bin(&format!("VALUES({g})")));
                            let mut parts = Vec::with_capacity(set.len());
                            for f in set {
                                if *f == tf || arbiter.contains(f) {
                                    return Err(RenderError::Lower(LowerError::KeyWritten(*f)));
                                }
                                let c = w.col(*f)?.0;
                                parts.push(format!("{c} = IF({cond}, VALUES({c}), {c})"));
                            }
                            format!(
                                "INSERT INTO {tbl} ({names}) VALUES ({}) ON DUPLICATE KEY UPDATE {}{ret}",
                                vals.join(", "),
                                parts.join(", ")
                            )
                        }
                        UpsertAction::Nothing => {
                            let mut vals = Vec::with_capacity(row.len());
                            for (f, v) in row {
                                vals.push(w.value(*f, v)?);
                            }
                            let mut conds = Vec::with_capacity(arbiter.len());
                            for f in arbiter {
                                let v = row.iter().find(|(g, _)| g == f).map(|(_, v)| v);
                                let Some(v) = v else { return Err(RenderError::Lower(LowerError::MissingKey(*f))) };
                                let c = w.col(*f)?.0;
                                let p = w.value(*f, v)?;
                                conds.push(match v {
                                    Value::Str(_) => format!("{} = {}", bin(&c), bin(p)),
                                    Value::Int(_) => format!("{c} = {p}"),
                                });
                            }
                            format!(
                                "INSERT INTO {tbl} ({names}) SELECT {} FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM {tbl} \
                                 WHERE {}){ret}",
                                vals.join(", "),
                                conds.join(" AND ")
                            )
                        }
                    }
                }
                _ => {
                    let mut vals = Vec::with_capacity(row.len());
                    for (f, v) in row {
                        vals.push(w.value(*f, v)?);
                    }
                    format!("INSERT INTO {tbl} ({names}) VALUES ({}){ret}", vals.join(", "))
                }
            }
        }
    };
    Ok(Rendered { stmt: Statement { sql, params: w.params }, returning_select })
}

/// `lower_op(op, schema, Exact)` then [`render`]. Run `aegis_data_ir::authorize` before this.
pub fn render_op(op: &Op, schema: &Schema, table: &MyTable) -> Result<Rendered, RenderError> {
    let l = lower_op(op, schema, Fidelity::Exact)?;
    render(&l, table)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use aegis_data_ir::{Collation, Column, Pred, UniqueIndex};
    use aegis_types::TenantId;

    // fields: 0 id (int), 1 tenant, 2 x, 3 y
    fn table(unique: Vec<Vec<Field>>) -> MyTable {
        let c = |field, name: &str, class| MyColumn { field, name: name.into(), class };
        MyTable {
            namespace: None,
            name: "t".into(),
            columns: vec![
                c(0, "id", MyClass::Int),
                c(1, "tenant", MyClass::Text),
                c(2, "x", MyClass::Text),
                c(3, "y", MyClass::Text),
            ],
            unique,
            fks: vec![],
        }
    }

    fn schema(keys: &[Field], unique: Vec<Vec<Field>>) -> Schema {
        Schema {
            collection: "t".into(),
            tenant_field: 1,
            columns: (0..4)
                .map(|f| Column {
                    field: f,
                    name: ["id", "tenant", "x", "y"][f as usize].into(),
                    nullable: f != 1,
                    collation: Collation::Binary,
                    key: keys.contains(&f),
                })
                .collect(),
            permitted: vec![0, 1, 2, 3],
            unique_indexes: unique.into_iter().map(|fields| UniqueIndex { fields, prefix: false }).collect(),
        }
    }

    fn op(kind: OpKind, filter: Pred, writes: Vec<(Field, Value)>, returning: Vec<Field>) -> Op {
        Op { tenant: TenantId::new(0x2a).unwrap(), collection: "t".into(), kind, filter, writes, returning }
    }

    #[test]
    fn read_forms() {
        let t = table(vec![vec![1, 0]]);
        let p = Pred::And(
            Box::new(Pred::Pfx(2, "é".into())),
            Box::new(Pred::Not(Box::new(Pred::IsIn(0, vec![Value::Int(3), Value::Str("3".into())])))),
        );
        let l = lower_op(&op(OpKind::Select, p, vec![], vec![0]), &schema(&[], vec![]), Fidelity::Exact).unwrap();
        let Stmt::Select { filter } = &l.stmt else { panic!() };
        let r = render_filter(filter, &t, Some("a")).unwrap();
        assert_eq!(
            r.sql,
            "((CASE WHEN `a`.`tenant` IS NULL THEN NULL ELSE (CAST(`a`.`tenant` AS BINARY) = CAST(? AS BINARY)) END) AND \
             ((CASE WHEN `a`.`x` IS NULL THEN NULL ELSE (LEFT(CAST(`a`.`x` AS BINARY), ?) = CAST(? AS BINARY)) END) AND \
             (NOT (CASE WHEN `a`.`id` IS NULL THEN NULL ELSE ((`a`.`id` = ?) OR FALSE) END))))"
        );
        assert_eq!(
            r.params,
            vec![Param::Text("000000000000002a".into()), Param::Int(2), Param::Text("é".into()), Param::Int(3)]
        );
    }

    #[test]
    fn upsert_forms() {
        let t = table(vec![vec![1, 0]]);
        let sc = schema(&[0], vec![vec![1, 0]]);
        let w = vec![(0, Value::Int(7)), (2, Value::Str("v".into()))];
        let r = render_op(&op(OpKind::Upsert, Pred::Tt, w.clone(), vec![0, 2]), &sc, &t).unwrap();
        assert_eq!(
            r.stmt.sql,
            "INSERT INTO `t` (`tenant`, `id`, `x`) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE `x` = \
             IF(CAST(`tenant` AS BINARY) = CAST(VALUES(`tenant`) AS BINARY), VALUES(`x`), `x`) RETURNING `id`, `x`"
        );
        let r = render_op(&op(OpKind::Upsert, Pred::Tt, vec![(0, Value::Int(7))], vec![]), &sc, &t).unwrap();
        assert_eq!(
            r.stmt.sql,
            "INSERT INTO `t` (`tenant`, `id`) SELECT ?, ? FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM `t` WHERE \
             `id` = ? AND CAST(`tenant` AS BINARY) = CAST(? AS BINARY))"
        );
        assert_eq!(r.stmt.params.len(), 4);
        // A second unique key: ODKU could land on another tenant's row -> refused.
        let t2 = table(vec![vec![1, 0], vec![0]]);
        assert!(render_op(&op(OpKind::Upsert, Pred::Tt, w, vec![]), &sc, &t2).is_err());
    }

    #[test]
    fn update_returning_select() {
        let t = table(vec![vec![1, 0]]);
        let sc = schema(&[0], vec![vec![1, 0]]);
        let o = op(OpKind::Update, Pred::Eq(0, Value::Int(1)), vec![(2, Value::Str("n".into()))], vec![0, 2]);
        let r = render_op(&o, &sc, &t).unwrap();
        assert!(!r.stmt.sql.contains("RETURNING"));
        let rs = r.returning_select.unwrap();
        assert!(rs.sql.starts_with("SELECT `id`, ? AS `x` FROM `t` WHERE ((CASE WHEN `tenant`"));
        assert!(rs.sql.ends_with(" FOR UPDATE"));
        assert_eq!(rs.params[0], Param::Text("n".into()));
        assert_eq!(rs.params[1], Param::Text("000000000000002a".into()));
        // class mismatch in a written value is refused, never coerced
        let o = op(OpKind::Update, Pred::Tt, vec![(2, Value::Int(1))], vec![]);
        assert_eq!(render_op(&o, &sc, &t), Err(RenderError::ValueClass(2)));
    }

    #[test]
    fn fk_and_unique_guards() {
        let mut t = table(vec![vec![0]]);
        let sc = schema(&[], vec![vec![0]]);
        let ins = op(OpKind::Insert, Pred::Tt, vec![(0, Value::Int(1))], vec![]);
        assert_eq!(render_op(&ins, &sc, &t), Err(RenderError::UniqueKeyWithoutTenant));
        t.unique = vec![vec![1, 0]];
        t.fks = vec![MyForeignKey {
            columns: vec![2],
            ref_table: "p".into(),
            ref_columns: vec!["k".into()],
            ref_tenant_column: Some("tenant".into()),
        }];
        let del = op(OpKind::Delete, Pred::Tt, vec![], vec![]);
        assert_eq!(render_op(&del, &sc, &t), Err(RenderError::ForeignKeyWithoutTenant));
    }
}
