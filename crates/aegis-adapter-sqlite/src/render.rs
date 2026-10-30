//! SQLite renderer for [`Lowered`] (crates/aegis-data-ir/src/lower.rs). Structural: one SQL node per [`SqlExpr`] node.

use crate::ENGINE_PIN;
use aegis_data_ir::{
    Adapter, EngineFamily, Fidelity, Field, LowerError, Lowered, Op, OpKind, Schema, SqlExpr, Stmt, UpsertAction,
    Value, denied, lower_op, parse_tenant_text, valid_collection,
};

/// One SQLite statement with `?` placeholders, bound in order: `Int` as INTEGER, `Str` as TEXT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    pub sql: String,
    pub params: Vec<Value>,
}

/// One foreign key between this collection and another table, as introspected (PRAGMA foreign_key_list).
/// Outgoing (this table references `remote_table`): `local` are the referencing columns. Incoming (`remote_table`
/// references this table): `local` are the referenced columns of this table. `remote` pairs with `local` by position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignKey {
    pub local: Vec<Field>,
    pub remote_table: String,
    pub remote: Vec<String>,
    /// The tenant column of `remote_table` when it is a known collection; `None` makes the key non-tenant-scoped.
    pub remote_tenant: Option<String>,
}

impl ForeignKey {
    /// The key maps this table's tenant column onto the other table's tenant column (and nothing else onto either),
    /// so whether the constraint holds depends only on rows of the same tenant (W6: no existence oracle).
    pub fn carries_tenant(&self, tenant_field: Field) -> bool {
        let Some(rt) = &self.remote_tenant else { return false };
        if self.local.len() != self.remote.len() {
            return false;
        }
        let mut hit = false;
        for (l, r) in self.local.iter().zip(&self.remote) {
            match (*l == tenant_field, r == rt) {
                (true, true) => hit = true,
                (false, false) => {}
                _ => return false,
            }
        }
        hit
    }
}

/// The introspected description of one collection: the F4 [`Schema`] filled from the live catalog plus its foreign
/// keys (F4 has no FK notion). Produced by [`crate::SqliteDb::check_schema`]; public so tests and subjects can build
/// one directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    pub schema: Schema,
    pub fks_out: Vec<ForeignKey>,
    pub fks_in: Vec<ForeignKey>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenderError {
    /// `lower_op` refused the op (F4 `check_schema` first).
    Lower(LowerError),
    /// The collection fails `valid_collection` or differs from the table's.
    BadCollection,
    /// A field the schema does not name.
    UnknownField(Field),
    /// A column name SQLite cannot carry as a quoted identifier (empty or containing NUL).
    BadIdentifier(Field),
    /// An alias that is not `[a-z_][a-z0-9_]{0,62}`.
    BadAlias,
    /// The tenant value is not the D4 text of a TenantId.
    TenantNotCanonical,
    /// A `Lowered` that `lower_op` cannot produce (kind/statement mismatch, missing tenant conjunct, tenant or key in
    /// a SET list, arbiter other than the sole (tenant, key) index, ...).
    Malformed(&'static str),
    /// INSERT/UPSERT (or an UPDATE of a column of that key) on a table with a unique key without the tenant column:
    /// whether it fails would reveal another tenant's row (W6).
    UniqueKeyWithoutTenant,
    /// A write on a table with a foreign key that does not map tenant to tenant (W6).
    ForeignKeyWithoutTenant,
    /// SELECT with no column to return.
    EmptyReturning,
    /// The F4 [`Schema`] has no foreign keys, so [`SqliteAdapter`] renders reads only; writes go through [`render`]
    /// with the introspected [`Table`].
    WritesNeedTable,
    /// The rendered text contains a denylisted keyword (defence in depth; never expected).
    Denied(&'static str),
    /// A prefix longer than i64::MAX bytes (unreachable in practice).
    TooLong,
}

/// [`Adapter`] (F4) view of the renderer. Reads only: see [`RenderError::WritesNeedTable`].
#[derive(Clone, Copy, Debug, Default)]
pub struct SqliteAdapter;

impl Adapter for SqliteAdapter {
    type Rendered = Rendered;
    type Error = RenderError;
    fn engine_pin(&self) -> &str {
        ENGINE_PIN
    }
    fn fidelity(&self) -> Fidelity {
        Fidelity::Exact
    }
    fn render(&self, op: &Op, schema: &Schema) -> Result<Rendered, RenderError> {
        if op.kind != OpKind::Select {
            return Err(RenderError::WritesNeedTable);
        }
        render(op, &Table { schema: schema.clone(), fks_out: Vec::new(), fks_in: Vec::new() })
    }
}

/// Lower (`lower_op` at `Fidelity::Exact`, which runs F4 `check_schema` first) and render one op. Total.
pub fn render(op: &Op, table: &Table) -> Result<Rendered, RenderError> {
    let l = lower_op(op, &table.schema, Fidelity::Exact).map_err(RenderError::Lower)?;
    render_lowered(&l, table)
}

/// Render a [`Lowered`] statement. The tree is re-validated (it has public fields): kind and statement agree, the
/// tenant is canonical, every filter is `And(CmpEq(tenant_field, tenant), _)`, rows start with the tenant, SET lists
/// hold no tenant or key column, an upsert's arbiter is the sole (tenant, key) unique index and its DO UPDATE set is
/// a subset of the written non-key columns, RETURNING ⊆ permitted. Then the W6 rules, then the text.
pub fn render_lowered(l: &Lowered, table: &Table) -> Result<Rendered, RenderError> {
    let s = &table.schema;
    if !valid_collection(&l.collection) || l.collection != s.collection {
        return Err(RenderError::BadCollection);
    }
    if l.tenant_field != s.tenant_field {
        return Err(RenderError::Malformed("tenant field differs from the schema"));
    }
    canonical(&l.tenant)?;
    w6(l, table)?;
    let tf = s.tenant_field;
    let keys: Vec<Field> = s.columns.iter().filter(|c| c.key && c.field != tf).map(|c| c.field).collect();
    let mut w = Writer::new(s, None)?;
    let tbl = qi(&l.collection);
    match (&l.stmt, l.kind) {
        (Stmt::Select { filter }, OpKind::Select) => {
            if l.returning.is_empty() {
                return Err(RenderError::EmptyReturning);
            }
            conjunct(l, filter)?;
            w.out.push_str("SELECT ");
            w.cols(&l.returning)?;
            w.out.push_str(" FROM ");
            w.out.push_str(&tbl);
            w.out.push_str(" WHERE ");
            w.expr(filter)?;
        }
        (Stmt::Update { set, filter }, OpKind::Update) => {
            if set.is_empty() {
                return Err(RenderError::Malformed("empty SET"));
            }
            distinct(set.iter().map(|(f, _)| *f))?;
            if set.iter().any(|(f, _)| *f == tf || keys.contains(f)) {
                return Err(RenderError::Malformed("SET of the tenant or a key column"));
            }
            conjunct(l, filter)?;
            w.out.push_str("UPDATE ");
            w.out.push_str(&tbl);
            w.out.push_str(" SET ");
            for (i, (f, v)) in set.iter().enumerate() {
                if i > 0 {
                    w.out.push_str(", ");
                }
                let c = w.name(*f)?;
                w.out.push_str(&c);
                w.out.push_str(" = ?");
                w.params.push(v.clone());
            }
            w.out.push_str(" WHERE ");
            w.expr(filter)?;
        }
        (Stmt::Delete { filter }, OpKind::Delete) => {
            conjunct(l, filter)?;
            w.out.push_str("DELETE FROM ");
            w.out.push_str(&tbl);
            w.out.push_str(" WHERE ");
            w.expr(filter)?;
        }
        (Stmt::Insert { row }, OpKind::Insert) => {
            insert_head(&mut w, l, &tbl, row, &keys)?;
        }
        (Stmt::Upsert { row, arbiter, action }, OpKind::Upsert) => {
            insert_head(&mut w, l, &tbl, row, &keys)?;
            sole_arbiter(s, arbiter)?;
            w.out.push_str(" ON CONFLICT (");
            w.cols(arbiter)?;
            w.out.push_str(") ");
            match action {
                UpsertAction::Nothing => w.out.push_str("DO NOTHING"),
                UpsertAction::Update { set, guard } => {
                    if *guard != tf {
                        return Err(RenderError::Malformed("upsert guard is not the tenant column"));
                    }
                    if set.is_empty() {
                        return Err(RenderError::Malformed("empty DO UPDATE set"));
                    }
                    distinct(set.iter().copied())?;
                    for f in set {
                        if *f == tf || keys.contains(f) || !row.iter().any(|(g, _)| g == f) {
                            return Err(RenderError::Malformed("DO UPDATE of a tenant, key or unwritten column"));
                        }
                    }
                    w.out.push_str("DO UPDATE SET ");
                    for (i, f) in set.iter().enumerate() {
                        if i > 0 {
                            w.out.push_str(", ");
                        }
                        let c = w.name(*f)?;
                        w.out.push_str(&c);
                        w.out.push_str(" = excluded.");
                        w.out.push_str(&c);
                    }
                    let g = w.name(tf)?;
                    w.out.push_str(" WHERE ");
                    w.out.push_str(&tbl);
                    w.out.push('.');
                    w.out.push_str(&g);
                    w.out.push_str(" = excluded.");
                    w.out.push_str(&g);
                    w.out.push_str(" COLLATE BINARY");
                }
            }
        }
        _ => return Err(RenderError::Malformed("kind and statement disagree")),
    }
    if l.kind != OpKind::Select && !l.returning.is_empty() {
        w.out.push_str(" RETURNING ");
        w.cols(&l.returning)?;
    }
    if l.returning.iter().any(|f| !s.permitted.contains(f)) {
        return Err(RenderError::Malformed("RETURNING a column outside permitted"));
    }
    w.finish()
}

/// The WHERE body (a boolean expression) of a Select, Update or Delete, every column qualified with `alias` when
/// given. Validated like [`render_lowered`] (tenant conjunct present, canonical tenant). For callers that compose the
/// statement around the filter (self-joins, EXISTS); [`render`] is the normal entry point.
pub fn render_where(l: &Lowered, schema: &Schema, alias: Option<&str>) -> Result<Rendered, RenderError> {
    if l.tenant_field != schema.tenant_field || l.collection != schema.collection {
        return Err(RenderError::Malformed("lowered statement is for another schema"));
    }
    canonical(&l.tenant)?;
    let filter = match &l.stmt {
        Stmt::Select { filter } | Stmt::Update { filter, .. } | Stmt::Delete { filter } => filter,
        Stmt::Insert { .. } | Stmt::Upsert { .. } => return Err(RenderError::Malformed("statement has no filter")),
    };
    conjunct(l, filter)?;
    let mut w = Writer::new(schema, alias)?;
    w.expr(filter)?;
    w.finish()
}

// ------------------------------------------------------------------------------------------------- validation

fn canonical(v: &Value) -> Result<(), RenderError> {
    match v {
        Value::Str(s) if parse_tenant_text(s).is_some() => Ok(()),
        _ => Err(RenderError::TenantNotCanonical),
    }
}

/// The filter is `And(CmpEq(tenant_field, tenant), _)` (lowerQ): the host tenant is the left child of the root.
fn conjunct(l: &Lowered, filter: &SqlExpr) -> Result<(), RenderError> {
    match filter {
        SqlExpr::And(a, _) if matches!(&**a, SqlExpr::CmpEq(f, v) if *f == l.tenant_field && *v == l.tenant) => Ok(()),
        _ => Err(RenderError::Malformed("filter lacks the tenant conjunct")),
    }
}

fn distinct(fs: impl Iterator<Item = Field>) -> Result<(), RenderError> {
    let mut seen: Vec<Field> = Vec::new();
    for f in fs {
        if seen.contains(&f) {
            return Err(RenderError::Malformed("column listed twice"));
        }
        seen.push(f);
    }
    Ok(())
}

fn sole_arbiter(s: &Schema, arbiter: &[Field]) -> Result<(), RenderError> {
    let mut want: Vec<Field> =
        s.columns.iter().filter(|c| c.key || c.field == s.tenant_field).map(|c| c.field).collect();
    want.sort_unstable();
    want.dedup();
    let mut got = arbiter.to_vec();
    got.sort_unstable();
    let ok = match s.unique_indexes.as_slice() {
        [only] => {
            let mut u = only.fields.clone();
            u.sort_unstable();
            !only.prefix && u == want && got == want && got.contains(&s.tenant_field) && got.len() >= 2
        }
        _ => false,
    };
    if ok { Ok(()) } else { Err(RenderError::Malformed("arbiter is not the sole (tenant, key) unique index")) }
}

/// W6 (uniform failure, no existence oracle). A constraint that a statement can trip must depend only on rows of the
/// same tenant: every unique key an INSERT/UPSERT can collide on (and an UPDATE writes into) contains the tenant,
/// every foreign key from the table (INSERT/UPSERT/UPDATE) and into it (DELETE/UPDATE/UPSERT) maps tenant to tenant.
fn w6(l: &Lowered, t: &Table) -> Result<(), RenderError> {
    let tf = t.schema.tenant_field;
    let global = |u: &&aegis_data_ir::UniqueIndex| u.prefix || !u.fields.contains(&tf);
    match &l.stmt {
        Stmt::Insert { .. } | Stmt::Upsert { .. } if t.schema.unique_indexes.iter().any(|u| global(&u)) => {
            return Err(RenderError::UniqueKeyWithoutTenant);
        }
        Stmt::Update { set, .. }
            if t.schema.unique_indexes.iter().filter(global).any(|u| set.iter().any(|(f, _)| u.fields.contains(f))) =>
        {
            return Err(RenderError::UniqueKeyWithoutTenant);
        }
        _ => {}
    }
    let out = matches!(l.kind, OpKind::Insert | OpKind::Upsert | OpKind::Update);
    let inc = matches!(l.kind, OpKind::Delete | OpKind::Update | OpKind::Upsert);
    if (out && t.fks_out.iter().any(|k| !k.carries_tenant(tf)))
        || (inc && t.fks_in.iter().any(|k| !k.carries_tenant(tf)))
    {
        return Err(RenderError::ForeignKeyWithoutTenant);
    }
    Ok(())
}

fn insert_head(
    w: &mut Writer<'_>,
    l: &Lowered,
    tbl: &str,
    row: &[(Field, Value)],
    keys: &[Field],
) -> Result<(), RenderError> {
    match row.split_first() {
        Some(((f, v), rest)) if *f == l.tenant_field && *v == l.tenant => {
            if rest.iter().any(|(g, _)| *g == l.tenant_field) {
                return Err(RenderError::Malformed("row carries a second tenant value"));
            }
        }
        _ => return Err(RenderError::Malformed("row does not start with the host tenant")),
    }
    distinct(row.iter().map(|(f, _)| *f))?;
    if let Some(k) = keys.iter().find(|k| !row.iter().any(|(f, _)| f == *k)) {
        return Err(RenderError::Lower(LowerError::MissingKey(*k)));
    }
    w.out.push_str("INSERT INTO ");
    w.out.push_str(tbl);
    w.out.push_str(" (");
    let fs: Vec<Field> = row.iter().map(|(f, _)| *f).collect();
    w.cols(&fs)?;
    w.out.push_str(") VALUES (");
    for (i, (_, v)) in row.iter().enumerate() {
        if i > 0 {
            w.out.push_str(", ");
        }
        w.out.push('?');
        w.params.push(v.clone());
    }
    w.out.push(')');
    Ok(())
}

// --------------------------------------------------------------------------------------------------- text

/// Quoted identifier: `"` doubled inside `"..."`.
fn qi(name: &str) -> String {
    let mut s = String::with_capacity(name.len().saturating_add(2));
    s.push('"');
    for c in name.chars() {
        if c == '"' {
            s.push('"');
        }
        s.push(c);
    }
    s.push('"');
    s
}

struct Writer<'a> {
    schema: &'a Schema,
    alias: Option<String>,
    out: String,
    params: Vec<Value>,
}

impl<'a> Writer<'a> {
    fn new(schema: &'a Schema, alias: Option<&str>) -> Result<Self, RenderError> {
        let alias = match alias {
            None => None,
            Some(a) if valid_collection(a) => Some(qi(a)),
            Some(_) => return Err(RenderError::BadAlias),
        };
        Ok(Writer { schema, alias, out: String::new(), params: Vec::new() })
    }

    /// Quoted column name (unqualified).
    fn name(&self, f: Field) -> Result<String, RenderError> {
        let c = self.schema.columns.iter().find(|c| c.field == f).ok_or(RenderError::UnknownField(f))?;
        if c.name.is_empty() || c.name.contains('\0') {
            return Err(RenderError::BadIdentifier(f));
        }
        Ok(qi(&c.name))
    }

    /// Column reference, qualified with the alias when there is one.
    fn col(&self, f: Field) -> Result<String, RenderError> {
        let n = self.name(f)?;
        Ok(match &self.alias {
            Some(a) => format!("{a}.{n}"),
            None => n,
        })
    }

    fn cols(&mut self, fs: &[Field]) -> Result<(), RenderError> {
        for (i, f) in fs.iter().enumerate() {
            if i > 0 {
                self.out.push_str(", ");
            }
            let n = self.name(*f)?;
            self.out.push_str(&n);
        }
        Ok(())
    }

    fn ph(&mut self, v: Value) -> &'static str {
        self.params.push(v);
        "?"
    }

    /// Exact class-strict equality: `typeof` guard, unary `+` (no affinity, no column collation), BINARY for text.
    fn eq_test(&mut self, c: &str, v: &Value) -> String {
        match v {
            Value::Int(_) => format!("(typeof({c}) = 'integer' AND +{c} = {})", self.ph(v.clone())),
            Value::Str(_) => format!("(typeof({c}) = 'text' AND +{c} = {} COLLATE BINARY)", self.ph(v.clone())),
        }
    }

    /// Lean `sql3` atom: NULL column ⇒ UNKNOWN, otherwise the exact test.
    fn atom(&mut self, c: &str, test: &str) {
        self.out.push_str("(CASE WHEN ");
        self.out.push_str(c);
        self.out.push_str(" IS NULL THEN NULL ELSE ");
        self.out.push_str(test);
        self.out.push_str(" END)");
    }

    fn expr(&mut self, e: &SqlExpr) -> Result<(), RenderError> {
        match e {
            SqlExpr::Lit(true) => self.out.push_str("(1=1)"),
            SqlExpr::Lit(false) => self.out.push_str("(1=0)"),
            SqlExpr::CmpEq(f, v) => {
                let c = self.col(*f)?;
                let t = self.eq_test(&c, v);
                self.atom(&c, &t);
            }
            SqlExpr::InList(f, vs) => {
                let c = self.col(*f)?;
                let t = if vs.is_empty() {
                    // `sql3_inList_nil`: FALSE on a present column, UNKNOWN on NULL (never constant FALSE).
                    String::from("(1=0)")
                } else {
                    let tests: Vec<String> = vs.iter().map(|v| self.eq_test(&c, v)).collect();
                    format!("({})", tests.join(" OR "))
                };
                self.atom(&c, &t);
            }
            SqlExpr::Between(f, lo, hi) => {
                let c = self.col(*f)?;
                let t = match (lo, hi) {
                    (Value::Int(_), Value::Int(_)) => {
                        let a = self.ph(lo.clone());
                        let b = self.ph(hi.clone());
                        format!("(typeof({c}) = 'integer' AND +{c} >= {a} AND +{c} <= {b})")
                    }
                    (Value::Str(_), Value::Str(_)) => {
                        let a = self.ph(lo.clone());
                        let b = self.ph(hi.clone());
                        format!("(typeof({c}) = 'text' AND +{c} >= {a} COLLATE BINARY AND +{c} <= {b} COLLATE BINARY)")
                    }
                    // refRange compares within one storage class only: mixed bounds admit nothing.
                    _ => String::from("(1=0)"),
                };
                self.atom(&c, &t);
            }
            SqlExpr::Pfx(f, s) => {
                let c = self.col(*f)?;
                let n = i64::try_from(s.len()).map_err(|_| RenderError::TooLong)?;
                // Byte prefix of the UTF-8 encoding (UTF-8 is prefix-free, so this is refPrefix). BLOB substr counts
                // bytes and does not stop at NUL; SQLite yields NULL for a zero-length BLOB, hence the coalesces.
                let a = self.ph(Value::Int(n));
                let b = self.ph(Value::Str(s.clone()));
                let t = format!(
                    "(typeof({c}) = 'text' AND coalesce(substr(CAST(+{c} AS BLOB), 1, {a}), x'') = \
                     coalesce(CAST({b} AS BLOB), x''))"
                );
                self.atom(&c, &t);
            }
            SqlExpr::And(a, b) | SqlExpr::Or(a, b) => {
                self.out.push('(');
                self.expr(a)?;
                self.out.push_str(if matches!(e, SqlExpr::And(..)) { " AND " } else { " OR " });
                self.expr(b)?;
                self.out.push(')');
            }
            SqlExpr::Not(a) => {
                self.out.push_str("(NOT ");
                self.expr(a)?;
                self.out.push(')');
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<Rendered, RenderError> {
        deny_scan(&self.out)?;
        Ok(Rendered { sql: self.out, params: self.params })
    }
}

/// Every bare word outside `'..'` literals and `".."` identifiers, checked against `denylist(Sqlite)`.
fn deny_scan(sql: &str) -> Result<(), RenderError> {
    let mut quote: Option<char> = None;
    let mut word = String::new();
    let mut chars = sql.chars().peekable();
    let check = |w: &mut String| -> Result<(), RenderError> {
        if let Some(d) = denied(EngineFamily::Sqlite, w) {
            return Err(RenderError::Denied(d.item));
        }
        w.clear();
        Ok(())
    };
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            if c == q {
                if chars.peek() == Some(&q) {
                    chars.next();
                } else {
                    quote = None;
                }
            }
            continue;
        }
        if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
            word.push(c);
            continue;
        }
        check(&mut word)?;
        if c == '\'' || c == '"' || c == '`' {
            quote = Some(c);
        }
    }
    if quote.is_some() {
        return Err(RenderError::Malformed("unterminated quote"));
    }
    check(&mut word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_scan_sees_bare_words_only() {
        assert_eq!(deny_scan(r#"SELECT "replace" FROM "t" WHERE 'ATTACH' = x'00'"#), Ok(()));
        assert_eq!(deny_scan("INSERT OR REPLACE INTO t VALUES (1)"), Err(RenderError::Denied("REPLACE")));
        assert_eq!(deny_scan("ATTACH 'x' AS y"), Err(RenderError::Denied("ATTACH")));
        assert_eq!(deny_scan("select 1 from \"a\"\"b\" where pragma"), Err(RenderError::Denied("PRAGMA")));
        assert!(deny_scan("'unterminated").is_err());
    }

    #[test]
    fn quoting() {
        assert_eq!(qi(r#"a"b"#), r#""a""b""#);
    }
}
