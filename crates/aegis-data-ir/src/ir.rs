//! Frozen interface F4 (see crate docs).

use aegis_types::TenantId;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

/// Column index in a schema (Lean: `Field := Nat`).
pub type Field = u32;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Value {
    Int(i64),
    Str(String),
}

/// IR filter. `And`/`Or` are binary; n-ary forms desugar with `and_n([]) = Tt`, `or_n([]) = Ff`, so an empty
/// disjunction can never widen access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pred {
    Tt,
    Ff,
    Eq(Field, Value),
    IsIn(Field, Vec<Value>),
    Range(Field, Value, Value),
    Pfx(Field, String),
    And(Box<Pred>, Box<Pred>),
    Or(Box<Pred>, Box<Pred>),
    Not(Box<Pred>),
}

impl Pred {
    pub fn and_n(ps: Vec<Pred>) -> Pred {
        ps.into_iter().rev().fold(Pred::Tt, |acc, p| Pred::And(Box::new(p), Box::new(acc)))
    }
    pub fn or_n(ps: Vec<Pred>) -> Pred {
        ps.into_iter().rev().fold(Pred::Ff, |acc, p| Pred::Or(Box::new(p), Box::new(acc)))
    }
    fn reads(&self, out: &mut Vec<Field>) {
        match self {
            Pred::Tt | Pred::Ff => {}
            Pred::Eq(f, _) | Pred::IsIn(f, _) | Pred::Range(f, _, _) | Pred::Pfx(f, _) => out.push(*f),
            Pred::And(a, b) | Pred::Or(a, b) => {
                a.reads(out);
                b.reads(out);
            }
            Pred::Not(a) => a.reads(out),
        }
    }
}

/// Operation kinds a capability may grant (D2: a child token's op bitmask is a subset of its parent's).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OpKind {
    Select,
    Insert,
    Update,
    Delete,
    Upsert,
}

/// One data-plane operation, already authorized for `tenant`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    pub tenant: TenantId,
    pub collection: String,
    pub kind: OpKind,
    pub filter: Pred,
    /// Columns written (Insert/Update/Upsert); W2 requires every post-image to carry `tenant`.
    pub writes: Vec<(Field, Value)>,
    /// Columns returned; W4 requires RETURNING ⊆ permitted columns.
    pub returning: Vec<Field>,
}

/// Engine collation of a column. Soundness needs engine equality to refine the reference (`Backend.Refines`);
/// case-insensitive or nondeterministic collations break it (`refines_necessary`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Collation {
    /// Byte-wise, deterministic and NO-PAD (PG "C" or deterministic ICU, SQLite BINARY, MariaDB
    /// utf8mb4_nopad_bin / VARBINARY, Redis keys). Trailing-space-padding `*_bin` collations are `PadSpace`.
    Binary,
    /// Binary but compares with trailing-space padding (MariaDB/MySQL utf8mb4_bin): 'acme ' = 'acme'.
    PadSpace,
    /// SQLite NOCASE, MySQL *_ci, citext and similar.
    CaseInsensitive,
    /// Nondeterministic ICU or anything else not byte-wise.
    Nondeterministic,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    pub field: Field,
    pub name: String,
    pub nullable: bool,
    pub collation: Collation,
    /// Part of the upsert/merge arbiter key (W3).
    pub key: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schema {
    pub collection: String,
    pub tenant_field: Field,
    pub columns: Vec<Column>,
    /// Columns a caller may read or return.
    pub permitted: Vec<Field>,
    /// Every unique index (including the primary key) as its column list. `prefix` marks an index that covers
    /// only a prefix of some column (e.g. MySQL `tenant(3)`).
    pub unique_indexes: Vec<UniqueIndex>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniqueIndex {
    pub fields: Vec<Field>,
    pub prefix: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaError {
    UnknownField(Field),
    /// `Not` is only sound on exact adapters (`refines_insufficient_for_not3`).
    NotRequiresExact,
    TenantFieldNullable,
    /// Tenant or key column with a non-binary collation (W3, `refines_necessary`).
    NonBinaryCollation(Field),
    TenantFieldWritten,
    ReturningNotPermitted(Field),
    /// Upsert needs the table's ONLY unique index to be exactly (tenant, key columns), full-length (W3, q4-005):
    /// engines such as MariaDB arbitrate on any unique index, so a second one lets an upsert land on a foreign row.
    UpsertArbiterNotTenantScoped,
    CollectionMismatch,
}

fn has_not(p: &Pred) -> bool {
    match p {
        Pred::Not(_) => true,
        Pred::And(a, b) | Pred::Or(a, b) => has_not(a) || has_not(b),
        _ => false,
    }
}

/// Static check an `Op` must pass before any adapter sees it. Total: never panics.
pub fn check_schema(op: &Op, s: &Schema, fidelity: Fidelity) -> Result<(), SchemaError> {
    if op.collection != s.collection {
        return Err(SchemaError::CollectionMismatch);
    }
    if s.columns.iter().any(|c| c.field == s.tenant_field && c.nullable) {
        return Err(SchemaError::TenantFieldNullable);
    }
    if let Some(c) = s.columns.iter().find(|c| (c.field == s.tenant_field || c.key) && c.collation != Collation::Binary)
    {
        return Err(SchemaError::NonBinaryCollation(c.field));
    }
    let mut reads = Vec::new();
    op.filter.reads(&mut reads);
    for f in reads.iter().chain(op.writes.iter().map(|(f, _)| f)).chain(op.returning.iter()) {
        if !s.columns.iter().any(|c| c.field == *f) {
            return Err(SchemaError::UnknownField(*f));
        }
    }
    if op.writes.iter().any(|(f, _)| *f == s.tenant_field) {
        return Err(SchemaError::TenantFieldWritten);
    }
    if let Some(f) = op.returning.iter().find(|f| !s.permitted.contains(f)) {
        return Err(SchemaError::ReturningNotPermitted(*f));
    }
    if op.kind == OpKind::Upsert {
        let mut want: Vec<Field> =
            s.columns.iter().filter(|c| c.key || c.field == s.tenant_field).map(|c| c.field).collect();
        want.sort_unstable();
        let ok = match s.unique_indexes.as_slice() {
            [only] => {
                let mut got = only.fields.clone();
                got.sort_unstable();
                !only.prefix && got == want && got.contains(&s.tenant_field) && got.len() >= 2
            }
            _ => false,
        };
        if !ok {
            return Err(SchemaError::UpsertArbiterNotTenantScoped);
        }
    }
    if fidelity != Fidelity::Exact && has_not(&op.filter) {
        return Err(SchemaError::NotRequiresExact);
    }
    Ok(())
}

/// What a backend can guarantee for the lowering-soundness theorem (Lean `Backend.Exact` vs `Backend.Refines`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fidelity {
    /// rows(render(lowerQ t p)) = {x | refQ3 t p x} (`rows_exact3`). Required for adapters accepting `Not`.
    /// Every rendered atom must yield UNKNOWN on a NULL column (so `In []` is never rendered as constant FALSE).
    Exact,
    /// rows ⊆ reference rows for `Not`-free predicates (never leaks; may miss).
    Refines,
}

/// An adapter lowers checked ops for one engine. Adapters outside the golden set run out of process
/// (aegis-adapter-host) and carry no assurance claim (golden extension contract, SPEC_INVARIANTS §H).
pub trait Adapter {
    type Rendered;
    type Error;
    fn engine_pin(&self) -> &str;
    fn fidelity(&self) -> Fidelity;
    /// Must render exactly `lowerQ(schema.tenant_field, op.tenant, op.filter)` plus the write/returning forms
    /// mandated for the engine (composite arbiters, FORCE RLS + WITH CHECK, no REPLACE family).
    fn render(&self, op: &Op, schema: &Schema) -> Result<Self::Rendered, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn schema() -> Schema {
        Schema {
            collection: "notes".into(),
            tenant_field: 0,
            columns: vec![
                Column { field: 0, name: "tenant".into(), nullable: false, collation: Collation::Binary, key: true },
                Column { field: 1, name: "title".into(), nullable: false, collation: Collation::Binary, key: true },
                Column {
                    field: 2,
                    name: "archived_at".into(),
                    nullable: true,
                    collation: Collation::Binary,
                    key: false,
                },
            ],
            permitted: vec![1, 2],
            unique_indexes: vec![UniqueIndex { fields: vec![0, 1], prefix: false }],
        }
    }

    fn op(filter: Pred) -> Op {
        let tenant = TenantId::new(9).unwrap_or_else(|_| unreachable!());
        Op { tenant, collection: "notes".into(), kind: OpKind::Select, filter, writes: vec![], returning: vec![1] }
    }

    #[test]
    fn not_needs_exact_and_tenant_writes_rejected() {
        let s = schema();
        let not_null = op(Pred::Not(Box::new(Pred::Eq(2, Value::Int(0)))));
        assert_eq!(check_schema(&not_null, &s, Fidelity::Exact), Ok(()));
        assert_eq!(check_schema(&not_null, &s, Fidelity::Refines), Err(SchemaError::NotRequiresExact));
        assert_eq!(check_schema(&op(Pred::Eq(2, Value::Int(0))), &s, Fidelity::Refines), Ok(()));
        let mut w = op(Pred::Tt);
        w.kind = OpKind::Update;
        w.writes = vec![(0, Value::Int(1))];
        assert_eq!(check_schema(&w, &s, Fidelity::Exact), Err(SchemaError::TenantFieldWritten));
        let mut ci = schema();
        if let Some(c) = ci.columns.first_mut() {
            c.collation = Collation::CaseInsensitive;
        }
        assert_eq!(check_schema(&op(Pred::Tt), &ci, Fidelity::Exact), Err(SchemaError::NonBinaryCollation(0)));
        if let Some(c) = ci.columns.first_mut() {
            c.collation = Collation::PadSpace;
        }
        assert_eq!(check_schema(&op(Pred::Tt), &ci, Fidelity::Exact), Err(SchemaError::NonBinaryCollation(0)));
        let mut up = op(Pred::Tt);
        up.kind = OpKind::Upsert;
        assert_eq!(check_schema(&up, &s, Fidelity::Exact), Ok(()));
        let mut two = schema();
        two.unique_indexes.push(UniqueIndex { fields: vec![1], prefix: false });
        assert_eq!(check_schema(&up, &two, Fidelity::Exact), Err(SchemaError::UpsertArbiterNotTenantScoped));
        let mut pre = schema();
        pre.unique_indexes = vec![UniqueIndex { fields: vec![0, 1], prefix: true }];
        assert_eq!(check_schema(&up, &pre, Fidelity::Exact), Err(SchemaError::UpsertArbiterNotTenantScoped));
        assert_eq!(Pred::or_n(vec![]), Pred::Ff);
        assert_eq!(Pred::and_n(vec![]), Pred::Tt);
    }
}
