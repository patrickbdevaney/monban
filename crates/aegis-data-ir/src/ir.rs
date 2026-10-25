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
    /// Byte-wise / deterministic (PG "C" or deterministic ICU, SQLite BINARY, Redis keys).
    Binary,
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaError {
    UnknownField(Field),
    NotOverNullable(Field),
    TenantFieldNullable,
    /// Tenant or key column with a non-binary collation (W3, `refines_necessary`).
    NonBinaryCollation(Field),
    TenantFieldWritten,
    ReturningNotPermitted(Field),
    CollectionMismatch,
}

fn has_nullable_not(p: &Pred, s: &Schema) -> Option<Field> {
    match p {
        Pred::Not(inner) => {
            let mut rs = Vec::new();
            inner.reads(&mut rs);
            rs.into_iter().find(|f| s.columns.iter().any(|c| c.field == *f && c.nullable))
        }
        Pred::And(a, b) | Pred::Or(a, b) => has_nullable_not(a, s).or_else(|| has_nullable_not(b, s)),
        _ => None,
    }
}

/// Static check an `Op` must pass before any adapter sees it. Total: never panics.
pub fn check_schema(op: &Op, s: &Schema) -> Result<(), SchemaError> {
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
    if let Some(f) = has_nullable_not(&op.filter, s) {
        return Err(SchemaError::NotOverNullable(f));
    }
    Ok(())
}

/// What a backend can guarantee for the lowering-soundness theorem (Lean `Backend.Exact` vs `Backend.Refines`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fidelity {
    /// rows(render(lowerQ t p)) = reference rows. Required for golden adapters exposing `Not`.
    Exact,
    /// rows ⊆ reference rows (never leaks; may miss).
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
                Column { field: 1, name: "title".into(), nullable: false, collation: Collation::Binary, key: false },
                Column {
                    field: 2,
                    name: "archived_at".into(),
                    nullable: true,
                    collation: Collation::Binary,
                    key: false,
                },
            ],
            permitted: vec![1, 2],
        }
    }

    fn op(filter: Pred) -> Op {
        let tenant = TenantId::new(9).unwrap_or_else(|_| unreachable!());
        Op { tenant, collection: "notes".into(), kind: OpKind::Select, filter, writes: vec![], returning: vec![1] }
    }

    #[test]
    fn rejects_not_over_nullable_and_tenant_writes() {
        let s = schema();
        assert_eq!(
            check_schema(&op(Pred::Not(Box::new(Pred::Eq(2, Value::Int(0))))), &s),
            Err(SchemaError::NotOverNullable(2))
        );
        assert_eq!(check_schema(&op(Pred::Not(Box::new(Pred::Eq(1, Value::Int(0))))), &s), Ok(()));
        let mut w = op(Pred::Tt);
        w.kind = OpKind::Update;
        w.writes = vec![(0, Value::Int(1))];
        assert_eq!(check_schema(&w, &s), Err(SchemaError::TenantFieldWritten));
        let mut ci = schema();
        if let Some(c) = ci.columns.first_mut() {
            c.collation = Collation::CaseInsensitive;
        }
        assert_eq!(check_schema(&op(Pred::Tt), &ci), Err(SchemaError::NonBinaryCollation(0)));
        assert_eq!(Pred::or_n(vec![]), Pred::Ff);
        assert_eq!(Pred::and_n(vec![]), Pred::Tt);
    }
}
