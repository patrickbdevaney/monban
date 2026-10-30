//! Capability check in host order (capset.rs): INV-NONEMPTY (absent data block denies, no empty set), authorize
//! before check_schema (W6), F8 name resolution and attenuation.

use aegis_data_ir::*;
use aegis_types::TenantId;

fn tid(v: u64) -> TenantId {
    TenantId::new(v).unwrap_or_else(|_| unreachable!())
}

fn notes() -> Schema {
    let col = |field, name: &str, key, nullable| Column {
        field,
        name: name.into(),
        nullable,
        collation: Collation::Binary,
        key,
    };
    Schema {
        collection: "notes".into(),
        tenant_field: 0,
        columns: vec![col(0, "tenant", false, false), col(1, "id", true, false), col(2, "title", false, true)],
        permitted: vec![1, 2],
        unique_indexes: vec![UniqueIndex { fields: vec![0, 1], prefix: false }],
    }
}

fn sel(filter: Pred, returning: Vec<Field>) -> Op {
    Op { tenant: tid(7), collection: "notes".into(), kind: OpKind::Select, filter, writes: vec![], returning }
}

fn caps(list: Vec<DataCap>) -> CapSet {
    CapSet::Caps(Caps::new(list).unwrap_or_else(|_| unreachable!()))
}

fn resolve(ops: &[&str], cols: &[&str]) -> Result<DataCap, ResolveError> {
    resolve_cap("db", "notes", ops, cols, &notes())
}

#[test]
fn absent_data_block_denies_everything() {
    let s = notes();
    for kind in OpKind::ALL {
        let mut o = sel(Pred::Tt, vec![]);
        o.kind = kind;
        assert_eq!(admit(None, "db", &o, &s, Fidelity::Exact), Err(Refusal::Denied), "{kind:?}");
    }
}

#[test]
fn deny_comes_before_schema_errors() {
    let s = notes();
    let read_title = caps(vec![resolve(&["select"], &["title"]).unwrap_or_else(|_| unreachable!())]);
    // A probe on a column the caller holds no capability for: Denied, never "UnknownField"/"ReturningNotPermitted".
    let probe = sel(Pred::Eq(99, Value::Int(0)), vec![0]);
    assert_eq!(admit(Some(&read_title), "db", &probe, &s, Fidelity::Exact), Err(Refusal::Denied));
    let mut other = sel(Pred::Tt, vec![2]);
    other.collection = "secrets".into();
    assert_eq!(admit(Some(&read_title), "db", &other, &s, Fidelity::Exact), Err(Refusal::Denied));
    // Unrestricted lifts the capability check only: the schema check still refuses.
    assert_eq!(
        admit(Some(&CapSet::Unrestricted), "db", &probe, &s, Fidelity::Exact),
        Err(Refusal::Schema(SchemaError::UnknownField(99)))
    );
    assert_eq!(
        admit(Some(&CapSet::Unrestricted), "db", &other, &s, Fidelity::Exact),
        Err(Refusal::Schema(SchemaError::CollectionMismatch))
    );
    // Covered and well-formed: admitted.
    assert_eq!(admit(Some(&read_title), "db", &sel(Pred::Eq(2, Value::Int(0)), vec![2]), &s, Fidelity::Exact), Ok(()));
    assert_eq!(
        admit(Some(&read_title), "other-db", &sel(Pred::Tt, vec![2]), &s, Fidelity::Exact),
        Err(Refusal::Denied)
    );
    // Covered but schema-invalid (Not on a Refines backend): the schema refusal is reachable only now.
    let not = sel(Pred::Not(Box::new(Pred::Eq(2, Value::Int(0)))), vec![2]);
    assert_eq!(
        admit(Some(&read_title), "db", &not, &s, Fidelity::Refines),
        Err(Refusal::Schema(SchemaError::NotRequiresExact))
    );
}

#[test]
fn resolution_never_widens() {
    let Ok(c) = resolve(&["select", "update", "select"], &["title", "id", "title"]) else { unreachable!() };
    assert_eq!((c.backend(), c.collection(), c.columns()), ("db", "notes", &[1, 2][..]));
    assert!(c.ops().contains(OpKind::Update) && !c.ops().contains(OpKind::Delete));
    assert_eq!(resolve(&[], &["title"]), Err(ResolveError::Cap(CapError::BadOps)));
    assert_eq!(resolve(&["select"], &[]), Err(ResolveError::Cap(CapError::EmptyColumns)));
    assert_eq!(resolve(&["SELECT"], &["title"]), Err(ResolveError::UnknownOp));
    assert_eq!(resolve(&["all"], &["title"]), Err(ResolveError::UnknownOp));
    assert_eq!(resolve(&["select"], &["*"]), Err(ResolveError::UnknownColumn));
    assert_eq!(resolve(&["select"], &["Title"]), Err(ResolveError::UnknownColumn));
    assert_eq!(resolve_cap("db", "users", &["select"], &["title"], &notes()), Err(ResolveError::CollectionMismatch));
    assert_eq!(
        resolve_cap("DB", "notes", &["select"], &["title"], &notes()),
        Err(ResolveError::Cap(CapError::BadBackendId))
    );
}

#[test]
fn attenuation_order() {
    let r = |ops: &[&str], cols: &[&str]| resolve(ops, cols).unwrap_or_else(|_| unreachable!());
    let parent = caps(vec![r(&["select", "update"], &["id", "title"])]);
    let narrower = caps(vec![r(&["select"], &["title"])]);
    let wider_ops = caps(vec![r(&["select", "delete"], &["title"])]);
    let wider_cols = caps(vec![r(&["select"], &["tenant", "title"])]);
    assert!(capset_within(&narrower, &parent));
    assert!(capset_within(&parent, &parent));
    assert!(!capset_within(&wider_ops, &parent));
    assert!(!capset_within(&wider_cols, &parent));
    assert!(!capset_within(&CapSet::Unrestricted, &parent));
    assert!(capset_within(&parent, &CapSet::Unrestricted));
    assert!(capset_within(&CapSet::Unrestricted, &CapSet::Unrestricted));
    // No union: two parent caps that each cover half do not contain a child needing both.
    let halves = caps(vec![r(&["select"], &["id"]), r(&["select"], &["title"])]);
    let both = caps(vec![r(&["select"], &["id", "title"])]);
    assert!(!capset_within(&both, &halves));
    let mut other_backend = r(&["select"], &["title"]);
    other_backend = DataCap::new("db2", "notes", other_backend.ops(), other_backend.columns().to_vec())
        .unwrap_or_else(|_| unreachable!());
    assert!(!cap_within(&other_backend, &r(&["select"], &["title"])));
}

#[test]
fn authorize_property_no_cap_covers_means_denied() {
    // Over a grid of ops and single-cap sets, admit agrees with "some cap covers the op" (then schema).
    let s = notes();
    let kinds = OpKind::ALL;
    let colsets: [&[&str]; 4] = [&["id"], &["title"], &["id", "title"], &["tenant", "id", "title"]];
    let mut admitted = 0;
    for k in kinds {
        for cs in colsets {
            let cap = resolve(&[k.name()], cs).unwrap_or_else(|_| unreachable!());
            let set = caps(vec![cap.clone()]);
            for f in [0u32, 1, 2] {
                for ret in [vec![], vec![1], vec![2]] {
                    let mut o = sel(Pred::Eq(f, Value::Int(1)), ret);
                    o.kind = OpKind::Select;
                    let got = admit(Some(&set), "db", &o, &s, Fidelity::Exact);
                    if !cap.covers("db", &o) {
                        assert_eq!(got, Err(Refusal::Denied));
                    } else if got.is_ok() {
                        admitted += 1;
                    }
                }
            }
        }
    }
    assert!(admitted > 0, "non-vacuous");
}
