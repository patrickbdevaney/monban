//! Capability check in host order (P4-datair-001, INV-NONEMPTY, W6): `authorize` (route `CapSet`) before
//! `check_schema`, so a caller without a covering capability learns nothing about the collection or its schema.
//!
//! Also: resolving an F8 capability (op names, column names) against an introspected schema into a [`DataCap`]
//! (an unknown name fails the boot, never widens), and the attenuation order on capability sets (D2).

use crate::ir::{
    CapError, CapSet, DataCap, Denied, Fidelity, Op, OpKind, OpMask, Schema, SchemaError, authorize, check_schema,
};
use alloc::vec::Vec;

/// Refusal from [`admit`]. `Denied` carries no reason (W6); a schema refusal is only reachable once some
/// capability covers the op.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    Denied,
    Schema(SchemaError),
}

impl From<Denied> for Refusal {
    fn from(_: Denied) -> Refusal {
        Refusal::Denied
    }
}

/// Host admission for one op: capability first, then the static schema check.
///
/// `caps` is the route's data endowment: `None` when the route has no F8 `data` block, which denies every op (it
/// never means `Unrestricted`, INV-NONEMPTY). `Unrestricted` lifts the capability check only; `check_schema` still
/// runs. Total: never panics.
pub fn admit(
    caps: Option<&CapSet>,
    backend: &str,
    op: &Op,
    schema: &Schema,
    fidelity: Fidelity,
) -> Result<(), Refusal> {
    let caps = caps.ok_or(Refusal::Denied)?;
    authorize(caps, backend, op)?;
    check_schema(op, schema, fidelity).map_err(Refusal::Schema)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolveError {
    Cap(CapError),
    /// An op name that is not one of the five F8 names.
    UnknownOp,
    /// A column name the introspected schema does not have.
    UnknownColumn,
    /// The capability names a collection other than the schema's.
    CollectionMismatch,
}

/// Build a [`DataCap`] from F8 names, resolving column names against the introspected `schema` of `collection`.
/// Empty `ops` or `columns`, unknown names and a mismatched collection are refused (INV-NONEMPTY: nothing here can
/// turn "none" into "all").
pub fn resolve_cap(
    backend: &str,
    collection: &str,
    ops: &[&str],
    columns: &[&str],
    schema: &Schema,
) -> Result<DataCap, ResolveError> {
    if schema.collection != collection {
        return Err(ResolveError::CollectionMismatch);
    }
    let mut kinds: Vec<OpKind> = Vec::with_capacity(ops.len());
    for o in ops {
        kinds.push(OpKind::from_name(o).ok_or(ResolveError::UnknownOp)?);
    }
    let mask = OpMask::of(&kinds).map_err(ResolveError::Cap)?;
    let mut fields = Vec::with_capacity(columns.len());
    for name in columns {
        let c = schema.columns.iter().find(|c| c.name == *name).ok_or(ResolveError::UnknownColumn)?;
        fields.push(c.field);
    }
    DataCap::new(backend, collection, mask, fields).map_err(ResolveError::Cap)
}

/// One capability is within another: same backend and collection, ops a subset, columns a subset.
pub fn cap_within(child: &DataCap, parent: &DataCap) -> bool {
    child.backend() == parent.backend()
        && child.collection() == parent.collection()
        && child.ops().is_subset_of(parent.ops())
        && child.columns().iter().all(|f| parent.columns().binary_search(f).is_ok())
}

/// Attenuation order (D2): every child capability lies within a single parent capability. `Unrestricted` is within
/// only `Unrestricted`; everything is within `Unrestricted`.
pub fn capset_within(child: &CapSet, parent: &CapSet) -> bool {
    match (child, parent) {
        (_, CapSet::Unrestricted) => true,
        (CapSet::Unrestricted, CapSet::Caps(_)) => false,
        (CapSet::Caps(c), CapSet::Caps(p)) => {
            c.as_slice().iter().all(|d| p.as_slice().iter().any(|q| cap_within(d, q)))
        }
    }
}
