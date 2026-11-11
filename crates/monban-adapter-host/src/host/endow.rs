//! Route endowment → F4 `CapSet` (INV-NONEMPTY at the boot seam).
//!
//! The assembly resolves F8 `routes[].data` against the introspected schemas (monban-config `resolve_data`, which
//! yields `ResolvedData::{Caps(Vec<ResolvedCap>), Unrestricted}`) and hands each route's result here as an
//! [`Endowment`] (field for field: `ResolvedCap { backend, collection, ops_bits, fields }` is [`CapParts`]).
//!
//! Rules (no conversion can widen authority):
//! * [`Endowment::Absent`] (no data block) and [`Endowment::Failed`] (resolution error, null) hold no `CapSet`:
//!   every op is denied. Neither is ever read as `Unrestricted`.
//! * [`Endowment::Unrestricted`] is the only way to `CapSet::Unrestricted` (explicit and CI-gated by
//!   `ci/unrestricted.py`).
//! * Each [`CapParts`] becomes one `DataCap` through `DataCap::new` (no empty op mask, no empty column list, F8
//!   name grammar). A part that `DataCap::new` refuses cannot cover any op, so it grants nothing and is counted in
//!   [`Converted::inert`]; the boot must refuse a route with `inert > 0` (monban-config already enforces the F8
//!   grammar, so this never happens with a validated config). Caps are never unioned.
//! * No representable cap left (including an empty list) → no `CapSet` → deny.

use monban_data_ir::{CapError, CapSet, Caps, DataCap, OpMask};

use crate::dispatch::DispatchMutations;

/// One resolved capability (monban-config `ResolvedCap`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapParts {
    pub backend: String,
    pub collection: String,
    /// `OpMask` bits (select 1, insert 2, update 4, delete 8, upsert 16).
    pub ops_bits: u8,
    pub fields: Vec<u32>,
}

/// A route's data endowment as the boot seam delivers it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endowment {
    /// The route has no data block.
    Absent,
    /// Resolution failed or produced nothing usable (an error must never become an empty-means-all principal).
    Failed,
    /// The explicit `"unrestricted"` literal.
    Unrestricted,
    Caps(Vec<CapParts>),
}

/// Result of [`capset`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Converted {
    /// The route's capability set; `None` denies every op.
    pub caps: Option<CapSet>,
    /// Parts refused by `DataCap::new` (they grant nothing). The boot must fail when non-zero.
    pub inert: usize,
    /// Set when the list as a whole was refused (e.g. more than `MAX_CAPS`).
    pub refused: Option<CapError>,
}

impl Converted {
    /// Boot check: a fully representable endowment (nothing inert, nothing refused).
    pub fn boot_ok(&self) -> bool {
        self.inert == 0 && self.refused.is_none()
    }
}

/// Convert one route endowment.
pub fn capset(e: &Endowment) -> Converted {
    capset_with(e, DispatchMutations::NONE)
}

#[doc(hidden)]
pub fn capset_with(e: &Endowment, muts: DispatchMutations) -> Converted {
    let none = |inert, refused| Converted { caps: None, inert, refused };
    match e {
        Endowment::Unrestricted => Converted { caps: Some(CapSet::Unrestricted), inert: 0, refused: None },
        Endowment::Absent if muts.unrestricted_implicit || muts.missing_means_all => {
            Converted { caps: Some(CapSet::Unrestricted), inert: 0, refused: None } // MUTATION (self-test only)
        }
        Endowment::Failed if muts.missing_means_all => {
            Converted { caps: Some(CapSet::Unrestricted), inert: 0, refused: None } // MUTATION (self-test only)
        }
        Endowment::Absent | Endowment::Failed => none(0, None),
        Endowment::Caps(parts) if parts.is_empty() && muts.empty_means_all => {
            Converted { caps: Some(CapSet::Unrestricted), inert: 0, refused: None } // MUTATION (self-test only)
        }
        Endowment::Caps(parts) => {
            let mut caps = Vec::with_capacity(parts.len());
            let mut inert = 0usize;
            for p in parts {
                match OpMask::from_bits(p.ops_bits)
                    .and_then(|m| DataCap::new(&p.backend, &p.collection, m, p.fields.clone()))
                {
                    Ok(c) => caps.push(c),
                    Err(_) => inert = inert.saturating_add(1),
                }
            }
            if caps.is_empty() {
                return none(inert, parts.is_empty().then_some(CapError::EmptyCapSet));
            }
            match Caps::new(caps) {
                Ok(c) => Converted { caps: Some(CapSet::Caps(c)), inert, refused: None },
                Err(e) => none(inert, Some(e)),
            }
        }
    }
}
