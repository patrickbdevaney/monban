//! Sealed newtypes shared by every layer (frozen interface F2).
//!
//! Constructor discipline is enforced by Cargo features plus `xtask layering`:
//! - `Principal` can only be minted with feature `authn-path`, which only `monban-token` may enable (INV-NO-AMBIENT).
//! - `Canon<K>` can only be built with feature `canon-owner`, which only `monban-canon` may enable (CANON-1, CANON-3).
//! - `RawFor<S>` can only be built with feature `raw-owner`, which only `monban-transport` may enable (CANON-3).
//!
//! No type here implements `Default`; there is no "anonymous" principal value other than the explicit `Subject::Public`.
#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use core::fmt;
use core::marker::PhantomData;

/// A policy-stage decision. `Error` exists so hosts can map timeouts, crashes and panics to it before
/// combination; the combiner never returns it (INV-FAILCLOSED, spec/AegisIR/Combine.lean).
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Decision {
    Allow,
    Deny,
    Error,
}

/// Error for identifier constructors: the input had more than one plausible reading or was out of range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidId;

macro_rules! id_newtype {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            /// Zero is reserved as "unset" and rejected, so a zeroed struct can never alias a real id.
            pub const fn new(raw: u64) -> Result<Self, InvalidId> {
                if raw == 0 { Err(InvalidId) } else { Ok(Self(raw)) }
            }
            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }
    };
}

id_newtype!(
    /// Tenant identifier. Every data-plane predicate is conjoined with `tenant = t` (lowering soundness).
    TenantId
);
id_newtype!(
    /// Matched route identifier; authorization keys on this, never on the raw path (CANON-5).
    RouteId
);
id_newtype!(
    /// Capability identifier inside a verified token.
    CapId
);

/// Who a request acts as.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Subject {
    /// Explicitly unauthenticated. Its authority is limited to budgets and address validation (CRS C7).
    Public,
    /// Authenticated subject, opaque bytes chosen by the authn path (bounded to 255 bytes).
    Authenticated(Box<[u8]>),
}

impl fmt::Debug for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Subject::Public => f.write_str("Public"),
            Subject::Authenticated(b) => write!(f, "Authenticated(<{} bytes>)", b.len()),
        }
    }
}

/// The verified identity a request runs as. Constructible only on the authn path (feature `authn-path`).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Principal {
    tenant: TenantId,
    subject: Subject,
}

impl Principal {
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
    pub fn subject(&self) -> &Subject {
        &self.subject
    }
}

impl fmt::Debug for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Principal").field("tenant", &self.tenant).field("subject", &self.subject).finish()
    }
}

/// Minting entry point; only compiled for the crate that owns authentication.
#[cfg(feature = "authn-path")]
pub mod authn_path {
    use super::{InvalidId, Principal, Subject, TenantId};
    use alloc::boxed::Box;

    pub const MAX_SUBJECT_BYTES: usize = 255;

    /// Called only after token verification succeeded (INV-NO-AMBIENT grant at entry).
    pub fn mint(tenant: TenantId, subject: Option<&[u8]>) -> Result<Principal, InvalidId> {
        let subject = match subject {
            None => Subject::Public,
            Some(b) if b.is_empty() || b.len() > MAX_SUBJECT_BYTES => return Err(InvalidId),
            Some(b) => Subject::Authenticated(Box::from(b)),
        };
        Ok(Principal { tenant, subject })
    }
}

/// Marker trait for canonical kinds (route path, query, authority, SNI, Origin, header set, cookie jar,
/// media type, JSON body, principal id). Sealed: kinds are defined here only.
pub trait CanonKind: sealed::Sealed + 'static {
    const NAME: &'static str;
}

mod sealed {
    pub trait Sealed {}
}

macro_rules! canon_kinds {
    ($($k:ident => $n:literal),* $(,)?) => {
        /// Canonical kinds (CANON-1).
        pub mod kind {
            $(
                #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
                pub enum $k {}
                impl super::sealed::Sealed for $k {}
                impl super::CanonKind for $k { const NAME: &'static str = $n; }
            )*
        }
    };
}

canon_kinds!(
    RoutePath => "route-path",
    Query => "query",
    Authority => "authority",
    Sni => "sni",
    Origin => "origin",
    HeaderSet => "header-set",
    CookieJar => "cookie-jar",
    MediaType => "media-type",
    JsonBody => "json-body",
);

/// A value that passed the single canonicalizer for kind `K`. Downstream code reads and re-serializes it;
/// it never sees the raw form (CANON-3, CANON-4).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Canon<K: CanonKind> {
    bytes: Box<[u8]>,
    _k: PhantomData<K>,
}

impl<K: CanonKind> Canon<K> {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<K: CanonKind> fmt::Debug for Canon<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Canon<{}>(<{} bytes>)", K::NAME, self.bytes.len())
    }
}

#[cfg(feature = "canon-owner")]
pub mod canon_owner {
    use super::{Canon, CanonKind};
    use alloc::boxed::Box;
    use core::marker::PhantomData;

    /// Only the canonicalizer calls this, after it accepted the input.
    pub fn seal<K: CanonKind>(bytes: Box<[u8]>) -> Canon<K> {
        Canon { bytes, _k: PhantomData }
    }
}

/// Marker for the one consumer allowed to see raw bytes of a field (e.g. a webhook signature scheme).
pub trait RawSignature: 'static {
    const NAME: &'static str;
}

/// Raw, unparsed bytes reserved for one signature verifier `S` (CANON-3 escape hatch).
pub struct RawFor<S: RawSignature> {
    bytes: Box<[u8]>,
    _s: PhantomData<S>,
}

impl<S: RawSignature> RawFor<S> {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<S: RawSignature> fmt::Debug for RawFor<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawFor<{}>(<{} bytes>)", S::NAME, self.bytes.len())
    }
}

#[cfg(feature = "raw-owner")]
pub mod raw_owner {
    use super::{RawFor, RawSignature};
    use alloc::boxed::Box;
    use core::marker::PhantomData;

    pub fn capture<S: RawSignature>(bytes: Box<[u8]>) -> RawFor<S> {
        RawFor { bytes, _s: PhantomData }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_ids_rejected() {
        assert_eq!(TenantId::new(0), Err(InvalidId));
        assert_eq!(RouteId::new(7).map(RouteId::get), Ok(7));
    }
}
