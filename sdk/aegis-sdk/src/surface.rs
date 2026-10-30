//! Frozen interface F7 (request-scoped subset; see crate docs).
//!
//! Re-frozen 2026-10-30 (P4-spec-002, decision D2(b); closes the q4-001 `MIRROR-DEVIATION: Ctx::grant`): `Ctx`
//! carries a private link to the host's live grant check, handlers obtain capability proofs only through
//! `Ctx::grant`, and the constructors of `Ctx`, `Granted` and `Tx` are `pub(crate)`, used only by the SDK's own host
//! driving loop (`host`, feature `host`). No crate outside aegis-sdk can mint any of the three.

use aegis_data_ir::{Op, OpKind};
use aegis_types::{Principal, RouteId};
use core::marker::PhantomData;

/// Proof that the host granted capability `C` for this request. No public constructor: only the host mints it.
#[derive(Debug)]
pub struct Granted<'r, C> {
    _c: PhantomData<C>,
    _r: PhantomData<&'r ()>,
}

impl<'r, C> Granted<'r, C> {
    pub(crate) fn mint() -> Self {
        Granted { _c: PhantomData, _r: PhantomData }
    }
}

/// Capability marker for data operations of kind `K` on one collection.
#[derive(Debug)]
pub struct DataCap<const K: u8>;

/// The host's live grant check for one request, step, message or job: the route's static endowment intersected with
/// the verified token, minus revocations. Crate-private: implemented only by the SDK host driving loop.
pub(crate) trait Grants: core::fmt::Debug {
    /// True iff data capability `op_code` (see `op_code`) is granted at the moment of the call.
    fn permits(&self, op_code: u8) -> bool;
}

/// Request context. Holds the principal and route; it cannot outlive the request.
#[derive(Debug)]
pub struct Ctx<'r> {
    principal: &'r Principal,
    route: RouteId,
    grants: &'r dyn Grants,
}

impl<'r> Ctx<'r> {
    #[cfg_attr(not(feature = "host"), allow(dead_code))]
    pub(crate) fn mint(principal: &'r Principal, route: RouteId, grants: &'r dyn Grants) -> Self {
        Ctx { principal, route, grants }
    }
    pub fn principal(&self) -> &'r Principal {
        self.principal
    }
    pub fn route(&self) -> RouteId {
        self.route
    }
    /// Host-checked proof for data capability `K` (an `op_code` value), tied to `'r`. `Denied` unless the route
    /// endowment and the live session permit `K` at the moment of the call (fail closed).
    pub fn grant<const K: u8>(&self) -> Result<Granted<'r, DataCap<K>>, SdkError> {
        if self.grants.permits(K) { Ok(Granted::mint()) } else { Err(SdkError::Denied) }
    }
}

/// Typestate transaction: effects are only durable after `commit` returns `Committed` (INV-NOMUT-C).
#[derive(Debug)]
pub struct Tx<'r, S> {
    _s: PhantomData<S>,
    _r: PhantomData<&'r ()>,
}

impl<'r, S> Tx<'r, S> {
    #[cfg_attr(not(feature = "host"), allow(dead_code))]
    pub(crate) fn mint() -> Self {
        Tx { _s: PhantomData, _r: PhantomData }
    }
}

#[derive(Debug)]
pub enum Open {}
#[derive(Debug)]
pub enum Committed {}

/// Failure surfaced to handlers. Uniform for authorization and existence (W6: no existence oracle).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdkError {
    Denied,
    Conflict,
    Unavailable,
}

/// The tenant-scoped database view. The host binds the tenant; handlers never pass it (the host overwrites
/// `Op::tenant` with the principal's tenant). Every view is also the request's `JobQueue` (supertrait), so handlers
/// reach `detach` through the db they are given.
pub trait TenantDb<'r>: crate::JobQueue<'r> {
    type Rows;
    fn begin(&self) -> Result<Tx<'r, Open>, SdkError>;
    fn run<const K: u8>(
        &self,
        tx: &mut Tx<'r, Open>,
        cap: &Granted<'r, DataCap<K>>,
        op: Op,
    ) -> Result<Self::Rows, SdkError>;
    fn commit(&self, tx: Tx<'r, Open>) -> Result<Tx<'r, Committed>, SdkError>;
}

/// A request-scoped handler.
pub trait ScopedHandler {
    type Response;
    fn handle<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<Self::Response, SdkError>;
}

/// Maps an `OpKind` to the const parameter used by `DataCap`.
pub const fn op_code(k: OpKind) -> u8 {
    match k {
        OpKind::Select => 1,
        OpKind::Insert => 2,
        OpKind::Update => 4,
        OpKind::Delete => 8,
        OpKind::Upsert => 16,
    }
}
