//! Frozen interface F7 (request-scoped subset; see crate docs).

use aegis_data_ir::{Op, OpKind};
use aegis_types::{Principal, RouteId};
use core::marker::PhantomData;

/// Proof that the host granted capability `C` for this request. No public constructor: only the host mints it.
#[derive(Debug)]
pub struct Granted<'r, C> {
    _c: PhantomData<C>,
    _r: PhantomData<&'r ()>,
}

/// Capability marker for data operations of kind `K` on one collection.
#[derive(Debug)]
pub struct DataCap<const K: u8>;

/// Request context. Holds the principal and route; it cannot outlive the request.
#[derive(Debug)]
pub struct Ctx<'r> {
    principal: &'r Principal,
    route: RouteId,
}

impl<'r> Ctx<'r> {
    pub fn principal(&self) -> &'r Principal {
        self.principal
    }
    pub fn route(&self) -> RouteId {
        self.route
    }
}

/// Typestate transaction: effects are only durable after `commit` returns `Committed` (INV-NOMUT-C).
#[derive(Debug)]
pub struct Tx<'r, S> {
    _s: PhantomData<S>,
    _r: PhantomData<&'r ()>,
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

/// The tenant-scoped database view. The host binds the tenant; handlers never pass it.
pub trait TenantDb<'r> {
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
