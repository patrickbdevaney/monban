//! Mirror of frozen F7 (`sdk/aegis-sdk/src/surface.rs`, request-scoped subset). Same type names, same field
//! shapes and the same variance (`PhantomData<&'r ()>` = covariant in `'r`, no `Clone`, no public constructor).
//! Deviations needed so a mock host can mint and run things are marked MIRROR-DEVIATION.

use core::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// MIRROR-DEVIATION: stands in for `aegis_types::RouteId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteId(pub u32);

/// MIRROR-DEVIATION: stands in for `aegis_types::Principal` (private fields, no public constructor).
#[derive(Debug, PartialEq, Eq)]
pub struct Principal {
    user: u64,
    tenant: u64,
}

impl Principal {
    pub(crate) fn new(user: u64, tenant: u64) -> Self {
        Principal { user, tenant }
    }
    pub fn user(&self) -> u64 {
        self.user
    }
    pub fn tenant(&self) -> u64 {
        self.tenant
    }
}

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

/// MIRROR-DEVIATION: host-owned live policy for one session. The frozen subset does not say how a handler
/// obtains a `Granted`; here `Ctx::grant` asks the host, which consults this (allowed mask minus revocations).
#[derive(Debug)]
pub struct Endowment {
    allowed: u8,
    revoked_caps: AtomicU8,
    session_revoked: AtomicBool,
}

impl Endowment {
    pub(crate) fn new(allowed: u8) -> Self {
        Endowment { allowed, revoked_caps: AtomicU8::new(0), session_revoked: AtomicBool::new(false) }
    }
    /// Control plane: revoke one capability kind while the session stays valid.
    pub fn revoke_cap(&self, k: u8) {
        self.revoked_caps.fetch_or(k, Ordering::SeqCst);
    }
    /// Control plane: revoke the whole session (token expiry, logout).
    pub fn revoke_session(&self) {
        self.session_revoked.store(true, Ordering::SeqCst);
    }
    pub fn session_live(&self) -> bool {
        !self.session_revoked.load(Ordering::SeqCst)
    }
    pub(crate) fn permits(&self, k: u8) -> bool {
        self.session_live() && self.allowed & k == k && self.revoked_caps.load(Ordering::SeqCst) & k == 0
    }
}

/// Request context. Holds the principal and route; it cannot outlive the request.
#[derive(Debug)]
pub struct Ctx<'r> {
    principal: &'r Principal,
    route: RouteId,
    // MIRROR-DEVIATION: host links needed by `grant` and by D2's `detach`.
    endow: &'r Endowment,
    pub(crate) jobs: &'r crate::d2::JobQueue,
}

impl<'r> Ctx<'r> {
    pub(crate) fn new(
        principal: &'r Principal,
        route: RouteId,
        endow: &'r Endowment,
        jobs: &'r crate::d2::JobQueue,
    ) -> Self {
        Ctx { principal, route, endow, jobs }
    }
    pub fn principal(&self) -> &'r Principal {
        self.principal
    }
    pub fn route(&self) -> RouteId {
        self.route
    }
    /// MIRROR-DEVIATION: host-checked grant for data capability `K`. The returned proof is tied to `'r`.
    pub fn grant<const K: u8>(&self) -> Result<Granted<'r, DataCap<K>>, SdkError> {
        if self.endow.permits(K) {
            Ok(Granted::mint())
        } else {
            Err(SdkError::Denied)
        }
    }
}

/// Typestate transaction: effects are only durable after `commit` returns `Committed` (INV-NOMUT-C).
#[derive(Debug)]
pub struct Tx<'r, S> {
    pub(crate) pending: Vec<Op>, // MIRROR-DEVIATION: the mock host buffers writes here
    _s: PhantomData<S>,
    _r: PhantomData<&'r ()>,
}

impl<'r, S> Tx<'r, S> {
    pub(crate) fn new() -> Self {
        Tx { pending: Vec::new(), _s: PhantomData, _r: PhantomData }
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

/// MIRROR-DEVIATION: stands in for `aegis_data_ir::{Op, OpKind}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpKind {
    Select,
    Insert,
    Update,
    Delete,
    Upsert,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    pub kind: OpKind,
    pub key: u64,
    pub val: String,
}

impl Op {
    pub fn select(key: u64) -> Op {
        Op { kind: OpKind::Select, key, val: String::new() }
    }
    pub fn insert(key: u64, val: &str) -> Op {
        Op { kind: OpKind::Insert, key, val: val.to_string() }
    }
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

/// MIRROR-DEVIATION: concrete row type so generic handlers can read results (F7 keeps `Rows` associated).
pub type Rows = Vec<(u64, String)>;

/// MIRROR-DEVIATION: shorthand bound used by the streaming extensions: a `TenantDb` with readable rows.
pub trait Db<'r>: TenantDb<'r, Rows = Rows> + Sync {}
impl<'r, T: TenantDb<'r, Rows = Rows> + Sync> Db<'r> for T {}

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

pub const SELECT: u8 = op_code(OpKind::Select);
pub const INSERT: u8 = op_code(OpKind::Insert);
