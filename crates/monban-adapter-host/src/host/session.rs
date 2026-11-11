//! The host's live grant state of one session (`monban_sdk::host::Session`).
//!
//! A session is the verified principal on one route: the route's static endowment (its F4 `CapSet`) intersected
//! with the verified token's op set, minus revocation. Every answer is read from the shared state at the moment of
//! the call ([`SessionHandle::permits`], [`SessionHandle::live`]); nothing is snapshotted at open, at detach or at
//! queueing time, so an epoch change or a revocation reaches the very next step, message or job (INV-NO-AMBIENT,
//! CRS C5).

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use monban_data_ir::CapSet;
use monban_data_ir::tenant_text;
use monban_types::{Principal, RouteId, Subject};

/// The five single-kind op codes (`monban_sdk::op_code`), as a mask.
pub const ALL_OPS: u8 = 0b1_1111;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// The op kinds a route endowment can ever grant: the union of its capabilities' op masks (`Unrestricted`: all;
/// no data block: none). Column and collection coverage is checked per op by `dispatch` (F4 `authorize`).
pub fn endowment_ops(caps: Option<&CapSet>) -> u8 {
    match caps {
        None => 0,
        Some(CapSet::Unrestricted) => ALL_OPS,
        Some(CapSet::Caps(c)) => c.as_slice().iter().fold(0u8, |m, d| m | d.ops().bits()) & ALL_OPS,
    }
}

/// Canonical identity bytes of a principal (pool keys, NC4 charge accounts): the 16-hex tenant (fixed width), then
/// `0` for `Public` or `1` followed by the authenticated subject bytes. Injective over principals.
pub fn principal_bytes(p: &Principal) -> Vec<u8> {
    let mut b = tenant_text(p.tenant()).into_bytes();
    match p.subject() {
        Subject::Public => b.push(0),
        Subject::Authenticated(s) => {
            b.push(1);
            b.extend_from_slice(s);
        }
    }
    b
}

struct Inner {
    id: u64,
    principal: Principal,
    route: RouteId,
    endowment: Option<Arc<CapSet>>,
    endowment_ops: u8,
    token_ops: AtomicU8,
    live: AtomicBool,
}

/// Shared handle to one session's live state. Cheap to clone; every clone sees revocations and epoch changes.
#[derive(Clone)]
pub struct SessionHandle(Arc<Inner>);

impl fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionHandle")
            .field("id", &self.0.id)
            .field("route", &self.0.route)
            .field("live", &self.live())
            .finish_non_exhaustive()
    }
}

impl SessionHandle {
    /// A live session. `endowment` is the route's capability set (`None`: the route has no data block);
    /// `token_ops` is the verified token's op mask (bits of `monban_sdk::op_code`).
    pub fn new(principal: Principal, route: RouteId, endowment: Option<Arc<CapSet>>, token_ops: u8) -> SessionHandle {
        let endowment_ops = endowment_ops(endowment.as_deref());
        SessionHandle(Arc::new(Inner {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            principal,
            route,
            endowment,
            endowment_ops,
            token_ops: AtomicU8::new(token_ops & ALL_OPS),
            live: AtomicBool::new(true),
        }))
    }

    /// Process-unique id of this session (for backend factories and logs).
    pub fn id(&self) -> u64 {
        self.0.id
    }

    pub fn principal(&self) -> &Principal {
        &self.0.principal
    }

    pub fn route(&self) -> RouteId {
        self.0.route
    }

    /// The route's endowment, for dispatch.
    pub fn endowment(&self) -> Option<Arc<CapSet>> {
        self.0.endowment.clone()
    }

    /// Revoke the session or its token: `live()` is false from now on, for every clone. Irreversible.
    pub fn revoke(&self) {
        self.0.live.store(false, Ordering::SeqCst);
    }

    /// Grant-epoch change (token re-verified or attenuated): `permits` answers from the new op mask from now on.
    pub fn set_token_ops(&self, ops: u8) {
        self.0.token_ops.store(ops & ALL_OPS, Ordering::SeqCst);
    }

    pub fn live(&self) -> bool {
        self.0.live.load(Ordering::SeqCst)
    }

    /// The op mask granted now: endowment ∩ token, empty once revoked.
    pub fn ops_now(&self) -> u8 {
        if !self.live() {
            return 0;
        }
        self.0.endowment_ops & self.0.token_ops.load(Ordering::SeqCst)
    }

    /// True iff the single-kind op code `k` is granted now.
    pub fn permits(&self, k: u8) -> bool {
        matches!(k, 1 | 2 | 4 | 8 | 16) && self.ops_now() & k != 0
    }
}

impl monban_sdk::host::Session for SessionHandle {
    fn permits(&self, op_code: u8) -> bool {
        SessionHandle::permits(self, op_code)
    }
    fn live(&self) -> bool {
        SessionHandle::live(self)
    }
}

/// Values frozen by a self-test mutation (`None` = read live). Production never freezes anything.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Frozen {
    pub(crate) live: Option<bool>,
    pub(crate) ops: Option<u8>,
}

impl Frozen {
    pub(crate) const NONE: Frozen = Frozen { live: None, ops: None };
}

/// What the SDK is handed for one scope: the live session, unless a self-test mutation froze part of it.
pub(crate) struct View<'a> {
    pub(crate) s: &'a SessionHandle,
    pub(crate) frozen: Frozen,
}

impl fmt::Debug for View<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("View").field("s", self.s).field("frozen", &self.frozen).finish()
    }
}

impl monban_sdk::host::Session for View<'_> {
    fn permits(&self, k: u8) -> bool {
        let ops = match self.frozen.ops {
            Some(o) => o,
            None => self.s.0.endowment_ops & self.s.0.token_ops.load(Ordering::SeqCst),
        };
        matches!(k, 1 | 2 | 4 | 8 | 16) && self.live() && ops & k != 0
    }
    fn live(&self) -> bool {
        self.frozen.live.unwrap_or_else(|| self.s.live())
    }
}
