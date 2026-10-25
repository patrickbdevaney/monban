//! Design 3: naive `tokio::spawn` with `'static` bounds.
//!
//! To let a handler spawn a producer task (the axum `Body::from_stream(ReceiverStream)` idiom), everything the
//! task touches must be `'static`. With F7's `Ctx<'r>`/`Granted<'r, C>` that does not compile (see the
//! `d3strict_*` corpus cases, E0521). So D3 is the "leaky 'static hatch": owned, `Arc`-backed, `'static`
//! capability handles (the shape the round-004 B1 owned extractors had).

use crate::host::Store;
use crate::surface::{op_code, Committed, Endowment, Op, OpKind, Open, Principal, SdkError};
use core::marker::PhantomData;
use std::sync::Arc;

pub use crate::d1::{Chunk, Event};

/// Owned request context: `'static + Send + Sync + Clone` (the leak).
#[derive(Clone, Debug)]
pub struct OwnedCtx {
    principal: Arc<Principal>,
    endow: Arc<Endowment>,
}

/// Owned grant: `'static` (not Clone, like F7, but nothing ties it to the request).
#[derive(Debug)]
pub struct OwnedGranted<const K: u8>(PhantomData<()>);

impl OwnedCtx {
    pub(crate) fn new(principal: Arc<Principal>, endow: Arc<Endowment>) -> Self {
        OwnedCtx { principal, endow }
    }
    pub fn principal(&self) -> &Principal {
        &self.principal
    }
    pub fn grant<const K: u8>(&self) -> Result<OwnedGranted<K>, SdkError> {
        if self.endow.permits(K) {
            Ok(OwnedGranted(PhantomData))
        } else {
            Err(SdkError::Denied)
        }
    }
}

/// Owned tenant db handle.
#[derive(Clone, Debug)]
pub struct OwnedDb {
    store: Arc<Store>,
    tenant: u64,
}

#[derive(Debug)]
pub struct OwnedTx<S> {
    pending: Vec<Op>,
    _s: PhantomData<S>,
}

impl OwnedDb {
    pub(crate) fn new(store: Arc<Store>, tenant: u64) -> Self {
        OwnedDb { store, tenant }
    }
    pub fn begin(&self) -> Result<OwnedTx<Open>, SdkError> {
        Ok(OwnedTx { pending: Vec::new(), _s: PhantomData })
    }
    pub fn run<const K: u8>(
        &self,
        tx: &mut OwnedTx<Open>,
        _cap: &OwnedGranted<K>,
        op: Op,
    ) -> Result<Vec<(u64, String)>, SdkError> {
        if op_code(op.kind) != K {
            return Err(SdkError::Denied);
        }
        if op.kind == OpKind::Select {
            self.store.select(self.tenant, op.key)
        } else {
            tx.pending.push(op);
            Ok(Vec::new())
        }
    }
    pub fn commit(&self, tx: OwnedTx<Open>) -> Result<OwnedTx<Committed>, SdkError> {
        self.store.apply(self.tenant, tx.pending)?;
        Ok(OwnedTx { pending: Vec::new(), _s: PhantomData })
    }
}

/// Producer end of a host-owned body channel. Host checks session liveness per send.
#[derive(Clone, Debug)]
pub struct BodyTx<T> {
    tx: tokio::sync::mpsc::Sender<T>,
    endow: Arc<Endowment>,
}

impl<T: Send> BodyTx<T> {
    pub(crate) fn new(tx: tokio::sync::mpsc::Sender<T>, endow: Arc<Endowment>) -> Self {
        BodyTx { tx, endow }
    }
    pub async fn send(&self, item: T) -> Result<(), SdkError> {
        if !self.endow.session_live() {
            return Err(SdkError::Unavailable);
        }
        self.tx.send(item).await.map_err(|_| SdkError::Unavailable)
    }
}

/// (a) the handler is expected to `tokio::spawn` a producer feeding `out`.
pub trait BodyHandler: Send + Sync + 'static {
    fn stream(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Chunk>) -> Result<(), SdkError>;
}
/// (b)
pub trait SseHandler: Send + Sync + 'static {
    fn events(&self, ctx: OwnedCtx, db: OwnedDb, out: BodyTx<Event>) -> Result<(), SdkError>;
}
/// (c)
pub trait WsHandler: Send + Sync + 'static {
    fn session(
        &self,
        ctx: OwnedCtx,
        db: OwnedDb,
        inbox: tokio::sync::mpsc::Receiver<String>,
        out: BodyTx<String>,
    ) -> Result<(), SdkError>;
}
/// (d) detached: the handler just `tokio::spawn`s with owned handles; there is no commit gate.
pub trait JobHandler: Send + Sync + 'static {
    fn handle(&self, ctx: OwnedCtx, db: OwnedDb) -> Result<(), SdkError>;
}
