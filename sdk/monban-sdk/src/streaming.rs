//! Frozen interface F7b: host-driven streaming extension (adopted from spike q4-001, design D2).
//!
//! Every stream, WebSocket session and detached job is a `'static` value that holds only plain data, never a
//! request-scoped capability. The host mints a fresh `Ctx<'m>` and db view for every step, message and job after
//! re-checking that the session is still live, and fails closed (`SdkError::Unavailable`) when it is not.
//! Host obligations (checked by the adapter-host oracle): per-step minting, never once per session; revoked
//! sessions deny their queued jobs; an idle/step budget per stream.
//! Deviation from the spike text: `detach` is a method of the host-provided `JobQueue`, still requiring the
//! committed-transaction proof. Re-frozen 2026-10-30 (P4-spec-002, D2(b)): `JobQueue<'r>` is a supertrait of
//! `TenantDb<'r>`, so every handler, step, message and job reaches `detach` through its db view. The SDK host collects
//! queued jobs and returns them to the backend owner, which runs each later with a fresh job-scoped context.

use crate::{Committed, Ctx, SdkError, TenantDb, Tx};
use alloc::boxed::Box;
use alloc::vec::Vec;

/// One pull of a host-driven stream.
#[derive(Debug, PartialEq, Eq)]
pub enum Step<T> {
    Item(T),
    Idle,
    Done,
}

/// A response-body chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk(pub Box<[u8]>);

/// A server-sent event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub id: u64,
    pub data: Box<[u8]>,
}

/// A WebSocket message (permessage-deflate is not supported: ARCHITECTURE §3.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WsMsg {
    Text(Box<str>),
    Binary(Box<[u8]>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum WsReply {
    Send(Vec<WsMsg>),
    Close,
}

/// Host-owned generator.
pub trait StreamGen: Send + 'static {
    type Item: Send + 'static;
    fn next<'m, D: TenantDb<'m>>(&mut self, ctx: Ctx<'m>, db: &D) -> Result<Step<Self::Item>, SdkError>;
}

pub trait BodyHandler: Send + Sync + 'static {
    type Gen: StreamGen<Item = Chunk>;
    fn open<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<Self::Gen, SdkError>;
}

pub trait SseHandler: Send + Sync + 'static {
    type Gen: StreamGen<Item = Event>;
    fn open<'r, D: TenantDb<'r>>(
        &self,
        ctx: Ctx<'r>,
        db: &D,
        last_event_id: Option<u64>,
    ) -> Result<Self::Gen, SdkError>;
}

pub trait WsSession: Send + 'static {
    fn on_message<'m, D: TenantDb<'m>>(&mut self, ctx: Ctx<'m>, db: &D, msg: &WsMsg) -> Result<WsReply, SdkError>;
}

pub trait WsHandler: Send + Sync + 'static {
    type Session: WsSession;
    fn open<'r, D: TenantDb<'r>>(&self, ctx: Ctx<'r>, db: &D) -> Result<Self::Session, SdkError>;
}

/// Detached job, run later by the host with a freshly minted job-scoped context.
pub trait Job: Send + 'static {
    fn run<'j, D: TenantDb<'j>>(self, ctx: Ctx<'j>, db: &D) -> Result<(), SdkError>;
}

/// Host-provided queue, reached through `TenantDb` (its supertrait). Jobs may only be queued after commit
/// (INV-NOMUT-C).
pub trait JobQueue<'r> {
    fn detach<J: Job>(&self, after: &Tx<'r, Committed>, job: J) -> Result<(), SdkError>;
}
