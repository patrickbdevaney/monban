//! Design 1: BORROWING streams tied to `'r`, driven by the host inside the request scope.
//!
//! The handler gets `Ctx<'r>`, `&'r D` and a host-owned sink/session that also borrows `'r`, and returns a future
//! bounded by `'r`. The host owns the request scope inside ONE connection task (an `async move` block that creates
//! the scope and borrows it), so that task is `'static` without any capability being `'static`.
//! No detached-job API exists here: nothing borrowed from `'r` can outlive the connection.

use crate::surface::{Ctx, Db, Endowment, SdkError};
use core::future::Future;
use std::collections::VecDeque;

pub type Chunk = String;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub id: u64,
    pub data: String,
}

/// Host-owned outbound sink, borrowed for the request. Each send re-checks session liveness (host-enforced).
#[derive(Debug)]
pub struct Sink<'r, T> {
    out: &'r mut Vec<T>,
    endow: &'r Endowment,
}

impl<'r, T: Send> Sink<'r, T> {
    pub(crate) fn new(out: &'r mut Vec<T>, endow: &'r Endowment) -> Self {
        Sink { out, endow }
    }
    pub async fn send(&mut self, item: T) -> Result<(), SdkError> {
        if !self.endow.session_live() {
            return Err(SdkError::Unavailable);
        }
        self.out.push(item);
        crate::YieldNow::default().await; // stands in for socket backpressure
        Ok(())
    }
}

/// Host-owned WebSocket session, borrowed for the request.
pub struct WsSession<'r> {
    inbox: &'r mut VecDeque<String>,
    out: Sink<'r, String>,
    seen: usize,
    before: &'r (dyn Fn(usize) + Send + Sync), // host hook run before delivering message i (tests revoke here)
}

impl core::fmt::Debug for WsSession<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WsSession")
    }
}

impl<'r> WsSession<'r> {
    pub(crate) fn new(
        inbox: &'r mut VecDeque<String>,
        out: Sink<'r, String>,
        before: &'r (dyn Fn(usize) + Send + Sync),
    ) -> Self {
        WsSession { inbox, out, seen: 0, before }
    }
    pub async fn recv(&mut self) -> Option<String> {
        crate::YieldNow::default().await;
        let m = self.inbox.pop_front()?;
        (self.before)(self.seen);
        self.seen += 1;
        Some(m)
    }
    pub async fn send(&mut self, m: String) -> Result<(), SdkError> {
        self.out.send(m).await
    }
}

/// (a) streamed response body.
pub trait BodyHandler: Send + Sync + 'static {
    fn stream<'r, D: Db<'r>>(
        &'r self,
        ctx: Ctx<'r>,
        db: &'r D,
        out: Sink<'r, Chunk>,
    ) -> impl Future<Output = Result<(), SdkError>> + Send + 'r;
}

/// (b) server-sent events.
pub trait SseHandler: Send + Sync + 'static {
    fn events<'r, D: Db<'r>>(
        &'r self,
        ctx: Ctx<'r>,
        db: &'r D,
        out: Sink<'r, Event>,
    ) -> impl Future<Output = Result<(), SdkError>> + Send + 'r;
}

/// (c) WebSocket session.
pub trait WsHandler: Send + Sync + 'static {
    fn session<'r, D: Db<'r>>(
        &'r self,
        ctx: Ctx<'r>,
        db: &'r D,
        ws: WsSession<'r>,
    ) -> impl Future<Output = Result<(), SdkError>> + Send + 'r;
}
