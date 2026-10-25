//! Frozen interface F3: the Exchange and the front-end hook trait.
//!
//! Every protocol front end (HTTP request/response, WebSocket, SSE, WebTransport as stream modes; gRPC, GraphQL,
//! MCP, webhooks as handler layers) is one `Exchange`: a canonical head plus a bounded message stream, normalized
//! once by the core. A front end customizes the core through at most two hooks. R-ING-1 reverses (per-protocol
//! stacks) if any front end needs a third.

use aegis_types::kind::{Authority, RoutePath};
use aegis_types::{Canon, RouteId};

/// Per-exchange limits, debited before work (NC4). Values come from the profile, never from the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExchangeBudget {
    pub max_message_bytes: u32,
    pub max_frame_bytes: u32,
    pub max_messages: u32,
    pub max_total_bytes: u64,
    /// TBI-8: no progress for this long closes the exchange.
    pub stall_ms: u32,
}

/// Stream mode the exchange runs in after its head was accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// One request body, one response body.
    Unary,
    /// Entered only after a validated 101 (WebSocket) or equivalent handshake.
    Framed,
    /// Server-to-client event stream (SSE).
    ServerStream,
}

/// The canonical head the core hands to front ends. Raw bytes are not reachable from here (CANON-3).
#[derive(Debug)]
pub struct Head<'a> {
    pub route: RouteId,
    pub authority: &'a Canon<Authority>,
    pub path: &'a Canon<RoutePath>,
    pub method: Method,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
    Connect,
}

/// Result of `on_head`: the only way to leave `Unary` mode is an explicit accepted upgrade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadVerdict {
    Accept(Mode, ExchangeBudget),
    /// Reject with a status; the core sends it and never forwards the exchange.
    Reject(u16),
}

/// Result of `on_message`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageVerdict {
    Continue,
    Close(u16),
}

/// A front end. Both hooks must be total and bounded; the core maps a panic or timeout in either to a reject.
pub trait FrontEnd {
    /// Hook 1: decide mode and budget from the canonical head.
    fn on_head(&self, head: &Head<'_>) -> HeadVerdict;
    /// Hook 2: inspect one complete message (already size-checked against the budget).
    fn on_message(&self, head: &Head<'_>, message: &[u8]) -> MessageVerdict;
}
