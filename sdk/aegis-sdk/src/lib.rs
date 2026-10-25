//! Handler SDK (B2 scoped adapter, frozen interface F7: request-scoped subset only).
//!
//! Application crates depend on this crate alone (no tokio/axum). A handler receives a `Ctx<'r>` whose lifetime
//! is the request; every effect needs a `Granted<C>` that only the host can produce from the verified token and
//! the route's static endowment (INV-NO-AMBIENT). Streaming, SSE, WebSocket and detached jobs are NOT frozen:
//! their shape waits on spike q4-001 (a leaky `'static` there would flip to a host-owned stream capability).
#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

mod surface;
pub use surface::*;
