//! Handler SDK (B2 scoped adapter, frozen interfaces F7 request-scoped surface and F7b streaming).
//!
//! Application crates depend on this crate alone (no tokio/axum). A handler receives a `Ctx<'r>` whose lifetime
//! is the request; every effect needs a `Granted<C>` that only the host can produce from the verified token and
//! the route's static endowment (INV-NO-AMBIENT). Streaming bodies, SSE, WebSocket sessions and detached jobs
//! are host-driven `'static` values that never hold a request-scoped capability (`streaming`, spike q4-001).
#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

mod streaming;
mod surface;
pub use streaming::*;
pub use surface::*;
