//! Tri-state fail-closed combiner (INV-FAILCLOSED, frozen interface F6) and the pure client side of the
//! out-of-process Cedar PDP (DEVIATIONS X-8).
//!
//! `combine` is the Rust image of `AegisIR.Combine.combine` (spec/AegisIR/Combine.lean); the two are kept
//! equal by differential testing against the Lean model (DRT, Phase 3). Hosts map a stage timeout, crash or
//! panic to `Decision::Error` before calling `combine`; for the Cedar PDP that mapping is [`pdp::PdpClient`],
//! which is pure (no I/O): the socket transport implements [`pdp::PdpTransport`] in a higher layer.
#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

mod combine;
pub use combine::*;

pub mod pdp;
