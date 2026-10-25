//! Tri-state fail-closed combiner (INV-FAILCLOSED, frozen interface F6) and, later, the Cedar adapter.
//!
//! `combine` is the Rust image of `AegisIR.Combine.combine` (spec/AegisIR/Combine.lean); the two are kept
//! equal by differential testing against the Lean model (DRT, Phase 3). Hosts map a stage timeout, crash or
//! panic to `Decision::Error` before calling `combine`.
#![forbid(unsafe_code)]
#![no_std]

mod combine;
pub use combine::*;
