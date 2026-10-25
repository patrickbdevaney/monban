//! Backend-agnostic data-plane IR (frozen interface F4). Postgres, SQLite and Redis are adapters, not the model.
//!
//! `Pred` mirrors `AegisIR.Pred` in spec/AegisIR/Lowering.lean constructor for constructor; the reference semantics is
//! `eval` there (two-valued, absent field ⇒ atom false). Every adapter renders `lowerQ tenant p`: the tenant conjunct
//! is added by the host from the minted `Principal`, never from request bytes.
//!
//! F4 freeze decision (provisional until spike q4-004 re-proves a three-valued reference): `check_schema` rejects
//! `Not` over any subtree that reads a nullable field, because Kleene NOT over an absent field can admit rows the
//! two-valued reference excludes (`refines_insufficient_for_not`, `not_absent_permits` in Lowering.lean).
#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

mod ir;
pub use ir::*;
