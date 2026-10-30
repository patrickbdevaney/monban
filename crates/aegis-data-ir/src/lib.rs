//! Backend-agnostic data-plane IR (frozen interface F4). Postgres, SQLite and Redis are adapters, not the model.
//!
//! `Pred` mirrors `AegisIR.Pred` in spec/AegisIR/Lowering.lean constructor for constructor; the reference semantics is
//! `eval` there (two-valued, absent field ⇒ atom false). Every adapter renders `lowerQ tenant p`: the tenant conjunct
//! is added by the host from the minted `Principal`, never from request bytes.
//!
//! Policy semantics are three-valued (`eval3`/`refQ3` in spec/AegisIR/ThreeValued.lean, adopted from spike q4-004):
//! on an exact backend the rendered SQL returns exactly the permitted rows; `Not` is accepted only by exact adapters.
//!
//! Host order per op: [`authorize`] (route `CapSet`, INV-NONEMPTY) → [`check_schema`] against the introspected
//! schema → budget pre-debit (NC4) → [`Adapter::render`] (or [`kv_plan`] on Redis/Valkey) → execute. Tenant values
//! reach engines only as [`tenant_text`] / [`kv_key_prefix`] (decision D4). The allowlist lock is [`lock_body`] plus a
//! `sha256` trailer; [`denylist`] is the per-family deny data; [`EnginePin`] gates server versions at connect.
#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

mod capset;
mod ir;
mod lock;
mod lower;
pub use capset::*;
pub use ir::*;
pub use lock::*;
pub use lower::*;
