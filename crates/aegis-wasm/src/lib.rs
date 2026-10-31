//! Wasm handler runtime for the P2 worker (PLAN-5 D1, D4, D6, D11; ARCHITECTURE §3.6 R-ISO-2/3): one Engine per
//! process built from the F8 `p2` values, the pooling allocator with the default 4 GiB reservation and 32 MiB guards,
//! MPK only as a density option, a fresh Store and instance per request, fuel as accounting, the epoch deadline as
//! the wall bound, and a ResourceLimiter at `memory_mib`.
//!
//! Linked only into the aegis-p2 worker binary, never into aegis-bin (D3, gate no-wasmtime-in-bin).
//!
//! Unsafe: exactly one audited site in the whole crate (DEVIATIONS X-14, `cargo xtask unsafe-sites` cap 1), the
//! deserialize of a `.cwasm` in [`engine::cwasm::load`], after its sha256 matched the digest the supervisor holds.
//! `abi` and `store` carry `#![forbid(unsafe_code)]`; `engine` is `deny` (its child `cwasm` holds the site).
//!
//! Spec: `spec/SPEC_INVARIANTS.md` §H (INV-P2), `interfaces/F14-p2-guest-abi.cddl`, `supply-chain/wasmtime-config.toml`.
#![deny(unsafe_code)]

pub mod abi;
pub mod engine;
#[cfg(feature = "test-hooks")]
pub mod fi;
pub mod store;

pub use engine::cwasm::{CwasmError, Digest};
pub use engine::{ConfigError, EngineError, EngineSettings, EpochTicker, Mpk, P2Engine, P2Limits};
pub use store::{Decision, Outcome, Report, RequestLimits, TrapKind, Worker, WorkerError};
