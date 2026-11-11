//! Supervisor, exec-spawned zygote, Landlock+seccomp, cordons, fork+Wasm mode, crash budgets.
//!
//! Phase 5:
//! - [`sandbox`] (P5-iso-001): the process sandbox every zygote, fork child and cordon installs before it serves.
//! - [`zygote`] (P5-iso-002): the fork+Wasm zygote loop: accept on the inherited listening socket, one fork child per
//!   connection with the child filter and an `ITIMER_REAL` wall bound.
//! - [`supervisor`] (P5-iso-002): spawn a worker by execve with the listening socket at fd 3; respawn by execve only.
//! - [`cordon`] (P5-iso-003): the supervisor's cordon table keyed by principal (never shared, bounded, idle reaping)
//!   and the cordon's multi-threaded serving loop.
//! - [`crash_budget`] (P5-iso-003): per-principal crash budget (D7), pure logic over caller-supplied instants.
//!
//! Phase 6:
//! - `fips` (feature `cmvp`, P6-cmvp-002, PLAN-6 D16): the linked AWS-LC FIPS module's version string, read at run
//!   time for monban-tls's P-PQ5 assertion.
//!
//! Spec: `spec/SPEC_INVARIANTS.md` (INV-P2), PLAN-5
//! D1/D2/D4/D5/D6/D7/D8.
//!
//! `unsafe_code` is `deny` (not `forbid`) for this crate only: each audited site carries `#[allow(unsafe_code)]`
//! and a `// SAFETY:` comment, capped at 20 by `cargo xtask unsafe-sites` (DEVIATIONS X-14).
#![deny(unsafe_code)]

pub mod cordon;
pub mod crash_budget;
#[cfg(feature = "cmvp")]
pub mod fips;
pub mod sandbox;
pub mod supervisor;
pub mod zygote;
