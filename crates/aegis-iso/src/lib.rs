//! Supervisor, exec-spawned zygote, Landlock+seccomp, cordons, fork+Wasm mode, crash budgets.
//!
//! Phase 5:
//! - [`sandbox`] (P5-iso-001): the process sandbox every zygote, fork child and cordon installs before it serves.
//! - [`zygote`] (P5-iso-002): the fork+Wasm zygote loop: accept on the inherited listening socket, one fork child per
//!   connection with the child filter and an `ITIMER_REAL` wall bound.
//! - [`supervisor`] (P5-iso-002): spawn a worker by execve with the listening socket at fd 3; respawn by execve only.
//!
//! The cordon and crash-budget modules land in P5-iso-003. Spec: `spec/SPEC_INVARIANTS.md` (INV-P2), PLAN-5
//! D2/D4/D5/D6/D8.
//!
//! `unsafe_code` is `deny` (not `forbid`) for this crate only: each audited site carries `#[allow(unsafe_code)]`
//! and a `// SAFETY:` comment, capped at 20 by `cargo xtask unsafe-sites` (DEVIATIONS X-14).
#![deny(unsafe_code)]

pub mod sandbox;
pub mod supervisor;
pub mod zygote;
