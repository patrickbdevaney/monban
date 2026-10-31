//! Supervisor, exec-spawned zygote, Landlock+seccomp, cordons, fork+Wasm mode, crash budgets.
//!
//! Phase 5: [`sandbox`] (P5-iso-001) is the process sandbox every zygote, fork child and cordon installs before it
//! serves. The zygote, cordon, supervisor and crash-budget modules land in P5-iso-002/003; until then nothing here
//! serves. Spec: `spec/SPEC_INVARIANTS.md` (INV-P2), PLAN-5 D2/D4/D5.
//!
//! `unsafe_code` is `deny` (not `forbid`) for this crate only: each audited site carries `#[allow(unsafe_code)]`
//! and a `// SAFETY:` comment, capped at 20 by `cargo xtask unsafe-sites` (DEVIATIONS X-14).
#![deny(unsafe_code)]

pub mod sandbox;
