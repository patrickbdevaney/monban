//! Supervisor, exec-spawned zygote, Landlock+seccomp, cordons, fork+Wasm mode, crash budgets.
//!
//! Phase-0 stub: every entry point fails closed. Spec: `spec/SPEC_INVARIANTS.md`.
#![forbid(unsafe_code)]
