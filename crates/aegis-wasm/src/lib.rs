//! Wasm handler runtime (feature p2): fresh Store per request, fuel, epoch watchdog, linker allowlist.
//!
//! Phase-0 stub: every entry point fails closed. Spec: `spec/SPEC_INVARIANTS.md`.
#![forbid(unsafe_code)]
