//! Pure wire parsers that run before any byte is read as TLS or HTTP (PREFLIGHT D-P7.2).
//!
//! - [`proxy`]: the PROXY protocol v2 header (haproxy proxy-protocol.txt §2.2; F1 PROXY-1..3).
//! - [`tls_peek`]: a bounded peek at one TLS ClientHello record (F1 L4-1; the `trust_anchors` input of SEL-1).
//!
//! P7-spec-002 pre-wires the crate with fail-closed stubs: every parser returns an error, so nothing built on it can
//! admit a connection until P7-wire-001 lands the real parsers (and their Kani bounds and fuzz targets).
//! The parsers use `core` only (no allocation), so the crate can go `no_std` once the parsers land.
//! Spec: `spec/SPEC_INVARIANTS.md` §F addendum.
#![forbid(unsafe_code)]

mod kani_proofs; // Kani harnesses; the module body is #[cfg(kani)] (see kani_proofs.rs)
pub mod proxy;
pub mod tls_peek;
