//! Pure wire parsers that run before any byte is read as TLS or HTTP (PREFLIGHT D-P7.2).
//!
//! - [`proxy`]: the PROXY protocol v2 header (haproxy proxy-protocol.txt §2.2; F1 PROXY-1..3).
//! - [`tls_peek`]: a bounded peek at one TLS ClientHello record (F1 L4-1; the `trust_anchors` input of SEL-1).
//!
//! Both parsers are total (no panic on any input), allocation-free (`core` only; every extracted field borrows from
//! the input), and read nothing past the length the input declares. The receiver rules are the proxy-l4 oracle's
//! (`oracles/proxy-l4/README.md`); `vector_tests` checks every vector in `oracles/proxy-l4/vectors/`. The Kani bounds
//! are in `kani_proofs.rs` (gate kani-wire) and the fuzz targets are `proxy_v2` and `client_hello_peek`.
//! Spec: `spec/SPEC_INVARIANTS.md` §F addendum.
#![forbid(unsafe_code)]
// `core` only; Kani builds the crate with std (its harness runtime), everything else sees no_std.
#![cfg_attr(not(kani), no_std)]

#[cfg(test)]
extern crate std;

mod kani_proofs; // Kani harnesses; the module body is #[cfg(kani)] (see kani_proofs.rs)
pub mod proxy;
mod rd;
pub mod tls_peek;
#[cfg(test)]
mod vector_tests;
