//! TLS profiles, PQ key exchange (incl. our SecP384r1MLKEM1024), ticketer per scope, STEK ring (P-PQ1..6).
//!
//! Unit P2-tls-001 (spec section F P-PQ1, P-PQ2, P-PQ4; frozen F12 `tls/verdicts.toml`):
//! - [`profile`]: the per-listener [`Profile`] lists and [`server_config`], the only way this crate builds a
//!   `rustls::ServerConfig`; with feature `tls-client` (off by default, off in the cmvp build:
//!   spikes/cmvp-client-policy mode A) also [`client_config`], the only rustls `ClientConfig` builder at L3
//!   (aegis-egress takes the built config by injection).
//! - [`kx`]: SecP384r1MLKEM1024 (0x11ED), ported from spike q4-026; in P-PUBLIC-WEB, P-UNIVERSAL and P-BSI-ALT.
//!   Features `kat` (KAT constructor, kx-kat gate) and `order-mutant` (combiner-order negative control) are test-only.
//!
//! Feature `cmvp` (PLAN-6 D1/D15, the profiles/cmvp overlay build): P-CNSA refused (no ML-DSA-87), P-UNIVERSAL and
//! P-BSI-ALT sign with ECDSA-P384 only, FIPS-CMVP buildable with the P-PQ5 module-identity assertion.
//!
//! Feature `mtc` (PLAN-7 D-P7.4, off by default, never with `cmvp`): [`select`], the MTC CredentialSelector over the
//! aegis-wire ClientHello peek.
//!
//! Not here yet: scoped ticketer + STEK ring (P-PQ3, P2-tls-002), PreferServerOrder backport.
#![forbid(unsafe_code)]

#[cfg(kani)]
mod kani_proofs; // Kani harnesses for the kx share parsing (P6-kani-001), run by ci/kani.sh --crate aegis-tls
pub mod kx;
pub mod profile;
/// Feature `mtc` (PREFLIGHT D-P7.4): the per-ClientHello [`CredentialSelector`] (F1 SEL-1..3). Compiled out of the
/// cmvp build even if both features are on, so MTC selection never reaches the certified-module binary.
#[cfg(all(feature = "mtc", not(feature = "cmvp")))]
pub mod select;

pub use profile::{
    FipsStatus, Profile, ProfileError, ProfileStatus, assert_profile, fips_check_with, fips_status_with,
    negotiable_versions, server_config, server_config_with,
};
#[cfg(feature = "tls-client")]
pub use profile::{assert_client_profile, client_config};
#[cfg(all(feature = "mtc", not(feature = "cmvp")))]
pub use select::{BoundSelector, Credential, CredentialKind, CredentialSelector, SelectError, key_scheme};
