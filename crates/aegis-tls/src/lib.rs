//! TLS profiles, PQ key exchange (incl. our SecP384r1MLKEM1024), ticketer per scope, STEK ring (P-PQ1..6).
//!
//! Unit P2-tls-001 (spec section F P-PQ1, P-PQ2, P-PQ4; frozen F12 `tls/verdicts.toml`):
//! - [`profile`]: the per-listener [`Profile`] lists and [`server_config`], the only way this crate builds a
//!   `rustls::ServerConfig`; with feature `tls-client` (off by default, off in the cmvp build:
//!   spikes/cmvp-client-policy mode A) also [`client_config`], the only rustls `ClientConfig` builder at L3
//!   (aegis-egress takes the built config by injection).
//! - [`kx`]: SecP384r1MLKEM1024 (0x11ED), ported from spike q4-026.
//!
//! Not here yet: scoped ticketer + STEK ring (P-PQ3, P2-tls-002), PreferServerOrder backport, cmvp build (P-PQ5).
#![forbid(unsafe_code)]

pub mod kx;
pub mod profile;

pub use profile::{
    FipsStatus, Profile, ProfileError, ProfileStatus, assert_profile, fips_status, negotiable_versions, server_config,
};
#[cfg(feature = "tls-client")]
pub use profile::{assert_client_profile, client_config};
