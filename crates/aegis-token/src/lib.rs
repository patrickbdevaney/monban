//! Capability tokens: Tier 0 table, Tier L HMAC chain (det-CBOR), Tier X COSE ML-DSA-65 verify. INV-ATTEN.
//!
//! Spec: frozen interface F5 (`interfaces/F5-token.cddl`), formal model `spec/AegisIR/Token.lean` (T1–T5),
//! ARCHITECTURE §3.5. This is the only crate allowed to call `aegis_types::authn_path::mint`; every verifier mints a
//! `Principal` only after the full check succeeded.
//!
//! - Verify is the conjunction of EVERY caveat (never leaf-only), plus `depthOk` (D3) and the F5 mint-shape check.
//! - `now` is a field of [`Req`]; nothing here reads a clock.
//! - Tags and Tier-0 handle digests are compared with AWS-LC's constant-time comparison.
//! - Every decoder is total and length-capped (4096 bytes for Tier L / Tier X payloads, 8192 for the COSE envelope).
//!
//! Rung: the semantics are DRT-tested against the Lean model (oracles/token-drt); the Lean theorems cover the
//! model, not this code. HMAC-SHA256, HKDF and ML-DSA-65 come from AWS-LC (trusted, not verified).
#![forbid(unsafe_code)]

pub mod caveat;
pub mod cbor;
pub mod tier0;
pub mod tier_l;
pub mod tier_x;

#[cfg(test)]
mod tests;

pub use caveat::{
    ArgPred, ArgVal, Caveat, Req, args_ok, denote, depth_ok, eff_depth, eff_exp, mint_shape_ok, path_segments, sat,
};
pub use tier_l::{KeyRing, MintParams, TokenL, attenuate, chain_tag, mac_valid, mint, verify, verify_decoded};
pub use tier_x::{XKeyRing, XPayload, verify_x};
pub use tier0::{Handle, Tier0Table};

/// Issuer / holder side failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenError {
    /// A field breaks an F5 shape or range limit.
    Invalid,
    /// The encoding would exceed 4096 bytes.
    TooLarge,
    /// exp is not in (mint_time, mint_time + 900].
    Ttl,
    UnknownKey,
    Crypto,
}

/// Verifier failure. Every variant is a denial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    Malformed,
    /// MAC or signature mismatch, or unknown key / handle.
    BadTag,
    /// The first caveats are not [aud, exp, depth_left].
    BadShape,
    /// More caveats than 3 + the effective depth (D3), or no depth caveat.
    DepthExceeded,
    /// Some caveat is not satisfied by the request.
    Denied,
    /// The request tenant or subject cannot form a `Principal`.
    BadPrincipal,
}
