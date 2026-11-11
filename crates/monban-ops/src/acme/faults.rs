//! Deliberate ACME faults for oracles/acme-pebble `--self-test` (feature `test-faults` only; PREFLIGHT R11).
//!
//! This module is compiled only with monban-ops feature `test-faults`, which only subjects/acme-subject enables. No
//! release graph of monban-bin (default, native, every shipped feature, cmvp) turns it on: gate no-test-faults.

use super::AcmeConfig;

/// Deliberate faults, used only by oracles/acme-pebble `--self-test` to show the CA and the client catch them.
/// All off by default.
#[derive(Clone, Copy, Debug, Default)]
pub struct Faults {
    /// Sign every JWS with a key other than the one the header names.
    pub wrong_jws_key: bool,
    /// Reuse an already-consumed nonce once (expect `badNonce` and a successful retry).
    pub replay_nonce: bool,
    /// Finalize with a CSR for a different name than the order's identifiers (expect rejection).
    pub csr_wrong_identifier: bool,
}

/// Sign with a key other than the one the JWS header names.
pub(super) fn wrong_jws_key(cfg: &AcmeConfig) -> bool {
    cfg.faults.wrong_jws_key
}

/// Reuse one consumed nonce.
pub(super) fn replay_nonce(cfg: &AcmeConfig) -> bool {
    cfg.faults.replay_nonce
}

/// Finalize with a CSR for other names than the order's.
pub(super) fn csr_wrong_identifier(cfg: &AcmeConfig) -> bool {
    cfg.faults.csr_wrong_identifier
}
