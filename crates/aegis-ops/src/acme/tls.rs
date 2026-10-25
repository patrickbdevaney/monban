//! The ACME client's rustls `ClientConfig`: the only `ClientConfig` aegis-ops builds, and only with feature
//! `acme` (spikes/cmvp-client-policy: in the cmvp profile this feature is off, so no client code is linked).
//!
//! Floor profile, PQ-preferring: TLS 1.3 only; key exchange = the P-PUBLIC-WEB group list from aegis-tls
//! (X25519MLKEM768, SecP256r1MLKEM768, then X25519 / P-256 for CAs that are not PQ yet); resumption disabled
//! (no session store, no TLS 1.2 tickets) and no early data, which is the configuration RUSTSEC-2026-0349 does not
//! affect; server certificates verified with webpki against the roots supplied by configuration only (no
//! built-in or platform roots). For Pebble the configured root is its test CA (`pebble.minica.pem`).

use std::sync::Arc;
use std::vec::Vec;

use aegis_tls::Profile;
use aegis_tls::profile::{group, kx_group};
use rustls::client::Resumption;
use rustls::crypto::{CryptoProvider, aws_lc_rs as prov};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, ProtocolVersion, RootCertStore};

use super::AcmeError;

/// Build the ACME client config. `roots` must be non-empty (fail closed: no implicit trust).
pub fn client_config(roots: &[CertificateDer<'static>]) -> Result<Arc<ClientConfig>, AcmeError> {
    if roots.is_empty() {
        return Err(AcmeError::Tls("no trust anchors configured".into()));
    }
    let mut store = RootCertStore::empty();
    for r in roots {
        store.add(r.clone()).map_err(|e| AcmeError::Tls(std::format!("bad trust anchor: {e}")))?;
    }
    let kx_groups = Profile::PublicWeb
        .kx_groups()
        .iter()
        .map(|c| kx_group(*c).ok_or(AcmeError::Tls(std::format!("no group 0x{c:04x}"))))
        .collect::<Result<Vec<_>, _>>()?;
    let base = prov::default_provider();
    let cipher_suites =
        base.cipher_suites.iter().copied().filter(|s| s.version().version == ProtocolVersion::TLSv1_3).collect();
    let provider = Arc::new(CryptoProvider { kx_groups, cipher_suites, ..base });
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| AcmeError::Tls(e.to_string()))?
        .with_root_certificates(store)
        .with_no_client_auth();
    cfg.resumption = Resumption::disabled();
    cfg.enable_early_data = false;
    cfg.alpn_protocols = std::vec![b"http/1.1".to_vec()];
    assert_client_floor(&cfg)?;
    Ok(Arc::new(cfg))
}

/// Startup assertion on the built config: PQ hybrid first, TLS 1.3 only, no early data.
pub fn assert_client_floor(cfg: &ClientConfig) -> Result<(), AcmeError> {
    let groups: Vec<u16> = cfg.crypto_provider().kx_groups.iter().map(|g| u16::from(g.name())).collect();
    if groups.first() != Some(&group::X25519MLKEM768) || groups != Profile::PublicWeb.kx_groups() {
        return Err(AcmeError::Tls(std::format!("client kx groups {groups:04x?} are not the floor list")));
    }
    if cfg.crypto_provider().cipher_suites.iter().any(|s| s.version().version != ProtocolVersion::TLSv1_3) {
        return Err(AcmeError::Tls("client allows a version other than TLS 1.3".into()));
    }
    if cfg.enable_early_data {
        return Err(AcmeError::Tls("client early data enabled".into()));
    }
    Ok(())
}
