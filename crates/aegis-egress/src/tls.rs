//! The egress rustls CLIENT (feature `tls-client`; compiled out of the cmvp build, spikes/cmvp-client-policy
//! mode A). Floor profile, PQ-preferring: TLS 1.3 only, key exchange `[X25519MLKEM768, SecP256r1MLKEM768, X25519,
//! secp256r1]` (hybrid first), no session resumption and no early data (so no RUSTSEC-2026-0349 ticket/key-share
//! prediction state is ever kept), ALPN `http/1.1`. Trust anchors are supplied by the caller.
//!
//! [`TlsClient::new`] is the only place this workspace crate builds a `rustls::ClientConfig`; the built config is
//! re-read by [`assert_client_profile`] before use.

use std::string::ToString;
use std::sync::Arc;
use std::vec::Vec;

use rustls::client::Resumption;
use rustls::crypto::{CryptoProvider, aws_lc_rs as prov};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ProtocolVersion, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::error::EgressError;
use crate::url::Host;

/// The client key-exchange preference list (TLS Supported Groups codepoints), hybrid PQ first.
pub const CLIENT_KX: &[u16] = &[0x11EC, 0x11EB, 0x001D, 0x0017];

/// A built, asserted client profile.
#[derive(Clone, Debug)]
pub struct TlsClient {
    cfg: Arc<ClientConfig>,
}

impl TlsClient {
    /// Build the PQ-preferring floor client profile with the caller's trust anchors.
    pub fn new(roots: RootCertStore) -> Result<Self, EgressError> {
        use prov::kx_group as g;
        let base = prov::default_provider();
        let provider = CryptoProvider {
            kx_groups: Vec::from([g::X25519MLKEM768, g::SECP256R1MLKEM768, g::X25519, g::SECP256R1]),
            cipher_suites: base
                .cipher_suites
                .iter()
                .copied()
                .filter(|s| s.version().version == ProtocolVersion::TLSv1_3)
                .collect(),
            ..base
        };
        let mut cfg = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| EgressError::Tls(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.resumption = Resumption::disabled();
        cfg.enable_early_data = false;
        cfg.alpn_protocols = Vec::from([b"http/1.1".to_vec()]);
        assert_client_profile(&cfg)?;
        Ok(Self { cfg: Arc::new(cfg) })
    }

    /// The built config (read-only).
    pub fn config(&self) -> &ClientConfig {
        &self.cfg
    }

    /// Handshake over an already-connected (vetted) TCP stream; SNI and certificate name are the URL's original host.
    pub async fn connect(&self, host: &Host, tcp: TcpStream) -> Result<TlsStream<TcpStream>, EgressError> {
        let name: ServerName<'static> = match host {
            Host::Name(n) => ServerName::try_from(n.clone()).map_err(|e| EgressError::Tls(e.to_string()))?,
            Host::V4(a) => ServerName::IpAddress(std::net::IpAddr::V4(*a).into()),
            Host::V6(a) => ServerName::IpAddress(std::net::IpAddr::V6(*a).into()),
        };
        TlsConnector::from(self.cfg.clone()).connect(name, tcp).await.map_err(|e| EgressError::Tls(e.to_string()))
    }
}

/// Startup assertion: kx list exactly [`CLIENT_KX`] in order, TLS 1.3 only, resumption disabled, no early data.
pub fn assert_client_profile(cfg: &ClientConfig) -> Result<(), EgressError> {
    let kx: Vec<u16> = cfg.crypto_provider().kx_groups.iter().map(|g| u16::from(g.name())).collect();
    if kx != CLIENT_KX {
        return Err(EgressError::Tls(format!("client kx {kx:04x?} != profile {CLIENT_KX:04x?}")));
    }
    if cfg.crypto_provider().cipher_suites.iter().any(|s| s.version().version != ProtocolVersion::TLSv1_3) {
        return Err(EgressError::Tls("non-TLS1.3 suite in client profile".to_string()));
    }
    if cfg.enable_early_data {
        return Err(EgressError::Tls("early data enabled".to_string()));
    }
    let r = format!("{:?}", cfg.resumption);
    if !r.contains("NoClientSessionStorage") || !r.contains("Disabled") {
        return Err(EgressError::Tls(format!("resumption not disabled: {r}")));
    }
    Ok(())
}
