//! The egress rustls CLIENT handshake (feature `tls-client`; compiled out of the cmvp build,
//! spikes/cmvp-client-policy mode A).
//!
//! This crate builds no `rustls::ClientConfig`. The profile (key exchange list, versions, resumption, early data,
//! ALPN, trust anchors) is built and asserted by aegis-tls (`aegis_tls::client_config`, feature `tls-client`) and
//! injected by the assembly layer through [`TlsClient::from_config`]. As a fail-closed backstop, `from_config`
//! re-checks the invariants egress itself depends on: TLS 1.3 only, resumption disabled, early data off
//! (RUSTSEC-2026-0349: no ticket or key-share-prediction state is ever kept) and ALPN exactly `http/1.1` (the
//! exchange is hand-written HTTP/1.1). The key-exchange list is aegis-tls's to assert, per profile.

use std::string::ToString;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ProtocolVersion};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::error::EgressError;
use crate::url::Host;

/// An injected, re-checked client config.
#[derive(Clone, Debug)]
pub struct TlsClient {
    cfg: Arc<ClientConfig>,
}

impl TlsClient {
    /// Take an already-built client config (from `aegis_tls::client_config`). Refuses a config that is not TLS 1.3
    /// only, keeps resumption state, enables early data, or does not offer exactly ALPN `http/1.1`.
    pub fn from_config(cfg: Arc<ClientConfig>) -> Result<Self, EgressError> {
        check_client_invariants(&cfg)?;
        Ok(Self { cfg })
    }

    /// The injected config (read-only).
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
        let s = TlsConnector::from(self.cfg.clone())
            .connect(name, tcp)
            .await
            .map_err(|e| EgressError::Tls(e.to_string()))?;
        check_session(s.get_ref().1)?;
        Ok(s)
    }
}

/// Fail-closed backstop on the established session (P8-hardening-001, gate egress-tls-e2e): TLS 1.3 was negotiated
/// and the server either selected no ALPN or `http/1.1` (rustls already refuses a protocol the client did not offer;
/// this re-reads the outcome instead of trusting the configuration alone).
pub fn check_session(c: &rustls::ClientConnection) -> Result<(), EgressError> {
    if c.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
        return Err(EgressError::Tls(format!("negotiated {:?}, not TLS 1.3", c.protocol_version())));
    }
    if c.alpn_protocol().is_some_and(|p| p != b"http/1.1") {
        return Err(EgressError::Tls("server selected an ALPN protocol other than http/1.1".to_string()));
    }
    Ok(())
}

/// The invariants egress depends on, re-read from the injected config: only TLS 1.3 suites, early data off,
/// resumption disabled (no session storage and no TLS 1.2 resumption, read from `Resumption`'s Debug form since
/// rustls exposes no accessor), ALPN exactly `[http/1.1]`.
pub fn check_client_invariants(cfg: &ClientConfig) -> Result<(), EgressError> {
    let suites = &cfg.crypto_provider().cipher_suites;
    if suites.is_empty() || suites.iter().any(|s| s.version().version != ProtocolVersion::TLSv1_3) {
        return Err(EgressError::Tls("injected client config is not TLS 1.3 only".to_string()));
    }
    if cfg.enable_early_data {
        return Err(EgressError::Tls("injected client config enables early data".to_string()));
    }
    let r = format!("{:?}", cfg.resumption);
    if !r.contains("NoClientSessionStorage") || !r.contains("Disabled") {
        return Err(EgressError::Tls(format!("injected client config keeps resumption state: {r}")));
    }
    if cfg.alpn_protocols.len() != 1 || cfg.alpn_protocols.first().map(Vec::as_slice) != Some(b"http/1.1".as_slice()) {
        return Err(EgressError::Tls(format!("injected client config ALPN {:?} != [http/1.1]", cfg.alpn_protocols)));
    }
    Ok(())
}
