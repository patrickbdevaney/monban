//! D13 negative: no rustls client, but the listener verifies client certificate chains (WebPkiClientVerifier).
use std::io::Read;
use std::sync::Arc;

use rustls::crypto::aws_lc_rs::kx_group;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;

static LEAF: &[u8] = include_bytes!("../../certs/leaf.pem");
static LEAF_KEY: &[u8] = include_bytes!("../../certs/leaf.key");

fn main() -> Result<(), cmvp_fixtures::BoxErr> {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(cmvp_fixtures::CA) {
        roots.add(c?)?;
    }
    let provider = cmvp_fixtures::provider_with(&[kx_group::SECP256R1MLKEM768, kx_group::SECP256R1]);
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build()?;
    let certs = CertificateDer::pem_slice_iter(LEAF).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(LEAF_KEY)?;
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    let mut conn = rustls::ServerConnection::new(Arc::new(cfg))?;
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    let mut rd = &input[..];
    while !rd.is_empty() {
        conn.read_tls(&mut rd)?;
        conn.process_new_packets()?;
    }
    cmvp_fixtures::server_main()
}
