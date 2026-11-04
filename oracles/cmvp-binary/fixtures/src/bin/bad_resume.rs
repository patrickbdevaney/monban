//! Negative: PQ-only groups, but the default session store (resumption + kx_hint) left in place.
use rustls::crypto::aws_lc_rs::kx_group;
use std::sync::Arc;

fn main() -> Result<(), cmvp_fixtures::BoxErr> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls::pki_types::pem::PemObject::pem_slice_iter(cmvp_fixtures::CA) {
        roots.add(c?)?;
    }
    let cfg = rustls::ClientConfig::builder_with_provider(cmvp_fixtures::provider_with(&[kx_group::SECP256R1MLKEM768]))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    if std::env::args().any(|a| a == "--probe") {
        println!("{}", cmvp_fixtures::probe::probe(Arc::new(cfg))?);
        return Ok(());
    }
    cmvp_fixtures::server_main()
}
