//! Negative: PQ-only groups, but the default session store (resumption + kx_hint) left in place.
use rustls::crypto::aws_lc_rs::kx_group;
use std::sync::Arc;

fn main() -> Result<(), tlsbins::BoxErr> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls::pki_types::pem::PemObject::pem_slice_iter(tlsbins::CA) {
        roots.add(c?)?;
    }
    let cfg = rustls::ClientConfig::builder_with_provider(tlsbins::provider_with(&[kx_group::SECP256R1MLKEM768]))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    if std::env::args().any(|a| a == "--probe") {
        println!("{}", tlsbins::probe::probe(Arc::new(cfg))?);
        return Ok(());
    }
    tlsbins::server_main()
}
