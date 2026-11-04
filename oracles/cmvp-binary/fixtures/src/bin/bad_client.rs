//! Negative: rustls default client (classical groups listed, default in-memory session store).
use std::sync::Arc;

fn main() -> Result<(), cmvp_fixtures::BoxErr> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls::pki_types::pem::PemObject::pem_slice_iter(cmvp_fixtures::CA) {
        roots.add(c?)?;
    }
    let cfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    if std::env::args().any(|a| a == "--probe") {
        println!("{}", cmvp_fixtures::probe::probe(Arc::new(cfg))?);
        return Ok(());
    }
    cmvp_fixtures::server_main()
}
