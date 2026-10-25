//! Negative: rustls default client (classical groups listed, default in-memory session store).
use std::sync::Arc;

fn main() -> Result<(), tlsbins::BoxErr> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls::pki_types::pem::PemObject::pem_slice_iter(tlsbins::CA) {
        roots.add(c?)?;
    }
    let cfg = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    if std::env::args().any(|a| a == "--probe") {
        println!("{}", tlsbins::probe::probe(Arc::new(cfg))?);
        return Ok(());
    }
    tlsbins::server_main()
}
