//! Client construction present in source and crate graph (feature tls-client on) but never called from main.
use std::sync::Arc;

#[allow(dead_code)]
fn never_called() -> Result<rustls::ClientConnection, tlsbins::BoxErr> {
    let cfg = rustls::ClientConfig::builder().with_root_certificates(rustls::RootCertStore::empty()).with_no_client_auth();
    Ok(rustls::ClientConnection::new(Arc::new(cfg), "localhost".try_into()?)?)
}

fn main() -> Result<(), tlsbins::BoxErr> {
    tlsbins::server_main()
}
