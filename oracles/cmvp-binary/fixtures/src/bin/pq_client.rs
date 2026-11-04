//! cmvp shape "pq-only": the only client comes from the blessed constructor.
fn main() -> Result<(), cmvp_fixtures::BoxErr> {
    let client = cmvp_fixtures::pqclient::pq_only_client_config()?; // startup assertion runs inside
    if std::env::args().any(|a| a == "--probe") {
        println!("{}", cmvp_fixtures::probe::probe(client.get())?);
        return Ok(());
    }
    cmvp_fixtures::server_main()
}
