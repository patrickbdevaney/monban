//! cmvp shape "pq-only": the only client comes from the blessed constructor.
fn main() -> Result<(), tlsbins::BoxErr> {
    let client = tlsbins::pqclient::pq_only_client_config()?; // startup assertion runs inside
    if std::env::args().any(|a| a == "--probe") {
        println!("{}", tlsbins::probe::probe(client.get())?);
        return Ok(());
    }
    tlsbins::server_main()
}
