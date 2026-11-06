//! mariadb-subject: drives `aegis-adapter-mysql` for oracles/lowering-read, lowering-write and schema-gate
//! (`--engine mariadb`).
//!
//! P7-spec-002 stub: every mode refuses (exit 2, message on stderr) and nothing is written to stdout, so an oracle run
//! against it fails instead of scoring a guessed answer. P7-adapter-mysql-001 lands the `lowering` and `schema` modes.
#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let why = aegis_adapter_mysql::MysqlError::Unimplemented;
    let _ = writeln!(std::io::stderr(), "mariadb-subject: mode {mode:?} refused: {why} (P7-adapter-mysql-001)");
    ExitCode::from(2)
}
