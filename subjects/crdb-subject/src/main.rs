//! crdb-subject: drives `aegis-adapter-pg` with the CockroachDB dialect (feature `crdb`) for oracles/lowering-read,
//! lowering-write and schema-gate (`--engine crdb`).
//!
//! P7-spec-002 stub: every mode refuses (exit 2, message on stderr) and nothing is written to stdout, so an oracle run
//! against it fails instead of scoring a guessed answer. P7-adapter-crdb-001 lands the `lowering` and `schema` modes on
//! `Dialect::Crdb`.
#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

/// Linked so the stub compiles against the adapter it will drive.
use aegis_adapter_pg as _;

fn main() -> ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let _ = writeln!(
        std::io::stderr(),
        "crdb-subject: mode {mode:?} refused: CockroachDB dialect not built (P7-adapter-crdb-001)"
    );
    ExitCode::from(2)
}
