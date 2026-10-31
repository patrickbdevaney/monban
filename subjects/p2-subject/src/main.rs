//! p2-subject: the P2 isolation code of aegis-iso over the oracles' subject protocols.
//!
//! Usage:
//!   `p2-subject probe --path forkwasm|cordon [--stage zygote] --probe <name> --allow-dir <dir> [--target <path>]
//!   [--fd <n>] [--port <p>]`: the syscall-negative probe protocol (`oracles/syscall-negative/README.md`), run on
//!   the real `aegis_iso::sandbox::install` profiles (zygote, fork child, cordon).
//!
//! `serve forkwasm|cordon` arrives with P5-iso-002/003; until then it fails closed (exit 78).
#![forbid(unsafe_code)]

use std::process::ExitCode;

/// EX_CONFIG: the fail-closed exit code used across AEGIS.
const EX_CONFIG: u8 = 78;
/// EX_USAGE.
const EX_USAGE: u8 = 64;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.split_first() {
        Some((cmd, rest)) if cmd == "probe" => ExitCode::from(aegis_iso::sandbox::probe::run(rest)),
        Some((cmd, _)) if cmd == "serve" => {
            eprintln!("p2-subject: serve is not implemented yet (P5-iso-002/003); fail closed");
            ExitCode::from(EX_CONFIG)
        }
        _ => {
            eprintln!(
                "usage: p2-subject probe --path forkwasm|cordon [--stage zygote] --probe <name> --allow-dir <dir> ..."
            );
            ExitCode::from(EX_USAGE)
        }
    }
}
