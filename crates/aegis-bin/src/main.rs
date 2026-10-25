//! AEGIS assembly binary. Phase 0: fail-closed default boot. With no validated configuration the process
//! refuses to bind any listener and exits non-zero (INV-NONEMPTY: no implicit "serve everything" mode).
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("aegis: no validated configuration and no implemented listener; refusing to serve (fail-closed boot)");
    ExitCode::from(78) // EX_CONFIG
}
