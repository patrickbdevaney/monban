//! P2 worker binary (PLAN-5 D3, DEVIATIONS X-13): exec-spawned zygote (fork+Wasm), per-principal cordon and the
//! sandboxed module compile. The only binary that links wasmtime (through aegis-wasm).
//!
//! `config --json [--mpk]` and `compile` are wired (P5-wasm-001). Every other invocation fails closed with exit 78
//! (EX_CONFIG) until its subcommand lands (zygote and cordon: P5-iso-002/003; probe: P5-iso-001, `test-hooks`).
#![forbid(unsafe_code)]

mod config;

use std::process::ExitCode;

/// EX_CONFIG (sysexits.h): the fail-closed boot exit code used across AEGIS.
const EX_CONFIG: u8 = 78;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(code) = config::dispatch(&args) {
        return code;
    }
    eprintln!("aegis-p2: not implemented (fail closed)");
    ExitCode::from(EX_CONFIG)
}
