//! P2 worker binary (PLAN-5 D3, DEVIATIONS X-13): exec-spawned zygote (fork+Wasm), per-principal cordon and the
//! sandboxed module compile. The only binary that links wasmtime (through aegis-wasm).
//!
//! Skeleton (P5-spec-002): every invocation fails closed with exit 78 (EX_CONFIG) until the subcommands land
//! (zygote and cordon: P5-iso-002/003; compile and `config --json`: P5-wasm-001; probe: P5-iso-001, `test-hooks`).
#![forbid(unsafe_code)]

use std::process::ExitCode;

/// EX_CONFIG (sysexits.h): the fail-closed boot exit code used across AEGIS.
const EX_CONFIG: u8 = 78;

fn main() -> ExitCode {
    eprintln!("aegis-p2: not implemented (fail closed)");
    ExitCode::from(EX_CONFIG)
}
