//! P2 worker binary (PLAN-5 D3, DEVIATIONS X-13): exec-spawned zygote (fork+Wasm), per-principal cordon and the
//! sandboxed module compile. The only binary that links wasmtime (through aegis-wasm).
//!
//! Command line (oracles/hostile-modules README; aegis-bin spawns exactly this):
//! - `config --json [--mpk]`: the effective engine configuration (config.rs, P5-wasm-001).
//! - `compile --in <module.wasm> --out <module.cwasm> [--mpk] [--memory-mib N] [--pool-slots N]`: installs the
//!   compile sandbox first (`Profile::compile`: no fork, no network, Landlock read on `--in`, write beneath the
//!   `--out` directory, seccomp, dumpable=0), then runs config.rs's compile. Exit 78 = refused.
//! - `zygote --module <c.cwasm> --sha256 <hex> [...]`: the fork+Wasm zygote (zygote.rs).
//! - `cordon ...`: fails closed (exit 78) until P5-iso-003.
//! - `probe ...` (`test-hooks` only): the syscall-negative probe protocol on the worker's own sandbox profiles.
//!
//! `test-hooks` and `mutants` builds read `AEGIS_P2_TEST_LANDLOCK_ABI=<n>` as the detected Landlock ABI for
//! compile, zygote, cordon and probe, and refuse below 4 with exit 78 (oracles/p2-e2e README, D2 simulation).
//! Golden builds ignore it.
#![forbid(unsafe_code)]

mod config;
mod zygote;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aegis_iso::sandbox::{self, Profile};

/// EX_CONFIG (sysexits.h): the fail-closed boot exit code used across AEGIS.
const EX_CONFIG: u8 = 78;
/// EX_USAGE.
const EX_USAGE: u8 = 64;

fn fail(code: u8, msg: &str) -> ExitCode {
    eprintln!("aegis-p2: {msg}");
    ExitCode::from(code)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((cmd, rest)) = args.split_first() else {
        return fail(EX_USAGE, "usage: aegis-p2 config|compile|zygote|cordon ...");
    };
    if matches!(cmd.as_str(), "compile" | "zygote" | "cordon" | "probe")
        && let Some(code) = landlock_override_refuses()
    {
        return code;
    }
    match cmd.as_str() {
        "compile" => {
            if let Err(e) = install_compile_sandbox(rest) {
                return fail(EX_CONFIG, &format!("compile: {e}"));
            }
            config::dispatch(&args).unwrap_or_else(|| fail(EX_CONFIG, "compile: not dispatched"))
        }
        "zygote" => zygote::run(rest),
        "cordon" => fail(EX_CONFIG, "cordon: not implemented yet (P5-iso-003); fail closed"),
        #[cfg(feature = "test-hooks")]
        "probe" => ExitCode::from(aegis_iso::sandbox::probe::run(rest)),
        _ => match config::dispatch(&args) {
            Some(code) => code,
            None => fail(EX_CONFIG, &format!("unknown subcommand {cmd:?} (fail closed)")),
        },
    }
}

/// D2 simulation for the p2-e2e oracle: `Some(78)` when `AEGIS_P2_TEST_LANDLOCK_ABI` is below 4.
#[cfg(any(feature = "test-hooks", feature = "mutants"))]
fn landlock_override_refuses() -> Option<ExitCode> {
    let v = std::env::var("AEGIS_P2_TEST_LANDLOCK_ABI").ok()?;
    match v.trim().parse::<u32>() {
        Ok(abi) if abi >= aegis_iso::sandbox::landlock::MIN_ABI => None,
        Ok(abi) => Some(fail(
            EX_CONFIG,
            &format!(
                "Landlock ABI {abi} (AEGIS_P2_TEST_LANDLOCK_ABI) < {}; P2 refused (PLAN-5 D2)",
                aegis_iso::sandbox::landlock::MIN_ABI
            ),
        )),
        Err(_) => Some(fail(EX_CONFIG, "AEGIS_P2_TEST_LANDLOCK_ABI is not a number; refused")),
    }
}

/// Golden builds ignore the override.
#[cfg(not(any(feature = "test-hooks", feature = "mutants")))]
fn landlock_override_refuses() -> Option<ExitCode> {
    None
}

/// The value after `flag` in `args`.
fn flag<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            return it.next().map(String::as_str);
        }
    }
    None
}

/// Installs `Profile::compile` for `compile --in I --out O`: Landlock read on I (and on this process's own
/// `/proc/<pid>/status`, which config.rs reads to confirm the sandbox), write beneath O's directory; the
/// cordon seccomp layout plus the atomic-write calls; dumpable=0; NO_NEW_PRIVS. Argument errors are left to
/// config.rs's parser, which runs next and reports them (a missing flag still refuses before any I/O).
fn install_compile_sandbox(args: &[String]) -> Result<(), String> {
    let (Some(input), Some(output)) = (flag(args, "--in"), flag(args, "--out")) else {
        return Err("--in and --out are required".into());
    };
    let input = std::fs::canonicalize(input).map_err(|e| format!("--in {input}: {e}"))?;
    let out_dir = match Path::new(output).parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let out_dir = std::fs::canonicalize(&out_dir).map_err(|e| format!("--out directory {}: {e}", out_dir.display()))?;
    let status = std::fs::canonicalize("/proc/self/status").map_err(|e| format!("/proc/self/status: {e}"))?;
    sandbox::install(&Profile::compile(vec![input, status], out_dir)).map(drop).map_err(|e| e.to_string())
}
