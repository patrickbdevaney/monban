//! `monban-p2 config --json [--mpk]` and `monban-p2 compile` (unit P5-wasm-001). main.rs (P5-iso-002) wires this
//! module in: `mod config;` and, first in `main`, `if let Some(code) = config::dispatch(&args) { return code; }`
//! with `args` = the arguments after argv[0].
//!
//! `config --json` builds the engine from the built-in F8 defaults (no config file) and prints the settings value
//! that engine was built from (`P2Engine::settings`), never a separate literal (supply-chain/wasmtime-config.toml
//! `[effective]`; `--mpk` gives `[effective]` + `[effective_mpk]`). Building the engine first means a configuration
//! wasmtime refuses exits non-zero instead of printing. Exception: `--mpk` on a host where wasmtime cannot enable
//! MPK (it does so on Intel x86_64 only, so not on the AMD desktop): the Config is made from the settings, the
//! Engine is not built, a note goes to stderr and the settings are printed (a worker with `p2.mpk = true` refuses
//! to boot on such a host, because `Mpk::Yes` never falls back to off).
//!
//! `compile --in <module.wasm> --out <file.cwasm> [--mpk] [--memory-mib N] [--pool-slots N]` validates the module
//! against the engine and the F14 shape and writes the serialized `.cwasm` (mode 0600, written to a temporary name
//! and renamed). It prints nothing: the supervisor computes the digest itself over the file. It runs sandboxed
//! (PLAN-5 D4: the P5-iso-001 cordon profile without the network), installed by the caller before `dispatch`; as a
//! fail-closed backstop it refuses to run unless `/proc/self/status` shows `NoNewPrivs: 1` and `Seccomp: 2`.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::ExitCode;

use monban_wasm::engine::cwasm;
use monban_wasm::{EngineSettings, P2Engine};

/// EX_USAGE.
const EX_USAGE: u8 = 64;
/// EX_DATAERR: the module was refused.
const EX_DATAERR: u8 = 65;
/// EX_IOERR.
const EX_IOERR: u8 = 74;
/// EX_CONFIG: the engine could not be built, or compile ran unsandboxed.
const EX_CONFIG: u8 = 78;

/// Runs `config` or `compile` when `args[0]` names one; `None` for any other subcommand.
pub fn dispatch(args: &[String]) -> Option<ExitCode> {
    let (cmd, rest) = args.split_first()?;
    match cmd.as_str() {
        "config" => Some(config(rest)),
        "compile" => Some(compile(rest)),
        _ => None,
    }
}

fn fail(code: u8, msg: &str) -> ExitCode {
    eprintln!("monban-p2: {msg}");
    ExitCode::from(code)
}

fn config(args: &[String]) -> ExitCode {
    let mut json = false;
    let mut mpk = false;
    for a in args {
        match a.as_str() {
            "--json" if !json => json = true,
            "--mpk" if !mpk => mpk = true,
            other => {
                return fail(
                    EX_USAGE,
                    &format!("config: unexpected argument {other:?} (usage: config --json [--mpk])"),
                );
            }
        }
    }
    if !json {
        return fail(EX_USAGE, "config: --json is required");
    }
    let settings = EngineSettings::defaults(mpk);
    if mpk && !EngineSettings::host_supports_mpk() {
        // The Engine cannot be built here (wasmtime enables MPK only on Intel x86_64 with PKU); a worker with
        // p2.mpk = true refuses to boot on this host. The settings printed are still the value the Engine is built
        // from wherever it can be, after the wasmtime Config was made from them.
        if let Err(e) = settings.check_config() {
            return fail(EX_CONFIG, &e.to_string());
        }
        eprintln!(
            "monban-p2: note: MPK unavailable on this host; engine not built for --mpk (the worker refuses p2.mpk here)"
        );
        println!("{}", settings.to_json());
        return ExitCode::SUCCESS;
    }
    let engine = match P2Engine::new(settings) {
        Ok(e) => e,
        Err(e) => return fail(EX_CONFIG, &e.to_string()),
    };
    println!("{}", engine.settings().to_json());
    ExitCode::SUCCESS
}

#[derive(Debug, Default)]
struct CompileArgs {
    input: Option<String>,
    output: Option<String>,
    mpk: bool,
    memory_mib: Option<u32>,
    pool_slots: Option<u32>,
}

fn parse_compile(args: &[String]) -> Result<CompileArgs, String> {
    let mut c = CompileArgs::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--in" if c.input.is_none() => c.input = Some(val()?),
            "--out" if c.output.is_none() => c.output = Some(val()?),
            "--mpk" if !c.mpk => c.mpk = true,
            "--memory-mib" if c.memory_mib.is_none() => {
                c.memory_mib = Some(val()?.parse().map_err(|_| "--memory-mib: not a number".to_string())?);
            }
            "--pool-slots" if c.pool_slots.is_none() => {
                c.pool_slots = Some(val()?.parse().map_err(|_| "--pool-slots: not a number".to_string())?);
            }
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    Ok(c)
}

/// The compile sandbox backstop: no-new-privs set and a seccomp filter installed (mode 2).
fn sandboxed() -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    let field = |k: &str| status.lines().find_map(|l| l.strip_prefix(k).map(str::trim));
    field("NoNewPrivs:") == Some("1") && field("Seccomp:") == Some("2")
}

fn write_atomic(out: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let name = out.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = out.with_file_name(format!(".{name}.tmp.{}", std::process::id()));
    let res = (|| {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, out)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

fn compile(args: &[String]) -> ExitCode {
    let a = match parse_compile(args) {
        Ok(a) => a,
        Err(m) => return fail(EX_USAGE, &format!("compile: {m} (usage: compile --in M.wasm --out M.cwasm [--mpk])")),
    };
    let (Some(input), Some(output)) = (a.input.as_deref(), a.output.as_deref()) else {
        return fail(EX_USAGE, "compile: --in and --out are required");
    };
    if !sandboxed() {
        return fail(EX_CONFIG, "compile: refusing to run outside the compile sandbox (NoNewPrivs/Seccomp not set)");
    }
    let defaults = EngineSettings::defaults(a.mpk);
    let settings = match EngineSettings::from_p2(
        a.memory_mib.unwrap_or_else(|| {
            u32::try_from(defaults.pooling_max_memory_size() >> 20).unwrap_or(monban_wasm::engine::MEMORY_MIB_DEFAULT)
        }),
        a.pool_slots.unwrap_or_else(|| defaults.pool_slots()),
        a.mpk,
    ) {
        Ok(s) => s,
        Err(e) => return fail(EX_CONFIG, &e.to_string()),
    };
    let engine = match P2Engine::new(settings) {
        Ok(e) => e,
        Err(e) => return fail(EX_CONFIG, &e.to_string()),
    };
    let wasm = match std::fs::read(input) {
        Ok(b) => b,
        Err(e) => return fail(EX_IOERR, &format!("compile: read {input}: {e}")),
    };
    let bytes = match cwasm::compile(&engine, &wasm) {
        Ok(b) => b,
        Err(e) => return fail(EX_DATAERR, &format!("compile: {e}")),
    };
    match write_atomic(Path::new(output), &bytes) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(EX_IOERR, &format!("compile: write {output}: {e}")),
    }
}
