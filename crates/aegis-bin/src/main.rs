//! AEGIS assembly binary: reverse-proxy mode "R" (IMPLEMENTATION_PLAN Phase 2).
//!
//! * `aegis` with no arguments, or with a config that does not validate: fail-closed boot, exit 78 (EX_CONFIG)
//!   before any socket is bound (INV-NONEMPTY: there is no implicit "serve everything" mode).
//! * `aegis check-config <path> [--print-effective]`: CFG-1/2 validation plus the assembly's own checks.
//! * `aegis --config <path> ...`: serve (see [`serve`]).
//! * `aegis agent --config <agent.json>`: the MCP listener gate (see [`agent`]; Phase 3, gateway mode "G").
//!
//! Modules: [`plan`] (config → listeners / routes), [`proxy`] (the `aegis_transport::App` that forwards: CANON-4;
//! inbound h1 and h2 are served by `aegis_transport::Server` with the AEGIS wrapper), [`upstream`] (pool keyed by the whole upstream config + epoch, H1/H2
//! clients), [`admin`] (metrics, healthz), [`audit`] (F9 admin events), [`tls`] (cert stores, profiles),
//! [`serve`] (boot, signals, reload, upgrade), [`native`] (modes A/D: `app:<name>` routes served by linked apps over
//! the golden SQLite/PG data plane, Tier-L tokens, idempotency, NC1/NC2/NC7/NC8).
#![forbid(unsafe_code)]

mod admin;
mod agent;
mod audit;
mod cli;
mod native;
mod plan;
mod proxy;
mod serve;
mod shared;
mod tls;
mod upstream;
mod util;

use std::process::ExitCode;

const EX_USAGE: u8 = 64;

fn check_config(path: &std::path::Path, print_effective: bool) -> ExitCode {
    let bytes = match serve::read_config(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("aegis: check-config: {e}");
            return ExitCode::from(serve::EX_CONFIG);
        }
    };
    let cfg = match aegis_config::parse_config(&bytes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("aegis: check-config {}: {e}", path.display());
            return ExitCode::from(serve::EX_CONFIG);
        }
    };
    let p = match plan::plan(&cfg) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("aegis: check-config {}: {e}", path.display());
            return ExitCode::from(serve::EX_CONFIG);
        }
    };
    for w in &p.warnings {
        eprintln!("aegis: check-config: warning: {w}");
    }
    if print_effective {
        println!("{}", String::from_utf8_lossy(cfg.effective_json()));
    }
    eprintln!("aegis: check-config {}: OK (config hash {})", path.display(), cfg.config_hash_hex());
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if let Some(("agent", rest)) = args.split_first().and_then(|(a, r)| a.to_str().map(|a| (a, r))) {
        return agent::run(rest);
    }
    match cli::parse(&args) {
        Ok(cli::Cmd::Bare) => {
            eprintln!("aegis: no validated configuration; refusing to serve (fail-closed boot)");
            ExitCode::from(serve::EX_CONFIG)
        }
        Ok(cli::Cmd::Help) => {
            println!("{}", cli::USAGE);
            ExitCode::SUCCESS
        }
        Ok(cli::Cmd::Check { path, print_effective }) => check_config(&path, print_effective),
        Ok(cli::Cmd::Serve(opts)) => serve::run(opts),
        Err(cli::UsageError(e)) => {
            eprintln!("aegis: {e}\n{}", cli::USAGE);
            ExitCode::from(EX_USAGE)
        }
    }
}
