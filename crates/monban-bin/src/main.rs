//! Monban assembly binary: reverse-proxy mode "R" (IMPLEMENTATION_PLAN Phase 2).
//!
//! * `monban` with no arguments, or with a config that does not validate: fail-closed boot, exit 78 (EX_CONFIG)
//!   before any socket is bound (INV-NONEMPTY: there is no implicit "serve everything" mode).
//! * `monban check-config <path> [--print-effective]`: CFG-1/2 validation plus the assembly's own checks. The dump
//!   is `Config::effective_dump`: the effective config plus `p2.isolation_effective` / `p2.usable_cpus` ([`cpus`]).
//! * `monban --config <path> ...`: serve (see [`serve`]). Phase 7, each behind its own feature and refused at boot
//!   (exit 78) by a build without it: PROXY v2 and L4 SNI passthrough (`front`, features `proxy-protocol` / `l4`),
//!   the MTC credential selector (feature `mtc`), `--front uring` / `listeners[].front` (feature `uring`), the
//!   crdb / mariadb adapter families (`native::adapters`). F8 `admission` sets the admission numbers
//!   ([`shared::admission_config`]; absent = the pre-Phase-7 constants).
//! * `monban agent --config <agent.json>`: the MCP listener gate (see [`agent`]; Phase 3, gateway mode "G").
//! * `monban --fips-check`: one line, `FIPS-CHECK: module="<linked module version string>" fips_mode=<bool>
//!   config_fips=<bool>` (or `module=none`), exit 0 (PLAN-6 D2, oracles/cmvp-binary F4 contract). `module` is the
//!   linked module's runtime `awslc_version_string` (monban-iso, D16), `fips_mode` is `try_fips_mode().is_ok()`,
//!   `config_fips` is the FIPS-CMVP config's `fips()` (false when P-PQ5 refuses it). The floor build prints
//!   `FIPS-CHECK: module=none fips_mode=false config_fips=false`.
//!
//! Modules: [`plan`] (config → listeners / routes), [`proxy`] (the `monban_transport::App` that forwards: CANON-4;
//! inbound h1 and h2 are served by `monban_transport::Server` with the Monban wrapper), [`upstream`] (pool keyed by the whole upstream config + epoch, H1/H2
//! clients), [`admin`] (metrics, healthz), [`audit`] (F9 admin events), [`tls`] (cert stores, profiles),
//! [`serve`] (boot, signals, reload, upgrade), [`native`] (modes A/D: `app:<name>` routes served by linked apps over
//! the golden SQLite/PG data plane, Tier-L tokens, idempotency, NC1/NC2/NC7/NC8), [`p2`] (feature `p2`, Phase 5:
//! `{"wasm": <module-id>}` routes served by exec-spawned monban-p2 workers; the F14 decoder, crash budget, cordons).
#![forbid(unsafe_code)]

mod admin;
mod agent;
mod audit;
mod cli;
mod cpus;
#[cfg(any(feature = "proxy-protocol", feature = "l4", all(feature = "mtc", not(feature = "cmvp"))))]
mod front;
#[cfg(any(feature = "native", feature = "p2"))]
mod keyring;
#[cfg(feature = "native")]
mod native;
#[cfg(not(feature = "native"))]
#[path = "native_stub.rs"]
mod native;
#[cfg(feature = "p2")]
mod p2;
#[cfg(not(feature = "p2"))]
#[path = "p2_stub.rs"]
mod p2;
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
            eprintln!("monban: check-config: {e}");
            return ExitCode::from(serve::EX_CONFIG);
        }
    };
    let cfg = match monban_config::parse_config(&bytes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("monban: check-config {}: {e}", path.display());
            return ExitCode::from(serve::EX_CONFIG);
        }
    };
    let p = match plan::plan(&cfg) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("monban: check-config {}: {e}", path.display());
            return ExitCode::from(serve::EX_CONFIG);
        }
    };
    for w in &p.warnings {
        eprintln!("monban: check-config: warning: {w}");
    }
    if print_effective {
        // The effective config plus the host-resolved P2 path (p2.isolation_effective, p2.usable_cpus; D23(b)).
        println!("{}", String::from_utf8_lossy(&cfg.effective_dump(cpus::usable())));
    }
    eprintln!("monban: check-config {}: OK (config hash {})", path.display(), cfg.config_hash_hex());
    ExitCode::SUCCESS
}

/// `monban --fips-check` (PLAN-6 D2; oracles/cmvp-binary F4 contract): the module identity as the linked module
/// reports it, the module's FIPS mode and the FIPS-CMVP config's `fips()`, no listener, config or certificate
/// needed. Always exit 0: the line is the report, judged by the oracle (cmvp line, or the floor line for the
/// `--expect floor` negative control).
fn fips_check() -> ExitCode {
    let st = monban_tls::fips_check_with(tls::linked_module());
    let module = match st.module {
        Some(m) => format!("{m:?}"),
        None => "none".to_string(),
    };
    println!("FIPS-CHECK: module={module} fips_mode={} config_fips={}", st.module_fips_mode, st.config_fips);
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args.first().and_then(|a| a.to_str()) == Some("--fips-check") {
        return fips_check();
    }
    if let Some(("agent", rest)) = args.split_first().and_then(|(a, r)| a.to_str().map(|a| (a, r))) {
        return agent::run(rest);
    }
    match cli::parse(&args) {
        Ok(cli::Cmd::Bare) => {
            eprintln!("monban: no validated configuration; refusing to serve (fail-closed boot)");
            ExitCode::from(serve::EX_CONFIG)
        }
        Ok(cli::Cmd::Help) => {
            println!("{}", cli::USAGE);
            ExitCode::SUCCESS
        }
        Ok(cli::Cmd::Check { path, print_effective }) => check_config(&path, print_effective),
        Ok(cli::Cmd::Serve(opts)) => serve::run(opts),
        Err(cli::UsageError(e)) => {
            eprintln!("monban: {e}\n{}", cli::USAGE);
            ExitCode::from(EX_USAGE)
        }
    }
}
