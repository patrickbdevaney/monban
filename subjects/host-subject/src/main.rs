//! Oracle subject for aegis-adapter-host (never linked into aegis).
//!
//! ```text
//! host-subject sdk-host [--mutate <m>]    oracles/sdk-host protocol (F7b host obligations, X-11 pool)
//! host-subject nonempty [--mutate <m>]    oracles/nonempty-props protocol (INV-NONEMPTY through dispatch)
//! ```
//!
//! Both modes drive production code: `aegis_adapter_host::host::Host` (pool, sessions, streams, jobs) and
//! `aegis_adapter_host::dispatch::prepare` (authorize → check_schema → allowlist → pre-debit → render) with the
//! adapters' real renderers. Mutations are aegis-adapter-host's own `#[doc(hidden)]` self-test switches; an unknown
//! mutation name exits 2.

mod engines;
mod json;
mod nonempty;
// The P4-pg-003 pool behind the dispatch executor seam: the pairing P4-bin-001 lifts into the assembly. No oracle
// mode drives a live PG, so the binary itself does not call it; its unit tests do.
#[cfg_attr(not(test), allow(dead_code))]
mod pg;
mod sdkhost;
mod token;

use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage: host-subject (sdk-host|nonempty) [--mutate <name>]");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mode, mutate) = match args.as_slice() {
        [m] => (m.as_str(), None),
        [m, flag, name] if flag == "--mutate" => (m.as_str(), Some(name.as_str())),
        _ => return usage(),
    };
    let r = match mode {
        "nonempty" => {
            let m = match mutate {
                None => aegis_adapter_host::dispatch::DispatchMutations::NONE,
                Some(n) => match nonempty::mutations(n) {
                    Some(m) => m,
                    None => {
                        eprintln!("host-subject: unknown nonempty mutation {n:?} (known: {:?})", nonempty::MUTATIONS);
                        return ExitCode::from(2);
                    }
                },
            };
            nonempty::serve(m)
        }
        "sdk-host" => {
            let m = match mutate {
                None => sdkhost::Muts::default(),
                Some(n) => match sdkhost::mutations(n) {
                    Some(m) => m,
                    None => {
                        eprintln!("host-subject: unknown sdk-host mutation {n:?} (known: {:?})", sdkhost::MUTATIONS);
                        return ExitCode::from(2);
                    }
                },
            };
            sdkhost::serve(m)
        }
        _ => return usage(),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("host-subject: {e}");
            ExitCode::FAILURE
        }
    }
}
