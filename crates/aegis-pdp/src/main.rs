//! `aegis-pdp`: the out-of-process Cedar PDP.
//!
//! ```text
//! aegis-pdp check --policies P.cedar --schema S.cedarschema
//! aegis-pdp serve --policies P.cedar --schema S.cedarschema (--listen PATH | --stdio)
//! aegis-pdp eval  --policies P.cedar --schema S.cedarschema   < cases.tsv
//! ```
//! `serve --listen` binds a SOCK_SEQPACKET socket at PATH (which must not exist). `serve --stdio` serves the
//! connected SOCK_SEQPACKET socketpair end the host passed as fd 0. Startup refuses (exit 2) on any schema, parse
//! or validation error. `eval` decides lines `principal\taction\tresource\tcontext-json\tentities-json` through
//! Cedar's own JSON parsers (no PDP-1 codec) and prints `ALLOW|DENY|ERROR <cedar detail>` per line; the oracle
//! uses it as the reference answer.
#![forbid(unsafe_code)]

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use aegis_pdp::engine::Engine;
use aegis_pdp::{server, uds, word};

const USAGE: &str = "usage: aegis-pdp (check|serve|eval) --policies FILE --schema FILE [--listen PATH | --stdio]";

struct Args {
    cmd: String,
    policies: PathBuf,
    schema: PathBuf,
    listen: Option<PathBuf>,
    stdio: bool,
}

fn parse() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().ok_or(USAGE)?;
    let (mut policies, mut schema, mut listen, mut stdio) = (None, None, None, false);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--policies" => policies = it.next().map(PathBuf::from),
            "--schema" => schema = it.next().map(PathBuf::from),
            "--listen" => listen = it.next().map(PathBuf::from),
            "--stdio" => stdio = true,
            _ => return Err(format!("unknown argument {a:?}\n{USAGE}")),
        }
    }
    Ok(Args { cmd, policies: policies.ok_or(USAGE)?, schema: schema.ok_or(USAGE)?, listen, stdio })
}

fn load(a: &Args) -> Result<Engine, String> {
    let p = std::fs::read_to_string(&a.policies).map_err(|e| format!("{}: {e}", a.policies.display()))?;
    let s = std::fs::read_to_string(&a.schema).map_err(|e| format!("{}: {e}", a.schema.display()))?;
    let (engine, warnings) = Engine::load(&p, &s)?;
    for w in warnings {
        eprintln!("aegis-pdp: {w}");
    }
    Ok(engine)
}

fn main() -> ExitCode {
    let args = match parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let engine = match load(&args) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("aegis-pdp: refusing to start: {e}");
            return ExitCode::from(2);
        }
    };
    match args.cmd.as_str() {
        "check" => {
            println!("aegis-pdp: OK ({} policies validated)", engine.policy_count());
            ExitCode::SUCCESS
        }
        "eval" => eval(&engine),
        "serve" => serve(engine, &args),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn serve(engine: Engine, args: &Args) -> ExitCode {
    let n = engine.policy_count();
    match (&args.listen, args.stdio) {
        (Some(path), false) => {
            let listener = match uds::listen_at(path) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("aegis-pdp: listen {}: {e}", path.display());
                    return ExitCode::from(1);
                }
            };
            eprintln!("aegis-pdp: serving {n} policies on {}", path.display());
            match server::serve_listener(Arc::new(engine), &listener) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("aegis-pdp: accept: {e}");
                    ExitCode::from(1)
                }
            }
        }
        (None, true) => {
            let stdin = std::io::stdin();
            if !uds::is_seqpacket(&stdin) {
                eprintln!("aegis-pdp: --stdio needs a SOCK_SEQPACKET socket on fd 0");
                return ExitCode::from(2);
            }
            match server::serve_conn(&engine, &stdin) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("aegis-pdp: {e}");
                    ExitCode::from(1)
                }
            }
        }
        _ => {
            eprintln!("aegis-pdp serve: exactly one of --listen PATH or --stdio\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn eval(engine: &Engine) -> ExitCode {
    let mut out = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { return ExitCode::from(1) };
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        let v = match f.as_slice() {
            [p, a, r, c, e] => engine.decide_json(p, a, r, c, e),
            _ => {
                eprintln!("aegis-pdp eval: expected 5 tab-separated fields");
                return ExitCode::from(2);
            }
        };
        if writeln!(out, "{} {}", word(v.decision), v.raw.replace('\n', " ")).and_then(|()| out.flush()).is_err() {
            return ExitCode::from(1);
        }
    }
    ExitCode::SUCCESS
}
