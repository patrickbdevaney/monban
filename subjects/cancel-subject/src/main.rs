//! cancel-subject: `aegis-adapter-pg`'s pool and NC3 release path under a synchronous DST host shell, over the
//! `oracles/cancel-sweep` subject event protocol (README "Subject event protocol" and "Synchronous host").
//!
//! ```text
//! oracles/cancel-sweep/run --seeds 200 --subject target/release/cancel-subject
//! oracles/cancel-sweep/run --self-test --subject target/release/cancel-subject     (appends --mutate <name>)
//! ```
//!
//! Code under test: `aegis_adapter_pg::pool` (key, bound, epoch retirement, leases) and `aegis_adapter_pg::checkin`
//! (checkin predicate on the client's `ProtoState`, quarantine, recovery within the op budget without a
//! CancelRequest, discard with a CancelRequest, NC4 charges, C8 reset on recycle). Harness code: the DST shell
//! (`host.rs`: handler on a worker thread, cancellation points at host-call boundaries, commit-point latch, limiter,
//! authz tri-state, upstream pool) and the pgwire fake that reports server truth (`fake.rs`).
//!
//! Lines over 1 MiB, unreadable JSON and unknown ops end the process with a non-zero status (the oracle then
//! reports the subject as failed); the subject never guesses.
#![forbid(unsafe_code)]

mod fake;
mod host;
mod json;

use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::process::ExitCode;

use aegis_adapter_pg::TenantId;
use fake::{World, s};
use host::{Abort, Host, Mode, Muts, Req, Step};
use json::{Json, emit};

const MAX_LINE: u64 = 1 << 20;
const MODES: [&str; 5] = ["drop", "rst", "timeout", "stage_timeout", "crash"];

fn str_of<'a>(j: &'a Json, k: &str) -> Result<&'a str, String> {
    j.get(k).and_then(Json::str).ok_or_else(|| format!("missing string field {k}"))
}

fn u64_of(j: &Json, k: &str) -> Result<u64, String> {
    match j.get(k) {
        Some(Json::Num(t)) => t.parse::<u64>().map_err(|_| format!("field {k}: not a u64: {t}")),
        _ => Err(format!("missing number field {k}")),
    }
}

fn bool_of(j: &Json, k: &str) -> bool {
    matches!(j.get(k), Some(Json::Bool(true)))
}

fn arr<'a>(j: Option<&'a Json>, what: &str) -> Result<&'a [Json], String> {
    match j {
        Some(Json::Arr(v)) => Ok(v),
        _ => Err(format!("{what}: expected an array")),
    }
}

fn strs(j: Option<&Json>, what: &str) -> Result<Vec<String>, String> {
    arr(j, what)?
        .iter()
        .map(|x| x.str().map(str::to_owned).ok_or_else(|| format!("{what}: expected strings")))
        .collect()
}

fn step(j: &Json) -> Result<Step, String> {
    let v = arr(Some(j), "step")?;
    let at = |i: usize| v.get(i).and_then(Json::str).map(str::to_owned).ok_or_else(|| format!("step field {i}"));
    Ok(match at(0)?.as_str() {
        "read" => Step::Read(strs(v.get(1), "read keys")?),
        "write" => Step::Write(at(1)?, at(2)?),
        "prepared" => Step::Prepared(at(1)?, at(2)?, at(3)?),
        "savepoint" => Step::Savepoint(at(1)?, at(2)?, at(3)?),
        "upstream" => Step::Upstream,
        "show" => Step::Show,
        other => return Err(format!("unknown step {other}")),
    })
}

fn req(j: &Json) -> Result<Req, String> {
    let abort = match j.get("abort") {
        None | Some(Json::Null) => None,
        Some(Json::Str(a)) if a == "before_begin" => Some(Abort::BeforeBegin),
        Some(Json::Str(a)) if a == "in_txn" => Some(Abort::InTxn),
        Some(other) => return Err(format!("unknown abort {}", emit(other))),
    };
    Ok(Req {
        id: str_of(j, "id")?.to_owned(),
        principal: str_of(j, "principal")?.to_owned(),
        idem_key: str_of(j, "idem_key")?.to_owned(),
        cost: u64_of(j, "cost")?,
        authority: str_of(j, "authority")?.to_owned(),
        authz: strs(j.get("authz"), "authz")?,
        pre_prepare: bool_of(j, "pre_prepare"),
        session_set: bool_of(j, "session_set"),
        op_budget: u64_of(j, "op_budget")?,
        stmt_ticks: u64_of(j, "stmt_ticks")?,
        steps: arr(j.get("steps"), "steps")?.iter().map(step).collect::<Result<_, _>>()?,
        abort,
    })
}

/// One scenario run; returns the event lines (ending with `end`).
fn run(job: &Json, muts: Muts) -> Result<Vec<String>, String> {
    let world: BTreeMap<String, String> = match job.get("world") {
        Some(Json::Obj(m)) => m
            .iter()
            .map(|(k, v)| v.str().map(|x| (k.clone(), x.to_owned())).ok_or_else(|| "world: string values".to_owned()))
            .collect::<Result<_, _>>()?,
        _ => return Err("world: expected an object".into()),
    };
    let requests: Vec<Req> = arr(job.get("requests"), "requests")?.iter().map(req).collect::<Result<_, _>>()?;
    let bumps: Vec<u64> = arr(job.get("bumps_before"), "bumps_before")?
        .iter()
        .map(|x| match x {
            Json::Num(t) => t.parse::<u64>().map_err(|_| "bumps_before: u64".to_owned()),
            _ => Err("bumps_before: numbers".to_owned()),
        })
        .collect::<Result<_, _>>()?;
    let target = u64_of(job, "target")?;
    let cancel_at = match job.get("cancel_at") {
        None | Some(Json::Null) => None,
        Some(Json::Num(t)) => Some(t.parse::<u64>().map_err(|_| "cancel_at: u64".to_owned())?),
        Some(_) => return Err("cancel_at: number or null".into()),
    };
    let mode = match job.get("mode") {
        None | Some(Json::Null) => None,
        Some(Json::Str(m)) => Some(Mode::parse(m).ok_or_else(|| format!("unknown mode {m}"))?),
        Some(_) => return Err("mode: string or null".into()),
    };
    // One tenant per principal, in order of first appearance (TenantId 1, 2, ...).
    let mut tenants = BTreeMap::new();
    for r in &requests {
        if !tenants.contains_key(&r.principal) {
            let next = u64::try_from(tenants.len()).unwrap_or(u64::MAX).saturating_add(1);
            let t = TenantId::new(next).map_err(|_| "tenant id".to_owned())?;
            tenants.insert(r.principal.clone(), t);
        }
    }
    let mut host = Host::new(World::new(world), muts, tenants);
    host.world().borrow_mut().durable("start");
    for (idx, r) in requests.iter().enumerate() {
        let idx = u64::try_from(idx).unwrap_or(u64::MAX);
        if bumps.contains(&idx) {
            host.bump();
        }
        let tgt = idx == target;
        host.run(r, if tgt { cancel_at } else { None }, if tgt { mode } else { None })?;
        host.world().borrow_mut().durable(&format!("after:{}", r.id));
    }
    let mut w = host.world().borrow_mut();
    w.out.ev("end", false, vec![]);
    Ok(std::mem::take(&mut w.out.lines))
}

fn main() -> ExitCode {
    let mut muts = Muts::default();
    let mut names = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match (a.as_str(), args.next()) {
            ("--mutate", Some(m)) if muts.apply(&m) => names.push(m),
            _ => {
                eprintln!("cancel-subject: usage: cancel-subject [--mutate <name>]...");
                return ExitCode::from(2);
            }
        }
    }
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    loop {
        let mut line = String::new();
        match (&mut input).take(MAX_LINE).read_line(&mut line) {
            Ok(0) => return ExitCode::SUCCESS,
            Ok(_) if !line.ends_with('\n') && line.len() as u64 >= MAX_LINE => {
                eprintln!("cancel-subject: line over 1 MiB");
                return ExitCode::FAILURE;
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("cancel-subject: read: {e}");
                return ExitCode::FAILURE;
            }
        }
        if line.trim().is_empty() {
            continue;
        }
        let msg = match json::parse(line.trim()) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("cancel-subject: bad JSON: {e}");
                return ExitCode::FAILURE;
            }
        };
        let reply: Vec<String> = match msg.get("op").and_then(Json::str) {
            Some("hello") => {
                let mut m = BTreeMap::new();
                m.insert("ev".to_owned(), s("hello"));
                m.insert("impl".to_owned(), s("aegis-adapter-pg pool + NC3 release (cancel-subject, sync DST host)"));
                m.insert("host".to_owned(), s("sync"));
                m.insert("modes".to_owned(), Json::Arr(MODES.iter().map(|x| s(x)).collect()));
                m.insert("mutations".to_owned(), Json::Arr(names.iter().map(|x| s(x)).collect()));
                vec![emit(&Json::Obj(m))]
            }
            Some("run") => match run(&msg, muts) {
                Ok(lines) => lines,
                Err(e) => {
                    eprintln!("cancel-subject: run refused: {e}");
                    return ExitCode::FAILURE;
                }
            },
            Some("quit") => return ExitCode::SUCCESS,
            _ => {
                eprintln!("cancel-subject: unknown op");
                return ExitCode::FAILURE;
            }
        };
        for l in reply {
            if writeln!(out, "{l}").is_err() {
                return ExitCode::FAILURE;
            }
        }
        if out.flush().is_err() {
            return ExitCode::FAILURE;
        }
    }
}
