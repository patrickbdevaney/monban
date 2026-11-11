//! admission-subject: speaks the admission-props event protocol (oracles/admission-props/README.md) on
//! stdin/stdout, driving the production `monban-admission` pipeline.
//!
//! Input: JSON lines (`config` resets state; `arrive` yields exactly one decision line; `done`/`close` yield none).
//! A malformed `arrive` whose id can still be read, or an `arrive` before any `config`, is rejected fail-closed
//! (503 at S0). Any other unreadable line is a protocol error: the subject exits 2 without guessing.
#![forbid(unsafe_code)]

mod json;

use std::io::{BufRead, BufWriter, Write};
use std::process::ExitCode;

use json::Json;
use monban_admission::{Admission, Arrive, Close, Config, Credential, Done, Lane, RejectStatus, Stage, Verdict};
use monban_budget::Gcra;

fn req_u64(j: &Json, k: &str) -> Result<u64, String> {
    j.get(k).and_then(Json::u64).ok_or_else(|| format!("missing/invalid u64 field {k:?}"))
}

fn req_str(j: &Json, k: &str) -> Result<String, String> {
    j.get(k).and_then(Json::str).map(str::to_string).ok_or_else(|| format!("missing/invalid string field {k:?}"))
}

fn opt_bool(j: &Json, k: &str) -> Result<bool, String> {
    match j.get(k) {
        None | Some(Json::Null) => Ok(false),
        Some(v) => v.bool().ok_or_else(|| format!("invalid bool field {k:?}")),
    }
}

fn opt_u64(j: &Json, k: &str) -> Result<u64, String> {
    match j.get(k) {
        None | Some(Json::Null) => Ok(0),
        Some(v) => v.u64().ok_or_else(|| format!("invalid u64 field {k:?}")),
    }
}

fn gcra(j: &Json, path: &[&str]) -> Result<Gcra, String> {
    let node = path.iter().try_fold(j, |n, k| n.get(k)).ok_or_else(|| format!("missing {}", path.join(".")))?;
    Ok(Gcra::new(req_u64(node, "T")?, req_u64(node, "b")?))
}

fn usize_of(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

fn parse_config(j: &Json) -> Result<Config, String> {
    Ok(Config {
        s1: Gcra::new(req_u64(j, "s1_T")?, req_u64(j, "s1_b")?),
        s1_store: usize_of(req_u64(j, "s1_store")?),
        s3_store: usize_of(req_u64(j, "s3_store")?),
        anon: gcra(j, &["cls", "anon"])?,
        session: gcra(j, &["cls", "session"])?,
        verified: gcra(j, &["cls", "verified"])?,
        agg_f: gcra(j, &["agg", "F"])?,
        agg_e: gcra(j, &["agg", "E"])?,
        exp_cost: req_u64(j, "exp_cost")?,
        stepup_cost: req_u64(j, "stepup_cost")?,
        stepup_bits: req_u64(j, "stepup_bits")?,
        limit: req_u64(j, "L")?,
        max_conns: req_u64(j, "max_conns")?,
        prefix_cap: req_u64(j, "prefix_cap")?,
        fresh_age_ns: req_u64(j, "fresh_age_ns")?,
    })
}

fn parse_cred(j: Option<&Json>) -> Result<Credential, String> {
    let Some(c) = j.filter(|c| **c != Json::Null) else { return Ok(Credential::None) };
    match c.get("kind").and_then(Json::str) {
        Some("none") => Ok(Credential::None),
        Some("verified") => Ok(Credential::Verified { id: req_str(c, "id")? }),
        Some("cookie") => Ok(Credential::Cookie {
            id: req_str(c, "id")?,
            minted: opt_u64(c, "minted")?,
            promoted: opt_bool(c, "promoted")?,
        }),
        _ => Err("invalid cred.kind".into()),
    }
}

fn parse_arrive(j: &Json, id: u64) -> Result<Arrive, String> {
    let lane = match j.get("lane") {
        None | Some(Json::Null) => Lane::Std,
        Some(v) => match v.str() {
            Some("std") => Lane::Std,
            Some("accessible") => Lane::Accessible,
            _ => return Err("invalid lane".into()),
        },
    };
    let fault = match j.get("fault") {
        None | Some(Json::Null) => None,
        Some(v) => Some(v.str().and_then(Stage::parse).ok_or("invalid fault")?),
    };
    Ok(Arrive {
        id,
        t: req_u64(j, "t")?,
        ip: req_str(j, "ip")?,
        prefix: req_str(j, "prefix")?,
        conn: req_str(j, "conn")?,
        newconn: opt_bool(j, "newconn")?,
        cred: parse_cred(j.get("cred"))?,
        cost: req_u64(j, "cost")?,
        pow: opt_u64(j, "pow")?,
        lane,
        fault,
    })
}

fn decision_line(id: u64, v: Verdict) -> String {
    let decision = if v == Verdict::Admit { "admit" } else { "reject" };
    format!(r#"{{"id":{id},"decision":"{decision}","status":{},"stage":"{}"}}"#, v.http_status(), v.stage().as_str())
}

const FAIL_CLOSED: Verdict = Verdict::Reject { stage: Stage::S0, status: RejectStatus::Unavailable };

fn step(line: &str, pipe: &mut Option<Admission>, out: &mut impl Write) -> Result<(), String> {
    let j = json::parse(line)?;
    match j.get("type").and_then(Json::str) {
        Some("config") => {
            *pipe = Some(Admission::new(parse_config(&j)?));
        }
        Some("arrive") => {
            let id = req_u64(&j, "id")?;
            let v = match (parse_arrive(&j, id), pipe.as_mut()) {
                (Ok(ev), Some(p)) => p.arrive(&ev),
                _ => FAIL_CLOSED,
            };
            writeln!(out, "{}", decision_line(id, v)).map_err(|e| e.to_string())?;
        }
        Some("done") => {
            let ev = Done {
                id: req_u64(&j, "id")?,
                t: req_u64(&j, "t")?,
                actual_cost: req_u64(&j, "actual_cost")?,
                cancelled: opt_bool(&j, "cancelled")?,
            };
            if let Some(p) = pipe.as_mut() {
                p.done(&ev);
            }
        }
        Some("close") => {
            let ev = Close { conn: req_str(&j, "conn")?, t: req_u64(&j, "t")? };
            if let Some(p) = pipe.as_mut() {
                p.close(&ev);
            }
        }
        _ => return Err("missing/unknown event type".into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut pipe: Option<Admission> = None;
    for (n, line) in stdin.lock().lines().enumerate() {
        let res = line.map_err(|e| e.to_string()).and_then(|l| {
            let l = l.trim();
            if l.is_empty() { Ok(()) } else { step(l, &mut pipe, &mut out) }
        });
        if let Err(e) = res {
            let _ = out.flush();
            eprintln!("admission-subject: line {}: {e}", n.saturating_add(1));
            return ExitCode::from(2);
        }
    }
    match out.flush() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("admission-subject: {e}");
            ExitCode::from(2)
        }
    }
}
