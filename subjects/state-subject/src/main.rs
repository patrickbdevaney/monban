//! state-subject: monban-state idempotency, outbox and commit-point latch over the state-props line protocol
//! (`oracles/state-props/README.md`, "Subject protocol").
//!
//! Usage: `state-subject <dir> [--idempotency-retention <s>] [--mutate <name>]...`
//!
//! IDEMP-R (Phase 8, README "Retention"): `--idempotency-retention` is [`State::set_retention`]; `CLOCK <unix_s>`
//! replaces the wall clock ([`State::set_clock`]); `PURGE` is [`State::purge_expired`] (`PURGED <n>`). The READY line
//! advertises `features=retention`.
//!
//! The wrapper only parses lines: BEGIN is [`State::begin`], WRITE is [`Lease::write`], EFFECT is
//! [`State::effect`], COMMIT is [`State::commit`] (the commit point; 202 when the timer fired after CP), ABORT is
//! [`State::abort`], DELIVER is one [`State::deliver`] pass whose sink writes the EFF line and waits for the oracle's
//! ACK (so an effect is marked delivered only after the sink took it), DUMP lists the committed user rows. Leases
//! live in memory.
//!
//! Self-test mutations: `idem-key-without-principal`, `replay-reexecutes`, `effect-before-commit` and
//! `outbox-drop-on-restart` are monban-state's hidden [`StateMutations`]; `latch-returns-408` (a 202 is printed as
//! 408) and `dedupe-unstable` (a fresh dedupe key on every delivery) are applied here, at the output.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use monban_state::{Begin, DeliverError, IdemKey, Lease, Outcome, Reply, State, StateMutations};

const MUTATIONS: [&str; 9] = [
    "idem-key-without-principal",
    "replay-reexecutes",
    "effect-before-commit",
    "outbox-drop-on-restart",
    "latch-returns-408",
    "dedupe-unstable",
    "retention-ignored",
    "retention-early",
    "purge-noop",
];

fn reply(line: &str) -> Result<(), ()> {
    let mut b = Vec::with_capacity(line.len() + 1);
    b.extend_from_slice(line.as_bytes());
    b.push(b'\n');
    let out = std::io::stdout();
    let mut lock = out.lock();
    lock.write_all(&b).and_then(|()| lock.flush()).map_err(|_| ())
}

fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return None;
    }
    s.as_bytes().chunks(2).map(|p| std::str::from_utf8(p).ok().and_then(|t| u8::from_str_radix(t, 16).ok())).collect()
}

fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        for n in [x >> 4, x & 0x0f] {
            if let Some(c) = D.get(usize::from(n)) {
                s.push(char::from(*c));
            }
        }
    }
    s
}

fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

#[derive(Debug, Default)]
struct Args {
    dir: PathBuf,
    muts: StateMutations,
    latch_408: bool,
    dedupe_unstable: bool,
    purge_noop: bool,
    retention: Option<u64>,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args::default();
    let mut dir = None;
    let mut it = std::env::args().skip(1);
    while let Some(x) = it.next() {
        if x == "--mutate" {
            match it.next().as_deref() {
                Some("idem-key-without-principal") => a.muts.idem_key_without_principal = true,
                Some("replay-reexecutes") => a.muts.replay_reexecutes = true,
                Some("effect-before-commit") => a.muts.effect_before_commit = true,
                Some("outbox-drop-on-restart") => a.muts.outbox_drop_on_restart = true,
                Some("latch-returns-408") => a.latch_408 = true,
                Some("dedupe-unstable") => a.dedupe_unstable = true,
                Some("retention-ignored") => a.muts.retention_ignored = true,
                Some("retention-early") => a.muts.retention_early = true,
                Some("purge-noop") => a.purge_noop = true,
                other => return Err(format!("unknown mutation {other:?}")),
            }
        } else if x == "--idempotency-retention" {
            let n = it.next().and_then(|v| v.parse::<u64>().ok()).ok_or("--idempotency-retention <seconds>")?;
            a.retention = Some(n);
        } else if x.starts_with("--") {
            return Err(format!("unknown flag {x}"));
        } else if dir.is_none() {
            dir = Some(PathBuf::from(x));
        } else {
            return Err(format!("unexpected argument {x}"));
        }
    }
    a.dir = dir.ok_or("usage: state-subject <dir> [--mutate <name>]...")?;
    Ok(a)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            let _ = reply(&format!("ERR open {}", one_line(&e)));
            return ExitCode::from(2);
        }
    };
    let opened =
        if args.muts == StateMutations::NONE { State::open(&args.dir) } else { State::open_with(&args.dir, args.muts) };
    let mut st = match opened {
        Ok(s) => s,
        Err(e) => {
            let _ = reply(&format!("ERR open {}", one_line(&e.to_string())));
            return ExitCode::from(3);
        }
    };
    if let Err(e) = st.set_retention(args.retention) {
        let _ = reply(&format!("ERR open {}", one_line(&e.to_string())));
        return ExitCode::from(2);
    }
    // CLOCK sets this; until then the system clock (u64::MAX = unset).
    let clock = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
    let c = std::sync::Arc::clone(&clock);
    let system = monban_state::Clock::system();
    st.set_clock(monban_state::Clock::new(move || match c.load(std::sync::atomic::Ordering::SeqCst) {
        u64::MAX => system.now(),
        t => t,
    }));
    if reply(&format!(
        "READY monban-state idem/outbox/latch sqlite={} features=retention mutations={}",
        monban_state::store::sqlite_version(),
        MUTATIONS.join(",")
    ))
    .is_err()
    {
        return ExitCode::from(4);
    }
    match serve(&mut st, &args, &clock) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => ExitCode::from(code),
    }
}

/// A fresh suffix per delivery (dedupe-unstable mutation only).
fn unstable_suffix(n: &mut u64) -> [u8; 4] {
    *n = n.wrapping_add(1);
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let x = (t as u64) ^ n.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ u64::from(std::process::id());
    let b = x.to_be_bytes();
    let mut out = [0u8; 4];
    for (o, v) in out.iter_mut().zip(b.iter().skip(4)) {
        *o = *v;
    }
    out
}

fn serve(st: &mut State, args: &Args, clock: &std::sync::atomic::AtomicU64) -> Result<(), u8> {
    let mut open: HashMap<String, Lease> = HashMap::new();
    let mut unstable_n = 0u64;
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    while let Some(line) = lines.next() {
        let Ok(line) = line else { break };
        let a: Vec<&str> = line.split_whitespace().collect();
        let r = match a.as_slice() {
            [] => continue,
            ["BEGIN", rid, p, k, dg] if is_token(rid) && is_token(p) && is_token(k) => {
                if open.contains_key(*rid) {
                    reply(&format!("ERR {rid} duplicate rid"))
                } else {
                    let res = unhex(dg)
                        .ok_or_else(|| "bad digest".to_string())
                        .and_then(|d| {
                            IdemKey::new(p.as_bytes(), k.as_bytes()).map(|ik| (ik, d)).map_err(|e| e.to_string())
                        })
                        .and_then(|(ik, d)| st.begin(&ik, &d).map_err(|e| e.to_string()));
                    match res {
                        Ok(Begin::New(lease)) => {
                            open.insert((*rid).to_string(), lease);
                            reply(&format!("NEW {rid}"))
                        }
                        Ok(Begin::Replay(o)) => reply(&format!("REPLAY {rid} {} {}", o.status, hex(&o.body))),
                        Ok(Begin::Conflict) => reply(&format!("CONFLICT {rid}")),
                        Ok(Begin::InFlight) => reply(&format!("INFLIGHT {rid}")),
                        Err(e) => reply(&format!("ERR {rid} begin {}", one_line(&e))),
                    }
                }
            }
            ["WRITE", rid, row, val] if is_token(row) => match (open.get_mut(*rid), unhex(val)) {
                (Some(lease), Some(v)) => {
                    lease.write(row.as_bytes(), &v);
                    reply(&format!("OK {rid}"))
                }
                _ => reply(&format!("ERR {rid} bad WRITE")),
            },
            ["EFFECT", rid, pl] => match (open.get_mut(*rid), unhex(pl)) {
                (Some(lease), Some(p)) => match st.effect(lease, &p) {
                    Ok(_) => reply(&format!("OK {rid}")),
                    Err(e) => {
                        let _ = reply(&format!("ERR {rid} effect {}", one_line(&e.to_string())));
                        return Err(4);
                    }
                },
                _ => reply(&format!("ERR {rid} bad EFFECT")),
            },
            ["COMMIT", rid, status, body, timer] => {
                let parsed = (
                    status.parse::<u16>().ok(),
                    unhex(body),
                    match *timer {
                        "0" => Some(false),
                        "1" => Some(true),
                        _ => None,
                    },
                );
                match (open.contains_key(*rid), parsed) {
                    (true, (Some(s), Some(b), Some(t))) => {
                        let Some(lease) = open.remove(*rid) else { return Err(4) };
                        match st.commit(lease, Outcome { status: s, body: b }, t) {
                            Ok(Reply::Outcome(o)) => reply(&format!("RESP {rid} {} {}", o.status, hex(&o.body))),
                            Ok(Reply::Accepted) => {
                                let code = if args.latch_408 { 408 } else { monban_state::ACCEPTED_STATUS }; // MUTATION
                                reply(&format!("RESP {rid} {code} -"))
                            }
                            Err(e) => {
                                // fail-stop: nothing acknowledged
                                let _ = reply(&format!("ERR {rid} commit {}", one_line(&e.to_string())));
                                return Err(4);
                            }
                        }
                    }
                    _ => reply(&format!("ERR {rid} bad COMMIT")),
                }
            }
            ["ABORT", rid] => match open.remove(*rid) {
                Some(lease) => {
                    st.abort(lease);
                    reply(&format!("OK {rid}"))
                }
                None => reply(&format!("ERR {rid} bad ABORT")),
            },
            ["DELIVER"] => {
                let unstable = args.dedupe_unstable;
                let res = st.deliver(|e| {
                    let mut dd = e.dedupe;
                    if unstable {
                        // MUTATION: last four bytes replaced on every delivery
                        let sfx = unstable_suffix(&mut unstable_n);
                        for (d, s) in dd.iter_mut().rev().zip(sfx.iter().rev()) {
                            *d = *s;
                        }
                    }
                    reply(&format!("EFF {} {}", hex(&dd), hex(&e.payload)))?;
                    // The sink accepted the effect only once the oracle ACKs it: a line still in the pipe is not
                    // delivered, so an unACKed effect stays pending across a SIGKILL.
                    match lines.next() {
                        Some(Ok(ack)) if ack.trim() == "ACK" => Ok(()),
                        _ => Err(()),
                    }
                });
                match res {
                    Ok(_) => reply("END"),
                    Err(DeliverError::Sink(())) => return Err(4),
                    Err(DeliverError::State(e)) => {
                        let _ = reply(&format!("ERR deliver {}", one_line(&e.to_string())));
                        return Err(4);
                    }
                }
            }
            ["DUMP"] => match st.user_rows() {
                Ok(rows) => {
                    let mut out = String::new();
                    for (k, v) in rows {
                        out.push_str(&format!("ROW {} {}\n", String::from_utf8_lossy(&k), hex(&v)));
                    }
                    out.push_str("END");
                    reply(&out)
                }
                Err(e) => {
                    let _ = reply(&format!("ERR dump {}", one_line(&e.to_string())));
                    return Err(4);
                }
            },
            ["CLOCK", t] => match t.parse::<u64>() {
                Ok(t) if t != u64::MAX => {
                    clock.store(t, std::sync::atomic::Ordering::SeqCst);
                    reply("OK clock")
                }
                _ => reply("ERR - bad CLOCK"),
            },
            ["PURGE"] => {
                if args.purge_noop {
                    reply("PURGED 0") // MUTATION
                } else {
                    match st.purge_expired() {
                        Ok(n) => reply(&format!("PURGED {n}")),
                        Err(e) => {
                            let _ = reply(&format!("ERR purge {}", one_line(&e.to_string())));
                            return Err(4);
                        }
                    }
                }
            }
            ["QUIT"] => break,
            other => {
                let rid = other.get(1).copied().unwrap_or("-");
                reply(&format!("ERR {rid} bad command {}", one_line(&line.chars().take(60).collect::<String>())))
            }
        };
        if r.is_err() {
            return Err(4);
        }
    }
    Ok(())
}
