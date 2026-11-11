//! `monban-p2 cordon --module <c.cwasm> --sha256 <hex> [--mpk] [--memory-mib N] [--pool-slots N] [--threads N]`
//! (PLAN-5 D1, D4, D5, D6, D8; F14 Part 2; ARCHITECTURE §3.6 single-tenant row as amended by q4-006;
//! oracles/hostile-modules README "worker command line").
//!
//! One cordon serves exactly one principal; the supervisor keys its cordon table by principal
//! (`monban_iso::cordon::Registry`) and spawns each cordon by execve (`monban_iso::supervisor`, D8), so a cordon never
//! sees a second principal's request. Boot (fail closed, exit 78 on any configuration error, before fd 3 is ever
//! accepted on):
//! 1. build the Engine from the same settings `monban-p2 compile` used (`--pool-slots` = F8 `p2.cordon_slots`,
//!    default 64; `--mpk` = the D11 density option, reservation and guards unchanged);
//! 2. load the `.cwasm` through `monban_wasm::engine::cwasm::load` (sha256 compared with `--sha256` before the one
//!    deserialize) and resolve it against the F14 Linker once (`InstancePre`);
//! 3. adopt fd 3 (the supervisor-held listening `SOCK_SEQPACKET` socket) and install `Profile::cordon` with no
//!    readable path while still single-threaded (Landlock, seccomp: threads only and no fork, dumpable=0,
//!    NO_NEW_PRIVS);
//! 4. start the epoch ticker (the wall bound, R-ISO-3) and `monban_iso::cordon::serve` with `--threads` serving
//!    threads (default: the pool size, so every slot can be in use).
//!
//! Per connection the cordon sends the F14 `ready` frame (and, in `test-hooks`/`mutants` builds, the `layout`
//! frame with its own load base and pid, D8), then serves that connection through `monban_wasm::abi::Session`
//! (P5-wasm-002), the same F14 worker code as the fork child of zygote.rs: `request` and its `body-chunk`s, a fresh
//! Store and instance with the F14 host functions, per-request handles and the five quotas under
//! `min(frame limits, boot ceilings)`, fuel and the epoch deadline at the effective `wall-ms` (a wall timeout is a
//! trap: `resp-end` trap 2), `resp-end`. A `cancel` for the request drops it with nothing more sent. A frame that does
//! not decode, is oversized or out of order closes the connection without a reply (the supervisor sees the
//! connection end: Error => Deny, D17).
//!
//! No pipelining: a connection carries one request at a time, and the supervisor must not send a second `request`
//! on a connection before the first one's `resp-end` (or its own `cancel`). `Session` reads frames only when it
//! expects one: a `request` read while it waits for a `body-chunk` or a `data-reply` is out of order and ends the
//! connection, and one that is queued while `handle()` runs is read only after the `resp-end`, so it is served after
//! the first, never beside it. F14 allows up to `cordon_slots` requests in flight per cordon; this worker gets that
//! concurrency from parallel connections (one serving thread per connection, started on demand up to `--threads`).
//! The zygote's fork child serves exactly one request per connection and then exits. Both paths share one frame
//! codec, `monban_wasm::abi::frame`.

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::ExitCode;

use monban_iso::cordon;
use monban_iso::sandbox::{self, Profile, SandboxError};
use monban_wasm::abi::{F14Worker, Session, frame};
use monban_wasm::engine::{FUEL_MAX, WALL_MS_MAX, cwasm};
use monban_wasm::{EpochTicker, P2Engine, P2Limits};

use crate::zygote::{mutant_memory_mib, parse_hex, settings};

/// EX_USAGE.
const EX_USAGE: u8 = 64;
/// EX_SOFTWARE.
const EX_SOFTWARE: u8 = 70;
/// EX_CONFIG: fail-closed boot.
const EX_CONFIG: u8 = 78;

fn fail(code: u8, msg: &str) -> ExitCode {
    eprintln!("monban-p2: {msg}");
    ExitCode::from(code)
}

#[derive(Debug, Default)]
struct Args {
    module: Option<String>,
    sha256: Option<String>,
    mpk: bool,
    memory_mib: Option<u32>,
    pool_slots: Option<u32>,
    threads: Option<usize>,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let mut val = || it.next().cloned().ok_or_else(|| format!("{k} needs a value"));
        match k.as_str() {
            "--module" if a.module.is_none() => a.module = Some(val()?),
            "--sha256" if a.sha256.is_none() => a.sha256 = Some(val()?),
            "--mpk" if !a.mpk => a.mpk = true,
            "--memory-mib" if a.memory_mib.is_none() => {
                a.memory_mib = Some(val()?.parse().map_err(|_| "--memory-mib: not a number".to_string())?);
            }
            "--pool-slots" if a.pool_slots.is_none() => {
                a.pool_slots = Some(val()?.parse().map_err(|_| "--pool-slots: not a number".to_string())?);
            }
            "--threads" if a.threads.is_none() => {
                a.threads = Some(val()?.parse().map_err(|_| "--threads: not a number".to_string())?);
            }
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    Ok(a)
}

/// `monban-p2 cordon ...`.
pub fn run(args: &[String]) -> ExitCode {
    let a = match parse(args) {
        Ok(a) => a,
        Err(e) => return fail(EX_USAGE, &format!("cordon: {e} (usage: cordon --module C.cwasm --sha256 HEX)")),
    };
    let (Some(module), Some(hex)) = (a.module.as_deref(), a.sha256.as_deref()) else {
        return fail(EX_USAGE, "cordon: --module and --sha256 are required");
    };
    let Some(digest) = parse_hex(hex) else {
        return fail(EX_USAGE, "cordon: --sha256 must be 64 lower-case hex digits");
    };
    let settings = match settings(a.mpk, mutant_memory_mib(a.memory_mib), a.pool_slots) {
        Ok(s) => s,
        Err(e) => return fail(EX_CONFIG, &format!("cordon: {e}")),
    };
    let threads = a.threads.unwrap_or_else(|| usize::try_from(settings.pool_slots()).unwrap_or(1));
    if !(1..=cordon::MAX_THREADS).contains(&threads) {
        return fail(EX_CONFIG, &format!("cordon: --threads {threads} outside 1..={}", cordon::MAX_THREADS));
    }
    let engine = match P2Engine::new(settings) {
        Ok(e) => e,
        Err(e) => return fail(EX_CONFIG, &format!("cordon: {e}")),
    };
    let m = match cwasm::load(&engine, Path::new(module), &digest) {
        Ok(m) => m,
        Err(e) => return fail(EX_CONFIG, &format!("cordon: {e}")),
    };
    let mem = u32::try_from(settings.pooling_max_memory_size() >> 20).unwrap_or(monban_wasm::engine::MEMORY_MIB_MIN);
    let ceiling = match P2Limits::new(FUEL_MAX, WALL_MS_MAX, mem) {
        Ok(c) => c,
        Err(e) => return fail(EX_CONFIG, &format!("cordon: {e}")),
    };
    let worker = match F14Worker::new(&engine, &m, ceiling) {
        Ok(w) => w,
        Err(e) => return fail(EX_CONFIG, &format!("cordon: {e}")),
    };
    drop(m);
    let listener = match monban_iso::zygote::adopt_listener() {
        Ok(l) => l,
        Err(e) => return fail(EX_CONFIG, &format!("cordon: fd 3 is not the listening socket: {e}")),
    };
    // Still single-threaded: the sandbox binds this thread and every thread started below inherits it.
    if let Err(e) = sandbox::install(&Profile::cordon(Vec::new())) {
        let code = if matches!(e, SandboxError::LandlockAbiTooOld(_)) { EX_CONFIG } else { EX_SOFTWARE };
        return fail(code, &format!("cordon: {e}"));
    }
    let ticker = match EpochTicker::start(&engine) {
        Ok(t) => t,
        Err(e) => return fail(EX_SOFTWARE, &format!("cordon: epoch ticker: {e}")),
    };
    let e = cordon::serve(listener, threads, move |conn| serve_conn(conn, &worker, &digest));
    drop(ticker);
    fail(EX_SOFTWARE, &format!("cordon: listening socket failed: {e}"))
}

/// One connection: `ready` (+ `layout`), then its requests one at a time until EOF or a bad frame.
fn serve_conn(conn: OwnedFd, worker: &F14Worker, digest: &cwasm::Digest) {
    let mut session = worker.session(UnixStream::from(conn));
    if session.send(&frame::ready(digest)) && layout_frame(&mut session) {
        // Why the session ended is not reported: the supervisor sees the connection close either way.
        let _ = session.serve_all();
    }
}

/// F14 `layout` frame `[22, 0, load-base, pid]` (D8): test-hooks and mutants builds only. The load base is the
/// address of a function of this binary, which moves with every execve (PIE + ASLR).
#[cfg(any(feature = "test-hooks", feature = "mutants"))]
fn layout_frame(s: &mut Session<'_>) -> bool {
    let base = layout_frame as fn(&mut Session<'_>) -> bool as usize;
    s.send(&frame::layout(u64::try_from(base).unwrap_or(0), u64::from(std::process::id())))
}

/// Golden builds send no layout frame.
#[cfg(not(any(feature = "test-hooks", feature = "mutants")))]
fn layout_frame(_s: &mut Session<'_>) -> bool {
    true
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    // The F14 frame codec is monban_wasm::abi::frame (tests: crates/monban-wasm/tests/abi.rs).
    #[test]
    fn arguments() {
        let a = parse(&["--module".into(), "m".into(), "--sha256".into(), "x".into(), "--threads".into(), "4".into()])
            .unwrap();
        assert_eq!(a.threads, Some(4));
        assert!(parse(&["--threads".into(), "4".into(), "--threads".into(), "5".into()]).is_err());
        assert!(parse(&["--principal".into(), "p".into()]).is_err());
        assert!(parse_hex(&"AB".repeat(32)).is_none());
    }
}
