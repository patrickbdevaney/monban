//! `aegis-p2 zygote --module <c.cwasm> --sha256 <hex> [--mpk] [--memory-mib N] [--pool-slots N]` (PLAN-5 D1, D4,
//! D5, D6; F14 Part 2; oracles/hostile-modules README "worker command line").
//!
//! Boot (fail closed, exit 78 on any error, before fd 3 is ever accepted on):
//! 1. build the Engine from the same settings `aegis-p2 compile` used (the `.cwasm` only deserializes into a
//!    compatible engine);
//! 2. load the `.cwasm` through `aegis_wasm::engine::cwasm::load`: read once, sha256 compared with `--sha256` (the
//!    digest the supervisor computed over the file the sandboxed compile wrote), deserialized from exactly the bytes
//!    that were hashed;
//! 3. resolve the module against the F14 Linker once (`InstancePre`; no compiler state is created);
//! 4. adopt fd 3 (the supervisor-held listening `SOCK_SEQPACKET` socket) and install `Profile::zygote` with no
//!    readable path (Landlock, seccomp, dumpable=0, NO_NEW_PRIVS);
//! 5. `aegis_iso::zygote::serve`: one fork child per connection (child filter, `ITIMER_REAL`).
//!
//! Per connection the child sends the F14 `ready` frame (and, in `test-hooks`/`mutants` builds, the `layout` frame)
//! and serves exactly one request through `aegis_wasm::abi::Session` (P5-wasm-002): `request` and its
//! `body-chunk`s, `ITIMER_REAL` re-armed at the request's effective `wall-ms`, `handle()` in a fresh instance with the
//! F14 host functions, handles and quotas under `min(frame limits, boot ceilings)`, `resp-end`, exit. Any frame that
//! does not decode, is oversized or out of order ends the child without a reply (the supervisor sees a worker death).

use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use aegis_iso::sandbox::{self, Profile, SandboxError};
use aegis_iso::zygote::{self, Spec};
use aegis_wasm::abi::{Closed, F14Worker, Served, Session, frame};
use aegis_wasm::engine::{FUEL_MAX, WALL_MS_MAX, cwasm};
use aegis_wasm::{EngineSettings, P2Engine, P2Limits, RequestLimits};

/// EX_USAGE.
const EX_USAGE: u8 = 64;
/// EX_SOFTWARE.
const EX_SOFTWARE: u8 = 70;
/// EX_CONFIG: fail-closed boot.
const EX_CONFIG: u8 = 78;
/// Child exit codes (diagnostics only; the supervisor treats any death without `resp-end` as Error).
const EXIT_DECODE: i32 = 2;
const EXIT_IO: i32 = 3;
const EXIT_LIMITS: i32 = 4;

fn fail(code: u8, msg: &str) -> ExitCode {
    eprintln!("aegis-p2: {msg}");
    ExitCode::from(code)
}

#[derive(Debug, Default)]
pub(crate) struct Args {
    pub(crate) module: Option<String>,
    pub(crate) sha256: Option<String>,
    pub(crate) mpk: bool,
    pub(crate) memory_mib: Option<u32>,
    pub(crate) pool_slots: Option<u32>,
}

pub(crate) fn parse(args: &[String]) -> Result<Args, String> {
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
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    Ok(a)
}

/// Lower-case 64-hex-digit sha256.
pub(crate) fn parse_hex(s: &str) -> Option<cwasm::Digest> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut d = [0u8; 32];
    for (i, out) in d.iter_mut().enumerate() {
        *out = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(d)
}

/// Engine settings shared with `aegis-p2 compile` (same flags, same defaults).
pub fn settings(mpk: bool, memory_mib: Option<u32>, pool_slots: Option<u32>) -> Result<EngineSettings, String> {
    let d = EngineSettings::defaults(mpk);
    let mem = memory_mib.unwrap_or_else(|| {
        u32::try_from(d.pooling_max_memory_size() >> 20).unwrap_or(aegis_wasm::engine::MEMORY_MIB_DEFAULT)
    });
    EngineSettings::from_p2(mem, pool_slots.unwrap_or_else(|| d.pool_slots()), mpk).map_err(|e| e.to_string())
}

/// `aegis-p2 zygote ...`.
pub fn run(args: &[String]) -> ExitCode {
    let a = match parse(args) {
        Ok(a) => a,
        Err(e) => return fail(EX_USAGE, &format!("zygote: {e} (usage: zygote --module C.cwasm --sha256 HEX)")),
    };
    let (Some(module), Some(hex)) = (a.module.as_deref(), a.sha256.as_deref()) else {
        return fail(EX_USAGE, "zygote: --module and --sha256 are required");
    };
    let Some(digest) = parse_hex(hex) else {
        return fail(EX_USAGE, "zygote: --sha256 must be 64 lower-case hex digits");
    };
    let settings = match settings(a.mpk, mutant_memory_mib(a.memory_mib), a.pool_slots) {
        Ok(s) => s,
        Err(e) => return fail(EX_CONFIG, &format!("zygote: {e}")),
    };
    let engine = match P2Engine::new(settings) {
        Ok(e) => e,
        Err(e) => return fail(EX_CONFIG, &format!("zygote: {e}")),
    };
    let m = match cwasm::load(&engine, Path::new(module), &digest) {
        Ok(m) => m,
        Err(e) => return fail(EX_CONFIG, &format!("zygote: {e}")),
    };
    let ceiling = match P2Limits::new(FUEL_MAX, WALL_MS_MAX, mem_mib(&settings)) {
        Ok(c) => c,
        Err(e) => return fail(EX_CONFIG, &format!("zygote: {e}")),
    };
    let worker = match F14Worker::new(&engine, &m, ceiling) {
        Ok(w) => w,
        Err(e) => return fail(EX_CONFIG, &format!("zygote: {e}")),
    };
    drop(m);
    let listener = match zygote::adopt_listener() {
        Ok(l) => l,
        Err(e) => return fail(EX_CONFIG, &format!("zygote: fd 3 is not the listening socket: {e}")),
    };
    if let Err(e) = sandbox::install(&Profile::zygote(Vec::new())) {
        let code = if matches!(e, SandboxError::LandlockAbiTooOld(_)) { EX_CONFIG } else { EX_SOFTWARE };
        return fail(code, &format!("zygote: {e}"));
    }
    let spec = mutant_spec(Spec::fork_per_connection(Duration::from_millis(WALL_MS_MAX)));
    let e = zygote::serve(listener, spec, |conn| serve_one(conn, &worker, &digest));
    fail(EX_SOFTWARE, &format!("zygote: listening socket failed: {e}"))
}

fn mem_mib(s: &EngineSettings) -> u32 {
    u32::try_from(s.pooling_max_memory_size() >> 20).unwrap_or(aegis_wasm::engine::MEMORY_MIB_MIN)
}

/// MUTANT no-limiter (`mutants` builds): the pooled slot is sized at the F8 maximum, so the per-request
/// ResourceLimiter is the only memory bound the mutant removes (with the pool at `memory_mib` the pool itself would
/// still cap growth and the mutant could not be told apart from the golden worker).
#[cfg(feature = "mutants")]
pub(crate) fn mutant_memory_mib(requested: Option<u32>) -> Option<u32> {
    use aegis_wasm::abi::mutant::{self, Mutant};
    if mutant::is(Mutant::NoLimiter) { Some(aegis_wasm::engine::MEMORY_MIB_MAX) } else { requested }
}

#[cfg(not(feature = "mutants"))]
pub(crate) fn mutant_memory_mib(requested: Option<u32>) -> Option<u32> {
    requested
}

/// MUTANT no-fuel-no-epoch (`mutants` builds): no `ITIMER_REAL` in the child either.
#[cfg(feature = "mutants")]
fn mutant_spec(spec: Spec) -> Spec {
    use aegis_wasm::abi::mutant::{self, Mutant};
    if mutant::is(Mutant::NoFuelNoEpoch) { spec.mutant_no_deadline() } else { spec }
}

#[cfg(not(feature = "mutants"))]
fn mutant_spec(spec: Spec) -> Spec {
    spec
}

/// Whether the child re-arms its wall bound per request (every build but the no-fuel-no-epoch mutant).
#[cfg(feature = "mutants")]
fn arms_wall_timer() -> bool {
    !aegis_wasm::abi::mutant::is(aegis_wasm::abi::mutant::Mutant::NoFuelNoEpoch)
}

#[cfg(not(feature = "mutants"))]
fn arms_wall_timer() -> bool {
    true
}

/// The child side of one connection: `ready` (and `layout`), then exactly one request.
fn serve_one(conn: OwnedFd, worker: &F14Worker, digest: &cwasm::Digest) -> i32 {
    let mut session = worker.session(UnixStream::from(conn));
    if !session.send(&frame::ready(digest)) || !layout_frame(&mut session) {
        return EXIT_IO;
    }
    let arm = |l: &RequestLimits| {
        !arms_wall_timer() || zygote::arm_wall_timer(Some(Duration::from_millis(l.wall_ms()))).is_ok()
    };
    match session.serve_one(arm) {
        Served::Answered { .. } | Served::Cancelled { .. } => 0,
        Served::Closed(Closed::Decode) => EXIT_DECODE,
        Served::Closed(Closed::Limits) => EXIT_LIMITS,
        Served::Closed(_) => EXIT_IO,
    }
}

/// F14 `layout` frame `[22, 0, load-base, pid]` (D8): test-hooks and mutants builds only. The load base is the
/// address of a function of this binary, which moves with every execve (PIE + ASLR) and is inherited across fork.
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

    // The F14 frame codec moved to aegis_wasm::abi::frame (tests: crates/aegis-wasm/tests/abi.rs).
    #[test]
    fn sha256_hex_is_strict() {
        assert_eq!(parse_hex(&"ab".repeat(32)).map(|d| d[0]), Some(0xab));
        assert!(parse_hex(&"AB".repeat(32)).is_none());
        assert!(parse_hex(&"ab".repeat(31)).is_none());
    }
}
