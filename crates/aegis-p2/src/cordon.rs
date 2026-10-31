//! `aegis-p2 cordon --module <c.cwasm> --sha256 <hex> [--mpk] [--memory-mib N] [--pool-slots N] [--threads N]`
//! (PLAN-5 D1, D4, D5, D6, D8; F14 Part 2; ARCHITECTURE §3.6 single-tenant row as amended by q4-006;
//! oracles/hostile-modules README "worker command line").
//!
//! One cordon serves exactly one principal; the supervisor keys its cordon table by principal
//! (`aegis_iso::cordon::Registry`) and spawns each cordon by execve (`aegis_iso::supervisor`, D8), so a cordon never
//! sees a second principal's request. Boot (fail closed, exit 78 on any configuration error, before fd 3 is ever
//! accepted on):
//! 1. build the Engine from the same settings `aegis-p2 compile` used (`--pool-slots` = F8 `p2.cordon_slots`,
//!    default 64; `--mpk` = the D11 density option, reservation and guards unchanged);
//! 2. load the `.cwasm` through `aegis_wasm::engine::cwasm::load` (sha256 compared with `--sha256` before the one
//!    deserialize) and resolve it against the F14 Linker once (`InstancePre`);
//! 3. adopt fd 3 (the supervisor-held listening `SOCK_SEQPACKET` socket) and install `Profile::cordon` with no
//!    readable path while still single-threaded (Landlock, seccomp: threads only and no fork, dumpable=0,
//!    NO_NEW_PRIVS);
//! 4. start the epoch ticker (the wall bound, R-ISO-3) and `aegis_iso::cordon::serve` with `--threads` serving
//!    threads (default: the pool size, so every slot can be in use).
//!
//! Per connection the cordon sends the F14 `ready` frame (and, in `test-hooks`/`mutants` builds, the `layout`
//! frame with its own load base and pid, D8), then serves that connection's requests one after another (F14 allows
//! at most `cordon_slots` in flight; this worker keeps one per connection and runs connections in parallel): read
//! `request` and its `body-chunk`s, run `handle()` in a fresh instance with `min(frame limits, boot ceilings)` and
//! the epoch deadline at the effective `wall-ms` (a wall timeout is a trap, `resp-end` trap 2), send `resp-end`. A
//! `cancel` for the request drops it with nothing sent. A frame that does not decode, is oversized or out of order
//! closes the connection without a reply (the supervisor sees the connection end: Error ⇒ Deny, D17).
//!
//! The frame codec below mirrors zygote.rs (same F10 encoding rule, same checks). zygote.rs is another unit's file
//! and keeps its codec private, so the cordon carries its own copy; both decode the same F14 frames.

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::ExitCode;

use aegis_iso::cordon;
use aegis_iso::sandbox::{self, Profile, SandboxError};
use aegis_wasm::engine::{FUEL_MAX, WALL_MS_MAX, cwasm};
use aegis_wasm::{EpochTicker, Outcome, P2Engine, P2Limits, RequestLimits, Worker};

use crate::zygote::{FRAME_MAX, settings};

/// EX_USAGE.
const EX_USAGE: u8 = 64;
/// EX_SOFTWARE.
const EX_SOFTWARE: u8 = 70;
/// EX_CONFIG: fail-closed boot.
const EX_CONFIG: u8 = 78;
/// F14 `guest-api-version`.
const GUEST_API_VERSION: u64 = 1;

fn fail(code: u8, msg: &str) -> ExitCode {
    eprintln!("aegis-p2: {msg}");
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

/// Lower-case 64-hex-digit sha256.
fn parse_hex(s: &str) -> Option<cwasm::Digest> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    let mut d = [0u8; 32];
    for (i, out) in d.iter_mut().enumerate() {
        *out = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(d)
}

/// `aegis-p2 cordon ...`.
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
    let settings = match settings(a.mpk, a.memory_mib, a.pool_slots) {
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
    let worker = match Worker::new(&engine, &m) {
        Ok(w) => w,
        Err(e) => return fail(EX_CONFIG, &format!("cordon: {e}")),
    };
    drop(m);
    let mem = u32::try_from(settings.pooling_max_memory_size() >> 20).unwrap_or(aegis_wasm::engine::MEMORY_MIB_MIN);
    let ceiling = match P2Limits::new(FUEL_MAX, WALL_MS_MAX, mem) {
        Ok(c) => c,
        Err(e) => return fail(EX_CONFIG, &format!("cordon: {e}")),
    };
    let listener = match aegis_iso::zygote::adopt_listener() {
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
    let e = cordon::serve(listener, threads, move |conn| serve_conn(conn, &worker, &digest, &ceiling));
    drop(ticker);
    fail(EX_SOFTWARE, &format!("cordon: listening socket failed: {e}"))
}

// ------------------------------------------------------------------------------------------------ F14 frames
/// The F10 encoding rule's writer (postcard positional, unsigned LEB128 varints).
#[derive(Debug, Default)]
struct Enc(Vec<u8>);

impl Enc {
    fn u(mut self, mut n: u64) -> Self {
        loop {
            let b = u8::try_from(n & 0x7f).unwrap_or(0);
            n >>= 7;
            if n == 0 {
                self.0.push(b);
                return self;
            }
            self.0.push(b | 0x80);
        }
    }
    fn bytes(self, b: &[u8]) -> Self {
        let mut s = self.u(u64::try_from(b.len()).unwrap_or(u64::MAX));
        s.0.extend_from_slice(b);
        s
    }
}

/// Total reader over one frame: every method returns `None` on malformed input.
#[derive(Debug)]
struct Dec<'a> {
    b: &'a [u8],
}

impl<'a> Dec<'a> {
    fn u(&mut self) -> Option<u64> {
        let mut v: u64 = 0;
        for k in 0..10u32 {
            let (&x, rest) = self.b.split_first()?;
            self.b = rest;
            let part = u64::from(x & 0x7f);
            if k == 9 && part > 1 {
                return None; // overflow past 64 bits
            }
            v |= part << (7 * k);
            if x & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = usize::try_from(self.u()?).ok()?;
        if n > self.b.len() {
            return None;
        }
        let (s, rest) = self.b.split_at(n);
        self.b = rest;
        Some(s)
    }
    fn text(&mut self) -> Option<&'a str> {
        std::str::from_utf8(self.bytes()?).ok()
    }
    fn boolean(&mut self) -> Option<bool> {
        let (&x, rest) = self.b.split_first()?;
        self.b = rest;
        match x {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
    fn done(&self) -> bool {
        self.b.is_empty()
    }
}

/// Upper bound on list lengths in a req-head (each element takes at least one byte, so the frame cap bounds it).
fn bounded(n: u64, d: &Dec<'_>) -> Option<u64> {
    (n <= u64::try_from(d.b.len()).unwrap_or(0)).then_some(n)
}

/// Decodes and validates an F14 `req-head` (checked only, as in zygote.rs, until the F14 host functions hand it to
/// the guest).
fn req_head(d: &mut Dec<'_>) -> Option<()> {
    d.text()?; // method
    d.text()?; // path
    match d.u()? {
        0 => {
            d.bytes()?;
        }
        1 => {
            let n = bounded(d.u()?, d)?;
            for _ in 0..n {
                d.text()?;
                d.text()?;
            }
        }
        _ => return None,
    }
    let n = bounded(d.u()?, d)?;
    for _ in 0..n {
        d.text()?;
        d.bytes()?;
    }
    match d.u()? {
        0 => {}
        1 => {
            d.u()?;
        }
        _ => return None,
    }
    Some(())
}

/// A decoded `request` frame: (req-id, the eight limits).
fn request(frame: &[u8]) -> Option<(u64, [u64; 8])> {
    let mut d = Dec { b: frame };
    if d.u()? != 0 {
        return None;
    }
    let rid = d.u()?;
    if rid == 0 {
        return None;
    }
    let mut lim = [0u64; 8];
    for l in &mut lim {
        *l = d.u()?;
    }
    req_head(&mut d)?;
    d.done().then_some((rid, lim))
}

/// What a frame after `request` means for req-id `rid`.
#[derive(Debug, PartialEq, Eq)]
enum Next {
    /// A `body-chunk`; `true` when it is the last one.
    Chunk(bool),
    /// `cancel` for `rid`: drop the request, send nothing.
    Cancel,
}

fn next_frame(frame: &[u8], rid: u64) -> Option<Next> {
    let mut d = Dec { b: frame };
    let tag = d.u()?;
    if d.u()? != rid {
        return None;
    }
    match tag {
        1 => {
            d.bytes()?;
            let last = d.boolean()?;
            d.done().then_some(Next::Chunk(last))
        }
        3 => d.done().then_some(Next::Cancel),
        _ => None,
    }
}

/// Reads one SEQPACKET message; `None` on EOF, error or a message longer than [`FRAME_MAX`].
fn recv(s: &mut UnixStream, buf: &mut [u8]) -> Option<usize> {
    let n = s.read(buf).ok()?;
    // buf is FRAME_MAX + 1 bytes and a longer message is truncated to it, so a full buffer means over the cap.
    (n > 0 && n <= FRAME_MAX).then_some(n)
}

fn send(s: &mut UnixStream, e: Enc) -> bool {
    s.write(&e.0).is_ok_and(|n| n == e.0.len())
}

/// One connection: `ready` (+ `layout`), then its requests one after another until EOF or a bad frame.
fn serve_conn(conn: OwnedFd, worker: &Worker, digest: &cwasm::Digest, ceiling: &P2Limits) {
    let mut s = UnixStream::from(conn);
    if !send(&mut s, Enc::default().u(16).u(0).u(GUEST_API_VERSION).bytes(digest)) || !layout_frame(&mut s) {
        return;
    }
    let mut buf = vec![0u8; FRAME_MAX + 1];
    'requests: loop {
        let Some(n) = recv(&mut s, &mut buf) else { return };
        let Some((rid, lim)) = buf.get(..n).and_then(request) else { return };
        loop {
            let Some(n) = recv(&mut s, &mut buf) else { return };
            match buf.get(..n).and_then(|f| next_frame(f, rid)) {
                Some(Next::Chunk(true)) => break,
                Some(Next::Chunk(false)) => {}
                Some(Next::Cancel) => continue 'requests,
                None => return, // another req-id, an unknown tag or a malformed frame
            }
        }
        let [fuel, wall_ms, memory_mib, ..] = lim;
        let Some(requested) = u32::try_from(memory_mib).ok().and_then(|m| P2Limits::new(fuel, wall_ms, m).ok()) else {
            return;
        };
        let limits = RequestLimits::clamped(&requested, ceiling);
        // Fresh Store and instance; the epoch deadline at limits.wall_ms bounds it (the ticker runs).
        let report = worker.handle(limits);
        let end = match report.outcome {
            Outcome::Returned(code) => Enc::default().u(19).u(rid).u(0).u(u64::from(code)),
            Outcome::Trapped(t) => Enc::default().u(19).u(rid).u(1).u(u64::from(t.code())),
        };
        if !send(&mut s, end.u(report.fuel_used)) {
            return;
        }
    }
}

/// F14 `layout` frame `[22, 0, load-base, pid]` (D8): test-hooks and mutants builds only. The load base is the
/// address of a function of this binary, which moves with every execve (PIE + ASLR).
#[cfg(any(feature = "test-hooks", feature = "mutants"))]
fn layout_frame(s: &mut UnixStream) -> bool {
    let base = layout_frame as fn(&mut UnixStream) -> bool as usize;
    send(s, Enc::default().u(22).u(0).u(u64::try_from(base).unwrap_or(0)).u(u64::from(std::process::id())))
}

/// Golden builds send no layout frame.
#[cfg(not(any(feature = "test-hooks", feature = "mutants")))]
fn layout_frame(_s: &mut UnixStream) -> bool {
    true
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn head() -> Enc {
        Enc::default().bytes(b"GET").bytes(b"/x").u(0).bytes(b"q=1").u(1).bytes(b"accept").bytes(b"*/*").u(0)
    }

    #[test]
    fn decodes_requests_chunks_and_cancel() {
        let mut f = Enc::default().u(0).u(7);
        for v in [15_000_000u64, 100, 16, 10_000, 64, 4_194_304, 1_048_576, 65_536] {
            f = f.u(v);
        }
        let mut frame = f.0;
        frame.extend(head().0);
        assert_eq!(request(&frame).map(|(r, l)| (r, l[0], l[1])), Some((7, 15_000_000, 100)));
        let mut t = frame.clone();
        t.push(0);
        assert!(request(&t).is_none());
        let mut last = Enc::default().u(1).u(7).bytes(b"abc").0;
        last.push(1);
        assert_eq!(next_frame(&last, 7), Some(Next::Chunk(true)));
        assert_eq!(next_frame(&last, 8), None);
        assert_eq!(next_frame(&Enc::default().u(3).u(7).0, 7), Some(Next::Cancel));
        assert_eq!(next_frame(&Enc::default().u(3).u(8).0, 7), None);
        assert_eq!(next_frame(&Enc::default().u(2).u(7).u(0).0, 7), None);
    }

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
