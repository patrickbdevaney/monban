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
//! Per connection the child sends the F14 `ready` frame (and, in `test-hooks`/`mutants` builds, the `layout` frame),
//! reads one `request` and its `body-chunk`s, re-arms `ITIMER_REAL` at the request's effective `wall-ms`, runs
//! `handle()` in a fresh instance with `min(frame limits, boot ceilings)`, sends `resp-end` and exits. Any frame that
//! does not decode, is oversized or out of order ends the child without a reply (the supervisor sees a worker death).

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use aegis_iso::sandbox::{self, Profile, SandboxError};
use aegis_iso::zygote::{self, Spec};
use aegis_wasm::engine::{FUEL_MAX, WALL_MS_MAX, cwasm};
use aegis_wasm::{EngineSettings, Outcome, P2Engine, P2Limits, RequestLimits, Worker};

/// EX_USAGE.
const EX_USAGE: u8 = 64;
/// EX_SOFTWARE.
const EX_SOFTWARE: u8 = 70;
/// EX_CONFIG: fail-closed boot.
const EX_CONFIG: u8 = 78;
/// F14 `guest-api-version`.
const GUEST_API_VERSION: u64 = 1;
/// F8 `p2.frame_max_bytes` default (64 KiB): the largest frame this worker reads.
pub const FRAME_MAX: usize = 64 << 10;
/// Child exit codes (diagnostics only; the supervisor treats any death without `resp-end` as Error).
const EXIT_DECODE: i32 = 2;
const EXIT_IO: i32 = 3;
const EXIT_LIMITS: i32 = 4;

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
    let settings = match settings(a.mpk, a.memory_mib, a.pool_slots) {
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
    let worker = match Worker::new(&engine, &m) {
        Ok(w) => w,
        Err(e) => return fail(EX_CONFIG, &format!("zygote: {e}")),
    };
    drop(m);
    let ceiling = match P2Limits::new(FUEL_MAX, WALL_MS_MAX, mem_mib(&settings)) {
        Ok(c) => c,
        Err(e) => return fail(EX_CONFIG, &format!("zygote: {e}")),
    };
    let listener = match zygote::adopt_listener() {
        Ok(l) => l,
        Err(e) => return fail(EX_CONFIG, &format!("zygote: fd 3 is not the listening socket: {e}")),
    };
    if let Err(e) = sandbox::install(&Profile::zygote(Vec::new())) {
        let code = if matches!(e, SandboxError::LandlockAbiTooOld(_)) { EX_CONFIG } else { EX_SOFTWARE };
        return fail(code, &format!("zygote: {e}"));
    }
    let spec = Spec::fork_per_connection(Duration::from_millis(WALL_MS_MAX));
    let e = zygote::serve(listener, spec, |conn| serve_one(conn, &worker, &digest, &ceiling));
    fail(EX_SOFTWARE, &format!("zygote: listening socket failed: {e}"))
}

fn mem_mib(s: &EngineSettings) -> u32 {
    u32::try_from(s.pooling_max_memory_size() >> 20).unwrap_or(aegis_wasm::engine::MEMORY_MIB_MIN)
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

/// Decodes and validates an F14 `req-head` (the worker copies it verbatim to the guest once the F14 host functions
/// exist, P5-wasm-002; here it is only checked).
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

/// A decoded `body-chunk` for `rid`: `Some(last)`. A `cancel` for `rid`, another tag or another req-id: `None`.
fn body_chunk(frame: &[u8], rid: u64) -> Option<bool> {
    let mut d = Dec { b: frame };
    if d.u()? != 1 || d.u()? != rid {
        return None;
    }
    d.bytes()?;
    let last = d.boolean()?;
    d.done().then_some(last)
}

/// Reads one SEQPACKET message; `None` on EOF, error or a message longer than [`FRAME_MAX`].
fn recv(s: &mut UnixStream, buf: &mut [u8]) -> Option<usize> {
    let n = s.read(buf).ok()?;
    // A message longer than the buffer is truncated to exactly its length: buf is FRAME_MAX + 1 bytes, so a full
    // buffer means the frame exceeded the cap.
    (n > 0 && n <= FRAME_MAX).then_some(n)
}

fn send(s: &mut UnixStream, e: Enc) -> bool {
    s.write(&e.0).is_ok_and(|n| n == e.0.len())
}

/// The child side of one connection.
fn serve_one(conn: OwnedFd, worker: &Worker, digest: &cwasm::Digest, ceiling: &P2Limits) -> i32 {
    let mut s = UnixStream::from(conn);
    if !send(&mut s, Enc::default().u(16).u(0).u(GUEST_API_VERSION).bytes(digest)) {
        return EXIT_IO;
    }
    if !layout_frame(&mut s) {
        return EXIT_IO;
    }
    let mut buf = vec![0u8; FRAME_MAX + 1];
    let Some(n) = recv(&mut s, &mut buf) else { return EXIT_IO };
    let Some((rid, lim)) = buf.get(..n).and_then(request) else { return EXIT_DECODE };
    loop {
        let Some(n) = recv(&mut s, &mut buf) else { return EXIT_IO };
        match buf.get(..n).and_then(|f| body_chunk(f, rid)) {
            Some(true) => break,
            Some(false) => {}
            None => return EXIT_DECODE, // cancel, another req-id, or a malformed frame
        }
    }
    let [fuel, wall_ms, memory_mib, ..] = lim;
    let Some(requested) = u32::try_from(memory_mib).ok().and_then(|m| P2Limits::new(fuel, wall_ms, m).ok()) else {
        return EXIT_LIMITS;
    };
    let limits = RequestLimits::clamped(&requested, ceiling);
    if zygote::arm_wall_timer(Some(Duration::from_millis(limits.wall_ms()))).is_err() {
        return EXIT_IO;
    }
    let report = worker.handle(limits);
    let end = match report.outcome {
        Outcome::Returned(code) => Enc::default().u(19).u(rid).u(0).u(u64::from(code)),
        Outcome::Trapped(t) => Enc::default().u(19).u(rid).u(1).u(u64::from(t.code())),
    };
    if send(&mut s, end.u(report.fuel_used)) { 0 } else { EXIT_IO }
}

/// F14 `layout` frame `[22, 0, load-base, pid]` (D8): test-hooks and mutants builds only. The load base is the
/// address of a function of this binary, which moves with every execve (PIE + ASLR) and is inherited across fork.
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
        // method, path, opaque query, one header, body-len null
        Enc::default().bytes(b"GET").bytes(b"/x").u(0).bytes(b"q=1").u(1).bytes(b"accept").bytes(b"*/*").u(0)
    }

    #[test]
    fn decodes_a_request_and_refuses_malformed_ones() {
        let mut f = Enc::default().u(0).u(7);
        for v in [15_000_000u64, 100, 16, 10_000, 64, 4_194_304, 1_048_576, 65_536] {
            f = f.u(v);
        }
        let mut frame = f.0;
        frame.extend(head().0);
        assert_eq!(request(&frame).map(|(r, l)| (r, l[0], l[1])), Some((7, 15_000_000, 100)));
        // trailing byte, truncation, req-id 0, wrong tag
        let mut t = frame.clone();
        t.push(0);
        assert!(request(&t).is_none());
        assert!(request(frame.get(..frame.len() - 1).unwrap_or_default()).is_none());
        let mut z = frame.clone();
        if let Some(b) = z.get_mut(1) {
            *b = 0;
        }
        assert!(request(&z).is_none());
        let mut w = frame;
        if let Some(b) = w.get_mut(0) {
            *b = 1;
        }
        assert!(request(&w).is_none());
    }

    #[test]
    fn body_chunks_must_match_the_request() {
        let c = Enc::default().u(1).u(7).bytes(b"abc");
        let mut last = c.0.clone();
        last.push(1);
        assert_eq!(body_chunk(&last, 7), Some(true));
        assert_eq!(body_chunk(&last, 8), None);
        let mut bad = c.0;
        bad.push(2);
        assert_eq!(body_chunk(&bad, 7), None);
        assert_eq!(body_chunk(&Enc::default().u(3).u(7).0, 7), None); // cancel
    }

    #[test]
    fn varints_are_total() {
        assert_eq!(Dec { b: &[0xff; 11] }.u(), None);
        assert_eq!(Dec { b: &[0x80] }.u(), None);
        assert_eq!(Dec { b: &Enc::default().u(u64::MAX).0 }.u(), Some(u64::MAX));
        assert_eq!(parse_hex(&"ab".repeat(32)).map(|d| d[0]), Some(0xab));
        assert!(parse_hex(&"AB".repeat(32)).is_none());
    }
}
