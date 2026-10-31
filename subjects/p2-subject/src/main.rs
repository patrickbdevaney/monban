//! p2-subject: the P2 isolation code of aegis-iso and aegis-wasm over the oracles' subject protocols.
//!
//! Usage:
//!   `p2-subject probe --path forkwasm|cordon [--stage zygote] --probe <name> --allow-dir <dir> [--target <path>]
//!   [--fd <n>] [--port <p>]`: the syscall-negative probe protocol (`oracles/syscall-negative/README.md`), run on
//!   the real `aegis_iso::sandbox::install` profiles (zygote, fork child, cordon).
//!
//!   `p2-subject serve forkwasm [--fuel N] [--wall-ms N] <guest.wasm> <data>`: the isolation-fi subject protocol
//!   (`oracles/isolation-fi/README.md`) on the real fork+Wasm path. fd 3 is the oracle's listening socket.
//!
//!   `p2-subject forkcost [--n N] [--fuel N] <guest.wasm> <data>`: per-fork cost of the D5 child filter (install
//!   time measured inside each child; fork+Wasm request with and without the child filter), one JSON line.
//!
//!   `serve cordon` arrives with P5-iso-003; until then it fails closed (exit 78).
//!
//! `serve forkwasm` follows the product layout (PLAN-5 D1, D4; spikes/q4-006): the first process acts as the
//! supervisor's compile step. It validates and compiles the guest (cached as a `.cwasm` in `$ISOFI_CWASM_DIR`, or
//! the temp dir), hashes the file, and re-executes itself with `--module <cwasm> --sha256 <hex>`, so the zygote
//! starts from the precompiled module with no compiler state (the isofi re-exec rule). The zygote loads the
//! `.cwasm` through the digest-checked `aegis_wasm::engine::cwasm::load`, resolves the module once
//! (`InstancePre`), installs `Profile::zygote` (Landlock: read-only beneath the data file's directory; seccomp) and
//! runs `aegis_iso::zygote::serve`: one fork child per connection with the child filter and `ITIMER_REAL` at
//! `--wall-ms`, a fresh instance per request with `--fuel`.
//!
//! In a `mutants` build `AEGIS_P2_MUTANT` selects a negative control: `no-fork` (the zygote serves in-process),
//! `no-deadline` (no `ITIMER_REAL`, fuel at the F8 ceiling), `reuse-instance` (a child keeps its instance and serves
//! up to 50 more connections). Unknown names leave the subject golden.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use aegis_iso::sandbox::{self, Forked, Profile};
use aegis_iso::zygote::{self, ChildEnd, Spec};
use aegis_wasm::engine::{FUEL_MAX, WALL_MS_MAX, cwasm};
use aegis_wasm::fi::{self, FiWorker};
use aegis_wasm::{EngineSettings, P2Engine, P2Limits, RequestLimits};

/// EX_CONFIG: the fail-closed exit code used across AEGIS.
const EX_CONFIG: u8 = 78;
/// EX_USAGE.
const EX_USAGE: u8 = 64;
/// EX_SOFTWARE.
const EX_SOFTWARE: u8 = 70;
/// isolation-fi's hostpoison marker: a corrupted host XORs every reply with this.
const CORRUPT_XOR: u32 = 0x5a5a;
/// reuse-instance mutant: further connections a child serves.
#[cfg(feature = "mutants")]
const REUSE_N: u32 = 50;

fn fail(code: u8, msg: &str) -> ExitCode {
    eprintln!("p2-subject: {msg}");
    ExitCode::from(code)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.split_first() {
        Some((cmd, rest)) if cmd == "probe" => ExitCode::from(aegis_iso::sandbox::probe::run(rest)),
        Some((cmd, rest)) if cmd == "serve" => match rest.split_first() {
            Some((p, r)) if p == "forkwasm" => serve_forkwasm(r),
            Some((p, _)) if p == "cordon" => {
                fail(EX_CONFIG, "serve cordon is not implemented yet (P5-iso-003); fail closed")
            }
            _ => fail(EX_USAGE, "usage: p2-subject serve forkwasm [--fuel N] [--wall-ms N] <guest.wasm> <data>"),
        },
        Some((cmd, rest)) if cmd == "forkcost" => forkcost(rest),
        _ => fail(
            EX_USAGE,
            "usage: p2-subject probe ... | serve forkwasm [--fuel N] [--wall-ms N] <guest> <data> | forkcost [--n N] <guest> <data>",
        ),
    }
}

// ------------------------------------------------------------------------------------------------ arguments
#[derive(Debug, Default, Clone)]
struct Args {
    guest: Option<String>,
    data: Option<String>,
    module: Option<String>,
    sha256: Option<String>,
    fuel: Option<u64>,
    wall_ms: Option<u64>,
    n: Option<usize>,
}

fn parse(v: &[String]) -> Result<Args, String> {
    let mut a = Args::default();
    let mut pos = Vec::new();
    let mut it = v.iter();
    while let Some(k) = it.next() {
        let mut val = || it.next().cloned().ok_or_else(|| format!("{k} needs a value"));
        match k.as_str() {
            "--module" => a.module = Some(val()?),
            "--sha256" => a.sha256 = Some(val()?),
            "--fuel" => a.fuel = Some(val()?.parse().map_err(|_| "--fuel: not a number".to_string())?),
            "--wall-ms" => a.wall_ms = Some(val()?.parse().map_err(|_| "--wall-ms: not a number".to_string())?),
            "--n" => a.n = Some(val()?.parse().map_err(|_| "--n: not a number".to_string())?),
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            s => pos.push(s.to_string()),
        }
    }
    let mut p = pos.into_iter();
    a.guest = p.next();
    a.data = p.next();
    if p.next().is_some() {
        return Err("too many arguments".into());
    }
    Ok(a)
}

/// Re-exec argv: the original options plus `--module`/`--sha256`.
fn reexec_args(a: &Args, module: &Path, hex: &str) -> Vec<String> {
    let mut v = vec!["--module".to_string(), module.display().to_string(), "--sha256".to_string(), hex.to_string()];
    if let Some(f) = a.fuel {
        v.extend(["--fuel".to_string(), f.to_string()]);
    }
    if let Some(w) = a.wall_ms {
        v.extend(["--wall-ms".to_string(), w.to_string()]);
    }
    if let Some(n) = a.n {
        v.extend(["--n".to_string(), n.to_string()]);
    }
    v.extend(a.guest.iter().cloned());
    v.extend(a.data.iter().cloned());
    v
}

fn parse_hex(s: &str) -> Option<cwasm::Digest> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut d = [0u8; 32];
    for (i, out) in d.iter_mut().enumerate() {
        let pair = s.get(2 * i..2 * i + 2)?;
        *out = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(d)
}

// ------------------------------------------------------------------------------------------------ compile stage
fn engine() -> Result<P2Engine, String> {
    P2Engine::new(EngineSettings::defaults(false)).map_err(|e| e.to_string())
}

/// The compile step (the supervisor's role in the product): compile the guest once into the cache directory and
/// return the `.cwasm` path with the sha256 of the file as written.
fn compile_cached(guest: &Path) -> Result<(PathBuf, String), String> {
    let wasm = std::fs::read(guest).map_err(|e| format!("read {}: {e}", guest.display()))?;
    let dir = std::env::var_os("ISOFI_CWASM_DIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    // Keyed by the guest bytes and this binary's engine settings (fixed defaults), so a stale artifact for another
    // guest or configuration is never picked up; wasmtime re-checks engine compatibility at load anyway.
    let eng = engine()?;
    let key_src = format!("{}|{}", cwasm::hex(&cwasm::sha256(&wasm)), eng.settings().to_json());
    let key = cwasm::hex(&cwasm::sha256(key_src.as_bytes()));
    let path = dir.join(format!("p2-subject-fi-{}.cwasm", key.get(..32).unwrap_or(&key)));
    if !path.exists() {
        let bytes = fi::compile(&eng, &wasm).map_err(|e| format!("compile: {e}"))?;
        let tmp = dir.join(format!(".p2-subject-fi-{}.{}", key.get(..32).unwrap_or(&key), std::process::id()));
        std::fs::write(&tmp, &bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &path).map_err(|e| format!("rename {}: {e}", path.display()))?;
    }
    let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok((path, cwasm::hex(&cwasm::sha256(&bytes))))
}

/// Stage 1: compile, hash, re-exec as the zygote. Returns only on error.
fn reexec_with_module(cmd: &str, a: &Args) -> ExitCode {
    let Some(guest) = a.guest.as_deref() else { return fail(EX_USAGE, "missing <guest.wasm>") };
    let (path, hex) = match compile_cached(Path::new(guest)) {
        Ok(x) => x,
        Err(e) => return fail(EX_CONFIG, &e),
    };
    let mut argv = vec![];
    if cmd == "forkwasm" {
        argv.extend(["serve".to_string(), "forkwasm".to_string()]);
    } else {
        argv.push(cmd.to_string());
    }
    argv.extend(reexec_args(a, &path, &hex));
    let err = std::process::Command::new("/proc/self/exe").args(&argv).exec();
    fail(EX_SOFTWARE, &format!("re-exec: {err}"))
}

/// Stage 2 setup: the digest-checked load and the pre-resolved module.
fn load_worker(a: &Args) -> Result<FiWorker, String> {
    let (Some(module), Some(hex)) = (a.module.as_deref(), a.sha256.as_deref()) else {
        return Err("missing --module/--sha256".into());
    };
    let digest = parse_hex(hex).ok_or("--sha256: not 64 hex digits")?;
    let eng = engine()?;
    let m = cwasm::load(&eng, Path::new(module), &digest).map_err(|e| e.to_string())?;
    FiWorker::new(&eng, &m)
}

fn limits(fuel: u64, wall_ms: u64) -> Result<RequestLimits, String> {
    P2Limits::new(fuel, wall_ms, aegis_wasm::engine::MEMORY_MIB_DEFAULT)
        .map(RequestLimits::from)
        .map_err(|e| e.to_string())
}

// ------------------------------------------------------------------------------------------------ serve forkwasm
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mutant {
    None,
    #[cfg(feature = "mutants")]
    NoFork,
    #[cfg(feature = "mutants")]
    NoDeadline,
    #[cfg(feature = "mutants")]
    ReuseInstance,
}

fn mutant() -> Mutant {
    #[cfg(feature = "mutants")]
    {
        match std::env::var("AEGIS_P2_MUTANT").as_deref() {
            Ok("no-fork") => return Mutant::NoFork,
            Ok("no-deadline") => return Mutant::NoDeadline,
            Ok("reuse-instance") => return Mutant::ReuseInstance,
            _ => {}
        }
    }
    Mutant::None
}

fn read_req(s: &mut UnixStream) -> std::io::Result<(u32, u32)> {
    let mut b = [0u8; 8];
    s.read_exact(&mut b)?;
    let [a0, a1, a2, a3, f0, f1, f2, f3] = b;
    Ok((u32::from_le_bytes([a0, a1, a2, a3]), u32::from_le_bytes([f0, f1, f2, f3])))
}

fn reply(s: &mut UnixStream, id: u32, h: u32) -> std::io::Result<()> {
    let h = if fi::host_corrupted() { h ^ CORRUPT_XOR } else { h };
    let mut o = [0u8; 8];
    let (l, r) = o.split_at_mut(4);
    l.copy_from_slice(&id.to_le_bytes());
    r.copy_from_slice(&h.to_le_bytes());
    s.write_all(&o)
}

/// The host's per-request I/O stand-in: read the data file once.
fn host_io(p: &Path) -> std::io::Result<usize> {
    let mut f = std::fs::File::open(p)?;
    let mut d = Vec::with_capacity(4096);
    f.read_to_end(&mut d)
}

fn serve_forkwasm(rest: &[String]) -> ExitCode {
    let a = match parse(rest) {
        Ok(a) => a,
        Err(e) => return fail(EX_USAGE, &e),
    };
    if a.module.is_none() {
        return reexec_with_module("forkwasm", &a);
    }
    let Some(data) = a.data.as_deref() else { return fail(EX_USAGE, "missing <data>") };
    // Absolute: Landlock is scoped to the data file's directory.
    let data = match std::fs::canonicalize(data) {
        Ok(d) => d,
        Err(e) => return fail(EX_USAGE, &format!("<data>: {e}")),
    };
    let Some(data_dir) = data.parent().map(Path::to_path_buf) else { return fail(EX_USAGE, "<data> has no parent") };
    let mutant = mutant();
    let wall_ms = a.wall_ms.unwrap_or(aegis_wasm::engine::WALL_MS_DEFAULT);
    let fuel = a.fuel.unwrap_or(aegis_wasm::engine::FUEL_DEFAULT);
    let mut spec = Spec::fork_per_connection(Duration::from_millis(wall_ms));
    let mut lim = match limits(fuel, wall_ms) {
        Ok(l) => l,
        Err(e) => return fail(EX_CONFIG, &e),
    };
    #[cfg(feature = "mutants")]
    match mutant {
        Mutant::NoFork => spec = spec.mutant_no_fork(),
        Mutant::NoDeadline => {
            // MUTANT: no ITIMER_REAL; fuel cannot be switched off in the product engine, so it goes to the F8 ceiling.
            spec = spec.mutant_no_deadline();
            lim = match limits(FUEL_MAX, WALL_MS_MAX) {
                Ok(l) => l,
                Err(e) => return fail(EX_CONFIG, &e),
            };
        }
        Mutant::ReuseInstance => spec = spec.mutant_reuse_child(REUSE_N),
        Mutant::None => {}
    }
    let _ = (&mut spec, &mut lim, FUEL_MAX, WALL_MS_MAX);
    let worker = match load_worker(&a) {
        Ok(w) => w,
        Err(e) => return fail(EX_CONFIG, &e),
    };
    let listener = match zygote::adopt_listener() {
        Ok(l) => l,
        Err(e) => return fail(EX_CONFIG, &format!("fd 3 is not the listening socket: {e}")),
    };
    let inst = match sandbox::install(&Profile::zygote(vec![data_dir])) {
        Ok(i) => i,
        Err(e) => {
            let code = if matches!(e, sandbox::SandboxError::LandlockAbiTooOld(_)) { EX_CONFIG } else { EX_SOFTWARE };
            return fail(code, &format!("zygote sandbox: {e}"));
        }
    };
    eprintln!(
        "p2-subject: forkwasm zygote pid {} ready (landlock abi {:?}, filter {} insns, wall {:?}, fuel {}, mutant {:?})",
        std::process::id(),
        inst.landlock.as_ref().map(|l| l.abi),
        inst.filter_len,
        spec.wall(),
        lim.fuel(),
        mutant
    );
    let mut kept: Option<fi::FiInstance> = None;
    let handler = move |conn: OwnedFd| -> i32 {
        let mut s = UnixStream::from(conn);
        let Ok((id, fault)) = read_req(&mut s) else { return 3 };
        if host_io(&data).is_err() {
            return 4;
        }
        let r = if mutant_reuse(mutant) {
            call_reused(&worker, &mut kept, lim, id, fault)
        } else {
            worker.call(lim, id, fault)
        };
        match r {
            Ok(h) => {
                if reply(&mut s, id, h).is_ok() {
                    0
                } else {
                    6
                }
            }
            Err(_) => 1, // trap: close without replying
        }
    };
    let e = zygote::serve(listener, spec, handler);
    fail(EX_SOFTWARE, &format!("listening socket failed: {e}"))
}

fn mutant_reuse(m: Mutant) -> bool {
    #[cfg(feature = "mutants")]
    if m == Mutant::ReuseInstance {
        return true;
    }
    let _ = m;
    false
}

/// MUTANT reuse-instance: the child keeps the instance of its first request for the following ones.
#[cfg(feature = "mutants")]
fn call_reused(
    w: &FiWorker,
    kept: &mut Option<fi::FiInstance>,
    lim: RequestLimits,
    id: u32,
    fault: u32,
) -> Result<u32, aegis_wasm::TrapKind> {
    if kept.is_none() {
        *kept = Some(w.instance(lim)?);
    }
    match kept.as_mut() {
        Some(i) => w.call_on(i, lim, id, fault),
        None => Err(aegis_wasm::TrapKind::Wasm),
    }
}

#[cfg(not(feature = "mutants"))]
fn call_reused(
    w: &FiWorker,
    _kept: &mut Option<fi::FiInstance>,
    lim: RequestLimits,
    id: u32,
    fault: u32,
) -> Result<u32, aegis_wasm::TrapKind> {
    w.call(lim, id, fault)
}

// ------------------------------------------------------------------------------------------------ forkcost
fn pct(v: &mut [f64], p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let i = ((v.len() as f64 - 1.0) * p).round() as usize;
    v.get(i).copied().unwrap_or(f64::NAN)
}

fn us(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e6
}

/// Forks one child running `body`, waits for it, returns (parent-side wall time in us, how it ended).
fn timed_child(body: impl FnOnce() -> i32) -> Result<(f64, ChildEnd), String> {
    let t = Instant::now();
    match sandbox::fork().map_err(|e| format!("fork: {e}"))? {
        Forked::Child => sandbox::exit_now(body()),
        Forked::Parent(pid) => {
            let end = zygote::wait_child(pid).map_err(|e| format!("wait: {e}"))?;
            Ok((us(t), end))
        }
    }
}

fn forkcost(rest: &[String]) -> ExitCode {
    let a = match parse(rest) {
        Ok(a) => a,
        Err(e) => return fail(EX_USAGE, &e),
    };
    if a.module.is_none() {
        return reexec_with_module("forkcost", &a);
    }
    let Some(data) = a.data.as_deref().and_then(|d| std::fs::canonicalize(d).ok()) else {
        return fail(EX_USAGE, "missing or bad <data>");
    };
    let Some(data_dir) = data.parent().map(Path::to_path_buf) else { return fail(EX_USAGE, "<data> has no parent") };
    let n = a.n.unwrap_or(2000);
    let lim = match limits(a.fuel.unwrap_or(aegis_wasm::engine::FUEL_DEFAULT), 100) {
        Ok(l) => l,
        Err(e) => return fail(EX_CONFIG, &e),
    };
    let worker = match load_worker(&a) {
        Ok(w) => w,
        Err(e) => return fail(EX_CONFIG, &e),
    };
    // Read before the sandbox: /proc/loadavg is outside the Landlock read set afterwards.
    let la = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    if let Err(e) = sandbox::install(&Profile::zygote(vec![data_dir])) {
        return fail(EX_SOFTWARE, &format!("zygote sandbox: {e}"));
    }
    // warm the code paths
    for i in 0..200u32 {
        let _ = worker.call(lim, i, 0);
    }
    let (mut install, mut with_f, mut without_f) = (Vec::new(), Vec::new(), Vec::new());
    let mut bad = 0usize;
    for i in 0..u32::try_from(n).unwrap_or(u32::MAX) {
        // A: the child filter install alone, timed inside the child, reported through a pipe.
        let Ok((mut rd, mut wr)) = std::io::pipe() else { return fail(EX_SOFTWARE, "pipe") };
        let r = timed_child(|| {
            let t = Instant::now();
            let ok = sandbox::install(&Profile::child()).is_ok();
            let ns = u64::try_from(t.elapsed().as_nanos()).unwrap_or(u64::MAX);
            if !ok || wr.write_all(&ns.to_le_bytes()).is_err() {
                return 1;
            }
            0
        });
        drop(wr);
        let mut b = [0u8; 8];
        match (r, rd.read_exact(&mut b)) {
            (Ok((_, ChildEnd::Exited(0))), Ok(())) => install.push(u64::from_le_bytes(b) as f64 / 1e3),
            _ => bad += 1,
        }
        // B: fork + child filter + fresh instance + call + exit (the per-request path, minus the socket).
        match timed_child(|| {
            if sandbox::install(&Profile::child()).is_err() {
                return 1;
            }
            i32::from(worker.call(lim, i, 0).is_err())
        }) {
            Ok((t, ChildEnd::Exited(0))) => with_f.push(t),
            _ => bad += 1,
        }
        // C: the same without the child filter (the D5 delta).
        match timed_child(|| i32::from(worker.call(lim, i, 0).is_err())) {
            Ok((t, ChildEnd::Exited(0))) => without_f.push(t),
            _ => bad += 1,
        }
    }
    let p = |v: &mut Vec<f64>| format!("{{\"p50\":{:.1},\"p99\":{:.1},\"n\":{}}}", pct(v, 0.5), pct(v, 0.99), v.len());
    println!(
        "{{\"child_filter_install_us\":{},\"fork_wasm_with_child_filter_us\":{},\"fork_wasm_without_child_filter_us\":{},\"failures\":{bad},\"loadavg_at_start\":\"{}\"}}",
        p(&mut install),
        p(&mut with_f),
        p(&mut without_f),
        la.trim()
    );
    ExitCode::SUCCESS
}
