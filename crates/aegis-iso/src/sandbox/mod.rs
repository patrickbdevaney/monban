//! The P2 process sandbox (ARCHITECTURE §3.6 R-ISO-4/5; PLAN-5 D2, D4, D5).
//!
//! No namespaces (D2: unprivileged user namespaces carry no capabilities on these hosts). A zygote or cordon is an
//! exec-spawned process that calls [`install`] once, single-threaded, before it serves:
//!
//! 1. refuse unless the process has exactly one thread (Landlock and a non-TSYNC filter bind the calling thread);
//! 2. `PR_SET_NO_NEW_PRIVS`;
//! 3. rlimits: `RLIMIT_CORE` = 0, `RLIMIT_NOFILE` = the profile's bound, `RLIMIT_NPROC` when the profile sets one;
//! 4. `PR_SET_DUMPABLE` = 0 (`/proc/<pid>` becomes root-owned, no core, no ptrace attach);
//! 5. Landlock, ABI ≥ 4 or refuse: read-only beneath the profile's paths, TCP bind/connect with no rule;
//! 6. the seccomp filter of [`filter`] (zygote or cordon layout);
//! 7. read back: NO_NEW_PRIVS = 1 and `PR_GET_DUMPABLE` = 0, else fail.
//!
//! A fork+Wasm child calls [`install`] with [`Profile::child`]: `RLIMIT_NPROC` = 0, then the small child filter
//! stacked on the inherited zygote filter (Landlock, dumpable=0 and NO_NEW_PRIVS are inherited across fork and
//! read back). Any failed step returns an error; the caller must exit without serving (fail closed).

pub mod filter;
pub mod landlock;
#[cfg(feature = "test-hooks")]
pub mod probe;
mod sys;

use std::fmt;
use std::io;
use std::path::PathBuf;

use rustix::process::{DumpableBehavior, Resource, Rlimit};

pub use filter::Kind as Stage;
pub use sys::{Forked, exit_now, fork};

/// Default `RLIMIT_NOFILE` for a zygote or cordon (the isofi reference value).
pub const DEFAULT_NOFILE: u64 = 256;

/// What a process is about to become.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// Zygote, cordon or fork child.
    pub stage: Stage,
    /// Absolute paths granted read access (module and data paths). Ignored for [`Stage::Child`] (inherited).
    pub read_paths: Vec<PathBuf>,
    /// `RLIMIT_NOFILE` (soft = hard).
    pub nofile: u64,
    /// `RLIMIT_NPROC` (soft = hard), if set. NPROC counts every process of the real uid, so a zygote or cordon
    /// sharing a uid with other processes cannot get a small value; the child always gets 0.
    pub nproc: Option<u64>,
}

impl Profile {
    /// The fork+Wasm zygote: may fork, may stack the child filter.
    pub fn zygote(read_paths: Vec<PathBuf>) -> Self {
        Self { stage: Stage::Zygote, read_paths, nofile: DEFAULT_NOFILE, nproc: None }
    }
    /// A per-principal cordon: threads only, no fork.
    pub fn cordon(read_paths: Vec<PathBuf>) -> Self {
        Self { stage: Stage::Cordon, read_paths, nofile: DEFAULT_NOFILE, nproc: None }
    }
    /// A fork+Wasm child (after fork, before guest code).
    pub fn child() -> Self {
        Self { stage: Stage::Child, read_paths: Vec::new(), nofile: DEFAULT_NOFILE, nproc: Some(0) }
    }
}

/// What [`install`] put in place (recorded by callers and the probe).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// The stage installed.
    pub stage: Stage,
    /// Landlock as enforced by this call (`None` for a child: inherited from the zygote).
    pub landlock: Option<landlock::Enforced>,
    /// Instructions in the loaded seccomp program.
    pub filter_len: usize,
}

/// Why the sandbox could not be installed. Every variant means "do not serve".
#[derive(Debug)]
pub enum SandboxError {
    /// Not x86_64 Linux: no filter exists for this target.
    UnsupportedTarget,
    /// The process has more than one thread (count given) or the count could not be read.
    NotSingleThreaded(Option<usize>),
    /// `PR_SET_NO_NEW_PRIVS` failed or did not read back as set.
    NoNewPrivs(Option<io::Error>),
    /// An rlimit could not be set.
    Rlimit(&'static str, io::Error),
    /// `PR_SET_DUMPABLE` failed or did not read back as 0.
    Dumpable(Option<io::Error>),
    /// Landlock is absent or disabled (errno).
    LandlockUnavailable(i32),
    /// Landlock ABI below [`landlock::MIN_ABI`] (D2: P2 refused).
    LandlockAbiTooOld(u32),
    /// A Landlock syscall failed.
    Landlock(&'static str, io::Error),
    /// A read path is unusable.
    Path(PathBuf, &'static str),
    /// A read path could not be opened (errno).
    PathOpen(PathBuf, i32),
    /// The filter could not be laid out.
    Filter(filter::FilterError),
    /// The seccomp filter could not be loaded.
    Seccomp(io::Error),
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedTarget => write!(f, "sandbox: unsupported target (x86_64 Linux only)"),
            Self::NotSingleThreaded(n) => {
                write!(f, "sandbox: install needs a single-threaded process (threads: {n:?})")
            }
            Self::NoNewPrivs(e) => write!(f, "sandbox: PR_SET_NO_NEW_PRIVS failed ({e:?})"),
            Self::Rlimit(r, e) => write!(f, "sandbox: setrlimit({r}) failed: {e}"),
            Self::Dumpable(e) => write!(f, "sandbox: PR_SET_DUMPABLE=0 failed or did not stick ({e:?})"),
            Self::LandlockUnavailable(e) => write!(f, "sandbox: Landlock unavailable (errno {e}); P2 refused"),
            Self::LandlockAbiTooOld(a) => {
                write!(f, "sandbox: Landlock ABI {a} < {}; P2 refused (PLAN-5 D2)", landlock::MIN_ABI)
            }
            Self::Landlock(s, e) => write!(f, "sandbox: landlock {s} failed: {e}"),
            Self::Path(p, why) => write!(f, "sandbox: read path {}: {why}", p.display()),
            Self::PathOpen(p, e) => write!(f, "sandbox: read path {}: open failed (errno {e})", p.display()),
            Self::Filter(e) => write!(f, "sandbox: filter layout: {e:?}"),
            Self::Seccomp(e) => write!(f, "sandbox: seccomp load failed: {e}"),
        }
    }
}

impl std::error::Error for SandboxError {}

/// Threads of the calling process, from `/proc/self/task`.
fn thread_count() -> Option<usize> {
    std::fs::read_dir("/proc/self/task").ok().map(|d| d.flatten().count())
}

fn set_rlimit(name: &'static str, r: Resource, v: u64) -> Result<(), SandboxError> {
    rustix::process::setrlimit(r, Rlimit { current: Some(v), maximum: Some(v) })
        .map_err(|e| SandboxError::Rlimit(name, e.into()))
}

fn read_back() -> Result<(), SandboxError> {
    match rustix::thread::no_new_privs() {
        Ok(true) => {}
        Ok(false) => return Err(SandboxError::NoNewPrivs(None)),
        Err(e) => return Err(SandboxError::NoNewPrivs(Some(e.into()))),
    }
    match rustix::process::dumpable_behavior() {
        Ok(DumpableBehavior::NotDumpable) => Ok(()),
        Ok(_) => Err(SandboxError::Dumpable(None)),
        Err(e) => Err(SandboxError::Dumpable(Some(e.into()))),
    }
}

/// Installs `profile` on the calling process. Irreversible; on `Err` the process is partly restricted and must
/// exit without serving.
pub fn install(profile: &Profile) -> Result<Installed, SandboxError> {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err(SandboxError::UnsupportedTarget);
    }
    let prog = filter::program(profile.stage).map_err(SandboxError::Filter)?;
    if profile.stage == Stage::Child {
        // Inherited from the zygote across fork; verify before stacking.
        read_back()?;
        set_rlimit("NPROC", Resource::Nproc, profile.nproc.unwrap_or(0))?;
        sys::seccomp_set_filter(&prog).map_err(SandboxError::Seccomp)?;
        return Ok(Installed { stage: profile.stage, landlock: None, filter_len: prog.len() });
    }
    match thread_count() {
        Some(1) => {}
        n => return Err(SandboxError::NotSingleThreaded(n)),
    }
    rustix::thread::set_no_new_privs(true).map_err(|e| SandboxError::NoNewPrivs(Some(e.into())))?;
    set_rlimit("CORE", Resource::Core, 0)?;
    set_rlimit("NOFILE", Resource::Nofile, profile.nofile)?;
    if let Some(n) = profile.nproc {
        set_rlimit("NPROC", Resource::Nproc, n)?;
    }
    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|e| SandboxError::Dumpable(Some(e.into())))?;
    let ll = landlock::enforce(&profile.read_paths)?;
    sys::seccomp_set_filter(&prog).map_err(SandboxError::Seccomp)?;
    read_back()?;
    Ok(Installed { stage: profile.stage, landlock: Some(ll), filter_len: prog.len() })
}
