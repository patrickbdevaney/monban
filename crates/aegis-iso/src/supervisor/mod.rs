//! Supervisor side of the P2 workers (ARCHITECTURE §3.6 R-ISO-5; PLAN-5 D8): spawn a worker by execve with the
//! supervisor-held listening socket at fd 3, and replace a dead one by a fresh execve. There is no fork-from-template
//! path: every zygote or cordon starts from `execve` of the worker binary, so each one gets a new ASLR layout (the
//! BROP crash-oracle defence). Consumed by aegis-bin (feature `p2`, P5-bin-001).
//!
//! The worker's environment is cleared and only `AEGIS_P2_*` variables of the supervisor are passed through
//! (oracles/p2-e2e README: test-hooks Landlock override and mutant selection reach every worker).

mod sys;

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};

/// The environment-variable prefix passed through to workers.
pub const ENV_PREFIX: &str = "AEGIS_P2_";

/// How to exec a worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerCmd {
    /// Absolute path of the worker binary (`aegis-p2`).
    pub exe: PathBuf,
    /// Arguments after argv\[0\] (e.g. `zygote --module M --sha256 H`).
    pub args: Vec<OsString>,
    /// The worker's whole environment (see [`passthrough_env`]).
    pub env: Vec<(OsString, OsString)>,
}

impl WorkerCmd {
    /// A command with the `AEGIS_P2_*` variables of this process as its environment.
    pub fn new(exe: PathBuf, args: Vec<OsString>) -> Self {
        Self { exe, args, env: passthrough_env(std::env::vars_os()) }
    }
}

/// The `AEGIS_P2_*` subset of `vars`, in order.
pub fn passthrough_env(vars: impl IntoIterator<Item = (OsString, OsString)>) -> Vec<(OsString, OsString)> {
    vars.into_iter().filter(|(k, _)| k.as_bytes().starts_with(ENV_PREFIX.as_bytes())).collect()
}

/// Spawns `cmd` by execve with `listener` as fd 3 (not close-on-exec) and stdin on /dev/null. The worker's stdout
/// and stderr are inherited. Every other descriptor of this process is close-on-exec (Rust std opens them so).
pub fn spawn(cmd: &WorkerCmd, listener: BorrowedFd<'_>) -> io::Result<Child> {
    let mut c = Command::new(&cmd.exe);
    c.args(&cmd.args).env_clear().stdin(Stdio::null());
    for (k, v) in &cmd.env {
        c.env(k, v);
    }
    sys::listener_at_fd3(&mut c, listener.as_raw_fd());
    c.spawn()
}

/// What [`Supervised::check`] observed.
#[derive(Debug)]
pub enum Event {
    /// The worker is running.
    Running,
    /// The worker had exited with this status and a fresh execve replaced it (new pid).
    Respawned {
        /// The dead worker's exit status.
        status: ExitStatus,
        /// The replacement's pid.
        pid: u32,
    },
}

/// One supervised worker (a zygote, or one cordon): the listening socket stays with the supervisor across
/// respawns, so connections queue in the kernel while a replacement starts.
#[derive(Debug)]
pub struct Supervised {
    cmd: WorkerCmd,
    listener: OwnedFd,
    child: Child,
    respawns: u64,
}

impl Supervised {
    /// Spawns the first worker.
    pub fn start(cmd: WorkerCmd, listener: OwnedFd) -> io::Result<Self> {
        let child = spawn(&cmd, listener.as_fd())?;
        Ok(Self { cmd, listener, child, respawns: 0 })
    }

    /// The current worker's pid.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Replacements so far.
    pub fn respawns(&self) -> u64 {
        self.respawns
    }

    /// The listening socket workers inherit.
    pub fn listener(&self) -> BorrowedFd<'_> {
        self.listener.as_fd()
    }

    /// Non-blocking: if the worker has exited, reap it and execve a replacement.
    pub fn check(&mut self) -> io::Result<Event> {
        match self.child.try_wait()? {
            None => Ok(Event::Running),
            Some(status) => {
                self.child = spawn(&self.cmd, self.listener.as_fd())?;
                self.respawns = self.respawns.saturating_add(1);
                Ok(Event::Respawned { status, pid: self.child.id() })
            }
        }
    }

    /// Kills the current worker (SIGKILL to its explicit pid) and reaps it; the next [`Supervised::check`]
    /// respawns it.
    pub fn kill(&mut self) -> io::Result<()> {
        self.child.kill()?;
        self.child.wait().map(drop)
    }

    /// Stops supervising: kills and reaps the worker, returns the listening socket.
    pub fn shutdown(mut self) -> OwnedFd {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.listener
    }
}

/// Lossless argument helper: `OsString` from anything string-like.
pub fn arg(s: impl AsRef<OsStr>) -> OsString {
    s.as_ref().to_os_string()
}
