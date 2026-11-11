//! The fork+Wasm zygote loop (PLAN-5 D1, D5, D6; ARCHITECTURE §3.6 R-ISO-3/5; spikes/q4-006 decision_effect).
//!
//! The zygote is an exec-spawned, single-threaded process. Before it calls [`serve`] it has loaded everything a
//! request needs and nothing a request may change (the Engine, the precompiled Module and an InstancePre, no
//! compiler state; see `monban-p2 zygote` and `p2-subject serve forkwasm`) and installed
//! [`crate::sandbox::Profile::zygote`]. [`serve`] then accepts on the supervisor-held listening socket (fd 3,
//! [`adopt_listener`]) and forks one child per connection. The child:
//!
//! 1. closes its copy of the listening socket (a child never accepts another connection, so a compromised child
//!    cannot pick up another principal's request);
//! 2. stacks the child filter ([`crate::sandbox::Profile::child`]: `RLIMIT_NPROC` = 0 and a filter that kills
//!    clone/fork/vfork/execve/execveat); if that fails it exits without serving (fail closed);
//! 3. arms `ITIMER_REAL` at the request's wall bound: SIGALRM's default action terminates it (R-ISO-3);
//! 4. runs the handler on the connection (a fresh Wasm instance per request is the handler's contract) and leaves
//!    through `_exit` with the handler's code.
//!
//! The zygote never runs guest code, closes its copy of the connection at once, and reaps exited children before
//! each accept (`waitpid(WNOHANG)`; no signal handler). A dead zygote is replaced by the supervisor with a fresh
//! execve, never a fork of a template ([`crate::supervisor`], D8). Residual (D9): children share the zygote's
//! address-space layout, which is inherent to fork; layout probing by crashing children is bounded by the
//! per-principal crash budget.

mod sys;

use std::io;
use std::os::fd::{AsFd, OwnedFd, RawFd};
use std::time::Duration;

use rustix::fs::FileType;
use rustix::net::SocketFlags;
use rustix::process::WaitOptions;

use crate::sandbox::{self, Forked, Profile};

/// The supervisor passes the listening socket as this descriptor (socket activation).
pub const LISTEN_FD: RawFd = 3;
/// Exit code of a child whose sandbox step failed (EX_SOFTWARE): it served nothing.
pub const EXIT_CHILD_SANDBOX: i32 = 70;
/// Exit code of a child whose wall-clock timer could not be armed: it served nothing.
pub const EXIT_CHILD_TIMER: i32 = 71;

/// Takes ownership of the inherited listening socket at [`LISTEN_FD`]. Fails unless fd 3 is open and a socket.
pub fn adopt_listener() -> io::Result<OwnedFd> {
    let fd = sys::adopt_inherited_fd(LISTEN_FD)?;
    let st = rustix::fs::fstat(&fd).map_err(io::Error::from)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::Socket {
        return Err(io::Error::from_raw_os_error(libc::ENOTSOCK));
    }
    Ok(fd)
}

/// Arms the calling process's one-shot `ITIMER_REAL` (`None` disarms). Exposed for the forked child of the
/// syscall probe and for measurement tools; [`serve`] arms it itself.
pub fn arm_wall_timer(wall: Option<Duration>) -> io::Result<()> {
    sys::set_itimer_real(wall)
}

/// How the zygote serves a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// One fork child per connection (the only golden mode).
    Fork,
    /// MUTANT no-fork: the zygote runs the handler in-process.
    #[cfg(feature = "mutants")]
    InProcess,
    /// MUTANT reuse-instance: a child that answered keeps serving up to this many further connections.
    #[cfg(feature = "mutants")]
    ReuseChild(u32),
}

/// What [`serve`] does per connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spec {
    wall: Option<Duration>,
    mode: Mode,
}

impl Spec {
    /// Golden: one fork child per connection, `ITIMER_REAL` at `wall` in each child. A zero `wall` is refused by
    /// the caller's config bounds (F8 `p2.wall_ms` >= 1); here it is raised to 1 ms so a deadline always exists.
    pub fn fork_per_connection(wall: Duration) -> Self {
        Self { wall: Some(wall.max(Duration::from_millis(1))), mode: Mode::Fork }
    }

    /// The wall bound armed in each child (`None` only in the no-deadline mutant).
    pub fn wall(&self) -> Option<Duration> {
        self.wall
    }

    /// MUTANT no-fork: the zygote serves every connection in-process (oracle negative control, never shipped).
    #[cfg(feature = "mutants")]
    pub fn mutant_no_fork(self) -> Self {
        Self { mode: Mode::InProcess, ..self }
    }

    /// MUTANT no-deadline: no `ITIMER_REAL` in the child (oracle negative control, never shipped).
    #[cfg(feature = "mutants")]
    pub fn mutant_no_deadline(self) -> Self {
        Self { wall: None, ..self }
    }

    /// MUTANT reuse-instance: a child that answered its first connection keeps the listening socket and serves up
    /// to `n` more connections with the same handler state (oracle negative control, never shipped).
    #[cfg(feature = "mutants")]
    pub fn mutant_reuse_child(self, n: u32) -> Self {
        Self { mode: Mode::ReuseChild(n), ..self }
    }
}

/// Reaps every exited child without blocking.
fn reap() {
    while let Ok(Some(_)) = rustix::process::waitpid(None, WaitOptions::NOHANG) {}
}

/// Accept errors after which the loop keeps going (transient or per-connection); anything else ends [`serve`].
fn transient(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(
            libc::EINTR
                | libc::ECONNABORTED
                | libc::EAGAIN
                | libc::EMFILE
                | libc::ENFILE
                | libc::ENOBUFS
                | libc::ENOMEM
                | libc::EPROTO
        )
    )
}

fn accept(listener: &OwnedFd) -> io::Result<OwnedFd> {
    rustix::net::accept_with(listener.as_fd(), SocketFlags::CLOEXEC).map_err(io::Error::from)
}

/// The child side of one connection. Never returns.
fn child<H: FnMut(OwnedFd) -> i32>(listener: OwnedFd, conn: OwnedFd, spec: Spec, handler: &mut H) -> ! {
    #[cfg(feature = "mutants")]
    if let Mode::ReuseChild(n) = spec.mode {
        child_reuse(listener, conn, spec, n, handler);
    }
    drop(listener);
    if sandbox::install(&Profile::child()).is_err() {
        sandbox::exit_now(EXIT_CHILD_SANDBOX);
    }
    if sys::set_itimer_real(spec.wall).is_err() {
        sandbox::exit_now(EXIT_CHILD_TIMER);
    }
    let code = handler(conn);
    sandbox::exit_now(code)
}

/// MUTANT reuse-instance child: serves the first connection, then up to `n` more from the listening socket.
#[cfg(feature = "mutants")]
fn child_reuse<H: FnMut(OwnedFd) -> i32>(listener: OwnedFd, conn: OwnedFd, spec: Spec, n: u32, handler: &mut H) -> ! {
    if sandbox::install(&Profile::child()).is_err() {
        sandbox::exit_now(EXIT_CHILD_SANDBOX);
    }
    if sys::set_itimer_real(spec.wall).is_err() {
        sandbox::exit_now(EXIT_CHILD_TIMER);
    }
    let first = handler(conn);
    if first != 0 {
        sandbox::exit_now(first);
    }
    for _ in 0..n {
        let _ = sys::set_itimer_real(None); // idle in accept: no wall bound
        let Ok(c) = accept(&listener) else { sandbox::exit_now(0) };
        if sys::set_itimer_real(spec.wall).is_err() {
            sandbox::exit_now(EXIT_CHILD_TIMER);
        }
        let code = handler(c);
        if code != 0 {
            sandbox::exit_now(code);
        }
    }
    sandbox::exit_now(0)
}

/// Serves connections on `listener` forever (see the module docs). Returns only on a non-transient accept error
/// (the listening socket is unusable); the caller exits and the supervisor respawns it by execve.
///
/// The caller must be single-threaded and have installed [`Profile::zygote`]: each child's
/// [`Profile::child`] install verifies the inherited sandbox and refuses (the child exits without serving) if it is
/// absent. `handler` runs in the child with the connection and returns the child's exit code.
pub fn serve<H: FnMut(OwnedFd) -> i32>(listener: OwnedFd, spec: Spec, mut handler: H) -> io::Error {
    loop {
        reap();
        let conn = match accept(&listener) {
            Ok(c) => c,
            Err(e) if transient(&e) => {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(e) => return e,
        };
        #[cfg(feature = "mutants")]
        if spec.mode == Mode::InProcess {
            let _ = handler(conn);
            continue;
        }
        match sandbox::fork() {
            Ok(Forked::Child) => child(listener, conn, spec, &mut handler),
            Ok(Forked::Parent(_)) => drop(conn),
            Err(_) => {
                // EAGAIN/ENOMEM: the client sees EOF (a failed request), the zygote lives on.
                drop(conn);
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

/// How a waited-for child ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildEnd {
    /// `_exit(code)`.
    Exited(i32),
    /// Killed by this signal.
    Signaled(i32),
}

/// Blocks until child `pid` ends (for measurement tools and the syscall probe; the zygote loop itself only reaps
/// with `WNOHANG`).
pub fn wait_child(pid: i32) -> io::Result<ChildEnd> {
    let p = rustix::process::Pid::from_raw(pid).ok_or_else(|| io::Error::from_raw_os_error(libc::ECHILD))?;
    match rustix::process::waitpid(Some(p), WaitOptions::empty()).map_err(io::Error::from)? {
        Some((_, st)) => match (st.exit_status(), st.terminating_signal()) {
            (Some(c), _) => Ok(ChildEnd::Exited(c)),
            (None, Some(s)) => Ok(ChildEnd::Signaled(s)),
            (None, None) => Err(io::Error::from_raw_os_error(libc::ECHILD)),
        },
        None => Err(io::Error::from_raw_os_error(libc::ECHILD)),
    }
}
