//! Raw syscalls of the zygote (PLAN-5 D4, DEVIATIONS X-14): every `unsafe` site of `zygote` lives here, each with a
//! `// SAFETY:` comment, counted by `cargo xtask unsafe-sites` (monban-iso cap 20).

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

/// Arms (or, with `None`, disarms) the one-shot `ITIMER_REAL` of the calling process. When it fires the kernel
/// sends SIGALRM, whose default action terminates the process: the wall-clock bound of a fork+Wasm child (R-ISO-3,
/// PLAN-5 D6). Nothing in the worker installs a SIGALRM handler.
pub(crate) fn set_itimer_real(wall: Option<Duration>) -> io::Result<()> {
    let d = wall.unwrap_or(Duration::ZERO);
    let secs = libc::time_t::try_from(d.as_secs()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let usecs = libc::suseconds_t::from(d.subsec_micros());
    // A zero value disarms; a non-zero duration under 1 us would round to zero, so it is raised to 1 us.
    let usecs = if wall.is_some() && secs == 0 && usecs == 0 { 1 } else { usecs };
    let t = libc::itimerval {
        it_interval: libc::timeval { tv_sec: 0, tv_usec: 0 },
        it_value: libc::timeval { tv_sec: secs, tv_usec: usecs },
    };
    // SAFETY: `t` is a live, fully initialised itimerval borrowed for the call; the old-value pointer is null, which
    // setitimer accepts (no old value is written).
    #[allow(unsafe_code)]
    let r = unsafe { libc::setitimer(libc::ITIMER_REAL, &raw const t, std::ptr::null_mut()) };
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Takes ownership of an inherited descriptor (socket activation: the supervisor-held listening socket arrives as
/// fd 3). The caller checks with [`fd_is_open`] first; this is called at most once per number per process.
pub(crate) fn adopt_inherited_fd(fd: RawFd) -> io::Result<OwnedFd> {
    if !fd_is_open(fd) {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    // SAFETY: `fd` is open (F_GETFD succeeded just above) and was inherited across execve from the supervisor,
    // which passes it for this process to own; nothing else in this process has wrapped it (the zygote and cordon
    // entry points adopt the listening fd exactly once, before any other code could open or wrap that number).
    #[allow(unsafe_code)]
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(owned)
}

/// Whether `fd` names an open descriptor (`fcntl(F_GETFD)` succeeds). Integer-only.
pub(crate) fn fd_is_open(fd: RawFd) -> bool {
    // SAFETY: fcntl(F_GETFD) on an integer reads only the descriptor table entry; an invalid number yields EBADF and
    // no memory is passed.
    #[allow(unsafe_code)]
    let r = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    r >= 0
}
