//! Raw-syscall sites of the supervisor (PLAN-5 D4, X-14): placing the listening socket at fd 3 between fork and
//! execve inside `std::process::Command`.

use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::zygote::LISTEN_FD;

/// In the forked child: makes `fd` the child's fd 3 and clears its `FD_CLOEXEC`. Returns false on failure (errno
/// set). dup2 to the same number is a no-op that keeps `FD_CLOEXEC`, so the flag is always cleared explicitly.
fn place(fd: RawFd) -> bool {
    // SAFETY: dup2 and fcntl(F_GETFD/F_SETFD) take integers only, touch only the descriptor table, and are
    // async-signal-safe, so they may run between fork and execve.
    #[allow(unsafe_code)]
    unsafe {
        if fd != LISTEN_FD && libc::dup2(fd, LISTEN_FD) < 0 {
            return false;
        }
        let fl = libc::fcntl(LISTEN_FD, libc::F_GETFD);
        fl >= 0 && libc::fcntl(LISTEN_FD, libc::F_SETFD, fl & !libc::FD_CLOEXEC) >= 0
    }
}

/// Arranges for `fd` to be the child's fd 3, without `FD_CLOEXEC`, just before execve.
pub(crate) fn listener_at_fd3(c: &mut Command, fd: RawFd) {
    let hook = move || -> std::io::Result<()> { if place(fd) { Ok(()) } else { Err(std::io::Error::last_os_error()) } };
    // SAFETY: the hook runs in the forked child before execve; it calls only `place` (dup2 and fcntl, both
    // async-signal-safe), allocates nothing on success and takes no lock (the error path builds an io::Error from
    // errno only). `fd` is the supervisor's listening socket, which the caller keeps open for the whole `spawn`.
    #[allow(unsafe_code)]
    unsafe {
        c.pre_exec(hook);
    }
}
