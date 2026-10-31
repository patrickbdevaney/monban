//! The raw-syscall layer of the sandbox: every `unsafe` site of `sandbox` outside the test-only probe lives here
//! (PLAN-5 D4, DEVIATIONS X-14; `cargo xtask unsafe-sites` caps aegis-iso at 20). Each wrapper takes only typed,
//! owned or borrowed Rust values, so the safe signature cannot be used to pass a dangling pointer.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use super::filter::Insn;

/// `struct sock_fprog`.
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const Insn,
}

/// `struct landlock_ruleset_attr` (ABI 6 layout; the size passed selects the prefix the kernel reads).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RulesetAttr {
    pub handled_access_fs: u64,
    pub handled_access_net: u64,
    pub scoped: u64,
}

/// `struct landlock_path_beneath_attr` (packed, as in the uapi header).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct PathBeneath {
    pub allowed_access: u64,
    pub parent_fd: i32,
}

const SYS_SECCOMP: libc::c_long = 317;
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;

fn check(r: libc::c_long) -> io::Result<libc::c_long> {
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(r) }
}

/// Loads `prog` as a seccomp filter for the calling thread (`seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)`).
/// Requires NO_NEW_PRIVS (set by the caller).
pub(crate) fn seccomp_set_filter(prog: &[Insn]) -> io::Result<()> {
    let len = u16::try_from(prog.len()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let fprog = SockFprog { len, filter: prog.as_ptr() };
    // SAFETY: `fprog` points at `prog`, a live slice of `len` `#[repr(C)]` sock_filter instructions borrowed for
    // the whole call; the kernel copies the program before returning and keeps no pointer into it.
    #[allow(unsafe_code)]
    let r = unsafe { libc::syscall(SYS_SECCOMP, SECCOMP_SET_MODE_FILTER, 0 as libc::c_ulong, &raw const fprog) };
    check(r).map(|_| ())
}

/// The Landlock ABI version, or the errno (`EOPNOTSUPP` when disabled, `ENOSYS` when absent).
pub(crate) fn landlock_abi() -> io::Result<u32> {
    // SAFETY: the version query passes a null attribute pointer with size 0, which the kernel never dereferences.
    #[allow(unsafe_code)]
    let r = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<RulesetAttr>(),
            0 as libc::size_t,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    check(r).and_then(|v| u32::try_from(v).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL)))
}

/// Creates a ruleset; `size` is the attribute prefix the running ABI understands (16 for ABI 4-5, 24 from 6).
pub(crate) fn landlock_create_ruleset(attr: &RulesetAttr, size: usize) -> io::Result<OwnedFd> {
    let size = size.min(std::mem::size_of::<RulesetAttr>());
    // SAFETY: `attr` is a live `#[repr(C)]` landlock_ruleset_attr and `size` never exceeds its size; on success
    // the kernel returns a new fd that nothing else owns, so adopting it into an `OwnedFd` is sound.
    #[allow(unsafe_code)]
    let fd = unsafe {
        let r = libc::syscall(SYS_LANDLOCK_CREATE_RULESET, attr as *const RulesetAttr, size, 0u32);
        let raw = check(r).and_then(|v| i32::try_from(v).map_err(|_| io::Error::from_raw_os_error(libc::EBADF)))?;
        OwnedFd::from_raw_fd(raw)
    };
    Ok(fd)
}

/// Adds one path-beneath rule to `ruleset`.
pub(crate) fn landlock_add_rule(ruleset: BorrowedFd<'_>, rule: &PathBeneath) -> io::Result<()> {
    // SAFETY: `rule` is a live packed landlock_path_beneath_attr and `ruleset` a borrowed open fd; the kernel
    // reads the attribute during the call only.
    #[allow(unsafe_code)]
    let r = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH,
            rule as *const PathBeneath,
            0u32,
        )
    };
    check(r).map(|_| ())
}

/// Enforces `ruleset` on the calling thread.
pub(crate) fn landlock_restrict_self(ruleset: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: integer-only syscall on a borrowed open fd; no memory is passed.
    #[allow(unsafe_code)]
    let r = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset.as_raw_fd(), 0u32) };
    check(r).map(|_| ())
}

/// Result of [`fork`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forked {
    /// In the parent, with the child's pid.
    Parent(i32),
    /// In the child.
    Child,
}

/// `fork(2)`. The caller must be single-threaded (the zygote is, D1), so the child inherits no lock held by
/// another thread; the child should only run its request and leave through [`exit_now`].
pub fn fork() -> io::Result<Forked> {
    // SAFETY: glibc fork runs its atfork handlers (malloc, stdio) so the child's allocator state is consistent;
    // the zygote calling this is single-threaded, which `install` enforces before any sandbox is applied.
    #[allow(unsafe_code)]
    let pid = unsafe { libc::fork() };
    match pid {
        p if p < 0 => Err(io::Error::last_os_error()),
        0 => Ok(Forked::Child),
        p => Ok(Forked::Parent(p)),
    }
}

/// `_exit(2)`: leaves without running atexit handlers or destructors (a fork child must not flush or tear down
/// state it shares with the zygote).
pub fn exit_now(code: i32) -> ! {
    // SAFETY: `_exit` takes an integer and never returns; it touches no Rust-visible memory.
    #[allow(unsafe_code)]
    unsafe {
        libc::_exit(code)
    }
}
