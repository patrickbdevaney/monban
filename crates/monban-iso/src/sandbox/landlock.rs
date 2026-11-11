//! Landlock for the P2 sandbox (PLAN-5 D2/D5): every filesystem right the running ABI knows is handled, and only
//! read access beneath the given module/data paths is granted; TCP bind and connect are handled with no rule (no
//! port is reachable); from ABI 6, abstract-UNIX-socket and signal scoping keep the domain from reaching
//! processes outside it. ABI below 4 is refused (fail closed: P2 routes are refused at boot, D2).

use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};

use rustix::fs::{FileType, Mode, OFlags};

use super::SandboxError;
use super::sys::{self, PathBeneath, RulesetAttr};

/// Minimum ABI (net rules arrived in ABI 4).
pub const MIN_ABI: u32 = 4;

const ACCESS_FS_EXECUTE: u64 = 1 << 0;
const ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_FS_READ_FILE: u64 = 1 << 2;
const ACCESS_FS_READ_DIR: u64 = 1 << 3;
const ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const ACCESS_FS_MAKE_REG: u64 = 1 << 8;
/// EXECUTE .. MAKE_SYM (ABI 1).
const ACCESS_FS_V1: u64 = (1 << 13) - 1;
const ACCESS_FS_REFER: u64 = 1 << 13;
const ACCESS_FS_TRUNCATE: u64 = 1 << 14;
const ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;
const ACCESS_NET_BIND_TCP: u64 = 1 << 0;
const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;
const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const SCOPE_SIGNAL: u64 = 1 << 1;

/// Every fs right the given ABI can handle.
pub fn handled_fs(abi: u32) -> u64 {
    let mut fs = ACCESS_FS_V1;
    if abi >= 2 {
        fs |= ACCESS_FS_REFER;
    }
    if abi >= 3 {
        fs |= ACCESS_FS_TRUNCATE;
    }
    if abi >= 5 {
        fs |= ACCESS_FS_IOCTL_DEV;
    }
    fs
}

/// The running kernel's Landlock ABI (`None` when Landlock is absent or disabled).
pub fn abi() -> Option<u32> {
    sys::landlock_abi().ok()
}

/// What was enforced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enforced {
    /// The ABI the ruleset was built for.
    pub abi: u32,
    /// Handled fs rights.
    pub handled_fs: u64,
    /// Handled net rights (always both TCP rights, with no rule).
    pub handled_net: u64,
    /// Scopes (0 below ABI 6).
    pub scoped: u64,
    /// The paths granted read access.
    pub read_paths: Vec<PathBuf>,
    /// The directories granted regular-file write, create and remove rights (compile output only).
    pub write_dirs: Vec<PathBuf>,
}

/// Builds and enforces the ruleset on the calling thread. NO_NEW_PRIVS must already be set. `write_dirs` (empty for
/// every serving profile) get read, regular-file write/create/remove and, from ABI 3, truncate rights beneath them.
pub fn enforce(read_paths: &[PathBuf], write_dirs: &[PathBuf]) -> Result<Enforced, SandboxError> {
    let abi = sys::landlock_abi().map_err(|e| SandboxError::LandlockUnavailable(e.raw_os_error().unwrap_or(0)))?;
    if abi < MIN_ABI {
        return Err(SandboxError::LandlockAbiTooOld(abi));
    }
    let scoped = if abi >= 6 { SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL } else { 0 };
    let attr = RulesetAttr {
        handled_access_fs: handled_fs(abi),
        handled_access_net: ACCESS_NET_BIND_TCP | ACCESS_NET_CONNECT_TCP,
        scoped,
    };
    let size = if abi >= 6 { 24 } else { 16 };
    let rs = sys::landlock_create_ruleset(&attr, size).map_err(|e| SandboxError::Landlock("create_ruleset", e))?;
    for p in read_paths {
        add_read_rule(&rs, p)?;
    }
    for d in write_dirs {
        add_write_dir_rule(&rs, d, abi)?;
    }
    sys::landlock_restrict_self(rs.as_fd()).map_err(|e| SandboxError::Landlock("restrict_self", e))?;
    Ok(Enforced {
        abi,
        handled_fs: attr.handled_access_fs,
        handled_net: attr.handled_access_net,
        scoped,
        read_paths: read_paths.to_vec(),
        write_dirs: write_dirs.to_vec(),
    })
}

fn add_read_rule(rs: &impl AsFd, p: &Path) -> Result<(), SandboxError> {
    if !p.is_absolute() {
        return Err(SandboxError::Path(p.to_path_buf(), "not absolute"));
    }
    let fd = rustix::fs::open(p, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
        .map_err(|e| SandboxError::PathOpen(p.to_path_buf(), e.raw_os_error()))?;
    let st = rustix::fs::fstat(&fd).map_err(|e| SandboxError::PathOpen(p.to_path_buf(), e.raw_os_error()))?;
    let allowed = match FileType::from_raw_mode(st.st_mode) {
        FileType::Directory => ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR,
        FileType::RegularFile => ACCESS_FS_READ_FILE,
        _ => return Err(SandboxError::Path(p.to_path_buf(), "neither a directory nor a regular file")),
    };
    debug_assert_eq!(allowed & ACCESS_FS_EXECUTE, 0);
    let rule = PathBeneath { allowed_access: allowed, parent_fd: fd.as_raw_fd() };
    sys::landlock_add_rule(rs.as_fd(), &rule).map_err(|e| SandboxError::Landlock("add_rule", e))
}

fn add_write_dir_rule(rs: &impl AsFd, d: &Path, abi: u32) -> Result<(), SandboxError> {
    if !d.is_absolute() {
        return Err(SandboxError::Path(d.to_path_buf(), "not absolute"));
    }
    let fd = rustix::fs::open(d, OFlags::PATH | OFlags::CLOEXEC | OFlags::DIRECTORY, Mode::empty())
        .map_err(|e| SandboxError::PathOpen(d.to_path_buf(), e.raw_os_error()))?;
    let mut allowed =
        ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR | ACCESS_FS_WRITE_FILE | ACCESS_FS_MAKE_REG | ACCESS_FS_REMOVE_FILE;
    if abi >= 3 {
        allowed |= ACCESS_FS_TRUNCATE;
    }
    debug_assert_eq!(allowed & ACCESS_FS_EXECUTE, 0);
    let rule = PathBeneath { allowed_access: allowed, parent_fd: fd.as_raw_fd() };
    sys::landlock_add_rule(rs.as_fd(), &rule).map_err(|e| SandboxError::Landlock("add_rule", e))
}
