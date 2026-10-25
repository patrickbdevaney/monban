//! UP-6 CLOEXEC hygiene, checked from `/proc/self/fdinfo` (no raw-fd handling, no unsafe).
//!
//! Before spawning a child the parent requires every fd above 2 to carry O_CLOEXEC, so only the fds placed on the
//! child's stdio slots on purpose cross exec. At startup a child requires that no fd above 2 survived exec.

use std::fs;

const O_CLOEXEC_OCTAL: u64 = 0o2_000_000;

/// Fds above 2 in this process that do not carry O_CLOEXEC (they would leak into a spawned child).
pub fn non_cloexec_fds() -> std::io::Result<Vec<i32>> {
    let mut out = Vec::new();
    for e in fs::read_dir("/proc/self/fd")? {
        let e = e?;
        let Some(fd) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
        if fd <= 2 {
            continue;
        }
        // The fd may have been closed meanwhile (including read_dir's own fd); skip vanished entries.
        let Ok(info) = fs::read_to_string(format!("/proc/self/fdinfo/{fd}")) else { continue };
        let flags =
            info.lines().find_map(|l| l.strip_prefix("flags:")).and_then(|v| u64::from_str_radix(v.trim(), 8).ok());
        match flags {
            Some(f) if f & O_CLOEXEC_OCTAL != 0 => {}
            Some(_) => out.push(fd),
            None => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn std_fds_are_cloexec_and_detected_otherwise() {
        let Ok(f) = fs::File::open("/dev/null") else { return };
        let fd = f.as_raw_fd();
        let before = non_cloexec_fds().unwrap_or_default();
        assert!(!before.contains(&fd), "std opens with O_CLOEXEC");
        // Clear FD_CLOEXEC on a duplicate and the audit must see it.
        let Ok(dup) = f.try_clone() else { return };
        let r = nix::fcntl::fcntl(&dup, nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()));
        assert!(r.is_ok());
        let after = non_cloexec_fds().unwrap_or_default();
        assert!(after.contains(&dup.as_raw_fd()));
    }
}
