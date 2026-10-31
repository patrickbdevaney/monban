//! Syscall probe (test-only, feature `test-hooks`, PLAN-5 D15) implementing the probe protocol of
//! `oracles/syscall-negative/README.md`:
//!
//! ```text
//! <subject> --path forkwasm|cordon [--stage zygote] --probe <name> --allow-dir <dir>
//!           [--target <path>] [--fd <n>] [--port <p>]
//! ```
//!
//! The probe installs the real sandbox of this crate ([`super::install`]) for the path, prints
//! `{"event":"armed",..}` and issues exactly the named syscall, then prints `{"event":"result",..}` if it returns.
//! On `--path forkwasm` without `--stage`, the zygote installs its profile, forks one child the way it does per
//! request, the child installs [`Profile::child`] and probes, and the zygote prints `{"event":"child-exit",..}`.
//! Before `armed`, an `{"event":"installed",..}` line records the Landlock ABI and filter size (ignored by the
//! oracle's judge, kept for the record).

use std::ffi::CString;
use std::io::Write;
use std::path::PathBuf;

use rustix::process::{Pid, WaitOptions};

use super::{Forked, Profile, Stage, exit_now, fork, install};

/// Exit code for usage errors (EX_USAGE).
const EX_USAGE: u8 = 64;
/// Exit code when the sandbox could not be installed (EX_SOFTWARE).
const EX_SOFTWARE: u8 = 70;

/// Probe names the protocol defines.
pub const PROBES: &[&str] = &[
    "noop",
    "dumpable",
    "clone_newuser",
    "unshare_newuser",
    "unshare_newnet",
    "setns",
    "clone3",
    "socket_inet",
    "socket_inet6",
    "socket_unix",
    "socket_netlink",
    "socketpair",
    "tcp_ulp",
    "bpf",
    "io_uring_setup",
    "perf_event_open",
    "ptrace",
    "process_vm_readv",
    "userfaultfd",
    "keyctl",
    "mount",
    "execve",
    "fork",
    "open_inside",
    "open_outside",
    "connect_tcp",
];

#[derive(Debug, Default)]
struct Args {
    path: String,
    stage: String,
    probe: String,
    allow_dir: String,
    target: String,
    fd: i32,
    port: u16,
}

fn parse(v: &[String]) -> Result<Args, String> {
    let mut a = Args { fd: -1, ..Args::default() };
    let mut it = v.iter();
    while let Some(k) = it.next() {
        let val = it.next().ok_or_else(|| format!("{k} needs a value"))?.clone();
        match k.as_str() {
            "--path" => a.path = val,
            "--stage" => a.stage = val,
            "--probe" => a.probe = val,
            "--allow-dir" => a.allow_dir = val,
            "--target" => a.target = val,
            "--fd" => a.fd = val.parse().map_err(|_| "--fd: not an integer".to_string())?,
            "--port" => a.port = val.parse().map_err(|_| "--port: not a port".to_string())?,
            _ => return Err(format!("unknown argument {k}")),
        }
    }
    if !PROBES.contains(&a.probe.as_str()) {
        return Err(format!("unknown --probe {:?}", a.probe));
    }
    if a.allow_dir.is_empty() {
        return Err("--allow-dir required".into());
    }
    match (a.path.as_str(), a.stage.as_str()) {
        ("cordon", "") | ("forkwasm", "") | ("forkwasm", "zygote") => Ok(a),
        (p, s) => Err(format!("unsupported --path {p:?} --stage {s:?}")),
    }
}

fn out(line: &str) {
    let mut o = std::io::stdout().lock();
    let _ = o.write_all(line.as_bytes());
    let _ = o.write_all(b"\n");
    let _ = o.flush();
}

const SIGCHLD: usize = 17;
const CLONE_NEWUSER: usize = 0x1000_0000;
const CLONE_NEWNET: usize = 0x4000_0000;
const O_CLOEXEC: usize = 0o2_000_000;

/// Read by the `process_vm_readv` probe (its own address space).
static REMOTE: [u8; 8] = *b"aegisprb";

/// Issues the probe's one syscall. Returns (ret, errno). Does not return for a successful execve; the child side
/// of a successful fork-like probe leaves at once through `_exit(0)` and the parent reaps it.
fn issue(a: &Args) -> (i64, i64) {
    use super::filter::nr;
    // Every buffer an argument points into is owned by this frame and outlives the syscall below.
    let target = CString::new(a.target.as_bytes()).unwrap_or_default();
    let clone3_args: [u64; 8] = [0, 0, 0, 0, SIGCHLD as u64, 0, 0, 0];
    let mut pair: [i32; 2] = [-1, -1];
    let ulp = *b"tls";
    let mut sockaddr = [0u8; 16];
    if let Some(s) = sockaddr.get_mut(0..2) {
        s.copy_from_slice(&2u16.to_le_bytes()); // AF_INET
    }
    if let Some(s) = sockaddr.get_mut(2..4) {
        s.copy_from_slice(&a.port.to_be_bytes());
    }
    if let Some(s) = sockaddr.get_mut(4..8) {
        s.copy_from_slice(&[127, 0, 0, 1]);
    }
    let bpf_attr = [0u8; 128];
    let mut uring_params = [0u8; 120];
    let mut perf_attr = [0u8; 128];
    if let Some(s) = perf_attr.get_mut(0..4) {
        s.copy_from_slice(&1u32.to_le_bytes()); // PERF_TYPE_SOFTWARE
    }
    if let Some(s) = perf_attr.get_mut(4..8) {
        s.copy_from_slice(&128u32.to_le_bytes()); // size
    }
    if let Some(s) = perf_attr.get_mut(40..48) {
        s.copy_from_slice(&(1u64 | (1 << 5) | (1 << 6)).to_le_bytes()); // disabled, exclude kernel/hv
    }
    let mut readbuf = [0u8; 8];
    let local_iov: [usize; 2] = [readbuf.as_mut_ptr() as usize, readbuf.len()];
    let remote_iov: [usize; 2] = [REMOTE.as_ptr() as usize, REMOTE.len()];
    let (src, dst, fstype) = (c"none", c"/", c"tmpfs");
    let bin_true = c"/bin/true";
    let argv: [*const libc::c_char; 2] = [bin_true.as_ptr(), std::ptr::null()];
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    let pid = std::process::id() as usize;
    let fd = a.fd as isize as usize;

    let p = |x: *const u8| x as usize;
    let (n, args): (u32, [usize; 6]) = match a.probe.as_str() {
        "noop" => (nr::GETPID, [0; 6]),
        "dumpable" => (nr::PRCTL, [3, 0, 0, 0, 0, 0]),
        "clone_newuser" => (nr::CLONE, [CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0, 0]),
        "fork" => (nr::CLONE, [SIGCHLD, 0, 0, 0, 0, 0]),
        "clone3" => (nr::CLONE3, [clone3_args.as_ptr() as usize, 64, 0, 0, 0, 0]),
        "unshare_newuser" => (nr::UNSHARE, [CLONE_NEWUSER, 0, 0, 0, 0, 0]),
        "unshare_newnet" => (nr::UNSHARE, [CLONE_NEWNET, 0, 0, 0, 0, 0]),
        "setns" => (nr::SETNS, [usize::MAX, 0, 0, 0, 0, 0]),
        "socket_inet" => (nr::SOCKET, [2, 1 | O_CLOEXEC, 0, 0, 0, 0]),
        "socket_inet6" => (nr::SOCKET, [10, 1 | O_CLOEXEC, 0, 0, 0, 0]),
        "socket_unix" => (nr::SOCKET, [1, 1 | O_CLOEXEC, 0, 0, 0, 0]),
        "socket_netlink" => (nr::SOCKET, [16, 3 | O_CLOEXEC, 0, 0, 0, 0]),
        "socketpair" => (nr::SOCKETPAIR, [1, 1, 0, pair.as_mut_ptr() as usize, 0, 0]),
        "tcp_ulp" => (nr::SETSOCKOPT, [fd, 6, 31, p(ulp.as_ptr()), ulp.len(), 0]),
        "connect_tcp" => (nr::CONNECT, [fd, p(sockaddr.as_ptr()), sockaddr.len(), 0, 0, 0]),
        "bpf" => (nr::BPF, [5, p(bpf_attr.as_ptr()), bpf_attr.len(), 0, 0, 0]),
        "io_uring_setup" => (nr::IO_URING_SETUP, [1, uring_params.as_mut_ptr() as usize, 0, 0, 0, 0]),
        "perf_event_open" => (nr::PERF_EVENT_OPEN, [p(perf_attr.as_ptr()), 0, usize::MAX, usize::MAX, 0, 0]),
        "ptrace" => (nr::PTRACE, [0; 6]),
        "process_vm_readv" => {
            (nr::PROCESS_VM_READV, [pid, local_iov.as_ptr() as usize, 1, remote_iov.as_ptr() as usize, 1, 0])
        }
        "userfaultfd" => (nr::USERFAULTFD, [O_CLOEXEC | 1, 0, 0, 0, 0, 0]), // UFFD_USER_MODE_ONLY
        "keyctl" => (nr::KEYCTL, [0, (-3isize) as usize, 0, 0, 0, 0]),      // GET_KEYRING_ID(session)
        "mount" => (nr::MOUNT, [p(src.as_ptr().cast()), p(dst.as_ptr().cast()), p(fstype.as_ptr().cast()), 0, 0, 0]),
        "execve" => {
            (nr::EXECVE, [p(bin_true.as_ptr().cast()), argv.as_ptr() as usize, envp.as_ptr() as usize, 0, 0, 0])
        }
        "open_inside" | "open_outside" => {
            (nr::OPENAT, [(-100isize) as usize, p(target.as_ptr().cast()), O_CLOEXEC, 0, 0, 0])
        }
        _ => return (-1, i64::from(libc::EINVAL)),
    };
    let [a0, a1, a2, a3, a4, a5] = args;
    // SAFETY: test-only (feature `test-hooks`). `n` is one of the fixed probe syscalls above and every pointer
    // argument points into a buffer of this frame (or a static) that is live and correctly sized for the call;
    // fork-like probes return 0 only in the child, which leaves through `_exit` at once below.
    #[allow(unsafe_code)]
    let r = unsafe { libc::syscall(libc::c_long::from(n), a0, a1, a2, a3, a4, a5) };
    let errno = if r < 0 { i64::from(std::io::Error::last_os_error().raw_os_error().unwrap_or(0)) } else { 0 };
    if matches!(a.probe.as_str(), "fork" | "clone_newuser" | "clone3") && r >= 0 {
        if r == 0 {
            exit_now(0);
        }
        if let Some(child) = i32::try_from(r).ok().and_then(Pid::from_raw) {
            let _ = rustix::process::waitpid(Some(child), WaitOptions::empty());
        }
    }
    let _ = (&pair, &readbuf, &uring_params);
    (r, errno)
}

fn probe_here(a: &Args, stage: &str) {
    out(&format!(
        "{{\"event\":\"armed\",\"probe\":\"{}\",\"path\":\"{}\",\"stage\":\"{stage}\",\"pid\":{}}}",
        a.probe,
        a.path,
        std::process::id()
    ));
    let (r, e) = issue(a);
    out(&format!(
        "{{\"event\":\"result\",\"probe\":\"{}\",\"path\":\"{}\",\"stage\":\"{stage}\",\"ret\":{r},\"errno\":{e}}}",
        a.probe, a.path
    ));
}

fn installed_line(a: &Args, inst: &super::Installed) {
    let abi = inst.landlock.as_ref().map_or("null".to_string(), |l| l.abi.to_string());
    let scoped = inst.landlock.as_ref().map_or(0, |l| l.scoped);
    let stage = match inst.stage {
        Stage::Zygote => "zygote",
        Stage::Cordon => "cordon",
        Stage::Child => "child",
        Stage::Compile => "compile",
    };
    out(&format!(
        "{{\"event\":\"installed\",\"probe\":\"{}\",\"path\":\"{}\",\"stage\":\"{stage}\",\"landlock_abi\":{abi},\"landlock_scoped\":{scoped},\"filter_len\":{}}}",
        a.probe, a.path, inst.filter_len
    ));
}

/// Runs the probe protocol over `args` (everything after the subject's own `probe` word). Returns the exit code.
pub fn run(args: &[String]) -> u8 {
    let a = match parse(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("probe: {e}");
            return EX_USAGE;
        }
    };
    let dir = match std::fs::canonicalize(&a.allow_dir) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("probe: --allow-dir: {e}");
            return EX_USAGE;
        }
    };
    let paths: Vec<PathBuf> = vec![dir];
    let profile = if a.path == "cordon" { Profile::cordon(paths) } else { Profile::zygote(paths) };
    let inst = match install(&profile) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("probe: {e}");
            return if matches!(e, super::SandboxError::LandlockAbiTooOld(_)) { 78 } else { EX_SOFTWARE };
        }
    };
    installed_line(&a, &inst);
    if a.path == "cordon" {
        probe_here(&a, "cordon");
        return 0;
    }
    if a.stage == "zygote" {
        probe_here(&a, "zygote");
        return 0;
    }
    let _ = std::io::stdout().lock().flush();
    match fork() {
        Ok(Forked::Child) => {
            match install(&Profile::child()) {
                Ok(i) => installed_line(&a, &i),
                Err(e) => {
                    eprintln!("probe: child: {e}");
                    exit_now(i32::from(EX_SOFTWARE));
                }
            }
            probe_here(&a, "child");
            exit_now(0);
        }
        Ok(Forked::Parent(pid)) => {
            let st =
                Pid::from_raw(pid).and_then(|p| rustix::process::waitpid(Some(p), WaitOptions::empty()).ok().flatten());
            let Some((_, st)) = st else {
                eprintln!("probe: waitpid failed");
                return EX_SOFTWARE;
            };
            let sig = st.terminating_signal().map_or("null".to_string(), |s| s.to_string());
            let code = st.exit_status().map_or("null".to_string(), |c| c.to_string());
            out(&format!(
                "{{\"event\":\"child-exit\",\"probe\":\"{}\",\"path\":\"forkwasm\",\"stage\":\"child\",\"pid\":{pid},\"signal\":{sig},\"code\":{code}}}",
                a.probe
            ));
            0
        }
        Err(e) => {
            eprintln!("probe: zygote fork failed: {e}");
            EX_SOFTWARE
        }
    }
}
