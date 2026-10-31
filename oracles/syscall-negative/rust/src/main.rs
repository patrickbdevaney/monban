// synprobe: the syscall-negative oracle's reference subject and its unfiltered host control.
//
// Reference subject (the measured isofi design, PLAN D2/D5, ARCHITECTURE R-ISO-4/5):
//   synprobe [--mutant <m>] --path forkwasm|cordon [--stage zygote|child] --probe <name> --allow-dir <dir>
//            [--target <path>] [--fd <n>] [--port <p>]
//   installs PR_SET_NO_NEW_PRIVS, RLIMIT_CORE=0, PR_SET_DUMPABLE=0, Landlock (fs read-only beneath --allow-dir,
//   TCP bind/connect with no rule allowed), then the seccomp filter; on forkwasm (stage child, the default) it
//   forks, the child adds the child-only filter (kills clone/fork/vfork/execve/execveat) and runs the probe.
// Host control:
//   synprobe --path none --probe <name> ...   runs the same syscall with no sandbox at all.
//   synprobe --facts                          prints {"landlock_abi":N}.
// Output protocol: see ../README.md "Probe protocol". x86_64 only.
#![allow(clippy::missing_safety_doc)]
use std::ffi::CString;
use std::io::Write;
use std::os::raw::{c_int, c_long};

#[cfg(not(target_arch = "x86_64"))]
compile_error!("synprobe is x86_64-only (seccomp arch check and syscall numbers)");

extern "C" {
    fn syscall(n: c_long, ...) -> c_long;
    fn __errno_location() -> *mut c_int;
}

mod nr {
    pub const READ: i64 = 0;
    pub const WRITE: i64 = 1;
    pub const CLOSE: i64 = 3;
    pub const FSTAT: i64 = 5;
    pub const POLL: i64 = 7;
    pub const LSEEK: i64 = 8;
    pub const MMAP: i64 = 9;
    pub const MPROTECT: i64 = 10;
    pub const MUNMAP: i64 = 11;
    pub const BRK: i64 = 12;
    pub const RT_SIGACTION: i64 = 13;
    pub const RT_SIGPROCMASK: i64 = 14;
    pub const RT_SIGRETURN: i64 = 15;
    pub const SCHED_YIELD: i64 = 24;
    pub const MREMAP: i64 = 25;
    pub const MADVISE: i64 = 28;
    pub const NANOSLEEP: i64 = 35;
    pub const GETPID: i64 = 39;
    pub const SOCKET: i64 = 41;
    pub const CONNECT: i64 = 42;
    pub const SENDTO: i64 = 44;
    pub const RECVFROM: i64 = 45;
    pub const SOCKETPAIR: i64 = 53;
    pub const SETSOCKOPT: i64 = 54;
    pub const CLONE: i64 = 56;
    pub const FORK: i64 = 57;
    pub const VFORK: i64 = 58;
    pub const EXECVE: i64 = 59;
    pub const EXIT: i64 = 60;
    pub const WAIT4: i64 = 61;
    pub const FCNTL: i64 = 72;
    pub const PTRACE: i64 = 101;
    pub const GETUID: i64 = 102;
    pub const GETPPID: i64 = 110;
    pub const SIGALTSTACK: i64 = 131;
    pub const PIVOT_ROOT: i64 = 155;
    pub const PRCTL: i64 = 157;
    pub const MOUNT: i64 = 165;
    pub const UMOUNT2: i64 = 166;
    pub const GETTID: i64 = 186;
    pub const FUTEX: i64 = 202;
    pub const SCHED_GETAFFINITY: i64 = 204;
    pub const CLOCK_GETTIME: i64 = 228;
    pub const CLOCK_NANOSLEEP: i64 = 230;
    pub const EXIT_GROUP: i64 = 231;
    pub const TGKILL: i64 = 234;
    pub const ADD_KEY: i64 = 248;
    pub const REQUEST_KEY: i64 = 249;
    pub const KEYCTL: i64 = 250;
    pub const OPENAT: i64 = 257;
    pub const NEWFSTATAT: i64 = 262;
    pub const UNSHARE: i64 = 272;
    pub const SET_ROBUST_LIST: i64 = 273;
    pub const ACCEPT4: i64 = 288;
    pub const PERF_EVENT_OPEN: i64 = 298;
    pub const PRLIMIT64: i64 = 302;
    pub const SETNS: i64 = 308;
    pub const PROCESS_VM_READV: i64 = 310;
    pub const PROCESS_VM_WRITEV: i64 = 311;
    pub const SECCOMP: i64 = 317;
    pub const GETRANDOM: i64 = 318;
    pub const BPF: i64 = 321;
    pub const EXECVEAT: i64 = 322;
    pub const USERFAULTFD: i64 = 323;
    pub const MEMBARRIER: i64 = 324;
    pub const STATX: i64 = 332;
    pub const RSEQ: i64 = 334;
    pub const IO_URING_SETUP: i64 = 425;
    pub const IO_URING_ENTER: i64 = 426;
    pub const IO_URING_REGISTER: i64 = 427;
    pub const OPEN_TREE: i64 = 428;
    pub const MOVE_MOUNT: i64 = 429;
    pub const FSOPEN: i64 = 430;
    pub const FSCONFIG: i64 = 431;
    pub const FSMOUNT: i64 = 432;
    pub const FSPICK: i64 = 433;
    pub const CLONE3: i64 = 435;
    pub const MOUNT_SETATTR: i64 = 442;
    pub const LANDLOCK_CREATE_RULESET: i64 = 444;
    pub const LANDLOCK_ADD_RULE: i64 = 445;
    pub const LANDLOCK_RESTRICT_SELF: i64 = 446;
}

const ENOSYS: u32 = 38;
const EPERM: u32 = 1;
const SIGCHLD: i64 = 17;
const CLONE_THREAD: u32 = 0x0001_0000;
const CLONE_NEWUSER: i64 = 0x1000_0000;
const CLONE_NEWNET: i64 = 0x4000_0000;
// CLONE_NEWTIME | NEWNS | NEWCGROUP | NEWUTS | NEWIPC | NEWUSER | NEWPID | NEWNET
const CLONE_NEW_MASK: u32 = 0x0000_0080 | 0x0002_0000 | 0x0200_0000 | 0x0400_0000 | 0x0800_0000 | 0x1000_0000 | 0x2000_0000 | 0x4000_0000;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_ERRNO: u32 = 0x0005_0000;
const RET_ALLOW: u32 = 0x7fff_0000;
const PR_SET_NO_NEW_PRIVS: i64 = 38;
const PR_SET_DUMPABLE: i64 = 4;
const PR_GET_DUMPABLE: i64 = 3;

fn errno() -> i64 {
    unsafe { *__errno_location() as i64 }
}
fn sys_ret(r: c_long) -> (i64, i64) {
    if r < 0 { (r as i64, errno()) } else { (r as i64, 0) }
}
fn out(line: &str) {
    let mut o = std::io::stdout().lock();
    let _ = o.write_all(line.as_bytes());
    let _ = o.write_all(b"\n");
    let _ = o.flush();
}
fn die(code: i32, msg: &str) -> ! {
    eprintln!("synprobe: {msg}");
    std::process::exit(code)
}
fn exit_now(code: i64) -> ! {
    unsafe {
        syscall(nr::EXIT_GROUP, code);
    }
    std::process::exit(code as i32)
}

// --------------------------------------------------------------------------------------------- args
#[derive(Default, Clone)]
struct Args {
    path: String,
    stage: String,
    probe: String,
    allow_dir: String,
    target: String,
    fd: i64,
    port: u16,
    mutant: String,
    facts: bool,
}
fn parse() -> Args {
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mut a = Args { fd: -1, ..Default::default() };
    let mut i = 0;
    while i < v.len() {
        let k = v[i].as_str();
        let val = || v.get(i + 1).cloned().unwrap_or_else(|| die(64, &format!("{k} needs a value")));
        match k {
            "--facts" => {
                a.facts = true;
                i += 1;
                continue;
            }
            "--path" => a.path = val(),
            "--stage" => a.stage = val(),
            "--probe" => a.probe = val(),
            "--allow-dir" => a.allow_dir = val(),
            "--target" => a.target = val(),
            "--fd" => a.fd = val().parse().unwrap_or_else(|_| die(64, "--fd")),
            "--port" => a.port = val().parse().unwrap_or_else(|_| die(64, "--port")),
            "--mutant" => a.mutant = val(),
            _ => die(64, &format!("unknown argument {k}")),
        }
        i += 2;
    }
    a
}

// --------------------------------------------------------------------------------------------- mutants
const MUTANTS: &[&str] = &[
    "no-clone-flag-filter",
    "no-denylist",
    "eperm-instead-of-kill",
    "clone3-allowed",
    "dumpable-1",
    "no-landlock",
    "no-child-filter",
];
struct Cfg {
    m: String,
}
impl Cfg {
    fn is(&self, m: &str) -> bool {
        self.m == m
    }
    fn kill(&self) -> u32 {
        if self.is("eperm-instead-of-kill") { RET_ERRNO | EPERM } else { RET_KILL_PROCESS }
    }
}

// --------------------------------------------------------------------------------------------- seccomp
#[repr(C)]
#[derive(Clone, Copy)]
struct Ins {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}
#[repr(C)]
struct Prog {
    len: u16,
    filter: *const Ins,
}
fn ld(off: u32) -> Ins {
    Ins { code: 0x20, jt: 0, jf: 0, k: off } // BPF_LD|BPF_W|BPF_ABS
}
fn jeq(k: u32, jt: u8, jf: u8) -> Ins {
    Ins { code: 0x15, jt, jf, k }
}
fn jge(k: u32, jt: u8, jf: u8) -> Ins {
    Ins { code: 0x35, jt, jf, k }
}
fn jset(k: u32, jt: u8, jf: u8) -> Ins {
    Ins { code: 0x45, jt, jf, k }
}
fn ret(k: u32) -> Ins {
    Ins { code: 0x06, jt: 0, jf: 0, k }
}
// seccomp_data: nr @0, arch @4, ip @8, args[i] @16+8i (low 32 bits first, little endian)
fn arg_lo(i: u32) -> u32 {
    16 + 8 * i
}

const DENYLIST: &[i64] = &[
    nr::UNSHARE, nr::SETNS, nr::SOCKET, nr::SOCKETPAIR, nr::BPF, nr::PERF_EVENT_OPEN, nr::IO_URING_SETUP,
    nr::IO_URING_ENTER, nr::IO_URING_REGISTER, nr::PTRACE, nr::PROCESS_VM_READV, nr::PROCESS_VM_WRITEV,
    nr::USERFAULTFD, nr::KEYCTL, nr::ADD_KEY, nr::REQUEST_KEY, nr::MOUNT, nr::UMOUNT2, nr::PIVOT_ROOT,
    nr::OPEN_TREE, nr::MOVE_MOUNT, nr::FSOPEN, nr::FSCONFIG, nr::FSMOUNT, nr::FSPICK, nr::MOUNT_SETATTR,
    nr::EXECVE, nr::EXECVEAT,
];
// What the reference needs after install. connect is allowed on purpose so that Landlock's net rule (not
// seccomp) is what the connect_tcp probe observes; prctl is unrestricted (reference simplification).
const ALLOWLIST: &[i64] = &[
    nr::READ, nr::WRITE, nr::CLOSE, nr::FSTAT, nr::NEWFSTATAT, nr::STATX, nr::LSEEK, nr::MMAP, nr::MUNMAP,
    nr::MPROTECT, nr::MADVISE, nr::BRK, nr::MREMAP, nr::FUTEX, nr::RT_SIGACTION, nr::RT_SIGPROCMASK,
    nr::RT_SIGRETURN, nr::SIGALTSTACK, nr::GETPID, nr::GETTID, nr::GETPPID, nr::GETUID, nr::GETRANDOM,
    nr::CLOCK_GETTIME, nr::CLOCK_NANOSLEEP, nr::NANOSLEEP, nr::SCHED_YIELD, nr::SCHED_GETAFFINITY, nr::EXIT,
    nr::EXIT_GROUP, nr::OPENAT, nr::FCNTL, nr::POLL, nr::WAIT4, nr::PRCTL, nr::CONNECT, nr::RSEQ,
    nr::SET_ROBUST_LIST, nr::TGKILL, nr::PRLIMIT64, nr::ACCEPT4, nr::RECVFROM, nr::SENDTO, nr::MEMBARRIER,
];

fn main_filter(c: &Cfg, cordon: bool) -> Vec<Ins> {
    let k = c.kill();
    let mut f = vec![ld(4), jeq(AUDIT_ARCH_X86_64, 1, 0), ret(k), ld(0), jge(0x4000_0000, 0, 1), ret(k)];
    // clone3 -> ENOSYS, so libc falls back to the flag-filtered clone (R-ISO-4)
    f.push(jeq(nr::CLONE3 as u32, 0, 1));
    f.push(ret(if c.is("clone3-allowed") { RET_ALLOW } else { RET_ERRNO | ENOSYS }));
    // clone: CLONE_NEW* -> kill; a cordon additionally only gets threads (no fork at all)
    let mut cb = vec![ld(arg_lo(0))];
    if !c.is("no-clone-flag-filter") {
        cb.push(jset(CLONE_NEW_MASK, 0, 1));
        cb.push(ret(k));
    }
    if cordon {
        cb.push(jset(CLONE_THREAD, 0, 1));
        cb.push(ret(RET_ALLOW));
        cb.push(ret(k));
    } else {
        cb.push(ret(RET_ALLOW));
    }
    f.push(jeq(nr::CLONE as u32, 0, cb.len() as u8));
    f.extend(cb);
    if c.is("no-clone-flag-filter") {
        for &n in &[nr::UNSHARE, nr::SETNS] {
            f.push(jeq(n as u32, 0, 1));
            f.push(ret(RET_ALLOW));
        }
    }
    let no_deny = c.is("no-denylist");
    if !no_deny {
        // setsockopt(fd, SOL_TCP=6, TCP_ULP=31, ..) -> kill; other setsockopt allowed
        let sb = [ld(arg_lo(1)), jeq(6, 0, 3), ld(arg_lo(2)), jeq(31, 0, 1), ret(k), ret(RET_ALLOW)];
        f.push(jeq(nr::SETSOCKOPT as u32, 0, sb.len() as u8));
        f.extend(sb);
        for &n in DENYLIST {
            f.push(jeq(n as u32, 0, 1));
            f.push(ret(k));
        }
    }
    let mut allow: Vec<i64> = ALLOWLIST.to_vec();
    if !cordon {
        allow.push(nr::SECCOMP); // the fork child installs its own filter
    }
    for n in allow {
        f.push(jeq(n as u32, 0, 1));
        f.push(ret(RET_ALLOW));
    }
    f.push(ret(if no_deny { RET_ALLOW } else { k }));
    f
}
fn child_filter(c: &Cfg) -> Vec<Ins> {
    let k = c.kill();
    let mut f = vec![ld(4), jeq(AUDIT_ARCH_X86_64, 1, 0), ret(k), ld(0)];
    for &n in &[nr::CLONE, nr::FORK, nr::VFORK, nr::EXECVE, nr::EXECVEAT] {
        f.push(jeq(n as u32, 0, 1));
        f.push(ret(k));
    }
    f.push(ret(RET_ALLOW));
    f
}
fn install_filter(f: &[Ins]) {
    let p = Prog { len: f.len() as u16, filter: f.as_ptr() };
    let r = unsafe {
        syscall(nr::PRCTL, PR_SET_NO_NEW_PRIVS, 1i64, 0i64, 0i64, 0i64);
        syscall(nr::SECCOMP, 1i64, 0i64, &p as *const Prog)
    };
    if r != 0 {
        die(70, &format!("seccomp install failed errno={}", errno()));
    }
}

// --------------------------------------------------------------------------------------------- landlock
fn landlock_abi() -> i64 {
    unsafe { syscall(nr::LANDLOCK_CREATE_RULESET, std::ptr::null::<u8>(), 0usize, 1u32) as i64 }
}
#[repr(C, packed)]
struct PathBeneath {
    allowed: u64,
    parent_fd: i32,
}
fn landlock(dir: &str) {
    let abi = landlock_abi();
    if abi < 4 {
        die(78, &format!("Landlock ABI {abi} < 4: P2 refused (PLAN D2)"));
    }
    let mut fs: u64 = (1 << 13) - 1;
    if abi >= 2 {
        fs |= 1 << 13; // REFER
    }
    if abi >= 3 {
        fs |= 1 << 14; // TRUNCATE
    }
    if abi >= 5 {
        fs |= 1 << 15; // IOCTL_DEV
    }
    let attr: [u64; 3] = [fs, 0b11 /* BIND_TCP | CONNECT_TCP, no rule */, 0];
    let size = if abi >= 6 { 24usize } else { 16usize };
    unsafe {
        let rs = syscall(nr::LANDLOCK_CREATE_RULESET, attr.as_ptr(), size, 0u32);
        if rs < 0 {
            die(70, &format!("landlock_create_ruleset errno={}", errno()));
        }
        let c = CString::new(dir).unwrap_or_else(|_| die(64, "--allow-dir"));
        let d = syscall(nr::OPENAT, -100i64, c.as_ptr(), 0o10000000i64 | 0o2000000i64); // O_PATH|O_CLOEXEC
        if d < 0 {
            die(70, &format!("open --allow-dir errno={}", errno()));
        }
        let pb = PathBeneath { allowed: (1 << 2) | (1 << 3), parent_fd: d as i32 }; // READ_FILE | READ_DIR
        if syscall(nr::LANDLOCK_ADD_RULE, rs, 1i64, &pb as *const PathBeneath, 0u32) != 0 {
            die(70, &format!("landlock_add_rule errno={}", errno()));
        }
        syscall(nr::CLOSE, d);
        syscall(nr::PRCTL, PR_SET_NO_NEW_PRIVS, 1i64, 0i64, 0i64, 0i64);
        if syscall(nr::LANDLOCK_RESTRICT_SELF, rs, 0u32) != 0 {
            die(70, &format!("landlock_restrict_self errno={}", errno()));
        }
        syscall(nr::CLOSE, rs);
    }
}

fn install_main(c: &Cfg, a: &Args, cordon: bool) {
    unsafe {
        syscall(nr::PRCTL, PR_SET_NO_NEW_PRIVS, 1i64, 0i64, 0i64, 0i64);
        let r: [u64; 2] = [0, 0];
        syscall(nr::PRLIMIT64, 0i64, 4i64 /* RLIMIT_CORE */, r.as_ptr(), std::ptr::null::<u8>());
        if !c.is("dumpable-1") {
            syscall(nr::PRCTL, PR_SET_DUMPABLE, 0i64, 0i64, 0i64, 0i64);
        }
    }
    if !c.is("no-landlock") {
        landlock(&a.allow_dir);
    }
    install_filter(&main_filter(c, cordon));
}

// --------------------------------------------------------------------------------------------- probes
static REMOTE: [u8; 8] = *b"synprobe";

fn wait_child(pid: i64) {
    let mut st: c_int = 0;
    unsafe {
        syscall(nr::WAIT4, pid, &mut st as *mut c_int, 0i64, std::ptr::null::<u8>());
    }
}
// Fork-like raw clone: the child exits at once, the parent reaps it.
fn clone_like(r: c_long) -> (i64, i64) {
    if r == 0 {
        exit_now(0);
    }
    let x = sys_ret(r);
    if x.0 > 0 {
        wait_child(x.0);
    }
    x
}

/// Runs one probe syscall. Returns (ret, errno). Never returns for a successful execve.
fn run_syscall(a: &Args) -> (i64, i64) {
    let tgt = || CString::new(a.target.clone()).unwrap_or_else(|_| die(64, "--target"));
    unsafe {
        match a.probe.as_str() {
            "noop" => sys_ret(syscall(nr::GETPID)),
            "dumpable" => sys_ret(syscall(nr::PRCTL, PR_GET_DUMPABLE, 0i64, 0i64, 0i64, 0i64)),
            "clone_newuser" => clone_like(syscall(nr::CLONE, CLONE_NEWUSER | SIGCHLD, 0i64, 0i64, 0i64, 0i64)),
            "fork" => clone_like(syscall(nr::CLONE, SIGCHLD, 0i64, 0i64, 0i64, 0i64)),
            "clone3" => {
                let ca: [u64; 8] = [0, 0, 0, 0, SIGCHLD as u64, 0, 0, 0];
                clone_like(syscall(nr::CLONE3, ca.as_ptr(), 64usize))
            }
            "unshare_newuser" => sys_ret(syscall(nr::UNSHARE, CLONE_NEWUSER)),
            "unshare_newnet" => sys_ret(syscall(nr::UNSHARE, CLONE_NEWNET)),
            "setns" => sys_ret(syscall(nr::SETNS, -1i64, 0i64)),
            "socket_inet" => sys_ret(syscall(nr::SOCKET, 2i64, 1i64 | 0o2000000, 0i64)),
            "socket_inet6" => sys_ret(syscall(nr::SOCKET, 10i64, 1i64 | 0o2000000, 0i64)),
            "socket_unix" => sys_ret(syscall(nr::SOCKET, 1i64, 1i64 | 0o2000000, 0i64)),
            "socket_netlink" => sys_ret(syscall(nr::SOCKET, 16i64, 3i64 | 0o2000000, 0i64)),
            "socketpair" => {
                let mut sv: [c_int; 2] = [-1, -1];
                sys_ret(syscall(nr::SOCKETPAIR, 1i64, 1i64, 0i64, sv.as_mut_ptr()))
            }
            "tcp_ulp" => {
                let v = b"tls";
                sys_ret(syscall(nr::SETSOCKOPT, a.fd, 6i64, 31i64, v.as_ptr(), 3u32))
            }
            "connect_tcp" => {
                let mut sa = [0u8; 16];
                sa[0] = 2; // AF_INET, little-endian u16
                sa[2..4].copy_from_slice(&a.port.to_be_bytes());
                sa[4..8].copy_from_slice(&[127, 0, 0, 1]);
                sys_ret(syscall(nr::CONNECT, a.fd, sa.as_ptr(), 16u32))
            }
            "bpf" => {
                let attr = [0u8; 128];
                sys_ret(syscall(nr::BPF, 5i64 /* BPF_PROG_LOAD */, attr.as_ptr(), 128u32))
            }
            "io_uring_setup" => {
                let mut p = [0u8; 120];
                sys_ret(syscall(nr::IO_URING_SETUP, 1u32, p.as_mut_ptr()))
            }
            "perf_event_open" => {
                let mut attr = [0u8; 128];
                attr[0..4].copy_from_slice(&1u32.to_le_bytes()); // PERF_TYPE_SOFTWARE
                attr[4..8].copy_from_slice(&128u32.to_le_bytes());
                attr[40..48].copy_from_slice(&(1u64 | (1 << 5) | (1 << 6)).to_le_bytes()); // disabled, excl kernel/hv
                sys_ret(syscall(nr::PERF_EVENT_OPEN, attr.as_ptr(), 0i64, -1i64, -1i64, 0i64))
            }
            "ptrace" => sys_ret(syscall(nr::PTRACE, 0i64 /* PTRACE_TRACEME */, 0i64, 0i64, 0i64)),
            "process_vm_readv" => {
                let mut buf = [0u8; 8];
                let local: [usize; 2] = [buf.as_mut_ptr() as usize, 8];
                let remote: [usize; 2] = [REMOTE.as_ptr() as usize, 8];
                let pid = syscall(nr::GETPID);
                sys_ret(syscall(nr::PROCESS_VM_READV, pid, local.as_ptr(), 1u64, remote.as_ptr(), 1u64, 0u64))
            }
            "userfaultfd" => sys_ret(syscall(nr::USERFAULTFD, 0o2000000i64 | 1 /* UFFD_USER_MODE_ONLY */)),
            "keyctl" => sys_ret(syscall(nr::KEYCTL, 0i64 /* GET_KEYRING_ID */, -3i64 /* session */, 0i64)),
            "mount" => {
                let (s, t, ty) = (CString::new("none").unwrap_or_default(), CString::new("/").unwrap_or_default(), CString::new("tmpfs").unwrap_or_default());
                sys_ret(syscall(nr::MOUNT, s.as_ptr(), t.as_ptr(), ty.as_ptr(), 0u64, std::ptr::null::<u8>()))
            }
            "execve" => {
                let p = CString::new("/bin/true").unwrap_or_default();
                let argv = [p.as_ptr(), std::ptr::null()];
                let envp: [*const i8; 1] = [std::ptr::null()];
                sys_ret(syscall(nr::EXECVE, p.as_ptr(), argv.as_ptr(), envp.as_ptr()))
            }
            "open_outside" | "open_inside" => {
                let t = tgt();
                sys_ret(syscall(nr::OPENAT, -100i64, t.as_ptr(), 0o2000000i64))
            }
            other => die(64, &format!("unknown probe {other}")),
        }
    }
}

fn probe_here(a: &Args, stage: &str) {
    out(&format!(
        "{{\"event\":\"armed\",\"probe\":\"{}\",\"path\":\"{}\",\"stage\":\"{}\",\"pid\":{}}}",
        a.probe,
        a.path,
        stage,
        std::process::id()
    ));
    let (r, e) = run_syscall(a);
    out(&format!(
        "{{\"event\":\"result\",\"probe\":\"{}\",\"path\":\"{}\",\"stage\":\"{}\",\"ret\":{},\"errno\":{}}}",
        a.probe, a.path, stage, r, e
    ));
}

fn main() {
    let a = parse();
    if a.facts {
        out(&format!("{{\"landlock_abi\":{}}}", landlock_abi()));
        return;
    }
    if !a.mutant.is_empty() && !MUTANTS.contains(&a.mutant.as_str()) {
        die(64, &format!("unknown mutant {}", a.mutant));
    }
    let c = Cfg { m: a.mutant.clone() };
    if a.probe.is_empty() {
        die(64, "--probe required");
    }
    match a.path.as_str() {
        "none" => probe_here(&a, "control"),
        "cordon" => {
            install_main(&c, &a, true);
            probe_here(&a, "cordon");
        }
        "forkwasm" => {
            install_main(&c, &a, false);
            if a.stage == "zygote" {
                probe_here(&a, "zygote");
            } else {
                let pid = unsafe { syscall(nr::CLONE, SIGCHLD, 0i64, 0i64, 0i64, 0i64) };
                if pid == 0 {
                    if !c.is("no-child-filter") {
                        install_filter(&child_filter(&c));
                    }
                    probe_here(&a, "child");
                    exit_now(0);
                }
                if pid < 0 {
                    die(70, &format!("zygote fork failed errno={}", errno()));
                }
                let mut st: c_int = 0;
                unsafe {
                    syscall(nr::WAIT4, pid as i64, &mut st as *mut c_int, 0i64, std::ptr::null::<u8>());
                }
                let (sig, code) = if st & 0x7f == 0 {
                    ("null".to_string(), ((st >> 8) & 0xff).to_string())
                } else {
                    ((st & 0x7f).to_string(), "null".to_string())
                };
                out(&format!(
                    "{{\"event\":\"child-exit\",\"probe\":\"{}\",\"path\":\"forkwasm\",\"stage\":\"child\",\"pid\":{},\"signal\":{},\"code\":{}}}",
                    a.probe, pid, sig, code
                ));
            }
        }
        p => die(64, &format!("unknown --path {p}")),
    }
    exit_now(0);
}
