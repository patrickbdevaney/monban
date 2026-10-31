//! seccomp-BPF programs for the P2 sandbox (PLAN-5 D5, ARCHITECTURE R-ISO-4/5). Pure: builds the instruction
//! vectors that [`super::install`] loads; nothing here touches the kernel, so the layout is unit-testable (the
//! `tests/sandbox_filter.rs` interpreter runs these programs against syscall numbers and arguments).
//!
//! Main filter (zygote and cordon), in evaluation order:
//! 1. arch check: anything but `AUDIT_ARCH_X86_64` is killed; x32 numbers (bit 30 set) are killed.
//! 2. `clone3` → `ERRNO(ENOSYS)`, so libc falls back to the flag-filtered `clone`.
//! 3. `clone`: any `CLONE_NEW*` bit → kill. A cordon additionally only gets `CLONE_THREAD` clones (no fork at all).
//! 4. `setsockopt`: only `SOL_SOCKET` options pass; every other level (`SOL_TCP`/`TCP_ULP` included) is killed.
//! 5. `prctl`: a small option allowlist; `PR_SET_DUMPABLE` (re-enabling dumps) and everything else is killed.
//! 6. `prlimit64`: only on the calling process (pid 0).
//! 7. explicit `KILL_PROCESS` denylist (checked before the allowlist, so a later allowlist edit cannot let one in).
//! 8. the allowlist; then default `KILL_PROCESS`.
//!
//! Child filter (fork+Wasm child, stacked on the inherited zygote filter): kills `clone`, `fork`, `vfork`,
//! `execve`, `execveat`; everything else falls through to the zygote filter.
//!
//! x86_64 numbers only; [`super::install`] refuses on any other target.

/// One classic-BPF instruction (`struct sock_filter`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    /// Opcode.
    pub code: u16,
    /// Jump offset if true.
    pub jt: u8,
    /// Jump offset if false.
    pub jf: u8,
    /// Constant operand.
    pub k: u32,
}

/// Which program to build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// fork+Wasm zygote: may fork (no `CLONE_NEW*`), may install the child filter.
    Zygote,
    /// Per-principal cordon: threads only, no fork, no further filters.
    Cordon,
    /// fork+Wasm child: the small stacked filter.
    Child,
    /// The sandboxed `aegis-p2 compile` (PLAN-5 D4): the cordon layout plus [`COMPILE_EXTRA`] (write the `.cwasm`
    /// atomically: fsync, rename, unlink), all bounded by Landlock to the output directory.
    Compile,
}

/// `AUDIT_ARCH_X86_64`.
pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
/// `SECCOMP_RET_KILL_PROCESS`.
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
/// `SECCOMP_RET_ERRNO` (low 16 bits carry the errno).
pub const RET_ERRNO: u32 = 0x0005_0000;
/// `SECCOMP_RET_ALLOW`.
pub const RET_ALLOW: u32 = 0x7fff_0000;
/// `ENOSYS`.
pub const ENOSYS: u32 = 38;
/// `__X32_SYSCALL_BIT`.
pub const X32_BIT: u32 = 0x4000_0000;
/// `CLONE_THREAD`.
pub const CLONE_THREAD: u32 = 0x0001_0000;
/// Every namespace flag: NEWTIME | NEWNS | NEWCGROUP | NEWUTS | NEWIPC | NEWUSER | NEWPID | NEWNET.
pub const CLONE_NEW_MASK: u32 =
    0x0000_0080 | 0x0002_0000 | 0x0200_0000 | 0x0400_0000 | 0x0800_0000 | 0x1000_0000 | 0x2000_0000 | 0x4000_0000;
/// `SOL_SOCKET`.
pub const SOL_SOCKET: u32 = 1;

/// `prctl` options the sandboxed process may use: GET_DUMPABLE, SET_NAME, GET_NAME, GET_SECCOMP,
/// SET_NO_NEW_PRIVS (only ever tightens), GET_NO_NEW_PRIVS, SET_VMA (glibc anon-mapping names).
pub const PRCTL_ALLOWED: &[u32] = &[3, 15, 16, 21, 38, 39, 0x5356_4d41];

/// x86_64 syscall numbers used by the filters.
#[allow(missing_docs)]
pub mod nr {
    pub const READ: u32 = 0;
    pub const WRITE: u32 = 1;
    pub const CLOSE: u32 = 3;
    pub const FSTAT: u32 = 5;
    pub const POLL: u32 = 7;
    pub const LSEEK: u32 = 8;
    pub const MMAP: u32 = 9;
    pub const MPROTECT: u32 = 10;
    pub const MUNMAP: u32 = 11;
    pub const BRK: u32 = 12;
    pub const RT_SIGACTION: u32 = 13;
    pub const RT_SIGPROCMASK: u32 = 14;
    pub const RT_SIGRETURN: u32 = 15;
    pub const IOCTL: u32 = 16;
    pub const PREAD64: u32 = 17;
    pub const PWRITE64: u32 = 18;
    pub const READV: u32 = 19;
    pub const WRITEV: u32 = 20;
    pub const SCHED_YIELD: u32 = 24;
    pub const MREMAP: u32 = 25;
    pub const MADVISE: u32 = 28;
    pub const DUP: u32 = 32;
    pub const NANOSLEEP: u32 = 35;
    pub const GETITIMER: u32 = 36;
    pub const SETITIMER: u32 = 38;
    pub const GETPID: u32 = 39;
    pub const SOCKET: u32 = 41;
    pub const CONNECT: u32 = 42;
    pub const ACCEPT: u32 = 43;
    pub const SENDTO: u32 = 44;
    pub const RECVFROM: u32 = 45;
    pub const SENDMSG: u32 = 46;
    pub const RECVMSG: u32 = 47;
    pub const SHUTDOWN: u32 = 48;
    pub const BIND: u32 = 49;
    pub const LISTEN: u32 = 50;
    pub const GETSOCKNAME: u32 = 51;
    pub const GETPEERNAME: u32 = 52;
    pub const SOCKETPAIR: u32 = 53;
    pub const SETSOCKOPT: u32 = 54;
    pub const GETSOCKOPT: u32 = 55;
    pub const CLONE: u32 = 56;
    pub const FORK: u32 = 57;
    pub const VFORK: u32 = 58;
    pub const EXECVE: u32 = 59;
    pub const EXIT: u32 = 60;
    pub const WAIT4: u32 = 61;
    pub const KILL: u32 = 62;
    pub const UNAME: u32 = 63;
    pub const FCNTL: u32 = 72;
    pub const FSYNC: u32 = 74;
    pub const FDATASYNC: u32 = 75;
    pub const FTRUNCATE: u32 = 77;
    pub const GETCWD: u32 = 79;
    pub const RENAME: u32 = 82;
    pub const UNLINK: u32 = 87;
    pub const READLINK: u32 = 89;
    pub const PTRACE: u32 = 101;
    pub const GETUID: u32 = 102;
    pub const GETGID: u32 = 104;
    pub const GETEUID: u32 = 107;
    pub const GETEGID: u32 = 108;
    pub const GETPPID: u32 = 110;
    pub const SIGALTSTACK: u32 = 131;
    pub const PIVOT_ROOT: u32 = 155;
    pub const PRCTL: u32 = 157;
    pub const CHROOT: u32 = 161;
    pub const MOUNT: u32 = 165;
    pub const UMOUNT2: u32 = 166;
    pub const SWAPON: u32 = 167;
    pub const SWAPOFF: u32 = 168;
    pub const REBOOT: u32 = 169;
    pub const INIT_MODULE: u32 = 175;
    pub const DELETE_MODULE: u32 = 176;
    pub const GETTID: u32 = 186;
    pub const FUTEX: u32 = 202;
    pub const SCHED_GETAFFINITY: u32 = 204;
    pub const GETDENTS64: u32 = 217;
    pub const CLOCK_GETTIME: u32 = 228;
    pub const CLOCK_GETRES: u32 = 229;
    pub const CLOCK_NANOSLEEP: u32 = 230;
    pub const EXIT_GROUP: u32 = 231;
    pub const EPOLL_WAIT: u32 = 232;
    pub const EPOLL_CTL: u32 = 233;
    pub const TGKILL: u32 = 234;
    pub const ADD_KEY: u32 = 248;
    pub const REQUEST_KEY: u32 = 249;
    pub const KEYCTL: u32 = 250;
    pub const OPENAT: u32 = 257;
    pub const NEWFSTATAT: u32 = 262;
    pub const UNLINKAT: u32 = 263;
    pub const RENAMEAT: u32 = 264;
    pub const READLINKAT: u32 = 267;
    pub const PPOLL: u32 = 271;
    pub const UNSHARE: u32 = 272;
    pub const SET_ROBUST_LIST: u32 = 273;
    pub const EPOLL_PWAIT: u32 = 281;
    pub const EVENTFD2: u32 = 290;
    pub const ACCEPT4: u32 = 288;
    pub const EPOLL_CREATE1: u32 = 291;
    pub const DUP3: u32 = 292;
    pub const PIPE2: u32 = 293;
    pub const PERF_EVENT_OPEN: u32 = 298;
    pub const PRLIMIT64: u32 = 302;
    pub const NAME_TO_HANDLE_AT: u32 = 303;
    pub const OPEN_BY_HANDLE_AT: u32 = 304;
    pub const SETNS: u32 = 308;
    pub const PROCESS_VM_READV: u32 = 310;
    pub const PROCESS_VM_WRITEV: u32 = 311;
    pub const KCMP: u32 = 312;
    pub const FINIT_MODULE: u32 = 313;
    pub const RENAMEAT2: u32 = 316;
    pub const SECCOMP: u32 = 317;
    pub const GETRANDOM: u32 = 318;
    pub const MEMFD_CREATE: u32 = 319;
    pub const KEXEC_FILE_LOAD: u32 = 320;
    pub const BPF: u32 = 321;
    pub const EXECVEAT: u32 = 322;
    pub const USERFAULTFD: u32 = 323;
    pub const MEMBARRIER: u32 = 324;
    pub const PKEY_MPROTECT: u32 = 329;
    pub const STATX: u32 = 332;
    pub const RSEQ: u32 = 334;
    pub const KEXEC_LOAD: u32 = 246;
    pub const IO_URING_SETUP: u32 = 425;
    pub const IO_URING_ENTER: u32 = 426;
    pub const IO_URING_REGISTER: u32 = 427;
    pub const OPEN_TREE: u32 = 428;
    pub const MOVE_MOUNT: u32 = 429;
    pub const FSOPEN: u32 = 430;
    pub const FSCONFIG: u32 = 431;
    pub const FSMOUNT: u32 = 432;
    pub const FSPICK: u32 = 433;
    pub const PIDFD_OPEN: u32 = 434;
    pub const CLONE3: u32 = 435;
    pub const PIDFD_GETFD: u32 = 438;
    pub const MOUNT_SETATTR: u32 = 442;
    pub const LANDLOCK_CREATE_RULESET: u32 = 444;
    pub const LANDLOCK_ADD_RULE: u32 = 445;
    pub const LANDLOCK_RESTRICT_SELF: u32 = 446;
}

/// Killed in the zygote and in every cordon (D5 plus the network, module, kexec and fd-stealing families).
/// `connect`, `bind` and `listen` are killed too: a worker only ever uses fds the supervisor passed in, so seccomp
/// is the first network wall and Landlock's TCP rule (no port allowed) the second.
pub const DENYLIST: &[u32] = &[
    nr::UNSHARE,
    nr::SETNS,
    nr::SOCKET,
    nr::SOCKETPAIR,
    nr::CONNECT,
    nr::BIND,
    nr::LISTEN,
    nr::BPF,
    nr::PERF_EVENT_OPEN,
    nr::IO_URING_SETUP,
    nr::IO_URING_ENTER,
    nr::IO_URING_REGISTER,
    nr::PTRACE,
    nr::PROCESS_VM_READV,
    nr::PROCESS_VM_WRITEV,
    nr::USERFAULTFD,
    nr::KEYCTL,
    nr::ADD_KEY,
    nr::REQUEST_KEY,
    nr::MOUNT,
    nr::UMOUNT2,
    nr::PIVOT_ROOT,
    nr::CHROOT,
    nr::OPEN_TREE,
    nr::MOVE_MOUNT,
    nr::FSOPEN,
    nr::FSCONFIG,
    nr::FSMOUNT,
    nr::FSPICK,
    nr::MOUNT_SETATTR,
    nr::EXECVE,
    nr::EXECVEAT,
    nr::FORK,
    nr::VFORK,
    nr::KILL,
    nr::IOCTL,
    nr::KCMP,
    nr::PIDFD_OPEN,
    nr::PIDFD_GETFD,
    nr::NAME_TO_HANDLE_AT,
    nr::OPEN_BY_HANDLE_AT,
    nr::INIT_MODULE,
    nr::FINIT_MODULE,
    nr::DELETE_MODULE,
    nr::KEXEC_LOAD,
    nr::KEXEC_FILE_LOAD,
    nr::SWAPON,
    nr::SWAPOFF,
    nr::REBOOT,
    nr::LANDLOCK_CREATE_RULESET,
    nr::LANDLOCK_ADD_RULE,
    nr::LANDLOCK_RESTRICT_SELF,
];

/// What a sandboxed zygote or cordon (Rust std, glibc, Wasmtime runtime with the pooling allocator, fd-passing
/// I/O) needs after install. Filesystem calls are bounded by Landlock, not here.
pub const ALLOWLIST: &[u32] = &[
    nr::READ,
    nr::WRITE,
    nr::READV,
    nr::WRITEV,
    nr::PREAD64,
    nr::PWRITE64,
    nr::CLOSE,
    nr::FSTAT,
    nr::NEWFSTATAT,
    nr::STATX,
    nr::LSEEK,
    nr::OPENAT,
    nr::GETDENTS64,
    nr::READLINK,
    nr::READLINKAT,
    nr::GETCWD,
    nr::FCNTL,
    nr::DUP,
    nr::DUP3,
    nr::PIPE2,
    nr::FTRUNCATE,
    nr::MEMFD_CREATE,
    nr::POLL,
    nr::PPOLL,
    nr::EPOLL_CREATE1,
    nr::EPOLL_CTL,
    nr::EPOLL_WAIT,
    nr::EPOLL_PWAIT,
    nr::EVENTFD2,
    nr::ACCEPT,
    nr::ACCEPT4,
    nr::RECVFROM,
    nr::SENDTO,
    nr::RECVMSG,
    nr::SENDMSG,
    nr::SHUTDOWN,
    nr::GETSOCKNAME,
    nr::GETPEERNAME,
    nr::GETSOCKOPT,
    nr::MMAP,
    nr::MUNMAP,
    nr::MPROTECT,
    nr::MADVISE,
    nr::MREMAP,
    nr::BRK,
    nr::MEMBARRIER,
    // Wasmtime's pooling allocator with memory_protection_keys (F8 `p2.mpk`, D11): it colours each slot's pages
    // with a key allocated at engine creation (pkey_alloc stays denied after install) on every instance
    // allocation. Same power as mprotect on the process's own mappings.
    nr::PKEY_MPROTECT,
    nr::FUTEX,
    nr::SET_ROBUST_LIST,
    nr::RSEQ,
    nr::RT_SIGACTION,
    nr::RT_SIGPROCMASK,
    nr::RT_SIGRETURN,
    nr::SIGALTSTACK,
    nr::TGKILL,
    nr::GETPID,
    nr::GETTID,
    nr::GETPPID,
    nr::GETUID,
    nr::GETEUID,
    nr::GETGID,
    nr::GETEGID,
    nr::UNAME,
    nr::GETRANDOM,
    nr::CLOCK_GETTIME,
    nr::CLOCK_GETRES,
    nr::CLOCK_NANOSLEEP,
    nr::NANOSLEEP,
    nr::GETITIMER,
    nr::SETITIMER,
    nr::SCHED_YIELD,
    nr::SCHED_GETAFFINITY,
    nr::WAIT4,
    nr::EXIT,
    nr::EXIT_GROUP,
];

/// Added to the cordon layout for [`Kind::Compile`] only: the atomic `.cwasm` write (temp file, fsync, rename; unlink
/// of the temp file on error). Landlock grants write, create and remove rights only beneath the output directory.
pub const COMPILE_EXTRA: &[u32] =
    &[nr::FSYNC, nr::FDATASYNC, nr::RENAME, nr::RENAMEAT, nr::RENAMEAT2, nr::UNLINK, nr::UNLINKAT];

/// Killed by the fork+Wasm child filter.
pub const CHILD_DENYLIST: &[u32] = &[nr::CLONE, nr::FORK, nr::VFORK, nr::EXECVE, nr::EXECVEAT];

const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const JGE_K: u16 = 0x35;
const JSET_K: u16 = 0x45;
const RET_K: u16 = 0x06;

fn ld(off: u32) -> Insn {
    Insn { code: LD_W_ABS, jt: 0, jf: 0, k: off }
}
fn jeq(k: u32, jt: u8, jf: u8) -> Insn {
    Insn { code: JEQ_K, jt, jf, k }
}
fn jge(k: u32, jt: u8, jf: u8) -> Insn {
    Insn { code: JGE_K, jt, jf, k }
}
fn jset(k: u32, jt: u8, jf: u8) -> Insn {
    Insn { code: JSET_K, jt, jf, k }
}
fn ret(k: u32) -> Insn {
    Insn { code: RET_K, jt: 0, jf: 0, k }
}

/// `seccomp_data` offsets: nr @0, arch @4, args\[i\] @16+8i (low 32 bits first on little-endian x86_64).
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
fn arg_lo(i: u32) -> u32 {
    16 + 8 * i
}
fn arg_hi(i: u32) -> u32 {
    20 + 8 * i
}

/// Appends `if nr == n { <body> }` where `body` must end in a return; the false branch skips the body.
fn guard(f: &mut Vec<Insn>, n: u32, body: Vec<Insn>) -> Result<(), FilterError> {
    let len = u8::try_from(body.len()).map_err(|_| FilterError::TooLong)?;
    f.push(jeq(n, 0, len));
    f.extend(body);
    Ok(())
}

/// A program could not be laid out (a conditional block longer than a BPF jump can span).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterError {
    /// A guarded block exceeded 255 instructions.
    TooLong,
}

/// Builds the program for `kind`. The program is re-entrant data: the nr accumulator is reloaded after every
/// block that loads an argument.
pub fn program(kind: Kind) -> Result<Vec<Insn>, FilterError> {
    let kill = ret(RET_KILL_PROCESS);
    let allow = ret(RET_ALLOW);
    let mut f = vec![ld(OFF_ARCH), jeq(AUDIT_ARCH_X86_64, 1, 0), kill, ld(OFF_NR), jge(X32_BIT, 0, 1), kill];
    if kind == Kind::Child {
        for &n in CHILD_DENYLIST {
            f.push(jeq(n, 0, 1));
            f.push(kill);
        }
        f.push(allow);
        return Ok(f);
    }
    // clone3 -> ENOSYS (R-ISO-4): libc falls back to clone, whose flags this filter can read.
    guard(&mut f, nr::CLONE3, vec![ret(RET_ERRNO | ENOSYS)])?;
    // clone: flags are arg0; the kernel uses only its low 32 bits (lower_32_bits(clone_flags)).
    let mut cb = vec![ld(arg_lo(0)), jset(CLONE_NEW_MASK, 0, 1), kill];
    if matches!(kind, Kind::Cordon | Kind::Compile) {
        cb.extend([jset(CLONE_THREAD, 0, 1), allow, kill]);
    } else {
        cb.push(allow);
    }
    guard(&mut f, nr::CLONE, cb)?;
    // setsockopt(fd, level, ..): only SOL_SOCKET (level is an int: low 32 bits).
    guard(&mut f, nr::SETSOCKOPT, vec![ld(arg_lo(1)), jeq(SOL_SOCKET, 0, 1), allow, kill])?;
    // prctl(option, ..): option allowlist (an int: low 32 bits).
    let mut pb = vec![ld(arg_lo(0))];
    for &o in PRCTL_ALLOWED {
        pb.push(jeq(o, 0, 1));
        pb.push(allow);
    }
    pb.push(kill);
    guard(&mut f, nr::PRCTL, pb)?;
    // prlimit64(pid, ..): the calling process only (pid 0, both halves).
    guard(&mut f, nr::PRLIMIT64, vec![ld(arg_lo(0)), jeq(0, 0, 3), ld(arg_hi(0)), jeq(0, 0, 1), allow, kill])?;
    for &n in DENYLIST {
        f.push(jeq(n, 0, 1));
        f.push(kill);
    }
    if kind == Kind::Zygote {
        // the fork child stacks its own filter
        f.push(jeq(nr::SECCOMP, 0, 1));
        f.push(allow);
    }
    if kind == Kind::Compile {
        for &n in COMPILE_EXTRA {
            f.push(jeq(n, 0, 1));
            f.push(allow);
        }
    }
    for &n in ALLOWLIST {
        f.push(jeq(n, 0, 1));
        f.push(allow);
    }
    f.push(kill);
    if f.len() > usize::from(u16::MAX) {
        return Err(FilterError::TooLong);
    }
    Ok(f)
}
