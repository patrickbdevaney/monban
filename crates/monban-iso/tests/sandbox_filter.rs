//! Layout tests for the seccomp programs of `monban_iso::sandbox::filter` (PLAN-5 D5), run through a small
//! classic-BPF interpreter: no kernel involved, so they run anywhere. The kernel-level check is the
//! syscall-negative oracle (gate p2-syscall-negative).

use monban_iso::sandbox::filter::{self, Insn, Kind, nr};

const KILL: u32 = filter::RET_KILL_PROCESS;
const ALLOW: u32 = filter::RET_ALLOW;
const ENOSYS: u32 = filter::RET_ERRNO | filter::ENOSYS;

/// Runs `prog` on a `seccomp_data` (nr, arch, args). Returns the action, or None on a malformed program.
fn run(prog: &[Insn], arch: u32, n: u32, args: [u64; 6]) -> Option<u32> {
    let word = |off: u32| -> Option<u32> {
        match off {
            0 => Some(n),
            4 => Some(arch),
            o if (16..64).contains(&o) && o % 4 == 0 => {
                let i = usize::try_from((o - 16) / 8).ok()?;
                let a = *args.get(i)?;
                Some(if (o - 16) % 8 == 0 { a as u32 } else { (a >> 32) as u32 })
            }
            _ => None,
        }
    };
    let mut acc = 0u32;
    let mut pc = 0usize;
    for _ in 0..10_000 {
        let ins = *prog.get(pc)?;
        match ins.code {
            0x20 => acc = word(ins.k)?,
            0x06 => return Some(ins.k),
            0x15 | 0x35 | 0x45 => {
                let t = match ins.code {
                    0x15 => acc == ins.k,
                    0x35 => acc >= ins.k,
                    _ => acc & ins.k != 0,
                };
                pc += usize::from(if t { ins.jt } else { ins.jf });
            }
            _ => return None,
        }
        pc += 1;
    }
    None
}

fn act(kind: Kind, n: u32, args: [u64; 6]) -> u32 {
    let prog = filter::program(kind).unwrap_or_default();
    run(&prog, filter::AUDIT_ARCH_X86_64, n, args).unwrap_or(0xdead)
}

const NONE: [u64; 6] = [0; 6];
const SIGCHLD: u64 = 17;
const THREAD_FLAGS: u64 = 0x003d_0f00; // glibc pthread_create

#[test]
fn programs_build_and_fit() {
    for k in [Kind::Zygote, Kind::Cordon, Kind::Child] {
        let p = filter::program(k);
        assert!(p.as_ref().is_ok_and(|p| !p.is_empty() && p.len() < 4096), "{k:?}: {p:?}");
    }
}

#[test]
fn wrong_arch_and_x32_are_killed() {
    for k in [Kind::Zygote, Kind::Cordon, Kind::Child] {
        let prog = filter::program(k).unwrap_or_default();
        assert_eq!(run(&prog, 0x4000_0003 /* i386 */, nr::GETPID, NONE), Some(KILL));
        assert_eq!(run(&prog, filter::AUDIT_ARCH_X86_64, nr::GETPID | filter::X32_BIT, NONE), Some(KILL));
    }
}

#[test]
fn d5_denylist_is_killed_in_zygote_and_cordon() {
    for k in [Kind::Zygote, Kind::Cordon] {
        for &n in filter::DENYLIST {
            assert_eq!(act(k, n, NONE), KILL, "{k:?} nr {n}");
        }
        assert_eq!(act(k, 9999, NONE), KILL, "{k:?}: default must be kill");
    }
}

#[test]
fn denylist_and_allowlist_are_disjoint() {
    for n in filter::DENYLIST {
        assert!(!filter::ALLOWLIST.contains(n), "nr {n} on both lists");
    }
}

#[test]
fn clone3_is_enosys_everywhere_it_is_reached() {
    assert_eq!(act(Kind::Zygote, nr::CLONE3, NONE), ENOSYS);
    assert_eq!(act(Kind::Cordon, nr::CLONE3, NONE), ENOSYS);
    // the child filter lets it fall through to the inherited zygote filter (ENOSYS)
    assert_eq!(act(Kind::Child, nr::CLONE3, NONE), ALLOW);
}

#[test]
fn clone_flag_filter() {
    let newuser = 0x1000_0000u64;
    let newnet = 0x4000_0000u64;
    for k in [Kind::Zygote, Kind::Cordon] {
        assert_eq!(act(k, nr::CLONE, [newuser | SIGCHLD, 0, 0, 0, 0, 0]), KILL, "{k:?}");
        assert_eq!(act(k, nr::CLONE, [newnet | THREAD_FLAGS, 0, 0, 0, 0, 0]), KILL, "{k:?}");
        assert_eq!(act(k, nr::CLONE, [THREAD_FLAGS, 0, 0, 0, 0, 0]), ALLOW, "{k:?}: threads");
    }
    // zygote forks; a cordon never does
    assert_eq!(act(Kind::Zygote, nr::CLONE, [0x0120_0011, 0, 0, 0, 0, 0]), ALLOW);
    assert_eq!(act(Kind::Cordon, nr::CLONE, [0x0120_0011, 0, 0, 0, 0, 0]), KILL);
}

#[test]
fn tcp_ulp_and_non_socket_levels_are_killed() {
    for k in [Kind::Zygote, Kind::Cordon] {
        assert_eq!(act(k, nr::SETSOCKOPT, [3, 6, 31, 0, 3, 0]), KILL, "{k:?} TCP_ULP");
        assert_eq!(act(k, nr::SETSOCKOPT, [3, 1, 20, 0, 16, 0]), ALLOW, "{k:?} SOL_SOCKET");
    }
}

#[test]
fn prctl_cannot_reenable_dumping() {
    for k in [Kind::Zygote, Kind::Cordon] {
        assert_eq!(act(k, nr::PRCTL, [4, 1, 0, 0, 0, 0]), KILL, "{k:?} PR_SET_DUMPABLE");
        assert_eq!(act(k, nr::PRCTL, [3, 0, 0, 0, 0, 0]), ALLOW, "{k:?} PR_GET_DUMPABLE");
        assert_eq!(act(k, nr::PRCTL, [22, 2, 0, 0, 0, 0]), KILL, "{k:?} PR_SET_SECCOMP");
    }
}

#[test]
fn prlimit_only_on_self() {
    for k in [Kind::Zygote, Kind::Cordon] {
        assert_eq!(act(k, nr::PRLIMIT64, [0, 7, 0, 0, 0, 0]), ALLOW, "{k:?}");
        assert_eq!(act(k, nr::PRLIMIT64, [1234, 7, 0, 0, 0, 0]), KILL, "{k:?}");
        assert_eq!(act(k, nr::PRLIMIT64, [1 << 32, 7, 0, 0, 0, 0]), KILL, "{k:?} high half");
    }
}

#[test]
fn only_the_zygote_may_stack_a_filter() {
    assert_eq!(act(Kind::Zygote, nr::SECCOMP, NONE), ALLOW);
    assert_eq!(act(Kind::Cordon, nr::SECCOMP, NONE), KILL);
}

#[test]
fn child_filter_kills_process_creation_and_exec_only() {
    for &n in filter::CHILD_DENYLIST {
        assert_eq!(act(Kind::Child, n, [THREAD_FLAGS, 0, 0, 0, 0, 0]), KILL, "nr {n}");
    }
    for n in [nr::READ, nr::WRITE, nr::MMAP, nr::SETITIMER, nr::EXIT_GROUP] {
        assert_eq!(act(Kind::Child, n, NONE), ALLOW, "nr {n}");
    }
}

#[test]
fn landlock_fs_rights_track_the_abi() {
    use monban_iso::sandbox::landlock::handled_fs;
    assert_eq!(handled_fs(1), (1 << 13) - 1);
    assert_eq!(handled_fs(4), (1 << 15) - 1);
    assert_eq!(handled_fs(7), (1 << 16) - 1);
}
