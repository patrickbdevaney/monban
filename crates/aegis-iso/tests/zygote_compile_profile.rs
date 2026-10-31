//! Layout of the compile filter (`Kind::Compile`, used by `aegis-p2 compile` before it runs; PLAN-5 D4) next to the
//! serving filters: the atomic-write calls are allowed only in the compile layout, which otherwise keeps the cordon's
//! rules (D5 denylist first, no fork, no network). Same classic-BPF interpreter as tests/sandbox_filter.rs.
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use aegis_iso::sandbox::filter::{self, Insn, Kind, nr};

const KILL: u32 = filter::RET_KILL_PROCESS;
const ALLOW: u32 = filter::RET_ALLOW;
const NONE: [u64; 6] = [0; 6];
const SIGCHLD: u64 = 17;
const THREAD_FLAGS: u64 = 0x003d_0f00;

fn run(prog: &[Insn], n: u32, args: [u64; 6]) -> Option<u32> {
    let word = |off: u32| -> Option<u32> {
        match off {
            0 => Some(n),
            4 => Some(filter::AUDIT_ARCH_X86_64),
            o if (16..64).contains(&o) && o % 4 == 0 => {
                let a = args[usize::try_from((o - 16) / 8).ok()?];
                Some(if (o - 16) % 8 == 0 { a as u32 } else { (a >> 32) as u32 })
            }
            _ => None,
        }
    };
    let (mut acc, mut pc) = (0u32, 0usize);
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
    run(&filter::program(kind).unwrap(), n, args).unwrap_or(0xdead)
}

#[test]
fn compile_layout_allows_the_atomic_write_and_nothing_else_new() {
    for &n in filter::COMPILE_EXTRA {
        assert_eq!(act(Kind::Compile, n, NONE), ALLOW, "compile nr {n}");
        assert_eq!(act(Kind::Zygote, n, NONE), KILL, "zygote nr {n}");
        assert_eq!(act(Kind::Cordon, n, NONE), KILL, "cordon nr {n}");
        assert!(!filter::DENYLIST.contains(&n), "nr {n} is on the denylist");
    }
    for &n in filter::DENYLIST {
        assert_eq!(act(Kind::Compile, n, NONE), KILL, "compile denylist nr {n}");
    }
    for &n in filter::ALLOWLIST {
        assert_eq!(act(Kind::Compile, n, NONE), act(Kind::Cordon, n, NONE), "nr {n} differs from the cordon");
    }
    // no fork, threads only; no seccomp stacking; default kill
    assert_eq!(act(Kind::Compile, nr::CLONE, [SIGCHLD, 0, 0, 0, 0, 0]), KILL);
    assert_eq!(act(Kind::Compile, nr::CLONE, [THREAD_FLAGS, 0, 0, 0, 0, 0]), ALLOW);
    assert_eq!(act(Kind::Compile, nr::SECCOMP, NONE), KILL);
    assert_eq!(act(Kind::Compile, 9999, NONE), KILL);
}
