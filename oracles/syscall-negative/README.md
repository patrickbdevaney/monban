# syscall-negative oracle (Phase-5 gate p2-syscall-negative)

`./run` checks that a P2 isolation subject's own sandbox kills (or, for clone3, answers ENOSYS to) every syscall a
Wasm-escaped attacker would use to reach the kernel's large attack surfaces, on both P2 paths. `./run --self-test`
shows the check turning red on seven mutated sandboxes. Unit P5-oracle-syscall-001; the gate itself is owned by
P5-iso-001 (`gates/phase-5.toml`).

## What is checked

Spec: ARCHITECTURE §3.6 R-ISO-4/5 (clone-flag filter, clone3 → ENOSYS, unshare/setns denied, the child denylist
socket/setsockopt(TCP_ULP)/bpf/perf/io_uring, PR_SET_DUMPABLE=0, exec spawn); PLAN D2 (namespaces unavailable;
AppArmor userns restriction; pass on the filter signature only) and D5 (seccomp layout, child-only filter, Landlock
before seccomp: fs read-only beneath the module/data dir, TCP bind/connect with no rule allowed). The INV-P2
statements of the F1 addendum (P5-spec-001) cite these obligations.

Probes (26), each run at three stages: `cordon`, `forkwasm-child` (fork child after the child filter, where guest
code runs), `forkwasm-zygote` (the zygote's own filter; `fork` is skipped there because the zygote must fork).
77 cells in total.

| kind | probes | pass only on |
|---|---|---|
| kill | clone(CLONE_NEWUSER), unshare(CLONE_NEWUSER), unshare(CLONE_NEWNET), setns, socket(AF_INET/AF_INET6/AF_UNIX/AF_NETLINK), socketpair, setsockopt(TCP_ULP,"tls") on a pre-opened established TCP fd, bpf(BPF_PROG_LOAD), io_uring_setup, perf_event_open, ptrace(TRACEME), process_vm_readv, userfaultfd, keyctl, mount, execve, fork (clone(SIGCHLD)) | death by SIGSYS |
| enosys | clone3 | errno ENOSYS, and only if the unfiltered control was not already ENOSYS |
| landlock | open a file outside the allowed dir; connect() a pre-opened unconnected TCP fd to 127.0.0.1 | errno EACCES (Landlock), or SIGSYS; EACCES only if the control was not already EACCES |
| dumpable | prctl(PR_GET_DUMPABLE) in cordon, zygote and child | ret 0 |
| allow (vacuity) | getpid; open a file inside the allowed dir | success (a sandbox that kills everything fails here) |

EPERM never passes: `unprivileged_bpf_disabled=2` already gives EPERM for bpf, so EPERM is indistinguishable from
the kernel default (PLAN D2). An error that is not the filter's signature fails, whatever the control said.

**Controls and host facts.** Before judging, every probe runs once unfiltered (`synprobe --path none`, the oracle's
own binary, independent of the subject). A control that already fails is reported as `masked (errno N)`; the
subject must still show the filter signature. A control that crashes or hangs fails the run (the oracle cannot
judge). Recorded host facts: kernel release, `apparmor_restrict_unprivileged_userns`,
`apparmor_restrict_unprivileged_unconfined`, `unprivileged_userns_clone`, `max_user_namespaces`,
`unprivileged_bpf_disabled`, `io_uring_disabled`, `perf_event_paranoid`, `unprivileged_userfaultfd`,
`yama/ptrace_scope`, and the Landlock ABI (`synprobe --facts`). The oracle is host-agnostic by construction: it
judges against the recorded control, so it has no `needs`.

## Probe protocol (`--subject '<cmd>'`)

The oracle splits `<cmd>` with shell rules and appends:

```
--path forkwasm|cordon [--stage zygote] --probe <name> --allow-dir <dir> [--target <path>] [--fd <n>] [--port <p>]
```

The subject must run **its own** sandbox install for that path (rlimits, PR_SET_NO_NEW_PRIVS, PR_SET_DUMPABLE=0,
Landlock with `<dir>` as the only readable module/data directory, seccomp), then issue exactly the named syscall.

- `--path cordon` or `--stage zygote`: the process that installed the sandbox issues the syscall.
- `--path forkwasm` without `--stage`: the zygote installs its sandbox, forks one child the way it does per request,
  the child installs the child-only filter and issues the syscall; the zygote reaps the child and reports it.
- `--fd <n>` is an fd the oracle passed in (inherited at the same number): an established TCP connection for
  `tcp_ulp`, an unconnected TCP socket for `connect_tcp` (with `--port`, a 127.0.0.1 listener held by the oracle).
  `--target` is the file for `open_inside` / `open_outside`.

Stdout carries JSON lines:

1. `{"event":"armed","probe":P,"path":..,"stage":"cordon|zygote|child","pid":N}`, flushed after the sandbox is in
   place and immediately before the syscall. A process that dies before this line is an error, not a pass (a
   sandbox that kills itself during install proves nothing).
2. The one outcome line. If the syscall returns: `{"event":"result","probe":P,"path":..,"stage":..,"ret":R,"errno":E}`
   (`errno` 0 when `ret >= 0`). If it does not return, the oracle reads the outcome from the process wait status
   (cordon, zygote stage) or from the zygote's line `{"event":"child-exit","probe":P,"path":"forkwasm",
   "stage":"child","pid":N,"signal":S|null,"code":C|null}` (child stage; the zygote must then exit 0).

A successful `execve` (of `/bin/true`) shows as armed, no result, exit 0, and is judged as "the syscall succeeded".
Probe names: `noop dumpable clone_newuser unshare_newuser unshare_newnet setns clone3 socket_inet socket_inet6
socket_unix socket_netlink socketpair tcp_ulp bpf io_uring_setup perf_event_open ptrace process_vm_readv userfaultfd
keyctl mount execve fork open_inside open_outside connect_tcp`. Each run has a 15 s timeout; the oracle starts the
subject in its own session and SIGKILLs that process group by its explicit pgid on timeout.

Real subjects (gate cmd): `target/p2/release/p2-subject probe` and `target/p2-test/release/aegis-p2 probe`
(test-hooks build, PLAN D15).

## Reference subject (`rust/`, `synprobe`)

No dependencies (libc symbols declared by hand), toolchain 1.98.0, x86_64 only. The isofi design (hand-rolled
Landlock and seccomp, `oracles/isolation-fi/rust/host/src/main.rs`) extended to D5:

- PR_SET_NO_NEW_PRIVS, RLIMIT_CORE=0, PR_SET_DUMPABLE=0; Landlock (refuses below ABI 4 with exit 78, as D2): every fs
  access right the ABI knows is handled, READ_FILE|READ_DIR allowed beneath `--allow-dir`; BIND_TCP|CONNECT_TCP
  handled with no rule; then seccomp.
- seccomp: arch check (x86_64, else kill), x32 numbers (≥0x40000000) killed; clone3 → ERRNO(ENOSYS); clone with any
  CLONE_NEW* bit → kill (a cordon additionally only gets clone with CLONE_THREAD: no fork); setsockopt(SOL_TCP,
  TCP_ULP) → kill; explicit KILL_PROCESS denylist (unshare, setns, socket, socketpair, bpf, perf_event_open,
  io_uring_*, ptrace, process_vm_readv/writev, userfaultfd, keyctl/add_key/request_key, mount family, execve,
  execveat); a small allowlist; default KILL_PROCESS. `connect` is allowlisted on purpose so the connect probe
  observes Landlock's net rule. `prctl` is unrestricted (reference simplification).
- forkwasm child filter: kills clone, fork, vfork, execve, execveat; everything else falls through to the inherited
  zygote filter.

## Self-test mutants (each must be red on an expected cell)

| mutant | change | expected red cell(s) (any of) | measured 2026-10-31 |
|---|---|---|---|
| no-clone-flag-filter | clone flag check removed, unshare/setns allowed | zygote clone_newuser, unshare_newuser | 10 cells red |
| no-denylist | explicit denylist and TCP_ULP rule removed, default ALLOW | socket_inet | 53 cells red |
| eperm-instead-of-kill | every KILL_PROCESS becomes ERRNO(EPERM) | bpf (EPERM equals the masked control) | 59 cells red |
| clone3-allowed | clone3 allowed | clone3 | 3 cells red |
| dumpable-1 | PR_SET_DUMPABLE(0) skipped | dumpable | 3 cells red |
| no-landlock | Landlock not installed | open_outside | 6 cells red |
| no-child-filter | fork child adds no filter | forkwasm-child fork | 1 cell red |

The unmutated reference must pass all 77 cells in the same self-test.

## Re-run in repo (laptop, 2026-10-31, Linux 6.17.0-14-generic, Landlock ABI 7)

- `./run`: `SYSCALL-NEGATIVE: PASS (77 cells on 3 stages, 5 masked controls, kernel 6.17.0-14-generic, landlock ABI 7)`.
- `./run --self-test`: `SYSCALL-NEGATIVE SELF-TEST: PASS (7/7 mutants red, reference green on 77 cells, 5 masked
  controls: unshare_newnet,setns,bpf,perf_event_open,mount)`.
- Host facts: apparmor_restrict_unprivileged_userns=1, unprivileged_bpf_disabled=2, io_uring_disabled=0,
  perf_event_paranoid=4, unprivileged_userfaultfd=0 (the probe uses UFFD_USER_MODE_ONLY, which the control
  permits), ptrace_scope=1. Unfiltered: clone/unshare(CLONE_NEWUSER) succeed (capability-less userns, as D2
  measured), io_uring_setup succeeds, TCP_ULP "tls" succeeds (tls module loaded), bpf EPERM, perf EACCES,
  unshare(CLONE_NEWNET) EPERM, mount EPERM, setns(-1) EBADF.

Provenance: design from `spikes/q4-006/README.md` (sha256 55613dcf…ac57d; Limits: "the child-only denylist was not
installed in the spike") and the isofi filter. No research artifact is executed.

## Known limits

- SIGSYS from SECCOMP_RET_KILL_PROCESS is not distinguishable from KILL_THREAD in a single-threaded probe, nor from
  SECCOMP_RET_TRAP with no SIGSYS handler installed, nor from a subject raising SIGSYS itself. The oracle accepts
  any SIGSYS death after the armed line.
- The subject reports its own child's fate on the forkwasm child stage (the zygote's `child-exit` line); a dishonest
  probe build could lie. The probe lives behind the `test-hooks` feature (D15) and is reviewed with the subject.
- setns is probed with fd -1 (control EBADF, masked); the filter kills on the syscall number, so arguments do not
  matter for the reference, but an argument-filtered subject rule is only exercised for that argument.
- Only the listed syscalls are probed; the allowlist itself is not enumerated (a subject that allows, say,
  `kexec_load` is not caught here). Arguments of allowlisted syscalls (prctl, ioctl) are not probed.
- x86_64 only. Kernel facts differ by host; on a VPS kernel without the AppArmor userns restriction, CLONE_NEWUSER
  grants capabilities in the new namespace, and the filter is the control either way (D2).
