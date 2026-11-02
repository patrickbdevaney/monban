# Phase 5 plan: P2 isolation, both paths (draft, spec author, 2026-10-31, base 2ab7ad5)

Scope (IMPLEMENTATION_PLAN §3 Phase 5): iso full (exec zygote, per-tenant cordons, fork+Wasm mode, crash budgets,
dumpable=0) and wasm (fresh instance per request, fuel, epoch watchdog, MPK density option behind the GHSA-6wgr/394w
assertions). Both P2 paths are built and gated, because P(R1 fires within 12 months) ≈ 0.38 at the 2.21/yr planning
rate (ARCHITECTURE §3.6). The Phase-1 verdict q4-006 picks the default (D1). Gate file: `gates/phase-5.toml`
(67 gates = 57 carried from Phase 4 + 10 new). Units: 16 JSON files here.

Starting point: `crates/aegis-iso` and `crates/aegis-wasm` are Phase-0 stubs (4-line lib.rs each, no third-party
dependency). wasmtime is not in the workspace Cargo.lock; it is pinned at 50.0.0 only in the
`oracles/isolation-fi/rust` workspace and in `supply-chain/lock-targets.toml`. The reference subjects in
`oracles/isolation-fi` (isofi: cordon and fork+Wasm, hand-rolled Landlock and seccomp over libc) are the measured
design. Phase 5 ports that design into the product crates and gates the real code.

## Gate → unit (each Phase-5 gate is in exactly one unit's acceptance)

| plan gate | gates in phase-5.toml | unit |
|---|---|---|
| ≤0.05 crash-attributable healthy failures/fault at 1%; 0 wrong answers; poison 0; recovery p99 ≤5 ms; throughput ≥0.5× at 1% loop: fork+Wasm path | p2-fault-forkwasm | P5-iso-002 |
| same five criteria: fresh-Wasm cordon path (+ the MPK density cell) | p2-fault-cordon | P5-iso-003 |
| negative syscall tests (CLONE_NEWUSER, socket, TCP_ULP, bpf, io_uring killed/ENOSYS), both paths | p2-syscall-negative | P5-iso-001 |
| hostile-module corpus: I1 (imports, handles), I2 (fuel, epoch, memory, table, stack, host-call and I/O quotas) at the worker | p2-hostile-worker | P5-wasm-002 |
| hostile-module corpus: I1 (capabilities at the supervisor), I5, I6-host, I7, end to end | p2-hostile-host | P5-bin-002 |
| wasmtime pin/config assertions (MPK only with unchanged reservation and guards) | wasmtime-config | P5-wasm-001 |
| re-run on a quiet VPS-class runner; thresholds move only if shifted >2× | p2-fault-vps | P5-vps-001 |
| (added) exec zygote and exec respawn, cordon per principal, crash budgets, dumpable=0, default path switchable by config, fail-closed boot | p2-e2e | P5-bin-001 |
| (added) no wasmtime/cranelift in any aegis-bin build (D3, X-13) | no-wasmtime-in-bin | P5-spec-002 |
| (added) unsafe sites: aegis-iso ≤20, aegis-wasm =1, each with `// SAFETY:` (D4, X-14) | unsafe-sites | P5-spec-002 |

Every new gate has a selftest that turns red on a mutant. The mutants are listed in each unit's `oracles` and
`acceptance.must`. Carried gates: the seven Phase-3/4 gates that still have no selftest (hygiene, tests, audit,
fail-closed-boot, build-subjects, config-totality, systemd-hardening) are unchanged. `budget` is extended to the
aegis-p2 worker binary (P5-spec-002), and `oracles-local` also builds the p2 targets. P5-config-001 has no gate of
its own: the carried config-totality gate and the p2-e2e boot family cover it.

## Roles

As in Phase 4, oracles and harness pieces are spec-author units. Every oracle exists outside the implementer's write
scope and has gone red before an implementer is assigned (§2). Implementer units never touch Cargo.toml or
Cargo.lock. P5-spec-002 pre-wires every third-party edge (wasmtime into aegis-wasm, libc into aegis-iso), creates
the `crates/aegis-p2` crate skeleton, and defines every cargo feature named below (aegis-bin `p2`/`p2-mutants`,
aegis-p2 `test-hooks`/`mutants`). The new subject crate `subjects/p2-subject` has path dependencies only (on
aegis-iso and aegis-wasm, never on wasmtime directly), so its unit may write its manifest. The integrator re-locks
path-only entries at merge, and lock-targets and lock-age must show no third-party version change.

## Unit graph and waves (→ = depends on)

```
W0  start now:   P5-spec-001  P5-spec-002  P5-oracle-fi-001  P5-oracle-syscall-001  P5-oracle-wtcfg-001
W0b spec-001 → P5-oracle-hostile-001, P5-oracle-e2e-001          (both need the F14 ABI and the F8 p2 block)
W1  P5-iso-001     → spec-002, oracle-syscall                     (sandbox: Landlock, seccomp, dumpable, probe)
    P5-wasm-001    → spec-001, spec-002, oracle-wtcfg             (engine config, cwasm, fresh Store, fuel, epoch, MPK)
    P5-config-001  → spec-001                                     (F8 p2 block in aegis-config)
W2  P5-iso-002     → iso-001, wasm-001, oracle-fi                 (exec zygote, fork+Wasm, worker binary, p2-subject)
W3  P5-iso-003     → iso-002                                      (cordon per principal, crash budget, supervisor respawn)
    P5-wasm-002    → wasm-001, iso-002, oracle-hostile            (F14 linker allowlist, handles, quotas)
W4  P5-bin-001     → iso-003, wasm-002, config-001, oracle-e2e    (aegis-bin feature p2: routes wasm:, F14 decoder, I5)
    P5-vps-001     → iso-003, oracle-fi, oracle-syscall           (kamrui re-run + laptop reference file)
W5  P5-bin-002     → bin-001, oracle-hostile                      (data_run authorize, audit-before-effect, I7 mapping)
GO  python3 -I ci/run-gates.py --phase 5
```

Critical path: spec-002 → iso-001 → iso-002 → iso-003 → bin-001 → bin-002. Waves are logical. The machine limit is
still ≤2 compiling agents (heavy.sh 6 GB). A wasmtime+cranelift release build is the largest compile so far, so
prefer `ci/remote.sh` for implementer iteration builds. Oracle units that build Wasm guests or reference hosts
(fi, syscall, hostile, e2e) compile in their own oracle workspaces. Write scopes are disjoint for every pair of units
not ordered by depends_on (checked by script over the JSON files). Units that share a crate are chained: iso-001 →
iso-002 → iso-003 (aegis-iso, aegis-p2, p2-subject); wasm-001 → wasm-002 (aegis-wasm; wasm-001 owns
`src/abi/mod.rs` as a fail-closed stub only); bin-001 → bin-002. The one textual overlap,
`supply-chain/wasmtime-config.toml`, is excluded from spec-002's `supply-chain/**`.

## Placement (laptop, desktop, kamrui)

- **Quiet host = this laptop** (i9-14900HX, Linux 6.17.0-14). These gates run here, never on the shared desktop:
  p2-fault-forkwasm, p2-fault-cordon (timing criteria G3/G4), p2-e2e (crash-budget windows, respawn timing) and
  p2-syscall-negative (it judges the stated 6.17 kernel). oracles/isolation-fi and oracles/p2-e2e get
  `needs` = `quiet-host`, so `ci/oracles.sh --where remote` stops running isolation-fi on the desktop (Phase 4 ran it
  there with `AEGIS_TIMING_GATES=advisory`). This follows the ct-dudect move (8d9351d).
- **Desktop (ci/remote.sh, default host)** handles build-heavy, timing-free gates: wasmtime-config,
  p2-hostile-worker, p2-hostile-host (count criteria only), plus the carried remote gates. Its kernel is 6.11.0-29
  (Landlock ABI 5), so it can run the sandboxed worker (D2 needs ABI ≥4).
- **VPS-class runner = kamrui** (Intel N95, 4 cores, Linux 6.17.0-41, load ≈0.2 when checked), through
  `ci/remote.sh --host kamrui` inside the p2-fault-vps gate (D10). Not `remote = true`, which targets the desktop.
- **No Phase-5 gate needs Docker.** Engine gates stay as in Phase 4. Observed in passing: kamrui has
  `/usr/bin/docker`, which bears on Phase-4 Q1. Not acted on here.

## Interfaces (frozen F-files)

Phase 5 **must not change** F2 (aegis-types), F3 (Exchange), F4 (data IR), F5 (token), F6 (combine), F7/F7b (SDK),
F9 (audit event), F10 (out-of-process module wire), F11 (upgrade handover), F12 (verdicts) or F13 (conformance
report). It needs these amendments, all in P5-spec-001 with re-freeze in the same commit:

- **F14 (new)** `interfaces/F14-p2-guest-abi.cddl` defines the P2 core-module guest ABI and the worker↔supervisor
  frames. Imports are a closed allowlist in module `aegis`. The request arrives as canonical structured values
  (never raw bytes). Response head and body are written through host calls and re-serialized by the supervisor.
  `log` takes module-authored data. `data_run` carries an F4 op encoded with the F10 `op` rule, cited by name (F10
  bytes unchanged). Handles are per-request, generation-tagged ids. `env.host_fault` exists only in `test-hooks`
  builds. Worker→supervisor frames are length-capped. A decode failure kills the worker and charges the crash
  budget, never the supervisor (the F10 rule, applied to F14). Register F14 in `ci/interfaces.py` IFACES.
- **F8 (additive)**: a `p2` block. `worker` path; per-route target `wasm:<module-id>` with module path and sha256;
  `isolation` = `forkwasm` | `cordon`, with the D1 default; `fuel` (default 15,000,000, bounded max), `wall_ms`
  (default 100, bounded), `memory_mib` (default 16, bounded); crash budget `{crashes: 3, window_s: 60,
  penalty_s: 600}` with bounded minimums so a gate can scale them; `mpk` boolean (default false). No field can
  express a cordon shared by principals. `additionalProperties: false`, and every limit is bounded.
- **F1 (addendum to §H)**: INV-P2 statements. They carry the q4-006 acceptance (0 healthy failures and 0 wrong
  answers per fault on the 6 guest classes plus hostabort/hostpoison for fork+Wasm, recovery p99 ≤5 ms, loop
  throughput ≥0.5×), "principals never share a cordon", exec respawn, the crash budget, dumpable=0 and the
  seccomp/Landlock obligations of D2/D5. Re-freeze with `ci/statements.py freeze spec`.

ARCHITECTURE §3.6's multi-principal row still reads "co-equal default candidates … decided in Phase 1". The q4-006
flip is recorded in spikes/APPLIED.md, which is authoritative. research/ is outside the spec-author scope, so the
row is not edited here.

## Spec decisions needed before wave 1 (spec author / operator)

- **D1 default path (from q4-006).** Multi-principal P2 data routes default to fork+Wasm. The alternative is one
  fresh-Wasm cordon per principal. Single-tenant P2 routes run fresh instances in a per-principal cordon.
- **D2 namespaces are unavailable; record what that means for cordons and for the negative tests.**
- **D3 wasmtime cannot enter aegis-bin within the budget.**
- **D4 `Module::deserialize` is `unsafe`, and aegis-wasm is `forbid(unsafe_code)`.**
- **D5–D16** follow from the spike limits and ARCHITECTURE R-ISO-2..5; see Decisions.

## Infeasible or blocked as written

- **"Quiet VPS-class runner."** No VPS exists. kamrui stands in (D10). Every P2 latency or throughput claim stays
  grade ≤B and provisional, as for q3-001/q4-006. The q4-006 reversal ("fork overhead >0.3 ms p50 or loop recovery
  unmet on the q3-001 real 1-vCPU VPS ⇒ cordon per principal") cannot be evaluated until one exists.
- **"Thresholds move only if shifted >2×."** In q4-006 the fork+Wasm loop service gap was 2.31 ms p99 on the laptop
  and 6.78 ms on kamrui (2.9×, over 5 ms in 2 of 3 trials). p2-fault-vps may therefore be red on that cell
  while every count criterion holds. D10 says who may move a threshold and how. No agent moves one.
- **GHSA-6wgr / GHSA-394w.** ARCHITECTURE cites them for "never density-tuned by guard shrinking". The advisory texts
  were not read in this session. P5-oracle-wtcfg-001 must read them and encode the exact affected config shapes as
  mutants, without guessing.

## Open questions

1. No real VPS, so the q4-006 reversal test is pending (above). Does the operator accept kamrui as the Phase-5 GO
   runner, with the claims capped at B?
2. Will the operator accept a per-runner threshold for the kamrui fork+Wasm loop recovery if it reproduces at >2×
   (D10)? Or should a kamrui miss count as evidence for the cordon-per-principal default?
3. aegis-p2 budget ceilings (crates, stripped size, non-crypto unsafe) are unknown until P5-spec-002 measures them.
   No number is proposed here.
4. cargo-vet coverage of wasmtime/cranelift 50.0.0 through the bytecode-alliance import is unverified. How large is
   the vet-baseline addition?
5. Does kamrui's ~/aegis-ci toolchain have Rust 1.98.0 with `wasm32-unknown-unknown` (isolation-fi's guest build)?
   q4-006 ran laptop-built binaries there. P5-vps-001 checks first.
6. Per-cordon cgroup v2 limits (systemd --user delegation) are unverified. Phase 5 bounds memory with the Wasmtime
   ResourceLimiter plus rlimits only, and RLIMIT_AS is unusable with the 4 GiB reservations.
7. What does the per-fork cost of the child's extra seccomp filter (D5) come to? P5-iso-002 measures it.
8. F14 `data_run` reuses the F10 `op` rule. If that proves impossible without editing F10, it becomes a P5-spec-001
   spec change with re-freeze, never an implementer edit.
9. Velocity is measured only as wall-clock time between commits. No agent-hour instrumentation exists in the repo.
10. Landlock ABI on a production VPS is unknown. D2 refuses P2 below ABI 4.
11. Hostile corpus "I/O amplification": P2 guests have no file or socket imports. The I2 cases are therefore
    host-call count and `data_run`/response byte quotas, not WASI I/O. Confirm this is the intended coverage.
12. cranelift: 0.137.1 reaches the 7-day lock age on 2026-11-05. P5-spec-002 pins whichever version passes lock-age
    on the day it runs.

---

## Decisions (integrator, 2026-10-31; operator standing authorization "proceed on all phases when each passes")

- **GO condition (q4-003, q1-009, velocity):** met. Evidence:
  1. **Phase 4 passed.** `gates/phase-4.verdict.json`: go = true, 107 steps including self-tests, git_head
     8d9351d, clean tree, chain 5e17779c6cb7. Committed in 2ab7ad5.
  2. **q4-003** (`spikes/q4-003/verdict.json`, decision_effect 5) takes procurement out of the Phase 4–5 decision.
     It neither blocks nor justifies Phase 5.
  3. **q1-009** (`spikes/q1-009/verdict.json`) is a keep. AI-found bugs are exploited at the base rate (1.3% vs
     1.4%), so no reverse condition fires. It is neutral to Phase 5, which rests on its own argument: the R1
     arithmetic in ARCHITECTURE §3.6 (P(≥3 M0 escapes in 12 months) = 0.38 at 2.21/yr) and the q4-006 flip.
  4. **Velocity**, from commit timestamps: Phase 2 GO 2026-10-26 02:05; Phase 3 GO 2026-10-30 00:46, including the
     2026-10-26 operator pause recorded in BACKLOG; Phase 4 plan 2026-10-30 01:01 → GO 2026-10-31 07:10 (~30 h wall),
     against a 300–600 h [E] estimate. This is wall-clock, not agent-hours (Q9).
  5. **Agent-infra segment evidence:** nothing new has been collected since Phase 4. As at Phase 4, the GO rests on
     the operator's Phases 0→7 directive and standing authorization, not on a segment study.

  Phase 5 therefore advances. Nothing above is a claim about P2 security; those claims come only from the gates.
- **D1 default P2 path:** adopted from q4-006 (verdict flip).
  - Multi-principal data routes: `isolation = "forkwasm"` by default. The zygote is exec-spawned and
    single-threaded. It holds the Engine, a locally precompiled Module and an InstancePre, and no compiler state.
    Each child creates a fresh instance and gets per-route fuel plus an ITIMER_REAL wall bound.
  - Alternative: `isolation = "cordon"`, one exec-spawned cordon per principal, with a fresh instance per request,
    a 64-slot pool, fuel and a 100 ms epoch.
  - Single-tenant routes use the cordon, keyed by principal.
  - A cordon shared by principals cannot be configured. aegis-iso refuses it at runtime because the cordon key is the
    principal.
  - Amended by D23 (b): the F8 default is now `isolation = "auto"`, which is forkwasm with ≥ 8 usable CPUs and
    cordon below that (VPS-class hosts). Explicit values are unchanged.
  - Switching the default is a config change plus reload, with no rebuild. If R1 fires, that switch is the whole
    response, which is why both paths are built. p2-e2e asserts that the same route serves correctly under both
    paths across a reload.
- **D2 namespaces and AppArmor (measured 2026-10-31).** On all three hosts, `kernel.apparmor_restrict_unprivileged_userns
  = 1` (laptop 6.17.0-14, kamrui 6.17.0-41, desktop 6.11.0-29). `unshare -U true` **succeeds** (exit 0), but the new
  namespace has no capabilities: writing uid_map gets EPERM, so `unshare -Ur` fails on all three hosts.
  `unshare -Urn` was checked on the laptop only, and it fails the same way. This matches
  the existing note that bwrap userns is blocked for the proof gate. Consequences:
  1. **No cordon relies on namespaces**: no user, net, mount or pid namespace, no bwrap, no unshare. A cordon or
     zygote is an exec-spawned process with PR_SET_NO_NEW_PRIVS, Landlock, seccomp, rlimits and PR_SET_DUMPABLE=0,
     which matches ARCHITECTURE R-ISO-4/5. Network denial comes from seccomp (socket killed) plus Landlock net
     rules.
  2. **Landlock ABI ≥4 is required.** Measured ABI is laptop 7, kamrui 7, desktop 5. Below 4, P2 routes are refused
     at boot (exit 78, fail closed).
  3. **Negative tests**:
     - CLONE_NEWUSER: the kernel *permits* an unprivileged process to create a (capability-less) user namespace here,
       so the probe is meaningful. Its unfiltered control succeeds, and under the filter it must die with SIGSYS.
     - bpf: it already fails with EPERM (`kernel.unprivileged_bpf_disabled = 2`). A probe therefore passes only on
       the filter's own signature (SIGSYS from SECCOMP_RET_KILL_PROCESS, or ENOSYS for clone3), never on EPERM or on
       another kernel or AppArmor denial.
     - Every probe first runs an unfiltered control and records the host facts (the AppArmor sysctls,
       unprivileged_bpf_disabled, io_uring_disabled = 0 on the laptop, Landlock ABI). A control that already fails is
       reported as "masked", and the filtered result must still be the filter signature.
     - A VPS kernel without the AppArmor restriction, where CLONE_NEWUSER grants capabilities, is more exposed. The
       filter is the control on either kernel.
- **D3 separate worker binary (DEVIATIONS X-13, proposed).** wasmtime and cranelift link only into a new crate,
  `crates/aegis-p2` (layer 5): the zygote, cordon and compile entry points, built on aegis-iso and aegis-wasm.
  aegis-bin (default, `native`, `p2` and every combination) gets no wasmtime or cranelift node, enforced by the gate
  no-wasmtime-in-bin. aegis-bin's `p2` feature adds only the aegis-iso supervisor (spawn, fd passing, respawn,
  crash budget) and the F14 decoder, with no new third-party crate. Reasons:
  - The core is at 45/60 third-party crates and 4,948/5,000 non-crypto unsafe lines (P4-spec-002 status).
  - The isolation-fi lock has 106 entries for wasmtime 50.0.0 + cranelift 0.137.0, including build and guest
    crates.
  - The design already exec-spawns the zygote, and fork cost grows with zygote RSS (q4-006 limits).

  aegis-p2 gets its own explicit ceilings, measured by P5-spec-002 and set by the integrator before W1 implementers
  start (Q3). The same pattern as X-8 (aegis-pdp) and X-12.
- **D4 unsafe sites (DEVIATIONS X-14, proposed).** aegis-iso: ≤20 sites (fork, prctl, seccomp, landlock_*,
  setitimer, fd adoption, _exit), each with `// SAFETY:`. aegis-wasm: exactly 1, the `Module::deserialize_file` of a
  `.cwasm` that this boot's sandboxed `aegis-p2 compile` produced. Its sha256 must equal the digest the supervisor
  holds and passes to the zygote/cordon. Never bytes from config or from a tenant (runwasi CVE-2026-47218 pattern).
  The alternative, compiling in the zygote with no unsafe, is rejected by q4-006: zygote RSS 11.8 vs 5.9 MiB and
  +43–84 µs per fork. xtask `UNSAFE_ALLOWED` gains aegis-wasm with a cap of 1. The new `cargo xtask unsafe-sites`
  enforces both caps and the SAFETY comments.
- **D5 seccomp layout.** One filter is installed in the zygote and in each cordon before it serves:
  - an argument-free allowlist of hot syscalls (cache-friendly);
  - the clone flag filter: CLONE_NEW* → kill;
  - clone3 → ENOSYS, so libc falls back to the filtered clone;
  - KILL_PROCESS for unshare, setns, socket, socketpair, setsockopt(TCP_ULP), bpf, perf_event_open, io_uring_setup/
    enter/register, ptrace, process_vm_readv/writev, userfaultfd, keyctl/add_key/request_key, mount family, execve
    and execveat.

  The zygote keeps accept4 on its inherited listening fd. Each fork child also installs a small second filter that
  kills clone, fork, vfork and execve. P5-iso-002 measures its install cost per fork and reports it; the
  p2-fault-forkwasm throughput criterion has to pass with it. Cordons get no fork at all. Landlock goes in before
  seccomp, once per process: fs read-only on the module and data paths only, and net with no rules allowed.
- **D6 fuel and watchdog.** Fuel is the deterministic compute budget. The DoS bound is the epoch (cordon, 100 ms)
  or ITIMER_REAL (fork child, 100 ms) (R-ISO-3). The default route fuel is 15,000,000 (q4-006: about 2 ms on the
  laptop, about 58× the reference handler). F8 bounds the maximum. The q4-006 rule "≤50× the route's p50 handler
  cost" stays an operator obligation documented in F8, not a config check, because p50 is unknown at config time.
  The fault gates run at the default.
- **D7 crash budget.** Per principal: 3 crash-attributable faults in 60 s → 429 for 600 s. A fault counts when it
  is a trap, an abnormal child exit, a cordon death, or an F14 decode failure caused by that principal's request.
  Healthy failures and other principals' faults never count. The gate scales the window and penalty through the F8
  knobs, which have bounded minimums. p2-e2e reads the effective defaults from the config dump.
- **D8 exec respawn.** A replacement zygote or cordon is always a fresh execve of aegis-p2 (new ASLR layout), never
  a fork of a template (BROP crash oracle, R-ISO-5). p2-e2e checks this with a `test-hooks` build of aegis-p2 that
  reports its own load base in an F14 status frame. dumpable=0 makes `/proc/<pid>/maps` unreadable from outside,
  which p2-e2e checks too: `/proc/<pid>` is owned by root while the worker is non-dumpable.
- **D9 residual: fork children share the zygote's layout.** That is inherent to fork. Probing layout by crashing
  children is bounded by the per-principal crash budget (3 per 60 s), and the zygote itself never serves requests.
  Claims must state this.
- **D10 the quiet VPS-class runner.**
  - The laptop is the quiet host and the reference: the p2-fault gates and p2-e2e run there.
  - kamrui is the VPS-class re-run (gate p2-fault-vps). It repeats both paths at 3 trials, with
    `--server-core 1 --client-cores 2,3`, plus p2-syscall-negative on its kernel.
  - kamrui is not a $5 KVM VPS (no steal time, no virtualized page tables), so claims stay ≤B and provisional.
  - Thresholds are the plan's: 0.05 per fault, 0 wrong, 0 poison, 5 ms, 0.5×. kamrui is gated at the same values.
  - P5-vps-001 commits the laptop reference metrics as `gates/p2-runner-reference.json`. isolation-fi reports the
    kamrui/laptop ratio per timing metric and flags any ratio >2×. It never moves a threshold itself.
  - A flagged metric may get a per-runner threshold only by a new integrator Decision in this file, naming both
    measurements and the operator's consent. Within 2×, nothing moves.
  - Count criteria (G0–G2, syscall, hostile) never move on any runner.
  - A kamrui miss does not by itself flip D1: the q4-006 reversal names a real VPS (Q2).
  - 2026-11-01 (operator consent): the quiet host moves to a dedicated GCP c2-standard-8 (8 Intel Xeon vCPUs, no
    other work on it; gates `remote = "quiet"`). The laptop stays the reference that set the thresholds; the GCP
    runner is judged at the same values, nothing moves. Why: the full run of 2026-11-01 was NO-GO only because no
    shared machine stayed quiet (desktop: no valid quiet.py attempt in 6 for ct-dudect and the p2-e2e self-test;
    laptop: isolation-fi reference cordon oom recovery p99 17168 us in a CPU-quiet window at memory PSI some avg10
    3.1, vs 3257 us idle). The guest has no steal time but no `pku` either, so the MPK cell stays on kamrui.
  - 2026-11-02 (integrator, operator chose "fix the path" over a per-runner threshold): the first GCP rehearsal
    missed G3 on the production fork+Wasm subject, oom recovery p99 6178 us (laptop reference 2593 us, x2.38) in a
    VALID quiet window. Cause (perf sched on the runner): an oom child costs ~8.6 ms CPU there (4096 page faults,
    zeroing, teardown; ~25x a healthy child) and ran whole ~3 ms EEVDF slices while freshly forked healthy children
    waited; two or three overlapping oom children stopped all completions for ~9-20 ms. Fix, no check changed:
    `sandbox::install(Profile::zygote)` requests a 100 us slice (`sched_setattr` sched_runtime, current nice kept,
    unprivileged, inherited by every fork child; aegis-iso unsafe sites 13 -> 14). Re-run on GCP: p2-fault-forkwasm
    PASS, oom recovery p99 1451 us, every other cell <= 949 us, healthy rps x1.00 of baseline. Cordon is unchanged (a
    short slice there raised healthy p50 ~145 -> ~200 us across 64 threads); it passes on GCP as is (oom 1129 us, loop
    1931 us). Slices are a Linux >= 6.12 feature; older kernels accept and ignore the request (`Installed::slice_ns`
    records it; the zygote_serve test checks the live slice of the zygote and a fork child).
- **D11 wasmtime pin and config (R-ISO-2).**
  - Version: wasmtime =50.0.0 (lock target; ≥49.0.4 floor, GHSA-897f). cranelift at whatever version passes lock-age
    on the day P5-spec-002 runs (Q12).
    **Amended 2026-10-31 (integrator, after W0):** the pin is 50.0.1 (RUSTSEC-2026-0422/0423/0424 affect 50.0.0),
    with cranelift 0.137.1, under the cooldown-bypass entries until 2026-11-05. The features are the four below plus
    `memory-protection-keys` (which implies `call-hook`), because `PoolingAllocationConfig::memory_protection_keys`
    only exists with that feature and the MPK density option is in scope. The oracles (isolation-fi,
    wasmtime-config) use the same pin and feature set.
    **Note 2026-11-01:** wasmtime 50 enables MPK only on Intel CPUs (`wasmtime-internal-core` `mpk::is_intel_cpu`),
    so the AMD desktop quiet runner cannot run the MPK variant; it is gated on kamrui (Intel N95, PKU) in
    p2-fault-vps with unchanged thresholds. AMD production hosts run cordon without MPK (the density option is
    off there; the engine refuses `--mpk` rather than silently dropping it).
  - Features: `default-features = false` plus exactly cranelift, pooling-allocator, runtime and std. No
    component-model in Phase 5: F14 is a core-module ABI, and R-ISO-2 lists it only as optional. No gc, threads,
    winch, wasi, wasi-http or component-model-async. `memory64(false)` and `gc(false)` are set explicitly.
  - Memory: 4 GiB reservation and 32 MiB guard, never shrunk.
  - MPK = `memory_protection_keys` as a density option only, with the reservation and guard asserted unchanged
    with and without it. All three hosts report `pku`.
  - `epoch_interruption(true)` and `consume_fuel(true)`.
  - The expected effective config is frozen in `supply-chain/wasmtime-config.toml`. `aegis-p2 config --json` must
    match it.
  - Security releases of wasmtime may bypass the 7-day lock-age only through `supply-chain/exceptions.toml`. Tenant
    code reaches Wasmtime, so a critical wasmtime fix is treated as attacker-reachable under the q1-009 ≤48 h
    rebuild row.
- **D12 F-file plan:** as in "Interfaces" above. F14 is new; F8 and F1 get additive amendments; the rest are
  unchanged.
- **D13 scope cut.** Out of Phase 5 and into the backlog or Phase 7: the egress fetch host function, the component
  model, WASI, out-of-process P3 modules, and density claims (MPK and pooling are gated for correctness and
  config, while density is record-only). P2 data access goes only through F14 `data_run` to the supervisor, which
  decodes, authorizes (CapSet, INV-NONEMPTY), audits before executing, and overwrites the tenant (the host choke
  point of the survival table, SPEC §H).
- **D14 trials.** At GO, the p2-fault gates run 3 trials per cell (about 90 faults per class), because 1 trial
  resolves 0.05/fault only as "0 or >0.03". PR checks run 1 trial. The existing rule stays: re-drive a cell once,
  for timing criteria only.
- **D15 test-only code.** `env.host_fault`, the syscall probe and the layout report live behind aegis-p2 feature
  `test-hooks`; the mutants live behind `mutants`/`p2-mutants`. Golden builds enable neither, and P5-bin-001 asserts
  this with a test like X-12's golden_build.rs. Probe and fault runs build into their own target dirs
  (target/p2-test, target/p2-mutants), so target/p2 always holds the shipped configuration.
- **D16 placement:** as in "Placement" above. Timing-sensitive work goes to the laptop (`needs` = quiet-host),
  build-heavy and timing-free work to the desktop through ci/remote.sh, and the VPS-class re-run to kamrui. Nothing
  needs Docker.
- **D17 Error ⇒ the Deny response (integrator, after W1).** Every Error outcome of a P2 route (trap, out of fuel, wall
  bound, quota, worker death, decode failure, any `handle()` code other than 0 or 1) returns the host's explicit-Deny
  response, byte-identical (403, same body), with no module byte. A principal in penalty gets 429. Reason: F14 says
  "Error ⇒ Deny", and one response for both stops a client from telling a trap from a deny. The p2-e2e oracle first
  expected 502 for Error and hostile-host expected the Deny bytes; p2-e2e now follows this rule and tells Error from
  Deny by route and process state, never by status.
- **D18 test-hooks never reach a shipped worker build.** p2-subject turns on aegis-iso/test-hooks, so p2-subject and
  aegis-p2 are never built in the same cargo invocation; cargo unifies features only within one invocation. The
  shipped worker is built alone (`-p aegis-p2`), and the test-hooks worker builds into target/p2-test. Gate commands
  keep this split.
- **D19 integrator wiring after W1.** `aegis-bin` refuses `{"wasm": id}` routes with a fail-closed error until
  P5-bin-001 lands (plan.rs). `aegis-p2 main` dispatches `config` and `compile` (P5-wasm-001). The unsandboxed
  `compile` refuses unless NoNewPrivs=1 and Seccomp=2, until P5-iso-002 installs the compile profile.
- **D20 fault-injection guest support in aegis-wasm (integrator, after W2).** The isolation-fi guest exports
  `handle(id, fault)` and imports `env.host_fault`, so it is not an F14 module. `crates/aegis-wasm/src/fi.rs` runs it
  behind `test-hooks` only: no unsafe code, no new dependency, the same engine config, the same digest-checked load
  and a fresh instance per call. P5-iso-002 supplied it as a patch because aegis-wasm is outside its write scope; the
  integrator applied it. P5-wasm-002 owns the file from here on and must keep it test-hooks only. The P5-iso-002
  compile profile (Kind::Compile: cordon layout plus fsync, rename and unlink, with Landlock write access only under
  `--out`) was reviewed and accepted; the denylist is unchanged.
- **D21 W3 integration: MPK cell, shared F14 codec, no pipelining, hostile oracle fix (integrator, after W3).**
  P5-iso-003 and P5-wasm-002 were merged; both were blocked only by write scope. The integrator applied:
  - **pkey_mprotect allowed** (x86_64 nr 329) in the aegis-iso seccomp ALLOWLIST. With MPK, wasmtime colours each
    pool slot with a key on every instance allocation. pkey_alloc stays denied after install, so it grants no more
    than mprotect on the process's own mappings. The DENYLIST, the child filter and the clone/prctl/setsockopt
    rules are unchanged.
  - **MPK stripe retry.** With MPK, wasmtime splits the pool into one stripe per key (64 slots over 16 keys: 4 per
    stripe on the laptop) and refuses a new Store whose stripe is full. `engine::is_pool_full` and
    `pool_retry_limit` (the pool size with MPK, 0 without) let `store::Worker::handle`, `fi::FiWorker::instance`
    (still test-hooks only, D20) and `abi::Session` move a refused request to a new Store before any guest code
    runs. The engine configuration is unchanged, and without MPK behaviour is unchanged.
  - **One F14 codec.** The zygote fork child and the cordon both serve through `aegis_wasm::abi::F14Worker`/`Session`
    and encode and decode frames only with `aegis_wasm::abi::frame`. The private codecs in zygote.rs and cordon.rs
    are gone. The cordon keeps the aegis-iso registry, crash budget, idle reaping, threads on demand and the epoch
    wall bound (wall timeout = `resp-end` trap 2).
  - **No pipelining.** A worker connection carries one request at a time: the fork child serves exactly one, and a
    cordon connection serves them in sequence. Cordon concurrency comes from parallel connections. The supervisor
    (P5-bin-001) must not send a second `request` before the first one's `resp-end` or its own `cancel`.
  - **hostile-modules oracle fix.** `exchange()` accepts exactly one D8 `layout` frame (sent by test-hooks and
    mutants builds), only in the first exchange of a connection and before any other frame. Every other unexpected
    frame is still a protocol violation. Before this fix every zygote cell of the worker self-test was red on the
    layout frame alone, so the zygote half of the self-test was vacuous.
- **D22 P5-bin-001 integration (integrator, after W4).**
  - **What a P2 principal is.** The crash-budget and cordon key is the verified token's (tenant, issuer kid). It is
    not the full Principal: aegis_token's subject includes the token nonce, so every new token would be a new
    principal, and a client could reset its crash budget by minting a token. Coarser is the safe direction here: one
    issuer's tokens for one tenant share a budget and a cordon. Principals of different tenants or issuers never
    share a cordon (D1 holds).
  - **Workers load one module each.** On forkwasm the zygotes, one per module, restart together as one set when any
    of them dies. On cordon, one group per principal holds one process per module used, and any death shuts the whole
    group down. Both always respawn by execve (D9).
  - **Fail-closed limits until a later unit lifts them.** frame_max_bytes other than 65536 is refused at plan time,
    because the worker has no flag to receive it. Data endowments on wasm routes are refused and data_run always
    answers "denied" until P5-bin-002. The request body is capped at 64 MiB on P2 routes. The supervisor re-checks
    the configured header limits.
  - **Accepted residuals.** No F14 cancel is sent when the client disconnects; the request is bounded by wall_ms plus
    2 s. On a decode failure or timeout the supervisor closes the fork child's connection instead of SIGKILLing it,
    because it does not learn the child's pid; the child dies at its next frame I/O or at its ITIMER_REAL bound.
  - **Integrator fixes applied.** The dumpable-1 worker mutant is in aegis-iso, mutants builds only. The p2-e2e
    oracle accepts the OpenMetrics `_total` sample of the reload counter. The p2-e2e selftest gets a mutants+test-hooks
    worker (--mutant-test-worker). The p2-fault-vps cmd runs every step and combines the exit codes.
- **D23 kamrui timing: resolved, option (b) (operator consent 2026-10-31; integrator Decision under D10).**
  - **Measurements.** P5-vps-001 on kamrui (Intel N95, 4 cores, Linux 6.17.0-41): every count criterion green on
    both paths. forkwasm G3 red on timing: oom recovery p99 6654 µs and 7076 µs against the 5 ms limit (laptop
    reference 2593 µs, ×2.57 / ×2.73); loop recovery 5719 µs once, 4591 µs once. This reproduces the q4-006 spike
    (6.78 ms). cordon passed on kamrui: oom recovery p99 1584 µs, loop 2398 µs. syscall-negative passed.
  - **Decision (b).** The 5 ms recovery threshold is kept on every runner. No per-runner threshold is introduced.
    Instead the fresh-Wasm cordon becomes the default isolation path on VPS-class hosts. F8 `p2.isolation` gains
    `"auto"`, which is the default when the member is absent (re-freeze of F8, same commit as this text).
  - **The rule.** `auto` resolves at boot and at every reload: usable CPUs < 8 → cordon, otherwise forkwasm.
    Usable CPUs = the process's affinity set (`sched_getaffinity`, read from `Cpus_allowed_list`), so a host pinned
    by `taskset` or a cpuset cgroup counts only its pinned CPUs. A CFS quota (`cpu.max`) is not counted. Why 8:
    forkwasm missed 5 ms on the 4-core N95 and passed on the 32-thread laptop (the reference). The cause of the
    miss was not isolated, and nothing between 4 and 32 CPUs was measured under the gate, so 8 is a conservative
    split, not a measured knee. It puts typical VPS sizes (1-4 vCPU) on cordon. Explicit `"forkwasm"` / `"cordon"`
    behave exactly as before. Single-tenant modules always get a per-principal cordon (D1). aegis logs the configured
    value, the resolved path and the CPU count at boot and at each reload. `check-config --print-effective` adds
    `p2.isolation_effective` and `p2.usable_cpus` to the dump. The config hash covers only the configured value, so
    it does not depend on the host.
  - **Gates.** p2-fault-vps (kamrui): cordon, now the default there, stays fully gated with unchanged thresholds.
    forkwasm keeps its count criteria gated, but its timing criteria (G3, G4) are report-only on kamrui
    (`--timing advisory`). That is allowed only because this Decision makes forkwasm a non-default path on
    VPS-class hosts. It is not a threshold move: the laptop gates p2-fault-forkwasm and p2-fault-cordon keep both
    paths fully timed. A new step builds aegis with feature p2 on kamrui and checks that the default resolves to
    cordon there (`ci/p2-auto-resolve.py`). p2-e2e adds the `auto` family: under `taskset` with 4 CPUs the default
    config resolves to cordon and serves wasm routes with one cordon per principal and no zygote; with 8 CPUs it
    resolves to forkwasm (zygote observed). On a host with fewer than 8 usable CPUs that half FAILs; it is never
    skipped. New supervisor mutant `auto-ignores-cpus` (always forkwasm), which must be caught by `auto.small.*`.
  - **Claims.** kamrui is accepted as the VPS-class runner, and claims from it are capped at grade B (it is not a
    virtualized $5 VPS, D10). The q4-006 reversal still names a real VPS (Q2).
  - **Residual.** On a small host running the default, requests within one principal share that principal's cordon
    process (a fresh Wasm instance per request in a 64-slot pool, fuel, a 100 ms epoch) instead of getting a fresh
    fork per request. A fault in the cordon process affects the principal's own concurrent requests, and the
    principal's crash budget charges it. Isolation between principals is unchanged: one exec-spawned cordon per
    principal, never shared (D1, P2-2). hostabort/hostpoison on cordon stay report-only, as in p2-fault-cordon. An
    operator who wants forkwasm on a small host can set it explicitly, but kamrui shows it misses the 5 ms
    recovery bound there.
- **D24 SQLite built for size (integrator, after W5).** P5-bin-002 met everything except the clause "native,p2 within
  the X-12 8.0 MB ceiling". The binary was 8,068,472 B on the laptop and 8,020,640 B on the desktop, and main was
  already over before that unit. The ceiling is kept. `[profile.release.package.libsqlite3-sys] opt-level = "s"`
  builds the bundled SQLite C for size, giving 7,175,712 B (native,p2) and 7,065,920 B (native; was 7,958,680),
  measured on the desktop. SQLite is the data engine, not request-path Rust. Rejected alternatives: global
  opt-level "s" (5.0 MB, but it changes every request-path crate) and per-crate "s" on aegis-bin, config and ops
  (larger under fat LTO). Cost: SQLite query CPU may rise; no gate measures it at this point (BENCH_PLAN). Gap noted:
  `cargo xtask budget` judges the size of default and native but not native,p2; adding native,p2 is a follow-up.
  Accepted P5-bin-002 readings:
  - A module data_run passes authorize, check_schema, the op budget and the render denylist, but not the notes app's
    allowlist lock, because a module is not that app and F8 has no lock field for modules.
  - Each data_run commits in its own transaction; a write followed by a trap stays committed and audited.
  - Only SQLite is exercised by an oracle; the PG pairing compiles but is unverified.
