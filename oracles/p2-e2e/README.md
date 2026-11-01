# p2-e2e: the P2 supervisor end to end (gate p2-e2e)

Unit P5-oracle-e2e-001; gate `p2-e2e` (owned by P5-bin-001, `gates/phase-5.toml`). A black-box oracle. It boots a
subject with oracle-written F8 configs whose routes target `{"wasm": <module-id>}`, mints F5 Tier-L tokens for
several principals, drives the subject over TLS (HTTP/1.1), and judges the answers together with the process tree
under the subject (`/proc`), the F14 layout reports of a test-hooks worker, and the effective-config dump.

aegis-bin has no `p2` code yet (P5-bin-001 builds it). For now the oracle PASSes on an oracle-local mock,
`ref_subject.py` (supervisor) plus `ref_worker.py` (worker), goes red on each of the 9 reference mutants, and accepts
`--subject/--worker/--test-worker` for the real binaries. `needs` = `quiet-host` (PLAN D16): the crash-budget windows
and the respawn polling are wall-clock based, so the oracle runs on the laptop, never on the shared desktop.

## Usage

```
oracles/p2-e2e/run                       # reference subject (mock), all families
oracles/p2-e2e/run --self-test           # reference PASS, then each of the 9 reference mutants must be red
oracles/p2-e2e/run --subject target/p2/release/aegis --worker target/p2/release/aegis-p2 \
                   --test-worker target/p2-test/release/aegis-p2                                  # gate cmd
oracles/p2-e2e/run --self-test --subject target/p2/release/aegis --worker target/p2/release/aegis-p2 \
                   --mutant-subject target/p2-mutants/release/aegis \
                   --mutant-worker target/p2-mutants/release/aegis-p2 [--mutant-test-worker <path>]   # gate selftest
```

With `--subject` alone (as `ci/oracles.sh` calls it once P5-bin-001 writes `default-subject`), the worker defaults to
`aegis-p2` next to the subject and the test worker to `target/p2-test/release/aegis-p2` when it exists; without a
test worker the respawn and Landlock families fail (cannot judge). The last line is `P2-E2E: PASS|FAIL (...)` or `P2-E2E SELF-TEST: PASS|FAIL (...)`; the exit code is 0 only on PASS.
The first line records the load average (integrator note: laptop timings are noisy under load). Stdlib Python only,
run as `python3 -I`; needs the `openssl` CLI (throwaway P-256 certificate). The oracle refuses to judge when run as
root (root reads every `/proc` entry, so dumpable=0 would be invisible). It needs `taskset` (util-linux) and at
least 8 usable CPUs for the `auto` family (the laptop has 32, the desktop 24); with fewer, `auto.large.*` FAILs
rather than being skipped. `--families boot,main,cordon,auto,respawn` limits
a run for debugging; a gate run never passes it.

Real runs build the guests first: `guest/` (Rust 1.98.0, `wasm32-unknown-unknown`, no dependencies, its own
`Cargo.lock`) through `ci/heavy.sh guest/build.sh <tmp>`, then the build directory is deleted. One build exports
`h_echo_a h_echo_b h_trap h_deny h_spin`; a second build with feature `fault` exports `h_abort` and imports
`env.host_fault`. For each kind the oracle rewrites the export section of a copy to exactly `memory` + `handle`
(`p2wire.select_handle`, every other section byte for byte) and checks the F14 import allowlist and types
(`p2wire.check_f14`) before use.

| module id | route | guest behaviour |
|---|---|---|
| echo-a / echo-b | `/a/` `/b/` | `resp_head(200, [])`, body = `A`/`B` marker byte, then the `req-head` bytes from `aegis.req_head` |
| trap | `/trap/` | `unreachable` (crash-attributable fault) |
| deny | `/deny/` | `handle()` = 1 (Deny, a healthy failure) |
| spin | `/spin/` | runaway loop; per-module `fuel` 1e9, `wall_ms` 1000, so a fork child lives long enough to be seen |
| abort | `/abort/` | `env.host_fault(1)`; configured only with the test-hooks worker (a golden worker refuses the import) |

## Families and checks

Spec: PLAN D1 (both paths, one cordon per principal, switch by config + reload), D23 option (b) (default `auto`:
cordon below 8 usable CPUs, else forkwasm), D2 (Landlock ABI >= 4 else refuse),
D7 (crash budget), D8 (exec respawn, dumpable=0), D15 (test hooks only in test builds); F8 `p2` block; F14 Part 1
(`handle()` codes), Part 2 (`layout` frame), Part 3 (I7 Error => Deny, D7 charging); SPEC_INVARIANTS §H INV-P2;
ARCHITECTURE §3.6 R-ISO-5.

| family | checks (prefix) | what must hold |
|---|---|---|
| dump | `dump.defaults.*`, `dump.scaled.*` | `check-config --print-effective` of a p2 block that omits them shows `isolation` auto, `fuel` 15000000, `wall_ms` 100, `memory_mib` 16, `mpk` false, `crash_budget` {3, 60, 600}; a scaled block (3/4/5 s, cordon) is reflected exactly |
| boot | `boot.<case>.exit78`, `.never-listened` | exit 78 and no accepted connection on the listener or admin port: missing worker; module digest mismatch; route naming an undeclared module; wasm route without a `p2` block; 7 attempts to express a shared cordon (`p2.cordon`, `p2.shared_cordon`, `p2.cordon_key`, module `cordon`, module `tenancy: "shared"`, module `principals`, route `p2`); Landlock ABI 3 simulated through the test-hooks worker (`boot.landlock-abi3`), with the control ABI 4 booting and serving (`boot.landlock-abi4-control.serves`) |
| wasm answers | `wasm.forkwasm.answer`, `wasm.cordon.answer`, `reload.to-*.answer` | 200, the right module's marker, and an echoed `req-head` that decodes strictly (postcard, no trailing bytes) with method GET, path = request path (or the route path), query = opaque `n=<nonce>` (or typed `[("n", nonce)]`), headers only from the F14 allowlist and including `accept: text/plain` (so no `authorization`), body-len null or 0. Concurrent, several principals, both modules |
| fork+Wasm structure | `wasm.forkwasm.zygote-observed`, `dumpable.forkwasm-*` | during a spin request a new process appears whose parent is another worker (not the supervisor), and after the request it is gone while its parent lives: that parent is the zygote. Both non-dumpable |
| crash budget | `budget.*` (forkwasm, plus a short cordon run) | knobs 3 crashes / 4 s window / 5 s penalty. 4 Deny (403) then a healthy answer (`budget.healthy-not-counted`); 2 traps (403, Deny response) then a healthy answer (below threshold); after the window, 1 trap then a healthy answer (`sliding-window`); 2 more traps: `/a/` and `/trap/` give 429 (`budget.exhausted-429`); principal B is served and its own trap does not exhaust it (`budget.other-principal-*`); after the penalty, A is served again (`penalty-expires`). If the 3 exhausting traps took longer than window - 0.5 s, `budget.<path>.timing` fails (cannot judge) and prints the load |
| reload switch | `reload.to-cordon.*`, `reload.to-forkwasm.*` | `isolation` forkwasm -> cordon by SIGHUP (applied = `aegis_proxy_config_reloads` advances): same routes answer correctly, each new principal gets a new long-lived worker process; cordon -> forkwasm: answers correct and a zygote is observed again |
| one cordon per principal | `cordon.per-principal.<i>`, `.count`, `cordon.kill-isolated.*`, `cordon.respawn-after-kill.*` | boot with `cordon`: each of 4 principals' first request makes a new worker process appear that is still alive 0.3 s later; all disjoint; SIGKILL of principal 0's cordon leaves principal 1's cordon alive and serving; principal 0 is served again within 10 s by a pid not seen before the kill |
| dumpable=0 | `dumpable.*` | every live worker (zygote, fork child, cordons, respawned ones): `/proc/<pid>/{status,maps,environ,fd}` owned by uid 0 and `/proc/<pid>/maps` unreadable (EACCES). Re-checked once after 0.2 s before failing (a just-exec'd worker may not have reached prctl yet) |
| isolation auto (D23 b) | `auto.small.*`, `auto.large.*`, `auto.explicit-*`, `dumpable.auto-*` | config with `p2.isolation` omitted. Dump under `taskset` with the first 1, 4 and 7 CPUs of the oracle's affinity set: `isolation` auto, `isolation_effective` cordon, `usable_cpus` = that count; with 8: forkwasm (`auto.*.dump.cpus<n>`). Explicit forkwasm at 1 CPU and explicit cordon at all CPUs are used as written. Serving under `taskset` (4 CPUs, as `taskset -c 0-3`): the boot log names `isolation auto -> cordon` and `4 usable CPUs`, wasm routes answer correctly, each of 3 new principals (after one warm-up principal) gets a new long-lived worker, and no fork child of a worker serves a spin request (`auto.small.no-zygote`). Serving with 8 CPUs: log `isolation auto -> forkwasm` / `8 usable CPUs`, correct answers, a zygote is observed and new principals get no new long-lived worker. A host that gives the oracle fewer than 8 CPUs FAILs `auto.large.*` (cannot judge; not a skip) |
| exec respawn (test-hooks worker) | `respawn.zygote.*`, `respawn.cordon.*`, `respawn.abort-is-deny*` | forkwasm: load base L1 from the layout line of an echo request; zygote Z1 found as above; oracle SIGKILLs Z1 (explicit pid); served again within 10 s; new zygote Z2 != Z1, Z1 gone, layout load base L2 != L1 (`respawn.zygote.load-base-changed`), Z2 non-dumpable; `/abort/` gives the Deny response and the zygote survives the child's abort (Z3 == Z2). cordon: first request spawns cordon C1 with a layout line whose pid is C1; `/abort/` kills it (Deny response); served again within 10 s by C2 (new pid, C1 gone) with a different load base; C2 non-dumpable |

## Subject contract (what P5-bin-001 must implement)

**Command line** (as oracles/native-e2e). `aegis --config <f8.json> --cert <pem> --key <pem> --audit-dir <d>
--runtime-dir <d> --token-keyring <file>`; readiness `GET /healthz` = 200 on `admin.bind`; reload on SIGHUP, counted
by the admin metric `aegis_proxy_config_reloads` only when applied; SIGTERM stops the process and its workers.
`aegis check-config <f8.json> --print-effective` exits 0 and prints the effective config as one JSON object on one
stdout line, including the `p2` block with every schema default applied (the "config dump", D7). Inside `p2` the
dump also carries `isolation_effective` (the path multi-principal modules are served on in this process's
environment) and `usable_cpus` (the size of the process's CPU affinity set it was resolved from), D23(b).
At boot and at each applied reload the supervisor logs (stdout or stderr) a line containing
`isolation <configured> -> <effective>` and `<n> usable CPUs`.

**Config written by the oracle.** One listener `P-PUBLIC-WEB` (`alpn ["h2","http/1.1"]`), vhost `aegis.test`,
routes `{"id", "path": "/a/", "to": {"wasm": "echo-a"}, "authz": "allow-all"}` (one per module), and

```json
"p2": {"worker": "<abs path>", "cache_dir": "<tmp>/p2cache", "isolation": "forkwasm|cordon" (absent: auto),
       "crash_budget": {"crashes": 3, "window_s": 4, "penalty_s": 5},
       "modules": [{"id": "echo-a", "path": "<tmp>/mod/echo-a.wasm", "sha256": "<hex>"},
                   {"id": "spin", "path": "...", "sha256": "...", "fuel": 1000000000, "wall_ms": 1000}, ...]}
```

The respawn family uses `crash_budget {100, 1, 1}` so its deliberate faults never trip a penalty.

**Principals.** `Authorization: Bearer <F5 Tier-L token>` minted as in native-e2e (caveats aud `aegis.test`, exp,
depth 2, ops 31, tenant T). Each principal has its own random tenant, so principals never share a tenant. The crash
budget key and the cordon key are the principal that `aegis_token::verify` mints.

**Responses.** `handle()` = 0: the module's status and body (the body is exactly the module's `resp_write` bytes; the
oracle decodes it). `handle()` = 1 (Deny): **403**. Error (trap, fuel, wall bound, quota, worker death, decode
failure, any other code): the Deny response, byte-identical (403, same body; PLAN D17: Error => Deny), no module
byte. Principal in penalty: **429** on every P2 route, before dispatch.

**Crash budget (D7).** A crash-attributable fault (trap, abnormal child exit, cordon death, F14 decode failure) of
principal P is recorded at CLOCK_MONOTONIC; when P has `crashes` records within the last `window_s`, P's P2 requests
get 429 for `penalty_s` from that crash. Records older than the window never count, and the oracle keeps
`penalty_s > window_s` so the semantics of records outliving a penalty are never exercised. Deny never counts. Other
principals are unaffected.

**Process structure.** Every worker process stays a descendant of the supervisor process (ppid chain, no daemonizing,
no reparenting) and is not a zombie while live. forkwasm: one exec-spawned zygote forks one child per request; the
child exits after its request. cordon: one long-lived exec-spawned process per principal (`max_cordons` and
`cordon_idle_s` at their defaults are never reached in a run), created when a principal first needs it; killing one
cordon affects no other principal; a dead zygote or cordon is replaced by a fresh execve (D8) and requests recover
within 10 s. Every worker sets PR_SET_DUMPABLE=0 before serving.

**Layout report (D8, test-hooks).** A test-hooks worker sends the F14 `layout` frame `[22, 0, load-base, pid]` on
every connection (a fork child reports the load base it inherited from its zygote; a cordon its own). For each one
the supervisor writes a line to stdout or stderr containing `aegis-p2-layout ` followed by the JSON object
`{"pid": <pid>, "load_base": <integer>}`. Golden workers send no layout frame.

**Landlock simulation (D2, test-hooks).** A test-hooks worker treats the environment variable
`AEGIS_P2_TEST_LANDLOCK_ABI=<n>` as the detected Landlock ABI wherever it reads the ABI (compile, zygote, cordon,
probe) and refuses below 4 (exit 78). The supervisor passes every `AEGIS_P2_*` variable through to the workers it
spawns, runs at least one worker (the sandboxed `aegis-p2 compile` of each module) before it listens, and exits 78
without listening when a worker refuses. Golden workers ignore the variable.

**Negative controls (`p2-mutants` / `mutants` builds, PLAN D15).** Selected by `AEGIS_P2_MUTANT=<name>` in the
supervisor's environment (passed through to workers). Names and the check family that must turn red:

| mutant | change | expected red family |
|---|---|---|
| shared-cordon | the cordon key is constant: two principals land in one cordon pid | `cordon.per-principal` |
| fork-respawn | a replacement zygote is forked from a template, not exec'd: same load base | `respawn.zygote.load-base` |
| global-crash-budget | one budget for all principals: principal B gets 429 | `budget.other-principal` |
| no-crash-budget | crashes never lead to 429 | `budget.exhausted` |
| budget-counts-healthy | Deny (a healthy failure) is charged | `budget.healthy-not-counted` |
| dumpable-1 | PR_SET_DUMPABLE(0) skipped: `/proc/<pid>` entries owned by the user | `dumpable.` |
| no-reload-switch | after a forkwasm -> cordon reload the route fails | `reload.` |
| boot-without-landlock-accepted | a worker's Landlock refusal at boot is ignored and the supervisor listens | `boot.landlock-abi3` |
| auto-ignores-cpus | `isolation: "auto"` is served as forkwasm whatever the CPU count (the dump stays truthful, so only the serving process tree and boot log show it) | `auto.small.` |

A mutant counts as caught only if at least one failed check starts with its expected prefix. In the real self-test,
the respawn and Landlock families need the layout report and the ABI override, so the `mutants` build of aegis-p2
must compile them in too (cfg `test-hooks` or `mutants`), unless the caller passes `--mutant-test-worker` for a
build with both features. The control run (mutant build, no `AEGIS_P2_MUTANT`) must PASS first.

## Reference subject (mock)

`ref_subject.py` models the supervisor: the F8 subset above (p2 keys, bounds and patterns read from
`interfaces/F8-config.schema.json`), a minimal F5 Tier-L verifier, boot checks (worker executable, digests, a
`compile` run of the worker per module), TLS via the stdlib, SIGHUP reload with last-known-good, the crash budget,
and the forkwasm/cordon dispatch over SOCK_SEQPACKET with JSON frames (not F14 postcard). `ref_worker.py` does not
execute Wasm: the reference guests are stub modules carrying their kind in a custom section (`p2wire.stub_module`).
It models the process structure (exec'd zygote forking per connection, exec'd cordon per principal),
PR_SET_DUMPABLE=0, refusal below Landlock ABI 4, and, behind `AEGIS_REF_TEST_HOOKS=1` (the oracle's test wrapper),
the layout report (an address inside libc: randomized per execve, kept across fork) and the ABI override. It installs
no Landlock or seccomp (oracles/syscall-negative judges those). Nothing from the mock is a claim about aegis.

## Re-run with the D23 `auto` family (2026-10-31)

- Laptop, reference subject, load average 150-340 (other jobs): `./run`: `P2-E2E: PASS (209 checks)`;
  `./run --self-test`: `PASS (9/9 mutants red ...)`, auto-ignores-cpus caught by 5 checks (`auto.small.boot-log`,
  `auto.small.cordon-per-principal.0..2`, `auto.small.no-zygote`).
- Desktop (24 CPUs, Linux 6.11, Landlock ABI 5, load 1.4-2.5; the laptop had 13 GB free disk, below what the four
  release builds need), the exact gate cmd and selftest through ci/remote.sh: real aegis + aegis-p2
  `P2-E2E: PASS (209 checks)`; selftest reference 9/9 and real subject 9/9 (`target/p2-mutants`), baseline green on
  209 checks. That host is not the quiet laptop, so this is not a substitute for the laptop gate run (needs).

## Re-run in repo (laptop, 2026-10-31, Linux 6.17.0-14-generic, Landlock ABI 7; before the `auto` family)

- `./run`: `P2-E2E: PASS (161 checks)`, 20.5 s, load average 5.7.
- `./run --self-test`: `P2-E2E SELF-TEST: PASS (8/8 mutants red on their expected checks, baseline green on 161
  checks; subject reference ref_subject.py + ref_worker.py)`, 105 s at load average 46.6 (1 min). Per mutant (failed
  checks / expected family): shared-cordon 7 (`cordon.per-principal.1..3`, `.count`), fork-respawn 1
  (`respawn.zygote.load-base-changed`), global-crash-budget 9, no-crash-budget 3, budget-counts-healthy 5,
  dumpable-1 7, no-reload-switch 32, boot-without-landlock-accepted 2 (`boot.landlock-abi3.exit78`,
  `.never-listened`).
- Real-mode path exercised against the pre-Phase-5 core binary `target/release/aegis` (no `p2` feature) with the mock
  worker: the guests built through ci/heavy.sh and passed `check_f14`; the run is red (13 failed: the config dump
  exits 78 and every boot refuses with `config error at "/p2": UnknownField`), as expected before P5-config-001 and
  P5-bin-001.
- Measured while designing the dumpable check (python ctypes fork + prctl, this laptop): after
  PR_SET_DUMPABLE(0), `/proc/<pid>/{stat,status,maps,fd,environ,mem,cmdline}` are owned by uid 0 and `maps` gives
  EACCES, but the `/proc/<pid>` directory itself stays owned by the task's euid (1000). With dumpable 1 all are 1000.

Provenance: designed from PLAN-5 D1/D2/D7/D8/D15, F14, the F8 `p2` block, oracles/native-e2e (token minting, client,
boot-refusal pattern, copied rather than imported so the directory stays self-contained) and oracles/syscall-negative
(probe conventions). No research artifact is executed.

## Known limits

- **`/proc/<pid>` ownership.** The acceptance phrase "root-owned /proc/<pid>" is implemented as root-owned per-pid
  entries plus an unreadable `maps`: since Linux 4.11 (`task_dump_owner` skips the `dr-xr-xr-x` pid directory) the
  directory keeps the euid even for a non-dumpable task (measured above). A worker running as root, or an oracle
  running as root, cannot be judged; the oracle refuses the latter.
- **Attribution of cordons to principals is structural.** Without a test hook, "one cordon per principal" is judged
  as "each new principal's first request makes a new long-lived worker process appear" plus kill isolation. A
  subject that pre-spawns a warm pool and hands a pool member to a new principal still shows a new pid (the pool
  refill) and is not distinguished from one that hands two principals the same member *after* the first four. The
  shared-cordon mutant shares from the first request on.
- **The zygote is found structurally** (parent of a short-lived worker child during a spin request). A subject that
  spawns workers through a long-lived helper process would make the helper look like a zygote in forkwasm checks.
- **Load base and pids are self-reported** by the test-hooks worker through the supervisor's log line; the oracle
  cross-checks the cordon's layout pid against the process tree but cannot read `/proc/<pid>/maps` (dumpable=0 is
  the point). A dishonest test build could lie; the hook is reviewed with the worker (D15).
- **Response mapping is fixed by this contract** (403 Deny; Error = the same Deny response, PLAN D17; 429 penalty).
  F14 says only "the host's own fixed response"; P5-bin-001 implements these codes, and the hostile-host oracle judges
  the bytes (I5). Because Error and Deny look the same, the budget and respawn checks tell them apart by route
  (`/deny/` vs `/trap/`, `/abort/`) and by process state, never by status.
- **Timing.** Budget windows are seconds and respawn waits are bounded at 10 s; the run reports a timing failure
  rather than a verdict when 3 sequential traps exceed the window (prints the load). Laptop only (`needs`).
- **The reference guests are stubs**; the Rust guests are checked structurally (`check_f14`) but have not yet been
  instantiated by Wasmtime here, because no aegis-p2 worker exists yet (first real use: P5-bin-001).
