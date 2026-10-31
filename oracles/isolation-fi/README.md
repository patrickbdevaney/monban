# isolation-fi oracle (Phase-5 P2 isolation fault gates)

`./run` drives a P2 isolation subject through injected faults and checks the Phase-5 gates
(IMPLEMENTATION_PLAN Phase 5; ARCHITECTURE §3.6). `./run --self-test` shows that the checks turn red on mutated
subjects.

## What is checked

Spec clauses covered: INV-FAILCLOSED host mapping (crash, panic or trap of a request yields a failed request and
never a wrong answer for anyone else); CRS **C8** (recycled objects reset, no per-request state leaks across
requests or principals); **Wasm budgets** (an epoch or wall-clock bound plus a ResourceLimiter actually bound a
runaway guest); and the §3.6 P2 acceptance rows.

Faults are injected at 1%, with n=3000 requests per cell and 16 concurrent closed-loop clients; the server is
pinned to one core.

| gate | criterion |
|---|---|
| G0 | no-fault baseline: 0 healthy failures and 0 wrong answers |
| G1 | crash-attributable healthy failures per injected fault <= 0.05 |
| G2 | 0 wrong answers (a poisoned instance or host must never answer a later request) |
| G3 | service-gap p99 <= 5 ms and no unrecovered fault. The gap runs from the end of the faulting request to the next healthy success; a fault is censored when no healthy request was issued after it |
| G4 | healthy throughput at 1% loop >= 0.5x the baseline |

Fault classes:
- Gated on both paths: panic, abort (`unreachable`), segv (out-of-bounds store), loop (a runaway handler doing real
  work), oom (grow until the limiter denies), poison (the guest mutates a global that every later call reads).
- **hostabort** (a host function aborts the host process) and **hostpoison** (a host function sets a flag that
  corrupts every later reply from that process): gated for the fork+Wasm path, where they test its containment
  claim, and only reported for the cordon path. A per-tenant cordon accepts cordon-local damage; a cordon shared by
  principals does not (spikes/q4-006).
- fdleak cannot be expressed by an M0 guest, which has no fd imports.

The timing gates G3 and G4 re-drive a failing cell once and keep the better attempt, because this laptop is shared.
The count gates G0-G2 are never retried.

## Subject interface (`--subject '<cmd>' --path cordon|forkwasm`)

The subject is a server command. `{guest}` (path to the oracle's guest.wasm) and `{data}` (a 4 KiB file the host
must read once per request, standing in for I/O) are substituted. The driver holds a listening Unix socket and
passes it as **fd 3** (socket activation), restarts the subject whenever it exits, and starts the command in its own
process group, which it SIGKILLs on restart and at the end of the run.

Protocol: one connection per request. The client sends 8 bytes, `id: u32 LE` then `fault: u32 LE`. The server calls
the guest export `handle(id, fault) -> u32` and replies with 8 bytes, `id` then the result. The correct result is
`work(id, 0x5a17c0de, data.bin)` (see `rust/work.rs`); any other value counts as a wrong answer. A trap means the
server closes the connection without replying. The guest imports `env.host_fault(code: u32)`. Code 1 must take the
serving host process down (abort); code 2 must corrupt that process's host state so that every later reply from the
process is wrong (the reference XORs results with 0x5a5a). Real AEGIS hosts wire these two codes in a test-only
build. A subject that does not honour them cannot claim the host-fault rows.

Reference subjects (built from `rust/`, Wasmtime 49.0.3, pooling allocator, 16 MiB limiter, default guards,
Landlock + seccomp, dumpable=0):
- `isofi serve cordon --threads 64 --budget fuel:15000000 --epoch-ms 100`: fresh instance per request in one
  process.
- `isofi serve forkwasm --budget fuel:15000000 --epoch-ms 100`: single-threaded zygote with a precompiled module;
  fork per request, `ITIMER_REAL` in the child.

## Self-test mutations (each must be caught)

| mutation | path | caught by |
|---|---|---|
| shared-store: one Store/Instance shared by all requests | cordon | G2 poison (917 wrong), G1 |
| recycle50: instance reused for 50 requests (a partial fix) | cordon | G2 poison (207 wrong), G1 |
| no-deadline: no fuel, no epoch deadline | cordon | G4 loop x0.02, G3 |
| no-fork: the zygote serves requests in-process | forkwasm | G2 hostpoison (915 wrong), G1 |
| no-deadline: no fuel, no itimer | forkwasm | G4 loop x0.08, G3 |
| epoch-only-4: epoch-only 100 ms, 4 threads (research E4; Phase 5) | cordon | G4 loop x0.14 |
| reuse-instance: the forked child keeps its instance and serves 50 more connections (Phase 5) | forkwasm | G2 poison (206 wrong), G1 |

`--self-test` also runs offline reference/record checks before any subject: a synthetic timing metric 2.1x the
reference (and a throughput 1/2.1x) is flagged, 1.9x is not, and a red cell set judged before and after loading a
mutated reference (mirrored red values, fake loose thresholds, verdict "PASS") keeps the same failures. Setting the
flag ratio to 1.8 or 2.2 turns these checks red (checked by hand, 2026-10-31).

The unmutated reference subjects must pass the same cells (the control), so the self-test also fails if the oracle
is red on a correct subject. The no-fork mutation is *not* caught by hostabort alone: a single-threaded in-process
server behind a supervisor-held socket loses only the in-flight request on abort (0 healthy failures, 3-4.5 ms
restart). That is why hostpoison exists.

## Phase 5: real subject, trials, record and reference (unit P5-oracle-fi-001, PLAN D10/D14)

`needs` = `quiet-host`: the timing gates G3/G4 run on the laptop (the quiet host and reference runner, PLAN D10),
so `ci/oracles.sh --where remote` no longer runs this oracle on the shared desktop.

| option | meaning |
|---|---|
| `--trials N` | pool N driver runs per cell (seeds `s`, `s+1000`, ...). Counts are summed, so G1 = sum healthy failures / sum injected (3 trials: about 90 faults per class, PLAN D14). G3 recovery p50/p99 are recomputed over the concatenated per-fault samples. Throughput = total requests / total wall time. Latency p99 = the worst trial's. The timing-only re-drive of a failing cell re-drives the whole pooled cell once. |
| `--record <json>` | write per-cell metrics (format `isolation-fi-record/1`: per path, host facts, subject, trials, n, rate, cores, verdict, and per cell the counts, latency and recovery percentiles, rps, `rps_vs_baseline`). It merges by path into an existing record file, so two runs (`--path forkwasm`, `--path cordon`) can build one reference file. |
| `--reference <json>` (repeatable) | after the verdict is fixed, print this runner/reference ratios for the timing metrics `p50_us p99_us recovery_p50_us recovery_p99_us rps rps_vs_baseline` and flag any shift above 2x in either direction. Report only: thresholds never move, and the reference file is never passed to the evaluator. A per-runner threshold needs an integrator Decision (PLAN D10). Count metrics are never ratioed. |
| `--self-test --path P --subject S --mutant-subject M` | real-subject self-test. S (golden build) and M with `AEGIS_P2_MUTANT` unset must pass the self-test cells (none, poison, loop, hostabort, hostpoison; n=1000). M is then run with `AEGIS_P2_MUTANT=<m>`, every cell for every mutant, and each mutant must turn the verdict red: forkwasm {no-fork, no-deadline, reuse-instance}, cordon {shared-store, recycle50, no-deadline, epoch-only-4}. A mutant that cannot serve the no-fault baseline counts as MISSED (broken, not caught). The oracle strips any inherited `AEGIS_P2_MUTANT` from control runs. |
| `--server-core C --client-cores a,b` | CPU pinning (taskset). Default `2` / `4,5,6,7`. On a 4-core runner (kamrui, Intel N95) use `--server-core 1 --client-cores 2,3`, which leaves core 0 for the OS and the driver's supervisor (PLAN D10). |

Real subject contract: the p2-subject speaks the 8-byte protocol above on fd 3, honours `env.host_fault` codes 1
and 2 in its test build, and in its `mutants` build reads `AEGIS_P2_MUTANT`. hostabort/hostpoison are gated for
forkwasm and reported for cordon. The reference `isofi serve` also reads `AEGIS_P2_MUTANT` when `--mutation` is not
given, so the mode is exercised before the real subject exists.

Measured on 2026-10-31 (laptop i9-14900HX, 32 threads, load average 12-14 from other agents' builds: not quiet).
The real p2-subject did not exist yet (built by P5-iso-002/003), so `--mutant-subject` mode was run with the
reference binary as both the subject and the mutants build:

```
forkwasm: control subject PASS; control mutants build (AEGIS_P2_MUTANT unset) PASS
  no-fork        CAUGHT: G2 hostpoison wrong_answers=982; G1 hostpoison blast=89.273
  no-deadline    CAUGHT: G3 loop unrecovered; G4 loop throughput x0.083<0.5
  reuse-instance CAUGHT: G2 poison wrong_answers=208; G2 hostpoison wrong_answers=77
ISOLATION-FI SELF-TEST: PASS (forkwasm real subject: 3/3 mutants caught ...)
cordon: control subject PASS; control mutants build PASS
  shared-store   CAUGHT: G2 poison wrong_answers=950
  recycle50      CAUGHT: G2 poison wrong_answers=126
  no-deadline    CAUGHT: G4 loop throughput x0.023<0.5
  epoch-only-4   CAUGHT: G4 loop throughput x0.192<0.5
ISOLATION-FI SELF-TEST: PASS (cordon real subject: 4/4 mutants caught ...)
negative control: a "mutants build" that ignores AEGIS_P2_MUTANT (env -u) ->
ISOLATION-FI SELF-TEST: FAIL (missed: no-fork, no-deadline, reuse-instance)
```

Record and reference, same day: `--trials 3 --record` on both reference paths wrote one file with 86-100 injected
faults per class. A red subject (`--mutation shared-store`) judged with a mutated reference (timing x2.1, fake
thresholds, verdict PASS) stayed `FAIL` (G2 poison 2845 wrong); a green subject against the same mutated reference
stayed `PASS` with 47 of 52 metrics flagged (5 were within 2x because the run's own timing shifted); against the
unmutated record it flagged 0.

Unit acceptance `./run --self-test && ./run --trials 3` (gate timing mode, fresh build each run):
- load average 7.7 rising to 29 (an unrelated 12-core test job): self-test PASS (7/7); `--trials 3` FAIL on
  `forkwasm G3 oom recovery_p99=5918us` after the timing re-drive. All count criteria were green.
- load average 4.7: `ISOLATION-FI SELF-TEST: PASS (7/7 mutations caught; unmutated control passes; reference checks
  pass; 14s)` and `ISOLATION-FI: PASS (cordon, forkwasm; 8 fault classes at 1%; 3 trial(s) per cell; 24s)`. Pooled
  oom recovery p99: cordon 2317 us, forkwasm 3670 us. Loop throughput: cordon x0.70, forkwasm x0.86.

## Re-run in this repository (2026-10-25, laptop i9-14900HX, shared machine)

`./run` takes 72 s including the build; `target/` is 544 MB and is deleted at exit:

```
  cordon: PASS
  forkwasm: PASS
ISOLATION-FI: PASS (cordon, forkwasm; 8 fault classes at 1%; 8s)
```

The cordon reported hostabort at 11.9 failures per fault and hostpoison at 99.7 wrong answers per fault (reported
only, not gated). The fork+Wasm path had 0 failures on every class.

`./run --self-test` takes 12 s on the kept build:

```
ISOLATION-FI SELF-TEST: PASS (5/5 mutations caught; unmutated control passes; 12s)
```

## Provenance (untrusted research inputs; read and rewritten, never executed in place)

| path under `research/state/raw/` | sha256 |
|---|---|
| round-004/04-work/fi/finat/src/main.rs | afd6cb3b02e357901c162d7849df17d516583667bd0398ab3ab020e41767dced |
| round-004/04-work/fi/finat/src/driver.rs | 48a0571f1e08c06e7504220f25050d76be0905798c11cbc0d61b0989c715bd06 |
| round-004/04-work/fi/fiwasm/src/main.rs | 098d9818b7b2c12a5567130617a75ff20d4ed7dff3730a8f5a2e46d36c8d8caa |
| round-004/04-work/fi/guest/src/lib.rs | e6ae4fad5ce033902323a03493125d44d9715aed539fd93886ae00a82aa2d9e1 |
| round-004/04-work/fi/common/work.rs | a37f89e17ce74a1dcb29558c46648adda7701edcce1505fa255411feb76d13f6 |
| round-004/04-work/fi/scripts/run_matrix.py | 4d28209542e463a55d76c750d7f9d2c411bba5eac8eabe27c9fd15fa08265786 |
| round-004/04-isolation-crash-blast-radius-measured.json | f6742f0a9f8b05b69bb467da7f298ab477d17bae28a17ea8efade6a51bf7a354 |
| round-002/07-bench/host/src/main.rs (pooling config) | 79316b47dbbab1914723215639fef2bb88654e0906bf15e7261a7ed43405d7d0 |
| round-001/04-bench/src/bin/forkpanic.rs | 49b9e1e00c50102eb267d5c453d5a63ad129fd1e2a5824a1ad0767789f0dc540 |

Changes from the research harness:
- Wasmtime 48.0.7 replaced by 50.0.0; the wasmtime-wasi dependency dropped.
- Fuel budget added; the fork+Wasm zygote is new (the research fork path was native).
- New host fault classes: hostabort and hostpoison.
- New metrics: service-gap recovery with censoring, and per-cell recovery samples.
- Subject process groups are cleaned up on restart and at exit.
- The data blob is regenerated (`data.bin`, sha256 ac64825f..., derived from SHA-256 of a counter).
- The runaway guest does real work, so that fuel per ms matches the handler's rate.

The research result reproduced here: E4 (epoch-only, 4 threads) gives loop p99 x34.2 against the research's x34.7
(spikes/q4-006).

## Pin

`wasmtime =50.0.0` (2026-10-20) is the lock target and meets the ARCHITECTURE floor of >=49.0.4 (GHSA-897f).
It was re-pinned from 49.0.3 on 2026-10-29. cranelift is held at 0.137.0 because 0.137.1 (2026-10-29) was under the
7-day lock age. To re-pin: edit `rust/host/Cargo.toml`, run `cargo update -p wasmtime --precise <v>`, then check
every lock entry is at least 7 days old (`lock-dates.txt` holds the current dates; the newest are the wasmtime
50.0.0 crates, 2026-10-20). Toolchain: Rust
1.98.0 (`rust/rust-toolchain.toml`), the installed toolchain that has the wasm32-unknown-unknown target.
`build.sh` changes into `rust/` so that rustup resolves that toolchain file.

## Known limits

- The default run is 1 trial per cell, with about 30 faults per class. A blast of 0.05 per fault is resolvable only
  as "0 or more than 0.03"; the Phase-5 gates use `--trials 3` (about 90 faults per class, PLAN D14).
- The cordon oom recovery p99 is marginal against 5 ms (q4-006: 1.2-6.6 ms). Pooled over 3 trials on the loaded
  laptop on 2026-10-31 it was 5620 us (FAIL), after one timing re-drive. This is a property of the measured design
  under load, not of the oracle. The gate is defined for a quiet host.
- Timing gates depend on the hardware: the fork path's loop service gap was 6.8 ms on an Intel N95. Re-calibrate the
  budgets or the thresholds on a quiet VPS-class runner, as Phase 5 requires.
- Host faults are simulated through `env.host_fault`. The negative syscall tests, the hostile-module corpus (I1-I7)
  and the wasmtime pin/config assertions are separate Phase-5 gates, not covered here.
- Sockets and the precompiled-module cache live in `.work/`, which is deleted at exit.

## Timing mode
`AEGIS_TIMING_GATES=advisory` (or `--timing advisory`) reports G3 recovery-p99 and G4 loop-throughput without gating
them, for shared build boxes where they are noise (cordon OOM recovery p99 measured 1.2–16 ms depending on host load).
Correctness criteria stay gated; the PASS line says `timing ADVISORY`. The Phase-5 gate runs in the default `gate` mode
on a quiet VPS-class runner, per IMPLEMENTATION_PLAN Phase 5. Never applies to `--self-test`.
