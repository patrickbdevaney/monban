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

The unmutated reference subjects must pass the same cells (the control), so the self-test also fails if the oracle
is red on a correct subject. The no-fork mutation is *not* caught by hostabort alone: a single-threaded in-process
server behind a supervisor-held socket loses only the in-flight request on abort (0 healthy failures, 3-4.5 ms
restart). That is why hostpoison exists.

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
- Wasmtime 48.0.7 replaced by 49.0.3; the wasmtime-wasi dependency dropped.
- Fuel budget added; the fork+Wasm zygote is new (the research fork path was native).
- New host fault classes: hostabort and hostpoison.
- New metrics: service-gap recovery with censoring, and per-cell recovery samples.
- Subject process groups are cleaned up on restart and at exit.
- The data blob is regenerated (`data.bin`, sha256 ac64825f..., derived from SHA-256 of a counter).
- The runaway guest does real work, so that fuel per ms matches the handler's rate.

The research result reproduced here: E4 (epoch-only, 4 threads) gives loop p99 x34.2 against the research's x34.7
(spikes/q4-006).

## Pin

`wasmtime =49.0.3` (2026-10-14) is the newest release that meets the 7-day lock age on 2026-10-25. It is **below**
the ARCHITECTURE floor of >=49.0.4 (GHSA-897f), which is acceptable only because the oracle runs its own
first-party guest. Re-pin to 49.0.4 on or after 2026-10-26, or to 50.0.0 (the lock target) on or after 2026-10-27:
edit `rust/host/Cargo.toml`, run `cargo update -p wasmtime --precise <v>`, then check every lock entry is at least
7 days old (`lock-dates.txt` holds the current dates; the newest is libc 0.2.191, 2026-10-16). Toolchain: Rust
1.98.0 (`rust/rust-toolchain.toml`), the installed toolchain that has the wasm32-unknown-unknown target.
`build.sh` changes into `rust/` so that rustup resolves that toolchain file.

## Known limits

- The reduced run is 1 trial per cell, with about 30 faults per class. A blast of 0.05 per fault is resolvable only
  as "0 or more than 0.03", so the spike's 5-trial run is the measurement and the oracle is a gate.
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
