# q4-006: fuel + 64-slot pool loop gate, and fork-cost run (fresh-Wasm cordon vs fork+Wasm for multi-principal P2)

Verdict: **flip**. Make fork+Wasm the multi-principal P2 default; the alternative is one fresh-Wasm cordon per
principal, and a cordon shared by several principals is not allowed. The single-tenant P2 row keeps the per-tenant
cordon, but with a per-route fuel budget of at most 50x the handler cost instead of a flat 10-50 ms. Grade B
(laptop plus a LAN stand-in for a VPS). Numbers and the exact decision text are in `verdict.json`.

## Method

Harness: `oracles/isolation-fi/rust` (`isofi`, same commit), built by `measure.sh` into `spikes/q4-006/target`
through `ci/heavy.sh`. `target/` is deleted afterwards (peak 544 MB). Wasmtime 49.0.3 is used with
`default-features = false` and features cranelift, pooling-allocator, runtime and std. The default 4 GiB reservation
and 32 MiB guard are kept, and the ResourceLimiter allows 16 MiB per instance. Every crate in `Cargo.lock` is at
least 7 days old; the newest is libc 0.2.191 from 2026-10-16 (`oracles/isolation-fi/lock-dates.txt`). Wasmtime
49.0.4 and 50.0.0 are still under the lock-age rule today (see Limits).

Subjects (each one is served by a process pinned to one core, with a supervisor-held listening socket,
`PR_SET_DUMPABLE=0`, and Landlock plus seccomp):
- **cordon** (`isofi serve cordon`): one process. Each request gets a fresh Store and instance from a 64-slot
  pooling allocator. T worker threads; the budget is epoch-only (100 ms) or fuel plus the 100 ms epoch backstop.
- **fork+Wasm** (`isofi serve forkwasm`): a single-threaded zygote that holds the Engine, the locally precompiled
  Module and the InstancePre. Per request it forks a child, which instantiates fresh, runs the call, replies and
  calls `_exit`. The budget is fuel plus a 100 ms `ITIMER_REAL`. If the zygote had to compile the module itself, it
  re-execs once so that it loads the cached cwasm instead.

Driver (`isofi drive`): closed loop with 16 concurrent clients and n=3000 requests per cell. A fault is injected
with probability r through a deterministic splitmix stream. The driver restarts the server when it exits and runs a
2 s liveness watchdog. Laptop: server on core 2, clients on cores 4-7, 5 trials per cell in shuffled order. kamrui
(Intel N95, the VPS stand-in): laptop-built binaries, server on core 1, clients on cores 2-3, 3 trials. The
temporary directory on kamrui was removed afterwards.

Fault classes: the Phase-5 guest classes (panic, abort, segv, loop, oom, poison) plus two host classes. hostabort
is a guest-triggerable host crash: a host function calls `abort()`. hostpoison is guest-triggerable host-state
corruption: a host flag corrupts every later reply from that process. fdleak cannot be expressed by an M0 guest,
which has no fd imports.

**Recovery** is the service gap: the time from the end of the faulting request to the next healthy success. A
fault is censored (not scored) when no healthy request was issued after it ended.

Budgets: 15M fuel is 2.0 ms of handler-like work on the laptop and 3.5 ms on the N95 (`data/calibrate.json`), about
58x one healthy request. 75M fuel is about 10 ms on the laptop.

## Results (laptop, 1% unless noted; medians over trials, counts pooled)

(a) Loop gate. Healthy p99 is shown as a multiple of the variant's no-fault baseline:

| variant | p99 at 1% | throughput at 1% | p99 at 5% | throughput at 5% |
|---|---|---|---|---|
| E4: epoch 100 ms, 4 threads (research config) | x34.2 | x0.163 | x69 | x0.039 |
| E64: epoch only, 64 slots | x4.95 | x0.234 | x8.5 | x0.093 |
| F4-2: fuel 2 ms, 4 threads | x2.79 | x0.759 | x6.0 | x0.330 |
| F64-10: fuel 10 ms, 64 slots | x4.56 | x0.323 | x8.1 | x0.103 |
| **F64-2: fuel 2 ms, 64 slots** | x3.06 | **x0.718** | x7.0 | x0.339 |
| FW-E: fork, itimer 100 ms only | x2.73 | x0.637 | x3.1 | x0.335 |
| FW-F10: fork, fuel 10 ms | x2.50 | x0.649 | x3.0 | x0.346 |
| **FW-F2: fork, fuel 2 ms** | x1.60 | **x0.898** | x2.1 | x0.643 |

Healthy p50 at 0, 1 and 5%: E4 783/685/3357 us; F64-2 722/675/1053 us; FW-F2 3039/3012/3023 us.

Throughput follows `c / (c + r*B)` to within 0.01-0.02 in every fuel variant, where c is the per-request core cost
(cordon 48.8 us, fork 192 us) and B is the budget. The 0.5x gate at 1% therefore needs B <= 100*c. The 64-slot
pool fixes p99 but not throughput: the fuel budget is what fixes throughput.

(b) and (c) fault gate at 1%, F2 budget:

| class | cordon: failures per fault / wrong / gap p99 | fork+Wasm: failures per fault / wrong / gap p99 |
|---|---|---|
| panic, abort, segv | 0 / 0 / 0.08-0.10 ms | 0 / 0 / 0.57-0.65 ms |
| loop | 0 / 0 / 1.13 ms (throughput x0.71) | 0 / 0 / 2.31 ms (throughput x0.89) |
| oom | 0 / 0 / 1.20 ms (6.6 ms in an earlier run) | 0 / 0 / 3.91 ms |
| poison | 0 / 0 / 0.09 ms | 0 / 0 / 0.77 ms |
| hostabort | **11.0** / 0 / 6.2 ms (restarts) | 0 / 0 / 0.63 ms |
| hostpoison | 0 failures, but **103.5 wrong answers per fault** | 0 / 0 / 0.60 ms |

Baseline throughput: cordon 20.4k rps, fork 5.2k rps (x0.25).

Fork cost (`forkcost`, zygote loading the cwasm):

| host | fork+exit+wait p50 | fork+Wasm request p50 / p99 | overhead over a fresh instance p50 / p99 |
|---|---|---|---|
| laptop | 57-63 us | 149-152 / 363-403 us | +99-102 / +304-321 us |
| N95 | 142-156 us | 311-316 / 545 us | +205-223 / +301-351 us |

If the module is compiled inside the zygote, the zygote's RSS doubles (11.8 MiB instead of 5.8 MiB) and each fork
costs +43 us on the laptop and +68-84 us on the N95.

kamrui (N95), 1%: fork+Wasm had 0 failures and 0 wrong answers on every class it ran (abort, loop, poison,
hostabort, hostpoison), but **the loop service gap p99 was 6.8 ms**, over the 5 ms gate in 2 of 3 trials. The cordon
had 0 failures on abort, loop and poison (loop gap 1.27 ms, throughput x0.84), and 11.3 failures per hostabort fault
plus 101.8 wrong answers per hostpoison fault. Baselines: cordon 7.5k rps, fork 2.2k rps.

## Gate verdict per path (Phase-5 criteria at 1%)

- **fork+Wasm**: passes every criterion on the laptop, for all 6 guest classes and both host classes. On the N95 it
  fails the recovery criterion for loop (6.8 ms against 5 ms).
- **fresh-Wasm cordon (F2, 64 slots)**: passes for the guest classes (the oom recovery is marginal across runs) and
  fails both host classes. That failure only matters when principals share a cordon, which is exactly the
  multi-principal case.
- Cordon with epoch-only or a 10 ms fuel budget: fails loop throughput.

## Why flip

For multi-principal data, the difference that matters is what one principal's request can do to other principals.
A guest-triggered host bug in a shared cordon failed about 11 other requests per fault and returned about 100 wrong
answers per fault. These are exact counts and do not depend on the hardware. fork+Wasm contained both with zero
failures. The M0 escape planning rate (2.21/yr, P(>=3 in a year) = 0.38) points the same way. The cost is +0.10 to
+0.22 ms p50 per request, which is under the R3 threshold of 0.3 ms at p50 and borderline at p99, and 0.25-0.30x the
cordon's throughput for a 36-64 us handler. The fallback, one cordon per principal, keeps the containment but costs
a process per principal.

## Reproduce

```
spikes/q4-006/measure.sh                       # TRIALS=5 used; heavy.sh job; writes data/, deletes target/
python3 -I spikes/q4-006/analyze.py spikes/q4-006/data > spikes/q4-006/data/summary.json
# LAN stand-in: LANDIR=/some/dir spikes/q4-006/measure.sh ; copy the dir to the host, then on the host:
python3 -I run_spike.py ./isofi guest.wasm $PWD/data.bin data forkcost 3 1
python3 -I run_spike.py ./isofi guest.wasm $PWD/data.bin data lan 3 1 2,3
```

Raw data: `data/{loop,fi,forkcost}.jsonl` (one summary per cell), `data/summary.json`, `data/srv-logs.tgz`, and the
same files for kamrui under `data-kamrui/`. Per-request TSVs were deleted to keep the repository small.

## Limits

- Laptop and LAN box only (grade B). The laptop was shared with other agents during the runs (1-min load 7-19).
  Latency columns are provisional; counts are exact. q3-001 must repeat `forkcost` and the `lan` phase on a real
  1-vCPU KVM VPS, which has steal time and virtualised page-table costs that the N95 does not.
- The handler is a toy (36-64 us) served over a Unix socket. Fork cost scales with zygote RSS; this zygote is
  5.8 MiB.
- Host faults are simulated. Real runtime bugs can disclose memory before they crash.
- Fuel per ms depends on code shape, so budgets need per-route calibration.
- The service gap scales with the path's own latency, which is why fork's loop gap on the N95 lands near 5 ms.
- One earlier 5-trial run (before hostpoison and the zygote re-exec were added; heavier machine load) measured the
  cordon oom gap at 6.6 ms. Those files were replaced by the final run.
- Wasmtime 49.0.3 is below the >=49.0.4 security floor (GHSA-897f). It runs only first-party test guests. 49.0.4
  (published 2026-10-19) becomes lock-age eligible on 2026-10-26 and 50.0.0 on 2026-10-27; re-pin then.
- The fork child only inherits the zygote's filter. The child-only denylist (socket, bpf, io_uring and others) is
  Phase-5 work.
