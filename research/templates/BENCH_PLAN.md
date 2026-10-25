# BENCH_PLAN (template, v4, 2026-10-25)

Source: ARCHITECTURE.md v4 §6, R-PERF-1/2/3, `w02.L5-bench-harness-spec`. Each optimization axis is reported separately; never a composite score.

## 1. Baselines (versions verified 2026-10-25)

| baseline | version | role | caveat |
|---|---|---|---|
| nginx | 1.31.8 | static, TLS, proxy | record OpenSSL version and groups |
| Envoy | v1.40.1 | proxy, H2, TLS | BoringSSL; 63 MB idle |
| Pingora | 0.9.0 | Rust proxy peer | panics on first connection with tokio ≥1.54 (#1059; PR #1060 unmerged): build with PR #1060 applied or tokio <1.54, and say which |
| Caddy | v2.11.7 | Go proxy, auto-TLS, household peer | Go crypto |
| HAProxy | latest 3.x LTS, exact version recorded | proxy | maxconn-dependent RSS 45–78 MB |
| Node.js | 24.22.1 LTS (`node:http`) | app-server role (W5/W6) | not a proxy baseline |
| Go | 1.27.3 `net/http` | app-server role | not a proxy baseline |
| PHP-FPM | distro version recorded | crash-containment control (W8) | measured parity reference (`r4i04.php-fpm-measured-control` B) |

## 2. Protocol (R-PERF-2)

- **Placement:** isolated cpuset core with idle SMT sibling, plus a `--cpus=1` run; 512 MB cgroup; unique high ports; lockfiles and configs committed.
- **Trials:** ABBA-interleaved, ≥5 reps; log loadavg, steal time (`/proc/stat`), kernel, governor per run.
- **Primary metric:** cgroup `cpu.stat` µs/request (robust on contended hosts). Secondary: p50/p99/p999.
- **Reporting:** **bands, never a best trial** (the round-2 "best trial" appeared in no log). Rankings only outside observed variance (2.8× seen on the laptop). Example: hybrid handshake overhead is reported as the band +12.5% to +17.5%, not a point.
- **Config parity:** same TLS version and named group per run (X25519 and X25519MLKEM768 separate); access logging all-off or all-on; workers = cores; same keepalive; H2 limits documented per server; every baseline config published beside results.
- **Hardware tiers:** T1 $5 1-vCPU KVM (**release reference**; laptop-derived gates are provisional until re-run here); T2 4-vCPU VPS; T3 64-core bare metal (phase 7).
- **Grade caps:** single-machine results cap at B; contended-host numbers cap at B and are labelled.
- **Machine safety (§0e):** ≤2 concurrent compile/bench jobs on disjoint cores, under `heavy.sh` memory cap.

## 3. Workloads

| id | workload | baselines | target / gate |
|---|---|---|---|
| W1 | static 1 KB, h1 and h2, keepalive | nginx, HAProxy, Pingora, Caddy, Envoy | median µs/req ≤2× nginx in the same run (≥0.5× nginx) — Phase-2 gate |
| W2 | TLS 1.3 full and resumed, X25519 vs X25519MLKEM768 | all five proxies | hybrid ≤1.3× X25519 (laptop band +12.5–17.5%, B) |
| W3 | reverse proxy to h1 echo upstream | proxies | publish only until T1 data |
| W4 | idle memory at 0 / 1k / 10k TLS conns | all | ≤8 MB idle, ≤25 MB at 1k (laptop 3.4–5.9 / 17.2, A) |
| W5 | JSON handler and MCP tool call through the gate | Node 24, Go 1.27 | publish; gate overhead is the number of interest |
| W6 | DB-mediated read (PG) vs direct driver | same handler without IR | per-op overhead; out-of-process budget ≈12.4k calls/s/core at 8.07 µs (re-baseline T1) |
| W7 | goodput under Rapid Reset / MadeYouReset / CONTINUATION / slowloris at 1 vCPU | proxies | **advisory** until a first run sets numbers (attack rates from the fuzz corpus) [E] |
| W8 | fault injection, 7 classes | PHP-FPM, fork, native | FI gate thresholds (IMPLEMENTATION_PLAN Phase 5) |
| W9 | reload under load | nginx USR2, HAProxy, Envoy hot restart, Caddy | 0 drops before D per 100 reloads |
| W10 | swarm scenarios per scenario, held-out seeds | — | **advisory** until simulator calibrated (D) |
| W11 | substrate cost: native, core Wasm, component, fresh pooled instance, fork, cordon | — | publish; toy-handler rankings are not quotable inside variance |
| W12 | handshake capacity on T1 (q3-001) | — | replaces the E-graded household estimate (~3.1–3.7k req/s 429-after-full-TLS X25519; ~2.7–3.3k hybrid, from own laptop handshake × 0.5 scale) |
| W13 | Wasm density | — | report tiny-module floor (7.1 KiB/instance) and component-with-WASI (~52 KB/instance, ~19.9k/GiB, VA-slot capped) as separate rows |

## 4. Current numbers (laptop, i9-14900HX; grade per row)
See ARCHITECTURE.md §6 table. Household and 4–16 vCPU rows are E until W12/T2 runs; 64-core is unmeasured.

## 5. Report format
One table per axis (security gates pass/fail, PQ overhead band, latency/throughput bands, memory, binary size, crash containment counts, DX mutant score), each with: workload id, tier, run ids, loadavg/steal, config hash, baseline configs link, grade.
