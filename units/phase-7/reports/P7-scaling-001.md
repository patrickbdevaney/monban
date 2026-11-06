# P7-scaling-001 report (spec-author, 2026-11-06)

**Verdict.** The harness is built and its self-test is green: 6 of 6 mutants go red. The gate `scaling` is **red**
on the default build. This is a real blocker, recorded in `bench/scaling/INFEASIBLE_REPORT.md` and not worked
around: aegis's hard-coded per-IP admission limit (S1/S3 anon, 1000 req/s, burst 2000) refuses any saturating
single-source h2load run. Also, a 24-core point cannot have disjoint cpusets on the 24-thread desktop.

## Delivered (bench/scaling/)

| file | what it does |
|---|---|
| `run` | Entry point. Re-executes under `ci/heavy.sh` for measuring runs; `--self-test` and `--gcp` are light. |
| `scaling.py` | The harness (stdlib Python): build, cpuset allocation, cpus.rs probe, h2load run and parse, report, judge, `--gcp` quota preflight, self-test. |
| `upstream.rs` | Static HTTP/1.1 upstream: std only, plain `rustc -O`, no dependencies. |
| `provision-h2load` | Installs nghttp2 1.69.0 h2load from the digest-pinned `oracles/transport-limits/Dockerfile` image (built on kamrui) into `~/aegis-ci/tools` on a box without docker. |
| `README.md` | Usage, method, the `--gcp` operator flow. |
| `INFEASIBLE_REPORT.md` | The admission blocker and the 24-core disjointness conflict. |
| `out/patrickd-B550-AORUS-ELITE-AX-V2-2026-11-06.json` | The recorded full desktop run. |

Acceptance "must" items:

- **The harness pins aegis to N CPUs, and the upstream and h2load to their own CPUs, with `taskset -c`.** The three
  sets are disjoint, and a point that cannot be disjoint is refused.
- **aegis is the default build (`--release --locked`, no features) in reverse-proxy mode with a static upstream.**
- **Per point it records:**
  - req/s (2xx), plus h2load's own all-responses figure;
  - p50 and p99 from h2load's `--log-file`;
  - errors;
  - S1..S6 admission rejects, read from aegis `/metrics`;
  - the CPU count aegis computes itself (`cpus.rs`, via `check-config --print-effective` → `p2.usable_cpus` under
    the same taskset; it matched N at every point that ran).
- **The report is written to `<record>/<host>-<date>.json`.**
- **`--gcp <machine-type>`:**
  - It is documented in the README.
  - It reads CPUS_ALL_REGIONS and the family's regional quota, and refuses (exit 3) when there is too little.
    Today's live result: `SCALING GCP: REFUSED (CPUS_ALL_REGIONS limit 12 (free 12) < 64 vCPUs for c2d-standard-64 ...)`.
  - It makes one call with no retry loop, and never creates a VM.

h2load was not on the desktop or in `~/.cache/aegis-tools`, and the desktop has no docker. It was provisioned with
`provision-h2load`, user-space only, under `~/aegis-ci/tools`.

## Acceptance run (desktop, via ci/remote.sh)

```
SCALING: 1 cores: 458 2xx req/s (32000 responses/s) p50 2.111 ms p99 14.017 ms errors 315860 (admission rejects 315406)
SCALING: 2 cores: 398 2xx req/s (32000 responses/s) p50 1.451 ms p99 5.369 ms errors 316528 (admission rejects 316004)
SCALING: FAIL (1 cores: 315860 errors (4xx 315406, 5xx 0, admission rejects 315406); 2 cores: ...; aegis admission refused load (hard-coded S1 per-IP GCRA 1000/s burst 2000, ...))
```

The self-test, which does not run because of the `&&` in acceptance.cmd, was run separately (local and remote):

```
SCALING SELF-TEST: PASS (unmutated green; 6/6 mutants red: error-at-8, 429-not-in-failed, admission-rejects-unseen-by-h2load, missing-point, no-report, gcp-quota-12)
```

## Full desktop run (`--cores 1,2,4,8,16,24`, 53 s wall)

| cores | aegis cpus | usable_cpus (cpus.rs) | 2xx req/s | all responses/s | p50 ms | p99 ms | errors | admission rejects |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0 | 1 | 465 | 32000 | 2.006 | 12.771 | 315896 | 315330 |
| 2 | 0,1 | 2 | 391 | 32000 | 1.198 | 6.15 | 316569 | 316073 |
| 4 | 0-3 | 4 | 349 | 32000 | 1.152 | 2.751 | 316981 | 316493 |
| 8 | 0-7 | 8 | 377 | 32000 | 1.103 | 3.279 | 316707 | 316215 |
| 16 | 0-15 | 16 | 348 | 32000 | 1.321 | 2.858 | 317046 | 316508 |
| 24 | - | - | - | - | - | - | - | refused: 24 + 4 h2load + 2 upstream > 24 CPUs |

Rung: advisory measurement, provisional (shared desktop, nice 15). The numbers measure the admission limiter, not
aegis scaling, so no scaling claim is made.

## Caveats

- Latencies are dominated by 429 responses: about 99% of requests were refused. They say nothing about the proxy
  path.
- h2load reported exactly 320,000 responses in every 10 s point. That looks like a client-side ceiling (refusals are
  cheap) and should be re-checked once admission admits the load.
- The admission counter delta equals h2load's 4xx count exactly, which confirms the attribution.
- The desktop's cpu numbering puts SMT siblings at i and i+12. Points up to 12 use distinct physical cores. At 16
  points the aegis set shares physical cores with the h2load and upstream sets, though never logical CPUs.

## Needs (integrator)

See INFEASIBLE_REPORT.md, "Minimal resolution":

- (a) configurable admission numbers (F8 re-freeze), or (b) a non-shipped bench feature;
- a desktop core list that fits disjointly (for example `1,2,4,8,16,18`).
