# bench/scaling: multi-core scaling harness (P7-scaling-001, PREFLIGHT D-P7.7)

Drives the default-build `aegis` (reverse-proxy mode, one `allow-all` route to a static upstream) with **h2load**
(nghttp2 1.69.0, the approved public load tool) at several core counts, and records req/s, p50/p99 and errors per
point. Gate `scaling` in `gates/phase-7.toml` is **advisory, record_only**. Every number is provisional: the desktop is
shared with the operator's other builds, and the run is niced under the ci lock.

## Usage

```
ci/remote.sh bench/scaling/run --cores 1,2,4,8,16,24 --record bench/scaling/out   # the gate command
ci/remote.sh bench/scaling/run --self-test                                        # negative controls (light)
bench/scaling/run --gcp c2d-standard-64 [--region us-central1]                     # quota preflight (laptop, gcloud)
```

Tuning flags: `--duration S` (default 10), `--warmup S` (default 0), `--client-cpus C` (4), `--upstream-cpus U` (2),
`--conns K` (32), `--streams M` (16), `--aegis BIN` (skip the build), `--h2load BIN`.

The last line is `SCALING: PASS|FAIL (...)`, `SCALING SELF-TEST: PASS|FAIL (...)` or `SCALING GCP: REFUSED (...)`.
A measuring run re-executes itself under `ci/heavy.sh` unless it is already under it (ci/remote.sh sets
`AEGIS_HEAVY_HELD=1`). `--record` is relative to the tree the run happens in. Under ci/remote.sh that is the
desktop's copy (`~/aegis-ci/repo-<hash>/`), so copy the JSON back before the next remote.sh sync deletes it.

## What one point does

1. Builds `aegis` with default features (`cargo build --release --locked -p aegis-bin`) and `upstream.rs` with
   plain `rustc -O` (std only, one thread per connection, keep-alive, a fixed 200), both through `ci/heavy.sh`.
2. Orders the usable CPUs so the first k sit on k distinct physical cores, with SMT siblings last. aegis gets the
   first N, h2load the last C, and the upstream the U before those. The three sets are **disjoint**, each applied
   with `taskset -c`. A point that does not fit (N + C + U > CPUs) is refused and reported, never overlapped. On the
   24-thread desktop the largest point is therefore 18, so `24` is refused there.
3. Reads the CPU count aegis itself computes (`crates/aegis-bin/src/cpus.rs`), via
   `taskset -c <aegis set> aegis check-config <probe> --print-effective` → `p2.usable_cpus`. The probe is the served
   config plus a placeholder `p2` block, because the dump prints `usable_cpus` only inside one. check-config does not
   open the module. The point is red unless that count equals N.
4. Mints a throwaway ECDSA P-256 certificate for `localhost` and starts the upstream and aegis on fresh loopback
   ports. Once `/healthz` answers, it runs
   `h2load -t C -c K -m M -D duration --log-file ... https://localhost:<port>/` (TLS 1.3, h2, P-PUBLIC-WEB).
5. Records per point:
   - `req_s`: 2xx responses per second. `h2load_req_s` is h2load's own figure, which counts refusals too.
   - `p50_ms` and `p99_ms`, from the per-request log.
   - h2load's raw summary lines.
   - `errors` = max(failed + errored + timeout, non-2xx). h2load already counts a non-2xx stream as failed.
   - the delta of aegis's `aegis_admission_rejects_total` per stage, scraped from `/metrics`.
   - the cpusets and `usable_cpus`.
   - `worker_threads`: the effective F8 `runtime.worker_threads` read back from the same `--print-effective` dump
     (printed only when it is not the default 2). The served config sets it to N (Phase 8, D-P8.3, R5), so the
     curve measures core scaling; before Phase 8 aegis-bin hard-coded 2 tokio workers and req/s plateaued at about
     31-42k from 2 cores up.
6. Stops the children by their own PIDs, then deletes the temp dir.

The report is `<record>/<host>-<YYYY-MM-DD>.json`. The verdict is computed from that file alone. **PASS** needs all
of the following:

- the report exists;
- every requested core count has a point;
- every point has 0 errors and 0 admission rejects;
- every point has at least one 2xx and req/s > 0;
- every point has `usable_cpus == N`, `worker_threads == N` and disjoint cpusets.

## Self-test (negative controls)

The self-test feeds a fake h2load (canned summary and per-request log) through the real invocation and parser, then
builds reports and judges them. The unmutated report must PASS. Each of these must go red:

| mutant | red because |
|---|---|
| `error-at-8` | h2load reports 1 failed request at 8 cores |
| `429-not-in-failed` | a 4xx in the status line that is not in `failed` |
| `admission-rejects-unseen-by-h2load` | aegis counted admission rejects that h2load did not see (for example, during a warm-up) |
| `missing-point` | the 4-core point is absent |
| `no-report` | the report file was never written |
| `workers-fixed-2` | every point ran 2 tokio workers whatever N (the pre-Phase-8 plateau; `runtime.worker_threads` not applied) |
| `gcp-quota-12` | `--gcp c2d-standard-64` against CPUS_ALL_REGIONS 12 must refuse |

It also checks that cpuset allocation refuses 24 + client on 24 CPUs, and is disjoint at 16 of 24.

## `--gcp <machine-type>` (the 64-core point; operator quota step)

`--gcp` is only a preflight. It reads `gcloud compute project-info describe` and
`gcloud compute regions describe <region>`. It **refuses** (exit 3, `SCALING GCP: REFUSED (...)`) when either of
these has fewer free vCPUs than the machine type needs:

- CPUS_ALL_REGIONS;
- the family's regional quota, for example `C2D_CPUS`.

It runs once and never retries: only the operator can raise a quota (Cloud console → IAM & Admin → Quotas;
PREFLIGHT P4.1). On 2026-11-06 CPUS_ALL_REGIONS is 12, so `c2d-standard-64` is refused. When quota suffices, it
prints `quota ok` and exits 4: this unit does not create VMs.

The manual run once quota exists. These steps are not automated, and they cost about an hour of c2d-standard-64
time:

1. Create a throwaway VM:
   `gcloud compute instances create aegis-scaling --zone us-central1-a --machine-type c2d-standard-64
   --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud`.
   **Correction (2026-11-07):** `c2d-standard-64` does not exist (C2D comes in 2, 4, 8, 16, 32, 56 and 112 vCPUs), and
   the `--gcp` preflight checks quota only, not that the type exists. The run below used `c2d-standard-56`, the largest
   C2D that fits CPUS_ALL_REGIONS 80. An exact 64-vCPU point needs another family (for example n2-standard-64: N2
   quota 200 in us-central1; n2d-standard-64 needs N2D_CPUS raised from 16).
2. Pin its host key the way `ci/release/vm.sh` does, and add an ssh alias.
3. Run `bench/scaling/provision-h2load --to <alias>`.
4. Run `ci/remote.sh --host <alias> bench/scaling/run --cores 1,2,4,8,16,32,48,56 --record bench/scaling/out`.
   That is 64 vCPUs minus the client and upstream CPUs.
5. Copy the JSON back, then delete the VM and check that it is gone.

## h2load provisioning

The desktop has no docker and no h2load package. `bench/scaling/provision-h2load` builds the digest-pinned image
from `oracles/transport-limits/Dockerfile` on kamrui (which has docker). It copies `h2load` and its musl library
closure out of the image into `~/aegis-ci/tools/h2load-1.69.0` on the target. A wrapper at
`~/aegis-ci/tools/bin/h2load` runs it through the image's own musl loader. No apt, no sudo, and nothing outside
`~/aegis-ci`. It was installed on the desktop this way on 2026-11-06.

## Small hosts

kamrui (4 CPUs) fits only N + client + upstream <= 4 disjointly, so with `--client-cpus 1 --upstream-cpus 1` its
largest point is 2: it can check the harness and the worker_threads read-back, not the curve past the old 2-worker
plateau. The curve (1, 2, 4, 8, 16, 18) is the desktop run, and 64 cores is the `--gcp` step below.

## Known blocker (2026-11-06, resolved)

The default build hard-codes a per-IP admission limit in `crates/aegis-bin/src/shared.rs` (`admission_config`): S1
and S3 anon are GCRA at 1000/s with a burst of 2000. h2load connects from the single source 127.0.0.1. Every
saturating point is therefore refused at S1 (429), and the gate is red at every core count. See
`INFEASIBLE_REPORT.md`.

## Run record: 2026-11-07, GCP c2d-standard-56 (PLAN-7 D-P7.7 large-VM point; provisional)

**Provisional:** one run of 10 s per point, on a cloud VM with possible noisy neighbours. Gate `scaling` is advisory,
record_only, and its thresholds are unchanged.

- **Machine:** throwaway VM `aegis-scaling`, `c2d-standard-56`, us-central1-a. AMD EPYC 7B13 (Milan), 1 socket,
  28 cores x 2 SMT = 56 vCPUs, 1 NUMA node, 220 GiB. Image ubuntu-2404-lts-amd64, kernel `7.0.0-1017-gcp`,
  glibc 2.39.
- **Binaries:**
  - `aegis` was built on kamrui (`ci/remote.sh --host kamrui`, `cargo build --release --locked -p aegis-bin`,
    default features, tree f1a9ee9) and shipped to the VM, sha256 `68eddeb5...be68c06`. Its highest versioned
    symbol is GLIBC_2.39, so it runs on ubuntu-2404 even though kamrui has glibc 2.42.
  - The upstream was built on the VM by the harness, using rustc 1.99.1 (rustup, pinned channel) and Ubuntu gcc as
    the linker.
  - h2load was installed with `bench/scaling/provision-h2load --to aegis-scaling` and reports `nghttp2/1.69.0`.
- **Host key:** pinned out of band from the VM's guest attributes (`hostkeys/`), with StrictHostKeyChecking=yes and
  a private known_hosts. It was never trusted on first use.
- **Server-side lifetime cap:** `--max-run-duration 7200s --instance-termination-action DELETE`.
- **Deletion:** every attempt was deleted, and `gcloud compute instances list` showed no `aegis-scaling` afterwards.

**Run A**, the gate shape: `--cores 1,2,4,8,16,28,32,48,50`, with the defaults (client 4, upstream 2, 32 conns,
16 streams, 10 s, warm-up 0). 50 = 56 - 4 - 2. Verdict: `SCALING: PASS (9 points, 0 errors)`. Report:
`out/aegis-scaling-2026-11-07.json`.

| cores | worker_threads | usable_cpus | 2xx req/s | p50 ms | p99 ms | errors | admission rejects |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 1 | 26738 | 11.04 | 76.92 | 0 | 0 |
| 2 | 2 | 2 | 48981 | 4.96 | 21.53 | 0 | 0 |
| 4 | 4 | 4 | 68059 | 0.89 | 25.94 | 0 | 0 |
| 8 | 8 | 8 | 123200 | 1.12 | 3.70 | 0 | 0 |
| 16 | 16 | 16 | 120495 | 0.84 | 3.77 | 0 | 0 |
| 28 | 28 | 28 | 118250 | 0.76 | 4.06 | 0 | 0 |
| 32 | 32 | 32 | 68714 | 0.79 | 27.12 | 0 | 0 |
| 48 | 48 | 48 | 70144 | 0.81 | 27.13 | 0 | 0 |
| 50 | 50 | 50 | 69566 | 0.83 | 27.31 | 0 | 0 |

What run A shows, as provisional observations rather than conclusions:

- **Scaling up to 8 cores:** throughput scales from 1 to 8 cores (about 4.6x) with worker_threads = N. That is past
  the pre-Phase-8 plateau of 2 workers.
- **Plateau from 8 to 28 cores, at about 120k/s:** this is consistent with the load generator being the limit, not
  aegis. h2load has 4 threads, and 32 connections cap the number of busy workers at 32.
- **Drop at 32 cores and above, to about 69k/s with p99 around 27 ms:**
  - CPUs 0-27 are distinct physical cores. CPUs 28-55 are their SMT siblings.
  - From 32 cores up, some aegis workers share physical cores with other aegis workers.
  - At every point, h2load (CPUs 52-55) and the upstream (CPUs 50-51) are SMT siblings of aegis CPUs 22-27. They are
    disjoint as logical CPUs but not as physical cores.
  - The cause of the drop is not isolated.

**Run B**, supplementary, to take the client limit away: `--cores 8,16,28,38 --client-cpus 16 --conns 256`.
Verdict: **FAIL**. Report: `out/client16-conns256/aegis-scaling-2026-11-07.json`.

- At every point, about 535-549k of about 1.0-1.16M responses in 10 s were **5xx**. 2xx throughput was 39-62k/s, and
  p50 was 31-39 ms.
- aegis counted admission rejects at stage S5 at 16, 28 and 38 cores (2864, 1033 and 308). It counted none at 8.
- Likely cause, not verified: the 2-CPU, thread-per-connection upstream, or an aegis upstream or S5 limit, is
  saturated by 256 x 16 concurrent streams.
- This is a finding for the integrator. It is not a harness or threshold change: at the gate's load shape (run A)
  there are 0 errors.

**Cost:** about 10 min of c2d-standard-56 time in total, across three short-lived VMs:

- Attempt 1 (c2d-standard-64) was rejected at create time, so no VM existed.
- Attempt 2 failed because the toolchain bootstrap did not install a default toolchain.
- Attempt 3 failed because the VM had no `cc` linker for the upstream.
- Attempt 4 is the run recorded above.

At about $2.5/h on-demand, that is about $0.45, paid from the $300 credit. spend-guard reported net cost 0.0 before
each create.

