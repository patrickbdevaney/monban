# bench/scaling: multi-core scaling harness (P7-scaling-001, PREFLIGHT D-P7.7)

Drives the default-build `aegis` (reverse-proxy mode, one `allow-all` route to a static upstream) with **h2load**
(nghttp2 1.69.0, the approved public load tool) at several core counts, and records req/s, p50/p99 and errors per
point. Gate `scaling` in `gates/phase-7.toml` is **advisory, record_only**. Every number is provisional: the desktop is
shared with the operator's other builds, and the run is niced under the ci lock.

## Usage

```
ci/remote.sh bench/scaling/run --cores 1,2,4,8,16,24 --record bench/scaling/out   # the gate command
ci/remote.sh bench/scaling/run --self-test                                        # negative controls (light)
bench/scaling/run --gcp n2-standard-64 [--region us-central1] [--zone us-central1-a] # type + quota preflight (laptop, gcloud)
```

Tuning flags: `--duration S` (default 10), `--warmup S` (default 0), `--client-cpus C` (4), `--upstream-cpus U` (2),
`--conns K` (32), `--streams M` (16), `--aegis BIN` (skip the build), `--h2load BIN`. On a host with docker but no
installed h2load (kamrui), `--h2load bench/scaling/h2load-docker` runs the pinned `aegis-h2load:1.69.0` image with the
caller's cpuset and host networking, and installs nothing.

The last line is `SCALING: PASS|FAIL (...)`, `SCALING SELF-TEST: PASS|FAIL (...)` or `SCALING GCP: REFUSED (...)`.
A measuring run re-executes itself under `ci/heavy.sh` unless it is already under it (ci/remote.sh sets
`AEGIS_HEAVY_HELD=1`). `--record` is relative to the tree the run happens in. Under ci/remote.sh that is the
desktop's copy (`~/aegis-ci/repo-<hash>/`), so copy the JSON back before the next remote.sh sync deletes it.

## What one run sets up (P8-bin-002)

- **File descriptors.** aegis's H1 upstream client holds one connection per in-flight stream (only 32 stay idle per
  key), so aegis needs about K x M + K fds. The harness raises its soft RLIMIT_NOFILE to max(K x M + K + 1024, 65536),
  capped at the hard limit, and the children inherit it. A hard limit below the need refuses the run. The report
  records `load.nofile` (before, set, hard).
- **S5.** The bench is one anonymous class, which may hold about 2/10 of `admission.concurrency` (aegis-admission
  class reservations). When K x M x 5 exceeds the default 4096, the served config sets `admission.concurrency` to
  K x M x 5 (`load.s5_concurrency`). The gate's 32 x 16 runs the unchanged default.
- **Upstream errors.** Each point records `aegis_upstream_errors`, aegis's own `aegis: upstream ...` lines by class,
  read before the temp dir is deleted. This is diagnostic only: the judge does not read it.

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
| `nofile-1024-at-256x16` | a soft fd limit of 1024 kept for 256 x 16 (run B: aegis answers 502 on EMFILE) |
| `nofile-hard-too-low` | a hard fd limit of 2048 accepted for 256 x 16 instead of refusing the run |
| `s5-share-below-offered` | S5 sized so that the anonymous class's 2/10 share is below the offered 256 x 16 streams |
| `gcp-quota-12` | `--gcp c2d-standard-56` against CPUS_ALL_REGIONS 12 must refuse |
| `gcp-no-such-type` | `--gcp c2d-standard-64` with ample quota must refuse: `machine-types describe` does not know it |
| `gcp-describe-other-type` | a describe of another type (c2d-standard-56) is not evidence that c2d-standard-64 exists |
| `gcp-guestcpus-from-describe` | the vCPU count is gcloud's `guestCpus`, not the number in the name |

It also checks that cpuset allocation refuses 24 + client on 24 CPUs, and is disjoint at 16 of 24.

## `--gcp <machine-type>` (the 64-core point; operator quota step)

`--gcp` is only a preflight. It reads `gcloud compute project-info describe`,
`gcloud compute regions describe <region>` and `gcloud compute machine-types describe <type> --zone <zone>` (zone
default `<region>-a`). It **refuses** (exit 3, `SCALING GCP: REFUSED (...)`) when:

- the machine type does not exist in that zone (P8-bin-002: `c2d-standard-64` passed the old quota-only check and
  was then rejected at create time; C2D comes in 2, 4, 8, 16, 32, 56 and 112 vCPUs);
- CPUS_ALL_REGIONS has fewer free vCPUs than the type's `guestCpus`;
- the family's regional quota, for example `C2D_CPUS` or `N2_CPUS`, has fewer free vCPUs than that.

It runs once and never retries: only the operator can raise a quota (Cloud console → IAM & Admin → Quotas;
PREFLIGHT P4.1). When the type exists and quota suffices, it prints `quota ok` and exits 4: this harness does not
create VMs.

Choosing `<type>` (quotas as read on 2026-11-07, us-central1; check again with `--gcp`):

| type | vCPUs | fits today? |
|---|---:|---|
| `c2d-standard-56` | 56 | yes (CPUS_ALL_REGIONS 80); the 2026-11-07 run below |
| `n2-standard-64` | 64 | yes: N2_CPUS 200, CPUS_ALL_REGIONS 80; the exact 64-vCPU point; the 2026-11-07 n2 run below |
| `n2d-standard-64` | 64 | no: N2D_CPUS 16 (operator raises it first) |
| `c2d-standard-64` | - | does not exist; `--gcp` refuses it |

The manual run once the preflight says `quota ok`. These steps are not automated, and they cost about an hour of VM
time:

1. Create a throwaway VM:
   `gcloud compute instances create aegis-scaling --zone us-central1-a --machine-type <type>
   --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud --max-run-duration 7200s
   --instance-termination-action DELETE`.
2. Pin its host key the way `ci/release/vm.sh` does, and add an ssh alias.
3. Run `bench/scaling/provision-h2load --to <alias>`.
4. Run `ci/remote.sh --host <alias> bench/scaling/run --cores <list> --record bench/scaling/out`, where the largest
   entry is the type's vCPUs minus `--client-cpus` and `--upstream-cpus` (defaults 4 and 2): for `n2-standard-64`
   `1,2,4,8,16,32,48,58`, for `c2d-standard-56` `1,2,4,8,16,28,32,48,50`. A larger entry is refused as not
   disjoint, never overlapped.
5. Copy the JSON back, then delete the VM and check that it is gone.

## h2load provisioning

The desktop has no docker and no h2load package. `bench/scaling/provision-h2load` builds the digest-pinned image
from `oracles/transport-limits/Dockerfile` on kamrui (which has docker). It copies `h2load` and its musl library
closure out of the image into `~/aegis-ci/tools/h2load-1.69.0` on the target. A wrapper at
`~/aegis-ci/tools/bin/h2load` runs it through the image's own musl loader. No apt, no sudo, and nothing outside
`~/aegis-ci`. It was installed on the desktop this way on 2026-11-06.

## Small hosts

kamrui (4 CPUs) fits only N + client + upstream <= 4 disjointly, so with `--client-cpus 1 --upstream-cpus 1` its
largest point is 2: it can check the harness, the worker_threads read-back and the run-B causes (above), not the
curve past the old 2-worker plateau. It has no installed h2load: use `--h2load bench/scaling/h2load-docker`. The curve (1, 2, 4, 8, 16, 18) is the desktop run, and 64 cores is the `--gcp` step below.

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
- Cause (P8-bin-002, reproduced on kamrui, 2026-11-07): **the bench config, in two parts. Neither is the bench
  upstream, and neither is an aegis defect.**
  - **The 5xx were 502s from EMFILE in aegis.** aegis's H1 upstream client opens one upstream connection per
    in-flight stream, keeping 32 idle per key. 256 x 16 = 4096 in-flight streams need about 4.4k fds. The harness
    started aegis under the login soft limit RLIMIT_NOFILE = 1024, on the VM and on kamrui alike. On kamrui, at
    2 aegis cores (client 1, upstream 1) with `--conns 256 --streams 16`, the point had 74502 5xx out of 156443.
    aegis logged 75150 `connect: Too many open files (os error 24)` lines and no other upstream error. With the soft
    limit raised to 65536 (hard 524288), the same point had 0 errors (78932 2xx). The production unit
    (deploy/aegis-hardened.service) sets `LimitNOFILE=65536`.
  - **The S5 rejects are admission by design.** The bench's requests are one anonymous class. S5 lets a class hold
    its 2/10 reservation and borrow only what the other classes do not hold in reserve, so the class holds about
    820 of the default 4096. Offered 4096 streams, the rejects at 16 cores and up are consistent with the faster
    points crossing that share (503). At 8 cores, and on kamrui at 2, too few streams reached admission at once. On kamrui the
    mechanism was shown at the same kind of ratio with `--conns 32 --streams 16` (512 offered). With
    `admission.concurrency` 1024 (share about 205), the point had 19880 S5 rejects. With 2560 (5x offered) it had 0.
  - **Fix (harness only; no threshold, judge or aegis change):** the harness raises the soft fd limit and sizes S5
    (see "What one run sets up"). At the gate's 32 x 16 shape the served config is unchanged. Run B has not been
    re-run on GCP (no GCP use in P8-bin-002). Its numbers above stay as recorded, and they are not a measure of
    aegis.
  - **aegis-side residual (not a bug fix here):** ARCHITECTURE UPS-1/UPS-4 (a per-upstream in-flight cap and an
    RLIMIT_NOFILE start-up preflight) are not implemented in aegis-bin. Under fd exhaustion aegis fails closed with
    502 per exchange and keeps serving. Refusing to start below a computed fd budget would refuse every oracle run
    under the 1024 default, so that is a design item for the integrator, not part of this unit.

**Cost:** about 10 min of c2d-standard-56 time in total, across three short-lived VMs:

- Attempt 1 (c2d-standard-64) was rejected at create time, so no VM existed.
- Attempt 2 failed because the toolchain bootstrap did not install a default toolchain.
- Attempt 3 failed because the VM had no `cc` linker for the upstream.
- Attempt 4 is the run recorded above.

At about $2.5/h on-demand, that is about $0.45, paid from the $300 credit. spend-guard reported net cost 0.0 before
each create.


## Run record: 2026-11-07, GCP n2-standard-64 (PLAN-8 64-core point; provisional)

**Provisional:** one run of 10 s per point, on a cloud VM with possible noisy neighbours. Gate `scaling` is advisory,
record_only, and its thresholds are unchanged. (The planned `c2d-standard-64` does not exist; `n2-standard-64` is the
exact 64-vCPU type that fits the quota.)

- **Machine:** throwaway VM `aegis-scaling`, `n2-standard-64`, us-central1-a. Intel Xeon @ 2.80GHz (family 6,
  model 85, stepping 7: Cascade Lake), 2 sockets x 16 cores x 2 SMT = 64 vCPUs, **2 NUMA nodes** (node0 CPUs 0-15
  and 32-47, node1 CPUs 16-31 and 48-63; CPU k and k+32 are SMT siblings), 251 GiB. Image ubuntu-2404-lts-amd64,
  kernel `7.0.0-1017-gcp`, glibc 2.39, hard RLIMIT_NOFILE 1048576.
- **Binaries:**
  - `aegis` was built on kamrui (`ci/remote.sh --host kamrui`, `cargo build --release --locked -p aegis-bin`,
    default features, tree 86eec82 on `phase8`) and shipped to the VM, sha256
    `00dddad761db81612f3a41693ef8ec119724ac7974c258718680e0513437f7ee`. Highest versioned symbol GLIBC_2.39.
  - The upstream was built on the VM by the harness, with rustc 1.99.1 (rustup into `~/aegis-ci`, default toolchain
    set at install) and Ubuntu gcc 13.3 as the linker (installed on the VM before the run).
  - h2load was installed with `bench/scaling/provision-h2load --to aegis-scaling` and reports `nghttp2/1.69.0`.
- **Host key:** pinned out of band from the VM's guest attributes (`hostkeys/`, `enable-guest-attributes=TRUE`),
  with StrictHostKeyChecking=yes, HostKeyAlias and a private known_hosts. It was never trusted on first use. The
  temporary ssh alias was removed after deletion.
- **Server-side lifetime cap:** `--max-run-duration 7200s --instance-termination-action DELETE`.
- **Deletion:** deleted with `gcloud compute instances delete` at 11:21Z; `gcloud compute instances list` showed no
  `aegis-scaling` afterwards (only the stopped `aegis-quiet`), and no orphan disk.

**Run A**, the gate shape: `--cores 1,2,4,8,16,32,48,58`, with the defaults (client 4, upstream 2, 32 conns,
16 streams, 10 s, warm-up 0; fd soft limit 65536, S5 default 4096). 58 = 64 - 4 - 2. Verdict:
`SCALING: PASS (8 points, 0 errors)`. Report: `out/n2-standard-64/aegis-scaling-2026-11-07.json`. Upstream on CPUs
58-59, h2load on 60-63 at every point (both on node1, SMT siblings of 26-31).

| cores | worker_threads | usable_cpus | 2xx req/s | p50 ms | p99 ms | errors | admission rejects |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 1 | 30992 | 9.09 | 73.01 | 0 | 0 |
| 2 | 2 | 2 | 53261 | 8.11 | 18.47 | 0 | 0 |
| 4 | 4 | 4 | 92071 | 1.09 | 16.22 | 0 | 0 |
| 8 | 8 | 8 | 165635 | 0.71 | 3.30 | 0 | 0 |
| 16 | 16 | 16 | 94752 | 1.01 | 16.16 | 0 | 0 |
| 32 | 32 | 32 | 93858 | 1.09 | 16.51 | 0 | 0 |
| 48 | 48 | 48 | 96249 | 0.92 | 16.72 | 0 | 0 |
| 58 | 58 | 58 | 96436 | 1.04 | 16.22 | 0 | 0 |

What run A shows, as provisional observations rather than conclusions:

- **Scaling up to 8 cores:** 1 to 8 cores is about 5.3x (31k to 166k/s) with worker_threads = N, the peak of the
  run. The same shape as c2d-standard-56 (peak at 8, about 123k/s there).
- **Plateau from 16 to 58 cores, at about 94-96k/s with p99 about 16 ms:** flat within 3%, but about 42% below the
  8-core peak. At 16 aegis is still on node0 physical cores only (0-15), so neither SMT sharing nor aegis spanning
  sockets explains the step from 8 to 16. 32 connections x 16 streams from 4 h2load threads is a fixed offered load;
  run B shows the client shape is part of the plateau (16 and 46 cores reach about 131k/s with 16 client CPUs), but
  8 cores stays the best point in both shapes. The cause of the drop past 8 is not isolated.

**Run B**, supplementary, to take the client limit away: `--cores 8,16,32,46 --client-cpus 16 --conns 256`
(46 = 64 - 16 - 2; fd soft limit 65536, S5 sized to 20480). Upstream on CPUs 46-47, h2load on 48-63. Verdict:
**FAIL**. Report: `out/n2-standard-64/client16-conns256/aegis-scaling-2026-11-07.json`.

| cores | 2xx req/s | all responses/s | p50 ms | p99 ms | errors (all 5xx) | admission rejects | aegis upstream errors |
|---:|---:|---:|---:|---:|---:|---:|---|
| 8 | 160331 | 160972 | 1.03 | 18.93 | 0 | 0 | none |
| 16 | 131001 | 131702 | 0.65 | 32.49 | 458 | 0 | 458 `connect: timeout` |
| 32 | 27729 | 85131 | 25.32 | 102.68 | 572640 | 0 | 572419 `connect: Connection refused`, 2046 `Connection reset by peer`, 3 `upstream closed` |
| 46 | 132518 | 133242 | 0.58 | 33.45 | 621 | 0 | 621 `connect: timeout` |

The P8-bin-002 harness fixes held: no EMFILE and no S5 rejects at any point. Cause of the 5xx (diagnosed on the VM
before deletion): **the bench upstream (`upstream.rs`), not aegis.** Every 5xx is a 502 for an upstream error that
aegis logged per exchange; aegis kept serving throughout.

- **32 cores: the bench upstream crashed.** The kernel log has
  `scaling-upstrea[752698]: segfault at 76de89dee9c8 ... error 4 likely on CPU 46` (an upstream CPU) during that
  point. The faulting code bytes match exactly one place in the VM's libc.so.6, `pthread_detach` + 0x20, reached from
  the upstream's main (accept) thread (sp in the main stack): `std::thread::spawn`'s JoinHandle is dropped at once,
  which detaches the just-spawned per-connection thread. The read faults on that thread's descriptor, in an unmapped
  page. This is consistent with a detach racing the exit of a very short-lived thread whose stack was already
  released (aegis keeps only 32 idle upstream connections per key, so 256 x 16 churns thousands of upstream
  connections and threads per second). After the crash nothing listened, hence 572k `Connection refused` and the
  resets on connections open at the time. A re-run of the 32-core point (same flags, core dumps on) did not crash:
  131592 2xx/s with 398 `connect: timeout`, so the crash is intermittent. No core was captured.
- **16, 46 (and the 32 re-run): listen-queue overflow at the upstream.** The kernel logged
  `Possible SYN flooding on port 127.0.0.1:<port>. Sending cookies.` once per point. aegis's upstream connect
  timeout is 5 s (`CONNECT_TIMEOUT`, crates/aegis-bin/src/upstream.rs), so a SYN dropped twice by a full accept queue
  (one accepting thread on 2 CPUs shared with thousands of serving threads) times out: 458-621 of about 1.3M
  exchanges (0.04%).
- **Not changed here:** no threshold, judge, aegis or upstream change. A sturdier bench upstream (a bounded thread
  pool or explicit detach handling, a larger backlog, more upstream CPUs) is a harness follow-up. As on c2d, run B is
  not a measure of aegis; it does show aegis answering 502 per exchange and staying up when its upstream dies.

**Cost:** one VM, created 11:09:59Z and deleted 11:21:05Z, about 11 min of n2-standard-64 time. At about $3.1/h
on-demand that is about $0.58, paid from the $300 credit. spend-guard reported net cost 0.0 before the create.
