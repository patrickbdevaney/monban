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
6. Stops the children by their own PIDs, then deletes the temp dir.

The report is `<record>/<host>-<YYYY-MM-DD>.json`. The verdict is computed from that file alone. **PASS** needs all
of the following:

- the report exists;
- every requested core count has a point;
- every point has 0 errors and 0 admission rejects;
- every point has at least one 2xx and req/s > 0;
- every point has `usable_cpus == N` and disjoint cpusets.

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

## Known blocker (2026-11-06)

The default build hard-codes a per-IP admission limit in `crates/aegis-bin/src/shared.rs` (`admission_config`): S1
and S3 anon are GCRA at 1000/s with a burst of 2000. h2load connects from the single source 127.0.0.1. Every
saturating point is therefore refused at S1 (429), and the gate is red at every core count. See
`INFEASIBLE_REPORT.md`.
