# P7-scaling-001: INFEASIBLE clause (gate `scaling`, PREFLIGHT D-P7.7)

## Spec clause

PREFLIGHT D-P7.7 and gates/phase-7.toml `scaling` require the following, run against the **default build** in
reverse-proxy mode:

- h2load at 1, 2, 4, 8, 16 and 24 cores on the desktop;
- `passes when every point ran with 0 errors and the report was written`;
- (unit acceptance) aegis and h2load pinned to **disjoint** cpusets.

## Failing cases

### 1. Admission refuses any saturating single-source load (all points)

`crates/aegis-bin/src/shared.rs::admission_config()` is hard-coded, with no config field or env:

- S1 (pre-auth, per IP): `Gcra::new(1_000_000, 2_000)`, which is 1000 requests/s with a burst of 2000;
- S3 anon (per IP): the same limit.

h2load has no source-address option, so every connection comes from 127.0.0.1. Any load above 1000 req/s from it is
refused at S1 with 429. Desktop, 2026-11-06, default build:

- run: `ci/remote.sh bench/scaling/run --cores 1,2,4,8,16,24 --record bench/scaling/out`;
- report: `bench/scaling/out/patrickd-B550-AORUS-ELITE-AX-V2-2026-11-06.json`;
- conditions: 32 conns × 16 streams, 10 s.

| cores | 2xx req/s | 4xx (h2load) | aegis_admission_rejects_total delta |
|---:|---:|---:|---|
| 1 | 465 | 315,330 | S1 315,330 |
| 2 | 391 | 316,073 | S1 316,073 |
| 4 | 349 | 316,493 | S1 316,493 |
| 8 | 377 | 316,215 | S1 316,215 |
| 16 | 348 | 316,508 | S1 316,508 |

h2load's 4xx count equals aegis's own S1 reject counter exactly. The 2xx rate is flat (about 350 to 465/s) whatever
the core count, so this run measures the limiter, not scaling.

There are two ways the harness could reach 0 errors, and both are refused here:

- **Drive below 1000 req/s.** This gives 0 errors but no scaling information. A "scaling" PASS from it would be a
  hollow measurement.
- **Spread load over many source addresses.** This needs hundreds of 127.x sources, through a user+net namespace
  with route tricks plus one h2load per address. That evades the limiter, and it is a custom flood setup, which the
  unit forbids.

Treating 429 as success would weaken the gate. It is not done.

### 2. The 24-core point cannot be disjoint on a 24-thread host

The desktop has 24 logical CPUs. aegis on 24 leaves 0 for h2load and the upstream, so disjoint cpusets are
impossible. The harness refuses the point and does not overlap. With the defaults (4 h2load CPUs, 2 upstream CPUs),
the largest desktop point is 18.

## Minimal resolution (needs an integrator decision; outside bench/scaling)

Either one of these resolves case 1:

- **(a)** Make the admission numbers configurable: a `limits.admission` block in F8 / aegis-config with the current
  values as defaults. The bench config then raises S1/S3 for loopback only. Admission stays on, so the run still
  pays its cost (the admission `Mutex` is on the hot path, and that is part of what scaling should show). This needs
  a re-freeze of the config schema.
- **(b)** Add a build feature that is off in every shipped profile (like `e2e-mutants`) and raises the per-IP
  numbers. This is weaker: the binary under test is then not the default build.

For case 2, change the gate's core list to `1,2,4,8,16,18` on the desktop, or decide that an overlapped 24-thread point is acceptable and
marked as such (not implemented: the harness never overlaps today). The integrator owns gates/phase-7.toml.

The harness needs no change for either: once admission admits the load, the same command records real points.
