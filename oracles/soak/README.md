# soak: long steady-load resource oracle (unit P8-soak-001)

Gate `soak` (gates/phase-8.toml, `remote = "quiet"`, the GCP c2-standard-8). It closes residual R17 (PREFLIGHT §P2:
"no long soak: leaks of fds, RSS or tasks over hours are unmeasured"). Decision PREFLIGHT D-P8.4, F1 SOAK-1
("resources return to baseline after load").

```
oracles/soak/run --hours 2                    # the gate: builds target/soak/release/{aegis,aegis-otlp}, ~2.5 h
oracles/soak/run --hours 24                   # record-only: last line SOAK: RECORD (...), exit 0 once written
oracles/soak/run --self-test                  # fake subjects in scaled time (x360), ~2 min, light
oracles/soak/run --hours H --aegis BIN --otlp BIN [--aegis-cpus 4] [--client-cpus 2] [--record FILE] [--keep]
```

The last line is `SOAK: PASS (...)` or `SOAK: FAIL (...)` (exit 0 only on PASS), `SOAK SELF-TEST: PASS|FAIL (...)`,
or `SOAK: RECORD (...)` for a record-only run (`--hours` > 2). The report JSON (every sample, every h2load segment,
metric deltas, exit codes, the audit verdict) goes to `--record` or `target/soak/out/soak-<host>-<utc>.json`.
`--subject` is an alias of `--aegis`. `needs` is `own-gate`: no aggregate runs this oracle. A measuring run
re-executes itself under `ci/heavy.sh` with the timeout raised to the run length + 1 h; under `ci/remote.sh` the
remote lock already serializes it. The oracle signals only the PIDs it started.

## What runs

| piece | how |
|---|---|
| subject | `aegis` built with `--features native,proxy-protocol,mtc` into `target/soak` (its own target dir, so no other gate's `target/release/aegis` changes features) |
| listener `pub` | `P-PUBLIC-WEB`, alpn h2 + http/1.1, `proxy_protocol.trusted = ["127.0.0.2/32"]` |
| PROXY | every load connection goes h2load → in-process shim → aegis; the shim re-originates it from 127.0.0.2 with a PROXY v2 `PROXY`/TCP4 header naming the client (PROXY-1: required from a trusted source) |
| selector | `tls.credentials`: one `mtc` credential (opaque blob, trust anchor 32473.1.7) and one `x509` credential, both scoped to `pub`, so every handshake goes through the CredentialSelector (h2load sends no `trust_anchors`, so x509 is served) |
| routes | `/px/` reverse proxy to a std-only static upstream (`upstream.rs`, a copy of bench/scaling's); `/sq/` apps/notes on a SQLite backend (`engine = "sqlite"`, WAL). No crdb, no external engine |
| tokens | F5 Tier-L tokens minted per h2load segment (tenant caveat, exp = segment + 300 s); 10 notes prefilled with POSTs |
| OTLP | `aegis-otlp --scrape http://127.0.0.1:<admin>/metrics --interval-ms 5000` with aegis's stdout+stderr on its stdin, exporting to an in-process OTLP/HTTP collector that answers 200 `{}` |
| load | h2load (nghttp2 1.69.0, fetched pinned from `h2load.lock`, sha256-checked, User-Agent aegis-ci) on its own CPUs; aegis is pinned to `--aegis-cpus` (default 4) CPUs on distinct physical cores; upstream and aegis-otlp share the remaining CPUs. A host without 4 + 2 + 1 CPUs is refused unless smaller counts are passed |
| runtime | `runtime.worker_threads = <aegis CPUs>` (D-P8.3) when `aegis check-config` accepts it; otherwise the binary default, recorded in the report notes |

## Procedure

1. **Calibrate**: h2load at full speed (32 conns × 4 streams, 5 s warm-up + 30 s) over both URIs (round-robin
   `/px/soak` and `/sq/<tenant>/n3`). The target is 50% of the measured 2xx req/s. Calibration runs at saturation
   and is outside the D-P8.4 criteria: non-2xx there is load shedding, recorded in the report notes but not judged;
   transport errors, timeouts or no 2xx at all are a fault. Three 5 s diagnostic probes follow (each URI alone
   through the shim, both URIs direct without PROXY); they are recorded, never judged.
2. **Baseline**: 30 s idle, then poll every 5 s until fds and tasks of both processes are unchanged over 3 polls
   (≤ 120 s). The baseline is taken after the calibration, so the upstream pool, the SQLite handles and the
   allocator arenas are already warm. A per-load leak still accumulates over every later segment.
3. **Steady load** for `--hours`: h2load `--rps` segments, connections sized at ≤ 200 req/s each, so a segment
   (≤ 300 s) stays below half of `limits.max_streams_per_conn` = 100,000. Each segment opens fresh connections, so
   connection setup and teardown run all the time. A sampler reads `/proc/<pid>/{status,fd,task}` of aegis and
   aegis-otlp every 10 s and the admin `/metrics` every 60 s.
4. **Settle**: after the last segment, poll every 5 s for up to 180 s until both processes are within ±5 fds and
   ±5 tasks of the baseline.
5. **Stop**: SIGTERM aegis (≤ 15 s), then aegis-otlp. Both must exit 0.
6. **Audit**: `oracles/tlog-verify/run --subject "oracles/soak/audit-copy <log dir>"` runs the independent Go
   verifier (x/mod sumdb tlog/note) over the one tlog-tiles log aegis wrote, keys taken from its `vkey`.

## Pass criterion (every item)

| check | criterion |
|---|---|
| `rss.slope.<proc>` | Theil–Sen slope of VmRSS ≤ **1 MiB/h** over the samples after the warm-up, for aegis and for aegis-otlp. The warm-up is **15 min**; a run shorter than 1 h warms up for a quarter of its length. The OLS slope is reported beside it |
| `fds.<proc>`, `tasks.<proc>` | after the settle, within **±5** of the baseline |
| `errors` | **0** in total: h2load failed + errored + timeout (or non-2xx, whichever is larger), PROXY shim errors, the deltas of `aegis_admission_rejects`, `aegis_proxy_upstream_errors`, `aegis_proxy_canon_rejects`, `aegis_proxy_authz_denied` and `aegis_crash_budget_trips`, aegis log lines during the load that look like errors (`panic|error|fail|upstream |refused|denied`), collector requests to unknown paths, a non-zero exit on SIGTERM |
| `fault` | none: a process died, `/metrics` unreachable after load, an h2load segment did not run, calibration transport errors or timeouts, no 2xx in calibration |
| `load.segment` | every segment delivered ≥ 80% of the target rate (a subject that slows down cannot shrink the load it is judged under) |
| `otlp` | the collector received metrics exports in the last quarter of the load |
| `audit` | `TLOG-VERIFY: PASS` |

## Self-test (negative controls)

`run --self-test` drives the same `run_soak` and `judge` code against `fakes.py` (a fake subject with an admin
`/healthz` and `/metrics` whose leaks show in `/proc`, a fake exporter, a fake h2load that brackets each run with
`/load/start` and `/load/stop` and prints an h2load summary, and a fake audit verifier) at a time scale of ×360
(1 virtual hour = 10 s). Two clean runs must PASS. Each mutant must FAIL with its intended criterion:

| mutant | must fail with |
|---|---|
| `rss-leak`: 2 MiB per virtual hour of load, pages written and kept | `rss.slope.aegis` |
| `fd-leak`: 10 fds per load bracket never closed | `fds.aegis` |
| `task-leak`: 6 threads per load bracket never exit | `tasks.aegis` |
| `one-error`: exactly one failed request in the whole run | `errors` |
| `audit-bad`: the log does not verify | `audit` |
| `otlp-dead`: the exporter never POSTs | `otlp` |
| `exit-nonzero`: exit 1 on SIGTERM | `errors` |
| `slow-load`: every segment delivers 70% of the asked rate | `load.segment` |

Five judge controls on exact synthetic series also run: a slope of 0.9 MiB/h passes and 1.1 MiB/h fails, a
30 MiB step inside the warm-up passes, baseline +5 fds passes and +6 fails.

## Provenance

Written for this unit. No research artifact was ported or executed. `upstream.rs` is a copy of
bench/scaling/upstream.rs, the h2load pins are a copy of oracles/front-equiv/h2load.lock, and the F5 minting
follows interfaces/F5-token.cddl as oracles/native-e2e's `mint` does.

## In-repo runs

See the unit's final report and the commit log for the run lines. The rung of each run is stated there:

- `run --self-test` (laptop, 2026-11-06): `SOAK SELF-TEST: PASS (8/8 subject mutants caught ...; 2 clean controls
  pass; 5 judge controls; scale x360)`. Clean controls: aegis-fake RSS slope about +0.1 MiB/h, fds and tasks equal
  to the baseline. Caught: rss-leak at +1.93..1.99 MiB/h, fd-leak at +130..140 fds, task-leak at +78..84 tasks.

## Known limits

- **Tasks are OS threads** (`/proc/<pid>/task`). Tokio tasks are not exposed by aegis (no metric), so a leaked
  tokio task that holds no fd and little memory is visible only through RSS growth.
- **The calibrated throughput is the full path's**, PROXY shim included. The shim is stdlib Python (two threads
  per connection) and may be the bottleneck. The soak load is then 50% of what the path carries, not 50% of
  aegis's own ceiling. The report records the calibration.
- **Reads only under steady load.** The SQLite route is exercised by GETs. Mutations need an `Idempotency-Key`, and
  idempotency keys never expire before P8-hardening-001 (R12), so a steady write load would grow the key store by
  design. Writes are the 10 prefill POSTs only.
- **One host, 2 h.** A pass is a 2-hour, one-host claim, provisional for longer runs (PLAN-8 claims table). The
  24 h variant records but does not gate.
- **Error log lines** are matched by pattern (aegis logs free-form text). A real error worded otherwise is missed;
  a benign line that matches the pattern turns the gate red. Either way the lines are in the report.
- A run shorter than 1 h scales the warm-up down to a quarter of the run. The RSS slope over a few minutes is noisy,
  so a short run says less than the 2 h gate.
