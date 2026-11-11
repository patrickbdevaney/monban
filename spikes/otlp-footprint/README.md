# otlp-footprint: in-process OTLP vs R-PERF-1

**Verdict: flip.** Move OTLP out of process. Built into the core, it pushes the crate count to 62–81, over the
≤60 budget, and takes size and idle RSS to the edge of their budgets. The hand-written OpenMetrics endpoint costs
+49 KB and 0 crates, so "metrics always compiled" (ARCHITECTURE §3.10) holds. See `verdict.json` for the exact
decision text.

## Method
`hello/` is a representative Monban "hello" server: tokio (multi-thread, 1 worker), hyper 1.12 (h1 + h2 via
hyper-util auto), and tokio-rustls / rustls 0.23.46 / aws-lc-rs 1.18.2 with prefer-post-quantum. It serves TLS 1.3
on loopback. It is built with the release profile from the root `Cargo.toml` (fat LTO, cgu=1, panic=abort,
strip=symbols). Features add one layer at a time:

| variant | adds |
|---|---|
| base | – |
| metrics | hand-written OpenMetrics 1.0 text on a separate loopback admin listener (atomics, `# EOF`) |
| metrics,logs | tracing + tracing-subscriber JSON logs (the logging baseline that OTLP would attach to) |
| metrics,logs,otlp | opentelemetry 0.33.1 SDK + opentelemetry-otlp http-proto + hyper-client (no tonic), tracing-opentelemetry 0.34 layer, traces (batch) + metrics (periodic reader) on the tokio runtime |
| metrics,logs,otlp-grpc | same but grpc-tonic (comparison only) |

Crate counts (`crates.py`):
- `metadata`: reachable from the root via normal edges in `cargo metadata`, as the task asked.
- `tree`: `cargo tree -e normal`.
- `shipped`: `cargo tree -e normal,no-proc-macro`, i.e. code that can end up in the binary.

`cargo metadata` over-counts by 2–3. Its resolve treats weak `dep?/feat` features as activating the dep, so
rustls-webpki's `ring?/alloc` adds ring and getrandom 0.2, which are never built.

`measure.sh` measures:
- stripped size;
- VmRSS 2 s after startup;
- VmRSS 3 s after 200 TLS requests (100 HTTP/1.1 and 100 h2, each on a new connection);
- OTLP export against `collector.py`, a dummy OTLP/HTTP sink. Traces and metrics POSTs arrived as
  `application/x-protobuf`.

There were 3 runs. Medians are reported below.

## Results (laptop i9-14900HX, grade B)

| variant | stripped B | Δ vs prev | shipped / tree / metadata crates | RSS start KB | RSS after 200 req KB |
|---|---|---|---|---|---|
| base | 4,124,888 | – | 41 / 46 / 49 | 4,212 | 5,376 |
| +metrics | 4,173,888 | +49,000 | 41 / 46 / 49 | 4,428 | 5,284 |
| +logs | 4,706,728 | +532,840 | 52 / 57 / 59 | 4,736 | 5,760 |
| +otlp (http) | 5,851,224 | +1,144,496 | 74 / 87 / 89 | 5,540 | 7,508 |
| +otlp-grpc | 5,870,280 | +19,056 vs http | 83 / 98 / 100 | 5,884 | 7,900 |

Raw data: `results/measure-run{1,2,3}.jsonl` and `results/crates-*.json` (full package lists).

**OTLP delta:**
- If tracing is already in the core: +1.14 MB, +22 shipped / +30 tree crates, +0.8 MB RSS idle and +1.75 MB after
  load.
- If tracing is not in the core: +1.68 MB, +33 / +41 crates, +2.2 MB RSS after load.
- Proxy count of lines containing `unsafe` in the added crates: about +1,009 (grade D).

The OTLP crates are opentelemetry ×5, tracing-opentelemetry, prost (+ derive), futures-util/-executor/-task,
rand 0.9 + chacha + ppv-lite86 + zerocopy, getrandom 0.3, thiserror 2, anyhow, itertools, either, tokio-stream,
tower-service, want, try-lock, percent-encoding, async-trait, and syn 2. syn 2 is a second syn version.

**Against R-PERF-1**, using the core baseline 4.21 MB / 40 crates / 3,325 unsafe lines / 3.4–5.9 MB RSS:

| budget | core + in-process OTLP | result |
|---|---|---|
| stripped ≤ 6.0 MB | 5.36–5.89 MB | uses 64–94% of the headroom |
| crates ≤ 60 | 62–81 | **busts** |
| idle RSS ≤ 8 MB | 7.7–8.1 MB at the top of the core range | at or over the limit |
| non-crypto unsafe ≤ 5,000 lines | about 4,334 | uses about 60% of the headroom |

As an off-by-default feature, OTLP would leave the *default* build's numbers alone. But its 30 packages would
still enter `Cargo.lock`, so every profile would carry them through vet, cooldown, deny and advisories. And an
operator who turns the feature on gets a binary that breaks the lean-core budgets.

**gRPC vs http:** almost the same size (+19 KB) but +9 crates. Use http/protobuf if OTLP is ever built in process.

## Out-of-process exporter (estimate, grade E, not built)
- **Core side:** span and metric records travel over the existing IPC as postcard frames, through a bounded ring
  that drops with a counter and never blocks. Estimated cost: about +20–60 KB, 0 new crates (assuming postcard
  and serde are already in the core), and about +0.3 MB RSS for a 256 KiB ring. Each batch costs one IPC hop
  (4.8–8.1 µs).
- **Metrics:** need no exporter. An OpenTelemetry Collector's Prometheus receiver scrapes the always-on
  OpenMetrics admin endpoint.
- **`monban-otel-export`:** about the measured otlp variant minus the TLS server: about 5–6 MB, about 7.5 MB RSS,
  70–90 crates. It is vetted as its own artifact, runs unprivileged, and is the only process with egress to the
  collector.
- **cmvp:** HTTPS to a collector means a rustls client (hyper-rustls). Out of process, that client stays out of
  the core, so P-PQ6 mode "compiled-out" stays possible for the cmvp core (see `../cmvp-client-policy`).

## Reproduce
```
cd /home/patrickd/aegis/spikes/otlp-footprint
python3 -I lockage.py hello/Cargo.lock --today 2026-10-25         # 139 packages, 0 violations
HEAVY_TIMEOUT=3600 ../../ci/heavy.sh ./build.sh > results/build.log 2>&1
for f in '' metrics metrics,logs metrics,logs,otlp metrics,logs,otlp-grpc; do n=${f:-base}; python3 -I crates.py hello "$f" > results/crates-${n//,/+}.json; done
for i in 1 2 3; do ./measure.sh > results/measure-run$i.jsonl 2> results/measure-run$i.stderr; done
rm -rf target bins
```

## Limits
- A hello server is not the Monban core. The deltas are added to the w02 core baseline, and the w02 crate-count
  method is not recorded.
- The collector was reached over plain HTTP. HTTPS would add hyper-rustls and a rustls client, so the in-process
  numbers are a lower bound. The OTLP logs signal was not exercised.
- tokio 1.53.3 and webpki 0.103.15 stand in for the floors 1.54.1 and 0.103.16, which are under 7 days old.
- RSS was measured on loopback with 1 worker. Spread between runs is about 0.3–0.5 MB. 1k-idle-TLS RSS was not
  measured.
- Run 1 (`results/run1-unfiltered/`) had no level filter on the OTLP subscriber. The exporter's own hyper-client
  TRACE events were exported back through the pipeline (feedback loop; grpc reached 10.9 MB RSS). The reported
  runs use `LevelFilter::INFO`. Any in-process OTLP must keep that filter.
- Unsafe is a token-count proxy, not cargo-geiger.
- The laptop result is capped at grade B.
