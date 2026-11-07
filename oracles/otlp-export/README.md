# otlp-export: aegis-otlp vs a mapping-checking OTLP/HTTP JSON collector

Unit P7-oracle-otlp-001. Gate `otlp-export` (gates/phase-7.toml, laptop). Implementer unit: P7-otlp-001.
Decision: PREFLIGHT D-P7.6. OTLP stays out of process (spikes/otlp-footprint, verdict flip). `aegis-otlp` is a
separate binary with no OpenTelemetry crates. It scrapes the admin listener's OpenMetrics text, reads aegis log
lines on stdin, and POSTs OTLP/HTTP JSON to `/v1/metrics` and `/v1/logs`.

```
oracles/otlp-export/run                                      # reference exporter (ref_exporter.py): PASS
oracles/otlp-export/run --exporter target/release/aegis-otlp # the gate: the real binary
oracles/otlp-export/run --self-test                          # reference PASS, 23 mutants + stub + absent FAIL
```
`--subject` is accepted as an alias of `--exporter` (oracles/README.md contract). With no flag the oracle judges
the reference, so the aggregate `oracles` gate (which runs every oracle without `needs`) stays green before
P7-otlp-001. The `otlp-export` gate always passes `--exporter`, so it is red until the binary exists and conforms.
There is no `default-subject` file yet. When P7-otlp-001 lands, the integrator can add one
(`target/release/aegis-otlp`) once `build-subjects` builds `-p aegis-otlp`.

## Exporter CLI contract (what P7-otlp-001 must provide)

```
aegis-otlp --scrape <TARGET> --endpoint <URL> --service-name <S> [--interval-ms <N>] [--resource-attr k=v]... [--once]
```

| flag | meaning |
|---|---|
| `--scrape http://HOST:PORT/PATH` | GET this URL over HTTP/1.1 on loopback TCP (the oracle passes `http://127.0.0.1:P/metrics`). |
| `--scrape unix:/ABS/PATH.sock` | GET `/metrics` over this unix stream socket (the admin listener's UDS form). |
| `--endpoint URL` | OTLP/HTTP **base** URL. Strip trailing `/`, then append `/v1/metrics` and `/v1/logs`. A path prefix is kept, so `http://h:p/collector/` gives `/collector/v1/metrics`. `https://` goes through the aegis-tls client profile (P8: exercised, see "https, retry and drop-and-count"). |
| `--ca-file PEM` | Required for `https://`: the only trust roots (no platform store). The oracle passes it. |
| `--service-name S` | Required. Every Resource carries the attribute `service.name` = S (`stringValue`). |
| `--interval-ms N` | Scrape and export period in interval mode. Default 10000. |
| `--resource-attr k=v` | Optional extra string resource attributes, repeatable. The oracle does not use it. |
| `--once` | Read stdin to EOF, do **exactly one** scrape, POST, then exit. Exit 0 only if the scrape parsed and every POST got a 2xx. Otherwise exit nonzero, and log lines are still exported. |

Interval mode (no `--once`):
- The exporter scrapes every N ms and exports.
- It streams stdin lines as they arrive. A line must be POSTed within `min(N, 1000) ms` plus transport time; the
  oracle allows 3 s at N=250 **with stdin still open**.
- At stdin EOF it keeps scraping.
- On SIGTERM it flushes queued logs and exits 0 within 5 s.

The exporter may split a signal across several requests, and may send requests with zero records. Each request:
- `POST`, `Content-Type: application/json` (optionally with `; charset=utf-8`);
- body: one `ExportMetricsServiceRequest` / `ExportLogsServiceRequest` in OTLP JSON;
- optionally `Content-Encoding: gzip`.

The oracle's collector answers `200`, `Content-Type: application/json`, `{}`, except in the failure cases below.

### https, retry and drop-and-count (P8-oracle-001, PREFLIGHT R9; implementer P8-otlp-001)

- **https.** `--endpoint https://127.0.0.1:P --ca-file ca.pem`: TLS 1.3 to a collector whose P-256 leaf
  (SAN `IP:127.0.0.1`, `DNS:localhost`, EKU serverAuth, CA:FALSE) is signed by a throwaway CA in `ca.pem`. The
  delivered requests must map exactly as over http. A chain that does not lead to `--ca-file` must get nothing
  delivered and a nonzero `--once` exit.
- **Retryable** (OTLP/HTTP specification, "Failures"): 429, 502, 503, 504 and transport failures. Each failed attempt
  is retried with backoff: every retry at least **100 ms** after the previous attempt, each gap at least **0.8 ×** the
  previous gap (it never shrinks beyond jitter), at least **2** and at most **8** attempts per request, all within
  **30 s**. A retry resends the same payload; it never re-scrapes (`--once` still scrapes exactly once). Nothing is
  sent for a request after one attempt was accepted.
- **Not retryable:** any other 4xx (the oracle uses 400): exactly one attempt.
- **Drop and count.** A request whose attempts are exhausted (or that got a non-retryable answer) is dropped; its log
  records are added to `aegis_otlp_dropped_log_records` and its metric points to `aegis_otlp_dropped_metric_points`
  (monotonic cumulative sums, exported as self-metrics). `--once` exits nonzero if anything was dropped.
- **No stall.** In interval mode a failing signal never stops the other: with `/v1/logs` failing, metrics exports keep
  being accepted at the interval. SIGTERM still exits 0 within 5 s (at most one more attempt per queued request).

## Mapping rules the oracle enforces

**Encoding.** These follow opentelemetry-proto docs/specification.md "JSON Protobuf Encoding" (excerpt in
`proto-excerpts.txt`) and the .proto field names.
- Keys are lowerCamelCase. A snake_case spelling of a known field is a FAIL. Unknown keys are ignored, as receivers
  MUST ignore them.
- Enums are integers only. `"AGGREGATION_TEMPORALITY_CUMULATIVE"` is a FAIL.
- 64-bit integers (`timeUnixNano`, `startTimeUnixNano`, `asInt`, `count`, `bucketCounts`, `intValue`) are decimal
  strings or JSON numbers.
- `traceId`/`spanId` are hex: 32 and 16 chars, case-insensitive. base64 is a FAIL.
- Each `Metric` has exactly one data oneof, and each `NumberDataPoint` has exactly one of `asInt`/`asDouble`.
- Every Resource has `service.name`. Every scope has a non-empty `InstrumentationScope.name`.

**Metrics.** OpenMetrics 1.0 → OTLP.

| OpenMetrics | OTLP |
|---|---|
| `# TYPE x counter`, samples `x_total` | Metric `name: "x"` (no `_total`), `sum` with `aggregationTemporality: 2` (CUMULATIVE) and `isMonotonic: true` |
| `x_created{…} T` (counter or histogram) | `startTimeUnixNano` = T·10⁹ (±1 µs) |
| no `_created` | `startTimeUnixNano` = a fixed time ≤ the first export (e.g. exporter start), the **same** for every export of the series, and ≤ `timeUnixNano` |
| `# TYPE x gauge` | `gauge` |
| `# TYPE x histogram`: `x_bucket{le}`, `x_count`, `x_sum` | `histogram` with CUMULATIVE temporality. `explicitBounds` = finite `le` values ascending. `bucketCounts` = **per-bucket** (de-cumulated) counts, length = bounds+1. `count`, `sum`. The `le` label is dropped from the attributes. |
| `# HELP` (unescaped `\\ \" \n`) | `description` |
| `# UNIT u` | `unit: "u"` verbatim. Absent or empty when there is no UNIT. |
| labels (unescaped) | `attributes`, exactly the label set, each a `stringValue` |
| value token `-?[0-9]+` within i64 | `asInt` exact (2⁵³+1 must survive, so no f64 round trip) |
| any other value token | `asDouble` |
| one scrape | each series exactly once. `timeUnixNano` lies within the run window. |

- The exporter must not invent metrics, except its own self-metrics named `aegis_otlp_*` (e.g. a drop counter).
- An exposition without the terminating `# EOF` is rejected whole. No points are exported from it, and `--once`
  exits nonzero.

**Log line mapping.** aegis today writes plain text to stderr (`aegis[PID]: msg`, `aegis: …`; see
`fixtures/aegis-stderr.log`). ARCHITECTURE §3.10 promises structured JSON logs. The exporter accepts both, one
record per non-empty line:

| input line | LogRecord |
|---|---|
| a JSON object | `timeUnixNano` = `ts` (RFC 3339, `Z` or `±hh:mm`, up to 9 fractional digits, exact ns). If `ts` is missing or invalid, it is unset. |
| | `severityText` = `level` exactly as given. `severityNumber` from `level`, case-insensitive: TRACE 1, DEBUG 5, INFO 9, WARN 13, ERROR 17, FATAL 21. Any other level gives 0 (unset). |
| | `body` = `msg` as an AnyValue |
| | `trace_id` (32 hex) → `traceId` and `span_id` (16 hex) → `spanId`, as hex |
| | every other key → `attributes`: string→`stringValue`, integer→`intValue`, float→`doubleValue`, bool→`boolValue`, array→`arrayValue`, object→`kvlistValue`; `null` keys omitted |
| anything else (plain text, non-object JSON, broken JSON) | `body.stringValue` = the line without its newline; no severity, no timeUnixNano, no attributes |
| every record | `observedTimeUnixNano` set (within the run window) |
| a line > 65536 bytes | dropped, or exported as plain text truncated to ≤ 65536 bytes. The lines after it still flow. |

Records arrive in input order.

## Cases

| case | scrape | stdin | asserts |
|---|---|---|---|
| once-tcp-real | TCP, `fixtures/aegis-metrics.txt` | `aegis-stderr.log` + `json-logs.jsonl` | every series of the 15 real families (26 points) mapped, spot values (debits{ip}=4, cert{serving}=2592000 gauge, config hash 14283538101851 exact, proxy_requests sum 4); 17 log records incl. all six levels, lowercase, unknown, missing ts, non-object, broken JSON, hex trace ids, typed/nested attributes |
| once-unix-synthetic | UDS, `fixtures/synthetic-metrics.txt` | 100 KiB line + one JSON line | histogram buckets/bounds/count/sum/`_created`/unit, label and HELP unescaping, 2⁵³+1 exact, float and negative gauges; oversize line bounded |
| once-truncated | TCP, real fixture minus `# EOF` | one JSON line | nonzero exit, no points, logs still exported |
| daemon | TCP, real fixture with a counter that moves per scrape | two lines written while running | ≥3 exports in ~5 s at 250 ms; exported values are scraped values, non-decreasing; `timeUnixNano` strictly increasing; `startTimeUnixNano` fixed; logs streamed ≤3 s; SIGTERM → exit 0 ≤5 s; endpoint prefix `/collector/` honoured |
| https-once | TLS collector, `--ca-file` = its CA | real fixture + 2 lines | exit 0; delivered over TLS; wire+schema, all series, logs mapped |
| https-untrusted | TLS collector, `--ca-file` = an unrelated CA | same | nonzero exit; nothing delivered |
| retry-recover | 503, 503, then 200 on each path | same | exit 0; scraped once; statuses per path exactly 503, 503, 200; backoff; accepted payloads map exactly once |
| retry-exhaust | 503 always | same | nonzero exit; 2..8 attempts per path; backoff; one payload per path |
| no-retry-400 | 400 always | same | nonzero exit; exactly one attempt per path |
| daemon-drop | `/v1/logs` 503 always, metrics 200, 250 ms interval | 3 JSON lines | keeps running; >= 3 metrics exports accepted in the 5 s after the lines; logs retried; an accepted export shows `aegis_otlp_dropped_log_records` >= 3 within 45 s; SIGTERM exit 0 <= 5 s |

Each case also checks:
- **wire+schema**: every request has the right path and Content-Type, and passes the JSON-mapping validator.
- **scraped-once** (`--once`): the admin mimic saw exactly one `GET /metrics`.

## Self-test (negative controls)

The reference exporter must PASS all 95 checks (53 before P8). Then each mutant (env `AEGIS_OTLP_REF_MUTANT`, reference only) must
FAIL. In the table, the first four are the unit's required mutants.

| mutant | caught by |
|---|---|
| counter-as-gauge | metrics.mapping (type gauge, expected sum) |
| drop-service-name | resource.service.name |
| protobuf-content-type (JSON body) | wire+schema (Content-Type) |
| severity-wrong (every level +1) | logs.mapping (severityNumber) |
| delta-temporality | metrics.mapping |
| cumulative-buckets | metrics.mapping (bucketCounts) |
| enum-names | wire+schema (enum as string) |
| snake-case-keys | wire+schema |
| keep-total-suffix | metrics.all-series |
| base64-trace-id | wire+schema (hex) |
| start-time-moves | daemon.cumulative-start-fixed |
| accept-truncated | once-truncated.exit-nonzero |
| logs-at-eof-only | daemon.logs-streamed |
| drop-attributes | metrics.all-series |
| int-as-double | metrics.mapping (asInt) |
| ignore-log-ts | logs.mapping (timeUnixNano) |
| https-skipped (an https endpoint silently not posted, exit 0) | https-once.delivered-over-tls |
| https-no-verify (`--ca-file` ignored, CERT_NONE) | https-untrusted.exit-nonzero / nothing-delivered |
| no-retry | retry-recover.exit-0 |
| retry-no-backoff | retry-recover.*.backoff |
| retry-unbounded (20 attempts) | retry-exhaust.*.bounded |
| retry-on-400 | no-retry-400.*.one-attempt |
| drop-uncounted | daemon-drop.drop-counted |

A stub that exits 0 and sends nothing must also FAIL, and so must an absent `--exporter` path.

## Provenance

- `fixtures/aegis-metrics.txt` (sha256 `1e4d83f5…6001`) is the real `GET /metrics` body from the prebuilt
  `~/aegis/target/release/aegis`:
  - binary sha256 `1674648655a5f3a05bafb8d48cf296d46d58b9cd3b1d6bb7c4eb6c7580d51ca4`, built 2026-11-04;
  - recorded 2026-11-06 on the laptop, with no rebuild;
  - config: one listener, admin on loopback, two routes (one with no authz), upstream down;
  - traffic: 4 requests (502, 403, 502, 400), then a SIGHUP;
  - format: `crates/aegis-metrics/src/render.rs` plus the `aegis_proxy_*` families from
    `crates/aegis-bin/src/admin.rs`;
  - response header: `content-type: application/openmetrics-text; version=1.0.0; charset=utf-8`.

  The oracle's admin mimic reproduces admin.rs's response shape: `HTTP/1.1`, lowercase headers,
  `connection: close`, one request per connection.
- `fixtures/aegis-stderr.log` (`aa417b24…6103`) is the same run's stderr, unmodified except one substitution: the
  scratch audit directory path is replaced by `/var/lib/aegis/audit/`.
- `fixtures/json-logs.jsonl` and `fixtures/synthetic-metrics.txt` are **synthetic**. aegis emits no JSON logs and
  no histogram today. They pin the contract for the promised JSON log shape and for OpenMetrics features (histogram,
  `_created`, UNIT, escapes, floats) that aegis-metrics' renderer can express or will grow.
- `proto-excerpts.txt` comes from opentelemetry-proto commit `169f2f2c7c1550c364d5eecb05d1b6163a011b06`, with the
  upstream sha256s listed in that file. It contains the JSON-encoding section of docs/specification.md verbatim
  and the field lists of the messages used. No whole files are vendored.

## Re-run in repo (2026-11-06, laptop)

- `run`: `OTLP-EXPORT: PASS (53 checks, subject reference ref_exporter.py)`, 3 of 3 runs, about 5.5 s each.
- `run --self-test`: `OTLP-EXPORT SELF-TEST: PASS (reference green; 16/16 mutants red; stub and absent binary
  red)`, about 28 s.
- `run --exporter target/release/aegis-otlp`: `OTLP-EXPORT: FAIL (exporter target/release/aegis-otlp is absent or
  not executable)`. That is red before P7-otlp-001, as required.
- A fail-closed stub (exit 1): 31 of 53 checks fail.

## Known limits

- P8: https, retry with backoff, the 400 no-retry rule, drop-and-count of log records and the no-stall rule are
  exercised (above). Still not exercised: `Retry-After`, 429/502/504 individually (503 stands for the retryable set),
  the bounded stdin queue's drop-oldest under a slow collector, and `aegis_otlp_dropped_metric_points`' value (it can
  only be exported through the failing metrics path). Self-metrics are otherwise allowed but not checked.
- The TLS collector is Python ssl (OpenSSL 3.x, TLS 1.3, P-256, X25519): it shows the exporter verifies the chain
  against `--ca-file` and speaks TLS 1.3, not which groups the aegis-tls client profile offers (the tls gates do).
- OpenMetrics features absent from aegis's renderer are not fed: per-sample timestamps, `info`/`stateset`/`summary`/
  `gaugehistogram`, exemplars, NaN/Inf values.
- The JSON log input schema is defined here because aegis does not yet emit JSON logs. If aegis-bin adopts a
  different JSON shape, this oracle and the contract change together, in a spec-author unit.
- The timing bounds in daemon mode (≤3 s log latency, ≥3 exports in about 5 s at 250 ms, exit ≤5 s after SIGTERM) are
  generous for loopback and are not performance claims.
- Rung: R2 end-to-end against a mapping-checking collector (PLAN-7). The validator is a hand-written reading of the
  proto JSON mapping, not a generated protobuf parser.

## Re-run in repo (2026-11-06, laptop, P8-oracle-001)

- `run`: `OTLP-EXPORT: PASS (95 checks, subject reference ref_exporter.py)`, about 19 s.
- `run --self-test`: `OTLP-EXPORT SELF-TEST: PASS (reference green; 23/23 mutants red; stub and absent binary red)`,
  about 2.5 min (drop-uncounted waits the full 45 s for a count that never comes).
- Against today's aegis-otlp (kamrui build at base 0e27b11): `OTLP-EXPORT: FAIL (10 failed, 85 passed)`. https-once
  and https-untrusted pass (https through `--ca-file` already works); every retry check is red (one attempt per
  request, no retry), and so is `daemon-drop.drop-counted`. no-retry-400 passes.
