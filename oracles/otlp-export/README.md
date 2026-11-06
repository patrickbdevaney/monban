# otlp-export: aegis-otlp vs a mapping-checking OTLP/HTTP JSON collector

Unit P7-oracle-otlp-001. Gate `otlp-export` (gates/phase-7.toml, laptop). Implementer unit: P7-otlp-001.
Decision: PREFLIGHT D-P7.6. OTLP stays out of process (spikes/otlp-footprint, verdict flip). `aegis-otlp` is a
separate binary with no OpenTelemetry crates. It scrapes the admin listener's OpenMetrics text, reads aegis log
lines on stdin, and POSTs OTLP/HTTP JSON to `/v1/metrics` and `/v1/logs`.

```
oracles/otlp-export/run                                      # reference exporter (ref_exporter.py): PASS
oracles/otlp-export/run --exporter target/release/aegis-otlp # the gate: the real binary
oracles/otlp-export/run --self-test                          # reference PASS, 16 mutants + stub + absent FAIL
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
| `--endpoint URL` | OTLP/HTTP **base** URL. Strip trailing `/`, then append `/v1/metrics` and `/v1/logs`. A path prefix is kept, so `http://h:p/collector/` gives `/collector/v1/metrics`. The oracle uses `http://`. `https://` goes through the aegis-tls client profile and is not exercised here. |
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

The oracle's collector answers `200`, `Content-Type: application/json`, `{}`. Retry and backoff are not exercised.

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

Each case also checks:
- **wire+schema**: every request has the right path and Content-Type, and passes the JSON-mapping validator.
- **scraped-once** (`--once`): the admin mimic saw exactly one `GET /metrics`.

## Self-test (negative controls)

The reference exporter must PASS all 53 checks. Then each mutant (env `AEGIS_OTLP_REF_MUTANT`, reference only) must
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

- Only plain-HTTP collectors are tested. The `https://` endpoint via the aegis-tls client profile is not exercised
  (no TLS collector in stdlib-only form without a cert setup; it can be added).
- Retry/backoff on 429/503, bounded-queue drop-oldest under backpressure, and the drop counter's value are not
  exercised. Self-metrics `aegis_otlp_*` are allowed but not checked.
- OpenMetrics features absent from aegis's renderer are not fed: per-sample timestamps, `info`/`stateset`/`summary`/
  `gaugehistogram`, exemplars, NaN/Inf values.
- The JSON log input schema is defined here because aegis does not yet emit JSON logs. If aegis-bin adopts a
  different JSON shape, this oracle and the contract change together, in a spec-author unit.
- The timing bounds in daemon mode (≤3 s log latency, ≥3 exports in about 5 s at 250 ms, exit ≤5 s after SIGTERM) are
  generous for loopback and are not performance claims.
- Rung: R2 end-to-end against a mapping-checking collector (PLAN-7). The validator is a hand-written reading of the
  proto JSON mapping, not a generated protobuf parser.
