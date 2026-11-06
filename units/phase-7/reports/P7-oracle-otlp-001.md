# P7-oracle-otlp-001 report (spec author, 2026-11-06, base 00ca246)

## What was built

`oracles/otlp-export/` (stdlib Python, `python3 -I`):
- `run`: the entry point. It matches the gate commands in `gates/phase-7.toml`.
- `otlp_oracle.py` contains three pieces:
  - a loopback OTLP/HTTP collector that validates every request against the opentelemetry-proto JSON mapping;
  - a fake aegis admin listener (TCP and unix socket, admin.rs wire shape);
  - the cases and the self-test.
- `ref_exporter.py`: a stdlib reference exporter that implements the CLI contract, plus 16 negative controls.
- `fixtures/`:
  - real recorded aegis `/metrics` and stderr;
  - synthetic JSON logs and a synthetic histogram/escapes exposition.
- `proto-excerpts.txt`: excerpts from opentelemetry-proto at commit 169f2f2, with upstream sha256s.
- `README.md`: the contract, the mapping rules, provenance and limits.

Only `oracles/otlp-export/**` and this report were written.

## Contract for P7-otlp-001

```
aegis-otlp --scrape <http://127.0.0.1:P/metrics | unix:/abs/path.sock> --endpoint <http://host:port[/prefix]>
           --service-name S [--interval-ms N (default 10000)] [--resource-attr k=v]... [--once]
```

`--once`:
- reads stdin to EOF;
- does exactly one scrape;
- POSTs `/v1/metrics` and `/v1/logs` as `application/json`;
- exits 0 only if the scrape parsed and every POST got a 2xx.

Interval mode:
- scrapes every N ms;
- streams stdin lines within min(N, 1 s);
- on SIGTERM, flushes and exits 0 within 5 s.

The full mapping is in the README:
- counter → monotonic cumulative `sum`, named without `_total`;
- `_created` → start time;
- histogram → de-cumulated `bucketCounts`;
- integer tokens → exact `asInt`;
- no `# EOF` → reject the scrape;
- JSON log lines: `ts`/`level`/`msg`/`trace_id`/`span_id`/other keys → attributes;
- plain lines → string body.

## Findings that shape the implementer's work

- aegis emits **no JSON logs** today. stderr is plain text (`aegis[PID]: …`). So the contract accepts both: JSON
  objects get the structured mapping, and any other line becomes a string body. The JSON field names are defined
  here (`ts`, `level`, `msg`, `trace_id`, `span_id`, rest → attributes), because ARCHITECTURE §3.10 promises JSON
  logs but no shape exists in the code.
- aegis emits **no histogram** today. Histogram mapping is required anyway (it is in the unit's `must`) and is
  fed from a synthetic exposition.
- The gate's `cargo build -p aegis-otlp` needs the crate skeleton from P7-spec-002. This unit does not create it.

## Evidence

```
$ oracles/otlp-export/run --exporter target/release/aegis-otlp      # red before P7-otlp-001
OTLP-EXPORT: FAIL (exporter target/release/aegis-otlp is absent or not executable)      rc=1
$ oracles/otlp-export/run --exporter <fail-closed stub, exit 1>
OTLP-EXPORT: FAIL (31 failed, 22 passed: once-tcp-real.exit-0, once-tcp-real.scraped-once, ...)
$ oracles/otlp-export/run
OTLP-EXPORT: PASS (53 checks, subject reference ref_exporter.py)
$ oracles/otlp-export/run --self-test
OTLP-EXPORT SELF-TEST: PASS (reference green; 16/16 mutants red; stub and absent binary red)
```

Each required mutant is caught by:
- counter-as-gauge: `metrics.mapping` (type gauge, expected sum);
- drop-service-name: `resource.service.name`;
- protobuf-content-type with a JSON body: `wire+schema` (Content-Type);
- severity-wrong: `logs.mapping` (severityNumber 2 != 1).

Twelve more mutants are also red. They are listed in the README.

## Limits

These are not exercised:
- the https endpoint;
- retry and backoff;
- drop-oldest under backpressure;
- OpenMetrics features aegis does not render.

Rung: R2 e2e against a hand-written mapping-checking collector. The fixtures were recorded from the prebuilt
binary 1674648655a5…; no rebuild.
