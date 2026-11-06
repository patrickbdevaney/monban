# P7-otlp-001 report (implementer, 2026-11-06, base 4789bce)

## Status: 52/53. Blocked on one feature flag (integrator).

`oracles/otlp-export/run --exporter target/release/aegis-otlp` gives
`OTLP-EXPORT: FAIL (1 failed, 52 passed: daemon.sigterm-exit-0)`.

The failing check needs a SIGTERM handler. aegis-otlp's tokio features (`rt, net, time, io-util, sync`, set by
P7-spec-002) leave out `signal`. Under `#![forbid(unsafe_code)]`, with no libc/rustix/signal-hook dependency, the
process cannot catch SIGTERM, so it dies with -15. That is a dependency/feature change, outside the implementer's
write scope, so it is not made here.

### Requested change (integrator)

`crates/aegis-otlp/Cargo.toml`:
```toml
tokio = { workspace = true, features = ["rt", "net", "time", "io-util", "sync", "signal"] }
```
- No new crate in the lock. `signal` pulls `signal-hook-registry`, which is already in Cargo.lock through aegis-bin.
  Cargo.lock sha256 was identical before and after (`7119a6bf…a61d`).
- The aegis-otlp normal graph goes from 32 to 34 crates (`cargo tree --prefix none | sort -u`).

Then this follow-up goes in `crates/aegis-otlp/src/main.rs` (my write scope; ready to land as soon as the feature
exists). It replaces the last three lines before `ExitCode::SUCCESS`:
```rust
    let stop = Arc::new(AtomicBool::new(false));
    // SIGTERM / SIGINT stop the loop; `run` flushes the queued logs before it returns, then exit 0.
    for kind in [tokio::signal::unix::SignalKind::terminate(), tokio::signal::unix::SignalKind::interrupt()] {
        let sig = {
            let _rt = rt.enter();
            tokio::signal::unix::signal(kind)
        };
        match sig {
            Ok(mut sig) => {
                let stop = stop.clone();
                rt.spawn(async move {
                    sig.recv().await;
                    stop.store(true, Ordering::SeqCst);
                });
            }
            Err(e) => {
                eprintln!("aegis-otlp: signal handler: {e}");
                return ExitCode::from(2);
            }
        }
    }
    rt.block_on(ex.run(&stop));
```
I tested this on a throwaway remote copy (desktop, ci/remote.sh), with both edits applied there only:
- clippy `-D warnings` clean;
- `OTLP-EXPORT: PASS (53 checks, subject target/release/aegis-otlp)`;
- binary 3 996 352 B.

## What was built (crates/aegis-otlp/src/)

| file | role |
|---|---|
| `main.rs` | CLI (the README contract, plus `--ca-file`, `--tls-profile`), `--once` and interval loops, self-metrics |
| `om.rs` | Bounded OpenMetrics 1.0 parser. Caps: 4 MiB, 10 000 samples, 2 000 families, 64 labels, 64 KiB lines. Rejects the whole exposition on a missing `# EOF`, content after it, an unknown escape, a duplicate label, a bad value, or a suffix that does not fit the type. |
| `otlp.rs` | Mapping to OTLP JSON: counter→monotonic cumulative `sum` without `_total`; `_created`→start time (exact decimal ns); gauge/unknown→`gauge`; histogram→de-cumulated `bucketCounts`, finite bounds, `le` dropped; exact `asInt`. Also the Resource/scope envelopes. |
| `logs.rs` | Log line→LogRecord. JSON goes through aegis-canon `parse_json` (the one JSON parser, X-2): RFC 3339 `ts`→exact ns, severity table, hex trace/span ids, typed attributes, nulls omitted. Anything else→string body. |
| `queue.rs` | Bounded stdin line reader (64 KiB; the rest of a longer line is discarded and the line exported truncated as plain text). Log queue capped at 10 000 records / 16 MiB, drop-oldest, with a counter. |
| `net.rs` | Scrape (TCP or UDS GET) and POST, both over aegis-egress's capped `http1::exchange`. https goes through `aegis_tls::client_config(profile, roots from --ca-file)` → `TlsClient::from_config` (no implicit trust). 10 s deadline per exchange. |
| `jsonw.rs` | JSON output: escaping, int64 as strings, doubles (non-finite→proto3 strings). |

Self-metrics: `aegis_otlp_dropped_log_records` and `aegis_otlp_failed_exports`. Both are cumulative sums, sent
with each metrics export.

## Evidence

- Acceptance (`ci/heavy.sh cargo build --release --locked -q -p aegis-otlp && oracles/otlp-export/run --exporter
  target/release/aegis-otlp`), run on the desktop through ci/remote.sh:
  `FAIL daemon.sigterm-exit-0: exit -15` / `OTLP-EXPORT: FAIL (1 failed, 52 passed: daemon.sigterm-exit-0)`.
- `cargo clippy --locked -p aegis-otlp --all-targets -- -D warnings`: clean. `cargo test -p aegis-otlp`: 10 passed.
- Binary (release): 3 962 600 B. Normal crate graph of aegis-otlp: 32 crates. 0 opentelemetry/prost/tonic.
- **The laptop run was not done.** heavy.sh refuses at 7.1 GB free (floor 10 GB), and the floor was not overridden.
  The laptop run of the gate is pending until disk is freed.

## Limits

- https endpoint, retry/backoff, and drop-oldest under backpressure are not exercised by the oracle (its known
  limits). Drop-oldest and the bounded reader have unit tests only. There is no retry: a failed POST is counted in
  `aegis_otlp_failed_exports` and logged to stderr, and those log records are dropped.
- Per-sample OpenMetrics timestamps and exemplars are accepted and ignored. `info`, `stateset`, `summary` and
  `gaugehistogram` families are skipped.
- Log JSON that is valid JSON but not strict I-JSON (duplicate keys, integers beyond 2^53, `-0`) is exported as a
  plain-text body. aegis-canon's parser decides.
- Rung: R2 end to end against the mapping-checking collector (52/53 now, 53/53 with the flag).
