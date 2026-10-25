# transport-limits

Resource-limit conformance of the HTTP/2 server (TBI-4 handler/stream caps, TBI-7 per-connection memory, TBI-8
stall deadline) measured against the running subject with the public benchmarking tool **h2load** (nghttp2 1.69.0,
from Alpine's `nghttp2=1.69.0-r0` on a digest-pinned `alpine:3.22`, see `Dockerfile`). Only h2load and curl are used.

| check | load | pass |
|---|---|---|
| stall | 10 connections × 100 streams of a 4 MiB body, zero stream window (`-w 0`) | every stream ended by the server within 13 s (stall_ms 10 s + slack); server RSS ≤ 192 MiB; a fresh client gets 200 within 2 s every second meanwhile |
| streams | 1 connection, 1,000 requested concurrent streams | 2,000/2,000 requests succeed (advertised 100-stream cap respected) |
| conns | 300 connections × 10 requests | 3,000/3,000 succeed |

Negative control (`--self-test`): the same stall run against the subject started with `--no-wrapper` (test-only
feature) must show streams that are never reaped (client timeouts at 30 s). Measured 2026-10-25 on the laptop:
with the wrapper 10.5 s / 0 timeouts / 8 MiB peak; without it 30.5 s / 1,000 client timeouts.

Limits: h2load reads responses, so the "large window, then stop reading" memory shape (the real TBI-7 threat per
spike q2-009) is not exercised here; it is covered by spike q2-009's measurements and the transport e2e tests. Rapid
Reset and CONTINUATION floods are rejected by h2 0.4.20's own limits (q2-009). Loopback, cleartext h2c only.
