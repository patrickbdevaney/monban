# hostile-modules oracle (Phase-5 gates p2-hostile-worker, p2-hostile-host)

Unit P5-oracle-hostile-001. The C2 adversarial corpus of the golden extension contract: hostile F14 core modules
that must leave the surviving invariants intact. **SPEC_INVARIANTS §H** (survive I1, I2, I5, I6-host, I7;
INV-P2 P2-7), **F14** (`interfaces/F14-p2-guest-abi.cddl`, Parts 1–3), F8 `p2` block, PLAN-5 D7, D13, Q11.
Every case maps to exactly one invariant id; the tables below are generated from `corpus/*.json` and the
self-test refuses to pass if a corpus id is missing from this file.

```
oracles/hostile-modules/run                       # both levels against the reference (hostref + ref_host.py)
oracles/hostile-modules/run --self-test           # both levels: reference green, 5 + 7 reference mutants red
oracles/hostile-modules/run --level worker --subject target/p2/release/monban-p2                      # gate cmd
oracles/hostile-modules/run --self-test --level worker --subject target/p2/release/monban-p2 \
    --mutant-subject target/p2-mutants/release/monban-p2                                              # gate selftest
oracles/hostile-modules/run --level host --subject target/p2/release/monban --worker target/p2/release/monban-p2
oracles/hostile-modules/run --self-test --level host --subject target/p2/release/monban --worker target/p2/release/monban-p2 \
    --mutant-subject target/p2-mutants/release/monban --mutant-worker target/p2-mutants/release/monban-p2
```

The last line is `HOSTILE-MODULES: PASS|FAIL (...)` or `HOSTILE-MODULES SELF-TEST: PASS|FAIL (...)`; exit 0 only on
PASS. `--only id,...` runs a subset and never prints PASS. The reference worker (`rust/`, wasmtime 50.0.1) is built
under `ci/heavy.sh` and `rust/target` is deleted at exit (`--keep-build` keeps it). Python is stdlib only, run as
`python3 -I`; the host level needs the `openssl` CLI (throwaway P-256 certificate). The load average is printed at
start and end; the oracle has count criteria only (no `needs` file), so it runs on the desktop (`remote = true`).
Deadlines are wall_ms + 2 s grace per request.

## Worker level (`--level worker`): subject contract for monban-p2

The oracle is the mock supervisor. It requires this worker command line (it is the same one monban-bin must use to
spawn the worker, so the host level can substitute the escaped worker):

- `<w> compile --in <module.wasm> --out <module.cwasm>`: exit 0 and the file written, or non-zero (78) = refused.
  The F14 static check happens here: imports outside the eight `monban.*` functions with their exact types (any
  other module or name, a memory, table or global import, `env.host_fault` in a golden build) and exports other than
  exactly `memory` + `handle() -> i32` refuse the module **before instantiation**.
- `<w> zygote --module <c.cwasm> --sha256 <hex>` (fork+Wasm) and `<w> cordon --module <c.cwasm> --sha256 <hex>`:
  fd 3 is a listening `SOCK_SEQPACKET` Unix socket. On each accepted connection the worker sends the F14 `ready`
  frame (guest-api-version 1, the sha256 of the .cwasm it loaded, which must equal `--sha256`). The zygote forks one
  child per connection; the child serves one request and exits. A cordon serves many requests on one connection,
  one at a time (no pipelining). A `test-hooks`/`mutants` worker may send one D8 `layout` frame after `ready`; the
  oracle accepts exactly one, only in the first exchange of a connection and before any other frame (PLAN D21).
  Any other frame outside the request's own frames is still a protocol violation.
  `<hex>` is the sha256 the oracle computed over the .cwasm that `compile` produced (D4); the worker refuses
  anything else before deserializing.
- Per request the oracle sends `request` (the F8 default limits unless the case overrides some) and the body as
  `body-chunk` frames ending with `last = true` (also for an empty body), answers every `data-run` with one
  `data-reply` (F10 `result`), and reads until `resp-end`. Mutants of a `mutants` build are selected with
  `AEGIS_P2_MUTANT=<name>`; unknown names (e.g. a supervisor mutant inherited through the environment) must leave the
  worker golden.

Judged per case on both paths: the outcome class (`ok` = resp-end code 0 with the expected body; `fail` = resp-end
with a trap code from the case's set, or worker death where `death_ok`; `refused` = compile refused), plus quota
ceilings on what the worker forwarded (data-run frames, body bytes, log bytes), op bytes forwarded verbatim, and the
zygote surviving every request. A frame that does not decode, a frame for an unknown req-id, a second resp-head or
a resp-body before resp-head fails the case (a golden worker never emits one). No resp-end within the deadline fails
it (unbounded request).

### Worker-level cases (`corpus/worker.json`)
| case | inv | expected outcome | what |
|---|---|---|---|
| `w-control-ok` | control | ok | Vacuity: a well-behaved module answers through resp_head/resp_write. |
| `w-control-data-run` | control | ok | Vacuity: data_run, result_read of a valid handle returns the supervisor's F10 result bytes, handle_drop. |
| `w-i1-import-host-fault` | I1 | refused | The test-only env.host_fault in a golden build (D15): refused at compile. |
| `w-i1-import-wasi` | I1 | refused | WASI (no ambient I/O, D13): refused. |
| `w-i1-import-unknown-monban` | I1 | refused | A non-allowlisted name in module monban (egress fetch is out of scope, D13): refused. |
| `w-i1-import-shared-kv` | I1 | refused | An effective-context-switch import (survival table I1: no effective-context switch): refused. |
| `w-i1-import-wrong-type` | I1 | refused | An allowlisted name with another signature: refused. |
| `w-i1-import-memory` | I1 | refused | A memory import: refused. |
| `w-i1-import-global` | I1 | refused | A global import: refused. |
| `w-i1-import-table` | I1 | refused | A table import: refused. |
| `w-i1-export-no-handle` | I1 | refused | Missing handle export: refused at compile (F14 exports are exact). |
| `w-i1-export-extra` | I1 | refused | An extra export: refused. |
| `w-i1-export-handle-type` | I1 | refused | handle with a parameter: refused. |
| `w-i1-export-no-memory` | I1 | refused | No memory export: refused. |
| `w-i1-handle-forged` | I1 | fail (trap 5) | A slot that was never issued (own handle + 1): trap 5. |
| `w-i1-handle-zero` | I1 | fail (trap 5) | Handle 0 (generation 0 is never issued): trap 5. |
| `w-i1-handle-foreign` | I1 | fail (trap 5) | Own slot under another generation: trap 5. |
| `w-i1-handle-dropped` | I1 | fail (trap 5) | Use after drop: trap 5. |
| `w-i1-handle-double-drop` | I1 | fail (trap 5) | Dropping twice: trap 5. |
| `w-i1-handle-previous-request` | I1 | fail (trap 5) | A handle issued to request n (emitted by a first request on the same connection/worker) presented in request n+1: trap 5. Handles die with the request. |
| `w-i1-context-switch-op-verbatim` | I1 | ok; op bytes verbatim | A data_run whose tenant field names another tenant: the worker forwards the op bytes verbatim (it holds no authority and resolves nothing); the supervisor overwrites the tenant (host level h-i1-ctx-*). |
| `w-i1-pointer-out-of-range` | I1 | fail (trap 7) | A host-call pointer range outside memory 0: trap 7, nothing copied. |
| `w-i1-log-bad-level` | I1 | fail (trap 7) | ABI misuse (log level 9) traps; no error code a module could probe with. |
| `w-i2-loop` | I2 | fail (trap 1/2, or worker death) | Infinite loop: ends by fuel or the wall bound well within wall_ms + grace. |
| `w-i2-fuel` | I2 | fail (trap 1) | A finite 3M-iteration loop under a 20,000-unit fuel limit: trap 1 (fuel is enforced, not advisory). |
| `w-i2-memory-bomb` | I2 | ok-or-fail (trap 3); max_pages<=256 | memory.grow one page at a time to 64 MiB: growth past memory_mib (16 MiB = 256 pages) is refused. |
| `w-i2-memory-initial` | I2 | refused-or-fail (trap 3/4) | A declared initial memory of 20 MiB (> memory_mib): never instantiated. |
| `w-i2-table-bomb` | I2 | fail (trap 3/4) | table.grow by 1,048,576 elements is refused by the limiter (the module traps on -1). |
| `w-i2-deep-recursion` | I2 | fail (trap 1/4) | Unbounded recursion: stack overflow trap (or fuel), the worker survives. |
| `w-i2-hostcall-flood` | I2 | fail (trap 6) | 200,000 req_head calls against max_host_calls = 10,000: trap 6. |
| `w-i2-datarun-flood` | I2 | fail (trap 6); max_data_run_frames<=64 | 100 data_runs against max_data_runs = 64: trap 6 and at most 64 data-run frames reach the supervisor. |
| `w-i2-data-byte-amplification` | I2 | fail (trap 6); max_data_run_frames<=4 | Each data_run reply is ~30 KB; max_data_bytes = 100,000: trap 6 by the 4th reply, no further data-run frames. |
| `w-i2-response-size-bomb` | I2 | fail (trap 6); max_resp_body<=65536 | 819,200 body bytes against max_resp_bytes = 65,536: trap 6; at most 65,536 body bytes are forwarded. |
| `w-i2-log-flood` | I2 | fail (trap 6); max_log_bytes<=4096 | 102,400 log bytes against max_log_bytes = 4,096: trap 6; at most 4,096 log bytes are forwarded. |

## Host level (`--level host`): subject contract for monban (feature p2)

Command line as for oracles/native-e2e (P4): `<monban> --config <f8.json> --cert --key --audit-dir --runtime-dir
--token-keyring`; readiness `GET /healthz` = 200 on `admin.bind`. The oracle writes one F8 config per boot: listener
`P-PUBLIC-WEB`, vhost `monban.test`, backend `sq` (sqlite, `path:<tmp>/notes.db`, `op_budget_ms` 5000), and per case
one module `m<i>` (`p2.modules[]`: path, sha256, optional `wall_ms`) and one route `{"path": "/c<i>/", "to": {"wasm":
"m<i>"}, "authz": "allow-all", "data": <cap>}`; `p2 = {worker, cache_dir, isolation, modules}` with every other p2
field at its default (crash budget 3/60 s/600 s). Four boots: `isolation = forkwasm` and `cordon`, each with the
real `--worker` and with the escaped worker. The notes table is the native-e2e schema (`tenant` = 16 lower-hex of
the u64, columns `tenant`=0, `id`=1, `body`=2) with one seeded victim row. Requests are HTTP/1.1 over TLS with an
F5 Tier-L token; every case uses its own random tenant, hence its own principal (D7 never couples cases).

Judged by:
- **Response bytes.** `allow`: 200, the module's `x-mod: 1` header, host-computed `content-length` and no
  `transfer-encoding`, the exact body (or the expected F10 result kind). `deny`: status and body identical to the
  host's response to an explicit Deny (`h-control-deny`, which must be non-2xx/3xx and carry no module byte) and none
  of the case's module markers anywhere in the raw response (headers included). Error, trap, timeout, decode failure
  and garbage codes must all equal Deny (I7; F14 Part 3: nothing reaches the client before resp-end(0)).
- **F9 audit log** in `--audit-dir`: every `<log>/tile/entries/**` entry bundle (C2SP tlog-tiles, big-endian
  u16-prefixed leaves; the widest partial wins). Required event for each data_run: `action = "p2.data_run"`,
  `actor.tenant` = the route-bound (token) tenant, `outcome = "allow"` (authorized, logged before execution) or
  `"deny"` (refused).
- **Effect sink**: `notes.db`, read directly. **Audit before effect**: for `h-i6-audit-before-effect` the oracle
  holds the SQLite write lock (`BEGIN IMMEDIATE`) while the request runs; the allow event must be in the log while
  the insert is still blocked (≤ 0.8 s), and the row must appear after release. **Audit-vs-effect diff** after every
  boot: no tenant has more rows than allow events (the seeded victim row excepted).
- `supervisor-alive`: the supervisor survives every case (F14: a decode failure never stops it).

**Escaped worker.** `escaped-worker` (written into the work dir) runs the reference worker with
`HOSTILE_ESCAPED=1`: it skips the worker-side I5 checks, forwards a second resp-head, sends a 70,000-byte resp-body
in one frame, and after a trap appends a late resp-head/resp-body/resp-end(0). It stands for a worker whose sandbox
or Wasmtime was escaped, and judges the supervisor's own decoder (§H: host decoders of module output are in the
verified TCB). It requires monban-bin to spawn the worker with the worker command line above.

### Host-level cases (`corpus/host.json`)
| case | inv | worker | cap | expected outcome | what |
|---|---|---|---|---|---|
| `h-control-allow` | control | real | none | allow | Vacuity: an Allow completion reaches the client re-serialized by the host. |
| `h-control-deny` | control | real | none | deny; absent: SECRET-DENY, x-mod | Explicit Deny: the host's fixed response; it defines the deny response every failure case must equal. |
| `h-control-data-run` | control | real | all | allow; result rows; effect {own_rows: 1}; audit {allow: 1} | Vacuity: an authorized data_run reaches SQLite under the route-bound tenant and is audited once. |
| `h-i1-cap-none` | I1 | real | none | allow; result err; effect {own_rows: 0, rowid_rows: 0}; audit {allow: 0, deny_min: 1} | Route without data capability (INV-NONEMPTY): the op is refused with the uniform error result, audited as refused, no effect. |
| `h-i1-cap-readonly` | I1 | real | ro | allow; result err; effect {own_rows: 0, rowid_rows: 0}; audit {allow: 0, deny_min: 1} | insert on a select-only capability: refused, no effect. |
| `h-i1-cap-collection` | I1 | real | all | allow; result err; audit {allow: 0, deny_min: 1} | A collection outside the route's CapSet: refused. |
| `h-i1-cap-column` | I1 | real | all | allow; result err; effect {own_rows: 0, rowid_rows: 0}; audit {allow: 0, deny_min: 1} | A write to a column outside the capability's columns: refused. |
| `h-i1-cap-tenant-write` | I1 | real | all | allow; result err; effect {own_rows: 0, rowid_rows: 0}; audit {allow: 0, deny_min: 1} | A write to the tenant column (F4 TenantFieldWritten): refused. |
| `h-i1-ctx-insert` | I1 | real | all | allow; result rows; effect {own_rows: 1, rowid_rows: 1}; audit {allow: 1} | Effective-context switch: the op names the victim tenant; the supervisor overwrites it with the route-bound tenant, so the row lands under the caller's tenant only. |
| `h-i1-ctx-select` | I1 | real | all | allow; result rows; audit {allow: 1} | A select naming the victim tenant returns none of the victim's rows. |
| `h-i1-malformed-op` | I1 | real | all | deny; effect {own_rows: 0}; audit {allow: 0} | An op that fails the F10 decoder: decode failure (worker killed, principal charged), host deny response, no effect. |
| `h-i1-deep-filter` | I1 | real | all | deny; audit {allow: 0} | A filter nested 200 deep (> F4 MAX_PRED_DEPTH = 64): decode failure before constructing, deny. |
| `h-i5-partial-body-then-trap` | I5 | real | none | deny; absent: SECRET-PARTIAL, x-mod | 42 KB of body (several resp-body frames) then a trap: nothing the module wrote reaches the client. |
| `h-i5-crlf-header` | I5 | real | none | deny; absent: x-injected, BAD-HEADER-BODY | Header value with CR LF (response splitting): rejected, never repaired. |
| `h-i5-lf-header` | I5 | real | none | deny; absent: x-injected, BAD-HEADER-BODY | Bare LF in a header value: rejected. |
| `h-i5-nul-header` | I5 | real | none | deny; absent: BAD-HEADER-BODY | NUL in a header value: rejected. |
| `h-i5-obs-text-header` | I5 | real | none | deny; absent: BAD-HEADER-BODY | obs-text (0xE9) in a header value (CVE-2026-73552 pattern): rejected. |
| `h-i5-invalid-utf8-header` | I5 | real | none | deny; absent: BAD-HEADER-BODY | Invalid UTF-8 bytes in a header value: rejected. |
| `h-i5-upper-name` | I5 | real | none | deny; absent: BAD-HEADER-BODY | A non-lower-case header name: rejected (not lower-cased). |
| `h-i5-space-name` | I5 | real | none | deny; absent: BAD-HEADER-BODY | A header name that is not an RFC 9110 token: rejected. |
| `h-i5-trailing-space` | I5 | real | none | deny; absent: BAD-HEADER-BODY | Trailing whitespace in a header value: rejected (not trimmed). |
| `h-i5-content-length` | I5 | real | none | deny; absent: BAD-HEADER-BODY | A module-authored framing field: rejected (framing is host-computed). |
| `h-i5-transfer-encoding` | I5 | real | none | deny; absent: BAD-HEADER-BODY, chunked | transfer-encoding from a module: rejected. |
| `h-i5-hop-by-hop` | I5 | real | none | deny; absent: BAD-HEADER-BODY | A hop-by-hop field: rejected. |
| `h-i5-too-many-headers` | I5 | real | none | deny; absent: MANY-HEADERS-BODY | 200 header fields > limits.max_header_fields (128): rejected. |
| `h-i5-header-list-size` | I5 | real | none | deny; absent: MANY-HEADERS-BODY | Summed header size 20,740 > limits.max_header_list_size (16,384): rejected. |
| `h-i5-double-head` | I5 | real | none | deny; absent: SECOND-HEAD, DOUBLE-HEAD-BODY | resp_head twice (double response): trap, deny. |
| `h-i5-status-range` | I5 | real | none | deny; absent: BAD-HEADER-BODY | A status outside 200..599 (101 Switching Protocols): rejected. |
| `e-i5-crlf-header` | I5 | escaped | none | deny; absent: x-injected, BAD-HEADER-BODY | Compromised worker forwards a CR LF header: the supervisor's re-check rejects it (decode failure); no module byte reaches the client. |
| `e-i5-obs-text-header` | I5 | escaped | none | deny; absent: BAD-HEADER-BODY | Compromised worker forwards obs-text: rejected by the supervisor. |
| `e-i5-framing-header` | I5 | escaped | none | deny; absent: BAD-HEADER-BODY, chunked | Compromised worker forwards transfer-encoding: rejected by the supervisor. |
| `e-i5-status-range` | I5 | escaped | none | deny; absent: BAD-HEADER-BODY | Compromised worker forwards status 101: rejected by the supervisor. |
| `e-i5-double-head` | I5 | escaped | none | deny; absent: SECOND-HEAD, DOUBLE-HEAD-BODY | Compromised worker sends two resp-head frames for one req-id: decode failure, deny. |
| `e-i5-late-response` | I5 | escaped | none | deny; absent: LATE-SECRET, SECRET-PARTIAL, x-late | After resp-end(trap) the compromised worker sends a late resp-head/resp-body/resp-end(0) for the finished req-id: never forwarded. |
| `e-i5-oversized-frame` | I5 | escaped | none | deny; absent: x-mod | A 70,000-byte resp-body frame (> frame_max_bytes 65,536): decode failure, deny. |
| `h-i6-audit-before-effect` | I6-host | real | all | any; effect {own_rows: 1}; audit {allow: 1}; audit seen while effect blocked | The oracle holds the SQLite write lock while the request runs: the p2.data_run audit event must already be in the log while the effect is still blocked; after release the row appears. |
| `h-i6-trap-after-effect` | I6-host | real | all | deny; audit {allow_min: 1} | data_run then trap: the authorized op stays audited although the request failed; no row exists without its audit event. |
| `h-i7-error-code` | I7 | real | none | deny; absent: SECRET-ERROR, x-mod | handle() returns 7 (Error): Deny. |
| `h-i7-garbage-code` | I7 | real | none | deny; absent: SECRET-GARBAGE, x-mod | handle() returns 0xFFFFFFFF: Error => Deny. |
| `h-i7-trap` | I7 | real | none | deny | A trap before any output: Deny. |
| `h-i7-trap-after-response` | I7 | real | none | deny; absent: SECRET-TRAP, x-mod | A complete response followed by a trap: the trap decides (Deny), the response is discarded. |
| `h-i7-timeout` | I7 | real | none | deny; absent: SECRET-LOOP, x-mod | Response written, then an infinite loop: the wall bound ends it and the host denies within wall_ms + grace. |
| `h-i7-crash-loop` | I7 | real | none | crash-budget | D7: three trapping requests from one principal, then that principal's next request (to a healthy route) gets 429; another principal's request to the healthy route still gets 200. |

## Self-test

`--self-test` without `--subject` runs both levels against the reference; with `--subject` it runs the given level:
the unmutated subject must PASS and every mutant (`AEGIS_P2_MUTANT=<name>` on the mutant build) must turn at least
one of its expected cases red.

| level | mutant | expected red (any of) | reference, measured 2026-10-31 |
|---|---|---|---|
| worker | extra-import (Linker and allowlist accept `env.host_fault` in a golden build) | w-i1-import-host-fault | red, 2 cells |
| worker | handle-not-cleared (handle table and generation carried to the next request of the process) | w-i1-handle-previous-request (cordon) | red, 1 cell |
| worker | no-hostcall-quota | w-i2-hostcall-flood | red, 2 cells |
| worker | no-fuel-no-epoch (no fuel, no epoch deadline, no ITIMER_REAL) | w-i2-fuel, w-i2-loop | red, 4 cells |
| worker | no-limiter | w-i2-memory-bomb, w-i2-memory-initial, w-i2-table-bomb | red, 6 cells |
| host | raw-passthrough (module header bytes written unchecked) | e-i5-crlf-header, e-i5-obs-text-header, e-i5-framing-header, e-i5-status-range | red, 8 cells |
| host | double-response-accepted (second resp-head / late frames accepted) | e-i5-double-head, e-i5-late-response | red, 4 cells |
| host | audit-after-effect | h-i6-audit-before-effect | red, 2 cells |
| host | no-audit-on-trap | h-i6-trap-after-effect | red, 6 cells |
| host | trap-maps-to-allow | h-i7-trap-after-response, h-i7-trap, h-i5-partial-body-then-trap | red, 44 cells |
| host | data-run-skips-authorize | h-i1-cap-none, h-i1-cap-readonly, h-i1-cap-column, h-i1-cap-collection | red, 10 cells |
| host | tenant-not-overwritten | h-i1-ctx-insert, h-i1-ctx-select | red, 10 cells |

The reference controls: worker level 68/68 cells green (34 cases × 2 paths), host level 96/96 cells green (4 boots).

## Reference subjects

- `rust/` **hostref** (wasmtime =50.0.1, features as PLAN-5 D11 amended: cranelift, memory-protection-keys,
  pooling-allocator, runtime, std; libc 0.2.191; `Cargo.lock` derived from oracles/isolation-fi by `mklock.py`, same
  third-party set). The worker command line above, F14 host functions with per-request generation-tagged handles,
  host-call/data_run/byte quotas, fuel + epoch (5 ms ticks) and an ITIMER_REAL backstop in fork children, a
  ResourceLimiter (memory_mib; tables ≤ 65,536 elements), the I5 header rules, and on-demand allocation (a pool
  bound would mask the no-limiter mutant). No sandbox: that is oracles/syscall-negative. The unit text says wasmtime
  =50.0.0; PLAN-5 D11 as amended moved the product and every oracle to 50.0.1 (RUSTSEC-2026-0422/0423/0424).
- `ref_host.py`: a stdlib-Python stand-in for monban (feature p2) on the host contract above: TLS front, F5 token
  check, crash budget, F14 decoder with the supervisor re-checks, data_run decode / tenant overwrite / authorize /
  audit / execute on SQLite, re-serialization, the deny response `403 denied`. Reference simplifications: requests
  on one cordon are sequential; on a decode failure a fork child is disconnected, not SIGKILLed.

## Research provenance

- `research/state/raw/round-002/03-verification-footprint-and-golden-contract.json`
  (sha256 7f677f8cae0d5fcb054bdcf02388a082a718dd0199c4710a20d2cb392c1f95fa): `vfg-invariant-survival-table`
  (I1–I8 definitions) and `vfg-conformance-suite-outline` C2 (loops, memory bombs, I/O amplification, forged/stale
  handles, use-after-drop, effective-context switch, double/late responses, oversized or non-canonical headers,
  obs-text/invalid UTF-8, crash loops, partial commit then trap; "host invariant monitors plus audit-vs-effect
  diff"). Read, not executed; every module here is written new against F14.
- PLAN-5 Q11: P2 guests have no file or socket imports, so "I/O amplification" is covered as host-call count and
  data_run / response / log byte quotas (w-i2-hostcall-flood, w-i2-datarun-flood, w-i2-data-byte-amplification,
  w-i2-response-size-bomb, w-i2-log-flood), not WASI I/O.

## Re-run in repo (laptop, 2026-10-31, Linux 6.17.0-14-generic)

- `--level worker` (reference): PASS, 68 cells ok (load 3.55).
- `--self-test --level worker` (reference): PASS, control green, 5/5 mutants red (load 3.4).
- `--level host` (reference): PASS, 96 cells ok over 4 boots (load 1.58).
- `--self-test --level host` (reference): PASS, control green, 7/7 mutants red, about 37 s (load 1.9).
- Full `./run --self-test` (laptop, `--keep-build`): PASS, README lists every case, worker control 68/68 + 5/5
  mutants red, host control 96/96 + 7/7 mutants red (load 2.6).
- Same through the real-subject code path (`--level host --subject <wrapper around ref_host.py> --worker hostref
  --mutant-subject ... --mutant-worker ...`): PASS, 7/7 red.
- Desktop (`ci/remote.sh oracles/hostile-modules/run --self-test`, Linux 6.11, the gate host): PASS, identical
  cell counts (load 3.8-7.3).
- Negative subject `/bin/false`: worker FAIL (26 ok = the 13 must-refuse cases x 2, 42 failed), host FAIL (0 ok,
  88 failed): refusing everything does not pass.
- Plain `./run` (laptop): PASS, worker 68 cells, host 96 cells (load 27, another agent's build running).
- The repo's current monban-p2 (fail-closed stub, exit 78) behaves like `/bin/false`: the gates are red until
  P5-wasm-002 and P5-bin-002 land.

## Known limits

- The real monban-p2, monban-bin p2 data_run and their mutants do not exist yet (W2–W5); the oracle has run only
  against its reference. The worker command line, the `p2.data_run` audit event shape and the deny-equality rule are
  defined here first; P5-iso-002/003, P5-wasm-002 and P5-bin-001/002 implement them (and p2-e2e must agree on the
  spawn command line).
- The linker allowlist is judged through `compile`: a worker whose static check is right but whose Linker defines
  extra names is not distinguishable from outside, since a refused module is never instantiated.
- The previous-request handle case can only go red on the cordon path (a fork child is a fresh process).
- Audit before effect is shown on one SQLite insert held by the oracle's write lock (≤ 0.8 s; the module's wall_ms
  is raised to 1000 so the worker's wall bound does not end the request while the effect is held). Other engines and
  op kinds rely on the same code path in the subject.
- Escaped-worker cases presuppose that the supervisor execs `p2.worker` with the command line above; a subject that
  spawns differently fails them (by design: the decoder must be exercised).
- Side channels (I4 microarchitectural) and I3 external effects are "assume golden" (§H) and not judged; the
  trap-after-effect case accepts a staged write that was rolled back (0 rows) as long as the authorized op is audited.
- Trap codes are untrusted classification (F14); the worker level checks them against the case's set because the
  reference and F14 define them, the host level never relies on them.
