# proxy-e2e: reverse-proxy end-to-end oracle (unit P2-proxy-001)

Black-box oracle for the Phase-2 reverse proxy (`aegis --config ...`). A stdlib-Python recording upstream stores
exactly the bytes it receives; the oracle drives `aegis` over TLS and compares what the client sent, what the
upstream saw and what came back.

## Usage

```
oracles/proxy-e2e/run --subject target/release/aegis [-v]
oracles/proxy-e2e/run --self-test [--mutant-subject <bin>] [-v]
```

`run` execs `python3 -I e2e.py` (stdlib only). The last line is `PROXY-E2E: PASS (...)` / `PROXY-E2E: FAIL (...)`
(exit 0 only on PASS) or `PROXY-E2E SELF-TEST: PASS|FAIL (...)`. Needs the `openssl` CLI (mints a throwaway
ECDSA P-256 self-signed certificate per run; P-PUBLIC-WEB only signs with ECDSA-P256-SHA256). HTTP/2 is exercised
with `curl --http2` when `curl -V` lists `HTTP2`; otherwise only h1 runs and the PASS line says so.

## Subject interface

`<subject> --config <file> --cert <pem> --key <pem> --audit-dir <dir>`; admin endpoint from the config's
`admin.bind` (`/healthz` for readiness, `/metrics`); SIGHUP = config reload; SIGTERM = stop. Every run uses fresh
ports (bound to 0, then released) and a temp dir that is removed afterwards.

## What is checked (spec ids from `spec/SPEC_INVARIANTS.md`)

| check | clause |
|---|---|
| GET `/api/%7euser/%c3%a9?b=2&a=%7e1&b=3` with `Host: AEGIS.test:<port>`: upstream request line is exactly `GET /api/~user/%C3%A9?b=2&a=~1&b=3 HTTP/1.1`; one `host` = canonical authority `aegis.test:<port>`; `x-test` value OWS-trimmed; every field name lowercase; `Connection`, `Keep-Alive` and the field `Connection` names are not forwarded; no framing fields on a bodyless request | CANON-4, CANON-1/2, H1 grammar (d), R-TLS-3 |
| POST with a **chunked** client body: upstream sees `content-length` = body length, no `transfer-encoding`, body byte-exact; POST with Content-Length likewise | CANON-4, H1 grammar (d) |
| upstream response hop-by-hop fields (`Connection: x-hop`, `X-Hop`, `Keep-Alive`) are not relayed to the client | RFC 9110 §7.6.1 |
| `/exact` forwarded as `/exact`; `/exact/` is a different canonical form → 404, not forwarded; `/api/dir/` forwarded with its slash | CANON-2 / q4-008 trailing slash |
| query `z=1&a=2&z=3&%41=x` forwarded in order (only the RFC 3986 §6.2.2 repair `%41`→`A`); `a=%zz` → 400, not forwarded | CANON-2 / q4-008 opaque query |
| `/api//x?q=1` → 308 `Location: /api/x?q=1`, never forwarded; `/api/a/../b` → 400 | CANON-2 / q4-008 empty segments, dot segments |
| SNI `aegis.test` + `Host: other.test` (a configured vhost) → 421, not forwarded; SNI = Host `other.test` → 200 | CANON-6 |
| route without `authz` → 403, GET and POST, upstream never sees it; `authz` naming a policy other than `allow-all` → 403 | INV-NONEMPTY, F8 `authz` |
| h2 (curl): same canonical forwarding as an HTTP/1.1 request with regenerated framing; `:authority` other.test → 421; no-authz → 403; `//` → 308 | CANON-4, CANON-6, INV-NONEMPTY |
| admin `/metrics`: `# TYPE` line for every golden family (`aegis_admission_rejects`, `aegis_budget_debits`, `aegis_crash_budget_trips`, `aegis_cert_seconds_to_expiry`, `aegis_fips_status`, `aegis_config_generation_hash`, `aegis_config_lkg_fallbacks`, `aegis_upgrade_forced_closes`), ends with `# EOF`; `aegis_budget_debits_total{scope="ip"}` and `aegis_proxy_authz_denied_total` move with traffic; serving cert gauge ≈ 30 d; `/healthz` 200 | ARCHITECTURE §3.10 metrics gate, CERT-1 |
| bad reload (syntax error; and a schema-valid config the assembly refuses: a `static` route) + SIGHUP: `aegis_config_lkg_fallbacks_total` increments, the old config still forwards and still denies | CFG-3 |
| two requests share one upstream connection (pool works); a changed config applied by SIGHUP → the next request uses a **new** upstream connection | CRS C3/C5 |
| no arguments → exit 78; config with an unknown field (listener on a known port) → exit 78 and nothing ever accepted a connection on that port; missing config file → exit 78 | INV-NONEMPTY (fail-closed boot), CFG-1 |

**PASS** iff every check passes.

## Self-test (negative controls)

The subject is `target/e2e-mutants/release/aegis` (built through `ci/heavy.sh` with `--features e2e-mutants`
into its own target dir if missing; the feature is off in every shipped build and adds env-var hooks only). The
unmutated run of that build must PASS first; then each mutant, selected with `AEGIS_E2E_MUTANT`, must FAIL:

| mutant | behaviour | caught by |
|---|---|---|
| `raw-path` | forwards the raw request target instead of `Canon<RoutePath>` + `Canon<Query>` | `get.request-line`, `query.opaque`, `h2.regenerated-h1` |
| `skip-authz-deny` | a route without `authz` is allowed | `noauthz.*`, `h2.noauthz.403` |
| `skip-lkg` | a failed reload drops the served config (empty table) and does not count | `lkg.*` |

## Provenance and in-repo runs

Written for this unit; no research artifact was ported. Results recorded at implementation time (2026-10-25,
laptop): `run --subject target/release/aegis` → `PROXY-E2E: PASS (48 checks)`; `--self-test` → `PROXY-E2E SELF-TEST: PASS
(3/3 mutants caught: raw-path, skip-authz-deny, skip-lkg)`.

## Known limits

- The upstream is HTTP/1.1 only (stdlib has no h2 server), so the h2 *upstream* framing (`"framing": "h2"`) and UDS
  upstreams are not exercised here.
- Admission rejects (401/429/503) are not driven: the provisional limits are far above what one client produces.
- The fail-closed boot check observes the port for ~5 s of process life by connecting; a socket bound and closed
  within one probe interval would be missed (the process exits in milliseconds, before any bind, by construction).
- The upgrade path (SIGUSR2) is not exercised here; `oracles/upgrade-harness` is the gate for UP-1..7.
