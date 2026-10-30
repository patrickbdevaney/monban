# crs-diff: cross-request-state differential oracle (units P4-oracle-crs-001, P4-crs-001)

Two families, one differential idea. A piece of state that a server carries from one request to the next and that
can determine a response or an authorization decision must depend only on the **scope** of the request that uses
it, never on an earlier request in a **different** scope. CRS scope σ = (cert-chain hash, authority, principal |
PUBLIC, auth context, epoch) (SPEC_INVARIANTS CRS C1–C8 + C5b "R2 two-scope differentials").

```
oracles/crs-diff/run --family tls-resume --subject target/release/aegis
oracles/crs-diff/run --family data --subject target/release/crs-subject --pg <dsn> --redis <url>
oracles/crs-diff/run --self-test [--family tls-resume|data]        # default: both families
```

Stdlib Python only (`python3 -I`). Last line is `CRS-DIFF: PASS|FAIL (...)` or `CRS-DIFF SELF-TEST: PASS|FAIL (...)`;
exit 0 only on PASS. The `tls-resume` family needs the host `openssl` CLI (the resumption client) and mints a
throwaway ECDSA P-256 certificate per run (OpenSSL 3.0 lacks X25519MLKEM768, so a P-PUBLIC-WEB listener is used, as
the notes in the unit require). The heavy release build is the gate command's job, not `run`'s.

## Family `tls-resume` — the nginx CVE-2025-23419 shape

A TLS session minted while the handshake served one scope must never be **Reused** once the handshake selects a
different scope. The checker mints a session on the open vhost (`a.test`, a context with no client-certificate
verification, ALPN `http/1.1`) and then attempts to resume it under scopes that differ in exactly one coordinate of
σ:

| cross-scope attempt | σ coordinate | spec clause |
|---|---|---|
| resume under a different vhost (`b.test` real / `secure.test`, mTLS, in the replica) | cert-chain hash / authority / verifier | CRS C2, R-PQC-6, ARCHITECTURE R-STATE-5 |
| resume under a different ALPN (`h2` vs `http/1.1`) | ALPN | CRS C2, R-PQC-6 |
| resume after an epoch bump (config reload / key change) | epoch | CRS C5/C5b |

**PASS** iff no cross-scope handshake is ever `Reused`. A same-scope resume (every σ coordinate identical) is
*allowed* and is deliberately **not** counted as a violation, so the oracle also accepts a correct future scoped
ticketer (P2-tls-002) instead of only a no-resumption server.

### Honest scope (binding; PLAN.md "Infeasible or blocked", unit notes)

Against today's aegis the real-binary run **passes by construction**: aegis issues no TLS 1.3 session tickets
(`send_tls13_tickets = 0`, `NoServerSessionStorage`) and has no mTLS listener, so nothing is ever resumable and no
cross-scope reuse is possible. This run is **not** evidence that ticket scoping is correct — there is no scoped
ticketer yet to be correct. The gate's teeth are entirely in:

1. the **self-test**, where an in-oracle vulnerable server reproducing the CVE-2025-23419 shape must go red; and
2. its role as a **regression guard**: when P2-tls-002 lands a scoped ticketer and/or an mTLS listener, this gate
   turns red the moment a ticket minted in one scope is accepted in another.

The vulnerable replica is a Python `ssl` server (per the unit notes): an SNI callback switches the connection to a
client-cert-verifying context (`secure.test`) *after* the base context has already accepted a resumption ticket it
minted on the open context (`a.test`), so the client-certificate check is skipped on resumption. This is caught (and
the cross-ALPN reuse on the same context is caught too). The safe control (no tickets issued, like today's aegis)
must pass, so the self-test proves both red-on-mutant and clean-on-good.

## Family `data` — two-scope data differential (C5b, R2)

The same request is run under scope A and then under scope B over the PG pool, the Redis connection, the
statement/type cache, the idempotency store and the outbox; B's observable state must never depend on A.

Checks (each a two-scope differential):

| check | spec clause |
|---|---|
| no backend connection shared across tenants; B's session tenant GUC is B's own tenant | C8, R-DB-5 (Valkey CVE-2025-67733) |
| an epoch bump reuses neither the pooled connection nor its statement/type cache | C3, C5 |
| a recycled connection carries no residual per-connection state (no ATTACH/temp/stale prepared) | C8, D7 (in-process clarification) |
| the idempotency store is keyed by principal — B never retrieves A's stored outcome | C2, C6 |
| the outbox is scoped by principal — B never observes A's entry | C2, NC6 |
| overarching: B's fixed sequence yields identical observations after two different A-prefixes | C5b (R2) |

**PASS** iff no check reports a cross-request leak.

### Subject wire protocol (what P4-crs-001's `crs-subject` must implement)

One JSON object per line on **stdin**; one JSON reply per line on **stdout** (stderr ignored). Tenants are 16 lower-
case hex digits of a u64 (`aegis_data_ir::tenant_text`). The subject connects to the engines itself from the `--pg`
/ `--redis` arguments the oracle appends to its argv; the oracle reads only the observation fields below and never
touches the engines directly.

```
{"op":"hello"}                                    -> {"ok":true}
{"op":"scope","principal":P,"tenant":T,"epoch":E} -> {"ok":true}
{"op":"do","kind":"sql"}                          -> {"conn":<str>,"guc":{"tenant":<str>},
                                                      "temp_residual":<bool>,"cache":<str>}
{"op":"do","kind":"idem","key":K,"value":V}       -> {"idem":<stored value|null>,"fresh":<bool>}
{"op":"do","kind":"outbox","entry":X}             -> {"outbox":[<entries visible under the current scope>]}
{"op":"bye"}                                       -> (exit)
```

- `scope` sets the scope for every following `do` until the next `scope`.
- `do kind=sql` models one data request end to end: acquire a pooled backend for the current scope, report its
  connection identity (`conn`, e.g. `pg_backend_pid`), the session tenant GUC observed on it (`guc.tenant`),
  whether a residual per-connection object was present **at acquire time** (`temp_residual`, C8/D7), and the
  statement/type cache identity it is bound to (`cache`); do the work; return the backend to the pool (reset on
  checkin). The connection key must be per (tenant, epoch); the cache must not survive an epoch bump.
- `do kind=idem` stores the outcome under (principal, key) and returns the prior outcome if one exists.
- `do kind=outbox` enqueues (principal, tenant, entry) and returns the entries visible under the current scope.

The self-test drives this same protocol against an in-oracle reference subject (the empty mutant set) and six
reference mutants, each of which must be caught: `shared-pool`, `pool-key-no-tenant`, `pool-key-no-epoch`,
`no-reset-on-recycle`, `idem-key-without-principal`, `outbox-no-principal`. The first five are the mutants named in
the unit's `acceptance.must`.

## Provenance

Written for these units; no executable research artifact was ported (the research material for this gate is
descriptive). Specification sources, all in-repo:

- `spec/SPEC_INVARIANTS.md` — CRS C1–C8 + C5b (incl. the Phase-4 D7 in-process clarification), NC6, F7.
- `research/ARCHITECTURE.md` — R-STATE-5 (line 292, "recycled objects reset"; nginx CVE-2025-23419 as a permanent
  regression), R-PQC-6 (line 208, "ticketer per (cert-chain hash, verifier, ALPN, epoch); no resumption on mTLS
  listeners"), R-DB-5 (no backend connection shared across tenants; Valkey CVE-2025-67733), threat table line 149
  and ticket evidence line 719.
- Phase-4 decision D7 (`units/phase-4/PLAN.md`) — C8 for in-process engines.

## In-repo runs (2026-10-30, laptop)

- `run --self-test` → both families PASS (tls: vulnerable replica caught [cross-vhost + cross-ALPN], safe control
  clean; data: reference clean, all 6 mutants caught).
- `ci/heavy.sh cargo build --release --locked -q -p aegis-bin` then
  `run --family tls-resume --subject target/release/aegis` → `CRS-DIFF: PASS (tls-resume: no cross-scope session
  reuse; ... no resumable session issued (tickets off))` — the by-construction PASS described above.
- The `--family data` real-subject run (against `target/release/crs-subject` over live pg17 + valkey) belongs to
  P4-crs-001, which builds that subject; this oracle supplies the checker and the data self-test.

## Known limits

- The real `tls-resume` pass is by construction today (no ticketer, no mTLS listener); see "Honest scope". It
  becomes load-bearing only once P2-tls-002 exists.
- OpenSSL 3.0 is the client, so the handshake is classical-only (P-PUBLIC-WEB); the PQ key-exchange path is not
  exercised here. Resumption scope, not key exchange, is what this oracle measures.
- The data family's correctness rests on the subject reporting its true connection identity, GUC, residual-state
  and cache observations; the oracle cannot see inside a subject that lies about them (same trust boundary as every
  subject-driven oracle here).
