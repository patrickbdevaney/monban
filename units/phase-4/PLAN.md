# Phase 4 plan: data plane + native handlers "A/D" (draft, spec author, 2026-10-30, base 67d279d)

Scope (IMPLEMENTATION_PLAN §3): data-ir; PG/SQLite/Redis adapters; state (idempotency, outbox, latch); SDK B2 with
streaming (q4-001 passed, F7b frozen); adapter-host. The phase is conditional (q4-003: justified only by agent-infra
evidence and velocity, not procurement), so the operator should confirm GO before wave 1. Gate file: `gates/phase-4.toml`
(57 gates = 34 carried from Phase 3 + 23 new). Units: 24 JSON files here.

## Gate → unit (each Phase-4 gate is in exactly one unit's acceptance)

| plan gate | gates in phase-4.toml | unit |
|---|---|---|
| read oracle leak=0 ∧ miss=0, ≥100k at ENGINE_PIN | lowering-read-sqlite / -pg / -redis | P4-sqlite-001 / P4-pg-002 / P4-redis-001 |
| write oracle hardened forms 0/300 per family | lowering-write-sqlite / -pg / -redis | same three |
| schema gate refuses every counterexample | schema-gate-static / -sqlite / -pg | P4-datair-001 / P4-sqlite-001 / P4-pg-002 |
| INV-NONEMPTY 100k/adapter | nonempty-props; unrestricted-ledger (boot + Unrestricted CI-gated) | P4-host-001; P4-config-001 |
| allowlist lock regenerates byte-identically | allowlist-lock | P4-datair-001 |
| cancel sweep green + self-test red ≤100 seeds | cancel-sweep | P4-pg-003 |
| CRS differentials incl. nginx CVE-2025-23419 replica | crs-tls; crs-data | P4-oracle-crs-001; P4-crs-001 |
| trybuild ≥25/32, residual as frozen | sdk-trybuild | P4-oracle-trybuild-001 |
| crash harness incl. double fault | crash-harness (full ~170k images, remote) | P4-state-001 |
| PG minor floor asserted | pg-version-floor | P4-pg-001 |
| PG19 blocked until ON CONFLICT fix | pg19-blocked | P4-pg-001 |
| no pg_query in aegis-bin graph | no-pg-query-in-bin | P4-spec-002 |
| (added) F7b host obligations, APPLIED q4-001 | sdk-host | P4-host-001 |
| (added) INV-IDEMP, NC2 latch, NC6 outbox | state-props | P4-state-002 |
| (added) modes A/D end to end, NC1/NC2/NC7 | native-e2e | P4-bin-001 |

Every new gate has a selftest that turns red on a mutant (listed in each unit's `oracles` / `acceptance.must`). Seven
carried Phase-3 gates still have no selftest (hygiene, tests, audit, fail-closed-boot, build-subjects, config-totality,
systemd-hardening); unchanged here.

## Roles

Oracles and harness pieces are spec-author units, so every oracle exists outside the implementer's write scope and has
gone red before an implementer is assigned (§2). This differs from Phase 3, where P3-egress-001/P3-pdp-001 wrote their
own oracle. Implementer units never touch Cargo.toml/Cargo.lock: P4-spec-002 pre-wires every third-party and path edge.
New `subjects/*` crates join the workspace by the existing glob; the integrator re-locks path-only entries at merge
(lock-targets and lock-age must show no third-party version change).

## Unit graph and waves (→ = depends on)

```
W0  start now:   P4-spec-001  P4-spec-002  P4-engines-001  P4-oracle-nonempty-001  P4-oracle-state-001
W0b (after the W0 unit named):
    engines-001 → P4-oracle-lowering-001, P4-oracle-schema-001, P4-oracle-crs-001, P4-oracle-pgver-001
    spec-002    → P4-oracle-trybuild-001 (owns gate sdk-trybuild), P4-oracle-host-001
    spec-001 + engines-001 → P4-oracle-e2e-001
W1  P4-datair-001   → spec-001, spec-002, oracle-schema
    P4-pg-001       → spec-002, engines, oracle-pgver          (wire client, SCRAM, version gate)
    P4-redis-001    → spec-001, spec-002, oracle-lowering
    P4-state-001    → spec-002, oracle-state                   (store; crash harness)
    P4-config-001   → spec-001, oracle-nonempty
W2  P4-sqlite-001   → datair, oracle-lowering, oracle-schema
    P4-pg-002       → pg-001, datair, oracle-lowering, oracle-schema   (renderer + live schema introspection)
    P4-state-002    → state-001                                (idempotency, outbox, latch)
W3  P4-pg-003       → pg-002, state-002, oracle-state          (pool, NC3, C8 reset; cancel DST subject)
    P4-host-001     → datair, sqlite-001, pg-002, redis-001, state-002, oracle-nonempty, oracle-host
W4  P4-crs-001      → pg-003, redis-001, state-002, oracle-crs
    P4-bin-001      → host-001, pg-003, config-001, oracle-e2e (wires apps/notes into aegis-bin)
GO  python3 -I ci/run-gates.py --phase 4
```

Critical path: spec-001 → datair → pg-002 → pg-003 → bin-001 (and host-001). Waves are logical. The machine limit is
≤2 compiling agents (heavy.sh 6 GB). Oracle units are mostly Python and run beside them; O-trybuild and the
lowering exec helper do compile. Write scopes are disjoint for every pair of units not ordered by depends_on (checked
by script; the only textual overlap, spec-002's `supply-chain/**`, explicitly excludes engines-001's engine-pins.toml).
Units that share a crate (pg-001 → pg-002 → pg-003; state-001 → state-002; spec-001 → datair) are chained.

## Live engines (no apt/sudo; Docker images ≤500 MB)

`ci/engines.sh` (P4-engines-001) starts throwaway containers on loopback, pinned by digest, and refuses images over
500 MB. Images that fit: postgres:17-alpine and postgres:18-alpine (≈270–290 MB; Debian postgres:17 at 454 MB also
fits), postgres:19rc1 (461 MB, already local, the only PG19 image), valkey/valkey:alpine (45 MB), redis:alpine
(119 MB). Out: mysql:8.4 (829 MB) and the supabase postgres image (1.24 GB). SQLite needs no image: the oracle runs it
at the adapter pin (3.53.2, via rusqlite =0.40.2 bundled in an oracle-local workspace), not Python's 3.45.3. Docker
gates run locally (no `remote`), because the LAN box is not known to have Docker. If it does, mark them remote.

## Spec decisions needed before wave 1 (spec author / operator)

- **D1 F4 has no allowlist lock format and no capability-set type.** IMPLEMENTATION_PLAN F4 says "Op IR + Adapter +
  allowlist lock format", but ir.rs has neither, and has no way to express INV-NONEMPTY's "Unrestricted is explicit".
  Proposal (P4-spec-001): additive types only (CapSet with no empty constructor, canonical lock format, denylist as
  data, EnginePin), keeping the Op/Pred/Schema layout so F10 (which mirrors Op) stays byte-compatible.
- **D2 F7 cannot be hosted as frozen.** `Ctx`, `Granted` and `Tx` have private fields and no constructor anywhere, so no
  host crate can mint them. Option (a): `aegis_sdk::host` minting functions, with the owner (aegis-adapter-host)
  enforced by xtask OWNERS. Weakness: xtask scans only workspace crates, so an out-of-tree app could call `host::`;
  trybuild cannot catch this, only the lint tier can. Option (b): move the host driving loop into aegis-sdk so minting
  stays `pub(crate)`, with adapter-host implementing a backend trait. (b) is stronger but grows the SDK trust zone.
  Recommendation: (b) if the SDK owner accepts it, else (a).
- **D3 Driver choice (DEVIATIONS X-10, proposed): owned PG v3 and RESP2 clients.** The budget is 41/60 third-party
  crates. tokio-postgres and redis-rs pull in an estimated 25+ crates (P4-spec-002 measures this with cargo tree and
  records it). NC3's checkin predicate also needs exact protocol truth (txn status, outstanding replies, open objects),
  which tokio-postgres does not expose (#1374). The oracles already speak both protocols in a few hundred lines. This
  follows the X-6/X-9 precedent. rusqlite (bundled C SQLite, about 6 crates) is unavoidable for the SQLite store and
  adapter: add it to the TCB ledger.
- **D4 F8 has no data-plane block** (backends, per-route data endowments, `unrestricted` literal), and the tenant value
  encoding is unspecified (TenantId is a u64, while the oracles use text tenants and Redis uses `t:{hex}:`). Both are
  P4-spec-001.
- **D5 trybuild "25/32, residual as frozen".** The 32 research mutants (M1–M16, N1, N1b, N2–N15) target axum-based async
  B2. F7 is synchronous and axum-free, so N5–N8/N10 become "dependency absent" rejections. ARCHITECTURE says residual
  {M15, M16} after the lint tier; the draft says {M15, M16, N9, N14}. The spec author must freeze the re-expressed
  corpus and residual set in `oracles/sdk-trybuild/expected.txt` before the first run.
- **D6 Synchronous F7 and the cancel sweep (X-11, proposed).** Handlers are sync, so they run on a bounded blocking
  pool, as the PDP client does, and cancellation points are host-call boundaries rather than handler futures. The
  cancel-sweep README must be amended (P4-oracle-state-001), otherwise "await" events have no meaning for the subject.
- **D7 CRS C8 for an embedded engine.** SQLite has no per-tenant credentials, and pooled connections are shared across
  tenants by construction. Proposal: an F1 clarification that C8 for in-process engines means no per-connection state
  (no ATTACH, no temp objects, PRAGMAs fixed at open), checked by schema-gate-sqlite and crs-data. This is a frozen-F1
  change, so it is not in any unit's write scope.
- **D8 W5 closure.** No oracle checks triggers, data-modifying CTEs or FK actions. Proposal: refuse them outright in the
  schema gate for Phase 4 (P4-oracle-schema-001 counterexamples), rather than prove closure.

## Infeasible or blocked as written

- **PG19 "until ON CONFLICT fix".** Only postgres:19rc1 is available locally, and whether 19.0 GA carries the fix is
  unverified. pg19-blocked therefore asserts refusal of every 19.x. Lifting it is a spec change naming the fixed minor
  plus a passing lowering-write RLS ON CONFLICT family on that image. Not infeasible, but permanently red-to-lift by
  design.
- **CVE-2025-23419 replica against aegis.** aegis disables tickets and has no mTLS listener, so the real-binary run
  passes by construction today. The gate is meaningful only through its self-test (an in-oracle vulnerable server)
  and as a guard for the future scoped ticketer (P2-tls-002). State this in claims; it is not evidence of a scoped
  ticketer.
- **PG floor 18.6.** That postgres:18.6-alpine exists and fits within 500 MB is unverified (no network check made).
  The Valkey/Redis floor for CVE-2025-67733 must be read from the advisory. P4-engines-001 resolves both and must not
  guess.
- **MariaDB/Cockroach (q4-005)** are out of Phase 4 (Phase 7 "more adapters"); their counterexamples enter the schema
  corpus only. MySQL stays non-golden (image 829 MB).

## Open questions

1. Does the LAN box have Docker? If yes, move the engine gates to remote.
2. The full crash-harness run is 30–45 min. Is a remote 2 h HEAVY_TIMEOUT acceptable, or should the gate run the
   reduced size and the full size go nightly?
3. NC6/NC7/NC8: the cancel-sweep model does not check them. state-props covers NC6 and native-e2e covers NC7; NC8
   (drain within T_drain) has no gate. Add one to native-e2e (shutdown during in-flight data requests)?
4. Real-driver regression corpus (sqlx #4393, tokio-postgres #1374, redis-py #2624): with owned drivers, only their
   shapes can be replayed against our client. Is that accepted as coverage?
5. With rusqlite in aegis-bin, budget and the cmvp FIPS lock: SQLite is non-crypto C, but confirm it adds no
   aws-lc/ring node.

---

## Decisions (integrator, 2026-10-30; operator standing authorization "proceed on all phases when each passes")

- **GO condition (q4-003):** met. The justification is agent-infra evidence and velocity: the operator's directive is
  Phases 0→7, and Phases 2–3 each closed in about 2 days of wall time.
- **D1:** accepted. Additive F4 types only (CapSet with no empty constructor, canonical lock format, denylist as data,
  EnginePin). The Op/Pred/Schema layout stays as it is (F10 compatible). Re-freeze in P4-spec-001.
- **D2:** option (b). The host driving loop lives in aegis-sdk and minting stays `pub(crate)`. adapter-host implements a
  backend trait. The SDK stays L1/L2-pure: the trait is the only effect seam, and no tokio or IO enters aegis-sdk.
- **D3:** accepted as DEVIATIONS X-10: owned PG v3 and RESP2 clients. P4-spec-002 records the cargo tree count it
  avoids. rusqlite (bundled) enters the TCB ledger as trusted, unverified C, the same tier as the AWS-LC C code in
  SECURITY_CLAIMS.md.
- **D4:** accepted. P4-spec-001 defines one canonical tenant encoding: TenantId u64 as lowercase 16-digit hex in every
  engine (SQL text column and Redis `t:{hex}:` prefix), and the F8 data block. The oracles adopt the same encoding.
- **D5:** freeze the target residual at ARCHITECTURE's {M15, M16}. N5–N8/N10 count as caught by dependency absence
  (compile_fail with the reason recorded). If N9 or N14 cannot be caught without weakening anything, the unit writes
  INFEASIBLE_REPORT.md. Nobody widens the residual silently. Gate threshold: ≥25/32, and the residual must equal the
  frozen file.
- **D6:** accepted as DEVIATIONS X-11. Sync handlers run on a bounded blocking pool, cancellation points are
  host-call boundaries, and the cancel-sweep README is amended in P4-oracle-state-001.
- **D7:** accepted. F1 clarification: for in-process engines, C8 means no per-connection state (no ATTACH, no temp
  objects, PRAGMAs fixed at open). This goes into P4-spec-001's write scope (spec/SPEC_INVARIANTS.md), with
  `ci/statements.py freeze spec` in the same commit.
- **D8:** accepted. The Phase 4 schema gate refuses triggers, data-modifying CTEs and FK actions outright.
- **Q1:** the desktop has no Docker, so engine gates run locally on the laptop.
- **Q2:** the GO runs the full crash harness remotely, with HEAVY_TIMEOUT 7200. PR checks use the reduced size.
- **Q3:** yes. native-e2e adds NC8: SIGTERM during in-flight data requests, drain within T_drain, and no request acked
  without a durable effect.
- **Q4:** accepted. Shapes of those driver bugs are replayed against the owned clients as regression cases.
- **Q5:** P4-spec-002 asserts with `cargo tree` that rusqlite adds no aws-lc/ring/openssl node and leaves the cmvp lock
  graph unchanged.
- **D9 (from P4-oracle-schema-001):** the ten live-only schema classes (TenantNotText, GeneratedTenant,
  TriggerOnCollection, RuleOnCollection, ForeignKeyAction, PartitionKeyMismatch, RlsNotForced, RlsPolicyWithoutCheck,
  RlsPolicyNotTenantScoped, NotATable) stay adapter error types that wrap F4 `SchemaError`. F4 is not re-frozen for
  them.
- **D10:** on PG the gate accepts only `C`/`POSIX` collations (and `default` only when the database default is C).
  That is stricter than the frozen F4 `Collation::Binary` comment ("deterministic ICU counts"), because deterministic
  ICU gives binary equality but not binary ordering, and Pfx/range lowering depends on ordering. The comment is fixed
  at the next F4 re-freeze; until then the gate is authoritative. Limit: RLS tenant scoping is judged from the policy
  text, so a policy can look scoped without being scoped. Claims must say this.
- **Finding:** a SQLite tenant column with INTEGER affinity stores some distinct 16-hex tenants as the same number
  (e.g. `00000000000001e5` and `0000000000100000` both become 100000), which turns a tenant-scoped upsert into a
  cross-tenant overwrite. Refused as TenantNotText and reproduced by the self-test.
- **D11 (from the finished lowering families, 2026-10-30): KV listing.** Redis/Valkey ACLs cannot key-restrict SCAN, so
  a per-tenant user holding `+scan` could list every tenant's key names. The reference `kv_acl` therefore grants only
  GET/SET/DEL, and the KV adapter refuses `kv_plan` Scan (Select Tt/Pfx) at runtime under the per-tenant user
  (`Unsupported`, fail closed). The renderer still produces the escaped pattern, because the read oracle checks
  rendering. Phase 7 / backlog: tenant-scoped listing via a per-tenant index key (ZRANGEBYLEX on `t:{hex}:<coll>:__idx`).
- **D12: Redis `default` user.** RESET logs a connection in as `default`, and ACL rules cannot block it. The adapter's
  provisioning connection must check at boot that `default` is disabled or has no permissions, and refuse to start
  otherwise. ci/engines.sh containers are throwaway and exempt; the native-e2e and crs runs must provision it that way.
- **R-DB-8 restated:** the ON CONFLICT WHERE peek reproduces on 17.11 and 18.6 too. Only the mandated composite-arbiter
  form with no user WHERE protects us, and claims must say so. PG19 stays blocked (19 also leaks through DO SELECT via a
  security_barrier view).
