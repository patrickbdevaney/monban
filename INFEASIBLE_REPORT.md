# INFEASIBLE_REPORT: P4-bin-001 (native data plane + apps/notes, gate native-e2e)

The data plane, apps/notes and the e2e-mutants negative controls are implemented and committed. The unit's
acceptance cannot pass from inside its write scope, for the reasons below. No check, oracle or limit was changed.

Acceptance as run on the laptop (2026-10-30, binaries built with `--offline`: the lock needs the integrator's
path-only re-lock for `notes`):

| step | last line |
|---|---|
| `oracles/native-e2e/run --subject target/release/aegis` (SQLite) | `NATIVE-E2E: FAIL (1 failed: sq.nc1.h2-rst-stream-before-cp.no-row)` (§1) |
| `ci/engines.sh with pg17 -- oracles/native-e2e/run --subject target/release/aegis --pg @pg17` | `NATIVE-E2E: FAIL (1 failed: harness)`: exit 78, `schema gate: RlsNotForced` (§3) |
| `oracles/native-e2e/run --self-test --subject target/release/aegis` | `SELF-TEST: FAIL (the unmutated subject must pass first: [sq.nc1.h2-rst-stream-before-cp.no-row])` (§1) |
| `cargo xtask budget` | `BUDGET: FAIL (stripped size 7926936 B > 6000000 B; …)` (§2) |
| scratch oracle copy with §3's RLS provisioning, pg17 | `FAIL (2 failed: sq.…h2-rst-stream…, pg.…h2-rst-stream…)` |
| same copy, h2-RST check skipped, `--self-test`, pg17 | `NATIVE-E2E SELF-TEST: PASS (6/6 mutants caught: tenant-from-path, commit-despite-cancel, body-before-cp, empty-caps-means-all, no-drain, ack-then-drop; backends sqlite+postgres)` |

Green: `cargo xtask allowlist-lock --check` (5 locks), `cargo xtask layering`, workspace clippy `-D warnings`, the new
apps/* ban-list clippy line (red on an injected `std::mem::forget`), aegis-bin/notes tests, `PROXY-E2E: PASS (48
checks)` and its self-test 3/3, `UNRESTRICTED: PASS`, bare `aegis` exit 78.

## 1. h2 `RST_STREAM(CANCEL)` before the commit point is invisible to aegis-bin (blocks native-e2e)

- **Clause:** oracles/native-e2e README "Cancellation": an h2 `RST_STREAM(CANCEL)` before CP rolls the transaction
  back (INV-NOMUT-C NC1). Check `<b>.nc1.h2-rst-stream-before-cp.no-row`.
- **Failing case:** `sq.nc1.h2-rst-stream-before-cp.no-row` (and `pg.…` on PG): the row is committed. This is the
  only failing check of the run against SQLite (`NATIVE-E2E: FAIL (1 failed: sq.nc1.h2-rst-stream-before-cp.no-row)`).
- **Minimal reason:** `aegis-transport` `h2srv::stream_task` awaits `pipeline::finish(app.handle(..))` to completion
  and polls `SendResponse::poll_reset` only afterwards (to skip sending). The `App` trait has no per-stream
  cancellation hook and the stream task keeps the handler future alive after the peer reset, so the assembly cannot
  observe the reset; the connection stays open (the oracle keeps it open past the hold), so no connection-level
  signal exists either. aegis-transport is outside this unit's write scope.
- **Minimal fix (transport owner):** in `stream_task`, race `finish(..)` against `poll_reset` on the stream's
  `SendResponse` and drop the handler future when the peer resets (the same drop the h2 connection teardown already
  does through `tasks.abort_all()`). aegis-bin's `InFlight` drop guard then cancels the commit gate (already wired).
- **Related (worked around, should also move into the transport):** h1 runs hyper with `half_close(true)`, so a client
  FIN while a handler runs is never read (`mid_message_detect_eof` returns Pending) and the handler future is not
  dropped. aegis-bin watches a duplicate of each public socket for read-closed/error readiness while an app handler
  runs; `nc1.h1-close-before-cp` and `nc1.tcp-rst-before-cp` pass with it.

## 2. Binary budget: stripped size 7.93 MB > 6.0 MB once SQLite and PG are linked (blocks `cargo xtask budget`)

- **Clause:** REPO_LAYOUT §6 / R-PERF-1, `cargo xtask budget` (stripped size ≤ 6,000,000 bytes).
- **Failing case:** `target/release/aegis` = 7,926,936 bytes with the data plane (5,335,032 before: main at db1b642).
  The third-party crate count is unchanged (rusqlite and the PG client were already in the graph through the
  pre-wired adapter edges; only dead-code elimination kept them out of the binary until now).
- **Minimal reason:** the bundled SQLite amalgamation (trusted C, D3) compiled at the release profile's opt-level 3 is
  most of the growth (sqlite-subject is 2.47 MB vs datair-subject 0.42 MB). Profiles and `LIBSQLITE3_FLAGS` live in
  the root `Cargo.toml` / build environment, outside this unit's scope (cargo ignores `[profile]` in member manifests).
- **Options (integrator/spec decision):** `[profile.release.package.libsqlite3-sys] opt-level = "z"` in the root
  manifest (measured below), SQLite `SQLITE_OMIT_*` compile options, or re-baselining the §6 size budget for the
  data plane. Measured (temporary, uncommitted root-manifest probe): `opt-level = "z"` for libsqlite3-sys alone gives
  7,027,576 bytes, still over, so a profile tweak on SQLite does not suffice; the decision is a size-budget re-baseline
  for modes A/D or a broader size profile. Everything else in the budget passes: 45/60 third-party crates,
  non-crypto unsafe 4,948/5,000 lines, idle RSS 6.97 MB/8 MB.

## 3. The oracle's PostgreSQL table is refused by the live schema gate (blocks the gate's `--pg @pg17` run)

- **Clause:** R-DB-7 / PLAN D8–D10: `aegis_adapter_pg::check_live_schema` requires ENABLE + FORCE ROW LEVEL SECURITY
  with tenant-guard policies; the unit's instructions require `check_live_schema` at boot (fail closed on refusal).
- **Failing case:** `ci/engines.sh with pg17 -- oracles/native-e2e/run --subject target/release/aegis --pg @pg17` →
  `FAIL harness: subject exited 78 at start: data backend "pg" (postgres): schema gate: RlsNotForced`.
- **Minimal reason:** oracles/native-e2e `Store.setup` creates `notes` without RLS, policy, or the RLS role. Its
  README already says: "If P4-oracle-schema-001 requires more of the schema (e.g. RLS), the spec author amends
  `Store.setup` here." aegis-bin must not rewrite a user table's security policy at boot.
- **Fix (spec author, oracles/native-e2e/e2e.py `Store.setup`):** `CREATE ROLE aegis_app NOLOGIN` (if missing),
  `GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO aegis_app`, `ALTER TABLE notes ENABLE/FORCE ROW LEVEL SECURITY`,
  `CREATE POLICY … FOR ALL TO aegis_app USING (tenant = current_setting('aegis.tenant', true) COLLATE "C") WITH CHECK
  (same)` (the shape of `aegis_adapter_pg::rls_policy`). With exactly that change (a scratch copy of the oracle, not
  committed), the run against pg17 is `NATIVE-E2E: FAIL (2 failed: sq.nc1.h2-rst-stream-before-cp.no-row,
  pg.nc1.h2-rst-stream-before-cp.no-row)`: every other SQLite and PG check passes.

## 4. Redis/Valkey: the buffered MULTI/EXEC commit cannot be sent (not in the gate command; refused at boot)

- **Clause:** PLAN D14 (outcome key in the same MULTI/EXEC under the tenant prefix); README "For KV, writes are
  applied only at commit (MULTI/EXEC)".
- **Minimal reason:** `aegis_adapter_redis::Connection::command` allows only GET/SET/DEL (MULTI/EXEC refused before a
  byte is written), and the per-tenant ACL user is `-@all +get +set +del`. A buffered, atomic commit needs an adapter
  API for a MULTI…EXEC batch and `+multi +exec` in `tenant_acl_rules` (both keyless, so no cross-tenant reach), owned
  by aegis-adapter-redis. Applying buffered writes one by one would not be atomic with the outcome key (a silent D14
  weakening), so aegis-bin refuses a `redis`/`valkey` backend at boot (exit 78) with this reason. The gate runs
  without `--kv`.

## 5. Not infeasible, but for the GO: request context reaches the dispatch seams by (backend, tenant)

aegis-bin may not depend on aegis-sdk (layering: only aegis-adapter-host and apps), so it cannot implement an SDK
backend or `host::Backends` (whose signature names `SdkError`); it drives scopes through adapter-host's
`EngineBackends`/`ScopeBackend`, whose renderer/executor seams see only `(principal, tenant, cancel)` and the op.
The commit gate, the D14 outcome record and the W6 point-op rule therefore find their request by (backend, principal
tenant), and requests of one tenant on one backend run one at a time (the slot is held until the pool task ends).
Correct and fail closed (an executor call without a registered context never reaches the engine), but it serializes
a tenant per backend. Fix (adapter-host owner): pass a per-call context (or the session id) through `ScopeInfo` /
`Backends::open`, or a bin-implementable `Backends` that does not name `SdkError`.
