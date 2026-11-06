# P7-adapter-crdb-001 report (implementer, 2026-11-06)

Gates: `lowering-read-crdb`, `lowering-write-crdb`, `schema-gate-crdb` (gates/phase-7.toml, kamrui), plus every carried PG
gate. Spec: PREFLIGHT D-P7.8, spikes/q4-005, the subject contract in reports/P7-oracle-adapters-001.md.

## What changed (write scope only)

| file | change |
|---|---|
| `crates/aegis-adapter-pg/build.rs` | With `CARGO_FEATURE_CRDB` only: compiles `OUT_DIR/crdb_pins.rs` (`CRDB_FLOORS: &[(maj, min, patch)]`, `CRDB_BLOCKED_SERIES`) from every `kind = "crdb"` pin. The floor must be exactly `major.minor.patch`. The pinned `version` must be in the floor's series and at or above it. The build fails closed on no allowed crdb pin, two floors for one series, or a series that is both allowed and blocked. Without the feature, crdb entries are skipped as before. |
| `src/lower.rs` | `Dialect { Postgres (default), #[cfg(feature="crdb")] Crdb }`, `#[non_exhaustive]`, so feature unification cannot break exhaustive matches elsewhere. Adds `render_dialect`, `render_op_dialect`. Only the upsert guard differs: crdb uses `"t"."tenant"::text = excluded."tenant"::text COLLATE "C"` (q4-005 finding 2). `UPSERT` is never rendered. `render` / `render_op` call these with `Postgres` and produce byte-identical output (unit test). |
| `src/schema.rs` | Adds `check_live_schema_dialect(conn, ns, declared, deadline, dialect)`. `check_live_schema` is that function with `Postgres` and is unchanged. Crdb follows refsubject.py `crdb=True`: it skips pg_database (`default` is byte order), exclusion constraints, rules, partitioning, `pg_partition_tree` and RLS (CockroachDB leaves relrowsecurity NULL); `coalesce(collprovider, '')` (NULL on CockroachDB); referenced table names come from a pg_class join instead of `::regclass`. |
| `src/crdb.rs` (feature `crdb`) | Version gate from `SELECT version()` (`server_version` is 13.0.0) against `CRDB_FLOORS`: same series, patch at or above the floor, pre-release / blocked / unknown series refused. Also `connect_admitted(cfg, pinned)` with a recheck on reconnect, and the bounded SERIALIZABLE retry (below). Unit tests cover the floor, refusals, recheck, the upsert-guard form, retry/backoff, the bound, non-retryable codes and the deadline. |
| `src/version.rs` | `AdmittedVersion::new` (`pub(crate)`, crdb only). |
| `src/lib.rs` | `pub mod crdb` (cfg), re-exports `Dialect`, `render_dialect`, `render_op_dialect`, `check_live_schema_dialect`. |
| `subjects/crdb-subject/src/{main,lowering,gate,json}.rs` | Replaces the stub. `lowering [--mutant drop-tenant]` is protocol v2, dialect `crdb` only; `rls_*` / `kv_*` / merge / cte / replace / raw_sql are refused. `lowering.rs` is pg-subject's with the dialect switched, so the IR mapping is identical. `schema` serves mode `crdb` (crdb gate connect + `check_live_schema_dialect(Crdb)`, namespace = schema) and `static`. |

### SERIALIZABLE retry

`crdb::run_serializable(conn, &RetryPolicy, deadline, body)` runs
`BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE; body; COMMIT` and retries the whole transaction on SQLSTATE 40001
only, at BEGIN, in the body or at COMMIT:

- **Failed attempts.** Each failed attempt is rolled back first. If the ROLLBACK fails, it stops; it never retries on top of an open transaction.
- **Bounds.** `max_attempts` (default 32, in 1..=`MAX_ATTEMPTS_CAP` 256, otherwise `BadPolicy`); capped exponential backoff (1 ms doubling to 64 ms); no attempt starts after the deadline.
- **Non-retryable errors.** 40003 (completion unknown) and every other error are final.
- **Rolled-back COMMIT.** A COMMIT whose tag is not `COMMIT` (the server rolled back an aborted transaction) is a failure.

`retry_serializable(policy, deadline, sleep, attempt)` is the loop without the connection (unit-tested).

## Gates

crdb, on kamrui, commands verbatim from gates/phase-7.toml via `ci/remote.sh --host kamrui`:

```
schema-gate-crdb          SCHEMA-GATE: PASS (every counterexample refused with its class, every golden accepted; crdb=20 engine_pin=[crdb=25.4.19]; 11.8s)
  selftest                SCHEMA-GATE SELF-TEST: PASS (12/12 mutants caught over crdb; reference passes through the subject protocol; dead subject caught; subject passes; 190.5s)
lowering-write-crdb       LOWERING-WRITE: PASS (cases=14422 families=13 W1=0 W2=0 W4=0 W6=0 W7=0 E=0 FORM=0 REFUSE=0 BIND=0 ACL=0 engine_pin=[crdb=25.4.19])
  selftest                LOWERING-WRITE SELF-TEST: PASS (17/17 mutants caught; positive control PASS; subject drop-tenant caught)   (crdb-reference-guard FORM=65, crdb-upsert-stmt W1=166)
lowering-read-crdb        LOWERING-READ: PASS (cases=300526 generated_unique[crdb=100000] ... leak=0 widen=0 miss=0 gap_vs_2vl(info)=32541 errors=0 unrefused=0 engine_pin=[crdb=25.4.19])   wall 1190.8 s
  selftest                LOWERING-READ SELF-TEST: PASS (11/11 mutants caught; research naive LEAKs reproduced; positive control PASS; subject drop-tenant caught; pin fixtures 12/12)
```

Carried PG gates, on the laptop via ci/heavy.sh + ci/engines.sh (15 GB free; kamrui refuses the laptop pg image ids):

```
pg-version-floor          PG-VERSION-GATE: PASS (subject: 52 cases (45 matrix + 7 reconnect); floors 17.11,18.6, blocked [19])
  selftest                PG-VERSION-GATE SELF-TEST: PASS (offline: reference clean on 52 cases, 9/9 mutants red)
pg19-blocked              PG-VERSION-GATE: PASS (live, subject: 19rc1=refuse 17.11=accept; floors 17.11,18.6, blocked [19])
  selftest                PG-VERSION-GATE SELF-TEST: PASS (... live 19rc1=refuse 17.11=accept: reference clean, mutants red: pg19-allowed,wrong-field)
schema-gate-pg            SCHEMA-GATE: PASS (... pg=37) x2 (pg17, pg18)   [re-run on the final source]
  selftest                SCHEMA-GATE SELF-TEST: PASS (18/18 mutants caught over pg; ...)   [re-run on the final source]
lowering-write-pg         LOWERING-WRITE: PASS (cases=31740 families=28 W1=0 ... engine_pin=[pg17=17.11, pg18=18.6])
  selftest                LOWERING-WRITE SELF-TEST: PASS (16/16 mutants caught; positive control PASS; subject drop-tenant caught)
lowering-read-pg          LOWERING-READ: PASS (cases=801056 generated_unique[pg=100000] ... leak=0 widen=0 miss=0 ... engine_pin=[pg17=17.11, pg18=18.6])
  selftest                LOWERING-READ SELF-TEST: PASS (6/6 mutants caught; ...; subject drop-tenant caught; pin fixtures 12/12)
```

The lowering-*-pg and version gates ran before the last two schema.rs edits. Both edits are inside `if crdb`
branches (the crdb relrowsecurity read and the collprovider coalesce). The `Postgres` path is textually unchanged,
and schema-gate-pg was re-run on the final source.

Also run: `cargo clippy --all-targets -D warnings` on aegis-adapter-pg + pg-subject (default) and on
aegis-adapter-pg `--features crdb` + crdb-subject: clean. `cargo test -p aegis-adapter-pg` with and without `crdb`: ok.
`cargo fmt --check`: clean.

## Infeasible / residual

Nothing infeasible; no check, oracle or limit was changed. No INFEASIBLE_REPORT.md.

- **Rung.** The renderer and schema gate are R2: executed differential at ENGINE_PIN 25.4.19 on kamrui, single node,
  in memory. The 40001 retry is unit-tested against injected errors (R1). No live contention test was run: `tests/` is
  outside the write scope, and no oracle drives concurrency. q4-005's probe is the live evidence that whole-transaction
  retry is exactly-once.
- **No RLS on crdb.** As decided in P7-oracle-adapters-001, tenant isolation on crdb rests on the rendered tenant
  conjunct, the upsert guard and the schema gate. There is no defence-in-depth policy.
- **Pool reset on crdb.** checkin/pool (C8 reset, NC3) were not changed or exercised against CockroachDB. P7-bin-001
  should check that the reset statements the pool issues are accepted by CockroachDB before wiring `adapter-crdb`.

## API for P7-bin-001 (all behind `aegis-adapter-pg/crdb`, i.e. aegis-bin `adapter-crdb`)

- `aegis_adapter_pg::Dialect::{Postgres, Crdb}` (non_exhaustive), `Dialect::is_crdb()`.
- `aegis_adapter_pg::render_op_dialect(op, schema, table, Dialect::Crdb) -> Result<Rendered, RenderError>` (and
  `render_dialect(&Lowered, &PgTable, Dialect)`); `render_filter` is dialect-independent.
- `aegis_adapter_pg::check_live_schema_dialect(&mut Connection, namespace, &Schema, deadline, Dialect::Crdb) ->
  Result<LiveTable, LiveSchemaError>` (no new error variants).
- `aegis_adapter_pg::crdb::connect_admitted(&ConnectConfig, Option<&AdmittedVersion>) -> Result<(Connection,
  AdmittedVersion), CrdbConnectError>` (`Wire(wire::Error)` | `Refused(CrdbVersionRefusal)`). Use it instead of
  `aegis_adapter_pg::connect_admitted`, which refuses CockroachDB (server_version 13.0.0). Pass `Some(&admitted)` in the
  pool connect closure for the R-DB-1 recheck.
- `aegis_adapter_pg::crdb::{admit_version, recheck, parse_version, CRDB_FLOORS, CRDB_BLOCKED_SERIES}`.
- `aegis_adapter_pg::crdb::run_serializable(&mut Connection, &RetryPolicy, deadline, |conn, attempt| -> Result<T,
  wire::Error>) -> Result<(T, attempts), TxnError>`, with `RetryPolicy::default()` (32 attempts, 1 to 64 ms backoff) and
  `TxnError::{Failed, Exhausted, Deadline, BadPolicy}`. The connection must be idle on entry. The body must not
  BEGIN/COMMIT itself and must be safe to re-run. `retry_serializable` is available for a custom executor.
