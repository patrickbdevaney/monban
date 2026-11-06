# P7-adapter-mysql-001 report (implementer, 2026-11-06, base 41f7c06)

Gates: `lowering-read-mariadb`, `lowering-write-mariadb`, `schema-gate-mariadb` (gates/phase-7.toml, remote kamrui).
All three gates PASS, and so do their self-tests. Nothing is infeasible, and no check was weakened. Only files in
the unit's write_scope changed (`crates/aegis-adapter-mysql/src/**`, `subjects/mariadb-subject/src/**`) plus this
report. No dependency was added: the crate uses the pre-wired aegis-types, aegis-data-ir and aws-lc-rs (SHA-1).
rustix(time) is pre-wired but unused.

## What was built

| file | content |
|---|---|
| `packet.rs` | Pure codec. `Rd` is a bounds-checked cursor (no indexing, no panics). It handles lenenc, the v10 handshake, OK / ERR / EOF, ColumnDefinition41, binary rows, prepare-OK and auth replies. A declared string length larger than the payload is refused. |
| `auth.rs` | `mysql_native_password` scramble on aws-lc-rs `SHA1_FOR_LEGACY_USE_ONLY`, with a KAT against the Python reference. |
| `dsn.rs` | `mysql://` / `mariadb://` DSN with percent-decoding. The host must be **loopback** (`127/8`, `::1`, `localhost`), otherwise `NotLoopback`: there is no TLS path yet. Keys: only `connect_timeout` and `io_timeout`. `Debug` redacts the password. |
| `version.rs` | Version gate. The floor comes from `supply-chain/engine-pins.toml` `[engines.mariadb] floor`, read with `include_str!` (no build.rs, no drift). The rule is the same series (major.minor) and >= floor; pre-release and non-MariaDB servers are refused. It runs **before any credential is sent**. |
| `conn.rs` | The wire client (details below). |
| `lower.rs` | The renderer of `aegis_data_ir::Lowered` in the q4-005 mandated forms. |
| `schema.rs` | Live `information_schema` gate (`check_live_schema`), in the reference `_my_check` order. |
| `mariadb-subject` | `lowering [--mutant drop-tenant]` (protocol v2) and `schema` (protocol v1, modes `mariadb` and `static`). Structured like pg-subject. Its `json.rs` is copied from pg-subject. |

**Wire client:**
- Handshake v10 and HandshakeResponse41.
- Capabilities never include MULTI_STATEMENTS, LOCAL_FILES, SSL or DEPRECATE_EOF.
- Auth always answers with mysql_native_password, then handles AuthSwitchRequest (native only, at most 3 rounds). A switch to `caching_sha2_password`, or AuthMoreData, is refused as `MysqlError::CachingSha2Refused`. Its message says that TLS is needed, and to use a native account on loopback. Every other plugin is refused, including `mysql_clear_password` and old-password.
- **The only commands are COM_STMT_PREPARE / COM_STMT_EXECUTE / COM_STMT_CLOSE / COM_QUIT.** There is no COM_QUERY in the client at all. Session setup and `BEGIN/COMMIT/ROLLBACK` are prepared statements too.
- Parameters are LONGLONG or VAR_STRING, always bound.
- Every sequence id is checked.
- A logical packet over `max_packet` (16 MiB default) is refused before anything is allocated.
- Results are capped by `Limits` (4096 columns, 1e6 rows, 64 MiB).
- The connect deadline covers TCP + handshake + auth + session pin. A per-command deadline is applied as a socket read/write timeout.
- Any I/O, framing or protocol error marks the connection broken, and it is never reused. A server ERR leaves it usable.
- Session pin: `sql_mode = STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION,ERROR_FOR_DIVISION_BY_ZERO`. The client then verifies, with a select, that the mode is strict and that `character_set_client/connection/results` = utf8mb4.
- `is_reusable` requires: not broken, no open transaction, empty buffer, and a nonblocking peek that finds the idle socket would block.

**Renderer forms:**
- String atoms are `CAST(c AS BINARY) <op> CAST(? AS BINARY)`.
- Prefixes are `LEFT(CAST(c AS BINARY), ?) = CAST(? AS BINARY)`, where `?` is the UTF-8 byte length.
- Int atoms are `c = ?` on int columns only. A class mismatch gives `FALSE`. An `Other`-class column is refused.
- Every atom is wrapped in `CASE WHEN c IS NULL THEN NULL ELSE .. END`.
- UPDATE has no RETURNING. Instead, `Rendered::returning_select` = `SELECT <post-image> FROM t WHERE <same lowerQ> FOR UPDATE`, and `Connection::run` refuses to run it outside a transaction (`NotInTransaction`).
- DELETE and INSERT use `RETURNING`.
- An upsert with update columns uses ODKU with `c = IF(CAST(t AS BINARY) = CAST(VALUES(t) AS BINARY), VALUES(c), c)`.
- An upsert without update columns uses `INSERT .. SELECT .. FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM t WHERE <binary own key>)`.
- Refused:
  - an upsert unless (tenant, key) is the sole unique key;
  - an insert or upsert on a table with any unique key that lacks the tenant;
  - any write whose FK does not map tenant to tenant;
  - a written value whose class differs from its column's.

**Schema gate:**
- The checks, in order: NotATable, UnknownField, the F4 probe (TenantFieldNullable / NonBinaryCollation / UpsertArbiterNotTenantScoped), GeneratedTenant, TenantNotText, TriggerOnCollection, ForeignKeyAction, NonTransactionalEngine.
- Collation mapping per the W3 amendment: `*_nopad_bin` / VARBINARY / int are Binary; CHAR / BINARY / `*_bin` are PadSpace; `*_ci` is CaseInsensitive; anything else is Nondeterministic.
- SUB_PART or a non-BTREE index counts as a prefix index.
- One addition runs after all oracle classes, so it cannot mask any of them: `NonUtf8Charset(f)`, for a string column that is neither utf8mb4 nor binary. The byte-length prefix test depends on UTF-8.

## Gates and self-tests (kamrui, MariaDB 11.8.9 pin)

```
schema-gate-mariadb   cmd:      SCHEMA-GATE: PASS (every counterexample refused with its class, every golden accepted; mariadb=25 engine_pin=[mariadb=11.8.9]; 0.2s)
                      selftest: SCHEMA-GATE SELF-TEST: PASS (13/13 mutants caught over mariadb; reference passes through the subject protocol; dead subject caught; subject passes; 4.7s)
lowering-write-mariadb cmd:     LOWERING-WRITE: PASS (cases=18022 families=16 W1=0 W2=0 W4=0 W6=0 W7=0 E=0 FORM=0 REFUSE=0 BIND=0 ACL=0 engine_pin=[mariadb=11.8.9])   wall 162 s
                      selftest: LOWERING-WRITE SELF-TEST: PASS (19/19 mutants caught; positive control PASS; subject drop-tenant caught)
lowering-read-mariadb cmd:      LOWERING-READ: PASS (cases=400532 generated_unique[mariadb=100000] ... leak=0 widen=0 miss=0 gap_vs_2vl(info)=39936 errors=0 unrefused=0 engine_pin=[mariadb=11.8.9])   wall 489 s
                      selftest: LOWERING-READ SELF-TEST: PASS (12/12 mutants caught; research naive LEAKs reproduced; positive control PASS; subject drop-tenant caught; pin fixtures 12/12)
```

The commands are verbatim from gates/phase-7.toml, each run as `ci/remote.sh --host kamrui bash -c '<cmd>'`. The
lowering-write run includes schema-gate-demo rows that show W4/E counts. They are information-only, on schemas the
schema gate refuses, as with the reference. Every verdict family is all zeros.

Other checks:
- `cargo clippy --locked -p aegis-adapter-mysql -p mariadb-subject --all-targets -- -D warnings` (kamrui): clean.
- `cargo test`: 22 unit tests pass:
  - packet: random and truncated input never panics;
  - fake-server tests: caching_sha2 switch refused, clear-password plugin refused, below-floor server gets no credentials, oversize packet and bad sequence id refused, hung server times out within the connect deadline;
  - DSN loopback refusals;
  - version gate;
  - renderer forms;
  - FK / unique guards;
  - collation mapping;
  - scramble KAT.
- `cargo fmt --check` and `cargo xtask layering` (`LAYERING: PASS`).

Rung: R2. These are executed differentials of the production renderer and the live gate at the engine pin, on
kamrui, against the oracle's own engine client. The wire client is covered by unit and fake-server tests, plus the
schema-gate runs, which connect, auth, pin the session and run prepared catalog queries over it. The client is
non-golden until the integrator records these gates. It is then golden at R2 per q4-005.

## Adapter API for P7-bin-001

```rust
use aegis_adapter_mysql::*;
ConnectConfig::from_dsn(&str) -> Result<ConnectConfig, MysqlError>      // loopback only; connect_timeout, io_timeout, max_packet
connect(&ConnectConfig) -> Result<Connection, MysqlError>               // = Connection::connect: TCP, handshake, native auth, version gate, session pin
Connection::execute(&mut self, sql, &[Param]) -> Result<QueryResult, MysqlError>          // prepared, io_timeout deadline
Connection::execute_until(&mut self, sql, &[Param], Instant) -> Result<QueryResult, MysqlError>
Connection::{begin, commit, rollback}(&mut self) -> Result<(), MysqlError>
Connection::run(&mut self, &Rendered) -> Result<QueryResult, MysqlError> // returning_select first (needs an open txn), then the statement
Connection::{is_reusable(&mut self), terminate(self, Duration), in_transaction, is_broken, server_version, version, set_limits}
check_live_schema(&mut Connection, namespace: &str, declared: &Schema, deadline: Instant) -> Result<LiveTable{schema, table: MyTable}, LiveSchemaError>
LiveSchemaError::class() -> Option<String>                              // protocol vocabulary; None = inspection failed
render_op(&Op, &Schema, &MyTable) -> Result<Rendered, RenderError>      // lower_op(Exact) + render; run authorize() first
render(&Lowered, &MyTable), render_filter(&SqlExpr, &MyTable, alias: Option<&str>) -> Result<Statement, RenderError>
Rendered { stmt: Statement { sql, params: Vec<Param> }, returning_select: Option<Statement> }
Param::{Int(i64), Text(String)};  QueryResult { columns: Vec<ColumnDef>, rows: Vec<Vec<Cell>>, affected_rows, last_insert_id }
Cell::{Null, Int, UInt, Float, Text, Bytes, Temporal}
MysqlError::{Dsn, NotLoopback, Connect, Io, Timeout, Protocol, PacketTooLarge, ResultTooLarge, Auth, CachingSha2Refused,
             VersionRefused, Session, Server(ServerError), Params{..}, NotInTransaction, Broken}
```

Intended host order per op:
1. `authorize`.
2. `check_live_schema` once per collection (cache the `LiveTable`).
3. `render_op(op, &live.schema, &live.table)`.
4. `begin`.
5. `run`.
6. `commit` (or `rollback` on error).

The stub's `MysqlError::Unimplemented` and `ConnectConfig { dsn, connect_timeout }` are gone. Nothing outside this
unit's scope used them.

## Residuals (for the integrator / P7-bin-001)

* **Not exercised live by any gate:**
  - `Connection::begin/commit/rollback/run`. The oracles execute the subject's SQL through their own Python client.
  - The ODKU / NOT EXISTS / RETURNING forms are validated by the gate, but the Rust client's execution of them is not.

  P7-bin-001 should add a live e2e test. A `crates/aegis-adapter-mysql/tests/` file is outside this unit's
  write_scope.
* **No pool or NC3 checkin path** like aegis-adapter-pg's. The client is one blocking connection.
  - Reuse needs `is_reusable()`.
  - A broken connection must be dropped.
  - There is no CancelRequest equivalent (MariaDB uses `KILL QUERY` on a second connection). This is not built.
* **Concurrency:** the oracles are single-connection.
  - The NOT EXISTS upsert form can raise a duplicate-key error under a race. That fails closed as an error, never as a cross-tenant write.
  - The FOR UPDATE emulation relies on InnoDB row locks, which the schema gate enforces.
* **The version floor is read at compile time** from engine-pins.toml. A pin bump needs a rebuild, which cargo triggers automatically.
* **caching_sha2_password, TLS and non-loopback servers are refused by design** until a TLS path exists (D-P7.8).
