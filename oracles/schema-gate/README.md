# schema-gate: counterexample-schema oracle (P4-oracle-schema-001)

Checks that the data-plane schema gate (F4 `check_schema` plus the adapters' live R-DB-7 `check_schema()`) refuses
every counterexample schema with the expected error class **and** accepts every golden schema. Accepting the goldens
matters: an adapter that refuses everything is red.

Spec clauses (`spec/SPEC_INVARIANTS.md`): **§E lowering soundness** (`refines_necessary`: tenant and key columns
need binary, deterministic collations), **INV-WRITE-SUBSET W3** (the arbiter is exactly (t, key), the table's ONLY
unique index, full length, binary, deterministic and NO PAD), **W5** (closure over triggers, data-modifying CTEs and
FK actions; Phase 4 decision **D8** refuses them outright), the **CRS C8 clarification for in-process engines**
(decision **D7**), and the W-forms "FORCE RLS + explicit WITH CHECK". ARCHITECTURE §3.8 R-DB-7 item (2): live
`check_schema()` (binary collations, no citext/NOCASE, partition-key opclass = the column's). D4: the tenant is a
16-digit lowercase hex TEXT column with a binary collation.

## Run

```
oracles/schema-gate/run                       # static + sqlite against the reference subject (~0.5 s)
oracles/schema-gate/run --static --subject 'target/release/datair-subject schema'
oracles/schema-gate/run --engine sqlite --subject 'target/release/sqlite-subject schema'
ci/engines.sh with pg17 -- oracles/schema-gate/run --engine pg --dsn @pg17 --subject 'target/release/pg-subject schema'
oracles/schema-gate/run --self-test [--static] [--engine sqlite] [--engine pg --dsn ...]
```

Without a mode flag, the run covers `static` and `sqlite`. `-v` prints one line per case. The last line is
`SCHEMA-GATE: PASS (...)` or `SCHEMA-GATE: FAIL (...)`. The exit code is 0 only on PASS. **The PG target must be
throwaway:** the oracle runs `create extension citext`, creates the collations `ci_nd` and `nd_canon` in `public`,
and drops and recreates the schema `monban_sg` for every case. SQLite cases are fresh files in a temporary directory.
The subject is started once, with the current directory as its working directory.

## Subject protocol (`--subject "<cmd>"`)

The oracle writes one JSON object per line to stdin and reads exactly one JSON object per line from stdout. Every
request has `v` (=1), `id` and `op: "schema"`. The reply must echo `id`, and carry exactly one of
`"ok": true` or `"refuse": "<Class>"`. The oracle compares only the text before the first `(`, so
`NonBinaryCollation(0)` (Rust `Debug` of `SchemaError::NonBinaryCollation(0)`) matches `NonBinaryCollation`.
Anything else is a protocol failure, and the case fails: no reply within 60 s, a missing id, both keys, or an
`error` reply.

```json
{"v":1,"id":1,"op":"schema","mode":"static","schema":{ F4 Schema }}
{"v":1,"id":2,"op":"schema","mode":"sqlite","path":"/tmp/schema-gate-x/case03.sqlite","collection":"notes","declared":{ F4 Schema }}
{"v":1,"id":3,"op":"schema","mode":"pg","dsn":"postgresql://postgres:pw@127.0.0.1:5xxxx/postgres","namespace":"monban_sg","collection":"notes","declared":{ F4 Schema }}
-> {"v":1,"id":1,"ok":true}   |   {"v":1,"id":1,"refuse":"UpsertArbiterNotTenantScoped"}
```

F4 Schema JSON uses the field names of `crates/monban-data-ir/src/ir.rs`:
`{"collection","tenant_field","columns":[{"field","name","nullable","collation":"Binary|PadSpace|CaseInsensitive|Nondeterministic","key"}],"permitted":[...],"unique_indexes":[{"fields":[...],"prefix":bool}]}`.

* **static.** Admission means `check_schema(probe, schema, Fidelity::Exact)` returns `Ok`, where
  probe = `Op{collection: schema.collection, kind: Upsert, filter: Tt, writes: [], returning: []}`. A schema must be
  fit to host every OpKind, because an F8 endowment can grant Upsert. The checks run in ir.rs order, and every
  counterexample has a single cause.
* **sqlite / pg.** `declared` is what an F8 config would state: the column names, which field is the tenant, which
  are keys, and the permitted columns. It is always the honest, all-Binary declaration with one (tenant, id)
  arbiter. The subject must **introspect the live catalog** for collations, NULL-ability, unique indexes, types,
  triggers, rules, FKs, RLS and partitioning, never trust `declared` for them, and then apply the F4 checks plus the
  live-only ones below. SQLite: open `path` read-only and look only at schema `main`. PG: connect to `dsn` and look up
  `namespace`.`collection`.

### Refusal classes

| class | F4 `SchemaError`? | meaning |
|---|---|---|
| `TenantFieldNullable` | yes | tenant column admits NULL (live: `notnull`/`attnotnull`; a SQLite rowid-table PK admits NULL unless declared NOT NULL) |
| `NonBinaryCollation` | yes | tenant or key column, or a unique-index key part over one, not byte-wise, deterministic and NO PAD: NOCASE, RTRIM, application-defined collations, citext, char(n)/bpchar, ICU (deterministic or not), any PG collation other than `C`/`POSIX` (`default` only when the database default is libc C/POSIX) |
| `UpsertArbiterNotTenantScoped` | yes | the unique-key set is not exactly one full-length, plain-column (tenant, key) index: missing tenant, a second unique index, a SQLite `INTEGER PRIMARY KEY` rowid alias, expression or prefix key parts, a partial index, a PG exclusion constraint, or no index at all |
| `TenantNotText` | no (adapter) | tenant column without TEXT affinity (SQLite) or not text/varchar (PG). Under INTEGER affinity, `'00000000000001e5'` and `'0000000000100000'` both store as 100000 and capture each other's rows; the self-test reproduces this |
| `GeneratedTenant` | no (adapter) | tenant is a generated column, so its post-image is not the bound tenant (W2) |
| `TriggerOnCollection` | no (adapter) | a user trigger on the collection, or on any of its partitions (W5, D8) |
| `RuleOnCollection` | no (adapter) | a PG rewrite rule other than `_RETURN` on the collection or a partition (W5, D8) |
| `ForeignKeyAction` | no (adapter) | an FK with an ON DELETE/UPDATE action other than NO ACTION/RESTRICT, from or into the collection (W5, D8) |
| `PartitionKeyMismatch` | no (adapter) | the PG partition key's opclass is not the column type's default for the strategy, its collation is not the column's, or it is an expression (R-DB-7) |
| `RlsNotForced` | no (adapter) | PG table without `relrowsecurity` and `relforcerowsecurity`, or without any policy |
| `RlsPolicyWithoutCheck` | no (adapter) | an ALL/INSERT/UPDATE policy without an explicit WITH CHECK (W-forms) |
| `RlsPolicyNotTenantScoped` | no (adapter) | a permissive policy expression that does not compare the tenant column with `current_setting(...)`, or that contains an OR or a `true` escape |
| `NotATable` | no (adapter) | the collection is a view or a (SQLite) virtual table |

F4 `SchemaError` has no variants for the live-only classes, and F4 is frozen (outside this unit's write scope). So
these classes are protocol vocabulary that the adapter error types (monban-adapter-sqlite/-pg) must carry next to
`SchemaError`. Whether to add them to F4 is a decision for the integrator.

## Corpus

**Static (20: 7 golden, 13 counterexamples).** Goldens: a (tenant,id) arbiter; the same arbiter listed as
(id,tenant); a non-key CaseInsensitive column; a non-key Nondeterministic column; two key columns; tenant at field 3;
tenant flagged as key. Counterexamples: nullable tenant; tenant CaseInsensitive, Nondeterministic (ICU level2,
q4-005 `en_u_ks_level2`) and PadSpace (q4-005 MariaDB `utf8mb4_bin`); key CaseInsensitive and PadSpace; PK without
tenant; second UNIQUE(id) (q4-005 reproducer 4); second UNIQUE(tenant,x) (q4-005 reproducer 5); prefix key part
`tenant(3)` (q4-005 reproducer 3); no unique index; an arbiter wider than (t,key); a tenant-only arbiter.

**SQLite (29: 8 golden, 21 counterexamples).** Goldens are the five lowering-oracle SQLite layouts (untyped,
NUMERIC, NOCASE data column with a plain index, STRICT ANY, STRICT typed), each with
`tenant text not null` and PK (tenant,id), plus: a composite PK WITHOUT ROWID with explicit COLLATE BINARY on a text
key; a sole unique index in place of a PK; a `varchar(16)` tenant. Counterexamples: nullable tenant; a rowid-table
PK(tenant,id) without NOT NULL; tenant NOCASE; tenant RTRIM (the PAD SPACE analogue); tenant with an
application-defined collation (D7: needs per-connection registration); WITHOUT ROWID with a NOCASE key column; a
sole unique index with COLLATE NOCASE over a BINARY tenant; tenant INTEGER affinity; tenant `any` in a non-STRICT
table (NUMERIC affinity); `id INTEGER PRIMARY KEY` only; a rowid alias plus UNIQUE(tenant,id); a second UNIQUE(id);
a prefix analogue `(tenant, substr(id,1,3))`; an expression arbiter `(lower(tenant), id)`; a partial unique index; a
trigger; an FK into the collection with ON DELETE CASCADE; an FK out of the collection with ON UPDATE SET NULL; a
generated tenant; a view; an fts5 virtual table (D7: module registration is per-connection).

**PG (36 or 37: 7 golden, 29 or 30 counterexamples).** Every golden and every counterexample that is not about RLS
has `ENABLE` + `FORCE ROW LEVEL SECURITY` and a policy
`USING (tenant = current_setting('monban.tenant')) WITH CHECK (same)`. Goldens are the lowering-oracle PG layouts
with a `"C"` tenant and PK (tenant,id): deterministic default collation, ICU ks-level2, ICU und with a plain index,
and citext on the data column `x`; plus a varchar tenant with a text key, both C; a sole unique index with separate
SELECT/INSERT policies; and a table partitioned by `list(tenant)` with one partition. Counterexamples: nullable
tenant; tenant citext, `ci_nd`, `und-x-icu` (deterministic, non-C), char(16) and bigint; a ci_nd key column; a sole
unique index with COLLATE ci_nd over a C tenant; PK without tenant; a second UNIQUE(id); a prefix analogue
`(tenant, left(id,3))`; an expression arbiter; an expression unique index beside the PK; a partial unique index; an
exclusion constraint `EXCLUDE USING btree (id WITH =)`; partition by `hash (tenant text_pattern_ops)`; a trigger on
the collection; a trigger on a partition; a DO ALSO rule; an FK in with CASCADE and an FK out with SET NULL; a
generated tenant; no RLS; RLS not forced; a FOR ALL policy without WITH CHECK; a policy `USING (true) WITH CHECK
(true)`; an extra permissive `FOR SELECT USING (true)`; a policy with an OR escape; a view. When the database default
collation is not C/POSIX, the run adds "tenant with the default collation" (the postgres images default to
`en_US.utf8`, so this case runs on pg17/pg18).

## Pass criterion

In every selected mode, every counterexample is refused with one of its expected classes and every golden is
accepted. The oracle must not hit a protocol error, and it must not hit a setup error: if a DDL statement fails, the
oracle FAILs rather than skipping the case.

## Self-test (negative controls)

`--self-test` first runs the reference subject (`refsubject.py serve`) **through the process protocol** as the
positive control. It must pass. Then it runs each mutant of the reference over that mode's corpus, and every
mutant must produce at least one failing case:

| mutant | modes | caught by (examples) |
|---|---|---|
| refuse-all | all | every golden rejected |
| accept-all | all | every counterexample accepted |
| ignore-collation | all | NOCASE / RTRIM / citext / ICU / PadSpace accepted |
| ignore-second-unique | all | UNIQUE(id), rowid alias, exclusion constraint |
| ignore-prefix-index | all | static prefix flag, partial unique index |
| ignore-nullable-tenant | all | nullable tenant |
| class-blind (right decisions, constant class) | all | wrong class |
| ignore-index-collation | sqlite, pg | unique index with COLLATE NOCASE / ci_nd over a binary column |
| ignore-triggers | sqlite, pg | trigger on the collection / partition |
| ignore-fk-actions | sqlite, pg | CASCADE / SET NULL FKs |
| ignore-generated | sqlite, pg | generated tenant |
| ignore-tenant-type | sqlite, pg | INTEGER / NUMERIC affinity, bigint |
| ignore-not-a-table | sqlite, pg | view, fts5 (wrong class) |
| declared-not-introspected (trusts `declared`) | sqlite, pg | every counterexample accepted |
| ignore-rowid-alias | sqlite | rowid alias + UNIQUE(tenant,id) |
| ignore-rules, ignore-exclusion, ignore-rls, ignore-partition | pg | DO ALSO rule; exclusion; RLS cases; text_pattern_ops |

It also checks that a subject which exits at once fails the oracle. With sqlite selected, it reproduces two
hazards in Python's SQLite, showing they are real rather than a matter of taste: (1) INTEGER affinity, where an
upsert for tenant `0000000000100000` overwrites tenant `00000000000001e5`'s row and returns it; (2) a NOCASE arbiter,
where tenant `...AB` overwrites tenant `...ab`.

## Re-run in repo (2026-10-30, Python 3.12, SQLite 3.45.3 (Python's), postgres:17.11-alpine and 18.6-alpine via ci/engines.sh)

* `run`: `SCHEMA-GATE: PASS (every counterexample refused with its class, every golden accepted; static=20 sqlite=29; 0.4s)`
* `run --self-test`: `SCHEMA-GATE SELF-TEST: PASS (22/22 mutants caught over static+sqlite; reference passes through the subject protocol; dead subject caught; 5.5s)`
* `ci/engines.sh with pg17 -- run --engine pg --dsn @pg17`: `SCHEMA-GATE: PASS (...; pg=37; 0.7s)`, and
  `--self-test`: `SCHEMA-GATE SELF-TEST: PASS (18/18 mutants caught over pg; ...; 11.0s)`
* The same pair on pg18 (18.6): PASS, pg=37, and SELF-TEST PASS 18/18.
* The gate self-test forms `--self-test --static` (7/7) and `--self-test --engine sqlite` (15/15) both PASS.

## Provenance (in-repo inputs; no research artifact was executed)

| sha256 | path | used for |
|---|---|---|
| 79af59aa6990e85f78dcf62c27ff0fb479d684f38a867e9e19f9a88a494a4a90 | crates/monban-data-ir/src/ir.rs | Schema/Collation/SchemaError layout, `check_schema` order (ported in `refsubject.py`) |
| 99c60c0e0d599d4ec7cfd7e90e609a65eb43a1b2180f17f82936b1345d2ae4dc | spec/SPEC_INVARIANTS.md | §E, W3, W5, C8 (D7) |
| f728d518fd3f1d304e1c63cbcdbbf685133da4e123c2483fcf7cc057648d24f6 | spikes/q4-005/README.md | PadSpace, second UNIQUE(id), UNIQUE(tenant,x), prefix key part, ICU level2 counterexamples |
| 09ef3bb1bcbe877571dbe7fbee6914e987ebdb3680f86f196cc72f0fcedcbcec | spikes/q4-005/verdict.json | W3 amendment text |
| e5774a4bbb32420a9fcaf4288b62085c5cf59d687bdbaff94ac6a40e792be5b4 | oracles/lowering-read/lowir.py | `pgwire.py` is a verbatim copy of its `PgError`/`Pg` (lines 570-700); lowering-read/-write schema layouts (goldens) and `ci_nd`/`nd_canon` collations |

## MariaDB and CockroachDB modes (P7-oracle-adapters-001, PREFLIGHT D-P7.8, spikes/q4-005)

```
ci/engines.sh with mariadb -- oracles/schema-gate/run --engine-pin --skip-sqlite --subject 'target/release/mariadb-subject schema' --engine mariadb --dsn @mariadb
ci/engines.sh with crdb    -- oracles/schema-gate/run --engine-pin --skip-sqlite --subject 'target/release/crdb-subject schema' --engine crdb --dsn @crdb
ci/engines.sh with mariadb,crdb -- oracles/schema-gate/run --self-test --skip-sqlite --engine mariadb --dsn @mariadb --engine crdb --dsn @crdb
```

New flags (all modes): `--dsn` is repeatable and routed by scheme (`mysql://` = mariadb; a `postgresql://` DSN is
crdb iff `version()` says CockroachDB); `--engine-pin` checks each live engine against
`supply-chain/engine-pins.toml` (same rule as `lowir.pin_check`); `--skip-sqlite` only stops the default
static+sqlite modes. `--self-test --subject CMD` (new; it used to be an error) runs the usual reference + mutant
self-test and then requires CMD to pass the same corpus.

Requests: `{"v":1,"id":N,"op":"schema","mode":"mariadb","dsn":"mysql://..","namespace":"monban_sg","collection":"notes","declared":{F4 Schema}}`
(namespace = the database the oracle drops and recreates per case) and the same with `"mode":"crdb"` and a
`postgresql://` DSN (namespace = schema in `defaultdb`). As for pg, the subject must introspect the live catalog,
never `declared`.

**MariaDB corpus (25: 5 golden, 20 counterexamples).** Goldens: tenant `utf8mb4_nopad_bin` + int id PK(tenant,id);
tenant `VARBINARY`; text key `nopad_bin`; a sole unique index; a non-key `general_ci` column with a plain index.
Counterexamples: nullable tenant; tenant `utf8mb4_bin` (PAD SPACE, q4-005 reproducer 1), `general_ci` (2), the 11.8
default `uca1400_ai_ci`, `uca1400_as_cs`, `CHAR(16) nopad_bin`, `BINARY(16)`; a `general_ci` key column; tenant
`BIGINT` (TenantNotText); PK without tenant; second `UNIQUE(id)` (4); second `UNIQUE(tenant,x)` (5);
`PRIMARY KEY (tenant(3), id)` (3); no unique index; trigger; FK cascade in; FK set-null out; generated tenant
(MariaDB generated columns cannot be NOT NULL, so TenantFieldNullable or GeneratedTenant); a view; a MyISAM table.
Collation mapping (W3 amendment): Binary only for VARBINARY, integer types and `*_nopad_bin`; `CHAR`/`BINARY` and
`*_bin` -> PadSpace; `*_ci` -> CaseInsensitive; anything else -> Nondeterministic. A `SUB_PART` or non-BTREE (long
unique HASH) index is a prefix index.

New refusal class **`NonTransactionalEngine`** (adapter, mariadb only): the collection's storage engine is not InnoDB.
MyISAM / MEMORY / Aria ignore transactions and row locks, and the mandated MariaDB UPDATE RETURNING form
(`SELECT .. FOR UPDATE` + `UPDATE` in one transaction) depends on both.

**CockroachDB corpus (20: 4 golden, 16 counterexamples).** Goldens: STRING tenant + INT8 id PK; STRING key;
varchar(32) tenant; a non-key `COLLATE en_u_ks_level2` column with an index. Counterexamples: nullable tenant (PK(id)
+ unique(tenant,id)); tenant `COLLATE en_u_ks_level2` (q4-005), `en_u_ks_level1`, `de`; a collated key column; tenant
INT8 and BYTES (TenantNotText); PK without tenant; second `UNIQUE(id)`; expression and partial unique indexes beside
the PK; FK cascade in / set-null out; a trigger; a computed tenant; a view. The reference reuses the pg introspection
with `crdb` flavour: a plain STRING has collation `default`, which is byte order on CockroachDB; a COLLATE'd STRING has
no pg_collation row (never binary); no rules / exclusion constraints / PG partitioning; **no RLS requirement** (RLS is
not part of the crdb dialect).

Mutants: mariadb = the common seven + ignore-triggers, ignore-fk-actions, ignore-tenant-type, ignore-not-a-table,
declared-not-introspected, ignore-engine (ignore-index-collation and ignore-generated have no isolating
counterexample on MariaDB: no per-index collation, no NOT NULL generated column); crdb = the common seven without
ignore-prefix-index + the live list without ignore-index-collation (no per-index-column COLLATE; every CockroachDB
table has a primary key, a hidden rowid one otherwise, so an expression / partial unique index is always a second
unique index and the prefix flag is masked by the only-unique-index check). The unit's "NOCASE / uca1400_ai_ci tenant accepted
-> red" is ignore-collation (and accept-all) on the `uca1400_ai_ci`, `general_ci` and `en_u_ks_level2` cases.

## Known limits

* **Stricter than the F4 doc comment.** `Collation::Binary` says "PG "C" or deterministic ICU". This gate refuses
  every PG collation except C/POSIX (the unit lists "PG non-C collation" as a counterexample, and D4 says binary).
  Equality under a deterministic collation is byte-wise, but ordering and the unique-index opclass are not. Flag
  for the integrator: amend the doc comment, or relax the `und-x-icu` and default-collation cases.
* RLS policy scoping is a textual heuristic over `pg_get_expr`: it requires the tenant column and
  `current_setting(`, with no OR and no `true`. A policy such as `tenant = tenant OR ...` is caught, but a scoped-looking
  expression that is not semantically tenant-scoped (a volatile function, a `current_setting` of another GUC) is
  not. Which roles a policy applies to, BYPASSRLS, and superuser connections are not checked (that is
  P4-pg-001/R-DB-1 territory).
* D8 data-modifying CTEs are a property of rendered statements, not of a schema. They are covered by the denylist
  and lowering-write, not here. Policies or defaults that call data-modifying functions are not detected.
* D7 coverage is limited to what a schema can show: application-defined collations and virtual-table modules
  (per-connection registration). ATTACH/DETACH, temp objects and per-request PRAGMAs are runtime connection
  behaviour (the F4 `denylist(Sqlite)` and crs-data), and this gate cannot observe them.
* The SQLite DDL is created with Python's SQLite 3.45.3. The subject reads the file at its own pin (3.54.1), and the
  file format is compatible. The reference reads the effective column collation from `EXPLAIN` (P4 of the Eq
  opcode). A Rust subject may use `sqlite3_table_column_metadata`.
* PG unique-index opclasses (for example `text_pattern_ops`) and SQLite/PG CHECK constraints are not judged.
  Partitions are checked for triggers and rules, but not for their own unique indexes or RLS (queries go through
  the parent).
* MariaDB/MySQL/CockroachDB counterexamples (q4-005) enter the static corpus only. Those engines are not golden in
  Phase 4.
