# q4-005: MariaDB + CockroachDB write oracle (INV-WRITE-SUBSET W1/W2/W4, W3 arbiter)

Plan row: "q4-005 MySQL/MariaDB + CockroachDB write oracle | leaks → extend denylist; adapters non-golden until 0 leaks".
**Verdict: flip.** Both engines leak when you use the naive forms, or the guarded forms on a schema that the gate
should have refused. That extends the denylist and adds engine-specific mandated forms. With those forms and the
amended W3 schema gate, there were **0 leaks in 10 800 cases per engine**, so both can be golden adapters (rung R2).
MySQL was not run: its image is over the size limit.

## Engines and images (sizes measured before pulling)

| engine | image | compressed | uncompressed | used |
|---|---|---|---|---|
| MariaDB 11.8.9 | `mariadb:11.8` @sha256:f16d7a34… | 103.9 MB | 334.5 MB (docker: 329 MB) | yes |
| CockroachDB v25.4.18 CCL | `cockroachdb/cockroach:latest-v25.4` @sha256:bedee431… | 184.5 MB | 464.3 MB (docker: 461 MB) | yes |
| MySQL 8.4 | `mysql:8.4` | 238.3 MB | 829.2 MB | **no** (> 500 MB) |

`image_size.py` gets the exact uncompressed size without storing anything. It streams each amd64 layer from the
registry and gunzips it on the fly. Both images were removed at the end.

## Method

* `q4005.py` imports `oracles/lowering-write/{write_oracle,lowir}.py` unmodified (sha256 8708b73f… / e5774a4b…).
  It reuses that oracle's row and Pred generators, the Lean-model effect prediction, the W1/W2/W4/E checks and the
  family driver. Each case snapshots the whole table, runs `BEGIN`, executes the rendered statement, snapshots
  again and runs `ROLLBACK`.
* `mywire.py` is a stdlib MySQL protocol client: mysql_native_password plus auth switch, binary prepared
  statements with bound parameters. It connects on plaintext loopback.
  CockroachDB uses the oracle's PG v3 client.
* MariaDB renderer (`MariaRenderer`, a new `mariadb` dialect) and CockroachDB renderer (the oracle's postgres
  renderer plus one fix to the upsert guard, see below).
* Configuration: 300 cases × 4 seeds per family per schema (1200). The families are U, D, UP (composite) and UPG
  (global key, which must be refused). Ill-formed requests are 10 % of cases (SET tenant, a row that carries a
  tenant) and must be refused.
* Tenant corpus: `acme ACME Acme "acme " a% evil ss ß`. It covers case, trailing space (PAD SPACE) and ß/ss.
  MariaDB `x/y/grp` use the server default `utf8mb4_uca1400_ai_ci`, and `collation_connection` is
  `utf8mb4_uca1400_ai_ci`. Both are deliberately adversarial.
* Schema-gate demo schemas are run with the same hardened renderer but are reported separately. They are the
  schemas the gate must refuse.
* `probes.py` holds the hand-written reproducers and the CockroachDB SERIALIZABLE retry experiment.

## Results (`run.log`, `results.json`)

Hardened forms, per engine, 9 families, 10 800 cases each:

| engine | schemas | W1 | W2 | W4 | E | engine errors (well-formed) |
|---|---|---|---|---|---|---|
| MariaDB 11.8.9 | id PK + tenant `utf8mb4_general_ci` (U/D, upsert refused); composite PK tenant `utf8mb4_nopad_bin`; composite PK tenant `VARBINARY` | 0 | 0 | 0 | 0 | 0 |
| CockroachDB 25.4.18 | id PK; composite PK; id PK + tenant `COLLATE en_u_ks_level2` (U/D, upsert refused) | 0 | 0 | 0 | 0 | 0 |

The `CAST(c AS BINARY)` atoms (MariaDB) and the `::text … COLLATE "C"` atoms (CockroachDB) neutralise the column
collation for UPDATE and DELETE, even on a case-insensitive tenant column. Only the upsert arbiter depends on the
schema.

Schema-gate demo: hardened upsert renderer, 1200 cases each. These are not in the verdict:

| schema | W1 | W4 | E | blocked |
|---|---|---|---|---|
| MariaDB composite PK `utf8mb4_bin` (binary but **PAD SPACE**) | 0 | **17** | 27 | 10 |
| MariaDB composite PK `utf8mb4_general_ci` | 0 | **86** | 141 | 55 |
| MariaDB composite PK default `uca1400_ai_ci` | 0 | **107** | 176 | 69 |
| MariaDB composite PK `nopad_bin` + second `UNIQUE(id)` | 0 | **528** | 817 | 289 |
| CockroachDB composite PK tenant `en_u_ks_level2` | 0 | 0 | 51 | 0 |
| CockroachDB composite PK + `UNIQUE(id)` | 0 | 0 | 817 | 817 (23505, fail-closed) |

**MariaDB-specific finding:** the tenant IF-guard in `ON DUPLICATE KEY UPDATE` stops the foreign write, but it does
not stop the leak. When the arbiter matches a foreign row, ODKU `RETURNING` still returns that row unchanged.
PostgreSQL's `DO UPDATE … WHERE false` returns nothing in the same situation. So on MariaDB the W3 schema gate is
load-bearing for W4, not only for E.

Self-test (`selftest.json`): every MariaDB mutant (11/11) and every CockroachDB mutant (8/8) was caught.
* Shared mutants: drop-tenant, upsert-global-arbiter, replace-into, returning-star, set-tenant-passthrough,
  upsert-tenant-from-row, like-prefix and refuse-all.
* MariaDB-only: my-column-collation, my-bin-padspace and my-update-returning-naive.
* CockroachDB-only: crdb-upsert-stmt and crdb-column-collation.
* Informational: `pg-no-collate-c` is equivalent on CockroachDB, because `::text` drops a collated string's locale.
  `crdb-reference-guard` (the oracle's PG guard used verbatim) is caught, W1=3 on the collated gate-demo schema.

## Leak reproducers (`probes.log`, `probes.json`)

MariaDB 11.8.9:
1. **PAD SPACE binary.** Composite PK `(tenant utf8mb4_bin, id)`, row `('acme',1,'secret-of-acme')`. Guarded ODKU
   for tenant `'acme '` with `RETURNING tenant,id,x` returns `('acme',1,'secret-of-acme')` (W4/W3).
   `utf8mb4_nopad_bin` inserts a separate row `('acme ',1)`.
2. Same leak with `utf8mb4_general_ci` and tenant `'ACME'`.
3. **Prefix key part.** `PRIMARY KEY (tenant(3), id)` leaks even under nopad_bin: `'acmX'` arbitrates onto
   `'acme'`. The guarded form leaks via RETURNING. The unguarded form overwrites (W1).
4. **ODKU arbiter = any unique index.** With PK(tenant,id) plus UNIQUE(id), the guarded form returns tenant
   evil's row and the unguarded form overwrites it.
5. With PK(tenant,id) plus UNIQUE(tenant,x) there is no foreign capture. But a request for id 99 resolves onto the
   tenant's own id 5, so the arbiter is not (t,id) and E is violated.
6. `REPLACE INTO` deletes the foreign row that conflicts on UNIQUE(id) (W1).
7. `sql_mode=''`, or `INSERT IGNORE` even under STRICT, truncates tenant `'acmeEVIL'` to `'acme'` (W2).
8. `UPDATE … RETURNING` is a syntax error (1064). RETURNING exists only on INSERT, REPLACE and DELETE (10.5+).
9. ODKU affected rows are 0, 1 or 2 for unchanged, inserted or updated. That is an existence signal (W6).

CockroachDB 25.4.18:
1. `UPSERT INTO` always uses the primary key as arbiter and cannot take a guard. On an id-PK table it overwrites
   tenant evil's row and re-tenants it (W1).
2. **The oracle's PG guard is unsound on CockroachDB.** `t.tenant = excluded.tenant COLLATE "C"` on an
   `en_u_ks_level2` column is evaluated under the left operand's collation. Tenant `'ACME'` therefore updates
   tenant `'acme'` (W1). On PostgreSQL the explicit COLLATE wins. The cast form
   `t.tenant::text = excluded.tenant::text COLLATE "C"` correctly does nothing (E only).
3. With a second UNIQUE(id), `ON CONFLICT (tenant,id)` and `UPSERT` raise 23505, which fails closed. Arbiter-less
   `ON CONFLICT DO NOTHING` silently skips the row, which is an existence signal.
4. SERIALIZABLE retries: 8 threads × 40 contended transactions gave 320 commits and 1830 × 40001 retries, with a
   maximum of 58 attempts. Whole-transaction retry produced exactly-once effects and no other errors.

## Decision effect (exact text in `verdict.json`)

* **W3 amendment.** The arbiter must be exactly (t, key) and must be the table's only unique index. Tenant and key
  columns must be byte-exact: binary **and NO PAD**, with no prefix-length key part. MariaDB/MySQL `*_bin` is PAD
  SPACE and does not qualify, so use `VARBINARY` or `utf8mb4_nopad_bin`.
* **F4.** The `Collation::Binary` doc should say "byte-wise, deterministic, NO PAD". PAD SPACE `*_bin` columns and
  prefix key parts should map to a non-Binary collation. `Schema` needs the set of unique indexes (or an attested
  flag) so `check_schema` can refuse Upsert when there is any other unique index.
* **Denylist.**
  * MariaDB/MySQL: REPLACE, `IGNORE` variants, ODKU unless the unique-index set is exactly {(t,key)}, multi-table
    UPDATE/DELETE, LOAD DATA, an unpinned sql_mode, and string comparison under the column collation or a PAD
    SPACE collation.
  * CockroachDB: the `UPSERT` statement, arbiter-less `ON CONFLICT`, and the postgres-dialect guard.
    CockroachDB needs its own dialect id.
* **Mandated forms.** See `verdict.json`. In short:
  * MariaDB: CAST-AS-BINARY atoms. UPDATE RETURNING is emulated with `SELECT … FOR UPDATE` plus `UPDATE` in one
    transaction. Upsert is guarded ODKU behind the gate. When there are no update columns, use
    `INSERT … SELECT … WHERE NOT EXISTS`.
  * CockroachDB: the guard casts both sides to text. Retry the whole transaction on 40001.
* **Golden.** MariaDB yes and CockroachDB yes, each conditional on the forms and the gate above. MySQL no (not
  tested).

## Reproduce

See `verdict.json` → `reproduce`: two `docker run` commands on 127.0.0.1:55721/55722, then `q4005.py` (full run
about 80 s, self-test about 40 s), then `probes.py`.

## Honest limits

* MySQL was not executed. Cockroach was single-node with an in-memory store. W5, W6 and MERGE were not run.
* The UPDATE RETURNING emulation was checked single-session only.
* The renderers are spike Python, not the Rust adapters.
* The measurement runs did **not** go through `ci/heavy.sh`. The heavy lock was queued behind 6 or more other
  agents' cargo and docker builds, so the runs used `nice -n 15` plus a timeout. The workload is a ~20 MB stdlib
  client against containers that were already running. The reproduce commands use heavy.sh.
* Grade B (laptop).
