# P7-oracle-adapters-001 report (spec author, 2026-11-06)

Gates: `lowering-read-mariadb`, `lowering-write-mariadb`, `schema-gate-mariadb`, `lowering-read-crdb`,
`lowering-write-crdb`, `schema-gate-crdb` (gates/phase-7.toml, remote kamrui). Source ported: spikes/q4-005
(q4005.py sha256 65802c3e…, mywire.py 678ca1b7…, probes.py 0ee2ebcd…), reviewed, updated from the spike's pre-D4
protocol v1 to v2.

## What changed

| file | change |
|---|---|
| `supply-chain/engine-pins.toml` | `[engines.mariadb]` kind `mariadb`, MariaDB 11.8.9, floor 11.8.9; `[engines.crdb]` kind `crdb` (per P7-spec-001 / aegis-config AdapterFamily), CockroachDB 25.4.19, floor 25.4.18, memory 2g. Digest, image_id, config_digest, bytes, registry sizes, version, policy, advisories + sources. |
| `ci/engines.sh` | kinds `mariadb` / `crdb` (series floor rule: same major.minor, numeric, no pre-release); MySQL-protocol probe (handshake v10 + native auth + `select version()`), CockroachDB probe (trust-only startup + `select version()`, since server_version is 13.0.0); container args (MariaDB root password + db `aegis`, tmpfs; CockroachDB `start-single-node --insecure`, in-memory 640 MiB store, admin UI on container loopback); optional pin `memory`; **image size = max(inspect .Size, sum of `docker history` layers)**, because kamrui's containerd store reports the compressed size as .Size; Id may equal image_id or config_digest. Self-test: +2 positive controls, +4 refusal fixtures (series, floor, server/pin mismatch, containerd unpacked > 500 MB), +10 floor unit checks; fake docker `history`, fake MariaDB / CockroachDB servers. |
| `oracles/lowering-{read,write}/lowmy.py` (new, byte-identical, sha256 973213e3…) | MySQL wire client (from mywire.py, + reply cap), `MariaRenderer` (dialect `mariadb`), `CrdbRenderer` (dialect `crdb`), `ExtRenderer` dispatcher, `serve`. Imports `lowir.py` unmodified (sha256 3eb7d790… unchanged in both dirs). |
| `oracles/lowering-read/read_oracle.py` | `--engine mariadb|crdb`, DSN routing, `MyDB`, schemas, q4-005 cex corpora, `--my-cases`/`--crdb-cases` (25 000/seed default), engine mutant lists, pin fixtures. Check unchanged. |
| `oracles/lowering-write/write_oracle.py` | `--engine mariadb|crdb`, `MariaEng` (with `returning_select` hook) / `CrdbEng`, MariaDB / CockroachDB / W6 / gate-demo schemas, dialect FORM rules (`my_form`, `crdb_form`, `reply_form`), engine mutant lists. W1/W2/W4/W6/E unchanged. |
| `oracles/schema-gate/{schema_gate,refsubject}.py`, `mywire.py` (new) | modes `mariadb` (25 cases) and `crdb` (20); `--dsn` repeatable + routed, `--engine-pin`, `--skip-sqlite`, `--self-test --subject` (subject positive control); reference `my_check` (information_schema) and the pg check with a crdb flavour; new class `NonTransactionalEngine`, mutant `ignore-engine`. |
| the three READMEs | sections "MariaDB and CockroachDB" (contract, corpora, mutants, limits). |

## Acceptance

```
$ ci/remote.sh --host kamrui ci/engines.sh self-test
...
  mutant no-size-check            RED (3 case(s) fail)
  mutant no-digest-check          RED (4 case(s) fail)
  mutant string-version-compare   RED (7 case(s) fail)
  mutant no-floor                 RED (23 case(s) fail)
ENGINES SELF-TEST: PASS (oversize image, unpinned tag, digest/Id mismatch, below-floor and pin-mismatch versions refused; 4/4 mutants red)
$ ci/remote.sh --host kamrui bash -c 'ci/engines.sh with mariadb,crdb -- ci/engines.sh versions'
engines: mariadb: mariadb@sha256:c4124d1a… 349528064 bytes <= 500000000
engines: crdb: cockroachdb/cockroach@sha256:5f4ea15c… 486612992 bytes <= 500000000
engines: mariadb: up, version 11.8.9 (allow) on 127.0.0.1
engines: crdb: up, version 25.4.19 (allow) on 127.0.0.1
mariadb  OK    mariadb 11.8.9 == pin, floor 11.8.9 (CVE-2026-97380, CVE-2026-107815 and the rest of the 11.8.9 set) 127.0.0.1:32771
crdb     OK    crdb 25.4.19 == pin, floor 25.4.18 (S-26102609 (fixed v25.4.18)) 127.0.0.1:32772
ENGINES VERSIONS: PASS (2/2)
engines: teardown: 0 container(s) left for run 3583993-d6768a1f
```

## Oracle self-tests on kamrui (reference subject `lowmy.py` / `refsubject.py`)

* `lowering-write --self-test --skip-sqlite --engine mariadb --dsn @mariadb --engine crdb --dsn @crdb`:
  `LOWERING-WRITE SELF-TEST: PASS (36/36 mutants caught; positive control PASS; subject drop-tenant caught)`
  (mariadb 19: incl. my-odku-unguarded FORM, my-update-returning-naive W4, my-column-collation, my-bin-padspace;
  crdb 17: incl. crdb-reference-guard FORM=65, crdb-upsert-stmt W1=166, crdb-column-collation W1=12).
* `lowering-read --self-test ...`: `LOWERING-READ SELF-TEST: PASS (23/23 mutants caught; research naive LEAKs
  reproduced; positive control PASS; subject drop-tenant caught; pin fixtures 12/12)`.
* `schema-gate --self-test --engine-pin ...`: `SCHEMA-GATE SELF-TEST: PASS (25/25 mutants caught over mariadb+crdb;
  reference passes through the subject protocol; dead subject caught engine_pin=[mariadb=11.8.9, crdb=25.4.19])`.
  The first run had `[crdb] ignore-prefix-index NOT CAUGHT`: on CockroachDB every table has a primary key (hidden
  rowid otherwise), so a partial / expression unique index is always a second unique index and refused by the
  only-unique-index check anyway. No counterexample can isolate that mutant on crdb, so it is out of the crdb list
  (README). This is not a weakening: no existing check changed, and the cases themselves are still refused.
* Carried laptop self-tests unchanged: write 25/25, read 20/20, schema-gate 22/22 (static+sqlite).

Unit oracles: "MariaDB naive upsert form accepted -> red" = `my-odku-unguarded` (FORM) and `upsert-global-arbiter`
/ `replace-into` (W1); "CockroachDB upsert guard without the q4-005 fix -> red" = `crdb-reference-guard` (FORM);
"NOCASE / uca1400_ai_ci tenant accepted by the schema gate -> red" = `ignore-collation` / `accept-all` on the
`uca1400_ai_ci`, `general_ci`, `utf8mb4_bin` and `en_u_ks_level2` cases.

## Red today (subjects absent)

`mariadb-subject` and `crdb-subject` do not exist yet. Every gate is red at its first step, and the oracle is red as
well, both against a missing binary and against a fail-closed stub (all on kamrui, 2026-11-06):

```
$ ci/heavy.sh cargo build --release --locked -q -p mariadb-subject      # first half of every *-mariadb gate cmd
error: package ID specification `mariadb-subject` did not match any packages            (rc 101)
$ ci/heavy.sh cargo build --release --locked -q -p crdb-subject
error: package ID specification `crdb-subject` did not match any packages               (rc 101)
$ ci/engines.sh with mariadb -- oracles/lowering-write/run --self-test --skip-sqlite --subject "target/release/mariadb-subject lowering" --engine mariadb --dsn @mariadb
FileNotFoundError: [Errno 2] No such file or directory: 'target/release/mariadb-subject'   (non-zero)
$ ci/engines.sh with crdb -- oracles/schema-gate/run --self-test --skip-sqlite --subject "target/release/crdb-subject schema" --engine crdb --dsn @crdb
FileNotFoundError: [Errno 2] No such file or directory: 'target/release/crdb-subject'
$ ci/engines.sh with crdb -- oracles/lowering-read/run --engine-pin --skip-sqlite --subject "target/release/crdb-subject lowering" --engine crdb --dsn @crdb
FileNotFoundError: [Errno 2] No such file or directory: 'target/release/crdb-subject'
# fail-closed stub (refuses everything), the shape a stub subject would have:
$ ci/engines.sh with mariadb -- oracles/lowering-write/run --engine-pin --skip-sqlite --n 50 --subject "python3 -I oracles/lowering-write/lowmy.py serve --mutant refuse-all" --engine mariadb --dsn @mariadb
LOWERING-WRITE: FAIL (E=1160; cases=3022 families=16 W1=0 W2=0 W4=0 W6=0 W7=0 E=1160 FORM=0 REFUSE=0 BIND=0 ACL=0 engine_pin=[mariadb=11.8.9])   rc 1
$ ci/engines.sh with crdb -- oracles/lowering-read/run --engine-pin --skip-sqlite --crdb-cases 200 --subject "python3 -I oracles/lowering-read/lowmy.py serve --mutant refuse-all" --engine crdb --dsn @crdb
rc 1 (refused / miss)
$ ci/engines.sh with mariadb -- oracles/schema-gate/run --engine-pin --skip-sqlite --subject "python3 -I oracles/schema-gate/refsubject.py serve --mutant refuse-all" --engine mariadb --dsn @mariadb
rc 1
$ ci/engines.sh with crdb -- oracles/schema-gate/run --engine-pin --skip-sqlite --subject "... refsubject.py serve --mutant accept-all" --engine crdb --dsn @crdb
[crdb] counterexample accepted: view as collection: ok
SCHEMA-GATE: FAIL (16 failing cases; crdb=20)   rc 1
```

The full-size runs with the reference subject are green, so the oracles are passable:

```
$ ci/engines.sh with mariadb,crdb -- oracles/lowering-write/run --engine-pin --skip-sqlite --engine mariadb --dsn @mariadb --engine crdb --dsn @crdb
LOWERING-WRITE: PASS (cases=32444 families=29 W1=0 W2=0 W4=0 W6=0 W7=0 E=0 FORM=0 REFUSE=0 BIND=0 ACL=0 engine_pin=[mariadb=11.8.9, crdb=25.4.19])   wall 457.6 s
$ ci/engines.sh with mariadb,crdb -- oracles/lowering-read/run --engine-pin --skip-sqlite --engine mariadb --dsn @mariadb --engine crdb --dsn @crdb
LOWERING-READ: PASS (cases=701058 generated_unique[mariadb=100000 crdb=100000] ... leak=0 widen=0 miss=0 gap_vs_2vl(info)=72477 errors=0 unrefused=0 engine_pin=[mariadb=11.8.9, crdb=25.4.19])   wall 2286.4 s
$ oracles/schema-gate/run --engine mariadb / --engine crdb (reference)
SCHEMA-GATE: PASS (... mariadb=25) / SCHEMA-GATE: PASS (... crdb=20)
```

Write corpus: 300 cases x 4 seeds = 1200 per family per schema per engine. Read: 25 000 x 4 seeds = 100 000 unique
generated cases per engine, each run over 4 (mariadb) or 3 (crdb) schemas, plus cex, handle and self-join families.
Expect about 40 min on kamrui for the read gate covering both engines (each gate runs one engine).

## Subject CLI contract (for P7-adapter-mysql-001 / P7-adapter-crdb-001)

Binaries `target/release/mariadb-subject` and `target/release/crdb-subject` (packages `mariadb-subject`,
`crdb-subject`; `subjects/<name>/src/**` is in the adapter units' write scope; the workspace member and Cargo entry
come from the integrator). Same shape as `pg-subject`:

* `<subject> lowering [--mutant drop-tenant]`: JSON lines on stdin/stdout, protocol v2 (`oracles/lowering-read/README.md`
  and `oracles/lowering-write/README.md`), echo `id`, one reply per line, `{"refuse": ".."}` for anything refused.
  Must serve `op` = `read`, `update`, `delete`, `insert`, `upsert` with `"dialect":"mariadb"` (mariadb-subject) or
  `"dialect":"crdb"` (crdb-subject), and refuse `merge` / `cte` / `replace` / `raw_sql`, non-canonical tenant handles
  (not 16 lower-case hex, non-zero), SET / update of the tenant or a key column, a `row` carrying the tenant, an
  upsert whose key lacks the tenant or whose `unique` list has a key without the tenant, an insert whose `unique`
  key lacks the tenant, and any write whose `fks` entry does not map tenant to the referenced tenant column.
  `--mutant drop-tenant` must drop the tenant conjunct (the self-test requires it to go red). No `rls_*` / `kv_*` ops.
  * mariadb: `?` placeholders; string atoms `CAST(c AS BINARY) <op> CAST(? AS BINARY)`; prefix
    `LEFT(CAST(c AS BINARY), <utf-8 byte length>) = CAST(? AS BINARY)`; ints `c = ?` only on int columns; class
    mismatch FALSE; `CASE WHEN c IS NULL THEN NULL ELSE .. END`; UPDATE without RETURNING plus
    `"returning_select": {"sql": "SELECT <post-image> FROM t WHERE <same lowered WHERE> FOR UPDATE", "params": [..]}`
    when `returning` is non-empty; DELETE / INSERT `.. RETURNING <permitted>`; upsert with update columns
    `INSERT .. VALUES .. ON DUPLICATE KEY UPDATE c = IF(CAST(t AS BINARY) = CAST(VALUES(t) AS BINARY), VALUES(c), c)
    [, ..] RETURNING ..`; upsert without update columns `INSERT .. SELECT .. FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM
    t WHERE <binary own key>) RETURNING ..`; never REPLACE / IGNORE / MERGE / WITH / ON CONFLICT.
  * crdb: the pg-subject forms (`$n`, `c::text = $n::text COLLATE "C"`, `::bigint`, `left(c::text, $n::int)`), with
    the upsert guard `WHERE "t"."tenant"::text = excluded."tenant"::text COLLATE "C"`; never `UPSERT`.
* `<subject> schema`: schema-gate protocol v1 (`oracles/schema-gate/README.md`), modes `mariadb`
  (`dsn` = `mysql://..`, `namespace` = database) / `crdb` (`dsn` = `postgresql://..`, `namespace` = schema), live
  introspection only, reply `{"ok":true}` or `{"refuse":"<Class>"}` with the classes in the README, plus
  `NonTransactionalEngine` (MariaDB, non-InnoDB). crdb: no RLS requirement.
* Gate commands (verbatim from gates/phase-7.toml):
  `ci/engines.sh with <eng> -- oracles/<oracle>/run --engine-pin --skip-sqlite --subject 'target/release/<eng>-subject <lowering|schema>' --engine <eng> --dsn @<eng>`
  and the `--self-test` variant (reference + mutants, then the subject must PASS; lowering also requires
  `<subject> --mutant drop-tenant` to go red).
* Implementer acceptance runs: `ci/remote.sh --host kamrui bash -c 'ci/heavy.sh cargo build --release --locked -q -p
  <eng>-subject && ci/engines.sh with <eng> -- oracles/lowering-write/run --engine-pin --skip-sqlite --subject
  "target/release/<eng>-subject lowering" --engine <eng> --dsn @<eng>'`.

## Infeasible / residual

Nothing infeasible; no check was weakened. No INFEASIBLE_REPORT.md.

Residuals and decisions for the integrator:

* **No RLS family on crdb or mariadb.** MariaDB has no RLS. CockroachDB 25.x has RLS, but the crdb dialect has no
  `rls_policy` / `rls_bind` in D-P7.8 or q4-005, and the PG RLS family needs NOINHERIT roles and SECURITY DEFINER
  snapshot functions. So: no RLS claim for crdb, and schema-gate-crdb does not require FORCE RLS. If the integrator
  wants RLS defence in depth on crdb, that needs its own spike.
* **Mutants not run on the new engines, with reasons** (READMEs): the RLS and kv mutants (no such feature);
  lowering-write two-valued-not (near-equivalent on typed columns, as on PG); lowering-read pg-no-collate-c on crdb
  (equivalent: `::text` drops the locale, q4-005); schema-gate ignore-index-collation (neither engine has
  per-index-column collation), ignore-generated on mariadb (a generated column cannot be NOT NULL, so nullability
  masks it), ignore-prefix-index on crdb (every table has a PK, so a prefix index is always a second unique index),
  and ignore-rules / exclusion / rls / partition / rowid-alias (PG / SQLite features).
* **New refusal class** `NonTransactionalEngine` (MariaDB). Like the other live-only classes, it is protocol
  vocabulary for the adapter error type, not an F4 `SchemaError`.
* **engines.sh on a containerd store.** kamrui's docker reports .Size as the compressed size and Id as the index
  digest. engines.sh now sizes images by the unpacked layer sum (a stricter check). The existing pg / valkey / redis
  pins record classic-store Ids (config digests), so `engines.sh with pg17` on kamrui would refuse on Id until those
  pins gain `config_digest` / kamrui `image_id`. I did not change them: they are outside this unit, and the PG gates run
  on the laptop.
* **CockroachDB 25.4.19 is 486.6 MB unpacked**, under 500 MB with little margin. Re-measure on every bump.
  MariaDB is 349.5 MB.
* Rung: the oracles are R2 executed differentials at the pins on kamrui, against the Python reference (the
  `lowmy.py` renderers). The adapters themselves are unbuilt. CockroachDB runs single-node, in-memory, with no
  concurrency (the 40001 retry is the adapter's to prove).
* A missing subject binary makes the oracle exit non-zero with a Python FileNotFoundError traceback (lowir.ProcSubject,
  unchanged). The gate command fails earlier anyway, at `cargo build -p <eng>-subject` (no such package).
