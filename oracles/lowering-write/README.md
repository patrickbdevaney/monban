# lowering-write: write-path differential oracle (INV-WRITE-SUBSET W1/W2/W4/W6)

Checks that rendered UPDATE / DELETE / INSERT / UPSERT statements and Redis/Valkey commands change only tenant-owned,
predicate-selected state, return only permitted data and fail uniformly. Spec clauses: **SPEC_INVARIANTS §E
INV-WRITE-SUBSET W1, W2, W4, W6** (W3 is observed through W1, W7 for the Redis family), mandated forms "composite
arbiters, no REPLACE family, no IGNORE variants, ON CONFLICT always names the conflict key, upsert WHERE without user
expressions" plus "MERGE and data-modifying CTE refused" (unit P4-oracle-lowering-001). IMPLEMENTATION_PLAN §2 row
"write oracle W1/W2/W4"; Phase 4 gate "write oracle hardened forms 0/300 per family".

## Run

```
oracles/lowering-write/run                         # default gate: SQLite (stdlib) + offline Redis model, ~12 s
oracles/lowering-write/run --self-test             # mutants must be caught, ~25 s
oracles/lowering-write/run --self-test --subject "<cmd>"   # + <cmd> must PASS, "<cmd> --mutant drop-tenant" must go red
oracles/lowering-write/run --n 300 --engine-pin    # SQLite at the adapter pin 3.53.2 (rust/sqlite-exec)
oracles/lowering-write/run --subject "<cmd>"       # plug in the Rust renderer (protocol below)
ci/engines.sh with pg17,pg18,valkey,redis -- oracles/lowering-write/run --n 300 --skip-sqlite --engine-pin \
    --engine pg --dsn @pg17 --engine pg --dsn @pg18 --engine redis --url @valkey --engine redis --url @redis
oracles/lowering-write/run --self-test --engine pg --dsn @pg17 --engine redis --url @valkey
```

Last line `LOWERING-WRITE: PASS (...)` / `FAIL (...)`, exit 0 only on PASS. `--n` = cases per family per schema per
seed (default 300, the research number); `--seeds` default 1,2,3,20261025; `--json FILE`; `--no-gate-demo`.
`--dsn` / `--url` repeatable, `--skip-sqlite`, `--engine-pin`, `--sqlite-exec`, `--pins` exactly as in
`oracles/lowering-read/README.md`.
Targets must be throwaway (table `t` is dropped; the Redis db is FLUSHed if non-empty). No third-party drivers
(in-file PG v3 wire client and RESP2 client, shared `lowir.py`).

## What is checked

Each case: snapshot the whole table (all tenants), `BEGIN`, execute the one rendered statement, snapshot, `ROLLBACK`.
With Delta = keys whose row differs (by the table's declared key):

* **W1** every changed key's pre-image has tenant `t` and, for UPDATE/DELETE, satisfies `Pred` (Lean `eval`).
* **W2** every changed key's post-image has tenant `t`; for UPDATE, columns outside SET are unchanged (the
  `r'.fields \ sets` clause of `INV_WRITE_SUBSET.md`, not checked in research).
* **W4** RETURNING columns ⊆ the permitted projection (the request's `returning`; the table has a `secret` column
  that is never permitted) and every returned row is a tenant-`t` pre/post image.
* **W3** (upsert arbiter selects a foreign row) shows up as W1 on that foreign pre-image.
* **E (effect)** the post-state and RETURNING multiset equal the Lean-model prediction: rows with
  `keeps EXACT r (lowerQ t p)` get SET applied / are deleted; a composite upsert inserts or updates `(t, id)`.
  Without E a renderer that does nothing, or one that updates rows the Lean lowering drops (two-valued NOT), passes.
* **W7** (Redis) GET/SCAN replies carry no key or value of another tenant.
* **W6** (uniform failure, no existence oracle) the same rendered INSERT is run on S0 (no foreign row) and S1 (another
  tenant holds a row with the same id, or the referenced parent group); the outcome (ok + RETURNING + own rows, or
  the error class / SQLSTATE) must be identical. Ids and groups are fresh, so the own outcome depends only on own rows.
* **FORM** (mandated forms) every write reply is one statement starting with the op's verb (UPDATE / DELETE /
  INSERT); no MERGE, WITH (CTE), REPLACE, IGNORE, RULE, `INSERT OR ...`, no `;`; `ON CONFLICT` is followed by
  `(conflict key)` and an upsert has one. Lexical scan outside literals, quoted identifiers and comments.
* **REFUSE** requests that must be refused were answered: non-canonical tenant handles; ops `merge`, `cte`,
  `replace`, `raw_sql`; invalid KV collection; KV key over 1024 bytes.

Ill-formed requests (10% of U and UP cases: `SET tenant = other`, a request `row` carrying `tenant`; all upserts on
a global-key table) must be refused or be W-safe; they get W checks, no E check. Engine errors are "blocked"
(fail-closed); a refused or blocked well-formed request is an E violation.

Families (SQLite; each 300 cases x 4 seeds per schema):

| family | schemas |
|---|---|
| U `UPDATE .. SET .. WHERE lowerQ RETURNING` | plain id PK, composite PK, NOCASE tenant, STRICT composite, untyped composite |
| D `DELETE .. WHERE lowerQ RETURNING` | same |
| UP composite-arbiter upsert `ON CONFLICT (tenant,id) DO UPDATE .. WHERE t.tenant = excluded.tenant COLLATE BINARY` | composite schemas |
| UPG upsert on a global-key table (reference refuses: arbiter must contain tenant) | plain, NOCASE |
| W6 INSERT, unique-key and FK existence (S0 vs S1) | composite PK + composite FK; global id PK + composite FK (reference refuses); composite PK + global FK (reference refuses) |
| refusals (non-canonical handles on update/upsert; merge, cte, replace, raw_sql ops) | once per engine |
| redis kv (aegis_data_ir::kv_plan): SET / SET NX / SET XX / DEL / GET / SCAN per (tenant, collection, key) with adversarial keys (`b:c`, `}:x`, `*`, `?`, `[a]`) and prefixes; E = exact kv_plan effect and reply; refusals for bad handles, collections, >1024-byte keys | model (offline) or live |

PG (`--engine pg`): U/D/UP/UPG on plain id PK, composite PK, ICU nondeterministic tenant (`ci_nd`), the three W6
schemas and the refusals.

Tenants (D4): handles are 16 lower-case hex TenantId texts (`TEN_HANDLES`); the research TEN confusers ("ACME",
"Acme", "acme ") are stored as non-canonical variants of the canonical `0000000000acce55` (upper case, mixed case,
trailing space) and are never handles. Hostile `SET tenant = other` / row tenants use other canonical handles.

Schema-gate demo (printed, not in the verdict): composite PK whose tenant column is NOCASE (SQLite) or ICU
nondeterministic (PG). The arbiter matches `ACME` for `acme`; the reference's tenant guard prevents the W1
capture, but the upsert silently does nothing (E = 51/1200 on both engines). So the schema gate must refuse such
schemas; a guard alone is not enough.

## Pass criterion

`W1 = W2 = W4 = W6 = W7 = E = FORM = REFUSE = 0` (and, with `--engine-pin`, every engine at its pin) and no engine
errors on well-formed requests, across all hardened families (each family
is 300 cases per seed per schema, so ≥ 300 per family as the Phase 4 gate requires).

## Self-test (negative controls)

| mutant | caught as |
|---|---|
| drop-tenant | W1 |
| or-precedence | W1 |
| upsert-global-arbiter (`ON CONFLICT (id) DO UPDATE`, no guard) | W1 (W3) |
| replace-into (`INSERT OR REPLACE`, REPLACE family) | W1 |
| returning-star (`RETURNING *`, wider than permitted) | W4 |
| set-tenant-passthrough | W2 |
| upsert-tenant-from-row | W2 |
| two-valued-not | E |
| like-prefix | W1 |
| refuse-all | E |
| kv-naive (key `t:<unpadded hex><collection>:..`, no delimiter: tenant 2 + `ac` == tenant 2a + `c`) | W1 |
| kv-escaped-colon (unpadded hex in braces; SCAN pattern `t:{<hex>*` drops the `}:` delimiter) | W7 |
| lenient-handle (any tenant handle accepted) | REFUSE |
| insert-global-key (INSERT accepted although a unique key lacks the tenant) | W6 |
| fk-global (write accepted although a foreign key does not carry the tenant) | W6 |
| upsert-as-merge (`MERGE INTO .. USING (VALUES ..)`) | FORM |
| update-via-cte (`WITH .. UPDATE`; data-modifying CTE on PG) | FORM |
| accept-merge (renders the merge / cte / replace / raw_sql ops) | REFUSE |
| kv-no-escape (SCAN prefix not glob-escaped) | E |
| kv-no-keycap (> 1024-byte key not refused) | REFUSE |
| kv-collection-colon (collection not validated) | REFUSE |

Plus a positive control: the `--subject` command (default `lowir.py serve`) must PASS on the self-test corpus of
every engine in scope, and the same command with ` --mutant drop-tenant` appended must go red (W1 or W7); without
`--subject`, upsert-global-arbiter served out-of-process must also be caught. With `--engine pg`: drop-tenant,
upsert-global-arbiter, returning-star, set-tenant-passthrough, pg-no-collate-c, insert-global-key, fk-global,
upsert-as-merge, update-via-cte; with `--engine redis`: kv-naive, kv-escaped-colon, kv-no-escape, drop-tenant.
`--skip-sqlite` skips the SQLite mutant list (for kv-only / pg-only subjects). two-valued-not is
not in the PG write list: PG comparisons already propagate NULL, so on these text columns the mutant is
near-equivalent (0/100 caught). It stays in the PG read self-test, where class-mismatch atoms expose it.

## Subject protocol

Same transport as `oracles/lowering-read/README.md`: `--subject "<cmd>"`, one JSON request per line on stdin, one
JSON reply per line on stdout, `id` echoed, values are JSON int | string, Pred as in the read README. Reference:
`python3 -I lowir.py serve [--mutant NAME]`. A reply is `{"sql": "<one statement>", "params": [...]}`, or
`{"refuse": "reason"}`.

Protocol v2 (tenant = 16 lower-case hex TenantId text, else refuse; see the read README for the v1 → v2 changes).
```json
{"v":2,"id":7,"op":"update","dialect":"sqlite","table":"t","tenant_field":"tenant","key":["tenant","id"],
 "unique":[["tenant","id"]],"fks":[],
 "columns":{"id":"INTEGER","tenant":"TEXT","grp":"TEXT","x":"TEXT","y":"TEXT","secret":"TEXT"},
 "tenant":"0000000000acce55","pred":["pfx","x","a"],"set":{"x":"U"},"returning":["id","x"]}
{"v":2,"id":8,"op":"delete", ...same envelope..., "pred":P, "returning":["id"]}
{"v":2,"id":9,"op":"upsert", ...same envelope..., "row":{"id":7,"grp":"g1","x":"N","y":"n"},"update":["x"],"returning":["id","x"]}
{"v":2,"id":10,"op":"insert", ...same envelope..., "row":{"id":1007,"grp":"g1","x":"N","y":"n"},"returning":["id","x"]}
```
`set` and `update` must not touch the tenant or key columns; `row` must not carry the tenant (the tenant value is
the host-minted `tenant` handle). `returning` is the permitted projection; the statement may return fewer columns,
never others. `key` is the table's primary key (the upsert arbiter must contain the tenant column). `unique` lists
every unique key and `fks` every foreign key
(`{"columns":[..],"ref_table":"p","ref_columns":[..],"ref_tenant_field":"tenant"}`): an `insert` / `upsert` on a
table whose unique key lacks the tenant, and any write on a table whose foreign key does not map tenant to the
referenced tenant column, must be refused (W6 / W3). Ops `merge`, `cte`, `replace`, `raw_sql` must be refused.
Example reference reply (postgres dialect):
```json
{"v":2,"id":9,"sql":"INSERT INTO \"t\" (\"tenant\", \"id\", \"x\") VALUES ($1, $2, $3) ON CONFLICT (\"tenant\", \"id\") DO UPDATE SET \"x\" = excluded.\"x\" WHERE \"t\".\"tenant\" = excluded.\"tenant\" COLLATE \"C\" RETURNING \"id\", \"x\"","params":["0000000000acce55",7,"N"]}
```
Redis/Valkey (aegis_data_ir::kv_plan; byte strings hex-encoded, keys and values UTF-8 text):
`{"op":"kv_set"|"kv_setnx"|"kv_setxx","tenant":T,"collection":C,"key_hex":..,"value_hex":..}` (Upsert `SET k v`,
Insert `SET k v NX`, Update `SET k v XX`), `{"op":"kv_del"|"kv_get","tenant":T,"collection":C,"key_hex":..}` →
`{"commands":[["<hex arg>",...],...]}` (executed in order); `{"op":"kv_key",...}` → `{"key_hex":..}`;
`{"op":"kv_scan","tenant":T,"collection":C,"prefix_hex":null|..}` → `{"pattern_hex":..}`. The oracle derives
ownership from the subject's own `kv_key`/`kv_scan` answers (encoding-independent): a changed key created by another
tenant is W1, a new key inside another tenant's scan pattern or outside the own ones is W2, a foreign key or value in
a reply is W7, and any other difference from the kv_plan effect (or a SCAN result other than the tenant's keys in that
collection with that prefix) is E. Reference encoding: `t:{<16hex>}:<collection>:<key>`, pattern
`t:{<16hex>}:<collection>:<glob_escape(prefix)>*`.

Reserved, implemented by the reference renderer but **not yet exercised by any family** (see pending):
`{"op":"kv_acl","tenant":T}` → `{"rules":[<ACL SETUSER tokens>]}`;
`{"op":"rls_policy","dialect":"postgres","table":"t","tenant_field":"tenant","role":R,"setting":S}` →
`{"statements":[sql,...]}`; `{"op":"rls_bind","dialect":"postgres","tenant":T,"role":R,"setting":S}` →
`{"statements":[{"sql":..,"params":[..]},...]}`. Subjects may refuse them until those families exist.

## Divergences from research (reported)

* **WD1** research `wporacle.check()` has no effect/completeness check; its RETURNING check is tenant-only (no
  column projection) and it does not check W2's "fields outside SET unchanged". All three are added here (E, W4
  columns, W2b); `returning-star` and `two-valued-not` are only caught because of them.
* **WD2** W3 needs a collation clause: a composite arbiter under a NOCASE / nondeterministic tenant collation
  matches a foreign tenant's key. With the guard there is no capture but a silent no-op (E = 51/1200); without it,
  capture. Suggested wording: arbiter `(t, key)` under a binary/deterministic collation, enforced by the schema gate.
* **WD3** the Lean side (`lowerQ`, three-valued `sql3`) is the effect model here too, so the read divergences D1/D3
  (NOT over NULL) apply to UPDATE/DELETE: rows the two-valued policy permits but SQL drops are not written.

## Research provenance (untrusted input: read, reviewed and re-implemented; never executed in place)

| sha256 | path under `research/state/raw/` | used for |
|---|---|---|
| 4597aaae4ac8e796c781065a27a2b763c5d03ae62af61712eae3993d8be5709b | round-004/02-work/wporacle.py | whole-table diff, W1/W2/W4 check, row generator, TEN corpus |
| 0a0852227860ca45bf96859c2e18c5f2f6d20847affc36c50b8d235b4cbfa410 | round-004/02-work/wp_run.py | op families (U/U2/U2h/D/UP1-5/R1-3/MERGE/CTE/triggers) → hardened forms + mutants |
| 151a639edd3f26cb9931b3c25a0e0eb266556df071ddbd70e66a91de40310677 | round-004/02-work/wp_run2.py | RLS-native families (read; not ported, see pending) |
| e7840634addd4b44d7a6e2cf640879b790e1a1d91d30e1371fb2eb1a0e9065de | round-004/02-work/wp_run3.py | RLS column-free writes (read; not ported) |
| cab8ebc637aec854391c759724f3f32ff688e8c5718df36559ee2783b1ed4f84 | round-004/02-work/wp_out.txt | research leak counts (naive vs hardened) |
| f7147cb3f373c69668c5332fd89fe78d144296b3781c413df2dc9ee4628053a8 | round-004/02-work/INV_WRITE_SUBSET.md | W1–W7 text |
| bf40f25f466691760de5153708884d6a07e213843cf78809be5d53b9f66d87bd | round-004/02-work/rd_run.py | RESP client, Redis key prefix/W7 reply check |
| 3360dea3ed10c819090ca1dbc791bb7303056e0fbe49f597f8ed82845f80860c | round-004/02-work/oracle.py | shared IR/lowering (see lowering-read) |
| 18e95e213b77215919b30f987e2ed63818b6bae8f038af4bddf5d25960e4a3dd | round-004/02-write-path-lowering-differential-oracle.json | findings, engines, PG19 ON CONFLICT note |

In-repo: `spec/AegisIR/Lowering.lean` 5b79eac2615fdd02e5f7260919080d178e9f7fd24206b9b56fd093f034c70203,
`spec/SPEC_INVARIANTS.md` 2d7444473fe2f878680c70ba87d721a52ba7a2a3348b1a24125a8363dab12ac1.
`lowir.py` is byte-identical to `oracles/lowering-read/lowir.py` (sha256 8a49928907e2d82320b7a0a3ba02db712ca580a6412d74d81b4eac62a5a15a85).

## Re-run in repo (2026-10-30, P4-oracle-lowering-001: D4 tenants, protocol v2; Python 3.12.9)

* `run`: `LOWERING-WRITE: PASS (cases=22837 families=20 W1=0 W2=0 W4=0 W6=0 W7=0 E=0 FORM=0 REFUSE=0)`, 12 s;
  schema-gate demo still E = 51/1200 (NOCASE composite arbiter).
* `--self-test`: `LOWERING-WRITE SELF-TEST: PASS (21/21 mutants caught; positive control PASS; subject drop-tenant caught)`, 23 s.
  With `--engine pg --dsn @pg17 --engine redis --url @valkey` (the unit acceptance): 34/34, `RC=0`.
* `--n 300 --engine-pin` (SQLite 3.53.2 via sqlite-exec): `LOWERING-WRITE: PASS (cases=22837 families=20 W1=0 W2=0 W4=0 W6=0 W7=0 E=0 FORM=0 REFUSE=0 engine_pin=[sqlite 3.53.2])`.
* `--n 300 --skip-sqlite --engine-pin --engine pg --dsn @pg17 --engine pg --dsn @pg18`: `LOWERING-WRITE: PASS (cases=28844 families=26 W1=0 W2=0 W4=0 W6=0 W7=0 E=0 FORM=0 REFUSE=0 engine_pin=[pg17=17.11, pg18=18.6])`.
* `--n 300 --skip-sqlite --engine-pin --engine redis --url @valkey --engine redis --url @redis`: `LOWERING-WRITE: PASS (cases=2430 families=2 W1=0 W2=0 W4=0 W6=0 W7=0 E=0 FORM=0 REFUSE=0 engine_pin=[valkey=9.1.2, redis=8.10.2])`.

## Re-run in repo (2026-10-25, Python 3.12.9, SQLite 3.45.3)

* `run`: `LOWERING-WRITE: PASS (cases=19200 families=16 W1=0 W2=0 W4=0 W7=0 E=0)`, 7 s.
* `--self-test`: `LOWERING-WRITE SELF-TEST: PASS (12/12 mutants caught; positive control PASS)`; with PG 17.11 + Valkey: 19/19.
* `--engine pg --engine redis` (postgres:17 = 17.11, valkey/valkey:alpine): `LOWERING-WRITE: PASS (cases=12000 families=10 W1=0 W2=0 W4=0 W7=0 E=0)`, 21 s.

## Known limits / pending

* **Pending from unit P4-oracle-lowering-001 (not done in this pass):** (a) the RLS-native PG families (wp_run2/3:
  FORCE RLS, WITH CHECK, owner bypass) with their mutants; (b) the PG19rc1 ON CONFLICT WHERE-before-RLS information
  run; (c) the Redis/Valkey `kv_acl` native-ACL family (the gate `lowering-write-redis` comment names it). The
  protocol ops are reserved and the reference renders them, but no family checks them yet, so the
  lowering-write-redis acceptance clause "ACL corpus: every hostile command refused" is **not yet gated**.
* W5 (triggers, data-modifying CTEs, FK actions) stays with the schema gate (PLAN D8). W6 is covered for INSERT
  (unique-key and FK existence); UPDATE of a uniquely-constrained column and DELETE under FK RESTRICT are not.
* The FORM check is lexical (keywords outside literals / quoted identifiers); it enforces the mandated forms, it
  does not prove the absence of other statement shapes.
* Redis: only string SET [NX|XX] / DEL / GET / SCAN are modelled offline.
* MySQL/MariaDB/CockroachDB (q4-005) not covered.
