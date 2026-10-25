# lowering-write: write-path differential oracle (INV-WRITE-SUBSET W1/W2/W4)

Checks that rendered UPDATE / DELETE / UPSERT statements and Redis/Valkey commands change only tenant-owned,
predicate-selected state and return only permitted data. Spec clauses: **SPEC_INVARIANTS §E INV-WRITE-SUBSET
W1, W2, W4** (W3 is observed through W1, W7 for the Redis family), mandated forms "composite arbiters, no REPLACE
family, upsert WHERE without user expressions". IMPLEMENTATION_PLAN §2 row "write oracle W1/W2/W4"; Phase 4 gate
"write oracle hardened forms 0/300 per family".

## Run

```
oracles/lowering-write/run                         # default gate: SQLite (stdlib) + offline Redis model, ~7 s
oracles/lowering-write/run --self-test             # mutants must be caught, ~11 s
oracles/lowering-write/run --subject "<cmd>"       # plug in the Rust renderer (protocol below)
oracles/lowering-write/run --engine pg --dsn postgresql://postgres:x@127.0.0.1:55711/postgres \
                           --engine redis --url redis://127.0.0.1:55712/9
oracles/lowering-write/run --self-test --engine pg --dsn ... --engine redis --url ...
```

Last line `LOWERING-WRITE: PASS (...)` / `FAIL (...)`, exit 0 only on PASS. `--n` = cases per family per schema per
seed (default 300, the research number); `--seeds` default 1,2,3,20261025; `--json FILE`; `--no-gate-demo`.
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
| redis kv: SET/DEL/GET/SCAN over the research tenant corpus with adversarial suffixes (`b:c`, `}:x`, `*`) | model (offline) or live |

PG (`--engine pg`): U/D/UP/UPG on plain id PK, composite PK, ICU nondeterministic tenant (`ci_nd`).

Schema-gate demo (printed, not in the verdict): composite PK whose tenant column is NOCASE (SQLite) or ICU
nondeterministic (PG). The arbiter matches `ACME` for `acme`; the reference's tenant guard prevents the W1
capture, but the upsert silently does nothing (E = 51/1200 on both engines). So the schema gate must refuse such
schemas; a guard alone is not enough.

## Pass criterion

`W1 = W2 = W4 = W7 = E = 0` and no engine errors on well-formed requests, across all hardened families (each family
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
| kv-naive (raw tenant in key and pattern) | W1 |
| kv-escaped-colon (escaped glob, ':' delimiter) | W7 |

Plus a positive control (the unmutated reference **through the `--subject` process protocol** must PASS) and
upsert-global-arbiter served out-of-process must be caught. With `--engine pg`: drop-tenant, upsert-global-arbiter,
returning-star, set-tenant-passthrough, pg-no-collate-c; with `--engine redis`: both kv mutants. two-valued-not is
not in the PG write list: PG comparisons already propagate NULL, so on these text columns the mutant is
near-equivalent (0/100 caught). It stays in the PG read self-test, where class-mismatch atoms expose it.

## Subject protocol

Same transport as `oracles/lowering-read/README.md`: `--subject "<cmd>"`, one JSON request per line on stdin, one
JSON reply per line on stdout, `id` echoed, values are JSON int | string, Pred as in the read README. Reference:
`python3 -I lowir.py serve [--mutant NAME]`. A reply is `{"sql": "<one statement>", "params": [...]}`, or
`{"refuse": "reason"}`.

```json
{"v":1,"id":7,"op":"update","dialect":"sqlite","table":"t","tenant_field":"tenant","key":["tenant","id"],
 "columns":{"id":"INTEGER","tenant":"TEXT","grp":"TEXT","x":"TEXT","y":"TEXT","secret":"TEXT"},
 "tenant":"acme","pred":["pfx","x","a"],"set":{"x":"U"},"returning":["id","x"]}
{"v":1,"id":8,"op":"delete", ...same envelope..., "pred":P, "returning":["id"]}
{"v":1,"id":9,"op":"upsert", ...same envelope..., "row":{"id":7,"grp":"g1","x":"N","y":"n"},"update":["x"],"returning":["id","x"]}
```
`set` and `update` must not touch the tenant or key columns; `row` must not carry the tenant (the tenant value is
the host-minted `tenant` handle). `returning` is the permitted projection; the statement may return fewer columns,
never others. `key` is the table's primary key (the upsert arbiter must contain the tenant column).
Example reference reply (postgres dialect):
```json
{"v":1,"id":9,"sql":"INSERT INTO \"t\" (\"tenant\", \"id\", \"x\") VALUES ($1, $2, $3) ON CONFLICT (\"tenant\", \"id\") DO UPDATE SET \"x\" = excluded.\"x\" WHERE \"t\".\"tenant\" = excluded.\"tenant\" COLLATE \"C\" RETURNING \"id\", \"x\"","params":["acme",7,"N"]}
```
Redis/Valkey (byte strings hex-encoded): `{"op":"kv_set","tenant":t,"suffix_hex":..,"value_hex":..}`,
`{"op":"kv_del",...}`, `{"op":"kv_get",...}` → `{"commands":[["<hex arg>",...],...]}` (executed in order);
`{"op":"kv_key",...}` → `{"key_hex":..}`; `{"op":"kv_scan","tenant":t}` → `{"pattern_hex":..}`. The oracle derives
ownership from the subject's own `kv_key`/`kv_scan` answers (encoding-independent): a changed key created by another
tenant is W1, a new key inside another tenant's scan pattern or outside the own one is W2, a foreign key or value in
a reply is W7. Reference encoding: `t:{hex(utf8 tenant)}:<suffix>`, pattern `t:{hex}:*`.

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
`lowir.py` is byte-identical to `oracles/lowering-read/lowir.py` (sha256 e5774a4bbb32420a9fcaf4288b62085c5cf59d687bdbaff94ac6a40e792be5b4).

## Re-run in repo (2026-10-25, Python 3.12.9, SQLite 3.45.3)

* `run`: `LOWERING-WRITE: PASS (cases=19200 families=16 W1=0 W2=0 W4=0 W7=0 E=0)`, 7 s.
* `--self-test`: `LOWERING-WRITE SELF-TEST: PASS (12/12 mutants caught; positive control PASS)`; with PG 17.11 + Valkey: 19/19.
* `--engine pg --engine redis` (postgres:17 = 17.11, valkey/valkey:alpine): `LOWERING-WRITE: PASS (cases=12000 families=10 W1=0 W2=0 W4=0 W7=0 E=0)`, 21 s.

## Known limits / pending

* W5 (triggers, data-modifying CTEs, FK actions), W6 (uniform failure / existence oracle), MERGE, RLS-native
  enforcement (wp_run2/3: FORCE RLS, WITH CHECK, owner bypass, SECURITY DEFINER triggers) are not ported: the
  research families exist and are listed in wp_run*.py. They need the schema gate as a subject, not just a renderer.
* PG 19rc1 (ON CONFLICT DO SELECT, plan's "PG19 blocked until ON CONFLICT fix") not run; image is present locally.
* Redis: only string SET/DEL/GET/SCAN are modelled offline; the research ACL hostile-command corpus (RENAME, COPY,
  SORT BY/GET/STORE, EVAL with undeclared keys, MOVE, SWAPDB...) in rd_run.py tests native ACL enforcement and is
  pending (it needs the adapter's ACL rule generator in the protocol).
* MySQL/MariaDB/CockroachDB (q4-005) not covered.
