# lowering-write: write-path differential oracle (INV-WRITE-SUBSET W1/W2/W4/W6, PG RLS, Redis ACL)

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
ci/engines.sh with pg19rc1 -- oracles/lowering-write/run --pg-onconflict-info --dsn @pg19rc1   # information only
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
* **BIND** (PG RLS family) after the request transaction ends (COMMIT or ROLLBACK = pool checkin; the oracle issues
  no reset) the connection is back to the login role and the tenant setting is empty.
* **ACL** (Redis/Valkey kv_acl family) the per-tenant ACL user's key patterns are exactly `t:{<16hex>}:*`, it has
  no pub/sub channel, and every hostile command is denied (ACL DRYRUN) and refused live; the oracle's corpus covers
  every item of the frozen RESP denylist (parsed from `crates/aegis-data-ir/src/ir.rs` at run time).
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
schemas and the refusals, plus the RLS-native family below.

**RLS-native family (PG; research wp_run2/wp_run3, R-DB-1/R-DB-8).** Defence in depth behind the renderer, so the
statements are composed by the ORACLE without a tenant conjunct and only the subject's policy and binding confine
them. Setup per seed: table `rt(id int primary key, tenant, peer, grp, x, y, secret)` (global id PK; `peer` holds
other tenants' handles), owned by a non-superuser `NOINHERIT` login role `aegis_rls_login`, which is a member of the
NOLOGIN role `aegis_rls_app`; the subject's `rls_policy` statements are executed by the owner (no superuser). Per
case (n per seed): `BEGIN`, the subject's `rls_bind` statements for a random tenant, one statement, whole-table
snapshot through a superuser-owned SECURITY DEFINER function inside the same transaction, then `COMMIT` (read-only
`sel`) or `ROLLBACK`. Statements: `sel` SELECT .. WHERE Pred, `upd` UPDATE SET x .. WHERE Pred RETURNING, `del`
DELETE .. WHERE Pred RETURNING, `updall` / `delall` column-free UPDATE / DELETE, `inso` own INSERT (well-formed: E
applies), and hostile `move` (column-free `SET tenant = other`), `movew` (`SET tenant = other WHERE id > 0
RETURNING`), `insf` (INSERT a foreign-tenant row), `upg` / `upgt` (global-arbiter upsert `ON CONFLICT (id) DO
UPDATE SET x` / `SET tenant, x`) (W-checks only). Also checked: FORM on the catalog (`relrowsecurity` and
`relforcerowsecurity`; at least one permissive policy covering all commands; every permissive policy's USING and
an explicit WITH CHECK reference the tenant column and `current_setting('<setting>'` and no other column), BIND at
every checkin, and an owner path (n/5 per seed: the owner login with the setting bound but no role switch; FORCE must
stop the owner bypass; W-checks only). The binding is required to be transaction-scoped (`SET LOCAL ROLE`,
`set_config(.., true)`), because the oracle's pool runs nothing at checkin.

**kv_acl hostile-command family (Redis/Valkey, live).** Per tenant in `KV_TEN` the oracle creates the ACL user
`aegis_kv_<hex>` with `ACL SETUSER <user> reset on ><random password> <subject rules...>`, checks `ACL GETUSER`
(keys exactly `~t:{<hex>}:*`, no selectors, no channels), runs the subject's own kv_set / kv_get / kv_setxx /
kv_setnx / kv_del commands AS that user (E: they must work), then for each of 108 hostile commands requires
`ACL DRYRUN` to deny and, executed live on a fresh connection as that user, an error reply and an unchanged keyspace
(db 0 and db 1, compared by DUMP; a change is W1). A command the DRYRUN already permits is counted and never executed
live (engine safety). Corpus: FLUSHALL [ASYNC], FLUSHDB, KEYS (*, foreign, own), CONFIG GET/SET/RESETSTAT/REWRITE,
EVAL (declared own key; undeclared foreign key), EVAL_RO, EVALSHA[_RO] (script pre-loaded by the admin), SCRIPT
LOAD/FLUSH/EXISTS, FUNCTION LOAD/LIST/FLUSH, FCALL[_RO], MODULE LIST/LOAD, DEBUG SLEEP/OBJECT, MIGRATE (key; KEYS
foreign), SWAPDB, MOVE, COPY (own->foreign, foreign->own, DB 1), RENAME / RENAMENX across tenants, SORT BY/GET/STORE
foreign, SORT_RO, SELECT, CLIENT LIST/KILL ID/KILL ADDR/SETNAME/NO-EVICT, ACL WHOAMI/LIST/GETUSER/SETUSER self
+@all/DELUSER/LOG, MONITOR, PUBLISH/SPUBLISH/SUBSCRIBE/PSUBSCRIBE/SSUBSCRIBE/PUBSUB, SCAN (no MATCH, `*`, foreign
pattern, foreign pattern + TYPE), cross-tenant GET/SET [NX|XX|GET]/DEL/MGET/EXISTS/TYPE/DUMP/OBJECT/UNLINK/GETDEL/
APPEND/EXPIRE/TOUCH/MEMORY USAGE, SAVE/BGSAVE/BGREWRITEAOF/REPLICAOF/SHUTDOWN/FAILOVER/WAIT/INFO/DBSIZE/RANDOMKEY/
LATENCY/SLOWLOG, Redis-module JSON.GET / FT._LIST, and GET/SET of the namespace neighbours `t:{T}`, `t:{T}x:k1`,
`t:{T0}:c:k1` (17 hex), `t:T:c:k1` (no braces), `t:{T`, `k1`. Without a live engine (default run) the rules get a
static check only (`redis kv_acl rules (static, offline)`: key patterns, channels, credential tokens, no category
grant, no denylisted / hostile command granted).

Finding: **SCAN cannot be confined by ACL** (it has no key argument; MATCH is not an ACL key), so a user with `+scan`
lists every tenant's key names and "cross-tenant SCAN patterns refused" is only satisfiable by not granting SCAN. The
reference rule therefore no longer grants `+scan` (pass 1 did; nothing exercised it), and `kv_plan::Scan` cannot run
under the per-tenant ACL user: the redis adapter needs a separate decision for Scan (for example a scan connection
whose replies the host re-checks, W7, or no native-ACL defence for Scan). Also: `RESET` (like AUTH/HELLO) is never
ACL-checked (ACL DRYRUN permits it under `-@all`) and re-authenticates as `default`, so deployments must run with the
`default` user off or without permissions (engine configuration; not a kv_acl property, so not in the corpus).

Tenants (D4): handles are 16 lower-case hex TenantId texts (`TEN_HANDLES`); the research TEN confusers ("ACME",
"Acme", "acme ") are stored as non-canonical variants of the canonical `0000000000acce55` (upper case, mixed case,
trailing space) and are never handles. Hostile `SET tenant = other` / row tenants use other canonical handles.

Schema-gate demo (printed, not in the verdict): composite PK whose tenant column is NOCASE (SQLite) or ICU
nondeterministic (PG). The arbiter matches `ACME` for `acme`; the reference's tenant guard prevents the W1
capture, but the upsert silently does nothing (E = 51/1200 on both engines). So the schema gate must refuse such
schemas; a guard alone is not enough.

## Pass criterion

`W1 = W2 = W4 = W6 = W7 = E = FORM = REFUSE = BIND = ACL = 0` (and, with `--engine-pin`, every engine at its pin) and no engine
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
| kv-acl-all (`+@all`) | ACL |
| kv-acl-allkeys (key pattern `~*`) | ACL |
| kv-acl-no-brace (`~t:{<hex>*`, tenant brace and delimiter missing) | ACL |
| kv-acl-eval (`+eval`) | ACL |

Plus a positive control: the `--subject` command (default `lowir.py serve`) must PASS on the self-test corpus of
every engine in scope, and the same command with ` --mutant drop-tenant` appended must go red (W1 or W7); without
`--subject`, upsert-global-arbiter served out-of-process must also be caught. With `--engine pg`: drop-tenant,
upsert-global-arbiter, returning-star, set-tenant-passthrough, pg-no-collate-c, insert-global-key, fk-global,
upsert-as-merge, update-via-cte and the RLS mutants (expected counter): rls-no-force (W1, owner path; also FORM),
rls-check-true (W2), rls-split-update-true (W1), rls-no-role (E: as the NOINHERIT owner under FORCE nothing is
visible), rls-no-check (FORM; `USING` without `WITH CHECK` is behaviourally equal on a FOR ALL policy because PG
reuses USING as the check, so only the catalog form catches it), rls-wrong-column (W4: rows whose `peer` is the
tenant become visible), rls-session-setting (BIND: `SET ROLE` + `set_config(.., false)` survive COMMIT); with
`--engine redis`: kv-naive, kv-escaped-colon, kv-no-escape, drop-tenant, kv-acl-all, kv-acl-allkeys,
kv-acl-no-brace, kv-acl-eval (all ACL).
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

Native-enforcement ops (exercised by the RLS and kv_acl families; a refusal of a well-formed request is E):

**kv_acl** `{"v":2,"id":N,"op":"kv_acl","tenant":T}` → `{"rules":["<token>",...]}`: the permission tokens of
`ACL SETUSER` for tenant T's user. The host prepends `reset on ><password>`, so the rules must not contain
credential / state tokens (`on`, `off`, `nopass`, `reset`, `resetpass`, `>`, `<`, `#`, `!`, `[skip-]sanitize-payload`;
FORM). Required effect: key patterns exactly `~t:{<T>}:*` (no `allkeys`, no extra `%R~`/`%W~` patterns, no
selectors), no pub/sub channels, no hostile command (above) permitted, while GET / SET (incl. NX / XX) / DEL on own
keys work. Non-canonical T: refuse. Reference reply:
`{"rules":["resetkeys","~t:{0000000000acce55}:*","resetchannels","-@all","+get","+set","+del"]}`.

**rls_policy** `{"v":2,"id":N,"op":"rls_policy","dialect":"postgres","table":"rt","tenant_field":"tenant",
"role":"aegis_rls_app","setting":"aegis.tenant","columns":{...}}` → `{"statements":["<sql>",...]}` (DDL, executed in
order by the table owner over the simple protocol). Required: ENABLE and FORCE ROW LEVEL SECURITY; permissive
policies covering all commands for `role` whose USING and an explicit WITH CHECK are both `tenant_field =
current_setting('<setting>', true)` under a deterministic binary comparison (reference: `COLLATE "C"`), referencing
no other column. Reference reply:
```json
{"statements":["ALTER TABLE \"rt\" ENABLE ROW LEVEL SECURITY","ALTER TABLE \"rt\" FORCE ROW LEVEL SECURITY",
 "CREATE POLICY aegis_tenant ON \"rt\" AS PERMISSIVE FOR ALL TO \"aegis_rls_app\" USING (\"tenant\" = current_setting('aegis.tenant', true) COLLATE \"C\") WITH CHECK (\"tenant\" = current_setting('aegis.tenant', true) COLLATE \"C\")"]}
```
**rls_bind** `{"v":2,"id":N,"op":"rls_bind","dialect":"postgres","tenant":T,"role":R,"setting":S}` →
`{"statements":[{"sql":"<sql>","params":[...]},...]}` executed in order right after the request's `BEGIN` (extended
protocol, `$n` placeholders). Required: per request and transaction-scoped, i.e. switch to `role` and set `setting`
to T so that both vanish at COMMIT / ROLLBACK (the oracle runs nothing at checkin). Non-canonical T: refuse.
Reference reply: `{"statements":[{"sql":"SET LOCAL ROLE \"aegis_rls_app\"","params":[]},
{"sql":"SELECT set_config($1, $2, true)","params":["aegis.tenant","0000000000acce55"]}]}`.

## PG ON CONFLICT information run (unit note 7; never a gate)

`run --pg-onconflict-info --dsn ...` sets up `rt` (global id PK) and `rt2` (composite PK (tenant,id)) with the
subject's FORCE RLS policy, a non-leakproof `aegis_peek(text)` that raises a NOTICE with its argument, binds tenant A
and probes row id 2 of tenant B (`x = 'secretB'`): P1 `INSERT .. ON CONFLICT (id) DO UPDATE SET x = excluded.x WHERE
aegis_peek(rt.x)`; P2 the same on the composite arbiter; P3-P6 UPDATE / DELETE / MERGE WHEN MATCHED AND / SELECT
with `aegis_peek` (controls); P7 PG19 `ON CONFLICT (id) DO SELECT RETURNING` on the RLS table; P8 the same through a
`security_barrier` view that filters the tenant (view-based tenancy, not RLS). It prints one line per probe and
`LOWERING-WRITE PG-ONCONFLICT-INFO (information only, not a gate): ...`, and exits 0 whatever it finds.

**Finding (2026-10-30, pinned images): the RLS + ON CONFLICT issue reproduces on 19rc1.** P1 raised
`NOTICE AEGIS_PEEK secretB`: PG evaluated the user function in the DO UPDATE WHERE on tenant B's row, and only then
refused with `42501 new row violates row-level security policy (USING expression)`. **It reproduces identically on
17.11 and 18.6**, so it is not specific to 19 and the allowed pins carry it too. The controls (P3-P6) see only own
rows on all three; the hardened form (P2, composite arbiter) never reaches B's row. AEGIS does not hit it because the
mandated forms put no user expression in the upsert WHERE and require a composite arbiter (FORM + W-checks above).
PG19-specific: P8, `ON CONFLICT DO SELECT` through a security_barrier view, **returned B's row** on 19rc1
(`(2, '0000000000000a25', 'secretB')`); on the RLS table itself DO SELECT is refused (P7, 42501). 17/18 have no DO
SELECT (P7/P8 n/a). So `pg19-blocked` stays justified (the R-DB-8 condition is still unfixed on 19rc1, plus the new
DO SELECT view leak), but its stated reason should say the WHERE-before-RLS evaluation also exists on 17.11/18.6 and
is mitigated there only by the mandated forms.

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
| 151a639edd3f26cb9931b3c25a0e0eb266556df071ddbd70e66a91de40310677 | round-004/02-work/wp_run2.py | RLS-native families: no-conjunct U3/D3, SET tenant with/without RETURNING, policy variants (ported as the RLS family) |
| e7840634addd4b44d7a6e2cf640879b790e1a1d91d30e1371fb2eb1a0e9065de | round-004/02-work/wp_run3.py | RLS column-free writes, global-arbiter upsert under RLS (ported: move / movew / upg) |
| 28f8eb1a518dfc001542ed5b2de18e1b3adf12d00191656898a3063e95ec1c2f | round-004/02-work/peek.sql | ON CONFLICT WHERE peek and controls (ported as P1, P3-P6) |
| 62f47fdfa5b7dcce9ec9dd01ba47bedc5ef9ea233e93ca116a5038f18fbc136d | round-004/02-work/repro.sql | R1-R6 (R2/R3 -> P1/P8; R6 ACL wildcard tenant -> kv_acl neighbours) |
| 51ea52d7ea849f49901c1109dc0b43880384043bdc7a52fc781b8fa66dd57abc | round-004/02-work/dosel.sql | DO SELECT probe (read; P7/P8) |
| cab8ebc637aec854391c759724f3f32ff688e8c5718df36559ee2783b1ed4f84 | round-004/02-work/wp_out.txt | research leak counts (naive vs hardened) |
| f7147cb3f373c69668c5332fd89fe78d144296b3781c413df2dc9ee4628053a8 | round-004/02-work/INV_WRITE_SUBSET.md | W1–W7 text |
| bf40f25f466691760de5153708884d6a07e213843cf78809be5d53b9f66d87bd | round-004/02-work/rd_run.py | RESP client, Redis key prefix/W7 reply check |
| 3360dea3ed10c819090ca1dbc791bb7303056e0fbe49f597f8ed82845f80860c | round-004/02-work/oracle.py | shared IR/lowering (see lowering-read) |
| 18e95e213b77215919b30f987e2ed63818b6bae8f038af4bddf5d25960e4a3dd | round-004/02-write-path-lowering-differential-oracle.json | findings, engines, PG19 ON CONFLICT note |

In-repo: `spec/AegisIR/Lowering.lean` 5b79eac2615fdd02e5f7260919080d178e9f7fd24206b9b56fd093f034c70203,
`spec/SPEC_INVARIANTS.md` 2d7444473fe2f878680c70ba87d721a52ba7a2a3348b1a24125a8363dab12ac1.
`lowir.py` is byte-identical to `oracles/lowering-read/lowir.py` (sha256 3eb7d79037e2dbb57b276da12d529f5b00fbe8778a3afe2d609891223151b14f).

In-repo: `crates/aegis-data-ir/src/ir.rs` 79af59aa6990e85f78dcf62c27ff0fb479d684f38a867e9e19f9a88a494a4a90 (RESP
denylist, read at run time).

## Re-run in repo (2026-10-30, P4-oracle-lowering-001 pass 2: RLS, kv_acl, PG ON CONFLICT info; Python 3.12.9)

* `run`: `LOWERING-WRITE: PASS (cases=22852 families=21 W1=0 W2=0 W4=0 W6=0 W7=0 E=0 FORM=0 REFUSE=0 BIND=0 ACL=0)`.
* `--self-test`: `LOWERING-WRITE SELF-TEST: PASS (25/25 mutants caught; positive control PASS; subject drop-tenant caught)`.
* Unit acceptance (read + write self-tests, then `ci/engines.sh with pg17,pg18,valkey` engine self-tests): `RC=0`,
  write with engines `LOWERING-WRITE SELF-TEST: PASS (49/49 mutants caught; positive control PASS; subject drop-tenant caught)`.
* `ci/engines.sh with redis -- run --self-test --skip-sqlite --engine redis --url @redis`:
  `LOWERING-WRITE SELF-TEST: PASS (8/8 mutants caught; positive control PASS; subject drop-tenant caught)`.
* `ci/heavy.sh ci/engines.sh with pg17,pg18 -- run --n 300 --skip-sqlite --engine-pin --engine pg --dsn @pg17 --engine pg --dsn @pg18`:
  `LOWERING-WRITE: PASS (cases=31740 families=28 W1=0 W2=0 W4=0 W6=0 W7=0 E=0 FORM=0 REFUSE=0 BIND=0 ACL=0 engine_pin=[pg17=17.11, pg18=18.6])`
  (RLS family 1448 cases per engine: 4 seeds x (policy + 300 bound + 60 owner-path) + 4 refusals).
* `ci/heavy.sh ci/engines.sh with valkey,redis -- run --n 300 --skip-sqlite --engine-pin --engine redis --url @valkey --engine redis --url @redis`:
  `LOWERING-WRITE: PASS (cases=3828 families=4 W1=0 W2=0 W4=0 W6=0 W7=0 E=0 FORM=0 REFUSE=0 BIND=0 ACL=0 engine_pin=[valkey=9.1.2, redis=8.10.2])`
  (kv_acl 699 cases per engine: 6 tenants x (rules + 6 own ops + 108 hostile) + 9 refusals).
* `ci/engines.sh with pg19rc1 -- run --pg-onconflict-info --dsn @pg19rc1`: `LOWERING-WRITE PG-ONCONFLICT-INFO
  (information only, not a gate): pg19rc1: P1 foreign-row peek REPRODUCES, P2 hardened clean, P7 DO SELECT/RLS clean,
  P8 DO SELECT/view LEAKS, controls P3-P6 clean`; with pg17,pg18,pg19rc1: P1 REPRODUCES on 17.11 and 18.6 as well.

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

## MariaDB and CockroachDB (P7-oracle-adapters-001, PREFLIGHT D-P7.8, spikes/q4-005)

`lowmy.py` sha256 973213e3688587ced334fd4b4757cb83963766136971022261a945aae8e6d324 (byte-identical in lowering-read and lowering-write); `lowir.py` unchanged (3eb7d790...).

```
ci/engines.sh with mariadb -- oracles/lowering-write/run --engine-pin --skip-sqlite --subject 'target/release/mariadb-subject lowering' --engine mariadb --dsn @mariadb
ci/engines.sh with crdb    -- oracles/lowering-write/run --engine-pin --skip-sqlite --subject 'target/release/crdb-subject lowering' --engine crdb --dsn @crdb
ci/engines.sh with mariadb,crdb -- oracles/lowering-write/run --self-test --skip-sqlite --engine mariadb --dsn @mariadb --engine crdb --dsn @crdb
```

`--engine mariadb` takes a `mysql://user:pw@host:port/db` DSN, `--engine crdb` a `postgresql://` DSN (a postgresql DSN is
CockroachDB iff its `version()` says so, so `--engine pg --dsn A --engine crdb --dsn B` pairs). Engines run on kamrui
(gates `lowering-write-mariadb`, `lowering-write-crdb`). The oracle core (row / Pred generators, Lean effect model,
W1/W2/W4/W6/E checks, family drivers) is unchanged; the engines add a driver (`MariaEng` over the in-file MySQL
client `lowmy.My`, `CrdbEng` = `PgEng`), schemas, two dialect FORM rules, and the reference renderers in `lowmy.py`.
Default `--n 300` x 4 seeds = 1200 cases per family per schema per engine (>= 300 x 4 as the unit requires).

Families per engine: refusals; U / D / UP / UPG over the schemas below; W6 (three FK / unique schemas, InnoDB for
MariaDB); schema-gate demo schemas (information only). No RLS family (neither dialect has `rls_policy` / `rls_bind`;
CockroachDB RLS is not claimed) and no kv families.

| engine | verdict schemas | gate-demo schemas (must be refused by schema-gate-*) |
|---|---|---|
| mariadb 11.8.9 | id PK + tenant `utf8mb4_general_ci`; id PK + tenant default `utf8mb4_uca1400_ai_ci`; composite PK tenant `utf8mb4_nopad_bin`; composite PK tenant `VARBINARY` (x/y/grp keep the server default `uca1400_ai_ci`) | composite PK tenant `utf8mb4_bin` (PAD SPACE), `utf8mb4_general_ci`, default `uca1400_ai_ci`; `nopad_bin` + second `UNIQUE(id)` |
| crdb 25.4.19 | id PK; composite PK; id PK + tenant `COLLATE en_u_ks_level2` | composite PK tenant `en_u_ks_level2`; composite PK + `UNIQUE(id)` |

Dialect FORM rules (token-level, outside literals; added to the existing FORM check, which still applies):

* **mariadb**: no `ON CONFLICT`; no `UPDATE .. RETURNING` (MariaDB has none); an upsert with update columns is
  `INSERT .. VALUES .. ON DUPLICATE KEY UPDATE` and **every** assignment is exactly
  `c = IF(CAST(t AS BINARY) = CAST(VALUES(t) AS BINARY), VALUES(c), c)` (c never the tenant or a key column); an
  upsert without update columns is `INSERT .. SELECT .. FROM DUAL WHERE NOT EXISTS (SELECT ..)`. REPLACE / IGNORE /
  MERGE / WITH stay forbidden by the base rule.
* **crdb**: no `UPSERT` statement; `ON CONFLICT (..) DO UPDATE` carries exactly the guard
  `WHERE <table>.<tenant>::text = excluded.<tenant>::text COLLATE "C"` (q4-005: the postgres guard without the casts is
  evaluated under the tenant column's collation on CockroachDB and lets `ACME` update `acme`).

### Subject contract additions (protocol v2, unchanged envelope)

Requests carry `"dialect":"mariadb"` or `"dialect":"crdb"`. `columns` are IR types (`int` / `text`), never the
physical collation: the subject must neutralise the column collation itself.

* **mariadb** placeholders are `?` (binary prepared statements; the oracle never interpolates). String atoms
  `CAST(c AS BINARY) <op> CAST(? AS BINARY)`; prefix `LEFT(CAST(c AS BINARY), <utf-8 byte length>) = CAST(? AS
  BINARY)`; ints `c = ?` on int columns only; class mismatch -> FALSE; NULL column -> NULL (`CASE WHEN c IS NULL THEN
  NULL ELSE .. END`). The oracle session pins `sql_mode = 'STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION,
  ERROR_FOR_DIVISION_BY_ZERO'` (the adapter must too). An UPDATE with a non-empty `returning` replies
  `{"sql":"UPDATE ..","params":[..],"returning_select":{"sql":"SELECT <post-image projection> FROM t WHERE
  <same lowered WHERE incl. tenant> FOR UPDATE","params":[..]}}`; the oracle runs `returning_select` immediately
  before `sql` in the same transaction and checks its rows exactly as RETURNING rows (W4 / E). `returning_select` in
  any other reply, or any dialect other than mariadb, is FORM. DELETE / INSERT / upsert use `RETURNING`.
* **crdb** is the postgres forms (`$n`, `::text .. COLLATE "C"` atoms, `::bigint`) with the upsert guard above.

### Self-test (`--engine mariadb` / `--engine crdb`)

Positive control (reference `lowmy.py`) PASS, then every SQL write mutant of the SQLite / PG lists plus the q4-005
ones must be caught:

| engine | mutants (expected counter) |
|---|---|
| mariadb | drop-tenant W1, or-precedence W1, upsert-global-arbiter W1, replace-into W1, returning-star W4, set-tenant-passthrough W2, upsert-tenant-from-row W2, like-prefix W1, refuse-all E, lenient-handle REFUSE, insert-global-key W6, fk-global W6, upsert-as-merge FORM, update-via-cte FORM, accept-merge REFUSE, **my-column-collation W1, my-bin-padspace W1, my-update-returning-naive W4, my-odku-unguarded FORM** (the naive MariaDB upsert) |
| crdb | drop-tenant W1, or-precedence W1, upsert-global-arbiter W1, returning-star W4, set-tenant-passthrough W2, upsert-tenant-from-row W2, like-prefix W1, refuse-all E, lenient-handle REFUSE, insert-global-key W6, fk-global W6, upsert-as-merge FORM, update-via-cte FORM, accept-merge REFUSE, **crdb-upsert-stmt W1, crdb-column-collation W1, crdb-reference-guard FORM** (the guard without the q4-005 fix) |

Then the `--subject` (default `lowmy.py serve`) must PASS and `<subject> --mutant drop-tenant` must go red. Not run
on these engines: two-valued-not (near-equivalent on typed columns, as on PG), the RLS and kv mutants (no such
feature in the dialect).

Limits: single-node CockroachDB with an in-memory store, no concurrency (the SERIALIZABLE 40001 retry is the
adapter's, see q4-005 probes); MariaDB `my-odku-unguarded` is behaviourally safe on gate-passing schemas (the arbiter
is exactly (t, key)), so it is caught by FORM, and by W4 only on the gate-demo schemas.

## Known limits / pending

* The pass-1 pending items (RLS-native families, PG19rc1 ON CONFLICT information run, kv_acl hostile-command
  family) are done (pass 2). Subjects (`pg-subject`, `redis-subject`) must now implement `rls_policy` / `rls_bind` /
  `kv_acl` as above: the families run in the `lowering-write-pg` / `lowering-write-redis` gates and a refusal is E.
* RLS family limits: one table shape (global id PK), one policy role; SECURITY DEFINER / invoker triggers (research
  T1-T3), partitioned tables (P2), MERGE under RLS and the RLS plan cache (q1012) are not exercised here (W5 / schema
  gate). `rls-no-check` is caught only by the catalog FORM check (behaviourally equal on FOR ALL, see self-test).
* kv_acl limits: ACL DRYRUN is trusted as the engine's ACL decision (live execution confirms the denials; permitted
  commands are not executed). Commands the corpus does not list (new server commands, other modules) are covered only
  via `-@all` in the reference, not by the oracle; the static offline check flags any category grant.
* W5 (triggers, data-modifying CTEs, FK actions) stays with the schema gate (PLAN D8). W6 is covered for INSERT
  (unique-key and FK existence); UPDATE of a uniquely-constrained column and DELETE under FK RESTRICT are not.
* The FORM check is lexical (keywords outside literals / quoted identifiers); it enforces the mandated forms, it
  does not prove the absence of other statement shapes.
* Redis: only string SET [NX|XX] / DEL / GET / SCAN are modelled offline.
* MySQL/MariaDB/CockroachDB (q4-005) not covered.

`--skip-kv` (2026-10-30): a SQL-only subject (sqlite-subject) is not asked the offline Redis-model families, which the
Redis gates cover with the KV renderer. It applies only to `--subject` runs and the subject positive control; the
oracle's own reference mutants always run every family.
