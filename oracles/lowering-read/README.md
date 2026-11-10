# lowering-read: read-path lowering differential oracle

Checks that a renderer of the IR filter (`Pred`) into engine queries is sound and complete against the formal model
in `spec/AegisIR/Lowering.lean` and `spec/AegisIR/ThreeValued.lean`. Spec clause: **SPEC_INVARIANTS §E "Lowering
soundness"** as rewritten by spike q4-004 (three-valued policy semantics: `eval3`, `refQ3`, `lower_exact3`,
`lowerQ_exact3`, `rows_exact3`, `not_absent_gap`, `sql3_inList_nil`, `inList_nil_not_const_false`; plus
`lower_sound_full`, `refines_necessary`) and its executed contract: **leak = 0 ∧ widen = 0 ∧ miss = 0 against
`refQ3`**, GAP vs the two-valued `refQ` reported as information only, ≥100k cases per ENGINE_PIN.
IMPLEMENTATION_PLAN §2 row "read lowering oracle".

## Run

```
oracles/lowering-read/run                                  # default gate: SQLite (Python stdlib 3.45.3) + offline Redis model, ~17 s
oracles/lowering-read/run --self-test                      # mutants must be caught, ~9 s
oracles/lowering-read/run --self-test --subject "<cmd>"    # + <cmd> must PASS and "<cmd> --mutant drop-tenant" must go red
ci/heavy.sh oracles/lowering-read/run --big --engine-pin   # 100k unique cases at SQLite 3.54.1 (sqlite-exec helper)
oracles/lowering-read/run --subject "<cmd>"                # plug in the Rust renderer (protocol below)
ci/engines.sh with pg17,pg18,valkey,redis -- oracles/lowering-read/run --big --skip-sqlite --engine-pin \
    --engine pg --dsn @pg17 --engine pg --dsn @pg18 --engine redis --url @valkey --engine redis --url @redis
oracles/lowering-read/run --self-test --engine pg --dsn @pg17 --engine redis --url @valkey   # + engine mutants
```

The last line is `LOWERING-READ: PASS (...)` / `LOWERING-READ: FAIL (...)`; exit code 0 only on PASS.
Flags: `--dsn` / `--url` are repeatable (every given PG / Redis-family engine is run). `--skip-sqlite` drops the
SQLite families (and the offline Redis model) for pg-only or kv-only subjects, also in `--self-test`. `--engine-pin`
reads `supply-chain/engine-pins.toml`, identifies each engine started by `ci/engines.sh` through its
`AEGIS_ENGINE_<NAME>` URL (else any pin of that kind and exact version), requires the exact pinned version with policy
`allow` (a blocked pin such as pg19rc1, an unknown version or a mismatch FAILs) and prints the versions in the PASS
line. `--sqlite-exec` (implied by `--engine-pin` when SQLite runs) executes all SQLite SQL through `rust/sqlite-exec`
(own workspace + Cargo.lock; rusqlite =0.41.1 bundled = SQLite 3.54.1, the adapter pin; it only executes, never
renders), built via `ci/heavy.sh` into a per-run `rust/target-*` that is deleted at exit (~25 s build). `--big` =
25,000 cases per seed for SQLite, PG and Redis (>=100k per engine with the 4 default seeds).
`--json FILE` writes the full report. `--seeds`, `--cases-per-seed`, `--rows`, `--selfjoin`, `--pg-cases`,
`--kv-cases` tune the corpus. PG and Redis targets must be **throwaway**: the oracle drops table `t` and FLUSHDBs the given db.
No third-party drivers: PG uses an in-file v3 wire client (trust/cleartext/md5/SCRAM-SHA-256, extended protocol,
text parameters), Redis/Valkey an in-file RESP2 client.

## What is checked

For each (stored rows, tenant handle `t`, `Pred p`) the subject renders `lowerQ t p` as a SQL boolean expression;
the oracle runs `select id from t where <expr>` and compares the returned ids with reference sets computed over the
rows **as stored** (read back after insert, so affinity conversions belong to the state, not the query):

| set | definition (Lean names) |
|---|---|
| permit | `refQ3 tenant t r p` (policy since q4-004: `eval3`, absent/NULL field ⇒ atom UNKNOWN, Kleene and/or/not, permitted iff `some true`) |
| model | `keeps EXACT r (lowerQ tenant t p)` (Kleene `sql3` over an exact backend); equal to permit by `lowerQ_exact3` |
| permit2 | `refQ tenant t r p` (the old two-valued `eval`, absent field ⇒ atom false); information only |
| got | rows the engine returned |

* **LEAK** = got − permit (unsound against the 3VL policy). **Must be 0.**
* **WIDEN** = got − model. **Must be 0.** Since permit = model it equals LEAK on a correct port; kept as a separate
  counter so a port bug in either reference shows up as a disagreement (see `theorem_violations`).
* **MISS** = (permit ∪ model) − got (Backend.Exact violated or incomplete renderer). **Must be 0.**
* **GAP** = permit2 − permit: rows the old two-valued reference permits and `refQ3` denies, i.e. NOT over an absent
  field (`not_absent_gap`). **Information only.** `--miss-vs-2vl` counts GAP as MISS and therefore FAILs; it exists
  to reproduce the pre-q4-004 D1 discussion, not as a gate.
* Also failing: engine errors on rendered SQL, refusals, and `theorem_violations`. On every evaluated row the Python
  port must satisfy `lower_exact3` (`sql3 EXACT (lower p) = eval3 p`), `lowerQ_exact3` (`keeps = refQ3`),
  `lower_sound_full` (`sql3 = some b → eval = b`) and `eval3_sound` (`eval3 = some b → eval = b`). This guards the
  port itself. `eval3`/`refQ3` live in `read_oracle.py`, not in `lowir.py`, because `lowir.py` must stay
  byte-identical with `oracles/lowering-write/lowir.py`.

Families (default run, SQLite 3.45.3 = Python's stdlib):

1. **cex**: the SQLite part of the research 78-case single-cause corpus (15 cases of `round-003/01-work/cex.py`),
   the NUL probes (`probe_nul.json`) and 5 in-repo regressions (NOT over NULL, NOT In [] over NULL, NUL inside a
   prefix, OR precedence, int64 clamping). The 11 PG cases run with `--engine pg`.
2. **research-replay**: a verbatim port of the research generator, replayed on the four research seeds
   1, 2, 3, 20261025 (400 rows x 3000 cases each) on the four research schemas. These are the "4 post-fix seeds":
   calibration r4c12 found seed 20261025 had only ever run pre-fix; it is now run post-fix: 0/0/0.
   Cases with float literals (not a Lean `Value`) are skipped and counted (2281 of 12000).
3. **lean-generated**: Lean-faithful generator (NOT, tt/ff, binary and n-ary And/Or incl. empty, mixed-class and
   inverted ranges, NUL bytes, int64 edges and out-of-range ints, tenant used inside the predicate, NULL tenants,
   stored REAL/BLOB-affinity values) x 5 schemas (untyped, NUMERIC affinity, NOCASE, STRICT ANY, STRICT typed).
   Default 3000 cases/seed x 4 seeds = 12,000 unique (60,000 executions); `--big` = 100,000 unique.
4. **self-join** (plan: "add a self-join family"; PG dca6a9e32 self-join-elimination class): the same table twice,
   `t AS a JOIN t AS b` and a correlated `EXISTS (... t AS b ...)`, each alias with its own rendered predicate
   (`alias`, `param_offset` in the request).
5. **redis keyspace** (aegis_data_ir::kv_plan, read side): logical rows (tenant, collection, key) are written under
   the subject's own `kv_key` answers. Physical keys must be injective (a key shared by two logical rows is a LEAK).
   `kv_scan` (Select Tt / Pfx) must return exactly the tenant's keys in that collection with that key prefix
   (adversarial prefixes and keys containing `* ? [ ] \ : } {`). `kv_get` (Select Eq) must be a single `GET <key>`
   that returns exactly that row's value. Cases are de-duplicated before counting (`--kv-cases` unique per seed).
   Offline via a line-for-line port of `stringmatchlen_impl` (redis 8.10.2 `src/util.c`); live via `SCAN MATCH` / `GET`
   with `--engine redis` (Valkey and Redis).
6. **refusals** (UNREFUSED must be 0): non-canonical tenant handles (upper case, padding, NUL, 15/17 digits, all
   zero, JSON int, fullwidth letters), invalid KV collections (outside `^[a-z_][a-z0-9_]{0,62}$`) and KV keys or
   patterns over 1024 bytes (`KV_MAX_KEY_BYTES`) must be refused. A 900-byte key must be accepted.

Tenants (D4, PLAN Decisions): handles are `tenant_text(TenantId)` = 16 lower-case hex digits. The research tenant
corpus is mapped through `R_TENANT_MAP`. Canonical research tenants become distinct TenantIds. The research confusers
("ACME", "Acme", "acme ", NFD, "01") become non-canonical stored values that a coarse comparison would equate with
the base tenant: upper-case hex (NOCASE / citext / ICU ks-level2), trailing space, a fullwidth digit (ICU width), and
the unpadded form. Further stored confusers: NUL suffix, int, `"0"*16`, the 15-digit and leading-space forms. Rows,
predicates and seeds are otherwise unchanged. A canonical-equivalence (NFC/NFD) confuser does not exist for hex
digits, so the `nd_canon` cex case now uses the width variant (it is no longer a canonical-equivalence witness).

PG (`--engine pg`): the 11 PG cex cases (ICU nondeterministic `ci_nd`/`nd_canon`, citext, glibc range, LIKE),
lean-generated x 4 PG schemas (deterministic default collation, ICU ks-level2, ICU und, citext; `y bigint`,
typed columns, NUL-free corpus because PG text cannot hold NUL), and the self-join family.

## Pass criterion

`leak = widen = miss = errors = refused = unrefused = theorem_violations = 0` (and, with `--engine-pin`, every engine at
its pin), with `permit = refQ3` (GAP vs `refQ` is not part of it). The default run has ≥10k unique generated cases
plus every research seed/regression case; `--big` gives ≥100k unique cases (the Phase 4 gate number).

## Self-test (negative controls)

`--self-test` runs each mutant renderer (in `lowir.py`, `MUTANTS`) on a reduced corpus and requires the stated
counter to go non-zero:

| mutant | caught as |
|---|---|
| drop-tenant | leak |
| two-valued-not (research StrictTyped atoms: FALSE on NULL) | leak (was widen under the 2VL gate) |
| in-nil-const-false (`In f []` rendered as constant FALSE; q4-004) | leak: `NOT (x in [])` on a NULL x returns the row, eval3 is UNKNOWN (`inList_nil_not_const_false`) |
| two-valued-not-absent (`NOT COALESCE(p, FALSE)`: absent ⇒ NOT true; q4-004) | leak (and widen) |
| or-precedence (`tenant AND a OR b`) | leak |
| like-prefix (LIKE s‖'%', no escaping of %/_) | leak |
| empty-or-true (`orN []` ⇒ TRUE) | leak |
| naive-bound (research NaiveBound) | leak |
| no-collate-binary (NOCASE survives unary +) | leak |
| no-affinity-guard (no typeof / unary +) | leak |
| range-exclusive (`<`/`>`) | miss |
| nul-prefix (research `substr(+col,1,n)`) | miss |
| selfjoin-alias (tenant conjunct always on alias a) | leak |
| refuse-all | miss |
| kv-naive (key `t:<unpadded hex><collection>:..`: tenant 2 + `ac` collides with tenant 2a + `c`) | leak |
| kv-escaped-colon (unpadded hex in braces; SCAN pattern `t:{<hex>*` drops the `}:` delimiter) | leak |
| lenient-handle (any tenant handle accepted and bound verbatim) | unrefused |
| kv-no-escape (SCAN prefix not glob-escaped) | leak |
| kv-no-keycap (keys / patterns > 1024 bytes not refused) | unrefused |
| kv-collection-colon (collection not validated) | unrefused |

The kv mutants changed meaning with the D4 encoding: with fixed-width hex handles the research glob-metachar tenants
(`a*`, `a?`) no longer exist, so the cross-tenant hazards left are a missing delimiter or padding.

The two q4-004 mutants are defined in `read_oracle.py` (`LOCAL_MUTANTS`, subclasses of `lowir.Renderer`). Against the
old 2VL permit set they score leak = 0 (only widen: 11 and 248 on the self-test corpus), so they are caught as leaks
only because the gate is now `refQ3`. The self-test also checks the two separating witnesses directly
(`not_absent_gap` and `NOT In []` on NULL: `refQ` permits, `refQ3` denies).

It also checks that naive-bound reproduces every research LEAK verdict of the SQLite cex corpus (10/10), that the
`refines_necessary` witness holds in the model, and that the `--engine-pin` logic accepts a matching pin and rejects a
mismatch, an unknown version, a blocked pin and the wrong kind (8 fixtures). Positive control: the `--subject`
command (default `lowir.py serve`) must PASS on the self-test corpus of every engine in scope, and the same command with
` --mutant drop-tenant` appended must go red (so a Rust subject must implement `--mutant drop-tenant`, which drops all
tenant scoping: SQL conjunct, KV prefix, ACL key pattern). With `--engine pg` it adds pg-no-collate-c, naive-bound,
like-prefix, two-valued-not, drop-tenant, lenient-handle. With `--engine redis` it adds kv-naive, kv-escaped-colon,
kv-no-escape, drop-tenant.

## Subject protocol (for aegis-data-ir / aegis-adapter-*)

`--subject "<cmd>"` starts `<cmd>` once; the oracle writes one JSON object per line to its stdin and reads exactly
one JSON object per line from its stdout (UTF-8; the oracle sends `ensure_ascii` JSON). Each request has `v` (=2) and
`id`; the reply must echo `id`. The reference implementation is `python3 -I lowir.py serve [--mutant NAME]`. A subject
must accept `--mutant drop-tenant` (self-test, see above); any request it cannot serve exactly is answered with
`{"refuse": ...}`.

**Protocol v2 (2026-10-30) changes from v1:** `tenant` is always the D4 text of a TenantId (exactly 16 lower-case hex
digits, not all zero; `aegis_data_ir::parse_tenant_text`), anything else must be refused; KV ops carry `collection`
and `key_hex` / `prefix_hex` (layout `t:{<16hex>}:<collection>:<key>`, aegis_data_ir::kv_plan) instead of
`suffix_hex`; new ops `insert`, `kv_setnx`, `kv_setxx`, `kv_acl`, `rls_policy`, `rls_bind` (write README); write
requests carry `unique` and `fks`; ops `merge`, `cte`, `replace`, `raw_sql` must be refused.

Values: JSON integer = Lean `Value.int`, JSON string = `Value.str`; nothing else (no floats, bools, null).
Pred (mirrors the Lean constructors; fields are column names):
`["tt"]`, `["ff"]`, `["eq",f,v]`, `["in",f,[v...]]`, `["range",f,lo,hi]`, `["pfx",f,s]`, `["and",p,q]`,
`["or",p,q]`, `["not",p]`, `["andN",[p...]]`, `["orN",[p...]]` (`andN [] = tt`, `orN [] = ff`).

**read** request:
```json
{"v":2,"id":1,"op":"read","dialect":"sqlite","table":"t","alias":null,"param_offset":0,
 "tenant_field":"tenant","columns":{"id":"integer","tenant":"text","x":"","y":""},
 "tenant":"0000000000acce55","pred":["not",["eq","x",1]]}
```
`dialect` is `sqlite` (placeholders `?`) or `postgres` (placeholders `$n`, numbered from `param_offset+1`).
`columns` maps every column to its declared type (renderers may rely on it; a typed dialect must). `alias`, if
non-null, qualifies every column (self-join family). Reply: a boolean SQL expression (the WHERE body) and its
parameters, or a refusal:
```json
{"v":2,"id":1,"sql":"((CASE WHEN \"tenant\" IS NULL THEN NULL ELSE (typeof(\"tenant\") = 'text' AND +\"tenant\" = ? COLLATE BINARY) END) AND (NOT (CASE WHEN \"x\" IS NULL THEN NULL ELSE (typeof(\"x\") = 'integer' AND +\"x\" = ?) END)))","params":["0000000000acce55",1]}
{"v":2,"id":1,"refuse":"reason"}
```
KV (byte strings hex; keys and prefixes are UTF-8 text, `Value::Str`):
**kv_key** `{"op":"kv_key","tenant":T,"collection":"notes","key_hex":"6b31"}` → `{"key_hex":"..."}`;
**kv_get** (Select Eq) same fields → `{"commands":[["474554","<key hex>"]]}` (exactly one GET);
**kv_scan** (Select Tt / Pfx) `{"op":"kv_scan","tenant":T,"collection":"notes","prefix_hex":null|"..."}` →
`{"pattern_hex":"..."}` (the oracle drives the SCAN cursor). Collections outside `^[a-z_][a-z0-9_]{0,62}$`, keys or
patterns over 1024 bytes and non-canonical handles must be refused.
Write ops (`update`, `delete`, `insert`, `upsert`, `kv_set`, `kv_setnx`, `kv_setxx`, `kv_del`, `kv_acl`,
`rls_policy`, `rls_bind`) are documented in
`oracles/lowering-write/README.md`; a renderer should implement all of them so one subject serves both oracles.
A subject may also answer `{"op":"hello"}`; the oracle does not require it.

## Reference renderer (follows Lowering.lean)

`lowir.py` ports `eval`, `lower`, `lowerQ`, `sql3`, `k3and/k3or/k3not`, `anyEq`, `refQ`, `keeps`, `Pred.andN/orN`
literally and renders structurally (one SQL node per `SqlExpr` node). Every atom is
`CASE WHEN col IS NULL THEN NULL ELSE <exact test> END`, so a NULL column is UNKNOWN exactly as in `sql3`, and the
exact tests make SQLite a `Backend.Exact` instance on all five schemas: SQLite `typeof(col)='<class>' AND +col = ?
COLLATE BINARY`; ranges with typeof guard, unary + and COLLATE BINARY (UTF-8 byte order = code-point order);
prefix as a byte prefix of the UTF-8 encoding (`coalesce(substr(CAST(+col AS BLOB),1,nbytes),x'') =
coalesce(CAST(? AS BLOB),x'')`; UTF-8 is prefix-free so this equals `refPrefix`); class-mismatched or
out-of-int64 literals render as constant FALSE atoms (ranges clamp). Postgres: `col::text = $n::text COLLATE "C"`,
`left(col::text,$n::int) = $m::text COLLATE "C"`, `bigint` comparisons, FALSE on class mismatch with the declared
column type.

## Divergences found (reported, not silently fixed)

* **D1 SPEC §E vs Lowering.lean (resolved 2026-10-25 by spike q4-004).** §E now defines the policy as `refQ3`, and
  `lowerQ_exact3` proves equality with SQL 3VL on exact backends, so the gate is against `refQ3` and the GAP below is
  information only. Original text: SPEC §E stated `Backend.Exact ⇒ rows(render(lower(t,p))) = {x | x.tenant = t ∧
  ⟦p⟧(x)}`. The Lean file proves only `sql3 = some b → eval = b` (`lower_sound_full`), i.e. ⊆. With NOT over a
  NULL/absent field the policy permits (`not_absent_permits`) and SQL drops, so equality is false: the default run
  measures GAP in 5,334 cases (46,944 with `--big`). Equality holds only for NOT-free predicates or non-null fields.
  The oracle then gated on `model` and reported GAP; the flag `--miss-vs-policy` applied the old SPEC wording and
  failed. That flag is now `--miss-vs-2vl` (GAP = refQ − refQ3, information only).
* **D2 research IR ≠ Lean IR.** The research oracle has no NOT and treats float as a third storage class; Lean
  `Value` is int | str only. 2281/12000 research-replay cases contain float literals and are skipped.
* **D3 research hardened atoms are two-valued.** `StrictTyped`'s `typeof(col)=... AND ...` is FALSE (not UNKNOWN)
  on NULL, so it disagrees with `sql3`; harmless in research (no NOT), but with NOT it is exactly the
  `two-valued-not` mutant (WIDEN > 0). The reference wraps atoms in `CASE WHEN col IS NULL THEN NULL`.
  On PG, `=`, `left()` and comparisons already propagate NULL, so there the wrapper matters only for
  class-mismatch FALSE atoms and empty IN.
* **D4 research hardened prefix misses on NUL.** SQLite text `substr()` stops at the first NUL, so
  `substr(+col,1,n) = ?` is false for a prefix containing NUL (MISS, fail-safe; Refines but not Exact). Kept as
  the `nul-prefix` mutant.
* **D5 own first fix was wrong, caught by this oracle.** SQLite returns NULL (not `x''`) for `substr`/`CAST` of a
  zero-length BLOB; the first BLOB-prefix rendering missed every empty stored string. Fixed with `coalesce`.
* **D6 Lean comment vs Lean definition for `inList []` (resolved by q4-004).** The `SqlExpr` comment said "[] ⇒
  FALSE", but `sql3 (.inList f [])` is UNKNOWN on a NULL column. The comment is fixed and `sql3_inList_nil` /
  `inList_nil_not_const_false` are proved. Research renders `(1=0)` (FALSE), which differs under NOT; that rendering
  is now the `in-nil-const-false` mutant. The reference follows the definition.

## Research provenance (untrusted input: read, reviewed and re-implemented; never executed in place)

| sha256 | path under `research/state/raw/` | used for |
|---|---|---|
| 3360dea3ed10c819090ca1dbc791bb7303056e0fbe49f597f8ed82845f80860c | round-004/02-work/oracle.py (= round-003/01-work/oracle.py) | reference/leak/miss definitions, generator (verbatim port), schemas, NaiveBound/StrictTyped (mutants), stringmatchlen, Redis tenants |
| 70a2a367294a2c34d1eb7d94f835bb7a67af0344264669d922b23a5f31d8f88f | round-004/02-work/oracle_typed.py (= round-003) | STRICT typed schema + coercion |
| bf40f25f466691760de5153708884d6a07e213843cf78809be5d53b9f66d87bd | round-004/02-work/rd_run.py | RESP client (reviewed port); it is a Redis write/ACL harness, see lowering-write |
| fe827188110589cc3ab018020400097224d00955dfa9f2d835e94bff2a3d4adc | round-003/01-work/cex.py | 78-case corpus (SQLite 15 + PG 11 cases) |
| 636f2d76e68aff9e71edec805e530e90644cff2c62448e27344955c664b2decf | round-003/01-work/cex_results.json | expected research verdicts (naive LEAK list) |
| fe9ca0d36f1d21023f658faaee8cdb5a9db270ba7767ae0e9855ea6877e1ec2b | round-003/01-work/probe_nul.json | NUL probe |
| 4579c4b6bba55d2214048b4a518906856b198ac5eaccc52300723b50fd556abe | round-003/01-work/q1012_repro.py | read; PG RLS plan-cache scenario, not a lowering check, not ported |
| 6a0f3a81a2b9853cec9a2d92c82383b26c5eef2302200839c4b0fa79ee5fc8cd | round-003/01-dataplane-ir-lowering-soundness.json | corpus description, denylist, contract |
| 7215e7d602f63958107895a8b16a4981ed27556e9880369fd911205d01a54267 | round-004/01-lean-check-lowering-and-token-proofs.json | not_absent_permits / refines_insufficient_for_not context |
| 468e2e5fafd906650f0a894b607f2dff077c6c51d56bdc51f091e8aa5c322e28 | round-004/12-calibration-two-sided-top-findings-r3.json | "4 post-fix seeds" (seed 20261025 pre-fix only) and self-join recommendation |
| df77c6e4aa6aceaa8d709615ddb43069d2da92a3b75ffdae0f76b5bd55dbd212 | round-004/_verify_r4_verdicts.json | same finding, verifier verdict |
| 18e95e213b77215919b30f987e2ed63818b6bae8f038af4bddf5d25960e4a3dd | round-004/02-write-path-lowering-differential-oracle.json | context |

In-repo inputs (2026-10-25, after q4-004): `spec/AegisIR/ThreeValued.lean` 278740ea86d7cdfc7a4e74acc72c2ba4af4c19a06a097ec716ee7396153d0135,
`spec/AegisIR/Lowering.lean` 007e2f74bda62896066c006a90cfa7f0438f05f6fb675616a925ae4140190f3e, `spec/SPEC_INVARIANTS.md` 1fd940943a4c1e67921cca70b5a556231598b6f0222e9c5821baffd0e02c82c1,
`spikes/q4-004/verdict.json` (decision and `oracle_follow_up`).
`lowir.py` is byte-identical to `oracles/lowering-write/lowir.py` (sha256 3eb7d79037e2dbb57b276da12d529f5b00fbe8778a3afe2d609891223151b14f).

## Re-run in repo (2026-10-25, after switching the gate to refQ3; Python 3.12, SQLite 3.45.3)

* `run`: `LOWERING-READ: PASS (cases=103917 generated_unique_sqlite=12000 (x5 schemas=60000) generated_unique_pg=0 (x4 schemas) leak=0 widen=0 miss=0 gap_vs_2vl(info)=5334 errors=0)`, 17 s. theorem_violations=0 (lower_exact3, lowerQ_exact3, lower_sound_full, eval3_sound on 1,727,370 row evaluations).
* `ci/heavy.sh ... --big`: `LOWERING-READ: PASS (cases=543917 generated_unique_sqlite=100000 (x5 schemas=500000) generated_unique_pg=0 (x4 schemas) leak=0 widen=0 miss=0 gap_vs_2vl(info)=46944 errors=0)`, 141 s (theorem_violations=0 over 6,548,757 row evaluations).
* `--self-test`: `LOWERING-READ SELF-TEST: PASS (16/16 mutants caught; research naive LEAKs reproduced; positive control PASS)`, 7.5 s.
* Not re-run after this change: `--engine pg` / `--engine redis` (no throwaway PG/Valkey container was started).
  Before the change (2-valued gate): PG 17.11 + Valkey PASS, 24,530 cases, self-test 21/21 with engines.

## Re-run in repo (2026-10-30, P4-oracle-lowering-001: D4 tenants, protocol v2; Python 3.12.9)

Engines from `ci/engines.sh with pg17,pg18,valkey,redis` (pinned digests; 17.11, 18.6, Valkey 9.1.2, Redis 8.10.2).
These close BACKLOG "re-run PG and Redis after the refQ3 switch".
* `run`: `LOWERING-READ: PASS (cases=113971 generated_unique[sqlite=12000 redis_model=10000] ... leak=0 widen=0 miss=0 gap_vs_2vl(info)=3623 errors=0 unrefused=0)`, 17 s.
* `--self-test`: `LOWERING-READ SELF-TEST: PASS (20/20 mutants caught; ...; subject drop-tenant caught; pin fixtures 8/8)`, 9 s.
  With `--engine pg --dsn @pg17 --engine redis --url @valkey` (the unit acceptance): 30/30, `RC=0`.
* `ci/heavy.sh run --big --engine-pin` (SQLite 3.53.2 via sqlite-exec): `LOWERING-READ: PASS (cases=643971 generated_unique[sqlite=100000 redis_model=100000] (sqlite x5 schemas=500000 ...) leak=0 widen=0 miss=0 gap_vs_2vl(info)=29982 errors=0 unrefused=0 engine_pin=[sqlite 3.53.2])`, 87 s.
* `--big --skip-sqlite --engine-pin --engine pg --dsn @pg17 --engine pg --dsn @pg18`: `LOWERING-READ: PASS (cases=801056 generated_unique[pg=100000] (... pg x4 schemas x2 engines) leak=0 widen=0 miss=0 gap_vs_2vl(info)=86776 errors=0 unrefused=0 engine_pin=[pg17=17.11, pg18=18.6])`, 143 s.
* `--big --skip-sqlite --engine-pin --engine redis --url @valkey --engine redis --url @redis`: `LOWERING-READ: PASS (cases=200114 generated_unique[redis=100000] ... leak=0 widen=0 miss=0 errors=0 unrefused=0 engine_pin=[valkey=9.1.2, redis=8.10.2])`, 37 s (100k de-duplicated cases per engine; the counter shows the minimum over engines).

## Re-run in repo (2026-10-30, P4-oracle-lowering-001 pass 2: RLS / kv_acl families in lowering-write)

`lowir.py` changed only in the write-side ops `kv_acl` (no `+scan`; new mutants `kv-acl-allkeys`, `kv-acl-no-brace`,
`kv-acl-eval`) and `rls_policy` / `rls_bind` (new mutants `rls-no-check`, `rls-wrong-column`,
`rls-session-setting`); no read path changed. Re-run:
* `run`: `LOWERING-READ: PASS (cases=113971 generated_unique[sqlite=12000 redis_model=10000] (sqlite x5 schemas=60000; pg x4 schemas x0 engines) leak=0 widen=0 miss=0 gap_vs_2vl(info)=3623 errors=0 unrefused=0)` (identical to pass 1).
* `--self-test`: `LOWERING-READ SELF-TEST: PASS (20/20 mutants caught; research naive LEAKs reproduced; positive control PASS; subject drop-tenant caught; pin fixtures 8/8)`;
  with `--engine pg --dsn @pg17 --engine redis --url @valkey` (unit acceptance): 30/30, `RC=0`.

## MariaDB and CockroachDB (P7-oracle-adapters-001, PREFLIGHT D-P7.8, spikes/q4-005)

`lowmy.py` sha256 973213e3688587ced334fd4b4757cb83963766136971022261a945aae8e6d324 (byte-identical in lowering-read and lowering-write); `lowir.py` unchanged (3eb7d790...).

```
ci/engines.sh with mariadb -- oracles/lowering-read/run --engine-pin --skip-sqlite --subject 'target/release/mariadb-subject lowering' --engine mariadb --dsn @mariadb
ci/engines.sh with crdb    -- oracles/lowering-read/run --engine-pin --skip-sqlite --subject 'target/release/crdb-subject lowering' --engine crdb --dsn @crdb
ci/engines.sh with mariadb,crdb -- oracles/lowering-read/run --self-test --skip-sqlite --engine mariadb --dsn @mariadb --engine crdb --dsn @crdb
```

`--engine mariadb` takes `mysql://user:pw@host:port/db`, `--engine crdb` a `postgresql://` DSN (CockroachDB iff its
`version()` says so). `--my-cases` / `--crdb-cases` default to 25,000 generated cases per seed, so the gate command
(no `--big`) runs >= 100k unique cases per engine with the 4 default seeds, each over every schema below. The check
(LEAK / WIDEN / MISS against `refQ3`, theorem checks, refusals of non-canonical handles) is unchanged; the engines add
a driver (`MyDB` over `lowmy.My`; CockroachDB reuses `PgDB`), schemas, a q4-005 cex corpus and the reference
dialects in `lowmy.py` (byte-identical copy in `oracles/lowering-write/`; it imports `lowir.py` unmodified).

| engine | schemas (tenant, x physical types; y bigint / INT8; requests declare IR types text / int) | cex corpus |
|---|---|---|
| mariadb 11.8.9 | default `utf8mb4_uca1400_ai_ci` (case+accent-insensitive, PAD SPACE); `utf8mb4_general_ci`; `utf8mb4_bin` (binary, PAD SPACE); `VARBINARY` tenant + `utf8mb4_nopad_bin` x. NUL-bearing values included. | 16 cases: case / PAD SPACE / accent / `ß`=`ss` collation confusers, LIKE case + `_` + backslash, int-vs-VARCHAR coercion (`'1'`, `'1e0'`), collation range, empty Or, NULL, NUL tenant |
| crdb 25.4.19 | `STRING` (byte order); `COLLATE en_u_ks_level2`; `COLLATE en_u_ks_level1` (tenant and x). No NUL (PG wire text). | 10 cases: collated tenant / field case and accent, collated range, LIKE `_` / backslash, trailing space, empty Or, NULL |

Plus the non-canonical handle family and a self-join family per seed. Subject contract: requests carry
`"dialect":"mariadb"` (placeholders `?`, atoms `CAST(c AS BINARY) <op> CAST(? AS BINARY)`, prefix
`LEFT(CAST(c AS BINARY), <utf-8 bytes>) = CAST(? AS BINARY)`, `TRUE`/`FALSE`, NULL column -> NULL) or
`"dialect":"crdb"` (the postgres forms: `$n`, `c::text = $n::text COLLATE "C"`, `::bigint`); the reply is the same
`{"sql": <boolean expression>, "params": [...]}`.

Self-test mutants (expected counter): mariadb drop-tenant, two-valued-not (widen), or-precedence, like-prefix,
empty-or-true, naive-bound, range-exclusive (miss), selfjoin-alias, refuse-all (miss), lenient-handle (unrefused),
my-column-collation, my-bin-padspace (leak unless noted); crdb the same generic list plus crdb-column-collation.
`pg-no-collate-c` is not in the crdb list: on CockroachDB `::text` already drops a collated string's locale, so it is
equivalent there (q4-005). The local q4-004 mutants (in-nil-const-false, two-valued-not-absent) subclass the
reference postgres / sqlite renderer and stay in the SQLite list. `--engine-pin` knows kinds `mariadb` and `crdb`.

## Known limits / pending

* The default run (and every self-test) executes SQLite with Python's stdlib 3.45.3; only `--engine-pin` /
  `--sqlite-exec` runs use the adapter pin 3.54.1. PG 19rc1 is not run here (blocked pin; `--engine-pin` FAILs on it).
  The Redis read side covers the key namespace only (no value filters exist in the IR for Redis).
* The sqlite-exec helper is trusted to forward SQL and values faithfully (it binds and reads via rusqlite; values are
  hex-encoded on the pipe). It is checked only indirectly: the reference passes and drop-tenant goes red through it.
* The reference evaluator and generators are self-written (calibration's overclaim risk still applies); the
  corpus is random over curated adversarial values, not exhaustive.
* Not covered: MySQL/MariaDB, SQL Server, MongoDB (doc-derived denylist only), timing/scoring side channels,
  RLS plan-cache (q1012), PG self-join elimination on PG master (needs a PG master build), engine logic bugs
  beyond what the corpus hits.
* Under the three-valued policy `NOT (f = v)` does not match rows whose f is NULL, and the IR has no `isNull` atom, so
  "f != v or f is missing" is not expressible yet (q4-004 follow-up). The oracle checks the semantics as frozen.
* F4's `Not` ⇒ `Fidelity::Exact` rule is enforced in `check_schema`, not here. This oracle tests one renderer that
  claims Exact; it does not test that a Refines adapter refuses `Not`.
