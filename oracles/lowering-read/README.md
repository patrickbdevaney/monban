# lowering-read: read-path lowering differential oracle

Checks that a renderer of the IR filter (`Pred`) into engine queries is sound and complete against the formal model
in `spec/AegisIR/Lowering.lean`. Spec clause: **SPEC_INVARIANTS §E "Lowering soundness"** (`lower_sound_pos`,
`lowerQ_sound`, `lower_sound_full`, `lowerQ_sound_full`, `refines_necessary`, `not_absent_permits`) and the
R-DB-7 executed contract (leak = 0 ∧ miss = 0, ≥100k cases per ENGINE_PIN). IMPLEMENTATION_PLAN §2 row
"read lowering oracle".

## Run

```
oracles/lowering-read/run                                  # default gate: SQLite (stdlib), offline, ~10 s
oracles/lowering-read/run --self-test                      # mutants must be caught, ~5 s
ci/heavy.sh oracles/lowering-read/run --big                # 100k unique generated cases (x5 schemas), ~45 s
oracles/lowering-read/run --subject "<cmd>"                # plug in the Rust renderer (protocol below)
oracles/lowering-read/run --engine pg --dsn postgresql://postgres:x@127.0.0.1:55711/postgres \
                          --engine redis --url redis://127.0.0.1:55712/9     # optional live engines
oracles/lowering-read/run --self-test --engine pg --dsn ... --engine redis --url ...   # + engine mutants
```

The last line is `LOWERING-READ: PASS (...)` / `LOWERING-READ: FAIL (...)`; exit code 0 only on PASS.
`--json FILE` writes the full report. `--seeds`, `--cases-per-seed`, `--rows`, `--selfjoin`, `--pg-cases` tune
the corpus. PG and Redis targets must be **throwaway**: the oracle drops table `t` and FLUSHDBs the given db.
No third-party drivers: PG uses an in-file v3 wire client (trust/cleartext/md5/SCRAM-SHA-256, extended protocol,
text parameters), Redis/Valkey an in-file RESP2 client.

## What is checked

For each (stored rows, tenant handle `t`, `Pred p`) the subject renders `lowerQ t p` as a SQL boolean expression;
the oracle runs `select id from t where <expr>` and compares the returned ids with reference sets computed over the
rows **as stored** (read back after insert, so affinity conversions belong to the state, not the query):

| set | definition (Lean names) |
|---|---|
| permit | `refQ tenant t r p` (policy, two-valued `eval`, absent field ⇒ atom false) |
| model | `keeps EXACT r (lowerQ tenant t p)` (Kleene `sql3` over an exact backend) |
| got | rows the engine returned |

* **LEAK** = got − permit (unsound). **Must be 0.**
* **WIDEN** = got − model (a row the Lean lowering drops; LEAK ⊆ WIDEN because model ⊆ permit by `lowerQ_sound_full`).
  **Must be 0.** This is what catches a two-valued NOT over NULL fields, which is *not* a leak under the current
  two-valued `eval` (see D1).
* **MISS** = model − got (Backend.Exact violated or incomplete renderer). **Must be 0.**
* **GAP** = permit − model: rows the policy permits but SQL 3VL drops (`not_absent_permits`). Reported, not failing;
  `--miss-vs-policy` counts GAP as MISS (it then FAILs: the spec decision "three-valued reference for NOT over absent
  fields" is still open).
* Also failing: engine errors on rendered SQL, refusals, and `theorem_violations` (on every evaluated row the
  Python port must satisfy `lower_sound_full`: `sql3 = some b → eval = b`; guards the port itself).

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
5. **redis keyspace**: `kv_key` must be injective across tenants; `kv_scan`'s pattern must match exactly the
   tenant's own keys, using the research tenant corpus (`a*`, `a?`, `a[b]`, `acme:x`, ...). Offline via a
   line-for-line port of `stringmatchlen_impl` (redis 8.10.2 `src/util.c`); live via `SCAN MATCH` with `--engine redis`.

PG (`--engine pg`): the 11 PG cex cases (ICU nondeterministic `ci_nd`/`nd_canon`, citext, glibc range, LIKE),
lean-generated x 4 PG schemas (deterministic default collation, ICU ks-level2, ICU und, citext; `y bigint`,
typed columns, NUL-free corpus because PG text cannot hold NUL), and the self-join family.

## Pass criterion

`leak = widen = miss = errors = refused = theorem_violations = 0`. The default run has ≥10k unique generated cases
plus every research seed/regression case; `--big` gives ≥100k unique cases (the Phase 4 gate number).

## Self-test (negative controls)

`--self-test` runs each mutant renderer (in `lowir.py`, `MUTANTS`) on a reduced corpus and requires the stated
counter to go non-zero:

| mutant | caught as |
|---|---|
| drop-tenant | leak |
| two-valued-not (research StrictTyped atoms: FALSE on NULL) | widen |
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
| kv-naive, kv-escaped-colon | leak |

It also checks that naive-bound reproduces every research LEAK verdict of the SQLite cex corpus (10/10), that the
`refines_necessary` witness holds in the model, that the unmutated reference passes **through the `--subject`
process protocol** (positive control), and that `drop-tenant` served out-of-process is caught. With `--engine pg`
it adds pg-no-collate-c, naive-bound, like-prefix, two-valued-not, drop-tenant; with `--engine redis` the two kv mutants.

## Subject protocol (for aegis-data-ir / aegis-adapter-*)

`--subject "<cmd>"` starts `<cmd>` once; the oracle writes one JSON object per line to its stdin and reads exactly
one JSON object per line from its stdout (UTF-8; the oracle sends `ensure_ascii` JSON). Each request has `v` (=1) and
`id`; the reply must echo `id`. The reference implementation is `python3 -I lowir.py serve [--mutant NAME]`.

Values: JSON integer = Lean `Value.int`, JSON string = `Value.str`; nothing else (no floats, bools, null).
Pred (mirrors the Lean constructors; fields are column names):
`["tt"]`, `["ff"]`, `["eq",f,v]`, `["in",f,[v...]]`, `["range",f,lo,hi]`, `["pfx",f,s]`, `["and",p,q]`,
`["or",p,q]`, `["not",p]`, `["andN",[p...]]`, `["orN",[p...]]` (`andN [] = tt`, `orN [] = ff`).

**read** request:
```json
{"v":1,"id":1,"op":"read","dialect":"sqlite","table":"t","alias":null,"param_offset":0,
 "tenant_field":"tenant","columns":{"id":"integer","tenant":"text","x":"","y":""},
 "tenant":"acme","pred":["not",["eq","x",1]]}
```
`dialect` is `sqlite` (placeholders `?`) or `postgres` (placeholders `$n`, numbered from `param_offset+1`).
`columns` maps every column to its declared type (renderers may rely on it; a typed dialect must). `alias`, if
non-null, qualifies every column (self-join family). Reply: a boolean SQL expression (the WHERE body) and its
parameters, or a refusal:
```json
{"v":1,"id":1,"sql":"((CASE WHEN \"tenant\" IS NULL THEN NULL ELSE (typeof(\"tenant\") = 'text' AND +\"tenant\" = ? COLLATE BINARY) END) AND (NOT (CASE WHEN \"x\" IS NULL THEN NULL ELSE (typeof(\"x\") = 'integer' AND +\"x\" = ?) END)))","params":["acme",1]}
{"v":1,"id":1,"refuse":"reason"}
```
**kv_key** `{"op":"kv_key","tenant":"acme","suffix_hex":"6b31"}` → `{"key_hex":"..."}`;
**kv_scan** `{"op":"kv_scan","tenant":"acme"}` → `{"pattern_hex":"..."}` (the oracle drives the SCAN cursor).
Write ops (`update`, `delete`, `upsert`, `kv_set`, `kv_del`, `kv_get`) are documented in
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

* **D1 SPEC §E vs Lowering.lean.** SPEC §E states `Backend.Exact ⇒ rows(render(lower(t,p))) = {x | x.tenant = t ∧
  ⟦p⟧(x)}`. The Lean file proves only `sql3 = some b → eval = b` (`lower_sound_full`), i.e. ⊆. With NOT over a
  NULL/absent field the policy permits (`not_absent_permits`) and SQL drops, so equality is false: the default run
  measures GAP in 5,334 cases (46,944 with `--big`). Equality holds only for NOT-free predicates or non-null fields.
  The oracle gates on `model` (what Lean proves a correct renderer returns) and reports GAP; `--miss-vs-policy`
  applies the SPEC wording and fails.
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
* **D6 Lean comment vs Lean definition for `inList []`.** The `SqlExpr` comment says "[] ⇒ FALSE", but
  `sql3 (.inList f [])` is UNKNOWN on a NULL column. Research renders `(1=0)` (FALSE), which differs under NOT. The
  reference follows the definition.

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

In-repo inputs: `spec/AegisIR/Lowering.lean` 5b79eac2615fdd02e5f7260919080d178e9f7fd24206b9b56fd093f034c70203,
`spec/SPEC_INVARIANTS.md` 2d7444473fe2f878680c70ba87d721a52ba7a2a3348b1a24125a8363dab12ac1.
`lowir.py` is byte-identical to `oracles/lowering-write/lowir.py` (sha256 e5774a4bbb32420a9fcaf4288b62085c5cf59d687bdbaff94ac6a40e792be5b4).

## Re-run in repo (2026-10-25, Python 3.12.9, SQLite 3.45.3)

* `run`: `LOWERING-READ: PASS (cases=103917 generated_unique_sqlite=12000 (x5 schemas=60000) ... leak=0 widen=0 miss=0 gap=5334 errors=0)`, 10 s.
* `ci/heavy.sh ... --big`: `LOWERING-READ: PASS (cases=543917 generated_unique_sqlite=100000 (x5 schemas=500000) ... leak=0 widen=0 miss=0 gap=46944 errors=0)`, 43 s.
* `--self-test`: `LOWERING-READ SELF-TEST: PASS (14/14 mutants caught; research naive LEAKs reproduced; positive control PASS)`;
  with PG 17.11 + Valkey: 21/21.
* `--engine pg` (postgres:17 image, 17.11) `--engine redis` (valkey/valkey:alpine), `--pg-cases 1500`: PASS, 24,530
  cases, leak=0 widen=0 miss=0, 14.7 s.

## Known limits / pending

* Engines are whatever the run used: SQLite is Python's bundled 3.45.3, not the ENGINE_PIN the adapter will ship;
  PG was tested on 17.11 only (19rc1 image present but not run); Redis read side covers the key namespace only
  (no value filters exist in the IR for Redis).
* The reference evaluator and generators are self-written (calibration's overclaim risk still applies); the
  corpus is random over curated adversarial values, not exhaustive.
* Not covered: MySQL/MariaDB, SQL Server, MongoDB (doc-derived denylist only), timing/scoring side channels,
  RLS plan-cache (q1012), PG self-join elimination on PG master (needs a PG master build), engine logic bugs
  beyond what the corpus hits.
* The GAP / three-valued reference decision (D1) is a spec decision; until it is made, NOT over nullable fields
  returns fewer rows than the policy permits.
