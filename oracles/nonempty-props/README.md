# nonempty-props: INV-NONEMPTY property oracle (gate `nonempty-props`)

A blocking gate for `aegis-adapter-host` (P4-host-001). It checks INV-NONEMPTY (`spec/SPEC_INVARIANTS.md` §A: "An
empty capability set denies; `Unrestricted` is explicit and CI-gated ... proptest 100k/adapter") on seeded
(capset, op) pairs for each of the four adapters `sqlite`, `pg`, `redis` and `oop` (out of process). A subject is
judged only by its replies. Until host-subject exists, the subject is the stdlib reference in `ref_subject.py`.
The "CI-gated" and default-boot half of the invariant is `ci/unrestricted.py` (gate `unrestricted-ledger`).

```
oracles/nonempty-props/run                        # reference subject, 100,000 cases per adapter, seed 1
oracles/nonempty-props/run --cases N --seed S
oracles/nonempty-props/run --subject '<cmd>'      # external subject speaking the protocol below
oracles/nonempty-props/run --mutate <m>           # reference (or --subject) run with a mutation, for diagnosis
oracles/nonempty-props/run --self-test            # 12 reference mutants + the protocol path; all must be caught
oracles/nonempty-props/run --self-test --subject '<cmd>'   # subject clean, and '<cmd> --mutate m' caught for 5 m
```
Last line: `NONEMPTY-PROPS: PASS (...)` or `NONEMPTY-PROPS: FAIL (...)`; for the self-test,
`NONEMPTY-PROPS SELF-TEST: PASS|FAIL (...)`. The exit code is 0 only on PASS. The default run (400k cases) takes
about 20 s on this laptop and the self-test about 8 s. Run both through `ci/heavy.sh`.

## What is checked

Each case is labelled when it is generated, and the label is re-checked against `cover()`, a restatement of the spec
in `nonempty_props.py` that does not use `ref_subject.py`.

| category (share) | capset | must |
|---|---|---|
| covering (30%) | a list holding one cap that covers the op, plus 0–3 non-covering decoys, shuffled | allow (non-vacuity) |
| unrestricted (6%) | the exact string `"unrestricted"` | allow (non-vacuity) |
| empty (6%) | `[]` | deny |
| absent (6%) | no `capset` member (the route has no data block) | deny |
| null (6%) | `null` (an error that produced an empty principal: LiteLLM CVE-2026-59822 shape) | deny |
| malformed (16%) | (a) scalars and look-alikes: `"*"`, `"all"`, `"Unrestricted"`, `" unrestricted"`, `{}`, `{"unrestricted":true}`, `true`, `0`, `["unrestricted"]`, `["*"]`, `[null]`, `[{}]` ...; (b) a covering cap broken in one field (ops or columns missing, `["*"]`, `["all"]`, upper-case op names, ops as a string, columns `null`/`true`/string ids/negative, an extra key) with decoys; (c) a valid covering cap next to a broken one | deny |
| noncovering (30%) | well-formed caps, none covering: wrong adapter (other adapter, case variant, `"*"`, `""`), wrong collection (other, prefix, suffix, trailing space, case variant, `"*"`, `""`), kind not in ops, a touched column missing, `columns: []`, `ops: []`, and the split pair (cap A has the kind but lacks column d; cap B has d but lacks the kind) | deny |

Violations: `ALLOW-ON-{EMPTY,ABSENT,NULL,MALFORMED,NONCOVERING}` (INV-NONEMPTY), `DENY-ON-{COVERING,UNRESTRICTED}`
(non-vacuity: a subject that denies everything is red), `RENDER-ON-DENY` (a deny must be decided before render is
reached), `PROTO` (missing, malformed or out-of-order reply).

**Vacuity guard.** The run fails if any (adapter, category) cell is 0, or if an adapter never replies
`allow` with `rendered: true` (the render step must be reachable, or "no render on deny" says nothing). The first
seven cases of every adapter cover the seven categories once, so even small runs are not vacuous.

## Pass criterion

0 violations over `--cases` (default 100,000) cases per adapter, and no empty coverage cell.

## Normative semantics (the contract for the Rust subject)

These are stated on the wire, not on Rust names. P4-spec-001 defines the types (Decision D1: CapSet has no empty
constructor, `Unrestricted` is an explicit variant).

1. A capset is the exact string `"unrestricted"`, or a non-empty list of caps. A cap is an object with exactly the
   members `adapter` (string), `collection` (string), `ops` (list of `select|insert|update|delete|upsert`) and
   `columns` (list of u32 field ids). Matching is exact and byte-wise. There are no wildcards and no case folding.
2. An absent capset, `null`, `[]`, any other string, any other JSON type, and any list that does not parse
   entirely deny every op. One malformed element makes the whole capset deny, even when another element covers
   (a typed parse into CapSet fails as a whole). Missing `ops` or `columns` never means "all".
3. `"unrestricted"` allows every op on every adapter and collection. Whether it may appear at all is
   `ci/unrestricted.py`'s job, not this oracle's.
4. A list capset allows an op only if a single cap covers it: `cap.adapter == adapter`,
   `cap.collection == op.collection`, `op.kind ∈ cap.ops`, and `touched(op) ⊆ cap.columns`, where
   `touched(op)` = the fields read by the filter ∪ the written fields ∪ the returning fields. Caps are never
   unioned. `columns: []` covers no column, and `ops: []` covers no kind. The generator never puts a covering cap
   next to an `ops: []` or `columns: []` cap, so whether those parse is left open.
5. Pipeline order: authorize, then (only if allowed) the later stages and render. A deny has `rendered: false`.

## Subject protocol

`--subject '<cmd>'` is split with shlex (no shell). The oracle runs the subject once per chunk of 5,000 requests:
it writes JSON lines to stdin, closes stdin, and reads exactly one JSON line per request from stdout, in order.
Exit code 0 is required. For the self-test, the oracle appends `--mutate <name>` to the command. The subject must
implement the five REQUIRED mutants below, and must exit non-zero for an unknown name.

Request (one line):
```
{"op":"authorize", "case":n, "adapter":"sqlite"|"pg"|"redis"|"oop",
 "capset": <capset>,            // member absent in the "absent" category
 "schema": {"collection":s, "tenant_field":0, "columns":[{"field":u32,"name":s,"nullable":false,
            "collation":"binary","key":bool}...], "permitted":[u32...], "unique_indexes":[{"fields":[0,1],"prefix":false}]},
 "data_op": {"tenant":"<16 lowercase hex digits>", "collection":s,
             "kind":"select"|"insert"|"update"|"delete"|"upsert",
             "filter":pred, "writes":[[u32, value]...], "returning":[u32...]}}
```
- `pred` uses the positional F10 encoding (`interfaces/F10-module-wire.cddl`): `[0]` tt, `[1]` ff, `[2,f,v]` eq,
  `[3,f,[v...]]` isIn, `[4,f,lo,hi]` range, `[5,f,s]` pfx, `[6,a,b]` and, `[7,a,b]` or, `[8,a]` not (never
  generated: Refines adapters reject Not). `value` is a JSON integer within ±(2⁵³−1), or a string.
- `tenant` follows Decision D4 (TenantId u64 as lowercase 16-digit hex), including 0x…01, 2⁶³ and 2⁶⁴−1.
- The op passes `check_schema` against `schema` (fidelity Refines): the tenant field (0) is never read, written or
  returned, returning ⊆ permitted, an upsert's only unique index is (tenant, key), and at least one column is
  touched. `redis` ops use the KV shape (P4-spec-001 KV mapping): kinds select/insert/upsert/delete, filter
  `eq`/`pfx` on the key field 1, writes to key 1 and value 2. So a subject can reach render on every allowed case.
- The request member that names the message is `op`. The data operation is `data_op`, because JSON cannot carry two
  `op` members. This is the only change from the unit note's `{op:'authorize', adapter, capset, op}`.

Reply (one line): `{"case":n, "decision":"allow"|"deny", "rendered":bool}`. Other members are ignored.
`decision` is the outcome of the authorization stage (INV-NONEMPTY). `rendered` says whether the pipeline
reached the adapter's render step for this request. A failure after authorization (schema, budget, render) does
not change `decision`.

## Self-test (negative controls)

Every mutant runs at 10,000 cases (2,500 per adapter, "caught within 1e4 cases"). The clean subject must pass at
that size.

| mutant (`ref_subject.MUTATIONS`) | bug | must fire | subject must implement |
|---|---|---|---|
| `empty-means-all` | `[]` grants everything | ALLOW-ON-EMPTY | yes |
| `missing-capset-means-all` | `null` or absent grants everything | ALLOW-ON-NULL / -ABSENT | yes |
| `unrestricted-implicit` | absent data block read as `"unrestricted"` | ALLOW-ON-ABSENT | yes |
| `deny-everything` | never allows | DENY-ON-COVERING / -UNRESTRICTED | yes |
| `render-on-deny` | renders before authorizing | RENDER-ON-DENY | yes |
| `empty-columns-means-all` | `columns: []` covers all columns | ALLOW-ON-NONCOVERING | ref only |
| `absent-field-means-all` | missing `ops`/`columns` means all | ALLOW-ON-MALFORMED | ref only |
| `wildcard` | `"*"` matches anything | ALLOW-ON-MALFORMED / -NONCOVERING | ref only |
| `cap-union` | ops and columns unioned across caps | ALLOW-ON-NONCOVERING | ref only |
| `name-prefix-match` | collection matched by prefix | ALLOW-ON-NONCOVERING | ref only |
| `case-insensitive` | names and `"unrestricted"` case-folded | ALLOW-ON-NONCOVERING / -MALFORMED | ref only |
| `lenient-parse` | malformed elements skipped, the rest honoured | ALLOW-ON-MALFORMED | ref only |

Without `--subject`, the self-test also runs `ref_subject.py` over stdin/stdout. Its decision digest must equal the
in-process reference's, and the five required mutants must be caught over the protocol. With `--subject`, the
subject must be clean, and each `<cmd> --mutate m` for the five required mutants must be caught.

## Research provenance (untrusted input: read and re-derived, never executed in place)

| source | sha256 | used for |
|---|---|---|
| research/state/raw/round-002/01-data-plane-backend-families-mediation.json | ccffc8e804fad43bd4357626217a89345d1a799acc4fc5bc80b50b6aeb879fc1 | node `dpf-empty-means-all-pattern` (A): NATS `publish: []` = allow all, absent permissions block = unrestricted, Kafka allow-if-no-acl, Hasura null filter = all rows, Syncope CVE-2026-73579 empty realm filter; INV-NONEMPTY text ("absent or empty capability set denies; 'unrestricted' is an explicit enum variant that fails CI unless allowlisted") |
| research/state/raw/round-003/01-dataplane-ir-lowering-soundness.json | 6a0f3a81a2b9853cec9a2d92c82383b26c5eef2302200839c4b0fa79ee5fc8cd | `irl-empty-or-widening-family` (A): the same failure at expression level (empty Or rendered as no condition), basis for the near-cover and split-pair families |
| research/ARCHITECTURE.md | 22848c5159ea2c6479def0f6e53aaa92c6b47458d3fced567fa5e7e0993a6dae | P-3 fail-closed floor (LiteLLM CVE-2026-59822: an error produced an empty principal → the `null` category) |
| spec/SPEC_INVARIANTS.md | 666bac8b28e5453dea87ec4c70a10cf28d3cf4e8750d36a17fce58968a808072 | INV-NONEMPTY statement and test obligation (100k/adapter) |
| crates/aegis-data-ir/src/ir.rs | 4a89c4c4e949734ff55c1c0f1de0ddb9d12bfd7deb57fb9be4f10f954f454c4a | OpKind, Op, Schema and check_schema rules the generated ops satisfy (pre-P4-spec-001 F4) |
| interfaces/F10-module-wire.cddl | dac0f21de4ecb9a871d0490f7ba9376f48f5f70281b5133988ebb02c90e9d7dc | positional pred encoding |

No research code was ported. The research gives the failure pattern only, so the generator, checker and reference
are new.

## Re-run in repo (2026-10-30)

- `ci/heavy.sh oracles/nonempty-props/run`: 400,000 cases (100,000 per adapter), digest `6feeb8ce53e572f0`,
  0 violations, every cell nonzero (for example sqlite covering=30134 malformed=16145 noncovering=29835),
  allow+rendered equals must-allow on every adapter. Last line:
  `NONEMPTY-PROPS: PASS (reference, 100000 cases/adapter x 4 adapters, seed 1; 0 allows on empty/absent/null/malformed/non-covering, 0 denies on covering/unrestricted, 0 renders on deny)`
- `ci/heavy.sh oracles/nonempty-props/run --self-test`: reference clean at 10,000 cases; 12/12 reference mutants
  caught, the earliest at case 0–36. The protocol digest equals the in-process digest (`a46286b9085bf894`), and the
  5 required mutants are caught over the protocol. Last line: `NONEMPTY-PROPS SELF-TEST: PASS (17/17 mutants caught ...)`
- `--self-test --subject 'python3 -I -B oracles/nonempty-props/ref_subject.py'`: subject clean, and 5/5 required
  mutants are caught (the path the host-subject gate selftest takes).

## Known limits

- Authorization is judged at the reply boundary. The oracle cannot see whether host-subject wires the same
  `authorize` that aegis-bin uses. P4-host-001's subject must call the production dispatch path, and review should
  check that.
- `rendered` is self-reported by the subject. RENDER-ON-DENY catches a pipeline that reports its order honestly,
  not one that lies.
- Capsets reach the subject as JSON (the F8 `data` shape). Typed construction in Rust is P4-spec-001's
  (no empty constructor). This oracle checks the decision, not the type.
- Whether `ops: []` / `columns: []` caps parse is left open (rule 4). Either answer must deny the op.
- The reference and the checker were written by the same author, so correlated misreadings are possible. Labels
  come from the generator's construction and `cover()`, not from `ref_subject.py`.
