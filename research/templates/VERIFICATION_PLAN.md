# VERIFICATION_PLAN (template, v4, 2026-10-25)

Source: ARCHITECTURE.md v4 §4–§5, R-FORMAL-2..6, R-ASSURE-1..4. Rungs R0–R5 as in ARCHITECTURE.md §4.1 (R4 = model proof linked by DRT; R5 = proof about shipped code). Every claim names the rung **reached**, never the target.

## 1. Per-component assurance rung

| component | rung now | target | mechanisms | spec-fidelity check |
|---|---|---|---|---|
| monban-types (Decision, Principal) | R3 | R3 + R4 DRT | sealed types; DRT to Lean Decision | vacuity: Decision has 3 inhabitants |
| monban-canon | R2 (CANON-DIFF executed) | R3 + optional R5 (Verus canon_path) | G1 proptest ≥100k; G2 pinned WPT + IdnaTestV2 through every identity parser; G3 34 dated regressions; G4 lock bans; Kani totality | executable reference canonicalizer; mutation (relax any clause ⇒ G3 red) |
| H1 framing | R2 | R4 (Lean grammar + DRT, Lean `Std.Http` second oracle) | HTTP Garden; framing corpus | grammar spec reviewed by a human; round-trip vacuity witness |
| monban-budget / transport wrapper | R1 | R5 (Kani TBI-5/6/9; Verus TBI-1/4/7) + R4 Lean composition | fuzz resource-ratio oracle; DST stall | oracle mutation: remove stall timer ⇒ red |
| monban-tls group selection, 0x11ED | R1 (verdicts PUB-T1..T6, FIPS-F1..F6) | **R4 Lean selection model + R5 Kani share parsing (Phase-6 gates)** | verdicts.toml; KATs; interop OpenSSL 3.5+/BoringSSL | model checked against every verdict id |
| monban-authz combiner | **R4 checked** | R4 + R1 host-mapping DST | Combine.lean (4 theorems) | vacuity; DST injects timeout/crash/panic |
| Cedar evaluator | DRT | DRT + axiom audit | `#print axioms` on CI | until run, Cedar theorems cited at B |
| monban-token | **R4 checked (model only)** | R4 + DRT + mint-shape lemma | Token.lean T1–T5 (16 thm); fuzz F1–F9 1e8; dudect | EUF-CMA, codec round-trip, CT compare listed as hypotheses with tests |
| monban-data-ir lowering | **R4 checked** + R2 executed (leak=0, miss=0) | + 3VL re-proof; renderer DRT 1e7 Preds | Lowering.lean; two-sided oracles per ENGINE_PIN; schema gate | Backend.Refines/Exact are hypotheses tested by oracle; Vacuity.lean |
| write path | R2 (W1/W2/W4 executed) | R4 Lean W1–W6 abstract engine + R2 all families | write oracle N=300/variant | engine-violation corpus (#19645, ON CONFLICT) |
| monban-state (NOMUT, durability) | R1 | R2 DST + TLA+/P model | cancel sweep (8 modes × 8 oracles); crash harness ~130k images (+double fault, EIO) | oracle self-test: "always reusable" checkin ⇒ red ≤100 seeds |
| CRS | R2 partial | R2 all scopes | two-scope differentials; nginx CVE-2025-23419 replica | remove epoch from pool key ⇒ C5 red |
| monban-admission | R1 (sim, uncalibrated, D) | R2 held-out seeds + TLA+ I3/I4/I6/I9/I10 + Kani I8 | swarm DST | per-scenario reporting, no in-sample tuning |
| monban-agent listener gate | R1 executed (43 cases) + R3 type | same | corpus with zero-handler counter | corpus derived from advisories, not from our code |
| monban-iso / monban-wasm | R1 executed (FI gate 740 cells) + R3 kernel | same on VPS runner | negative syscall tests; hostile-module corpus | poison test must be red for instance reuse |
| monban-audit | R0 | R1 Kani/proptest I1–I3 + Tessera oracle | log-vs-effect diff | — |
| monban-config | R0 | R1 Kani totality + fuzz 1e7 | 3× oversize LKG test | — |
| monban-ops upgrade | R0 | R1 harness + TLA+ UP model | 200 upgrades at 5/s under 2k conn/s; naive REUSEPORT control must fail | — |
| SDK B2 | R3 (25/32 mutants) | R3 + streaming | trybuild corpus | mutant set self-built: add externally sourced mutants |

## 2. Proof obligations (statements in SPEC_INVARIANTS.md)

| obligation | tool | effort [E] | LLM share |
|---|---|---|---|
| F1 no ambient authority (Lean step semantics + induction) | Lean | 300–600 LOC, 1–2 wk | high once semantics fixed (semantics human-written) |
| F2 mint-shape + `verify → aud ∧ now<exp` | Lean | <1 d | very high |
| F3 host mapping | DST | ~2 d | n/a |
| F4 NOMUT protocol model; NC4/NC5 | TLA+/P; Lean/Kani | 1–2 wk; ~3 d | medium (~37% on inductive invariants) |
| F5 TBI structs, ledgers, composition; GCRA I8 | Kani; Verus; Lean | ~1 wk; 2–3 wk; 2–3 d | Kani high; Verus 70–85% |
| F6 H1 grammar unambiguity + round trip | Lean + DRT | spec 1–2 wk review + proofs 2–4 wk | proofs 70–85%; spec is the risk |
| F7 W1–W6 abstract engine; 3VL re-proof | Lean | 1–2 wk; ~1 wk | high |
| F8 group selection; 0x11ED share parsing | Lean; Kani | 1–2 d; ~1 wk incl. KATs/interop | high |
| F10 confused-deputy NI | DST 2-run; optional Lean relational | ~1 wk; 2–4 wk | medium |
| F11 audit, totality, healthy floor | Kani/proptest; TLA+ | 1–2 wk each | high |

Portfolio: LLM API cost negligible (~$1–6/obligation); binding cost is 8–14 person-weeks expert spec review + 2–4 person-weeks checker qualification.

## 3. Proof gate (R-FORMAL-3) — executed in research

1. Toolchain pin + exact commit (Lean v4.35.0 @eb6cafb, Init-only, `lakefile.toml` zero `require`).
2. `lake build` fails on any `sorry`.
3. `ci/axiom_audit.py`: each theorem's axioms ⊆ {propext, Classical.choice, Quot.sound}.
4. `native_decide`, `bv_decide` banned (grep + axiom check).
5. Release tier: `lake check --paranoid` (6 checkers, ~245 s / 1.0 GB).
6. Before any `--from-export`: exported prelude declarations byte-identical to the pinned toolchain's (Lean #15908 closed 2026-10-24 as non-standard prelude).
7. Negative control each run: a theorem using `native_decide` and one with `sorry` must FAIL.
8. Kani: main ≥ PR #4910; serial; 6 GB cap; CBMC exit ∉ {0,10}, OOM or timeout ⇒ FAIL.
9. Verus 0.2026.10.18: `-V check-erasure`; deny `assume(`, `admit(`, `external_body`, `assume_specification`, axiom fns outside `TRUSTED.toml` (LOC budget); spec-triviality check.
10. Known-false-proof corpus (Lean #14484/#14576/#15908, native_decide control, sorry control, Z3 unsound-unsat, Kani OOM) 100% rejected on every checker bump.
11. Watch: re-check stored proofs within 7 days of a checker soundness advisory.

**Admission rule:** no Lean claim above grade C without a file path and a gate log.

## 4. Spec-fidelity checks (R-FORMAL-6)

Each spec ships: (a) an executable form run against vectors and the DRT corpus; (b) a spec-mutation test (weakening or flipping any clause must fail a test); (c) a vacuity witness (a concrete model satisfying all hypotheses); (d) a hypothesis ledger: every assumption the Rust code could violate, with its oracle (`r4e01.spec-fidelity-audit` pattern). Specs are human-owned or from a separate agent; the proof-writing agent never merges spec diffs. Falsifier: if agent success on the first 20 core obligations is <70% within 10 iterations, those obligations drop to R2 and claims are downgraded.

## 5. Claim ledger record (R-ASSURE-3)

```yaml
claim: CL-TENANT-READ-01
statement: "No row with tenant ≠ σ.tenant is returned by any read lowered for request r"
invariant: [lowering_sound, INV-NONEMPTY, INV-NO-AMBIENT]
rung_reached: R4 (model) + R2 (executed oracle)
evidence:                                     # ≥2 distinct kinds
  - {kind: proof,  artifact: spec/AegisIR/Lowering.lean, gate_log_sha256: "<hash>", axioms: [propext, Classical.choice, Quot.sound]}
  - {kind: oracle, artifact: oracles/lowering-read, result: "leak=0 miss=0 @ ENGINE_PIN=pg17.11"}
hypotheses_trusted: [Backend.Exact(pg17.11, binary collation), renderer = lower]
hypothesis_tests: [DRT renderer-vs-Lean AST, schema gate]
vacuity_witness: spec/AegisIR/Vacuity.lean#keeps_nonvacuous
tcb_delta: [monban-data-ir renderer, tokio-postgres@<rev>, PG planner]
residual: [timing/scoring channels, engine optimizer bugs between pins]
reversal: "any leak or miss > 0 at a new ENGINE_PIN; Lean pin bump fails the gate"
reverify_on: [engine bump, Lean bump, IR change, checker soundness advisory within 7 d]
```
CI lint: build fails if a grade/rung in ARCHITECTURE.md disagrees with the graph or the artifact, or a claim has <2 evidence kinds or no residual.

## 6. Test/oracle stack (cross-reference SUPPLY_CHAIN §D gate numbers)

Unit/feature (9), property (10), trybuild (11), proof (12), Kani (13), DST turmoil 0.7.2 with replaced CryptoProvider (14: same-seed trace hash equal; 0 getrandom/clock syscalls after init; every fault class fires in first 1,000 seeds), oracle mutation (15), fuzz (16: h1, h2/hpack, token, config, WAL, MCP JSON-RPC, upgrade handover), config totality (17), differential HTTP Garden + CANON-DIFF (18), data-plane oracles (19), agent corpus (20), TLS verdicts (21), Miri/ASan/TSan/loom (22), cargo-mutants (23: fail on exit {2,3} for parser/authz/WAL/config diffs; nightly ratchet; target <10% [E]), isolation FI (24), upgrade (25), cert + outage (26), systemd/pod (27), conformance BoGo/Wycheproof/duvet/C0–C4 (28), AI red team (29, advisory), release (30), watch (31).

## 7. AI-discovery posture (R-ASSURE-4)
Per release: 1-week LLM audit sprint on changed TB1/TB2-reachable code. Nightly red team on staging with canaries (advisory until baselines). Weekly replay of every past exploit. Publish reachable-unproven-surface = Tier-S LOC − code under an **R5** claim (R4-only code counts as unproven); >10% rise needs sign-off [E].
