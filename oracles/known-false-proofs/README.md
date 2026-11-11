# known-false-proofs oracle (Phase 0 "verify wall")

A corpus of **known ways to make a proof checker accept a false or unjustified theorem**. Every
case MUST be *rejected* by the Monban proof gate (`ci/gate.sh`), and the rejection MUST *name the
planted defect* (not an unrelated error). This is the negative half of R-FORMAL-5 / AA7
("proof false PASS"): an oracle that cannot be made red is not a gate.

Spec clauses: `research/templates/VERIFICATION_PLAN.md` step 10 (known-false-proof corpus 100%
rejected on every checker bump), step 6 (prelude identity before `--from-export`); ARCHITECTURE
AA7, AA12 ("proof-checker false PASS"), and the gate design in ARCHITECTURE §"Pick [A executed]".

## What the gate checks (ci/gate.sh), and which step each case trips

1. toolchain pin (`leanprover/lean4:v4.35.0`, exact commit `eb6cafb`); **no `lakefile.lean`**.
2. `lake build`; any `declaration uses 'sorry'` warning fails; the Lean kernel itself runs here.
3. **forbidden source-token scan** + per-theorem **axiom allowlist** `{propext, Classical.choice,
   Quot.sound}` (`ci/axiom_audit.py`). Banned tokens: `sorry admit native_decide ofReduceBool
   ofReduceNat trustCompiler implemented_by @[extern axiom unsafe debug.skipKernelTC bv_decide
   opaque set_option maxRecDepth decide:=true`.
4. `lake check --paranoid`: kernel + leanchecker-paranoid + lean4lean + nanoda + con-leche +
   con-ron must all accept.
5. frozen statement hashes in `STATEMENTS.sha256` unchanged (`ci/statements.py check`).

Steps run in order and the gate **exits at the first failing step**, so a case that trips step 2
never reaches step 3. The statement-hash and honest-control cases are the only ones that reach
steps 4–5 (so `run` is slow: `--paranoid` is ~4 min each).

## Running

    oracles/known-false-proofs/run              # every exploit must be rejected; spec-only reported
    oracles/known-false-proofs/run --self-test  # also requires the gate to ACCEPT one honest case

On this laptop bwrap userns is blocked: invoke as
`AEGIS_NO_SANDBOX=1 ci/heavy.sh oracles/known-false-proofs/run [--self-test]`. `run` calls
`ci/gate.sh` directly; wrap the WHOLE run once in `ci/heavy.sh`. Do not wrap each gate call:
`flock` is not reentrant, so `heavy.sh run` with an inner `heavy.sh gate.sh` deadlocks the
machine-wide lock (this happened during development and was fixed). Last line:
`KNOWN-FALSE-PROOFS: PASS (n rejected, m spec-only)`; exit 0 only on PASS.

`run` requires, per case: `expect` = `FAIL` (exploit, gate must reject naming the defect in
`defect`), `SPECONLY` (tool not installed / out of gate scope; reported, never passed), or
`ACCEPT` (honest control, `--self-test` only; gate must accept). If the gate ever ACCEPTS a
`FAIL` case, that is a **gate hole** and `run` reports it prominently with the reproducer path.

## Cases

Each `cases/<id>/` is a minimal Lean package (`lakefile.toml` + `lean-toolchain` +
`KF.lean`) unless noted. "Gate step" is the step whose failure names the defect.

| id | source | exploits | gate step that rejects |
|----|--------|----------|------------------------|
| `sorry` | core | `sorry` closes any goal (`sorryAx`) | 2 (sorry warning) + 3 (token + axiom) |
| `admit` | core | tactic spelling of `sorry` | 2 + 3 |
| `native-decide` | core | compiles+trusts the decision proc, bypassing the kernel; per-decl native axiom | 3 (token + `_native.native_decide.ax`) |
| `user-axiom` | core | user `axiom` = unjustified assumption | 3 (token + axiom `KF.cheat`) |
| `implemented-by` | core | `@[implemented_by]` lies to the compiler; `native_decide` certifies the lie | 3 (token `implemented_by`) |
| `extern` | core | `@[extern]` binds to a C symbol that can disagree with the Lean body | 3 (token `@[extern`) |
| `opaque-unsafe` | core | `unsafe` skips kernel checking; `opaque` hides a body | 3 (tokens `opaque`,`unsafe`) |
| `ofReduceBool` | lean4 (legacy axiom) | `Lean.ofReduceBool` certifies a compiled bool into the logic | 2 (unknown identifier; **removed in 4.35.0**) + 3 token ban |
| `skipKernelTC` | core | `set_option debug.skipKernelTC true` turns off kernel type-checking | 3 (token `skipKernelTC`) |
| `lakefile-lean` | Lake DSL | `lakefile.lean` runs arbitrary Lean/IO at configure time | 1 (`lakefile.lean present`) |
| `statement-hash` | — | theorem STATEMENT weakened (`… → True`) vs the frozen ledger; proof still valid | 5 (`changed statement`) |
| `lean-14484` | [#14484](https://github.com/leanprover/lean4/issues/14484) | kernel skipped the closure check on `opaque` values → axiom-free `False` from a loose fvar | 2 (kernel: `declaration has free variables`) |
| `lean-14576` | [#14576](https://github.com/leanprover/lean4/issues/14576) | kernel accepted a `.proj` naming the wrong structure → axiom-free `False` | 2 (kernel: `invalid projection`) |
| `hidden-axiom` | gate-design probe | user `axiom` in a NON-root module + `@[simp] theorem` on one line: token scan reads roots only, name regex misses the theorem → "0 theorems audited; AXIOM GATE: PASS" for a proof of `1 = 2` | **4 only** (`lake check`: "Axiom 'KF.Helper.cheat' is not permitted") |
| `lean-15908` | [#15908](https://github.com/leanprover/lean4/issues/15908) | export redefines the prelude's `Nat.add`; the name-dispatched kernel reduction trusts it | **SPEC-ONLY** (export-trust, not source build) |
| `z3-unsound-unsat` | — | SMT solver reports `unsat` for a satisfiable formula | **SPEC-ONLY** (Z3 not installed) |
| `kani-oom` | Kani #4905 / [#4910](https://github.com/model-checking/kani/pull/4910) | model-checker OOM/timeout misread as "verified" | **SPEC-ONLY** (Kani/CBMC not installed) |

### Upstream-fixed cases (kept per the brief)

`lean-14484` (fixed by [PR #14498](https://github.com/leanprover/lean4/pull/14498) "kernel to
check opaque values for fvars") and `lean-14576` (fixed by
[PR #14577](https://github.com/leanprover/lean4/pull/14577) "check the structure name when
comparing projections in the kernel") are **fixed in Lean 4.35.0**: the crafted declarations are
built exactly and fed to the kernel, which now *rejects* them at `lake build`. Verified on this
host (4.35.0 @ eb6cafb). We keep the cases — they are the faithful reproducers and they prove the
pinned toolchain closes the hole; if the pin ever regressed, the case would start building.

`ofReduceBool`: in 4.35.0 `native_decide` no longer uses a single global `Lean.ofReduceBool`
axiom (it emits per-declaration native axioms; see
`~/.elan/toolchains/.../src/lean/Lean/Meta/Native.lean`). The identifier is gone, so the case
fails to elaborate *and* the token scan bans it regardless.

### `lean-15908` resolution (and a note on the current gate)

#15908 was closed **not planned / not a kernel soundness bug** (Leo de Moura): the exploit lives
in the *export-trust* model — it hand-edits an NDJSON export so `Nat.add` is non-canonical. Of
the six checkers, Lean-default, Lean-paranoid and nanoda accepted it; lean4lean, con-leche and
con-ron rejected it; `comparator` rejects it on prelude mismatch. The current `ci/gate.sh` never
consumes an external export (step 4 builds and exports the project itself with the pinned
toolchain), so the prelude is always canonical and the exploit is **unreachable by
construction** — but the gate has *no* prelude-identity assertion and *no* `--from-export` path.
If `--from-export` is ever added, it must first assert exported prelude declarations are
byte-identical to the pinned toolchain's and require unanimous checker acceptance (see
`cases/lean-15908/SPEC.md`). This is a documented residual, not a live hole.

## Finding: steps 2-3 are bypassable; only step 4 catches `hidden-axiom`

No exploit in this corpus gets through the full current gate. But `cases/hidden-axiom/`
bypasses steps 2-3 completely:
- `ci/axiom_audit.py` scans tokens only in library ROOT files, so an `axiom` in an imported
  non-root module is never seen;
- its theorem-name regex `\s*(?:private\s+)?(?:theorem|lemma)\s+…` misses `@[simp] theorem`,
  `protected theorem`, `nonrec theorem`, etc., so no `#print axioms` row is emitted.
Result: `0 theorems audited … AXIOM GATE: PASS` for a package proving `1 = 2`. Step 4 rejects it.
`lake check`'s own axiom policy fires ("Axiom 'KF.Helper.cheat' is not permitted; it is used by
'KF.bad'", verified in non-paranoid mode). In `--paranoid` mode the run aborts earlier:
Lean-paranoid, lean4lean and Lean-default *accept* the kernel check, while nanoda crashes
("declaration not found in infer_const") and con-leche/con-ron decline the non-standard axiom.
Implications (not gate edits, which are out of scope here):
1. Any fast path that runs only steps 2-3 (ARCHITECTURE line 340 makes `--paranoid` "CI only")
   would PASS this. Step 3's allowlist is weaker than documented.
2. The axiom audit should run `#print axioms` over every theorem in the environment (or every
   module the lib builds), not regex-extracted root names. The token scan should cover every
   built module.
3. Step-4/5 failures exit through `set -e` with no `PROOF GATE: FAIL` line. The reason is only
   in the checker output.
4. For frozen `spec/` theorems, the statement ledger plus transitive `#print axioms` still
   cover this, because a frozen theorem using a hidden axiom is audited by name.

## Spec-only cases (tools not installed here)

`lean-15908`, `z3-unsound-unsat`, `kani-oom` ship as `cases/<id>/SPEC.md`: the input, the wrong
verdict absent the defense, and the gate rule that must catch it (SMT = hint only, never proof;
Kani exit must be in `{0,10}`, OOM/timeout = FAIL). `run` reports them `SPEC-ONLY`; it never
counts one as passed.

## Honest control (both directions)

`cases/honest-control/` is a genuinely true theorem (`Nat.add_comm`, `rfl`) with an allowed proof
and its own frozen `STATEMENTS.sha256`. Under `--self-test` the gate must **ACCEPT** it (full run
through step 5). If the gate rejects the honest case or accepts any exploit, the self-test FAILs.
So the oracle demonstrates both red (14 rejections) and green (1 acceptance).

## Provenance

- Lean issues reconstructed from the live GitHub issues (URLs above), fetched 2026-10-25;
  cross-referenced with `research/state/graph.jsonl` nodes
  (`v4.lean-checker-disagreement-15908`, the 2026 Lean soundness-record node listing
  #14484/#14576) and `research/ARCHITECTURE.md` (lines 33, 100, 155, 340, 397, 435).
- Kani #4905 / #4910 and the "proof-checker false PASS" row: `research/ARCHITECTURE.md` AA12 and
  `research/templates/IMPLEMENTATION_PLAN.md` plan row; research note
  `vfg-kani-footprint-and-gate-failures`.
- Re-run in-repo: `ci/gate.sh` (4.35.0 @ eb6cafb) on every case; results in the run output.

## Known limits

- The two kernel metaprogram exploits (#14484/#14576) are *fixed* in the pinned toolchain, so
  they exercise the kernel's rejection path, not a live bypass. That is the intended Phase-0
  state (pin ≥ fix).
- SMT and Kani cases are specifications only; they bind the implementation-phase SMT/Kani
  bridges, which do not exist yet.
- `run` is slow (~10–15 min) because `statement-hash`, `hidden-axiom` and (under `--self-test`)
  `honest-control` exercise `lake check --paranoid` (6 checkers, ~4 min each). The other 11
  Lean cases fail fast (< 5 s each).
