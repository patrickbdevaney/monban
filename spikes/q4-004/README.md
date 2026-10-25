# q4-004: three-valued reference for `Not` over nullable fields

**Verdict: flip.** Lean proves that on every `Backend.Exact` backend the SQL lowering agrees exactly with a Kleene
three-valued policy reference `eval3`, for every predicate including `Not` over NULL/absent fields. F4 can therefore
stop rejecting `Not` over nullable fields. The new rule gates `Not` by adapter fidelity (Exact only) and requires
NULL-propagating atoms. See `verdict.json` for the exact F4 rule and the replacement §E clause.

## Method
- `lean/` is a copy of `spec/` (lakefile.toml, lean-toolchain v4.35.0, core only, no `require`) plus a new root
  `AegisIR/ThreeValued.lean`. Lowering/Token/Combine/Vacuity are unchanged except one comment (`inList []`).
- `eval3 : Row → Pred → Option Bool`: atoms are `(r f).map <reference test>` (absent ⇒ `none`); connectives are
  the existing `k3and/k3or/k3not`. `refQ3 tf t r p := eval3 r (tenant = t ∧ p) == some true`.
- Main proof: induction on `Pred`, reusing `beq_exact/anyEq_exact/brange_exact/bpfx_exact` from Lowering.lean.
  The 2VL relation reuses `lower_sound_full` instantiated at `refBackend` (sql3 refBackend ∘ lower = eval3).

## Results (theorems, namespace AegisIR.ThreeValued)
| theorem | statement |
|---|---|
| lower_exact3 | `B.Exact → sql3 B r (lower p) = eval3 r p` (all p) |
| lowerQ_exact3 | `B.Exact → keeps B r (lowerQ tf t p) = refQ3 tf t r p` |
| rows_exact3 | `B.Exact → db.filter (keeps …) = db.filter (refQ3 …)` |
| eval3_sound | `eval3 r p = some b → eval r p = b` (all p) |
| refQ3_imp_refQ | `refQ3 → refQ` |
| eval3_pos_iff / refQ3_pos_eq | NOT-free p: `eval3 r p = some true ↔ eval r p = true`; `refQ3 = refQ` |
| eval3_total | every read field present ⇒ `eval3 r p = some (eval r p)` |
| not_absent_gap | `r f = none → eval (¬(f=v)) = true ∧ eval3 (¬(f=v)) = none` (counterexample to 2VL = 3VL) |
| sql3_inList_nil, eval3_isIn_nil | `In []` = FALSE if present, UNKNOWN if NULL |
| inList_nil_not_const_false | constant-FALSE rendering of `In []` gives TRUE under NOT on NULL; the lowering gives UNKNOWN |
| lower_sound_pos3 | Refines + NOT-free ⇒ SQL TRUE ⇒ eval3 TRUE |
| refines_insufficient_for_not3 | Refines is not enough for NOT under 3VL either |
| exact3_nonvacuous_null/present | vacuity witnesses |

Gate (`gate.log`): build OK, 0 sorry, 64 theorems audited `AXIOM GATE: PASS`, Lean paranoid / lean4lean / nanoda /
con-leche / con-ron / default kernels accept, `STATEMENT GATE: PASS (117 frozen declarations unchanged)`,
`PROOF GATE: PASS`. `ledger-diff.txt`: 22 additions, 0 changes vs `spec/STATEMENTS.sha256`.

## inList [] (BACKLOG / oracle D6)
The definition is right; the comment was incomplete. `sql3 (.inList f [])` is FALSE on a present column and UNKNOWN
on NULL, which equals `eval3 (.isIn f [])`. The copy fixes the comment (hash-neutral). Renderers must not emit `(1=0)`
for a nullable column.

## Reproduce
```
cd /home/patrickd/aegis
AEGIS_NO_SANDBOX=1 ci/heavy.sh ci/gate.sh spikes/q4-004/lean
python3 -I ci/statements.py freeze spikes/q4-004/lean && diff spec/STATEMENTS.sha256 spikes/q4-004/lean/STATEMENTS.sha256
rm -rf spikes/q4-004/lean/.lake
```

## Honest limits
- Model only (R4). The Rust F4 check and the renderers are not proved; Backend.Exact per engine is still discharged
  by oracles/lowering-read (whose gating `permit` set should switch to refQ3).
- Policy meaning changes only for NOT over NULL: `NOT (f = v)` no longer matches rows with f NULL (fewer rows,
  never more: eval3_sound). With no `isNull` atom in the IR, "f ≠ v or f missing" can't be expressed. That is a
  follow-up.
- The present F4 code does not check adapter fidelity. In the model, a Refines adapter is already unsound with Not
  over non-nullable fields. The proposed rule closes this gap.
- The spike-local ledger was re-frozen so gate step 5 can run. The diff is the evidence that no frozen statement
  changed.
