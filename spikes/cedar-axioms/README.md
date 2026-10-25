# Spike cedar-axioms: `#print axioms` over the Cedar Lean proofs (R-AUTHZ-1 grade)

**Verdict: flip, split citation.** The evaluator, authorizer, validator, typechecker, TPE, slicing and batched-evaluator
theorems at cedar-spec v4.14.0 use only `{propext, Classical.choice, Quot.sound}`, so they can be cited at **A**.
Every SymCC theorem (symbolic compiler and verification queries, which back the deploy-time cedar-policy-symcc checks)
depends on 10 `native_decide` axioms, so those stay at **B**. Nothing depends on `sorryAx`, `Lean.ofReduceBool` or a
user axiom.

## Method
- Tag: cedar-policy 4.14.0 ↔ cedar-spec tag `v4.14.0` = `d1a0a5cd1bd2eb87d03119e6f2c4580aba440d65` (2026-10-16).
  `cedar-lean/lean-toolchain` = Lean v4.34.1. The only dependency is Batteries `f2effa3d` (v4.34.0). No Mathlib
  (doc-gen4 is only required under `-K env=dev`).
- Host: LAN box **kamrui** (Intel N95, 4 cores, 14 GB, Ubuntu 25.10), standing in for CI. Everything ran inside
  `~/aegis-ci/bin/heavy` (= `../q2-013/scripts/heavy.sh`): a systemd user scope with MemoryMax=8G, swap off, nice 15.
- Build: `scripts/build.sh` installs elan into `~/aegis-ci/elan` and runs
  `lake build Cedar.Thm Cedar.Thm.Verification Cedar.Thm.SymbolicCompilation`.
- Audit: `scripts/AxiomAudit.lean`, run with `lake env lean`:
  1. `#print axioms` for 22 theorems our claims would cite.
  2. `#cedar_axiom_scan`: a memoized walk of the kernel environment over **every** theorem declared in a `Cedar.*`
     module (17,052 theorems, private ones included). It prints each theorem whose axiom set is not a subset of the
     allowlist.
- Negative controls (`scripts/Control.lean`, `raw/control.out`): `native_decide` shows up as
  `ctl_native._native.native_decide.ax_1_1`, `sorry` as `sorryAx`, and a user axiom by its name. `decide` proves
  `(0 : Int64).toInt = 0` with no axioms.

## Results
| item | value |
|---|---|
| build | 333 jobs, OK, 0 `sorry` warnings; wall 12 min 09 s, user 2099 s (307% CPU) |
| build memory | max single-process RSS 1.48 GB; cgroup peak 1.73 GB (includes page cache) |
| audit run | 39 s; max RSS 2.03 GB (mmapped .olean files); cgroup peak 0.43 GB |
| disk | elan + Lean v4.34.1 full toolchain 3.0 GB; cedar-spec source 12 MB; `.lake` 503 MB (batteries 77 MB, build 426 MB) |
| theorems scanned | 17,052 |
| within allowlist | 16,968 |
| using `native_decide` axioms | 84 |
| `sorryAx` / `ofReduceBool` / user axioms | 0 / 0 / 0 |

Cited theorems with clean axioms `[propext, Classical.choice, Quot.sound]`:
`forbid_trumps_permit`, `default_deny`, `allowed_only_if_explicitly_permitted`,
`allowed_iff_explicitly_permitted_and_not_denied`, `denied_iff_explicitly_denied_or_not_permitted`,
`order_and_dup_independent`, `validation_is_sound`, `validation_is_sound_response`, `validate_with_level_is_sound`,
`typecheck_is_sound`, `isAuthorized_eq_for_sound_policy_slice`, `batched_authorize_decision_eq_authorize`,
`reauthorize_is_sound`, `partial_authorize_decision_is_sound`, `partial_authorize_erroring_policies_is_sound`.

Offending theorems (84; full list in `raw/audit.out`, grouped by file in `raw/nonstd_by_file.txt`): 22 in
`Thm/Verification.lean` (all `verify*_is_sound/complete`), 22 in `Thm/WellTypedVerification.lean`, 4 in
`Thm/SymbolicCompilation.lean` (`compile_is_sound`, `compile_is_complete`, `isAuthorized_is_sound`,
`isAuthorized_is_complete`), and the rest under `Thm/SymCC/**` (Authorizer, Compiler, Enforcer, Verifier), plus the
root lemmas themselves.

The 10 offending axioms come from 7 root lemmas:
- `Cedar/Data/Int64.lean`: `Int64.toInt_nonneg_of_ge_zero`, `Int64.toInt_neg_of_not_ge_zero` (each proves
  `(0 : Int64).toInt = 0` by `native_decide`);
- `Cedar/Thm/SymCC/Data/Ext.lean` (private): `msPerDay_eq`, `msPerDay_toInt`, `msPerDay_gt_one`, `toDate_eq_smod`,
  `toInt_div_msPerDay` (datetime constants such as `msPerDay = 86400000` and `(-(2^63)).tdiv 86400000`).

**Correction to ARCHITECTURE §3.5.** "Int64 `native_decide` is in the TPE closure" is true of the *import* closure:
`Cedar.Data.Int64` is imported by everything. It is false of the *axiom* closure: no TPE, authorization or validation
theorem uses those lemmas. So a module-level grep over-reports. The CI gate has to check axioms per theorem
(`AxiomAudit.lean` part 2).

## Decision effect
See `verdict.json` → `decision_effect`. In short:
- R-AUTHZ-1 "verified Lean model" for the authorizer, validator and TPE moves to A at v4.14.0, with gate log `raw/audit.out`.
- SymCC soundness stays at B. This adds to the SymCC TCB already listed in §3.5 (cvc5 #12926/#12927): it now also
  trusts the Lean compiler for the 7 `native_decide` lemmas.
- Re-run on every cedar-policy bump. The axiom set can change between tags.

## Reproduce (kamrui)
```
~/aegis-ci/bin/cedar-build.sh                       # scripts/build.sh
cd ~/aegis-ci/src/cedar-spec/cedar-lean
ELAN_HOME=~/aegis-ci/elan PATH=~/aegis-ci/elan/bin:$PATH MEM=8G ~/aegis-ci/bin/heavy \
  lake env lean ~/aegis-ci/work/cedar-axioms/AxiomAudit.lean
~/aegis-ci/elan/toolchains/leanprover--lean4---v4.34.1/bin/lean ~/aegis-ci/work/cedar-axioms/Control.lean
```

## Limits
- The axioms were read from `.olean` files that the same Lean binary produced. No independent kernel re-check was run
  (`lean4checker` or `lake check --paranoid`), so Lean kernel or elaborator bugs (the #14484/#14576/#15908 class) are
  not excluded. That is the next step for the CI gate.
- These are theorems about Cedar's Lean model. The Rust crate is tied to it only by Cedar's DRT, so the claim wording
  stays "verified Lean model + DRT-tested Rust evaluator".
- We chose Part 1's theorem list. Part 2 covers every theorem, so a cited theorem cannot hide.
- The 7 root lemmas are trivial constant facts, and `decide` handles one of them here. An upstream PR replacing them
  would likely move SymCC to A as well. Not attempted.
- Measured on a LAN box, not a CI runner: grade B for timings, grade A for the axiom sets.
