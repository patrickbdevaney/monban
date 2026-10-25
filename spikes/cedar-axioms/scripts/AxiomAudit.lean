/-
 cedar-axioms spike: axiom audit of the Cedar Lean proofs at cedar-spec v4.14.0.
 Part 1: `#print axioms` on the theorems our claims cite (R-AUTHZ-1).
 Part 2: memoized scan of EVERY theorem declared in a `Cedar.*` module; prints each theorem whose axiom set is not
         a subset of {propext, Classical.choice, Quot.sound}, and the distinct offending axioms.
 Run from cedar-spec/cedar-lean:  lake env lean <path>/AxiomAudit.lean
-/
import Cedar.Thm
import Cedar.Thm.Verification
import Cedar.Thm.SymbolicCompilation
import Lean
open Lean Elab Command

-- Part 1: cited theorems
-- authorization
#print axioms Cedar.Thm.forbid_trumps_permit
#print axioms Cedar.Thm.default_deny
#print axioms Cedar.Thm.allowed_only_if_explicitly_permitted
#print axioms Cedar.Thm.allowed_iff_explicitly_permitted_and_not_denied
#print axioms Cedar.Thm.denied_iff_explicitly_denied_or_not_permitted
#print axioms Cedar.Thm.order_and_dup_independent
-- validation / typechecking
#print axioms Cedar.Thm.validation_is_sound
#print axioms Cedar.Thm.validation_is_sound_response
#print axioms Cedar.Thm.validate_with_level_is_sound
#print axioms Cedar.Thm.typecheck_is_sound
-- slicing, batched evaluator
#print axioms Cedar.Thm.isAuthorized_eq_for_sound_policy_slice
#print axioms Cedar.Thm.batched_authorize_decision_eq_authorize
-- TPE (type-aware partial evaluation)
#print axioms Cedar.Thm.reauthorize_is_sound
#print axioms Cedar.Thm.partial_authorize_decision_is_sound
#print axioms Cedar.Thm.partial_authorize_erroring_policies_is_sound
-- SymCC (symbolic compiler and verification queries used by cedar-policy-symcc)
#print axioms Cedar.Thm.compile_is_sound
#print axioms Cedar.Thm.compile_is_complete
#print axioms Cedar.Thm.isAuthorized_is_sound
#print axioms Cedar.Thm.isAuthorized_is_complete
#print axioms Cedar.Thm.verifyNeverErrors_is_sound
#print axioms Cedar.Thm.verifyAlwaysMatches_is_sound
#print axioms Cedar.Thm.verifyNeverMatches_is_sound

-- Part 2: whole-closure scan
abbrev AxSet := Std.HashSet Name

def stdAxioms : AxSet := ({} : AxSet) |>.insert ``propext |>.insert ``Classical.choice |>.insert ``Quot.sound

partial def axOf (env : Environment) (n : Name) : StateM (Std.HashMap Name AxSet) AxSet := do
  if let some s := (← get).get? n then return s
  modify (·.insert n {}) -- cycle guard (unsafe/partial impls)
  let deps : Array Name ← match env.find? n with
    | some (.axiomInfo _) => pure #[]
    | some (.inductInfo v) => pure (v.type.getUsedConstants ++ v.ctors.toArray)
    | some ci => pure (ci.type.getUsedConstants ++ ((ci.value? (allowOpaque := true)).map (·.getUsedConstants) |>.getD #[]))
    | none => pure #[]
  let mut acc : AxSet := {}
  if let some (.axiomInfo _) := env.find? n then acc := acc.insert n
  for c in deps do
    for a in (← axOf env c) do acc := acc.insert a
  modify (·.insert n acc)
  return acc

def inCedar (env : Environment) (n : Name) : Bool :=
  match env.getModuleIdxFor? n with
  | some idx => (env.header.moduleNames[idx.toNat]!).getRoot == `Cedar
  | none => false

elab "#cedar_axiom_scan" : command => do
  let env ← getEnv
  let thms := env.constants.fold (init := #[]) fun acc n ci =>
    match ci with
    | .thmInfo _ => if inCedar env n then acc.push n else acc
    | _ => acc
  let (res, _) := (thms.mapM (fun n => do return (n, ← axOf env n))).run {}
  let mut bad : Array (Name × Array Name) := #[]
  let mut offenders : Std.HashMap Name Nat := {}
  for (n, s) in res do
    let extra := s.toArray.filter (!stdAxioms.contains ·)
    if !extra.isEmpty then
      bad := bad.push (n, extra)
      for a in extra do offenders := offenders.insert a (offenders.getD a 0 + 1)
  logInfo m!"SCAN theorems_in_Cedar_modules={thms.size} nonstandard={bad.size}"
  for (a, k) in offenders.toArray do
    logInfo m!"OFFENDING_AXIOM {a} used_by={k}"
  for (n, extra) in bad do
    logInfo m!"NONSTD {n} : {extra.toList}"

#cedar_axiom_scan
