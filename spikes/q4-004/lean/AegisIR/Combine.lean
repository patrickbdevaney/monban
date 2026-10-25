/-
AEGIS host combiner: three-valued module decisions, fail-closed combination.
r4 E01 (2026-10-25): FIRST Lean text for graph node vfg-policy-tristate-failclosed-invariant, which r2 graded A as
"proven in Lean" although no Lean file existed in state/raw (overclaim; corrected here by an executed check).
Semantics chosen (spec decision, flagged): empty decision list ⇒ deny (no policy = no access); any error ⇒ deny;
any deny ⇒ deny; allow only if non-empty and every decision is allow.  A timeout/crash of a module is mapped to
`error` by the host BEFORE combination (Rust obligation, tested by DST; not provable here).
-/
namespace AegisIR.Combine

inductive Decision where
  | allow | deny | error
  deriving DecidableEq, Repr

def combine (ds : List Decision) : Decision :=
  if ds.isEmpty then .deny
  else if ds.all (· == .allow) then .allow
  else .deny

/-- combine_failclosed: an allow result implies no module erred. -/
theorem combine_failclosed (ds : List Decision) : combine ds = .allow → ∀ d ∈ ds, d ≠ .error := by
  intro h d hd he
  subst he
  unfold combine at h
  split at h
  · cases h
  · split at h
    · rename_i _ hall
      have := List.all_eq_true.mp hall _ hd
      simp at this
    · cases h

/-- Stronger: allow iff non-empty and unanimous allow. -/
theorem combine_allow_iff (ds : List Decision) :
    combine ds = .allow ↔ (ds ≠ [] ∧ ∀ d ∈ ds, d = .allow) := by
  unfold combine
  constructor
  · intro h
    split at h
    · cases h
    · rename_i hne
      split at h
      · rename_i hall
        refine ⟨fun he => by simp [he] at hne, fun d hd => ?_⟩
        have := List.all_eq_true.mp hall d hd
        simpa using this
      · cases h
  · rintro ⟨hne, hall⟩
    have h1 : ds.isEmpty = false := by cases ds with
      | nil => exact absurd rfl hne
      | cons _ _ => rfl
    have h2 : ds.all (· == .allow) = true := List.all_eq_true.mpr (fun d hd => by simp [hall d hd])
    simp [h1, h2]

theorem combine_empty : combine [] = .deny := rfl

/-- Never returns error: the error class is absorbed into deny at the boundary. -/
theorem combine_ne_error (ds : List Decision) : combine ds ≠ .error := by
  unfold combine; split
  · decide
  · split <;> decide

end AegisIR.Combine
