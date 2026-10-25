/-
q4-004 (Phase-1 spike): a THREE-VALUED policy reference for the IR filter fragment, and its exact agreement with
the SQL lowering.  Core Lean 4 only.  Definitions in Lowering.lean are untouched (this module only adds).

  * `eval3 r p : Option Bool` is Kleene 3VL over the same atoms as `eval`: an absent (NULL) field makes the atom
    UNKNOWN (`none`); connectives are `k3and/k3or/k3not` from Lowering.lean.
  * `lower_exact3`: for every `Backend.Exact` B, `sql3 B r (lower p) = eval3 r p` for EVERY `p` (NOT included).
    Hence rows(SQL WHERE) = {x | eval3 x p = some true} exactly (`lowerQ_exact3`, `rows_exact3`).
  * Relation to the two-valued `eval`:
      - `eval3_sound`: eval3 r p = some b → eval r p = b, for every p (3VL is never more permissive);
      - `eval3_pos_iff`: on NOT-free p, eval3 r p = some true ↔ eval r p = true (no behaviour change);
      - `eval3_total`: when every field p reads is present, eval3 r p = some (eval r p);
      - `not_absent_gap`: NOT over an absent field: eval = true, eval3 = none (the measured GAP, now by definition).
  * `sql3_inList_nil` / `inList_nil_not_const_false`: the `In []` atom is FALSE on a present column and UNKNOWN on
    NULL; rendering it as constant FALSE (1=0) is NOT exact under NOT.
-/
import AegisIR.Lowering
import AegisIR.Vacuity

namespace AegisIR.ThreeValued
open AegisIR AegisIR.Vacuity

/-- Three-valued policy semantics (Kleene). Absent (NULL) field ⇒ atom UNKNOWN. -/
def eval3 (r : Row) : Pred → Option Bool
  | .tt => some true
  | .ff => some false
  | .eq f v => (r f).map (fun x => decide (x = v))
  | .isIn f vs => (r f).map (fun x => vs.contains x)
  | .range f lo hi => (r f).map (fun x => refRange lo hi x)
  | .pfx f s => (r f).map (fun x => refPrefix s x)
  | .and p q => k3and (eval3 r p) (eval3 r q)
  | .or p q => k3or (eval3 r p) (eval3 r q)
  | .not p => k3not (eval3 r p)

/-- Policy permit under 3VL: the tenant conjunct AND p is TRUE (UNKNOWN and FALSE deny). -/
def refQ3 (tenantField : Field) (t : Value) (r : Row) (p : Pred) : Bool :=
  eval3 r (.and (.eq tenantField t) p) == some true

/-- Fields an IR predicate reads. -/
def readsOf : Pred → List Field
  | .tt => []
  | .ff => []
  | .eq f _ => [f]
  | .isIn f _ => [f]
  | .range f _ _ => [f]
  | .pfx f _ => [f]
  | .and p q => readsOf p ++ readsOf q
  | .or p q => readsOf p ++ readsOf q
  | .not p => readsOf p

-- ---------------------------------------------------------------------------------------------- exactness
/-- MAIN THEOREM (q4-004): on every exact backend the lowered SQL agrees with the 3VL reference on every row and
    every predicate, NOT over nullable fields included. -/
theorem lower_exact3 {B : Backend} (h : B.Exact) (r : Row) :
    ∀ p : Pred, sql3 B r (lower p) = eval3 r p := by
  intro p
  induction p with
  | tt => rfl
  | ff => rfl
  | eq f v =>
    simp only [lower, sql3, eval3]
    cases r f with
    | none => rfl
    | some x => simp only [Option.map_some, beq_exact h]
  | isIn f vs =>
    simp only [lower, sql3, eval3]
    cases r f with
    | none => rfl
    | some x => simp only [Option.map_some, anyEq_exact h]
  | range f lo hi =>
    simp only [lower, sql3, eval3]
    cases r f with
    | none => rfl
    | some x => simp only [Option.map_some, brange_exact h]
  | pfx f s =>
    simp only [lower, sql3, eval3]
    cases r f with
    | none => rfl
    | some x => simp only [Option.map_some, bpfx_exact h]
  | and p q ihp ihq => simp only [lower, sql3, eval3, ihp, ihq]
  | or p q ihp ihq => simp only [lower, sql3, eval3, ihp, ihq]
  | not p ihp => simp only [lower, sql3, eval3, ihp]

/-- Query level, with the mandatory tenant conjunct: WHERE keeps a row iff the 3VL policy permits it. -/
theorem lowerQ_exact3 {B : Backend} (h : B.Exact) (tf : Field) (t : Value) (r : Row) (p : Pred) :
    keeps B r (lowerQ tf t p) = refQ3 tf t r p := by
  have e : sql3 B r (lowerQ tf t p) = eval3 r (.and (.eq tf t) p) := lower_exact3 h r (.and (.eq tf t) p)
  simp only [keeps, refQ3, e]

/-- Set form over a finite table: rows(render(lowerQ t p), db) = {x ∈ db | refQ3 t p x}, order preserved. -/
theorem rows_exact3 {B : Backend} (h : B.Exact) (tf : Field) (t : Value) (p : Pred) (db : List Row) :
    db.filter (fun x => keeps B x (lowerQ tf t p)) = db.filter (fun x => refQ3 tf t x p) := by
  congr 1
  funext x
  exact lowerQ_exact3 h tf t x p

-- ---------------------------------------------------------------------------------------------- vs eval
/-- 3VL is never more permissive than the two-valued reference (any definite 3VL answer agrees with `eval`). -/
theorem eval3_sound (r : Row) (p : Pred) (b : Bool) (h3 : eval3 r p = some b) : eval r p = b := by
  have e : sql3 refBackend r (lower p) = eval3 r p := lower_exact3 refBackend_exact r p
  exact lower_sound_full refBackend_exact r p b (e.trans h3)

theorem refQ3_imp_refQ (tf : Field) (t : Value) (r : Row) (p : Pred) (h3 : refQ3 tf t r p = true) :
    refQ tf t r p = true := by
  have hs : eval3 r (.and (.eq tf t) p) = some true := by simpa [refQ3] using h3
  exact eval3_sound r _ true hs

/-- On NOT-free predicates a two-valued permit is also a 3VL permit. -/
theorem eval3_pos_complete (r : Row) :
    ∀ p : Pred, p.positive = true → eval r p = true → eval3 r p = some true := by
  intro p
  induction p with
  | tt => intro _ _; rfl
  | ff => intro _ he; simp [eval] at he
  | eq f v =>
    intro _ he
    cases hr : r f with
    | none => simp [eval, hr] at he
    | some x => simp only [eval, hr] at he; simp only [eval3, hr, Option.map_some, he]
  | isIn f vs =>
    intro _ he
    cases hr : r f with
    | none => simp [eval, hr] at he
    | some x => simp only [eval, hr] at he; simp only [eval3, hr, Option.map_some, he]
  | range f lo hi =>
    intro _ he
    cases hr : r f with
    | none => simp [eval, hr] at he
    | some x => simp only [eval, hr] at he; simp only [eval3, hr, Option.map_some, he]
  | pfx f s =>
    intro _ he
    cases hr : r f with
    | none => simp [eval, hr] at he
    | some x => simp only [eval, hr] at he; simp only [eval3, hr, Option.map_some, he]
  | and p q ihp ihq =>
    intro hpos he
    simp only [Pred.positive, Bool.and_eq_true] at hpos
    simp only [eval, Bool.and_eq_true] at he
    simp only [eval3, ihp hpos.1 he.1, ihq hpos.2 he.2, k3and]
  | or p q ihp ihq =>
    intro hpos he
    simp only [Pred.positive, Bool.and_eq_true] at hpos
    simp only [eval, Bool.or_eq_true] at he
    cases he with
    | inl h1 => simp only [eval3, ihp hpos.1 h1, k3or]
    | inr h2 =>
      simp only [eval3, ihq hpos.2 h2]
      cases eval3 r p with
      | none => rfl
      | some a => cases a <;> rfl
  | not p _ => intro hpos _; simp [Pred.positive] at hpos

/-- NOT-free predicates: adopting the 3VL reference changes no permit decision. -/
theorem eval3_pos_iff (r : Row) (p : Pred) (hp : p.positive = true) :
    eval3 r p = some true ↔ eval r p = true :=
  ⟨eval3_sound r p true, eval3_pos_complete r p hp⟩

theorem refQ3_pos_eq (tf : Field) (t : Value) (r : Row) (p : Pred) (hp : p.positive = true) :
    refQ3 tf t r p = refQ tf t r p := by
  have hp' : (Pred.and (.eq tf t) p).positive = true := by simp [Pred.positive, hp]
  have iff := eval3_pos_iff r (.and (.eq tf t) p) hp'
  cases hq : refQ tf t r p with
  | true =>
    have : eval3 r (.and (.eq tf t) p) = some true := iff.2 (by simpa [refQ] using hq)
    simp [refQ3, this]
  | false =>
    cases h3 : refQ3 tf t r p with
    | false => rfl
    | true => have := refQ3_imp_refQ tf t r p h3; rw [hq] at this; cases this

theorem k3and_some_some (a b : Bool) : k3and (some a) (some b) = some (a && b) := by
  cases a <;> cases b <;> rfl
theorem k3or_some_some (a b : Bool) : k3or (some a) (some b) = some (a || b) := by
  cases a <;> cases b <;> rfl

/-- Where no field read by p is NULL, 3VL and 2VL coincide: the gap is caused by NULLs and nothing else. -/
theorem eval3_total (r : Row) :
    ∀ p : Pred, (∀ f, f ∈ readsOf p → (r f).isSome = true) → eval3 r p = some (eval r p) := by
  intro p
  induction p with
  | tt => intro _; rfl
  | ff => intro _; rfl
  | eq f v =>
    intro hs
    have hf := hs f (by simp [readsOf])
    cases hr : r f with
    | none => rw [hr] at hf; cases hf
    | some x => simp only [eval3, eval, hr, Option.map_some]
  | isIn f vs =>
    intro hs
    have hf := hs f (by simp [readsOf])
    cases hr : r f with
    | none => rw [hr] at hf; cases hf
    | some x => simp only [eval3, eval, hr, Option.map_some]
  | range f lo hi =>
    intro hs
    have hf := hs f (by simp [readsOf])
    cases hr : r f with
    | none => rw [hr] at hf; cases hf
    | some x => simp only [eval3, eval, hr, Option.map_some]
  | pfx f s =>
    intro hs
    have hf := hs f (by simp [readsOf])
    cases hr : r f with
    | none => rw [hr] at hf; cases hf
    | some x => simp only [eval3, eval, hr, Option.map_some]
  | and p q ihp ihq =>
    intro hs
    have h1 := ihp (fun f hf => hs f (by simp [readsOf, hf]))
    have h2 := ihq (fun f hf => hs f (by simp [readsOf, hf]))
    simp only [eval3, eval, h1, h2, k3and_some_some]
  | or p q ihp ihq =>
    intro hs
    have h1 := ihp (fun f hf => hs f (by simp [readsOf, hf]))
    have h2 := ihq (fun f hf => hs f (by simp [readsOf, hf]))
    simp only [eval3, eval, h1, h2, k3or_some_some]
  | not p ihp =>
    intro hs
    have h1 := ihp (fun f hf => hs f (by simp [readsOf, hf]))
    simp only [eval3, eval, h1, k3not]

/-- Counterexample for NOT: the two references diverge exactly on NOT over an absent field. -/
theorem not_absent_gap (f : Field) (v : Value) (r : Row) (hr : r f = none) :
    eval r (.not (.eq f v)) = true ∧ eval3 r (.not (.eq f v)) = none := by
  constructor
  · simp [eval, hr]
  · simp [eval3, hr, k3not]

-- ---------------------------------------------------------------------------------------------- In []
/-- `In []`: FALSE on a present column, UNKNOWN on NULL (the Lowering.lean comment "[] ⇒ FALSE" is incomplete). -/
theorem sql3_inList_nil (B : Backend) (r : Row) (f : Field) :
    sql3 B r (.inList f []) = (r f).map (fun _ => false) := by
  simp only [sql3]
  cases r f with
  | none => rfl
  | some x => rfl

theorem eval3_isIn_nil (r : Row) (f : Field) : eval3 r (.isIn f []) = (r f).map (fun _ => false) := by
  simp only [eval3]
  cases r f with
  | none => rfl
  | some x => rfl

/-- Rendering `In []` as the constant FALSE (research `(1=0)`) is not exact: under NOT over a NULL column it yields
    TRUE where the lowering and the 3VL reference yield UNKNOWN. -/
theorem inList_nil_not_const_false (B : Backend) (r : Row) (f : Field) (hr : r f = none) :
    sql3 B r (lower (.not (.isIn f []))) = none ∧ eval3 r (.not (.isIn f [])) = none ∧
    sql3 B r (.not (.lit false)) = some true := by
  refine ⟨?_, ?_, rfl⟩
  · simp [lower, sql3, hr, k3not]
  · simp [eval3, hr, k3not]

-- ---------------------------------------------------------------------------------------------- Refines only
/-- Under mere refinement the 3VL reference still bounds the positive fragment (no leak). -/
theorem lower_sound_pos3 {B : Backend} (h : B.Refines) (r : Row) (p : Pred) (hp : p.positive = true)
    (hs : sql3 B r (lower p) = some true) : eval3 r p = some true :=
  eval3_pos_complete r p hp (lower_sound_pos h r p hp hs)

/-- ... and NOT still needs exactness: a refining backend leaks under NOT against the 3VL reference too. -/
theorem refines_insufficient_for_not3 :
    keeps neverEq row1 (lower (.not (.eq 1 (.int 5)))) = true ∧
    eval3 row1 (.not (.eq 1 (.int 5))) = some false := by
  refine ⟨by decide, by decide⟩

-- ---------------------------------------------------------------------------------------------- vacuity
/-- Non-vacuity of lowerQ_exact3 on the interesting case: field 2 is absent in row1 (a nullable column holding
    NULL). The exact backend drops the row, refQ3 denies it, the old refQ permits it. -/
theorem exact3_nonvacuous_null :
    keeps refBackend row1 (lowerQ 0 (.str "acme") (.not (.eq 2 (.int 7)))) = false ∧
    refQ3 0 (.str "acme") row1 (.not (.eq 2 (.int 7))) = false ∧
    refQ 0 (.str "acme") row1 (.not (.eq 2 (.int 7))) = true := by
  refine ⟨by decide, by decide, by decide⟩

/-- ... and on a present nullable value NOT behaves classically (keeps = refQ3 = true). -/
theorem exact3_nonvacuous_present :
    keeps refBackend row1 (lowerQ 0 (.str "acme") (.not (.eq 1 (.int 7)))) = true ∧
    refQ3 0 (.str "acme") row1 (.not (.eq 1 (.int 7))) = true := by
  refine ⟨by decide, by decide⟩

end AegisIR.ThreeValued
