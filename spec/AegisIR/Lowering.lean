/-
Monban op-capability IR — filter fragment and its SQL lowering, core Lean 4 only (no Mathlib, no Batteries).
STATUS: r3 draft written 2026-10-25 without a toolchain; r4 E01 CHECKED it with lean 4.35.0 (eb6cafb) on 2026-10-25.
        r3 draft as written FAILED: 3 errors (anyEq_sound: `simp [List.contains]` hit maxRecDepth twice; lower_sound_pos
        isIn case: simp normalises `vs.contains x = true` to `x ∈ vs`) + 1 sorry (lower_sound_full).
        r4 changes are PROOF-ONLY (definitions/semantics byte-identical to r3): anyEq_sound restated via `List.elem`
        simp lemmas, isIn case closes via `List.contains_iff_mem`-free rewrite, lower_sound_full proved (no sorry).

Shape of the result:
  * `Pred` is the IR filter (eq / in / range / prefix / and / or / not / tt / ff); n-ary And/Or desugar to
    binary with And [] = tt and Or [] = ff (so an empty disjunction can never widen).
  * `eval` is the policy (reference) semantics: two-valued; an absent/NULL field makes every atom false.
  * `SqlExpr` is a mini SQL WHERE language with Kleene three-valued logic (Option Bool, none = UNKNOWN).
  * The backend's comparison primitives are a PARAMETER `B : Backend`. Soundness holds for every backend whose
    primitives REFINE the reference ones (`Backend.Refines`). Those refinement facts are exactly what collation,
    type affinity, citext, nondeterministic ICU collations and LIKE-wildcards violate; they are NOT provable in Lean
    about the real engine and are discharged per adapter by the executed differential oracle (TCB item).
-/
namespace AegisIR

inductive Value where
  | int  : Int → Value
  | str  : String → Value
  deriving DecidableEq, Repr

abbrev Field := Nat
abbrev Row := Field → Option Value

/-- IR filter fragment. `prefix` is only meaningful on strings. -/
inductive Pred where
  | tt     : Pred
  | ff     : Pred
  | eq     : Field → Value → Pred
  | isIn   : Field → List Value → Pred
  | range  : Field → Value → Value → Pred
  | pfx    : Field → String → Pred
  | and    : Pred → Pred → Pred
  | or     : Pred → Pred → Pred
  | not    : Pred → Pred
  deriving Repr

/-- n-ary constructors used by the IR front end. -/
def Pred.andN : List Pred → Pred
  | []      => .tt
  | p :: ps => .and p (Pred.andN ps)
def Pred.orN : List Pred → Pred
  | []      => .ff
  | p :: ps => .or p (Pred.orN ps)

/-- Reference order: only within the same storage class; ints numerically, strings by code point list. -/
def refLe : Value → Value → Bool
  | .int a, .int b => decide (a ≤ b)
  | .str a, .str b => decide (a.toList.map Char.toNat ≤ b.toList.map Char.toNat)  -- lexicographic on code points
  | _, _ => false

def refRange (lo hi x : Value) : Bool := refLe lo x && refLe x hi

def refPrefix (s : String) : Value → Bool
  | .str x => s.toList.isPrefixOf x.toList
  | _ => false

/-- Policy semantics. Absent (NULL) field ⇒ atom false. -/
def eval (r : Row) : Pred → Bool
  | .tt => true
  | .ff => false
  | .eq f v => match r f with | some x => decide (x = v) | none => false
  | .isIn f vs => match r f with | some x => vs.contains x | none => false
  | .range f lo hi => match r f with | some x => refRange lo hi x | none => false
  | .pfx f s => match r f with | some x => refPrefix s x | none => false
  | .and p q => eval r p && eval r q
  | .or p q => eval r p || eval r q
  | .not p => !(eval r p)

/-- What the backend actually computes for each primitive comparison (collation, affinity, …). -/
structure Backend where
  beq    : Value → Value → Bool          -- column = literal
  brange : Value → Value → Value → Bool  -- lo <= column AND column <= hi
  bpfx   : String → Value → Bool         -- prefix test as rendered (substr/left/LIKE …)

/-- Refinement: whenever the backend says yes, the reference says yes. This is the per-adapter contract. -/
structure Backend.Refines (B : Backend) : Prop where
  eq_ok    : ∀ x v, B.beq x v = true → x = v
  range_ok : ∀ lo hi x, B.brange lo hi x = true → refRange lo hi x = true
  pfx_ok   : ∀ s x, B.bpfx s x = true → refPrefix s x = true

/-- Mini SQL WHERE expressions. -/
inductive SqlExpr where
  | lit    : Bool → SqlExpr
  | cmpEq  : Field → Value → SqlExpr
  | inList : Field → List Value → SqlExpr          -- (f = v1 OR f = v2 ...); [] ⇒ FALSE on a non-NULL column, UNKNOWN on NULL (sql3_inList_nil)
  | between: Field → Value → Value → SqlExpr
  | pfx    : Field → String → SqlExpr
  | and    : SqlExpr → SqlExpr → SqlExpr
  | or     : SqlExpr → SqlExpr → SqlExpr
  | not    : SqlExpr → SqlExpr

/-- Kleene connectives. -/
def k3and : Option Bool → Option Bool → Option Bool
  | some false, _ => some false
  | _, some false => some false
  | some true, some true => some true
  | _, _ => none
def k3or : Option Bool → Option Bool → Option Bool
  | some true, _ => some true
  | _, some true => some true
  | some false, some false => some false
  | _, _ => none
def k3not : Option Bool → Option Bool
  | some b => some (!b)
  | none => none

def anyEq (B : Backend) (x : Value) : List Value → Bool
  | [] => false
  | v :: vs => B.beq x v || anyEq B x vs

/-- Three-valued SQL evaluation over a row; NULL column ⇒ UNKNOWN for every comparison. -/
def sql3 (B : Backend) (r : Row) : SqlExpr → Option Bool
  | .lit b => some b
  | .cmpEq f v => (r f).map (fun x => B.beq x v)
  | .inList f vs => (r f).map (fun x => anyEq B x vs)
  | .between f lo hi => (r f).map (fun x => B.brange lo hi x)
  | .pfx f s => (r f).map (fun x => B.bpfx s x)
  | .and a b => k3and (sql3 B r a) (sql3 B r b)
  | .or a b => k3or (sql3 B r a) (sql3 B r b)
  | .not a => k3not (sql3 B r a)

/-- The lowering under test (structural; tenant conjunct added by `lowerQ`). -/
def lower : Pred → SqlExpr
  | .tt => .lit true
  | .ff => .lit false
  | .eq f v => .cmpEq f v
  | .isIn f vs => .inList f vs
  | .range f lo hi => .between f lo hi
  | .pfx f s => .pfx f s
  | .and p q => .and (lower p) (lower q)
  | .or p q => .or (lower p) (lower q)
  | .not p => .not (lower p)

/-- Mandatory tenant conjunct: the handle is a host-minted value, never request bytes. -/
def lowerQ (tenantField : Field) (t : Value) (p : Pred) : SqlExpr := .and (.cmpEq tenantField t) (lower p)
def refQ (tenantField : Field) (t : Value) (r : Row) (p : Pred) : Bool := eval r (.and (.eq tenantField t) p)

/-- WHERE keeps a row iff the condition is TRUE (UNKNOWN and FALSE drop it). -/
def keeps (B : Backend) (r : Row) (e : SqlExpr) : Bool := sql3 B r e == some true

-- ---------------------------------------------------------------------------------------------- lemmas
theorem anyEq_sound {B : Backend} (h : B.Refines) (x : Value) :
    ∀ vs, anyEq B x vs = true → vs.contains x = true := by
  intro vs
  induction vs with
  | nil => simp [anyEq]
  | cons v vs ih =>
    intro hv
    simp only [anyEq, Bool.or_eq_true] at hv
    cases hv with
    | inl he => have := h.eq_ok x v he; subst this; simp
    | inr ht => have := ih ht; simp at this ⊢; exact Or.inr this

/-- Kleene invariant (needed for NOT): a DEFINITE backend answer agrees with the reference in both polarities.
    `some true ⇒ eval = true` and `some false ⇒ eval = false`.  The second half needs the backend to be EXACT
    (refines in both directions) on atoms; with refinement only, we keep the positive fragment theorem below and
    state the NOT-fragment version under `Backend.Exact`. -/
structure Backend.Exact (B : Backend) : Prop extends B.Refines where
  eq_cpl    : ∀ x v, x = v → B.beq x v = true
  range_cpl : ∀ lo hi x, refRange lo hi x = true → B.brange lo hi x = true
  pfx_cpl   : ∀ s x, refPrefix s x = true → B.bpfx s x = true

theorem k3and_true : ∀ a b : Option Bool, k3and a b = some true → a = some true ∧ b = some true := by
  intro a b h
  cases a with
  | none => cases b with
    | none => simp [k3and] at h
    | some y => cases y <;> simp [k3and] at h
  | some x => cases x <;> cases b with
    | none => simp [k3and] at h
    | some y => cases y <;> simp [k3and] at h ⊢

theorem k3or_true : ∀ a b : Option Bool, k3or a b = some true → a = some true ∨ b = some true := by
  intro a b h
  cases a with
  | none => cases b with
    | none => simp [k3or] at h
    | some y => cases y <;> simp [k3or] at h ⊢
  | some x => cases x <;> cases b with
    | none => simp [k3or] at h ⊢
    | some y => cases y <;> simp [k3or] at h ⊢

/-- Positive (NOT-free) fragment. -/
def Pred.positive : Pred → Bool
  | .not _ => false
  | .and p q => p.positive && q.positive
  | .or p q => p.positive && q.positive
  | _ => true

/-- MAIN THEOREM (positive fragment): for any refining backend, a row kept by the lowered WHERE is permitted by
    the policy.  This covers Eq/In/Range/Prefix/And/Or/empty-In/empty-Or and NULLs. -/
theorem lower_sound_pos {B : Backend} (h : B.Refines) (r : Row) :
    ∀ p : Pred, p.positive = true → sql3 B r (lower p) = some true → eval r p = true := by
  intro p
  induction p with
  | tt => intro _ _; rfl
  | ff => intro _ hs; simp [lower, sql3] at hs
  | eq f v =>
    intro _ hs; simp only [lower, sql3] at hs
    cases hr : r f with
    | none => simp [hr] at hs
    | some x => simp [hr] at hs; simp [eval, hr, h.eq_ok x v hs]
  | isIn f vs =>
    intro _ hs; simp only [lower, sql3] at hs
    cases hr : r f with
    | none => simp [hr] at hs
    | some x =>
      simp [hr] at hs
      have hc := anyEq_sound h x vs hs
      simp only [eval, hr]; exact hc
  | range f lo hi =>
    intro _ hs; simp only [lower, sql3] at hs
    cases hr : r f with
    | none => simp [hr] at hs
    | some x => simp [hr] at hs; simp [eval, hr]; exact h.range_ok lo hi x hs
  | pfx f s =>
    intro _ hs; simp only [lower, sql3] at hs
    cases hr : r f with
    | none => simp [hr] at hs
    | some x => simp [hr] at hs; simp [eval, hr]; exact h.pfx_ok s x hs
  | and p q ihp ihq =>
    intro hpos hs
    simp only [Pred.positive, Bool.and_eq_true] at hpos
    simp only [lower, sql3] at hs
    have ⟨h1, h2⟩ := k3and_true _ _ hs
    simp [eval, ihp hpos.1 h1, ihq hpos.2 h2]
  | or p q ihp ihq =>
    intro hpos hs
    simp only [Pred.positive, Bool.and_eq_true] at hpos
    simp only [lower, sql3] at hs
    cases k3or_true _ _ hs with
    | inl h1 => simp [eval, ihp hpos.1 h1]
    | inr h2 => simp [eval, ihq hpos.2 h2]
  | not p _ => intro hpos _; simp [Pred.positive] at hpos

/-- Query-level soundness with the mandatory tenant conjunct. -/
theorem lowerQ_sound {B : Backend} (h : B.Refines) (tf : Field) (t : Value) (r : Row) (p : Pred)
    (hp : p.positive = true) (hk : keeps B r (lowerQ tf t p) = true) : refQ tf t r p = true := by
  have : p.positive = true ∧ (Pred.eq tf t).positive = true := ⟨hp, rfl⟩
  have hs : sql3 B r (lower (.and (.eq tf t) p)) = some true := by
    simpa [keeps, lowerQ, lower] using hk
  exact lower_sound_pos h r (.and (.eq tf t) p) (by simp [Pred.positive, hp]) hs

/-- With NOT: soundness needs EXACT atoms (two-sided). Stated; proof is the same induction carrying the pair
    invariant (some b ⇒ eval = b). Effort: ~40 more lines. -/
theorem anyEq_exact {B : Backend} (h : B.Exact) (x : Value) :
    ∀ vs, anyEq B x vs = vs.contains x := by
  intro vs
  induction vs with
  | nil => simp [anyEq]
  | cons v vs ih =>
    simp only [anyEq, ih, List.contains_cons]
    cases hb : B.beq x v with
    | true => have := h.eq_ok x v hb; subst this; simp
    | false =>
      have hne : x ≠ v := fun he => by have := h.eq_cpl x v he; rw [hb] at this; cases this
      simp [hne]

theorem beq_exact {B : Backend} (h : B.Exact) (x v : Value) : B.beq x v = decide (x = v) := by
  cases hb : B.beq x v with
  | true => have := h.eq_ok x v hb; simp [this]
  | false => have hne : x ≠ v := fun he => by have := h.eq_cpl x v he; rw [hb] at this; cases this
             simp [hne]

theorem brange_exact {B : Backend} (h : B.Exact) (lo hi x : Value) : B.brange lo hi x = refRange lo hi x := by
  cases hb : B.brange lo hi x with
  | true => exact (h.range_ok lo hi x hb).symm
  | false =>
    cases hr : refRange lo hi x with
    | false => rfl
    | true => have := h.range_cpl lo hi x hr; rw [hb] at this; cases this

theorem bpfx_exact {B : Backend} (h : B.Exact) (s : String) (x : Value) : B.bpfx s x = refPrefix s x := by
  cases hb : B.bpfx s x with
  | true => exact (h.pfx_ok s x hb).symm
  | false =>
    cases hr : refPrefix s x with
    | false => rfl
    | true => have := h.pfx_cpl s x hr; rw [hb] at this; cases this

theorem k3and_some : ∀ (a c : Option Bool) (b : Bool), k3and a c = some b →
    (∃ x y, a = some x ∧ c = some y ∧ b = (x && y)) ∨ (b = false ∧ (a = some false ∨ c = some false)) := by
  intro a c b h
  rcases a with _ | ⟨_ | _⟩ <;> rcases c with _ | ⟨_ | _⟩ <;> cases b <;> simp_all [k3and]

theorem k3or_some : ∀ (a c : Option Bool) (b : Bool), k3or a c = some b →
    (∃ x y, a = some x ∧ c = some y ∧ b = (x || y)) ∨ (b = true ∧ (a = some true ∨ c = some true)) := by
  intro a c b h
  rcases a with _ | ⟨_ | _⟩ <;> rcases c with _ | ⟨_ | _⟩ <;> cases b <;> simp_all [k3or]

theorem lower_sound_full {B : Backend} (h : B.Exact) (r : Row) :
    ∀ p : Pred, ∀ b : Bool, sql3 B r (lower p) = some b → eval r p = b := by
  intro p
  induction p with
  | tt => intro b hs; simp [lower, sql3] at hs; simp [eval, hs]
  | ff => intro b hs; simp [lower, sql3] at hs; simp [eval, hs]
  | eq f v =>
    intro b hs; simp only [lower, sql3] at hs
    cases hr : r f with
    | none => simp [hr] at hs
    | some x => simp [hr] at hs; simp only [eval, hr]; rw [← hs, beq_exact h]
  | isIn f vs =>
    intro b hs; simp only [lower, sql3] at hs
    cases hr : r f with
    | none => simp [hr] at hs
    | some x => simp [hr] at hs; simp only [eval, hr]; rw [← hs, anyEq_exact h]
  | range f lo hi =>
    intro b hs; simp only [lower, sql3] at hs
    cases hr : r f with
    | none => simp [hr] at hs
    | some x => simp [hr] at hs; simp only [eval, hr]; rw [← hs, brange_exact h]
  | pfx f s =>
    intro b hs; simp only [lower, sql3] at hs
    cases hr : r f with
    | none => simp [hr] at hs
    | some x => simp [hr] at hs; simp only [eval, hr]; rw [← hs, bpfx_exact h]
  | and p q ihp ihq =>
    intro b hs; simp only [lower, sql3] at hs
    rcases k3and_some _ _ _ hs with ⟨x, y, h1, h2, hb⟩ | ⟨hb, h1 | h2⟩
    · simp only [eval, ihp x h1, ihq y h2, hb]
    · simp only [eval, ihp false h1, hb, Bool.false_and]
    · simp only [eval, ihq false h2, hb, Bool.and_false]
  | or p q ihp ihq =>
    intro b hs; simp only [lower, sql3] at hs
    rcases k3or_some _ _ _ hs with ⟨x, y, h1, h2, hb⟩ | ⟨hb, h1 | h2⟩
    · simp only [eval, ihp x h1, ihq y h2, hb]
    · simp only [eval, ihp true h1, hb, Bool.true_or]
    · simp only [eval, ihq true h2, hb, Bool.or_true]
  | not p ihp =>
    intro b hs; simp only [lower, sql3] at hs
    cases ha : sql3 B r (lower p) with
    | none => simp [ha, k3not] at hs
    | some a => simp [ha, k3not] at hs; simp only [eval, ihp a ha, hs, Bool.not_not]

/-- Query-level soundness WITH NOT, under exact atoms. -/
theorem lowerQ_sound_full {B : Backend} (h : B.Exact) (tf : Field) (t : Value) (r : Row) (p : Pred)
    (hk : keeps B r (lowerQ tf t p) = true) : refQ tf t r p = true := by
  have hs : sql3 B r (lower (.and (.eq tf t) p)) = some true := by
    simpa [keeps, lowerQ, lower] using hk
  exact lower_sound_full h r _ true hs

/-- SPEC-GAP WITNESS (r4): the reference semantics is two-valued with "absent ⇒ atom false", so a NOT over an
    absent field PERMITS at the policy level.  SQL drops the row (UNKNOWN), so the SQL lowering is still sound, but
    any adapter that implements `eval` literally (e.g. a document store whose `$ne` matches missing fields) grants
    rows the policy author probably meant to deny. -/
theorem not_absent_permits (f : Field) (v : Value) (r : Row) (hr : r f = none) :
    eval r (.not (.eq f v)) = true := by simp [eval, hr]

/-- Counter-theorem (why Refines is necessary): if the backend's equality is coarser than the reference
    on some pair (NOCASE 'ACME'='acme', affinity 1='1', ICU NFC=NFD), the lowering is unsound. -/
theorem refines_necessary (B : Backend) (tf : Field) (x t : Value) (hne : x ≠ t) (hb : B.beq x t = true) :
    ∃ r : Row, keeps B r (lowerQ tf t .tt) = true ∧ refQ tf t r .tt = false := by
  refine ⟨fun f => if f = tf then some x else none, ?_, ?_⟩
  · simp [keeps, lowerQ, lower, sql3, hb, k3and]
  · simp [refQ, eval, hne]

/-- n-ary desugaring: empty disjunction denotes FALSE (cannot widen), empty conjunction TRUE. -/
theorem orN_nil (r : Row) : eval r (Pred.orN []) = false := rfl
theorem andN_nil (r : Row) : eval r (Pred.andN []) = true := rfl

end AegisIR
