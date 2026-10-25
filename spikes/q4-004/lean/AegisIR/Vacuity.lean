/-
Vacuity / non-triviality witnesses (r4 E01). A theorem with unsatisfiable hypotheses is trivially true; each block
below exhibits a concrete model satisfying ALL hypotheses of the corresponding theorem, so the theorem is not vacuous.
Plus negative witnesses showing which hypotheses are load-bearing (dropping them makes the conclusion false).
-/
import AegisIR.Lowering
import AegisIR.Token
import AegisIR.Combine

namespace AegisIR.Vacuity
open AegisIR AegisIR.Token AegisIR.Combine

/-- The reference backend (what a correct adapter computes). -/
def refBackend : Backend where
  beq x v := decide (x = v)
  brange := refRange
  bpfx := refPrefix

theorem refBackend_exact : refBackend.Exact where
  eq_ok x v h := by simpa [refBackend] using h
  range_ok _ _ _ h := h
  pfx_ok _ _ h := h
  eq_cpl x v h := by simp [refBackend, h]
  range_cpl _ _ _ h := h
  pfx_cpl _ _ h := h

theorem refBackend_refines : refBackend.Refines := refBackend_exact.toRefines

/-- lowerQ_sound / lowerQ_sound_full hypotheses jointly satisfiable: a row that the lowered query keeps. -/
def row1 : Row := fun f => if f = 0 then some (.str "acme") else if f = 1 then some (.int 5) else none

theorem keeps_nonvacuous :
    keeps refBackend row1 (lowerQ 0 (.str "acme") (.not (.eq 1 (.int 7)))) = true := by decide

/-- A strictly-refining (NOT exact) backend: equality never matches. Refines holds, Exact fails. Under NOT it is
    UNSOUND, which shows Exact (not merely Refines) is needed for lower_sound_full. -/
def neverEq : Backend where
  beq _ _ := false
  brange _ _ _ := false
  bpfx _ _ := false

theorem neverEq_refines : neverEq.Refines where
  eq_ok _ _ h := by simp [neverEq] at h
  range_ok _ _ _ h := by simp [neverEq] at h
  pfx_ok _ _ h := by simp [neverEq] at h

theorem refines_insufficient_for_not :
    keeps neverEq row1 (lowerQ 0 (.str "acme") (.not (.eq 1 (.int 5)))) = false ∧
    keeps neverEq row1 (lower (.not (.eq 1 (.int 5)))) = true ∧
    eval row1 (.not (.eq 1 (.int 5))) = false := by
  refine ⟨by decide, by decide, by decide⟩

/-- Token theorem hypotheses satisfiable: a well-minted token that verifies under a toy MAC. -/
def req1 : Req := { aud := "api", ops := 1, res := ["t1", "doc"], tenant := [1], holder := [9],
                    tool := "read", args := [("n", .int 3)], now := 10 }

def cav1 : List Caveat := [.aud "api", .exp 100, .depth 2, .res ["t1"], .tool "read" [("n", .range 0 5)]]

theorem token_nonvacuous : WellMinted cav1 "api" 100 2 ∧ denote cav1 req1 = true ∧ depthOk cav1 = true :=
  ⟨⟨_, rfl⟩, by decide, by decide⟩

/-- D1 witness: a string-prefix reading of res_prefix would admit /t1 -> /t10; segment prefix does not. -/
theorem segment_prefix_blocks_t10 : sat { req1 with res := ["t10", "doc"] } (.res ["t1"]) = false := by decide

/-- D3 witness: a 3rd post-mint caveat on a depth-2 token fails depthOk. -/
theorem depth_enforced : depthOk (cav1 ++ [.nbf 0]) = false := by decide

theorem combine_nonvacuous : combine [.allow, .allow] = .allow ∧ combine [.allow, .error] = .deny := by decide

end AegisIR.Vacuity
