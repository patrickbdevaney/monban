namespace KF
/- EXPLOIT: the `Lean.ofReduceBool` axiom certifies a compiled `reduceBool` result into the
   logic. A lying compiler => false proof. FIXED UPSTREAM: in Lean 4.35.0 `native_decide` no
   longer uses a single global `ofReduceBool`; it emits per-declaration native axioms (see
   src/lean/Lean/Meta/Native.lean). The identifier is gone, so this fails to elaborate; the
   forbidden-token scan bans the token besides. -/
theorem via_ofReduceBool : (2 : Nat) < 3 :=
  of_decide_eq_true (Lean.ofReduceBool (Nat.decLt 2 3 |> decide) true rfl)
end KF
