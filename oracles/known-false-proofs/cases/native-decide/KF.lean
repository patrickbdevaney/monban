namespace KF
/- EXPLOIT: `native_decide` compiles the decision procedure to native code and trusts
   its result, bypassing the kernel. It emits a per-declaration `_native.native_decide.ax`
   axiom. The statement here is true, but the TRUST is misplaced: a lying `@[extern]`/
   `@[implemented_by]` (see cases implemented-by / extern) turns this into a false proof. -/
theorem via_native : (12345 * 6789 : Nat) = 83810205 := by native_decide
end KF
