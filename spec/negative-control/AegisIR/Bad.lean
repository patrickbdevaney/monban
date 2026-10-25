namespace AegisIR.Bad
theorem uses_sorry : 2 + 2 = 5 := by sorry
theorem uses_native : 123456 * 654321 = 80779853376 := by native_decide
axiom cheat : False
theorem uses_axiom : 1 = 2 := cheat.elim
end AegisIR.Bad
