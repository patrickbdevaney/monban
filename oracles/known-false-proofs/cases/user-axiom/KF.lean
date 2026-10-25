namespace KF
/- EXPLOIT: a user-declared `axiom` adds an unjustified assumption the kernel trusts. -/
axiom cheat : False
theorem false_via_axiom : 1 = 2 := cheat.elim
end KF
