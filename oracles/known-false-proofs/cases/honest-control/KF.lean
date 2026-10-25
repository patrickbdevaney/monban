namespace KF
/- HONEST CONTROL: a genuinely true theorem, proof uses no axioms (or only the allowlist).
   The gate MUST accept this. If it rejects, the gate is over-strict and the oracle fails. -/
theorem add_comm_two (a b : Nat) : a + b = b + a := Nat.add_comm a b
theorem keep_closed : (0 : Nat) + 0 = 0 := rfl
end KF
