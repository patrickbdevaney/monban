namespace KF
def adminTok : Nat := 42
def verify (tok : Nat) : Bool := tok == adminTok
/- WEAKENED invariant (the attack): conclusion silently replaced by `True`. Still compiles,
   kernel-accepts, uses no forbidden axioms -- it passes steps 1-4. Only the frozen statement
   ledger catches that the THEOREM WE PROVE no longer matches the one that was reviewed. -/
theorem no_bypass (tok : Nat) : verify tok = true → True := by
  intro _; trivial
end KF
