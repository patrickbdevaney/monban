-- Negative controls for the audit: each must show a non-standard axiom.
theorem ctl_native : (0 : Int64).toInt = 0 := by native_decide
theorem ctl_sorry : (1 : Nat) = 2 := by sorry
axiom ctl_user_ax : False
theorem ctl_user : (1 : Nat) = 2 := ctl_user_ax.elim
theorem ctl_clean : (0 : Int64).toInt = 0 := by decide
#print axioms ctl_native
#print axioms ctl_sorry
#print axioms ctl_user
#print axioms ctl_clean
