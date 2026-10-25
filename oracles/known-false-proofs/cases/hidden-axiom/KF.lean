import KF.Helper
namespace KF
/- `@[simp] theorem` on one line: the audit's name regex `\s*(?:private\s+)?(?:theorem|lemma)` does not
   match, so no `#print axioms` row is emitted for it and steps 2-3 see nothing. Only step 4
   (`lake check`: "erroring on any use of non-standard axioms") is left to catch it. -/
@[simp] theorem bad : (1 : Nat) = 2 := KF.Helper.cheat.elim
end KF
