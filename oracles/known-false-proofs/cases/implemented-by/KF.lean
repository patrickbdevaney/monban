namespace KF
/- EXPLOIT: `@[implemented_by]` makes the COMPILER use `fakeCheck` (always true) while the
   kernel still sees `realCheck`. `native_decide` then certifies the compiled (lying) answer,
   producing a theorem the kernel-level definition does not support. A lie the logic trusts. -/
def realCheck (_ : Nat) : Bool := false
@[implemented_by realCheck] def fakeCheck (_ : Nat) : Bool := false  -- decl the compiler replaces
unsafe def fakeImpl (_ : Nat) : Bool := true
@[implemented_by fakeImpl] def badCheck (n : Nat) : Bool := realCheck n
theorem lie : badCheck 7 = true := by native_decide
end KF
