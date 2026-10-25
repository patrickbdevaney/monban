namespace KF
/- EXPLOIT: `@[extern]` binds a Lean definition to a C symbol. If the C side disagrees with
   the Lean body, compiled evaluation (and `native_decide`) certifies the C answer while the
   kernel trusts the Lean body. Here the Lean body is `false`; a lying extern would return
   true. The token is banned outright regardless of whether the symbol resolves. -/
@[extern "lean_kf_always_true"] def externCheck (_ : Nat) : Bool := false
theorem via_extern : externCheck 7 = false := rfl
end KF
