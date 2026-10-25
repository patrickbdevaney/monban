import Lean
open Lean Elab Command
/- Lean issue #14484 (closed 2026-07-22 via PR #14498 "kernel to check opaque values for
   fvars"). The pre-fix kernel type-checked an opaque value but SKIPPED the closure check,
   so an opaque constant whose value is a loose free variable -- typeable as `False` via a
   primed inference cache -- slipped in axiom-free, yielding a proof of `False`.
   Reproduced as faithfully as 4.35.0 allows: we build exactly that `opaqueDecl` and feed it
   to the kernel. FIXED UPSTREAM in 4.35.0: the kernel now rejects with
   "declaration has free variables". -/
namespace KF
run_cmd liftCoreM do
  let fv : Expr := .fvar ⟨`x⟩
  let decl := Declaration.opaqueDecl {
    name := `KF.evil, levelParams := [], type := mkConst ``False,
    value := fv, isUnsafe := false }
  Lean.addDecl decl
end KF
