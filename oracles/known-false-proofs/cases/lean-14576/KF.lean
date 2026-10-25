import Lean
open Lean Elab Command
/- Lean issue #14576 (closed 2026-08-03 via PR #14577 "check the structure name when
   comparing projections in the kernel"). The pre-fix kernel accepted a `.proj` that named
   one structure while projecting a value of a DIFFERENT structure, so reading field 0 of
   `C` (type `False`) out of a `W`-typed value produced an axiom-free `False`.
   Reproduced faithfully: we build that exact `.proj` and feed it to the kernel.
   FIXED UPSTREAM in 4.35.0: the kernel now rejects with "invalid projection". -/
namespace KF
structure C where c : False
structure W where w : Nat
run_cmd liftCoreM do
  let wval : Expr := (mkConst ``KF.W.mk).app (mkNatLit 7)
  let bad  : Expr := .proj ``KF.C 0 wval
  let decl := Declaration.thmDecl {
    name := `KF.evil, levelParams := [], type := mkConst ``False, value := bad }
  Lean.addDecl decl
end KF
