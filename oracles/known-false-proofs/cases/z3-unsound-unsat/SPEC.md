# z3-unsound-unsat -- SMT solver reports UNSAT for a satisfiable formula (SPEC-ONLY)

## What it exploits
SMT solvers have had soundness bugs where a SAT (or unknown) formula is reported `unsat`.
If a pipeline treats `unsat` of (not P) as a PROOF of P, one solver bug becomes a false
theorem. Classes: incorrect simplification/rewrite, nonlinear/bitvector/float incompleteness
reported as unsat, or a buggy tactic chain.

## Input (data)
A query file `query.smt2` asserting the negation of a FALSE goal; a buggy/compromised solver
returns `unsat`, which a naive gate would read as "goal proved".
(No .smt2 shipped as an executable artifact: Z3 is not installed on this host, and SMT output
is a HINT only, never admitted as proof -- see the gate rule below.)

## Expected wrong verdict
`unsat` -> pipeline concludes the (false) goal is a theorem.

## The gate rule that MUST catch it
SMT results are HINTS ONLY and are NEVER admitted as proof. Any obligation discharged by an
SMT solver must be reconstructed as a kernel-checked Lean proof (or an independent checker)
before it counts. An `unsat` with no reconstructable certificate = FAIL, not PASS. At minimum,
require an UNSAT CORE / proof certificate replayed by a second, independent checker; a lone
solver's `unsat` is inadmissible.

## Why SPEC-ONLY
Z3/cvc5 are not installed here and the gate does not (and must not) call a solver as an oracle
of truth. Recorded as a specification the implementation-phase SMT bridge must satisfy.
