# lean-15908 -- prelude redefinition via a hand-edited export (SPEC-ONLY here)

Source: https://github.com/leanprover/lean4/issues/15908 (opened & closed 2026-10-24)
Also: https://hackmd.io/Tu2Z97xHSQilI7b91HQfAw , https://github.com/leanprover/comparator

## What it exploits
The kernel's native `Nat.add` reduction dispatches on the CONSTANT NAME `Nat.add` and does
not check that the environment's `Nat.add` is the canonical definition. An attacker who
controls an EXPORT FILE (NDJSON) can redefine `Nat.add`, then derive an axiom-free `False`.
Reported checker verdicts on the exploit export:
  - Lean paranoid : ACCEPT
  - Lean default  : ACCEPT
  - nanoda        : ACCEPT
  - lean4lean     : REJECT ("invalid form for primitive def Nat.add")
  - con-leche     : REJECT ("nonstandard structural Nat operation (Nat.add)")
  - con-ron       : REJECT ("nonstandard structural Nat operation")
Maintainer (Leo de Moura) closed it "not planned": NOT a kernel soundness bug, because the
export replaces the official prelude; `comparator` rejects it ("Const does not match between
challenge and target 'Nat.add'").

## Why SPEC-ONLY on this gate
The exploit lives in the EXPORT-TRUST model (`lake check --from-export <attacker file>`),
not in `lake build` of first-party source. The current ci/gate.sh never consumes an external
export: step 4 BUILDS and exports the project itself with the pinned toolchain, so the prelude
is always canonical and this exploit is unreachable by construction.

## Expected wrong verdict (absent the defense)
Feeding the attacker's export to a bare `lake check --from-export` with Lean's own kernel =>
PASS (axiom-free False), as two of six checkers showed.

## The gate rule that must catch it (when --from-export is ever enabled)
Before accepting ANY `--from-export`, assert the exported prelude declarations are
byte-identical to the pinned toolchain's (VERIFICATION_PLAN step 6; ARCHITECTURE "#15908
closure"), AND require ALL SIX checkers to accept (the ensemble already rejects: lean4lean,
con-leche, con-ron caught it). Divergence among checkers => FAIL.

## Residual / gate hole
ci/gate.sh has NO prelude-identity assertion and NO `--from-export` path today. It is immune
only because it refuses external exports entirely. If a future change adds `--from-export`
without the prelude-identity check + unanimous-checker rule, this exploit becomes live.
