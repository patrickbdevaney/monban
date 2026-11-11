#!/usr/bin/env bash
# Monban proof gate (core Lean 4.35.0, no Mathlib). Usage: ci/gate.sh [lean-project-dir]  (default: spec/)
# Exit 0 only if every step passes:
#   1 toolchain pin + no dependencies + no lakefile.lean
#   2 lake build; any `sorry` warning fails
#   3 per-theorem axiom ALLOWLIST {propext, Classical.choice, Quot.sound} + forbidden-token scan (ci/axiom_audit.py)
#   4 lake check --paranoid: kernel + leanchecker-paranoid + lean4lean + nanoda + con-leche + con-ron all accept
#   5 statement hashes in spec/STATEMENTS.sha256 unchanged (frozen F1 statements; proofs may change, statements may not)
# Negative control: `ci/gate.sh spec/negative-control` must FAIL (sorry, native_decide, user axiom).
# Env: AEGIS_NO_SANDBOX=1 adds --inadvisably-no-sandbox (hosts where bwrap userns is blocked; first-party sources only).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJ="$(cd "${1:-$ROOT/spec}" && pwd)"
want='leanprover/lean4:v4.35.0'
export PATH="$HOME/.elan/toolchains/leanprover--lean4---v4.35.0/bin:$PATH"
cd "$PROJ"
[ "$(cat lean-toolchain)" = "$want" ] || { echo "GATE FAIL: lean-toolchain != $want"; exit 1; }
lean --version | grep -q 'version 4.35.0, x86_64-unknown-linux-gnu, commit eb6cafb7290e8bd5f2937522d8d804f58f02bafc' \
  || { echo "GATE FAIL: lean binary is not 4.35.0@eb6cafb"; exit 1; }
[ ! -e lakefile.lean ] || { echo "GATE FAIL: lakefile.lean present (use lakefile.toml; no Lake DSL code execution)"; exit 1; }
echo "== step 2: lake build"
log=$(lake build 2>&1) || { echo "$log" | tail -20; echo "GATE FAIL: lake build"; exit 1; }
echo "$log" | grep -v '^trace' | tail -3
fail=0
if echo "$log" | grep -q 'declaration uses .sorry.'; then echo "GATE FAIL: sorry warning"; fail=1; fi
echo "== step 3: axiom allowlist"; python3 -I "$ROOT/ci/axiom_audit.py" . || fail=1
[ "$fail" = 0 ] || { echo "PROOF GATE: FAIL"; exit 1; }
echo "== step 4: lake check --paranoid"
extra=(); [ "${AEGIS_NO_SANDBOX:-0}" = 1 ] && extra=(--inadvisably-no-sandbox)
lake check --paranoid "${extra[@]}" || { echo "PROOF GATE: FAIL (step 4: an independent checker rejected the build)"; exit 1; }
if [ -f STATEMENTS.sha256 ]; then
  echo "== step 5: frozen statement hashes"
  python3 -I "$ROOT/ci/statements.py" check . || { echo "PROOF GATE: FAIL (step 5: frozen statement changed)"; exit 1; }
fi
echo "PROOF GATE: PASS"
