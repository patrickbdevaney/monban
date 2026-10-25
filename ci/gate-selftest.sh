#!/usr/bin/env bash
# Negative control for ci/gate.sh: the gate must FAIL on spec/negative-control and name every planted defect.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
out=$("$ROOT/ci/gate.sh" "$ROOT/spec/negative-control" 2>&1); rc=$?
[ $rc -ne 0 ] || { echo "SELFTEST FAIL: gate passed the negative control"; exit 1; }
for want in 'sorry warning' 'native_decide\b/' 'axiom\b/' "uses_sorry: unpermitted axioms ['sorryAx']" \
            'uses_native: unpermitted axioms' "uses_axiom: unpermitted axioms ['AegisIR.Bad.cheat']" 'PROOF GATE: FAIL'; do
  grep -qF -- "$want" <<<"$out" || { echo "SELFTEST FAIL: gate output lacks: $want"; echo "$out" | tail -30; exit 1; }
done
# Frozen-statement control: weakening a frozen theorem statement in a copy of spec/ must fail the ledger check.
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
cp -r "$ROOT/spec/AegisIR" "$ROOT/spec/lakefile.toml" "$ROOT/spec/STATEMENTS.sha256" "$t/"
sed -i 's/theorem combine_empty : combine \[\] = .deny/theorem combine_empty : combine [] ≠ .allow/' "$t/AegisIR/Combine.lean"
if python3 -I "$ROOT/ci/statements.py" check "$t" >/dev/null; then echo "SELFTEST FAIL: weakened statement not detected"; exit 1; fi
echo "GATE SELFTEST: PASS (negative control rejected with every planted defect named; weakened statement detected)"
