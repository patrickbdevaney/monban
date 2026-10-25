#!/usr/bin/env bash
# Runs every oracle under oracles/*/run in the given mode: `run` (default subject/reference) or `self-test`.
# Fails if any oracle fails, or if an oracle directory lacks an executable `run`.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; mode="${1:-run}"; fail=0; n=0
for d in "$ROOT"/oracles/*/; do
  name=$(basename "$d"); r="$d/run"
  [ -x "$r" ] || { echo "ORACLES: $name has no executable run"; fail=1; continue; }
  n=$((n+1))
  if [ "$mode" = self-test ]; then out=$("$ROOT/ci/heavy.sh" "$r" --self-test 2>&1); else out=$("$ROOT/ci/heavy.sh" "$r" 2>&1); fi
  rc=$?; echo "[$name] $(echo "$out" | grep -v '^\s*$' | tail -1)"; [ $rc -eq 0 ] || fail=1
done
[ $n -gt 0 ] || { echo "ORACLES: none found"; exit 1; }
[ $fail = 0 ] && echo "ORACLES ($mode): PASS ($n oracles)" || { echo "ORACLES ($mode): FAIL"; exit 1; }
