#!/usr/bin/env bash
# Runs every oracle under oracles/*/run in the given mode: `run` (default subject/reference) or `self-test`.
# Fails if any oracle fails, or if an oracle directory lacks an executable `run`. Oracles that judge a production
# binary list it in `default-subject`; build those subjects first (gate build-subjects).
set -uo pipefail
# Placement: an oracle that needs host facilities lists them in `needs` (docker, lean). `--where remote` runs only
# oracles with no needs (for the LAN build box); `--where local` runs only oracles that have needs. Default: all.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; mode="${1:-run}"; where="all"; fail=0; n=0
[ "${2:-}" = --where ] && where="${3:-all}"
for d in "$ROOT"/oracles/*/; do
  name=$(basename "$d"); r="$d/run"
  if [ "$where" = remote ] && [ -f "$d/needs" ]; then continue; fi
  if [ "$where" = local ] && [ ! -f "$d/needs" ]; then continue; fi
  [ -x "$r" ] || { echo "ORACLES: $name has no executable run"; fail=1; continue; }
  n=$((n+1))
  # An oracle that needs a production subject names it in default-subject (a path relative to the repo root).
  subj=(); [ -f "$d/default-subject" ] && subj=(--subject "$ROOT/$(head -1 "$d/default-subject")")
  if [ "$mode" = self-test ]; then out=$("$ROOT/ci/heavy.sh" "$r" --self-test 2>&1); else out=$("$ROOT/ci/heavy.sh" "$r" "${subj[@]}" 2>&1); fi
  rc=$?; echo "[$name] $(echo "$out" | grep -v '^\s*$' | tail -1)"; [ $rc -eq 0 ] || fail=1
done
[ $n -gt 0 ] || { echo "ORACLES: none found"; exit 1; }
[ $fail = 0 ] && echo "ORACLES ($mode): PASS ($n oracles)" || { echo "ORACLES ($mode): FAIL"; exit 1; }
