#!/usr/bin/env bash
# Runs every oracle under oracles/*/run in the given mode: `run` (default subject/reference) or `self-test`.
# Fails if any oracle fails, or if an oracle directory lacks an executable `run`. Oracles that judge a production
# binary list it in `default-subject`; build those subjects first (gate build-subjects).
set -uo pipefail
# Placement: an oracle that needs host facilities lists them in `needs` (docker, lean). `--where remote` runs only
# oracles with no needs (for the LAN build box); `--where local` runs oracles with any need other than quiet-host
# (docker, lean: this laptop); `--where quiet` runs oracles whose only need is quiet-host (the dedicated quiet
# runner, ssh alias `quiet`). Every quiet-host oracle, wherever it runs, goes under ci/quiet.py, which waits for a
# quiet host and voids any attempt that saw foreign load. Default: all.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; mode="${1:-run}"; where="all"; fail=0; n=0
[ "${2:-}" = --where ] && where="${3:-all}"
# ORACLES_DIR overrides the oracle directory (ci/oracles-agg-selftest.sh points it at fixtures).
for d in "${ORACLES_DIR:-$ROOT/oracles}"/*/; do
  name=$(basename "$d"); r="$d/run"
  if [ "$where" = remote ] && [ -f "$d/needs" ]; then continue; fi
  quiet=0; [ -f "$d/needs" ] && grep -qx quiet-host "$d/needs" && quiet=1
  other=0; [ -f "$d/needs" ] && awk 'NF && $1 != "quiet-host" {f=1} END {exit !f}' "$d/needs" && other=1
  if [ "$where" = local ] && [ $other = 0 ]; then continue; fi
  if [ "$where" = quiet ] && { [ $quiet = 0 ] || [ $other = 1 ]; }; then continue; fi
  guard=(); [ $quiet = 1 ] && guard=("$ROOT/ci/quiet.py")
  [ -x "$r" ] || { echo "ORACLES: $name has no executable run"; fail=1; continue; }
  n=$((n+1))
  # An oracle that needs a production subject names it in default-subject (a path relative to the repo root).
  subj=(); [ -f "$d/default-subject" ] && subj=(--subject "$ROOT/$(head -1 "$d/default-subject")")
  if [ "$mode" = self-test ]; then out=$("$ROOT/ci/heavy.sh" "${guard[@]}" "$r" --self-test 2>&1); else out=$("$ROOT/ci/heavy.sh" "${guard[@]}" "$r" "${subj[@]}" 2>&1); fi
  rc=$?
  echo "$out" | grep '^quiet.py:' | sed "s/^/[$name] /" || true
  echo "[$name] $(echo "$out" | grep -v '^\s*$' | tail -1)"; [ $rc -eq 0 ] || fail=1
done
[ $n -gt 0 ] || { echo "ORACLES: none found"; exit 1; }
[ $fail = 0 ] && echo "ORACLES ($mode): PASS ($n oracles)" || { echo "ORACLES ($mode): FAIL"; exit 1; }
