#!/usr/bin/env bash
# The aggregator must go red when one oracle fails and green when all pass (a regression once took the exit
# status of the output-echo pipeline instead of the oracle's, so a failed oracle could read as PASS).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; F="$ROOT/ci/fixtures/oracles-agg"
out=$(ORACLES_DIR="$F/fail" "$ROOT/ci/oracles.sh" run --where local 2>&1) && { echo "$out"; echo "ORACLES-AGG SELF-TEST: FAIL (a failing oracle did not fail the run)"; exit 1; }
echo "$out" | grep -q '^ORACLES (run): FAIL$' || { echo "$out"; echo "ORACLES-AGG SELF-TEST: FAIL (no FAIL line)"; exit 1; }
out=$(ORACLES_DIR="$F/pass" "$ROOT/ci/oracles.sh" run --where local 2>&1) || { echo "$out"; echo "ORACLES-AGG SELF-TEST: FAIL (all-pass fixture failed)"; exit 1; }
echo "ORACLES-AGG SELF-TEST: PASS (failing oracle fails the run; all-pass fixture passes)"
