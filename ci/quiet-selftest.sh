#!/usr/bin/env bash
# Self-test for ci/quiet.py (run under ci/heavy.sh or ci/remote.sh): a guarded command that runs while 4 busy
# loops burn CPU in a separate scope (foreign load) must come back INVALID (exit 75) and never with its own verdict;
# the same command on a quiet host must come back VALID with its own exit status.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
export QUIET_ATTEMPTS=1 QUIET_SETTLE_S=10 QUIET_WAIT_S=600
ok=$("$ROOT/ci/quiet.py" sh -c 'sleep 12; echo GUARDED: PASS' 2>&1); rc=$?
[ $rc = 0 ] && echo "$ok" | tail -1 | grep -qx 'GUARDED: PASS' || { echo "$ok"; echo "QUIET SELF-TEST: FAIL (quiet control not VALID/PASS, rc=$rc)"; exit 1; }
# The burners start only after the guard has settled (sleep 15 > settle 10), so they land inside the run window.
systemd-run --user --scope -q timeout 45 sh -c "sleep 15; for i in 1 2 3 4; do timeout 30 sh -c 'while :; do :; done' & done; wait" &
burn=$!
bad=$("$ROOT/ci/quiet.py" sh -c 'sleep 25; echo GUARDED: PASS' 2>&1); rc=$?
wait $burn 2>/dev/null
if [ $rc = 75 ] && echo "$bad" | grep -q 'attempt 1/1 INVALID' && ! echo "$bad" | tail -1 | grep -qx 'GUARDED: PASS'; then
  echo "QUIET SELF-TEST: PASS (quiet control VALID; 4 foreign busy loops voided the attempt)"
else
  echo "$bad"; echo "QUIET SELF-TEST: FAIL (foreign load not detected, rc=$rc)"; exit 1
fi
