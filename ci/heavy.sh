#!/usr/bin/env bash
# Run a heavy command (compile, fuzz, load test, simulation) under machine-wide safety limits:
# one heavy job at a time (flock), memory cap, low priority, timeout, and a free-disk guard.
# Reentrant: a command already running under heavy.sh (AEGIS_HEAVY_HELD=1) executes nested heavy.sh calls
# directly, so wrappers that call wrappers cannot deadlock on the lock.
set -euo pipefail
if [ "${AEGIS_HEAVY_HELD:-0}" = 1 ]; then exec "$@"; fi
MIN_FREE_GB=${MIN_FREE_GB:-10}
free_gb=$(df -BG --output=avail "$HOME" | tail -1 | tr -dc 0-9)
if [ "${free_gb:-0}" -lt "$MIN_FREE_GB" ]; then
  echo "heavy.sh: refusing, only ${free_gb}G free (< ${MIN_FREE_GB}G)" >&2; exit 75
fi
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4} CARGO_INCREMENTAL=0 AEGIS_HEAVY_HELD=1
exec 9>/tmp/aegis-heavy.lock
if ! flock -n 9; then echo "heavy.sh: waiting for the heavy-job lock (one at a time)..." >&2; flock 9; fi
exec systemd-run --user --scope -q -p MemoryMax="${HEAVY_MEM:-6G}" -p MemorySwapMax=1G \
  nice -n 15 timeout "${HEAVY_TIMEOUT:-1800}" "$@"
