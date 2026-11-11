#!/usr/bin/env bash
# Run a heavy research job (cargo build/bench/install, toolchain install, load test, crash simulation) safely on the
# operator's laptop (directive §0e): one heavy job at a time machine-wide, memory-capped, low priority, disk-guarded.
# Usage: heavy.sh <command...>     e.g. heavy.sh cargo build --release
set -u
MIN_FREE_GB=${MIN_FREE_GB:-10}
free_gb=$(df -BG --output=avail "$HOME" | tail -1 | tr -dc 0-9)
if [ "$free_gb" -lt "$MIN_FREE_GB" ]; then
  echo "heavy.sh: REFUSED — only ${free_gb}G free on /home (need ${MIN_FREE_GB}G). Delete your own target/ dirs or skip the experiment and record it as an implementation-phase spike." >&2
  exit 75
fi
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4} CARGO_INCREMENTAL=0
echo "heavy.sh: waiting for the heavy-job lock (one at a time)..." >&2
exec flock /tmp/monban-heavy.lock \
  systemd-run --user --scope -q -p MemoryMax=${HEAVY_MEM:-6G} -p MemorySwapMax=1G \
  nice -n 15 timeout ${HEAVY_TIMEOUT:-1800} "$@"
