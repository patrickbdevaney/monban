#!/usr/bin/env bash
# q4-006 laptop measurement: one heavy.sh job builds the harness (oracles/isolation-fi/rust, same commit) into
# spikes/q4-006/target, calibrates fuel, runs the phases, and deletes target/. Usage: ./measure.sh [phases...]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
if [ -z "${Q4006_UNDER_HEAVY:-}" ]; then
  exec env Q4006_UNDER_HEAVY=1 HEAVY_TIMEOUT="${HEAVY_TIMEOUT:-1790}" "$REPO/ci/heavy.sh" "$0" "$@"
fi
T="$HERE/target"; D="$HERE/data"; mkdir -p "$D"
trap '[ "${KEEP:-0}" = 1 ] || rm -rf "$T"' EXIT
"$REPO/oracles/isolation-fi/rust/build.sh" "$T"
B="$T/release/isofi"; G="$T/wasm32-unknown-unknown/release/guest.wasm"; DATA="$REPO/oracles/isolation-fi/rust/data.bin"
du -sh "$T" | tee -a "$D/disk.txt"
sha256sum "$B" "$G" > "$D/binaries.sha256"
[ -s "$D/calibrate.json" ] || taskset -c 2 "$B" calibrate --guest "$G" | tee "$D/calibrate.json"
for ph in "${@:-loop fi forkcost}"; do
  for p in $ph; do python3 -I "$HERE/run_spike.py" "$B" "$G" "$DATA" "$D" "$p" "${TRIALS:-3}"; done
done
if [ -n "${LANDIR:-}" ]; then mkdir -p "$LANDIR"; cp "$B" "$G" "$DATA" "$HERE/run_spike.py" "$LANDIR/"; fi
