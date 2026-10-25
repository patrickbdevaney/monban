#!/usr/bin/env bash
# Full q2-009 matrix. Usage (from spikes/q2-009):
#   CARGO_TARGET_DIR=$PWD/target ../../ci/heavy.sh cargo build --release --offline
#   HEAVY_TIMEOUT=2400 ../../ci/heavy.sh ./run.sh
set -euo pipefail
cd "$(dirname "$0")"
for shape in window0 bigwin-noread; do
  for impl in hyper-baseline h2-baseline h2-wrapper; do
    for c in 1 10 100; do ./run_one.sh "$impl" "$shape" "$c" 100 25000 32000 12; done
  done
done
for shape in slowread rapidreset continuation; do
  for impl in hyper-baseline h2-baseline h2-wrapper; do ./run_one.sh "$impl" "$shape" 10 100 25000 32000 12; done
done
# idle-close demonstration (TBI-8, 30 s): wrapper, long hold
./run_one.sh h2-wrapper bigwin-noread 10 100 50000 55000 12 long
