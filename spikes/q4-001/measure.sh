#!/usr/bin/env bash
# Run under ci/heavy.sh (see run.sh). 1) runtime oracle, 2) trybuild measurement (all cases as compile_fail).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$HERE"
export CARGO_TARGET_DIR="$HERE/target"
cargo test -p corpus --test runtime 2>&1 | tee results/runtime.log | grep -E "^test |test result|panicked|error" 
Q4_MEASURE=1 TRYBUILD=overwrite cargo test -p corpus --test mutants > results/measure.raw.log 2>&1; sed -i "s/\x1b\[[0-9;]*m//g" results/measure.raw.log
true
grep -cE "^test mutants/" results/measure.raw.log || true
