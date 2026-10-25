#!/usr/bin/env bash
# Run under ci/heavy.sh (see run.sh). 1) runtime oracle, 2) trybuild measurement (all cases as compile_fail).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$HERE"
export CARGO_TARGET_DIR="$HERE/target"
cargo test -p corpus --test runtime 2>&1 | tee results/runtime.log | grep -E "^test |test result|panicked|error" 
Q4_MEASURE=1 TRYBUILD=overwrite cargo test -p corpus --test mutants 2>&1 > results/measure.log
grep -E "^test mutants/" results/measure.log | sed 's/\x1b\[[0-9;]*m//g' > results/measure-summary.txt
wc -l results/measure-summary.txt
