#!/usr/bin/env bash
# Run under ci/heavy.sh. Cold build + runtime oracle + trybuild corpus in lock mode (expected.txt).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$HERE"
export CARGO_TARGET_DIR="$HERE/target"
rustc --version
cargo test -p corpus --test runtime --test mutants 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E "^test |test result|panicked|^error" 
