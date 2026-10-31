#!/usr/bin/env bash
# Build the reference worker (release). Must be called under ci/heavy.sh. Usage: build.sh <target-dir>
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
T=${1:?target dir}
cd "$HERE"  # rust-toolchain.toml (1.98.0) is resolved from the cwd
cargo build --release --locked --quiet --manifest-path "$HERE/Cargo.toml" --target-dir "$T" -p hostref
