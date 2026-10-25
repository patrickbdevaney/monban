#!/usr/bin/env bash
# Build host (release) + guest (wasm32). Must be called under ci/heavy.sh. Usage: build.sh <target-dir>
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
T=${1:?target dir}
cargo build --release --locked --quiet --manifest-path "$HERE/Cargo.toml" --target-dir "$T" -p isofi
cargo build --release --locked --quiet --manifest-path "$HERE/Cargo.toml" --target-dir "$T" -p guest --target wasm32-unknown-unknown
