#!/usr/bin/env bash
# Build the p2-e2e guests (wasm32-unknown-unknown, no dependencies). Must be called under ci/heavy.sh.
# Usage: build.sh <target-dir>
#   <target-dir>/plain/wasm32-unknown-unknown/release/p2e2e_guest.wasm   F14 `monban` imports only
#   <target-dir>/fault/wasm32-unknown-unknown/release/p2e2e_guest.wasm   + env.host_fault (test-hooks workers only)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
T=${1:?target dir}
cd "$HERE"  # rust-toolchain.toml (1.98.0, has wasm32-unknown-unknown) is resolved from the cwd
cargo build --release --locked --quiet --manifest-path "$HERE/Cargo.toml" --target wasm32-unknown-unknown \
  --target-dir "$T/plain"
cargo build --release --locked --quiet --manifest-path "$HERE/Cargo.toml" --target wasm32-unknown-unknown \
  --target-dir "$T/fault" --features fault
