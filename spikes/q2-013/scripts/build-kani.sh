#!/usr/bin/env bash
# Build Kani (release profile) from the pinned main commit. Run on kamrui after setup-toolchains.sh.
set -euxo pipefail
CI=$HOME/aegis-ci
export RUSTUP_HOME=$CI/rustup CARGO_HOME=$CI/cargo PATH=$CI/cargo/bin:$CI/cbmc/usr/bin:$PATH
cd $CI/src/kani
rustup show active-toolchain || rustup toolchain install   # installs nightly-2026-10-12 + components per rust-toolchain.toml
MEM=8G TMO=7200 CARGO_BUILD_JOBS=4 $CI/bin/heavy cargo build-dev -- --release
ls target/kani/bin
