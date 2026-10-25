#!/usr/bin/env bash
# G3 double build (SUPPLY_CHAIN §B). Builds aegis-bin --release twice from two copies of the tree at different paths,
# with different CARGO_HOME, CARGO_TARGET_DIR and SOURCE_DATE_EPOCH, and requires byte-identical binaries.
#   ci/repro.sh               -> REPRO: PASS iff sha256 equal
#   ci/repro.sh --self-test   -> builds without the path remaps; PASS iff the binaries DIFFER (control is live)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
W="${AEGIS_REPRO_DIR:-${TMPDIR:-/tmp}/aegis-repro}"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT
selftest=0; [ "${1:-}" = --self-test ] && selftest=1
build() {  # $1 = slot name, $2 = epoch
  local src="$W/$1/src-$1-tree" home="$W/$1/cargo-home" tgt="$W/$1/target"
  mkdir -p "$src" "$home"
  git -C "$ROOT" archive --format=tar HEAD | tar -x -C "$src"
  [ -d "$HOME/.cargo/registry" ] && ln -s "$HOME/.cargo/registry" "$home/registry"
  local flags=""
  if [ $selftest = 0 ]; then
    flags="--remap-path-prefix=$src=/src --remap-path-prefix=$home/registry/src=/cargo/registry --remap-path-prefix=$HOME/.cargo/registry/src=/cargo/registry --remap-path-prefix=${RUSTUP_HOME:-$HOME/.rustup}=/rustup"
  fi
  # The workspace .cargo/config.toml remaps /home; override it so only these flags apply.
  (cd "$src" && SOURCE_DATE_EPOCH="$2" CARGO_HOME="$home" CARGO_TARGET_DIR="$tgt" RUSTFLAGS="$flags -Cforce-frame-pointers=yes ${AEGIS_REPRO_EXTRA:-}" \
     "$ROOT/ci/heavy.sh" cargo build --release --locked --offline -q -p aegis-bin)
  sha256sum "$tgt/release/aegis" | cut -d' ' -f1
}
a=$(build a 1700000000); b=$(build b 1800000000)
echo "a=$a"; echo "b=$b"
if [ $selftest = 0 ]; then
  [ "$a" = "$b" ] && echo "REPRO: PASS" || { echo "REPRO: FAIL (binaries differ)"; exit 1; }
else
  [ "$a" != "$b" ] && echo "REPRO SELF-TEST: PASS (unremapped builds differ, so the remap is load-bearing)" \
    || { echo "REPRO SELF-TEST: FAIL (builds equal even without remaps; the control proves nothing)"; exit 1; }
fi
