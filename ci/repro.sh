#!/usr/bin/env bash
# G3 double build (SUPPLY_CHAIN §B). Builds monban-bin --release twice from two copies of the tree at different paths,
# with different CARGO_HOME, CARGO_TARGET_DIR and SOURCE_DATE_EPOCH, and requires byte-identical binaries.
#   ci/repro.sh               -> REPRO: PASS iff sha256 equal
#   ci/repro.sh --self-test   -> builds without the path remaps; PASS iff the binaries DIFFER (control is live)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
W="${AEGIS_REPRO_DIR:-${TMPDIR:-/tmp}/monban-repro}"; rm -rf "$W"; mkdir -p "$W"
trap 'rm -rf "$W"' EXIT
selftest=0; [ "${1:-}" = --self-test ] && selftest=1
build() {  # $1 = slot name, $2 = epoch
  local src="$W/$1/src-$1-tree" home="$W/$1/cargo-home" tgt="$W/$1/target"
  mkdir -p "$src" "$home"
  git -C "$ROOT" archive --format=tar HEAD | tar -x -C "$src"
  REG="${CARGO_HOME:-$HOME/.cargo}/registry"
  [ -d "$REG" ] && ln -s "$REG" "$home/registry"
  local flags=""
  if [ $selftest = 0 ]; then
    flags="--remap-path-prefix=$src=/src --remap-path-prefix=$home/registry/src=/cargo/registry --remap-path-prefix=$REG/src=/cargo/registry --remap-path-prefix=${RUSTUP_HOME:-$HOME/.rustup}=/rustup"
  fi
  # The workspace .cargo/config.toml remaps /home; override it so only these flags apply.
  (cd "$src" && CARGO_PROFILE_RELEASE_DEBUG="${DEBUG_LEVEL:-0}" CARGO_PROFILE_RELEASE_STRIP="${STRIP:-symbols}" SOURCE_DATE_EPOCH="$2" CARGO_HOME="$home" CARGO_TARGET_DIR="$tgt" RUSTFLAGS="$flags -Cforce-frame-pointers=yes ${AEGIS_REPRO_EXTRA:-}" \
     "$ROOT/ci/heavy.sh" cargo build --release --locked --offline -q -p monban-bin)
  sha256sum "$tgt/release/monban" | cut -d' ' -f1
}
# Debug info embeds absolute source/registry paths (DW_AT_comp_dir etc.), so building with debuginfo=2 and no strip
# is what makes the remap observable. PASS needs equality at both debug=0 (shipping) and debug=2; the self-test
# drops the remaps at debug=2 and needs a difference.
if [ $selftest = 0 ]; then
  a=$(build a 1700000000); b=$(build b 1800000000)
  [ "$a" = "$b" ] || { echo "a=$a b=$b"; echo "REPRO: FAIL (debug=0 binaries differ)"; exit 1; }
  echo "debug=0: $a"
fi
export DEBUG_LEVEL=2 STRIP=none
a=$(build a2 1700000000); b=$(build b2 1800000000)
echo "debug=2: a=$a"; echo "debug=2: b=$b"
if [ $selftest = 0 ]; then
  [ "$a" = "$b" ] && echo "REPRO: PASS" || { echo "REPRO: FAIL (binaries differ)"; exit 1; }
else
  [ "$a" != "$b" ] && echo "REPRO SELF-TEST: PASS (unremapped builds differ, so the remap is load-bearing)" \
    || { echo "REPRO SELF-TEST: FAIL (builds equal even without remaps; the control proves nothing)"; exit 1; }
fi
