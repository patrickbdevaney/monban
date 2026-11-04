#!/usr/bin/env bash
# cmvp overlay build (PLAN-6 D1). A crate can belong to one cargo workspace only, so the cmvp configuration is the
# root tree copied to target/cmvp-src with profiles/cmvp/overlay.toml applied to [workspace.dependencies] and
# profiles/cmvp/Cargo.lock as its lock. Nothing outside target/ is written (except --lock, which rewrites
# profiles/cmvp/Cargo.lock).
#
#   profiles/cmvp/build.sh [--check]   build aegis-bin (feature cmvp) and tls-subject (feature cmvp) with --locked
#                                      --release inside the AL2023 image (deploy/build/al2023.Containerfile, < 500 MB
#                                      asserted); output in target/cmvp/release/. Needs docker, Go 1.27.3
#                                      ($AEGIS_GO, default ~/aegis-ci/go1.27.3) and the pinned rustup toolchain, all
#                                      mounted read-only. Heavy: run through ci/remote.sh --host kamrui.
#   profiles/cmvp/build.sh --lock      regenerate profiles/cmvp/Cargo.lock from the root lock with the minimal change
#                                      the overlay forces, then aws-lc-fips-sys --precise <pins.toml> (light: resolve
#                                      only, no compile)
#   profiles/cmvp/build.sh --metadata  print `cargo metadata --locked --format-version 1` of the overlay tree (light;
#                                      used by `cargo xtask fips-lock --profile cmvp`)
#   profiles/cmvp/build.sh --vet       `cargo vet --locked` over the overlay tree and the cmvp lock (light)
# Env: CMVP_CARGO_PROFILE=release|dev (default release), CMVP_PACKAGES (default "aegis-bin tls-subject").
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
P="$ROOT/profiles/cmvp"
SRC="$ROOT/target/cmvp-src"
MODE="${1:---check}"

prepare() {
  mkdir -p "$SRC"
  rsync -a --delete \
    --exclude /target/ --exclude /.git --exclude /.claude/ --exclude '**/target/' --exclude '**/.lake/' \
    --exclude /research/ --exclude /spikes/ --exclude /fuzz/ --exclude /oracles/ --exclude /gates/out/ \
    --exclude '**/__pycache__/' "$ROOT/" "$SRC/"
  python3 -I "$P/overlay.py" "$P/overlay.toml" "$ROOT/Cargo.toml" "$SRC/Cargo.toml"
}

case "$MODE" in
  --metadata)
    [ -f "$P/Cargo.lock" ] || { echo "cmvp: profiles/cmvp/Cargo.lock missing (run build.sh --lock)" >&2; exit 1; }
    prepare 2>/dev/null
    cp "$P/Cargo.lock" "$SRC/Cargo.lock"
    exec cargo metadata --locked --format-version 1 --manifest-path "$SRC/Cargo.toml"
    ;;
  --vet)
    # cargo vet over the cmvp lock (D1: vet applies to it as to the root lock), with the repo's supply-chain/.
    [ -f "$P/Cargo.lock" ] || { echo "cmvp: profiles/cmvp/Cargo.lock missing (run build.sh --lock)" >&2; exit 1; }
    prepare 2>/dev/null
    cp "$P/Cargo.lock" "$SRC/Cargo.lock"
    exec cargo vet --locked --manifest-path "$SRC/Cargo.toml"
    ;;
  --lock)
    prepare
    cp "$ROOT/Cargo.lock" "$SRC/Cargo.lock"
    fips_sys=$(sed -n 's/^aws-lc-fips-sys = "\(.*\)"$/\1/p' "$P/pins.toml")
    [ -n "$fips_sys" ] || { echo "cmvp: no aws-lc-fips-sys pin in pins.toml" >&2; exit 1; }
    # Non-locked metadata re-resolves only what the overlay forces (cargo keeps every other locked version).
    cargo metadata --format-version 1 --manifest-path "$SRC/Cargo.toml" > /dev/null
    cargo update --manifest-path "$SRC/Cargo.toml" -p aws-lc-fips-sys --precise "$fips_sys"
    cargo metadata --locked --format-version 1 --manifest-path "$SRC/Cargo.toml" > /dev/null
    cp "$SRC/Cargo.lock" "$P/Cargo.lock"
    echo "cmvp: wrote profiles/cmvp/Cargo.lock"
    ;;
  --check)
    [ -f "$P/Cargo.lock" ] || { echo "cmvp: profiles/cmvp/Cargo.lock missing (run build.sh --lock)" >&2; exit 1; }
    command -v docker > /dev/null || { echo "cmvp: docker not found (run via ci/remote.sh --host kamrui)" >&2; exit 1; }
    prepare
    cp "$P/Cargo.lock" "$SRC/Cargo.lock"
    CF="$ROOT/deploy/build/al2023.Containerfile"
    IMG="aegis-al2023-build:$(sha256sum "$CF" | cut -c1-12)"
    if ! docker image inspect "$IMG" > /dev/null 2>&1; then
      docker build -q -t "$IMG" -f "$CF" "$ROOT/deploy/build" > /dev/null
    fi
    # The 500 MB rule is about the unpacked image (its root filesystem), not the compressed content size that
    # `docker image inspect .Size` reports under the containerd store (~168 MB for ~460 MB unpacked).
    size=$(docker run --rm --network none --entrypoint sh "$IMG" -c 'du -sxk / 2>/dev/null | tail -1' | awk '{print $1 * 1024}')
    [ -n "$size" ] && [ "$size" -lt 500000000 ] || { echo "cmvp: image $IMG unpacked ${size:-?} B (>= 500 MB limit)" >&2; exit 1; }
    echo "cmvp: image $IMG unpacked $size B (< 500 MB)"
    RUSTUP="$(realpath "${RUSTUP_HOME:-$HOME/.rustup}")"
    GO="$(realpath "${AEGIS_GO:-$HOME/aegis-ci/go1.27.3}")"
    [ -x "$GO/bin/go" ] || { echo "cmvp: Go not found at $GO" >&2; exit 1; }
    chan=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml")
    TC="$RUSTUP/toolchains/$chan-x86_64-unknown-linux-gnu"
    [ -x "$TC/bin/cargo" ] || { echo "cmvp: toolchain $chan not installed under $RUSTUP" >&2; exit 1; }
    OUT="$(realpath "$ROOT/target")/cmvp"
    mkdir -p "$OUT/home"
    prof="${CMVP_CARGO_PROFILE:-release}"
    pkgs=(); feats=()
    for p in ${CMVP_PACKAGES:-aegis-bin tls-subject}; do pkgs+=(-p "$p"); feats+=("$p/cmvp"); done
    flags=(--locked --keep-going --no-default-features "${pkgs[@]}" --features "$(IFS=,; echo "${feats[*]}")")
    [ "$prof" = release ] && flags+=(--release)
    echo "cmvp: cargo build ${flags[*]} (AL2023, Go $("$GO/bin/go" version | cut -d' ' -f3))"
    docker run --rm --user "$(id -u):$(id -g)" \
      -v "$(realpath "$SRC"):/src:ro" -v "$OUT:/out" -v "$TC:/opt/rust:ro" -v "$GO:/opt/go:ro" \
      -e HOME=/out/home -e CARGO_HOME=/out/cargo-home -e CARGO_TARGET_DIR=/out -e GOCACHE=/out/gocache \
      -e GOPATH=/out/gopath -e GOTOOLCHAIN=local -e GOFLAGS=-mod=mod -e CARGO_INCREMENTAL=0 \
      -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" -e PATH=/opt/rust/bin:/opt/go/bin:/usr/bin:/bin \
      -w /src "$IMG" cargo build "${flags[@]}"
    echo "cmvp: BUILD PASS ($prof; outputs in target/cmvp/$prof/)"
    ;;
  *) echo "usage: profiles/cmvp/build.sh [--check|--lock|--metadata|--vet]" >&2; exit 2 ;;
esac
