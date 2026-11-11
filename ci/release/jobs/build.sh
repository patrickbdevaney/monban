#!/usr/bin/env bash
# Release job 1: build A (PLAN-6 D6). Runs `cargo auditable build --release --locked --offline -p monban-bin` inside
# the pinned AL2023 image (deploy/build/al2023.Containerfile), with no network, the source, the cargo registry, the
# Rust toolchain, Go and cargo-auditable all mounted read-only, and fixed in-container paths so an independent
# rebuild (D7, P6-release-002) sees the same paths.
#
#   build.sh --profile floor|cmvp --src DIR --registry DIR --toolchain DIR --go DIR --auditable FILE
#            --image NAME:TAG --epoch N --scratch DIR --out DIR
#
# Writes OUT/monban-<profile> (the binary) and OUT/build-info.json (image id, rustc -vV, go version, cargo -V,
# cargo-auditable sha256, rustflags, epoch, command, sha256 of the binary and of Cargo.lock). Holds no keys.
# Reproducibility: SOURCE_DATE_EPOCH = the commit time (given by the pipeline), RUSTFLAGS remaps the registry and
# toolchain paths as ci/repro.sh does (RUSTFLAGS replaces .cargo/config.toml's build.rustflags), and the profile is the
# workspace release profile (codegen-units 1, fat LTO, strip symbols).
set -euo pipefail
die() { echo "build: $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --profile) PROFILE="$2" ;; --src) SRC="$2" ;; --registry) REG="$2" ;; --toolchain) TC="$2" ;; --go) GO="$2" ;;
    --auditable) AUD="$2" ;; --image) IMG="$2" ;; --epoch) EPOCH="$2" ;; --scratch) S="$2" ;; --out) OUT="$2" ;;
    *) die "unknown argument $1" ;;
  esac
  shift 2
done
for v in PROFILE SRC REG TC GO AUD IMG EPOCH S OUT; do [ -n "${!v:-}" ] || die "missing --${v,,}"; done
case "$PROFILE" in floor) FEAT=() ;; cmvp) FEAT=(--features monban-bin/cmvp) ;; *) die "profile must be floor or cmvp" ;; esac
[[ "$EPOCH" =~ ^[0-9]+$ ]] || die "bad epoch"
mkdir -p "$S/target" "$S/home" "$S/cargo-home/registry" "$OUT"
RUSTFLAGS="--remap-path-prefix=/src=/src --remap-path-prefix=/job/cargo-home/registry/src=/cargo/registry"
RUSTFLAGS+=" --remap-path-prefix=/opt/rust=/rustup --remap-path-prefix=/job/target=/target -Cforce-frame-pointers=yes"
CMD=(cargo auditable build --release --locked --offline -p monban-bin "${FEAT[@]}")
LIMITS=(--label "monban-release-job=$$" --memory 8g --memory-swap 9g --cpu-shares 256)
trap 'docker ps -aq --filter "label=monban-release-job=$$" | xargs -r docker rm -f > /dev/null 2>&1 || true' EXIT
RUN=(docker run --rm --network none "${LIMITS[@]}" --user "$(id -u):$(id -g)"
  -v "$SRC:/src:ro" -v "$S/target:/job/target" -v "$S/home:/job/home" -v "$S/cargo-home:/job/cargo-home"
  -v "$REG:/job/cargo-home/registry:ro" -v "$TC:/opt/rust:ro" -v "$GO:/opt/go:ro"
  -v "$AUD:/opt/tools/cargo-auditable:ro"
  -e HOME=/job/home -e CARGO_HOME=/job/cargo-home -e CARGO_TARGET_DIR=/job/target -e CARGO_INCREMENTAL=0
  -e CARGO_NET_OFFLINE=true -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" -e SOURCE_DATE_EPOCH="$EPOCH"
  -e RUSTFLAGS="$RUSTFLAGS" -e TZ=UTC -e LC_ALL=C -e GOCACHE=/job/home/gocache -e GOPATH=/job/home/gopath
  -e GOTOOLCHAIN=local -e GOFLAGS=-mod=mod -e GOTELEMETRY=off
  -e PATH=/opt/rust/bin:/opt/go/bin:/opt/tools:/usr/bin:/bin -w /src "$IMG")
rustc_vv=$("${RUN[@]}" rustc -vV)
go_v=$("${RUN[@]}" go version)
cargo_v=$("${RUN[@]}" cargo -V)
cc_v=$("${RUN[@]}" gcc --version | head -1)
echo "build: $PROFILE in $IMG ($(echo "$rustc_vv" | head -1); $go_v)"
echo "build: ${CMD[*]}"
if ! "${RUN[@]}" "${CMD[@]}"; then
  if [ "$PROFILE" = cmvp ]; then
    die "cmvp build FAILED. Known cause until P6-cmvp-001 lands (PLAN-6 D15): aws-lc-rs 1.15.3 compiles ML-DSA out \
under fips, so monban-audit/src/note.rs, monban-token/src/tier_x.rs (and tls-subject) do not compile on cmvp."
  fi
  die "$PROFILE build FAILED"
fi
BIN="$S/target/release/monban"
[ -f "$BIN" ] || die "no binary at target/release/monban"
cp "$BIN" "$OUT/monban-$PROFILE"
bin_sha=$(sha256sum "$OUT/monban-$PROFILE" | cut -d' ' -f1)
img_id=$(docker image inspect -f '{{.Id}}' "$IMG")
base=$(sed -n 's/^FROM \(.*\)$/\1/p' "$SRC/deploy/build/al2023.Containerfile")
BI_PROFILE="$PROFILE" BI_SHA="$bin_sha" BI_CMD="${CMD[*]}" BI_EPOCH="$EPOCH" BI_RUSTFLAGS="$RUSTFLAGS" BI_IMG="$IMG" \
BI_IMG_ID="$img_id" BI_BASE="$base" BI_CF_SHA="$(sha256sum "$SRC/deploy/build/al2023.Containerfile" | cut -d' ' -f1)" \
BI_RUSTC="$rustc_vv" BI_CARGO="$cargo_v" BI_GO="$go_v" BI_CC="$cc_v" BI_AUD_SHA="$(sha256sum "$AUD" | cut -d' ' -f1)" \
BI_LOCK_SHA="$(sha256sum "$SRC/Cargo.lock" | cut -d' ' -f1)" python3 -I -c '
import json, os, sys
e = os.environ
info = {
    "profile": e["BI_PROFILE"],
    "artifact": "artifacts/monban-" + e["BI_PROFILE"],
    "sha256": e["BI_SHA"],
    "command": e["BI_CMD"].split(),
    "source_date_epoch": int(e["BI_EPOCH"]),
    "rustflags": e["BI_RUSTFLAGS"],
    "image": {"name": e["BI_IMG"], "id": e["BI_IMG_ID"], "base": e["BI_BASE"],
              "containerfile_sha256": e["BI_CF_SHA"]},
    "rustc_vV": e["BI_RUSTC"],
    "cargo_V": e["BI_CARGO"],
    "go_version": e["BI_GO"],
    "cc_version": e["BI_CC"],
    "cargo_auditable_sha256": e["BI_AUD_SHA"],
    "cargo_lock_sha256": e["BI_LOCK_SHA"],
    "paths": {"src": "/src", "target": "/job/target", "cargo_home": "/job/cargo-home", "rust": "/opt/rust",
              "go": "/opt/go"},
}
with open(sys.argv[1], "w") as f:
    json.dump(info, f, indent=1, sort_keys=True)
    f.write("\n")
' "$OUT/build-info.json"
echo "build: $PROFILE monban-$PROFILE sha256 $bin_sha"
