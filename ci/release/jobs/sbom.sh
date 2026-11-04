#!/usr/bin/env bash
# Release job 2: SBOM (PLAN-6 D6). CycloneDX JSON for aegis-bin (the release package, with the profile's features) via
# the pinned cargo-cyclonedx (ci/tools.lock), run inside the same AL2023 image with no network and the registry and
# toolchain mounted read-only. cargo-cyclonedx writes its BOM next to the package manifest, so this job works on its
# own copy of the source in its scratch dir and checks afterwards that Cargo.lock was not changed.
#
#   sbom.sh --profile floor|cmvp --src DIR --registry DIR --toolchain DIR --cyclonedx FILE --image NAME:TAG
#           --epoch N --scratch DIR --out DIR
#
# Writes OUT/sbom.cdx.json. SOURCE_DATE_EPOCH (honoured by cargo-cyclonedx) is the commit time. Holds no keys.
set -euo pipefail
die() { echo "sbom: $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --profile) PROFILE="$2" ;; --src) SRC="$2" ;; --registry) REG="$2" ;; --toolchain) TC="$2" ;;
    --cyclonedx) CDX="$2" ;; --image) IMG="$2" ;; --epoch) EPOCH="$2" ;; --scratch) S="$2" ;; --out) OUT="$2" ;;
    *) die "unknown argument $1" ;;
  esac
  shift 2
done
for v in PROFILE SRC REG TC CDX IMG EPOCH S OUT; do [ -n "${!v:-}" ] || die "missing --${v,,}"; done
case "$PROFILE" in floor) FEAT=() ;; cmvp) FEAT=(--features cmvp) ;; *) die "profile must be floor or cmvp" ;; esac
mkdir -p "$S/home" "$S/cargo-home/registry" "$OUT"
cp -a "$SRC" "$S/src"
chmod -R u+w "$S/src"
trap 'docker ps -aq --filter "label=aegis-release-job=$$" | xargs -r docker rm -f > /dev/null 2>&1 || true' EXIT
docker run --rm --network none --label "aegis-release-job=$$" --memory 8g --memory-swap 9g --cpu-shares 256 \
  --user "$(id -u):$(id -g)" \
  -v "$S/src:/job/src" -v "$S/home:/job/home" -v "$S/cargo-home:/job/cargo-home" \
  -v "$REG:/job/cargo-home/registry:ro" -v "$TC:/opt/rust:ro" -v "$CDX:/opt/tools/cargo-cyclonedx:ro" \
  -e HOME=/job/home -e CARGO_HOME=/job/cargo-home -e CARGO_NET_OFFLINE=true -e SOURCE_DATE_EPOCH="$EPOCH" \
  -e TZ=UTC -e LC_ALL=C -e PATH=/opt/rust/bin:/opt/tools:/usr/bin:/bin -w /job/src "$IMG" \
  cargo cyclonedx --manifest-path /job/src/crates/aegis-bin/Cargo.toml --format json --spec-version 1.5 \
  --target x86_64-unknown-linux-gnu --override-filename aegis-sbom "${FEAT[@]}" -q
cmp -s "$SRC/Cargo.lock" "$S/src/Cargo.lock" || die "cargo-cyclonedx changed Cargo.lock"
BOM="$S/src/crates/aegis-bin/aegis-sbom.json"
[ -f "$BOM" ] || die "no BOM at crates/aegis-bin/aegis-sbom.json"
python3 -I -c '
import json, sys
d = json.load(open(sys.argv[1]))
assert d.get("bomFormat") == "CycloneDX" and isinstance(d.get("specVersion"), str), "not CycloneDX"
names = {c.get("name") for c in d.get("components", [])}
assert d["metadata"]["component"]["name"] == "aegis-bin", "BOM does not describe aegis-bin"
assert len(names) > 10, "suspiciously few components"
sv = d["specVersion"]
print(f"sbom: CycloneDX {sv}, {len(names)} components")
' "$BOM" || die "BOM check failed"
cp "$BOM" "$OUT/sbom.cdx.json"
echo "sbom: sha256 $(sha256sum "$OUT/sbom.cdx.json" | cut -d' ' -f1)"
