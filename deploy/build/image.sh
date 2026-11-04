#!/usr/bin/env bash
# Build (or reuse) the pinned AL2023 build image from deploy/build/al2023.Containerfile and assert its size
# (PLAN-6 D6/D7, PREFLIGHT P2/D-P3: no Docker image >= 500 MB).
#   deploy/build/image.sh            -> prints `IMAGE <name:tag> <image id>` on its last line
# The image name is the one profiles/cmvp/build.sh uses, aegis-al2023-build:<first 12 hex of sha256(Containerfile)>,
# so a changed recipe is a new tag and both scripts share one image. The 500 MB rule is about the unpacked root
# filesystem, measured as build.sh does (`du -sxk /` inside the image, x 1024); docker's own image size (the
# compressed content size under the containerd store) is asserted too. Both must be < 500,000,000 B. An existing image
# with the tag is reused. Needs network (dnf) only when the image is not present.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CF="$HERE/al2023.Containerfile"
LIMIT=500000000
command -v docker > /dev/null || { echo "image: docker not found" >&2; exit 1; }
IMG="aegis-al2023-build:$(sha256sum "$CF" | cut -c1-12)"
if ! docker image inspect "$IMG" > /dev/null 2>&1; then
  echo "image: building $IMG from deploy/build/al2023.Containerfile" >&2
  docker build -q -t "$IMG" -f "$CF" "$HERE" > /dev/null
fi
id=$(docker image inspect -f '{{.Id}}' "$IMG")
size=$(docker image inspect -f '{{.Size}}' "$IMG")
rootfs=$(docker run --rm --network none --entrypoint sh "$IMG" -c 'du -sxk / 2>/dev/null | tail -1' | awk '{print $1 * 1024}')
[[ "$size" =~ ^[0-9]+$ && "$rootfs" =~ ^[0-9]+$ ]] || { echo "image: could not measure $IMG" >&2; exit 1; }
if [ "$size" -ge $LIMIT ] || [ "$rootfs" -ge $LIMIT ]; then
  echo "image: $IMG is too large (unpacked $rootfs B, content $size B; limit $LIMIT B)" >&2
  exit 1
fi
echo "image: $IMG unpacked $rootfs B, content $size B (< $LIMIT B)" >&2
echo "IMAGE $IMG $id"
