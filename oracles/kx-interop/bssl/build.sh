#!/usr/bin/env bash
# Build (once) the image monban-bssl:<commit12> holding BoringSSL's `bssl` tool at the commit pinned in bssl/LOCK.
#   bssl/build.sh <workdir>     prints the image tag on the last line; exit 0 on success
# Steps: verify the commit is >= 7 days old; download the source tarball (User-Agent aegis-ci) and check its sha256;
# build `bssl` in a throwaway AL2023 container (dnf cmake + gcc-c++; no Go, no perl: BoringSSL ships gen/); build the
# runtime image from bssl/Containerfile; delete the source and build tree. Reuses the image if the tag exists.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
work="${1:?usage: build.sh <workdir>}"
get() { sed -n "s/^$1=//p" "$here/LOCK"; }
commit=$(get commit); date=$(get commit_date); url=$(get url); sum=$(get sha256); base=$(get base)
tag="monban-bssl:${commit:0:12}"
age=$(( ( $(date +%s) - $(date -d "$date" +%s) ) / 86400 ))
[ "$age" -ge 7 ] || { echo "bssl: pinned commit $commit is $age days old (< 7)" >&2; exit 1; }
if docker image inspect "$tag" >/dev/null 2>&1; then echo "$tag"; exit 0; fi
mkdir -p "$work"; src="$work/bssl-src"; out="$work/bssl-out"
rm -rf "$src" "$out"; mkdir -p "$src" "$out"
curl -fsSL -A aegis-ci -o "$work/bssl.tar.gz" "$url"
echo "$sum  $work/bssl.tar.gz" | sha256sum -c --quiet - || { echo "bssl: tarball sha256 mismatch" >&2; exit 1; }
tar xzf "$work/bssl.tar.gz" -C "$src" --strip-components=1
rm -f "$work/bssl.tar.gz"
uid="$(id -u):$(id -g)"
# The build container is --rm; its source mount is read-only; only /out (the built binary) is written back.
docker run --rm --network host -v "$src:/src:ro" -v "$out:/out" "$base" bash -ec "
  dnf install -y -q cmake gcc-c++ libstdc++-static make >/dev/null
  cmake -S /src -B /tmp/b -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF \
    -DCMAKE_EXE_LINKER_FLAGS='-static-libstdc++ -static-libgcc' >/dev/null
  cmake --build /tmp/b --target bssl -j4 >/dev/null
  cp /tmp/b/bssl /out/bssl; chown $uid /out/bssl"
docker build -q --build-arg BASE="$base" -t "$tag" -f "$here/Containerfile" "$out" >/dev/null
rm -rf "$src" "$out"
size=$(docker image inspect "$tag" --format '{{.Size}}')
[ "$size" -le 500000000 ] || { docker rmi "$tag" >/dev/null; echo "bssl: image $size bytes > 500 MB, removed" >&2; exit 1; }
echo "$tag"
