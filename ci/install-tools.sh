#!/usr/bin/env bash
# Installs the pinned gate tools from ci/tools.lock into $AEGIS_TOOLS (default ~/.cache/aegis-tools), verifying sha256.
# Prebuilt release binaries only (no `cargo install`: avoids compiling on the laptop, §0e). Idempotent.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="${AEGIS_TOOLS:-$HOME/.cache/aegis-tools}"; mkdir -p "$T/bin" "$T/dl"
grep -v '^#' "$ROOT/ci/tools.lock" | while IFS=$'\t' read -r name tag _pub sha url; do
  [ -n "$name" ] || continue
  stamp="$T/bin/.$name.$sha"
  [ -f "$stamp" ] && [ -x "$T/bin/$name" ] && continue
  f="$T/dl/$(basename "$url")"
  curl -sfL --retry 3 -o "$f" "$url"
  echo "$sha  $f" | sha256sum -c --quiet || { echo "install-tools: sha256 mismatch for $name"; rm -f "$f"; exit 1; }
  d=$(mktemp -d "$T/dl/x.XXXX"); tar -xf "$f" -C "$d"
  bin=$(find "$d" -type f -name "$name" -perm -u+x | head -1); [ -n "$bin" ] || { echo "no $name binary in $url"; exit 1; }
  install -m 0755 "$bin" "$T/bin/$name"; rm -rf "$d" "$T/bin/.$name."*; touch "$stamp"
  echo "installed $name $tag"
done
echo "tools in $T/bin"
