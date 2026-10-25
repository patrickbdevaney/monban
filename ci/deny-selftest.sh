#!/usr/bin/env bash
# Negative control for the deny gate: a scratch workspace depending on a banned crate (bincode) must be rejected.
set -euo pipefail
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
mkdir -p "$d/src"; echo 'fn main() {}' > "$d/src/main.rs"
cat > "$d/Cargo.toml" <<'T'
[package]
name = "deny-selftest"
version = "0.0.0"
edition = "2024"
publish = false
[dependencies]
bincode = "=1.3.3"
T
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cp "$ROOT/deny.toml" "$d/deny.toml"
(cd "$d" && cargo generate-lockfile -q)
out=$(cd "$d" && cargo deny check bans 2>&1) && { echo "DENY SELF-TEST: FAIL (banned crate accepted)"; exit 1; }
grep -q "banned" <<<"$out" && grep -q "bincode" <<<"$out" || { echo "DENY SELF-TEST: FAIL (rejected, but not for the ban)"; echo "$out" | tail -5; exit 1; }
echo "DENY SELF-TEST: PASS (banned crate bincode rejected)"
