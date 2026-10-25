#!/usr/bin/env bash
# Build every variant (one heavy job). Usage: HEAVY_TIMEOUT=3600 ../../ci/heavy.sh ./build.sh   (from this dir)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export CARGO_TARGET_DIR="$here/target"
mkdir -p "$here/bins"
for f in "" metrics "metrics,logs" "metrics,logs,otlp" "metrics,logs,otlp-grpc"; do
  n=${f:-base}; n=${n//,/+}
  echo "== build $n"
  ( cd "$here/hello" && cargo build --release --locked -q --features "$f" )
  cp "$CARGO_TARGET_DIR/release/hello" "$here/bins/hello-$n"
done
ls -l "$here/bins"
