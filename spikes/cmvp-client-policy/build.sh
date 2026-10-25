#!/usr/bin/env bash
# Heavy part (one job): build the five binaries unstripped with linker maps, two of them also stripped (shipped form),
# and run clippy per binary. Usage (from this dir): HEAVY_TIMEOUT=3600 ../../ci/heavy.sh ./build.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export CARGO_TARGET_DIR="$here/target"
cd "$here/tlsbins"
mkdir -p "$here/out"
b() { # name features strip suffix
  local f=(); [ -n "$2" ] && f=(--features "$2")
  CARGO_PROFILE_RELEASE_STRIP=$3 cargo rustc --release --locked -q --bin "$1" "${f[@]}" -- \
    -C link-arg=-Wl,-Map="$here/out/$1$4.map"
  cp "$CARGO_TARGET_DIR/release/$1" "$here/out/$1$4"
}
b srv_only "" none ""
for x in dead_client pq_client bad_client bad_resume; do b $x tls-client none ""; done
b srv_only "" symbols .stripped
b pq_client tls-client symbols .stripped
for x in pq_client bad_client bad_resume dead_client; do
  cargo clippy --locked -q --features tls-client --lib --bin $x > "$here/out/clippy-$x.log" 2>&1 || true
done
cargo clippy --locked -q --lib --bin srv_only > "$here/out/clippy-srv_only.log" 2>&1 || true
ls -l "$here/out"
