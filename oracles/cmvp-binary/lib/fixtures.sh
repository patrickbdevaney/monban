#!/usr/bin/env bash
# Build the self-test fixtures (heavy: through ci/heavy.sh; under ci/remote.sh it runs directly). Outputs:
#   target/cmvp-binary-fixtures/plain/release/{srv_only,srv_mtls,fips_*}         default features (shipped form,
#                                                                                strip = "symbols")
#   target/cmvp-binary-fixtures/client/release/{srv_only,dead_client,pq_client,bad_client,bad_resume}
#                                                                                feature tls-client on
#   target/cmvp-binary-fixtures/clippy-<bin>.log                                 clippy with fixtures/clippy.toml
# Linker maps and unstripped twins are NOT built here: the client-policy oracle relinks them itself (cargo rustc on
# the final crate only), the same way it does on the cmvp tree.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
M="$HERE/fixtures/Cargo.toml"
T="$(realpath -m "$ROOT/target")/cmvp-binary-fixtures"
mkdir -p "$T"
H="$ROOT/ci/heavy.sh"
CARGO_TARGET_DIR="$T/plain" "$H" cargo build --release --locked -q --manifest-path "$M" --workspace --bins
CARGO_TARGET_DIR="$T/client" "$H" cargo build --release --locked -q --manifest-path "$M" --features tls-client \
  --bin srv_only --bin dead_client --bin pq_client --bin bad_client --bin bad_resume
cd "$HERE/fixtures"   # clippy.toml is read from the manifest dir
for x in pq_client bad_client bad_resume dead_client; do
  CARGO_TARGET_DIR="$T/client" "$H" cargo clippy --locked -q --manifest-path "$M" --features tls-client --lib \
    --bin "$x" > "$T/clippy-$x.log" 2>&1 || true
done
CARGO_TARGET_DIR="$T/plain" "$H" cargo clippy --locked -q --manifest-path "$M" --lib --bin srv_only \
  > "$T/clippy-srv_only.log" 2>&1 || true
echo "fixtures: built under $T"
