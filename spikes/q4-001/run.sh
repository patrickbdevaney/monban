#!/usr/bin/env bash
# Reproduce: every cargo call goes through ci/heavy.sh with the target dir inside this spike.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
export CARGO_TARGET_DIR="$HERE/target"
cd "$HERE"
exec /home/patrickd/aegis/ci/heavy.sh cargo "$@"
