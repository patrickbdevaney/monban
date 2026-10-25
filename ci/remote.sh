#!/usr/bin/env bash
# Run a heavy command on a LAN build box instead of this laptop.
#   ci/remote.sh [--host H] <command...>     default host: desktop (Ryzen 9 5900X, shared with other builds)
# Syncs the working tree (including uncommitted changes, excluding build output) to H:~/aegis-ci/repo, then runs the
# command there with an isolated toolchain (~/aegis-ci/{rustup,cargo}, Rust from rust-toolchain.toml), its own
# target dir, and polite limits: one aegis job at a time on that host (flock), MemoryMax 12G, nice 15, 8 build jobs.
# Nested ci/heavy.sh calls run directly (AEGIS_HEAVY_HELD=1): the remote lock already serializes.
# Exit status is the remote command's. Nothing outside ~/aegis-ci is touched on the remote host.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST=desktop
if [ "${1:-}" = --host ]; then HOST="$2"; shift 2; fi
[ $# -gt 0 ] || { echo "usage: ci/remote.sh [--host H] <command...>"; exit 2; }
R='~/aegis-ci'
rsync -az --delete \
  --exclude /target/ --exclude '**/target/' --exclude '**/.lake/' --exclude '/research/state/raw/' \
  --exclude '**/__pycache__/' --exclude '/gates/out/' \
  -e "ssh -o BatchMode=yes" "$ROOT/" "$HOST:aegis-ci/repo/"
cmd=$(printf '%q ' "$@")
ssh -o BatchMode=yes "$HOST" "bash -lc '
  set -euo pipefail
  export RUSTUP_HOME=$R/rustup CARGO_HOME=$R/cargo CARGO_TARGET_DIR=$R/target AEGIS_TOOLS=$R/tools
  export PATH=$R/cargo/bin:$R/tools/bin:\$PATH CARGO_BUILD_JOBS=8 CARGO_INCREMENTAL=0 AEGIS_HEAVY_HELD=1
  cd $R/repo
  ln -sfn $R/target target
  exec flock $R/heavy.lock systemd-run --user --scope -q -p MemoryMax=12G -p MemorySwapMax=1G nice -n 15 $cmd
'"
