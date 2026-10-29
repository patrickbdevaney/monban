#!/usr/bin/env bash
# Run a heavy command on a LAN build box instead of this laptop.
#   ci/remote.sh [--host H] <command...>     default host: desktop (Ryzen 9 5900X, shared with other builds)
# Syncs the working tree (including uncommitted changes, excluding build output) to H:~/aegis-ci/repo (or repo-<hash>), then runs the
# command there with an isolated toolchain (~/aegis-ci/{rustup,cargo}, Rust from rust-toolchain.toml), its own
# target dir, and polite limits: one aegis job at a time on that host (flock), MemoryMax 12G and 8 build jobs (kamrui: 9G, 4), nice 15.
# Nested ci/heavy.sh calls run directly (AEGIS_HEAVY_HELD=1): the remote lock already serializes.
# The command travels base64-encoded, so quoting inside it cannot break the remote shell.
# Exit status is the remote command's. Nothing outside ~/aegis-ci is touched on the remote host.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST=desktop
if [ "${1:-}" = --host ]; then HOST="$2"; shift 2
# Default host unreachable (powered off): fall back to kamrui (4 cores, 14 GB; also the prover box).
elif ! ssh -o BatchMode=yes -o ConnectTimeout=5 desktop true 2>/dev/null; then
  echo "remote.sh: desktop unreachable, using kamrui" >&2; HOST=kamrui
fi
MEM=12G JOBS=8; [ "$HOST" = kamrui ] && { MEM=9G; JOBS=4; }
[ $# -gt 0 ] || { echo "usage: ci/remote.sh [--host H] <command...>"; exit 2; }
# One remote tree per local checkout, so parallel worktrees (agents) never rsync --delete over each other's source.
REPO=repo; [ "$(basename "$ROOT")" = aegis ] || REPO="repo-$(printf %s "$ROOT" | sha256sum | cut -c1-12)"
rsync -az --delete \
  --exclude /target/ --exclude /.claude/ --exclude '**/target/' --exclude '**/.lake/' --exclude '/research/state/raw/' \
  --exclude '**/__pycache__/' --exclude '/gates/out/' \
  -e "ssh -o BatchMode=yes" "$ROOT/" "$HOST:aegis-ci/$REPO/"
cmd_b64=$(printf '%q ' "$@" | base64 -w0)
remote_script='
set -euo pipefail
R=$HOME/aegis-ci
export RUSTUP_HOME=$R/rustup CARGO_HOME=$R/cargo CARGO_TARGET_DIR=$R/target AEGIS_TOOLS=$R/tools
export PATH=$R/cargo/bin:$R/tools/bin:$PATH CARGO_BUILD_JOBS=$4 CARGO_INCREMENTAL=0 AEGIS_HEAVY_HELD=1
cd $R/$2
ln -sfn $R/target target
CMD=$(printf "%s" "$1" | base64 -d)
exec flock $R/heavy.lock systemd-run --user --scope -q -p MemoryMax=$3 -p MemorySwapMax=1G nice -n 15 bash -c "$CMD"
'
ssh -o BatchMode=yes "$HOST" bash -c "$(printf '%q' "$remote_script")" _ "$cmd_b64" "$REPO" "$MEM" "$JOBS"
