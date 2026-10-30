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
# Each remote tree gets its own target dir: a shared one let a worktree run a binary another worktree had built
# (uplifted target/release/<bin> is overwritten by whoever built last). The main checkout keeps $R/target (fuzz paths).
T=$R/target; [ "$2" = repo ] || T=$R/target-$2
export RUSTUP_HOME=$R/rustup CARGO_HOME=$R/cargo CARGO_TARGET_DIR=$T AEGIS_TOOLS=$R/tools
export PATH=$R/cargo/bin:$R/tools/bin:$PATH CARGO_BUILD_JOBS=$4 CARGO_INCREMENTAL=0 AEGIS_HEAVY_HELD=1
cd $R/$2
mkdir -p "$T"; ln -sfn "$T" target
touch "$T" "$R/$2"   # mark this tree and target in use before waiting on the lock, so pruning never takes them
CMD=$(printf "%s" "$1" | base64 -d)
# Under the lock: drop worktree targets/trees idle > 2 days, and keep at most 4 worktree targets (disk is shared).
exec flock $R/heavy.lock bash -c '\''
  find "$1" -maxdepth 1 -name "target-repo-*" -mtime +2 -exec rm -rf {} + 2>/dev/null || true
  find "$1" -maxdepth 1 -name "repo-*" -mtime +2 -exec rm -rf {} + 2>/dev/null || true
  ls -dt "$1"/target-repo-* 2>/dev/null | tail -n +5 | grep -v -x "$2" | xargs -r rm -rf
  exec systemd-run --user --scope -q -p MemoryMax=$3 -p MemorySwapMax=1G nice -n 15 bash -c "$4"
'\'' _ "$R" "$T" "$3" "$CMD"
'
ssh -o BatchMode=yes "$HOST" bash -c "$(printf '%q' "$remote_script")" _ "$cmd_b64" "$REPO" "$MEM" "$JOBS"
