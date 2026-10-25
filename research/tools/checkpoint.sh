#!/usr/bin/env bash
# Durable research checkpoint, safe to run while a workflow is mid-flight.
# Snapshots research/ (minus build junk) plus the live workflow journal(s) into refs/heads/checkpoints
# via a private index, so main's index/worktree are never touched, then pushes that branch to the forge.
# Restore one file:  git -C ~/aegis show checkpoints:research/state/graph.jsonl > /tmp/graph.jsonl
# Restore state dir: git -C ~/aegis restore --source=checkpoints -- research/state research/reports
# Cron: */10 * * * * /bin/bash /home/patrickd/aegis/research/tools/checkpoint.sh >/dev/null 2>&1
set -euo pipefail
REPO=/home/patrickd/aegis
MAX_KB=${CKPT_MAX_KB:-2048}                      # skip binaries/tool caches explorers leave behind
SESS=/home/patrickd/.claude/projects/-home-patrickd
exec 9>/tmp/aegis-checkpoint.lock; flock -n 9 || exit 0
cd "$REPO"

# 1. Mirror live workflow journals (agent return values = the resume cache) into the repo tree.
#    journal.jsonl lets a NEW session hand-author a continuation even though resumeFromRunId is same-session only.
J=research/state/raw/_journals
mkdir -p "$J"
find "$SESS" -path '*/subagents/workflows/wf_*/journal.jsonl' -mmin -2880 2>/dev/null | while read -r f; do
  run=$(basename "$(dirname "$f")")
  grep -q 'AEGIS' "$f" 2>/dev/null || continue     # only this track's runs
  cp -p "$f" "$J/$run.journal.jsonl.tmp" && mv "$J/$run.journal.jsonl.tmp" "$J/$run.journal.jsonl"
done

# 2. Build the snapshot tree in a private index.
export GIT_INDEX_FILE="$REPO/.git/checkpoint.index"
rm -f "$GIT_INDEX_FILE"
git read-tree HEAD
git ls-files -z --others --modified --exclude-standard -- research \
  | while IFS= read -r -d '' p; do
      case "$p" in */.git/*|*/cargohome/*|*/target/*|*-work/*|*/node_modules/*) continue;; esac
      if [ -f "$p" ]; then if [ "$(du -k "$p" | cut -f1)" -le "$MAX_KB" ]; then printf '%s\0' "$p"; fi
      else printf '%s\0' "$p"; fi                  # deleted tracked file: let add record removal
    done | xargs -0 -r git add -A --
# journals are gitignored as raw transcripts? force-add them explicitly
git add -f -- "$J" 2>/dev/null || true
tree=$(git write-tree)

parent=$(git rev-parse -q --verify refs/heads/checkpoints || true)
[ -n "$parent" ] && [ "$(git rev-parse "$parent^{tree}")" = "$tree" ] && exit 0   # nothing new
msg="checkpoint $(date -u +%FT%TZ) $(ls research/reports/round-*.md 2>/dev/null | tail -1 | xargs -r basename)"
commit=$(git commit-tree "$tree" -p "${parent:-HEAD}" -m "$msg")
git update-ref refs/heads/checkpoints "$commit"
rm -f "$GIT_INDEX_FILE"
timeout 120 git push -q -f origin checkpoints 2>/dev/null || echo "push failed (local checkpoint kept)" >&2
echo "$msg $commit"
