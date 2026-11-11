#!/usr/bin/env bash
# Kani proof gate (units P2-kani-tbi-001, P6-kani-001). It runs on the prover box (kamrui:~/aegis-ci) over ssh.
#
#   ci/kani.sh [--crate C] [--neg N]                    every harness in crates/C/src/kani_proofs.rs, plus N
#   ci/kani.sh [--crate C] [--neg N] --expect-neg-only  only the negative control N (it must FAIL on its own
#                                                       assertion); --self-test is the same mode
#
# Defaults: --crate monban-budget --neg negative_control_unclamped_refill, so the kani-tbi invocations
# (`ci/kani.sh`, `ci/kani.sh --self-test`) are unchanged. kani-kx is
# `ci/kani.sh --crate monban-tls --neg negative_control_indexing_split`.
# kani-wire (P7-spec-002) is `ci/kani.sh --serial --mem 6G -p monban-wire` / `ci/kani.sh --self-test -p monban-wire`:
# `-p C` is `--crate C`; `--mem M` sets the per-harness MemoryMax (as KANI_MEM); `--serial` is accepted for clarity
# (harnesses always run one at a time). Without --neg the negative control is the crate's own: monban-wire
# negative_control_planted_oob, every other crate negative_control_unclamped_refill (the monban-budget one, as before).
# kani-kx-client (P8-kani-001) is `ci/kani.sh --serial --mem 6G -p monban-tls --only client_` / `... --self-test
# -p monban-tls --only client_`: `--only P` selects the harnesses whose name starts with P. Without --neg, its negative
# control is the one selected harness whose name contains "negative_control" (exactly one, else FAIL). An --only run
# uses its own remote work dir (kani-<crate>-<P without trailing _>), so it never rsyncs over a concurrent
# full-crate run.
# Every selected harness whose name contains "negative_control" is a negative control, never a positive: --neg (or
# the default) names the required one, and any other selected negative control runs too and must also FAIL on its own
# "NEGATIVE CONTROL" assertion (so a full-crate run such as kani-kx also runs the client_ negative control red).
#
# The script syncs the crate (and any monban-* path deps it declares) to $KANI_HOST:~/aegis-ci/work/<dir> with a
# generated minimal workspace manifest (<dir> = p2-kani for monban-budget, kani-<crate> otherwise). Third-party
# `workspace = true` deps of the synced crates are copied verbatim from the root [workspace.dependencies], and
# then the root Cargo.lock is synced too, so they resolve to the locked versions. If the proofs file uses
# `kani::stub`, the harnesses run with `-Z stubbing`. It asserts the Kani checkout is a descendant of the PR #4910
# merge (16c774cf). Main still reports "0.68.0", so the version string proves nothing. Harnesses then run
# serially, each in its own `systemd-run --user --scope` with MemoryMax (default 6G), swap off, nice 15 and a
# timeout (default 1800 s). If systemd user scopes are unavailable it falls back to `ulimit -v`.
# A positive harness passes only on kani exit 0, "VERIFICATION:- SUCCESSFUL", one verified harness with
# 0 failures, and all cover properties satisfied. Any other exit (CBMC status outside {0,10} surfaces as a
# kani failure), an OOM, or a timeout (124/137/143) is FAIL.
# The negative control passes only if kani reports VERIFICATION:- FAILED with exit 1 and the failed check is
# its own "NEGATIVE CONTROL" assertion, with no OOM and no timeout.
# Env: KANI_HOST (kamrui), KANI_MEM (6G), KANI_TIMEOUT (1800), KANI_HARNESSES (space-separated subset).
set -uo pipefail

HOST=${KANI_HOST:-kamrui}
MEM=${KANI_MEM:-6G}
TMO=${KANI_TIMEOUT:-1800}
PR4910_MERGE=16c774cf
CRATE=monban-budget
NEG=
ONLY=

usage() { echo "usage: ci/kani.sh [--crate|-p CRATE] [--neg HARNESS] [--only PREFIX] [--mem M] [--serial] [--expect-neg-only|--self-test]" >&2; exit 2; }
MODE=all
while [ $# -gt 0 ]; do
  case "$1" in
    --self-test|--expect-neg-only) MODE=self; shift ;;
    --crate|-p) [ $# -ge 2 ] || usage; CRATE=$2; shift 2 ;;
    --neg) [ $# -ge 2 ] || usage; NEG=$2; shift 2 ;;
    --mem) [ $# -ge 2 ] || usage; MEM=$2; shift 2 ;;
    --only) [ $# -ge 2 ] || usage; ONLY=$2; shift 2 ;;
    --serial) shift ;;
    *) usage ;;
  esac
done
[ -z "$ONLY" ] || [[ "$ONLY" =~ ^[a-z][a-z0-9_]*$ ]] || { echo "kani.sh: bad --only prefix $ONLY" >&2; exit 2; }
if [ -z "$NEG" ] && [ -z "$ONLY" ]; then
  case "$CRATE" in
    monban-wire) NEG=negative_control_planted_oob ;;
    *) NEG=negative_control_unclamped_refill ;;
  esac
fi
[[ "$MEM" =~ ^[0-9]+[KMG]$ ]] || { echo "kani.sh: bad --mem $MEM (e.g. 6G)" >&2; exit 2; }
[[ "$CRATE" =~ ^monban-[a-z0-9-]+$ ]] || { echo "kani.sh: bad crate name $CRATE" >&2; exit 2; }
[ -z "$NEG" ] || [[ "$NEG" =~ ^[a-z_0-9]+$ ]] || { echo "kani.sh: bad harness name $NEG" >&2; exit 2; }
if [ "$CRATE" = monban-budget ]; then WDIR=p2-kani; else WDIR=kani-$CRATE; fi
[ -z "$ONLY" ] || WDIR=kani-$CRATE-${ONLY%_}

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PROOFS=$ROOT/crates/$CRATE/src/kani_proofs.rs
fail_both() { echo "kani.sh: $*" >&2; [ "$MODE" = all ] && echo "KANI: FAIL"; echo "KANI SELF-TEST: FAIL"; exit 1; }
[ -f "$PROOFS" ] || fail_both "missing $PROOFS"

# Harness list = every `#[kani::proof]` fn in the proofs file (the gate cannot silently skip one).
mapfile -t ALL < <(awk '/#\[kani::proof\]/{p=1; next} p && /fn [a-z_0-9]+\(/{match($0, /fn [a-z_0-9]+/); print substr($0, RSTART+3, RLENGTH-3); p=0}' "$PROOFS")
SEL=()
for h in "${ALL[@]}"; do [ -z "$ONLY" ] || [[ "$h" == "$ONLY"* ]] && SEL+=("$h"); done
[ "${#SEL[@]}" -gt 0 ] || fail_both "no harness in $PROOFS starts with $ONLY"
if [ -z "$NEG" ]; then # --only without --neg: the one selected negative control
  mapfile -t cand < <(printf '%s\n' "${SEL[@]}" | grep 'negative_control')
  [ "${#cand[@]}" = 1 ] || fail_both "--only $ONLY selects ${#cand[@]} negative controls (need exactly 1, or pass --neg)"
  NEG=${cand[0]}
fi
printf '%s\n' "${SEL[@]}" | grep -qx "$NEG" || fail_both "negative control $NEG not found in $PROOFS${ONLY:+ under --only $ONLY}"
POS=() NEGS=("$NEG")
for h in "${SEL[@]}"; do
  if [[ "$h" == *negative_control* ]]; then [ "$h" = "$NEG" ] || NEGS+=("$h"); else POS+=("$h"); fi
done
[ "${#POS[@]}" -gt 0 ] || fail_both "no positive harnesses found"
if [ -n "${KANI_HARNESSES:-}" ]; then read -r -a POS <<<"$KANI_HARNESSES"; fi
[ "$MODE" = self ] && POS=()

# Crates to sync: the crate plus monban-* path deps declared in its [dependencies].
CRATES=("$CRATE")
mapfile -t DEPS < <(awk '/^\[dependencies\]/{d=1; next} /^\[/{d=0} d && /^monban-[a-z0-9-]+ *=/{sub(/ *=.*/, ""); print}' \
  "$ROOT/crates/$CRATE/Cargo.toml")
for d in "${DEPS[@]}"; do [ -n "$d" ] && CRATES+=("$d"); done

# Third-party `workspace = true` deps of the synced crates ([dependencies] only), taken from the root manifest.
mapfile -t EXT < <(for c in "${CRATES[@]}"; do
  awk '/^\[dependencies\]/{d=1; next} /^\[/{d=0} d && /^[a-z0-9_-]+ *= *\{.*workspace *= *true/ && !/^monban-/{sub(/ *=.*/, ""); print}' \
    "$ROOT/crates/$c/Cargo.toml"; done | sort -u)

# Minimal workspace manifest: members + [workspace.package] + [workspace.lints.*] + monban-* path deps
# + the third-party deps above, verbatim from the root [workspace.dependencies].
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
{
  echo '[workspace]'
  echo 'resolver = "3"'
  printf 'members = ['; for c in "${CRATES[@]}"; do printf '"crates/%s", ' "$c"; done; echo ']'
  echo
  awk '/^\[/{keep = ($0 ~ /^\[workspace\.(package|lints\.rust|lints\.clippy)\]/)} keep' "$ROOT/Cargo.toml"
  if [ "${#CRATES[@]}" -gt 1 ] || [ "${#EXT[@]}" -gt 0 ]; then
    echo '[workspace.dependencies]'
    for c in "${CRATES[@]:1}"; do echo "$c = { path = \"crates/$c\" }"; done
    for e in "${EXT[@]}"; do
      line=$(awk -v k="$e" '/^\[/{w = ($0 == "[workspace.dependencies]")} w && $1 == k && $2 == "=" {print; exit}' "$ROOT/Cargo.toml")
      [ -n "$line" ] || { echo "MISSING_WS_DEP $e"; continue; }
      echo "$line"
    done
  fi
} >"$STAGE/Cargo.toml"
grep -q '^MISSING_WS_DEP' "$STAGE/Cargo.toml" && fail_both "$(grep '^MISSING_WS_DEP' "$STAGE/Cargo.toml" | head -1) (not in the root [workspace.dependencies])"
KZ=none
grep -q 'kani::stub(' "$PROOFS" && KZ=stubbing

ssh -o BatchMode=yes "$HOST" "mkdir -p ~/aegis-ci/work/$WDIR/crates" || fail_both "ssh $HOST failed"
for c in "${CRATES[@]}"; do
  rsync -a --delete --exclude target -e 'ssh -o BatchMode=yes' "$ROOT/crates/$c/" "$HOST:aegis-ci/work/$WDIR/crates/$c/" \
    || fail_both "rsync of $c failed"
done
rsync -a -e 'ssh -o BatchMode=yes' "$STAGE/Cargo.toml" "$HOST:aegis-ci/work/$WDIR/Cargo.toml" || fail_both "rsync of manifest failed"
if [ "${#EXT[@]}" -gt 0 ]; then
  rsync -a -e 'ssh -o BatchMode=yes' "$ROOT/Cargo.lock" "$HOST:aegis-ci/work/$WDIR/Cargo.lock" || fail_both "rsync of Cargo.lock failed"
fi

# Remote runner: prints one "RESULT <name> <OK|FAIL> ..." line per harness plus a "COMMIT" line.
# shellcheck disable=SC2087
NEGLIST=$(IFS=,; echo "${NEGS[*]}")
ssh -o BatchMode=yes "$HOST" bash -s -- "$MEM" "$TMO" "$PR4910_MERGE" "$CRATE" "$NEGLIST" "$MODE" "$WDIR" "$KZ" "${POS[@]}" <<'REMOTE' | tee "$STAGE/out.txt"
set -uo pipefail
MEM=$1 TMO=$2 MERGE=$3 CRATE=$4 NEGLIST=$5 MODE=$6 WDIR=$7 KZ=$8; shift 8
IFS=, read -r -a NEGS <<<"$NEGLIST"
KARGS=""; [ "$KZ" = none ] || KARGS="-Z $KZ" # one ssh word on the wire, split here
CI=$HOME/aegis-ci
export RUSTUP_HOME=$CI/rustup CARGO_HOME=$CI/cargo PATH=$CI/src/kani/scripts:$CI/cargo/bin:$CI/cbmc/usr/bin:$PATH
W=$CI/work/$WDIR; mkdir -p "$W/logs"; cd "$W" || exit 3
K=$CI/src/kani
commit=$(git -C "$K" rev-parse HEAD 2>/dev/null) || { echo "COMMIT FAIL no kani checkout"; exit 0; }
if git -C "$K" merge-base --is-ancestor "$MERGE" "$commit" 2>/dev/null \
   && [ -z "$(git -C "$K" status --porcelain --untracked-files=no)" ] && [ -x "$K/target/kani/bin/kani-driver" ]; then
  echo "COMMIT OK $commit (descendant of $MERGE; clean tree; $(kani --version 2>/dev/null | head -1))"
else
  echo "COMMIT FAIL $commit is not a clean descendant of $MERGE (or the build is missing)"
fi
if systemd-run --user --scope -q true 2>/dev/null; then SCOPE=1; else SCOPE=0; fi
run_one() { # name rustflags is_negative(0|1)
  local h=$1 rf=$2 isneg=$3 log="$W/logs/$1.log"
  if [ "$SCOPE" = 1 ]; then
    RUSTFLAGS="$rf" systemd-run --user --scope -q -p MemoryMax="$MEM" -p MemorySwapMax=0 nice -n 15 bash -c '
      cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); s=$(date +%s.%N)
      timeout "$0" cargo kani -p "$1" $3 --harness "kani_proofs::harnesses::$2" --exact; rc=$?
      echo "GATE rc=$rc wall=$(echo "$(date +%s.%N) - $s" | bc) peak=$(cat "$cg/memory.peak" 2>/dev/null || echo na) oom=$(awk "/^oom_kill /{print \$2}" "$cg/memory.events" 2>/dev/null)"
      exit $rc' "$TMO" "$CRATE" "$h" "$KARGS" >"$log" 2>&1
  else
    local kb; kb=$(numfmt --from=iec "$MEM"); kb=$((kb / 1024))
    RUSTFLAGS="$rf" bash -c 'ulimit -v "$1"; s=$(date +%s.%N); nice -n 15 timeout "$0" cargo kani -p "$2" $4 --harness "kani_proofs::harnesses::$3" --exact; rc=$?
      echo "GATE rc=$rc wall=$(echo "$(date +%s.%N) - $s" | bc) peak=na oom=na"; exit $rc' "$TMO" "$kb" "$CRATE" "$h" "$KARGS" >"$log" 2>&1
  fi
  local rc=$? g; g=$(grep -E '^GATE ' "$log" | tail -1)
  local rc_in wall peak oom
  rc_in=$(sed -n 's/.*GATE rc=\([0-9]*\).*/\1/p' <<<"$g"); rc_in=${rc_in:-$rc}
  wall=$(sed -n 's/.* wall=\([0-9.]*\).*/\1/p' <<<"$g"); peak=$(sed -n 's/.* peak=\([0-9a-z]*\).*/\1/p' <<<"$g")
  oom=$(sed -n 's/.* oom=\([0-9a-z]*\).*/\1/p' <<<"$g")
  local memflag=0; grep -qiE 'out of memory|bad_alloc' "$log" && memflag=1
  [ -n "$oom" ] && [ "$oom" != na ] && [ "$oom" != 0 ] && memflag=1
  local mb=na; [[ "$peak" =~ ^[0-9]+$ ]] && mb=$((peak / 1048576))MB
  local verdict=FAIL why=""
  if [ "$isneg" = 1 ]; then
    if [ "$rc" = 1 ] && [ "$rc_in" = 1 ] && [ "$memflag" = 0 ] && grep -q 'VERIFICATION:- FAILED' "$log" \
       && grep -A3 'Failed Checks:' "$log" | grep -q 'NEGATIVE CONTROL'; then verdict=FAIL_AS_EXPECTED
    else why="negative control did not fail on its own assertion"; verdict=NOT_RED; fi
  else
    local cov; cov=$(grep -oE '\*\* [0-9]+ of [0-9]+ cover properties satisfied' "$log" | tail -1)
    local cov_ok=1
    if [ -n "$cov" ]; then read -r _ a _ b _ <<<"$cov"; [ "$a" = "$b" ] || cov_ok=0; fi
    if [ "$rc" = 0 ] && [ "$rc_in" = 0 ] && [ "$memflag" = 0 ] && grep -q 'VERIFICATION:- SUCCESSFUL' "$log" \
       && ! grep -q 'VERIFICATION:- FAILED' "$log" \
       && grep -qE 'Complete - 1 successfully verified harnesses, 0 failures' "$log" && [ "$cov_ok" = 1 ]; then verdict=OK
    else
      case "$rc_in" in 124|137|143) why="timeout/killed";; esac
      [ "$memflag" = 1 ] && why="OOM"
      [ "$cov_ok" = 0 ] && why="unsatisfied cover ($cov)"
      [ -z "$why" ] && why="rc=$rc_in"
    fi
  fi
  echo "RESULT $h $verdict rc=$rc_in wall=${wall:-na}s peak=$mb ${cov:-} ${why:+($why)}"
}
for h in "$@"; do run_one "$h" "" 0; done
for n in "${NEGS[@]}"; do run_one "$n" "--cfg monban_kani_negative" 1; done
REMOTE

OUT=$STAGE/out.txt
grep -q '^COMMIT OK' "$OUT" && commit_ok=1 || commit_ok=0
self=PASS; [ "$commit_ok" = 1 ] || self=FAIL
for n in "${NEGS[@]}"; do grep -qE "^RESULT $n FAIL_AS_EXPECTED" "$OUT" || self=FAIL; done
if [ "$MODE" = all ]; then
  pass=1
  [ "$commit_ok" = 1 ] || pass=0
  for h in "${POS[@]}"; do grep -qE "^RESULT $h OK " "$OUT" || pass=0; done
  [ "$self" = PASS ] || pass=0
  [ "$pass" = 1 ] && echo "KANI: PASS" || echo "KANI: FAIL"
fi
echo "KANI SELF-TEST: $self"
if [ "$self" = PASS ] && { [ "$MODE" = self ] || [ "${pass:-0}" = 1 ]; }; then exit 0; fi
exit 1
