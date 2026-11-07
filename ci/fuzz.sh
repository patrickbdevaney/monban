#!/usr/bin/env bash
# AEGIS fuzz gate (unit P3-fuzz-001): libFuzzer targets in fuzz/ (a separate cargo workspace).
#
#   ci/fuzz.sh setup                     install the pinned nightly + cargo-fuzz (ci/tools.lock "#fuzz:" rows)
#   ci/fuzz.sh seed                      regenerate the seed inputs in fuzz/corpus/ from the crates' own encoders
#   ci/fuzz.sh run --execs N [--targets a,b] [--jobs J]
#                                        every target to >= N executions; exit 0 only if all reach N with 0 crashes,
#                                        0 per-input timeouts, 0 OOMs and no wall-clock timeout
#   ci/fuzz.sh self-test [--targets a,b] build with --cfg fuzzing_selftest (a planted panic in each target, fuzz
#                                        workspace only) and require every planted panic found within 1e6 executions
#   ci/fuzz.sh minimize [--targets a,b]  merge the last run's working corpus into fuzz/corpus/<target> (minimized)
#
# Runs only on a LAN build box with the isolated toolchain (ci/remote.sh sets RUSTUP_HOME/CARGO_HOME under
# ~/aegis-ci): `ci/remote.sh ci/fuzz.sh run --execs 100000000`. Never on the laptop (disk; nightly is not
# installed there). Env: AEGIS_FUZZ_JOBS (parallel processes), AEGIS_FUZZ_SPLIT ("t=W ..." processes per target), AEGIS_FUZZ_TARGET_TIMEOUT (seconds per target),
# AEGIS_FUZZ_RSS_MB (libFuzzer -rss_limit_mb, default 1200), AEGIS_FUZZ_INPUT_TIMEOUT (per input, default 10 s).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGETS_ALL="h1_head token canon_json combiner config audit pdp_wire egress mcp_gate proxy_v2 client_hello_peek pg_message"
# Listed in the unit but not fuzzable yet (documented in fuzz/Cargo.toml).
SKIPPED="none"
# Targets slower than ~10k exec/s on the desktop are split over W processes sharing one corpus (sum of execs >= N).
# mcp_gate runs ~1.3k exec/s per process (up to 8 requests x 2-3 full gate checks, each a JWT verify + JSON parse).
SPLIT_DEFAULT="config=4 token=2 audit=2 mcp_gate=8"

lock_row() { grep "^#fuzz:$1	" "$ROOT/ci/tools.lock" | head -1 | cut -c7-; }
field() { printf '%s\n' "$1" | cut -f"$2"; }
NIGHTLY_ROW=$(lock_row nightly); FUZZ_ROW=$(lock_row cargo-fuzz)
NIGHTLY=$(field "$NIGHTLY_ROW" 2); NIGHTLY_SHA=$(field "$NIGHTLY_ROW" 4); NIGHTLY_URL=$(field "$NIGHTLY_ROW" 5)
CF_VER=$(field "$FUZZ_ROW" 2); CF_SHA=$(field "$FUZZ_ROW" 4)
[ -n "$NIGHTLY" ] && [ -n "$CF_VER" ] || { echo "fuzz.sh: no #fuzz: pins in ci/tools.lock" >&2; exit 2; }

TD_BASE="${CARGO_TARGET_DIR:-$ROOT/target}"
TRIPLE=x86_64-unknown-linux-gnu
WORK="$TD_BASE/fuzz-work-$(basename "$ROOT")"
RSS_MB=${AEGIS_FUZZ_RSS_MB:-1200}
INPUT_TIMEOUT=${AEGIS_FUZZ_INPUT_TIMEOUT:-10}
# Smaller ASan quarantine: ~11 concurrent processes must stay under the remote 12 GB cgroup cap.
export ASAN_OPTIONS="${ASAN_OPTIONS:-quarantine_size_mb=64:malloc_context_size=10}"

need_isolated() {
  case "${RUSTUP_HOME:-}" in
    */aegis-ci/rustup) ;;
    *) [ "${AEGIS_FUZZ_ANY_HOST:-0}" = 1 ] || {
         echo "fuzz.sh: refusing: not in the isolated LAN toolchain (run through ci/remote.sh)" >&2; exit 2; } ;;
  esac
}

cmd_setup() {
  need_isolated
  if ! rustup toolchain list | grep -q "^$NIGHTLY-"; then
    local d; d=$(mktemp -d)
    curl -sfL --retry 3 -A aegis-ci -o "$d/m.toml" "$NIGHTLY_URL"
    echo "$NIGHTLY_SHA  $d/m.toml" | sha256sum -c --quiet || { echo "fuzz.sh: nightly manifest sha256 mismatch" >&2; rm -rf "$d"; exit 1; }
    rm -rf "$d"
    rustup toolchain install "$NIGHTLY" --profile minimal --no-self-update
  fi
  local have; have=$(cargo-fuzz --version 2>/dev/null || true)
  if [ "$have" != "cargo-fuzz $CF_VER" ]; then
    # Sparse-index checksum must equal the pin; cargo then verifies the downloaded .crate against the index.
    local idx; idx=$(curl -sf --retry 3 -A aegis-ci https://index.crates.io/ca/rg/cargo-fuzz)
    printf '%s\n' "$idx" | grep -F "\"vers\":\"$CF_VER\"" | grep -qF "\"cksum\":\"$CF_SHA\"" \
      || { echo "fuzz.sh: cargo-fuzz $CF_VER index checksum does not match ci/tools.lock" >&2; exit 1; }
    (cd / && cargo +"${AEGIS_STABLE:-1.99.1}" install --locked --version "$CF_VER" cargo-fuzz \
       --root "${AEGIS_TOOLS:-$CARGO_HOME}" --target-dir "$TD_BASE/cargo-fuzz-build")
    rm -rf "$TD_BASE/cargo-fuzz-build"
  fi
  rustup run "$NIGHTLY" rustc --version
  cargo-fuzz --version
}

parse_targets() {
  TARGETS="$TARGETS_ALL"
  EXECS=""
  JOBS_OPT=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --execs) EXECS="$2"; shift 2 ;;
      --targets) TARGETS="${2//,/ }"; shift 2 ;;
      --jobs) JOBS_OPT="$2"; shift 2 ;;
      *) echo "fuzz.sh: unknown option $1" >&2; exit 2 ;;
    esac
  done
  local n; n=$(wc -w <<<"$TARGETS")
  local half=$(( $(nproc) / 2 )); [ "$half" -ge 1 ] || half=1
  JOBS=${JOBS_OPT:-${AEGIS_FUZZ_JOBS:-$half}}
  [ "$JOBS" -le "$n" ] || JOBS=$n
}

build() { # $1 = target dir, extra RUSTFLAGS in $2. Release + debug assertions (overflow checks on).
  local t
  if [ "$TARGETS" = "$TARGETS_ALL" ]; then
    RUSTFLAGS="${2:-}" cargo +"$NIGHTLY" fuzz build --fuzz-dir fuzz --target-dir "$1" -O --debug-assertions
  else
    for t in $TARGETS; do
      RUSTFLAGS="${2:-}" cargo +"$NIGHTLY" fuzz build --fuzz-dir fuzz --target-dir "$1" -O --debug-assertions "$t"
    done
  fi
}

# One libFuzzer process per target, JOBS at a time. Writes $WORK/<t>.log and $WORK/<t>.status.
workers_of() { # $1 = target, $2 = mode. Slow targets run as W independent processes on one shared corpus.
  [ "$2" = run ] || { echo 1; return; }
  local kv
  for kv in ${AEGIS_FUZZ_SPLIT:-$SPLIT_DEFAULT}; do
    [ "${kv%%=*}" = "$1" ] && { echo "${kv#*=}"; return; }
  done
  echo 1
}

# libFuzzer processes, JOBS at a time: each target's N executions are split over workers_of() processes
# (ceil(N/W) each, so the sum is >= N). Writes $WORK/<mode>-<t>.<k>.log and .status.
run_all() { # $1 = binary dir, $2 = runs per target, $3 = per-process wall timeout, $4 = mode (run|selftest)
  local bindir=$1 runs=$2 wall=$3 mode=$4
  mkdir -p "$WORK"
  local t k w
  for t in $TARGETS; do
    rm -rf "$WORK/$mode-$t" "$WORK/$mode-$t-artifacts" "$WORK/$mode-$t".*.log "$WORK/$mode-$t".*.status
    mkdir -p "$WORK/$mode-$t" "$WORK/$mode-$t-artifacts" "fuzz/corpus/$t"
    cp -r "${SEED_SRC:-fuzz/corpus}/$t/." "$WORK/$mode-$t/" 2>/dev/null || true
  done
  for t in $TARGETS; do
    w=$(workers_of "$t" "$mode")
    for k in $(seq 1 "$w"); do
      while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n || true; done
      (
        set +e
        timeout --kill-after=30 "$wall" "$bindir/$t" "$WORK/$mode-$t" -runs=$(( (runs + w - 1) / w )) \
          -timeout="$INPUT_TIMEOUT" -rss_limit_mb="$RSS_MB" -max_len=8192 -print_final_stats=1 \
          -artifact_prefix="$WORK/$mode-$t-artifacts/" > "$WORK/$mode-$t.$k.log" 2>&1
        echo $? > "$WORK/$mode-$t.$k.status"
      ) &
    done
  done
  wait
}

stat_of() { { grep -m1 "^stat::$2:" "$1" 2>/dev/null || true; } | awk '{print $2}'; }

cmd_run() {
  need_isolated
  parse_targets "$@"
  [ -n "$EXECS" ] || { echo "usage: ci/fuzz.sh run --execs N" >&2; exit 2; }
  local wall=${AEGIS_FUZZ_TARGET_TIMEOUT:-$(( EXECS / 1000 + 600 ))}
  local td="$TD_BASE/fuzz"
  build "$td"
  local procs=0 t
  for t in $TARGETS; do procs=$(( procs + $(workers_of "$t" run) )); done
  if [ -z "$JOBS_OPT${AEGIS_FUZZ_JOBS:-}" ]; then
    JOBS=$(( $(nproc) / 2 )); [ "$JOBS" -ge 1 ] || JOBS=1; [ "$JOBS" -le "$procs" ] || JOBS=$procs
  fi
  echo "fuzz.sh: $NIGHTLY, cargo-fuzz $CF_VER, $(wc -w <<<"$TARGETS") targets x $EXECS execs ($procs processes," \
       "split: ${AEGIS_FUZZ_SPLIT:-$SPLIT_DEFAULT}), jobs=$JOBS, wall/process=${wall}s, rss_limit=${RSS_MB}MB"
  local t0=$SECONDS
  run_all "$td/$TRIPLE/release" "$EXECS" "$wall" run
  echo "fuzz.sh: wall clock $(( SECONDS - t0 ))s"
  local ok=0 bad=()
  printf '%-12s %-3s %-12s %-9s %-8s %-7s %s\n' target W execs exec/s seconds rss_mb result
  for t in $TARGETS; do
    local n=0 eps=0 secs=0 rss=0 res=ok log st x
    for log in "$WORK/run-$t".*.log; do
      st=$(cat "${log%.log}.status" 2>/dev/null || echo 99)
      x=$(stat_of "$log" number_of_executed_units); n=$(( n + ${x:-0} ))
      x=$(stat_of "$log" average_exec_per_sec); eps=$(( eps + ${x:-0} ))
      x=$(stat_of "$log" peak_rss_mb); [ "${x:-0}" -le "$rss" ] || rss=$x
      x=$({ grep -m1 -o 'Done [0-9]* runs in [0-9]* second' "$log" || true; } | awk '{print $5}')
      [ "${x:-0}" -le "$secs" ] || secs=$x
      [ "$res" = ok ] || continue
      if [ "$st" = 124 ] || [ "$st" = 137 ]; then res="wall-timeout"
      elif grep -q 'ERROR: libFuzzer: timeout' "$log"; then res="input-timeout"
      elif grep -qE 'ERROR: libFuzzer: (out-of-memory|malloc limit)' "$log"; then res="oom"
      elif grep -qE "ERROR: libFuzzer: deadly signal|panicked at|ERROR: AddressSanitizer" "$log"; then res="crash"
      elif [ "$st" != 0 ]; then res="exit-$st"
      fi
      if [ "$res" != ok ]; then grep -m3 -E 'panicked at|ERROR: libFuzzer|SUMMARY' "$log" | sed "s/^/  $t: /" || true; fi
    done
    [ "$res" != ok ] || [ "$n" -ge "$EXECS" ] || res="short"
    printf '%-12s %-3s %-12s %-9s %-8s %-7s %s\n' "$t" "$(workers_of "$t" run)" "$n" "$eps" "$secs" "$rss" "$res"
    if [ "$res" = ok ]; then ok=$((ok + 1)); else bad+=("$t:$res"); fi
    if [ "$res" != ok ]; then
      ls "$WORK/run-$t-artifacts/" 2>/dev/null | sed "s|^|  $t artifact: $WORK/run-$t-artifacts/|" || true
    fi
  done
  local nt; nt=$(wc -w <<<"$TARGETS")
  if [ "${#bad[@]}" -eq 0 ]; then
    echo "FUZZ: PASS ($ok/$nt targets reached $EXECS execs, 0 crashes/timeouts/OOMs; skipped: $SKIPPED)"
  else
    echo "FUZZ: FAIL ($ok/$nt targets clean at $EXECS execs; failed: ${bad[*]}; skipped: $SKIPPED)"
    exit 1
  fi
}

cmd_selftest() {
  need_isolated
  parse_targets "$@"
  local td="$TD_BASE/fuzz-selftest"
  build "$td" "--cfg fuzzing_selftest"
  # Start from the initial seeds (examples/seeds.rs), not the grown corpus: no seed meets a planted condition, so
  # the fuzzer has to mutate its way to each one (a grown corpus may already contain the trigger).
  rm -rf "$WORK/selftest-seeds"
  cargo +"$NIGHTLY" run -q --manifest-path fuzz/Cargo.toml --target-dir "$TD_BASE/fuzz-seeds" --example seeds \
    -- "$WORK/selftest-seeds" > /dev/null
  SEED_SRC="$WORK/selftest-seeds"
  # Time-to-find is random (each planted condition is one mutation from a seed, yet one 1e6 attempt misses it
  # occasionally), so a target that misses gets up to 2 more independent attempts, each from the seeds with the
  # full 1e6 budget. A planted panic that is unreachable still misses all 3 and fails.
  local all=$TARGETS ok=0 bad=() t attempt
  for attempt in 1 2 3; do
    run_all "$td/$TRIPLE/release" 1000000 "${AEGIS_FUZZ_TARGET_TIMEOUT:-1800}" selftest
    bad=()
    for t in $TARGETS; do
      local log="$WORK/selftest-$t.1.log" st; st=$(cat "$WORK/selftest-$t.1.status" 2>/dev/null || echo 99)
      local n; n=$({ grep -oE '^#[0-9]+' "$log" || true; } | tail -1 | tr -d '#')
      if [ "$st" != 0 ] && grep -q 'AEGIS_FUZZ_SELFTEST planted panic reached' "$log"; then
        echo "self-test $t: planted panic found (attempt $attempt, after ~${n:-?} execs)"; ok=$((ok + 1))
      else
        echo "self-test $t: NOT found within 1e6 execs (attempt $attempt, exit $st)"; bad+=("$t")
        grep -m3 -E 'panicked at|ERROR: libFuzzer|Done' "$log" | sed "s/^/  $t: /" || true
      fi
    done
    [ "${#bad[@]}" -eq 0 ] && break
    TARGETS="${bad[*]}"
  done
  TARGETS=$all
  local n; n=$(wc -w <<<"$TARGETS")
  if [ "${#bad[@]}" -eq 0 ]; then
    echo "FUZZ: PASS (self-test: $ok/$n planted panics found within 1e6 execs, <= 3 independent attempts each)"
  else
    echo "FUZZ: FAIL (self-test: $ok/$n found; missed: ${bad[*]})"
    exit 1
  fi
}

cmd_minimize() {
  need_isolated
  parse_targets "$@"
  local bin="$TD_BASE/fuzz/$TRIPLE/release" t
  for t in $TARGETS; do
    [ -d "$WORK/run-$t" ] || { echo "minimize $t: no working corpus (run first)"; continue; }
    local new="fuzz/corpus/$t.min"
    rm -rf "$new"; mkdir -p "$new"
    "$bin/$t" -merge=1 -max_len=8192 -rss_limit_mb="$RSS_MB" "$new" "fuzz/corpus/$t" "$WORK/run-$t" \
      > "$WORK/minimize-$t.log" 2>&1
    rm -rf "fuzz/corpus/$t"; mv "$new" "fuzz/corpus/$t"
    echo "minimize $t: $(ls "fuzz/corpus/$t" | wc -l) files, $(du -sh "fuzz/corpus/$t" | cut -f1)"
  done
}

cmd_seed() {
  need_isolated
  cargo +"$NIGHTLY" run -q --manifest-path fuzz/Cargo.toml --target-dir "$TD_BASE/fuzz-seeds" --example seeds -- fuzz/corpus
  ls fuzz/corpus
}

case "${1:-}" in
  setup) shift; cmd_setup "$@" ;;
  seed) shift; cmd_seed "$@" ;;
  run) shift; cmd_run "$@" ;;
  self-test) shift; cmd_selftest "$@" ;;
  minimize) shift; cmd_minimize "$@" ;;
  *) sed -n '2,17p' "$0"; exit 2 ;;
esac
