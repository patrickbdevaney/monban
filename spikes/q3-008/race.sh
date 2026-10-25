#!/usr/bin/env bash
# Reuse-path correctness probe: vary in-flight query length vs cancel time so the CancelRequest races query
# completion. usage: race.sh <out.jsonl> <pg-image> <client-cpu> <server-cpu> <n>
set -uo pipefail
D=$(cd "$(dirname "$0")" && pwd); OUT=$1; IMG=$2; CC=$3; SC=$4; N=$5; B=${BIN:-$D/target/release/q3008}
"$D/pg.sh" stop; CG=$("$D/pg.sh" start "$IMG" "$SC") || exit 1
for sa in 50:2 3:2 2:2 2:1 1:1; do s=${sa%%:*}; a=${sa##*:}
  echo "== sleep ${s}ms cancel-after ${a}ms" >&2
  Q3008_SLEEP_MS=$s Q3008_CANCEL_AFTER_MS=$a taskset -c "$CC" "$B" --cgroup "$CG" --label "race-s${s}-a${a}" \
    --user trustu --mode reuse --n "$N" --warmup 50 --conc 1 | tee -a "$OUT"
done
"$D/pg.sh" stop
