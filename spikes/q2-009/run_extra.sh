#!/usr/bin/env bash
# Extra runs: frame-level observation of rapid-reset / CONTINUATION, and the second-wave reuse test.
#   HEAVY_TIMEOUT=1200 ../../ci/heavy.sh ./run_extra.sh
set -euo pipefail
cd "$(dirname "$0")"
bin=$PWD/target/release/q2009
for impl in hyper-baseline h2-baseline h2-wrapper; do
  ./run_one.sh "$impl" rapidreset 10 100 8000 10000 12
  ./run_one.sh "$impl" rapidreset 1 1000 8000 10000 12 burst1000   # > RST bucket burst (TBI-5)
  ./run_one.sh "$impl" continuation 10 100 8000 10000 12
done
# second wave: 100 conns at t~1 s, another 100 conns at t~13 s (after the 10 s reap of wave 1).
for impl in h2-wrapper h2-baseline; do
  port=$((20000 + RANDOM % 2000)); tag="${impl}__bigwin-noread__c100-wave2"
  "$bin" server --impl "$impl" --port "$port" --ledger-mib 12 >raw/$tag.log 2>raw/$tag.stat.raw &
  spid=$!; sleep 0.5
  "$bin" sample --pid "$spid" --ms 250 --dur-ms 30000 >raw/$tag.rss.csv &
  smp=$!; sleep 1
  "$bin" attack --port "$port" --conns 100 --hold-ms 27000 --shape bigwin-noread >>raw/$tag.log 2>&1 &
  a1=$!; sleep 12
  "$bin" attack --port "$port" --conns 100 --hold-ms 15000 --shape bigwin-noread >>raw/$tag.log 2>&1 || true
  wait $a1 $smp || true; kill $spid; wait $spid 2>/dev/null || true
  { echo "t_ms,conns,streams,buffered_kib_total,max_conn_buffered_kib,reaped"; sed -n 's/^STAT //p' raw/$tag.stat.raw; } >raw/$tag.stat.csv
  rm -f raw/$tag.stat.raw; echo "done $tag"
done
