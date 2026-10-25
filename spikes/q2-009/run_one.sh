#!/usr/bin/env bash
# One measurement: server impl x attack shape x connections. Run under ci/heavy.sh (see run.sh).
# Writes raw/<impl>__<shape>__c<conns>.{rss.csv,stat.csv,log}
# usage: run_one.sh <impl> <shape> <conns> [streams=100] [hold_ms=25000] [sample_ms=32000] [ledger_mib=12]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
bin=$here/target/release/q2009
impl=$1 shape=$2 conns=$3 streams=${4:-100} hold=${5:-25000} dur=${6:-32000} ledger=${7:-12}
port=$((18000 + RANDOM % 2000))
tag="${impl}__${shape}__c${conns}"
out=$here/raw
mkdir -p "$out"
ulimit -n 8192 || true

"$bin" server --impl "$impl" --port "$port" --body-mib 64 --ledger-mib "$ledger" \
  >"$out/$tag.log" 2>"$out/$tag.stat.raw" &
spid=$!
for _ in $(seq 50); do grep -q READY "$out/$tag.log" 2>/dev/null && break; sleep 0.1; done
"$bin" sample --pid "$spid" --ms 250 --dur-ms "$dur" >"$out/$tag.rss.csv" &
smp=$!
sleep 1   # idle baseline samples
"$bin" attack --port "$port" --conns "$conns" --streams "$streams" --hold-ms "$hold" --shape "$shape" \
  >>"$out/$tag.log" 2>&1 || echo "attack exit $?" >>"$out/$tag.log"
wait "$smp" || true
kill "$spid" 2>/dev/null || true
wait "$spid" 2>/dev/null || true
{ echo "t_ms,conns,streams,buffered_kib_total,max_conn_buffered_kib,reaped"; sed -n 's/^STAT //p' "$out/$tag.stat.raw"; } >"$out/$tag.stat.csv"
grep -v '^STAT ' "$out/$tag.stat.raw" >>"$out/$tag.log" || true
rm -f "$out/$tag.stat.raw"
echo "done $tag"
