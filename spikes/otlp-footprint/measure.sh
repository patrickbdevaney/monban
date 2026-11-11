#!/usr/bin/env bash
# Light measurement of built variants (no compile): stripped size, idle RSS (after start; after 200 TLS requests),
# OTLP export check against a dummy collector. Usage: ./measure.sh > results/measure.jsonl
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
rss() { awk '/VmRSS/{print $2}' "/proc/$1/status"; }
python3 -I "$here/collector.py" 14318 > "$here/results/collector.log" 2>&1 & col=$!
trap 'kill $col 2>/dev/null || true' EXIT
sleep 0.5
port=18443
for b in base metrics metrics+logs metrics+logs+otlp metrics+logs+otlp-grpc; do
  bin="$here/bins/hello-$b"; [ -x "$bin" ] || continue
  port=$((port+1))
  size=$(stat -c %s "$bin")
  HELLO_PORT=$port OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:14318 HELLO_OTLP_INTERVAL_S=1 \
    "$bin" 2> "$here/results/stderr-$b.log" & pid=$!
  for _ in $(seq 50); do grep -q ready "$here/results/stderr-$b.log" 2>/dev/null && break; sleep 0.1; done
  sleep 2; r0=$(rss $pid); thr0=$(ls /proc/$pid/task | wc -l)
  for i in $(seq 100); do curl -sk --http1.1 "https://localhost:$port/" -o /dev/null; curl -sk --http2 "https://localhost:$port/" -o /dev/null; done
  m=""; [ "${b#*metrics}" != "$b" ] && m=$(curl -s http://127.0.0.1:9100/metrics | grep -c '^monban_' || true)
  sleep 3; r1=$(rss $pid); thr1=$(ls /proc/$pid/task | wc -l)
  kill $pid; wait $pid 2>/dev/null || true
  echo "{\"variant\":\"$b\",\"stripped_bytes\":$size,\"idle_rss_kb_start\":$r0,\"idle_rss_kb_after_200req\":$r1,\"threads_start\":$thr0,\"threads_after\":$thr1,\"openmetrics_series\":\"$m\"}"
done
echo "collector:" >&2; sort "$here/results/collector.log" | awk '{print $1,$2}' | uniq -c >&2
