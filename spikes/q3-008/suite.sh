#!/usr/bin/env bash
# q3-008 measurement suite. usage: suite.sh <out.jsonl> <pg-image> <client-cpu> <server-cpu> <n-latency> <rate-secs>
# Starts a throwaway loopback PG (pg.sh), runs latency (conc 1, separate cores) and rate runs (conc 16) with the
# server on its own core ("split") and on the client's core ("shared" = 1-vCPU box), then removes the container.
set -uo pipefail
D=$(cd "$(dirname "$0")" && pwd); OUT=$1; IMG=$2; CC=$3; SC=$4; NL=$5; SECS=$6
B=${BIN:-$D/target/release/q3008}; CA=$D/certs/ca.crt
{ echo "{\"host\":\"$(hostname)\",\"cpu\":\"$(lscpu | sed -n 's/^Model name: *//p')\",\"kernel\":\"$(uname -r)\",\"governor\":\"$(cat /sys/devices/system/cpu/cpu$CC/cpufreq/scaling_governor 2>/dev/null)\",\"image\":\"$IMG\",\"client_cpu\":$CC,\"server_cpu\":$SC,\"loadavg\":\"$(cut -d' ' -f1-3 /proc/loadavg)\",\"date\":\"$(date -Is)\"}"; } >> "$OUT"
"$D/pg.sh" stop; CG=$("$D/pg.sh" start "$IMG" "$SC" ${PGARGS:-}) || { echo "pg start failed"; exit 1; }
docker exec q3008-pg postgres --version >&2
run() { taskset -c "$CC" "$B" --cgroup "$CG" --ca "$CA" "$@" | tee -a "$OUT"; }
CFGS=${CFGS:-"trustu:off postgres:off postgres:p256"}
for cfg in $CFGS; do u=${cfg%%:*}; t=${cfg##*:}
  for m in connect discard discard-nocancel reuse; do
    run --label lat-split --user "$u" --tls "$t" --mode "$m" --n "$NL" --warmup 100 --conc 1
  done
done
for cfg in $CFGS; do u=${cfg%%:*}; t=${cfg##*:}
  for m in connect discard reuse; do
    run --label rate-split --user "$u" --tls "$t" --mode "$m" --secs "$SECS" --warmup 64 --conc 16
  done
done
docker update --cpuset-cpus "$CC" q3008-pg >/dev/null
for cfg in $CFGS; do u=${cfg%%:*}; t=${cfg##*:}
  for m in connect discard reuse; do
    run --label rate-shared --user "$u" --tls "$t" --mode "$m" --secs "$SECS" --warmup 64 --conc 16
  done
  run --label lat-shared --user "$u" --tls "$t" --mode discard --n "$NL" --warmup 100 --conc 1
done
docker exec q3008-pg psql -p 55432 -U postgres -Atc "select count(*) from pg_stat_activity where backend_type='client backend'" >&2
"$D/pg.sh" stop
