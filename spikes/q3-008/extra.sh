#!/usr/bin/env bash
# Repeat of the key rows + the reuse-wait mode (no CancelRequest). usage: extra.sh <out.jsonl> <img> <ccpu> <scpu> <n> <secs>
set -uo pipefail
D=$(cd "$(dirname "$0")" && pwd); OUT=$1; IMG=$2; CC=$3; SC=$4; NL=$5; SECS=$6; B=${BIN:-$D/target/release/q3008}
echo "{\"host\":\"$(hostname)\",\"cpu\":\"$(lscpu | sed -n 's/^Model name: *//p')\",\"kernel\":\"$(uname -r)\",\"governor\":\"\",\"image\":\"$IMG\",\"client_cpu\":$CC,\"server_cpu\":$SC,\"loadavg\":\"$(cut -d' ' -f1-3 /proc/loadavg)\",\"date\":\"$(date -Is)\"}" >> "$OUT"
"$D/pg.sh" stop; CG=$("$D/pg.sh" start "$IMG" "$SC") || exit 1
run() { taskset -c "$CC" "$B" --cgroup "$CG" --ca "$D/certs/ca.crt" "$@" | tee -a "$OUT"; }
for cfg in trustu:off postgres:p256; do u=${cfg%%:*}; t=${cfg##*:}
  for m in connect discard reuse reuse-wait; do run --label lat-split --user $u --tls $t --mode $m --n $NL --warmup 100 --conc 1; done
done
docker update --cpuset-cpus "$CC" q3008-pg >/dev/null
for cfg in trustu:off postgres:p256; do u=${cfg%%:*}; t=${cfg##*:}
  for m in connect discard reuse reuse-wait; do run --label rate-shared --user $u --tls $t --mode $m --secs $SECS --warmup 64 --conc 16; done
done
echo "loadavg at end $(cut -d' ' -f1-3 /proc/loadavg)" >&2
"$D/pg.sh" stop
