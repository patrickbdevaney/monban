#!/usr/bin/env bash
# bench.sh HSBENCH OUT.jsonl SERVER_CORE CLIENT_CORES REPS [SECS] [THREADS]
# ABBA-interleaved: rep r runs the config list forward (r even) or reversed (r odd). Server pinned to one core.
set -u
B=$1; OUT=$2; SC=$3; CC=$4; REPS=$5; SECS=${6:-8}; TH=${7:-24}; WARM=2; PORT=18443
ctx() { # $1 = tag
  printf '{"kind":"ctx","tag":"%s","host":"%s","kernel":"%s","model":"%s","gov":"%s","loadavg":"%s","stat_cpu":"%s","stat_core":"%s"}\n' \
    "$1" "$(hostname)" "$(uname -r)" "$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //')" \
    "$(cat /sys/devices/system/cpu/cpu$SC/cpufreq/scaling_governor 2>/dev/null)" "$(cat /proc/loadavg)" \
    "$(grep '^cpu ' /proc/stat)" "$(grep "^cpu$SC " /proc/stat)"
}
CFGS=()
for g in x25519 x25519mlkem768 p256mlkem768; do
  CFGS+=("$g hs 0 2 full" "$g hs 1 2 resumed" "$g reject 0 2 reject" "$g reject 0 0 reject_notickets")
done
ctx start >> "$OUT"
printf '{"kind":"flags","flags":"%s"}\n' "$(grep -m1 '^flags' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //')" >> "$OUT"
for ((r=0; r<REPS; r++)); do
  idx=($(seq 0 $((${#CFGS[@]}-1)))); [ $((r%2)) = 1 ] && idx=($(printf '%s\n' "${idx[@]}" | tac))
  for i in "${idx[@]}"; do
    set -- ${CFGS[$i]}
    s0=$(grep "^cpu$SC " /proc/stat)
    taskset -c "$SC" "$B" server --port $PORT --group $1 --mode $2 --tickets $4 --secs $SECS --warm $WARM --label "$5 rep=$r" > /tmp/hs.srv.$$ &
    sp=$!; sleep 0.3
    taskset -c "$CC" "$B" client --addr 127.0.0.1:$PORT --group $1 --mode $2 --resume $3 --threads $TH --secs $((SECS+WARM)) > /tmp/hs.cli.$$
    wait $sp
    s1=$(grep "^cpu$SC " /proc/stat)
    printf '%s\n' "$(cat /tmp/hs.srv.$$ | sed "s/}\$/,\"case\":\"$5\",\"rep\":$r,\"core_stat_before\":\"$s0\",\"core_stat_after\":\"$s1\"}/")" >> "$OUT"
    cat /tmp/hs.cli.$$ >> "$OUT"
    PORT=$((PORT+1))
  done
done
ctx end >> "$OUT"
rm -f /tmp/hs.srv.$$ /tmp/hs.cli.$$
