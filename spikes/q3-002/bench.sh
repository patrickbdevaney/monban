#!/usr/bin/env bash
# bench.sh IPCHOP OUT.jsonl CORE_A CORE_B REPS
# Per rep (ABBA: order reversed on odd reps): {uds,pipe} x {same: A/A, cross: A/B} x {64 B, 64 KiB}.
set -u
B=$1; OUT=$2; A=$3; C=$4; REPS=$5
ctx() {
  printf '{"kind":"ctx","tag":"%s","host":"%s","kernel":"%s","model":"%s","gov":"%s","loadavg":"%s","stat_cpu":"%s","stat_a":"%s","stat_b":"%s","freq_a_khz":"%s"}\n' \
    "$1" "$(hostname)" "$(uname -r)" "$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //')" \
    "$(cat /sys/devices/system/cpu/cpu$A/cpufreq/scaling_governor 2>/dev/null)" "$(cat /proc/loadavg)" \
    "$(grep '^cpu ' /proc/stat)" "$(grep "^cpu$A " /proc/stat)" "$(grep "^cpu$C " /proc/stat)" \
    "$(cat /sys/devices/system/cpu/cpu$A/cpufreq/scaling_cur_freq 2>/dev/null)"
}
CFGS=()
for t in uds pipe; do for pl in "same $A" "cross $C"; do for s in "64 20000" "65536 3000"; do
  set -- $pl $s; CFGS+=("$t $1 $2 $3 $4"); done; done; done
ctx start >> "$OUT"
for ((r=0; r<REPS; r++)); do
  idx=($(seq 0 $((${#CFGS[@]}-1)))); [ $((r%2)) = 1 ] && idx=($(printf '%s\n' "${idx[@]}" | tac))
  for i in "${idx[@]}"; do
    set -- ${CFGS[$i]}
    "$B" run --transport $1 --client-core $A --server-core $3 --size $4 --n $5 --label "$2 rep=$r" >> "$OUT"
  done
done
ctx end >> "$OUT"
