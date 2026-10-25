#!/usr/bin/env bash
# bench-remote.sh SERVER_HOST CLIENT_HOST SERVER_ADDR OUT.jsonl SERVER_CORE REPS [SECS] [THREADS]
# Orchestrated from the laptop over ssh: server pinned to one core on SERVER_HOST (all its other cores left to the
# OS / background load), load generator on CLIENT_HOST. Binaries must already be at ~/aegis-spike-q3/hsbench.
set -u
SH=$1; CH=$2; SA=$3; OUT=$4; SC=$5; REPS=$6; SECS=${7:-8}; TH=${8:-64}; WARM=2; PORT=20443
D='~/aegis-spike-q3'
CFGS=()
for g in x25519 x25519mlkem768 p256mlkem768; do
  CFGS+=("$g hs 0 2 full" "$g hs 1 2 resumed" "$g reject 0 2 reject" "$g reject 0 0 reject_notickets")
done
ssh $SH "printf '{\"kind\":\"ctx\",\"tag\":\"start\",\"host\":\"%s\",\"kernel\":\"%s\",\"model\":\"%s\",\"gov\":\"%s\",\"loadavg\":\"%s\",\"stat_cpu\":\"%s\",\"stat_core\":\"%s\"}\n' \"\$(hostname)\" \"\$(uname -r)\" \"\$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //')\" \"\$(cat /sys/devices/system/cpu/cpu$SC/cpufreq/scaling_governor)\" \"\$(cat /proc/loadavg)\" \"\$(grep '^cpu ' /proc/stat)\" \"\$(grep '^cpu$SC ' /proc/stat)\"" >> "$OUT"
for ((r=0; r<REPS; r++)); do
  idx=($(seq 0 $((${#CFGS[@]}-1)))); [ $((r%2)) = 1 ] && idx=($(printf '%s\n' "${idx[@]}" | tac))
  for i in "${idx[@]}"; do
    set -- ${CFGS[$i]}
    ssh $SH "cd $D; s0=\$(grep '^cpu$SC ' /proc/stat); t0=\$(awk '{print \$14+\$15}' /proc/\$(pgrep -x tailscaled)/stat); echo \"\$s0\" > s0; echo \$t0 > t0; nohup taskset -c $SC ./hsbench server --port $PORT --group $1 --mode $2 --tickets $4 --secs $SECS --warm $WARM --label '$5 rep=$r' > srv.out 2>&1 < /dev/null & ( sleep $((WARM+SECS/2)); cat /sys/devices/system/cpu/cpu$SC/cpufreq/scaling_cur_freq > frq ) > /dev/null 2>&1 &"
    sleep 0.5
    ssh $CH "$D/hsbench client --addr $SA:$PORT --group $1 --mode $2 --resume $3 --threads $TH --secs $((SECS+WARM))" >> "$OUT"
    sleep 0.5
    ssh $SH "cd $D; while pgrep -f 'hsbench serve[r] --port $PORT' >/dev/null; do sleep 0.2; done; s1=\$(grep '^cpu$SC ' /proc/stat); t1=\$(awk '{print \$14+\$15}' /proc/\$(pgrep -x tailscaled)/stat); sed \"s/}\\\$/,\\\"case\\\":\\\"$5\\\",\\\"rep\\\":$r,\\\"core_stat_before\\\":\\\"\$(cat s0)\\\",\\\"core_stat_after\\\":\\\"\$s1\\\",\\\"freq_mid_khz\\\":\$(cat frq),\\\"tailscaled_ticks\\\":\$((t1-\$(cat t0))),\\\"loadgen\\\":\\\"remote $CH via $SA\\\",\\\"others\\\":\\\"\$(ps -eo pcpu,comm --sort=-pcpu | sed -n 2,4p | tr -s ' ' | tr '\n' ';')\\\"}/\" srv.out" >> "$OUT"
    PORT=$((PORT+1))
  done
done
ssh $SH "printf '{\"kind\":\"ctx\",\"tag\":\"end\",\"host\":\"%s\",\"kernel\":\"%s\",\"model\":\"%s\",\"gov\":\"%s\",\"loadavg\":\"%s\",\"stat_cpu\":\"%s\",\"stat_core\":\"%s\"}\n' \"\$(hostname)\" \"\$(uname -r)\" \"\$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //')\" \"\$(cat /sys/devices/system/cpu/cpu$SC/cpufreq/scaling_governor)\" \"\$(cat /proc/loadavg)\" \"\$(grep '^cpu ' /proc/stat)\" \"\$(grep '^cpu$SC ' /proc/stat)\"" >> "$OUT"
