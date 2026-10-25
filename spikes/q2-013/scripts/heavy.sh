#!/usr/bin/env bash
# kamrui stand-in for ci/heavy.sh: one cgroup scope with a hard memory cap (swap disabled so the cap is real),
# nice 15, timeout; prints GNU time -v (max RSS of the largest single process) and the cgroup memory.peak
# (whole process tree, includes page cache charged to the scope).
# usage: MEM=6G TMO=1800 [OOMPOL=continue] heavy.sh <cmd...>   (OOMPolicy=stop, the default, tears down the whole
# scope on an OOM kill, so the wrapper itself dies with 143; continue lets the job report its own exit code)
set -u
MEM=${MEM:-6G}; TMO=${TMO:-1800}
exec systemd-run --user --scope -q -p MemoryMax="$MEM" -p MemorySwapMax=0 -p OOMPolicy="${OOMPOL:-stop}" \
  nice -n 15 bash -c '
    cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
    start=$(date +%s.%N)
    timeout "$0" /usr/bin/time -v "$@"; rc=$?
    end=$(date +%s.%N)
    echo "HEAVY rc=$rc wall_s=$(echo "$end - $start" | bc) cgroup_peak_bytes=$(cat $cg/memory.peak) memmax=$(cat $cg/memory.max) oom_events=$(grep -E "^oom_kill " $cg/memory.events)" >&2
    exit $rc' "$TMO" "$@"
