#!/usr/bin/env bash
# Kani exit-code semantics under forced OOM. Each case prints kani's exit code and verdict line.
set -u
CI=$HOME/aegis-ci
export RUSTUP_HOME=$CI/rustup CARGO_HOME=$CI/cargo
BASE=$CI/src/kani/scripts:$CI/cargo/bin:$CI/cbmc/usr/bin:$PATH
cd $CI/work/q2-013
run() { # name mem extra-path vlimit
  PATH=$3$BASE OOMPOL=${OOMPOL:-stop} CBMC_VLIMIT_KB=$4 MEM=$2 TMO=1500 $CI/bin/heavy kani oom.rs --harness oom_with_real_bug --exact > logs/oom-$1.log 2>&1
  rc=$?
  echo "$1: kani_exit=$rc | $(grep -E 'VERIFICATION:' logs/oom-$1.log | tr '\n' ' ') | $(grep -E -i 'out of memory|CBMC failed|status' logs/oom-$1.log | grep -v -E '^\s*(Exit status|Command)' | head -3 | tr '\n' ' ') | $(grep HEAVY logs/oom-$1.log)"
}
if [ "${ROUND:-1}" = 1 ]; then
  run cgroup-150M 150M "" 0                       # OOMPolicy=stop: systemd tears the scope down
  run ulimit-400M 6G "$CI/bin/cbmc-ulimit:" 400000 # bad_alloc inside CBMC: the #4905 path
  run control-6G 6G "" 0                          # K=32 at 6 GB (did not finish in 25 min, peak 2.09 GB)
else
  # round 2: kani's own exit code on a cgroup OOM kill, and a positive control that finishes (K=8)
  OOMPOL=continue run cgroup-150M-continue 150M "" 0
  sed 's/const K: usize = 32;/const K: usize = 8;/; s/unwind(33)/unwind(9)/' oom.rs > oom_k8.rs
  PATH=$BASE MEM=6G TMO=1500 $CI/bin/heavy kani oom_k8.rs --harness oom_with_real_bug --exact > logs/oom-control-k8.log 2>&1
  echo "control-k8-6G: kani_exit=$? | $(grep -E 'VERIFICATION:|real bug' logs/oom-control-k8.log | tr '\n' ' ') | $(grep HEAVY logs/oom-control-k8.log)"
fi
