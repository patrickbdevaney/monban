#!/usr/bin/env bash
# Scaling of the GCRA I1 trace harness with trace length N (solver time, not RAM, is the limit).
set -u
CI=$HOME/aegis-ci
export RUSTUP_HOME=$CI/rustup CARGO_HOME=$CI/cargo PATH=$CI/src/kani/scripts:$CI/cargo/bin:$CI/cbmc/usr/bin:$PATH
cd $CI/work/q2-013
for spec in "fixed_t 3" "fixed_t 4" " 2" " 3"; do
  set -- $spec; if [ $# -eq 2 ]; then h=gcra_window_bound_trace_$1; n=$2; else h=gcra_window_bound_trace; n=$1; fi
  sed "s/const N: usize = 6;/const N: usize = $n;/; s/unwind(7)/unwind($((n+1)))/g" budget.rs > budget_n$n.rs
  MEM=6G TMO=900 $CI/bin/heavy kani budget_n$n.rs --harness proofs::$h --exact > logs/kani-scale-$h-n$n.log 2>&1
  echo "$h N=$n exit=$? $(grep -E 'VERIFICATION:' logs/kani-scale-$h-n$n.log) $(grep HEAVY logs/kani-scale-$h-n$n.log)"
done
