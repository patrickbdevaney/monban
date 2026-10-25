#!/usr/bin/env bash
# Run each Kani harness serially under the 6 GB CI cap. usage: run-kani.sh [harness...]
set -u
CI=$HOME/aegis-ci
export RUSTUP_HOME=$CI/rustup CARGO_HOME=$CI/cargo PATH=$CI/src/kani/scripts:$CI/cargo/bin:$CI/cbmc/usr/bin:$PATH
W=$CI/work/q2-013; cd $W
H=${*:-rst_step_inductive rst_rate_bound_trace gcra_step gcra_window_bound_trace}
for h in $H; do
  echo "=== $h"
  MEM=${MEM:-6G} TMO=${TMO:-1800} $CI/bin/heavy kani budget.rs --harness "proofs::$h" --exact > logs/kani-$h.log 2>&1
  echo "kani exit=$?"
  grep -E "VERIFICATION:|Verification Time|CBMC failed|out of memory|HEAVY|Maximum resident|Elapsed|Complete -|Failed Checks" logs/kani-$h.log
done
