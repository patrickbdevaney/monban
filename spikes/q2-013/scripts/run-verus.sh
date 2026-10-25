#!/usr/bin/env bash
# Verify the permit-ledger harness with the pinned Verus release under the 6 GB cap.
# Erasure check is on by default in this release (opt-out --no-erasure-check); `-V check-erasure` does not exist.
set -u
CI=$HOME/aegis-ci
export RUSTUP_HOME=$CI/rustup CARGO_HOME=$CI/cargo PATH=$CI/cargo/bin:$PATH
cd $CI/work/q2-013
MEM=${MEM:-6G} TMO=${TMO:-1800} $CI/bin/heavy $CI/verus/verus-x86-linux/verus ${1:-permit_ledger.rs} --time > logs/verus-${2:-permit_ledger}.log 2>&1
echo "verus exit=$?"
cat logs/verus-${2:-permit_ledger}.log | grep -v -E "^\s+(Average|Major|Minor|Voluntary|Involuntary|Swaps|File|Socket|Signals|Page)"
