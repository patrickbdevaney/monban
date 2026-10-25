# kani-oom -- model checker OOM/timeout misread as "verification passed" (SPEC-ONLY)

Source: Kani #4905 (proof-checker false PASS record), fix lineage #4910
  https://github.com/model-checking/kani/pull/4910
  (ARCHITECTURE AA12 "proof-checker false PASS"; research note vfg-kani-footprint-and-gate-failures)

## What it exploits
When Kani/CBMC runs out of memory or hits a timeout, some wrapper/exit-code handling reported
a non-failure, so an UNFINISHED check is mistaken for a successful (safe) verdict. Memory
exhaustion => no counterexample found => "looks" verified, though nothing was proved.

## Input (data)
A harness whose state space is large enough to exhaust the 6 GB cap (research 0e) or exceed
HEAVY_TIMEOUT. Not shipped/executed: Kani and CBMC are not installed on this host.

## Expected wrong verdict
Process killed by OOM/timeout, but the surrounding script treats a nonzero-but-not-{0,10}
exit (or a swallowed signal) as PASS.

## The gate rule that MUST catch it
Kani's exit code MUST be in {0, 10} to be a VALID RESULT: 0 = verification success,
10 = verification failure (counterexample). ANY OTHER exit (including OOM kill 137,
timeout 124, CBMC error) = FAIL, never PASS. OOM and timeout are explicitly FAIL. Run serial,
under the 6 GB / HEAVY_TIMEOUT cap via ci/heavy.sh, and assert the exit code is exactly 0
before counting a harness as discharged.

## Why SPEC-ONLY
Kani/CBMC are not installed here. Recorded as the exit-code hardening the implementation-phase
Kani gate (R-FORMAL-3) must enforce.
