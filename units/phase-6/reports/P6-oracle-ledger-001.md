# P6-oracle-ledger-001 report

Built `xtask/src/ledger.rs`: `cargo xtask ledger-check [--ledger PATH] [--evidence-dir DIR] [--self-test]` (PLAN-6 D10).

Integration (P6-spec-002, single writer of xtask/src/main.rs) needs exactly these two lines:

    mod ledger;                                              // next to the other `mod` lines
    Some("ledger-check") => ledger::run(&args),              // in main()'s match; run() skips the leading "ledger-check"

(`&args[1..]` would trip clippy::indexing_slicing; `&args` is correct.)

## Checks
- strict TOML-subset parse (comments, `[[exception]]`, `key = "basic string"`); bad lines, duplicate keys, unknown keys fail.
  xtask has no dependencies (no toml crate), so no dep was added.
- required non-empty: crate, version, kind, reason, approver, expires; expires a real YYYY-MM-DD, not before today (UTC).
- kind in {cooldown-bypass, advisory-accepted}.
- advisory-accepted also needs advisory, evidence, evidence_must. The log `<evidence-dir>/<file name of evidence>` must
  exist, contain evidence_must as a whole line, end in `[exit 0]`, and have mtime >= mtime of `<evidence-dir>/.run-start`.
  No marker: fail closed.

## Freshness mechanism (integrator action needed)
ci/run-gates.py writes no run-start marker today, and its journal is only written at the end of the run, so nothing
during a run identifies the current run. Needed one-line change in ci/run-gates.py main(), right after the
`os.makedirs(... "logs" ...)` line:

    open(os.path.join(outdir, "logs", ".run-start"), "w").write(head + "\n")

A log from an earlier run (whose sha is that run's) predates the marker and is rejected.

## Results (2026-11-04)
- `cargo xtask ledger-check` -> `LEDGER-CHECK: FAIL (2 violation(s) in 27 entries)`: block-buffer@0.10.4 is
  advisory-accepted with no `evidence`/`evidence_must`. There is no 0349 entry yet. Expected red per the acceptance.
- `cargo xtask ledger-check --self-test` -> `LEDGER-CHECK SELF-TEST: PASS (clean ledger green; 20/20 mutants red)`.
  The mutants include all five from the unit file plus 15 more.
- Meta check: with the expiry comparison disabled, the self-test reports `FAIL (mutant not rejected: expired entry)`.
- `ci/heavy.sh cargo clippy -p xtask --all-targets -- -D warnings` is clean; the unit tests (dates, strings) pass.

## Open
- P6-spec-002 must give the existing block-buffer advisory-accepted entry evidence, or the gate stays red. D10 as
  written applies to every advisory-accepted entry.
- The 0349 entry's `evidence_must` must be the exact PASS line that oracles/cmvp-binary/client-policy prints
  (P6-oracle-fips-001). The self-test uses `CLIENT-POLICY: PASS (compiled-out)` only as a placeholder.
