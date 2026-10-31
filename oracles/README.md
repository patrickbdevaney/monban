# Oracles (the verify wall)

Oracles are never linked into the binary. A unit of implementation work is only assigned once its oracle exists
here, outside the implementer's write scope, and has been shown to FAIL on a negative control
(IMPLEMENTATION_PLAN §2: "an oracle that cannot be made red is not a gate").

## Contract (every oracle)

- Directory `oracles/<name>/`, self-contained. Nothing outside it is edited by the porter.
- `oracles/<name>/run [--subject <cmd-or-url>] [options]`: executable entry point. The last line is
  `<NAME>: PASS` or `<NAME>: FAIL (...)`, and the exit code is 0 only on PASS.
- `oracles/<name>/run --self-test`: runs the oracle against a deliberately mutated subject or reference
  (e.g. a lenient canonicalizer, a lowering that drops the tenant conjunct). It exits 0 only if the mutation was
  caught, printing `<NAME> SELF-TEST: PASS (...)`. Several mutations are better than one.
- Subject interface: until the Rust crate exists, the oracle runs against the reference model ported from
  research, and accepts `--subject` so the real implementation can be plugged in later without editing the oracle.
- If the oracle judges a production binary, put its path (relative to the repo root) in `default-subject`, so
  `ci/oracles.sh` passes `--subject` automatically.
- `README.md` records: what is checked (spec clause ids from `spec/SPEC_INVARIANTS.md`), the pass criterion, the
  research provenance (source paths under `research/state/raw/` and their sha256), what was re-run in-repo and the
  result, and known limits.
- Research artifacts are **untrusted input**: read and understand them before porting, never execute them in place,
  re-run the negative control in the repo.
- Python: stdlib only, invoked as `python3 -I`. No pip installs. Rust: its own workspace under the oracle dir
  (excluded from the main workspace), with its own `Cargo.lock`, built only through `ci/heavy.sh`.
- Laptop safety (research §0e): every compile, load test or simulation goes through `ci/heavy.sh`; ≤1.5 GB of disk per
  oracle including build output; delete `target/` after measuring; no Docker image >500 MB; no apt/sudo.

`needs` value `quiet-host` (2026-10-30): the oracle has wall-clock-sensitive checks (native-e2e lands cancels inside a
1.2 s hold), so it runs only on the local quiet runner, never on the shared LAN build box.
ct-dudect has it too (2026-10-30): its |t| crossed 4.5 twice at desktop load ≈ 13 and stays ≤ 2.8 on a quiet box.
