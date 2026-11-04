# P6-conformance-001 report (implementer)

Built `conformance/run` (python3 -I, stdlib + optional jsonschema). The contract is in its docstring.

## Level map (real gate names only; the runner refuses to start if a member is not a gate defined before `conformance`)
- C0: fips-lock budget layering no-cedar-in-bin no-wasmtime-in-bin unsafe-sites panic-abort config-totality.
  cmvp adds cmvp-client-policy and **fips-binary**. fips-binary is not in the brief's list. I added it because it is a
  static check of the cmvp binary ('AWS-LC FIPS 3.1.0', linked module). It makes the gate stricter, not weaker.
- C1: tls-verdicts h2-conformance transport-limits reverse-proxy-e2e kx-interop kx-kat. cmvp adds clienthello-cmvp.
- C2: p2-hostile-host p2-hostile-worker mcp-gateway `oracles-remote[ssrf-corpus]`.
- C3 (reported, not gated): select-drt and lowering-{read,write}-{sqlite,pg,redis}. C4: no gate, so total 0.
- p2-subject (kind module): C2 only (p2-hostile-worker, p2-hostile-host).
- Expected members that have no gate of their own:
  - ssrf corpus: no ssrf gate exists. The SSRF-CORPUS oracle runs inside oracles-remote, so this member requires that
    gate's `[ssrf-corpus] SSRF-CORPUS: PASS` / `SELF-TEST: PASS` lines.
  - "config pin" (D8 C0).
  - C4 traceability.

## Pass rule
A gate passes only if all of these hold:
- `.run-start` exists;
- the -cmd.log exists, is newer than `.run-start`, starts with `$ <the toml cmd>` (plain, or with run-gates' remote
  wrapping), and its last line is `[exit 0]`;
- the -selftest.log meets the same conditions when the gate has a selftest.

Anything else counts as fail. No result is ever reported as skipped.

## Artifact digest (needs other units)
The digest comes only from logs that pass the rule above:
- `RELEASE-PIPELINE: PASS (<profile>, artifacts/aegis-<profile> sha256 <hex>` (ci/release/pipeline.sh prints this),
  read from the release-verify log (floor) and the release-rebuild log (floor, cmvp);
- `CONFORMANCE-ARTIFACT: <subject> sha256 <hex>`, found in any of the subject's gate logs.

All digests found for a subject must agree. If none is found, or two differ, there is no report and the gate fails.

**Open items:**
1. release-rebuild (P6-release-002) must let pipeline.sh's PASS line for cmvp reach its log.
2. Nothing prints a p2-subject digest yet. The integrator should append something like
   `&& printf 'CONFORMANCE-ARTIFACT: p2-subject sha256 %s\n' "$(sha256sum target/p2/release/aegis-p2 | cut -c1-64)"`
   to the p2-hostile-host cmd (gates/phase-6.toml is outside my scope).
3. Until that happens the conformance gate stays red. I chose this on purpose: without a digest no report can be written.

## Signing
- Per-run Ed25519, SLH-DSA-SHA2-128s and ML-DSA-87 keys are generated in a mktemp dir on kamrui with /usr/bin/openssl
  3.5.3. The script removes the dir and confirms with `DESTROYED`.
- Only canonical bytes go over ssh stdin. Only public keys and signatures come back.
- Every report has `test_keys: true`. Public keys are written to gates/out/conformance/keys/.
- Each report is re-read from disk, validated (strict validator, plus jsonschema 2020-12 when importable), and all
  three signatures are verified on kamrui. Key types are checked too.
- I checked kamrui /tmp afterwards: no leftover dirs and no PRIVATE KEY files.

## Acceptance
- `conformance/run --self-test` → `CONFORMANCE SELF-TEST: PASS (15 checks ...)`.
- `conformance/run --logs gates/out/logs` → `CONFORMANCE: FAIL (aegis-bin-floor no report; ...)`. This worktree has
  no phase-6 run, so there is no .run-start and no logs. The command is red by design until a full
  `ci/run-gates.py --phase 6` run has produced the logs and the digest lines.
- Self-test red: two runner mutants, run from a temporary copy that was then deleted.
  - Freshness check disabled → `CONFORMANCE SELF-TEST: FAIL (stale-log)`.
  - `[exit N]` check loosened → `FAIL (fork-tls-client-in-cmvp, selftest-fails, digest-from-failing-log)`.
- jsonschema on the laptop has no rfc3339-validator, so it skips `format: date-time`. The strict validator checks it.
