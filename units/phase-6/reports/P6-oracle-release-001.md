# P6-oracle-release-001 report

Built `ci/release/verify.py` (release-verify oracle, F1 REL-1..REL-5, PLAN-6 D6, PREFLIGHT D-P2) and
`ci/release/fixtures/gen_release.py` (fixture generator, no keys). The release directory layout contract (v1) is
in the verify.py docstring. P6-release-001's pipeline must write exactly that layout.

## Acceptance
`ci/remote.sh --host kamrui ci/release/verify.py --self-test` returned:

    RELEASE-VERIFY: PASS (self-test: 5 clean releases accepted; 26/26 mutants refused, each with its own reason; throwaway keys deleted)

A mutant counts as refused only if exit = 1, the set of `REASON` tags is exactly {its expected tag}, and the final
line is `RELEASE-VERIFY: FAIL (<that tag>: ...)`.

- **Clean releases accepted:** v1 with pinned root and state; v1 TOFU with test keys; v2 after v1 (monotonic, root
  v1->v2); v2 again (identical metadata); a production-shaped release (no test markers) with pinned root and no flag.
- **Mutants from the unit file:**
  - 2/5 root signatures: `root-2of5` (anchor) and `root-rotation-2of5` (python-tuf UnsignedMetadataError), both
    REL-2 root-threshold.
  - One of the three signatures wrong: `sig-bad-{ed25519,slh-dsa-sha2-128s,ml-dsa-87}`, REL-1 signature-invalid.
  - Signatures over different digests: `sig-other-digest`, REL-1 digest-mismatch.
  - Test keys without the flag: `test-keys-no-flag` and `no-marker-file`, REL-4 test-keys.
  - Rollback: `rollback-targets` (targets v1 < trusted v2), REL-2 rollback.
  - Expired timestamp: `timestamp-expired`, REL-2 expired.
  - SBOM != attested: `sbom-mismatch`, REL-5 sbom-mismatch.
- **Extra mutants:**
  - root-policy-threshold2
  - sig-missing-ml-dsa-87
  - sig-wrong-alg-key (ML-DSA-44 in the 87 slot)
  - sums-mismatch
  - equal-version-timestamp
  - targets-expired
  - subject-mismatch
  - attest-sig-bad
  - attest-key-reuse
  - rebuild-mismatch (`--expect-sha256`)
  - artifact-tampered (post-TUF)
  - unlisted-file
  - private-key (D-P2)
  - tofu-without-test-keys
  - no-anchor
- **Meta check (red):** I disabled checks in temporary copies (deleted afterwards). Each copy made the self-test
  print FAIL:
  - digest-equality check removed: `sig-other-digest` passes, self-test FAIL.
  - equal-version-different-bytes rule removed: `equal-version-timestamp` passes, self-test FAIL.
  - REL-4 refusal removed: `test-keys-no-flag` and `no-marker-file` pass, self-test FAIL.

## Tools (integrator: cross-check with P6-spec-002 `#py:` rows)
P6-spec-002 has not pinned these yet, so I created a throwaway venv on kamrui at `~/aegis-ci/py-tuf` (Python 3.13.7).
Install command: `pip install --no-deps --only-binary :all: --require-hashes -r ~/aegis-ci/py-tuf/requirements.txt`.
All versions were published at least 7 days before 2026-11-04 (newest is pycparser, 2026-10-22).

| package | version | published | wheel sha256 |
|---|---|---|---|
| tuf | 7.0.1 | 2026-09-02 | d30434bda6e079ab303fb30d1b3006d939a10ca34783b1573d61cd9b802fa45c (py3-none-any) |
| securesystemslib | 1.6.0 | 2026-10-20 | 1c1aa00f058f4851f038d409c8ca4a727db854a91f07ec3a0fa047bb93e43e0e (py3-none-any) |
| urllib3 | 2.8.0 | 2026-09-15 | 0cf3cae568d36aa9576b28dfb35f11328f1cb974ca7647d9475ebb86c75ac6e3 (py3-none-any) |
| cryptography | 50.0.2 | 2026-09-30 | 9dab55f57c74c3cad24c323bacbbd04be4705ba6eb0d92e920b1fc4837ed5079 (cp311-abi3-manylinux_2_34_x86_64) |
| cffi | 2.1.1 | 2026-08-03 | a931079504ecc49efed7744c476a5c343a92fabf66dec2db95edb1b2fdc770e2 (cp313-manylinux_2_17_x86_64) |
| pycparser | 3.12 | 2026-10-22 | a076f3f489b39b43ed13563a1dafe42447445bec2e294154ec5c57fcdda4c85e (py3-none-any) |

How verify.py finds and checks the tools:
- It re-execs itself under `$AEGIS_PY_TUF_PYTHON` or `~/aegis-ci/py-tuf/bin/python` when `tuf` is not importable.
- It checks the installed versions against the `#py:<name> <version> ...` rows in ci/tools.lock (first two
  whitespace-separated columns). While there are no such rows, it uses its `FALLBACK_PINS`, which are the table above.
- If P6-spec-002 pins other versions, the tools.lock rows win and the venv must be rebuilt to match them.

OpenSSL is 3.5.3 at /usr/bin/openssl (override with `$AEGIS_OPENSSL`). verify.py requires version 3.5 or later.

## Design notes / interpretations (please review)
- **REL-2 "equal version is a rollback".** An equal version is accepted only if the metadata is byte-identical to
  what --state recorded. That covers an unrotated root and re-verifying the same release. An equal version with
  different bytes is refused.
- **Rollback state.** The state is verify.py's own `--state DIR` record (`root.json` plus `aegis-state.json`), written
  only on PASS. ngclient runs against a fresh temp dir bootstrapped from the trusted root, so it never verifies cached
  metadata in place of the release's metadata.
- **No state, no rollback check.** Rollback can only be detected with --state. The gate command
  (`verify.py --allow-test-keys target/release-out`) has no state, so it relies on the self-test for REL-2
  monotonicity.
- **Trust anchor.** The anchor is `--trusted-root` or the state root. TOFU on `tuf/1.root.json` is allowed only with
  `--allow-test-keys` and only for a release that is test-key marked. Without an anchor the release is refused.
- **Triple-signature keys.** The keys ship in `sigs/*.pub.pem` and are anchored through TUF targets, not pinned
  separately. A production verifier gets its key trust from the pinned root.
- **REL-3 scope.** verify.py compares the attested digest with build A (the shipped artifact) and with any
  `--expect-sha256` digests. The build B comparison is release-rebuild (D7), which can pass B's digest through
  `--expect-sha256`.
- **SBOM in SLSA v1.** The attested SBOM is `predicate.runDetails.byproducts[name=sbom.cdx.json]`. The SBOM is also a
  line in SHA256SUMS, so the triple signature covers it.

## Open
- The gate's `cmd` needs `ci/release/pipeline.sh` (P6-release-001).
- `ci/release/README.md` is outside my write_scope. The contract lives in the verify.py docstring.
- Rung: R1 for the verifier logic on fixture releases (executed self-test). R0 for REL-1..5 on real releases until the
  release-verify gate runs on pipeline output.
