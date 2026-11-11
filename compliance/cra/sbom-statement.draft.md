Status: DRAFT, not published

# SBOM statement (draft)

Every Monban release carries a software bill of materials in CycloneDX JSON (CRA Annex I Part II (1); COMPLIANCE_MAP
§4 row SR-2/3/5).

- **Where it comes from.** Release job 2 (`ci/release/jobs/sbom.sh`) runs the pinned `cargo-cyclonedx`
  (`ci/tools.lock`) for `monban-bin` with the profile's features, inside the same digest-pinned AL2023 build image,
  with no network. The pipeline is `ci/release/pipeline.sh --profile floor|cmvp`.
- **What is shipped.** `sbom.cdx.json` in the release directory (layout v1, `ci/release/verify.py` docstring). It is
  listed in `SHA256SUMS`, so the triple signature (Ed25519 + SLH-DSA-SHA2-128s + ML-DSA-87) covers it, and it is a
  byproduct in the SLSA provenance attestation (`ci/release/jobs/attest.py`).
- **How it is checked.** `ci/release/verify.py` refuses a release whose SBOM digest differs from the attested one
  (REL-5, mutant `sbom-mismatch`); gate `release-verify`. The binary also embeds its dependency list
  (`cargo auditable`).
- **Scope.** The SBOM lists the Rust crates linked into the binary, including the C libraries they bundle (AWS-LC,
  SQLite). It does not list the kernel, libc or the build host.
- **Limits.** Releases so far are built with throwaway test keys only (PREFLIGHT D-P2); no SBOM has been published.
  A CBOM (cryptographic inventory) is derivable from the lock and the SBOM but is not a separate artifact yet.
