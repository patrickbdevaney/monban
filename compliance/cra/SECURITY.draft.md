Status: DRAFT, not published

# AEGIS security policy and coordinated vulnerability disclosure (draft)

This is a draft of the CVD policy that the CRA steward/manufacturer file set needs (COMPLIANCE_MAP §5). It is kept
under `compliance/cra/` on purpose: a SECURITY.md at the repository root (or in `.github/` or `docs/`) would be read
by GitHub and Forgejo as a live policy, and the operator has not set up vulnerability reporting (PREFLIGHT D-P1,
operator decision 2026-11-04). There is no contact channel today. Do not move this file until the operator publishes
the set.

## Reporting a vulnerability

- Contact: `<operator to supply>`
- Encryption key for reports: `<operator to supply>`
- Languages: `<operator to supply>`

Please include: the affected build (floor or cmvp, version, and the release's SHA256SUMS line), the profile and
configuration, steps to reproduce, and the impact you observed. Do not include personal data of third parties.

## What is in scope

- The golden reference build of AEGIS (`aegis-bin`, floor and cmvp builds) and its released artifacts.
- The claims in SECURITY_CLAIMS.md "What is claimed", at the rung each claim states. A counterexample to an R4
  model theorem, an R2 oracle disagreement, or a bypass of a fail-closed path is in scope.
- The release pipeline's signatures, TUF metadata, provenance and SBOM.

## What is out of scope, or reported upstream

- Components that are trusted, not verified (SECURITY_CLAIMS.md): hyper, h2, tokio, rustls, the AWS-LC C code, the
  Rust compiler, SQLite C, the kernel and libc. Report those to their upstream projects; we will track the advisory
  and issue a VEX statement for AEGIS builds.
- Third-party adapters, modules and handlers, and forked or modified binaries (the conformance report labels them
  `fork`).
- Volumetric denial of service. AEGIS does rate limiting and resource budgeting; it is not a network filtering
  product.

## What reporters can expect

| step | target |
|---|---|
| acknowledgement | `<operator to supply>` (proposed: 3 working days) |
| triage decision (in scope, severity) | `<operator to supply>` (proposed: 10 working days) |
| fix or mitigation for a confirmed issue | depends on severity; actively exploited issues follow the CRA Art 14 timeline in `PSIRT-runbook.md` |
| public advisory | CSAF 2.0 advisory and VEX (templates in `csaf/`), coordinated with the reporter |
| credit | in the advisory's acknowledgments, if the reporter wants it |

Default embargo: `<operator to supply>` (proposed: 90 days, or the fixed release date if earlier).

## Safe harbour

`<operator to supply>`: a safe-harbour statement for good-faith research, to be written with the license decision.

## Supported versions

See `support-period.draft.md`.
