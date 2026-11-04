# P6-compliance-001 report (spec author, 2026-11-04, base main 93e3022)

## Built
- `compliance/COMPLIANCE_MAP.md`: the template instantiated, sections 1–8, with the template's wording rules restated
  (and enforced).
  - §4 has 15 rows: the template's 14, plus SC-5 for admission control, described as rate limiting and resource
    budgets. Each row carries `evidence_kinds` (≥2, `;`-separated) and a `gate_id` list (32 distinct names, all
    real gates in `gates/phase-6.toml`). The residuals copy what the reports measured. Examples:
    - fips-binary's relative-path defect;
    - cmvp-client-policy ERROR at R0 (P6-cmvp-002 items 5 and 6);
    - test keys only (D-P2);
    - release-rebuild pending P6-release-002 (no report yet);
    - STEK rotation not gated (R0).
  - §4.1 is the SA-17(1) theorem table. It has 22 frozen theorems from Select, Combine, Token, Lowering, ThreeValued
    and Vacuity. Each row gives the rung (R4 model; Select also has R2 correspondence through select-drt) and what
    the theorem does NOT cover.
  - The trusted-not-verified list (hyper, h2, tokio, rustls, the AWS-LC C code, rustc) and the D15/D17 cmvp facts:
    - ML-DSA is not approved in AWS-LC 3.1.0;
    - P-CNSA is refused on cmvp;
    - the gov profiles use ECDSA-P384 on cmvp;
    - approved mode is claimed only on AL2023 with the cmvp lock.
  - Also: laptop numbers are provisional; interop is [A] measured; Kani covers share parsing only.
- `compliance/cra/` (D-P1, all drafts):
  - the Markdown drafts: `SECURITY.draft.md` (contact `<operator to supply>`), `PSIRT-runbook.md`,
    `sbom-statement.draft.md` (points to `ci/release/jobs/sbom.sh` → `sbom.cdx.json`, REL-5),
    `support-period.draft.md`, `eu-declaration-of-conformity.draft.md`, `steward-attestation.draft.md`;
  - `csaf/advisory-template.json` and `csaf/vex-template.json`, carrying `document.notes` "Status: DRAFT, not
    published" and `tracking.status = draft`;
  - `schemas/csaf_json_schema.json`: the official OASIS CSAF 2.0 schema, unmodified, fetched with User-Agent aegis-ci;
    sha256 29c114b3… pinned in the checker and in `schemas/SOURCES.txt`.
  - Nothing was written at the repo root: no LICENSE, no SECURITY.md, no GitHub settings.
- `ci/compliance.py check | --self-test`: `python3 -I`, stdlib only.
  - It has a built-in validator for the JSON-Schema keyword subset the CSAF schema uses. Unknown keywords and
    non-local `$ref`s are errors.
  - If `jsonschema` can be imported, it runs as a second validator.
  - It adds CSAF profile checks: category per file, product-id references (6.1.1), VEX not-affected justification
    and affected remediation, and no `scores` (the CVSS schemas are not vendored).
  - It does a structural CycloneDX check on any `*.cdx.json` under compliance/. There are none today; the real SBOM
    is checked by release-verify.
  - It checks for SECURITY.md at the root, in `.github/` and in `docs/`, and for LICENSE/COPYING at the root.
  - It enforces the wording rules: FedRAMP-ready/-authorized, WAF, admission+firewall on one line, and "approved
    mode" without AL2023.
  - It requires the trusted list and the ML-DSA statement to be present.

## Acceptance
```
$ python3 -I ci/compliance.py check
COMPLIANCE: PASS (15 control rows, 32 gate ids in gates/phase-6.toml, 22 SA-17(1) theorems frozen in spec/STATEMENTS.sha256, 8 CRA drafts unpublished, 2 CSAF 2.0 documents schema-valid (validator: builtin+jsonschema), 0 CycloneDX; no root SECURITY.md, no LICENSE)
$ python3 -I ci/compliance.py --self-test
COMPLIANCE SELF-TEST: PASS (baseline clean; 31/31 mutants red with the exact expected tag)
```
- Both commands also PASS with `python3 -I -S`, where jsonschema is absent so only the built-in validator runs, and
  with `/usr/bin/python3` 3.12.3.
- The self-test needs each mutant's tag set to equal the expected set exactly. The unit's mutants are all covered:
  - unknown gate_id;
  - an SA-17(1) theorem not in STATEMENTS, plus a `def` used as a theorem and an R2 rung;
  - a CRA file without the DRAFT header, plus a JSON file with status final;
  - SECURITY.md at the root and in `.github/`;
  - LICENSE at the root;
  - 'FedRAMP-ready';
  - 'WAF' and 'firewall' used for admission;
  - invalid CSAF: wrong version, missing tracking.id, a bad date-time, broken JSON syntax, a dangling product id,
    an unjustified not_affected, the wrong category, and a tampered schema.
- Extra mutants: evidence kinds <2, a missing control row, a missing SSDF (draft) label, a missing trusted
  component, a missing ML-DSA statement, a missing CRA file, a missing support-period line, an e-mail contact, and
  an invalid CycloneDX file.
- Red before green: the first check run was red on my own map. The template evidence id `ops.cra-annex3-waf-risk`
  matched a case-insensitive WAF rule. The rule is now case-sensitive for `WAF` and case-insensitive for "web
  application firewall". The id stays allowed and the WAF mutants stay red. The first self-test had the ML-DSA
  mutant green, because the statement appears twice; the mutant now removes every occurrence.

## Open
- Map residuals that depend on other units:
  - P6-cmvp-002 open items 5 and 6 (the fips-binary relative path; the cmvp-client-policy R0 ERROR). Until 6 is green,
    the VEX "not affected" justification for 0349/0382 has no current gate log, and the map says so.
  - P6-release-002 (release-rebuild) has no report yet.
  - When those land, the integrator updates the §3/§4 residual text. The checker does not depend on them.
- The 0x11ED FIPS-boundary check (PLAN-6 open question 2) is not done, so 0x11ED is not listed under the FIPS profile.
