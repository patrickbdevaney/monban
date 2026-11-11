Status: DRAFT, not published

# AEGIS PSIRT runbook (draft)

Draft procedure for handling a vulnerability in AEGIS (COMPLIANCE_MAP §5, §1 row 2026-09-11). Reports arrive through
the channel in the root `SECURITY.md` (GitHub private vulnerability reporting). The CRA parts are not in force: AEGIS
is distributed free and not monetised (operator decision 2026-11-11). The reporting deadlines below bind a
manufacturer that makes AEGIS available on the market in the course of a commercial activity (CRA Art 14), and an
open-source steward under Art 24(3) from 2027-12-11. Which role applies is an operator decision.

## Roles

| role | holder |
|---|---|
| PSIRT lead (decides severity, embargo, publication) | `<operator to supply>` |
| SRP submitter (ENISA Single Reporting Platform account) | `<operator to supply>` |
| release manager (holds the release keys, TUF roles) | `<operator to supply>` (real key custody is PREFLIGHT §P4) |

## Clock

**T0 = the moment AEGIS becomes aware** of an actively exploited vulnerability or a severe incident. T0 is stamped as
an event in the AEGIS audit tlog (tamper-evident, signed checkpoint), so the clock cannot be backdated.

| deadline | action (manufacturer role, CRA Art 14) |
|---|---|
| T0 | open a private tracking record; stamp T0 in the tlog; start the embargo |
| T0 + 24 h | **early warning** via the ENISA SRP to the CSIRT coordinator (and ENISA): which member states, whether exploitation is known to be malicious |
| T0 + 72 h | **vulnerability notification** via the SRP: general nature, exploit, corrective or mitigating measures, sensitivity |
| fix + ≤14 days | **final report** for a vulnerability: description, severity and impact, malicious actor information if available, the security update |
| T0 + 1 month | **final report** for a severe incident |
| at fix | inform impacted users (CSAF advisory + VEX), in a structured, machine-readable format |

For vulnerabilities that are not actively exploited, the Art 14 notification duties do not start, but the CVD
policy in the root `SECURITY.md` applies.

## Procedure

1. **Intake.** Record the report verbatim. Acknowledge within the CVD target. Assign an internal id `AEGIS-YYYY-NNNN`.
2. **Triage.** Reproduce on the golden build (floor and cmvp). Map it to a SECURITY_CLAIMS.md row: does it break a
   claim (which rung)? Is it in a trusted, not verified component (hyper, h2, tokio, rustls, AWS-LC C, rustc)? If
   upstream: report upstream, track the advisory, prepare a VEX statement.
3. **Severity.** Score it (CVSS v3.1 or v4, recorded in the advisory). Decide whether Art 14 applies (actively
   exploited).
4. **Fix.** The fix lands with a regression test or oracle case that is red before the fix. If a proof or frozen
   statement must change, that is a spec-author change with a re-freeze (CLAUDE.md); a check is never weakened to
   close an issue.
5. **Release.** Run the release pipeline (`ci/release/pipeline.sh`) for floor and cmvp; `release-verify` and
   `release-rebuild` must be green; the SBOM and the attestation travel with the release.
6. **Advisory.** Fill `csaf/advisory-template.json` and `csaf/vex-template.json`; set `tracking.status` to `final`;
   validate against the vendored CSAF 2.0 schema (`python3 -I ci/compliance.py check` does this for the templates).
7. **Notify.** SRP final report (deadline above), CSAF publication, reporter credit.
8. **Close.** Post-incident review; add the case to the relevant oracle corpus.

## Exception ledger

An accepted advisory in a dependency is recorded in `supply-chain/exceptions.toml` with an approver, a reason, an
expiry and a gate log as evidence (`cargo xtask ledger-check`). A VEX "not affected" statement for a release cites
the same gate log from the same release run, or is not issued.
