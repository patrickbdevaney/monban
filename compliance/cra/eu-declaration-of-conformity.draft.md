Status: DRAFT, not published

# EU declaration of conformity (draft, CRA Annex V structure)

Not signed, not issued. A declaration of conformity is drawn up only by a manufacturer that places AEGIS on the EU
market, after the conformity assessment. Self-assessment (module A, internal control) is the intended route; it is
available only if AEGIS is not an important product of class II or a critical product. Admission control is
therefore described as rate limiting and resource budgeting, not as a network filtering product (COMPLIANCE_MAP
wording rules). Whether AEGIS falls under Annex III at all is `<operator to supply>` (legal review).

1. Product: AEGIS web server, version `<operator to supply>`, builds floor and cmvp; identified by the release
   `SHA256SUMS` digest.
2. Manufacturer: `<operator to supply>` (name and address); authorised representative: `<operator to supply>`.
3. This declaration is issued under the sole responsibility of the manufacturer.
4. Object of the declaration: the release identified in 1, with its SBOM (`sbom-statement.draft.md`).
5. The object is in conformity with Regulation (EU) 2024/2847 (Cyber Resilience Act) `<and any other Union
   legislation: operator to supply>`.
6. Harmonised standards or common specifications applied: `<operator to supply>` (none harmonised for this product
   category at the time of drafting).
7. Notified body: none (internal control, module A), unless the operator's legal review finds otherwise.
8. Additional information: support period (`support-period.draft.md`); vulnerability handling (`SECURITY.md` at the repo root,
   `PSIRT-runbook.md`); technical documentation: `research/ARCHITECTURE.md`, SECURITY_CLAIMS.md,
   `compliance/COMPLIANCE_MAP.md` and the gate logs of the release run.

Signed for and on behalf of: `<operator to supply>`
Place and date of issue: `<operator to supply>`
Name, function, signature: `<operator to supply>`

Note on claims: machine-checked proofs in this project cover Lean models (rung R4), not the Rust code, and no
regulator credits them; the trusted, not verified components (hyper, h2, tokio, rustls, the AWS-LC C code, rustc)
are listed in SECURITY_CLAIMS.md.
