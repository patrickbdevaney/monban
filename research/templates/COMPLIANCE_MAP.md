# COMPLIANCE_MAP (template, v4, 2026-10-25)

Source: ARCHITECTURE.md v4 §3.11, R-OPS-1/3/4/10, R-PQC-2/3/8. Re-verified 2026-10-25 where marked ✓. **Wording rules first:**
- Never "FedRAMP-ready" or "FedRAMP-authorized"; authorization belongs to the deploying CSP.
- No NIAP PP exists for web servers/gateways (`ops.niap-no-pp` C). If CC is demanded: PP_APP + TLS package, or an EUCC/CC EAL4+ ST; EAL6/7 is a separately funded decision (~3.5 years, millions).
- **No regulator credits machine-checked code proofs** (`sc.regulator-2025-26-statements` B). The formal **policy model** maps to SA-17(1); test legs stay mandatory.
- CRA: describe admission control as rate limiting, not a WAF/firewall (Annex III class II risk, `ops.cra-annex3-waf-risk` C).
- SSDF 1.2 controls are labelled "draft" (IPD 2025-12-17 ✓); SSDF 1.1 is final.
- FIPS "approved mode" only on Amazon Linux 2023 with the cmvp lock; never on household Debian/Ubuntu/musl builds.

## 1. Dated obligations

| date | obligation | Monban response | grade |
|---|---|---|---|
| 2026-01-01 | CISA bad practices: memory-safety roadmap or MSL (voluntary) | Rust; roadmap row lists C residue (aws-lc, SQLite, kernel) | A ✓ |
| 2026-06-22 | **EO 14412**: federal HVA/high-impact PQ key establishment by 2030-12-31, signatures by 2031-12-31; CBOM guidance in 270 days; FAR rule ~2026-12; NSS excluded | P-UNIVERSAL / P-PUBLIC-WEB; CBOM from the lock | A ✓ |
| **2026-09-11** | CRA Art 14 manufacturer reporting via ENISA SRP: early warning 24 h, notification 72 h, final report 14 d after fix (vulns) / 1 month (incidents) | binding on any monetized distributor; PSIRT runbook; CSAF/VEX | A ✓ (`v2.cra-monetization-trigger` B) |
| 2026-09-21 | FIPS 140-2 certificates historical | only 140-3 modules; AWS-LC 3.1.0 is 140-3 | B |
| 2027-01-01 | CNSA 2.0: new NSS acquisitions CNSA-capable | P-CNSA opt-in | C (NSA FAQ 403) |
| **2027-12-11** | CRA full application; **open-source steward reporting Art 24(3)** | steward file set published regardless | A ✓ |
| 2030 | CNSA 2.0 software signing exclusive; ASD ISM: ECDH/ECDSA/RSA and ML-KEM-768/ML-DSA-65 not approved beyond 2030; NIST IR 8547 draft deprecates 112-bit | ML-DSA-87 release signature; P-UNIVERSAL (0x11ED, our KxGroup) | C / A (`r4e10.asd-ism-2026-09`) / B ✓ |
| 2033 | CNSA 2.0 browsers/servers/cloud exclusive | P-CNSA on NSS | C |
| 2035 | IR 8547 draft disallows quantum-vulnerable PK; NSM-10 goal | profiles | B |

## 2. PQ profiles × jurisdictions [A primaries / B decision]

| profile | groups | signatures | jurisdictions | status |
|---|---|---|---|---|
| P-PUBLIC-WEB | 0x11EC, 0x11ED, 0x11EB, X25519, P-256 | ECDSA-P256 (WebPKI) | general | shipping |
| P-UNIVERSAL | 0x11ED only | ML-DSA-87 / ECDSA-P384 private | the only group in the intersection of US-civil, EU (BSI/ANSSI), UK, AU, CA, JP post-2030 lists | **0x11ED is Monban-owned** (rustls #3293 closed unmerged); KATs + interop + Kani before claiming; FIPS-boundary check for cmvp |
| P-BSI-ALT | 0x11ED, 0x11EB | — | DE | as above |
| P-CNSA | ML-KEM-1024 (0x0202) + ML-DSA-87 | ML-DSA-87 | US NSS (opt-in) | pure ML-KEM non-conformant in FR (ANSSI-PG-083 v3.00), hybrid-only in BSI TR-02102 |
| FIPS (cmvp lock) | SECP256R1MLKEM768, P-256, P-384 (+0x11ED after boundary check) | ECDSA (ML-DSA not approved in AWS-LC 3.1.0) | US federal | AL2023 OEs only |

All government profiles: TLS 1.3 only, AES-GCM only; no 0-RTT, X25519, Ed25519, ChaCha20, TLS 1.2.

## 3. FIPS 140-3 path [A mechanics / B decision]
Two locks: **floor** (rustls 0.23.46 + aws-lc-rs 1.18.x, AWS-LC FIPS 4.2.0 source, uncertified, no claim) and **cmvp** (rustls =0.23.43 + aws-lc-rs =1.15.3 + aws-lc-fips-sys =0.13.11 = AWS-LC FIPS 3.1.0, CMVP #5298 dynamic / #5314 static). No lock satisfies rustls ≥0.23.44 with fips-sys 0.13.11 (`r4tri.no-co-resolvable-lock` A 0.95). ML-KEM approved; ML-DSA/SLH-DSA not; X25519 outside. No ML-DSA CMVP certificate exists anywhere (✓). cmvp clients compiled out or PQ-only (RUSTSEC-2026-0349 is client-side). Evidence emitted: gate log, `/healthz` fips_status, audit event, binary string `AWS-LC FIPS 3.1.0`. Reversal: AWS-LC 4/5 certificate matching a fips-sys version (none on 2026-10-25 ✓) or rustls 0.24.

## 4. Control map (NIST 800-53 r5 5.2.0 ↔ FedRAMP 20x KSI v2026.10.13.01 ↔ SSDF ↔ CRA Annex I)

Row schema: `{control, ksi[], ssdf[], cra[], mechanism, evidence_kinds[≥2], evidence_artifact, gate_id, residual, grade, last_verified}`.

| control | KSI | SSDF | CRA | mechanism | machine evidence | residual |
|---|---|---|---|---|---|---|
| SC-13 | SVC-SIN | — | I(2)(e) | cmvp lock + FIPS-string gate + `--fips-check` | gate 8 log; `/healthz`; audit | AL2023-only; advisory ledger |
| SC-8/8(1) | SVC-SIN, CNA-MAT | — | I(2)(e) | TLS 1.3-only listeners per profile | ClientHello matrix (gate 21) | public listener classical for X25519-first/classical-only clients |
| SC-12 | SVC-ASM | — | I(2)(e) | credentials + atomic swap + STEK ≤24 h | rotation audit events | operator-held roots |
| SI-7/7(1)/7(15) | SVC-VRI | PS.2.1, PS.3.2 | I(2)(f) | triple-signed release, SLSA L3, self-digest at start | attestation, TUF metadata, repro hashes | token-published core crates |
| CM-7 | CMT-RMV | PW.9 | I(2)(a)(c) | default-deny config; systemd ≤2 | default-config boot gate; systemd-analyze log | operator "Unrestricted" overrides (CI-gated) |
| CM-2 | CMT-RMV | — | — | config hash at boot, in every event | audit log | — |
| AU-2/3/12 | MLA-LET | — | I(2)(l) | event schema F9 | schema test | module-authored content |
| AU-9(3)/AU-10/SI-7(7) | SVC-VRI | — | I(2)(f)(l) | tlog-tiles + witness (+ ML-DSA-87 cosign in gov) | consistency proofs | needs external witness |
| SA-11 | — | PW.7, PW.8 | I(2)(a) | gate stack | CI logs per gate | spec fidelity |
| SA-15(13) | — | PO.6.2 (draft) | — | logging syntax spec | schema | — |
| SA-17(1) | — | — | — | Lean policy, token and lowering models + DRT/oracle correspondence | gate log, theorem table | no regulator credits code proofs; R4 only |
| SR-2/3/5 | SCR-MIT | PO.1, PS.3 | I(2)(a), Art 13(5) | G1–G10 + SBOM | SBOM, vet store | xz-class windows |
| SI-2 / RA-5 | INR | RV.1–3 | Art 14 | PSIRT 24 h/72 h/14 d; CSAF/VEX | advisory feed | reporter reachability |
| PS.4.3 anti-rollback | — | PS.4.3 (draft) | I(2)(c) | TUF monotonic version | client test | built to the draft |

## 5. CRA steward / manufacturer file set
SECURITY.md (CVD policy, contact), PSIRT runbook (T0 = "aware" stamped as a tlog event; T+24 h early warning via SRP for manufacturer distributors; T+72 h notification; final report ≤14 d after fix), CSAF 2.0 advisories + VEX per release, SBOM (CycloneDX, attested), support period statement, EU declaration of conformity (self-assessment route), steward attestation if a legal-person steward exists.

## 6. Government buyer route (R-OPS-10) [C]
Memory-safe language + FIPS 140-3 module (cmvp) + EAL4+ ST only if demanded + formal policy model (SA-17(1)) + COMPLIANCE_MAP evidence bundle per release. Procurement scoring of these properties is unverified (q4-003).

## 7. Export control [E: not researched in the map]
Standard, published algorithms only (TLS 1.3, ML-KEM, ML-DSA, SLH-DSA, AES-GCM, SHA-2). Record before commercial binary distribution: US EAR classification for publicly available open-source encryption (EAR §734.3(b)(3) / §742.15(b)) and any mass-market treatment for commercial builds; EU dual-use Annex I Cat. 5 Part 2 notes. Not legal advice; obtain counsel before export to embargoed destinations.

## 8. Licenses
cargo-deny 11-SPDX allowlist (from `sc3.deny-golden-duplicates`); GPL tools (HTTP Garden) run as external containers, never linked; vendored EverParse output keeps its license header.
