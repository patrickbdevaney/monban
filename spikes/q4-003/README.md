# q4-003: Do procurement texts require what AEGIS offers?

**Verdict: flip D-13** to "visible compliance, invisible proofs". Grade B. Date 2026-10-25.
Machine-readable: `verdict.json`. Full scored table with one URL per row: `scores.csv`.

## Question and flip condition
ARCHITECTURE §1 P-2 / §7 D-13: positioning is "invisible assurance, parity first", based on 56 selection threads
that never mention PQ, formal verification or compliance (with a selection-bias caveat). D-13 flips on
procurement scoring evidence. P-2 reverses if procurement texts (RFPs, STIGs) score PQ, memory safety or formal
assurance for gateways. Phases 4–6 are conditional on this spike and q1-009.

## Method
- Purposive corpus of 25 documents dated 2025-01 to 2026-10: US federal (EO, OMB, CISA, FedRAMP CR26, NIST),
  DoD/NSS (CNSA 2.0, CNSSP-15, DISA SRG, SWFT), EU (CRA, PQC roadmap), UK (NCSC, Code of Practice),
  France (ANSSI), Australia (ISM Sept 2026, AusCERT questionnaire), Canada (TBS SPIN), enterprise
  questionnaires (CSA CCM/CAIQ v4.1), and 3 real reverse-proxy/WAF tenders.
- Each document is scored per feature as **M** (must / shall / contract clause / CAT I), **S** (should /
  preferred / scored / risk-managed baseline control), **m** (may / example), or **–** (absent).
- Primary text was read where reachable (PDF via `pdftotext`, OSCAL JSON parsed). Where the primary was blocked
  (NSA 403, EUR-Lex bot wall, ANSSI, cyber.gov.au timeouts), a mirror or secondary source was used and the
  grade lowered to B or C.

## Results (counts out of 25: M / S / m / absent)

| feature | M | S | m | – | where it is a MUST |
|---|---|---|---|---|---|
| memory-safe language | 0 | 2 | 0 | 23 | nowhere. ASD ISM-1826 (choose server-app vendors committed to MSL) is the strongest |
| FIPS 140-validated module | 4 | 2 | 0 | 19 | Canada contracts (from 2026-04-01), DISA Web Server SRG (CAT I), NSS/NIAP, EO 14412 FAR rule (proposed, 2030) |
| PQC with dates | 5 | 5 | 0 | 15 | EO 14412, **OMB M-26-15 (names "API proxies" and "API gateways")**, CNSSP-15 (NSS buys from 2027-01-01), Canada, ANSSI (2027, announced) |
| formal verification / SA-17(1) | 0 | 0 | 1 | 24 | nowhere. SA-17(1) is in no 800-53B baseline; SSDF 1.2 draft lists it as an optional example |
| SBOM | 1 | 6 | 1 | 17 | EU CRA Annex I Part II(1), from 2027-12-11. US federal SBOM is now only "may require on request" (M-26-05) |
| SLSA / build provenance | 0 | 2 | 0 | 23 | nowhere (ASD ISM-2056, SSDF PS.3.2 are SHOULD) |
| reproducible builds | 0 | 1 | 1 | 23 | nowhere (ASD ISM-2155 is new in Sept 2026) |
| CBOM (extra) | 0 | 2 | 0 | 23 | forthcoming: CISA minimum elements due ~2027-03 under EO 14412 |

The 3 real tenders (Colombia WAF RFP 2025-08, Coquitlam WAF RFIQ 2025-04, UZH reverse proxy 2026-06) ask for
**none** of the seven features. They ask for OWASP Top 10 alignment, ISO 27001, SOC 2, PCI DSS, SIEM/firewall
integration and operations. UZH's incumbent is Apache httpd + ModSecurity.

### Key quotes (primary)
- OMB M-26-15 (2026-06-24): network infrastructure that terminates TLS, "including … cloud gateways, and
  Application Programming Interface (API) proxies—must be configured to support PQC-capable key exchanges";
  "API gateways and application workloads must be configured to issue and validate PQC-signed tokens"; agencies
  "must support … TLS … 1.3 … not later than January 2, 2030". It also lists configuration-driven cryptography,
  "not compiled into the application binary", as one way to get crypto agility.
- EO 14412 §4(b), §6(c): HVAs and high-impact systems move to PQC key establishment by 2030-12-31 and to PQC
  signatures by 2031-12-31. The FAR Council must propose a rule requiring covered contractors to comply with
  NIST FIPS, PQC FIPS included, by 2030-12-31.
- OMB M-26-05 (2026-01-23): rescinds M-22-18/M-23-16. Agencies "may choose to adopt contractual terms that
  require a software producer to provide a current software bill of materials (SBOM) upon request".
- FedRAMP CR26 CMU-CSO-UVM: "Providers with Class C Certifications SHOULD use cryptographic modules or update
  streams" with active CMVP validations. Documenting the modules is a MUST.
- Canada SPIN (2025-10-09) §6.3.1: by 2026-04-01, all contracts with a digital component must include clauses
  for PQC per ITSP.40.111, CMVP-certified modules, and crypto agility.
- ASD ISM (OSCAL v2026.09.4): ISM-1826 (server-application vendors committed to Secure by Design with
  "memory-safe programming languages or less preferably memory-safe programming practices"); ISM-1917 (new
  crypto must support ML-DSA-87, ML-KEM-1024, SHA-384/512 and AES-256 by 2030); ISM-1990 (FIPS 140-3
  validation preferred); ISM-1730 (SBOM); ISM-2056 (build provenance); ISM-2155 (reproducible builds,
  Sept 2026); ISM-2083 (CBOM). No control mentions formal methods. The patch windows in ISM-1876/1877 (48 h
  for critical flaws or working exploits on internet-facing systems) are relevant to q1-009.
- NIST 800-53B OSCAL: the High baseline selects `sa-17`. No baseline selects `sa-17.1` or `sr-4`.

## Interpretation
- **Claim "buyers don't ask for assurance".** It is true for *formal* assurance: no procurement text requires
  formal verification and none scores it. It is mostly true for memory safety: one jurisdiction has a SHOULD.
  It is false for *crypto and supply-chain compliance*. PQC has dated MUSTs that name proxies and gateways,
  FIPS-validated modules gate DoD/NSS/Canada, and SBOM gates the EU CRA. Commodity proxies already ship hybrid
  PQ by default (P-2), so PQC is table stakes for regulated buyers rather than a differentiator. Getting it
  wrong excludes you; getting it right does not win the deal.
- **Selection bias, both ways.** Regulator texts over-represent what governments say they want. Small-buyer
  RFPs under-represent regulated buyers. No federal proxy/gateway RFP text was retrievable. The texts measure
  stated requirements, not award decisions.

## Procurement-gating vs nice-to-have (for the Phase 4–6 decision)
| AEGIS feature | status | phase effect |
|---|---|---|
| PQ hybrid KX by default, ML-KEM-1024 group (0x11ED) | **gating** (US fed/NSS 2027–2031, CA 2026, AU 2030, FR 2027) | keep; lead the copy with it |
| PQC-signed tokens at the gateway (M-26-15) | **gating (federal, by plan dates)** | add to the R-PQC roadmap for aegis-token |
| FIPS 140-3 profile (cmvp lock) | **gating** for DoD/NSS/Canada; SHOULD for FedRAMP Class C | Phase 6 justified by demand |
| SBOM (CycloneDX/SPDX, ≥ top-level deps) | **gating** EU CRA 2027-12-11; SHOULD elsewhere | move into the Phase 2 release |
| CBOM | emerging (ASD SHOULD; US guidance ~2027) | move into the Phase 2 release (cheap) |
| SLSA L3 provenance, reproducible build | nice-to-have (AU SHOULD) | keep in Phase 6; artefacts can ship earlier |
| memory-safe language (Rust) | nice-to-have (AU selection criterion) | no phase effect |
| formal verification / Lean gates / NOT-proven list | **not procurement-relevant** | justify on safety grounds only; keep out of procurement copy |
| data plane (Ph 4), P2 isolation (Ph 5) | not addressed by any text | decide on agent-infra evidence and velocity, not q4-003 |

## Reproduction
See `verdict.json` → `reproduce`. Every row of `scores.csv` carries its URL and access date (2026-10-25).

## Honest limits
See `verdict.json` → `limits`. The most important: FAR rules under EO 14412 are not yet proposed. ANSSI's 2027
date is an announced aim. SIG 2026 and Microsoft SSPA content could not be verified. The corpus is purposive,
not random.

## Sources (all accessed 2026-10-25)
See `scores.csv` for the per-row URL. Secondary sources used for context:
https://www.mayerbrown.com/en/insights/publications/2026/02/omb-rescinds-biden-era-software-security-memoranda ·
https://www.infosecurity-magazine.com/news/cisa-post-quantum-cryptography/ ·
https://cyber.gc.ca/en/guidance/roadmap-migration-post-quantum-cryptography-government-canada-itsm40001 ·
https://www.enisa.europa.eu/media/56885 · https://www.techuk.org/insights/news/national-cyber-security-publishes-timelines-for-migration-to-post-quantum-cryptography ·
https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1 · https://www.wiley.law/alert-OMB-Rescinds-Secure-Software-Development-Mandate-in-Favor-of-a-Risk-Based-Approach ·
https://labs.cloudsecurityalliance.org/research/csa-research-note-eo14409-pqc-migration-2030-20260624-csa-st/ ·
https://www.skadden.com/insights/publications/2026/06/big-changes-coming-for-government-contractors
