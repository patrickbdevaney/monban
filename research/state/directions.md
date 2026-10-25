# AEGIS direction coverage (state/directions.md)

Maintained by the integrator (META §8a). Axis cell = pillar | source type | stance | era, classified deterministically from each query and its logged axes (classifier in the round-1 integrator script; rules: regex buckets on query+axes text, recency-explorer queries forced to last-60d). Explorers logged axes as free text; vocabulary and deployment-scale axes were not logged consistently and so are NOT tracked here yet (see self_improvement.md).

## Round 1 (2026-10-24)

- Queries: 473; distinct axis cells: 124; **direction_diversity = 0.262** (cells/queries).
- Intra-round exact/near dup rate (novelty_gate, Jaccard>=0.75): 0.004; cross-explorer near-dups (Jaccard>=0.5): 7.
- mechanical_novelty (novelty_gate metrics --round 1) = 1.0, trivially: no earlier round exists.

### Axis value totals

- **source_type**: repo-advisory 139, paper 106, web-other 66, spec-rfc 56, benchmark 36, cve-incident 35, vendor-doc 32, forum 3
- **stance**: proponent 370, skeptic-negative 72, attacker 31
- **era**: 2025-26 366, last-60d 61, historical 46
- **pillar**: W-FORMAL 60, W-SUPPLY+W-ASSURE 52, W-UNKNOWN 52, W-THREAT 48, W-STATE+W-DATA-GATE 46, R+S 42, W-TRANSPORT+W-PQC 40, W-ISOLATION 33, W-AUTHZ 33, W-GAP 32, K-CALIBRATION 26, W-AGENT-PROTOCOL 9

### Yield per explorer direction (new non-merged L4/L5 nodes per query)

| explorer target | queries | nodes | new L4/L5 | L4/L5 per query |
|---|---|---|---|---|
| transport-stacks-and-pqc-deployment-reality | 40 | 34 | 31 | 0.78 |
| authz-capabilities-with-formal-semantics | 33 | 43 | 22 | 0.67 |
| agent-protocols-primary-source-status | 9 | 30 | 6 | 0.67 |
| supply-chain-provenance-and-deterministic-sim-ci | 52 | 34 | 30 | 0.58 |
| isolation-substrates-measured-and-escaped | 33 | 26 | 13 | 0.39 |
| identifier-calibration-seed-and-prior-claims | 26 | 12 | 9 | 0.35 |
| formal-proofs-in-production-and-llm-proof-synthesis | 60 | 28 | 18 | 0.30 |
| recency-sweep-last-60-days | 52 | 21 | 10 | 0.19 |
| state-durability-and-db-gate-failure-modes | 46 | 39 | 4 | 0.09 |
| threat-cve-record-and-ai-exploit-speed | 48 | 15 | 4 | 0.08 |
| gap-prior-art-servers-and-unserved-slot | 32 | 32 | 0 | 0.00 |
| historical-and-formal-web-foundations-why-they-died | 42 | 19 | 0 | 0.00 |

Note: W-GAP and R+S yield 0 L4/L5 by construction (survey of systems/history produces L3 nodes); judge them by L3 node count, not this column.

### Cell coverage (all cells, count of queries)

| cell | queries |
|---|---|
| W-UNKNOWN|repo-advisory|proponent|last-60d | 22 |
| W-SUPPLY+W-ASSURE|web-other|proponent|2025-26 | 19 |
| W-FORMAL|paper|proponent|2025-26 | 19 |
| R+S|paper|proponent|historical | 14 |
| W-THREAT|repo-advisory|proponent|2025-26 | 14 |
| W-STATE+W-DATA-GATE|paper|proponent|2025-26 | 14 |
| W-UNKNOWN|spec-rfc|proponent|last-60d | 11 |
| W-FORMAL|vendor-doc|proponent|2025-26 | 11 |
| W-TRANSPORT+W-PQC|spec-rfc|proponent|2025-26 | 10 |
| W-FORMAL|repo-advisory|proponent|2025-26 | 10 |
| K-CALIBRATION|repo-advisory|proponent|2025-26 | 10 |
| W-STATE+W-DATA-GATE|repo-advisory|proponent|2025-26 | 10 |
| W-SUPPLY+W-ASSURE|repo-advisory|proponent|2025-26 | 10 |
| W-SUPPLY+W-ASSURE|benchmark|proponent|2025-26 | 10 |
| W-GAP|repo-advisory|proponent|2025-26 | 9 |
| R+S|web-other|proponent|historical | 8 |
| W-AUTHZ|paper|proponent|2025-26 | 8 |
| W-GAP|web-other|proponent|2025-26 | 8 |
| W-UNKNOWN|paper|proponent|last-60d | 8 |
| W-THREAT|cve-incident|attacker|2025-26 | 7 |
| K-CALIBRATION|spec-rfc|proponent|2025-26 | 7 |
| W-ISOLATION|benchmark|proponent|2025-26 | 7 |
| R+S|repo-advisory|proponent|historical | 7 |
| W-AUTHZ|spec-rfc|proponent|2025-26 | 6 |
| K-CALIBRATION|paper|proponent|2025-26 | 6 |
| W-STATE+W-DATA-GATE|repo-advisory|skeptic-negative|2025-26 | 6 |
| W-GAP|vendor-doc|proponent|2025-26 | 6 |
| W-TRANSPORT+W-PQC|repo-advisory|proponent|2025-26 | 5 |
| W-SUPPLY+W-ASSURE|paper|proponent|2025-26 | 5 |
| W-ISOLATION|repo-advisory|skeptic-negative|2025-26 | 5 |
| W-UNKNOWN|cve-incident|proponent|last-60d | 5 |
| W-ISOLATION|paper|proponent|2025-26 | 5 |
| W-ISOLATION|paper|skeptic-negative|2025-26 | 5 |
| W-AUTHZ|paper|proponent|historical | 5 |
| W-STATE+W-DATA-GATE|web-other|skeptic-negative|2025-26 | 5 |
| W-TRANSPORT+W-PQC|vendor-doc|proponent|2025-26 | 4 |
| W-THREAT|repo-advisory|attacker|2025-26 | 4 |
| W-AGENT-PROTOCOL|spec-rfc|proponent|2025-26 | 4 |
| W-STATE+W-DATA-GATE|spec-rfc|skeptic-negative|2025-26 | 4 |
| W-TRANSPORT+W-PQC|cve-incident|skeptic-negative|2025-26 | 4 |
| W-FORMAL|benchmark|proponent|2025-26 | 4 |
| W-TRANSPORT+W-PQC|benchmark|proponent|2025-26 | 4 |
| W-THREAT|cve-incident|proponent|2025-26 | 4 |
| R+S|spec-rfc|proponent|historical | 3 |
| W-TRANSPORT+W-PQC|cve-incident|attacker|2025-26 | 3 |
| W-THREAT|web-other|proponent|2025-26 | 3 |
| W-FORMAL|repo-advisory|skeptic-negative|2025-26 | 3 |
| W-AUTHZ|repo-advisory|proponent|2025-26 | 3 |
| W-AGENT-PROTOCOL|repo-advisory|proponent|2025-26 | 3 |
| W-FORMAL|web-other|proponent|2025-26 | 3 |
| W-GAP|repo-advisory|skeptic-negative|2025-26 | 3 |
| W-SUPPLY+W-ASSURE|repo-advisory|skeptic-negative|2025-26 | 3 |
| W-AUTHZ|paper|attacker|2025-26 | 2 |
| W-THREAT|repo-advisory|attacker|last-60d | 2 |
| W-STATE+W-DATA-GATE|web-other|proponent|2025-26 | 2 |
| W-ISOLATION|cve-incident|attacker|2025-26 | 2 |
| W-ISOLATION|cve-incident|skeptic-negative|2025-26 | 2 |
| R+S|forum|proponent|historical | 2 |
| W-FORMAL|paper|skeptic-negative|2025-26 | 2 |
| R+S|paper|proponent|2025-26 | 2 |
| W-AUTHZ|benchmark|proponent|2025-26 | 2 |
| W-AGENT-PROTOCOL|vendor-doc|proponent|2025-26 | 2 |
| W-TRANSPORT+W-PQC|benchmark|skeptic-negative|2025-26 | 2 |
| W-ISOLATION|spec-rfc|proponent|2025-26 | 2 |
| K-CALIBRATION|web-other|proponent|2025-26 | 2 |
| W-AUTHZ|web-other|skeptic-negative|2025-26 | 2 |
| R+S|cve-incident|proponent|2025-26 | 2 |
| W-FORMAL|spec-rfc|skeptic-negative|2025-26 | 2 |
| W-THREAT|web-other|skeptic-negative|2025-26 | 2 |
| W-AUTHZ|vendor-doc|proponent|2025-26 | 2 |
| W-THREAT|benchmark|proponent|2025-26 | 2 |
| W-THREAT|paper|attacker|2025-26 | 2 |
| W-THREAT|repo-advisory|skeptic-negative|2025-26 | 2 |
| W-SUPPLY+W-ASSURE|web-other|skeptic-negative|2025-26 | 2 |
| W-UNKNOWN|web-other|proponent|last-60d | 2 |
| W-GAP|web-other|skeptic-negative|2025-26 | 2 |
| W-TRANSPORT+W-PQC|paper|proponent|historical | 2 |
| R+S|benchmark|proponent|historical | 1 |
| R+S|paper|skeptic-negative|2025-26 | 1 |
| W-AUTHZ|repo-advisory|skeptic-negative|2025-26 | 1 |
| W-THREAT|vendor-doc|proponent|2025-26 | 1 |
| W-STATE+W-DATA-GATE|cve-incident|proponent|2025-26 | 1 |
| W-STATE+W-DATA-GATE|spec-rfc|proponent|2025-26 | 1 |
| W-UNKNOWN|web-other|attacker|last-60d | 1 |
| W-ISOLATION|vendor-doc|skeptic-negative|2025-26 | 1 |
| W-TRANSPORT+W-PQC|repo-advisory|proponent|last-60d | 1 |
| R+S|repo-advisory|skeptic-negative|historical | 1 |
| R+S|benchmark|proponent|2025-26 | 1 |
| W-FORMAL|repo-advisory|skeptic-negative|last-60d | 1 |
| W-UNKNOWN|cve-incident|attacker|last-60d | 1 |
| W-UNKNOWN|repo-advisory|skeptic-negative|last-60d | 1 |
| W-FORMAL|spec-rfc|proponent|2025-26 | 1 |
| W-ISOLATION|vendor-doc|proponent|2025-26 | 1 |
| W-SUPPLY+W-ASSURE|vendor-doc|proponent|2025-26 | 1 |
| W-SUPPLY+W-ASSURE|spec-rfc|proponent|2025-26 | 1 |
| W-TRANSPORT+W-PQC|spec-rfc|proponent|last-60d | 1 |
| W-ISOLATION|cve-incident|skeptic-negative|historical | 1 |
| W-FORMAL|vendor-doc|skeptic-negative|2025-26 | 1 |
| W-FORMAL|benchmark|skeptic-negative|2025-26 | 1 |
| K-CALIBRATION|web-other|skeptic-negative|2025-26 | 1 |
| W-ISOLATION|repo-advisory|proponent|2025-26 | 1 |
| W-AUTHZ|spec-rfc|skeptic-negative|2025-26 | 1 |
| W-GAP|benchmark|proponent|2025-26 | 1 |
| W-GAP|repo-advisory|attacker|2025-26 | 1 |
| W-GAP|cve-incident|proponent|2025-26 | 1 |
| W-UNKNOWN|paper|attacker|last-60d | 1 |
| W-ISOLATION|paper|attacker|2025-26 | 1 |
| W-THREAT|paper|proponent|2025-26 | 1 |
| W-THREAT|cve-incident|skeptic-negative|2025-26 | 1 |
| W-THREAT|spec-rfc|proponent|2025-26 | 1 |
| W-SUPPLY+W-ASSURE|web-other|attacker|2025-26 | 1 |
| W-FORMAL|web-other|attacker|2025-26 | 1 |
| W-AUTHZ|vendor-doc|skeptic-negative|2025-26 | 1 |
| W-FORMAL|repo-advisory|proponent|last-60d | 1 |
| W-THREAT|spec-rfc|proponent|last-60d | 1 |
| W-THREAT|web-other|attacker|last-60d | 1 |
| W-STATE+W-DATA-GATE|paper|proponent|historical | 1 |
| W-STATE+W-DATA-GATE|cve-incident|skeptic-negative|2025-26 | 1 |
| W-STATE+W-DATA-GATE|vendor-doc|skeptic-negative|2025-26 | 1 |
| W-TRANSPORT+W-PQC|paper|attacker|2025-26 | 1 |
| W-GAP|forum|proponent|2025-26 | 1 |
| W-TRANSPORT+W-PQC|web-other|proponent|last-60d | 1 |
| W-TRANSPORT+W-PQC|paper|skeptic-negative|2025-26 | 1 |
| W-TRANSPORT+W-PQC|benchmark|proponent|historical | 1 |

### Redundant directions (flag for meta-optimizer)

- recency-sweep-last-60-days vs threat-cve-record-and-ai-exploit-speed (J=0.5): "HAProxy smuggling 2026" ~ "HAProxy CVE 2023 2024 2025 request smuggling"
- recency-sweep-last-60-days vs isolation-substrates-measured-and-escaped (J=0.5): "gh api wasmtime security-advisories" ~ "gh api repos/bytecodealliance/wasmtime/security-advisories full list"
- authz-capabilities-with-formal-semantics vs historical-and-formal-web-foundations-why-they-died (J=0.67): "OCapN specification status Spritely Goblins CapTP 2026" ~ "OCapN Spritely Goblins status"
- recency-sweep-last-60-days vs formal-proofs-in-production-and-llm-proof-synthesis (J=0.5): "gh verus soundness issues" ~ "Verus soundness issue github label"
- transport-stacks-and-pqc-deployment-reality vs formal-proofs-in-production-and-llm-proof-synthesis (J=0.56): "libcrux ML-KEM OpenSSH mlkem768x25519 default verified hax" ~ "libcrux hax ML-KEM verified OpenSSH Signal deployment"
- transport-stacks-and-pqc-deployment-reality vs formal-proofs-in-production-and-llm-proof-synthesis (J=0.6): "aws-lc ML-KEM formal verification s2n-bignum mlkem-native CBMC HOL Light" ~ "s2n-bignum HOL Light aws-lc formal verification coverage"
- transport-stacks-and-pqc-deployment-reality vs formal-proofs-in-production-and-llm-proof-synthesis (J=0.5): "EverParse 3D production use Hyper-V vswitch network parser verified 2025" ~ "EverParse Hyper-V vSwitch Windows deployment verified parsers"
- Over-dense cells: proponent x 2025-26 x repo-advisory/paper across W-FORMAL, W-UNKNOWN, W-THREAT, W-SUPPLY+ASSURE (>=10 queries each). gh-api advisory sweeps were run independently by explorers 01, 02, 04, 06, 08, 11 over overlapping repos (wasmtime, pingora, quinn, rustls, envoy, nginx): one shared advisory-snapshot tool would remove that repetition.
- Formal-verification of crypto (libcrux, aws-lc/s2n-bignum, EverParse) was queried by both 03 and 06.

### Thin / empty cells (cheapest new directions for round 2)

- Pillars with ZERO targeted queries: W-ABUSE, W-OPS, W-PERF, W-DX (only incidental), data-plane families beyond Postgres/SQLite (§0b), protocol-agnostic ingress/modularity (§0b), verification-toolchain footprint (§0c).
- Stance: attacker 31 and skeptic/negative 72 of 473; source type: forum 3, vendor-doc 32, benchmark 36; era: historical 46.
- Not logged at all: deployment scale (household VPS / enterprise / hyperscaler / government) and vocabulary (economics, network ops-SRE, standards-policy). Round 2 explorers must log these axes in the fixed format.

### Retired / exhausted directions

- None retired after one round (no prior round to compare yield).
