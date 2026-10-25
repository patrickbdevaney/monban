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

## Round 2 (2026-10-25)

- Queries: 301; distinct axis cells (pillar | source type | stance | era): 115; **direction_diversity = 0.382** (cells/queries; round 1: 0.262).
- With the vocabulary axis added (pillar | source | stance | era | vocab; classified by regex from query+axes text): 181 cells, diversity 0.601. Vocabulary was not tracked in round 1, so it is not comparable across rounds.
- Cross-round: 108 of 115 cells are new by exact label, but round-2 pillar labels differ from round 1 (e.g. `W-TRANSPORT+W-FORMAL`). Normalized to the primary pillar, **222 of 301 queries (0.738) landed in cells unseen in round 1**. Use 0.738 as the honest cell-novelty figure.
- novelty_gate metrics --round 2: url 0.898, query 0.977, node 0.953 (0.877 after zero credit for 16 reused/merged ids), axis-cell 0.910, intra-round dup rate 0.010; mechanical_novelty 0.898 (script) / **0.877 adjusted**.
- Near-dups: 2 cross-explorer pairs inside round 2 (data-plane vs calibration, both checking rustls X25519MLKEM768 defaults, J=0.62/0.86); 7 queries at J>=0.5 against round-1 queries (listed below).
- Classifier caveat: only 5 of 301 queries classify as last-60d because explorers rarely wrote dates into queries or axes; 264 of 301 have no deployment-scale signal. Era and scale columns are therefore under-counted, not evidence of under-exploration.

### Axis value totals (round 2)

- **source_type**: repo-advisory 114, paper 42, spec-rfc 34, vendor-doc 29, cve-incident 22, benchmark 20, web-other 19, talk 15, forum 6
- **stance**: proponent 169, skeptic-negative 72, attacker 60
- **era**: 2025-26 281, historical 15, last-60d 5
- **vocab**: offensive 70, PL-formal 57, systems 43, standards-policy 35, cryptography 29, network-SRE 27, database 22, web-dev 15, economics 3
- **scale**: unspecified 264, hyperscaler 15, government 10, enterprise 9, household 3
- **pillar**: W-BRIDGE 43, W-DATA-GATE 42, W-TRANSPORT+W-FORMAL 32, W-STATE 31, K-CALIBRATION 28, W-FORMAL+W-ASSURE 26, W-UNKNOWN 25, W-OPS 21, W-ABUSE 16, W-AGENT-PROTOCOL+W-THREAT 13, W-ISOLATION 12, W-PERF+W-GAP 12

### Yield per explorer direction (round 2)

| explorer target | queries | new nodes | new non-merged L4/L5 | L4/L5 per query | r1 nodes revised |
|---|---|---|---|---|---|
| agent-gateway-cves-to-invariants | 13 | 15 | 14 | 1.08 | 0 |
| lean-footprint-measured-vs-incumbents | 12 | 11 | 9 | 0.75 | 0 |
| verification-footprint-and-golden-contract | 26 | 21 | 19 | 0.73 | 0 |
| talks-nonenglish-adjacent-field-scan | 25 | 23 | 16 | 0.64 | 0 |
| isolation-decision-inputs-measured | 12 | 8 | 7 | 0.58 | 0 |
| data-plane-backend-families-mediation | 42 | 27 | 23 | 0.55 | 0 |
| h2-h3-budget-invariant-and-harness | 32 | 16 | 16 | 0.5 | 0 |
| abuse-admission-control-under-swarms | 16 | 22 | 7 | 0.44 | 0 |
| ops-compliance-government-adoptability | 21 | 12 | 8 | 0.38 | 0 |
| state-crash-consistency-experiment | 31 | 15 | 11 | 0.35 | 0 |
| cross-request-state-invariant-counterexamples | 43 | 20 | 4 | 0.09 | 0 |
| two-sided-calibration-load-bearing-numbers | 28 | 1 | 0 | 0.0 | 20 |

Notes: cross-request-state (10) is low on L4/L5 per query by construction: it produced 14 L3 counterexample classes plus 4 L5 spec artifacts, the round's main bridge. Calibration (12) produced 1 new node and 20 revisions of existing load-bearing nodes; judge it by revisions (4 moved down, 5 up, 12 unchanged), not by new nodes. Agent-gateway (09) yielded most per query (1.08) from bulk `gh api` advisory pulls (instrumented lens).

### Cell coverage, round 2 (count of queries per cell)

`W-UNKNOWN|talk|proponent|2025-26` 15, `W-DATA-GATE|repo-advisory|attacker|2025-26` 12, `W-DATA-GATE|repo-advisory|proponent|2025-26` 10, `W-DATA-GATE|vendor-doc|proponent|2025-26` 9, `W-FORMAL+W-ASSURE|repo-advisory|proponent|2025-26` 8, `W-OPS|spec-rfc|proponent|2025-26` 7, `W-TRANSPORT+W-FORMAL|repo-advisory|skeptic-negative|2025-26` 7, `K-CALIBRATION|repo-advisory|proponent|2025-26` 7, `W-BRIDGE|repo-advisory|attacker|2025-26` 7, `W-STATE|vendor-doc|proponent|2025-26` 7, `W-STATE|repo-advisory|proponent|2025-26` 6, `W-AGENT-PROTOCOL+W-THREAT|repo-advisory|attacker|2025-26` 5, `W-BRIDGE|paper|proponent|2025-26` 5, `W-BRIDGE|spec-rfc|proponent|2025-26` 5, `K-CALIBRATION|repo-advisory|skeptic-negative|2025-26` 5, `W-ISOLATION|benchmark|proponent|2025-26` 5, `W-DATA-GATE|repo-advisory|skeptic-negative|2025-26` 5, `W-TRANSPORT+W-FORMAL|paper|attacker|2025-26` 5, `W-TRANSPORT+W-FORMAL|paper|proponent|2025-26` 5, `W-OPS|repo-advisory|proponent|2025-26` 4, `W-TRANSPORT+W-FORMAL|repo-advisory|proponent|2025-26` 4, `W-UNKNOWN|paper|proponent|2025-26` 4, `W-BRIDGE|repo-advisory|proponent|2025-26` 4, `W-PERF+W-GAP|benchmark|proponent|2025-26` 4, `W-STATE|web-other|proponent|2025-26` 4, `W-FORMAL+W-ASSURE|repo-advisory|skeptic-negative|2025-26` 4, `W-ABUSE|repo-advisory|skeptic-negative|2025-26` 3, `W-BRIDGE|paper|attacker|2025-26` 3, `K-CALIBRATION|spec-rfc|proponent|2025-26` 3, `W-UNKNOWN|cve-incident|attacker|2025-26` 3, `W-ABUSE|web-other|proponent|2025-26` 3, `W-ABUSE|spec-rfc|proponent|2025-26` 3, `W-AGENT-PROTOCOL+W-THREAT|cve-incident|attacker|2025-26` 3, `W-BRIDGE|repo-advisory|skeptic-negative|2025-26` 3, `W-STATE|paper|proponent|2025-26` 3, `W-OPS|vendor-doc|proponent|2025-26` 3, `W-STATE|forum|skeptic-negative|2025-26` 3, `W-FORMAL+W-ASSURE|spec-rfc|proponent|2025-26` 3, `W-FORMAL+W-ASSURE|benchmark|proponent|2025-26` 3, `W-OPS|benchmark|proponent|2025-26` 2, `W-OPS|web-other|proponent|2025-26` 2, `W-ABUSE|spec-rfc|skeptic-negative|2025-26` 2, `W-UNKNOWN|paper|attacker|2025-26` 2, `W-BRIDGE|paper|attacker|historical` 2, `W-BRIDGE|cve-incident|attacker|2025-26` 2, `K-CALIBRATION|cve-incident|skeptic-negative|2025-26` 2, `K-CALIBRATION|web-other|skeptic-negative|2025-26` 2, `W-ABUSE|web-other|skeptic-negative|2025-26` 2, `W-ISOLATION|repo-advisory|proponent|2025-26` 2, `W-STATE|paper|proponent|historical` 2, `W-AGENT-PROTOCOL+W-THREAT|paper|attacker|2025-26` 2, `W-AGENT-PROTOCOL+W-THREAT|repo-advisory|proponent|2025-26` 2, `W-TRANSPORT+W-FORMAL|paper|skeptic-negative|2025-26` 2, `W-PERF+W-GAP|repo-advisory|proponent|2025-26` 2, `W-STATE|repo-advisory|skeptic-negative|2025-26` 2, `W-TRANSPORT+W-FORMAL|spec-rfc|proponent|2025-26` 2, `W-DATA-GATE|cve-incident|skeptic-negative|2025-26` 2, `W-DATA-GATE|cve-incident|attacker|2025-26` 2, `W-TRANSPORT+W-FORMAL|vendor-doc|skeptic-negative|2025-26` 2, `W-FORMAL+W-ASSURE|vendor-doc|skeptic-negative|2025-26` 2, `W-FORMAL+W-ASSURE|spec-rfc|skeptic-negative|2025-26` 2, `W-PERF+W-GAP|vendor-doc|proponent|2025-26` 2, `W-OPS|spec-rfc|skeptic-negative|2025-26` 1, `W-ABUSE|benchmark|skeptic-negative|2025-26` 1, `W-ABUSE|benchmark|proponent|2025-26` 1, `W-ISOLATION|repo-advisory|skeptic-negative|last-60d` 1, `W-BRIDGE|spec-rfc|attacker|2025-26` 1, `W-BRIDGE|cve-incident|skeptic-negative|2025-26` 1, `W-BRIDGE|forum|proponent|2025-26` 1, `K-CALIBRATION|cve-incident|attacker|last-60d` 1, `W-STATE|benchmark|skeptic-negative|2025-26` 1, `W-AGENT-PROTOCOL+W-THREAT|spec-rfc|attacker|2025-26` 1, `W-ISOLATION|repo-advisory|skeptic-negative|2025-26` 1, `W-UNKNOWN|spec-rfc|attacker|2025-26` 1, `K-CALIBRATION|benchmark|skeptic-negative|last-60d` 1, `W-BRIDGE|repo-advisory|skeptic-negative|historical` 1, `W-BRIDGE|cve-incident|proponent|historical` 1, `W-ABUSE|paper|proponent|2025-26` 1, `K-CALIBRATION|repo-advisory|attacker|2025-26` 1, `W-BRIDGE|paper|proponent|historical` 1, `W-BRIDGE|cve-incident|proponent|2025-26` 1, `W-ISOLATION|web-other|proponent|2025-26` 1, `K-CALIBRATION|repo-advisory|skeptic-negative|last-60d` 1, `W-BRIDGE|cve-incident|skeptic-negative|historical` 1, `W-BRIDGE|web-other|attacker|historical` 1, `W-STATE|paper|skeptic-negative|2025-26` 1, `W-STATE|forum|proponent|historical` 1, `W-TRANSPORT+W-FORMAL|repo-advisory|attacker|last-60d` 1, `W-BRIDGE|web-other|proponent|historical` 1, `K-CALIBRATION|spec-rfc|skeptic-negative|2025-26` 1, `W-OPS|repo-advisory|skeptic-negative|2025-26` 1, `W-BRIDGE|vendor-doc|proponent|2025-26` 1, `W-OPS|paper|proponent|2025-26` 1, `W-PERF+W-GAP|benchmark|skeptic-negative|2025-26` 1, `K-CALIBRATION|cve-incident|skeptic-negative|historical` 1, `W-BRIDGE|web-other|skeptic-negative|historical` 1, `W-FORMAL+W-ASSURE|benchmark|skeptic-negative|2025-26` 1, `W-TRANSPORT+W-FORMAL|repo-advisory|attacker|2025-26` 1, `W-TRANSPORT+W-FORMAL|cve-incident|attacker|2025-26` 1, `K-CALIBRATION|vendor-doc|proponent|2025-26` 1, `K-CALIBRATION|paper|skeptic-negative|2025-26` 1, `W-TRANSPORT+W-FORMAL|vendor-doc|proponent|2025-26` 1, `W-TRANSPORT+W-FORMAL|vendor-doc|attacker|2025-26` 1, `K-CALIBRATION|repo-advisory|proponent|historical` 1, `W-STATE|forum|proponent|2025-26` 1, `W-DATA-GATE|repo-advisory|skeptic-negative|historical` 1, `W-DATA-GATE|spec-rfc|proponent|2025-26` 1, `W-FORMAL+W-ASSURE|cve-incident|skeptic-negative|2025-26` 1, `W-FORMAL+W-ASSURE|repo-advisory|attacker|2025-26` 1, `W-ISOLATION|paper|proponent|2025-26` 1, `W-ISOLATION|spec-rfc|attacker|2025-26` 1, `W-PERF+W-GAP|repo-advisory|skeptic-negative|2025-26` 1, `W-PERF+W-GAP|web-other|proponent|2025-26` 1, `W-FORMAL+W-ASSURE|paper|proponent|2025-26` 1, `W-PERF+W-GAP|web-other|skeptic-negative|2025-26` 1

### Redundant directions (flag for meta-optimizer)

- data-plane-backend-families-mediation vs two-sided-calibration (J=0.86): both re-checked "rustls default key exchange X25519MLKEM768 version". One shared crate-default snapshot would remove this.
- Re-run against round 1 (J>=0.5): `gh api wasmtime security-advisories snapshot` (07, J=0.67 vs r1 04/11: third independent pull of the same advisory list; round-1 proposal #1 shared advisory snapshot is still unimplemented); `CERT VU#421644 CONTINUATION CVE list` (06, J=0.83); `CERT VU#767506 MadeYouReset vendor not-affected reasons` (06, 0.57); `gh api verus-lang label:soundness counts` (12, 0.56; a deliberate re-verification); `Cloudflare Radar post-quantum share` (12, 0.50; re-verification); `TiDB privilege escalation CVE 2024` (01, 0.50); `rustls X25519MLKEM768 default key exchange release` (01, 0.57).
- Over-dense cells: W-UNKNOWN|talk|proponent (15, slide-only sources graded C), W-DATA-GATE|repo-advisory (22 across attacker/proponent: per-family CVE sweeps, appropriate for a 17-family survey, but the same pattern should not be repeated per family next round).
- Low-yield direction: per-family CVE id hunting to hit a "2 dated CVEs" quota produced the round's only suspect identifiers (dpf-mysql-mariadb, two unresolved CVE ids). Retire quota-driven id hunting; ask for mechanisms instead.

### Thin / empty cells (cheapest new directions for round 3)

- Pillars still thin: W-DX (3 nodes, no targeted query in two rounds), W-SUPPLY (0 new in round 2), W-GAP (only measured via 02), R/S history (retired), W-PQC authentication (MTC, ML-DSA cert cost) untouched since round 1.
- Source types: forum 6, talk 15 (mostly root URLs), patent 0, dataset 0, non-English 3 queries (JVN, KpqC, Japan NCO). Economics vocabulary: 3 queries (x402 attacks only).
- Stance: proponent 169 of 301 (56%; round 1 78%): skeptic/negative 72 and attacker 60 improved sharply.
- Scale: household 3, government 10, enterprise 9, hyperscaler 15 explicit. 64-core/bare-metal performance: 0 queries.
- Instruments not yet used: real-kernel crash rig (dm-log-writes), quiet-host benchmarks, differential fuzz campaigns (HTTP Garden), Kani/Verus runs on our own harnesses: these are implementation-phase spikes (see frontier queue), not research directions.

### Retired / exhausted directions (after round 2)

- Wasmtime advisory list pulls (3 independent pulls in two rounds): exhausted; snapshot now in `state/raw/round-002/07-data/`.
- MCP SDK advisory corpus by `gh api`: covered to 58 rows (+7 verifier rows); extend only for new repos (Ruby/Kotlin/PHP SDKs, litellm, context-forge).
- CERT VU lists for Rapid Reset / CONTINUATION / MadeYouReset: exhausted (corpus node l4-cve-corpus-h2-h3-2023-2026).
- Identifier existence calibration: exhausted (r1). Number recalibration with per-year bands: still productive (explorer 12 moved 9 of 21 nodes: 4 down, 5 up).
- Per-family DB CVE quota hunting: retire (see above).
- Survey-level reading of Anubis/PoW: done; only measurement (accessibility audit, JA4 false-positive rates) remains.

## Round 3 (2026-10-25)

- Queries: 290. Distinct 4-axis cells: 106, so **direction_diversity = 0.366** (round 2: 0.382). With the vocabulary axis: 166 cells, **0.572** (round 2: 0.601).
- 84 of 106 cells are new (154 of 166 five-axis cells), and 70.3% of queries landed in an unused cell. Pillar labels are per-target (`W-DATA-GATE+W-FORMAL`, `W-TRANSPORT-INGRESS`, `W-OPS+W-PERF`), which inflates newness. A pillar-only view: 9 of 12 targets sat in pillars already queried, but at a new instrument (executed tooling, simulation, reproducers, source reads).
- Intra-round dup rate (novelty_gate) 0.003. Cross-explorer near-dups (J ≥ 0.5): 0. Prior-round near-dups (J ≥ 0.5): 1 (dx "Ur/Web Chlipala typed SQL XSS guarantees", J = 0.55 vs a round-1 history query).
- mechanical_novelty (novelty_gate metrics --round 3) = **0.881** (URL novelty is binding; query 0.997, node 0.948, axis-cell 0.966).

### Axis value totals (round 3)

- **source_type**: spec-rfc 70, repo-advisory 66, web-other 43, vendor-doc 42, paper 23, cve-incident 23, benchmark 18, forum 4, talk 1
- **stance**: proponent 201, skeptic-negative 60, attacker 29
- **era**: 2025-26 255, last-60d 27, historical 8
- **vocab**: systems 100, standards-policy 35, offensive 34, cryptography 29, web-dev 28, PL-formal 26, database 19, network-SRE 14, economics 5
- **scale**: unspecified 261, hyperscaler 15, government 13, household 1

### Yield per explorer direction (round 3; new non-merged L4/L5 nodes per query)

| explorer target | queries | new nodes | new L4/L5 | per query | instrument |
|---|---|---|---|---|---|
| ingress-nonhttp-frontends-defect-classes | 6 | 17 | 16 | 2.67 | OSV/gh api resolution + source read (queries under-logged) |
| supply-chain-executed-on-golden-pins | 14 | 23 | 22 | 1.57 | executed vet/deny/audit/geiger/cooldown/repro |
| abuse-economics-and-swarm-simulation | 20 | 19 | 19 | 0.95 | own DES simulator + vendor price pages |
| pq-authentication-and-hrr-acceptance | 21 | 16 | 16 | 0.76 | executed HRR probes + handshake byte measurement |
| modularity-ipc-and-normalization-copy-spike | 20 | 14 | 14 | 0.70 | own benchmark harness |
| zero-downtime-reload-and-scaleout-state | 19 | 24 | 13 | 0.68 | raw source reads (nginx/Envoy/Pingora/shellflip) + papers |
| authz-token-format-code-level | 28 | 18 | 14 | 0.50 | microbench + library census + PoC |
| dataplane-ir-lowering-soundness | 31 | 17 | 14 | 0.45 | executed differential oracle + reproducers + Lean draft |
| dx-agent-checkable-handler-surface | 19 | 12 | 8 | 0.42 | mutant compile experiment + PDF tables |
| bridge-async-cancellation-failure-atomicity | 55 | 23 | 17 | 0.31 | gh api issue searches per crate (best hit rate) |
| uu-adjacent-fields-and-unused-sources | 37 | 17 | 4 | 0.11 | OSV/datatracker deltas, patents, adjacent fields (negatives by design) |
| calibration-two-sided-could-flip-decisions | 20 | 0 | 0 | — | 11 revisions of load-bearing nodes |

Note: the highest yields came from **changing the instrument** (executing tools against the golden lock, simulators, reproducers), not from new topics. That is the §0d descend rule working.

### Cell coverage, round 3 (count of queries per cell)

`W-UNKNOWN|spec-rfc|proponent|2025-26` 16, `W-BRIDGE|repo-advisory|proponent|2025-26` 14, `W-PERF|benchmark|proponent|2025-26` 9, `W-UNKNOWN|web-other|proponent|2025-26` 8, `W-UNKNOWN|spec-rfc|proponent|last-60d` 8, `W-AUTHZ|repo-advisory|proponent|2025-26` 7, `W-ABUSE|vendor-doc|proponent|2025-26` 6, `W-BRIDGE|repo-advisory|attacker|2025-26` 6, `W-BRIDGE|vendor-doc|proponent|2025-26` 6, `W-AUTHZ|spec-rfc|proponent|2025-26` 6, `W-DATA-GATE+W-FORMAL|repo-advisory|proponent|2025-26` 6, `W-PQC|spec-rfc|proponent|last-60d` 6, `W-OPS+W-PERF|vendor-doc|proponent|2025-26` 5, `W-DATA-GATE+W-FORMAL|paper|proponent|2025-26` 5, `K-CALIBRATION|repo-advisory|skeptic-negative|2025-26` 5, `W-BRIDGE|web-other|proponent|2025-26` 5, `W-DX|web-other|proponent|2025-26` 5, `W-DX|vendor-doc|proponent|2025-26` 5, `W-DATA-GATE+W-FORMAL|vendor-doc|proponent|2025-26` 5, `W-DATA-GATE+W-FORMAL|spec-rfc|proponent|2025-26` 5, `W-ABUSE|cve-incident|attacker|2025-26` 4, `W-BRIDGE|cve-incident|skeptic-negative|2025-26` 4, `W-BRIDGE|web-other|skeptic-negative|2025-26` 4, `W-AUTHZ|spec-rfc|proponent|last-60d` 4, `W-AUTHZ|repo-advisory|attacker|2025-26` 4, `W-ABUSE|benchmark|proponent|2025-26` 4, `K-CALIBRATION|spec-rfc|skeptic-negative|2025-26` 4, `W-PERF|vendor-doc|proponent|2025-26` 4, `W-OPS+W-PERF|web-other|proponent|2025-26` 3, `W-BRIDGE|cve-incident|attacker|2025-26` 3, `W-BRIDGE|spec-rfc|proponent|2025-26` 3, `W-SUPPLY|web-other|proponent|2025-26` 3, `W-ABUSE|paper|skeptic-negative|2025-26` 3, `W-PQC|repo-advisory|skeptic-negative|last-60d` 3, `K-CALIBRATION|spec-rfc|proponent|2025-26` 3, `W-BRIDGE|web-other|proponent|historical` 3, `W-PERF|web-other|proponent|2025-26` 3, `W-SUPPLY|cve-incident|proponent|2025-26` 3, `W-BRIDGE|repo-advisory|skeptic-negative|2025-26` 3, `W-DATA-GATE+W-FORMAL|vendor-doc|attacker|2025-26` 3, `W-OPS+W-PERF|paper|proponent|2025-26` 2, `W-OPS+W-PERF|repo-advisory|proponent|2025-26` 2, `W-OPS+W-PERF|cve-incident|skeptic-negative|2025-26` 2, `W-OPS+W-PERF|spec-rfc|proponent|2025-26` 2, `W-TRANSPORT-INGRESS|repo-advisory|attacker|2025-26` 2, `W-UNKNOWN|vendor-doc|proponent|2025-26` 2, `W-DX|benchmark|proponent|2025-26` 2, `W-DX|paper|proponent|2025-26` 2, `W-PERF|repo-advisory|proponent|2025-26` 2, `W-SUPPLY|paper|proponent|2025-26` 2, `W-DATA-GATE+W-FORMAL|paper|skeptic-negative|2025-26` 2, `K-CALIBRATION|spec-rfc|skeptic-negative|last-60d` 2, `W-DATA-GATE+W-FORMAL|web-other|proponent|2025-26` 2, `W-PQC|repo-advisory|skeptic-negative|2025-26` 2, `W-AUTHZ|forum|skeptic-negative|2025-26` 2, `W-PQC|vendor-doc|skeptic-negative|2025-26` 2, `W-PQC|spec-rfc|skeptic-negative|2025-26` 2, `W-PQC|paper|skeptic-negative|2025-26` 2, `W-OPS+W-PERF|vendor-doc|proponent|historical` 1, `W-ABUSE|web-other|proponent|2025-26` 1, `W-BRIDGE|repo-advisory|proponent|historical` 1, `W-DATA-GATE+W-FORMAL|vendor-doc|skeptic-negative|2025-26` 1, `W-DATA-GATE+W-FORMAL|web-other|attacker|2025-26` 1, `W-OPS+W-PERF|forum|proponent|2025-26` 1, `K-CALIBRATION|benchmark|skeptic-negative|2025-26` 1, `W-TRANSPORT-INGRESS|cve-incident|skeptic-negative|2025-26` 1, `W-BRIDGE|talk|proponent|2025-26` 1, `K-CALIBRATION|web-other|proponent|2025-26` 1, `W-TRANSPORT-INGRESS|spec-rfc|skeptic-negative|2025-26` 1, `W-OPS+W-PERF|paper|skeptic-negative|2025-26` 1, `W-DX|paper|skeptic-negative|2025-26` 1, `W-DX|web-other|skeptic-negative|2025-26` 1, `W-DX|benchmark|skeptic-negative|2025-26` 1, `W-TRANSPORT-INGRESS|cve-incident|attacker|2025-26` 1, `W-DX|repo-advisory|proponent|2025-26` 1, `W-DX|spec-rfc|proponent|2025-26` 1, `K-CALIBRATION|vendor-doc|proponent|last-60d` 1, `W-PERF|web-other|skeptic-negative|2025-26` 1, `W-SUPPLY|repo-advisory|attacker|2025-26` 1, `W-SUPPLY|repo-advisory|proponent|last-60d` 1, `W-PERF|cve-incident|skeptic-negative|2025-26` 1, `W-UNKNOWN|repo-advisory|proponent|2025-26` 1, `W-TRANSPORT-INGRESS|spec-rfc|attacker|2025-26` 1, `W-UNKNOWN|cve-incident|proponent|2025-26` 1, `K-CALIBRATION|cve-incident|attacker|2025-26` 1, `W-UNKNOWN|forum|proponent|2025-26` 1, `K-CALIBRATION|cve-incident|skeptic-negative|2025-26` 1, `K-CALIBRATION|web-other|skeptic-negative|2025-26` 1, `W-ABUSE|repo-advisory|proponent|2025-26` 1, `W-BRIDGE|paper|proponent|historical` 1, `W-BRIDGE|benchmark|proponent|2025-26` 1, `W-DATA-GATE+W-FORMAL|web-other|skeptic-negative|2025-26` 1, `W-ABUSE|repo-advisory|attacker|2025-26` 1, `W-SUPPLY|spec-rfc|proponent|2025-26` 1, `W-SUPPLY|repo-advisory|proponent|2025-26` 1, `W-SUPPLY|cve-incident|skeptic-negative|2025-26` 1, `W-SUPPLY|spec-rfc|skeptic-negative|2025-26` 1, `W-AUTHZ|spec-rfc|attacker|2025-26` 1, `W-PQC|vendor-doc|proponent|last-60d` 1, `W-AUTHZ|paper|skeptic-negative|2025-26` 1, `W-AUTHZ|spec-rfc|proponent|historical` 1, `W-AUTHZ|paper|proponent|2025-26` 1, `W-PQC|repo-advisory|proponent|last-60d` 1, `W-AUTHZ|repo-advisory|skeptic-negative|2025-26` 1, `W-PQC|spec-rfc|proponent|2025-26` 1, `W-PQC|spec-rfc|skeptic-negative|historical` 1

### Redundant directions (flag for meta-optimizer)

- **Advisory re-pulls.** tokio RUSTSEC-2026-0384/0386 were reported by explorers 04 and 11. The rustls 0.23.46 batch was touched by 03, 04 and 11. Wasmtime advisories came from 06 (cancel class) and 11 (OSV snapshot) despite the round-2 retirement. Make `state/raw/round-003/_advisories/` the shared snapshot and require deltas only.
- **Same-incident re-nodes.** Two nodes re-described incidents already in the map (Cloudflare 2025-11-18, arrayref) and were merged with same-as. The novelty_gate `topic` check should catch incident ids (CVE/RUSTSEC/date) and not just token overlap.
- **Over-dense cells:** `W-UNKNOWN|spec-rfc|proponent|*` (24 across eras: datatracker sweeps; appropriate once per round, not more) and `W-BRIDGE|repo-advisory|proponent` (14: per-crate issue searches; productive, keep).

### Thin / empty cells (cheapest new directions for round 4 or the implementation phase)

- **Economics vocabulary:** 5 queries, all abuse pricing. Market/willingness-to-switch (q1-038) is untouched.
- **Scale:** household 1 explicit; 64-core/bare metal 0. Every 1-vCPU number is a laptop extrapolation, so the next instrument is a real VPS (spikes q3-001/q3-002), not a search.
- **Source types:** forum 4, talk 1, patent (11 only), dataset 0, non-English 0 this round.
- **Pillars with no round-3 target:** W-ISOLATION (2 nodes, both incidental), W-AGENT-PROTOCOL (2), W-FORMAL (only unchecked drafts; Lean has not been executed in three rounds).
- **Stance:** proponent 69% (round 2: 56%), so it slid back. Next round should mandate one skeptic/negative direction per explorer again.

### Retired / exhausted directions (after round 3)

- **Retired:**
  - Literature on ingress front-end defect classes (WS/gRPC/GraphQL/webhook/SSE/PROXY). Only runtime checks remain (q3-032).
  - Token-format surveys: 15 candidates enumerated, 11 libraries censused, decision made.
  - rustls server group-selection semantics: executed, with verdicts frozen.
  - Cooldown semantics: executed on cargo 1.98; recheck only on 1.100 stable.
  - Lowering hazards in SQLite/PG/Redis (executed). Only the write path, OpenSearch and timing remain.
  - Reload mechanisms survey (5 mechanisms, 6 systems). Only measurement remains (q3-033).
- **Still productive:**
  - Executed tooling against the golden lock: geiger/vet/deny reruns on each lock change are CI, not research.
  - Bridge hunts that pair one invariant with ≥10 instances (cancellation this round, cross-request state in round 2): keep one per round.

## Round 4 (2026-10-25)

- Queries: 334 (merged from `state/raw/round-004/_queries.log`). Distinct 4-axis cells: 111, so **direction_diversity = 0.332** (round 3: 0.366). With the vocabulary axis: 153 cells, **0.458**.
- The forum-mining explorer (switching economics) logged 114 queries in only 8 cells, and 94 of them are intra-label near-dups (J ≥ 0.5): per-thread fetch strings such as "HN item <id>", not distinct directions. Without it: 220 queries, 103 cells, **0.468**.
- 60 of 111 cells are new (129 of 153 five-axis cells); 47% of queries landed in an unused cell (round 3: 70%). Pillar labels are now canonical per target (one W-* pillar each, as round-3 proposal 4 asked), so this number is lower than round 3 partly because the inflation is gone.
- novelty_gate: intra-round query dup rate 0.069 (round 3: 0.003), entirely from the forum explorer. Cross-explorer near-dups (J ≥ 0.5): 0. Prior-round near-dups: 6 (CISA bad-practices page, wasmtime advisory pull, Redis ACL docs, PG advisory list, CMVP #5314, Firecracker SPECIFICATION.md). All six were re-reads to verify a specific claim, which §0d allows.
- mechanical_novelty (`novelty_gate.py metrics --round 4`) = **0.909** (URL novelty binding; query 0.982, node 0.960, axis-cell 0.958).

### Axis value totals (round 4)

- **source_type**: forum 101, repo-advisory 70, spec-rfc 48, web-other 37, cve-incident 32, vendor-doc 24, paper 19, benchmark 3
- **stance**: proponent 175, skeptic-negative 125, attacker 34 (proponent 52%, down from 69%: the round-3 stance quota worked)
- **era**: 2025-26 286, historical 22, last-60d 26
- **vocab**: PL-formal 67, economics 59, systems 53, offensive 49, standards-policy 32, cryptography 32, network-SRE 25, database 9, web-dev 8
- **scale**: unspecified 251, enterprise 35, government 28, household 12, hyperscaler 8

### Yield per explorer direction (round 4; new non-merged L4/L5 nodes per query)

| explorer target | queries | cells | new nodes | new L4/L5 | per query | instrument |
|---|---|---|---|---|---|---|
| non-us-national-pqc-crypto-regimes | 16 | 6 | 20 | 17 | 1.06 | primary PDFs via curl + pdftotext (DE/FR/EN/JA), IANA CSV |
| fips-golden-version-triangle-one-lock | 9 | 4 | 9 | 8 | 0.89 | executed cargo resolver + FIPS handshake probe |
| lean-check-lowering-and-token-proofs | 23 | 13 | 20 | 19 | 0.83 | first Lean toolchain execution, 6-checker gate, negative control |
| write-path-lowering-differential-oracle | 15 | 6 | 11 | 11 | 0.73 | executed write oracle on PG/SQLite/Valkey/Redis |
| dx-capability-sdk-mutants-real-axum-async | 13 | 8 | 12 | 9 | 0.69 | 32 mutants x 4 shapes compiled on real axum; trybuild gate |
| uu-incident-dataset-outage-root-causes | 19 | 7 | 16 | 11 | 0.58 | hand-coded incident dataset (172 rows) from bulk APIs |
| isolation-crash-blast-radius-measured | 25 | 18 | 19 | 14 | 0.56 | 740-cell fault-injection experiment + PHP-FPM control |
| mcp-gateway-conformance-corpus-executed | 17 | 8 | 8 | 8 | 0.47 | 43-case corpus executed against 5 implementations |
| bridge-canonical-identity-one-owner | 34 | 16 | 17 | 13 | 0.38 | executed cross-crate differential (12 parsers) + OSV ledger |
| safety-critical-certification-assurance-historical | 31 | 10 | 16 | 11 | 0.35 | standards + certificates + pdftotext of primary PDFs |
| calibration-two-sided-top-findings-r3 | 18 | 9 | 3 | 3 | 0.17 | 13 revisions; re-executed cooldown; scorecard of 34 predictions |
| switching-economics-practitioner-forums | 114 | 8 | 12 | 2 | 0.02 | HN Algolia / Lemmy / Discourse / GitHub GraphQL coding (L1-L3 by design) |

Note: executed instruments again dominate yield. The economics explorer's low L4/L5 ratio is expected: its output is demand evidence (L1-L3). Judge it on whether it changes a decision. It does: R-GAP-1 positioning (§1 of the draft).

### Cell coverage, round 4 (count of queries per cell, top)

`W-GAP|forum|skeptic-negative|2025-26` 52, `W-GAP|forum|proponent|2025-26` 43, `W-THREAT|cve-incident|proponent|2025-26` 12, `W-GAP|repo-advisory|proponent|2025-26` 12, `T-SAFETY-CERT|web-other|proponent|2025-26` 10, `W-AGENT-PROTOCOL|repo-advisory|attacker|2025-26` 10, `W-BRIDGE|cve-incident|skeptic-negative|2025-26` 9, `W-DATA-GATE|vendor-doc|proponent|2025-26` 8, `W-PQC|spec-rfc|proponent|2025-26` 7, `W-FORMAL|repo-advisory|skeptic-negative|last-60d` 6, plus 101 cells with ≤6 each (full map in the scratchpad `r4_cells.json`, mirrored by `state/queries.jsonl` cell fields).

### Redundant directions (flag for meta-optimizer)

- **Forum thread fetches logged as queries.** 94 near-dup lines from one explorer. Log one query per search strategy and count thread fetches separately, or they swamp the diversity metric.
- **Same recomputation twice.** The Wasmtime M0 escape rate was recomputed independently by explorers 04 and 12 (merged with same-as). The aws-lc-fips-sys 0.13.11 advisory exposure was found by 03 and 12 (merged). The 2026 Lean soundness record was compiled by 01 and 09 (merged). The planner should give a calibration target the explicit list of numbers other targets will touch.
- **Contradicting range.** 03 and 12 both stated the aws-lc-rs FIPS window, and they disagree (1.15.2-1.17.1 vs 1.15.1-1.17.2). The verifier settled it for 03 (1.17.2 yanked).

### Thin / empty cells (cheapest new directions)

- **benchmark** source type: 3 queries. Most measurements were own experiments, not literature, which is fine; a real 1-vCPU VPS is still the missing instrument (q3-001/q3-002).
- **hyperscaler** scale 8, **household** 12. **database** vocab 9 (outside the write-path explorer). **last-60d** era 26.
- **Pillars with no round-4 target:** W-STATE (0 new nodes), W-ABUSE (0), W-PERF (1), W-OPS (1, though outage classes from explorer 11 land on ops rules), W-SUPPLY (6, via the FIPS lock and calibration only).
- **Non-English primaries:** first use this round (DE, FR, JA, ZH, KO press). Chinese primaries (OSCCA GM/T, GB/T 38636) are still thin.

### Retired / exhausted directions (after round 4)

- **Retired:**
  - **Lean feasibility.** The toolchain was executed, the footprint measured (712 MB Init-only, paranoid 4 min / 1.0 GB) and the gate built. What remains is proof work, which is implementation.
  - **FIPS version triangle.** Resolved as empty at the floor; two lock profiles. Re-open only on an AWS-LC 4/5 certificate or a rustls 0.24 release.
  - **Crash blast-radius literature.** Measured. What remains are gate spikes: fuel budget, CLONE_INTO_CGROUP.
  - **Practitioner forum mining on proxy selection.** Demand criteria are counted. Reddit/lobste.rs are walled; procurement documents are the next instrument (q4-003), not more forums.
  - **National PQC regimes outside China.** The matrix is filled from primaries. Only BSI 2027 / ANSSI qualification text / ECCG ACM v3 final remain as dated deltas.
  - **Safety-critical certification history.** No regulator credits code proofs. Only DO-330 primary text and quantified DO-333 credit remain (low expected info gain).
- **Still productive:**
  - Executed differentials and oracles: lowering read/write, identity canonicalization, MCP corpus, FIPS probe.
  - Calibration against raw logs. It caught reproducibility gaps in the threat-ledger script and 9 stale grade tags in the draft.
