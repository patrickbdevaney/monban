# THREAT_MODEL (template, v4, 2026-10-25)

Source: ARCHITECTURE.md v4 §2, §4. Grades per META §3.

## 1. Scope and assumptions
- Asset under protection: the AEGIS binary in front of (or replacing) an app server, its data-plane adapters, its build and release chain.
- Out of scope: ML-model threats (poisoning, extraction); the server bounds a confused model's authority (AA4), it does not defend the model.
- Assumed: TLS 1.3 and hybrid-KEM security (literature + rustls); HMAC EUF-CMA; Linux kernel enforces seccomp/Landlock as documented; CMVP module behaves as certified on AL2023.

## 2. Adversary classes

| id | adversary | capability | evidence | grade |
|---|---|---|---|---|
| AA1 | AI-automated vulnerability discovery | finds reachable bugs in weeks; rediscovery common | `wasmtime-llm-audit-sprint-2026-04` A; `v.http2-bomb-cve-2026-49975`; `r3e11.ai-found-bug-flood-vendor-posture` A | A |
| AA1-skeptic | same, outcome-measured | 1.3% of AI-assisted CVEs exploited (base rate); CVE→KEV median 120 → 80 days | `skeptic-ai-exploit-overhype` B; VulnCheck H1 2026 | B |
| AA2 | live adaptive protocol agents | probe H1/H2/H3 state; choose cancellation instant | RUSTSEC-2025-0070; `ac.attacker-chosen-cancel-instant` B; `r2e11.haproxy-cve-2026-33555` | A/B |
| AA3 | agent swarms | residential proxies, solvers, headless browsers | `r3e07-price-sheet-2026-10` B | B / D defences |
| AA4 | confused authorized agent | valid capability, attacker-controlled inputs | CaMeL, Progent, `dpf-agent-db-tool-bypass-cluster` | B |
| AA5 | malicious agent-protocol client | Origin/session/audience/JSON gaps | `l5.mcp-lc-passrate-matrix` B; LiteLLM KEV | A/B |
| AA6 | agents in our supply chain / dev loop | slopsquatting, SDK edits, proof cheating | `sc3.slopsquat-rust-study-2606` B; `llm-verusage-2025` B | B |
| AA7 | proof-pipeline attacker | adversarial metaprograms, Lake deps, crafted exports | `v4.lean-soundness-threat-is-build-supply-chain` B; #15908 | B |
| AA8 | malicious tenant module/adapter | arbitrary code in its cordon | M0 2.21/yr [1.14, 3.86]; P(≥3 in 12 mo) = 0.38 | B |
| AA9 | network adversary incl. HNDL | record now; downgrade where possible | RUSTSEC-2026-0349 is **client-side**; server mitigation = HRR (`r3pq.hrr-acceptance-test` A) | A |
| AA10 | insider / compromised operator or CI | config push, keys, runners | `uu11.cfg-push-class` A; 5/12 incidents CI (`sc3.incident-class-fractions` B) | A/B |
| AA0 | non-adversarial failure | config, certs, exhaustion, retries, DNS, reload | 160 coded outages, 0 memory corruption (postmortems exclude breaches: not a reason to down-weight memory safety) | C |

## 3. Assets
1. Cross-tenant data. 2. Authority material (MAC keys, STEKs, TLS keys, per-tenant DB creds, signing/TUF keys). 3. Availability per tenant and global. 4. Audit-log integrity. 5. Build identity. 6. PQ confidentiality of recorded sessions.

## 4. Trust boundaries
TB1 Internet → TLS + aegis-canon (reject-don't-repair). TB2 capability boundary at handler dispatch (sealed `Cap<O>`, `Ctx<'r>`). TB3 per-tenant OS cordon / fork child for P2. TB4 backend (per-tenant native credentials; RLS as defence in depth; engine bugs in scope). TB5 build side (proof + supply-chain gate). Diagram: ARCHITECTURE.md §2.3.

## 5. Ranked threats (KEV and advisory-volume metrics both kept)

| rank | class | primary mitigations | rule |
|---|---|---|---|
| 1 | H2/H3/QUIC exhaustion, translation amplification, stalled flow control | wrapper TBI-1..9; H3 off | R-TLS-1/2/7 |
| 2 | identity canonicalization divergence; fail-open authz | CANON-1..8; route-id authz; tri-state combine; INV-NONEMPTY | R-ING-4, R-AUTHZ-5, R-DB-3 |
| 3 | smuggling / parser differentials | strict H1, framing regeneration, validated-101, one TLS mode per port | R-TLS-3/8 |
| 4 | TLS logic / PQ downgrade | pq-required agent listeners; hybrid-first public + PreferServerOrder backport; profiles; scoped tickets | R-PQC-1/6/8 |
| 5 | agent-protocol origin/session/audience; confused deputy | listener-gate type; sealed state; F10 | R-AGENT-4..7 |
| 6 | cross-request state scope | CRS C1–C8 + C5b; fresh instances | R-STATE-5 |
| 7 | async cancellation | INV-NOMUT-C; cancel sweep | R-THR-5, R-STATE-6/7 |
| 8 | data-plane injection/authz incl. writes | typed IR; two-sided oracles; W1–W7 | R-DB-2..8 |
| 9 | memory corruption | Rust; C out of process except aws-lc, SQLite | R-THR-3 |
| 10 | sandbox escape | cordons / fork+Wasm; seccomp/Landlock; pins | R-ISO-1..5 |
| 11 | supply chain | G1–G10 | R-SUP-1..6 |
| 12 | proof-checker false PASS | allowlist, prelude identity, Kani exit hardening | R-FORMAL-3 |
| — | outages | CFG/CERT/UPS/OPS | R-THR-6, R-OPS-9 |

Reverse: a year of KEV + advisory data reorders the top three under both metrics; q1-009 shows AI-found bugs exploited above base rate (then ≤24 h SLA for all TCB code).

## 6. STRIDE-style per boundary (checklist rows to fill per release)

| boundary | spoofing | tampering | repudiation | info disclosure | DoS | elevation |
|---|---|---|---|---|---|---|
| TB1 | SNI/:authority/Origin bind else 421 | canon reject; framing regen | audit req_id | ticket scope AAD; no 0-RTT | TBI, S0–S6 | — |
| TB2 | Principal not default-constructible | sealed handles | audit decision events | CRS σ | S6 deadlines | no ambient authority (F1) |
| TB3 | — | local-MAC .cwasm | crash-budget events | fresh instance; dumpable=0 | epoch + watchdog; crash budget | seccomp/Landlock, clone filter, exec spawn |
| TB4 | per-tenant creds | W1–W7; FORCE+WITH CHECK | outbox | two-sided read oracle | budgets rows/bytes/ms | allowlist lock; denylists |
| TB5 | trusted publishing ancestry; TUF | repro; tarball parity; vet | tlog + attestation | — | — | CODEOWNERS on spec/sdk/gates |

## 7. Response time (one table; none is a rule until the release drill runs)

| component class | trigger | SLO | grade |
|---|---|---|---|
| aegis-canon, transport wrapper, H1 framing | report/advisory | ≤24 h to signed release | C cadence / E number |
| Tier-S dependency | upstream fix | ≤7 days to signed rebuild | B direction / E number |
| any TCB component | advisory | ≤6 h to TUF release (drill target) | E |
| any feature while unpatched | — | runtime kill-switch | B |

## 8. Residual risks (pointer)
ARCHITECTURE.md §4.4 NOT-proven list is normative for this file.
