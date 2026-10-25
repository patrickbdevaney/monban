# AEGIS reference architecture and decision record, v4

| field | value |
|---|---|
| version | **v4** (first synthesis; it supersedes nothing, because ARCHITECTURE-DRAFT.md stays the working rule ledger) |
| date | 2026-10-25 |
| built from | the independent map: `state/graph.jsonl` (1,016 records), `state/edges.jsonl` (1,382), `ARCHITECTURE-DRAFT.md` (97 rules), `reports/round-001..004.md`, `state/self_improvement.md`, `state/lenses.md` |
| saturation | **NOT reached.** Round-4 mechanical novelty 0.909 (bar: below 0.2 for two consecutive rounds); Good-Turing unseen mass ~0.88 (strict singletons 0.22); decision-direction stability 85/86 = 0.988 (judged ~0.90 after discounting material amendments). Per directive §0c this document is the **build baseline**: almost every remaining open item closes by an implementation spike, not by more literature |
| prior treatments | PDF1, PDF2 and `seed_conversation.md` were read **only at this synthesis stage**, to reconcile (§10, §11). No decision below rests on prior text alone |
| grade convention | META §3. A rule's grade is its weakest load-bearing input. "E design" = our own inference from graded inputs. Tags like `[A executed / B decision / D numbers]` grade each part separately |
| companion files | `templates/{REPO_LAYOUT, IMPLEMENTATION_PLAN, THREAT_MODEL, VERIFICATION_PLAN, SPEC_INVARIANTS, SUPPLY_CHAIN, COMPLIANCE_MAP, BENCH_PLAN}.md` |

**Naming hard gate.** RFC 10032 (the AEGIS AEAD, CFRG) collides with the working name. Rename before any public release. Crate names use `aegis-` as a placeholder.

**Optimization axes are reported separately, never as one score** (directive §0): AI-adversary security · PQ confidentiality and authenticity · correctness · durability and crash isolation · performance · household leanness · developer and agent ergonomics · enterprise and government adoptability.

## 0. Re-checked on 2026-10-25 (crates.io, GitHub API, primary pages)

| item | value on 2026-10-25 | consequence |
|---|---|---|
| rustls | 0.23.46 (2026-10-14); **no SecP384r1MLKEM1024 (0x11ED)** | the 0x11ED group is AEGIS-owned code (see below) |
| rustls PR #2929 "Add ML-KEM-1024 KEM" | **merged 2026-02-23** (source of `kx_group::MLKEM1024`) | pure ML-KEM-1024 (P-CNSA) is available upstream |
| rustls PR #3293 "Add SECP384R1MLKEM1024 hybrid key exchange" | **closed unmerged 2026-10-01**; maintainer: build it through the public `SupportedKxGroup` API ("literally the 10-line structure which is in this PR") | `pred-rustls-secp384r1mlkem1024` (p = 0.6) is stale; re-scored to **p ≈ 0.2 [E]** for an upstream group by end-2027. 0x11ED enters the Tier-S TCB as our code |
| rustls-webpki | 0.103.16 (2026-10-20) | floor ≥0.103.16 |
| hyper / h2 | 1.12.0 / 0.4.20 (2026-10-06) | golden lock targets |
| tokio | 1.54.1 (2026-10-21) | Pingora 0.9.0 still panics with tokio ≥1.54 (PR #1060 open) |
| wasmtime | 50.0.0 (2026-10-20), 49.0.4 (2026-10-19); last advisory batch 2026-10-19 (GHSA-897f critical, GHSA-mghf critical aarch64) | pin unchanged |
| cedar-policy / symcc | 4.14.0 / 0.8.0 (2026-10-17) | — |
| rmcp | 3.7.0 (2026-10-22) | — |
| aws-lc-rs / aws-lc-fips-sys | 1.18.2 / 0.14.3 (0.14.3 is the decoy for the cmvp lock) | two FIPS locks |
| MCP latest dated revision | 2026-07-28 (release tag 2026-07-28T16:47Z) | both eras supported |
| Lean | v4.35.0 (2026-10-12) stable; v4.36.0-rc1 exists | pin 4.35.0 |
| Lean issue #15908 | closed 2026-10-24, "not a kernel soundness bug" (export replaced the standard prelude) | gate asserts prelude identity before `--from-export` |
| Kani | PR #4910 merged 2026-09-30; latest release 0.68.0 (2026-09-16) predates it | pin a main commit ≥ #4910 |
| Verus | 0.2026.10.18 (latest non-rolling) | CI only |
| Rust stable | 1.99.1; cargo `min-publish-age` stabilized in cargo#17335 for **1.100** (not in 1.99.1) | `xtask lock-age` fallback until the toolchain bump |
| AWS-LC FIPS certificates | #5146, #5298, #5314, #5429; **no AWS-LC 4.x certificate** (AWS-LC 4 in Comment Resolution since 2026-10-22) | R-PQC-2 reversal has not fired |
| ML-DSA in any CMVP certificate | none found | "FIPS-validated ML-DSA" impossible today |
| CRA | ENISA SRP live 2026-09-11; steward reporting Art 24(3) from 2027-12-11 | R-OPS-3 sharpened |
| NIST IR 8547 / SSDF | IR 8547 still IPD (2024-11-12); SSDF 1.1 final, 1.2 IPD | label draft gates as draft |
| EO 14412 | signed 2026-06-22; PQ key establishment by 2030-12-31, signatures by 2031-12-31 | P-UNIVERSAL / CBOM |
| AI-found CVE exploitation | VulnCheck H1 2026: 1.3% (base rate); median CVE→KEV 120 → 80 days | R-THR-2 framing |
| agentgateway / nucleus | v1.7.0-alpha.1 (2026-10-21) / v2.7.0 (2026-10-08) | §1 rescoring |
| cosign | v3.1.4 (2026-10-20) | floor ≥3.1.0 (DSSE to Rekor v2) |

Sources: https://crates.io/crates/rustls · https://github.com/rustls/rustls/pull/3293 · https://github.com/rustls/rustls/pull/2929 · https://github.com/modelcontextprotocol/modelcontextprotocol/releases/tag/2026-07-28 · https://github.com/leanprover/lean4/issues/15908 · https://github.com/model-checking/kani/pull/4910 · https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-897f-g5gm-fmxm · https://github.com/rust-lang/cargo/pull/17335 · https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5298 (also /5314, /5429) · https://www.enisa.europa.eu/news/the-cra-single-reporting-platform-is-launched · https://www.whitehouse.gov/wp-content/uploads/2026/06/eo-14412.pdf · https://the-decoder.com/ai-finds-plenty-of-security-flaws-but-almost-none-of-them-get-exploited/ · https://github.com/agentgateway/agentgateway/releases · https://github.com/coproduct-opensource/nucleus

---

## 1. Positioning and the unserved gap (§9.1)

**P-1 [C absence claim; A leanness column].** The gap is an *integration* of properties plus evidence; no single primitive is missing. The round-1..3 survey (~45 repos; `gap.unserved-combination`, `gap.no-assurance-claims`) used six loose columns. The critic showed that on a loose reading nucleus scores 4–5 of them and agentgateway 4, which would fire the round-1 reversal condition. The columns are therefore **tightened** and every candidate re-scored:

| col | tightened definition |
|---|---|
| a | memory-safe **single binary front proxy within the lean budget** (≤6 MB core, ≤60 crates) |
| b | **per-request** crash and tenant isolation (PHP-parity fault classes), not per-pod |
| c | capability authorization checked at the boundary **with fail-closed construction** |
| d | native agent-protocol handling, both MCP eras, Origin gate on by default |
| e | PQ-TLS by default **with server-enforced** hybrid on agent/API listeners |
| f | machine-checked claims **with a published TCB and NOT-proven list** |

| project (re-checked 2026-10-25) | a | b | c | d | e | f | notes |
|---|---|---|---|---|---|---|---|
| nucleus v2.7.0 | ✗ (>100 crates; tool proxy, not a front proxy) | ~ (Firecracker per pod) | ✓ (Lean 4 IFC lattice) | ~ (MCP) | ? | ~ (Lean + Kani; TCB not published as such) | closest on c/f, but for tool proxying |
| agentgateway 1.6/1.7-alpha | ✗ (not lean; front proxy yes) | ✗ | ~ (CEL; forwards client Authorization upstream; sessions not principal-bound) | ~ (Origin opt-in) | ✓ (aws-lc-rs 1.18) | ✗ (no FM/DST) | `l4.defaults-vs-configurable-matrix` B |
| Pingora 0.9 | ✗ (174 crates; tokio ≥1.54 panic, `w02.pingora-tokio-panic` A) | ✗ | ✗ | ✗ | ~ | ✗ | — |
| Envoy | ✗ (107 MB; 63 MB idle) | ✗ | ~ | ~ | ~ | ✗ | — |
| Caddy | ✗ (52 MB; 45 MB idle) | ✗ | ✗ | ✗ | ~ (Go default hybrid) | ✗ | — |
| nginx | ✗ (C; 2026 memory-bug surge, 19 of 26 advisories) | ✗ | ✗ | ✗ | ~ (OpenSSL 3.5) | ✗ | 8.05 MB with libs |

Our core measures 4.21 MB stripped, 40 crates, idle RSS 3.4–5.9 MB (`w02.size-deps-table`, `w02.idle-rss-table` A).

**Concession.** Under loose definitions the gap is narrower than round 1 claimed. The defensible unserved slot is: *a lean front-proxy binary + per-request isolation + a backend-agnostic data plane with checked tenant lowering + fail-closed authz + published TCB*. **Reverse:** a project holds ≥4 of the tightened columns. Grade stays C.

**P-2 [C demand / B deal breakers]. Who switches, and why.** In 56 public selection threads (~8,175 comments), PQ, formal verification and compliance were never stated as switching criteria; hybrid PQ is already a silent default in OpenSSL 3.5, Go and CDNs (`econ.differentiators-absent`, `v4.pq-hybrid-invisible-default` C). **Selection-bias caveat (critic):** those threads come from users of commodity proxies, so the absence says little about agent-infra or regulated buyers. This finding does **not** justify cutting proof work; it only shapes positioning copy, and q4-003 (procurement texts) is a hard input before any copy is written.
- **First segment:** agent-infra builders: credential isolation, MCP authz, audit, cost, compiled single binary (`econ.agent-gateway-criteria` C, `econ.who-switches-first` D).
- **v1 deal breakers** (`econ.deal-breakers` B): (1) ingress-nginx migration parity (annotation translation + a defaults-compatible profile tested against a Nine-style default-diff checklist); (2) no default drift; (3) no paywalled observability (so metrics ship at v1, §3.10); (4) a foundation or multi-maintainer home (River died with its grant); (5) graceful reload, rate limiting and metrics at v1.
- **Household bar:** 3-line config, auto-ACME, static binary, hot reload, rate limiting, metrics (`econ.household-criteria` C).
- **Regulated buyers** are reached top-down: BSI, ANSSI, ASD and EO 14412 mandate PQ by date (`r4e10.matrix-jurisdiction-requirements` B); the route is R-OPS-10 (§3.11).
- **Reverse:** procurement texts (RFPs, STIGs) score PQ, memory safety or formal assurance for gateways (q4-003).

**P-3 [A]. Fail-closed construction is the positioning floor.** Empty or absent policy meaning allow-all recurs in NATS, Kafka, FDB, Hasura, Turso, Syncope (CVE-2026-73579) and LiteLLM (CVE-2026-59822, KEV 2026-09-02: an error produced an empty principal) (`dpf-empty-means-all-pattern`, `r2e11.litellm-failopen`). CI boots the shipped default config and fails if any effective limit is `None`.

---

## 2. Threat model (§9.2; full version in `templates/THREAT_MODEL.md`)

### 2.1 Adversary classes

| id | adversary | capability assumed | key evidence | grade |
|---|---|---|---|---|
| **AA1** | AI-automated vulnerability discovery on our public source and deps | finds reachable parser/budget/logic bugs in weeks; known bugs get rediscovered | Wasmtime LLM sprint: 11 of 12 advisories in 3 weeks, diminishing after week 1 (`wasmtime-llm-audit-sprint-2026-04` A); HTTP/2 Bomb found by reasoning (`v.http2-bomb-cve-2026-49975`); OpenSSH 10.6 notes independent rediscovery (`r3e11.ai-found-bug-flood-vendor-posture` A) | A (capability) |
| AA1-skeptic | same, measured against outcomes | volume ≫ exploitation: 14 of 1,061 AI-assisted CVEs exploited (1.3%, base rate); Glasswing >23k findings → 126 CVEs → 1 exploited; AIxCC CRSs patched 0 of 6 C zero-days outside the competition | `skeptic-ai-exploit-overhype` B, `v.aixcc-sok-usenix26` C; VulnCheck H1 2026 re-checked; 24 h / 8 h time-to-exploit claims are D | B |
| AA2 | live adaptive protocol agents | cheap per-probe reasoning over H1/H2/H3 state; choose the cancellation instant | MadeYouReset (RUSTSEC-2025-0070); hyper drops the service future on RST_STREAM (`ac.attacker-chosen-cancel-instant` B); HAProxy H3→H1 desync (`r2e11.haproxy-cve-2026-33555`) | A/B |
| AA3 | agent swarms (abuse economics) | residential proxies, CAPTCHA solving, headless browsers, LLM calls at 2026 prices | `r3e07-price-sheet-2026-10` B | B prices / D our numbers |
| AA4 | authorized but confused agent (prompt-injected client holding a real capability) | valid token; attacker-controlled inputs | CaMeL (`camel-2503.18813`), Progent (`progent-2504.11703`), `approval-to-abuse-2610.22987`, `dpf-agent-db-tool-bypass-cluster` | B (class) |
| AA5 | malicious agent-protocol client | Origin/session/audience/JSON-parser gaps | 43-case corpus vs 5 implementations: Origin protection off or absent in rmcp, agentgateway, py and TS (`l5.mcp-lc-passrate-matrix` B); LiteLLM fail-open in KEV | A/B |
| AA6 | agents in our supply chain and dev loop | slopsquatting; edits to SDK/capability code; proof cheating (7–14% without a static checker) | `sc3.slopsquat-rust-study-2606` B, `llm-verusage-2025` B, `rec60-spec-fidelity-verus` A | B |
| AA7 | attacker on the proof pipeline | adversarial Lean metaprograms, malicious Lake deps, crafted exports | `v4.lean-soundness-threat-is-build-supply-chain` B; checker disagreement on #15908 (`v4.lean-checker-disagreement-15908` B) | B |
| AA8 | malicious tenant module / third-party adapter | arbitrary Wasm or out-of-process code in its cordon | M0 escape planning rate 2.21/yr [1.14, 3.86], 0.36/yr since 2024, 1.23/yr 2026 YTD (`r4i04.m0-escape-rate-denominators` B); Oct-2026 Cranelift criticals (`rec60-wasmtime-cranelift-crit-2026-10` A) | B |
| AA9 | network adversary incl. harvest-now-decrypt-later | records now; downgrades where possible | **RUSTSEC-2026-0349 is a client-side bug** (poisoned per-server-name key-share prediction, `rec60-rustls-0.23.46-downgrade`); its server-side relevance is only the HRR mitigation, executed in `r3pq.hrr-acceptance-test` A | A |
| AA10 | insider / compromised operator or CI | config push, key access, runner compromise | config push largest outage class 17.5% (`uu11.outage-class-frequency-table` C); Cloudflare 2025-11-18 (`uu11.cfg-push-class` A); 5 of 12 supply-chain incidents were CI compromises (`sc3.incident-class-fractions` B) | C/A |
| AA0 | non-adversarial failure | config, certs, exhaustion, retry storms, DNS, reload | 0 of 160 coded outages from memory corruption (R-THR-6). **Caveat:** public postmortems exclude breaches by construction, so this does **not** down-weight memory safety | C freq / A–B instances |

**What follows from AA1 [B decision].** The question shifts from "will they find bugs?" to "what does a found bug yield?": (i) **reachable-unproven-surface mass** is a security budget, not only a leanness goal; (ii) **fix-to-deployed time** is the response variable (§3.14 SLA table). Proofs help against AA1 only to the rung they reach: an **R5** proof (on the shipped code) removes in-spec bugs; every proof we have today is **R4** (a model linked to Rust by DRT), which *shrinks* the search space to renderer, codec and DRT gaps but does not remove it. The residual concentrates on spec fidelity and glue: in the 2017 EuroSys study of verified distributed systems (one sample, scope: three verified systems), 16 of 16 bugs were in shims, specs or assumptions, none in verified cores (`fail-spec-fidelity-studies` A).

### 2.2 Assets (by blast radius)
1. Cross-tenant data confidentiality and integrity (rows, objects, cached responses).
2. Authority material: token MAC keys, STEKs, TLS keys, per-tenant DB credentials, signing and TUF keys.
3. Availability per tenant and global, on a 1-vCPU box.
4. Audit-log integrity and completeness.
5. Build identity: lockfile, toolchain digest, proof artifacts, attestations.
6. PQ confidentiality of recorded sessions (HNDL horizon).

### 2.3 Trust boundaries

```
 Internet (browsers, REST agents, MCP agents, browser-driving agents, AI exploit tooling)   AA2 AA3 AA5 AA9
   │  TLS 1.3 only; one TLS mode per port (R-TLS-8); jurisdiction kx profile per listener
 ┌─▼──────────── supervisor (exec-spawned; holds listen sockets, STEK ring, crash budgets) ─────────────┐
 │ TB1 B1 transport: rustls + hyper/h2 + AEGIS budget wrapper (TBI-1..9)                               │
 │     B2 aegis-canon: one owner per identity kind, reject-don't-repair (CANON-1..8)                    │
 │     B3 admission S0..S6 (pre-auth GCRA, classes, aggregate cost budgets, CoDel, deadlines)           │
 │     B4 authn → Principal (not default-constructible) → Cedar PDP + token verifier → tri-state Combine│
 │ TB2 B5 handler dispatch by provenance [capability boundary: sealed Cap<O>, Ctx<'r>, no ambient]       │
 │        P1 native (scoped SDK)  │ TB3 P2 fresh Wasm in per-tenant OS cordon, or fork+Wasm  │ P3/P4    │
 │        └──────── effect API (host-staged; NC1–NC8 commit-point latch, outbox) ───────┘     proc/µVM  │
 │     B6 data plane: typed Op IR → per-adapter lowering (Lean-checked model) → allowlist lock          │
 │        C-binding / third-party adapters out of process (seccomp+Landlock, postcard over UDS)         │
 │     B7 effects: outbox, idempotency store, tlog-tiles audit                                          │
 └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
   │ TB4 per-tenant native creds (RLS role / STS tags / ACL user); RLS FORCE+WITH CHECK = defence in depth
   ▼ databases, any family; engine bugs in scope (PG BUG #19645, ON CONFLICT-before-RLS)    ▼ egress guard (pinned IP)
 TB5 build side (never shipped): Lean 4.35 Init-only + 6 checkers, Kani ≥#4910, Verus+Z3, TLC; cargo vet/deny,
     cooldown, repro double build, SLSA/TUF. Agents (AA6/AA7) may write code and proofs; they may NOT edit specs,
     the SDK, gate scripts or allowlists.
```

### 2.4 Ranked threats (both metrics kept)

| rank | class | KEV / in the wild | Rust-stack advisory volume | AI-era multiplier | grade |
|---|---|---|---|---|---|
| 1 | H2/H3/QUIC protocol-state exhaustion, incl. translation amplification and stalled flow control | low KEV | ~55% of deduped clusters since 2023, falling | high (HTTP/2 Bomb by reasoning; Calif ratios up to ~5,700:1 on Envoy, `v2.calif-h2bomb-ratios` B) | A class / B share |
| 2 | identity canonicalization divergence, fail-open authz | **leads KEV** (5–6 of 8 OSS middle-tier entries) | rising: 34 dated instances, 24 from 2026 (`r4e07.instance-ledger` B) | high | A/B |
| 3 | smuggling and parser differentials (H1, H3→H1, Upgrade: TLS) | yes | steady | high (`http1-desync-2025` B) | A |
| 4 | TLS logic and PQ downgrade | — | 25% of 2026 clusters | medium | B |
| 5 | agent-protocol origin/session/audience, confused deputy | LiteLLM KEV | MCP SDK cluster Apr–Oct 2026 (`j-mcp-sdk-advisories`) | highest growth | A/B |
| 6 | cross-request state scope (tickets, pools, caches, reused instances) | nginx CVE-2025-23419 | — | medium; any reused context poisons (`r4i04.state-leak-c8-measured` A) | A |
| 7 | async cancellation (attacker picks the instant) | redis-py / ChatGPT 2023 | 15 instances, 6 in 2026 | medium-high | A inst / B class |
| 8 | data-plane injection and authz per family, incl. writes | — | upsert captures another tenant's row 261/300 (`wpo-upsert-keyspace-capture` A) | high | A |
| 9 | memory corruption (RCE tail) | 2026 C-server surge (httpd 20 of 44) | Rust protocol logic unsafe-free | high for the C still in our TCB | A |
| 10 | sandbox escape (Wasm/kernel) | — | 2.21/yr planning rate | high | B |
| 11 | supply chain (account takeover, slopsquatting, OSV blind spots) | xz class | 7 of 133 repo GHSAs invisible to OSV (`r4c12.repo-ghsa-osv-blindspot` A) | high | A |
| 12 | proof-checker false PASS | — | Kani #4905; Lean 2026 record | new | B |
| — | non-adversarial outages: config 17.5% > latent bug 12.5% > exhaustion 10.6% | — | — | — | C |

**Reverse:** a year of KEV and advisory data reorders the top three under both metrics; or q1-009 shows AI-found bugs are exploited above the base rate (then the ≤24 h SLA becomes a rule for all TCB code).

---

## 3. Reference architecture: component record (§9.3)

Each entry: pick, pin, ≥2 alternatives, grade, reversal.

**Pin hygiene (one rule, applied in every file).** `Cargo.toml` uses caret ranges plus **security floors**. The exact versions below are what the **golden `Cargo.lock`** must resolve to, enforced by `cargo metadata` gates; byte identity comes from `--locked` + lock gates, which keeps the security-bypass path open (R-SUP-3). The **cmvp FIPS lock** is the only place with `=` pins in a `Cargo.toml` profile, because certification needs byte identity of the module (R-PQC-2).

### 3.1 Transport and HTTP

- **Pick [A]:** hyper 1.12.0 + h2 0.4.20 on tokio 1.54.x, epoll, HTTP/1.1 + HTTP/2. Floors: hyper ≥1.12.0, h2 ≥0.4.20.
- **Golden settings** (`l5-config-pin-table-transport`): max_concurrent_streams 100; max_header_list_size 16384; header_table_size 4096; max_pending_accept_reset_streams 20; max_local_error_reset_streams 256; stream/conn window 256 KiB / 1 MiB; max_frame 16384; send buffer 400 KiB; keepalive interval and timeout 20 s.
- **AEGIS wrapper (ours; hyper/h2 lack these):** field count ≤128 incl. cookie crumbs; handler semaphore 100 with 4× queue, then GOAWAY ENHANCE_YOUR_CALM; RST bucket burst 100, refill 33/s; ≤10k total streams per connection; per-stream stall deadline 10 s; connection idle 30 s; Host vs :authority binding (hyper/h2 never compare them: `r4e07.hyper-h2-authority-host-unchecked` A).
- **Invariant:** TBI-1..9 (`l5-transport-budget-invariant-tbi` B): Kani for pure counters, Verus for ledgers, Lean for composition, fuzz (resource-ratio oracle) + DST for stalls.
- **Upstream framing [B]:** H2 or framed UDS; any H1 upstream regenerates framing (R-TLS-3).
- **Alternatives:** Pingora core (174 crates; tokio panic; MadeYouReset RUSTSEC-2025-0070) — not a base. Hand-written H1 + EverParse/Vest framings — no verified HPACK/QPACK decoder exists in any prover (`l4-no-verified-hpack-qpack-decoder` B); Vest H2 frame header only as later hardening. io_uring thread-per-core — rejected (D-2).
- **Reverse:** hyper/h2 ship a field-count cap and stall timer → shrink the wrapper; measured C_FIELD makes TBI-7 exceed 16 MiB/connection → lower the stream cap.
- **HTTP/3 [A/B]: off in the golden** until hyperium/h3 #366/#377/#378 land (#366 open 2026-10-25; h3 0.0.8 has `max_field_section_size = VarInt::MAX`). If enabled: quinn ≥0.11.19, receive_window 4 MiB (default ≈250 MB/conn), 100 bidi / 8 uni, ACK_FREQUENCY and datagrams off; QUIC listener authenticates with ECDSA only (any ML-DSA chain ≥10.5 KB breaks the 3× anti-amplification budget, `r3pq.quic-amp-budget-mldsa` B, modelled). Alternatives: s2n-quic (sane 3.75 MB defaults); quiche (lower its 24 MiB window). Reverse: h3 merges finite defaults and quinn has 6 months without a HIGH advisory (11 GHSAs in 2026, 3 HIGH invisible to OSV).

### 3.2 TLS, PQC and certificates

- **Pick [A]:** rustls ≥0.23.46 + aws-lc-rs, rustls-webpki ≥0.103.16. `prefer-post-quantum` asserted on **every** rustls in the lock via `cargo metadata` (the golden's own direct dependency lacked it until round 4, `r4tri.golden-lock-no-pq-feature` A); `kx_groups[0]` asserted at startup.
- **Per-listener kx policy** (executed, `r3pq.hrr-acceptance-test` A 0.93). rustls 0.23.46 server follows the **client's** group order and sends HRR only when the share for the group it picked is missing.
  - **Agent / API / internal listeners: pq-required**, `kx_groups=[X25519MLKEM768]`: hybrid-listing clients get HRR; X25519-only clients get alert 40.
  - **Public browser listener:** server `kx_groups` lists hybrid first. Under client order, a client that lists hybrid first but sends only an X25519 share (the RUSTSEC-2026-0349-poisoned shape) gets HRR to hybrid (verdict PUB-T1). **Exact residual: clients that list X25519 before hybrid, or offer only classical groups, negotiate classical.** With >65% of human HTTPS already PQ-hybrid (`pq-share-telemetry` A, Cloudflare Apr 2026), that residual is about a third of human clients.
  - `ServerConfig.kx_selector`/`PreferServerOrder` is on rustls main as 28ee6c68. **Backport it** onto the golden rustls as a patch carried under the exception ledger (SUPPLY_CHAIN) rather than waiting for a release; then public listeners can prefer hybrid server-side (residual shrinks to classical-only clients).
  - **Verdict file (F12, `tls/verdicts.toml`)** freezes 12 verdicts: PUB-T1..T6 from `r3pq.hrr-acceptance-test` and FIPS-F1..F6 from `r4tri.fips-handshake-verdicts`. Any change blocks a rustls/aws-lc bump. Other files cite verdict ids, never a count.
- **Jurisdiction profiles (R-PQC-8) [A primaries / B decision]:**

  | profile | groups | notes |
  |---|---|---|
  | P-PUBLIC-WEB | [0x11EC X25519MLKEM768, 0x11ED, 0x11EB, X25519, P-256] | browser interop |
  | P-UNIVERSAL | [0x11ED SecP384r1MLKEM1024] | the only group in the **intersection** of the US-civil, EU (BSI/ANSSI), UK, AU, CA and JP post-2030 lists. (Individually, US FIPS accepts 0x11EB and UK NCSC accepts ML-KEM-768.) |
  | P-BSI-ALT | [0x11ED, 0x11EB] | — |
  | P-CNSA (opt-in, US NSS) | [0x0202 ML-KEM-1024] + ML-DSA-87 | pure ML-KEM is non-conformant in France (ANSSI-PG-083 v3.00) and hybrid-only in BSI TR-02102 (`r4e10.anssi-pg083-pure-nonconformant` A) |

  All government profiles: TLS 1.3 only, AES-GCM only; no 0-RTT, X25519, Ed25519 or ChaCha20.
  - **0x11ED is AEGIS-owned [A fact / B decision].** rustls PR #3293 closed unmerged; build a `SupportedKxGroup` composing aws-lc-rs P-384 ECDH + ML-KEM-1024 (RFC 10024 order). It enters Tier-S TCB with: KATs against draft-ietf-tls-ecdhe-mlkem vectors; interop vs OpenSSL 3.5+ and BoringSSL; a Kani panic-freedom harness on share parsing (**Phase-6 gate**, not optional); a FIPS-boundary check that both components are inside the AWS-LC 3.1.0 approved boundary before claiming FIPS for P-UNIVERSAL. Reverse: an upstream rustls group lands (p ≈ 0.2, E).
- **FIPS (R-PQC-2) [B]: two locks**, because no lock satisfies both rustls ≥0.23.44 and fips-sys 0.13.11 (`r4tri.no-co-resolvable-lock` A 0.95).
  - **floor:** rustls 0.23.46 + aws-lc-rs 1.18.x; module source AWS-LC FIPS 4.2.0, **not certified**; no CMVP claim.
  - **cmvp:** rustls =0.23.43 + aws-lc-rs =1.15.3 + aws-lc-fips-sys =0.13.11 = AWS-LC FIPS 3.1.0 (CMVP #5298/#5314). aws-lc-rs window 1.15.2–1.17.1 (1.17.2 yanked). Tested operational environments **Amazon Linux 2023 only** (`r4tri.tested-env-only-al2023` A 0.85), so Debian/Ubuntu/musl household builds cannot claim approved mode. ML-KEM approved; ML-DSA and SLH-DSA not; X25519 outside the boundary. FIPS listener groups explicit: [SECP256R1MLKEM768, P-256, P-384] with `config.fips()` asserted (DEFAULT_KX_GROUPS lacks 0x11EB even with prefer-post-quantum).
  - **cmvp advisory ledger and the 0349 correction (critic).** The cmvp lock carries RUSTSEC-2026-0042/0043 (fips-sys), 0349, 0285/0346/0348 and webpki 0382. **0349 is a client-side bug**, and the architecture *does* contain rustls clients (instant-acme ACME, the egress guard, H2 upstream to origins, ML-DSA-44 mTLS origin pulls). The earlier justification "uses no rustls client" is therefore **invalid as specified**. The cmvp profile must satisfy one of two gated conditions, and the ledger entry cites which:
    1. **clients compiled out:** feature `tls-client` off in cmvp; a `cargo metadata` + symbol gate proves no `rustls::ClientConfig` construction is reachable; ACME runs as an external process; upstreams are reached over local UDS/h2c or through a separate egress process; **or**
    2. **clients PQ-only:** every cmvp `ClientConfig` has `kx_groups=[SECP256R1MLKEM768]` (no classical group to downgrade to) and no client resumption/key-share-prediction store; a startup assertion and a unit test enforce it.
  - **Gates:** exactly one fips-sys node reachable from aws-lc-rs (defeats the decoy lock: `try_fips_mode()` cannot tell 3.1.0 from 4.2.0, `r4tri.fips-sys-decoy-lock` A, `r4tri.try-fips-mode-blind` A); the string `AWS-LC FIPS 3.1.0` present in the release binary; `FipsStatus` to the audit log and `/healthz`.
  - **Alternatives:** fork rustls 0.23.46 with ML-DSA stripped against aws-lc-rs 1.15.3 (~30 edits, spike); OpenSSL 3.5 FIPS provider (C TCB); floor-only with no CMVP claim.
  - **Reverse:** an AWS-LC 4/5 certificate whose module string matches a fips-sys version; rustls 0.24 changes the aws-lc-rs bound.
- **Authentication (R-PQC-4) [B]:** public WebPKI stays ECDSA-P256 (CA/B SC-106, ML-DSA in public X.509, withdrawn 2026-10-21, `r3pq.cab-sc106-withdrawn` A). Certificate layer is a `CredentialSelector` over X.509, standalone MTC and landmark MTC; Chrome CQRP tests MTC in Chrome 152 Canary (`r3pq.chrome-cqrp-testing` A); adopt rustls TrustAnchorResolver when PR #3376 lands. Private hops use ML-DSA-44 now (11.7 KB flight, fits initcwnd 10, ~+90 µs server CPU, `r3pq.mldsa-handshake-measured` A); gov profiles ML-DSA-87. Reverse: Chrome Stable ships MTC and rustls merges #3376 (p = 0.55 for 2027), or CRQC estimates move inside 2030.
- **Tickets and 0-RTT (R-PQC-6) [A/B]:** one ticketer per (cert-chain hash, verifier, ALPN, epoch) with scope in AAD; no resumption on mTLS listeners; STEK ≤24 h with a 2-key window; refuse an all-zero key; 0-RTT off; STEK crosses an upgrade by pipe only. Evidence: nginx CVE-2025-23419, Apache CVE-2025-23048, Hebrok (USENIX Sec'25).
- **PQ-signed tokens (R-PQC-7) [A]:** in the body or by reference; a 16 KB header fails on default nginx, hyper and Node, and HPACK never indexes multi-KB literals.
- **Release signing (R-PQC-5, amended) [B decision / C jurisdiction fit]:** the release manifest carries **three detached signatures**, AND-composed per profile: Ed25519 (ecosystem tooling; never the only one), SLH-DSA-SHA2-128s (stateless, hash-only hedge for a solo key), ML-DSA-87 (CNSA/ASD buyers; SLH-DSA is absent from CNSA 2.0 and ASD's approved list, `r4e10.golden-signature-profiles` B). Gov profiles drop Ed25519 from the required set. LMS/XMSS only with HSM-enforced state (RFC 10033 state-reuse forgery hazards, `r3e11.rfcs-published-in-window` A). The earlier "SLH-DSA-SHAKE-256s for AU" option is withdrawn (contradicted by the ASD list).
- **Non-FIPS crypto provider (Phase-7 spike) [C].** The floor/household profile makes no CMVP claim yet ships ~2.09M bundled C/asm lines (r4 measure of the floor `aws-lc-sys` tree, including generated asm; re-measure per lock profile, since the cmvp lock bundles AWS-LC 3.1.0 and differs). Spike: a `CryptoProvider` from verified ML-KEM (libcrux, hax/F*) + audited X25519/P-256, to shrink Tier-S C for P-PUBLIC-WEB. Claim if adopted: "smaller C surface", not "verified TLS" (verified libraries still ship unverified wrappers: RUSTSEC-2026-0331/0329; `fail-libcrux-spec-bugs-2026` A).

### 3.3 Parser and normalizer (ingress core)

- **Pick [B decision; A executed differential; E invariant]:** one normalization core whose object is an **Exchange** with a message stream (per-message and per-lifetime budgets, non-destructive, raw bytes retained). Feature-gated front ends: WS, SSE, WebTransport as stream modes; gRPC, GraphQL, MCP, webhooks as handler layers; L4/PROXY a separate crate. Zero-copy normalization: 30 µs user CPU per 10 MB (`w02.norm-copy-cost-measured` A 0.75).
- **aegis-canon (R-ING-4):** pure, `forbid(unsafe)`, one `canon_K` per identity kind, sealed `Canon_K` newtypes. CANON-2 reject-don't-repair (encoded `/ \ ;` NUL, dot segments, duplicate singletons, duplicate JSON keys, NBSP-trimmed cookies, duplicate media-type params, userinfo in :authority). Hosts: exact ASCII-lowercase A-label match, **no IDNA on ingress**. SNI, :authority and Origin bind to one vhost, else 421. Authz keys only on the matched route id (grpc-go CVE-2026-33186 matched a raw `:path`). JSON: I-JSON, parsed once by a duplicate-rejecting serde_json 1.0.154 visitor shared by policy and handler; simd-json and sonic-rs banned.
  - **Executed:** a strict reference canonicalizer drove pairwise disagreement on accepted inputs from 331/331/69 to 0/0/0 (paths, hosts, JSON) across 12 Rust parsers + CPython (`r4e07.canon-ref-zero-disagreement` A).
  - **Gate CANON-DIFF G1–G4:** ≥100k-case proptest; pinned WPT + IdnaTestV2 through every identity parser in the lock in <1 s; 34 dated regressions; lock bans.
- **Front ends (R-ING-2) [A classes / C numbers]:** WebSocket — typed Origin, leave framed mode only after a validated 101 (Pingora CVE-2026-2833), no permessage-deflate, 1 MiB message / 64 KiB frame. gRPC — explicit limits (tonic 0.14.6 passes `None`, overriding hyper's 200). GraphQL — behind the core; 415 on text/plain, 405 on mutation-over-GET, 64 KiB body, explicit depth/complexity/alias (async-graphql 7.2.1 defaults all `None`). Webhooks — raw-byte signature with `subtle` compare, replay store TTL ≥ retry horizon (Stripe 3 days), egress guard. SSE — ≤8 streams per principal.
- **Alternatives:** per-protocol stacks (rejected unless a front end needs >2 core hooks); normalize-and-forward-canonical (lighttpd, Cloudflare, DISA) as a per-clause fallback; WHATWG host parsing on ingress (rejected: IPv4 shorthand, #914 Bidi drift, `v4.whatwg-914-bidi-deno-divergence` B).
- **Reverse:** per clause, if the false-reject spike shows >0.1% on real request lines (q4-008); no-IDNA if golden clients send U-labels.

### 3.4 Admission and abuse control

- **Pick [B mechanisms / D numbers]:** S0 → S6 for 1 vCPU, from round 3's deterministic simulator.

  | stage | rule |
  |---|---|
  | S0 | 2,048 connections, 32 per IP prefix, 10 s header deadline |
  | S0.5 handshake reservation | full TLS handshakes use ≤50% of each 5 ms accept window (sim: human failure 7.9% → 0.9%) |
  | S1 pre-auth GCRA (governor 0.10.4) | 10 req/s, burst 50, O(1) eviction |
  | S2 classes | verified 0.30 / established 0.40 / fresh (<60 s cookie) 0.10 / anonymous 0.20 |
  | S3 aggregate expensive-tier budgets, identity-count independent | A_f = 300 units/s (fresh + anonymous), A_e = 400 (established) |
  | S4 | step-up 16-bit PoW for anonymous cost ≥100; rungs {16, 18}, never 24 (112 s in a browser); accessible lane required |
  | S5 | Gradient2 min 4 / initial 8 / max 32; CoDel 20 ms cheap, 250 ms expensive |
  | S6 | 250 ms deadline/fuel; DB timeout 2 s; pre-debit, cancels charged (NC4) |

  Rejects: 429 + Retry-After per identity, 503 with jitter globally, **never 200**.
- **Why:** round-2 defaults collapse under a 10k-IP solver swarm (99.1% human failure); per-identity budgets are non-binding once N ≥ B/b (I11); per-IP limiting alone gives 74–98% human failure (`r3e07-r2-defaults-collapse`, `r3e07-per-ip-collapse` D).
- **Honest status:** the tuned table **fails** C1 in aged_swarm, flash_crowd and worst-seed dc_swarm, and C2 under cheap_flood; fitted in-sample (`r3e07-L5-swarm-acceptance-criteria` r4, D). Numbers are provisional config defaults, not claims.
- **R-ABUSE-5 [D/B]:** make expensive endpoints cheap/cached first (Forgejo CPU 100% → 10%); behaviour scores only weight budgets; a hard deny needs a cryptographic identity signal (classifier FP 4–6%, XGuardian).
- **Alternatives:** PoW-gate-first/Anubis (headless Chrome solves it; returns 200; speed bump only, `abuse-anubis-bypass-evidence` B); Privacy Pass (trusted issuer only); x402 payment gating (not golden; volume unverified, `cal-x402-volume`); ASN/subnet keying (unmeasured).
- **Reverse:** calibrated rerun — q3-001 (real 1-vCPU handshake), q3-003 (pre-crypto PSK visibility), q3-005 (sim v2 on held-out seeds).

### 3.5 Authentication and authorization

- **PDP [C decision; A/B inputs]:** Cedar 4.14.0 + cedar-policy-symcc 0.8.x; policies validated and SMT-checked at deploy; an error in a forbid yields Deny. Claim wording: "verified Lean model + DRT-tested Rust evaluator". Cedar Lean theorems cited at **B** until `#print axioms` runs on CI (Int64 `native_decide` is in the TPE closure, 159 modules / 41k LOC, `r4e01.cedar-tpe-closure-native-decide` B). cvc5 #12926/#12927 in the SymCC TCB. G10 watches Cedar GHSA-m84h (<4.13, invisible to OSV; 4.14.0 clean).
  - Alternatives: OPA/Rego (no verified evaluator; SQL compile unsound for SQL Server LIKE, `irl-opa-compile-sql-lowering-defects` A); SpiceDB/OpenFGA (Zanzibar, kept for relationship-heavy apps); Biscuit (rejected, D-3).
- **Combiner (R-AUTHZ-5) [A]:** tri-state Allow/Deny/Error; error, timeout or crash → Deny. `Combine.lean` checked: empty ⇒ deny, any error ⇒ deny, allow iff unanimous, never returns error (`r4e01.combine-failclosed-first-check` A; round-2's "proven" claim had no file). `Principal` not default-constructible. Host mapping of timeout/crash/panic → Error is untested (DST, Phase 3).
- **Capability token (R-AUTHZ-2/6) [B decision; A model only]:**

  | tier | format | measured cost |
  |---|---|---|
  | Tier 0 (default) | opaque handle + server table | verify 83 ns; instant revocation |
  | Tier L | HMAC-SHA256 chain, deterministic CBOR `[1, kid, nonce, caveats[1..64], tag]`; closed caveats {aud, exp, nbf, ops mask, res_prefix, cnf_jkt, tenant, tool+argcon, depth_left}; K_aud = HKDF(K, 'aegis-cap-v1'‖aud‖kid); exp ≤900 s; ≤4 KiB | 5 caveats 1.2 µs |
  | Tier X | COSE_Sign1 ML-DSA-65 (RFC 9964), only at trust-domain crossings | 114 µs, ~7 KB |

  Attenuation evaluates the **conjunction of every caveat**; leaf-only + subsumption rejected (Tenuo CEL bypass confirmed, unfixed on main 486be6819; private disclosure pending with the operator). Lean T1–T5 checked (16 theorems, `r4e01.token-T1-T6-checked` A) — **model only: HMAC EUF-CMA, the CBOR codec round-trip and constant-time compare are assumed; T5 `verify_iff` is definitional and has no security content without EUF-CMA.** To ratify at spec freeze: D1 segment-prefix resources (plain prefix lets /t1 admit /t10); D2 op-bitmask subset; D3 depth at verify; D4 missing argument denies; add a mint-shape check to drop the WellMinted hypothesis. Verifiers take `now` as a parameter. CBOR parser: EverParse deterministic-CBOR Rust v2026.10.07 vendored at a tag (record the real crate name; `cbordet*` in the tree).
  - Rejected: Biscuit (3 blocks 158 µs; no PQ; 1 ms wall-clock `max_time` → 5 in 40,800 nondeterministic denials); UCAN (crates.io 0.4.0 from 2023); ZCAP; JWT (Token Time Bomb, NDSS'26: 31 vulns across 43 implementations).
  - Reverse: offline third-party verification without a shared secret → Tier X default; AAT/DT adopted by a WG with COSE + ML-DSA → use as Tier X; Biscuit ships PQ + deterministic fuel; Tier 0 p99 >5 µs at depth 8.
- **Agent endpoints (R-AUTHZ-4, R-AGENT-3) [A/B]:** RFC 9728 PRM, RFC 8707 audience binding, RFC 9207 iss (MUST in MCP 2026-07-28), CIMD instead of DCR; Web Bot Auth / RFC 9421 verification only after S1 (attacker-triggerable cost); external OAuth tokens terminate at ingress and are exchanged; RFC 8693 `act` informational only.

### 3.6 Isolation substrate

- **Pick [E design; A perf; B containment; C advisory rate]:** substrate by code provenance (R-ISO-1/5, amended).

  | provenance | substrate | acceptance (fault gate at 1% rate) |
  |---|---|---|
  | P1 first-party Rust | native, scoped SDK (§3.12); catch_unwind; resource ledger; recycle at 1,000 requests; supervisor-held socket | panic 0; abort/segv ≤12 healthy failures per fault; fd leak and poisoning 0 by lint |
  | P2 agent-generated, single tenant | **fresh** Wasmtime instance per request (reuse 1; fuel 10–50 ms; 16 MiB) in a **per-tenant** cordon (seccomp + Landlock, exec-spawned) | ≤0.05 healthy failures per fault, 0 wrong answers, recovery p99 ≤5 ms, poison 0 |
  | P2, multi-principal data | **co-equal default candidates:** fork child of an exec-spawned single-threaded zygote running Wasm (**fork+Wasm**), or one cordon per principal. Decided in Phase 1 by q4-006 (fuel + 64-slot pool loop gate) + a VPS fork-cost run | fork 7/7 PHP-parity classes, 0 on every fault class, LOOP p99 ×3.37 vs fresh Wasm ×34.7 |
  | P3 third-party multi-tenant | per-cordon processes or microVM | — |
  | P4 arbitrary native | microVM / gVisor | — |

  Measured containment, 740 cells (`r4i04.blast-radius-table` B, `r4i04.php-fpm-measured-control` B): PHP parity is fork 7/7, fresh Wasm 6/6 (fd leak not expressible), native 1/7. Poison: native 97, Wasm reuse 93, fresh Wasm 0, fork 0.
- **Why fork+Wasm is built now, not left as a reversal (critic, arithmetic).** Reversal R1 is "≥3 M0-class escapes in 12 months". Under Poisson at the planning rate λ = 2.21/yr, P(≥3 in 12 months) = **0.38** (≈0.13 at the 2026-YTD 1.23/yr; 0.006 at 0.36/yr). The earlier "P ≈ 0.14" did not match the stated rate. At 0.38, moving P2 to fork+Wasm is the likely state within ~2 years, so **Phase 5 builds and gates both paths**. Fork's cost (124 µs–1.5 ms per request) is the counterweight.
- **Wasmtime pin (R-ISO-2) [B]:** ≥36.0.19 (36 LTS) or ≥49.0.4 on any arch (aarch64 GHSA-mghf affects 37.0.0–48.0.6); 50.0.0 current. `default-features=false` + cranelift, pooling-allocator, runtime, std (+component-model); no component-model-async, gc, threads, winch, wasi-fs. memory64 and gc false explicitly; default 4 GiB reservation + 32 MiB guards, **never density-tuned by guard shrinking** (GHSA-6wgr, GHSA-394w); epoch + ResourceLimiter. **Never wasmtime-wasi-http for egress** (RUSTSEC-2026-0350/0376); egress via a narrow fetch host function. `.cwasm` precompiled and MACed locally; never `Module::deserialize` untrusted bytes (runwasi CVE-2026-47218). `wasmtime serve` instance and concurrent reuse pinned to 1.
- **MPK (corrected).** MPK *was* measured (`wasmtime-pooling-local-bench`: pooling p50 6.9 µs vs 7.1 µs with MPK, no latency gain). MPK striping is Wasmtime's supported way to get density *while keeping* guard protection; it is not guard shrinking. Keep it as a **density option** behind the same GHSA-6wgr/394w config assertions; not rejected, not default.
- **Fuel vs epoch reconciled:** the DoS **bound** is the epoch plus a wall-clock watchdog in host code (R-ISO-3: fuel is not a security bound, `fuel-not-a-security-bound` B). Fuel is the deterministic per-request compute budget for replay and accounting.
- **OS sandbox (R-ISO-4/5) [A/B]:** Landlock then seccomp installed once per zygote (+135 µs per install measured, `zygote-sandbox-recipe-measured`); hot syscalls argument-free (bitmap cache, +18–30 ns); clone-flag filter denies CLONE_NEW*, clone3 → ENOSYS, unshare/setns denied (`r4i04.seccomp-clone-flag-gap`); child denies socket, setsockopt(TCP_ULP), bpf, perf, io_uring; PR_SET_DUMPABLE=0 (under apport p99 104 ms → 2.4 ms, `r4i04.coredump-pipe-hang` A); **exec spawn** (a respawned fork server is a BROP crash oracle); per-principal crash budget 3 in 60 s → 429 for 10 min.
- **Alternatives:** V8 isolates (OOM process-fatal without NearHeapLimitCallback); Hyperlight/Firecracker (P3/P4); gVisor (P4); Wasm-only boundary (rejected as sole boundary at 2.21/yr); instance reuse (93 poisoned answers, rejected).
- **Reverse:** R1 ≥3 M0 escapes in 12 months (P ≈ 0.38 at λ = 2.21) or Wasm patch lag >7 days → fork+Wasm default for all P2; R2 a kernelCTF LPE reachable through the worker allowlist → microVM tier; R3 fork overhead <0.3 ms → fork+Wasm default; R4 an audited `Instance::reset` passes the poison test → reuse allowed; R5 P1 unsafe/globals cannot be eliminated → P1 to cordon-recycle.

### 3.7 State, WAL and idempotency

- **INV-NOMUT-C (R-STATE-6) [B]** replaces "failed request ⇒ no mutation": NC1 cancellation = failure; NC2 commit-point latch (timer after CP → 202 + idempotency retrieval, never 408); NC3 discard-on-cancel checkin (reusable only if ReadyForQuery ∧ txn `I` ∧ no outstanding replies ∧ server objects closed); NC4 pre-debit, cancels charged; NC5 cancelled authz = Deny; NC6 effects only via outbox; NC7 no body bytes before CP; NC8 drain within T_drain. Host enforces NC1/3/4/5/8 (survive malicious modules). Basis: 15 instances in 5 ecosystems (sqlx #4393, diesel_async #304, redis-py CVE-2023-28858, Go CVE-2025-47907, Wasmtime CVE-2026-27195; `ac.root-cause-drop-at-await` A).
  - Driver pins: sqlx git ≥f1e94ec (0.9.0 on crates.io still has #4393); diesel_async ≥PR #305; tokio-postgres 0.7.18 + PR #1374; oneshot ≥0.1.12.
  - Cancel-sweep gate: `CancelAt<N>`, 8 modes × 8 oracles; PR gate every handler × site × {drop, RST, timeout} + 200 seeds. clippy CR1–CR9 (tokio Mutex banned in core; `select!` only where listed in `cancel-audit.toml`).
  - Reverse NC3 → state-tracked reuse if PG reconnect p50 >20 ms or 1 vCPU saturates <200 cancels/s (q3-008).
- **Idempotency (R-STATE-2) [A spec / E design]:** IETF idempotency-key draft-08 + Stripe semantics; key (principal, key), principal a MUST; exactly-once claimed nowhere; effect classes declared (R-STATE-3).
- **Store of record (R-STATE-4) [A pins / C choice]:** gated by our crash harness (~130k crash images, positive and negative controls). Default **SQLite ≥3.51.3, WAL + synchronous=FULL, single writer** (0 of 4,010 images lost an acked write). Passing alternatives: redb 4.4.0 2PC + Durability::Immediate (`check_integrity` detect-only, never auto-repair); fjall 3.1.12 SyncAll; LMDB/heed 0.23 default; canopydb `commit_with(true)`. Fail: redb Durability::None, fjall Buffer, canopydb `commit()`, SQLite WAL+NORMAL (lost acks in 85% of images). Bootstrap: fsync file + parent dir before serving. Reverse: double-fault + fsync-EIO stage (q2-007).
- **Cross-request state (R-STATE-5) [B]:** CRS C1–C8 + C5b, scope σ = (cert-chain hash, authority, principal|PUBLIC, auth context, epoch). Upstream pool key = `derive(Hash, Eq)` over the whole `UpstreamConnConfig` (hyper-util's (Scheme, Authority) insufficient; curl's ~18–20 reuse CVEs came from hand-enumerated keys). Recycled objects reset (Tomcat CVE-2026-101356).

### 3.8 Data plane (backend-agnostic; Postgres and SQLite are examples)

- **Pick [B decision / C design]: typed operation-capability IR, generate-don't-parse (R-DB-2).** `Op{tenant: TenantId (verified session only), cap: CapId (build-time), budget{rows ≤10k, bytes ≤8 MiB, ms ≤5000}, kind}`; `OpKind` = Get | Query{pred, proj, order, limit} | Put | Delete | Append | Subscribe | BlobGet | BlobPut | Presign{ttl ≤900} | Call | VectorSearch{k ≤100} | Named{stmt_id}. And([]) = TRUE, Or([]) = FALSE, Kleene 3VL. The adapter **is** the DB client; native protocols never exposed downstream (Envoy marks every DB wire filter `requires_trusted_downstream_and_upstream`, `dpf-envoy-db-filters-untrusted` A).
- **Build-time lock (R-DB-3/4) [A/B, C]:** `allowlist.<adapter>.lock`, INV-NONEMPTY (empty capability set denies), CVE-traced denylists: Redis EVAL, FLUSH*, SWAPDB, KEYS; Mongo `$where`, `$function`, zlib; Cypher CALL/APOC; Kafka admin and `sasl.*`; NATS `>`, `$JS.API`; DynamoDB Scan; S3 TTL >900 s. Regex read-only validators rejected. **Per-family normalizers that link C (e.g. pg_query/libpg_query, GHSA-6ggm OOB write) run at build time only, or in the out-of-process tier — never in the request path.**
- **Native enforcement (R-DB-5) [B]:** core mints per-tenant credentials (RLS role, STS `dynamodb:LeadingKeys`, Redis ACL user, Kafka PREFIXED, NATS account, FDB tenant); no backend connection shared across tenants (Valkey CVE-2025-67733); server-version gate at connect (MongoBleed, ITW). PEP-only families (MySQL, TiDB, libSQL, Mongo, Cassandra, Neo4j CE, Qdrant, search, time series, upstream HTTP) put the adapter in the trust boundary, stated in the extension contract.
- **Adapter isolation (R-DB-6, R-MOD-1) [B/A]:** in process — first-party pure-Rust drivers with ≲15 unsafe sites (tokio-postgres, mysql_async, redis, scylla, async-nats, mongodb, tiberius, rskafka, object_store, qdrant-client). Out of process (seccomp + Landlock worker, postcard 1.1.3 over UDS, `serde_bytes`, bodies as fds; bincode banned, RUSTSEC-2025-0141) — C-binding drivers (libsql, foundationdb, rdkafka, questdb-rs) and every third-party adapter. Hop 4.8 µs same core / 8.07 µs cross core; budget rate × 8.07 µs ≤10% of a core ≈ **12.4k calls/s/core** (`w02.ipc-hop-cost-1core` A 0.78; laptop, re-baseline on T1).
- **Read soundness (R-DB-7) [A model; A executed SQLite/PG/Redis; B doc-derived MySQL/SQL Server/Mongo]:** Lean `lower_sound_full` checked (axioms {propext, Classical.choice, Quot.sound}). Contract: (1) `Backend.Refines`/`Exact` claim; (2) live `check_schema()` (binary collations, no citext/NOCASE, partition-key opclass = column's); (3) executed differential with leak = 0, **and miss = 0 when NOT is exposed** (PG BUG #19645), ≥100k cases at the engine pin, re-run on every bump. Denylist: no LIKE/GLOB for Prefix; COLLATE "C" in PG; utf8mb4_0900_bin in MySQL; BIN2 + ESCAPE in SQL Server; Redis keys `t:{hex(tenant)}:`; Mongo explicit `$eq` + not-array. Spec decision for freeze: three-valued reference for NOT over absent fields (q4-004).
- **Write soundness (R-DB-8) [A executed / B invariant]:** INV-WRITE-SUBSET W1–W7. Executed: upsert on a globally unique key captured another tenant's row in 261/300 cases on PG 17.11, PG 19rc1 and SQLite. Mandated: composite (tenant, id) arbiters, FORCE RLS + explicit WITH CHECK, no REPLACE family, upsert WHERE without user expressions. **PG19 gated** on the fix for ON CONFLICT WHERE evaluated before the RLS check (`wpo-pg-onconflict-where-peek` A 0.86).
- **Postgres adapter (R-DB-1) [A/B]:** PG ≥18.6 / 17.11; SET LOCAL ROLE + statement caching (verified by our q1-012 reproducer); tenant GUCs only with `is_local=true`; recycle pooled connections after minor upgrades and role DDL (CVE-2026-14666); PgBouncer ≥1.26.1 on a private socket.
- **Alternatives:** pgwire proxy + statement allowlist (rejected: exposes a native protocol, PG-only, pg_query C in process); WIT-first data interfaces (no standard relational WIT; wasi-keyvalue stalled); per-family traits (tenant binding reimplemented 17 times); policy-to-SQL compilers (OPA unsound for SQL Server LIKE); Hasura NDC (existence proof only).
- **Reverse:** `Named` exceeds 20% of golden ops, or a standardized data WIT appears.

### 3.9 Agent-protocol projection

- **Pick [A]:** MCP 2026-07-28 primary + the 2025-11-25 path mandatory until ≥2027-07 (SEP-2596). 2026-07-28 removes sessions and initialize, adds MRTR `InputRequiredResult`, requires Mcp-Method/Mcp-Name headers (SEP-2243) (`rec60-mcp-2026-07-28`, `cal-mcp-2026-07-28` A). Header values with control characters are base64-sentinel encoded, not rejected. Stateless is **not** a security property: seal requestState by default. rmcp 3.7.0 (Apache-2.0) pinned, re-audited per bump (5 GHSAs Jun–Oct 2026).
- **Listener gate as a type (R-AGENT-4/7) [B]:** Host/:authority allowlist; Origin allowlist in both eras regardless of SDK defaults (`l4.defaults-vs-configurable-matrix` B); absent Origin only with bearer or mTLS; `application/json` POST; header/body consistency (-32020) checked against the **same** JSON owner as aegis-canon; sealed handles over (principal, route, backend, policy version, ttl); resolved-address egress; case-folded tool namespace. CI runs the executed **43-case corpus** with a zero-handler counter assertion. The official conformance suite is not evidence (its dns-rebinding scenario passes rmcp default with no Origin validation; -32020 violations are warnings; `l4.conformance-suite-gap-origin-only`).
- **Projection (R-AGENT-2) [C]:** one handler IR in JSON Schema 2020-12 → OpenAPI 3.2.1, MCP tools, WebMCP, Server Card.
- **Control plane (R-AGENT-6) [B]:** tenant A's route/policy never binds tenant B's backend without a grant (agentgateway GHSA-g7j8/jwm2).
- **Alternatives:** stateless-only MCP (rejected: deprecation window); an MCP gateway in front (agentgateway, docker-mcp — defaults fail the corpus); A2A v1.0.x, AP2 v0.2.0 as later handler layers.
- **Reverse:** the official suite adds Origin-only and -32020-strict cases (p = 0.7) → reuse its cases.

### 3.10 Observability and audit

- **Audit log (R-OPS-5) [B]:** C2SP tlog-tiles. JSON-lines events (ts, seq, actor, action, object, outcome, req_id, config_hash, fips_status) as RFC 6962 leaves; single writer; checkpoint signed only after tile fsync; invariants I1–I7; admin actions fail closed, data-plane events drop with a counter. **Tamper evidence needs an external witness:** optional for household, mandatory for gov/enterprise. Checkpoint key: Ed25519 signed-note, plus a **mandatory ML-DSA-87 cosignature in gov profiles** (which drop Ed25519 as a sufficient signature). No production Rust writer (tlog_tiles 0.2.0, stale since 2025-04-18), so we build one with Go Tessera v1.0.4 (avoid 1.0.3) as conformance oracle. Alternatives: Trillian (heavy); BLAKE3 hash chain (no standard verifier or witness ecosystem).
- **Metrics at v1 [B for the requirement, from `econ.deal-breakers`; E for the shape].** An OpenMetrics/Prometheus text endpoint on a separate admin listener (loopback or UDS by default), **always compiled in, no feature flag**, plus structured JSON logs to journald/stdout and W3C `traceparent` propagation (MCP 2026-07-28 puts it in `_meta`). Golden counters: rejects per admission stage, budget debits, crash-budget trips, `cert_seconds_to_expiry`, `fips_status`, config-generation hash, last-known-good fallbacks, upgrade forced closes. This is a **Phase-2 gate**. Only **OTLP** stays behind a Cargo feature pending a footprint spike (the graph has 0 OTel nodes); if it busts R-PERF-1, run it as an out-of-process exporter over the existing IPC.
- **Log hygiene [C]:** escape attacker bytes (operators' debugging agents read logs, `r2e11.waf-log-injection-agents`); log size budget: drop with a counter, never block (UPS-5); CLOCK_MONOTONIC durations, log clock steps >1 s.

### 3.11 Config and ops

- **Config [A/B]:** typed parse with `deny_unknown_fields` + emitted JSON Schema; `aegis check-config` (pure, nonzero on error) in ExecStartPre; secrets via systemd `LoadCredential(Encrypted)`; `parse_config` total, never panics (CFG-1: Kani + 1e7 fuzz); hard size caps (CFG-2); last-known-good on Err (CFG-3); staged apply shadow → 1% → bake → full with auto-rollback (CFG-4); deny `unwrap`/`expect` in core. Basis: Cloudflare 2025-11-18 (oversized generated file hit an `unwrap`, `uu11.cfg-push-class` A).
- **ACME and certs [B/C]:** instant-acme 0.8.5 with `fips` (no release since 2026-02-24: maintenance watch; alternative rustls-acme), ARI renewal, Pebble in CI, atomic `ResolvesServerCert` swap; CERT-1..4: expiry gauge with alerts at 30/14/7/3 days, `check-config --tls` preflight, faketime +400 d CI test. In the cmvp profile ACME is external or PQ-only per §3.2.
- **systemd [A]:** `systemd-analyze security --offline --threshold=2` CI gate (measured 1.4) + runtime test; DynamicUser, ProtectSystem=strict, CapabilityBoundingSet=CAP_NET_BIND_SERVICE, MemoryDenyWriteExecute; a Cranelift worker gets its own unit.
- **Upgrade (R-OPS-7) [C protocol / A mechanisms]:** parent spawns child with fd inheritance (`nix` 0.31 + `sd-notify` 0.5) + FDSTORE. **Never a second-process SO_REUSEPORT bind** (RSTs queued connections: 2–3 per million per reload in HAProxy's measurement). UP-1..7: claim-or-close every received fd, two-phase GOAWAY, drain deadline, STEK by pipe, authenticated handover socket. Gate: 200 upgrades at 5/s under 2k new conn/s with 0 RSTs.
- **Upstream/ops guards (R-OPS-9) [C]:** UPS-1..6 (per-upstream inflight caps, deadline propagation, retries ≤10%, RLIMIT_NOFILE preflight, TTL re-resolution); OPS-1..5 (healthy ≥ ceil(f·N) as a TLA+ invariant, dry-run default, linear-time regex only — fancy-regex/pcre2 banned, CLOCK_MONOTONIC).
- **Compliance (R-OPS-1/3/4/10) [A/B/C]:** CRA Art 14 reporting live since 2026-09-11; full application and steward reporting (Art 24(3)) 2027-12-11. COMPLIANCE_MAP → 800-53 r5 / FedRAMP 20x KSIs; never "FedRAMP-ready". No NIAP PP for web servers/gateways. Government route: MSL + FIPS module + EAL4+ ST if demanded + a formal **policy model** (SA-17(1)); no regulator credits code proofs (`sc.regulator-2025-26-statements` B). Export control: mass-market TLS/ML-KEM/ML-DSA; note kept in COMPLIANCE_MAP.
- **Scale-out (R-OPS-8) [B]:** `TicketKeyRing`, `RateLimitStore`, `IdempotencyStore`, `AuditSequencer` behind traits, single-node implementations first.

### 3.12 Developer and coding-agent surface

- **Pick [B]:** first-party handlers in native Rust against a separate-crate capability-typed **scoped adapter (B2)** SDK on axum 0.8.9 / tokio 1.54.1: routes-only registration, sealed `for<'r> ScopedHandler<'r, E>`, non-Clone `Ctx<'r, E>`, `TenantDb<'r>`, `Tx<'r>` with `Tx<Open> → Committed` typestate, private-field `Principal`; app crates have no tokio/axum dependency; background work only via a `Detached` capability; clippy ban list (spawn family, Box::leak, mem::forget, std Mutex/OnceLock, State/Extension); agents denied edits to `sdk/**`. Measured on real axum: B2 rejects 25/32 mutants at compile time (28/32 without tokio/axum deps) vs owned extractors 16/32 and plain axum 3/32 (`dx.r4-real-axum-mutant-scores` B; mutant set self-built). CI: trybuild 1.0.122 corpus, 18.8 s cold. Semantic residuals (M15, M16) go to Cedar + oracle tests.
- **Deploy artifact (R-DX-2) [B]:** OCI + cosign (≥3.1.0), digest-pinned; bare static binary + signed manifest for household.
- **Alternatives:** WIT component handlers (P2 path only); Ur/Web-style DSL (adoption/bus factor, `hist-urweb-adoption-bus-factor`); Encore-style codegen.
- **Reverse:** streaming/SSE/WS/body extraction needs a leaky `'static` hatch (q4-001); B2 diagnostics measurably hurt agent repair (q4-002).

### 3.13 Formal and assurance toolchain (build-time only)

- **Pick [A executed]:** Lean 4.35.0 Init-only subset (712 MB; `lakefile.toml` with zero `require`); 45 theorems checked (Lowering, Token, Combine), 0 sorry. Gate: pin + exact-commit check; `lake build` failing on any sorry; per-theorem axiom **allowlist** {propext, Classical.choice, Quot.sound}; `native_decide`/`bv_decide` banned; `lake check --paranoid` (6 checkers, ~245 s / 1.0 GB, CI only); before any `--from-export`, assert exported prelude declarations are byte-identical to the pinned toolchain's (Lean #15908 closure). TLC 362 MB. Kani main ≥#4910, serial, 6 GB cap, OOM/timeout = FAIL, CBMC exit ∉ {0,10} = FAIL. Verus 0.2026.10.18 + Z3 CI-only for ledgers. No Mathlib, no Aeneas, no prover LLMs in the required path. **No Lean claim above grade C without a file path and a gate log.**
- **Alternatives:** Verus-primary (3.16 GB; 131 soundness-labelled issues, 41 open — ledgers only); F*/EverParse (parsers, vendored output); Rocq (not chosen); Aeneas → Lean (needs Mathlib: 5.8 GB, 9.9 GB RAM — out).
- **Assurance structure (R-FORMAL-5, R-ASSURE-1/2/3) [B]:** every claim has ≥2 evidence kinds + a residual (claim ledger, §4.2); known-false-proof corpus 100% rejected on every checker bump; DST on a sans-IO core with turmoil 0.7.2, replacing the rustls CryptoProvider under simulation (aws-lc jitter/RDRAND not interposable, `as.dst-entropy-leak` A); conformance suite C0–C4 for third parties.
- **LLM proof policy (R-FORMAL-6, new) [B]:** see §5.2.

### 3.14 Supply chain and response time (summary; full list in `templates/SUPPLY_CHAIN.md`)

- **Gates [A/B]:** `--locked`; cargo-vet 0.10.3 from zero exemptions (183 of 233 unaudited on the golden lock); cargo-deny 0.20.2 with an 11-SPDX allowlist; cargo-audit 0.22.2; **G10 repo-GHSA poll** (7 of 133 invisible to OSV); new-crate intake gate for agent-added deps; reproducible double build (toolchain 1.99.1, remap flags, lto + cgu = 1 + panic=abort; toolchain digest + auditable mode in build identity); tarball-git parity; trusted-publishing ancestry; SLSA Build L3 provenance + independent rebuild; zizmor workflow lint; TUF root 3/5; triple-signed manifest.
- **Cooldown (corrected):** 7-day window with an audited security bypass (the 7-day window lands vulnerable webpki 0.103.15; 14 days lands the rustls 0.23.45 PQ downgrade). Native `global-min-publish-age` is stable only from Rust 1.100, **not** in the pinned 1.99.1, so until the toolchain bump the window is enforced by `xtask lock-age` (crates.io `created_at` per lock entry) + Dependabot `cooldown`.
- **Ordering:** from the incident back-test (`sc3.incident-gate-matrix` C, ordering only), time and novelty gates beat provenance gates.
- **Response-time SLOs — one table (critic item 9). None is a rule until the release drill spike has run.**

  | component class | trigger | SLO | grade |
  |---|---|---|---|
  | `aegis-canon`, transport wrapper, H1 framing (our attacker-reachable code) | private report or advisory | ≤24 h to signed release | C cadence (`rec60-ai-offense-trend`) / E number |
  | any Tier-S dependency | upstream fix published | ≤7 days to signed golden rebuild | B direction (R-THR-2) / E number |
  | any TCB component, best case | published advisory | ≤6 h advisory → TUF-published release, measured by a quarterly drill | E (target to measure, not a commitment) |
  | all features | any of the above while unpatched | runtime kill-switch per feature | B |
  | upgrade path | weekly | upgrade drill (R-OPS-7) | B |

---

## 4. Assurance case (§9.4)

### 4.1 Assurance rungs (our ladder; each claim names the rung it *reached*, never the target)

| rung | meaning | example in map |
|---|---|---|
| R0 | precise statement only | `inv-no-ambient-authority` [E] |
| R1 | executed test/fuzz/property test with a negative control | cancel sweep `ac.l5-cancel-sweep-harness` [B] |
| R2 | executed differential oracle or DST against a reference, incl. oracle mutation | CANON-DIFF `r4e07.canon-ref-zero-disagreement`; write oracle `wpo-inv-write-subset` |
| R3 | type/ABI/capability boundary enforced by compiler or kernel | trybuild corpus `dx.r4-l5-ci-gate-trybuild` [B]; seccomp |
| R4 | machine-checked **model** proof tied to Rust by DRT | Lean `lower_sound_full`, Token T1–T5, Combine (`r4e01.l5-theorem-status-table` A) |
| R5 | machine-checked proof **about the shipped implementation** (Verus/Kani on the code) | none yet in the golden |

**Claim-admission rule (R-FORMAL-3):** a proof claim above C needs a file path and a log from `ci/gate.sh` + `ci/axiom_audit.py`. Round 2's "combine_failclosed proven" had no file (`r4e01.combine-failclosed-first-check` A); round 3's Lowering.lean failed to elaborate (`r4e01.lowering-r3-draft-failed-check` A).

### 4.2 Threat → mitigation → mechanism (rung now → target) → residual

Every row has ≥2 evidence kinds (R-FORMAL-5). "Executed" = run on pinned versions with a log in `state/raw/`.

| threat | mitigation (rule) | mechanism, rung now → target | residual |
|---|---|---|---|
| H2/H3 exhaustion | golden hyper/h2 + wrapper; TBI-1..9; H3 off (R-TLS-1/2/7) | R1 fuzz resource-ratio oracle over the CVE corpus (`l4-cve-corpus-h2-h3-2023-2026`) → R5 Kani TBI-5/6/9 structs, Verus ledgers TBI-1/4/7, R4 Lean composition | TBI-4/7/8 not provable over h2 as written (`l5-tbi-tool-assignment` B); C_FIELD measured only; new composition variants yearly |
| canonicalization / fail-open authz | CANON-1..8; authz on route id; tri-state Combine; INV-NONEMPTY (R-ING-4, R-AUTHZ-5, R-DB-3) | **R4 checked** Combine; **R2 executed** CANON-DIFF; R3 sealed Canon_K → optional R5 Verus canon_path | real-traffic false-reject rate (q4-008); Cedar evaluator DRT only; Cedar axioms unaudited |
| smuggling | strict H1; H2 upstream; regenerate framing; validated-101; one TLS mode per port (R-TLS-3/8) | R2 HTTP Garden + framing corpus → R4 Lean H1 grammar + DRT | **no verified H1 parser exists anywhere** (`gap-verified-http1-parser` C) |
| TLS / PQ downgrade | rustls ≥0.23.46; pq-required agent/API listeners; profiles; scoped ticketers; 0-RTT off (R-PQC-1/6/8) | **R1 executed** verdicts PUB-T1..T6, FIPS-F1..F6 (A); C0 static profile check → R4 Lean group-selection model (Phase-6 gate) | public listener classical for X25519-first / classical-only clients (~⅓); cmvp ledger; 0x11ED is our code |
| agent protocol (AA5) | listener-gate type; sealed requestState; shared JSON owner; resolved-address egress (R-AGENT-4..7) | **R1 executed** 43-case corpus, zero-handler assertion; R3 gate type | absent-Origin interop; SDK churn |
| confused deputy (AA4) | authority by capability, never by a low-integrity string; no merged deputy/requester authority | R0 → R2 two-run DST hyperproperty (`inv-confused-deputy-ni` E) | the server cannot repair the model; label propagation across MCP/A2A hops unbuilt |
| cross-request state | CRS C1–C8 + C5b; fresh instance per request (R-STATE-5, R-ISO-5) | R2 two-scope oracles; poison test in the FI gate | class list not yet exhaustive |
| cancellation | NC1–NC8; commit-point latch; discard-on-cancel; driver pins (R-STATE-6/7) | **R1** cancel sweep; lint CR1–CR9 → TLA+/P model | only executed paths swept; upstream fixes unreleased (rust-postgres #1374) |
| data plane (read) | typed IR; denylists; native creds; two-sided contract (R-DB-2..7) | **R4 checked** `lower_sound_full`; **R2 executed** leak=0 ∧ miss=0; schema gate | Refines/Exact violated by real engines (#19645); renderer = model by DRT only; 3VL gap; timing channels (`irl-post-filter-side-channel-2026`) |
| data plane (write) | W1–W7; composite arbiters; FORCE + WITH CHECK; no REPLACE (R-DB-8) | **R2 executed** W1/W2/W4 on PG/SQLite/Redis → R4 Lean W1–W6 over an abstract engine | MySQL/Mongo/Cockroach unexecuted; EPQ concurrency; PG ON CONFLICT ordering unfixed |
| memory corruption | Rust; `forbid(unsafe)` in our crates; C drivers out of process | R1 Miri, sanitizers, geiger ceilings; R3 crate boundary | aws-lc C (~2.09M lines floor tree); tokio 2,527 unsafe items; rustc |
| sandbox escape (AA8) | per-tenant cordon / fork+Wasm; Wasmtime pins; clone filter; exec spawn; dumpable=0 (R-ISO-1/2/4/5) | R3 kernel boundary; **R1 executed** FI gate (740 cells) | 2.21/yr planning rate (P(≥3/yr) = 0.38); kernel LPE via allowlisted syscalls; laptop-only numbers |
| AI discovery (AA1) | minimal reachable surface; proof coverage; SLA table §3.14; kill-switches; upgrade drill (R-THR-2, R-ASSURE-4) | R1 per-release AI audit sprint + weekly replay of every past exploit; C0 surface metric | unknown unknowns in unproven glue; R4-only code counts as unproven |
| supply chain (AA6) | locked, cooldown + bypass, vet ratchet, intake, repro, provenance, G10 (R-SUP-1..6) | double build, attestation verify, `fips_lock_gate.py` | xz-class long windows; OSV lag |
| proof false PASS (AA7) | axiom allowlist; native_decide banned; no third-party Lean deps; own exports + prelude identity; Kani exit hardening (R-FORMAL-3) | **executed** gate PASS on golden, FAIL on negative control; known-false-proof corpus (R-FORMAL-5) | shared-spec bugs across checkers; spec fidelity |
| abuse swarms (AA3) | S0–S6, S0.5, classes, aggregate budgets (R-ABUSE-1..5) | R2 swarm DST on held-out seeds | **fails 3 scenarios**; simulator uncalibrated [D] |
| outages (AA0) | CFG/CERT/UPS/OPS (R-OPS-9) | R1 config fuzz 1e7, faketime +400 d; TLA+ healthy ≥ floor | latent logic bugs on valid input |
| remote timing | constant time at TCP-timestamp resolution (R-THR-4) | R1 dudect/ctgrind, pinned compiler | compiler-induced timing (Clangover class) |
| durability | ack ⇒ fsynced; dir fsync at bootstrap (R-STATE-4) | R1 crash harness ~130k images | double fault and EIO untested (q2-007) |

**Claim ledger (R-ASSURE-3, new) [B].** Each claim is a YAML record (template in `templates/VERIFICATION_PLAN.md`): statement, invariants, `rung_reached`, ≥2 evidence kinds with artifact hashes, trusted hypotheses and their tests, vacuity witness, TCB delta, residual, reversal, re-verify triggers. A CI lint fails the build if any grade or rung in this file disagrees with the graph or the artifact (round-4 calibration found 9 stale tags, `r4c12.stale-grade-list-2026-10-25`).

**AI-discovery posture (R-ASSURE-4, new) [B mechanisms / C cadence / E thresholds].** (a) per release, a 1-week LLM audit sprint on code reachable from TB1/TB2 that changed since the last sprint (Wasmtime: diminishing after week 1); (b) nightly red-team stage against staging with planted canaries, N = 20 pinned-model episodes per family, pass = 0 canary triggers, every past exploit replayed weekly (`as.ai-redteam-ci` C) — **advisory until a first run sets baselines**; own server only (hard gate §8); (c) SLAs per the §3.14 table; (d) publish a **reachable-unproven-surface** metric per release = Tier-S LOC minus code covered by an **R5** claim (R4-only code counts as unproven Rust); a rise >10% needs sign-off (threshold E).

### 4.3 TCB ledger

**Tier S — shipped, attacker-reachable, unproven (the AA1 surface).**

| component | size | why trusted | reduction / assurance |
|---|---|---|---|
| rustc + LLVM + std | 166 open I-unsound issues (r1) | no alternative compiler | Ferrocene 26.02.0 for safety regimes (`sc.ferrocene-qualified-rustc` B); bootstrap-verify stretch gate |
| tokio | 155k LOC; 2,527 unsafe items | async runtime | current_thread shell; DST |
| hyper / h2 / httparse | 16.7k / 15.2k / 3k LOC; unsafe items hyper 123, h2 3 | HTTP/1–2 | wrapper enforces TBI-4/8; pins; corpus |
| rustls + webpki ≥0.103.16 | 45.7k LOC, 6 unsafe sites; protocol logic unsafe-free | TLS 1.3 | verdict gate; BoGo, Wycheproof |
| aws-lc-rs / aws-lc-sys (floor) and aws-lc-fips-sys (cmvp) | 11,271 unsafe binding lines; ~2.09M bundled C/asm lines measured in r4 on the floor tree incl. generated asm (r2 said 1.5M, different scope); **cmvp tree to be measured separately** | crypto; FIPS boundary on cmvp (#5298/#5314) | verified parts only (s2n-bignum, mlkem-native); libcrux-provider spike for non-FIPS |
| **0x11ED hybrid KxGroup (ours)** | ~10–50 LOC composition | upstream declined (#3293) | KATs, interop, Kani share parsing (Phase-6 gate) |
| AEGIS transport wrapper | ours, small | TBI-1/4/5/8 | Kani + Verus |
| aegis-canon | ours + serde_json 1.0.154 dup-rejecting visitor, http 1.5.0, percent-encoding 2.3.2 | single identity owner | CANON-DIFF; optional Verus |
| Cedar Rust evaluator 4.14.0 | 15.7k LOC (cedar-policy-core 134k lines in lock) | PDP | DRT vs Lean; axiom audit pending |
| token verifier + EverParse det-CBOR | ours + vendored verified parser (tree hash recorded) | Tier L | T1–T5 model; mint-shape check to add |
| in-process adapters | mongodb 91.7k / 14 unsafe; scylla 93.9k / 3; redis 49.3k / 6 | backend access | two-sided oracles per ENGINE_PIN |
| pool checkin predicate, drop guards, supervisor, upgrade handover parser, tlog writer | ours | NC3, UP-1..7, audit | cancel sweep; handover fuzz; Tessera oracle |
| Wasmtime + Cranelift (P2/P3) | M0 2.21 escapes/yr | tenant code | always inside a per-tenant OS cordon or fork child |
| Linux kernel: seccomp, Landlock, cgroups, systemd | — | sandbox | negative syscall tests; clone3 ENOSYS |
| SQLite (default store) | C in process | durability | crash harness; weigh as TCB lines |

**Tier D — defence in depth, never relied on alone:** PG RLS (FORCE + WITH CHECK), vetted triggers, PG planner (engine bugs in scope).

**Tier B — build-time only; a false PASS voids Tier-S claims.**

| component | size | assurance |
|---|---|---|
| Lean 4.35.0 Init-only | 712 MB carve, sha256-pinned; `--paranoid` 228–245 s / ~1.0 GB over 58,609 declarations | 6 checkers; allowlist; known-false-proof corpus; prelude identity |
| `ci/gate.sh`, `ci/axiom_audit.py` | ours | negative-control FAIL required each run |
| Verus 0.2026.10.18 + Z3 | 3.16 GB incl. rustc 1.99.1; 131 soundness-labelled issues (41 open) | dated pin; `-V check-erasure`; spec-triviality check |
| Kani (main ≥ #4910) + CBMC | ~2 GB | exit ∉ {0,10} ⇒ FAIL; serial; 6 GB cap |
| TLC / Apalache, cvc5 | TLC 362 MB at 2.67M states | liveness models only |
| CI runners, Sigstore/Rekor, TUF 3/5 keys | — | bwrap AppArmor profile; toolchain digest in build identity |

**Lock mass (golden, 233 crates):** 116 of 165 linux-tree crates unaudited by any imported vet set (3.66M lines). Protocol logic is unsafe-free; the unsafe mass is in runtime and allocator (`sc3`, A).

### 4.4 NOT proven (explicit)

1. **Spec fidelity** of every proved component — the dominant residual (`fail-spec-fidelity-studies` A; 2017 EuroSys sample).
2. Any property of the **Rust code** behind an R4 model: every current proof is R4 (renderer = Lean `lower`, token verifier, Combine host mapping, all by DRT/tests only).
3. The Rust HTTP/1.1 framing parser (no verified H1 parser exists in production anywhere).
4. TBI-4/7/8 over hyper/h2 as written; C_FIELD; the async shell and liveness.
5. CANON-1..8 beyond the small-corpus differential; real-traffic false-reject rate.
6. Cedar Rust evaluator (DRT only); Cedar Lean theorems stay B until `#print axioms` on CI.
7. Per-adapter Refines/Exact (engines violate Exact: PG BUG #19645); the 3VL reference; timing/scoring channels.
8. Write path beyond W1/W2/W4 on PG/SQLite/Redis; MySQL/Mongo/Cockroach writes; concurrent (EPQ) writes.
9. Token outside the model: Rust verifier, CBOR codec link, constant-time compare, HMAC EUF-CMA (assumption).
10. INV-NOMUT-C beyond swept paths; unreleased driver fixes.
11. TLS 1.3 and hybrid-KEM security (assumed from literature and rustls); our 0x11ED composition (KAT/interop only until Kani); aws-lc C outside verified parts.
12. Wasmtime runtime, WASI, Cranelift lowering (VeriISLE covers a subset; GHSA-897f escaped it); KVM; kernel LPE through allowlisted syscalls.
13. Microarchitectural tenant isolation inside a shared process (no node measured it); per-tenant process is the only boundary.
14. Admission numbers (fail 3 scenarios; simulator uncalibrated); I3/I4/I6/I9/I10 model-only.
15. Upgrade UP-1..7 (spec only); crash consistency beyond single crashes; DST fidelity (aws-lc raw getrandom).
16. Confused-deputy noninterference (F10): statement only.
17. **Proof-checker independence:** checkers disagree on adversarial preludes; six-checker acceptance is evidence only for exports from our own standard prelude.
18. Isolation and performance numbers beyond one laptop; outage frequencies as true incidence.
19. **No regulator credits any of these proofs** (R-OPS-10); test legs stay mandatory (DO-333, CompCert-at-MTU precedent).

---

## 5. Formal properties (§9.5; precise statements in `templates/SPEC_INVARIANTS.md`)

Notation: r request; σ(r) scope tuple (issuer chain hash, authority, principal/tenant, auth context, config epoch); Held(r,t) capabilities held by r at t; ⟦τ⟧ token denotation ⊆ Requests × Time; D(r) resources acquired; CP(r) commit point. Effort is per obligation and [E] unless a node is cited.

| # | invariant | tool → rung | status 2026-10-25 | effort to next rung | LLM share (§5.2) |
|---|---|---|---|---|---|
| F1 | **No ambient authority.** ∀ trace, r, effect e: ∃ c ∈ Held(r, t⁻ₑ) with permits(c, e); Held changes only by Grant at entry (derive(verified_token) ∪ static endow(route)), Introduction by explicit argument, or Creation over fresh objects; no effect API callable without a `Cap<O>`, which has no public constructor | R3 sealed `Cap<O>`, linker allowlist, disallowed-methods, deny import ban (survives malicious modules, `vfg-invariant-survival-table` B) + R4 Lean induction over handler/effect steps | R0 [E]; R3 partly via B2 SDK (25/32) | Lean semantics + theorem 300–600 LOC, 1–2 wk | high once semantics fixed; semantics are human/separate-agent work |
| F2 | **Attenuation monotonicity.** ⟦append(τ,b)⟧ ⊆ ⟦τ⟧; chains ⊆ ceiling(issuer); conjunction of *all* caveats; D1–D4; policy diffs without a human need SymCC `implies(p', p)` | R4 Lean Token.lean + fuzz F1–F9 + DRT | **R4 checked** (16 theorems, 1.25 s / 498 MB, `r4e01.token-T1-T6-checked` A); model only, EUF-CMA assumed | mint-shape + `verify → aud ∧ now<exp` ~20 LOC; DRT 3–5 d | very high (demonstrated) |
| F3 | **Fail-closed decision.** combine([]) = deny; error ∈ ds ⇒ deny; allow ⇔ ds ≠ [] ∧ ∀d. d = allow; host maps timeout/crash/panic → error before combine | R4 Lean Combine + R1 DST host mapping | **R4 checked** (4 theorems); host mapping untested | DST ~2 d | done |
| F4 | **INV-NOMUT-C.** every termination before CP(r) ⇒ Outcome Failed and durable user-visible rows changed by r = ∅ (mod sequences, advisory locks, stats); NC2 latch from CP; NC3 discard mid-protocol resources; NC4 pre-debit, cancels charged; NC5 cancelled authz = deny | R1 cancel sweep + R2 DST + TLA+/P with cancel as nondeterministic action; Lean/Kani NC4/NC5 | R1 executed; model unbuilt | TLA+/P 1–2 wk; Lean NC4/5 ~3 d | medium (~37% on Anvil-class inductive invariants) |
| F5 | **Bounded resources.** TBI-1..9 (field block ≤16,384 B and ≤128 fields; decode work linear; HPACK ≤4,096, QPACK 0; handlers ≤100 + queue ≤400 per conn with permit held for task lifetime; RST bucket 100/33 s⁻¹, server resets ≤256, streams ≤10,000; buffered ≤ window; memory; stall 10 s; no overflow). Admission I1 Σ cost over [t,t+W] ≤ bᵢ + rᵢW; I2 admitting j never changes TATᵢ, i ≠ j; I4 eviction mints ≤ anonymous burst. Wasm: epoch, ResourceLimiter, host-call and I/O quotas | Kani structs + GCRA algebra; Verus ledgers; Lean composition; proptest TBI-2; DST TBI-8; TLA+ I3/I4/I6 | R1 corpus; R5 unrun; RAM unmeasured (q2-013) | Kani ~1 wk; Verus 2–3 wk; Lean 2–3 d | Kani high; Verus 70–85% (E) |
| F6 | **Parser canonicality / no desync.** unambiguity \|parses(S)\| ≤ 1; round-trip parse(ser(m)) = m, ser(parse(S)) = canon(S); reject CL+TE, dup CL, TE ≠ "chunked", bare LF/CR, obs-fold, Expect on bodyless; forward ser(Canon_K) never raw; CANON-1 one canon_K per kind; CANON-2 reject ambiguous; CANON-3 sealed | R4 Lean H1 grammar + DRT (+ Lean `Std.Http` second oracle); EverParse 3D for binary framings; R2 CANON-DIFF; optional R5 Verus canon_path | R2 small corpus; R4 unbuilt | grammar spec 1–2 wk expert review + proofs 2–4 wk | proofs 70–85%; **the grammar spec is the risk** (best autoformalization 77.8%) |
| F7 | **Tenant isolation (logical).** ∀ effect e for r: tenant(e.target) = σ(r).tenant or PUBLIC; composed of F1 + `lower_sound_full` (under Backend.Exact) + W1–W7 + CRS C2 + C8 + INV-NONEMPTY. Microarchitectural isolation not provable | R4 Lean reads **checked**, writes W1–W6 seed + R2 two-sided read and write oracles per ENGINE_PIN + schema gate + CRS differentials | reads R4+R2 [A]; writes R2 partial [A/B]; CRS R2 [B] | Lean W1–W6 1–2 wk; 3VL re-proof (q4-004) ~1 wk; MySQL/Mongo (q4-005) 1–2 wk | high for lemmas; engine refinement only testable |
| F8 | **PQC handshake (server obligations).** P-PQ1 pq-required ⇒ no classical-only transcript; X25519-only ⇒ alert 40 (PUB-T4); P-PQ2 negotiated group ∈ profile.kx and sigalg ∈ profile, set equals profile; P-PQ3 resumption only if ticket scope = current (AAD); P-PQ4 0-RTT and TLS 1.2 off in gov profiles; P-PQ5 FIPS module identity = pinned CMVP build. TLS 1.3 and the KEM combiner assumed | R1 verdict matrix per profile × lock; C0 lock gates; **R4 Lean group-selection model + Kani 0x11ED share parsing as Phase-6 gates** (cheapest R5-class claim in the system) | R1 [A] for P-PQ1 on rustls 0.23.46; P-PQ2 for 0x11ED unbuilt | Lean model 1–2 d; 0x11ED KATs + interop ~1 wk | high |
| F9 | **Lowering soundness** | R4 Lean | **checked**: lower_sound_pos, lowerQ_sound, refines_necessary, lower_sound_full, lowerQ_sound_full, not_absent_permits; vacuity in Vacuity.lean (`r4e01.spec-fidelity-audit` A) | 3VL decision at freeze | done |
| F10 | **Confused-deputy freedom** as integrity noninterference: ∀ σ₁, σ₂ with σ₁\|H = σ₂\|H: AuthSel(σ₁) = AuthSel(σ₂); L reaches arguments only through label-checked sinks | R2 two-run DST; optional R4 Lean relational; Verus ghost labels | R0 [E] | DST ~1 wk; Lean 2–4 wk | medium |
| F11 | audit append-only and completeness; ack ⇒ durable; healthy ≥ ceil(f·N); config/canon totality | Kani/proptest + Tessera oracle; crash harness; TLA+; Kani totality + fuzz 1e7 | R1/R0 mix | 1–2 wk each | high |

**Portfolio cost [E].** LLM API cost is negligible (~$1–6 per obligation: Rust-Prover median $1.17, `rec60-rust-prover-llm-proofs` B; VeruSAGE $5.61 per system task, `llm-verusage-2025` B; CryptoProver ~$467 library scale, `vfg-cryptoprover-cloud-llm-optional` B). The binding cost is **expert spec review**: ~8–14 person-weeks for F1, F4, F5, F6, F7, F10, plus 2–4 person-weeks for checker qualification (TOR + known-false-proof corpus).

### 5.2 What LLM proof synthesis can discharge, and the policy

| obligation shape | evidence | realistic unattended success |
|---|---|---|
| local lemmas over given specs in core Lean | this research: 45 theorems after an execution loop; never-executed drafts were wrong | very high with a loop; ~0% trustworthy without |
| Verus system proofs with specs given | VeruSAGE 81% overall, Anvil inductive invariants 37% [B]; KVerus repo-level 51% [B] | 50–85%; lower for protocol invariants |
| repository-scale Lean | VeriSoftBench Pass@8 31–41%; math provers don't transfer (`llm-lean-provers-transfer` B) | 30–40% |
| multi-function composition | DafnyComp 3.7% (`llm-dafny-agents` C) | low |
| low-level asm (HOL Light) | s2n-bignum-bench ≤6.35% | very low; reuse verified crypto |
| **writing specs** | best 77.8%; 42.3% of verifier-accepted LLM artifacts pass semantic checks (`rec60-spec-fidelity-verus` A) | **not dischargeable** |
| cheating | assume/admit/spec edits 7–14% without a checker, <1.5% with | — |

**R-FORMAL-6 (new) [B]:** (1) agents may write proofs and harnesses; they may not edit `spec/`, `Vacuity.lean`, the axiom allowlist, gate scripts, the SDK crate or `TRUSTED.toml` (CODEOWNERS; the proof-writing agent never merges spec diffs); (2) each spec ships an executable form, a spec-mutation test, a vacuity witness and a hypothesis ledger; (3) Lean bans native_decide/bv_decide with allowlist {propext, Classical.choice, Quot.sound}; Verus denies `assume(`, `admit(`, `external_body`, `assume_specification`, axiom fns outside `TRUSTED.toml`, requires `-V check-erasure`; Kani exit ∉ {0,10}/OOM/timeout = FAIL; (4) falsifier: if agent success on the first 20 core obligations is <70% within 10 iterations, those drop to the R2 property-test rung and the claim is downgraded (`hist-ironfleet-cost-vs-llm` B); (5) prover LLMs run in the cloud only and are never a trusted build step (§0c).

---

## 6. Performance model per deployment size (§9.6; protocol in `templates/BENCH_PLAN.md`)

Every number is single-machine (one laptop, i9-14900HX) and capped at B for absolutes unless marked. Protocol R-PERF-2: isolated cpuset + `--cpus=1` run, 512 MB, ABBA ≥5 reps, loadavg and steal logged, cgroup `cpu.stat` µs/request primary, **bands not best trials**, rankings only outside the observed ~2.8× variance.

| quantity | value | grade | node |
|---|---|---|---|
| core binary / crates / non-crypto unsafe | 4.21 MB / 40 / 3,325 lines (budget ≤6 MB / ≤60 / ≤5,000) | A | `w02.L5-lean-budget` |
| idle RSS; 1k idle TLS conns | 3.4–5.9 MB; 17.2 MB | A | `w02.idle-rss-table` |
| full TLS 1.3 handshake server CPU, X25519 | band 123.4–141.7 µs (noisy trial 254.8) | B | `w02.handshake-pq-cost` |
| hybrid X25519MLKEM768 overhead | **band +12.5% to +17.5%** (trials differ; not a point estimate); rustls ~2× cheaper than OpenSSL servers | B | same |
| new handshakes per core | ~6.9–8.0k/s rustls (direction A) | B | same |
| per-request substrate cost | native 0.38 µs; core Wasm 1.06 µs; component 1.24 µs warm; fresh pooled component 20 µs p50; tiny-module pooled instantiate 6.9 µs p50; fork 124 µs–1.5 ms | A | `isolation-decision-inputs-table`, `wasmtime-pooling-local-bench` |
| toy 30 µs handler, 1 core | native 22.6k rps, fresh Wasm 21.1k, cordon 24.1k, fork 8.2k, PHP-FPM 9.1k — **ranking not quotable** (inside the laptop variance; does not show cordons are free) | B | `r4i04.blast-radius-table` |
| Wasm density per GiB | **tiny-module floor** 7.1 KiB/instance ≈ 147k/GiB (`wasmtime-pooling-local-bench`); **component-with-WASI handler** ~52 KB/instance ≈ 19.9k/GiB, capped by ~31k VA slots (4 GiB + 32 MiB guard) (r2) | B | — |
| fork children / cordons per GiB | ~5–10k fork children; ~1,000 cordons; PHP 2.8 MiB/worker | B | `r4i04.blast-radius-table` |
| IPC hop | 4.8 µs same core / 8.07 µs cross core | A | `w02.ipc-hop-cost-1core` |
| token verify | handle 83 ns; HMAC 5 caveats 1.2 µs; ML-DSA-65 114 µs | B | `r3e05.token-verify-microbench` |

**Household, $5 VPS (1 vCPU, 1 GB) [E: extrapolated, no real-guest run].** Recomputed from **our own** handshake measurement (critic item 6) × the E-graded VPS scale factor 0.5 used in `r3e07-defender-stage-cost-table`: full handshake ≈ 247–283 µs → **~3.1–3.7k req/s of 429-after-full-TLS (X25519), ~2.7–3.3k with hybrid**. The round-3 table's 1,131 / 941 req/s used a third-party 424 µs figure (InfoQ, C) and +21% (Red Sift/OpenSSL, C) and is superseded; the TLS floor still binds before the limiter, but at ~2.5–3.5× more capacity than previously stated. Cost-100 handler work ≈ 32 req/s (D, unchanged). Keep-alive traffic to cheap handlers is bounded by the toy-handler row (~20k rps on a dedicated core; a shared vCPU degrades this). Memory allows tens of thousands of idle TLS connections (~17 KB each, E). The cmvp profile cannot claim approved mode unless the OS is AL2023. Lean `--paranoid` never runs here.

**Small/enterprise node (4–16 vCPU) [E]:** tokio work-stealing expected near-linear for TLS-bound work; isolation tiers scale by worker count; adapter hop budget ~12.4k calls/s/core cross-core; a local-only `RateLimitStore` multiplies limits by replica count (R-OPS-8).

**64-core / hyperscale [unmeasured]:** thread-per-core vs work-stealing and io_uring vs epoll unmeasured on our workload; `PreferServerOrder` and QUIC-LB matter. Treat any claim as E.

**Spikes that turn these rows into A/B:** q3-001 (real 1-vCPU handshake, full vs resumed), q3-002 (ipcbench on a VPS), q2-009 (window-0 stall harness), a VPS fork-cost run, a 64-core scaling run.

---

## 7. Decision record (§9.7)

**D-1 Wasm vs native handlers.** *For Wasm everywhere:* uniform boundary, density, language neutrality, deterministic fuel. *Against:* M0 escape planning rate 2.21/yr (P(≥3 in a year) = 0.38); ~2× codegen cost on serde-class handlers; instance reuse poisons state (93 wrong answers); guest-triggerable host aborts 0.7–3.9/yr; native Rust behind a capability SDK rejects 25/32 structural mutants at compile time. **Decision:** by provenance (§3.6), with fork+Wasm built as a co-equal P2 path [E design; A/B/C inputs]. **Flip:** R1–R5.

**D-2 io_uring thread-per-core vs epoll + tokio.** *For io_uring:* fewer syscalls, SQPOLL, completion ownership. *Against:* 0 KEV but 161 NVD io_uring CVEs (54 in 2026); Google: 60% of kCTF submissions used io_uring, disabled on ChromeOS and production servers; Docker default seccomp blocks it; our worker allowlist must deny it; Rust io_uring runtimes stale (tokio-uring 2024-05, monoio 2024-08, glommio 2024-03; spargio single-author, experimental, last push 2026-03, `cal-spargio` A); the 370k-vs-270k rps figure is one 2023 comment (`cal-uring-370k` D); TLS handshakes (~7–8k/s/core) dominate, not syscalls. **Decision:** epoll default [B]; io_uring opt-in on the trusted front only, never in workers. **Flip:** measured >1.3× CPU/request on our TLS workload with a maintained runtime + no reachable LPE under our allowlist.

**D-3 Cedar vs Biscuit vs both.** *For Biscuit:* offline attenuation, one format, Datalog. *Against:* 158 µs for 3 blocks; no PQ; wall-clock `max_time` → nondeterministic denials; last release 2025-07; the prior's AIP figures (135/324 µs) were not found — the paper reports 0.516 ms at depth 3, 0.745 ms at depth 5 (`cal-aip`). *For Cedar:* Lean model, DRT, SymCC, AWS adoption. *Against:* no delegation RFC; Rust evaluator unproven. **Decision:** Cedar PDP + our three-tier token [C/B]. **Flip:** Biscuit ships PQ + fuel + scoping; a Cedar delegation RFC lands.

**D-4 QUIC/H3 now vs later.** *For now:* mobile, migration, same HNDL story. *Against:* h3 unbounded QPACK/field defaults; quinn 11 GHSAs in 2026 (HIGH ones OSV-invisible); H3→H1 seams are the 2026 desync site (HAProxy CVE-2026-33555; CDN Tsunami 36–350× QPACK expansion); ML-DSA chains break amplification limits; zero-drop upgrades need CID routing. **Decision:** off in the golden [A/B]. **Flip:** §3.1.

**D-5 MCP version.** *For 2026-07-28 only:* stateless, simpler. *Against:* TS SDK's LATEST still 2025-11-25; 12-month deprecation window. **Decision:** both eras behind one listener-gate type [A].

**D-6 Store of record: SQLite vs redb.** *For redb:* pure Rust, CoW B-trees. *Against:* dense 2026 durability-fix stream incl. crash-during-recovery silently rolling back committed data (4.2.0); read paths never verify page checksums (#1334). *For SQLite:* passes at FULL; decades of fuzzing. *Against:* C in process (weigh as TCB lines). **Decision:** SQLite WAL FULL default, redb 2PC + Immediate as the pure-Rust option [C choice / A pins]. **Flip:** double-fault/EIO results.

**D-7 Data mediation: typed IR vs pgwire proxy vs RLS alone.** *For the proxy:* unchanged apps. *Against:* PG-only (§0b), libpg_query in process, wire filters documented as needing trusted peers. *Against RLS alone:* WITH CHECK(true) masked whenever the write reads a column; ON CONFLICT ordering bug; 261/300 upsert captures. **Decision:** typed IR + native creds as defence in depth + two-sided oracles [B/C]. **Flip:** `Named` >20% of ops.

**D-8 Primary prover: Lean vs Verus.** *For Verus:* proofs on the Rust code. *Against:* 3.16 GB; 131 soundness-labelled issues (41 open); spec fidelity is the real risk (77.8% upper bound for LLM specs). *For Lean:* 712 MB measured, executed six-checker gate, the spec → model → DRT pattern Cedar uses. (The operator naming Lean is a **directive constraint**, not evidence; the footprint numbers carry the decision.) **Decision:** Lean for models/specs; Verus + Kani for code-level ledgers and structs [A footprint / B fit]. **Flip:** an obligation needing Mathlib, or Verus peak RAM >16 GB on the first 10 obligations.

**D-9 Identity: reject vs normalize.** *For normalize:* fewer false rejects. *Against:* 34 dated divergence instances, 24 in 2026. **Decision:** reject-don't-repair with a per-clause 308 fallback [B]. **Flip:** q4-008 >0.1%.

**D-10 PQ key exchange at the server.** *For pq-required everywhere:* no downgrade. *Against:* **about a third** of human clients are still classical-only (>65% PQ-hybrid by Apr 2026, `pq-share-telemetry` A), so pq-required still breaks a third of browsers. **Decision:** per listener; public listener hybrid-first with exact residual stated, PreferServerOrder backported [A verdicts]. **Flip:** classical-only share falls below ~2% → pq-required on public listeners too.

**D-11 FIPS: one lock vs two.** One lock is impossible (A 0.95). **Decision:** two lock profiles, with clients compiled out or PQ-only in cmvp; alternatives: forked-rustls spike, or no CMVP claim [B].

**D-12 Modularity: features vs in-process Wasm components vs out-of-process IPC vs dlopen.** dlopen rejected (no stable ABI; loaded code invisible to audit). Out-of-process narrowed by the measured hop cost. **Decision:** Cargo features + out-of-process only within the hop budget [B].

**D-13 Positioning: sell assurance vs invisible assurance.** **Decision:** invisible, parity first [C/D], with the selection-bias caveat (§1 P-2); proof work is not cut on this basis. **Flip:** procurement scoring evidence (q4-003).

**D-14 Kubernetes microservices (PDF2 baseline) vs a single binary.** *For K8s:* independent scaling and fault isolation per service. *Against (argued from TCB and household viability only):* multiplies TCB, config surface and operator burden; cannot meet the $5-VPS household rung or the ≤6 MB budget. (Config push being the top outage class applies to the single binary too, hence CFG-1..4; Envoy's size is an Envoy property.) **Decision:** single binary with in-process isolation tiers; Kubernetes-friendly (rung E2) but not Kubernetes-dependent [B].

---

## 8. Repository, implementation plan and hard gates (§9.8, §9.9)

The repository layout, phased plan, gate YAMLs and agent execution rules are in `templates/REPO_LAYOUT.md` and `templates/IMPLEMENTATION_PLAN.md`. Summary:

- **Phase 0** repo, pins, frozen interfaces F1–F13, verify wall ported with every negative control red. **Phase 1** eleven decision-flipping spikes (+ q4-003/q1-009 reading). **Phase 2** reverse-proxy mode (first shippable). **Phase 3** agent gateway. **Phase 4** data plane + native SDK handlers. **Phase 5** P2 isolation (fresh-Wasm cordons **and** fork+Wasm). **Phase 6** jurisdiction/FIPS profiles, 0x11ED + Lean selection model gates, reproducible triple-signed release. **Phase 7** deferred modules (H3, L4, WebTransport, io_uring front, MTC, libcrux provider).
- **Minimum shippable cut line (critic item 23):** Phases 0–2 with gates 0–8, 12, 18, 21 and the metrics gate. Phases 4–6 are conditional on q4-003, q1-009 and the velocity measured after Phase 2. Total phases 0–6 ≈ 1,050–2,050 agent-hours [E] + 8–14 person-weeks spec review + 2–4 checker qualification.

**Hard gates (§9.9).** No offensive tooling beyond test harnesses for our own server (red-team stage and differential fuzzers target only AEGIS staging; HTTP Garden, which is GPL-3.0, runs as an external container and is not linked). Licenses: cargo-deny 11-SPDX allowlist; Tenuo CEL finding is under private disclosure, not published. **Export control [E: not researched in the map; general knowledge only]:** AEGIS uses standard, publicly available TLS 1.3, ML-KEM, ML-DSA, SLH-DSA and AES-GCM; open-source publication of such crypto is generally treated as publicly available under US EAR (§734.3(b)(3), with the 2021 simplification of the TSU notification) and as mass-market elsewhere. Record the classification in `COMPLIANCE_MAP.md` before distributing binaries commercially; this is not legal advice.

---

## 9. Implementation-phase items that could still flip a load-bearing rule

| item | rule at risk | closes by |
|---|---|---|
| q3-001 real 1-vCPU handshake | R-ABUSE-1, R-PERF-1 | spike |
| q3-002 IPC hop on a VPS | R-MOD-1 | spike |
| q4-008 CANON false-reject rate | R-ING-4 | spike |
| q4-026/028 0x11ED KxGroup + interop + FIPS boundary | R-PQC-8 × R-PQC-2 | spike (now ours by necessity) |
| q4-004 three-valued Lean reference | R-DB-7 | Lean |
| q4-005 MySQL/Cockroach write oracle | R-DB-8 | spike |
| q4-006 fuel gate + VPS fork cost | R-ISO-1/5 (fresh Wasm vs fork+Wasm default) | spike |
| q2-007 double fault + EIO | R-STATE-4 | spike |
| q3-008 PG reconnect under discard-on-cancel | R-STATE-6 NC3 | spike |
| q2-009 window-0 stall | TBI-8 | spike |
| q4-001/002 streaming in B2; agent repair | R-DX-1 | spike |
| q2-013 Kani/Verus RAM | R-FORMAL-2 | spike |
| Cedar `#print axioms` on CI | R-AUTHZ-1 grade | spike |
| q3-005 swarm sim v2 held-out | R-ABUSE-1/4 | spike |
| cmvp client-out vs PQ-only gate | R-PQC-2 ledger validity | spike |
| OTLP footprint | §3.10 | spike |
| release drill (≤6 h target) | R-THR-2 numbers | spike |
| agent success on first 20 obligations | R-FORMAL-6 | spike |
| q4-003 procurement texts | R-GAP-4, D-13 | **research** |
| q1-009 LLM- vs human-found exploitation | R-THR-2 SLA scope | **research** |

Per §0c the recommendation is to **pivot to building**: every phase gate already exists as an executed or specified harness.

---

## 10. Reconciliation with the prior treatments (PDF1, PDF2, seed conversation)

Read only at this stage. Verdicts: **confirmed** (independent evidence agrees), **refuted** (independent evidence contradicts), **they missed** (found only by the map), **adopted with independent evidence** (same pick, own evidence).

### 10.1 Item-by-item

| prior claim (source) | verdict | independent evidence |
|---|---|---|
| rustls + aws-lc-rs (PDF1, seed) | **adopted with independent evidence** | ~2× cheaper handshakes than OpenSSL servers; +12.5–17.5% hybrid band; FIPS module map, two-lock finding, decoy lock (`w02.handshake-pq-cost`, `r4tri.*`) |
| "aws-lc-rs natively provides FIPS 140-3 validated ML-KEM … X25519MLKEM768 and SecP256r1MLKEM768 by default" (PDF1) | **refuted in part** | validation needs the `fips` feature + exact fips-sys =0.13.11 on AL2023 OEs; default build is uncertified 4.2.0 source; X25519 outside boundary; default kx list lacks 0x11EB; `fips()==true` can't tell 3.1.0 from 4.2.0 (`r4tri.no-co-resolvable-lock`, `r4tri.fips-sys-decoy-lock`, `r4tri.try-fips-mode-blind`, `r4tri.tested-env-only-al2023` A) |
| X25519MLKEM768 everywhere (PDF1, seed) | **partly confirmed**: public-web default only | per-listener verdicts; jurisdiction matrix makes 0x11ED the intersection group, and 0x11ED is our own code (#3293 closed) |
| ML-DSA-65 + Ed25519 TLS auth (PDF1, seed) | **refuted** for public WebPKI | SC-106 withdrawn 2026-10-21; ML-DSA-44 on private hops; MTC later (`r3pq.cab-sc106-withdrawn`, `r3pq.mldsa-handshake-measured`) |
| SLH-DSA for releases/roots; MTC (seed) | **confirmed, amended** | add ML-DSA-87 (ASD/CNSA omit SLH-DSA): triple signature (`pq-release-signing`, `r4e10.golden-signature-profiles`) |
| Wasmtime 49+ pooling + MPK + fuel/epoch as the sandbox (PDF1, seed) | **partly confirmed, narrowed to P2** | pin ≥36.0.19 or ≥49.0.4; fresh instance per request inside per-tenant OS cordons or fork+Wasm; MPK measured (no latency gain; density option only); "<15 µs warm instantiation" **confirmed** for tiny core modules (6.9 µs p50), not components with WASI (20 µs); "10k instances in <2 GB" **confirmed** as a floor (7.1 KiB tiny; ~52 KB component) |
| "Fuel strictly bounds execution" (PDF1) | **refuted** | fuel bypass/amplification CVEs; epoch ~2× cheaper (`fuel-not-a-security-bound` B) |
| wasmtime-wasi-http (PDF1) | **refuted** | RUSTSEC-2026-0350/0376 |
| `Module::deserialize` of signed .cwasm (PDF1) | **amended** | local MAC only (runwasi CVE-2026-47218) |
| "mathematically absolute isolation"; "formally verified Cranelift" (seed) | **refuted / narrowed** | M0 2.21 escapes/yr; VeriISLE covers a subset of lowering rules; GHSA-897f escaped it |
| Landlock + seccomp self-sandbox (seed) | **adopted with independent evidence** | +135 µs per install → once per zygote; clone-flag gap; exec spawn (`zygote-sandbox-recipe-measured`, `r4i04.seccomp-clone-flag-gap`) |
| spargio / io_uring thread-per-core (PDF1, seed) | **refuted** | D-2 (`cal-spargio`, `io-uring-security-record`, `cal-uring-370k`) |
| quinn HTTP/3 ingress; QUIC migration (PDF1, seed) | **deferred** | D-4 |
| biscuit-auth 6 + AIP + Datalog (PDF1, seed) | **refuted** | D-3 (`cal-aip`, `r3e05.biscuit-wallclock-limit-observed`); the attenuation-monotonicity *property* is R4-checked in our own token model |
| zero ambient authority (PDF1, seed) | **confirmed** as an invariant | host handles, linker allowlist, seccomp; survives malicious modules (`vfg-invariant-survival-table`) |
| "Iron Gate": pgwire 0.41 + pg_query + SET LOCAL RLS (PDF1, seed) | **refuted as the design; parts adopted** | typed IR across families, no native protocol downstream (`dpf-envoy-db-filters-untrusted`); SET LOCAL ROLE adopted on our q1-012 reproducer with version floors; pg_query (C, GHSA-6ggm) allowed only at build time or out of process; "proven cross-tenant RLS isolation" **refuted** by the write oracle (261/300) and the ON CONFLICT ordering bug |
| per-query `queries.lock` (PDF1) | **adopted with independent evidence, generalized** | backend-agnostic `allowlist.<adapter>.lock` (R-DB-4) |
| redb group-commit session WAL (PDF1, seed) | **alternative, not default** | harness passes redb only with 2PC + Immediate; SQLite FULL default (`cc.result-redb`, `sdg-redb`) |
| per-request CoW arena; journaled replay; MRTR via WAL (seed, PDF1) | **replaced** | fresh instance + `Tx` typestate + commit-point latch; exactly-once claimed nowhere (R-STATE-3/6) |
| "Failed request ⇒ `*grant == *old(grant)`" (PDF1 Verus snippet) | **refuted as the guarantee** | ignores cancellation (15 instances), ambiguous commit, sequences, pooled protocol state; replaced by INV-NOMUT-C (`ac.l5-inv-nomut-c` B) |
| Verus verified core + Z3 4.12.5 stage-1 gate + KVerus loop in the build (PDF1) | **refuted as primary and as a trusted step** | Lean primary on measured footprint (D-8); KVerus exists (`cal-kverus` A, arXiv 2605.03822) but is a paper, no crate; LLMs optional accelerators only (§0c) |
| "LLM output is never a trusted artifact; the checker is the authority" (PDF1) | **confirmed, strengthened** | VeruSAGE cheat rates; our never-executed Lean drafts failed; we add spec-fidelity gates (R-FORMAL-6) |
| madsim DST (PDF1) | **adopted in kind, different instrument** | turmoil 0.7.2 + sans-IO; madsim-tokio stale since 2024-10 (`as.dst-ecosystem`); **they missed** that aws-lc entropy can't be interposed (`as.dst-entropy-leak` A) |
| MCP 2026-07-28 Streamable HTTP, Mcp-Method/Mcp-Name, MRTR (PDF1) | **confirmed; identifiers real** (`cal-mcp-2026-07-28`, re-checked) | corrections: control-char header values are base64-sentinel encoded; sessions/SSE resumability removed; header-first token evaluation must be paired with -32020 consistency via the shared JSON owner; "100% conformance-suite compliance" is not evidence |
| x402 402-gate; "165M transactions" (PDF1, seed) | **not adopted; figure refuted** | no primary source; x402.org widget 75.41M, possibly static; agentic share 0.6–7.5% (`cal-x402-volume`, `j-x402-volume`) |
| PoW (Equihash/Argon2), Privacy Pass, cost-weighted budgets (seed) | **budgets confirmed in spirit, must be aggregate**; PoW speed bump; Privacy Pass needs a trusted issuer | `r3e07-*`, `abuse-anubis-bypass-evidence`, `abuse-privacy-pass-rfcs` |
| machine-cadence detection as a block (seed) | **refuted as a hard deny** | classifier FP 4–6% (`r3e11.xguardian-server-side-anticheat`) |
| one handler projected to HTML/JSON/MCP (PDF1, seed) | **confirmed** [C] | R-AGENT-2; OAS 3.2.1, Arazzo 1.1.0 |
| IFC/taint labels in the WIT ABI; `UntrustedAgentInput` (PDF1, seed) | **adopted as a property with independent evidence, not as a mechanism** | formalized as F10 from CaMeL and Progent; still [E]; runtime lattice is a post-v1 candidate (nucleus does it for tool proxies) |
| Cap'n Proto / FlatBuffers, "0 ns serialization" (seed, PDF1) | **refuted for IPC** | postcard + `serde_bytes`; 4.9× penalty without `serde_bytes` at 64 KB (`w02.serde-bytes-pitfall`) |
| HACL*/libcrux, CompCert/VeriISLE (seed) | **not chosen for FIPS; libcrux kept as a Phase-7 spike** | aws-lc-rs required for FIPS; verified libs ship unverified wrappers (RUSTSEC-2026-0331/0329, `fail-libcrux-spec-bugs-2026`) |
| Nix/Bazel reproducible builds (seed) | **refuted as day-1 choice** | pinned container + remap flags byte-identical (`sc3.repro-ablation-golden` A); Nix/Lix local root privesc 2026-10-13; StageX stretch path (`sc.build-system-alternatives` D) |
| threshold-signed releases (seed) | **adopted with independent evidence, narrowed** | TUF 3/5 root; protects distribution, 0/12 incidents at intake (`sc.sigstore-tuf-threshold`, `sc3.incident-gate-matrix`) |
| Merkle/BLAKE3 tamper-evident log (seed) | **modified** | C2SP tlog-tiles (RFC 6962) for witness/Tessera interop; **they missed** that tamper evidence needs an external witness |
| "~25 MB static binary on a $5 VPS" (seed) | **confirmed in spirit, refuted in magnitude** | 4.21 MB core; ≤9 MB full without JIT |
| hot-swap signed .wasm cartridges (seed) | **modified** | OCI + cosign digest pin; local MAC for .cwasm |
| seL4, SEV-SNP/TDX, SMT-off, DANE/DNSSEC, self-certifying addresses (seed) | **missed by our map** (not researched to grade) | open; none flips a load-bearing rule for the single-binary Linux golden |
| Kubernetes microservices + zero trust (PDF2) | **not adopted as default** (D-14) | rung E2 only |
| PDF2 ML-model threats (poisoning, extraction, adversarial training) | **out of scope** | reappears only as AA4 (server bounds a confused model's authority) |
| PDF2 SBOM + SCA failing on high CVSS | **adopted, strengthened** | fail on any advisory + vet, cooldown, G10, intake |
| PDF2 HSM/KMS keys; WORM logs + SIEM | **partly adopted** | optional KMS `CredentialSource`; tlog + witness instead of WORM |
| PDF2 quarterly red team; `sanitize_input` regex stripping | quarterly → **nightly gate 29 (advisory)**; regex sanitizing **refuted** (reject-don't-repair) | `as.ai-redteam-ci` C, R-ING-4 B |
| PDF2 canary/staged rollout, immutable logs, chaos | **adopted with independent evidence** | CFG-4 from the outage dataset; tlog-tiles; DST |
| reverse-proxy-first strangler migration (PDF2) | **adopted with independent evidence** | `econ.deal-breakers` B, `econ.who-switches-first` D |
| PDF1 "> 300k RPS on 8 cores"; weeks 1–14 schedule | **unsupported** | replaced by same-run band targets and risk-ordered phases with instrumented velocity |
| PDF1 weak points listed in the seed (no threat→obligation map, no TCB, no NOT-proven list, no smuggling hardening, no supply-chain story) | **confirmed as gaps** | filled by §2–§4 and templates |

### 10.2 Missed by the priors, found independently

Async cancellation as a threat class (R-THR-5/R-STATE-6) · cross-request state scope (CRS) · identity canonicalization as one class (CANON) · write-path tenant capture (R-DB-8) and the engine-bug two-sided contract · FIPS lock triangle, decoy lock, AL2023-only OE, and that 0349 is client-side · jurisdiction PQ profiles, ANSSI pure-ML-KEM non-conformance, and that 0x11ED must be our code · EO 14412 · measured crash-containment fault gate · non-adversarial outage gates · proof-checker false PASS (Kani #4905, native_decide, #15908 prelude) · spec fidelity as dominant residual · AI-discovery skeptic data and the fix-to-deploy framing · repo-GHSA OSV blind spot · cooldown vs security-floor conflict and mandatory bypass · CI-pipeline compromise as the largest incident class · in-place upgrade protocol · CRA monetization and steward triggers · no regulator credits code proofs · demand-side positioning.

---

## 11. Anchoring audit (decision → prior-treatment pick → our pick → independent evidence)

| decision | prior-treatment pick | our pick | independent evidence (nodes) |
|---|---|---|---|
| language / packaging | Rust single binary (PDF1, seed) | Rust single binary, ≤6 MB core | `w02.size-deps-table` A, `w02.idle-rss-table` A; R-THR-3 C-server surge |
| TLS library | rustls + aws-lc-rs (PDF1, seed) | same, two FIPS locks, cmvp clients out or PQ-only | `w02.handshake-pq-cost` B, `r4tri.no-co-resolvable-lock` A, `r4tri.fips-sys-decoy-lock` A |
| KEM default | X25519MLKEM768 (PDF1, seed) | per listener + jurisdiction profiles; 0x11ED ours | `r3pq.hrr-acceptance-test` A, `r4e10.anssi-pg083-pure-nonconformant` A, `pq-share-telemetry` A, rustls #3293 |
| TLS auth | ML-DSA-65 + Ed25519 (PDF1) | ECDSA-P256 public, ML-DSA-44 private, MTC later | `r3pq.cab-sc106-withdrawn` A, `r3pq.mldsa-handshake-measured` A |
| release signing | SLH-DSA (seed) | Ed25519 + SLH-DSA-SHA2-128s + ML-DSA-87 | `pq-release-signing` B, `r4e10.golden-signature-profiles` B |
| HTTP stack | hyper (PDF1) | hyper/h2 + AEGIS wrapper | R-TLS-1 A, `l5-transport-budget-invariant-tbi` B, `r4e07.hyper-h2-authority-host-unchecked` A |
| I/O model | spargio io_uring TPC (PDF1, seed) | epoll + tokio | `cal-spargio` A, `io-uring-security-record`, `cal-uring-370k` D |
| HTTP/3 | quinn now (PDF1, seed) | off until h3 fixes | h3 #366 open; `r3pq.quic-amp-budget-mldsa` B; `r4c12.repo-ghsa-osv-blindspot` A |
| handler isolation | Wasmtime pooling + MPK primary (PDF1, seed) | provenance tiers; fresh Wasm in cordons and fork+Wasm for P2 | `r4i04.blast-radius-table` B, `r4i04.m0-escape-rate-denominators` B, `wasmtime-pooling-local-bench` |
| OS sandbox | Landlock + seccomp (seed) | same, once per exec-spawned zygote | `zygote-sandbox-recipe-measured`, `r4i04.seccomp-clone-flag-gap`, R-ISO-4 A |
| authz | Biscuit + AIP Datalog (PDF1, seed) | Cedar + tri-state combiner + three-tier token | `r3e05.token-verify-microbench` B, `r3e05.biscuit-wallclock-limit-observed`, `cal-aip`, `r4e01.combine-failclosed-first-check` A |
| data gate | pgwire proxy + pg_query + SET LOCAL (PDF1, seed) | typed op IR, Lean-checked lowering, two-sided oracles | `dpf-envoy-db-filters-untrusted` A, `r4e01.lower-sound-full-proved` A, `wpo-upsert-keyspace-capture` A |
| store | redb session WAL (PDF1, seed) | SQLite WAL FULL default, redb 2PC alt | crash harness ~130k images (`cc.result-redb`, `sdg-redb`) |
| no-mutation guarantee | Verus `*grant == *old(grant)` (PDF1) | INV-NOMUT-C NC1–NC8 | `ac.root-cause-drop-at-await` A, `ac.l5-inv-nomut-c` B |
| prover | Verus primary + Z3 + KVerus (PDF1) | Lean 4.35 Init-only primary; Verus/Kani CI-only | `r4e01.lakefile-toml-init-only` A, `r4e01.l5-proof-ci-gate` A, `fail-verifier-soundness-bugs` |
| simulation | madsim (PDF1) | turmoil + sans-IO + replaced CryptoProvider | `as.dst-ecosystem` A, `as.dst-entropy-leak` A, `as.oracle-mutation` B |
| MCP | 2026-07-28 (PDF1) | both eras behind a listener-gate type | `cal-mcp-2026-07-28` A, `l5.mcp-lc-passrate-matrix` B |
| IPC encoding | Cap'n Proto / FlatBuffers (seed, PDF1) | postcard + serde_bytes | `w02.serde-bytes-pitfall`, `w02.ipc-hop-cost-1core` A |
| builds | Nix/Bazel (seed) | pinned container + remap flags | `sc3.repro-ablation-golden` A |
| release distribution | threshold signing (seed) | TUF 3/5 + SLSA L3 + independent rebuild | `sc.sigstore-tuf-threshold` B, `sc3.l5-release-attest-rebuild` |
| audit log | BLAKE3 Merkle (seed) / WORM (PDF2) | C2SP tlog-tiles + witness | `ops.audit-log-spec` B |
| deployment | K8s microservices (PDF2) | single binary, K8s rung E2 | R-GAP-4; §1 lean measurements |
| migration | strangler (PDF2) | reverse-proxy-first strangler | `econ.deal-breakers` B, `econ.ingress-nginx-migration-cost` B |
| red team | quarterly (PDF2) | nightly advisory gate | `as.ai-redteam-ci` C (weakest coincident pick; kept on CVE-Bench/garak/promptfoo evidence, not PDF2) |

**Result:** no pick rests only on prior text. Where our pick coincides with a prior pick, the evidence column carries it; in 16 of the 24 rows our pick differs from or narrows the prior pick.

---

## Appendix A. Evidence index (item → node ids / URLs → grade → last checked)

"Last checked" is the date the node was last verified in the map or re-checked at this synthesis (2026-10-25 = re-checked today against a primary source).

| item | node ids / URLs | grade | last checked |
|---|---|---|---|
| unserved combination, rescored | `gap.unserved-combination`, `gap.no-assurance-claims`, `l4.defaults-vs-configurable-matrix`; github.com/coproduct-opensource/nucleus; github.com/agentgateway/agentgateway | C | 2026-10-25 |
| lean budget, RSS | `w02.size-deps-table`, `w02.idle-rss-table`, `w02.L5-lean-budget` | A | 2026-10 (r2) |
| demand / deal breakers | `econ.differentiators-absent`, `econ.deal-breakers`, `econ.who-switches-first`, `econ.agent-gateway-criteria`, `econ.household-criteria`, `v4.pq-hybrid-invisible-default` | B/C/D | 2026-10 (r4) |
| fail-open pattern | `dpf-empty-means-all-pattern`, `r2e11.litellm-failopen` | A | 2026-10 (r2) |
| AI offense / skeptic | `wasmtime-llm-audit-sprint-2026-04`, `skeptic-ai-exploit-overhype`, `v.aixcc-sok-usenix26`, `r3e11.ai-found-bug-flood-vendor-posture`; the-decoder.com, cyberscoop.com | A/B/C | 2026-10-25 |
| threat ranking | `r4e07.instance-ledger`, `v2.calif-h2bomb-ratios`, `http1-desync-2025`, `j-mcp-sdk-advisories`, `uu11.outage-class-frequency-table` | A/B/C | 2026-10 (r4) |
| transport pins + wrapper | `l5-config-pin-table-transport`, `l5-transport-budget-invariant-tbi`, `l5-tbi-tool-assignment`, `r4e07.hyper-h2-authority-host-unchecked`; crates.io hyper/h2 | A/B | 2026-10-25 |
| H3 deferral | hyperium/h3 #366; `r3pq.quic-amp-budget-mldsa`, `r4c12.repo-ghsa-osv-blindspot` | A/B | 2026-10-25 |
| HRR verdicts | `r3pq.hrr-acceptance-test` (PUB-T1..T6), `r4tri.fips-handshake-verdicts` (FIPS-F1..F6) | A | 2026-10-25 (r3/r4 executed) |
| PQ share | `pq-share-telemetry` | A | 2026-04 data |
| jurisdiction profiles | `r4e10.matrix-jurisdiction-requirements`, `r4e10.anssi-pg083-pure-nonconformant`, `r4e10.golden-signature-profiles`, `r4e10.eo14412-us-baseline`, `r4e10.asd-ism-2026-09` | A/B | 2026-10-25 |
| 0x11ED gap | `r4e10.rustls-secp384r1mlkem1024-gap`, `pred-rustls-secp384r1mlkem1024` (re-scored p ≈ 0.2); github.com/rustls/rustls/pull/3293, /pull/2929 | A fact / E prediction | 2026-10-25 |
| FIPS two locks | `r4tri.no-co-resolvable-lock`, `r4tri.fips-sys-decoy-lock`, `r4tri.try-fips-mode-blind`, `r4tri.tested-env-only-al2023`, `r4tri.cmvp-pin-carries-advisories`, `v4.cmvp-lock-carries-rustsec-0349`, `r4tri.golden-lock-no-pq-feature`; CMVP #5298/#5314/#5429 | A/B | 2026-10-25 |
| 0349 client-side | `rec60-rustls-0.23.46-downgrade` | A | 2026-10-25 |
| PQ authentication | `r3pq.cab-sc106-withdrawn`, `r3pq.chrome-cqrp-testing`, `r3pq.mldsa-handshake-measured` | A | 2026-10 (r3) |
| tickets | `crs-ce-stek-lifecycle`; CVE-2025-23419, CVE-2025-23048 | A/B | 2026-10 (r2) |
| release signing | `pq-release-signing`, `r3e11.rfcs-published-in-window` | A/B | 2026-10 (r4) |
| canon | `r4e07.canon-ref-zero-disagreement`, `r4e07.invariant-canon-one-owner`, `r4e07.ci-gate-canon-property`, `v4.whatwg-914-bidi-deno-divergence`, `w02.norm-copy-cost-measured` | A/B/E | 2026-10 (r4) |
| admission | `r3e07-r2-defaults-collapse`, `r3e07-per-ip-collapse`, `r3e07-L5-swarm-acceptance-criteria`, `r3e07-defender-stage-cost-table` (superseded TLS inputs), `r3e07-price-sheet-2026-10`, `abuse-anubis-bypass-evidence`, `abuse-privacy-pass-rfcs`, `cal-x402-volume` | B/D | 2026-10 (r3/r4) |
| Cedar | `r4e01.cedar-tpe-closure-native-decide`, `irl-opa-compile-sql-lowering-defects`; Cedar GHSA-m84h; github.com/cedar-policy/cedar/releases | B/A | 2026-10-25 |
| combiner / token | `r4e01.combine-failclosed-first-check`, `r4e01.token-T1-T6-checked`, `r3e05.token-verify-microbench`, `r3e05.biscuit-wallclock-limit-observed`, `cal-aip` | A/B | 2026-10 (r4) |
| isolation | `r4i04.blast-radius-table`, `r4i04.php-fpm-measured-control`, `r4i04.m0-escape-rate-denominators`, `r4i04.state-leak-c8-measured`, `r4i04.coredump-pipe-hang`, `r4i04.seccomp-clone-flag-gap`, `zygote-sandbox-recipe-measured`, `wasmtime-pooling-local-bench`, `isolation-decision-inputs-table`, `fuel-not-a-security-bound`, `rec60-wasmtime-cranelift-crit-2026-10`; GHSA-897f, GHSA-mghf | A/B/C | 2026-10-25 |
| cancellation | `ac.root-cause-drop-at-await`, `ac.attacker-chosen-cancel-instant`, `ac.l5-inv-nomut-c`, `ac.l5-cancel-sweep-harness` | A/B | 2026-10 (r3) |
| store of record | crash harness (`cc.result-redb`, `sdg-redb`) | A pins / C choice | 2026-10 (r2) |
| data plane read/write | `dpf-envoy-db-filters-untrusted`, `r4e01.lower-sound-full-proved`, `r4e01.not-absent-permits-spec-gap`, `r4e01.spec-fidelity-audit`, `wpo-inv-write-subset`, `wpo-upsert-keyspace-capture`, `wpo-pg-onconflict-where-peek`, `irl-l5-q1012-role-plan-cache-gate`, `irl-post-filter-side-channel-2026` | A/B | 2026-10 (r4) |
| IPC | `w02.ipc-hop-cost-1core`, `w02.serde-bytes-pitfall` | A | 2026-10 (r2/r3) |
| MCP | `rec60-mcp-2026-07-28`, `cal-mcp-2026-07-28`, `l5.mcp-lc-passrate-matrix`, `l5.mcp-lc-corpus-runnable`, `l4.conformance-suite-gap-origin-only`; MCP release tag 2026-07-28 | A/B | 2026-10-25 |
| audit log | `ops.audit-log-spec`; github.com/C2SP/C2SP/blob/main/tlog-tiles.md | B | 2026-10-25 |
| observability | none in graph (0 OTel nodes); `econ.deal-breakers` for the requirement | E / B | 2026-10-25 |
| config/outage gates | `uu11.cfg-push-class`, `uu11.l5-config-lkg-canary-rule`, `uu11.l5-cert-expiry-gate`, `uu11.l5-upstream-budget-retry-budget` | A/C | 2026-10 (r4) |
| systemd | `ops.systemd-baseline-score` | A | 2026-10 (r2) |
| upgrade | `zd.l5-upgrade-harness-gate` | C | 2026-10 (r3) |
| compliance | `ops.cra-obligation-split`, `v2.cra-monetization-trigger`, `ops.fedramp-20x-ksi-mapping`, `ops.niap-no-pp`, `ops.cra-annex3-waf-risk`, `sc.regulator-2025-26-statements`; ENISA, csrc.nist.gov/pubs/ir/8547/ipd, csrc.nist.gov/projects/ssdf, whitehouse.gov EO 14412, cisa.gov bad practices | A/B/C | 2026-10-25 |
| DX | `dx.r4-real-axum-mutant-scores`, `dx.r4-l5-ci-gate-trybuild`, `hist-urweb-adoption-bus-factor` | B | 2026-10 (r4) |
| proofs and checkers | `r4e01.l5-proof-ci-gate`, `r4e01.lakefile-toml-init-only`, `r4e01.l5-theorem-status-table`, `r4e01.lowering-r3-draft-failed-check`, `v4.lean-checker-disagreement-15908`, `v4.lean-soundness-threat-is-build-supply-chain`, `vfg-kani-footprint-and-gate-failures`, `fail-verifier-soundness-bugs`, `fail-spec-fidelity-studies`; lean4 #15908, kani #4910 | A/B | 2026-10-25 |
| LLM proving | `llm-verusage-2025`, `cal-kverus`, `llm-lean-provers-transfer`, `llm-dafny-agents`, `rec60-spec-fidelity-verus`, `rec60-rust-prover-llm-proofs`, `vfg-cryptoprover-cloud-llm-optional`, `hist-ironfleet-cost-vs-llm`, `proof-aeneas-symcrypt` | A/B/C | 2026-10 (r1–r4) |
| DST / fuzz / mutants | `as.dst-ecosystem`, `as.dst-entropy-leak`, `as.oracle-mutation`, `as.fuzz-gate`, `as.http-diff-fuzz`, `as.mutants-gate`, `as.ai-redteam-ci` | A/B/C | 2026-10 (r1–r3) |
| supply chain | `sc3.l5-ci-gate-list`, `sc3.golden-lock-gate-run`, `sc3.vet-zero-exemption-baseline`, `sc3.cooldown-executed-cargo-198`, `v4.cooldown-holds-vulnerable-webpki`, `sc3.repro-ablation-golden`, `sc3.tarball-git-parity-golden`, `sc3.trustpub-sha-gate`, `sc3.incident-gate-matrix`, `sc3.incident-class-fractions`, `sc3.slopsquat-rust-study-2606`, `sc3.arrayref-trust-model-gap`, `sc3.geiger-014-golden-unsafe`, `sc.sigstore-tuf-threshold`, `sc.auditable-sbom`, `sc.ferrocene-qualified-rustc`, `sc.rustc-bootstrap-trust`, `sc.build-system-alternatives`; cargo#17335; static.rust-lang.org channel | A/B/C/D | 2026-10-25 |
| handshake cost | `w02.handshake-pq-cost` | B | 2026-10 (r2) |
| io_uring | `cal-spargio`, `io-uring-security-record`, `cal-uring-370k` | A/D | 2026-10 (r1) |
