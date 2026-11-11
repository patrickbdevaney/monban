# Monban: LATEST cumulative view (through round 4, 2026-10-25)

Sources:
- State:
  - `state/graph.jsonl`: 938 node ids, of which 910 are canonical (non-merged); 78 revision records.
  - `state/edges.jsonl`: 1,382 edges.
  - `state/seen.jsonl`: 2,109 canonical URLs.
  - `state/frontier_queue.jsonl`: 575 items.
  - `state/predictions.jsonl`: 43, scored as of 2026-10-25; one resolved TRUE.
- Rules: `ARCHITECTURE-DRAFT.md` (97 rules).
- Round history: `reports/round-001.md` through `round-004.md`.
- Blind-research status (§0a): independent map only, not yet reconciled with the prior treatments.

**Saturation status: NOT saturated.**
- Mechanical novelty: round 2 = 0.898, round 3 = 0.881, round 4 = **0.909**. The threshold is < 0.2 in two consecutive rounds.
- Round-4 unseen mass ≈ 0.88 (strict singletons 0.22). First visible overlap: three topics were found twice by different explorers and merged.
- Decisions are stable: 85 of 86 round-3 rules kept direction (**0.988**). One changed: R-PQC-3. The pure CNSA profile is demoted to an opt-in profile, because France rules pure ML-KEM non-conformant.
- The open load-bearing questions are almost all implementation-phase spikes:
  - a real 1-vCPU handshake and IPC hop
  - streaming in the scoped SDK
  - the false-reject rate of strict canonicalization
  - a custom 0x11ED key-exchange group
  - the fuel-budget gate
  - MySQL/Mongo write oracles
  - a three-valued IR reference in Lean

  Only two are literature questions: procurement texts (q4-003) and LLM-found advisory rates (q1-009).
- Per §0c, the default is to pivot to building at the round cap.

## 1. Map: pillar × layer node counts (canonical nodes, cumulative)

| pillar | L1 | L2 | L3 | L4 | L5 | total | new in r4 |
|---|---|---|---|---|---|---|---|
| W-DATA-GATE | 0 | 2 | 15 | 52 | 14 | 83 | 17 |
| W-AUTHZ | 0 | 2 | 26 | 29 | 15 | 72 | 7 |
| W-TRANSPORT (incl. ingress front ends) | 0 | 0 | 4 | 59 | 7 | 70 | 6 |
| W-FORMAL | 0 | 1 | 11 | 43 | 10 | 65 | 16 |
| W-PQC | 0 | 1 | 5 | 48 | 10 | 64 | 25 |
| W-AGENT-PROTOCOL | 1 | 1 | 27 | 25 | 8 | 62 | 10 |
| W-ISOLATION | 0 | 3 | 13 | 30 | 11 | 57 | 15 |
| W-STATE | 0 | 3 | 28 | 8 | 10 | 49 | 0 |
| W-SUPPLY | 0 | 0 | 2 | 29 | 16 | 47 | 6 |
| W-GAP | 2 | 8 | 32 | 3 | 0 | 45 | 14 |
| W-OPS | 1 | 1 | 14 | 19 | 8 | 43 | 1 |
| W-ABUSE | 1 | 3 | 12 | 19 | 8 | 43 | 0 |
| W-THREAT | 3 | 11 | 7 | 14 | 5 | 40 | 17 |
| W-BRIDGE (cross-request state, cancellation, canonical identity) | 0 | 4 | 17 | 4 | 7 | 32 | 9 |
| W-DX | 0 | 2 | 8 | 15 | 5 | 30 | 12 |
| W-PERF | 0 | 0 | 3 | 14 | 11 | 28 | 1 |
| W-ASSURE | 0 | 0 | 3 | 8 | 14 | 25 | 3 |
| R-HISTORY | 0 | 0 | 18 | 1 | 0 | 19 | 2 |
| T-SAFETY-CERT (new r4) | 0 | 3 | 1 | 9 | 3 | 16 | 16 |
| K-CALIBRATION | 0 | 0 | 0 | 9 | 2 | 11 | 2 (+13 revisions) |
| S-FORMAL-WEB | 0 | 1 | 4 | 2 | 0 | 7 | 0 |
| W-UNKNOWN | 1 | 0 | 0 | 1 | 0 | 2 | 0 |

Grades (canonical nodes, latest record): A 342 · B 394 · C 119 · D 27 · E 28.

Verification:
- Round 1: 173 of 333 checked (17 up, 28 down).
- Round 2: 168 of 211 (15 up, 45 down).
- Round 3: 161 of 211 (4 up, 52 down).
- Round 4: 150 of 176 (15 up, 43 down). Downs were mostly single-machine experiments, citation mismatches and checker-independence overclaims; there was one outright range error (aws-lc-rs 1.17.2).

Thin areas after round 4:
- Pillars: W-STATE, W-ABUSE, W-PERF, W-OPS had no round-4 target (W-OPS gained rules from the outage dataset).
- Axes: benchmark sources, hyperscaler/household scale, database vocabulary outside the write path, Chinese primaries.

## 2. Best-known choice per pillar (grade; alternatives; key nodes)

| pillar | best-known choice now | grade | alternatives kept in map | key nodes |
|---|---|---|---|---|
| W-THREAT | Two adversarial rankings (KEV: canonicalization/fail-open authz first; Rust advisory volume: resource exhaustion ~55-61%, falling, TLS logic rising). Identity canonicalization divergence is one class: 11 instance classes, 34 dated instances (24 from 2026). Plus a **non-adversarial outage ranking**: config push 17.5% > latent bug 12.5% > exhaustion 10.6% > capacity > retry/dependency/DNS > reload/cert 5% each; 0 memory-corruption causes in 160 outages | B (classes A; outage frequencies C) | skeptic: AI-found CVEs exploited at base rate | `threat-ledger-middle-tier-2023-2026`, `r4e07.instance-ledger`, `uu11.outage-class-frequency-table`, `ac.root-cause-drop-at-await` |
| W-GAP | Integration + assurance + measured leanness is the gap; **positioning changed by demand data**: assurance is an invisible default; enter via agent-infra builders (credential isolation, MCP authz, audit, compiled binary); clear migration parity, default drift, paywall and governance deal breakers first | C (gap) / C-D (demand) / B (deal breakers) | Pingora, Envoy, Caddy, Traefik (ingress-nginx compat), HAProxy, agentgateway, nucleus | `gap.unserved-combination`, `econ.differentiators-absent`, `econ.deal-breakers`, `econ.who-switches-first` |
| W-TRANSPORT | Normalization core with an Exchange object and front-end defect-class rules (unchanged), plus **CANON-1..8 in one `monban-canon` crate**: reject-don't-repair, sealed Canon_K, authz on the matched route id, SNI/authority/Origin binding (421) with userinfo rejected, exact-match A-label hosts (no IDNA on ingress), duplicate-rejecting JSON/cookie/media-type owners; simd-json/sonic-rs banned; CANON-DIFF gate. hyper/h2 do not check Host vs :authority, so the core does | A (differential, pins) / B (classes, identity sub-claim) / E (invariant) | normalize-and-forward (lighttpd/Cloudflare), WHATWG host parsing (rejected), per-protocol stacks | `r4e07.invariant-canon-one-owner`, `r4e07.canon-ref-zero-disagreement`, `r4e07.hyper-h2-authority-host-unchecked`, `r3e09.ring1-verdict-amendment` |
| W-PQC | **Typed jurisdiction profile set:** P-UNIVERSAL = SecP384r1MLKEM1024 (0x11ED; missing from rustls 0.23.46, so a custom group or upstream PR is a blocker), P-CNSA pure ML-KEM-1024 + ML-DSA-87 opt-in, P-PUBLIC-WEB (X25519MLKEM768 first), gov profiles without X25519/Ed25519/ChaCha/0-RTT. Server: pq-required on agent/API listeners, client order on public; FIPS listener sets kx_groups explicitly. **FIPS: two lock profiles** (floor: rustls 0.23.46 + aws-lc-rs 1.18; cmvp: rustls 0.23.43 + aws-lc-rs 1.15.3 + fips-sys 0.13.11, AL2023 operational environments only, with an advisory-exception list); single-fips-sys and FIPS-string gates | A (primaries, resolver, verdicts) / B (profile decision, FIPS decision) | OpenSSL 3.5 FIPS provider; forked rustls without ML-DSA (spike); floor-only, no CMVP claim | `r4e10.golden-tls-kex-profiles`, `r4e10.matrix-jurisdiction-requirements`, `r4tri.no-co-resolvable-lock`, `r4tri.fips-sys-decoy-lock`, `r3pq.hrr-acceptance-test` |
| W-ISOLATION | Provenance table, direction unchanged, now with **measured containment**: P1 native + catch_unwind + resource ledger + supervisor-held socket + crash budget; P2 fresh Wasm instance per request (reuse 1, fuel 10-50 ms) in a **per-tenant** OS-sandboxed cordon, exec-spawned; multi-principal P2 = fork per request from an exec-spawned zygote. dumpable=0; clone-flag filter, clone3 ENOSYS; Wasmtime ≥36.0.19 or ≥49.0.4 on any arch; serve reuse pinned to 1. Escape planning rate 2.21/yr; trigger ≥3 M0 escapes in 12 months | B (containment) / A (perf, pins) / C (rates, kernel reachability) / E (expected loss) | V8 isolates (OOM process-fatal), Hyperlight, Firecracker, gVisor | `r4i04.provenance-substrate-decision-table`, `r4i04.blast-radius-table`, `r4i04.php-fpm-measured-control`, `wasmtime-advisory-share-by-config` |
| W-STATE | Unchanged from round 3: INV-NOMUT-C (NC1-NC8), cancel sweep, CR1-CR9, driver pins, idempotency with the principal in the key, crash-harness-gated store (SQLite WAL+FULL default), CRS C1-C8 + C5b + C8 (C8 now measured: reused context poisons nearly all later requests) | A/B/C | one-txn+outbox alone; state-tracked reuse | `ac.l5-inv-nomut-c`, `crs-l5-invariant-text`, `r4i04.state-leak-c8-measured` |
| W-AUTHZ | Cedar 4.14 PDP (cite its Lean theorems at B until `#print axioms` runs; Int64 native_decide in the TPE closure). Token tiers (opaque handle default / HMAC chain in verified CBOR / COSE ML-DSA-65 at crossings); **token model T1-T5 checked in Lean**, with D1 segment-prefix resources, D3 verify-time depth and D4 missing-argument-denies to ratify; **Combine fail-closed checked** (first real file) | A (checked models) / B (decision, Cedar theorem status) | Biscuit, UCAN, ZCAP, AAT/DT drafts, JWT (avoid) | `r4e01.token-T1-T6-checked`, `r4e01.token-spec-sharpenings`, `r4e01.combine-failclosed-first-check`, `r3e05.l5-token-decision` |
| W-DATA-GATE | Backend-agnostic op IR with per-adapter lowering. **Lean model checked** (lower_sound_full closed). Adapter contract **two-sided** (leak = 0 ∧ miss = 0) for any adapter exposing NOT; schema gate refuses mismatched partition keys; three-valued reference to decide at freeze. **Write path:** INV-WRITE-SUBSET W1-W7, executed write oracle, composite arbiters, FORCE + WITH CHECK RLS, no REPLACE family, upsert WHERE without user expressions, Redis flush/swap bans; PG19 gated on the ON CONFLICT ordering fix | A (executed, model) / B (denylists, Mongo/MySQL doc-derived) / C (IR design) | RLS alone; SQLite authorizer; policy-to-SQL compilers | `r4e01.lower-sound-full-proved`, `r4e01.exact-vs-refines-not-witness`, `wpo-inv-write-subset`, `wpo-l5-write-denylist`, `wpo-pg-onconflict-where-peek`, `irl-l5-unsound-lowering-denylist` |
| W-AGENT-PROTOCOL | MCP 2026-07-28 (still the latest dated revision on 2026-10-25) + 2025-11-25 path. Listener gate enforces Host/Origin in both eras regardless of SDK defaults (Origin protection is default-off or absent in rmcp, agentgateway, py, TS modern). **43-case corpus executed** against 5 implementations; 2026-07-28 delta (-32020, -32022, 404/-32601, GET 405, sealed requestState). The official conformance suite is not evidence (warnings on MUSTs; no Origin-only case) | B (corpus, defaults) / A (spec revision) / C (suite gap) | A2A, AP2; reuse official cases once strict | `l5.mcp-lc-corpus-runnable`, `l5.mcp-lc-passrate-matrix`, `l5.listener-gate-delta-2026-07-28`, `l4.defaults-vs-configurable-matrix` |
| W-ABUSE | Round-3 tuned pipeline kept as mechanism. **Overclaim corrected**: C1/C2 were mixed-scenario only; the tuned table fails aged_swarm, flash_crowd, worst-seed dc_swarm (C1) and cheap_flood (C2); report per scenario, tune on held-out seeds | D (numbers) / B (mechanisms) | Anubis Argon2id, Privacy Pass, ASN keying | `r3e07-L5-swarm-acceptance-criteria`, `r3e07-L5-tuned-default-table` |
| W-FORMAL | Lean 4.35.0 Init-only toolchain (**712 MB** with lakefile.toml, zero requires); 45 theorems checked, 0 sorry; gate = pin check → build (no sorry) → per-theorem axiom **allowlist** {propext, Classical.choice, Quot.sound} → `lake check --paranoid` (6 checkers, ~4 min / 1.0 GB, CI only); native_decide banned; from-export only on own exports; known-false-proof corpus. Checkers disagree on adversarial preludes (#15908). Verus/Kani CI-only | A (executed) / B (checker independence, qualification argument) | Verus, Kani, F*, Rocq; DO-330 TQL-5-style qualification | `r4e01.l5-proof-ci-gate`, `r4e01.lakefile-toml-init-only`, `r4e01.native-decide-aux-axiom-naming`, `v4.lean-checker-disagreement-15908`, `sc.implication-checker-qualification-arguments` |
| W-ASSURE | Executed oracles first (lowering read/write, identity differential, MCP corpus, FIPS probe, cancel sweep). New gates: isolation fault-injection gate (counts hard, latency soft), CANON-DIFF, trybuild compile-fail corpus, Lean proof gate, CFG/CERT/UPS/OPS gates. Assurance case: every claim has ≥2 evidence kinds plus a residual | A/B | Antithesis, LazyFS | `r4i04.isolation-fault-ci-gate`, `r4e07.ci-gate-canon-property`, `dx.r4-l5-ci-gate-trybuild`, `sc.implication-case-structure-diverse-evidence` |
| W-SUPPLY | Round-3 gates plus **G10 repo-GHSA poll** (7 of 133 repo GHSAs were invisible to OSV on 2026-10-25), an expiring reachability-justified ignore list for certified pins, single-fips-sys and FIPS-string gates; the 7-day cooldown with the audited bypass is confirmed mandatory (it lands the vulnerable webpki); `prefer-post-quantum` missing from the golden's own rustls dependency, now fixed | A (executed) / B (policies) | Nix/StageX, TUF | `r4c12.repo-ghsa-osv-blindspot`, `sc3.cooldown-executed-cargo-198`, `r4tri.golden-lock-no-pq-feature`, `sc3.l5-ci-gate-list` |
| W-PERF | Core numbers unchanged. IPC hop: same-core 4.8 µs is the best case, cross-core 8.07 µs (budget ≈12.4k calls/s/core). Substrates on 1 core: native 22.6k rps, fresh Wasm 21.1k, cordon 24.1k, fork 8.2k, PHP-FPM 9.1k (toy handler). Crash restart 1.3-1.9 ms with a held socket | A (laptop) / B (substrate bands) | iceoryx2 / shm rings | `w02.ipc-hop-cost-1core`, `r4i04.blast-radius-table`, `w02.handshake-pq-cost` |
| W-OPS | Round-3 ops rules plus **outage-derived gates**: CFG-1..4 (total parse, bounded artifacts, last-known-good, staged apply), CERT-1..4 (expiry gauge, preflight, atomic swap, faketime CI), UPS-1..6 (per-upstream budgets, deadlines, retry budget, rlimit preflight, log budget, TTL re-resolution), OPS-1..5 (healthy floor, dry-run, linear regex, monotonic clock, readiness-ack reload). **Government-buyer route:** memory-safe language + FIPS module + EAL4+ ST if demanded + formal policy model (SA-17(1)); no regulator credits code proofs | C (gates, buyer route) / A-B (incidents, certificates) | EAL7 as a separately funded decision; Ferrocene for safety regimes | `uu11.l5-config-lkg-canary-rule`, `uu11.l5-cert-expiry-gate`, `uu11.l5-upstream-budget-retry-budget`, `sc.implication-buyer-recognition-route`, `zd.l5-upgrade-protocol` |
| W-DX | **Scoped-adapter capability SDK (B2)** on real axum: Routes-only registration with a sealed `for<'r> ScopedHandler`, borrowed `Ctx<'r>`, app crates without tokio/axum dependencies, Tx Drop guard, Detached capability for background work, clippy ban list, trybuild gate; owned extractors rejected (`'static` escapes). Open: streaming/SSE/WS/body extraction and agent repair on B2 diagnostics | B (experiment, decision) / C (prior art) | owned extractors (16/32), plain axum + lints (3/32), WIT handlers, cap-std reuse | `dx.r4-l5-decision-update`, `dx.r4-real-axum-mutant-scores`, `dx.r4-l5-sdk-api-changes`, `dx.r4-l5-ci-gate-trybuild` |
| T-SAFETY-CERT (new) | Proofs discharge specific claims; tests/fuzz/DST stay independent legs (DO-333, CompCert at MTU). Checkers get TQL-5-style qualification arguments with a known-false-proof corpus; no prover is qualified anywhere, so qualification cost is not a discriminator. Real EAL6/7 evaluations are rare, slow and costly; the realistic ceiling is EAL4+/EAL5+ | B (standards, precedents) / C (negative existence) | Ferrocene-qualified rustc; EAL7 | `sc.do333-credit-scope`, `sc.do330-tql-verification-tools`, `sc.compcert-qualification-evidence`, `sc.cc-eal6-eal7-real-evals` |

## 3. Threat → mitigation → assurance matrix (current)

| threat (rank) | mitigation | assurance mechanism | rung | residual |
|---|---|---|---|---|
| 1 H2/H3 resource exhaustion [A] | golden pins + wrapper; TBI-1..9; H3 off; explicit tonic limits | Kani H1-H5; Verus ledgers; Lean composition; fuzz resource oracle; DST stall | proof (structs) + test | TBI-4/7/8 rely on the wrapper; C_FIELD |
| 2 canonicalization / fail-open authz [A/B] | **CANON-1..8 (one owner per identity, reject-don't-repair)**; authz on route id; Cedar; tri-state combiner (checked); INV-NONEMPTY; binary collations | CANON-DIFF G1-G4; Cedar Lean + DRT; Lean Combine (checked); lowering oracle | proof (model) + differential + DRT | false-reject rate; Cedar Rust evaluator; Cedar theorem axioms |
| 3 smuggling / differentials [A] | strict H1; H2 upstream; validated-101 gate; one JSON owner shared by policy and handler; Host = :authority binding | HTTP Garden; framing corpus (q3-013); Lean H1 model; identity differential | model + differential | Rust H1 parser unproven |
| 4 memory corruption [A] | Rust; forbid(unsafe); C drivers out of process; geiger ceilings | Miri, sanitizers, unsafe gate | type + test | aws-lc C, tokio, rustc |
| 5 agent origin/session/audience [A/B] | listener-gate type in both eras regardless of SDK defaults; sealed handles | **executed 43-case corpus**; CSWSH matrix | type + test | absent-Origin interop; SDK churn |
| 6 cross-request state scope [A] | CRS C1-C8 + C5b; fresh instance per request (C8 measured) | two-scope oracles; poison test in the isolation gate | test | unenumerated classes |
| 7 TLS logic / PQ downgrade [B] | rustls ≥0.23.46; pq-required on agent/API listeners; **jurisdiction profiles**; FIPS kx explicit | HRR test on both lock profiles; per-profile ClientHello matrix | test | public listener classical for X25519-first clients; cmvp lock carries 0349; 0x11ED absent |
| 8 data-plane injection / authz per family [A] | typed IR; lock + denylists; **two-sided refinement contract**; **write denylist + INV-WRITE-SUBSET**; native per-tenant creds | Lean model (checked); two-sided executed oracle; write oracle; schema gate; RLS CI with column-free writes | proof (model) + test | Exact violated by engines (BUG #19645); PG ON CONFLICT order; MySQL/Mongo writes; timing channels |
| async cancellation [A] | INV-NOMUT-C; discard-on-cancel; SDK Drop guard (not a backstop) | cancel sweep; CR1-CR9; TLA+/P | test + lint + model | executed paths only |
| non-adversarial outages (r4) [C freq / A-B instances] | CFG/CERT/UPS/OPS gates | config fuzz; faketime; slow-upstream DST; TLA+ healthy ≥ floor | test + model | latent logic bugs on valid input |
| crash blast radius (r4) [B] | per-tenant fresh-instance substrates; dumpable=0; held socket; crash budgets | isolation fault-injection gate | test | laptop-only numbers |
| 9 decompression / complexity [B] | decode budgets; no permessage-deflate; GraphQL cost to the core budget | fuzz ratio oracle | test | — |
| 10 supply chain [A] | locked + cooldown with bypass + vet + intake + repro + parity + provenance + rebuild + workflow lint + **G10 repo GHSAs** | double build; attestation; zizmor; fips_lock_gate | provenance | xz-class long windows; OSV lag |
| proof-checker false PASS (r4) [B] | allowlist; native_decide ban; 6 checkers; own exports only; no third-party Lean deps | executed gate + negative control; known-false-proof corpus | process | shared-spec bugs; spec fidelity |
| admission swarms [B] | S0.5, fresh class, aggregate budgets, step-up PoW | per-scenario acceptance on held-out seeds | sim + test | fails 3 scenarios; uncalibrated sim |
| reload / upgrade [A mechanisms] | fd inheritance; claim-or-close; GOAWAY; drain deadline; readiness ack | upgrade harness | test + model | forced closes after D; H3 resets |
| sandbox escape [A/B] | OS sandbox around Wasm; pins (any arch); clone filter; exec spawn | config assertions; 72 h SLO; negative syscall tests | boundary | 2.21 escapes/yr planning rate; kernel LPE via allowlisted syscalls |
| durability loss [A] | ack ⇒ fsynced; bootstrap dir fsync | crash harness + DST | test | double fault, EIO |
| remote timing [A] | constant time at TCP-ts resolution | dudect/ctgrind | test | lowering timing channel |

## 4. TCB ledger (current)

- **Toolchain and runtime:** rustc/LLVM/std (Ferrocene-qualified option for safety regimes); tokio (155k LOC).
- **HTTP stack:** hyper, h2, httparse, the Monban transport wrapper (ours), and **`monban-canon`** (ours; one identity canonicalizer).
- **TLS and crypto:** rustls; aws-lc-rs/aws-lc-sys. Two lock profiles: floor (AWS-LC FIPS 4.2.0 source, uncertified) and cmvp (AWS-LC FIPS 3.1.0, CMVP #5298/#5314, AL2023 operational environments only, with documented advisory exceptions).
- **Data plane:** adapters in process (each driver's full LOC). Per-adapter Refines/Exact hypotheses are tested by a two-sided oracle, not proven. For writes, PG RLS (FORCE + WITH CHECK) and vetted triggers. Engine logic bugs are in scope.
- **Ours:** pool checkin predicate and drop guards; token verifier + EverParse deterministic CBOR; upgrade handover parser; tlog writer; supervisor (sockets, crash budgets, exec-spawned zygote).
- **Linux kernel:** seccomp (clone-flag filter), Landlock, cgroups, systemd sandboxing; KVM if microVM.
- **Wasmtime/Cranelift:** P2/P3 only, inside per-tenant OS sandboxes.
- **Policy:** Cedar Rust evaluator (DRT); the Lean compiler only for analyses that use native_decide.
- **Build-time checkers, never shipped:** Lean 4.35.0 Init-only toolchain + 6 checkers + gate scripts; Verus + Z3; Kani/CBMC ≥#4910; TLC; cvc5. Specs and model hypotheses are trusted.
- **Stores:** Postgres (adapter); embedded store (harness-gated).
- **CI/release:** runners (bwrap AppArmor profile needed for the lake sandbox), Sigstore, TUF keys; toolchain digest and auditable mode in the build identity.

**NOT proven:**
- IR lowering for real engines: the model is checked; Refines/Exact, renderer = model and the 3VL reference are tested or open.
- The write path (oracle-tested W1/W2/W4 only).
- CANON-1..8 (differential on a small corpus).
- Cedar Rust evaluator, and Cedar's Lean theorems' axiom status.
- Rust HTTP/1.1 framing; TBI-4/7/8 over hyper/h2; the async shell and liveness.
- Cancel safety beyond swept paths.
- Wasmtime runtime and glue; KVM; aws-lc C outside its verified parts.
- Native DB enforcement; normalizer ≡ backend parser; microarchitectural tenant isolation.
- Admission numbers (fail 3 scenarios) and I3/I4/I6/I9/I10.
- Token outside the model: Rust verifier, codec, constant-time compare, HMAC EUF-CMA. Upgrade UP-1..7 are statements only.
- Store crash consistency beyond single crashes; handler noninterference; DST fidelity; spec fidelity.
- Proof-checker independence.
- Isolation numbers beyond one laptop; outage frequencies as incidence.
- No regulator credits any of these proofs.

## 5. Top bridges

1. **Fail-closed construction** (r2) now covers the config plane too: CFG-1..4, with totality as one proof rung shared by config parse and identity canonicalization (r4).
2. **Scope tuple σ = tenant handle = clean pooled connection** (r2+r3), with CRS C8 now measured (r4): only a fresh instance per request has zero poisoning.
3. **One owner per identity, at every layer** (r3+r4): grpc-go `:path`, SQL collation, Host vs :authority, MCP Origin defaults and the JSON header/body check (-32020) are one class with one fix, `monban-canon`.
4. **Engine bugs break adapter contracts from both sides** (r4). PG BUG #19645 (completeness) and ON CONFLICT before RLS (side effects) require a two-sided read oracle and a write oracle on every engine bump, and one three-valued reference for NOT and the write W1 clause.
5. **The lockfile is a security artifact** (r3+r4): cooldown vs security floors; prefer-post-quantum; the empty FIPS triangle; the decoy fips-sys lock; repo GHSAs invisible to OSV. Gates read `cargo metadata`, not grep.
6. **One proof pattern on one small toolchain** (r3+r4): verified parser + core-Lean semantics theorem + DRT to Rust, now **executed** (712 MB, 45 theorems). The gate is the qualification evidence (DO-330 TQL-5 style).
7. **Executed oracles beat reading** (r3+r4). This round they caught a broken Lean draft, a phantom "proven" claim, a tenant-capture upsert, a silent FIPS module swap and a canonicalizer bug.
8. **Demand vs mandate** (r4): forums never ask for PQ or proofs, while national rules mandate PQ by date. Ship assurance as invisible defaults and profile evidence; win adoption on parity.
9. **Crash containment = durability = abuse** (r4). Fork-server crash containment is also a BROP oracle: exec spawn plus per-principal crash budgets. The fd-leak gray failure is the lab twin of the 10.6% exhaustion outage class.
10. Carried over:
    - budgets at two layers + one admission ledger
    - drain = cancellation
    - interposition is unsound for Rust
    - modularity = isolation = TCB accounting
    - generated artifacts are untrusted input

## 6. Open frontier (top of `state/frontier_queue.jsonl`)

| id | score | question (abridged) | closes by |
|---|---|---|---|
| q3-001 | 0.80 | rustls full vs resumed handshake CPU on a real $5 vCPU | spike (R-ABUSE-1, R-PERF-1) |
| q4-001 | 0.80 | B2 scoped adapter for streaming/SSE/WS and detached jobs | spike (R-DX-1) |
| q1-009 | 0.80 | LLM-found vs human-found advisory rates | research (R-THR-2) |
| q3-002 | 0.75 | ipcbench on a real 1-vCPU VPS, same-core vs cross-core | spike (R-MOD-1) |
| q2-009 | 0.75 | Window-0 stalled flow-control harness vs golden pins | spike (TBI-8) |
| q4-002 | 0.70 | Agent repair success on B2 diagnostics | spike (R-DX-1) |
| q4-003 | 0.70 | Procurement texts: do they score PQ-TLS, memory safety, formal assurance? | research (R-GAP-4) |
| q3-005 | 0.70 | Swarm simulator v2; per-scenario, held-out seeds | spike (R-ABUSE-4) |
| q2-013 | 0.70 | Kani/Verus RAM and time on TBI harnesses | spike (R-FORMAL-2) |
| q2-007 | 0.70 | Double-fault + fsync-EIO crash harness | spike (R-STATE-4) |
| q4-004 | 0.60 | Three-valued IR reference; re-prove lower_sound_full | Lean (R-DB-7) |
| q4-005 | 0.60 | Write oracle on MySQL/MariaDB + CockroachDB | spike (R-DB-8) |
| q4-006 | 0.60 | Fuel budget + 64-slot pool for the Wasm loop gate | spike (R-ISO-5) |
| q4-008 | 0.60 | False-reject rate of strict canonicalization on 1M request lines | spike (R-ING-4) |
| q4-026/028 | 0.50 | 0x11ED in rustls (custom group or upstream) | spike (R-PQC-8) |

**Decisions that could still flip** (load-bearing, support at E/C/D):
- R-ISO-1 (expected-loss model; kernel reachability)
- R-ING-4 (false-reject rate)
- R-PQC-8 (0x11ED; BSI 2027)
- R-DB-7/8 (3VL reference; PG fix; MySQL/Mongo)
- R-GAP-4 (procurement evidence)
- R-ABUSE-1 (D)
- R-STATE-4 (double faults)
- R-GAP-1 (short shelf life; recheck at synthesis)

Every one closes during implementation (spikes, prototypes, harness runs), except q4-003 procurement and the R-GAP-1 recheck. The research recommendation per §0c: **pivot to building at the round cap.**
