# AEGIS: LATEST cumulative view (through round 1, 2026-10-24)

Sources:
- State: `state/graph.jsonl` (345 nodes), `state/edges.jsonl` (363 edges), `state/seen.jsonl` (736 canonical URLs), `state/frontier_queue.jsonl` (144 items).
- Rules: `ARCHITECTURE-DRAFT.md` (41 rules).
- Round history: `reports/round-001.md`.
- Blind-research status (§0a): independent map only; not yet reconciled with prior treatments.

**Saturation status: NOT saturated.**
- mechanical_novelty is 1.0 (trivial, since this is round 1).
- Unseen-mass estimate: 0.95 strict-singleton, 0.71 with partial matches.
- Four pillars have no targeted coverage (W-ABUSE, W-OPS, W-PERF, W-DX), and neither do the §0b/§0c areas.

## 1. Map: pillar × layer node counts

| pillar | L1 | L2 | L3 | L4 | L5 | total |
|---|---|---|---|---|---|---|
| W-THREAT | 1 | 8 | 4 | 6 | 1 | 20 |
| W-GAP | 0 | 5 | 27 | 1 | 0 | 33 |
| W-TRANSPORT | 0 | 0 | 1 | 22 | 0 | 23 |
| W-PQC | 0 | 0 | 0 | 23 | 0 | 23 |
| W-ISOLATION | 0 | 3 | 10 | 13 | 2 | 28 |
| W-STATE | 0 | 3 | 23 | 0 | 2 | 28 |
| W-AUTHZ | 0 | 2 | 20 | 17 | 6 | 45 |
| W-DATA-GATE | 0 | 1 | 10 | 1 | 1 | 13 |
| W-AGENT-PROTOCOL | 1 | 1 | 22 | 6 | 1 | 31 |
| W-ABUSE | 0 | 0 | 0 | 0 | 0 | **0** |
| W-FORMAL | 0 | 1 | 5 | 16 | 2 | 24 |
| W-ASSURE | 0 | 0 | 3 | 7 | 7 | 17 |
| W-SUPPLY | 0 | 0 | 1 | 11 | 7 | 19 |
| W-PERF | 0 | 0 | 1 | 0 | 0 | **1** |
| W-OPS | 0 | 0 | 0 | 1 | 0 | **1** |
| W-DX | 0 | 0 | 2 | 1 | 0 | **3** |
| R-HISTORY | 0 | 0 | 17 | 0 | 0 | 17 |
| S-FORMAL-WEB | 0 | 1 | 4 | 2 | 0 | 7 |
| K-CALIBRATION | 0 | 0 | 0 | 12 | 0 | 12 |

Grades: A 130 · B 159 · C 37 · D 3 · E 16. Verification: 173 of 333 explorer nodes passed the two-sided check; 17 moved up and 28 moved down.

## 2. Best-known choice per pillar (grade; alternatives; reversal)

| pillar | best-known choice now | grade | alternatives kept in map | key nodes |
|---|---|---|---|---|
| W-THREAT | Rank: H2/H3 resource exhaustion > canonicalization/fail-open authz > smuggling > C memory corruption (RCE tail) > agent origin/session/audience > TLS logic/PQ downgrade > decompression > supply chain. Mitigate logic and resource classes first; hours-scale patch pipeline | B (classes A) | skeptic view: AI-found CVEs exploited at base rate (1.3%) | `threat-ledger-middle-tier-2023-2026`, `result-memory-safety-would-not-prevent-fraction`, `v.http2-bomb-cve-2026-49975` |
| W-GAP | Position as integration plus assurance; fail-closed defaults as a feature; governance-screened bases | C (absence claim) | Pingora, Envoy, Caddy, Spin, agentgateway, Docker MCP Gateway, Hyperlight, Firecracker | `gap.unserved-combination`, `gap.insecure-defaults` |
| W-TRANSPORT | hyper 1.12.0 + h2 ≥0.4.20, H1/H2 over TCP with explicit budgets; H2/framed upstream; strict H1 grammar; epoll; H3 opt-in or at edge | A/B | quinn/s2n-quic/quiche (H3), Pingora, io_uring opt-in | `crate-hyper-h2`, `crate-quinn`, `io-uring-security-record` |
| W-PQC | rustls 0.23.46 + aws-lc-rs, X25519MLKEM768 + HRR-to-PQ; FIPS profile aws-lc-rs =1.17.4 with SecP256r1MLKEM768; ECDSA public certs until MTC; Ed25519 + SLH-DSA release signing | A (FIPS group B) | OpenSSL 3.5 / Go module; CNSA ML-KEM-1024 profile (C); ML-DSA private PKI | `std-rfc10024-ecdhe-mlkem`, `fips-cmvp-mlkem-modules`, `v.rhel-fips-hybrid-groups`, `std-mtc-plants` |
| W-ISOLATION | Provenance-keyed table: native Rust + capability ctx + arena + catch_unwind for first-party; hardened Wasmtime in a sandboxed worker for agent code; process cordons or microVM for third party; microVM/gVisor for native code | E design (A/B inputs) | V8 isolates (workerd says "not a hardened sandbox"), Hyperlight, Firecracker, gVisor, fork-server, CHERI (watch) | `isolation-decision-table-by-provenance`, `wasmtime-pooling-local-bench` |
| W-STATE | One txn per request (no mutation on failure); idempotency per draft-08 + Stripe in the same txn; effect classes declared; any store-of-record gated by our crash harness (SQLite WAL FULL as default candidate) | B (harness E) | redb 4.4, fjall, LMDB/heed, sled (excluded), Temporal/Restate/DBOS patterns | `sdg-failed-request-no-mutation`, `sdg-idempotency-draft`, `sdg-embedded-store-selection` |
| W-AUTHZ | Cedar 4.14 + symcc as PDP (error-in-forbid ⇒ Deny); own two-tier attenuable token (HMAC inside a domain, ML-DSA/hybrid root at crossings); machine-diff approvals; IFC labels on wire | C decision (A/B inputs); token E | Biscuit, Macaroons, UCAN, ZCAP, Rego, OpenFGA/SpiceDB, CaMeL/Progent/FIDES | `l5-authz-stack-recommendation`, `cedar-lean-proofs-2026-10`, `pqc-capability-token-design` |
| W-DATA-GATE | (Postgres adapter only) fingerprint allowlist of Parse messages; SET LOCAL ROLE in one txn per request; session state banned; RLS defence-in-depth only; PG ≥18.6/17.11. **The backend-agnostic model is not yet researched (§0b)** | A/B (adapter); open (general) | PgBouncer/PgDog/Supavisor/pgcat, sqlx/sqlc/pg_query, RLS-as-primary (rejected) | `sdg-l5-db-gate-invariants`, `sdg-rls-plan-cache-family`, `sdg-txn-pooling-session-leak` |
| W-AGENT-PROTOCOL | MCP 2026-07-28 stateless + 2025-11-25 shim; PRM/8707/9207/CIMD; Web Bot Auth (RFC 9421); generic 402 module optional; one JSON-Schema-2020-12 IR projected to OpenAPI/MCP/WebMCP | A (projection C) | A2A 1.0.1, AP2, ACP, UCP, x402/MPP, llms.txt (barely consumed) | `j-mcp-2026-07-28`, `j-webbotauth`, `j-projection-implication` |
| W-ABUSE | **none** (only per-connection budgets from W-THREAT I1) | — | — | queue q1-008 |
| W-FORMAL | Verus for small kernels; Lean for model semantics (Cedar-style model + DRT; Aeneas where it fits); Kani for unsafe/glue; TLA+/P + DST for liveness; reuse verified crypto and parsers; spec-fidelity CI gate | B | Creusot, Prusti, hax/F*, Dafny, LLM math provers (do not transfer) | `llm-verusage-2025`, `rec60-spec-fidelity-verus`, `practice-agent-proof-pipeline`, `estimate-proof-cost-per-component` |
| W-ASSURE | sans-IO core + turmoil DST; oracle mutation; cargo-mutants ratchet; fuzz + HTTP Garden differential; Miri/sanitizers on unsafe; AI red-team canary stage | A/B/C | madsim, bach, Antithesis (cost unknown), shuttle/loom | `as.dst-harness-spec`, `as.oracle-mutation`, `ci.stage-list` |
| W-SUPPLY | `--locked`; cargo-vet with new-crate hard fail; deny/audit; cargo min-publish-age + Dependabot cooldown; unsafe ceilings; repro double build; SLSA L3; TUF 3/5 | A/B | Nix, StageX, Bazel (D); mrustc bootstrap (B) | `sc.vet-import-sets`, `v.cargo-min-publish-age-rfc3923`, `sc.repro-build-experiment` |
| W-PERF | Measured: pooled Wasm 6.9 µs; fork 124 µs (small parent). Nanvix table. QUIC 45% slower at 1 Gbps. No server benchmarks yet | A local / B | TechEmpower archived | `wasmtime-pooling-local-bench`, `nanvix-same-hw-coldstart-2026`, `hist-techempower-sunset` |
| W-OPS | CRA reporting (24 h/72 h/14 d) since 2026-09-11; everything else open | B | — | `rec60-cra-reporting-live` |
| W-DX | Native Rust for first-party handlers; typed SQL/HTML AST in SDK (Ur/Web lesson); language head-to-head open | A lesson / B rates | OCaml/Haskell/Gleam (lag one-shot), WIT components | `hist-urweb-guarantees-and-nonguarantees`, `v.fpeval-probe-2026` |

## 3. Threat → mitigation → assurance matrix (current)

| threat (rank) | mitigation | assurance mechanism | rung | residual |
|---|---|---|---|---|
| 1 H2/H3 resource exhaustion [A] | default-on decoded-byte, stream and reset budgets per conn/tenant; bounded handlers; H3 opt-in | regression corpus (Rapid Reset, MadeYouReset, H2 Bomb, Header Accordions); fuzz oracle out/in ≤ K; proposed budget invariant | test → (proof candidate) | new variant ~yearly |
| 2 canonicalization / fail-open authz [A/B] | single canonical request form; fail-closed loader; Cedar PDP; error-in-forbid ⇒ Deny | Cedar Lean model + DRT; verifyNeverErrors; default-config gate | proof (model) + DRT | Cedar Rust evaluator and parser |
| 3 smuggling / differentials [A] | strict H1 grammar; H2/framed upstream; regenerate framing | HTTP Garden differential; HTTP Terminator; EverParse/Vest for binary framings | differential test / generated-verified parser | H1 text parser unproven |
| 4 memory corruption [A] | Rust; first-party forbid(unsafe); unsafe ceilings | Miri, ASan/TSan, geiger ceiling gate | type boundary + test | aws-lc C, tokio unsafe, rustc |
| 5 agent origin/session/audience, confused deputy [B] | stateless MCP; origin allowlist; audience-typed tokens; capability context; IFC labels; machine-diff approvals | SDK-advisory regression corpus; 2-run NI fuzz; Ajar metric; red-team canaries | type boundary + test | NI only tested |
| 6 TLS logic / PQ downgrade [B] | pinned rustls; HRR policy; closed group enum | downgrade harness; BoGo; Wycheproof | test | WebPKI PQ auth gap |
| 7 decompression / complexity [B] | decode budgets; no Brotli cert compression | fuzz with ratio oracle | test | — |
| 8 supply chain [A incident] | locked + cooldown + vet + no-network build.rs + repro + SLSA + TUF | double-build hash equality; attestation verify; zizmor | process / provenance | long-dwell maintainer compromise |
| sandbox escape [A/B] | provenance table; process cordons; config pin | advisory SLO; upstream VeriISLE | boundary | ~3 escape-class bugs/yr |
| cross-request state leak [A] | stateless protocols; SET LOCAL only; fresh Store per request | pooler canary; trap-reuse test | type/API boundary + test | PG plan-cache CVE family |
| durability loss [A/B] | txn per request; ack ⇒ fsynced; EIO ⇒ abort | crash harness; DST disk model; oracle mutation | DST + test | DST fidelity; store bugs |

## 4. TCB ledger (current)

rustc/LLVM/std · tokio (155k LOC) · hyper (16.7k) / h2 (15.2k) / httparse (3k, 75 unsafe) · rustls (45.7k, 6 unsafe) · aws-lc-rs + aws-lc-sys (2.09M lines vendored C; verified parts: mlkem-native, s2n-bignum) · Linux kernel (seccomp, Landlock, cgroups; KVM if microVM) · Wasmtime/Cranelift (P2/P3 only) · Cedar Rust evaluator (15.7k; DRT) · build-time checkers: Verus+Z3, Lean kernel, cvc5, Kani/CBMC (never shipped to the server, §0c) · specs themselves · Postgres server and planner (adapter) · embedded store (harness-gated) · CI/release: GitHub runners, Sigstore, TUF keys.

**NOT proven:**
- the Cedar Rust evaluator
- HTTP/1.1 text framing
- the async I/O shell
- Wasmtime runtime/WASI/component glue and the x64 Cranelift lowering
- KVM
- aws-lc C outside its verified parts
- handler noninterference
- DST fidelity
- store crash consistency
- the fidelity of every spec

## 5. Top bridges

1. **Unauthenticated cross-request state** joins W-DATA-GATE (pooler/RLS plan cache), W-PQC (rustls cached key-share downgrade), W-AGENT-PROTOCOL (MCP removed sessions) and W-ISOLATION (store reuse after trap). Candidate core invariant.
2. **Determinism** joins W-AUTHZ (fuel, not wall clock), W-ISOLATION (epoch vs fuel) and W-ASSURE (DST entropy leak via raw getrandom in aws-lc).
3. **Fail-open defaults** join W-GAP, W-AUTHZ (Cedar skip-on-error), W-STATE (NATS ack-before-fsync) and W-THREAT (KEV auth bypass). One default-config gate covers all four.
4. **AI-found bugs** span W-ISOLATION, W-STATE, W-TRANSPORT and W-THREAT. The same capability doubles as the AI red-team CI stage.
5. **"HTTP/1 must die" ↔ verified-parser gap ↔ EverParse/Vest.** Verify binary framings and avoid HTTP/1 upstream.
6. **Spec fidelity** joins W-FORMAL (VerusEval 42.3%), W-PQC (libcrux spec bugs) and W-AUTHZ (Cedar proves the model, not the Rust code). Executable-spec differential testing is the shared remedy.

## 6. Open frontier (top of `state/frontier_queue.jsonl`)

| id | score | question (abridged) | why |
|---|---|---|---|
| q1-001 | 0.95 | Data-plane abstraction across all backend families | §0b mandatory; only the PG/SQLite adapter is researched |
| q1-002 | 0.95 | Protocol-agnostic ingress + modularity mechanism + leanness measurements vs nginx/Caddy/Pingora/Envoy/HAProxy | §0b mandatory |
| q1-003 | 0.90 | agentgateway / docker-mcp-gateway CVE diffs → violated invariants | turns CVEs into SPEC_INVARIANTS |
| q1-004 | 0.90 | Verification toolchain footprint; Lean without Mathlib; per-component prover | §0c mandatory |
| q1-005 | 0.85 | H2/H3 budgets as a Verus/Kani invariant | largest threat class |
| q1-006 | 0.85 | Share of Wasmtime advisories that hit the hardened config | sets P2 residual risk |
| q1-007 | 0.85 | Golden extension contract and which invariants survive third-party modules | §0c |
| q1-008 | 0.85 | W-ABUSE pillar | zero nodes |
| q1-010/011 | 0.80 | Component-model per-request cost; ML-KEM handshake on 1 vCPU | perf model empty |
| q1-012 | 0.80 | CVE-2026-14666 reproducer: SET LOCAL ROLE + plan cache | gates R-DB-1 |

**Decisions that could still flip** (load-bearing, support E/C):
- R-ISO-1 (isolation table)
- R-AUTHZ-1/2 (Cedar PDP, own token)
- R-STATE-4 (store choice)
- R-DB-1 (adapter identity mechanism)
- R-AGENT-2 (single IR projection)
- R-GAP-1 (gap framing)
- R-DB-2 (data-plane model; entirely open)
