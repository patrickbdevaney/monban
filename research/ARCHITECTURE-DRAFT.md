# AEGIS ARCHITECTURE-DRAFT (running; integrator-maintained)

Status: **after round 1 (2026-10-24)**. This is the running protocol of directive §9. It is built only from the independent map (`state/graph.jsonl`) under the §0a blind-research rule. It is not reconciled with the prior treatments; that happens only at Synthesize/Critique/Final. Every rule carries an evidence grade, node ids, and a reversal condition.

Grade convention:
- A/B/C/D/E as in META §3.
- A rule's grade is the weakest link among its load-bearing evidence. A decision built on graded inputs but inferred by us is marked E (design) or C (decision with independent support).
- §0b applies: Postgres/SQLite rules are **adapter** rules, not the data-plane design. §0c applies: proofs are build-time only.

---

## 1. Positioning and the unserved gap

- **R-GAP-1** [C] The gap is integration plus assurance, not a missing primitive.
  - No surveyed system (~45 repos) combines all of: a memory-safe single binary, per-request isolation, capability authz, native agent protocols, PQ-TLS, and machine-checked claims.
  - Nearest competitors by column: Pingora (transport), Spin (isolation), agentgateway (agent protocol).
  - Nodes: `gap.unserved-combination`, `gap.no-assurance-claims`, `gap.agentgateway`, `gap.spin`, `gap.pingora`.
  - Reverse if a project or closed product is found holding ≥4 of the 6 columns.
- **R-GAP-2** [A] Fail-closed default configuration is a positioning requirement, enforced as a CI gate that tests the shipped default config.
  - Docker MCP Gateway, Ferron, Pingora and agentgateway all shipped fail-open or insecure defaults in 2026.
  - Nodes: `gap.insecure-defaults`, `gap.docker-mcp-gateway`, `gap.ferron`.
  - Reverse: never; this is a hygiene floor.
- **R-GAP-3** [A] Choose bases and dependencies by governance: multi-maintainer or foundation, and a release within 24 months.
  - NGINX Unit archived, River dormant, Lunatic dormant, Ur/Web has 86% of commits from one author, Hails dormant since 2016.
  - Nodes: `gap.dormancy-churn`, `hist-urweb-adoption-bus-factor`, `hist-meta-blocker-matrix`.

## 2. Threat model (ranked, likelihood × impact)

- **R-THR-1** [B] Rank threats in this order:
  1. H2/H3/QUIC protocol-state resource exhaustion [A]
  2. Path/host canonicalization and fail-open authz logic [A/B]
  3. Request smuggling and parser differentials [A]
  4. Memory corruption in C/C++ components, the RCE tail [A]
  5. Agent/MCP origin binding, session-principal binding and token audience [B]
  6. TLS validation logic, including PQ downgrade [B]
  7. Decompression and algorithmic complexity [B]
  8. Supply chain: account takeover and slopsquatting [A incident / B rates]
  - Nodes: `threat-ledger-middle-tier-2023-2026` and the `threat-*` refinements, `v.http2-bomb-cve-2026-49975`, `sc.arrayref-incident`.
  - Reverse if a year of KEV and advisory data reorders the top three.
- **R-THR-2** [B] Assume AI-accelerated discovery. Every TCB component needs a rebuild-and-release path measured in hours, plus runtime feature kill-switches.
  - Basis: day-zero exploitation share of 23.4% in 1H2026 (falling from 28.9%) and a 2026 advisory surge (nginx 26 vs 2; wasmtime, quinn and rustls waves).
  - The skeptic data (14 of 1,061 AI-found CVEs exploited) is noted; it argues against panic, not against the pipeline.
  - Nodes: `result-time-to-exploit-trend`, `observation-2026-advisory-surge`, `skeptic-ai-exploit-overhype`, `result-ai-discovery-capability-2025-2026`.
  - Diff r1: the framing changed from "no patch window" to "hours-scale pipeline".
- **R-THR-3** [B] Memory safety is required (it removes the RCE tail) but ranked as insufficient. Mitigation effort goes first to logic and resource classes.
  - Basis: about 81% of KEV additions are non-memory; ~99% of memory-safe-server advisories are logic or resource bugs.
  - Node: `result-memory-safety-would-not-prevent-fraction`.

## 3. Reference architecture (component picks; each one candidate among alternatives)

### Transport / parser
- **R-TLS-1** [A] Front protocols: HTTP/1.1 and HTTP/2 over TCP, using hyper `=1.12.0` and h2 `>=0.4.20`.
  - Set explicit budgets: max_header_size, max_concurrent_streams, reset-rate, decoded header list, body caps.
  - Alternatives: Pingora as a framework (8 GHSA, weak defaults), Go net/http (8 net/http fixes in one release).
  - Nodes: `crate-hyper-h2`, `rec60-go-1.27.2-batch`, `gap.pingora`.
  - Reverse if hyper/h2 show a sustained HIGH-advisory wave like quinn's.
- **R-TLS-2** [A/B] HTTP/3 is opt-in. Default to terminating QUIC at an edge or CDN, or running it in an isolated worker with a cgroup memory cap.
  - Basis: quinn-proto had 11 HIGH DoS advisories in 2026, including a fix-of-fix. hyperium/h3 0.0.8 is stale and QPACK is unbounded. QUIC is 45% slower than H2 at 1 Gbps.
  - Alternatives: s2n-quic (Kani proofs, 6 advisories); quiche (FFI UAF CVE).
  - Nodes: `crate-quinn`, `crate-h3`, `rec60-header-accordions-qpack`, `quic-perf-reality`, `crate-s2n-quic`.
  - Reverse after 6 months with no HIGH quinn advisory, plus h3 shipping finite QPACK defaults (prediction `pred-h3-qpack-limit`).
- **R-TLS-3** [B] Upstream framing is HTTP/2 or a framed Unix socket by default. Any HTTP/1.1 upstream regenerates framing.
  - Strict H1 grammar: reject CL+TE, duplicate CL even if equal, TE on HTTP/1.0, bare LF/CR, obs-fold, and bodies on GET/HEAD/OPTIONS unless allow-listed.
  - Nodes: `threat-request-smuggling-desync`, `rec60-ai-desync-http-terminator`, `http1-desync-2025`.
  - Reverse if a machine-proved H1 framing parser lands, which would let H1 upstreams stay unregenerated.
- **R-TLS-4** [A] TLS uses rustls `=0.23.46` + aws-lc-rs, and rustls-webpki `>=0.103.16` (emSign distrust and name-constraint wave).
  - Disable Brotli certificate decompression. Lint against Debug output on session types.
  - Nodes: `crate-rustls-pq`, `adv-rustls-2026-wave`, `rec60-name-constraints-emsign-wave`.
  - Diff r1: the webpki pin was raised by the verifier.
- **R-TLS-5** [B] Default to epoll. io_uring is opt-in for the trusted front only. Workers deny io_uring syscalls by seccomp, and CI asserts EPERM.
  - Basis: io_uring had 54 NVD CVEs in 2026 YTD vs 11 for epoll, and a 2026 LPE on a hardened kernel. Drop-in gains are 0–10%.
  - Nodes: `io-uring-security-record`, `io-uring-perf-reality`, `rec60-kernel-isolation`.
  - Reverse if a measured ≥30% gain appears on our workload with zcrx+kTLS at ≤10 Gbps, with no new LPE in 12 months.
- **R-TLS-6** [B] Verify binary framings (H2 frames, QUIC varints, PROXY v2, CBOR tokens) with generated verified parsers (EverParse/3D, Vest). Leave HTTP/1 text framing to R-TLS-3 plus differential fuzzing.
  - Nodes: `proof-everparse-hyperv`, `proof-vest-verdict`, `gap-verified-http1-parser`, `v.coq-vst-http-kv-itp2021`.

### PQC
- **R-PQC-1** [A] Key exchange prefers X25519MLKEM768. The server sends HRR to the PQ group whenever the client lists it. Pre-standard Kyber codepoints are rejected.
  - Invariant: no unauthenticated input changes the next ClientHello's key_share set.
  - Nodes: `std-rfc10024-ecdhe-mlkem`, `rec60-rustls-0.23.46-downgrade`, `std-key-share-prediction`.
- **R-PQC-2** [B] FIPS profile: aws-lc-rs `=1.17.4` with the `fips` feature, which maps to AWS-LC FIPS v3 (CMVP #5314/#5298, includes ML-KEM).
  - Default group in FIPS mode is SecP256r1MLKEM768.
  - CI blocks 1.18.x in the FIPS profile, and also blocks the yanked 1.17.2.
  - Nodes: `fips-cmvp-mlkem-modules`, `crate-aws-lc-rs`, `v.rhel-fips-hybrid-groups`, `std-sp800-227` (C).
  - Diff r1: the default group changed. Reverse when a FIPS v4 certificate is listed (`pred-awslc-fips-v4-cmvp`).
- **R-PQC-3** [C] CNSA 2.0 profile: ML-KEM-1024 hybrids now. A pure ML-KEM-1024 group is pending a contested draft. ML-DSA-87/LMS for signing.
  - Nodes: `std-cnsa2-dates` (secondary sources), `v.pure-mlkem-tls-draft-contested`.
  - Reverse when the NSA primary text differs.
- **R-PQC-4** [B] Public WebPKI certificates stay ECDSA until Merkle Tree Certificates arrive. Build a pluggable certificate layer and ACME rotation down to ≤7-day lifetimes. ML-DSA X.509 is for private PKI only.
  - Nodes: `std-mtc-plants`, `std-pq-x509-rfcs`, `std-cab-pq-ballots`, `pq-size-mtu-reality`.
- **R-PQC-5** [B] Release signing is dual Ed25519 + SLH-DSA-SHA2-128s. Node: `pq-release-signing`.

### Isolation
- **R-ISO-1** [E design; A/B inputs] Isolation is keyed by code provenance:
  - **P1, first-party:** native Rust with a capability-typed context, a per-request arena, catch_unwind (panic=unwind), forbid(unsafe) plus lint bans, and server-wide seccomp+Landlock.
  - **P2, agent-generated or semi-trusted:** hardened Wasmtime components in a sandboxed worker process, with a fresh Store per request.
  - **P3, multi-tenant third party:** Wasm inside per-trust-cordon processes, or a microVM for high-value tenants.
  - **P4, arbitrary native code:** microVM or gVisor only.
  - Nodes: `isolation-decision-table-by-provenance`, `wasm-vs-native-verdict`, `wasmtime-pooling-local-bench`, `nanvix-same-hw-coldstart-2026`, `rust-type-system-not-adversarial-boundary`, `spectre-posture-matrix`.
  - Reverse:
    - 12 months with no x86_64 tier-1 critical plus >80% x64 VeriISLE coverage → P3 may drop the process split for low-value tenants.
    - Hyperlight 1.0 with an audit and <2 ms cold start → replaces in-process Wasm for P2.
- **R-ISO-2** [B] Wasmtime config pin: x86_64 tier-1 only, Cranelift, `wasm_memory64(false)`, Spectre mitigations and signals-based traps on, Winch off, GC/component-model-async/exceptions off unless needed, `epoch_interruption(true)`, and a pooling allocator with explicit totals.
  - Version: `>=36.0.19` on LTS or `>=50.0.0`. Watch RustSec/GHSA with a 72 h patch SLO.
  - Nodes: `wasmtime-memory64-spectre-config`, `rec60-wasmtime-cranelift-crit-2026-10`, `wasmtime-ghsa-record-2021-2026`.
  - Open: q1-006 (which share of advisories hit this config).
- **R-ISO-3** [A] ISO invariants:
  - A Store or arena that saw a trap or panic is never reused.
  - Guests get no ambient filesystem; I/O goes through host-mediated capabilities with byte and operation budgets (cgroup io.max beneath).
  - CPU is bounded by an epoch deadline plus a wall-clock watchdog. Fuel is never the DoS bound.
  - Nodes: `crash-isolation-semantics`, `wasi-resource-isolation-attack-usenix25`, `fuel-not-a-security-bound`, `cal-wasmtime-13467`.

### Authn / authz
- **R-AUTHZ-1** [C decision; A/B inputs] PDP: Cedar `4.14.x` + cedar-policy-symcc `0.8.x`.
  - Policies are validated and SMT-checked at deploy time, never parsed from untrusted text on the request path.
  - An error in a `forbid` policy yields Deny (a documented deviation), plus a CI gate running verifyNeverErrors on every forbid.
  - Rejected as PDP: Rego (no semantics), OpenFGA/SpiceDB (fail-open bug cluster; usable as entity store only), Biscuit (no model, no PQC, wall-clock limits, no release in 15 months), Oso (archived).
  - Nodes: `l5-authz-stack-recommendation`, `cedar-lean-proofs-2026-10`, `cedar-policy-crate-4.14`, `cedar-skip-on-error-semantics`, `authz-formal-pdp-comparison`.
  - Reverse if Biscuit gains a model, ML-DSA and fuel limits, or a Cedar delegation RFC lands (`pred-cedar-no-delegation`).
- **R-AUTHZ-2** [E] Capability token in two tiers:
  - Inside one trust domain: HMAC chain (Macaroon-style typed caveats, 32 B each, PQ-safe).
  - At trust-domain crossings: an ML-DSA-65 or hybrid root. The algorithm set is a closed enum.
  - After first presentation, pass a by-reference handle (a per-hop ML-DSA chain is 11–16 KB).
  - Nodes: `pqc-capability-token-design`, `fips204-mldsa-sizes`, `macaroons-ndss2014`, `gap-verified-attenuable-pq-token`.
  - Open: header limits (q1-045), IETF attenuation drafts (`v.ietf-agent-attenuation-drafts`, E).
- **R-AUTHZ-3** [B] Capability widening is shown as a machine-computed set diff, never as model-authored text. Approval signs a canonical effect digest. Provenance labels travel on the wire across MCP/A2A.
  - Basis: single-agent CaMeL does not compose across agents.
  - Nodes: `approval-to-abuse-2610.22987`, `rec60-agent-authz-attacks`, `camel-noncompositional-2610.05640`, `progent-2504.11703`.
- **R-AUTHZ-4** [B] Agent endpoints by default:
  - Origin allowlist (403 otherwise), RFC 9728 PRM, RFC 8707 audience binding, RFC 9207 iss check when present, CIMD. DCR is legacy only.
  - Tokens are audience-typed, so token passthrough is impossible.
  - Nodes: `j-mcp-auth`, `j-mcp-security-bp`, `j-mcp-sdk-advisories`, `threat-mcp-agent-layer`.

### State / WAL / idempotency
- **R-STATE-1** [B] Failed request ⇒ no committed mutation (INV-NOMUT), by construction: one transaction per request and no autonomous commits.
  - Carve-outs: sequences, advisory locks, stats, and ambiguous commit.
  - External effects happen only after commit, through an outbox.
  - Nodes: `sdg-failed-request-no-mutation`, `sdg-jepsen-postgres`.
- **R-STATE-2** [A spec / E design] Idempotency follows draft-ietf-httpapi-idempotency-key-header-08 plus Stripe v1 semantics:
  - Key is scoped (tenant, principal, method, route, key) plus a request fingerprint.
  - Responses: 422 on mismatch, 409 while in flight, replay when done. TTL ≥24 h.
  - The idempotency record is written in the same transaction as the effect.
  - Nodes: `sdg-idempotency-draft`, `sdg-stripe-idempotency`, `sdg-l5-idempotency-store`.
- **R-STATE-3** [B] Every external effect class declares one of: tx-colocated, peer-idempotent(key), at-most-once, or human-reconcile. Exactly-once execution of an arbitrary external effect is claimed nowhere. Node: `sdg-exactly-once-boundary`.
- **R-STATE-4** [B] Any store-of-record must pass our crash harness: ALICE reorderings, bit flips, misdirected writes, EIO on fsync (abort, never retry), and crash during recovery, with 0 violations over 1e5 states nightly.
  - Current default candidate: SQLite WAL `synchronous=FULL`, single writer, `>=3.53.0`. Alternative: redb `4.4.x` with Durability::Immediate.
  - Nodes: `sdg-embedded-store-selection`, `sdg-l5-crash-harness`, `v.rebello-atc20-fsync-failures`, `sdg-redb`, `sdg-sqlite-wal`.
  - Reverse on harness results.

### DB gate (adapter rules; general data-plane model open under §0b)
- **R-DB-1** [A/B] Postgres adapter:
  - Forward only Parse messages whose fingerprint is in the allowlist; Bind parameters only.
  - Each request runs in BEGIN..COMMIT with SET LOCAL ROLE.
  - No session state (reject non-LOCAL SET, set_config(,,false), DISCARD, LISTEN, session locks, WITH HOLD, temp tables).
  - RLS is defence-in-depth only, with FORCE RLS and column grants. PG `>=18.6/17.11`.
  - Pooler, if any, sits on a private socket: PgBouncer `>=1.26.1`.
  - Nodes: `sdg-l5-db-gate-invariants`, `sdg-txn-pooling-session-leak`, `sdg-rls-plan-cache-family`, `sdg-pgbouncer`, `sdg-compile-time-extraction`, `sdg-db-gate-residual-risk` (C).
  - Reverse on the q1-012 reproducer result.
- **R-DB-2** [open] A backend-agnostic mediation model (typed operation IR, per-adapter build-time allowlists, out-of-process adapters) has no evidence yet. Round 2 target q1-001.

### Agent-protocol projection
- **R-AGENT-1** [A] MCP 2026-07-28 is the primary target, with a 2025-11-25 compatibility shim.
  - It is stateless: no per-connection protocol state, server/discover implemented, routing on Mcp-Method/Mcp-Name before body parse.
  - Nodes: `j-mcp-2026-07-28`, `j-mcp-stateless-no-sessions`, `j-rmcp-sdk`.
- **R-AGENT-2** [C] One handler IR (JSON Schema 2020-12) projects to OpenAPI 3.2, MCP tools, WebMCP and Server Card.
  - CI checks round-trip equality and denies external `$ref`.
  - Nodes: `j-projection-implication`, `j-openapi-arazzo`.
- **R-AGENT-3** [A/B] Agent identity uses a Web Bot Auth / RFC 9421 verifier with bounded, no-redirect directory fetch. Payments sit behind an optional generic HTTP 402 interface (x402/MPP volume evidence is C). Emit both Content-Usage and Content-Signal.
  - Nodes: `j-webbotauth`, `j-rfc9421`, `j-x402-volume`, `j-aipref`.

### Observability / ops
- **R-OPS-1** [B] EU CRA reporting has been live since 2026-09-11: a 24 h / 72 h / 14 d runbook, PSIRT contact, VEX/CSAF output, and a tamper-evident awareness timestamp. Node: `rec60-cra-reporting-live`. The rest of W-OPS is open (q1-015).

## 4. Assurance case (threat → mitigation → mechanism → residual)

| threat | mitigation | assurance mechanism | residual |
|---|---|---|---|
| H2/H3 resource exhaustion | per-conn/tenant decoded-byte, stream, reset budgets on by default; H3 opt-in | fuzz oracle out/in ≤ K; regression corpus of Rapid Reset, MadeYouReset, H2 Bomb, Header Accordions; proposed Verus/Kani budget invariant (q1-005) | new composition variants yearly (`pred-new-h2h3-dos-variant` p=0.75) |
| smuggling / parser differential | strict H1 grammar; H2/framed upstream; regenerate framing | HTTP Garden differential gate; HTTP Terminator run (released); EverParse for binary framings | H1 text parser unproven |
| canonicalization / authz bypass | single canonical request form consumed by routing and authz; Cedar PDP | Cedar Lean model + DRT; ACL-on-canonical-form oracle | Cedar Rust evaluator and parser not proven |
| fail-open config | fail-closed loader; error-in-forbid ⇒ Deny | default-config CI gate; verifyNeverErrors | operator overrides |
| memory corruption | Rust, forbid(unsafe) in first-party code, unsafe allowlist ceilings | Miri on unsafe-reaching tests; ASan/TSan; cargo-geiger ceilings | aws-lc C (2.09M LOC vendored), tokio/memchr unsafe, rustc |
| agent confused deputy / injection | capability context; IFC labels on wire; machine-diff approvals | 2-run NI fuzz on AuthSel; Ajar open-privilege metric; AI red-team canaries | NI for general handlers undecidable, so tested only |
| MCP origin/session/audience | stateless MCP; origin allowlist; audience-typed tokens | SDK-advisory regression corpus (~30 cases) | new SDK classes |
| PQ downgrade / TLS logic | HRR policy; pinned rustls; closed group enum | downgrade-injection harness; BoGo; Wycheproof | WebPKI PQ auth absent until MTC |
| sandbox escape (Wasm/KVM) | provenance table; process cordons; nested virt off | config pin; advisory SLO; VeriISLE upstream | ~3 escape-class Wasmtime bugs/yr; KVM core bugs |
| cross-request state leak | stateless protocol layer; SET LOCAL only; fresh Store | pooler canary test (A dirties, B asserts baseline) | PG plan-cache CVE family (~0.9/yr) |
| durability loss | one txn/request; ack ⇒ fsynced; fsync EIO ⇒ abort | crash harness; DST with simulated disk; oracle mutation | DST fidelity gap; store bugs |
| supply chain | `--locked`, cooldown, vet new-crate fail, no network in build.rs, SLSA L3, TUF 3/5 | repro double-build; attestation verify; zizmor | maintainer account takeover in long-dwell attacks (xz class) |

### TCB ledger (round 1; sizes where measured)
- **rustc + LLVM + std.** 166 open I-unsound issues. Bootstrap via mrustc is possible but no DDC report exists.
- **tokio.** 155k LOC, 2,394 unsafe expressions used.
- **hyper/h2/httparse.** 16.7k / 15.2k / 3k LOC; unsafe 62 / 1 / 75 sites.
- **rustls.** 45.7k LOC, 6 unsafe sites.
- **aws-lc-rs / aws-lc-sys.** 2.09M lines of vendored C. mlkem-native carries CBMC + HOL Light proofs. FIPS module boundary.
- **Linux kernel.** seccomp-bpf, Landlock, cgroups. KVM if microVMs are used.
- **Wasmtime + Cranelift.** P2/P3 paths only. VeriISLE rule checks are partial: aarch64-heavy, x64 thin.
- **Cedar Rust evaluator.** 15.7k LOC, DRT-tested against the Lean model. The Lean kernel and cvc5 are trusted for the analyses.
- **Proof checkers (build time only).** Verus + Z3 (41 open soundness issues; Z3 unsound-unsat bugs), Lean kernel, Kani/CBMC. Specs themselves are TCB.
- **Postgres server and planner.** RLS is defence-in-depth only. Adapter libraries: pg_query (C parser in process, heap OOB fixed), sqlx/pgwire.
- **SQLite or the chosen embedded store.** Gated by our harness.
- **CI and release infrastructure.** GitHub Actions runners, Sigstore/Rekor, the TUF root keys.

### NOT proven (explicit)
- Rust evaluator of Cedar (DRT only).
- HTTP/1.1 text framing.
- The tokio/hyper I/O shell.
- Wasmtime runtime, WASI and component glue.
- The x86_64 Cranelift lowering.
- KVM.
- The aws-lc C outside mlkem-native/s2n-bignum.
- Noninterference of arbitrary handlers.
- DST fidelity to the real kernel, TLS entropy and disk semantics.
- Embedded store crash consistency.
- Spec fidelity of every proved component.

## 5. Formal properties (named; rung)

| invariant | statement source | tool / rung (proposed) |
|---|---|---|
| no_ambient_authority | `inv-no-ambient-authority` | Lean induction over step relation; Rust sealed `Cap<O>` type boundary |
| attenuation_monotonicity | `inv-attenuation-monotonicity` | Lean denotation lemma; Verus checker refinement + DRT; symcc checkImplies on policy diffs |
| confused_deputy_NI(AuthSel) | `inv-confused-deputy-ni` | Lean relational property for mediator; 2-run hyperproperty fuzz for handlers |
| decision_total_deterministic_failclosed | `inv-decision-determinism-failclosed` | fuel-step limits; DRT with error-to-deny overlay |
| failed_request_no_mutation | `sdg-failed-request-no-mutation` | by construction + DST kill at every await |
| no_session_state (pooled backend) | `sdg-txn-pooling-session-leak` | protocol-level reject + canary test |
| bounded_resources_per_request | `l5-structural-controls-implied` I1 | budget invariant (Verus/Kani candidate, q1-005) + fuzz oracle |
| parser_canonicality / no_desync | `http1-desync-2025` | parse/serialize/parse identity property + differential fuzz; EverParse for binary |
| store_never_reused_after_trap | `crash-isolation-semantics` | type/API boundary + test |
| pq_no_downgrade | `adv-rustls-2026-wave` | downgrade-injection test |
| ack_implies_durable | `sdg-jepsen-nats` | crash harness + DST |

Proof pipeline rule **R-FORMAL-1** [B/E] (`practice-agent-proof-pipeline`, `rec60-spec-fidelity-verus`, `fail-libcrux-spec-bugs-2026`):
- Pin verifier and solver.
- No assume/admit/external_body outside a reviewed TRUSTED ledger, which has a LOC budget.
- No admitted, lax or skipped modules.
- Specs live under CODEOWNERS.
- Separate agents write the spec and the proof.
- Executable specs are tested against RFC vectors and differential corpora.
- Specs are mutation-tested.

**R-FORMAL-2** [B] Prover choice per component:
- SMT-backed Rust (Verus) for small kernels: budgets, the token checker, journal.
- Lean for model-level semantics: Cedar-style model plus DRT, Aeneas where extraction fits. This satisfies §0c's Lean requirement.
- Kani bounded harnesses for unsafe and async glue.
- TLA+/P plus DST for liveness. Agents close about 37% of liveness obligations, so do not plan to prove liveness in Verus.
- Ignore miniF2F/PutnamBench as evidence.
- Nodes: `llm-verusage-2025`, `llm-lean-provers-transfer`, `proof-anvil-osdi24`, `estimate-proof-cost-per-component`, `rec60-rust-prover-llm-proofs`.
- Open: toolchain footprint (q1-004).

## 6. Performance model (round 1: thin)

- Measured locally:
  - Pooled Wasm instance: 6.9 µs p50.
  - fork+exit+wait: 124 µs p50 from a small parent, 33 ms from a 1 GiB parent.
- From Nanvix (same hardware):
  - Process cold start: 3.3 ms.
  - Hyperlight: 7.7 ms.
  - Firecracker snapshot: 69 ms.
- QUIC is 45% slower than H2 at 1 Gbps [B].
- io_uring drop-in gains are 0–10% [C].
- Not measured: $5-VPS and 64-core targets, ML-KEM handshake cost, binary size, idle RSS.
- TechEmpower is archived (2026-03-24), so we need our own harness [A]. Open: q1-002, q1-011, q1-016.

## 7. Decision record (contested choices, both sides)

- **Wasm vs native handlers.** Native for first-party code: it gives equal crash containment at 7 µs and avoids ~5 Wasm criticals per year. Wasm for untrusted code: it is the cheapest real boundary, about 1000× cheaper than Hyperlight. Decision R-ISO-1. Evidence on both sides: `wasm-vs-native-verdict`, `rust-type-system-not-adversarial-boundary`.
- **io_uring vs epoll.** epoll (R-TLS-5).
- **Cedar vs Biscuit vs both.** Cedar as PDP plus our own minimal token (R-AUTHZ-1/2). The biscuit side (attenuation, third-party blocks) is recorded in `biscuit-auth-6.0`.
- **QUIC now vs later.** Later or at the edge (R-TLS-2).
- **MCP version.** 2026-07-28 with a 2025-11-25 shim (R-AGENT-1).

## 8. Supply chain and process gates (feeds templates/)

- **R-SUP-1** [A/C] All builds use `--locked`.
  - `cargo vet --locked` with an exemptions ratchet, plus a hard fail on any new unaudited crate in the lock diff.
  - cargo-deny `0.20.2` and cargo-audit `0.22.2` run on every PR and daily.
  - Agents cannot edit `supply-chain/`, `deny.toml`, `ci/` or `.github/` (CODEOWNERS).
  - Nodes: `sc.vet-import-sets`, `sc.vet-ci-gate` (C), `sc.deny-audit-gate`.
- **R-SUP-2** [A] Unsafe budget: `unsafe_code=forbid` in first-party crates except one sys-boundary crate, plus a per-crate geiger ceiling allowlist. Node: `sc.unsafe-budget`.
- **R-SUP-3** [B] Cooldown uses cargo min-publish-age (Rust ≥1.100) plus Dependabot cooldown (7 days default, 3 for patches, security bypass). build.rs runs with no network.
  - Nodes: `v.cargo-min-publish-age-rfc3923`, `sc.cooldown-policy` (C), `sc.arrayref-incident`.
  - Diff r1: native mechanism replaces "none".
- **R-SUP-4** [A/B] Reproducible double build: remap-path-prefix for source, registry and rustup; a digest-pinned container; SOURCE_DATE_EPOCH.
  - Release goes out through SLSA L3 attestation, with a TUF root of 3-of-5 and targets of 2-of-3 (tough `>=0.24.0`, plus a duplicate-signature negative test).
  - Workflows are linted with zizmor and use 40-character SHA-pinned actions.
  - Nodes: `sc.repro-build-experiment`, `sc.slsa-attest`, `sc.sigstore-tuf-threshold`, `sc.gha-hardening`.
  - Toolchain pin: re-confirm the 1.99.x/1.100 release, since the local rustc is 1.88.
- **R-ASSURE-1** [C/B/A] Deterministic simulation and testing:
  - DST runs on a sans-IO protocol, WAL and authz core, with turmoil `0.7.2` and an injected Rng and Clock. TLS stays outside the simulation because aws-lc calls `getrandom` directly.
  - Oracle mutation: every invariant must be shown to fail on a seeded bug within 1000 seeds.
  - cargo-mutants runs as a diff gate plus a ratchet. The reference missed-rate on httparse is 25–34%.
  - Fuzzing: a 10 s smoke run per target on PR, CIFuzz for 150 s, and nightly runs.
  - HTTP Garden runs as a differential gate in an external container (it is GPL).
  - Nodes: `as.dst-harness-spec`, `as.dst-entropy-leak`, `as.oracle-mutation`, `as.mutants-gate`, `as.fuzz-gate`, `as.http-diff-fuzz`, `ci.stage-list`.

## 9. Hard gates

- Offensive tooling is limited to test harnesses against our own server. HTTP Terminator, Garden, the red-team stage and CVE-Bench-style canaries run in staging only, with no egress.
- Licences: HTTP Garden is GPL-3.0, so run it as an external container only. AFL++ is AGPL, so avoid it. Sozu is AGPL, so do not use it as a base.
- Export control: the crypto is standard (TLS, ML-KEM, ML-DSA). An export-control note is still to be written (COMPLIANCE_MAP).

---

## R. Rule diff log

- **Round 1 (2026-10-24):** created R-GAP-1..3, R-THR-1..3, R-TLS-1..6, R-PQC-1..5, R-ISO-1..3, R-AUTHZ-1..4, R-STATE-1..4, R-DB-1..2, R-AGENT-1..3, R-OPS-1, R-FORMAL-1..2, R-SUP-1..4 and R-ASSURE-1 (41 rules).
- Changes forced by verifiers within round 1: R-SUP-3, R-PQC-2, R-TLS-4 and R-THR-2 (see `reports/round-001.md` §4).
- Load-bearing rules with E/C support that round 2 must test: R-ISO-1, R-AUTHZ-1/2, R-STATE-4, R-DB-1 (q1-012), R-AGENT-2, R-GAP-1.
- **Anchoring audit:** not performed at this stage by design (§0a). The integrator did not read the prior treatments. Each rule above cites only independent map nodes.
