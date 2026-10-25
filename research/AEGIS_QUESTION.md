# FRONTIER CARTOGRAPHER — AEGIS track: the formally-assured, agent-hardened, post-quantum middle-tier web server

Directive v1, 2026-10-24. A recursive research directive. Section numbers mirror `/home/patrickd/frontier-research/meta/META_RESEARCH_PROMPT.md`. Where
this file is silent, that file's rules apply verbatim (§3 calibration, §8 dedup, §8a directional uniqueness, §11
epistemics). The build-side rules of `/home/patrickd/frontier-research/meta/PROTOCOL.md` §2 apply to the implementation plan this track produces: spec
freeze, verify wall before code, formal ladder, journaling. The operator's words are in §15. Seed hypotheses are in
`state/seed_conversation.md`. Prior treatments to deduplicate against are in `state/prior_treatments/`.

"Aegis" is a working name only. It is not a prior.

---

## 0. Purpose and deliverable

The question: **what is the Pareto-optimal architecture, repository and implementation plan for the middle-tier
web/application/gateway server of the agentic era?** It sits in the slot nginx + PHP-FPM / Node / FastAPI / Go / Envoy
occupy today, between human browsers, REST/API agents, MCP agents and browser-driving agents upstream, and existing
databases (Postgres, SQLite, Redis) and CDNs downstream and at the edge.

The goal is to be secure **by construction and by process**, not by the operator eyeballing code. Every security claim
should trace to one of:
- a machine-checked proof
- a type/ABI/capability boundary
- a deterministic test oracle
- a reproducible-build and provenance chain

Each one comes with an explicit statement of what is trusted (TCB) and what is NOT proven.

Optimize jointly, and report each separately (never collapse them into one score):
- security against adversarial AI agents and AI-automated vulnerability discovery
- post-quantum confidentiality and authenticity
- correctness
- durability and crash isolation (the "PHP miracle")
- throughput, latency and scalability
- lightweight, household viability (a $5 VPS through to bare metal, a single binary)
- developer and coding-agent ergonomics
- enterprise and government adoptability (FIPS 140-3, CNSA 2.0, FedRAMP/NIST 800-53, EU CRA, memory-safety roadmaps)

Build and keep current:
1. **The AEGIS MAP.** A deduplicated, graded graph from abstract to specific. It covers threats, prior-art servers and
   runtimes, protocols, crates and libraries (with versions, CVE history and maintenance status), verification tools (and
   what they can and cannot prove), proofs that exist, benchmarks, standards and their dates, and the unserved gaps.
2. **`research/ARCHITECTURE.md`.** The reference architecture and formal design: components, the trust boundaries diagram,
   the threat → mitigation → assurance mapping, the TCB ledger, and the decision record with alternatives and reversal
   conditions.
3. **`research/templates/`.** It holds:
   - REPO_LAYOUT.md: workspace and crate tree, dependency policy, toolchain pins
   - IMPLEMENTATION_PLAN.md: phased, each phase with machine-checkable acceptance gates and go/no-go
   - THREAT_MODEL.md
   - VERIFICATION_PLAN.md: per-component assurance rung, proof obligations, spec-fidelity checks
   - SPEC_INVARIANTS.md: precise statements of the safety and liveness properties, ready to become Verus/TLA+/Lean/P
     specs
   - SUPPLY_CHAIN.md
   - COMPLIANCE_MAP.md
   - BENCH_PLAN.md: workloads, baselines, honest comparison protocol

## 0a. OPERATOR STEER (2026-10-24; overrides any conflicting instruction here or in a stage prompt)

> "in your deep research i want to emphasize don't opinionate on the research that is extant, overfit or get bias on what it says use your sota opus/sonnet research where possible to make the optimal server"

What this means for every agent:
- **Derive the architecture from first principles and primary evidence.** PDF1, PDF2 and the seed conversation are a list
  of hypotheses to test plus a dedup ledger. They are not a starting design.
  - Do not frame findings as "improving PDF1" or "confirming the conversation".
  - Never prefer a component because a prior treatment named it. Wasmtime, Biscuit, io_uring, QUIC, Verus, redb,
    Cap'n Proto, x402, the "Iron Gate" and the crate layout are each one candidate among several.
  - A finding that a prior choice is wrong, unnecessary or second-best is as valuable as a confirmation.
- **Open every decision.** For each component, the planner and explorers must search the alternative space independently
  first, including options the priors never mentioned, and only then check whether a prior treatment's pick survives.
- **Anchoring check.** Synthesizers and critics must name each architecture decision where the final pick equals a
  prior-treatment pick, and give the independent evidence for it. If the only support is the prior text, the decision is
  E and gets reopened.
- **Blind research, informed synthesis** (operator, 2026-10-24: "you can still synthesize at the end with prior research just
  make sure your research work and insights are independent"):
  - Planner, explorers, verifiers, integrator, meta and judge do NOT read `state/prior_treatments/` or
    `state/seed_conversation.md`. The one exception is a single round-1 calibration explorer whose brief says it checks the
    flagged identifiers. That explorer reports only exists/doesn't-exist verdicts, never designs.
  - Only the Synthesize/Critique/Final stages read the prior treatments. They do it to reconcile: what we confirmed, what
    we refuted, what they missed, what we adopt from them with independent evidence. The ANCHORING AUDIT is part of this.
- Use Opus where judgment is deep (formal methods, threat modeling, architecture tradeoffs, synthesis) and Sonnet for
  breadth.

## 0b. OPERATOR STEER: ambidextrous, modular, lean (2026-10-24, added mid-run; applies from round 2 and to synthesis)

> "one of the files i gave shows an architecture with an aegis-db-gate. and postgresql rls and sqlite embedded. but we are trying to build a server backend that ambidextrously handles modularly all database types, frontend ingress and all addressable concerns for being the future infrastructure of the web. make sure we don't simply overfit on those two and we have thhe lean optimal best stack."

What this requires:
- **Data plane is backend-agnostic.** Postgres + RLS and embedded SQLite are two adapters among many, not the design.
  - Research the general mediation model first: typed operation allowlists, capability-scoped data access, a policy
    enforcement point in the server for backends with no native row security, and native enforcement (RLS, grants, IAM
    conditions) where it exists.
  - Cover each family with its own injection/authz failure modes, drivers (Rust maturity, async, TLS/PQC support), wire
    protocols and pooling:
    - relational: Postgres, MySQL/MariaDB, SQLite/libSQL/Turso, distributed SQL such as CockroachDB/Yugabyte/TiDB,
      SQL Server
    - document: MongoDB
    - KV/cache: Redis/Valkey, FoundationDB, DynamoDB
    - wide-column: Cassandra/Scylla
    - graph
    - vector: pgvector, Qdrant
    - search: OpenSearch, Meilisearch, Tantivy
    - time series
    - object storage: S3-compatible
    - streams/queues: Kafka/Redpanda, NATS
    - upstream HTTP/gRPC services
  - Find the smallest uniform abstraction that does NOT lose per-backend safety. Candidates include a query-capability IR,
    per-adapter allowlists generated at build time, and a WIT/trait data interface.
  - Cover how adapters are added without growing the TCB: out-of-process adapters, sandboxed adapters, feature-gated
    compile-time modules.
- **Ingress is protocol-agnostic.** In scope:
  - HTTP/1.1/2/3, WebSockets/WebTransport, SSE
  - gRPC/Connect, GraphQL (and its DoS/complexity risks)
  - MCP, A2A, webhooks (signature verification)
  - static assets, reverse-proxy/load-balancer mode, TCP/UDP stream proxying
  - browser-driving agents
  The design question is one protocol-normalization core with pluggable front ends, versus per-protocol stacks.
- **Lean is a hard constraint, not a nice-to-have.** The minimal core must be small, auditable and provable. Everything
  else is an optional module with an explicit TCB, size and attack-surface cost. Measure:
  - binary size
  - dependency count
  - unsafe LOC
  - idle RSS
  Compare against nginx, Caddy, Pingora, Envoy and HAProxy. Prefer designs where an unused module adds zero code to the
  running server.
- **Modularity mechanism is a research question:**
  - compile-time features
  - Wasm components
  - out-of-process plugins over a capability IPC
  - dynamic loading (likely rejected; say why)
  Weigh it against assurance (each extension point is a trust boundary needing a spec).
- The planner gives rounds 2+ at least one target on the data-plane abstraction across backend families and one on
  protocol-agnostic ingress + modularity/leanness. Synthesis must present the data plane and ingress as modular layers,
  with Postgres/SQLite as examples only.

## 0c. OPERATOR STEER: golden reference, build-time proofs, no local prover models, stop rule (2026-10-24, mid-run)

> "yes the server should be as versatile to any frontend standup or dataabse as needed. lean proving should be necessary, but llm open weights to run lean proofs shouldn't run on the vps and shouldn't be required. we can precompute security for a reference server format "our golden", but we aren't responsible for the formal security of downstream forks or db integrations of others. on this laptop, i cannot really spare the space per se for formal lean open weight llms nor the vram. when we reach a point of demonstrable saturation on  the dedup different directions discipline, then we can pivot from research to implementation so its not endless recursion and token spend on diminishiong returns."

What this requires:
- **Versatility.** The server must work with any frontend stack and any database (§0b).
- **Machine-checked proofs are required, with Lean in the assurance story.** Lean 4 is the operator's named prover and a
  required part of the story. Lean-only is not required: Verus, Kani or F* may carry specific components where the
  evidence says they fit better. Choose per component on evidence, and say why.
- **Proofs are build-time artifacts, never runtime work.**
  - Proofs are authored at development time (cloud coding agents plus humans) and checked by a small trusted kernel or
    solver in CI/release.
  - The production VPS/server does zero proving and ships zero prover dependencies.
- **No open-weight prover LLMs, anywhere in the required path.**
  - Not on the VPS, and not on the operator's laptop: it has little spare disk and VRAM.
  - LLM proof synthesis (DeepSeek-Prover, Kimina, Goedel and similar) may appear only as an optional accelerator. The plan
    must work without it.
  - Report the disk and RAM footprint of each required verification toolchain: Lean 4 + Mathlib (avoid Mathlib if the
    proofs don't need it), Verus + Z3, Kani/CBMC, and so on. Prefer the smallest toolchain that discharges the
    obligations.
- **Responsibility boundary: "our golden".**
  - We precompute and publish the assurance case for ONE reference build, "the golden": a pinned configuration, module
    set and adapters.
  - We are NOT responsible for the formal security of downstream forks or third-party DB/frontend integrations.
  - We ARE responsible for:
    - a precise extension contract (interfaces + specs)
    - a conformance test suite third parties can run
    - core invariants that, by architecture, a misbehaving sandboxed/out-of-process module cannot break
  - Say which invariants survive arbitrary third-party modules and which assume the golden's modules.
- **Stop rule: research ends at demonstrable saturation, then implementation starts.**
  - Saturation means two consecutive rounds that each have:
    - novelty < 0.2 under the §8a directional-uniqueness discipline (new axis cells exhausted, not just repeated
      phrasing)
    - load-bearing architecture decisions stable (≥ 0.75 unchanged)
    - no open area that could flip a load-bearing decision
  - Otherwise, the current run's round cap ends the research.
  - The final synthesis's OPEN GAPS must say which gaps can be closed during implementation (spikes, benchmarks,
    prototypes) instead of by more research. The default is to pivot to building.
  - Another research round is justified only if an unresolved gap would change a load-bearing decision, and then at most
    one targeted round.

## 1. The questions (score each separately)

- **W-THREAT.** What actually breaks middle-tier servers, and what changes when attackers are LLM agents?
  - Classic failures, from CVE and incident data for nginx, Envoy, HAProxy, Node/undici, hyper/h2, Go net/http, PHP-FPM,
    Caddy, Pingora: request smuggling and desync, parser differentials, HTTP/2 Rapid Reset and its successors, CONTINUATION
    floods, QUIC-specific attacks, slowloris, ReDoS, decompression bombs, SSRF, deserialization, path traversal.
  - Agent-specific failures: indirect prompt injection reaching tools, confused deputy, MCP tool poisoning, rug-pull and
    shadowing, token passthrough, DNS rebinding on local MCP, session hijack.
  - AI-automated vulnerability discovery: DARPA AIxCC results, Google Big Sleep, XBOW, OSS-Fuzz-gen, and the 2025–26 agent
    exploit benchmarks such as CVE-Bench and BountyBench. Weigh what they imply for time-to-exploit.
  - Also cover HNDL / quantum timelines, supply-chain attacks (xz, slopsquatting, crate typosquats) and insider/operator
    threats.
  - Rank each by likelihood × impact, with evidence.
- **W-GAP (prior art and the unserved space).** Map honestly what already exists and what is genuinely missing:
  - Proxies and servers: Pingora, River, Envoy, NGINX (and the status of NGINX Unit), Caddy, Traefik, HAProxy
  - Wasm hosts: Spin/Fermyon, wasmCloud, WasmEdge, Wasmer Edge, workerd/Cloudflare Workers, Fastly Compute
  - Microvms and unikernels: Hyperlight, Firecracker, Unikraft
  - Runtimes and platforms: Lunatic, Deno/Bun, Encore, Convex, PostgREST/Supabase/Hasura
  - MCP gateways and agent firewalls
  - Formally verified servers and stacks: Ironclad/IronFleet, Everest/EverParse, Project Everest's verified TLS, Vale,
    miTLS, seL4-based web stacks
  - For each: what it gets right, CVE record, adoption, license, and why it does or doesn't fill this slot. What would
    users actually switch for?
- **W-TRANSPORT.** The safest high-performance network front:
  - HTTP/1.1, HTTP/2 and HTTP/3 stacks in Rust/Zig/C (hyper, h2, quinn, s2n-quic, quiche, tquic, msquic, picoquic,
    lsquic), with their fuzzing and CVE record
  - io_uring: real wins vs its security history; Google and others disabled it
  - epoll thread-per-core, kTLS, GSO/GRO, XDP/eBPF pre-filtering
  - Verified or generated parsers: EverParse/3D, Narcissus, nom vs hand-written, parse-don't-validate
  - Smuggling-proof normalization, and HTTP/2 and HTTP/3 flow-control DoS defenses
- **W-PQC.** The exact PQC posture for 2026–2035:
  - ML-KEM hybrid deployment status (browsers, rustls/aws-lc-rs/BoringSSL/OpenSSL 3.5+)
  - ML-DSA in WebPKI vs reality: certificate size, Chrome's stance, Merkle Tree Certificates status, KEMTLS/AuthKEM
  - SLH-DSA for code signing; hash-based LMS/XMSS for firmware and releases
  - Verified implementations (libcrux/hax, HACL*, aws-lc formal verification via SAW/s2n-bignum), side channels
    (KyberSlash, timing)
  - CNSA 2.0 dates, NIST IR 8547 deprecation timeline, FIPS 140-3 module availability in Rust
  - PQC for capability tokens and session tickets; crypto agility design
- **W-ISOLATION.** The per-request / per-tenant isolation substrate that delivers PHP's crash immunity and density without
  its insecurity:
  - Wasmtime: pooling allocator, MPK, fuel vs epoch, its CVE and security-advisory history, Spectre mitigations, Cranelift
    verification work
  - Alternatives: V8 isolates, Hyperlight micro-VMs, Firecracker, gVisor, process-per-request fork servers (prefork +
    seccomp), CHERI/Morello, Landlock/seccomp self-sandboxing, unikernels
  - Measured instantiation latency, memory per instance, and density
  - Is Wasm the right boundary, or is a native-Rust handler with capability-typed APIs plus OS sandboxing better for
    first-party code? Decide by threat model (first-party vs third-party/agent-written code).
- **W-STATE.** Durability and connection fluidity:
  - idempotency keys (IETF draft), durable execution/journaled replay (Temporal, Restate, DBOS, Golem, Cloudflare Durable
    Objects / Workflows)
  - CoW per-request write buffering vs DB transactions
  - session resumption, QUIC migration, MCP session semantics
  - embedded WAL choices (redb, LMDB/heed, fjall, sled status, SQLite WAL) with crash-consistency evidence
  - exactly-once side effects: what is achievable and what is not
- **W-AUTHZ.** The authorization model that makes confused deputy and prompt-injection privilege escalation structurally
  impossible:
  - object capabilities, Biscuit, Macaroons, UCAN, ZCAP-LD
  - Cedar (formally verified in Lean/Dafny, with differential testing)
  - OPA/Rego, Zanzibar/SpiceDB/OpenFGA
  - OAuth 2.1 + the MCP authorization spec (RFC 9728 protected-resource metadata, DPoP, RFC 8707 resource indicators,
    token-exchange), GNAP
  - HTTP Message Signatures (RFC 9421) / Web Bot Auth for agent identity
  - IFC/taint systems (FIDES, CaMeL, other dual-LLM patterns)
  - Which policy language has formal semantics plus a verified evaluator plus analyzable policies (SMT)?
- **W-DATA-GATE.** Mediating DB access without rewriting the DB:
  - prepared-statement allowlists and compile-time query extraction (sqlx, pg_query.rs, sqlc)
  - RLS pitfalls (SET LOCAL with poolers, leakproof functions, policy bypasses, CVEs)
  - poolers (PgBouncer, PgDog, Supavisor, pgcat), pgwire libraries
  - SQLite in-process vs Postgres
  - DB-side least privilege (roles, column grants)
  - proofs or analyses of query authorization (e.g. verified SQL semantics, Cosette/QED-style equivalence)
  - Quantify residual risk.
- **W-AGENT-PROTOCOL.** What agents actually speak in late 2026, as primary sources:
  - MCP spec revisions and dates: verify the real latest revision; transports, auth and security best-practices pages
  - A2A, AP2, ACP (agentic commerce), x402 (real volumes, spec, facilitators)
  - llms.txt, robots/content-signals, pay-per-crawl, Web Bot Auth, OpenAPI/Arazzo
  - Browser-driving agents and how servers distinguish or serve them
  - How one handler definition can project to HTML, JSON, OpenAPI and MCP tool schemas safely
- **W-ABUSE.** Admission control and economic defense under agent swarms:
  - token buckets/GCRA, adaptive concurrency limits (Netflix concurrency-limits, gradient), CoDel and load shedding
  - cost-weighted budgets (fuel, DB cost)
  - Privacy Pass (RFC 9576–9578) and rate-limited tokens, PoW gates (Anubis, measured effect), x402/micropayments
  - Residential-proxy botnets; fairness for humans
- **W-FORMAL.** What can actually be proven for a server like this in 2026, at what cost, and by whom (humans vs LLM
  agents)?
  - Verus, with its verified-systems record: Anvil, Atmosphere, VeriSMo, Asterinas-related work, the AWS/Microsoft uses
  - Kani (AWS Rust std verification challenge), Creusot, Aeneas/Charon→Lean, Prusti, hax→F*/Coq
  - F*/Low*/EverParse, Dafny, TLA+/Apalache, P language (AWS S3), Lean 4
  - LLM-driven proof synthesis: AutoVerus, AlphaVerus, SAFE, Verus-bench results, DeepSeek-Prover/Kimina/Goedel for Lean,
    Dafny agents
  - Spec fidelity and TCB, plus known verifier soundness bugs. Name the trusted pieces.
- **W-ASSURE (process).** Deterministic, process-based assurance beyond proofs:
  - deterministic simulation testing (FoundationDB, TigerBeetle VOPR, Antithesis, madsim, turmoil, S2, Polar Signals)
  - Jepsen-style checking
  - coverage-guided and structure-aware fuzzing (cargo-fuzz, LibAFL, OSS-Fuzz), differential fuzzing against nginx/hyper
  - mutation testing (cargo-mutants), property tests, model-based testing with trace validation, Miri, sanitizers
  - continuous AI red-teaming as a CI stage (agent attack harnesses)
- **W-SUPPLY.** Provenance and supply chain:
  - dependency minimization, cargo-vet/crev/audit/deny, cargo-auditable SBOM
  - reproducible builds (Rust reproducibility status; Nix, Bazel, StageX), SLSA L3+, Sigstore/in-toto, TUF for updates
  - bootstrapping trust in rustc (mrustc, diverse double-compiling)
  - threshold release signing, unsafe-code budgets
  - LLM-introduced dependency risk
- **W-PERF.** Honest performance and scale:
  - TechEmpower and real proxy benchmarks: Pingora's production numbers, Envoy vs nginx
  - io_uring vs epoll measured, thread-per-core vs work-stealing
  - Wasm call overhead (component model canonical ABI cost), serialization costs (JSON vs Cap'n Proto vs FlatBuffers vs
    WIT), TLS handshake cost with ML-KEM
  - zero-downtime reload (SO_REUSEPORT, fd handoff), horizontal scale-out and multi-node state
  - Concrete targets for a $5 VPS and for 64-core bare metal
- **W-OPS.** Household viability and enterprise operability:
  - single-binary install, ACME automation, config language and validation, secrets and key rotation
  - observability (OpenTelemetry, structured audit logs, tamper-evident logs: Trillian/Tessera, transparency logs)
  - upgrades and rollbacks, systemd hardening
  - multi-tenant hosting mode; Kubernetes friendliness
  - compliance: FIPS mode, FedRAMP, NIST SSDF, EU CRA (dates and obligations), CISA memory-safety guidance
- **W-DX.** The developer and coding-agent surface:
  - which handler language and SDK shape lets LLM agents write code that the toolchain can check (Rust typestate, WIT
    components, Gleam/OCaml/Haskell?)
  - evidence on LLM correctness with strict types and verifiers
  - PHP-like deploy (drop a signed artifact), local dev loop
  - migration path from existing nginx/Node/PHP apps (a reverse-proxy mode first?)
- **W-UNKNOWN.** Unknown unknowns: releases, papers, CVEs and standards from the last 60 days that change any of the above.

## 2. Operator context (facts; not priors)
- Solo technical founder working with AI coding agents (Claude Code, local fleet). The implementation will be written
  mostly by coding agents under strict verifiers, so the plan must be **agent-executable**: precise specs, frozen
  interfaces, oracles first.
- The operator's own past projects are **never** priors or head starts (standing rule).
- Out of scope to reinvent: the database engine, the CDN, the physical network. In scope: everything a server binary and
  its build/deploy process control, plus its interfaces to those boundaries.

## 3. Calibration
As in META §3, two-sided.
- **Overclaim risks specific to this domain:**
  - "provably secure" claims that prove a model, not the code; specs that miss the attack
  - vendor benchmark tables
  - microbenchmarks presented as system throughput
  - "zero-cost" serialization or isolation
  - Wasm "absolute isolation" despite runtime CVEs and Spectre
  - PQC claims ignoring size, MTU and certificate-ecosystem realities
  - LLM-invented specs, RFC numbers, crate versions and papers. The prior PDF1 contains several suspects; check every
    identifier resolves.
- **Underclaim risks:**
  - dismissing verified components that exist in production (HACL* in Firefox and Linux, EverParse in Windows/Hyper-V,
    Cedar at AWS, s2n-bignum, libcrux in OpenSSH/Signal, seL4 deployments)
  - assuming proofs are too costly when LLM proof-synthesis results say otherwise
  - treating "nobody shipped it" as "impossible"
- Quantify. Grades A–E as META §3.

## 4. Layers
- **L0** pillar (W-*)
- **L1** sub-area (e.g. W-TRANSPORT → HTTP/2 DoS)
- **L2** approach (e.g. stream-concurrency budgets with reset-rate accounting)
- **L3** specific crate, tool, paper, spec, CVE or system
- **L4** versions, parameters, measured numbers, CVE ids, proof coverage, license, maintenance status, failure modes
- **L5** an actionable artifact for the repo: an exact crate pin + config, an invariant statement, a WIT/interface sketch,
  a test or fuzz harness spec, a CI gate, an acceptance criterion

Edge types are as in META §4, plus:
- `mitigates(threat)`
- `proves(property, tool, tcb)`
- `trusts(component)`
- `alternative_to`
- `depends_on`
- `cve(id)`
- `standardized_by(spec, date)`
- `conflicts_with`
- `fills_gap`

## 5. Seed domain map (widen every round)
One domain per W-pillar above (letters A–Q in pillar order), plus:
- R. Historical lessons: AOLserver, Erlang/Yaws/Cowboy, OCaml/Ocsigen, Ur/Web (a type-safe web language with security
  guarantees), the E language/Waterken, Joe-E, CGI→FastCGI, mod_php.
- S. Formal web foundations: verified HTTP/TLS stacks, verified web frameworks (Ur/Web, Jif/SIF, Swift/Hails, LWeb, Fable,
  Storm), IFC web systems, capability web (CapTP/OCapN, Spritely Goblins).

## 6. Traversal
As in META §6:
- UCB frontier selection
- ≥25% explore
- ≥50% descend to L3–L5
- ≥1 unknown-unknowns
- ≥1 calibration target from round 2 on. Round 1 should already include one calibration target that verifies the
  suspicious identifiers in PDF1 and the seed conversation.
- §8a directional uniqueness via `state/raw/round-NNN/_queries.log` and `state/queries.jsonl`

Recency rule: this field moves monthly. Every round sweeps the last 30–60 days for:
- MCP and IETF drafts
- wasmtime, rustls and quinn releases and advisories
- RustSec advisories
- PQC deployment news
- verification papers (CAV/OSDI/SOSP/CCS/PLDI 2026)

## 7. Schema
As in META §7. Additional node fields:
- Crate/tool nodes: `repo`, `version`, `last_release`, `license`, `unsafe_loc` or `unsafe` share if known, `cve_count`,
  `fuzzed` (bool / OSS-Fuzz), `maintainers`, `verified_parts`.
- Threat nodes: `cwe`, `example_cves`, `likelihood`, `impact`, `agent_amplified (bool)`.
- Proof nodes: `property`, `tool`, `tcb`, `effort` (person-months or LOC ratio), `llm_synthesizable` (evidence).
- Standard nodes: `id`, `status`, `date`, `mandatory_for` (e.g. CNSA 2.0 by year).

## 8. Dedup and directional uniqueness
As in META §8 and §8a. Reconciliation against `state/prior_treatments/` happens only at synthesis (§0a): a synthesized
item that only restates PDF1/PDF2 must be verified or refuted from the independent map, never re-reported.

Direction axes for this track:
- pillar
- layer
- vocabulary (systems / PL-formal methods / offensive security / network ops-SRE / cryptography / standards-policy /
  web-dev practitioner / economics)
- source type (paper / spec-RFC / repo+issue+advisory / CVE+incident writeup / benchmark log / forum / vendor doc / talk)
- stance (proponent / skeptic / negative result / attacker)
- era (historical / 2025 / last 60 days)
- deployment scale (household VPS / enterprise / hyperscaler / government)

## 9. What ARCHITECTURE.md must contain
1. **Positioning and the unserved gap.** What exists, what is missing, who switches and why.
2. **Threat model.** Adversary classes (incl. AI-agent attackers and AI-automated exploit discovery), assets, trust
   boundaries diagram, ranked threats.
3. **Reference architecture.** Each component with the chosen implementation (crate + version pin), alternatives,
   reversal condition, and evidence grade. Covers: transport/TLS/PQC, parser/normalizer, admission/abuse control,
   authn/authz, isolation, state/WAL/idempotency, DB gate, agent-protocol projection, observability/audit, config/ops.
4. **Assurance case.** Threat → mitigation → assurance mechanism (proof / type boundary / DST / fuzz / test) → residual
   risk. Plus a **TCB ledger** (every trusted component, its size and why it is trusted) and an explicit **"NOT proven"
   list**.
5. **Formal properties.** The core invariants stated precisely: no ambient authority, attenuation monotonicity, failed
   request ⇒ no state mutation, bounded resources per request, parser canonicality / no desync, tenant isolation, and so
   on. Each is mapped to a tool and a rung.
6. **Performance model.** Expected throughput and latency per deployment size, graded; the benchmark protocol.
7. **Decision record.** Each contested choice (Wasm vs native handlers; io_uring vs epoll; Biscuit vs Cedar vs both;
   QUIC now vs later; MCP version) with evidence on both sides.
8. **Repository and implementation plan** (in templates). Phases ordered by risk retired per engineering hour, every gate
   machine-checkable, written so coding agents can execute it under the META PROTOCOL §2 build rules.
9. **Hard gates.** No offensive tooling beyond test harnesses for our own server. Respect licenses. Export-control note
   for crypto if relevant.

## 10. Round report
As in META §10.

## 11. Epistemics
As in META §11.
- Date every spec revision, crate version, CVE and benchmark.
- Every crate, RFC, paper and spec identifier must be fetched and confirmed to exist before it is graded above E.
- LLM-generated reports (including PDF1/PDF2) are E until verified.

## 12. Self-application
Findings that would improve this research system go to `state/self_improvement.md`.

## 13. Never
- Never prune.
- Never write outside `~/aegis/research/`.
- Never run attack traffic against third-party systems.
- Never treat the prior PDFs or the seed conversation as evidence.

## 14. Files
As in META §14, under `~/aegis/research/`. The deliverable is `research/ARCHITECTURE.md` + `research/templates/`. The running draft is
`research/ARCHITECTURE-DRAFT.md`.

## 15. The operator's words (verbatim, 2026-10-24)

> based on our conversation up to now, do formal deep research on the optimal circumspect concern scalable secure formally correct web server backend of the agentic era to derive the stack/architecture of the repo and implementation plan

> . use the optimal deep research dynamic workflow methodology we established on this computer in another claude conversation. the goal of this deep research is to uncover the actual architecture and set out on the code implementation. two deep research treatments exist already: home/patrickd/downloads/Agentic Web Server Architecture Plan.pdf and executive summary.pdf in the same dir. you can use them to deduplicate in different unexplored directions and/or do your own treatment as well so that we explore exploit ucb1 bandits style the internet to make the fastest, scalable, secure, ai agent hardened, lightweight server of the future that is bulletproof and circumspectly accounts for all considerations as the best agentic era native solution pareto for the internet with utility, ergonomics, military grade security to optimize security, infrastructural bulletproof durability, and protection against adversarial agents, post quantum decryption and all other possible networking concerns for websites and internet infrastructural in its addressable scope, with suitable usability for enterprises, governments, etc in an era of ai agent adversarial cyberwarfare. the implementation plan should be formally correct and deterministic and provably secure by design not by me eyeballing and trying to vouch for the procedural or code security. it should approach stability and absolute security by virtue of process, circumspect provenance and auditing and fulfill all the gaps that the research says are unserved for scalability, lightweight, agent hardening and all of the other possible concerns formally correct and secure by design and formal language/computability determinism.

> (from the same conversation, operator scope statement) i mean mostly in the sense of software, servers, vps, networking; i think that is more the addressable scope for such a thing than to talk about physical cables. but the most amount of formal security for a software server is desirable ... pairing a secure migrated database (which is honestly out of scope probably for us to be disrupting postgres or sqlite or similar) so that we have a backend server we produce that minimizes the attack surface for hostile agents ... the logic of separating this server as an nginx or node or rest type environment separate from rethinking the relational, nosql, or distributed database or cloud cdn frontend is the best way to think about it right? ... now we don't have to make that tradeoff with ai agent based coding
