# AEGIS: LATEST cumulative view (through round 3, 2026-10-25)

Sources:
- State:
  - `state/graph.jsonl`: 756 node ids, of which 728 are canonical (non-merged); 47 revision records.
  - `state/edges.jsonl`: 1,116 edges.
  - `state/seen.jsonl`: 1,660 canonical URLs.
  - `state/frontier_queue.jsonl`: 432 items.
  - `state/predictions.jsonl`: 34.
- Rules: `ARCHITECTURE-DRAFT.md` (86 rules).
- Round history: `reports/round-001.md`, `round-002.md`, `round-003.md`.
- Blind-research status (§0a): independent map only, not yet reconciled with prior treatments.

**Saturation status: NOT saturated.**
- Mechanical novelty: round 2 = 0.898, round 3 = **0.881**. The threshold is < 0.2 in two consecutive rounds.
- Round-3 unseen mass ≈ 0.96 (strict singletons 0.29).
- Decisions are stable: 68 of 71 round-2 rules kept direction (0.958). Three narrowed on measured evidence: R-PQC-1 per-listener HRR, R-MOD-1 hop budget, R-PQC-3 pure CNSA profile.
- The open load-bearing questions are now almost all **implementation-phase spikes** (§6), not literature gaps:
  - a real 1-vCPU handshake and IPC hop
  - the FIPS lock triangle
  - checking Lowering.lean
  - mutants against real axum
  - reconnect cost under discard-on-cancel
  - the upgrade harness
- Per §0c, the default is to pivot to building after the round cap. Another research round is justified only for an area that could flip a load-bearing decision.

## 1. Map: pillar × layer node counts (canonical nodes, cumulative)

| pillar | L1 | L2 | L3 | L4 | L5 | total | new in r3 |
|---|---|---|---|---|---|---|---|
| W-DATA-GATE | 0 | 2 | 15 | 38 | 11 | 66 | 24 |
| W-AUTHZ | 0 | 2 | 26 | 26 | 11 | 65 | 18 |
| W-TRANSPORT (incl. ingress front ends) | 0 | 0 | 3 | 53 | 6 | 62 | 22 |
| W-AGENT-PROTOCOL | 1 | 1 | 27 | 18 | 5 | 52 | 2 |
| W-FORMAL | 0 | 1 | 10 | 31 | 7 | 49 | 4 |
| W-STATE | 0 | 3 | 28 | 8 | 10 | 49 | 7 |
| W-ABUSE | 1 | 3 | 12 | 19 | 8 | 43 | 21 |
| W-ISOLATION | 0 | 3 | 10 | 21 | 8 | 42 | 2 |
| W-OPS | 1 | 1 | 14 | 18 | 8 | 42 | 25 |
| W-SUPPLY | 0 | 0 | 2 | 26 | 13 | 41 | 23 |
| W-PQC | 0 | 1 | 2 | 32 | 3 | 38 | 16 |
| W-GAP | 0 | 5 | 25 | 1 | 0 | 31 | 1 |
| W-PERF | 0 | 0 | 3 | 13 | 11 | 27 | 15 |
| W-THREAT | 1 | 9 | 6 | 6 | 1 | 23 | 2 |
| W-BRIDGE (cross-request state, cancellation) | 0 | 3 | 15 | 1 | 4 | 23 | 3 (+20 cancellation nodes filed under their home pillar) |
| W-ASSURE | 0 | 0 | 3 | 8 | 11 | 22 | 3 |
| W-DX | 0 | 2 | 5 | 9 | 2 | **18** | 15 (was 3) |
| R-HISTORY | 0 | 0 | 17 | 0 | 0 | 17 | 0 |
| K-CALIBRATION | 0 | 0 | 0 | 9 | 0 | 9 | 0 (+11 revisions) |
| S-FORMAL-WEB | 0 | 1 | 4 | 2 | 0 | 7 | 0 |
| W-UNKNOWN | 1 | 0 | 0 | 1 | 0 | 2 | 2 (most adjacent-field nodes filed under home pillars) |

Grades (canonical nodes, latest record): A 279 · B 304 · C 97 · D 25 · E 23.

Verification:
- Round 1: 173 of 333 checked (17 up, 28 down).
- Round 2: 168 of 211 (15 up, 45 down).
- Round 3: 161 of 211 (4 up, 52 down; mostly source misattribution or modelled-as-measured, not refutation).

Thin areas after round 3:
- Pillars: W-ISOLATION and W-AGENT-PROTOCOL (2 new each), W-FORMAL (only unchecked Lean drafts).
- Axes: economics vocabulary, household scale, non-English sources, forums and talks.

## 2. Best-known choice per pillar (grade; alternatives; key nodes)

| pillar | best-known choice now | grade | alternatives kept in map | key nodes |
|---|---|---|---|---|
| W-THREAT | Two rankings, metric stated. By KEV: canonicalization/fail-open authz > smuggling > memory RCE. By Rust-stack advisory volume (alias-deduped): resource exhaustion 61% (CI 47-73), falling to 50% in 2026, with TLS logic rising to 25%. New class: async cancellation with an attacker-chosen instant. Cross-stack classes recurring in 6 weeks: trailers, H3→H1, validator/handler divergence, unbounded sizes. AI-found bugs are rediscovered independently, so patch SLA ≤7 days | B (classes A) | skeptic: AI-found CVEs exploited at base rate | `threat-ledger-middle-tier-2023-2026`, `ac.root-cause-drop-at-await`, `r3e11.cross-stack-bug-classes-sep-oct-2026`, `r3e11.ai-found-bug-flood-vendor-posture` |
| W-GAP | Integration + assurance + measured leanness. Closest 2026 prior art: nucleus (agent IFC runtime, Lean+Kani, not a front proxy) and agentgateway (PQ via aws-lc-rs, CEL). No system holds the conjunction | C (absence) / A (lean numbers) | Pingora, Envoy, Caddy, HAProxy, Spin, agentgateway, nucleus, Rullst | `gap.unserved-combination`, `w02.size-deps-table` |
| W-TRANSPORT | One normalization core whose object is an **Exchange** (message stream, per-message and per-lifetime budgets), non-destructive normalization, canonical route identity for authz. Front ends feature-gated, with defect-class rules: typed Origin; leave framed mode only after a validated 101; no permessage-deflate; GraphQL behind the core; webhooks verified over raw bytes; SSE caps; CI fails any effective unbounded limit. L4/PROXY is a separate module. WebTransport is out of v1. hyper =1.12.0 / h2 =0.4.20 + wrapper (TBI-1..9). H3 off in the golden | A (pins, classes) / B (TBI) / C (core structure, numbers) | per-protocol stacks; tonic (set limits explicitly; `None` default), async-graphql (limits `None`), quinn ≥0.11.19, s2n-quic | `r3e09.ring1-verdict-amendment`, `r3e09.ws-upgrade-smuggling`, `r3e09.grpc-defect-classes`, `l5-transport-budget-invariant-tbi`, `w02.norm-copy-cost-measured` |
| W-PQC | rustls ≥0.23.46 with `prefer-post-quantum` asserted on every rustls in the lock. **pq-required kx_groups on agent/API listeners; client order on the public listener** until `PreferServerOrder` ships. HRR verdicts frozen in CI. Public certs ECDSA-P256 via ACME (ARI, profiles); ML-DSA-44 on private hops now; MTC through a CredentialSelector. PQ tokens go in the body or by reference. FIPS: separate lock with aws-lc-fips-sys =0.13.11 (AWS-LC FIPS 3.1.0, CMVP #5298/#5314; ML-KEM approved, ML-DSA not) + aws-lc-rs 1.15.2-1.17.2. CNSA: pure ML-KEM-1024 + ML-DSA-87 (not FIPS-approvable today) | A (KA verdicts, sizes) / B (FIPS pin, auth posture) / C (CNSA compliance) | OpenSSL 3.5/Go modules; composite ML-DSA for long-lived signatures; AuthKEM rejected; dual chains (blocked by CA/B) | `r3pq.hrr-acceptance-test`, `r3pq.prefer-pq-feature-pitfall`, `r3pq.pq-auth-posture-decision`, `ops.fips-module-boundary-pin`, `v3.aws-lc-rs-fips-sys-range`, `r3pq.header-limit-table` |
| W-ISOLATION | Provenance table (unchanged direction). Wasm is never the sole boundary for third-party code: M0 escape rate 0.36-2.0/yr. Wasmtime ≥36.0.19 (36 line) or ≥49.0.4/50.0.0; component-model-async off; Store discarded after any dropped call; **no wasmtime-wasi-http for egress** (narrow host fetch). OS sandbox around every Wasm worker | E design / A inputs / B pin / C rate | V8 isolates, Hyperlight, Firecracker, gVisor | `isolation-decision-inputs-table`, `wasmtime-advisory-share-by-config`, `ac.i07-wasmtime-cancel-advisories`, `r3e11.wasi-http-host-side-framing-batch` |
| W-STATE | **INV-NOMUT-C (NC1-NC8)**: cancellation is failure; commit-point latch (timeouts after commit return 202); discard-on-cancel checkin predicate; pre-debit accounting that charges cancels; cancelled authz denies; output gate; drain bound. Cancel sweep + clippy CR1-CR9 + driver pins. Idempotency with the principal in the key; store-of-record gated by the crash harness (SQLite WAL+FULL default); CRS C1-C8 + C5b (buffers empty at key change) + C8 recycled-object reset | A (pins, instances) / B (INV-NOMUT-C, CRS) / C (store choice) | one-txn+outbox alone (closes ~5 of 15 instances); state-tracked reuse (if reconnect is expensive) | `ac.l5-inv-nomut-c`, `ac.l5-cancel-sweep-harness`, `ac.l5-coding-rule-lint-gate`, `crs-l5-invariant-text`, `cc.ranking-negative` |
| W-AUTHZ | Cedar 4.14 + symcc PDP (SymCC path trusts the Lean compiler via native_decide; no delegation RFC; TPE has no native lowering). Token: **Tier 0 opaque handle (default), Tier L HMAC chain in verified CBOR, Tier X COSE ML-DSA-65 at crossings**; external tokens exchanged at ingress. Attenuation = conjunction of every caveat (never leaf-only + subsumption); `now` as a parameter; no wall-clock authz limits | B (decision) / A (Tenuo counterexample, drafts) / C (Lean statements) | Biscuit (158 µs, no PQ, 1 ms wall clock), UCAN, ZCAP, AAT/DT drafts, JWT (avoid) | `r3e05.l5-token-decision`, `r3e05.tenuo-cel-attenuation-bypass`, `r3e05.token-verify-microbench`, `l5-authz-stack-recommendation`, `vfg-policy-tristate-failclosed-invariant` |
| W-DATA-GATE | **Backend-agnostic** typed op-capability IR (And([])=TRUE, Or([])=FALSE) lowered per adapter. **Adapter refinement contract**: Lean Refines claim + live schema gate + executed oracle with leak_cases = 0 at ENGINE_PIN, re-run on engine bumps. Unsound-lowering denylist: binary collations, no LIKE/GLOB for Prefix, Redis `t:{hex(tenant)}:`, Mongo `$eq` + not-array; builders that drop empty sub-expressions banned. INV-NONEMPTY, allowlist lock, native per-tenant credentials, no shared connections. PG: SET LOCAL ROLE + statement cache allowed; `is_local` GUCs only; minor floor + recycle after upgrade and role DDL | A (executed SQLite/PG/Redis) / B (Mongo/MySQL/MSSQL) / E (Lean theorem) / C (IR design) | policy-to-SQL compilers (OPA compile: unsound for SQL Server, literals inline); Cedar TPE; RLS-only | `irl-l5-differential-oracle-harness`, `irl-l5-unsound-lowering-denylist`, `irl-l5-lean-lowering-theorems`, `irl-l5-q1012-role-plan-cache-gate`, `dpf-l5-op-capability-ir` |
| W-AGENT-PROTOCOL | Unchanged from round 2: MCP 2026-07-28 + mandatory 2025-11-25 path; listener-gate type; sealed handles; strict shared JSON parse; resolved egress; 33-case corpus. Round 3 adds the SSE budget class and MCP-adjacent individual drafts, none on the standards track | A/B/C | A2A, AP2, EMVCo agentic payments (draft) | `l5.origin-audience-session-rules`, `l5.conformance-manifest`, `r3e11.ietf-window-agent-individual-drafts` |
| W-ABUSE | Pipeline S0 → **S0.5 handshake reservation** → S1 (10/s burst 50) → classify → cost classes with **fresh vs established session classes** → **aggregate expensive-tier budgets independent of identity count** (300/400 units/s) → step-up 16-bit PoW for anonymous expensive requests → Gradient2 (4/8/32) + CoDel (20/250 ms). No CPU-keyed challenge; PoW ≤18 bits. I1-I11; acceptance C1-C12 (tuned passes all but C5 NAT flash crowd; C11 untested). First make expensive endpoints cheap. Behaviour scores only weight budgets | D (numbers) / B (mechanisms) / C (PoW asymmetry measured) | Anubis WASM Argon2id (unmeasured), Privacy Pass, ASN keying | `r3e07-L5-tuned-default-table`, `r3e07-L5-swarm-acceptance-criteria`, `r3e07-r2-defaults-collapse`, `r3e07-pow-asymmetry-measured`, `r3e07-L5-cost-model-sheet` |
| W-FORMAL | Lean 4.35 core (no Mathlib) + TLC on the laptop; Verus/Kani/EverParse CI-only; gate = `lake check --paranoid` + axiom allowlist + native_decide ban + Kani ≥#4910. New Lean drafts (lowering, token T1-T6) are **unchecked** (SPK-LEAN-IR-1) | A (footprint) / B-C (tool map) / E (new drafts) | Creusot, Prusti, F*, Dafny, Velvet/Veil (CAV'26, Lean-native) | `vfg-toolchain-pin-footprint-table`, `vfg-proof-ci-gate-spec`, `irl-l5-lean-lowering-theorems`, `r3e11.velvet-veil-lean-verifiers` |
| W-ASSURE | Executed oracles first. DST with a deterministic CryptoProvider; cancel sweep; lowering oracle; ingress conformance harness (CVE→test traceability); upgrade harness; mutants gate; conformance suite C0-C4 | A/B | Antithesis, LazyFS | `ac.l5-cancel-sweep-harness`, `irl-l5-differential-oracle-harness`, `r3e09.L5-ingress-conformance-harness`, `zd.l5-upgrade-harness-gate` |
| W-SUPPLY | Executed on the 233-crate golden lock: audit 0 vulnerabilities; deny skip list of 6 duplicates; vet with zero exemptions = 116/165 linux crates unaudited (3.66M lines). **7-day cooldown + audited security bypass** (a 14-day window lands the rustls PQ downgrade); no `=` pins under cooldown; security floors. Repro gate with 3 remap flags (toolchain + auditable mode = build identity). Tarball-git parity; trustpub ancestry; release = provenance + independent rebuild; non-dismissable workflow lint; new-crate intake gate | A (executed) / B (policies) / C (incident matrix) | Nix/StageX, TUF (0/12 at intake), SLSA verify alone (2/12) | `sc3.golden-lock-gate-run`, `sc3.cooldown-executed-cargo-198`, `sc3.repro-ablation-golden`, `sc3.l5-ci-gate-list`, `sc3.l5-new-crate-intake` |
| W-PERF | Core numbers unchanged (4.21 MB, idle 3.4-5.9 MB). PQ handshake +12.5-15% (rustls, logged bands). IPC hop 4.8 µs UDS / 2.1 µs ring vs 0.02-0.05 µs in process; zero-copy normalization 30 µs per 10 MB. IPC wire rules (postcard, serde_bytes, fds for bodies, no spin on ≤2 CPUs). ML-DSA-44 flight 11.7 KB. Bands from interleaved trials only | A (laptop) / B (bands) / C (OOP thresholds) | iceoryx2 / shm rings (vendor 240 ns, needs a spare core) | `w02.ipc-hop-cost-1core`, `w02.norm-copy-cost-measured`, `w02.handshake-pq-cost`, `r3pq.mldsa-handshake-measured` |
| W-OPS | systemd ≤2 gate; CRA (Art 14 live, OJ-confirmed); 800-53/KSI map (46 KSIs; AU-9(3) fixed); tlog audit; instant-acme + ARI. **In-place upgrade UP-1..7**: fd inheritance + FDSTORE, claim-or-close fds, two-phase GOAWAY, drain deadline, STEK by pipe, authenticated handover; QUIC resets accepted in v1. Scale-out state behind traits. Rename before public release (RFC 10032 collision) | A (systemd, CRA, mechanisms) / B / C (protocol) | nginx USR2, HAProxy fd transfer, Envoy hot restart, tableflip/shellflip, tcp_migrate_req | `zd.l5-upgrade-protocol`, `zd.l4-orphan-socket-blackhole`, `zd.l3-scaleout-state-matrix`, `ops.cra-obligation-split` |
| W-DX | **Capability-typed handler SDK in a separate crate** (router-built Ctx with a non-optional Principal; tenant-scoped handles; effect classes; Tx typestate; HTML/URL/Secret newtypes); agents denied edits to the SDK; compile-fail mutant corpus as a CI gate. Rust is not an agent handicap (one shared benchmark pool). Deploy artifact = OCI + cosign, digest-pinned | C (decision) / B (toy experiment, benchmarks) | plain axum + lints; WIT component handlers; Encore-style codegen; policy-core/typesec-agent/capsec (to evaluate) | `dx.l5-decision-sdk-shape`, `dx.exp-handler-sdk-mutants`, `dx.exp-error-signal`, `v3.typed-authz-ctx-prior-art`, `dx.deploy-prior-art` |

## 3. Threat → mitigation → assurance matrix (current)

| threat (rank) | mitigation | assurance mechanism | rung | residual |
|---|---|---|---|---|
| 1 H2/H3 resource exhaustion [A] | golden pins + wrapper; TBI-1..9; H3 off; explicit tonic limits | Kani H1-H5; Verus ledgers; Lean composition; fuzz resource oracle; DST stall | proof (structs) + test | TBI-4/7/8 rely on the wrapper; C_FIELD |
| 2 canonicalization / fail-open authz [A/B] | canonical route identity (grpc-go :path); Cedar; tri-state combiner; INV-NONEMPTY; binary collations for tenant ids | Cedar Lean model + DRT; Lean combine_failclosed; build lock; lowering oracle | proof (model) + DRT + test | Cedar Rust evaluator; Lean compiler on the SymCC path; cvc5 |
| 3 smuggling / differentials (H3→H1, Upgrade/101, trailers, JSON) [A] | strict H1; H2 upstream; validated-101 gate; one parse shared by policy and handler; trailers dropped at bridges | HTTP Garden; differential framing corpus (q3-013); Lean H1 model | model + differential | Rust H1 parser unproven |
| 4 memory corruption [A] | Rust; forbid(unsafe); C drivers out of process; geiger ceilings | Miri, sanitizers, unsafe gate | type + test | aws-lc C, tokio, rustc |
| 5 agent origin/session/audience [A/B] | listener-gate type; sealed handles; typed Origin for WS/SSE | 33-case corpus; CSWSH matrix | type + test | absent-Origin interop |
| 6 cross-request state scope [A] | CRS C1-C8 + C5b + recycled-object reset | two-scope oracles; Tomcat-style mix-up test | test | unenumerated classes |
| 7 TLS logic / PQ downgrade [B] | rustls ≥0.23.46; pq-required on agent/API listeners; prefer-post-quantum assertion | 5-verdict HRR test; lockfile feature audit; BoGo | test | public listener classical for X25519-first clients |
| 8 data-plane injection / authz per family [A] | typed IR; lock + denylists; refinement contract; native per-tenant creds | executed oracle leak=0; schema gate; Lean Refines (unchecked) | test + model | write path; timing channels; engine logic bugs |
| async cancellation (r3) [A] | INV-NOMUT-C; discard-on-cancel; commit latch; pinned driver fixes | cancel sweep (8 modes × 8 oracles); CR1-CR9 lints; TLA+/P | test + lint + model | executed paths only; unreleased upstream fixes |
| 9 decompression / complexity [B] | decode budgets; no permessage-deflate; GraphQL cost to the core budget | fuzz ratio oracle; 10k-alias/field tests | test | — |
| 10 supply chain [A] | locked + 7-day cooldown with bypass + vet + intake + repro + parity + provenance + rebuild + workflow lint | double build; attestation verify; zizmor; negative-control PRs | provenance | maintainer takeover with a long window (xz 34 d) |
| admission swarms [B] | S0.5 reservation; fresh class; aggregate expensive budgets; step-up PoW | swarm acceptance C1-C12 (10 × 10 seeds); I8 Kani; TLA+ I9/I10 | sim + test | uncalibrated sim; NAT flash crowd |
| reload / upgrade (r3) [A mechanisms] | fd inheritance; claim-or-close; GOAWAY; drain deadline | upgrade harness + negative control; fuzz handover | test + model | forced closes after D; H3 resets |
| sandbox escape [A/B] | OS sandbox around Wasm; pins; no wasi-http egress | config CI assertion; 72 h SLO | boundary | M0 0.36-2.0 escapes/yr |
| extension-boundary decoding [A] | host parses + re-serializes | conformance C2 | test | host decoder |
| durability loss [A] | ack ⇒ fsynced; bootstrap dir fsync | crash harness + DST | test | double fault, EIO |
| remote timing [A] | constant time at TCP-ts resolution; Range/Prefix timing on the NOT-proven list | dudect/ctgrind | test | lowering timing channel |
| config-plane failure [A] | validated generated config; last-known-good; canary; no unwrap | clippy deny; config fuzz | lint + test | — |

## 4. TCB ledger (current)

- **Toolchain and runtime:** rustc/LLVM/std; tokio (155k LOC; 2,527 used unsafe items).
- **HTTP stack:** hyper (16.7k LOC; 123 unsafe items), h2 (15.2k; 3), httparse (3k), plus the **AEGIS transport wrapper** (ours).
- **TLS and crypto:** rustls (45.7k LOC, unsafe-free); aws-lc-rs/aws-lc-sys (11.3k unsafe binding lines; 1.5M bundled C/asm LOC; 2.09M lines in the vet backlog). FIPS boundary: AWS-LC FIPS 3.1.0 under the FIPS lock (ML-KEM approved; X25519 and ML-DSA outside).
- **Data plane:** adapters in process (each driver's full LOC); DB drivers pinned at git revisions (sqlx, diesel_async, patched tokio-postgres). Per-adapter `Backend.Refines` facts + engine collation/affinity semantics: tested, not proven; engine logic bugs are in scope.
- **Ours:** the pool checkin predicate and drop guards; the token verifier + EverParse deterministic-CBOR (verified parser); the upgrade handover parser; the tlog writer.
- **Linux kernel:** seccomp, Landlock, cgroups, systemd sandboxing, fd passing; KVM if microVM.
- **Wasmtime/Cranelift:** P2/P3 only, inside an OS sandbox.
- **Host decoders of module output.**
- **Policy:** Cedar Rust evaluator (DRT); the Lean compiler for SymCC analyses only.
- **Build-time checkers, never shipped:** Lean kernel + nanoda/lean4lean, Verus + Z3, Kani/CBMC ≥#4910, TLC, cvc5. Specs are trusted.
- **Stores:** Postgres (adapter); embedded store (harness-gated).
- **CI/release:** runners, Sigstore, TUF keys; toolchain digest and auditable mode in the attested build identity.

**NOT proven:**
- Cedar Rust evaluator.
- Rust HTTP/1.1 framing.
- TBI-4/7/8 over hyper/h2.
- The async I/O shell and its liveness.
- Cancel safety beyond swept paths.
- Wasmtime runtime and glue; KVM.
- aws-lc C outside its verified parts.
- IR lowering soundness: the Lean model is unchecked (T4 sorry); refinement is tested; write path, projection and timing are out of scope.
- Native DB enforcement; normalizer ≡ backend parser.
- Microarchitectural tenant isolation.
- Admission I3/I4/I6/I9/I10 and the tuned numbers.
- Token T1-T6 and upgrade UP-1..7 (statements only).
- Store crash consistency beyond single crashes.
- Handler noninterference.
- DST fidelity.
- Spec fidelity.

## 5. Top bridges

1. **Fail-closed construction** (r2) now also covers the config plane: validate-then-swap on reload, and CI fails any effective unbounded limit (tonic `None`, async-graphql `None`).
2. **Scope tuple σ = tenant handle = clean pooled connection** (r2+r3). CRS C8, NC3's checkin predicate and the lowering theorem's role/GUC binding are one precondition: a cancelled BEGIN (sqlx#4393) breaks all three.
3. **Checker vs evaluator** (r3). Tenuo's leaf-only + subsumption design and the empty-OR family both widen authority silently. One canonical evaluator over the full conjunction fixes both, with Or([]) = FALSE.
4. **Canonical identity** (r3). grpc-go `:path` and SQL collation/LIKE tenant collisions are one class: each identity gets one canonicalization owner.
5. **Supply chain × PQC** (r3). A blanket cooldown lands the PQ downgrade; `default-features=false` makes rustls classical; the FIPS pin conflicts with the golden lock. The lockfile is a security artifact for PQ, not just provenance.
6. **One proof pattern** (r3): verified parser + core-Lean semantics theorem + DRT to Rust, for tokens and data-plane lowering, on one small toolchain.
7. **Executed oracles beat reading** (r3). They found bugs in code written to be safe, in drivers with unreleased fixes, and in a mainstream policy compiler.
8. **Budgets at two layers + one admission ledger** (r2+r3): TBI per connection, I1-I11 per identity, and NC4 pre-debit with charged cancellations.
9. **Drain = cancellation** (r3): one T_drain bound for the upgrade protocol and INV-NOMUT-C.
10. Carried over:
    - interposition is unsound for Rust
    - modularity = isolation = TCB accounting (now with a measured hop cost)
    - generated artifacts are untrusted input
    - determinism as a security property

## 6. Open frontier (top of `state/frontier_queue.jsonl`)

| id | score | question (abridged) | closes by |
|---|---|---|---|
| q3-001 | 0.80 | rustls full vs resumed handshake CPU on a real $5 vCPU | spike (R-ABUSE-1, R-PERF-1) |
| q1-013 | 0.80 | Crash blast radius: PHP-FPM vs pooled Wasm vs fork-server | spike |
| q1-009 | 0.80 | LLM-found vs human-found advisory rates | research (R-THR-2) |
| q2-009 | 0.75 | Window-0 stalled flow-control harness vs golden pins | spike (TBI-8) |
| q3-004 | 0.70 | Golden version triangle: rustls floor + prefer-post-quantum + FIPS pin | spike (R-PQC-2) |
| q3-002 | 0.70 | ipcbench on a real 1-vCPU KVM VPS | spike (R-MOD-1) |
| q3-003 | 0.70 | Pre-TLS resumed-handshake prioritisation by ClientHello PSK identity | research + spike (S0.5) |
| q2-013 | 0.70 | Kani/Verus RAM and time on TBI harnesses | spike (R-FORMAL-2) |
| q2-007 | 0.70 | Double-fault + fsync-EIO crash harness | spike (R-STATE-4) |
| q3-005 | 0.65 | Swarm simulator v2 (measured handshake, resumption, /64 churn, RST cancel storms) | spike |
| q3-006 | 0.60 | Write-path lowering soundness | research + Lean (R-DB-7) |
| q3-008 | 0.60 | Discard-on-cancel reconnect cost | spike (R-STATE-6 NC3) |
| q3-012 | 0.60 | Capability-SDK mutants against real axum async handlers | spike (R-DX-1) |
| q3-013 | 0.60 | Differential HTTP framing corpus from the Sept-Oct 2026 ids | spike |
| q3-020 | 0.50 | Check Lowering.lean; close lower_sound_full | spike |

**Decisions that could still flip** (load-bearing, support at E/C):
- R-ISO-1 (M0 escape rate)
- R-PQC-2 (FIPS lock triangle)
- R-ING-1 (C)
- R-DX-1 (C; async lifetimes)
- R-DB-2/7 (Lean unchecked; write path)
- R-ABUSE-1 (D; uncalibrated)
- R-STATE-4 (double faults)
- R-GAP-1 (short shelf life)

Every one of these closes during implementation (spikes, prototypes, harness runs) except R-GAP-1, which is a recheck at final synthesis. The research recommendation per §0c: **pivot to building at the round cap.**
