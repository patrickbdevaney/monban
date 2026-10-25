# AEGIS round 2 report (2026-10-25)

Integrator: sole writer of map state for round 2. Inputs: 12 explorers (raw JSON in `state/raw/round-002/`) and 12 two-sided verifier passes. Blind research rule (§0a) held: the integrator did not open `state/prior_treatments/` or `state/seed_conversation.md`.

Crash recovery note: the laptop crashed from memory exhaustion during the explorer stage (§0e). Explorers 05 (ops/compliance) and 11 (talks/non-English) left raw files holding only node ids or a note. The integrator transcribed their structured returns into `05-…structured.json` and `11-…structured.json` (originals untouched). Verifier verdicts again existed only in the orchestrator payload, so the integrator re-keyed 168 verdicts into `_verify_r2_verdicts.json` and 82 "missed" items plus 13 promoted nodes into `_verify_r2_missed.json`. The integration script is `state/raw/round-002/_integrate_r2.py`. It is deterministic and refuses to run twice.

## 1. Delta

| metric | value |
|---|---|
| new nodes appended to `state/graph.jsonl` | **204** (191 from explorers + 13 promoted from verifier "missed" lists) |
| by layer (new) | L1 1 · L2 6 · L3 48 · L4 103 · L5 46 |
| by grade (new, after verification) | A 75 · B 90 · C 32 · D 3 · E 4 |
| revision records of round-1 nodes | 24 (20 re-verified by the calibration explorer, 4 integrator corrections). Same id, `revision_round: 2`, never renamed |
| merges (same-as into an existing node) | 5 (`cranelift-default-config-escape-2026-10` → `rec60-wasmtime-cranelift-crit-2026-10`; `adv-rustls-pq-downgrade-2026-0349` → `rec60-rustls-0.23.46-downgrade`; `fin.rmcp-3.7.0` → `j-rmcp-sdk`; `vfg-cryptoprover-cloud-llm-optional` → `rec60-cryptoprover-symcrypt`; `v2.awslc-rs-fips-crate-map` → `crate-aws-lc-rs`) |
| edges appended to `state/edges.jsonl` | 366 (281 explorer edges + 5 same-as + 37 refines + 10 contradicts + 33 integrator bridge edges); 0 dangling |
| canonical URLs appended to `state/seen.jsonl` | 502 (450 new, 52 re-seen and marked `revisit`) |
| queries merged into `state/queries.jsonl` | 301 |
| frontier queue (rebuilt) | 288 items: 163 open, 20 partial, 21 done, 84 absorbed |
| predictions appended | 11 (total 24) |
| verification | 168 of 211 explorer records (80%) two-sided checked: 15 up, 45 down, 108 unchanged. Over-claim ratio 3:1 (round 1: 28 down / 17 up) |
| refuted or materially corrected claims (kept with grade and reason, never pruned) | `dpf-mysql-mariadb` → C (two CVE ids unresolved and suspect); `dpf-graph-neo4j` (CVE-2026-35402 is an MCP server, not Neo4j); `l4-cve-corpus-h2-h3-2023-2026` (Pingora ratio and Envoy CVE id not in the primary source); `crs-ce-jwks-unverified-kid` → C; `fin.spec-absent-origin` (spec gap, not a permit); `ops.cra-annex3-waf-risk` → C 0.45; `abuse-residential-proxy-scale` (Kimwolf 100-200M unsourced); `v.http2-bomb-cve-2026-49975` (CVE is Apache-only; revision record) |

### Mechanical novelty

`python3 -I tools/novelty_gate.py metrics --round 2`, copied verbatim:

```json
{
 "round": 2,
 "queries": 301,
 "urls": 460,
 "nodes": 211,
 "url_novelty": 0.8978260869565218,
 "query_novelty": 0.9767441860465116,
 "node_novelty": 0.95260663507109,
 "axis_cell_novelty": 0.9102990033222591,
 "intra_round_query_dup_rate": 0.009966777408637873,
 "mechanical_novelty": 0.8978260869565218
}
```

**`delta.novelty_ratio = 0.877`.** The script's node_novelty compares titles only against round-1 raw output. It therefore credited 16 nodes whose ids already exist in the graph (explorer 12's re-verifications with rewritten titles, plus 4 same-as merges). Applying the directive's zero-credit rule to those 16 gives node novelty 185/211 = 0.877. That makes it the least-novel dimension, below url 0.898. The script value 0.898 is reported alongside it. Either way the round is far from the §0c saturation threshold (< 0.2).

### Singletons and unseen mass

- 204 new nodes form 199 new clusters. All 199 are singletons: found by exactly one explorer and matching nothing existing.
- Cross-explorer overlap inside round 2 was nearly zero. The highest title+summary Jaccard between nodes from different explorers was 0.17, so targets were orthogonal as planned.
- Good–Turing unseen mass, round 2 alone: 199/204 = **0.975**.
- Treating any cross-explorer or cross-round link (refines, contradicts, bridge, extends to an existing node) as a partial match leaves **88 strict singletons** (0.43).
- Saturation is not indicated on any measure.

### Direction diversity (§8a)

- 115 distinct axis cells (pillar × source type × stance × era) over 301 queries = **0.382**. Round 1 was 0.262.
- With the vocabulary axis added, 181 cells (0.601).
- Normalized to the primary pillar, **222 of 301 queries (0.738) landed in cells unseen in round 1**. Raw cell novelty (108/115) is inflated because round-2 pillar labels differ from round 1's.
- Stance mix improved: proponent 56% (round 1: 78%), skeptic/negative 72, attacker 60.
- Redundant directions:
  - Explorers 01 and 12 both re-checked rustls default groups (J = 0.86).
  - A third independent pull of the wasmtime advisory list.
  - Re-pulls of the CERT VU lists.
- Full table in `state/directions.md`.

## 2. Top 10 findings (actionability × grade; L4/L5 first)

1. **Backend-agnostic data plane: a typed operation-capability IR, INV-NONEMPTY, and a build-time allowlist lock per adapter.** [B decision / C design; A inputs]
   - Of 17 non-Postgres families, 6 have native row/document read enforcement, 5 have prefix/namespace enforcement, and the rest need an in-server PEP. Every native mechanism documents bypasses (`dpf-family-matrix`).
   - Envoy marks every DB wire-protocol filter as requiring a trusted downstream, which supports "generate, don't parse" (`dpf-envoy-db-filters-untrusted`, A).
   - Empty or absent policy means allow-all in NATS, Kafka, FDB, Hasura and Turso; Apache Syncope CVE-2026-73579 voided authz across SQL, Neo4j and OpenSearch (`dpf-empty-means-all-pattern`, A).
   - 2026 agent/MCP DB tools had their text-level read-only validators bypassed for both SQL and Cypher (`dpf-agent-db-tool-bypass-cluster`, A).
   - → R-DB-2..6: one IR with a host-owned tenant handle (`dpf-l5-op-capability-ir`); per-family denylists traced to dated CVEs (`dpf-l5-allowlist-generation`); native per-tenant credentials where they exist; no cross-tenant connection sharing; C-binding drivers (libsql, foundationdb, rdkafka, questdb-rs) out of process (`dpf-l5-adapter-isolation`).
2. **Transport Budget Invariant TBI-1..9 and the exact hyper/h2 gaps.** [A mechanics / B spec]
   - Grep-verified in h2 0.4.20 / hyper 1.12.0: no header field-count cap, no stall or send timeout anywhere, and handlers spawned by hyper outlive h2's reset accounting (the MadeYouReset gap). Raw h2 defaults allow unlimited streams and a 16 MiB header list (`l4-h2-budget-mechanics-0.4.20`).
   - Only s2n-quic has Kani proofs, and none covers resource budgets (`l4-transport-harness-census-2026-10`).
   - CERT VU#885548 (stalled flow control, 2026-07-22, JVN) is the advisory instance of the missing stall deadline (`r2e11.h2-stalled-flowcontrol`, A).
   - → golden config pins plus an AEGIS wrapper (fields ≤128, handler permits with a 4× queue, RST bucket, 10 s stall deadline) and a Kani/Verus/Lean/fuzz/DST tool split per clause (`l5-transport-budget-invariant-tbi`, `l5-tbi-tool-assignment`, `l5-config-pin-table-transport`).
3. **Crash-consistency experiment: which embedded stores lose acknowledged writes, under which config.** [A]
   - About 130k crash images across 7 stores, with controls: the no-fsync control loses acks in ~99% of drop-all cuts, the CRC+fdatasync+dir-fsync control in 0/8020.
   - PASS: SQLite WAL+FULL, redb 2PC+Immediate, fjall SyncAll, canopydb `commit_with(true)`, LMDB defaults.
   - FAIL: redb Durability::None (6000/6160 lost), fjall default Buffer (6658/12030), canopydb default `commit()` (10600/12030), SQLite WAL+NORMAL (85% of images), LMDB NO_SYNC (corruption plus reader SIGSEGV).
   - The cause is acks before fsync and a missing parent-directory fsync, not torn writes.
   - Negative result: an LD_PRELOAD interposer is blind to rustix raw syscalls; the first fjall run was 100% false positives.
   - → bootstrap dir-fsync rule; per-store pins; interposer-independent harness (`cc.ranking-negative`, `cc.l5-config-pin`, `cc.neg-ldpreload-rustix`).
4. **Lean footprint, measured against incumbents.** [A]
   - hyper+rustls core: 4.21 MB stripped, 40 crates, idle RSS 3.4-5.9 MB, 1k idle TLS connections 17.2 MB.
   - Incumbents: nginx 1.33 MB + 6.7 MB libs (8.05 MB), 12.7 MB idle; Pingora 7.24 MB / 174 crates, 6.9 MB idle; Caddy 52 MB / 45 MB idle; Envoy 107 MB / 63 MB idle.
   - X25519MLKEM768 costs rustls +17.5% server CPU per handshake, against +29-39% for the OpenSSL-based servers and Caddy. Extra wire bytes are about 1.1/1.2 KB.
   - Optional modules: Wasmtime with Cranelift adds 8.94 MB and 57 crates; runtime-only adds 393 KB; features that are off add zero.
   - A fresh Pingora 0.9.0 build with tokio ≥1.54 panics on the first connection (#1059; the fix PR #1060 is unmerged and main has the same code).
   - → lean budget table, feature-gate rule, lockfile plus post-bump smoke (`w02.L5-lean-budget`, `w02.L5-feature-gate-rule`, `w02.pingora-tokio-panic` A, up).
5. **Verification toolchain: Lean core plus TLC fits in ~1.1 GB; the gate must defend against false PASSes.** [A]
   - Sizes: Lean 4.35 core with no Mathlib is 676 MB to 1.0 GB, with 0.5 GB RSS. Verus is 3.16 GB and Kani about 2 GB, so both are CI-only. Mathlib is avoidable: Cedar needs only Batteries, but Aeneas needs Mathlib, so Aeneas is out of the required path.
   - Kani 0.68.0 reported VERIFICATION SUCCESSFUL when CBMC ran out of memory (#4905). The fix, PR #4910, is in no release yet.
   - Lean kernel soundness bugs in 2026 (#14807, found with AI models) were also accepted by nanoda.
   - `native_decide` and `bv_decide` add axioms that trust the Lean compiler.
   - → `lake check --paranoid`, an axiom allowlist, a native_decide ban, Kani pinned at or after #4910 with exit-code hardening and OOM treated as FAIL (`vfg-toolchain-pin-footprint-table`, `vfg-proof-ci-gate-spec`, `vfg-kani-footprint-and-gate-failures` A, up).
6. **Isolation inputs, measured; Wasm alone is not a boundary for hostile code.** [A measurements / B classification]
   - Component canonical-ABI floor is about 85 ns; the ABI is 2-7% of call cost, and Wasm codegen (~2× native) is the real cost. A fresh pooled component instance with WASI costs 20 µs p50 and 52 KB.
   - Fork from a zygote costs 124 µs at 8 MB and 1.5 ms at 256 MB. Installing Landlock and seccomp in the child adds about 135 µs, so install them once per worker. Cacheable seccomp costs 18-30 ns per syscall.
   - On the minimal M0 config, 6 of 65 2024-26 advisories are guest-triggerable, including 1 default-config escape (GHSA-897f, CVSS 9.9; versions 37-42 are unpatched).
   - Shrinking guards for density re-opens GHSA-6wgr and GHSA-394w.
   - → an OS sandbox always around the Wasm worker; exact pin; never density-tune (`canonical-abi-cost-measured`, `zygote-sandbox-recipe-measured`, `wasmtime-advisory-share-by-config`, `skeptic-small-reservation-pooling-recipe`).
7. **Cross-request state scope (CRS C1-C8) replaces round 1's bridge invariant.** [A counterexamples / B spec]
   - TLS 1.3 tickets are authenticated (STEK-sealed) but unscoped. Cross-vhost resumption bypassed mTLS in nginx (CVE-2025-23419), Apache (CVE-2025-23048), LiteSpeed and Caddy, and also enabled server-auth bypass in six provider clusters.
   - QUIC NEW_TOKEN shows that legitimate unauthenticated state exists.
   - curl's 2026 cluster of about 18-20 reuse/state CVEs comes from hand-enumerated pool keys. hyper-util's pool key is only `(Scheme, Authority)`.
   - → scope tuple σ, a keying table (pool key = derive(Hash, Eq) over the whole config), and per-clause oracles with oracle mutation (`crs-l5-invariant-text`, `crs-l5-keying-table`, `crs-ce-pool-reuse-incomplete-key` A, up).
8. **Agent-gateway CVEs mapped to invariants.** [A corpus / B invariants]
   - 58 dated MCP advisories from 2025-06 to 2026-10, in 8 classes. The same default-off DNS-rebinding bug was filed in 6 SDKs within five months, and fixes recur (TS, agentgateway, rmcp, Inspector, ToolHive).
   - Statelessness removes session confusion but not the Origin, parser, audience or SSRF classes, and it adds attacker-held `requestState`.
   - The 2026-07-28 spec leaves absent Origin unspecified.
   - → a listener-gate type, a 33-case advisory-derived conformance corpus, and a control-plane attachment invariant (`adv.corpus-r2-09`, `l5.invariant-list`, `l5.origin-audience-session-rules`, `l5.conformance-manifest`, `v2.agentgateway-referencegrant`).
9. **W-ABUSE: PoW gates are speed bumps; swarms defeat per-IP limits; admission is economics plus queueing.** [B bypass evidence / C incidents / E parameters]
   - Headless-Chrome scrapers computed Anubis PoW (#978). Anubis d4 is about 17-28 ms native, and cost per session is under a cent a month.
   - In 2025-26 incidents, what held was making expensive endpoints cheap, a global load-keyed shed, and identity budgets.
   - No RFC rate-limited Privacy Pass token exists, and ARC is undeployed.
   - → admission pipeline S0-S6 (numbers grade E), budget invariants I1-I7, and a swarm DST acceptance spec (`abuse-anubis-bypass-evidence` B, up; `abuse-L5-admission-pipeline-1vcpu`; `abuse-L5-budget-invariants`; `abuse-L5-swarm-sim-spec`).
10. **Ops, compliance and recency items that change rules.** [A/B]
    - systemd hardening measured from 9.4 to 1.4 with a runtime test (A).
    - FIPS means an exact validated crate pin, but which version is byte-identical to CMVP #5298/#5314 is unresolved. Gate on `FipsStatus::Certified`.
    - CRA: an open-source steward owes a documented policy; a monetized offering makes the distributor a manufacturer.
    - Audit log specified as C2SP tlog-tiles.
    - There is no NIAP protection profile for web servers.
    - Recency (A):
      - Opossum (USENIX Sec'26, CVE-2025-49812): never implement `Upgrade: TLS`.
      - Cloudflare's 2025-11-18 outage came from a Rust `unwrap()` on an oversized generated config: treat generated config as untrusted.
      - runwasi CVE-2026-47218: never deserialize untrusted precompiled Wasm.
      - TCP timestamps defeat network-noise timing arguments.

## 3. New bridges (cross-domain edges, `origin: integrator-bridge`)

- **Fail-closed construction.** One invariant family across five pillars:
  - data plane: empty policy means allow-all (`dpf-empty-means-all-pattern`)
  - authz: Error, timeout or crash means Deny (`vfg-policy-tristate-failclosed-invariant`)
  - agent layer: a KEV-listed auth error produced an empty principal (`r2e11.litellm-failopen`)
  - admission: I7, no fail-open stage (`abuse-L5-budget-invariants`)
  - gateway: invariant 6 (`l5.invariant-list`)
  - → one host combiner, plus a `Principal` type that cannot be default-constructed.
- **Scope tuple = tenant handle.** CRS σ (`crs-l5-keying-table`) and the data-plane `tenant-handle` resource (`dpf-l5-op-capability-ir`) are the same object. Valkey's response-stream injection (`dpf-redis-valkey`) is CRS C8, never share a connection across tenants. The RFC 7541 shared-compression hazard is demonstrated for QPACK on pooled backend H3 (`r2e11.h3-proxy-qpack-sidechannel`).
- **Interposition is unsound for Rust.** rustix raw syscalls escaped the crash harness's LD_PRELOAD shim (`cc.neg-ldpreload-rustix`). aws-lc's jitter and RDRAND entropy escapes DST interposition (`as.dst-entropy-leak`). The shared remedy is interposer-independent instruments: FUSE or dm-log-writes for disk, and a deterministic CryptoProvider for simulation.
- **Budgets at two layers.** Transport TBI (per connection) sits under admission I1-I7 (per identity and cost class): one ledger type, one proof approach (`l5-transport-budget-invariant-tbi` ↔ `abuse-L5-budget-invariants`).
- **Modularity = isolation = TCB accounting.** Measured feature costs (`w02.feature-cost-unused`), adapter isolation by driver type (`dpf-l5-adapter-isolation`), zygote cost (`zygote-sandbox-recipe-measured`) and the golden survival table (`vfg-invariant-survival-table`) answer one question together: what runs in process, what runs out of process, and what each costs in TCB. Only native per-tenant credentials survive a malicious adapter.
- **Generated artifacts are untrusted input.** Generated config (Cloudflare outage), precompiled Wasm (runwasi) and generated allowlist locks (`dpf-l5-allowlist-generation`) each need build-time validation and runtime fail-soft behaviour.
- **Parser differentials inside policy.** ToolHive's JSON dup/case/BOM bypasses and APISIX CVE-2026-94269 (path normalization) are the same class as HTTP smuggling, one layer up. One strict shared parse serves policy and handler.

## 4. Protocol changes (rule diffs, with evidence)

Full text is in `ARCHITECTURE-DRAFT.md`. Round 2 adds 30 rules and changes 27 round-1 rules. No rule is deleted and none reversed direction. The rule count goes from 41 to 71.

- `R-DB-2` open → **decided** [B/C]: typed operation-capability IR with per-adapter lowering; WIT only as the out-of-process encoding. Evidence: `dpf-uniform-abstraction-comparison`, `dpf-envoy-db-filters-untrusted` (A), `dpf-agent-db-tool-bypass-cluster` (A).
- `+R-DB-3/4/5/6`: INV-NONEMPTY [A/B]; build-time allowlist lock with family denylists [C]; native per-tenant credentials and no cross-tenant connection sharing [B]; adapter isolation by driver type [B].
- `+R-ING-1` [C]: one normalization core plus feature-gated front ends; translation seams buffer and budget before downgrade. `+R-TLS-8` [A]: one TLS mode per port, no `Upgrade: TLS`.
- `+R-MOD-1` [B]: Cargo features; no dlopen; compiler-bearing modules out of process or precompiled+MACed. `+R-PERF-1/2` [B]: lean budget and benchmark protocol.
- `R-TLS-1` amended: golden hyper pins plus the AEGIS wrapper. `+R-TLS-7` [B]: TBI-1..9 as a named invariant with tool assignment. `R-TLS-2` amended: H3 off in the golden; quinn `receive_window` 4 MiB.
- `R-PQC-1` amended: carve-outs and a mandatory HRR acceptance test. `R-PQC-2` **B → C**: the byte-identical FIPS pin is unresolved. `+R-PQC-6` [A/B]: scoped ticketers, STEK hygiene, 0-RTT off.
- `R-ISO-1` amended: measured inputs; an OS sandbox always wraps Wasm. `R-ISO-2` amended: exact pin (≥36.0.19 on the 36 line, or ≥43), explicit memory64/gc off, never density-tune, MDWX worker split. `+R-ISO-4` [A]: Landlock then seccomp, installed once per worker.
- `+R-AUTHZ-5` [A/B]: tri-state fail-closed combiner. `R-AUTHZ-1` amended: TCB wording (Lean compiler via native_decide; cvc5). `R-AUTHZ-2` amended: no JWT.
- `R-STATE-4` amended: measured pass/fail table and the bootstrap dir-fsync rule; pins move to A, store choice stays C. `+R-STATE-5` [B]: CRS C1-C8 supersedes the round-1 bridge invariant.
- `R-AGENT-1` amended: stateless is not sufficient; sealed requestState. `+R-AGENT-4/5/6` [B]: listener-gate type; advisory-derived conformance corpus; control-plane attachment invariant.
- `+R-ABUSE-1..4` [E numbers / B mechanisms]: admission pipeline; PoW as a speed bump; aggregate controls; budget invariants and swarm DST acceptance.
- `+R-OPS-2..6` [A/B]: systemd gate; CRA posture; COMPLIANCE_MAP; tlog-tiles audit log; ACME, config and secrets, generated-config fail-soft, no unwrap.
- `R-FORMAL-2` amended: concrete required toolchain (Lean core + TLC, ~1.1 GB); Aeneas out. `+R-FORMAL-3` [A]: proof-gate hardening. `+R-FORMAL-4` [B]: golden extension contract survival table.
- `R-ASSURE-1` amended: replace the CryptoProvider under DST. `+R-ASSURE-2` [B]: third-party conformance suite C0-C4.
- `R-THR-1` amended: ranking metric made explicit; new classes for cross-request state and data-plane injection. `R-THR-3` amended: the 2026 memory-bug surge in C servers. `+R-THR-4` [A]: remote timing via TCP timestamps.

**Decision stability (input to the saturation judge).** Of 40 decided round-1 rules, 40 kept their direction (1.00). 14 of 41 kept their text unchanged (0.34). The ≥0.75 stability criterion holds on direction but not on text: round 2 mostly added parameters, pins and carve-outs, and flipped nothing. Load-bearing decisions whose support is still E or C: R-ISO-1, R-AUTHZ-2, R-ING-1, R-DB-2/4 design, R-ABUSE-1/4 numbers, R-PQC-2, R-GAP-1.

## 5. Calibration notes (two-sided verification)

- Over-claim ratio 45 down : 15 up (3:1), against 1.6:1 in round 1. Most down-moves were weak sources: slide decks cited by media root URL, an SEO-style blog for the smuggling seam, and aggregator CVE ids. Others were stats the explorer could not tie to a primary source.
- **Suspect identifiers.** CVE-2026-107814 and CVE-2026-90997 (MySQL) did not resolve and look mis-transcribed, so `dpf-mysql-mariadb` drops to C 0.55. The structural claim (no native RLS) stands. Quota-driven CVE hunting ("2 dated CVEs per family") produced the round's only suspect identifiers, so that direction is retired.
- **Misattribution corrected.**
  - CVE-2026-35402 is in the mcp-neo4j-cypher MCP server (CVSS4 2.3), not in Neo4j or APOC.
  - CVE-2026-49975 is Apache mod_h2 only. Envoy's fix is GHSA-22m2, and the Pingora ratio is not in the primary post (revision record on `v.http2-bomb-cve-2026-49975`).
  - JLSEC-2026-1360 and RUSTSEC-2026-0096 are the aarch64 jhxm advisory, not GHSA-897f, 6wgr or 394w.
  - FedRAMP has 10 KSI groups, not 11.
  - C(2026)5252 could not be verified; the March 2026 CRA consultation draft is the verifiable text.
- **Moved up on defender evidence.**
  - Pingora panic: PR #1060 exists and main is still affected.
  - Kani false-PASS: PR #4910 merged after 0.68.0.
  - The MCP fix-twice pattern holds across 5 projects.
  - The curl reuse cluster is larger than claimed.
  - 0-RTT: curl CVE-2026-9545.
  - canopydb defaults were confirmed from source.
  - Opossum: CVE-2025-49812.
  - LiteLLM CVE-2026-59822 is in CISA KEV.
  - aws-lc entropy cannot be interposed.
  - Verus soundness rate: 81 issues in Oct 2026, possibly a bulk batch.
  - Spec fidelity: Verus-SpecGym.
  - Supabase grant-default dates.
  - Authz alternatives: SpiceDB is mostly fail-closed.
- **Calibration explorer (12)** re-verified 21 load-bearing numbers and moved 9 (4 down, 5 up).
  - The pooled KEV non-memory share (78.8-81.9%) hides a 2026 memory-bug surge in C servers.
  - Cedar has 3,776 declarations (not 3,912) plus 10 `native_decide`.
  - The "real test gap" cited for cargo-mutants was an equivalent mutant.
  - RFC 10024's "PQ solved" needs carve-outs.
  - Supavisor's fix is merged but only in an RC.
- **Measurement-quality caveats.**
  - The benchmark host was contended (loadavg ~41, up to 2.8× variance), so only class-level throughput claims stand.
  - heavy.sh refused two measurements on disk grounds: C_FIELD and Verus/Kani RAM. Both are recorded as implementation spikes.

## 6. Open frontier (top of `state/frontier_queue.jsonl`)

| id | score | question (abridged) | why |
|---|---|---|---|
| q2-001 | 0.90 | Out-of-process module/adapter IPC cost vs in-process (UDS + postcard / WIT ABI; redis GET, scylla SELECT, S3 presign, wasmtime helper) | Decides R-DB-6 and R-MOD-1 thresholds; three explorers asked independently. **Implementation spike** |
| q2-002 | 0.80 | Does the rustls server HRR to X25519MLKEM768 when the client lists it but sends only an X25519 share? | R-PQC-1 acceptance test. **Spike** (hours) |
| q1-012 | 0.80 | Postgres SET LOCAL ROLE + prepared statements + plan cache across role switches (CVE-2026-14666 reproducer) | R-DB-1 adapter identity mechanism |
| q1-013 / q1-014 | 0.80 | Crash blast radius PHP-FPM vs pooled Wasm vs fork-server; head-to-head coding-agent pass rate by handler language | W-DX has had no targeted query in two rounds |
| q1-009 | 0.80 | LLM-found vs human-found advisory rates | R-THR-2 time-to-exploit |
| q2-004 / q2-012 | 0.75 / 0.65 | rustls/quinn ticket binding to SNI/cert chain; PQ forward secrecy on resumption (psk_ke vs psk_dhe_ke) | R-PQC-6 wrapper vs fork |
| q2-009 | 0.75 | Window-0 stalled flow-control harness against the hyper/h2 golden pins (VU#885548) | TBI-8. **Spike** |
| q2-007 | 0.70 | Crash harness with double-fault and fsync-EIO stages (redb 1PC+C vs 2PC) | R-STATE-4 (redb's real bugs were double faults). **Spike** |
| q2-013 | 0.65 | Run TBI Kani H1-H5 and the Verus twin on a 4-vCPU/16 GB runner; peak RAM | R-FORMAL-2 reversal condition. **Spike** |
| q2-011 | 0.65 | Prove Pred lowering sound per adapter (Lean/Verus), or Cedar tpe residuals | Would make IR lowering a golden proof obligation |
| q2-014 | 0.60 | Which DB servers negotiate X25519MLKEM768 as TLS servers | Driver-side PQ inherited; server side unknown |

**Decisions that could still flip** (load-bearing, support E/C):
- R-ISO-1: depends on M0 escape recurrence.
- R-ING-1: depends on normalization copy cost (q2-016).
- R-DB-2/R-DB-6: depend on IR expressiveness and IPC cost (q2-001).
- R-PQC-2: FIPS pin identity.
- R-ABUSE-1: numbers await the swarm simulation.
- R-STATE-4: double-fault results.
- R-AUTHZ-2: token format.

Most of these close by **implementation-phase spikes** (benchmarks, harness runs, reproducers), not more literature research (§0c default).

## 7. Self-improvement (summary; full text appended to `state/self_improvement.md`)

- Verifier output on disk is still missing (round-1 proposal #7 not implemented): 168 verdicts were re-keyed by hand.
- Crash-truncated raw files: explorers must persist full node JSON incrementally.
- `novelty_gate.py metrics` crashes on any `*.json` in a round directory whose `nodes` field is not a list. The integrator hit this with its own metrics dump, renamed the file to `.txt`, and changed no script. The gate also gives novelty credit to reused ids.
- Pillar labels drift between rounds, which inflates raw cell novelty; era and scale are mostly unlogged. A closed axis vocabulary is needed.
- Queue dedup at Jaccard 0.45 missed paraphrased duplicates: the IPC-cost question appeared 3 times, the window-0 harness and the Verus/Kani spike twice each. Use containment scoring.
- Benchmarks ran on a contended host. Serialize benchmark runs, not only builds.
