# Monban round 1 report (2026-10-24)

Integrator: round-1 sole writer of map state. Inputs: 12 explorers (raw JSON in `state/raw/round-001/`) and 12 two-sided verifier passes. Blind research rule (§0a) held: the integrator did not open `state/prior_treatments/` or `state/seed_conversation.md`. Explorer 12 (calibration) reported exists/doesn't-exist verdicts only; those enter the map as K-CALIBRATION nodes, not as design input.

## 1. Delta

| metric | value |
|---|---|
| nodes written to `state/graph.jsonl` | 345 (333 from explorers + 12 promoted from verifier "missed" lists) |
| by layer | L1 2 · L2 25 · L3 150 · L4 139 · L5 29 |
| by grade (after verification) | A 130 · B 159 · C 37 · D 3 · E 16 |
| merges (same-as into a canonical node) | 18 nodes into 16 multi-explorer clusters |
| edges written to `state/edges.jsonl` | 363 (explorer edges + 17 same-as + 38 refines + 5 contradicts from the integrator); 0 dangling |
| canonical URLs in `state/seen.jsonl` | 736 |
| queries merged into `state/queries.jsonl` | 473 |
| frontier queue | 144 items (129 open, 6 partial, 9 absorbed into nodes) |
| predictions appended | 13 |
| nodes two-sided verified | 173 of 333 (52%): 17 up, 28 down, 288 unchanged (incl. not-sampled) |
| refuted or materially corrected headline claims | 4 (`sc.cooldown-policy`, `std-sp800-227`, `llm-dafny-agents`, `iso-glue-not-boundary-pattern`); all kept with grade and reason, none pruned |

**Mechanical novelty** (`python3 -I tools/novelty_gate.py metrics --round 1`, copied verbatim):

```json
{"round": 1, "queries": 473, "urls": 701, "nodes": 333,
 "url_novelty": 1.0, "query_novelty": 1.0, "node_novelty": 1.0, "axis_cell_novelty": 1.0,
 "intra_round_query_dup_rate": 0.004228329809725159, "mechanical_novelty": 1.0}
```

`delta.novelty_ratio = 1.0`. This is trivial, because round 1 has no earlier round to compare against. It says nothing about saturation.

**Singletons and unseen mass.** 327 canonical clusters. 311 are found by exactly one explorer (no same-as match), so the Good–Turing unseen-mass estimate is 311/327 = **0.95**. Counting partial matches (any cross-explorer refines/contradicts/same-as link) as non-singleton leaves 232 strict singletons, or 0.71. Either way the space is far from saturated. That is expected after one round of mostly orthogonal targets.

**Direction diversity** (§8a): 124 distinct axis cells (pillar × source type × stance × era) over 473 queries = **0.262**. Intra-round dup rate is 0.004. There are 7 cross-explorer near-dup queries (Jaccard ≥ 0.5), listed in `state/directions.md`. Skew: 78% of queries are proponent-stance, 77% are 2025–26 era, and only 3 are forum sources. Four pillars got zero targeted queries: W-ABUSE, W-OPS, W-PERF and W-DX. The §0b/§0c areas (data-plane families, protocol-agnostic ingress/leanness, verification-toolchain footprint) are untouched.

## 2. Top 10 findings (actionability × grade; L4/L5 first)

1. **Memory safety is necessary but not sufficient. Logic and resource classes dominate what is exploited.** [B, `result-memory-safety-would-not-prevent-fraction`] About 81% of KEV additions 2023–26 are non-memory (verifier recomputed 723/890). Every OSS middle-tier KEV entry is non-memory. Memory-safe servers have ≤1% memory-corruption advisories. Rust still shipped smuggling in Pingora, auth fail-open in Ferron, and 11 DoS HIGHs in quinn. → Rank mitigations by logic/resource class first. Memory safety removes the RCE tail (nginx 2026: about 19 of 26 advisories are memory, CVE-2026-42533 CVSS4 9.2).
2. **HTTP/2 and HTTP/3 protocol-state resource exhaustion is the top threat class, and it recurs every year regardless of language.** [A, `threat-h2-h3-resource-exhaustion`, `v.http2-bomb-cve-2026-49975`, `rec60-header-accordions-qpack`] The HTTP/2 Bomb (2026-06) hit nginx, httpd, IIS, Envoy and Pingora in default config. Header Accordions (2026-10-20) hit 7 of 10 H3 stacks. hyperium/h3 0.0.8 defaults `max_field_section_size` to `VarInt::MAX`. → Decoded-size and concurrency budgets on by default, plus a fuzz oracle that bounds output bytes / input bytes.
3. **A measured, provenance-keyed isolation table.** [A local bench + B literature; decision is E] Pooled Wasmtime instantiate+call+drop measured 6.9 µs p50 / 14.6 µs p99, about 7 KiB per instance, 4.4 µs teardown (`wasmtime-pooling-local-bench`). Hyperlight is about 7.7 ms and Firecracker is about 1 s cold or 69 ms from snapshot, on the same hardware (`nanvix-same-hw-coldstart-2026`). But Wasmtime shipped critical escapes in April and October 2026 (`rec60-wasmtime-cranelift-crit-2026-10`), and safe Rust is not an adversarial boundary (166 open I-unsound). → Native Rust for first-party code, Wasm in a sandboxed worker for agent or semi-trusted code, never Wasm alone across distrusting tenants (`isolation-decision-table-by-provenance`).
4. **PQ key agreement is a solved default. PQ authentication is not.** [A, `std-rfc10024-ecdhe-mlkem`, `crate-rustls-pq`, `fips-cmvp-mlkem-modules`] RFC 10024 is a Proposed Standard. rustls 0.23.46 prefers X25519MLKEM768. CMVP #5314 (AWS-LC 3) includes ML-KEM. Correction from verification: X25519MLKEM768 is **not negotiable in RHEL FIPS mode**, so a FIPS profile must default to SecP256r1MLKEM768 (`v.rhel-fips-hybrid-groups`, which pushed `std-sp800-227` down to C). Public PQ authentication waits on Merkle Tree Certificates, still a draft (`std-mtc-plants`). rustls GHSA-w44r showed PQ can be silently downgraded through a cached key share. → A server HRR policy is required.
5. **Cedar is the only policy engine with formal semantics, a differential-tested evaluator and decidable SMT analysis. It has no delegation.** [A/B, `cedar-lean-proofs-2026-10`, `authz-formal-pdp-comparison`] 3,912 Lean theorems with 0 sorry at 301bdd2. The Rust evaluator is DRT-tested, not proven. Live hazards: skip-on-error lets an erroring `forbid` fail open, and GHSA-m84h lets a 258 B policy cause a ~29 GB parser allocation. No token system combines semantics, a verified checker and PQ signatures (`gap-verified-attenuable-pq-token`).
6. **Proof labour is now cheap. Spec fidelity is the binding cost.** [B/A, `llm-verusage-2025`, `rec60-rust-prover-llm-proofs`, `rec60-spec-fidelity-verus`, `fail-libcrux-spec-bugs-2026`] Agents prove more than 80% of real Verus system obligations at about $6 each. Rust-Prover proved 1,325/1,325 small theorems at a median of $1.17. But only 42.3% of verifier-accepted LLM artifacts pass all semantic checks. Verus has 41 open soundness issues. libcrux spec bugs hid in admitted and skipped modules. → CI gate: no trust annotations outside a ledger, no admitted modules, executable specs checked against vectors and differential corpora.
7. **The DB gate's main failure class is session state crossing requests.** [A, `sdg-rls-plan-cache-family`, `sdg-txn-pooling-session-leak`, `sdg-pgbouncer`] There are 9 RLS confidentiality CVEs in about 10.5 years (CVE-2026-14666: cached policies survive role change). PgDog has open SET ROLE and GUC leaks. PgBouncer CVE-2026-107350 (CVSS 8.8) allows SCRAM impersonation. → Identity only via `SET LOCAL` inside one transaction per request, session state banned at the protocol layer, RLS as defence-in-depth only. Postgres is one adapter among many (§0b); the general mediation model is not yet researched.
8. **No embedded store has a clean 2026 crash record, and none is known to handle fsync failure.** [A/B, `sdg-embedded-store-selection`, `sdg-redb`, `sdg-fjall`, `v.rebello-atc20-fsync-failures`] SQLite had a 16-year WAL-reset bug, fixed in 2026. redb read paths verify no checksums (8,163 of 8,224 byte flips go undetected). fjall's fsync-ordering fix was made blind, without a reproducer. → Any store-of-record must pass our own ALICE-style plus bit-flip plus EIO harness (`sdg-l5-crash-harness`).
9. **MCP 2026-07-28 is stateless.** [A, `j-mcp-2026-07-28`, `j-mcp-stateless-no-sessions`] Sessions and initialize are removed, Mcp-Method/Mcp-Name headers are required, DCR is deprecated in favour of CIMD. This removes the session-table CVE class (`j-mcp-sdk-advisories`: about 30 SDK advisories, Dec 2025 to Oct 2026), so the MCP layer can be a pure per-request function. Web Bot Auth on RFC 9421 is the only agent-identity track with both WG adoption and CDN deployment.
10. **Supply-chain gates measured on a real lockfile.** [A, `sc.vet-import-sets`, `sc.unsafe-budget`, `sc.repro-build-experiment`, `sc.arrayref-incident`] Five public cargo-vet import sets fully audit only 14 of 94 crates in a hyper+rustls+tokio lock (3.94M-line backlog, 2.09M of it vendored aws-lc C). Three remap flags gave byte-identical builds across directories. The arrayref account takeover was live for 86–107 minutes. Correction: Cargo **does** have a native cooldown, min-publish-age (RFC 3923), stabilized for Rust 1.100 (`v.cargo-min-publish-age-rfc3923`). `sc.cooldown-policy` is refuted on that point and graded C.

## 3. New bridges (cross-domain edges)

- **Unauthenticated state carried across requests** is one root cause across four pillars: pooler session leaks and RLS plan caches (W-DATA-GATE), rustls cached key-share PQ downgrade (W-PQC), MCP session tables that 2026-07-28 deleted (W-AGENT-PROTOCOL), and Wasmtime stores reusable after a trap (W-ISOLATION). → Candidate core invariant: no cross-request state that unauthenticated input can influence (`sdg-txn-pooling-session-leak` ↔ `adv-rustls-2026-wave` ↔ `j-mcp-stateless-no-sessions` ↔ `crash-isolation-semantics`).
- **Determinism as a security property.** Biscuit's 1 ms wall-clock RunLimits, Wasmtime epoch interruption (non-deterministic) vs fuel (deterministic but bypassable), and aws-lc raw `getrandom` syscalls that escape DST interposition (`as.dst-entropy-leak`) all join authorization reproducibility (`inv-decision-determinism-failclosed`) to the DST harness (`as.dst-harness-spec`).
- **Fail-open defaults** recur across gateways (`gap.insecure-defaults`), Cedar skip-on-error (`cedar-skip-on-error-semantics`), KEV CWE-287/288/306 and NATS ack-before-fsync (`sdg-jepsen-nats`). → One "fail-closed default-config" CI gate serves W-THREAT, W-AUTHZ and W-STATE.
- **AI-found bugs** show up across W-ISOLATION (11 of 12 Wasmtime April advisories), W-STATE (redb 4.1.0 fixes), W-TRANSPORT (HTTP/2 Bomb by Codex; Envoy Brotli by OpenAI) and W-THREAT (advisory surge). The same capability is a defensive CI stage (`as.ai-redteam-ci`).
- **"HTTP/1 must die" ↔ the verified-parser gap ↔ EverParse.** Avoid HTTP/1 upstream. Verify binary framings (H2 frames, QUIC varints, PROXY v2) with EverParse/Vest at no proof effort. HTTP/1.1 text framing is the remaining fills_gap target (`threat-request-smuggling-desync` ↔ `gap-verified-http1-parser` ↔ `proof-everparse-hyperv`).

## 4. Protocol changes (rule diffs, all new in round 1)

Recorded in full in `ARCHITECTURE-DRAFT.md` §R. Round 1 creates 41 rules (R-GAP-1 through R-ASSURE-1). Nothing existed before, so there are no deletions. The rules a verifier moved:
- `+R-SUP-3` cooldown: was "no native Cargo support, use Dependabot". Now "cargo min-publish-age (Rust 1.100) plus Dependabot cooldown". Evidence: `v.cargo-min-publish-age-rfc3923` [B].
- `+R-PQC-2` FIPS profile: was "X25519MLKEM768 FIPS-approvable via SP 800-56C". Now "SecP256r1MLKEM768 default in FIPS profile, X25519MLKEM768 only outside FIPS". Evidence: `v.rhel-fips-hybrid-groups` [B].
- `+R-TLS-4` webpki pin: was "≥0.103.13". Now "≥0.103.16". Evidence: RUSTSEC-2026-0382 [A].
- `+R-THR-2` patch window: was "assume no patch window". Now "hours-scale rebuild pipeline and kill-switches, motivated by the day-zero share (23.4%, falling from 28.9%), not by an absolute no-window claim". Evidence: `result-time-to-exploit-trend` [B].

## 5. Calibration notes (two-sided verification)

**Moved up:**
- `threat-h2-h3-resource-exhaustion`: cross-language HTTP/2 Bomb.
- `threat-memory-corruption-c-servers`
- `wasmtime-llm-audit-sprint-2026-04` (primary post confirmed) → A.
- `wasi-resource-isolation-attack-usenix25` (PDF confirmed) → A.
- `proof-aeneas-symcrypt`: code is public.
- `sdg-redb`: silent corruption is worse than reported.
- `sdg-fsyncgate`: Rebello answers the open question.
- `sc.arrayref-incident`
- `rec60-go-1.27.2-batch`
- `hist-techempower-sunset`
- Agent-authz papers: progent, camel-noncompositional, approval-to-abuse, rec60-agent-authz-attacks.

**Moved down:**
- `sc.cooldown-policy` → C: headline refuted.
- `std-sp800-227` → C: FIPS-approvable is not FIPS-deployable.
- `llm-dafny-agents` → C: apples-to-oranges comparison.
- `iso-glue-not-boundary-pattern`: its own examples contradict it.
- `wasmtime-ghsa-record-2021-2026`: "57 in 2026" is unverified, and RustSec counts 41.
- `cranelift-veriisle-ci`: the "caught CVE-2026-34971" narrative is unsourced.
- `kvm-januscape-cve-2026-53359`: needs nested virtualization exposed.
- `fuel-not-a-security-bound`
- `j-x402-volume` → C: mixed windows.
- `sc.rustsec-volume`: 2.3× vs 2025, not 4–5×.
- `sc.vet-ci-gate`: a trusted-publisher entry would not have stopped arrayref.
- `skeptic-ai-exploit-overhype`
- `threat-fail-open-config-and-auth-logic`: the KEV evidence is proprietary appliances.

**Numeric drift found (identifier exists, number differs):**
- ExploitGym 17.5%/13.4% vs claimed 18.1%/13.8%.
- CyberGym "97%" not found.
- Ferron 6 high/critical, not 7.
- quinn 11 GHSAs, not 12.
- workerd 2 GHSA, not 0.
- HTTP Terminator was published 2026-08-05 and is already open source.
- FoxIO URL returns 404.
- MCP "iss MUST" is only MUST-when-present.
- tough GHSA date was 2026-04-24.
- Rust 1.99.1 is unconfirmed.
- The slopsquat preprint's models are small/mid tier, not frontier.

Lesson for round 2: existence is reliable, numbers are not. Every load-bearing number needs a source-table check.

**Calibration target (explorer 12):**
- 0 of 37 PDF1 identifiers are nonexistent, but 3 exist with different content.
- RFC 9680 is the IETF antitrust guidelines, not MTC.
- x402 "165M tx" is not found in any primary source.
- The AIP latency figures (135/324 µs) are absent from the paper.

These are recorded as exists/doesn't-exist facts only.

## 6. Open frontier (top seeds for round 2; full list in `state/frontier_queue.jsonl`)

1. q1-001 [0.95] Data-plane abstraction across backend families (§0b mandatory).
2. q1-002 [0.95] Protocol-agnostic ingress plus modularity mechanism plus leanness measurements against nginx/Caddy/Pingora/Envoy/HAProxy (§0b mandatory).
3. q1-003 [0.90] Turn the agentgateway session-overwrite and docker/mcp-gateway CVE-2026-76092 diffs into violated invariants (W-AUTHZ L5).
4. q1-004 [0.90] Verification toolchain disk/RAM footprint and per-component prover choice, Lean without Mathlib (§0c mandatory).
5. q1-005 [0.85] H2/H3 resource budgets as a Verus/Kani-checkable invariant over an h2/quinn-style state machine.
6. q1-006 [0.85] Fraction of Wasmtime 2026 advisories that touch a minimal hardened config.
7. q1-007 [0.85] Golden extension contract: which invariants survive arbitrary out-of-process modules (§0c).
8. q1-008 [0.85] W-ABUSE pillar (zero nodes).
9. q1-010/011 [0.80] Component-model per-request cost; ML-KEM handshake cost on a 1 vCPU $5 VPS.
10. q1-012 [0.80] CVE-2026-14666 reproducer: does `SET LOCAL ROLE` + prepared statements + `DISCARD PLANS` suffice?

Round-2 planning rule (§0d): every target must pass `novelty_gate.py target` (< 0.6) or be a DESCEND that changes the instrument. Round 1 left most measurements and L5 artifacts as specs, so measurement-instrument descends are cheap and legitimate.
