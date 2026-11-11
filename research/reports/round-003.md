# Monban round 3 report (2026-10-25)

Integrator: sole writer of map state for round 3. Inputs: 12 explorers (raw JSON in `state/raw/round-003/`) and 12 two-sided verifier passes. The blind-research rule (§0a) held: the integrator did not open `state/prior_treatments/` or `state/seed_conversation.md`.

Crash recovery note: this integration ran after the operator's machine crashed from memory exhaustion ("continue, my system crashed from memory"). No round-3 state had been written before the crash (0 records with `first_seen_round: 3`), so the integration started clean. The integrator ran no heavy jobs; everything was stdlib Python over JSONL.
- Explorer 09's raw JSON had lost its `seeds` key. Its 5 seeds were restored from the relayed compact findings (`EXTRA_SEEDS` in the script).
- Verifier verdicts existed only in the orchestrator payload. The integrator re-keyed 161 verdicts into `state/raw/round-003/_verify_r3_verdicts.json`, and 70 "missed" items plus 7 promoted nodes into `_verify_r3_missed.json`.
- Script: `state/raw/round-003/_integrate_r3.py`. It is deterministic and refuses to run twice. Pre-write backups are in the session scratchpad.

## 1. Delta

| metric | value |
|---|---|
| new nodes appended to `state/graph.jsonl` | **207**: 200 from explorers, 7 promoted from verifier "missed" lists (`v3.*`) |
| by layer (new) | L1 2 · L2 6 · L3 34 · L4 121 · L5 44 (**80% at L4/L5**; round 2: 73%) |
| by grade (new, after verification) | A 87 · B 70 · C 28 · D 19 · E 3 |
| revision records of existing nodes | 23. 11 are calibration re-verifications (explorer 12) and 12 are integrator corrections from round-3 evidence. Same id, `revision_round: 3`, never renamed |
| merges (same-as into an existing node) | 2: `zd.l4-config-push-outage` → `r2e11.cloudflare-2025-11-18` (same incident); `sc3.arrayref-trust-model-gap` → `sc.arrayref-incident` (same RUSTSEC-2026-0260) |
| edges appended to `state/edges.jsonl` | 387: 343 explorer, 2 same-as, 18 refines, 5 contradicts, 19 integrator bridges. 0 dangling |
| canonical URLs appended to `state/seen.jsonl` | 544: 474 new, 70 re-seen and marked `revisit` |
| queries merged into `state/queries.jsonl` | 290 (one mislabelled `golden-lock` line mapped to the supply-chain explorer) |
| frontier queue (rebuilt) | 432 items: 263 open, 33 partial, 38 done, 98 absorbed. 19 round-1/2 items closed or advanced (see §6) |
| predictions appended | 10 (total 34) |
| verification | 161 of 211 explorer records (76%) two-sided checked: **4 up, 52 down, 105 unchanged**. Over-claim ratio 13:1 (round 2: 3:1). That is a sharper verifier, not worse explorers: most "down" moves are a source misattribution or a modelled number presented as measured, not a refutation |
| refuted or materially corrected (kept with grade and reason, never pruned) | `dx.claw-swe-rust-agentic` B→C (task pool shared with SWE-bench Multilingual, so not independent; contamination likely); `dx.compiler-feedback-ablations` B→C (AdaTrans and 2607.13080 do not support the claims attached to them); `ops.fips-module-boundary-pin` A→B (aws-lc-rs range wrong: 1.17.3+ needs fips-sys ≥0.13.16); `ac.attacker-chosen-cancel-instant` A→B (RUSTSEC-2025-0070 is pingora-core, not hyper); `ac.i11-ratelimit-incr-expire-window` B→C (crash-triggered, not cancellation); `w02.L5-adapter-oop-threshold-table` B→C (policy from one laptop number); `w02.handshake-pq-cost` A→B (the reported "best trial" 123.4 µs appears in no log); `r3e11.wasi-http-host-side-framing-batch` (CVE-2026-58494 is a June advisory, not part of the October batch); `sc3.incident-gate-matrix` stays C (self-scored counterfactuals) |

### Mechanical novelty

`python3 -I tools/novelty_gate.py metrics --round 3`, run before any state write and copied verbatim (also in `state/raw/round-003/_metrics_r3.txt`):

```json
{
 "round": 3,
 "queries": 290,
 "urls": 537,
 "nodes": 211,
 "url_novelty": 0.8808193668528864,
 "query_novelty": 0.996551724137931,
 "node_novelty": 0.9478672985781991,
 "axis_cell_novelty": 0.9655172413793104,
 "intra_round_query_dup_rate": 0.0034482758620689655,
 "mechanical_novelty": 0.8808193668528864
}
```

- **delta.novelty_ratio = 0.881** (the mechanical value; round 2 was 0.898).
- An earlier run, before the two verifier JSON files were written into the round directory, gave 531 URLs and 0.879. The difference is 6 verifier-cited URLs.
- Node novelty: the gate counts 211 nodes. The 11 non-novel ones are explorer 12's re-verifications of existing ids, which became revision records and earn zero novelty credit. 200 / 211 = 0.948. The 2 same-as merges also earn zero credit, so the merge-adjusted node novelty is 198 / 211 = 0.938. The binding term is still URL novelty (0.881).
- **Saturation (§0c): not met.** The threshold is mechanical_novelty < 0.2 in two consecutive rounds; round 3 is 0.881.

### Singletons and unseen mass

- **Singletons: 198** of the 200 new explorer nodes were found by exactly one explorer and match nothing existing (no same-as).
- **Strict singletons: 61.** These additionally have no edge to another explorer's node or to a round-1/2 node.
- The cross-explorer near-duplicate scan (title+summary token Jaccard) found no pair ≥ 0.2 among new nodes.
- Good-Turing unseen-mass estimate: 198 / 207 ≈ **0.96** (strict 0.29; round 2 was 0.975 / 0.43).
- Explorers are finding mostly unique material, but less of it stands alone: more new nodes attach to the existing graph (139 of 200 cross-linked vs 111 of 199 in round 2). That is what a descend-heavy round should look like.

### Direction diversity (§8a)

- Queries 290, distinct 4-axis cells (pillar | source type | stance | era) **106**: **direction_diversity = 0.366** (round 2: 0.382). With the vocabulary axis there are 166 cells: **0.572**.
- 84 of 106 cells (154 of 166 five-axis cells) are new, and 70.3% of queries landed in a cell not used before. Caveat: pillar labels are per-target (for example `W-DATA-GATE+W-FORMAL`, `W-TRANSPORT-INGRESS`), which inflates cell newness, as in round 2.
- Intra-round dup rate 0.003. Cross-explorer near-dups (J ≥ 0.5): 0. Prior-round near-dups: 1 (dx: "Ur/Web Chlipala typed SQL XSS guarantees", J = 0.55 vs a round-1 history query).
- Axis totals:
  - source type: spec-rfc 70, repo-advisory 66, web-other 43, vendor-doc 42, paper 23, cve-incident 23, benchmark 18, forum 4, talk 1
  - stance: proponent 201, skeptic-negative 60, attacker 29
  - era: 2025-26 255, last-60d 27, historical 8
  - vocabulary: systems 100, standards-policy 35, offensive 34, cryptography 29, web-dev 28, PL-formal 26, database 19, network-SRE 14, economics 5
  - scale: unspecified 261, hyperscaler 15, government 13, household 1
- Yield (new non-merged L4/L5 nodes per query):

| explorer | queries | new nodes | L4/L5 | per query |
|---|---|---|---|---|
| ingress-nonhttp-frontends-defect-classes | 6 | 17 | 16 | 2.67 (bulk OSV/`gh api` resolution; queries under-logged) |
| supply-chain-executed-on-golden-pins | 14 | 23 | 22 | 1.57 (executed tooling) |
| abuse-economics-and-swarm-simulation | 20 | 19 | 19 | 0.95 (own simulator) |
| pq-authentication-and-hrr-acceptance | 21 | 16 | 16 | 0.76 |
| modularity-ipc-and-normalization-copy-spike | 20 | 14 | 14 | 0.70 |
| zero-downtime-reload-and-scaleout-state | 19 | 24 | 13 | 0.68 |
| authz-token-format-code-level | 28 | 18 | 14 | 0.50 |
| dataplane-ir-lowering-soundness | 31 | 17 | 14 | 0.45 |
| dx-agent-checkable-handler-surface | 19 | 12 | 8 | 0.42 |
| bridge-async-cancellation-failure-atomicity | 55 | 23 | 17 | 0.31 (most queries; `gh api` issue searches had the best hit rate) |
| uu-adjacent-fields-and-unused-sources | 37 | 17 | 4 | 0.11 (adjacent-field negatives by design) |
| calibration-two-sided-could-flip-decisions | 20 | 0 | 0 | 11 revisions (judge by revisions) |

- Redundant directions to flag:
  - Explorers 04 and 11 both re-reported tokio RUSTSEC-2026-0384/0386, and explorers 03, 04 and 11 each touched the rustls 0.23.46 advisory batch. A shared advisory snapshot (`_advisories/`, produced this round by 11) should be the single source next round.
  - The wasmtime advisory list was pulled again (11's OSV snapshot plus 06's cancel advisories) despite being retired in round 2. Only the delta since 2026-08-25 was new.
- Under-explored: economics vocabulary (5 queries, all in the abuse explorer), household scale (1 explicit), forum (4), talk (1), patent (11's scan only), non-English (0 this round).

## 2. Top findings (actionability × grade; L4/L5 first)

1. **The default rustls server is not downgrade-proof** (`r3pq.hrr-acceptance-test`, A 0.93; `r3pq.rustls-kx-client-order`, A).
   - Hand-built ClientHellos against rustls =0.23.46: the server picks the first client-listed group it supports and sends HRR only when the share for that group is missing.
   - A client that lists X25519 first gets a classical handshake. The only knob on 0.23.x is `kx_groups=[X25519MLKEM768]` (pq-required), which gives HRR 0x11EC to hybrid-listing clients and alert 40 to classical-only ones.
   - Server-preference order exists only on unreleased main (`KeyExchangeSelector::PreferServerOrder`).
   - Consequence: R-PQC-1 is split per listener.
2. **Every naive data-plane lowering leaked tenants** (`irl-l5-differential-oracle-harness`, A; `irl-sqlite-affinity-collation-cex`, `irl-pg-collation-cex`, `irl-redis-glob-key-prefix-cex`, A; `irl-l5-unsound-lowering-denylist`, A 0.80).
   - An executed reference-vs-native oracle on SQLite, PG 17.11 / 19rc1 and a port of the Redis matcher found leaks every time: SQLite 1,004-1,492 of 3,000 cases; PG 282-725 depending on collation; Redis 10 of 19 tenants.
   - It also caught a leak in the explorer's own hardened SQLite form (affinity coercion: `'' >= 10`).
   - PG 18 turned a fail-closed LIKE error into a leak, so engine upgrades must re-run the oracle.
   - Golden: binary collation on every text comparison, never LIKE/GLOB for Prefix, Redis `t:{hex(tenant)}:` keys (ACL patterns too), Or([]) = FALSE, plus the adapter refinement contract (new R-DB-7).
3. **Async cancellation poisons pooled connections and leaks across users** (`ac.root-cause-drop-at-await`, A 0.82; `ac.i01-sqlx-4393-begin-cancel`, A 0.95; `ac.i03-diesel-async-304-stale-result`, A 0.95; `ac.i07-wasmtime-cancel-advisories`, A).
   - 15 instances across 5 ecosystems, 6 from 2026.
   - Three fixes were main-only or unreleased on 2026-10-25: sqlx f1e94ec, diesel_async #305, and rust-postgres #1374, which is still open.
   - hyper drops the service future on h2 RST and h1 close, so a remote client chooses the cancellation instant. "One txn per request + outbox" closes only about 5 of 15.
   - New invariant INV-NOMUT-C NC1-NC8, a cancel-sweep harness and CR1-CR9 lint rules (R-STATE-6/7).
4. **A blanket dependency cooldown lands the PQ downgrade** (`sc3.cooldown-executed-cargo-198`, A 0.90).
   - Executed on cargo 1.98 `-Zmin-publish-age`: a 14-day window resolves rustls 0.23.45 (RUSTSEC-2026-0346..0349, incl. silent classical-KX downgrade), webpki 0.103.15 and tokio 1.53.2. In total, 6 advisories plus exact-pin hard errors.
   - Policy: 7 days plus an audited security-advisory bypass; caret ranges plus lock and security floors, not `=` pins (R-SUP-3).
   - Dates corrected: RFC 3923 merged 2026-05-18; stabilization PR #17335 merged 2026-08-28 for 1.100.0.
5. **FIPS pin resolved, and it conflicts with the golden lock** (`ops.fips-module-boundary-pin` r3 revision, B 0.82; `v3.aws-lc-rs-fips-sys-range`, A 0.85).
   - aws-lc-fips-sys =0.13.11 vendors AWS-LC FIPS 3.1.0 (CMVP #5298/#5314, issued 2026-06-03/05). ML-KEM 512/768/1024 is approved; ML-DSA/SLH-DSA are not, and X25519 is outside the boundary.
   - Only aws-lc-rs 1.15.2-1.17.2 can resolve it. The executed golden lock resolved aws-lc-rs 1.18.2 (unvalidated v4 line), so the FIPS golden is a separate lock with a Cargo.lock checksum gate.
   - AWS-LC 4 is in Comment Resolution (2026-10-22). This closes q2-019 and moves R-PQC-2 from C to B.
6. **`default-features=false` makes rustls silently classical** (`r3pq.prefer-pq-feature-pitfall`, A 0.93): DEFAULT_KX_GROUPS becomes [X25519, P256, P384, X25519MLKEM768] (319 B ClientHello vs 1,539 B). CI must assert `prefer-post-quantum` on every rustls in the lock and `kx_groups[0]` at runtime (bridges to supply-chain gates).
7. **Attenuation needs the conjunction, not a subsumption checker** (`r3e05.tenuo-cel-attenuation-bypass`, A 0.82; `r3e05.token-verify-microbench`, B).
   - Tenuo 0.3.3 (non-default `cel` feature) checks attenuation syntactically and authorizes the leaf only, so a child can widen authority. This was confirmed locally and is unfixed on main.
   - The operator should report it privately to security@tenuo.ai. The PoC is not published.
   - Measured verify costs: opaque handle 83 ns, HMAC chain with 5 caveats 1.2 µs, Biscuit with 3 blocks 158 µs, ML-DSA-65 114 µs per block.
   - The token decision moves from E to B (R-AUTHZ-2, new R-AUTHZ-6).
8. **SET LOCAL ROLE + statement cache is safe on patched PG; session-level GUCs leak** (`irl-l5-q1012-role-plan-cache-gate`, A 0.85; `irl-cve-2026-14666-fix-anatomy`, A 0.95; `v3.cve-2026-14666-session-persistence`, A).
   - Tested on PG 17.11/19rc1 under all three `plan_cache_mode` values, with a positive control.
   - The advisory says stale policies persist until the session ends, so the gate must recycle pooled connections after the minor upgrade as well as check the floor.
   - Closes q1-012.
9. **Out-of-process hop measured** (`w02.ipc-hop-cost-1core`, A 0.80; `w02.serde-bytes-pitfall`, A; `w02.spin-ring-negative-result`, A).
   - Measured on one pinned core: UDS 4.8 µs, futex shm ring 2.1 µs, in-process 0.02-0.05 µs.
   - A spin-then-futex ring costs 638 µs per call on 1 core. Default serde byte slices make a 64 KB hop 4.9× slower.
   - Placement is decided by unsafe/C-binding count first and the hop budget second. This partially triggers R-MOD-1's reversal condition (see §4).
10. **Reproducible golden binary** (`sc3.repro-ablation-golden`, A 0.78).
    - The 233-crate lock built byte-identical across CARGO_HOME, directory and SOURCE_DATE_EPOCH with exactly 3 `--remap-path-prefix` flags (src, registry, rustup); it differed with none or with the source-only remap.
    - Changing the rustc version or using `cargo auditable` changes the hash, so both belong in the attested build identity.
    - Only same-host reproducibility is shown.
11. **Front-end defect classes are mostly core-once** (`r3e09.ws-upgrade-smuggling`, A 0.90; `r3e09.grpc-defect-classes`, A; `r3e09.ws-cswsh-origin`, A; `r3e09.tonic-connect-crate-scorecard`, B).
    - Pingora CVE-2026-2833 (critical, fixed 0.8.0) forwarded bytes before a validated 101.
    - grpc-go CVE-2026-33186: authz matched a raw `:path`.
    - Rust WebSocket crates do not check Origin, and none implement permessage-deflate (4 deflate-ordering CVEs elsewhere in 2026, 3 verified).
    - tonic passes `max_concurrent_streams(None)` through to hyper, removing its default of 200 (static read; runtime check pending).
12. **The round-2 admission defaults collapse in simulation** (`r3e07-r2-defaults-collapse`, D 0.65; `r3e07-L5-tuned-default-table`, D; `r3e07-pow-asymmetry-measured`, C up).
    - In a deterministic simulator, a 10k-IP solver swarm drives human failure to 99.1%. Causes: PoW-minted cookies share the human class, there is no aggregate cap on the expensive tier, and per-identity budgets never bind across 10k identities.
    - The tuned table passes C1-C4 and C6-C10 over 10 seeds × 10 scenarios. C5 (50-user NAT flash crowd) fails; C11 is untested.
    - PoW asymmetry is 430-860× single-thread and far larger for a farm.
    - Grade D: an uncalibrated simulator, but the mechanisms are structural.

## 3. New bridges (19 edges, `origin: integrator-bridge`)

1. **Pooled-connection hygiene ↔ data-plane proofs.** NC3's checkin predicate (ReadyForQuery `I`, no outstanding replies, server objects closed) is a precondition of the tenant role/GUC binding that the lowering theorem trusts (`ac.l5-inv-nomut-c` → `irl-l5-backend-refinement-contract`). sqlx#4393 (a cancelled BEGIN keeps the previous principal's txn) sits next to q1012 (clean connections are safe): both gates are needed.
2. **Checker vs evaluator.** Tenuo (leaf-only evaluation plus a syntactic subsumption checker) and the empty-OR family (SQLAlchemy `or_()`, go-sqlbuilder, ucast-prisma) both widen authority silently. One fix covers both: a single canonical evaluator over the full conjunction, with Or([]) = FALSE.
3. **Canonical identity.** grpc-go's `:path` authz bypass and SQL collation/LIKE tenant collisions are one class: policy compares a non-canonical form. Each identity gets one canonicalization owner, and binary collation is used everywhere.
4. **Supply chain × PQC.** The lockfile feature audit asserts `prefer-post-quantum`. A 14-day cooldown resolves the RUSTSEC-2026-0349 rustls; the HRR acceptance test is the behavioural backstop when cooldown and security floors disagree.
5. **FIPS × golden lock** (`conflicts_with`). The executed golden lock resolved aws-lc-rs 1.18.2, while the FIPS pin needs ≤1.17.2. This produced new frontier item q3-004.
6. **Perf budget.** A 4.8 µs IPC hop vs ~424-848 µs for a full TLS handshake: adapter IPC is under 1% of a new-connection request but about 100× a cached key lookup.
7. **Abuse × atomicity.** An RST-timed cancel costs the attacker one frame but forces a discard-on-cancel reconnect (TLS+SCRAM). It must be charged (NC4), or it becomes a reconnect amplifier against the ~1.1k full-handshake/s floor. NC4 and I8 are one ledger.
8. **Drain = cancellation.** The upgrade drain deadline (UP-4) cancels in-flight requests; NC2's commit-point latch decides which complete. One T_drain bound covers both.
9. **Fail-closed config.** Validate-then-swap with last-known-good on reload, and CI fails on any effective unbounded limit at ingress. "Defaults are the bug": tonic `None`, async-graphql `None`, Pingora CVE-2026-105297.
10. **One proof pattern.** The token (verified CBOR parser + core-Lean T1-T6) and the data plane (Lowering.lean) share "verified parser + core-Lean semantics theorem + DRT to Rust" on one toolchain (Lean core, no Mathlib).
11. **Agents weaken boundaries when tools suggest it.** rustc's in-crate "make the field public" help and `cargo add` of hallucinated crates both apply. Deny agent edits to `sdk/**`, and route `cargo add` through the intake gate.
12. **Executed oracles beat reading.** The lowering oracle and the cancel sweep both found bugs in code written to be safe. Run both against real PG nightly.
13. Others:
    - Cross-stack trailer/bridge/validator classes support the core-once matrix.
    - Webhook raw-body signatures constrain the typed Ctx: it needs a verified-before-parse capability.
    - Reproducible-build identity feeds the upgrade signature check.
    - Out-of-process adapters make cancel = crash cheap.

## 4. Protocol changes (rule diffs, with evidence; full text in `ARCHITECTURE-DRAFT.md` §R)

- **15 new rules; 37 amended; 3 with a direction change; 0 deleted. Total 86.**
- **Direction changes (honest reversals or narrowings):**
  - **R-PQC-1** (A): "HRR to hybrid whenever the client lists it" cannot be implemented on 0.23.x defaults (the server follows client order). Agent/API listeners now use pq-required `kx_groups=[X25519MLKEM768]`. The public browser listener keeps client order until rustls ships `PreferServerOrder` (reversal R2).
  - **R-MOD-1** (B): its reversal condition ("out-of-process IPC > 2× in-process for typical handler calls") is met for cheap ops: a presign-shaped op is 5.2× and a key lookup about 100×. Out-of-process is narrowed to C-binding, third-party or compiler-bearing modules within a hop budget (≤20k calls/s/core, ≤10% of a core). Hot pure-Rust paths stay in process.
  - **R-PQC-3** (B mechanics / C compliance): the CNSA 2.0 TLS profile (draft-becker-05) is pure ML-KEM-1024 + ML-DSA-87, which rustls 0.23.46 already supports (21.3 KB flight measured). The "no SecP384r1MLKEM1024" blocker no longer applies. The new blocker is that ML-DSA is not approved in AWS-LC FIPS 3.1.0, so a profile cannot be both FIPS-validated and CNSA-ML-DSA today.
- **Grade moves:**
  - R-PQC-2 C→B (pin resolved).
  - R-AUTHZ-2 E→B (token decision with measured costs and alternatives).
  - R-ABUSE-1 E→D (simulated numbers replace guesses).
- **New:**
  - R-THR-5 async-cancellation threat class
  - R-ING-2 front-end defect-class rules
  - R-ING-3 separate L4/PROXY module
  - R-PERF-3 IPC wire rules
  - R-PQC-7 PQ token size/transport
  - R-AUTHZ-6 conjunction attenuation, `now` as a parameter
  - R-STATE-6 INV-NOMUT-C
  - R-STATE-7 cancel-correct coding rules and sweep gate
  - R-DB-7 adapter refinement contract + oracle gate + denylist
  - R-ABUSE-5 cheap-endpoint economics, behaviour scores only weight budgets
  - R-OPS-7 in-place upgrade protocol UP-1..7
  - R-OPS-8 scale-out state behind traits
  - R-SUP-5 incident back-test (C)
  - R-DX-1 capability-typed handler SDK (C)
  - R-DX-2 OCI + cosign deploy artifact
- **Decision stability (for the saturation judge):** of the 71 round-2 rules, 68 kept direction (**0.958**), above the 0.75 bar. But novelty is 0.881, and at least 4 open areas could still flip a load-bearing decision (§6).

## 5. Calibration notes (two-sided verification)

- **Up (4):**
  - `w02.prior-art-ipc-overheads` → B (MeshInsight Table 2 confirmed, but these are sidecar per-filter rows).
  - `r3e07-pow-asymmetry-measured` (multi-thread 1.1-3.4 GH/s makes farm asymmetry far larger).
  - `zd.l4-reuseport-kernel-migration` → A (CVE-2026-46015 verified at INCIBE).
  - `zd.l4-quic-across-processes` (nginx 1.31.7 preserves QUIC across reload and live upgrade: zero-drop H3 upgrade is shippable).
- **Down (52), by class:**
  - **Source misattribution:**
    - rust-postgres URLs point to rust-lang instead of sfackler
    - MadeYouReset advisory is pingora-core
    - pgx#679 is unrelated
    - CVE-2026-58494 has the wrong date
    - AdaTrans / 2607.13080 misused
    - InfoQ benchmark has no CPU model
    - Red Sift numbers are OpenSSL, not rustls
  - **Modelled presented as measured:** QUIC datagram counts, the swarm sim's CPU scale, the 1-vCPU projections, the Lean timing projections.
  - **Independence:** Claw-SWE-Bench and SWE-bench Multilingual share the Rust pool.
  - **Range or wording errors:** aws-lc-rs FIPS range; FPEval repair gains are about 1-3 pp, not 2-5 pp; "four" deflate CVEs is three.
  - **Self-scored matrices** (incident gates, core vs per-front-end classes): grade C.
- **Calibration explorer (12) revisions:**
  - `w02.handshake-pq-cost` A→B: the rustls PQ overhead recomputed from raw logs is +12.5-15.0% (the +17.5% "best trial" is not in any log); Envoy +24-25%; OpenSSL servers +29-74%.
  - `wasmtime-advisory-share-by-config` and `isolation-decision-inputs-table` → C: the 6/65 share is a denominator artifact. They are restated as an M0 escape rate of 0.36-2.0/yr.
  - `crs-l5-invariant-text` → B, with C5b (buffers empty at every key/epoch change) and the C8 recycling clause added.
  - `threat-ledger-middle-tier-2023-2026`: Rust resource-exhaustion share is 61% (CI 47-73%), falling to 50% in 2026, with TLS logic at 25%.
  - `ops.cra-obligation-split` A (Official Journal confirmed).
  - `ops.compliance-map-800-53` A (AU-9(3) misattribution fixed).
  - `gap.unserved-combination` C unchanged. New prior art: coproduct-opensource/nucleus (agent IFC runtime, Lean 4 + Kani). Its shelf life is short.
- **Verifier-promoted nodes (7):** `v3.aws-lc-rs-fips-sys-range` (A), `v3.cve-2026-14666-session-persistence` (A), `v3.go81199-sigalgs-cert-trigger` (B; the Go middlebox trigger is `signature_algorithms_cert` only), `v3.typed-authz-ctx-prior-art` (C; policy-core/typesec-agent/capsec), `v3.claw-swe-shared-task-pool` (B), `v3.nginx-quic-bpf-live-upgrade-limits` (B), `v3.iceoryx2-fosdem-2026` (C).

## 6. Open frontier (top of `state/frontier_queue.jsonl`)

- Queue items closed this round: q2-001, q2-016, q1-002, q1-012, q2-002, q1-043, q1-073, q1-028, q1-092, q1-077, q1-132, q1-034, q1-044, q1-060, q1-064, q2-019, q2-058.
- Partial: q2-011, q1-103, q1-124, q1-052, q1-127, q1-022, q1-131, q2-018, q2-063, q1-014, q2-004, q1-117, q1-134, q2-064, q1-025, q1-046.

| id | score | question (abridged) | closes by |
|---|---|---|---|
| q3-001 | 0.80 | rustls full vs resumed handshake CPU on a real $5 vCPU (ECDSA, X25519MLKEM768) | spike; replaces the sim's cpu_scale (R-ABUSE-1, R-PERF-1) |
| q1-013 | 0.80 | Crash blast radius: PHP-FPM vs pooled Wasm vs fork-server | spike |
| q1-009 | 0.80 | LLM-found vs human-found advisory rates | research (R-THR-2) |
| q2-009 | 0.75 | Window-0 stalled flow-control harness vs golden pins | spike (TBI-8) |
| q3-004 | 0.70 | Golden version triangle: rustls floor + prefer-post-quantum + FIPS pin in one lock | spike (R-PQC-2, could flip the FIPS golden) |
| q3-002 | 0.70 | ipcbench on a real 1-vCPU KVM VPS (steal time) | spike (R-MOD-1 gates) |
| q3-003 | 0.70 | Pre-TLS admission: prioritise resumed handshakes by ClientHello PSK identity | research + spike (R-ABUSE-1 S0.5) |
| q2-013 | 0.70 | Kani/Verus RAM and time on TBI harnesses | spike |
| q3-005 | 0.65 | Swarm simulator v2 (measured handshake cost, resumption, /64 churn, RST cancel storms) | spike |
| q3-006 | 0.60 | Write-path lowering soundness (UPDATE/DELETE/upsert tenant) | research + Lean (R-DB-7) |
| q3-008 | 0.60 | Discard-on-cancel reconnect cost and RST storm on 1 vCPU | spike (NC3) |
| q3-012 / q3-031 | 0.60 / 0.55 | Mutants vs real axum async handlers; LLM trial on SDK shapes A/B | spike (R-DX-1) |
| q3-013 | 0.60 | Differential HTTP framing corpus from the Sept-Oct 2026 cross-stack ids | spike (I-TRAILER, I-ONE-PARSE) |
| q3-015 | 0.55 | Timing channel under the hardened lowering (Range/Prefix in agent IR) | research + spike |
| q3-020 | 0.50 | Check Lowering.lean (SPK-LEAN-IR-1), close lower_sound_full | spike (E→A) |

**Decisions that could still flip** (load-bearing, support at E/C):
- R-ISO-1: M0 escape rate band 0.36-2.0/yr; `pred-wasmtime-m0-escape`.
- R-PQC-2: the FIPS golden lock triangle, q3-004.
- R-ING-1: still C; tonic/async-graphql runtime checks.
- R-DX-1: C; async lifetimes in real axum (q3-012).
- R-DB-7 / R-DB-2: the Lean theorem is unchecked (q3-020) and the write path is unproven (q3-006).
- R-ABUSE-1: D; uncalibrated simulator.

Nearly all of these close by implementation-phase spikes, not more literature (§0c).

## 7. Self-improvement (summary; full text appended to `state/self_improvement.md`)

- Run released artifacts by default (an OPA binary, pip/npm packages, paper figshare artifacts). This was the highest A-grade yield per hour this round (explorers 01, 04, 06).
- Shared advisory snapshot: 11's `_advisories/` should be the single source; three explorers re-pulled overlapping advisories.
- `heavy.sh`: two jobs launched 3 s apart were not serialized (explorer 03), and the queue blocked pure-Python jobs (07). Add a light-job lane, and write per-run unique output files.
- novelty_gate `topic` gave a false COVERED on generic tokens (06) and unrelated nearest nodes for DX (08). It needs aspect tags.
- Explorers must checkpoint within 2 minutes; the crash left several without progress files.
- Integrator: verifier verdicts again arrived only in the orchestrator payload. Verifiers should write `_verify_rNNN_verdicts.json` themselves.
