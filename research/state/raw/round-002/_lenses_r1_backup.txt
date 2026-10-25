# AEGIS lenses (state/lenses.md)

Maintained by the META-OPTIMIZER after each round. Append dated sections. Never delete earlier lessons. Newest guidance first in the "CURRENT" block, history below.
Evidence base for entry 2026-10-24: reports/round-001.md, graph.jsonl (327 non-merged nodes), queries.jsonl (473), directions.md, per-explorer raw JSON and progress files. Round 1 had no earlier round, so "novelty" is trivially 1.0 and yield is measured by node quality (layer, grade, verifier movement), not by novelty.

## CURRENT GUIDANCE (after round 1; apply to round 2 planning, §12)

### A. Ranked lenses (what produced novel, specific, well-graded nodes)

Metric: share of L4/L5 nodes, L5 count, A+B share, verifier-down rate (overclaim), in 327 nodes.

| rank | lens (explorer) | nodes | L4+L5 | L5 | A | verifier down | verdict |
|---|---|---|---|---|---|---|---|
| 1 | Supply chain + DST/assurance, run as EXPERIMENTS on a real lockfile / real crate (08) | 34 | 30 | 14 | 16 | 4 | Best. Produced 14 of 29 L5 artifacts. Instruments: cargo-vet over a real hyper+rustls lock, cargo-mutants on httparse (33.7% missed), repro-build flags. |
| 2 | Transport + PQC from primary advisories, RFCs, release notes (06) | 31 | 31 | 0 | 15 | 1 | Highest L4 density (every node L4) and lowest down-rate. No L5 yet: next step is the config/fuzz-oracle artifact. |
| 3 | AuthZ: formal-semantics papers + Lean/Cedar source + GHSA (05) | 43 | 22 | 6 | 3 | 3 | Many L5 (6) but grade-heavy B (31) and only 3 A: claims rest on papers, not reproduced. 5 E nodes. Good for artifacts, weak for evidence; add reproduction. |
| 4 | Threat ledger via bulk primary data: gh api security-advisories, OSV, CISA KEV JSON (01) | 15 | 4 | 1 | 4 | 2 | Few nodes but each is a dataset-backed ranking (one L1 node is load-bearing). Highest evidence per node. Use for measurement questions, not for node count. |
| 5 | Isolation: local microbenchmark + advisory table (04) | 26 | 13 | 2 | 7 | 5 | Converted vendor D claims to A in under 10 min. Highest down-rate among instrumented lenses (5/26): the lit-review half over-claimed (iso-glue pattern, fuel). Keep bench, tighten lit half. |
| 6 | State/DB-gate failure modes (09) | 39 | 4 | 3 | 20 | 3 | 20 A nodes but 35 of 39 are L2/L3: they list CVEs and stores, not parameters. Yield per query 0.09 on L4/5. Descend with an instrument (reproducer, crash harness), do not re-survey. |
| 7 | Agent protocols, primary spec/repo reads (07) | 30 | 6 | 1 | 15 | 6 | Most over-graded explorer: 20 A claimed, 15 final, 6 of 30 moved down (20%). Spec reading is easy to grade A; numbers (x402 volumes, "MUST" wording) drift. |
| 8 | Formal proofs/LLM provers (03) | 26 | 18 | 2 | 3 | 1 | Good L4 but only 3 A: mostly paper results (B). 60 queries for 26 nodes = diminishing; vendor-doc and proponent-paper heavy. |
| 9 | Recency sweep, last 60 days (11) | 14 | 10 | 0 | 6 | 1 | 52 queries, 14 nodes (0.19 L4/5 per query). Valuable (found HTTP/2 Bomb, Header Accordions, Wasmtime crit Oct 2026, cargo min-publish-age) but is a feed, not a descent: its nodes should be merged into pillar descents. |
| 10 | Calibration (12) | 9 | 9 | 0 | 5 | 0 | Cheap, reliable verdicts: 0/37 nonexistent identifiers. Low marginal value in round 2 if confined to identifier existence. Its value is numbers, not existence (see C). |
| 11 | W-GAP survey of prior-art servers (02) | 29 | 0 | 0 | 17 | 0 | All L3 by construction. 12 of 29 sampled by verifiers, none moved. Reliable, but done. Do not re-survey; extend only with measured lean numbers (§0b). |
| 12 | Historical R+S (10) | 19 | 0 | 0 | 9 | 2 | All L2/L3 lessons. Yielded a design-relevant "why they died" set but no parameters. One more round at most and only with a specific hypothesis (e.g. Ur/Web/Waterken lesson mapped to an invariant). |

Verdict: **instrumented lenses (run it, measure it, diff it) beat reading lenses**. The top 5 by quality (08, 06, 01, 04, 05) each ran code, bulk-queried a primary database, or checked a spec against source. The two pure-survey lenses (02, 10) are fully mined at L3.

### B. Dead or exhausted (retire unless a new instrument is named)

- Re-surveying prior-art servers (Pingora, Envoy, nginx, Caddy, HAProxy) by README/doc: exhausted. Only measurement, defect-hunt or lean-footprint descents are legitimate.
- Generic "what is MCP / what is Cedar / what is Wasmtime" overviews: exhausted at L3.
- Historical systems as survey (Ur/Web, Yaws, AOLserver...): exhausted at survey level.
- Identifier existence checking for PDF1-style names: done; 0/37 nonexistent.
- Vendor-doc / proponent-paper queries on formal proofs: diminishing (60 queries, 26 nodes, 3 A).
- PQC key-agreement status: closed (RFC 10024, rustls, CMVP #5314). Open PQC work is authentication (MTC), cost, FIPS profile.

### C. Calibration drift (round-1 evidence)

Method: explorer grade vs final grade (n=327). Cross-tab: A to A 119, A to B 11, B to A 2, B to B 140, B to C 2, D to C 1, rest equal. Verifier moves: 27 down, 17 up of 173 sampled (16% down, 10% up).
- **Systematic over-claim on grade**: explorers over-graded 14 nodes, under-graded 2 (7:1). Concentrated in 07 (A claimed 20, 15 survived), 02/09 on counts. Rule: treat explorer A as B-plus until a verifier recomputes the number.
- **Over-claim lives in numbers, not existence.** Identifiers resolved at about 100%, but about 15 load-bearing numbers drifted (ExploitGym, CyberGym "97%", Ferron, quinn 11 vs 12, workerd, Rust 1.99.1, wasmtime GHSA counts 81/57/41, x402 volumes, sc.rustsec 4-5x vs 2.3x). Same-repo advisory counts disagreed across explorers, so even A-grade counts need a single dated snapshot.
- **Narrative claims over-claim more than datasets**: "caught CVE-2026-34971" (unsourced), "fuel not a security bound", "iso-glue-not-boundary" contradicted by its own examples, cooldown-policy "no native Cargo support" refuted. Pattern: a punchy lesson node built from two examples. Demand three independent datapoints or grade C.
- **Underclaim is rare and fixable**: 17 up-moves came from verifiers finding the primary (PDFs, code public, Rebello fsync paper). Underclaim risk is in the skeptic direction: "unfixable / nobody shipped" was not tested. Round 2 needs explorers whose stance is to test a "solved" claim, not just to refute "unsolved".
- **Confidence is nearly uncalibrated by mean shift**: mean confidence delta explorer to final is -0.001 to -0.022 across explorers (tiny). Confidence barely moves when grade moves, so use grade, not confidence, for gating.
- **load_bearing is inflated**: about 203 of 327 nodes (62%) flagged load-bearing. The flag no longer discriminates. Planner: use load_bearing AND actionability >= 0.85 AND grade <= B as the "must two-sided check" set.
- **Verifier coverage was 52% and document-ordered** (about the first 15 per explorer, 15 of 15 for most; 02 only 12 of 29; 09 15 of 39). Unchecked nodes carry explorer calibration, which is biased up.
- **Grade E nodes (16)** cluster in authz (5), formal (2), state (3), isolation (2): LLM-style or unresolved claims. They are properly graded; keep out of decisions.

### D. Under-sampled domains and layers

- **Zero or near-zero**: W-PERF (1 node), W-OPS (1), W-DX (3), W-ABUSE (0). These were not targeted. They go first in round 2 as already planned.
- **Mandated areas with no coverage**: the §0b data-plane across backend families, the protocol-agnostic ingress plus modularity/leanness measurement, and §0c verification-toolchain disk/RAM footprint, golden vs third-party invariant survival.
- **Layer skew**: L5 is 29 of 327 (9%), and 14 of 29 come from one explorer; 0 L5 from transport (31 L4 nodes!), 0 from agent-protocols beyond 1, 0 from threat beyond 1. The §6 floor is 50% descend to L3-L5, but L5 artifacts (config pins, invariants, harness specs) are the repository's actual inputs. Round 2 should require each descend target to emit at least 3 L5 nodes.
- **Stance skew**: 78% proponent, 15% skeptic-negative, 7% attacker. Source skew: 3 forum queries of 473; era 77% 2025-26, 13% last-60d, 10% historical. Deployment-scale and vocabulary axes were not logged (see self_improvement item 2). Under-sampled: practitioner postmortems and operator forums (HN, lobste.rs, Reddit r/rust, vendor engineering blogs on failed migrations), negative results, benchmark logs from independent third parties, government/enterprise compliance sources (FedRAMP, CRA text, NIAP), household-VPS operator experience.
- **Pillars with high node count but low depth**: W-GAP (29 nodes, 0 L4), R+S (19, 0 L4), W-STATE (A-heavy but L3). Depth, not breadth, is needed there.
- **Pillar merging hid coverage**: explorers combined pillars (state+data-gate, supply+assure, transport+PQC). Round 2 should split W-STATE and W-DATA-GATE descents (data-gate is only 13 nodes, and all Postgres-centric).

### E. Research-method findings from the map itself (planner, §12)

1. **Cross-pillar root causes beat per-pillar lists.** The strongest round-1 insight (unauthenticated cross-request state as one root cause in DATA-GATE, PQC, MCP, ISOLATION) came from integrator bridging, not from any explorer. Reserve 1 target per round for a bridge hunt: pick a candidate invariant from section 3 of round-001.md and search for counterexamples in a pillar that has not been cross-linked (e.g. does the "no unauthenticated cross-request state" rule break in QUIC 0-RTT/session tickets, TLS resumption, idempotency keys, cache keys?).
2. **Recurring year-over-year defect classes are better evidence than single CVEs.** Top threat finding (H2/H3 resource exhaustion recurs in every stack) came from bulk advisory data across 10+ servers. Prefer queries returning a table over a case. Do the same for isolation, parsers, authz fail-open.
3. **Measure what the architecture decision turns on.** The isolation decision gained an A node from a 10-minute local bench; the supply-chain gates from real lockfile runs. Candidate round-2 measurements, each cheap: component-model call cost, ML-KEM handshake on 1 vCPU, binary size/RSS/dependency count for nginx/Caddy/Pingora/Envoy/HAProxy minimal builds, Lean toolchain disk/RAM footprint (without Mathlib), Verus+Z3 footprint, GCRA/adaptive limits under synthetic agent swarm.
4. **AI-found-bug surge distorts counts.** 2026 advisories per project (wasmtime 8 to 61 OSV rows; nginx 26; Envoy 37) are inflated by AI discovery and GHSA backfill. Any "N CVEs" claim must be reported with dedupe (GHSA+RUSTSEC dupes) and a date. Rank by class and exploitability, not count.
5. **Honest numbers need a source-table check.** Require `numbers_checked` in verifier output (self_improvement item 4). Highest drift: counts, percentages, volume claims, version numbers from LLM-style secondary text.
6. **Hit rate by source type (qualitative, from progress files)**: gh api advisories / OSV / KEV JSON > release notes and changelogs > RFC/IETF datatracker > author-hosted paper PDFs > vendor blogs > secondary news. Vendor-doc material is capped at D/C unless reproduced (Mythos Preview marked D).
7. **Selection insight for UCB**: with 12 targets in round 1, the UCB explore term was uniform. In round 2, rank by (a) mandate coverage (§0b/§0c), (b) layer deficit (L5 per pillar), (c) instrument change, and (d) frontier-queue priority; do not weight by round-1 node count (it correlates with survey breadth, not decision value).
8. **Retire into directions.md as exhausted**: W-GAP server survey, R+S survey, PQC key-agreement status, PDF-identifier existence. Re-open only with a named new instrument.

### F. Concrete round-2 plan hints (priority order)

1. §0b data-plane across backend families (relational, KV, document, object, streams, vector, search) with per-family injection/authz failure and Rust driver maturity table. Instrument: defect/CVE hunt plus driver audit. Emit L5: adapter capability IR sketch.
2. §0b ingress + modularity + lean measurement. Instrument: build and measure minimal binaries (size, deps, unsafe LOC, idle RSS) for nginx, Caddy, Pingora, Envoy, HAProxy, plus a hyper+rustls hello. Cheap and A-grade.
3. §0c verification footprint and golden/third-party invariant survival (Lean without Mathlib, Verus+Z3, Kani, F*). Instrument: install and measure disk/RAM, or read release sizes.
4. W-ABUSE (zero nodes), W-PERF, W-OPS, W-DX, as planned, each with a measured or artifact instrument.
5. Two-sided calibration of the most load-bearing round-1 claims, focusing on numbers (tables above), with the unverified 48% of nodes ordered by load_bearing AND actionability. Include skeptical probes of "solved" claims (PQ KEX solved; Cedar sole policy engine; embedded stores all flawed; MCP stateless; 81% non-memory KEV) in the "claim is wrong in the other direction" form.
6. L5 harvest: one target that converts round-1 L4 nodes in transport/threat/DB-gate into harness specs, config pins, invariants (H2 decoded-size budget oracle, SET LOCAL ROLE reproducer, PQ downgrade HRR test).
7. Under-sampled source/stance targets: negative-result and attacker stance, forum/practitioner postmortems, government compliance.

## HISTORY

### 2026-10-24, after round 1 (META-OPTIMIZER)
- Created this file. Ranked 12 lenses, identified instrument-based lenses as the top yield, listed exhausted lenses, calibration drift (7:1 over-claim on grade, numeric drift, inflated load_bearing, 52% sequential verifier coverage), the zero-coverage pillars (W-ABUSE, W-PERF, W-OPS, W-DX) and mandated §0b/§0c areas, layer skew (L5 9%, half from one explorer), and stance/source skew (78% proponent, 3 forum queries).
- Caveats: round 1 has no prior round, so mechanical novelty (1.0) cannot rank lenses; ranking uses node layer/grade/verifier movement. The L4/L5-per-query column in directions.md is distorted by pillars that are L3-by-construction and by queries-per-node differences; do not use it alone. Some verifier outcomes are sampled (52%), so per-explorer down-rates are noisy (n about 15 each).
