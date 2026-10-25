# AEGIS lenses (state/lenses.md)

Maintained by the META-OPTIMIZER after each round. Append dated sections. Never delete earlier lessons. Newest guidance first in the "CURRENT" block, history below.
Evidence base for entry 2026-10-24: reports/round-001.md, graph.jsonl (327 non-merged nodes), queries.jsonl (473), directions.md, per-explorer raw JSON and progress files. Round 1 had no earlier round, so "novelty" is trivially 1.0 and yield is measured by node quality (layer, grade, verifier movement), not by novelty.

## CURRENT GUIDANCE (after round 4; apply to the next planning step, §12)

Evidence base for the 2026-10-25 (post-r4) entry: reports/round-004.md, graph.jsonl (179 non-merged r4 explorer+verifier nodes; per-explorer cross-tab recomputed from graph.jsonl), self_improvement.md r4 proposals. Verifier coverage 85% (150/176). Per-explorer n is 3-20, so rates are noisy.

### A4. Round-4 lens ranking (n = new non-merged nodes; L45 = L4+L5; down = verifier moved grade down)

| rank | lens / instrument (explorer) | n | L45 | L5 | A | C-E | down | verdict |
|---|---|---|---|---|---|---|---|---|
| 1 | Resolver/metadata + pinned-crate probe at the golden pins (03 FIPS triangle) | 8 | 8 | 7 | 7 | 0 | 0 (2 up) | Best calibrated and most decision-relevant: crates.io metadata alone proves the empty triangle. Pure instrument + control, no modelling. |
| 2 | Primary-document sweep in non-English/non-US sources, pdftotext (10 non-US PQC) | 20 | 17 | 3 | 8 | 2 | 6 | Highest yield per query (1.06) and the only direction change (R-PQC-3). Down-moves are "national primaries not re-fetched by verifier" (version-pinned snapshots), not wrong claims. |
| 3 | Executed differential oracle across engines (02 write path; 01 lean-check) | 11 / 20 | 11 / 19 | 3 / 8 | 9 / 14 | 0 / 1 | 0 / 4 | Lean: first-ever execution falsified the r2 "proven" claim and the r3 draft, 8 L5. Write oracle: 0 down, 261/300 leak reproduced on 3 engines. Down-moves in Lean are checker-independence and release attribution, not the proofs. |
| 4 | Executed corpus differential across implementations (07 bridge) | 17 | 13 | 5 | 7 | 5 | 4 | Strong core (zero-disagreement canonicalizer, 3 unreported upstream issues) but 5 C-E: tail nodes are policy restatements. Keep the instrument, cut the tail. |
| 5 | Compiled mutants on real framework (05 DX) | 12 | 9 | 3 | 1 | 1 | 4 | Real answer (25/32 vs 16/32 vs 3/32) but only 1 A: mutant sets are our own construction so verifiers cap at B. Add an external-mutant control next time. |
| 6 | Fault injection with control (04 isolation) | 18 | 14 | 4 | 3 | 2 | **9** | Most over-claimed per node: single contended laptop, naive native baseline. Findings stand as B with ratios; absolute numbers C. Do not run again without an idle host or a replicated second machine. |
| 7 | Historical/regulatory-standard reading (09 safety-critical) | 15 | 11 | 3 | 0 | 4 | 2 | Produced the DO-330 / TQL-5 / SA-17 bridge (a real design argument) but zero A: standards text graded B at best. Use for argument structure, not for numbers. |
| 8 | Hand-coded dataset from incident postmortems (11 UU) | 16 | 11 | 4 | 1 | **8** | 2 | Produced the only novel threat-model finding (0/160 outages from memory corruption), but half C-E: n=160 hand-labelled, one coder, duration median did not reproduce. UU works only when a dataset is built and counts are scripted. |
| 9 | MCP conformance executed (06) | 8 | 8 | 3 | 2 | 1 | 3 | Low yield (0.47) and 3 citation mismatches (#553/#570). Executed, but the claims riding on it cite issues that say other things. |
| 10 | Forum demand mining (08 switching) | 12 | 2 | 0 | 1 | 6 | 6 | Dead as a node source (0.02 L45/query). Valuable as ONE negative result (0 of ~8,175 comments name PQ) which is itself C. Retire unless a different instrument (procurement RFP texts, survey data) is named (q4-003). |
| 11 | Two-sided calibration of prior top findings (12) | 3 new + 13 rev | 3 | 2 | 3 | 0 | n/a | Cheap and necessary: found 9 stale grade tags, Swarm D, FIPS range error. Count revisions, not nodes, as yield. |

Verifier-promoted `v4.*` nodes (19): 8 of 19 are A; best value per verifier hour came from the cooldown/webpki and checker-disagreement items. The verifier "missed" list is a productive second explorer.

### B4. Dead or exhausted (add to earlier lists)

- Forum thread mining for demand (08): retired. Logged as queries it distorts diversity and dup metrics.
- WebFetch on PDFs and cyber.gov.au / ec.europa.eu / media.defense.gov / reddit / lobste.rs: blocked or useless; use pdftotext on saved files, the GitHub OSCAL repo, ENISA, cellar, Lemmy/Discourse/HN Algolia.
- More single-laptop absolute performance numbers (isolation, IPC, handshake): C unless idle host. They belong to the implementation spikes on a real VPS (q3-001/002, q4-006).
- MCP SDK default-reading without execution: covered; the open MCP work is q4-001 style SDK extension, not more conformance.
- Re-deriving the FIPS lock, Lean soundness record, Wasmtime M0 rate: done three times by two explorers each. Closed unless a version bumps.

### C4. Calibration drift (round-4 evidence)

- Over-claim ratio at the verifier fell from 13:1 (r3) to 2.9:1 (43 down vs 15 up of 150). The r3 recommendations (read/recomputed/modelled tags, medians, files for proofs) worked. Drift is now narrower and specific.
- Remaining systematic over-claim classes, by size: (1) single-machine experiments graded A (isolation: 9 down of 18); (2) citation does not say what the node says (conformance #553/#570, PR #15156, HotOS'19, Django 34225): about 8 nodes; (3) own mapping presented as data (kernelCTF reachability); (4) absence-of-evidence from thin samples (forums C/D); (5) checker independence overstated (6 checkers share a kernel and a frontend); (6) version-pinned snapshots left as A without a pin date.
- Under-claim: 15 up, concentrated in resolver/metadata and primary-source facts (FIPS, national regimes, upstream issue confirmations). Explorers under-grade facts that reduce to one crates.io/GitHub API field. Allow A 0.9+ when the claim is one fetched machine-readable field plus date.
- Stale-tag rate is a process problem, not an explorer problem: 9 stale tags in the draft in r4 (3 in r3). Lint the draft against the graph every integration.
- Phantom proof: the r2 "combine_failclosed proven" had no file. Rule stays: no proof above C without path + gate log.
- Calibration-explorer finding: planning values repriced, not refuted (Wasmtime 2.21/yr; Kani #4910 0.85 to 0.5). Predictions drift down in p when they depend on upstream release dates: apply a 0.8x prior to any "release by date" prediction.

### D4. Under-sampled domains and layers

- Pillars: W-STATE, W-ABUSE, W-PERF, W-OPS had 0, 0, 1, 1 new nodes; W-UNKNOWN, S-FORMAL-WEB, K, R-HISTORY, W-DX, W-ASSURE, W-THREAT were thin before r4 and only partly refilled (DX, ASSURE, THREAT got a target).
- Axes: benchmark sources 3, database vocabulary 9, web-dev vocabulary 8, household scale 12, historical era 22, last-60d era 26, attacker stance 34. L1-L3 are now only 20% of new nodes; that is fine for a descend phase but means few new hypotheses are entering.
- Mongo/MySQL write path, CockroachDB RLS, Valkey ACL beyond the prefix side-channel: open (q4-005, q3-006 partial).
- Procurement texts (FedRAMP/CNSA/CRA) as an evidence source for demand (q4-003): the one remaining research-not-spike item with a reversal rule (R-GAP-4).
- LLM-found vs human-found advisory rates (q1-009) still open; R-THR-2 rests on it.

### E4. Research-method findings from the round-4 map (planner, §12)

1. **Diminishing returns are on the decisions, not the nodes.** Mechanical novelty is 0.909 but decision stability is 0.988 (85/86 rules kept direction; 1 direction change, from non-US primary documents). Of the 11 new rules, most extend rather than reverse. Use decision stability plus strict-singleton rate (0.22, down from 0.29) as the stop signal, not URL novelty: URL novelty will stay high on executed instruments forever.
2. **Instrument changes produced the flips; breadth did not.** Every top-10 finding came from executing something on a pin (Lean, Postgres/SQLite, resolver, 12 parsers, axum, fault injection) or reading a primary document in a new language. Surveys and forums produced none. Descend-with-an-instrument remains the dominant strategy; keep the §0d(b) requirement.
3. **Executed work falsifies earlier prose.** Lean falsified a graded A, write oracle falsified the "WITH CHECK covers it" assumption, the resolver falsified the "one lock" assumption. Plan one explorer per round whose only job is to execute a prior-round claim that is still stated or source-read only (check by grepping the graph for "measured"/"executed" first).
4. **Remaining load-bearing uncertainties are spikes, not literature.** Of the 14 top frontier items 12 close by implementation-phase spikes (real VPS, MySQL write oracle, false-reject rate on real traffic, fuel budget, 0x11ED KxGroup). q4-003 and q1-009 are the only research items. This is the argument the plan notes already make (§0c) and it holds after r4: pivot unless the planner can name a decision with a reversal rule that research could flip.
5. **Pairs of explorers duplicated work (3 merges; one version-range contradiction).** Give the planner a numbers-touched manifest and the calibration explorer the same manifest. Integrator-side id/version-range dedup.
6. **Forum and UU targets inflate the query log.** Count only `search` kind in metrics; log fetches as `fetch`. Report diversity with and without the largest explorer.
7. **UU yield depends on building a dataset.** The one UU target that did (incident table) produced the only new threat-model class. Adjacent-field reading (r3) did not. Keep UU slots only for targets that name a dataset and a scripted count.
8. **Verifier "missed" lists produce 19 promoted nodes at no extra explorer cost.** Keep them, and have verifiers write verdict + missed files (fifth round it is not done: now a data-loss risk).
9. **Strict-singleton nodes (40) cluster in executed work (wpo, r4e07, r4i04, uu11).** These are the novel part; pair each with a neighbour-pillar edge, as the bridge step did (21 integrator bridges).

### F4. Concrete next-step hints (priority order)

1. Default after r4: pivot to implementation, treating the queue as spikes (§0c, E3.1). A round 5 is justified only for: (a) q4-003 procurement texts with a reversal rule on R-GAP-4; (b) q1-009 LLM- vs human-found advisories; (c) a three-valued reference Lean re-proof (q4-004), which is executable, small and flips the R-DB-7 spec freeze; (d) MySQL/Mongo write oracle (q4-005).
2. If round 5 runs: <=8 targets, 6+ descend with a named instrument on a pin, 1 UU with a dataset, 1 calibration with a numbers-touched manifest. At most 2 compiling explorers concurrently (the crash was memory exhaustion); every brief states RSS cap and runs builds under heavy.sh with `systemd-run --scope -p MemoryMax`.
3. Mandatory brief lines: progress file within 2 minutes; per-explorer clone dirs; source-access preflight (blocked-site list above); executed-command logs saved; one pillar per target in canonical W-* form; `kind` column on query log; verifier verdict file path stated; grade ceiling rules (proof needs file + log, press claim stays secondary, single-machine perf caps at B).
4. Prefer replication over novelty for the isolation and DX results: run the isolation table on a second machine or idle window; build an external mutant set for DX.
5. Cover W-STATE, W-ABUSE, W-PERF, W-OPS only via spikes with executable harnesses; do not open literature targets there.

### History entry

#### 2026-10-25, after round 4 (META-OPTIMIZER; post-crash, memory-exhaustion recovery)

- Round 4: 182 new nodes (80% L4/L5, 59 A), 31 revisions, 11 new rules, 28 amended, 1 direction change (R-PQC-3); decision stability 0.988; mechanical novelty 0.909; Good-Turing 0.88; strict singletons 40; verifier over-claim ratio 2.9:1 (from 13:1).
- Best lenses: resolver/metadata and pinned probes (03), primary documents in non-English sources (10), first-time execution of long-unchecked artifacts (01 Lean, 02 write oracle), cross-implementation differential corpus (07). Worst: forum mining (08), single-laptop absolute numbers (04), standards-reading without executables (09), MCP default-reading (06).
- Calibration moved from "everything over-claimed" to specific classes (single machine, citation mismatch, own mapping, thin-sample absence). Under-claims exist for one-field machine-readable facts.
- Method findings: stop on decision flips not URL novelty; calibration needs a numbers-touched manifest; UU needs a dataset; verifier files still not self-written; memory safety: cap RSS per heavy job.
- Planner recommendation: pivot to implementation; a round 5 only for the four named research or small-Lean items.

---

## PRIOR GUIDANCE: AFTER ROUND 3 (superseded by the block above, retained, never deleted)

## (formerly CURRENT) GUIDANCE after round 3; apply to round 4 planning, §12

Evidence base for the 2026-10-25 entry: reports/round-003.md, graph.jsonl (207 new r3 nodes, 11 explorer-12 revisions, 12 integrator corrections), per-explorer cross-tab computed from graph.jsonl (layer, grade, verifier direction), the yield table and metrics (url novelty 0.881, direction diversity 0.366 / 0.572 with vocab, Good-Turing 0.96, decision stability 0.958). Verifier coverage 76% (161/211), n is 12-23 per explorer, so per-explorer rates are noisy.

### A3. Round-3 lens ranking (new non-merged nodes; L45 = L4+L5; down = verifier moved grade down)

| rank | lens / instrument (explorer) | n | L45 | L5 | A | C-E | down | verdict |
|---|---|---|---|---|---|---|---|---|
| 1 | Executed tooling on the golden pins with a control (04 supply: cargo 1.98 cooldown, repro-build ablation, geiger/vet/deny) | 22 | 22 | 6 | 14 | 1 | 4 | Best overall. Every node L4+, 64% A, 3 of the round's top-10 findings (cooldown lands PQ downgrade, FIPS-vs-lock conflict, 3-flag remap repro). Cheap, decision-flipping because it intersects other pillars (bridge to PQC). |
| 2 | Hand-built protocol probes against pinned crate (03 PQ auth: crafted ClientHellos vs rustls =0.23.46) | 16 | 16 | 5 | 10 | 0 | 1 | Best calibrated: 0 C-E, 1 down. Produced a direction change (R-PQC-1). Positive and negative control plus pinned version is the recipe. Skeptic-on-size stance paid. |
| 3 | Measured micro-benchmark with controls (02 IPC spike) | 14 | 14 | 9 | 8 | 3 | 6 | Highest L5 share (9/14), but 6 down: absolute numbers from a laptop/contended core and "policy from one number" got marked down. Class-level and ratio claims stand; cap absolute us at B and record loadavg/cpuset. |
| 4 | Executed differential oracle on real engines (01 IR soundness: SQLite, PG 17/19rc1, Redis matcher) | 17 | 14 | 5 | 11 | 2 | 7 | Found a leak in every naive lowering, and in the explorer's own hardened form. Down-rate 7/17 is mostly wording/attribution around the oracle, not the oracle. Lean file itself still unexecuted (q3-020): the formal half of this target did not run. |
| 5 | Own simulator (07 abuse) | 19 | 19 | 5 | 1 | 17 | 2 | Converted E into D (R-ABUSE-1 E->D) and found a structural collapse (99.1% human failure), but grade is capped at D until the cost scale is measured. Judge by decision movement, not grade. Verifiers rarely mark a clearly-labelled simulation down: so low down-rate here is honest labelling, not strength. |
| 6 | Bridge hunt with one invariant and >=10 instances, via `gh api` issue search (06 cancellation) | 23 | 17 | 4 | 12 | 2 | 5 | Largest and most cross-pillar (15 instances in 5 ecosystems, INV-NOMUT-C, 19-edge bridge set). 55 queries for 0.31 L45/query: lowest efficiency of the productive lenses. 5 explorer-to-verifier inflations: instance-to-class leaps and fix-state errors (RUSTSEC-2025-0070 is pingora, not hyper). |
| 7 | Code-level read with local PoC (05 authz token: census, Tenuo, verify microbench) | 18 | 14 | 4 | 7 | 3 | 2 | One security finding (Tenuo cel attenuation bypass, confirmed locally, unfixed on main) and the E->B decision. 28 queries, 0.50/query. Census part is reading, mostly B. |
| 8 | Network-SRE vocabulary at hyperscaler scale (10 reload) | 23 | 13 | 2 | 9 | 3 | 3 | Fine yield (24 nodes) but 10 L3: mechanism survey. Two of its L4s were ups (nginx QUIC live upgrade, SO_REUSEPORT CVE). Retire survey; only measurement (q3-033) remains. |
| 9 | Attacker-stance bulk resolution of OSV/`gh api` for non-HTTP front ends (09) | 17 | 16 | 2 | 4 | 5 | 8 | Highest L4 density per query (2.67, queries under-logged) but worst calibration of the productive group: 8/17 down, 5 inflations. Matrix scoring ("core-once") and static reads (tonic `None`) were self-scored or unrun. Needs the runtime check it names. |
| 10 | PL-formal skeptic on agent-checkable DX (08) | 12 | 8 | 1 | 0 | 6 | 7 | Weakest lens with an instrument. Zero A, 7/12 down: benchmark independence (Claw-SWE vs SWE-bench Multilingual), misused papers. No experiment ran. A stub compile-feedback experiment (q3-012) must precede any more DX reading. |
| 11 | Unknown-unknowns by adjacent-field vocabulary / patents / datasets / non-English (11) | 17 | 4 | 0 | 7 | 6 | 2 | 0.11 L45/query by design. 4 of 17 L45, no L5, load_bearing 4. Its one durable artifact was the shared `_advisories/` snapshot. Value is as feed and as negative evidence, not as nodes. Keep at most 1 slot and judge by "which queue item did it unblock". |
| 12 | Calibration (12) | 0 new, 11 revisions | n/a | 0 | n/a | n/a | 4 down, 5 up (verifier pass) | Again the highest decision value per node: recomputed from raw logs (handshake PQ +12.5-15.0%), denominators (6/65 -> M0 rate 0.36-2.0/yr), re-ranked top findings. Keep. |

Verdict (r3): r1/r2 finding holds and sharpens. **Run the released artifact or pinned crate, with a positive control and a recorded threat to the instrument** won again (04, 03, 01, 02). Simulators grade D until their cost scale is measured, but still beat reading (07: E->D). Pure reading lenses (08, 09 matrix parts, 10, 11) land at C-E or get marked down 40-60%. Layer density of new nodes: L4 58%, L5 21% (44/207), L45 80% (r2: 73%); the 3+ L5 quota worked for every descend target except 08.

### B3. Dead or exhausted (add to r1/r2 lists; retire unless a new instrument is named)

- Literature on ingress front-end defect classes (WS, gRPC, GraphQL, webhook, SSE, PROXY): only runtime checks remain (q3-032). Do not re-survey.
- Token-format surveys: 15 candidates, 11 libraries censused, decision made (R-AUTHZ-2 B). Only the Tenuo private disclosure and R-AUTHZ-6 conformance remain.
- rustls server group-selection semantics: executed, frozen (R-PQC-1 per listener). Recheck only when PreferServerOrder ships.
- Cooldown semantics: executed on cargo 1.98; recheck on 1.100 stable only.
- Lowering hazards in SQLite/PG/Redis for reads: executed. Remaining: write path, OpenSearch, timing (q3-006, q3-015).
- Reload-mechanism surveys (5 mechanisms, 6 systems): done; measurement only.
- Advisory pulls of any kind (wasmtime, tokio, rustls): use the shared snapshot `state/raw/round-003/_advisories/`; delta since 2026-08-25 only. Three explorers still re-pulled overlapping sets despite the r2 retirement, so this must be enforced in briefs, not just noted.
- Slide-only / adjacent-field "UU" sweeps as a standalone target: 0.11 L45/query; fold into descend targets as a single "adjacent-vocabulary" query each.
- Benchmark-independence claims for DX (Claw-SWE etc.): closed, C.

### C3. Calibration drift (round-3 evidence)

- **Over-claim ratio 13:1 (52 down : 4 up)**, 32% down, 2% up, 65% unchanged of 161 (r2 3:1; r1 1.6:1). The trend is monotone across three rounds. The integrator reads it as a sharper verifier plus harder sources, since most down moves were attribution or modelled-as-measured, not refutations. Treat it as a planner constraint anyway: explorers are systematically **over-claiming on the provenance and labelling of numbers**, not on the existence of findings.
- **Per-explorer down share of new nodes**: 08 58%, 09 47%, 01 41%, 02 43%, 06 22%, 04 18%, 10 13%, 05 11%, 07 11%, 11 12%, 03 6%. Expect 40-60% down for a pure-reading or self-scored-matrix explorer, 40% for a fast micro-benchmark on a shared host, 5-20% for a pinned-version probe with controls.
- **Where grades inflated (explorer -> final)**: (1) modelled values presented as measured (QUIC datagram counts, swarm CPU scale, 1-vCPU and Lean timing projections); (2) source misattribution on identifiers that exist (RUSTSEC-2025-0070 pingora vs hyper, pgx#679, rust-postgres URLs pointing at rust-lang, CVE-2026-58494 date, Red Sift numbers are OpenSSL); (3) range errors on versions (aws-lc-rs FIPS range), "four" CVEs that are three; (4) independence (shared task pool); (5) self-scored matrices (incident gates, core vs per-front-end classes) graded above C; (6) policy derived from one measurement (adapter OOP threshold from one laptop number). Explorer-to-final grade downgrades concentrated in 06 and 09 (5 each), 08 (3).
- **Where it under-claimed (4 up)**: defender-side facts found late (nginx QUIC live upgrade, SO_REUSEPORT CVE at INCIBE). The r2 fix ("state of fix on main at date X" on every bug node) was applied: 3 fixes found main-only/unreleased were recorded up front. Keep.
- **Calibration explorer 12 effect**: 11 revisions, mostly recomputing from raw logs and denominators. Pattern: a headline "best trial" or share-of-total that is not in any log. Mandate in every brief: report median and raw-log location, never the best trial.
- **Confidence still does not track grade**; load_bearing flagged on ~58% of nodes (122/207 by count of lb). Keep gating on lb AND L4+ AND A/B AND decision text.
- **New check to require**: for every number in a bug or benchmark node, `numbers_checked` must say whether it is "read", "recomputed from raw", or "modelled". Verifiers marked down 15+ nodes for exactly this.
- Net grade distribution of the 207: A 87 (42%), B 70, C 28, D 19, E 3. D/E are almost all 07 (simulated, labelled) and 08.

### D3. Under-sampled domains and layers (round 4 targets, if another research round is justified at all)

- **Cells still empty (r3 queries)**: economics vocabulary 5 (all abuse), household scale 1, forum 4, talk 1, patent only in 11, dataset 0, non-English 0 (the UU brief asked for them and still logged 0 non-English; verify the explorer actually ran any, or drop the claim).
- **Pillars with no round-3 target and thin counts**: W-ISOLATION 2 nodes (both incidental; M0 escape rate 0.36-2.0/yr could flip R-ISO-1), W-AGENT-PROTOCOL 2, W-FORMAL 4 (Lean has not been executed in three rounds). These are the largest unexplored pillar areas and W-ISOLATION is a load-bearing decision.
- **Stance**: proponent 201/290 = 69% (r2 56%), skeptic 21%, attacker 10%. It slid back. Make the mandate per explorer: at least 30% of queries skeptic or attacker, and name the claim being attacked.
- **Era**: 2025-26 88%, last-60d 9%, historical 3%. Historical (pre-2023 analogues) is nearly unused; relevant for formal-methods cost curves, PQ-migration (SHA-1, 1024-bit RSA sunset), and zero-downtime upgrade prior art (HAProxy, OpenSSH, Erlang hot code).
- **Vocabulary**: systems 34%, standards-policy 12%, offensive 12%, cryptography 10%, web-dev 10%, PL-formal 9%, database 7%, network-SRE 5%, economics 2%. Economics, network-SRE, PL-formal are thin; "safety-critical / avionics assurance" and "game-server / anti-cheat" are unused vocabularies.
- **Layer**: no L1/L2 content beyond 8 nodes; fine. L5 artifacts exist and are executed for transport, supply, data-plane reads, IPC, token; still **unexecuted**: Lowering.lean (SPK-LEAN-IR-1), window-0 stall harness, double-fault crash stage, mutants vs real axum, Kani/Verus RAM. The best L5 next is an executed harness, not another drafted one.

### E3. Research-method findings from the round-3 map (planner, §12)

1. **The binding constraint moved from literature to implementation spikes.** Of 15 top frontier items, ~11 are spikes (q3-001/002/005/008/012/013/020, q2-009/013, q1-013). Decision stability 0.958 with 68/71 rules unchanged says more reading does not flip decisions; only four areas can (R-ISO-1, R-PQC-2 triangle, R-ING-1 runtime, R-DB-7 Lean, R-ABUSE-1 calibration). Planner rule: a research target is selectable only if it names the rule id it could flip AND no spike with a protocol already covers it. Per §0c, after the round cap the default is build.
2. **Novelty is saturating on the wrong signal.** URL novelty 0.88 and unseen mass 0.96 are driven by the world (2026 advisory wave, ~50 new advisories a week), not by map coverage. Use decision-flip count and strict-singleton rate (0.29, r2 0.43, falling) as the stopping signals; strict-singleton falling is the real convergence evidence.
3. **Descend beats explore on specificity but explore found the three direction-relevant bridges.** Descend targets: 80% L45. UU/explore reading targets: 24% L45. Keep explore at <=20% and tie each to an open queue item instead of a vocabulary quota.
4. **Bridge hunts and executed oracles find cross-pillar facts that single-pillar descents miss**: the FIPS-vs-golden-lock conflict came from supply x PQC; drain = cancellation from reload x async; the NC3 checkin predicate from cancel x data-plane. Planner: always give each executed-tooling target a "neighbour pillar to interfere with" field and require a bridge edge in its output.
5. **Cheap executed tooling > expensive build.** Highest yield per hour came from running a released binary/crate with a control (04, 03, 01). Two crash/queue problems cost time: heavy.sh did not serialize two jobs launched 3 s apart, and pure-python jobs blocked behind builds. Add a light-job lane before the next round.
6. **Yield per query is a misleading efficiency measure** (09: 2.67 via bulk OSV resolution with under-logged queries; 06: 0.31 with 55 logged queries, yet 06 produced more cross-pillar structure). Use L5 count and bridge-edge count per explorer-hour instead, and log bulk resolutions as queries.
7. **Verifier is now a first-class instrument.** 76% coverage, 52 down, found misattributions the explorers could not see. Require verifiers to write `_verify_rNNN_verdicts.json` themselves (the orchestrator payload was the only copy again; this cost the integrator 161 re-keyed verdicts after the crash). Raise coverage to 100% for load_bearing A/B nodes.
8. **Crash recovery works if work is checkpointed in-file**: explorers appended `<nn>-nodes.jsonl` as they went, so the integration restarted clean. Progress files within 2 minutes are still missing for several explorers; make the first progress write a gate before any web query.
9. **novelty_gate weaknesses to fix before round 4**: `topic` false COVERED on generic tokens and unrelated nearest nodes for DX; needs aspect tags and incident-id matching (two same-incident re-nodes got merged post hoc).
10. **Prediction ledger**: 34 predictions, 10 added; none graded yet. Add a resolve-by date and score at least the dated ones (e.g. rustls PreferServerOrder release, sqlx f1e94ec release, AWS-LC 4 CMVP) at the next round.

### F3. Concrete round-4 plan hints (priority order, only if the planner judges another round worth it)

1. Prefer **executing** over researching: (a) check Lowering.lean in Lean core (q3-020; E->A for R-DB-2/7), (b) q3-004 golden version triangle in one lock (rustls floor + prefer-post-quantum + FIPS pin), (c) q3-012 mutants/LLM trial on SDK shape A vs B with a stub axum crate, (d) q3-001/002 on a real 1-vCPU VPS if one can be rented, else leave for build phase. Keep to <=3 compiling explorers at once.
2. One **W-ISOLATION** descent with an instrument (wasmtime escape-rate table is sourced from advisories; test M0-vs-process boundary cost with the 02 bench harness) because R-ISO-1 is load-bearing and has the thinnest evidence.
3. One **W-FORMAL / W-AGENT-PROTOCOL** pair only if it ships an executed artifact (Lean or Kani run on a small TBI harness). No reading-only formal target.
4. Write-path lowering soundness (q3-006) as the extension of explorer 01's oracle (reuse the harness, add UPDATE/DELETE/upsert, tenant column mutation). Highest expected L5 per hour from the existing code.
5. Swarm sim v2 (q3-005) only after q3-001 gives a real handshake cost; otherwise the next result is again grade D.
6. Calibration explorer again with the same recipe, plus a scoring pass over the prediction ledger. Give it the `_advisories/` snapshot and the 52 downs list, and ask it to re-verify the top-12 findings above.
7. Cap UU/explore at one slot; require each to name the queue item it would unblock.
8. Brief requirements for every explorer: numbers tagged read/recomputed/modelled; fix state on main; stance quota 30% skeptic/attacker; log bulk resolutions as queries; first progress write before the first web query; verdict files written by verifiers.

### History entry

#### 2026-10-25, after round 3 (META-OPTIMIZER)

- Round 3 produced 207 new nodes, 80% L4/L5, 44 L5, 87 A, with 13:1 over-claim ratio at the verifier (sharper, with source-misattribution and modelled-as-measured as the main classes). Decision stability 0.958; 3 direction changes (R-PQC-1, R-MOD-1, R-PQC-3).
- Best lenses: executed tooling on golden pins (04), crafted-protocol probes against a pinned crate (03), executed differential oracle (01), micro-bench with ratio claims (02), cross-pillar bridge hunt (06). Worst: DX reading (08), adjacent-field UU (11 as nodes), attacker-stance bulk matrices without a runtime check (09 calibration).
- Method changes recommended: stop-signal = decision flips + strict singleton rate; verifier writes verdict files; light-job lane in heavy.sh; numbers_checked tagged read/recomputed/modelled; stance quota; advisory snapshot is mandatory input; execute Lowering.lean before any further data-plane research.

## PRIOR GUIDANCE: AFTER ROUND 2 (superseded by the block above for round-4 planning, retained, never deleted)

## (formerly CURRENT) GUIDANCE after round 2

Evidence base for the 2026-10-25 entry: reports/round-002.md, graph.jsonl (204 new round-2 nodes plus 24 revisions), the per-explorer cross-tab computed from graph.jsonl (layer, explorer grade, verifier direction), directions.md, and the metrics (mechanical novelty 0.877-0.898, direction diversity 0.382). Round 2 was far from saturation (Good-Turing unseen mass 0.975), so lens ranking is by quality, not by novelty alone. Caveat: verifier coverage was 80% (168/211), but verifier outcomes are per node, n is 8-27 per explorer, so per-explorer rates are noisy.

### A2. Round-2 lens ranking (new nodes; L4+L5 = specific; L5 = repo artifacts; down = verifier moved grade down)

| rank | lens / instrument (explorer) | nodes | L4+L5 | L5 | A | down | verdict |
|---|---|---|---|---|---|---|---|
| 1 | Own measurement with controls and negative results: crash-consistency rig, 130k images, 7 stores (08) | 15 | 11 | 8 | 9 | 1 | Best. Highest L5 share (8 of 15), lowest down-rate, only lens that produced a method finding (LD_PRELOAD blind to rustix). A positive-and-negative control is what made the A grades stick. |
| 2 | Spec-and-source forensic read plus invariant drafting: h2/hyper grep at pinned versions, TBI-1..9 (06) | 16 | 16 | 6 | 4 | 4 | Every node L4+. Strong L5, but 10 B and 4 down: invariants are specs, so B at best until a harness runs (q2-009). |
| 3 | Footprint measurement of tools and incumbents (02, 03) | 32 | 29 | 9 | 18 | 10 | 03 (verification footprint) 21 nodes, 6 L5, 12 A, but 7 down: the A claims were numbers from release pages, and two failure claims (Kani OOM false PASS, Lean kernel bugs) needed re-checking. 02 (lean binaries) 11 nodes, 6 A, 3 L5. Cheap, decision-relevant, and shared the benchmark-contention problem. |
| 4 | Isolation measured plus advisory table (07) | 8 | 8 | 5 | 4 | 2 | Small but dense: 5 L5 of 8. Round 2 changed the instrument from survey to bench and it paid again. |
| 5 | Agent-gateway CVE corpus mapped to invariants (09) | 15 | 15 | 4 | 4 | 3 | Best-calibrated on numbers (numbers_checked with API source). L4 everywhere. Repeat only for new SDK repos. |
| 6 | Data-plane family sweep with attacker stance (01) | 27 | 23 | 3 | 13 | 4 | Largest haul, A-heavy, 3 L5 (IR, allowlist lock, adapter isolation). Per-family CVE hunting produced the round's only suspect ids. Mechanism questions work, id quotas do not. |
| 7 | Talks and non-English scan (11) | 23 | 16 | 0 | 10 | 3 | 7 C nodes, 0 L5. Found real items (JVN VU#885548 stall, Opossum, Cloudflare unwrap outage) but slide-only sources capped at C; value is as a feed into pillar descents. |
| 8 | Ops, compliance, government (05) | 12 | 8 | 5 | 2 | 4 | 5 L5 but 4 of 12 down and only 2 A. WAF-blocked government domains and a crash; sources are legal prose, so numbers and dates drift (CRA, FedRAMP KSI counts). Needs fetch fallbacks. |
| 9 | Abuse under swarms (04) | 22 | 7 | 3 | 3 | 4 | Weakest. 11 L3, 7 C/D/E, parameters grade E. No instrument ran; the L5 pipeline and budget invariants rest on forum/incident writeups. Needs the simulation (q2 swarm DST) before any further reading. |
| 10 | Cross-request-state bridge hunt (10) | 20 | 4 | 3 | 6 | 6 | Not L4/L5-dense (15 L3 counterexample classes) but produced the round's main cross-pillar invariant (CRS C1-C8) and 3 L5. Judge by bridges, not layers. 6 of 20 down: counterexample classes built from two instances. |
| 11 | Calibration (12) | 1 new, 20 revisions | n/a | 0 | n/a | 4 down, 5 up of 21 | Productive because it recomputed numbers with per-year bands; moved 9 of 21. Unproductive on identifier existence (r1). |

Verdict (r2): the r1 finding holds. **Run it, measure it, with a control** beats read it. New refinement: the best lens was not just "instrumented" but "instrumented with a deliberate negative or positive control and a recorded threat to the instrument" (08, 06's grep-at-pinned-version, 03's range reads). Reading lenses on legal or policy text (05) and incident forums (04) over-claim parameters. Layer-density of new nodes: L4 51%, L5 23% (46/204), up from L5 9% in round 1, so the per-target L5 quota worked and should stay at 3+.

### B2. Dead or exhausted (retire unless a new instrument is named); r1 list in the history block still applies

- Wasmtime advisory list pulls (3 independent pulls): done; snapshot in raw/round-002/07-data/. CERT VU lists for Rapid Reset / CONTINUATION / MadeYouReset: done.
- Per-family DB CVE quota hunting (id quotas): retired. Replace with mechanism questions plus a required numbers_checked primary URL.
- Anubis/PoW survey reading: done; only an accessibility audit or JA4 false-positive measurement remains.
- Rustls default-group re-checks (01 and 12 both did it, J=0.86): closed; any new PQ claim must cite the shared crate-default snapshot.
- MCP SDK advisory corpus (58 rows): extend only for new repos (Ruby/Kotlin/PHP SDKs, litellm, context-forge).
- Slide-deck-only talk sources (DEF CON media root URLs): capped at C; do not target unless a paper or repo exists.
- Identifier existence and unmeasured "N CVEs per project" counts: closed.

### C2. Calibration drift (round-2 evidence)

- **Over-claim got worse, not better.** Round 2: 45 down : 15 up (3:1), 108 unchanged of 168 checked (27% down, 9% up, 64% unchanged). Round 1: 28 down : 17 up (1.6:1) and 16% down. The directive-driven round-2 targets ran in harder sources (legal text, forums, slides, aggregator CVE pages), which is the cause, not a model change. Per-explorer down share of new nodes: 03 33%, 05 33%, 10 30%, 06 25%, 04 18%, 02 27%, 11 13%, 01 15%, 09 20%, 07 25%, 08 7%. Expect 25-30% down for any explorer on a policy, forum or invariant-spec source; 7-15% for an explorer with a control experiment or API-pulled corpus.
- **Where grades inflate**: (1) numbers read from a release page or blog (sizes, counts, dates) graded A without recompute; (2) invariants and specs graded B before any harness exists (06, 10); (3) "N examples therefore a class" (10, 4); (4) mis-attributed identifiers (CVE-2026-35402, 49975, JLSEC/RUSTSEC ids): existence passes, semantics fail, so check what the cited item is, not that it exists.
- **Under-claim**: 15 up-moves were mostly defender evidence found late: unmerged-fix PRs (Pingora #1060, Kani #4910), curl cluster size, canopydb defaults from source. Pattern: explorers state a bug without checking the fix PR and main; verifiers upgrade when they find it. Add "state of fix on main at date X" to every bug node.
- **Confidence**: still not moving with grade; keep gating on grade. load_bearing: ~128 of 204 new nodes flagged (63%), the same inflation as round 1 (62%). The flag is not a selector; use load_bearing AND L4+ AND grade A/B AND decision-feeding text.
- **Measurement quality** is now a calibration issue: the host was contended (loadavg ~41) and variance reached 2.8x, so only class-level throughput claims stand. Any benchmark node must record loadavg, cpuset and kernel, and be capped at B for absolute numbers.
- **Net grade distribution of the 204**: A 75 (37%), B 90, C 32, D 3, E 4. The 7 D/E nodes are all abuse parameters (04); keep them out of rules until simulated.

### D2. Under-sampled domains and layers (round 3 targets)

- **W-DX**: 3 nodes, no targeted query in 2 rounds; q1-013 and q1-014 are open. Needs an instrument that costs no API money: static analysis of strict-type error surfaces, a stub handler SDK compile-time-feedback experiment, or published pass-rate datasets (read, with a B cap).
- **W-SUPPLY**: 0 new nodes in round 2 (round-1 08 was the top lens). The golden's lockfile, reproducible-build and min-publish-age gates are unexercised against the round-2 pins (hyper 1.12.0, h2 0.4.20, wasmtime pin, rustls). A re-run of the round-1 lockfile experiment on the golden pins is the cheapest high-yield target.
- **W-PQC authentication** (MTC, ML-DSA cert size/handshake cost, FIPS crate pin identity R-PQC-2): untouched since round 1; the key-agreement side is closed, so this is the live PQC frontier.
- **W-PERF at scale**: 64-core/bare-metal 0 queries; household VPS scale 3 queries; the quiet-host benchmark is not available. Treat as implementation spike.
- **W-GAP / W-AUTHZ**: authz round-2 content came mostly from CRS and agent targets, not a dedicated authz descent (token format R-AUTHZ-2 is E/C and could flip). A Biscuit vs Cedar vs capability-handle comparison with real code is the open L5 gap.
- **Source types**: forum 6, patent 0, dataset 0, non-English 3. Economics vocabulary 3 queries. Stance proponent 56% (down from 78%) is fine; still under-sampled: negative results other than 08, skeptic stance on formal-verification cost.
- **Layer**: transport L5 is now covered (6), but data-plane (3 L5), lean (3), ops (5) have candidate artifacts none of which has been executed. The next round's best L5 is an executed harness, not another drafted one.

### E2. Research-method findings from the round-2 map (planner, §12)

1. **Round 2 is the first time the map's value is in spikes, not literature.** 11 of the 18 top frontier items are labelled implementation-phase spikes. Per §0c, the planner should stop adding reading targets for a question where the open item is already a spike with a protocol, and instead (a) execute the spikes that fit heavy.sh limits (HRR to X25519MLKEM768 test, window-0 stall harness, SET LOCAL ROLE reproducer: all hours, <1.5 GB), and (b) leave the rest for implementation. Plan at most 6 reading targets and 4-6 executed-spike targets in round 3.
2. **Spikes that fit the box right now** (no model weights, <1.5 GB, one heavy job at a time): q2-002 HRR test, q2-009 window-0 harness (h2 0.4.20 / hyper 1.12.0 pins), q1-012 Postgres role-switch reproducer (docker), q2-001 IPC cost UDS+postcard vs in-process (small crates), q2-007 double-fault crash stage (extends 08's harness), q2-016 normalization copy cost. Those that need >6 GB or a Verus/Kani 4-vCPU/16 GB run (q2-013) stay spikes.
3. **Queue hygiene is a method defect.** Three paraphrases of the IPC question (01, 02, integrator), two of the window-0 harness, two Verus/Kani spikes passed the Jaccard 0.45 dedup. The planner should dedupe the 163 open items by containment first and expect about 40% fewer distinct items. Do this before UCB ranking.
4. **Bridge hunts keep paying.** One-invariant-vs-many-classes (10) produced fail-closed, scope-tuple, budgets-two-layers, interposition-unsound and generated-artifacts-untrusted bridges. Keep one per round; round-3 candidates from section 3 of round-002.md: (a) does INV-NONEMPTY / fail-closed survive timeouts under the DB cancel path? (b) does the scope tuple handle QUIC connection migration and H3 pooled backends? (c) interposition-unsound: do other instruments (Miri, sanitizers, DST clock) share the blind spot?
5. **Read both sides of every bug node.** 15 of 15 up-moves were fix-state discoveries; check fix PR and main before grading a defect.
6. **Source quality ladder (r2 update)**: gh api / OSV / crates.io API / datatracker > source-at-pinned-version grep > own measurement with control > release notes > RFC/NIST text > conference slides > forum/blog > SEO/news. Government/legal and slide sources need a verifier reading the primary, graded C until then.
7. **Counts are brittle three ways**: GHSA vs RUSTSEC dupes, PR vs issue in gh search, and pooled rates hiding a 2026 surge. Use one dated advisory snapshot per round under state/raw/round-NNN/_advisories/ and report per-year bands. The calibration target in round 3 should consume the shared snapshot, not repull.
8. **Selection for UCB (r2 lesson)**: the best predictors of a good target were (a) a named instrument with a control, (b) a mandate or zero-coverage pillar, (c) a prior-round L4 node being converted to an executed L5. The worst were (a) breadth surveys of a family (01's 17 families), (b) forum-sourced parameters (04), (c) slide-based scans (11). Weight the next UCB by expected L5-executed count, not breadth.
9. **Pillar naming still drifts** (`W-TRANSPORT+W-FORMAL`), inflating raw cell novelty (108/115 raw vs 0.738 normalized). Use the primary W-* pillar in domain.
10. **Crash resilience is now part of method.** The memory crash cost two explorers their node lists. Explorers append each node to `<nn>-nodes.jsonl` immediately; the planner should cap concurrent explorers that compile or benchmark to 3 and give each a disjoint core set.

### F2. Concrete round-3 plan hints (priority order)

1. Execute fitting spikes (E2.2) as three or four targets: each emits a pass/fail artifact with a control and a recorded loadavg.
2. W-SUPPLY executed against the golden pins (cargo-vet, cargo-auditable, repro-build diff, min-publish-age) and the toolchain-pin file.
3. W-PQC authentication (MTC, ML-DSA cost, FIPS pin identity), reading plus size/handshake measurement.
4. W-DX with a no-API-cost instrument; defer the head-to-head pass-rate test.
5. Authz token-format descent (Biscuit vs Cedar vs capability handle) with a code-level comparison; this is the load-bearing item still at E/C.
6. W-ABUSE re-run only as the swarm simulation (1 vCPU container); do not read further.
7. One bridge hunt (E2.4); one unknown-unknowns on a vocabulary not used yet (economics, patents, datasets); one calibration on the 25-30% down-risk nodes (05, 10, 06, 03) using the shared advisory snapshot.
8. Stop-rule check: round 2 mechanical novelty 0.877-0.898 vs <0.2 threshold; decision direction stability 1.00 but text 0.34; do not expect saturation before round 4-5. Rounds that execute spikes will lower URL novelty; that is expected and not a sign of saturation by itself.

## HISTORY

### 2026-10-25, after round 2 (META-OPTIMIZER)
- Prepended the CURRENT block (sections A2-F2). Ranked 11 lenses; instrument-with-control (08, 07, 03, 02) beat reading; abuse (04) and talks (11) lowest. Over-claim ratio worsened 1.6:1 to 3:1 because round-2 targets used harder sources (legal text, forums, slides). L5 rose from 9% to 23% of new nodes after the quota. Under-sampled: W-DX, W-SUPPLY, PQ authentication, authz token format. Method findings: map value shifted to spikes; queue dedup must use containment; bridge hunts pay; fix-state check; contended-host benchmarks capped at B.
- Round-1 guidance below (A-F) is retained verbatim as lessons; its F plan was executed except W-DX and the ABUSE instrument.
- Caveat: per-explorer rates use n of 8-27; verifier coverage 80% (r1: 52%).

---

## ROUND-1 GUIDANCE (superseded by the block above, retained, never deleted)


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
