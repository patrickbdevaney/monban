
## from explorer 04 (round 1, isolation)
- gh api repos/<owner>/<repo>/security-advisories returns complete structured GHSA lists (severity, credits, dates); highest-yield needle for CVE-record questions.
- Local microbenchmarks on operator hardware (04-bench/) converted vendor D claims to A data in <10 min; use for perf questions when toolchain exists.
- Local rustc is 1.88; wasmtime 50 needs 1.97 -> repo plan must pin rust-toolchain.toml.

## AEGIS round 1 integrator proposals (2026-10-24, §12)
1. **Shared advisory-snapshot tool** [evidence A: six explorers (01, 02, 04, 06, 08, 11) independently ran `gh api .../security-advisories` over overlapping repos, and counts disagreed: wasmtime 81/57/41, quinn 11 vs 12]. Add `tools/advisory_snapshot.py <owner/repo>...` that writes dated JSON to `state/raw/round-NNN/_advisories/`; explorers read it before querying. Measure: fewer cross-explorer near-dup queries (round 1: 7) and zero count conflicts between nodes.
2. **Fixed axes format in `_queries.log`** [evidence: free-text axes produced 124 cells from regex inference; vocabulary and deployment-scale axes were unrecoverable]. Require `pillar=..;vocab=..;src=..;stance=..;era=..;scale=..` with closed value sets from directive §8. Measure: direction_diversity computed exactly, without classifier error.
3. **Pillar naming** [evidence: the planner used letters that do not match directive §5 order (J=agent-protocol, P=formal, M=unknown, N+O=supply+assure), and explorers mixed letters with W-* names]. Planner and explorers must put the W-* pillar name in node `domain`. Measure: 0 unmapped domains (round 1 needed a per-explorer letter map).
4. **Numeric reconciliation step for verifiers** [evidence: identifiers resolved ~100% but about 15 load-bearing numbers drifted (ExploitGym, CyberGym, Ferron, quinn, workerd, Rust 1.99.1, HTTP Terminator date)]. The verifier prompt should require a `numbers_checked: [{claim, source_value, match}]` array per verdict. Measure: share of A/B nodes with source-table-checked numbers.
5. **Verifier coverage** [round 1 sampled 173 of 333 nodes (52%), mostly the first ~15 per explorer]. Prioritize load_bearing nodes and all L5 artifacts for verification instead of document order. Measure: 100% of load-bearing nodes two-sided checked.
6. **Directive-mandated targets enter the queue automatically** [evidence: §0b/§0c added mid-run had no round-1 coverage]. The planner should read a `state/mandates.jsonl`. The integrator seeded q1-001/002/004/007 by hand this round.
7. **Explorer raw JSON schema** [evidence: verifier verdicts exist only in the orchestrator payload, not on disk]. The workflow should write each verifier's output to `state/raw/round-NNN/<nn>-verify.json` so the integrator does not transcribe verdicts and later rounds can audit them. This round the integrator re-keyed grade/confidence/direction plus a short note into graph nodes (`verify` field).
8. **novelty_gate canonicalization mismatch** [observed, not edited]: novelty_gate canonicalizes GitHub URLs as https paths while META §8 asks for `gh:owner/repo`. The integrator wrote both raw and `gh:`-canonical forms into seen.jsonl, and novelty_gate's regex still extracts the raw `url` field. No script was changed.

## AEGIS round 1 meta-optimizer proposals (2026-10-24, §12)
1. **Add a per-node `instrument` field** (read / bulk-data / local-run / reproduce / diff) at explorer time. Evidence: lens ranking showed instrumented lenses carry most L5 and A nodes, but it had to be inferred from progress files. Measure: planner can rank lenses by instrument yield mechanically.
2. **Cap `load_bearing` per explorer at about 25% and require a one-line decision it feeds** [evidence: 203 of 327 = 62% flagged]. Measure: verifier priority set is discriminating.
3. **Planner must set a per-target L5 quota (>=3)** [evidence: 29 L5 of 327, 14 from one explorer, 0 from transport].
4. **Log explorer `grade_explorer` and verifier grade separately and report net over-claim ratio each round** [round 1: 14 down vs 2 up, 7:1]; this is already stored, so only the report line is missing.

- [r2 explorer 03 verification-footprint, 2026-10-25] heavy.sh guards only /home free space; jobs writing to /tmp scratch (root fs, 39G free) get refused when /home dips under 10G. Suggest heavy.sh take a target-dir arg and check that filesystem. Also: installed size of a remote zip can be measured with HTTP range reads of the central directory (a few MB fetched instead of the whole archive); use this before any toolchain install. Scratchpad dir is shared across sessions (other agents' 2 GB there) - per-explorer subdirs advised.

## AEGIS round 2 integrator proposals (2026-10-25, §12)
1. **Persist verifier output to disk (re-raised; round-1 #7 not implemented)** [evidence: 168 verdicts plus 82 missed items again existed only in the orchestrator payload; the integrator re-keyed them into `state/raw/round-002/_verify_r2_verdicts.json` and `_verify_r2_missed.json` by hand]. The workflow should write `<nn>-verify.json` next to each explorer file. Measure: zero hand-transcribed verdicts.
2. **Crash-safe explorer output** [evidence: explorers 05 and 11 left raw files with only node ids or a note after the memory crash; full nodes survived only in the structured return, transcribed to `*.structured.json`]. Explorers should append each node to a `<nn>-nodes.jsonl` as soon as it is created, as well as checkpointing progress.md. Measure: every raw file has `nodes` with full fields.
3. **novelty_gate.py robustness (observed; script not edited, per §0d)** [evidence: `metrics` raised `TypeError: 'int' object is not iterable` because the integrator's own metrics dump `_metrics_r2.json` had `"nodes": 211` at top level; it reads every `*.json` in a round dir]. The integrator renamed the dump to `_metrics_r2.txt`. Proposed fix: skip non-list `nodes` and ignore `_`-prefixed files. Meanwhile, never write `*.json` files with a top-level `nodes` integer into `state/raw/round-NNN/`.
4. **novelty_gate node_novelty should give zero credit to reused ids** [evidence: explorer 12 re-verified 20 existing ids with rewritten titles; title-only scoring against round<N raw counted 16 of them as novel; adjusted node novelty 0.953 → 0.877, which became the binding mechanical dimension]. Proposed fix: a node whose id is already in graph.jsonl, or that is merged same-as, scores 0.
5. **Closed axis vocabulary in `_queries.log` (re-raised; round-1 #2 not implemented)** [evidence: free-text axes again; round-2 pillar labels differ from round 1's (e.g. `W-TRANSPORT+W-FORMAL`), so raw cell novelty is 108/115 but only 0.738 when normalized to the primary pillar; era logged as last-60d for only 5 of 301 queries; scale unspecified for 264]. Require `pillar=;vocab=;src=;stance=;era=;scale=` with closed value sets.
6. **Queue dedup by containment, not only Jaccard** [evidence: three paraphrases of the out-of-process IPC-cost spike (01, 02, integrator), two of the window-0 harness (06/11 vs integrator), two of the Verus/Kani RAM spike passed the 0.45 Jaccard dedup and had to be merged by hand]. Use novelty_gate's `nscore` (title Jaccard or token containment) at ≥0.5.
7. **Quota-driven identifier hunting produces suspect ids** [evidence: the only unresolved identifiers of the round (CVE-2026-107814, CVE-2026-90997 in `dpf-mysql-mariadb`) came from a "2 dated CVEs per family" quota; DEF CON items cited only `media.defcon.org`]. Replace id quotas with mechanism questions, and require a `numbers_checked` entry with a primary-source URL for every id and number (09 did this and was the best-calibrated explorer).
8. **Benchmark isolation** [evidence: loadavg ~41 from sibling explorers produced up to 2.8× throughput variance (02) and slowed crash sweeps 5-10× (08)]. heavy.sh serializes heavy jobs but measurements still overlap other sessions' loads; add a `heavy.sh --quiet-window` mode that waits for loadavg < cores/2 before benchmark runs, and record loadavg in every measurement.
9. **Disk preflight for heavy.sh** [evidence: 03 and 06 had measurements refused because /home had <10 GB free while /tmp had space; shared scratchpad held ~5.7 GB of duplicate clones]. Accept a target-dir argument, keep a shared read-only clone cache, and GC scratchpad clones between rounds.
10. **Mandate-driven targets worked** [evidence: §0b/§0c targets (data plane, ingress/leanness, verification footprint, golden contract) were all executed this round and produced 5 of the top 10 findings]. Keep the planner reading a mandates list; add W-DX and PQ authentication as mandates for round 3 (both have had no targeted query since round 1).

## Round 2 explorer self-improvement notes (collected by integrator, 2026-10-25)
- [01 data-plane] WebFetch to nvd.nist.gov blocked: use services.nvd.nist.gov REST API (pubStartDate range ≤120 days; filter client side) and cveawg.mitre.org/api/cve/<id>. GitHub code search ~10 req/min: batch with ≥7 s sleeps. Checkpoints allowed resume after OOM without rerunning queries.
- [02 lean footprint] Reserve cores or serialize benchmark explorers; a shared high-port registry avoids collisions (8080 held by siblings); smaps_rollup of container processes needs a helper container with `--pid=container:<name>`; pin Cargo.lock for benchmark builds.
- [03 verification] Zip central-directory range reads give installed size without downloading; per-explorer scratch subdirs.
- [04 abuse] Direct API fetches (crates.io, api.github.com, datatracker) beat WebSearch for L4 facts; when sources disagree on a default, fetch the config at repo HEAD and record the date.
- [05 ops] Add a fetch-fallback list for WAF-blocked government domains (EUR-Lex, CISA); checkpoint every ~5 sources.
- [06 transport] Duplicate clones of h2/h3/quinn/quiche/rustls across sessions: shared read-only clone cache.
- [07 isolation] Record toolchain pins (rustc 1.98 for wasmtime 48) up front; never `pkill -f` a pattern present in your own command line; write benchmark output with `stdbuf -oL` to files.
- [08 crash] Add a per-store strace-coverage self-check to any interposer harness; cap parallelism at -P4; use pidfiles.
- [09 agent gateway] Require `numbers_checked` with primary API source per number; compute counts by script.
- [10 cross-request] One-invariant-vs-≥10-classes bridge hunts gave sharper results than single-pillar dives: keep one per round.
- [11 talks] Persist node JSON incrementally; run novelty_gate topic per item; fetch primary or downgrade.
- [12 calibration] Recount traps: `gh search` label counts include PRs unless `is:issue`; gh contents API truncates at 1000 entries; KEV lags disclosure; require per-year bands for pooled rates; semantically check cited examples, not only existence.
2026-10-25T02:19:03-04:00 explorer07: heavy.sh lock was held by sibling cargo builds; pure-python sims (<100MB RSS, nice 19, 3 procs) run outside the lock

---
(r3 explorer 01 dataplane-ir-lowering-soundness, 2026-10-25)
- DBLP search API is behind an Anubis PoW page; use arXiv export API / Semantic Scholar for bibliographic sweeps.
- Running the competitor (OPA static binary, SQLAlchemy, ucast-prisma installed to scratchpad, <100 MB) yielded A-grade defects fast; add "execute existing art when a <100 MB binary/package exists" as a default tactic.
- Briefs should list docker images already present (postgres:17 here = 17.11, already patched for the CVE under study) so reproducer feasibility is known up front.

- (round 3, explorer 03 pq-auth, 2026-10-25) heavy.sh: two jobs launched by one explorer 3 s apart both ran concurrently under the lock and clobbered one output file; a queued job was not visible in ps. Check flock semantics with systemd-run --scope; write each run to a unique file.

---
## Round 3 proposals (integrator, 2026-10-25; §12)

Explorer-reported (verbatim intent, condensed):
- [01] DBLP is behind an Anubis PoW page: use the arXiv export API / Semantic Scholar. Executing the existing art (OPA binary, pip/npm packages <100 MB) gave A-grade defects fast: make it a default tactic. Briefs should list docker images already present.
- [02] Record per-run loadavg and pick an idle core with an idle SMT sibling (`tools/pick_idle_core.sh`). Give each transport a time budget and an `ONLY=` filter in benchmark templates. WebFetch cannot read PDFs: save then run pdftotext (standard tactic, also 08 and 10).
- [03] heavy.sh did not serialize two jobs launched 3 s apart, and a queued job was invisible in ps: verify flock under systemd-run --scope; until then, write each run to a unique file. Absolute CPU on the shared host (load 36-77) is stable only as ratios: grade C unless replicated on an idle host. Harness templates must not read stdin at exit.
- [04] Use `gh api` merged_at/created_at for date claims (round 1 recorded RFC 3923 creation as acceptance). Batch heavy builds into one driver script. Document the novelty_gate invocation path. META rule: fetch and re-run released paper artifacts for every load-bearing measured number. `cargo vet init` auto-exempts every crate: strip exemptions before any coverage claim.
- [05] The scratchpad repos dir is shared across explorers: use per-explorer clone dirs. Pre-build a shared bench cache. Pin `cargo +1.98.0` as the research toolchain (system rustc 1.88 is too old). mailarchive.ietf.org returns 403: use the datatracker API.
- [06] novelty_gate `topic` gave a false COVERED on generic tokens (clippy/gate/lint): it needs an aspect/content check. Add a mechanism-tagging pass (cancel/drop/timeout) over bulk advisory dumps: round-1 dumps already held CVE-2026-27195 and CVE-2025-47907 unanalysed. Per-crate `gh api search/issues` with mechanism keywords had the best yield.
- [07] Add a light-job lane in heavy.sh for no-compile jobs. `python3 -I` ignores the script dir: insert `sys.path`. Never `pkill -f` a pattern in your own command line. Vendor pricing pages via WebFetch are reliable; search summaries are not.
- [08] novelty_gate topic returned unrelated nearest nodes for DX: add per-pillar coverage tags. Write the first checkpoint within 2 minutes (the crash left no progress file).
- [09] OSV-resolve every CVE/GHSA id before citing (caught 2 non-resolving ids). Add a `crate_scorecard.sh` tool (gh security-advisories + crates.io + OSV in 3 commands). "Read defaults from source" belongs on the L4 checklist.
- [10] Check sibling progress files before starting. Curl raw GitHub source into the scratchpad instead of relying on WebFetch summaries for L4 facts.
- [11] Add `tools/osv_delta.py` and `tools/dt_delta.py` (keyless dated deltas). Google Patents xhr returns 503 after ~6 rapid calls: space calls 10 s+. Mark gated standards as access-limited instead of re-querying. Checkpoint every 2 sources.
- [12] Calibrators grep raw logs for every headline benchmark number (the w02 "best trial" was in no log). Use the Publications Office cellar URL for EU law. Always pair an advisory share with per-year counts.

Integrator proposals (new):
1. **Verifiers write their own verdict files.** For the third round running, two-sided verdicts existed only in the orchestrator payload and the integrator re-keyed 161 verdicts by hand, which risks transcription error. Each verifier should write `state/raw/round-NNN/_verify_<explorer>.json` with {id: [grade, confidence, direction, note, urls]} plus a `missed` list.
2. **Shared advisory snapshot as an input, not an output.** Promote `state/raw/round-003/_advisories/` (OSV + GitHub releases, dated) to `state/advisories/` and have explorers query deltas against it. Three explorers re-pulled the same rustls/tokio/wasmtime advisories this round.
3. **Incident-id dedup in novelty_gate.** Two same-incident nodes slipped through (Cloudflare 2025-11-18, arrayref RUSTSEC-2026-0260). Extract CVE/GHSA/RUSTSEC ids and incident dates from node text and treat an id match as COVERED regardless of token Jaccard.
4. **Stable pillar labels in the query log.** Per-target composite pillar labels inflate axis-cell novelty. Log the canonical W-* pillar separately from the target label.
5. **Seeds key required in raw JSON.** Explorer 09's raw file lost its `seeds` key; the integrator restored them from the relayed findings. Validate raw JSON against a schema (nodes, edges, seeds, protocol_implications) at explorer exit.
6. **Lean has never been executed in three rounds.** Two load-bearing Lean drafts (lowering, token) are unchecked. If the disk budget allows (projected <0.7 GB, <5 s), run one `lake build` of a core-only project under heavy.sh as an early implementation-phase spike, because the R-FORMAL-2 toolchain claim rests on it.
7. **Explicit stance quota.** Proponent share slid from 56% to 69%. Re-impose ≥1 skeptic/negative direction per explorer in briefs.

- (explorer 11, r4) Statuspage API caps at 50 and ignores paging; regex auto-coding of outage text unusable; use manual snippet labels with scripted counts.
