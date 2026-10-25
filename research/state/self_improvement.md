
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
