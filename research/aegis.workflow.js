export const meta = {
  name: 'frontier-cartographer-aegis',
  description: 'Recursive deep research on the formally-assured, agent-hardened, post-quantum middle-tier web server; then synthesize ARCHITECTURE.md + repo/implementation plan',
  phases: [
    { title: 'Plan', detail: 'UCB frontier selection: explore / descend / unknown-unknowns / calibration' },
    { title: 'Explore', detail: 'one explorer per target (Sonnet breadth, Opus deep), each piped into a two-sided verifier' },
    { title: 'Integrate', detail: 'single writer: dedup, graph, report, protocol draft' },
    { title: 'Meta', detail: 'lenses rewrite + saturation judge' },
    { title: 'Synthesize', detail: 'parallel protocol angles' },
    { title: 'Critique', detail: 'two-sided adversarial critique' },
    { title: 'Final', detail: 'write ARCHITECTURE.md and templates' },
  ],
}

const ROOT = '/home/patrickd/aegis/research'
const DIRECTIVE = `${ROOT}/AEGIS_QUESTION.md`
const DATE = args.date
const START = args.round || 1
const ROUNDS = args.rounds || 4
const N = args.explorers || 10
const MAX_OPUS = args.maxOpusExplorers == null ? 4 : args.maxOpusExplorers
const QUIET = args.quietNeeded || 2
const SYNTH = args.synthesize !== false
// Model tiering: every stage pinned (never the session model). Override with args.models / args.efforts.
const M = Object.assign({ planner: 'sonnet', verify: 'sonnet', integrate: 'opus', meta: 'sonnet', judge: 'sonnet', synth: 'sonnet', critic: 'opus', final: 'opus' }, args.models || {})
const EFF = Object.assign({ verify: 'medium', judge: 'medium', meta: 'medium' }, args.efforts || {})
const mo = (key, opts) => Object.assign({}, opts, { model: M[key] }, EFF[key] ? { effort: EFF[key] } : {})
const pad = n => String(n).padStart(3, '0')
const HEAD = `You are part of the FRONTIER CARTOGRAPHER — AEGIS track. Read the directive ${DIRECTIVE} in full first (especially §0a OPERATOR STEER against anchoring, §1 questions, §3 calibration, §4 layers, §7 schema, §11 epistemics). META rules it inherits are in /home/patrickd/frontier-research/meta/META_RESEARCH_PROMPT.md (§3, §8, §8a, §11). BLIND RESEARCH (§0a): do NOT open ${ROOT}/state/prior_treatments/ or ${ROOT}/state/seed_conversation.md unless your brief is the round-1 identifier-calibration target (that target reports exists/doesn't-exist verdicts only). Your work and insights must be independent; reconciliation with prior research happens only at final synthesis. Run \`date\`; today is on or after ${DATE}. Only write inside ${ROOT}/.`

const PLAN_SCHEMA = {
  type: 'object',
  properties: {
    targets: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          label: { type: 'string', description: 'short kebab-case slug' },
          kind: { type: 'string', enum: ['explore', 'descend', 'unknown-unknowns', 'calibration', 'reverify'] },
          domain: { type: 'string', description: '§5 letter(s) or new domain name' },
          layer_from: { type: 'string' },
          layer_to: { type: 'string' },
          tier: { type: 'string', enum: ['sonnet', 'opus'], description: 'opus only for targets needing deep technical judgment (formal methods, theory, synthesis of conflicting evidence)' },
          brief: { type: 'string', description: 'what to find, how specific, which needle-hunting tactics, which existing node ids to extend' },
          ucb_reason: { type: 'string' },
        },
        required: ['label', 'kind', 'domain', 'layer_from', 'layer_to', 'tier', 'brief', 'ucb_reason'],
      },
    },
    plan_notes: { type: 'string' },
  },
  required: ['targets', 'plan_notes'],
}

const FIND_SCHEMA = {
  type: 'object',
  properties: {
    nodes: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' }, layer: { type: 'string' }, domain: { type: 'string' }, type: { type: 'string' },
          title: { type: 'string' }, summary: { type: 'string' }, specifics: { type: 'string' },
          urls: { type: 'array', items: { type: 'string' } },
          evidence_grade: { type: 'string', enum: ['A', 'B', 'C', 'D', 'E'] },
          confidence: { type: 'number' }, overclaim_risk: { type: 'string' }, underclaim_risk: { type: 'string' },
          actionability: { type: 'number' }, load_bearing: { type: 'boolean' },
        },
        required: ['id', 'layer', 'domain', 'type', 'title', 'summary', 'urls', 'evidence_grade', 'confidence', 'actionability', 'load_bearing'],
      },
    },
    edges: { type: 'array', items: { type: 'object', properties: { src: { type: 'string' }, dst: { type: 'string' }, type: { type: 'string' }, note: { type: 'string' } }, required: ['src', 'dst', 'type'] } },
    seeds: { type: 'array', items: { type: 'object', properties: { question: { type: 'string' }, layer: { type: 'string' }, domain: { type: 'string' }, expected_info_gain: { type: 'number' }, reason: { type: 'string' } }, required: ['question', 'layer', 'expected_info_gain'] } },
    protocol_implications: { type: 'array', items: { type: 'string' } },
    self_improvement: { type: 'array', items: { type: 'string' }, description: 'findings that would improve this research system itself (§12)' },
    raw_file: { type: 'string' },
  },
  required: ['nodes', 'edges', 'seeds', 'protocol_implications', 'raw_file'],
}

const VERIFY_SCHEMA = {
  type: 'object',
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          prosecutor: { type: 'string', description: 'strongest evidence the claim is overstated/wrong' },
          defender: { type: 'string', description: 'strongest evidence the claim is understated, or that a hedged/dismissed point is actually stronger' },
          grade: { type: 'string', enum: ['A', 'B', 'C', 'D', 'E'] },
          confidence: { type: 'number' },
          direction: { type: 'string', enum: ['up', 'down', 'unchanged', 'refuted'] },
          urls: { type: 'array', items: { type: 'string' } },
        },
        required: ['id', 'prosecutor', 'defender', 'grade', 'confidence', 'direction'],
      },
    },
    missed: { type: 'array', items: { type: 'string' }, description: 'important specifics the explorer missed' },
  },
  required: ['verdicts', 'missed'],
}

const INTEG_SCHEMA = {
  type: 'object',
  properties: {
    delta: {
      type: 'object',
      properties: {
        new_nodes: { type: 'number' }, merged: { type: 'number' }, new_edges: { type: 'number' }, bridges: { type: 'number' },
        by_layer: { type: 'string' }, direction_diversity: { type: 'number' }, novelty_ratio: { type: 'number' }, singletons: { type: 'number' }, queue_size: { type: 'number' },
      },
      required: ['new_nodes', 'merged', 'new_edges', 'novelty_ratio', 'queue_size'],
    },
    protocol_rule_changes: { type: 'array', items: { type: 'string' } },
    top_findings: { type: 'array', items: { type: 'string' } },
  },
  required: ['delta', 'protocol_rule_changes', 'top_findings'],
}

const JUDGE_SCHEMA = {
  type: 'object',
  properties: {
    saturated: { type: 'boolean' },
    novelty_ratio: { type: 'number' },
    unseen_mass_estimate: { type: 'number', description: 'Good-Turing style: fraction of probability mass on not-yet-seen nodes' },
    protocol_stability: { type: 'number', description: 'fraction of load-bearing ARCHITECTURE-DRAFT rules unchanged this round' },
    open_areas_that_could_flip_rules: { type: 'array', items: { type: 'string' } },
    reasons: { type: 'string' },
  },
  required: ['saturated', 'novelty_ratio', 'unseen_mass_estimate', 'protocol_stability', 'open_areas_that_could_flip_rules', 'reasons'],
}

// One automatic retry for agents lost to transient failures (network drops, classifier stops); the retry reads the progress file.
const retry = (p, o) => agent(p, o).then(r => r || (log(`${o.label} failed; retrying once`), agent(p, Object.assign({}, o, { label: `${o.label}:retry` }))))
const history = []
let quiet = 0
let round = START
for (; round < START + ROUNDS; round++) {
  const RR = pad(round)
  const RAW = `${ROOT}/state/raw/round-${RR}`
  log(`AEGIS round ${round} (quiet ${quiet}/${QUIET})`)

  phase('Plan')
  const plan = await agent(`${HEAD}
You are the PLANNER for AEGIS round ${round}. ${round === START && START === 1 ? 'This is the FIRST round: state files may not exist yet. Seed from §1/§5 so the round covers the pillars broadly AND already descends to L3–L5. Must include: W-THREAT (real CVE/incident record of middle-tier servers + AI-automated exploit discovery evidence), W-GAP (prior-art servers/runtimes and what is genuinely unserved), W-FORMAL (what has actually been proven in production-grade Rust/C/F* systems and LLM proof-synthesis results), W-ISOLATION (per-request isolation substrates compared with measured numbers and CVE records), W-AUTHZ (policy/capability systems with formal semantics), W-TRANSPORT+W-PQC (stack + PQC deployment reality), W-AGENT-PROTOCOL (primary-source MCP/A2A/x402/Web Bot Auth status), W-SUPPLY+W-ASSURE (provenance + deterministic simulation/fuzzing), plus one unknown-unknowns recency sweep (last 60 days) and one calibration target that checks every suspicious identifier flagged in state/seed_conversation.md (MCP 2026-07-28 headers, spargio, KVerus, AIP, wasmtime #13467, x402 volumes, RFC 9680, crate versions). Pillars not covered this round go first in round 2.' : `Read ${ROOT}/state/frontier_queue.jsonl, graph.jsonl (skim; count by domain/layer), lenses.md, round_log.md, self_improvement.md and ${ROOT}/reports/LATEST.md.`}
Pick exactly ${N} targets using the §6 UCB rule and constraints: ≥${Math.ceil(N / 4)} explore, ≥${Math.ceil(N / 2)} descend (to L3–L5), ≥1 unknown-unknowns${round > START || START > 1 ? ', ≥1 calibration (two-sided re-examination of the most load-bearing claims)' : ''}. No two targets may overlap substantially, and per §8a every pair must differ on ≥3 direction axes (domain, layer, vocabulary, source type, stance, time, mechanism, scale); read state/directions.md and state/queries.jsonl if they exist and aim at empty/thin axis cells. State each target's axis values in its brief. Mark tier 'opus' for at most ${MAX_OPUS} targets that need the deepest technical judgment; the rest 'sonnet'. Each brief must demand specifics (numbers, params, repos, failure modes, dated sources) and name the needle-hunting tactics to use. Do not write files.`, mo('planner', { label: `plan:r${round}`, phase: 'Plan', schema: PLAN_SCHEMA }))

  let targets = (plan && plan.targets) || []
  if (targets.length > N) { log(`planner returned ${targets.length} targets; using first ${N}`); targets = targets.slice(0, N) }
  let opusLeft = MAX_OPUS
  targets = targets.map(t => {
    const tier = t.tier === 'opus' && opusLeft > 0 ? (opusLeft--, 'opus') : 'sonnet'
    return Object.assign({}, t, { tier })
  })
  log(`round ${round}: ${targets.length} targets (${targets.filter(t => t.tier === 'opus').length} opus): ${targets.map(t => `${t.kind}/${t.label}`).join(', ')}`)

  const results = await pipeline(
    targets,
    (t, _o, i) => {
      const II = String(i + 1).padStart(2, '0')
      const raw = `${RAW}/${II}-${t.label}.json`
      const prog = `${RAW}/${II}-${t.label}.progress.md`
      return retry(`${HEAD}
You are AEGIS EXPLORER ${II} in round ${round}. Target (${t.kind}, domain ${t.domain}, ${t.layer_from} → ${t.layer_to}):
${t.brief}
Why this target: ${t.ucb_reason}

Method: web search and fetch extensively (aim for 25+ distinct sources; primary sources first). Use needle-hunting tactics: citation chaining both ways, GitHub code/issues/PRs/release notes, appendices and ablations, OpenReview reviews, leaderboards and their logs, RFCs/IETF drafts/datatracker and spec repos, RustSec/GHSA/CVE databases and incident write-ups, OSS-Fuzz, academic venues (OSDI/SOSP/USENIX Security/CCS/S&P/NDSS/PLDI/CAV/POPL 2024–2026), verification tool repos and Zulip, practitioner threads (HN, lobste.rs, Rust forums, Discord), conference talks, benchmark logs, negative results and post-mortems. Push to the most specific layer the evidence supports: exact crate/spec/CVE identifiers with versions and dates (fetch each to confirm it exists), measured numbers with hardware and conditions, proof coverage and TCB, license and maintenance status, failure modes, and the L5 artifact it implies for our repo (crate pin + config, invariant statement, interface sketch, test/fuzz harness, CI gate, acceptance criterion). Anti-anchoring (§0a): for any component decision, enumerate the alternatives yourself before looking at what the prior treatments chose. Apply §3 to yourself: state overclaim AND underclaim risk per load-bearing node; existence proofs beat priors; quantify instead of hedging.
Directional uniqueness (§8a, mandatory): log every query you run with a single short append to ${RAW}/_queries.log as "${t.label}\t<query>\t<axes>"; before each batch of searches read that file and ${ROOT}/state/queries.jsonl and never repeat a direction a sibling or prior round took — move along an untaken axis (other field's vocabulary, other source type, contrarian/negative stance, other era). Span ≥4 vocabularies, ≥3 source types and ≥1 contrarian direction.
Before deduping, check ${ROOT}/state/graph.jsonl (if it exists) with grep for your topic and REUSE existing ids for things already in the map; add edges from your new nodes to them.
Checkpointing (rate-limit safety): append findings to ${prog} every ~5 sources (create dirs as needed). If ${prog} already exists, read it first and continue from it instead of restarting.
When done, write your full findings (all nodes, edges, seeds, notes, source list) as JSON to ${raw}, then return the structured result (it can be more compact than the raw file but must include every load-bearing node). Return raw_file = ${raw}.`, { label: `explore:r${round}:${t.label}`, phase: 'Explore', schema: FIND_SCHEMA, model: t.tier })
    },
    (f, t) => {
      if (!f) return null
      const lb = (f.nodes || []).filter(n => n.load_bearing || n.actionability >= 0.6).slice(0, 15)
      if (!lb.length) return { target: t, find: f, verify: null }
      return agent(`${HEAD}
You are a TWO-SIDED VERIFIER (§3.4) for AEGIS round ${round}, target "${t.label}". For each claim below run BOTH passes with fresh web searches: PROSECUTOR (refute or downgrade: overclaim, vendor hype, contamination, cherry-picking, staleness, nonexistent sources; check every URL resolves and says what is claimed) and DEFENDER (find evidence the claim is understated, or that something hedged as hard/infeasible has existence proofs or newer stronger results). Assign a final grade/confidence/direction per id. Also list important specifics the explorer missed. Explorer's raw file: ${f.raw_file}. Do not write files.

${JSON.stringify(lb.map(n => ({ id: n.id, title: n.title, summary: n.summary, specifics: n.specifics, urls: n.urls, grade: n.evidence_grade, confidence: n.confidence })), null, 1)}`, mo('verify', { label: `verify:r${round}:${t.label}`, phase: 'Explore', schema: VERIFY_SCHEMA }))
        .then(v => ({ target: t, find: f, verify: v }))
    },
  )
  const done = results.filter(Boolean)
  const dropped = targets.length - done.length
  if (dropped) log(`round ${round}: ${dropped} explorer chain(s) returned nothing`)

  phase('Integrate')
  const integ = await agent(`${HEAD}
You are the INTEGRATOR for AEGIS round ${round} — the ONLY writer of map state. Inputs below: each explorer's compact findings (full raw JSON in ${RAW}/) and its two-sided verifier verdicts. Do all of:
1. Dedup per §8 against ${ROOT}/state/graph.jsonl and seen.jsonl (create files if missing): canonicalize URLs, resolve entities, merge near-duplicates with same-as edges, apply verifier grade/confidence changes (keep refuted nodes with grade and reason — never prune).
2. Append new nodes to state/graph.jsonl and edges to state/edges.jsonl (§7 schema, plus first_seen_round=${round}, last_verified=${DATE}); append every source URL to state/seen.jsonl; rebuild state/frontier_queue.jsonl (all unexplored seeds + verifier "missed" items, deduped, scored by expected info gain; mark explored seeds done); append checkable predictions to state/predictions.jsonl.
3. Write ${ROOT}/reports/round-${RR}.md per §10 and rewrite ${ROOT}/reports/LATEST.md as the cumulative view (map by domain×layer counts, best-known choice per pillar W-THREAT/W-GAP/W-TRANSPORT/W-PQC/W-ISOLATION/W-STATE/W-AUTHZ/W-DATA-GATE/W-AGENT-PROTOCOL/W-ABUSE/W-FORMAL/W-ASSURE/W-SUPPLY/W-PERF/W-OPS/W-DX with grades and alternatives, the current threat→mitigation→assurance matrix, the TCB ledger, top bridges, open frontier).
4. Update ${ROOT}/ARCHITECTURE-DRAFT.md (create if missing): the running protocol per §9, every rule with evidence grade, node ids/URLs and reversal condition; record rule diffs.
5. Per §8a: merge ${RAW}/_queries.log into state/queries.jsonl, update state/directions.md (axis-cell coverage and yield per query), compute direction_diversity = distinct axis cells / queries, and flag redundant directions. Report it in the round report.
6. Append §12 proposals to state/self_improvement.md and a one-line entry "AEGIS round ${round} — <date> — <delta>" to state/round_log.md.
Count singletons (nodes found by exactly one explorer and matching nothing existing) for the saturation estimate.

${JSON.stringify(done.map(d => ({ target: { label: d.target.label, kind: d.target.kind, domain: d.target.domain }, find: d.find, verify: d.verify })))}`, mo('integrate', { label: `integrate:r${round}`, phase: 'Integrate', schema: INTEG_SCHEMA }))

  phase('Meta')
  const [metaOut, judge] = await parallel([
    () => agent(`${HEAD}
You are the META-OPTIMIZER after AEGIS round ${round}. Read ${ROOT}/reports/round-${RR}.md, LATEST.md, state/lenses.md (create if missing), state/self_improvement.md and the plan notes below. Rewrite state/lenses.md to make the next round more productive: which lenses/tactics/source types yielded the most novel, specific (L4/L5), well-graded nodes; which were dead; under-sampled domains and layers; calibration drift (are explorers systematically over- or under-claiming?); and any research-method finding from the map itself that should change how the planner selects targets (§12). Keep a dated history section; do not delete prior lessons. Return a 10-line summary.
Plan notes: ${plan ? plan.plan_notes : '(planner failed)'}`, mo('meta', { label: `meta:r${round}`, phase: 'Meta' })),
    () => agent(`${HEAD}
You are the SATURATION JUDGE after AEGIS round ${round}. Integrator delta: ${JSON.stringify(integ ? integ.delta : null)}. Read ${ROOT}/reports/round-${RR}.md, the previous round report if any, LATEST.md and ARCHITECTURE-DRAFT.md. Estimate novelty, Good-Turing unseen mass (singletons / total new observations), and protocol stability (share of load-bearing rules unchanged). Be adversarial: saturated=true ONLY if novelty < 0.2 AND protocol_stability >= 0.75 AND no open area could plausibly flip a load-bearing rule. Do not write files.`, mo('judge', { label: `judge:r${round}`, phase: 'Meta', schema: JUDGE_SCHEMA })),
  ])
  history.push({ round, delta: integ ? integ.delta : null, judge, meta: metaOut, ruleChanges: integ ? integ.protocol_rule_changes : null })
  if (judge && judge.saturated) quiet++
  else quiet = 0
  log(`round ${round}: novelty=${judge ? judge.novelty_ratio : '?'} unseen=${judge ? judge.unseen_mass_estimate : '?'} stability=${judge ? judge.protocol_stability : '?'} saturated=${judge ? judge.saturated : '?'} → quiet ${quiet}/${QUIET}`)
  if (quiet >= QUIET) { log(`AEGIS saturated after round ${round}`); break }
}
const lastRound = Math.min(round, START + ROUNDS - 1)
const saturated = quiet >= QUIET
if (!saturated) log(`Stopped after round ${lastRound} without saturation (cap ${ROUNDS} rounds); continue later with args.round=${lastRound + 1}`)
if (!SYNTH) return { history, lastRound, saturated }

const CTX = `${HEAD}
You are synthesizing the AEGIS map after rounds ${START}–${lastRound}. Read ${ROOT}/reports/LATEST.md, every reports/round-*.md, ARCHITECTURE-DRAFT.md, state/self_improvement.md, state/lenses.md, and grep state/graph.jsonl / edges.jsonl for the nodes you rely on. Saturation ${saturated ? 'WAS' : 'was NOT yet'} reached; history: ${JSON.stringify(history)}. Re-verify time-sensitive claims on the web. Cite node ids and URLs. Do not write files. Synthesis stage only: you MAY now read ${ROOT}/state/prior_treatments/ and ${ROOT}/state/seed_conversation.md to RECONCILE (confirmed / refuted / missed by them / adopted from them with independent evidence); the design itself must stand on the independent map.`

phase('Synthesize')
const ANGLES = [
  { key: 'architecture', prompt: 'REFERENCE ARCHITECTURE + DECISION RECORD (directive §9.1, §9.3, §9.6, §9.7): positioning and the unserved gap vs real prior art; every component (transport/TLS/PQC, parser/normalizer, admission/abuse, authn/authz, isolation, state/WAL/idempotency, DB gate, agent-protocol projection, observability/audit, config/ops) with chosen implementation + version pin, 2+ alternatives, evidence grade, reversal condition; the performance model per deployment size; every contested decision argued both ways. Derive from the map, not from the prior treatments; flag each pick that coincides with a prior-treatment pick and give its independent evidence.' },
  { key: 'assurance', prompt: 'THREAT MODEL + ASSURANCE CASE (directive §9.2, §9.4, §9.5): adversary classes incl. AI-agent attackers and AI-automated exploit discovery; ranked threats with evidence; threat -> mitigation -> assurance mechanism (proof / type or capability boundary / deterministic simulation / fuzz / test) -> residual risk; the TCB ledger with sizes; the explicit NOT-PROVEN list; the formal invariants stated precisely (no ambient authority, attenuation monotonicity, failed request => no state mutation, bounded resources per request, parser canonicality / no desync, tenant isolation, PQC handshake properties) each mapped to a tool, rung and effort estimate, including what LLM proof synthesis can realistically discharge.' },
  { key: 'process', prompt: 'PROVENANCE + COMPLIANCE + OPS (W-SUPPLY, W-ASSURE, W-OPS, W-PQC timelines): dependency policy and minimization, reproducible/bootstrapped builds, SLSA/Sigstore/TUF release chain, CI gate stack (proof check, DST seeds, fuzz corpora, mutation score, differential tests, AI red-team stage) with pass criteria; key management and rotation; observability and tamper-evident audit logs; compliance map (FIPS 140-3 module path, CNSA 2.0 dates, FedRAMP/NIST 800-53/SSDF, EU CRA obligations and dates, CISA memory-safety guidance); household single-binary deployment through enterprise/Kubernetes.' },
  { key: 'plan', prompt: 'REPOSITORY + IMPLEMENTATION PLAN (directive §9.8, META PROTOCOL §2): workspace/crate tree with each crate role, allowed dependencies, unsafe budget and assurance rung; toolchain pins; frozen interfaces to write first; phases ordered by risk retired per engineering hour, each with deliverables, machine-checkable acceptance gates and go/no-go; the verify wall (specs, oracles, harnesses) built before code; how coding agents execute it (spec author vs implementer separation, INFEASIBLE exit, parallel partitions, journaling); a migration path for existing apps (reverse-proxy mode first?); the benchmark protocol and honest baselines (nginx, Envoy, Pingora, Caddy, Node, Go).' },
]
const synth = (await parallel(ANGLES.map(a => () =>
  agent(`${CTX}\n\nANGLE ${a.key}. ${a.prompt}\nReturn a thorough markdown section with concrete rules, numbers, templates and evidence grades.`, mo('synth', { label: `synth:${a.key}`, phase: 'Synthesize' }))
    .then(text => ({ key: a.key, text }))))).filter(Boolean)

phase('Critique')
const critique = await agent(`${CTX}\n\nYou are a TWO-SIDED CRITIC of the three protocol sections below. PROSECUTE: unsupported or overgraded claims, vendor hype, contradictions between sections, decisions whose only support is a prior treatment (anchoring, per §0a), unverifiable or invented identifiers, 'provably secure' claims whose proof does not cover the attack, microbenchmarks presented as system throughput, phases whose gates are not machine-checkable, plans a solo founder + coding agents cannot execute, survivorship bias. DEFEND: places where the sections are too timid — hedges that the evidence doesn't require, dismissed techniques with existence proofs, missing high-ceiling methods present in the map, verified components dismissed as too costly, and places the sections defer to convention where the evidence supports a stronger design. Verify on the web where needed. Return a numbered list of corrections.\n\n${synth.map(s => `=== ${s.key} ===\n${s.text}`).join('\n\n')}`, mo('critic', { label: 'critic', phase: 'Critique' }))

phase('Final')
const final = await agent(`${CTX}\n\nYou are the FINAL WRITER. Merge the sections below, apply every valid correction from the critic, and write:
(a) ${ROOT}/ARCHITECTURE.md per directive §9 (version it v${lastRound} with date and saturation status), with an evidence appendix (item → node ids/URLs → grade → last checked) and a RECONCILIATION section vs prior research (PDF1, PDF2, seed conversation: confirmed / refuted / they missed / adopted with independent evidence) and an ANCHORING AUDIT table (decision → prior-treatment pick → our pick → independent evidence).
(b) ${ROOT}/templates/: REPO_LAYOUT.md, IMPLEMENTATION_PLAN.md, THREAT_MODEL.md, VERIFICATION_PLAN.md, SPEC_INVARIANTS.md, SUPPLY_CHAIN.md, COMPLIANCE_MAP.md, BENCH_PLAN.md (contents per directive §0).
You may write only these files. Return a 15-line executive summary.

${synth.map(s => `=== ${s.key} ===\n${s.text}`).join('\n\n')}

=== CRITIC ===
${critique}`, mo('final', { label: 'final-writer', phase: 'Final' }))

return { history, lastRound, saturated, summary: final }
