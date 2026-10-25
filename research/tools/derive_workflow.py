# Derives aegis.workflow.js from ~/frontier-research/arsenal/arsenal.workflow.js (same pattern as sovereign/tools/derive_workflow.py).
# Run: python3 -I ~/aegis/research/tools/derive_workflow.py
# Refuses while research/.inflight-run exists: regenerating changes agent prompts and voids that run's resume cache.
import os, sys
if os.path.exists('/home/patrickd/aegis/research/.inflight-run') and '--force' not in sys.argv:
    sys.exit('refusing: a run is in flight (research/.inflight-run); delete it when the run has finished')
s = open('/home/patrickd/frontier-research/arsenal/arsenal.workflow.js').read()

def rep(a, b):
    global s
    assert a in s, a[:80]
    s = s.replace(a, b)

rep("name: 'frontier-cartographer-arsenal'", "name: 'frontier-cartographer-aegis'")
rep("description: 'Recursive deep research on the operator leverage ladder + full-stack toolchain; then synthesize PLAYBOOK.md'",
    "description: 'Recursive deep research on the formally-assured, agent-hardened, post-quantum middle-tier web server; then synthesize ARCHITECTURE.md + repo/implementation plan'")
rep("{ title: 'Final', detail: 'write PLAYBOOK.md and templates' }", "{ title: 'Final', detail: 'write ARCHITECTURE.md and templates' }")
rep("const ROOT = '/home/patrickd/frontier-research/arsenal'", "const ROOT = '/home/patrickd/aegis/research'")
rep("const DIRECTIVE = `${ROOT}/ARSENAL_QUESTION.md`", "const DIRECTIVE = `${ROOT}/AEGIS_QUESTION.md`")
rep("You are part of the FRONTIER CARTOGRAPHER — ARSENAL track. Read the directive ${DIRECTIVE} in full first (especially §3 calibration doctrine, §4 layers, §7 schema, §11 epistemics).",
    "You are part of the FRONTIER CARTOGRAPHER — AEGIS track. Read the directive ${DIRECTIVE} in full first (especially §0a OPERATOR STEER against anchoring, §1 questions, §3 calibration, §4 layers, §7 schema, §11 epistemics). "
    "META rules it inherits are in /home/patrickd/frontier-research/meta/META_RESEARCH_PROMPT.md (§3, §8, §8a, §11). BLIND RESEARCH (§0a): do NOT open ${ROOT}/state/prior_treatments/ or ${ROOT}/state/seed_conversation.md "
    "unless your brief is the round-1 identifier-calibration target (that target reports exists/doesn't-exist verdicts only). Your work and insights must be independent; reconciliation with prior research happens only at final synthesis.")

a = s.index("'This is the FIRST round:")
b = s.index("' : `Read ${ROOT}/state/frontier_queue.jsonl") + 1
s = s[:a] + ("'This is the FIRST round: state files may not exist yet. Seed from §1/§5 so the round covers the pillars broadly AND already "
             "descends to L3–L5. Must include: W-THREAT (real CVE/incident record of middle-tier servers + AI-automated exploit discovery evidence), "
             "W-GAP (prior-art servers/runtimes and what is genuinely unserved), W-FORMAL (what has actually been proven in production-grade Rust/C/F* systems and "
             "LLM proof-synthesis results), W-ISOLATION (per-request isolation substrates compared with measured numbers and CVE records), W-AUTHZ "
             "(policy/capability systems with formal semantics), W-TRANSPORT+W-PQC (stack + PQC deployment reality), W-AGENT-PROTOCOL (primary-source MCP/A2A/x402/"
             "Web Bot Auth status), W-SUPPLY+W-ASSURE (provenance + deterministic simulation/fuzzing), plus one unknown-unknowns recency sweep (last 60 days) and one "
             "calibration target that checks every suspicious identifier flagged in state/seed_conversation.md (MCP 2026-07-28 headers, spargio, KVerus, AIP, "
             "wasmtime #13467, x402 volumes, RFC 9680, crate versions). Pillars not covered this round go first in round 2.'") + s[b:]

rep("You are ARSENAL EXPLORER", "You are AEGIS EXPLORER")
rep("practitioner threads (Lean Zulip, HN, X, Discord), conference talks, negative results.",
    "RFCs/IETF drafts/datatracker and spec repos, RustSec/GHSA/CVE databases and incident write-ups, OSS-Fuzz, academic venues "
    "(OSDI/SOSP/USENIX Security/CCS/S&P/NDSS/PLDI/CAV/POPL 2024–2026), verification tool repos and Zulip, practitioner threads (HN, lobste.rs, "
    "Rust forums, Discord), conference talks, benchmark logs, negative results and post-mortems.")
rep("Push to the most specific layer the evidence supports: exact technique names, parameters, measured numbers, repos with stars/last-commit, failure modes, configs and commands.",
    "Push to the most specific layer the evidence supports: exact crate/spec/CVE identifiers with versions and dates (fetch each to confirm it exists), "
    "measured numbers with hardware and conditions, proof coverage and TCB, license and maintenance status, failure modes, and the L5 artifact it implies "
    "for our repo (crate pin + config, invariant statement, interface sketch, test/fuzz harness, CI gate, acceptance criterion). "
    "Anti-anchoring (§0a): for any component decision, enumerate the alternatives yourself before looking at what the prior treatments chose.")
rep("PLAYBOOK-DRAFT", "ARCHITECTURE-DRAFT")
rep("best-known tools/rungs/processes per question A-LADDER/A-TOOLS/A-PROCESS/A-THROUGHPUT with grades",
    "best-known choice per pillar W-THREAT/W-GAP/W-TRANSPORT/W-PQC/W-ISOLATION/W-STATE/W-AUTHZ/W-DATA-GATE/W-AGENT-PROTOCOL/W-ABUSE/W-FORMAL/W-ASSURE/"
    "W-SUPPLY/W-PERF/W-OPS/W-DX with grades and alternatives, the current threat→mitigation→assurance matrix, the TCB ledger")
rep("1. Dedup per §8 against ${ROOT}/state/graph.jsonl and seen.jsonl",
    "1. Dedup per §8 against ${ROOT}/state/graph.jsonl and seen.jsonl")
for w in ("ARSENAL round", "ARSENAL saturated", "ARSENAL map"):
    rep(w, w.replace("ARSENAL", "AEGIS"))

a = s.index("const ANGLES = [")
b = s.index("]\n", a) + 2
s = s[:a] + """const ANGLES = [
  { key: 'architecture', prompt: 'REFERENCE ARCHITECTURE + DECISION RECORD (directive §9.1, §9.3, §9.6, §9.7): positioning and the unserved gap vs real prior art; every component (transport/TLS/PQC, parser/normalizer, admission/abuse, authn/authz, isolation, state/WAL/idempotency, DB gate, agent-protocol projection, observability/audit, config/ops) with chosen implementation + version pin, 2+ alternatives, evidence grade, reversal condition; the performance model per deployment size; every contested decision argued both ways. Derive from the map, not from the prior treatments; flag each pick that coincides with a prior-treatment pick and give its independent evidence.' },
  { key: 'assurance', prompt: 'THREAT MODEL + ASSURANCE CASE (directive §9.2, §9.4, §9.5): adversary classes incl. AI-agent attackers and AI-automated exploit discovery; ranked threats with evidence; threat -> mitigation -> assurance mechanism (proof / type or capability boundary / deterministic simulation / fuzz / test) -> residual risk; the TCB ledger with sizes; the explicit NOT-PROVEN list; the formal invariants stated precisely (no ambient authority, attenuation monotonicity, failed request => no state mutation, bounded resources per request, parser canonicality / no desync, tenant isolation, PQC handshake properties) each mapped to a tool, rung and effort estimate, including what LLM proof synthesis can realistically discharge.' },
  { key: 'process', prompt: 'PROVENANCE + COMPLIANCE + OPS (W-SUPPLY, W-ASSURE, W-OPS, W-PQC timelines): dependency policy and minimization, reproducible/bootstrapped builds, SLSA/Sigstore/TUF release chain, CI gate stack (proof check, DST seeds, fuzz corpora, mutation score, differential tests, AI red-team stage) with pass criteria; key management and rotation; observability and tamper-evident audit logs; compliance map (FIPS 140-3 module path, CNSA 2.0 dates, FedRAMP/NIST 800-53/SSDF, EU CRA obligations and dates, CISA memory-safety guidance); household single-binary deployment through enterprise/Kubernetes.' },
  { key: 'plan', prompt: 'REPOSITORY + IMPLEMENTATION PLAN (directive §9.8, META PROTOCOL §2): workspace/crate tree with each crate role, allowed dependencies, unsafe budget and assurance rung; toolchain pins; frozen interfaces to write first; phases ordered by risk retired per engineering hour, each with deliverables, machine-checkable acceptance gates and go/no-go; the verify wall (specs, oracles, harnesses) built before code; how coding agents execute it (spec author vs implementer separation, INFEASIBLE exit, parallel partitions, journaling); a migration path for existing apps (reverse-proxy mode first?); the benchmark protocol and honest baselines (nginx, Envoy, Pingora, Caddy, Node, Go).' },
]
""" + s[b:]
rep("Re-verify time-sensitive claims on the web. Cite node ids and URLs. Do not write files.`",
    "Re-verify time-sensitive claims on the web. Cite node ids and URLs. Do not write files. "
    "Synthesis stage only: you MAY now read ${ROOT}/state/prior_treatments/ and ${ROOT}/state/seed_conversation.md to RECONCILE (confirmed / refuted / missed by them / adopted from them with independent evidence); the design itself must stand on the independent map.`")
rep("rules that don't fit a solo operator's fleet and budget",
    "decisions whose only support is a prior treatment (anchoring, per §0a), unverifiable or invented identifiers, 'provably secure' claims whose proof does not cover the attack, "
    "microbenchmarks presented as system throughput, phases whose gates are not machine-checkable, plans a solo founder + coding agents cannot execute")
rep("missing high-ceiling methods present in the map.",
    "missing high-ceiling methods present in the map, verified components dismissed as too costly, and places the sections defer to convention where the evidence supports a stronger design.")

a = s.index("(a) ${ROOT}/PLAYBOOK.md")
b = s.index("You may write only these files.")
s = s[:a] + """(a) ${ROOT}/ARCHITECTURE.md per directive §9 (version it v${lastRound} with date and saturation status), with an evidence appendix (item → node ids/URLs → grade → last checked) and a RECONCILIATION section vs prior research (PDF1, PDF2, seed conversation: confirmed / refuted / they missed / adopted with independent evidence) and an ANCHORING AUDIT table (decision → prior-treatment pick → our pick → independent evidence).
(b) ${ROOT}/templates/: REPO_LAYOUT.md, IMPLEMENTATION_PLAN.md, THREAT_MODEL.md, VERIFICATION_PLAN.md, SPEC_INVARIANTS.md, SUPPLY_CHAIN.md, COMPLIANCE_MAP.md, BENCH_PLAN.md (contents per directive §0).
""" + s[b:]

# Crash/session-loss resumability (META resume is same-session only; these make a fresh run restartable from disk).
rep("If ${prog} already exists, read it first and continue from it instead of restarting.",
    "If ${prog} already exists, read it first and continue from it instead of restarting. If ${raw} already exists and is complete JSON "
    "(nodes + source list), a previous attempt finished: do NOT redo research, return its contents as the structured result.")
rep("You are the INTEGRATOR for AEGIS round ${round} — the ONLY writer of map state.",
    "You are the INTEGRATOR for AEGIS round ${round} — the ONLY writer of map state. IDEMPOTENCY: a previous attempt may have crashed mid-write, "
    "so before appending check state/graph.jsonl, edges.jsonl and seen.jsonl for entries with first_seen_round=${round} and skip ids/URLs already present; "
    "rewrite whole files (frontier_queue, LATEST, ARCHITECTURE-DRAFT) via a temp file then rename, never truncate in place.")

left = [l for l in s.splitlines() if 'ARSENAL' in l or 'PLAYBOOK' in l or 'A-LADDER' in l]
assert not left, left
open('/home/patrickd/aegis/research/aegis.workflow.js', 'w').write(s)
print('ok', len(s))
