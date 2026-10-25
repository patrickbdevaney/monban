#!/usr/bin/env python3
"""AEGIS round-3 integrator: dedup vs round-1 state, verifier grades, append graph/edges/seen/queries,
rebuild frontier queue, predictions. Deterministic. Inputs: raw/round-002/*.json (+ .structured.json for
explorers 05 and 11 whose raw files were truncated by the crash), _verify_r2_verdicts.json, _verify_r2_missed.json.
Run once:  python3 -I _integrate_r2.py  (refuses to run twice: checks graph for first_seen_round==2)."""
import json, glob, os, re, sys, collections
sys.path.insert(0, '/home/patrickd/aegis/research/tools')
from novelty_gate import toks, jac, nscore  # same tokenizer as the gate

R = 3
DATE = '2026-10-24'          # per integrator brief (last_verified value); wall clock is 2026-10-25
ROOT = '/home/patrickd/aegis/research'
ST = ROOT + '/state'
RAW = ST + '/raw/round-003'
SCR = '/tmp/claude-1000/-home-patrickd/b4045317-3a36-45b5-8cfe-a4b20991f0b0/scratchpad'
DRY = '--dry' in sys.argv

from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
def canon(u):  # META §8 form (gh:owner/repo for repo roots), identical to round-1 integrator
    try: p = urlsplit(u.strip())
    except ValueError: return u.strip()
    host = (p.hostname or '').lower()
    if host.startswith('www.'): host = host[4:]
    if p.scheme == 'file': return u.strip()
    if host == 'arxiv.org':
        m = re.search(r'(\d{4}\.\d{4,5})', p.path)
        if m: return 'arxiv:' + m.group(1)
    if host == 'github.com':
        parts = [x for x in p.path.split('/') if x]
        if len(parts) == 2: return f'gh:{parts[0]}/{parts[1]}'
    q = [(k, v) for k, v in parse_qsl(p.query) if not k.lower().startswith(('utm_', 'ref', 'fbclid', 'gclid'))]
    path = re.sub(r'/+$', '', p.path) or '/'
    return urlunsplit(('https', host, path, urlencode(sorted(q)), ''))

def walk_urls(o, acc):
    if isinstance(o, str):
        for u in re.findall(r'(?:https?|file)://[^\s"\'<>)\]]+', o): acc.add(u.rstrip('.,;'))
    elif isinstance(o, dict):
        for v in o.values(): walk_urls(v, acc)
    elif isinstance(o, list):
        for v in o: walk_urls(v, acc)

def jl(path):
    out = []
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line: out.append(json.loads(line))
    return out

PMAP = {'W-DATA': 'W-DATA-GATE', 'W-AGENT': 'W-AGENT-PROTOCOL', 'W-ISOLATE': 'W-ISOLATION', 'W-AUTH': 'W-AUTHZ',
        'W-PARSE': 'W-TRANSPORT', 'W-WASM': 'W-ISOLATION', 'W-PROOF': 'W-FORMAL', 'W-BRIDGE': 'W-BRIDGE'}
def pillar(dom):
    dom = dom or ''
    if dom.startswith('C-CRYPTO'): return 'W-PQC'
    if dom.startswith('K-CALIBRATION'): return 'K-CALIBRATION'
    m = re.search(r'W-[A-Z]+(?:-[A-Z]+)*', dom)
    if not m: return 'W-?' + dom
    p = m.group(0)
    for k, v in PMAP.items():
        if p == k or p.startswith(k + '-') and k in ('W-DATA', 'W-AGENT'): return v
    return PMAP.get(p, p)

# ---------------- load existing state ----------------

# ---------------- load existing state ----------------
G = {}
for n in jl(ST + '/graph.jsonl'): G[n['id']] = n          # last record wins
if any(n.get('first_seen_round') == R or n.get('revision_round') == R for n in G.values()):
    sys.exit('round 3 already integrated; refusing to append twice')
E_old = jl(ST + '/edges.jsonl')
E_keys = {(e['src'], e['dst'], e['type']) for e in E_old}
seen_old = {}
for s in jl(ST + '/seen.jsonl'): seen_old[s['canon']] = s

# ---------------- load round-3 explorer output ----------------
EXTRA_SEEDS = {'09': [  # explorer 09 raw JSON lost its seeds key; restored from the relayed compact findings
 ('Runtime-verify tonic Server default effective SETTINGS_MAX_CONCURRENT_STREAMS and async-graphql axum behaviour (text/plain POST, GET mutation, body cap) under heavy.sh', 'L4', 'W-TRANSPORT/ingress', .5, 'Two source-read defaults findings (B/C) that could become CVE-class defaults; cheap implementation-phase spike'),
 ('Does hyper/axum/tonic routing canonicalize :path/URI before tower authz layers (Rust analogue of grpc-go CVE-2026-33186)? Differential test h2 :path variants', 'L4', 'W-TRANSPORT/ingress', .45, 'Only spec-differential class not covered by budgets; no Rust evidence either way'),
 ('MCP streamable HTTP and A2A as ingress front ends: SSE session resumption, Origin/DNS-rebinding rules, per-session budgets from the MCP spec and CVEs', 'L4', 'W-AGENT-PROTOCOL', .4, 'SSE budget class maps directly to MCP transport; agent-swarm reconnect storms unmeasured'),
 ('Outbound egress guard design for webhook delivery/callback registration: IP pinning at connect, redirect policy, NAT64/6to4 handling, Rust crates (reqwest resolver hooks, ssrf-safe connectors)', 'L3', 'W-ABUSE', .4, 'Highest-count 2026 webhook CVE class and outside ingress; uncovered in map'),
 ('Formal/Kani feasibility for a ~1k-LOC RFC 6455 frame codec and the 349-LOC Standard Webhooks verifier', 'L4', 'W-FORMAL', .35, 'Smallest candidate parsers for the first machine-checked ingress modules'),
]}
files = {}
for f in sorted(glob.glob(RAW + '/[0-9][0-9]-*.json')):
    b = os.path.basename(f)
    o = json.load(open(f))
    if isinstance(o, dict) and o.get('nodes'): files[b[:2]] = (b, o)
assert len(files) == 12, sorted(files)
LABEL = {}
nodes, edges, seeds, explorer_of = [], [], [], {}
for pre, (b, o) in sorted(files.items()):
    label = re.sub(r'^\d+-', '', b.split('.')[0])
    LABEL[pre] = label
    for n in o.get('nodes', []):
        n = dict(n); n['explorer'] = f'{pre}-{label}'; explorer_of[n['id']] = pre
        n['pillar'] = pillar(n.get('domain', ''))
        nodes.append(n)
    for e in o.get('edges', []):
        edges.append({'src': e['src'], 'dst': e['dst'], 'type': e['type'], 'note': e.get('note', ''), 'evidence_url': '', 'origin': f'explorer-{pre}', 'round': R})
    for s in o.get('seeds', []):
        s = dict(s); s['from_explorer'] = pre; seeds.append(s)
    for q, l, d, g, r in EXTRA_SEEDS.get(pre, []):
        seeds.append({'question': q, 'layer': l, 'domain': d, 'expected_info_gain': g, 'reason': r, 'from_explorer': pre})

V = json.load(open(RAW + '/_verify_r3_verdicts.json'))
VM = json.load(open(RAW + '/_verify_r3_missed.json'))
for vn in VM['vnodes']:
    n = dict(vn); n['domain'] = vn['pillar']; n['explorer'] = vn['found_by']; n['specifics'] = ''
    n['overclaim_risk'] = 'Verifier-sourced; single verification pass.'; n['underclaim_risk'] = ''
    explorer_of[n['id']] = 'V' + vn['found_by'][-2:]
    nodes.append(n)

# ---------------- integrator dedup decisions ----------------
SAME_AS = [  # (round-3 node, canonical existing node, note)
 ('zd.l4-config-push-outage', 'r2e11.cloudflare-2025-11-18', 'same incident (Cloudflare 2025-11-18); r3 adds lessons validate-then-swap/canary/kill switch; verifier: root cause was a ClickHouse permission change doubling query output, not an operator push'),
 ('sc3.arrayref-trust-model-gap', 'sc.arrayref-incident', 'same incident RUSTSEC-2026-0260; r3 adds 86-107 min live window, proc-macro1 build.rs delivery and the cargo-vet publisher-trust gap'),
]
REFINES = [  # (src refines dst) cross-explorer / cross-round
 ('sc3.rustls-advisory-batch-2026-10', 'rec60-rustls-0.23.46-downgrade'), ('r3pq.hrr-acceptance-test', 'rec60-rustls-0.23.46-downgrade'),
 ('r3e11.quinn-proto-0.11.18-19', 'crate-quinn'), ('r3e09.grpc-defect-classes', 'dpf-upstream-http-grpc'),
 ('r3e11.wasi-http-host-side-framing-batch', 'wasmtime-minimal-config-pin'), ('ac.i07-wasmtime-cancel-advisories', 'wasmtime-advisory-share-by-config'),
 ('r3e07-tls-handshake-floor', 'w02.handshake-pq-cost'), ('r3e11.tokio-1.54-regression-and-asyncfd', 'w02.pingora-tokio-panic'),
 ('v3.aws-lc-rs-fips-sys-range', 'crate-aws-lc-rs'), ('v3.cve-2026-14666-session-persistence', 'irl-l5-q1012-role-plan-cache-gate'),
 ('v3.cve-2026-14666-session-persistence', 'sdg-rls-plan-cache-family'), ('v3.go81199-sigalgs-cert-trigger', 'r3pq.go127-mldsa-middlebox'),
 ('v3.typed-authz-ctx-prior-art', 'dx.sdk-design-space-matrix'), ('v3.claw-swe-shared-task-pool', 'dx.claw-swe-rust-agentic'),
 ('v3.nginx-quic-bpf-live-upgrade-limits', 'zd.l4-quic-across-processes'), ('v3.iceoryx2-fosdem-2026', 'w02.shm-crate-landscape'),
 ('w02.norm-copy-cost-measured', 'w02.ingress-design-verdict'), ('irl-l5-q1012-role-plan-cache-gate', 'sdg-rls-plan-cache-family'),
]
CONTRADICTS = [  # (src, dst, note)
 ('v3.aws-lc-rs-fips-sys-range', 'ops.fips-module-boundary-pin', 'explorer-12 lever "any aws-lc-rs >=1.15,<1.18" is wrong: 1.17.3 needs fips-sys ^0.13.16, 1.17.4 ^0.13.17; safe range 1.15.2-1.17.2'),
 ('v3.claw-swe-shared-task-pool', 'dx.swebench-multilingual-rust', 'same Rust task pool; not independent corroboration'),
 ('r3e11.tokio-1.54-regression-and-asyncfd', 'sc3.rustls-advisory-batch-2026-10', 'overlap, not contradiction: both report RUSTSEC-2026-0384/0386; r3e11 adds 1.54.0 yanked and no 1.52.x backport'),
 ('r3pq.hrr-acceptance-test', 'dpf-rustls-pq-driver-inheritance', 'default 0.23.46 server follows client group order: an X25519-first client gets classical; PQ only by HRR under pq-required kx_groups'),
 ('ac.counter-hypothesis-one-txn-outbox', 'sdg-failed-request-no-mutation', 'one-txn+outbox closes ~5 of 15 cancellation instances; INV-NOMUT needs NC1-NC8'),
]
BRIDGES = [  # integrator cross-explorer edges (type, note): the round-3 bridges
 ('ac.l5-inv-nomut-c', 'irl-l5-backend-refinement-contract', 'precondition_for', 'BRIDGE pooled-connection hygiene: NC3 checkin predicate (ReadyForQuery I, no outstanding replies) is a precondition of the tenant role/GUC binding the lowering theorem trusts'),
 ('ac.i01-sqlx-4393-begin-cancel', 'irl-l5-q1012-role-plan-cache-gate', 'related', 'BRIDGE: q1012 shows SET LOCAL ROLE + plan cache correct on clean connections; sqlx#4393 shows a cancelled BEGIN leaves a pooled conn inside the previous principal\'s txn: both gates are needed'),
 ('r3e05.tenuo-cel-attenuation-bypass', 'irl-empty-or-widening-family', 'related', 'BRIDGE checker-vs-evaluator class: leaf-only evaluation + syntactic subsumption checker (Tenuo) and dropped empty sub-expressions (SQLAlchemy or_()) both widen authority silently; fix = evaluate the full conjunction in one canonical evaluator, Or([])=FALSE'),
 ('irl-l5-unsound-lowering-denylist', 'r3e09.grpc-defect-classes', 'related', 'BRIDGE canonical identity: grpc-go :path authz bypass and SQL collation/LIKE tenant collisions are one class (policy compares a non-canonical form); one canonicalization owner per identity, binary collation everywhere'),
 ('r3pq.prefer-pq-feature-pitfall', 'sc3.l5-ci-gate-list', 'constrains', 'BRIDGE supply chain x PQC: lockfile/feature audit must assert prefer-post-quantum on every rustls in Cargo.lock (default-features=false is silently classical)'),
 ('sc3.cooldown-executed-cargo-198', 'r3pq.hrr-acceptance-test', 'related', 'BRIDGE: a 14-day cooldown resolved rustls 0.23.45 (RUSTSEC-2026-0349 PQ downgrade); the HRR acceptance test is the behavioural backstop when cooldown and security floors disagree'),
 ('w02.ipc-hop-cost-1core', 'r3e07-defender-stage-cost-table', 'quantifies', 'BRIDGE perf budget: 4.8 us UDS hop vs ~424-848 us full TLS handshake: adapter IPC is <1% of a new-connection request but ~100x a cached key lookup'),
 ('ac.attacker-chosen-cancel-instant', 'r3e07-tls-handshake-floor', 'related', 'BRIDGE abuse x atomicity: an RST-timed cancel costs the attacker one frame but forces a discard-on-cancel reconnect (NC3, TLS+SCRAM); must be charged (NC4) or it is a reconnect amplifier against the ~1.1k full-handshake/s floor'),
 ('zd.l4-config-push-outage', 'r3e09.L5-per-frontend-budget-table', 'related', 'BRIDGE fail-closed config: validate-then-swap with last-known-good (reload) + CI fails any effective unbounded limit (ingress); defaults are the bug (tonic streams None, async-graphql limits None, Pingora 105297)'),
 ('zd.l5-upgrade-protocol', 'ac.l5-inv-nomut-c', 'related', 'BRIDGE drain = cancellation: UP-4 drain deadline cancels in-flight requests; NC2 commit-point latch decides which complete; one T_drain bound for both'),
 ('r3e09.webhook-defect-classes', 'dx.l5-decision-sdk-shape', 'constrains', 'raw-body signatures need Exchange-level raw bytes: the typed Ctx must expose a verified-before-parse capability instead of only a normalized body'),
 ('r3e11.cross-stack-bug-classes-sep-oct-2026', 'r3e09.core-vs-per-frontend-matrix', 'supports', 'BRIDGE: trailers, H3->H1 bridging, validator/handler divergence and unbounded sizes recur across 7 stacks in 6 weeks; all are core-once classes (I-ONE-PARSE = one canonical parse handed to policy and handler)'),
 ('r3e05.everparse-cborrs-2026-10', 'irl-l5-lean-lowering-theorems', 'related', 'BRIDGE proof pattern: token (verified CBOR parser + core-Lean T1-T6) and data plane (Lowering.lean) share "verified parser + core-Lean semantics theorem + DRT to Rust" on one toolchain (Lean core, no Mathlib)'),
 ('sc3.repro-ablation-golden', 'zd.l5-upgrade-protocol', 'related', 'BRIDGE release identity: binary hash depends on toolchain and auditable mode; the upgrade protocol signature-checks B against the attested digest before spawn'),
 ('ops.fips-module-boundary-pin', 'sc3.golden-lock-gate-run', 'conflicts_with', 'BRIDGE FIPS x golden lock: the executed golden lock resolved aws-lc-rs 1.18.2 / aws-lc-sys 0.46 (unvalidated v4 line); the FIPS golden needs aws-lc-rs 1.15.2-1.17.2 + aws-lc-fips-sys =0.13.11 and must still satisfy rustls 0.23.46'),
 ('r3e07-L5-budget-invariants-additions', 'ac.l5-inv-nomut-c', 'related', 'BRIDGE one ledger: NC4 (pre-debit, never refund, charge cancellations) and I8 aggregate expensive-tier budget are the same admission ledger'),
 ('dx.exp-error-signal', 'sc3.l5-new-crate-intake', 'related', 'BRIDGE agents weaken boundaries when tools suggest it (rustc "make the field public"; cargo add of hallucinated crates): deny agent edits to sdk/** and route cargo add through the intake gate'),
 ('irl-l5-differential-oracle-harness', 'ac.l5-cancel-sweep-harness', 'related', 'BRIDGE executed oracles beat reading: both harnesses found bugs in code written to be safe (hardened SQLite lowering; 3 unreleased driver fixes); run both against real PG in nightly CI'),
 ('w02.L5-adapter-oop-threshold-table', 'ac.principle-cancel-equals-crash', 'related', 'BRIDGE out-of-process adapters make cancel-equals-crash cheap: killing a helper resets all driver state; costs 4.8 us/hop + 250-615 us respawn'),
]

ids_new = {n['id'] for n in nodes}
ids_all = set(G) | ids_new
for a, b, _ in SAME_AS: assert a in ids_new and b in G, (a, b)
for a, b in REFINES: assert a in ids_all and b in ids_all, (a, b)
for a, b, _ in CONTRADICTS: assert a in ids_all and b in ids_all, (a, b)
for a, b, _, _ in BRIDGES: assert a in ids_all and b in ids_all, (a, b)
miss_v = [k for k in V if k not in ids_new]
assert not miss_v, miss_v

# ---------------- apply verdicts; split new vs revision of existing ids ----------------
new_nodes, revisions = [], []
for n in nodes:
    n['grade_explorer'] = n.get('evidence_grade'); n['confidence_explorer'] = n.get('confidence')
    if n['id'] in V:
        g, c, d, note = V[n['id']]
        n['evidence_grade'] = g; n['confidence'] = c; n['verify'] = {'status': 'two-sided', 'direction': d, 'note': note, 'round': R}
    elif n['explorer'].startswith('verifier'):
        n['verify'] = {'status': 'verifier-sourced', 'direction': 'new', 'note': 'promoted from verifier missed-list', 'round': R}
    else:
        n['verify'] = {'status': 'not-sampled', 'direction': 'unchanged', 'note': 'verifier sampled other nodes; explorer grade kept', 'round': R}
    n['last_verified'] = DATE
    n['urls_canon'] = sorted({canon(u) for u in n.get('urls', []) if u})
    if n['id'] in G:   # explorer 12 re-verification of an existing node: revision record, never a new id
        old = G[n['id']]
        rev = dict(old)
        rev.update({k: n[k] for k in ('evidence_grade', 'confidence', 'verify', 'last_verified') if k in n})
        rev['revision_round'] = R
        rev['revision_by'] = n['explorer']
        rev['revision_title'] = n.get('title')
        rev['revision_summary'] = n.get('summary')
        rev['revision_specifics'] = n.get('specifics', '')
        rev['urls'] = list(dict.fromkeys(list(old.get('urls', [])) + list(n.get('urls', []))))
        rev['urls_canon'] = sorted({canon(u) for u in rev['urls']})
        rev['grade_before_revision'] = old.get('evidence_grade'); rev['confidence_before_revision'] = old.get('confidence')
        rev['first_seen_round'] = old.get('first_seen_round', 1)
        revisions.append(rev)
    else:
        n['first_seen_round'] = R
        new_nodes.append(n)

def revise(i, **kw):
    base = next((r for r in revisions if r['id'] == i), None) or G[i]
    rev = dict(base); rev.update(kw); rev['revision_round'] = R; rev['revision_by'] = 'integrator-r3'; rev['last_verified'] = DATE
    if base in revisions: revisions.remove(base)
    revisions.append(rev)
revise('crate-aws-lc-rs', correction='RESOLVED r3: aws-lc-fips-sys =0.13.11 vendors AWS-LC FIPS 3.1.0 (CMVP #5298/#5314, ML-KEM approved, ML-DSA not); only aws-lc-rs 1.15.2-1.17.2 accept fips-sys ^0.13.1 (1.17.3 needs ^0.13.16, 1.17.4 ^0.13.17, 1.18 needs 0.14.x). See ops.fips-module-boundary-pin (r3 revision), v3.aws-lc-rs-fips-sys-range.', evidence_grade='A', confidence=0.85)
revise('abuse-pow-economics-calc', correction='Superseded r3 by measurement: native SHA-256 62-89 MH/s single thread (not 2.3 MH/s), 1.1-3.4 GH/s multi-thread, in-browser ~150 kH/s; asymmetry 430-860x single-thread. See r3e07-pow-asymmetry-measured.', superseded_by='r3e07-pow-asymmetry-measured')
revise('abuse-L5-admission-pipeline-1vcpu', correction='r3 simulator: r2 default parameters fail C1-C4 under a 10k-IP solver swarm (human failure 99.1%, verified success 59.7%); replaced by r3e07-L5-tuned-default-table (D) with fresh-session class, aggregate expensive-tier budgets and handshake reservation.', superseded_by='r3e07-L5-tuned-default-table')
revise('sdg-rls-plan-cache-family', correction='r3: CVE-2026-14666 fix 1974acf23 (no regression test) and an executed q1012 reproducer on 17.11/19rc1 (SET LOCAL ROLE + statement cache safe on patched minors; session-level set_config leaks). Advisory: stale policies persist until invalidation or session end, so recycle pooled connections after the minor upgrade.')
revise('v.cargo-min-publish-age-rfc3923', correction='r3 dates via gh api: RFC 3923 PR created 2026-02-23, merged 2026-05-18; stabilization PR #17335 merged 2026-08-28 (milestone 1.100.0); r1 recorded PR creation as acceptance. Executed on 1.98.0 nightly: 14-day window resolves 6 known advisories on the golden lock.')
revise('sc.slopsquat-rates', correction='r3: Rust data exists (arXiv 2606.08444, Internetware 2026): headline 22.23% counts std items; re-extraction gives 6.1% of use-roots (0.7-3.0% of samples), 272 unregistered names. See sc3.slopsquat-rust-study-2606.')
revise('w02.ingress-design-verdict', correction='r3: copy cost measured (zero-copy Bytes 0 userspace copies, owned codec +0.58-0.72 ms per 10 MB at 1 core); core object must be an Exchange with a message stream; L4/PROXY handling separate below L7; WebTransport and permessage-deflate deferred from golden v1 (r3e09.ring1-verdict-amendment, w02.norm-copy-cost-measured).')
revise('inv-attenuation-monotonicity', correction='r3 counterexample: Tenuo 0.3.3 (cel feature) leaf-only evaluation + syntactic subsumption checker accepts widening children (r3e05.tenuo-cel-attenuation-bypass, A). Golden form: evaluate the conjunction of every caveat in the chain; monotonicity is then List.all_append (r3e05.l5-token-wire-format-lean).')
revise('dpf-rustls-pq-driver-inheritance', correction='r3: only with the prefer-post-quantum feature; rustls 0.23.46 with default-features=false orders X25519 first (319 B ClientHello, classical). Server side follows client order (r3pq.prefer-pq-feature-pitfall, r3pq.hrr-acceptance-test).')
revise('sc.cooldown-policy', correction='r3 executed: native cargo cooldown exists (stable in 1.100.0); a blanket 14-day window on the golden lock resolved rustls 0.23.45 and 6 advisories and broke exact pins. Policy: 7 days + audited security-advisory bypass (sc3.l5-cooldown-security-bypass).')
revise('rec60-rustls-0.23.46-downgrade', correction='r3 server-side verdicts executed (r3pq.hrr-acceptance-test): the default 0.23.46 server follows client group order, so an X25519-first client negotiates classical; pq-required kx_groups=[X25519MLKEM768] yields HRR 0x11EC or alert 40.')
revise('dpf-l5-adapter-isolation', correction='r3: out-of-process hop measured 4.8 us (UDS) / 2.1 us (futex ring) per call on one pinned laptop core vs 0.02-0.05 us in process; placement by unsafe/C-binding count first, hop budget second (w02.L5-adapter-oop-threshold-table, C).')

# ---------------- clusters / singletons ----------------
par = {i: i for i in ids_all}
def find(x):
    while par[x] != x: par[x] = par[par[x]]; x = par[x]
    return x
for a, b, _ in SAME_AS: par[find(a)] = find(b)
for n in new_nodes:
    c = find(n['id']); n['cluster'] = c; n['merged_into'] = c if c != n['id'] else None
merged_new = [n for n in new_nodes if n['merged_into']]
singletons = [n for n in new_nodes if not n['merged_into'] and not n['explorer'].startswith('verifier')]
xlinked = set()
all_new_edges = edges + [{'src': a, 'dst': b} for a, b in REFINES] + [{'src': a, 'dst': b} for a, b, _ in CONTRADICTS] + [{'src': a, 'dst': b} for a, b, _, _ in BRIDGES]
def grp(i):
    if i in G: return 'old'
    return explorer_of.get(i, '?')[:3]
for e in all_new_edges:
    if e['src'] in ids_all and e['dst'] in ids_all and grp(e['src']) != grp(e['dst']):
        xlinked.add(e['src']); xlinked.add(e['dst'])
strict_singletons = [n for n in singletons if n['id'] not in xlinked]
# cross-explorer near-duplicate scan among round-3 new nodes (title+summary Jaccard)
nt = [(n['id'], explorer_of.get(n['id']), toks(n.get('title', '') + ' ' + n.get('summary', ''))) for n in new_nodes]
xdup = []
for i in range(len(nt)):
    for j in range(i + 1, len(nt)):
        if nt[i][1] != nt[j][1]:
            s = jac(nt[i][2], nt[j][2])
            if s >= .2: xdup.append((round(s, 2), nt[i][0], nt[j][0]))
xdup.sort(reverse=True)

# ---------------- edges ----------------
for a, b, note in SAME_AS: edges.append({'src': a, 'dst': b, 'type': 'same-as', 'note': note, 'evidence_url': '', 'origin': 'integrator', 'round': R})
for a, b in REFINES: edges.append({'src': a, 'dst': b, 'type': 'refines', 'note': 'integrator cross-explorer/cross-round link', 'evidence_url': '', 'origin': 'integrator', 'round': R})
for a, b, note in CONTRADICTS: edges.append({'src': a, 'dst': b, 'type': 'contradicts', 'note': note, 'evidence_url': '', 'origin': 'integrator/verifier', 'round': R})
for a, b, t, note in BRIDGES: edges.append({'src': a, 'dst': b, 'type': t, 'note': note, 'evidence_url': '', 'origin': 'integrator-bridge', 'round': R})
E2, k2 = [], set()
for e in edges:
    k = (e['src'], e['dst'], e['type'])
    if k in k2 or k in E_keys: continue
    k2.add(k); E2.append(e)
edges = E2
dangling = [e for e in edges if e['src'] not in ids_all or e['dst'] not in ids_all]
assert not dangling, dangling[:5]
n_bridges = sum(1 for e in edges if e['origin'] == 'integrator-bridge')

# ---------------- seen ----------------
urlmap = collections.defaultdict(lambda: {'explorers': set(), 'nodes': set(), 'raw': None})
for pre, (b, o) in files.items():
    acc = set(); walk_urls(o, acc)
    for u in acc:
        c = canon(u); urlmap[c]['explorers'].add(pre); urlmap[c]['raw'] = urlmap[c]['raw'] or u
for n in nodes:
    for u in n.get('urls', []):
        if not u or not re.match(r'(https?|file)://', u): continue
        c = canon(u); urlmap[c]['nodes'].add(n['id']); urlmap[c]['raw'] = urlmap[c]['raw'] or u
        if n['explorer'].startswith('verifier'): urlmap[c]['explorers'].add(n['explorer'])
VERIFIER_URLS = ['https://github.com/sfackler/rust-postgres/pull/1374', 'https://github.com/sfackler/rust-postgres/issues/1394', 'https://github.com/diesel-rs/diesel_async/pull/305',
 'https://github.com/golang/go/issues/74831', 'https://github.com/oxidecomputer/dropshot/pull/701', 'https://github.com/oxidecomputer/omicron/pull/3140',
 'https://docs.rs/crate/shmem-ipc/latest', 'https://github.com/hydroid7/iceoryx2', 'https://fosdem.org/2026/events/attachments/M7TKVG-meet-iceoryx2/slides/262419/fosdem-mi_tra9vup.pdf',
 'https://arxiv.org/html/2606.08444v2', 'https://arxiv.org/html/2601.02060v1', 'https://osv.dev/vulnerability/CVE-2026-33186', 'https://www.postgresql.org/support/security/CVE-2026-14666/',
 'https://libraries.io/cargo/typesec-agent', 'https://rust-digger.code-maven.com/crates/policy-core', 'https://docs.rs/typesec-agent/0.13.1', 'https://docs.rs/crate/capsec/latest',
 'https://snyk.io/blog/type-level-security/', 'https://crates.io/api/v1/crates/aws-lc-rs/versions', 'https://crates.io/api/v1/crates/aws-lc-fips-sys/versions',
 'https://github.com/rustls/rustls/issues/3214', 'https://github.com/golang/go/issues/81199', 'https://nginx.org/en/docs/http/ngx_http_v3_module.html']
for u in VERIFIER_URLS:
    c = canon(u); urlmap[c]['explorers'].add('verifier'); urlmap[c]['raw'] = urlmap[c]['raw'] or u
seen_new = [c for c in urlmap if c not in seen_old]
seen_re = [c for c in urlmap if c in seen_old]

# ---------------- queries ----------------
def classify(q, axes):
    t = (q + ' ' + axes).lower()
    src = ('paper' if re.search(r'arxiv|paper|osdi|sosp|usenix|pldi|popl|ccs|ndss|icse|thesis|\bpdf\b|vldb|eprint', t) else
           'spec-rfc' if re.search(r'rfc|draft|spec|datatracker|ietf|w3c|nist|fips|standard|cnsa|sep-|primary-law|eur-lex|regulation', t) else
           'repo-advisory' if re.search(r'ghsa|advisor|github|issue|repo|crate|release|changelog|rustsec|gh ', t) else
           'cve-incident' if re.search(r'cve|kev|incident|exploit|attack|breach|oss-security|compromis|postmortem|outage', t) else
           'benchmark' if re.search(r'bench|latency|throughput|rps|measure|own-experiment|perf|rss', t) else
           'vendor-doc' if re.search(r'blog|vendor|docs|cloudflare|aws|google|microsoft|stripe', t) else
           'forum' if re.search(r'forum|reddit|hacker news|lobste|discussion|mailing|lkml', t) else
           'talk' if re.search(r'talk|slides|def ?con|black ?hat|conference', t) else 'web-other')
    stance = ('skeptic-negative' if re.search(r'contrarian|negative|skeptic|critique|fail|limit|overhype|bypass|pitfall|footgun|wrong|doesn.t|not |prosecutor', t) else
              'attacker' if re.search(r'attack|exploit|offens|escape|smuggl|poison|offsec', t) else 'proponent')
    era = ('last-60d' if re.search(r'last.?60|recen|oct 2026|sep 2026|aug 2026|2026-(08|09|10)|october|september', t) else
           'historical' if re.search(r'histor|20(0|1)\d|legacy|foundational|retrospect', t) else '2025-26')
    vocab = ('PL-formal' if re.search(r'pl-formal|formal|lean|verus|kani|proof|tla|smt|coq|f\*', t) else
             'cryptography' if re.search(r'crypto|pqc|mlkem|ml-kem|tls|fips|cmvp|stek|ticket', t) else
             'offensive' if re.search(r'offens|attack|exploit|offsec|cve|ghsa|bypass|smuggl', t) else
             'standards-policy' if re.search(r'standards|policy|gov|law|regulat|cra|fedramp|nist|ssdf', t) else
             'network-SRE' if re.search(r'sre|ops|systemd|kernel|network|queueing|cdn|load', t) else
             'economics' if re.search(r'econom|cost|pricing|market|payment|x402', t) else
             'database' if re.search(r'database|db-|sql|redis|mongo|kafka|store|wal|fsync', t) else
             'web-dev' if re.search(r'web-dev|practitioner|api|browser|framework', t) else 'systems')
    scale = ('government' if re.search(r'gov|fedramp|fips|cnsa|nist', t) else 'household' if re.search(r'household|vps|1 ?vcpu|laptop', t) else
             'hyperscaler' if re.search(r'hyperscal|cloudflare|aws|google|cdn', t) else 'enterprise' if re.search(r'enterprise', t) else 'unspecified')
    return src, stance, era, vocab, scale
LABEL2PILLAR = {'dataplane-ir-lowering-soundness': 'W-DATA-GATE+W-FORMAL', 'modularity-ipc-and-normalization-copy-spike': 'W-PERF',
 'pq-authentication-and-hrr-acceptance': 'W-PQC', 'supply-chain-executed-on-golden-pins': 'W-SUPPLY', 'golden-lock': 'W-SUPPLY',
 'authz-token-format-code-level': 'W-AUTHZ', 'bridge-async-cancellation-failure-atomicity': 'W-BRIDGE',
 'abuse-economics-and-swarm-simulation': 'W-ABUSE', 'dx-agent-checkable-handler-surface': 'W-DX',
 'ingress-nonhttp-frontends-defect-classes': 'W-TRANSPORT-INGRESS', 'zero-downtime-reload-and-scaleout-state': 'W-OPS+W-PERF',
 'uu-adjacent-fields-and-unused-sources': 'W-UNKNOWN', 'calibration-two-sided-could-flip-decisions': 'K-CALIBRATION'}
prior_Q = jl(ST + '/queries.jsonl')
prior_q = [toks(q.get('query', '')) for q in prior_Q]
prior_cells = {q.get('cell') for q in prior_Q}
prior_cells5 = {q.get('cell5') for q in prior_Q if q.get('cell5')}
Q = []
for line in open(RAW + '/_queries.log', errors='replace'):
    p = line.rstrip('\n').split('\t')
    if len(p) < 2 or not p[1].strip(): continue
    lab, q, axes = p[0], p[1], (p[2] if len(p) > 2 else '')
    if lab == 'golden-lock': lab = 'supply-chain-executed-on-golden-pins'
    src, stance, era, vocab, scale = classify(q, axes)
    pl = LABEL2PILLAR.get(lab, '?')
    Q.append({'round': R, 'label': lab, 'query': q, 'axes': axes, 'pillar': pl, 'source_type': src, 'stance': stance, 'era': era,
              'vocab': vocab, 'scale': scale, 'cell': f'{pl}|{src}|{stance}|{era}', 'cell5': f'{pl}|{src}|{stance}|{era}|{vocab}'})
tq = [toks(x['query']) for x in Q]
nd_pairs = []
for i in range(len(Q)):
    best = (0, None)
    for j in range(i):
        s = jac(tq[i], tq[j])
        if s > best[0]: best = (s, j)
    Q[i]['max_prior_jaccard'] = round(best[0], 2)
    Q[i]['near_dup_of'] = (Q[best[1]]['label'] + ': ' + Q[best[1]]['query']) if best[0] >= .5 else None
    if best[0] >= .5: nd_pairs.append((Q[i]['label'], Q[best[1]]['label'], round(best[0], 2), Q[i]['query'], Q[best[1]]['query']))
    bp = max(((jac(tq[i], pq), k) for k, pq in enumerate(prior_q)), default=(0, None))
    Q[i]['max_prior_round_jaccard'] = round(bp[0], 2)
    if bp[0] >= .5: Q[i]['prior_round_near_dup_of'] = f"r{prior_Q[bp[1]].get('round')} {prior_Q[bp[1]].get('label')}: {prior_Q[bp[1]].get('query')}"
cells = collections.Counter(x['cell'] for x in Q)
cells5 = collections.Counter(x['cell5'] for x in Q)
direction_diversity = len(cells) / len(Q)
direction_diversity5 = len(cells5) / len(Q)
new_cells = [c for c in cells if c not in prior_cells]
new_cells5 = [c for c in cells5 if c not in prior_cells5]
q_in_new_cells = sum(cells[c] for c in new_cells) / len(Q)

yl = {}
for lab in sorted(set(LABEL2PILLAR) - {'golden-lock'}):
    nq = sum(1 for x in Q if x['label'] == lab)
    nn = [n for n in new_nodes if n['explorer'].endswith(lab)]
    revs = sum(1 for r in revisions if str(r.get('revision_by', '')).endswith(lab))
    l45 = sum(1 for n in nn if n.get('layer') in ('L4', 'L5') and not n['merged_into'])
    yl[lab] = (nq, len(nn), l45, (round(l45 / nq, 2) if nq else None), revs)

# ---------------- frontier queue ----------------
Qold = jl(ST + '/frontier_queue.jsonl')
DONE_IDS = {  # id: (status, resolved_by)
 'q2-001': ('done', 'w02.ipc-hop-cost-1core, w02.redis-presign-shaped-ops, w02.helper-process-rss-spawn, w02.L5-adapter-oop-threshold-table (laptop core; 1-vCPU VPS rerun is a new seed)'),
 'q2-016': ('done', 'w02.norm-copy-cost-measured, w02.ingress-design-verdict-measured-update'),
 'q1-002': ('done', 'r3e09.ring1-verdict-amendment, r3e09.core-vs-per-frontend-matrix, w02.norm-copy-cost-measured, w02.ipc-hop-cost-1core'),
 'q1-012': ('done', 'irl-l5-q1012-role-plan-cache-gate (patched minors; unpatched 17.10 control is a new seed)'),
 'q2-011': ('partial', 'irl-l5-lean-lowering-theorems (unchecked, T4 sorry), irl-l5-differential-oracle-harness, irl-l5-backend-refinement-contract'),
 'q2-002': ('done', 'r3pq.hrr-acceptance-test, r3pq.rustls-kx-client-order'),
 'q1-043': ('done', 'r3pq.header-limit-table, r3pq.hpack-large-token-literal'),
 'q1-073': ('done', 'r3pq.composite-mldsa-status-sizes'),
 'q1-103': ('partial', 'r3pq.chrome-cqrp-testing (ML-DSA private PKI from Chrome 150); Firefox/Apple plans: r3pq.apple-mtc-policy-absent'),
 'q1-124': ('partial', 'r3pq.mtc-server-obligations (MTC draft-07 status; KVerus/io_uring parts open)'),
 'q1-028': ('done', 'sc3.slopsquat-rust-study-2606 (agent-loop installable rate is a new seed)'),
 'q1-052': ('partial', 'sc3.repro-ablation-golden (same host only; cross-host open)'),
 'q1-092': ('done', 'sc3.repro-ablation-golden (1.98.0/1.99.1 identical, 1.93.1 differs)'),
 'q1-077': ('done', 'sc3.incident-gate-matrix (C), sc3.slsa-scope-limit'),
 'q1-127': ('partial', 'sc3.xz-window-cooldown-limit (research.swtch timeline; Freund post not fetched)'),
 'q1-132': ('done', 'r3e11.tokio-1.54-regression-and-asyncfd, sc3.rustls-advisory-batch-2026-10'),
 'q1-022': ('partial', 'r3e05.spike-cedar-lean-vs-rust (protocol only; over budget)'),
 'q1-034': ('done', 'r3e05.everparse-cborrs-2026-10 (crate name to confirm)'),
 'q1-044': ('done', 'r3e05.cedar-no-delegation-rfc (negative)'),
 'q1-060': ('done', 'r3e05.draft-niyikiza-aat-01, r3e05.draft-asor-wimse-dt-02'),
 'q1-064': ('done', 'r3e05.alt-space-token-formats (none found; T1-T5 would be first)'),
 'q1-131': ('partial', 'r3e05.code-level-token-verifier-table (crates.io ucan still 0.4.0)'),
 'q2-019': ('done', 'ops.fips-module-boundary-pin r3 revision, v3.aws-lc-rs-fips-sys-range (no AWS-LC 4 cert; 0.13.11 = 3.1.0)'),
 'q2-018': ('partial', 'r3e07-gcra-eviction-churn (own GCRA, not governor 0.10.4)'),
 'q2-063': ('partial', 'r3e07-r2-defaults-collapse, r3e07-pow-ladder-negative (simulation, not field data)'),
 'q1-014': ('partial', 'dx.claw-swe-rust-agentic, dx.swebench-multilingual-rust, dx.fpeval-probe-corrections (no head-to-head trial)'),
 'q2-004': ('partial', 'zd.l4-stek-continuity (rustls TicketRotator lifetimes); SNI binding still open'),
 'q1-117': ('partial', 'r3e11.osv-snapshot-2026-10-25'),
 'q1-134': ('partial', 'r3e09.grpc-defect-classes (GHSA-7gpj = CVE-2026-105297), r3e09.ws-upgrade-smuggling'),
 'q2-064': ('partial', 'r3e11.osv-snapshot-2026-10-25 (no hyper/h2 advisories 2026-08-25..10-25)'),
 'q2-058': ('done', 'ac.l5-inv-nomut-c, ac.counter-hypothesis-one-txn-outbox'),
 'q1-025': ('partial', 'r3e11.ai-found-bug-flood-vendor-posture'),
 'q1-046': ('partial', 'ops.fips-module-boundary-pin r3 (AWS-LC 4 Comment Resolution 2026-10-22)'),
}
for m in Qold:
    if m['id'] in DONE_IDS:
        m['status'], m['resolved_by'] = DONE_IDS[m['id']]
        m['resolved_round'] = R
items = []
for s in seeds:
    items.append({'question': s['question'], 'layer': s.get('layer'), 'domain': s.get('domain', ''), 'expected_info_gain': float(s.get('expected_info_gain', .5)),
                  'reason': s.get('reason', ''), 'sources': [f"explorer-{s['from_explorer']}"], 'kind': 'seed'})
for mm in VM['missed']:
    items.append({'question': mm['text'], 'layer': 'L4', 'domain': mm.get('domain', ''), 'expected_info_gain': float(mm.get('eig', .4)),
                  'reason': 'verifier missed-list', 'sources': [f"verifier-{mm['explorer']}"], 'kind': 'missed', 'absorbed_into': mm.get('absorbed')})
INTEGRATOR_SEEDS = [
 ('Resolve the golden version triangle: rustls 0.23.46 (security floor) + aws-lc-rs 1.15.2-1.17.2 + aws-lc-fips-sys =0.13.11 for the FIPS golden, vs the executed golden lock that resolved aws-lc-rs 1.18.2; does a lock exist that satisfies the rustls floor, prefer-post-quantum and the CMVP pin at once?', 'L5', 'W-PQC', .7, 'Bridge 04x12: FIPS pin and golden lock conflict (integrator)'),
 ('One executable spec for data-plane filters: unify Lowering.lean eval, the Python reference evaluator and a Cedar TPE residual->Pred translation as the DRT oracle for every adapter', 'L5', 'W-FORMAL', .5, 'Bridge 01x05: three separate semantic artefacts can diverge (verifier missed)'),
 ('Swarm simulator v2: replace cpu_scale=0.5 with a measured 1-vCPU rustls full/resumed handshake cost, add TLS resumption share, IPv6 /64 key churn and RST-timed cancel storms (NC4 charging)', 'L5', 'W-ABUSE', .65, 'Bridge 06x07: cancellations and resumption missing from the admission model'),
]
for q, l, d, g, r in INTEGRATOR_SEEDS:
    items.append({'question': q, 'layer': l, 'domain': d, 'expected_info_gain': g, 'reason': r, 'sources': ['integrator'], 'kind': 'integrator'})
qold_t = [(m, toks(m['question'])) for m in Qold]
merged = []
n_into_old = 0
for it in items:
    t = toks(it['question'])
    hit = None
    for m in merged:
        if jac(t, m['_t']) >= .45: hit = m; break
    if not hit:
        for m, mt in qold_t:
            if m['status'] in ('open', 'partial') and jac(t, mt) >= .45:
                m['expected_info_gain'] = max(m['expected_info_gain'], it['expected_info_gain']); m['sources'] = list(m['sources']) + it['sources']
                m.setdefault('dup_questions', []).append(it['question']); n_into_old += 1; hit = 'old'; break
    if hit == 'old': continue
    if hit:
        hit['expected_info_gain'] = max(hit['expected_info_gain'], it['expected_info_gain']); hit['sources'] += it['sources']
        hit['dup_questions'].append(it['question'])
        if it.get('absorbed_into') and not hit.get('absorbed_into'): hit['absorbed_into'] = it['absorbed_into']
        if not it.get('absorbed_into'): hit['_has_open'] = True
    else:
        it['_t'] = t; it['dup_questions'] = []; it['_has_open'] = not it.get('absorbed_into'); merged.append(it)
for m in merged:
    m['status'] = 'absorbed' if (m.get('absorbed_into') and not m['_has_open']) else 'open'
    m['resolved_by'] = m.get('absorbed_into') or ''
    m['added_round'] = R
PEN = {'open': 1.0, 'partial': .6, 'absorbed': .3, 'done': 0}
allq = Qold + merged
for m in allq:
    bonus = .05 * (len(set(m['sources'])) - 1)
    m['score'] = round(min(1.0, m['expected_info_gain'] + bonus) * PEN[m['status']], 3)
allq.sort(key=lambda m: (-m['score'], m.get('id', 'zz')))
k = 0
for m in allq:
    m.pop('_t', None); m.pop('_has_open', None)
    if not m.get('id'):
        k += 1; m['id'] = f'q3-{k:03d}'

# ---------------- predictions ----------------
PRED = [
 ('pred-chrome-mtc-default-2027', 'Chrome Stable verifies publicly-trusted MTCs by default (CQRS launched) by 2027-12-31', '2027-12-31', 'Chrome release notes / chromerootprogram cqrp pages', .55, 'r3pq.pq-auth-posture-decision'),
 ('pred-cab-mldsa-ballot-2027', 'CA/B Forum adopts a ballot permitting ML-DSA in publicly-trusted TLS server certificates by 2027-12-31', '2027-12-31', 'cabforum.org ballots', .2, 'r3pq.cab-sc106-withdrawn'),
 ('pred-rustls-trust-anchor-ids', 'rustls releases trust anchor IDs support (PR #3376 or successor) in a crates.io release by 2027-06-30', '2027-06-30', 'rustls release notes', .65, 'r3pq.mtc-server-obligations'),
 ('pred-sqlx-cancel-fix-release', 'sqlx publishes a crates.io release containing f1e94ec (cancelled Pool::begin fix, #4394) by 2027-01-31', '2027-01-31', 'crates.io sqlx versions + transact-rs/sqlx changelog', .6, 'ac.i01-sqlx-4393-begin-cancel'),
 ('pred-tokio-postgres-1374', 'rust-postgres PR #1374 (drop guard for server-side state on cancel) is merged by 2027-03-31', '2027-03-31', 'github.com/sfackler/rust-postgres/pull/1374', .5, 'ac.i02-tokio-postgres-1374-leak'),
 ('pred-wasmtime-cm-async-cancel-adv', 'At least one further Wasmtime advisory whose trigger is dropping/cancelling a component-model-async call is published between 2026-10-25 and 2027-04-30', '2027-04-30', 'gh api repos/bytecodealliance/wasmtime/security-advisories', .55, 'ac.i07-wasmtime-cancel-advisories'),
 ('pred-pg-14666-regress-test', 'PostgreSQL adds a regression test covering role-change invalidation of RLS plans (CVE-2026-14666 class) by 2027-06-30', '2027-06-30', 'git log src/test/regress for plancache/rowsecurity role tests', .35, 'irl-cve-2026-14666-fix-anatomy'),
 ('pred-webtrans-h3-rfc', 'draft-ietf-webtrans-http3 is published as an RFC by 2027-06-30', '2027-06-30', 'datatracker.ietf.org/doc/draft-ietf-webtrans-http3', .35, 'r3e09.webtransport-defect-classes'),
 ('pred-tenuo-cel-advisory', 'Tenuo publishes a fix or security advisory for CEL attenuation validation by 2027-01-31 (after private report)', '2027-01-31', 'github.com/tenuo-ai/tenuo releases / security advisories', .45, 'r3e05.tenuo-cel-attenuation-bypass'),
 ('pred-awslc4-cmvp-2027q1', 'CMVP issues a certificate for AWS-LC FIPS 4.x (currently Comment Resolution, 2026-10-22) by 2027-03-31', '2027-03-31', 'CMVP Modules In Process list / certificate search', .5, 'ops.fips-module-boundary-pin'),
]
old_pid = {p['id'] for p in jl(ST + '/predictions.jsonl')}
PRED = [p for p in PRED if p[0] not in old_pid]

# ---------------- write ----------------
by_layer = collections.Counter(n.get('layer') for n in new_nodes)
by_pl = collections.Counter((n['pillar'], n.get('layer')) for n in new_nodes)
grades = collections.Counter(n['evidence_grade'] for n in new_nodes)
dirs = collections.Counter(n['verify']['direction'] for n in nodes)
summary = dict(new_nodes=len(new_nodes), explorer_new=len([n for n in new_nodes if not n['explorer'].startswith('verifier')]),
               verifier_nodes=len(VM['vnodes']), revisions=len(revisions), revision_ids=[r['id'] for r in revisions], merged_same_as=len(merged_new), edges=len(edges), bridges=n_bridges,
               edges_by_origin=dict(collections.Counter(e['origin'].split('-')[0] for e in edges)),
               singletons=len(singletons), strict_singletons=len(strict_singletons), by_layer=dict(by_layer), grades=dict(grades),
               verify_dirs=dict(dirs), sampled=sum(1 for n in nodes if n['verify']['status'] == 'two-sided'), urls_total=len(urlmap),
               urls_new=len(seen_new), urls_reseen=len(seen_re), queries=len(Q), cells=len(cells), new_cells=len(new_cells), cells5=len(cells5), new_cells5=len(new_cells5),
               q_share_in_new_cells=round(q_in_new_cells, 3),
               direction_diversity=round(direction_diversity, 3), direction_diversity_5axis=round(direction_diversity5, 3),
               queue=len(allq), queue_open=sum(1 for m in allq if m['status'] == 'open'), queue_partial=sum(1 for m in allq if m['status'] == 'partial'),
               queue_done=sum(1 for m in allq if m['status'] == 'done'), queue_absorbed=sum(1 for m in allq if m['status'] == 'absorbed'),
               merged_into_old_queue=n_into_old, predictions=len(PRED), yields=yl,
               axis_counts={k: dict(collections.Counter(x[k] for x in Q)) for k in ('source_type', 'stance', 'era', 'pillar', 'vocab', 'scale')},
               by_pillar_layer={f'{a}|{b}': c for (a, b), c in sorted(by_pl.items())}, cross_near_dups=[p for p in nd_pairs if p[0] != p[1]],
               prior_round_near_dups=[(x['label'], x['max_prior_round_jaccard'], x['query'], x.get('prior_round_near_dup_of')) for x in Q if x['max_prior_round_jaccard'] >= .5],
               top_cells=cells.most_common(15), xdup_nodes=xdup[:15])
json.dump(summary, open(SCR + '/r3_summary.json', 'w'), indent=1, default=list)
json.dump({'cells': dict(cells), 'cells5': dict(cells5), 'new_cells': new_cells}, open(SCR + '/r3_cells.json', 'w'), indent=1)
json.dump([{k: m.get(k) for k in ('id', 'score', 'status', 'question', 'resolved_by', 'sources', 'layer', 'domain')} for m in allq], open(SCR + '/r3_queue_view.json', 'w'), indent=1)
if DRY:
    print(json.dumps({k: v for k, v in summary.items() if k not in ('by_pillar_layer', 'cross_near_dups', 'axis_counts', 'revision_ids')}, indent=1, default=list)); sys.exit(0)
with open(ST + '/graph.jsonl', 'a') as f:
    for n in new_nodes + revisions: f.write(json.dumps(n, ensure_ascii=False) + '\n')
with open(ST + '/edges.jsonl', 'a') as f:
    for e in edges: f.write(json.dumps(e, ensure_ascii=False) + '\n')
with open(ST + '/seen.jsonl', 'a') as f:
    for c in sorted(urlmap):
        d = urlmap[c]
        rec = {'url': d['raw'], 'canon': c, 'first_seen_round': seen_old[c]['first_seen_round'] if c in seen_old else R, 'last_seen_round': R,
               'found_by': sorted(d['explorers']), 'nodes': sorted(d['nodes'])}
        if c in seen_old: rec['revisit'] = True
        f.write(json.dumps(rec) + '\n')
with open(ST + '/queries.jsonl', 'a') as f:
    for x in Q: f.write(json.dumps(x, ensure_ascii=False) + '\n')
with open(ST + '/frontier_queue.jsonl', 'w') as f:
    for m in allq: f.write(json.dumps(m, ensure_ascii=False) + '\n')
with open(ST + '/predictions.jsonl', 'a') as f:
    for pid, claim, by, how, p, src in PRED:
        f.write(json.dumps({'id': pid, 'claim': claim, 'resolve_by': by, 'how_to_check': how, 'p': p, 'source_node': src, 'made_round': R, 'made_date': '2026-10-25'}) + '\n')
print(json.dumps({k: v for k, v in summary.items() if k not in ('by_pillar_layer', 'cross_near_dups', 'axis_counts', 'revision_ids')}, indent=1, default=list))
