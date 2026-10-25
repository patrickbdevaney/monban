#!/usr/bin/env python3
"""AEGIS round-2 integrator: dedup vs round-1 state, verifier grades, append graph/edges/seen/queries,
rebuild frontier queue, predictions. Deterministic. Inputs: raw/round-002/*.json (+ .structured.json for
explorers 05 and 11 whose raw files were truncated by the crash), _verify_r2_verdicts.json, _verify_r2_missed.json.
Run once:  python3 -I _integrate_r2.py  (refuses to run twice: checks graph for first_seen_round==2)."""
import json, glob, os, re, sys, collections
sys.path.insert(0, '/home/patrickd/aegis/research/tools')
from novelty_gate import toks, jac, nscore  # same tokenizer as the gate

R = 2
DATE = '2026-10-24'          # per integrator brief (last_verified value); wall clock is 2026-10-25
ROOT = '/home/patrickd/aegis/research'
ST = ROOT + '/state'
RAW = ST + '/raw/round-002'
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
G = {}
for n in jl(ST + '/graph.jsonl'): G[n['id']] = n          # last record wins
if any(n.get('first_seen_round') == 2 or n.get('revision_round') == 2 for n in G.values()):
    sys.exit('round 2 already integrated; refusing to append twice')
E_old = jl(ST + '/edges.jsonl')
E_keys = {(e['src'], e['dst'], e['type']) for e in E_old}
seen_old = {}
for s in jl(ST + '/seen.jsonl'): seen_old[s['canon']] = s

# ---------------- load round-2 explorer output ----------------
files = {}
for f in sorted(glob.glob(RAW + '/[0-9][0-9]-*.json')):
    b = os.path.basename(f)
    if b.endswith('.final_table.json'): continue
    pre = b[:2]
    o = json.load(open(f))
    if not isinstance(o, dict): continue
    if b.endswith('.structured.json') or pre not in files or not files[pre][1].get('nodes'):
        files[pre] = (b, o)
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
assert len(files) == 12, sorted(files)

V = json.load(open(RAW + '/_verify_r2_verdicts.json'))
VM = json.load(open(RAW + '/_verify_r2_missed.json'))
for vn in VM['vnodes']:
    n = dict(vn); n['domain'] = vn['pillar']; n['explorer'] = vn['found_by']; n['specifics'] = ''
    n['overclaim_risk'] = 'Verifier-sourced; single verification pass.'; n['underclaim_risk'] = ''
    explorer_of[n['id']] = 'V' + vn['found_by'][-2:]
    nodes.append(n)

# ---------------- integrator dedup decisions ----------------
SAME_AS = [  # (round-2 node, canonical existing node, note)
 ('cranelift-default-config-escape-2026-10', 'rec60-wasmtime-cranelift-crit-2026-10', 'same advisory GHSA-897f (r1 node is the Oct batch); r2 adds M0-config residual and citation fixes'),
 ('adv-rustls-pq-downgrade-2026-0349', 'rec60-rustls-0.23.46-downgrade', 'same advisory RUSTSEC-2026-0349 / GHSA-w44r'),
 ('fin.rmcp-3.7.0', 'j-rmcp-sdk', 'same release rmcp 3.7.0; r2 corrects licence (Apache-2.0 per crates.io) and README claim'),
 ('vfg-cryptoprover-cloud-llm-optional', 'rec60-cryptoprover-symcrypt', 'same paper arXiv 2608.00965'),
 ('v2.awslc-rs-fips-crate-map', 'crate-aws-lc-rs', 'same crate/module map; verifier adds README pin warning and CMVP #5429'),
]
REFINES = [  # (src refines dst) cross-explorer / cross-round
 ('v2.calif-h2bomb-ratios', 'v.http2-bomb-cve-2026-49975'), ('l4-cve-corpus-h2-h3-2023-2026', 'threat-h2-h3-resource-exhaustion'),
 ('v2.docker-mcp-gateway-advisories-r2', 'gap.docker-mcp-gateway'), ('v2.rmcp-more-advisories', 'j-mcp-sdk-advisories'),
 ('adv.corpus-r2-09', 'j-mcp-sdk-advisories'), ('v2.crdb-rls-on-conflict-gap', 'dpf-distributed-sql'), ('v2.mongobleed-itw', 'dpf-mongodb'),
 ('v2.cra-implementing-reg-2025-2392', 'ops.cra-annex3-waf-risk'), ('v2.cra-monetization-trigger', 'ops.cra-obligation-split'),
 ('ops.fips-module-boundary-pin', 'fips-cmvp-mlkem-modules'), ('v2.fedramp-class-tiers', 'ops.fedramp-20x-ksi-mapping'),
 ('v2.curl-0rtt-early-data-2026-9545', 'crs-ce-0rtt-replay'), ('v2.curl-2026-auth-state-cluster', 'crs-ce-pool-reuse-incomplete-key'),
 ('v2.curl-2026-auth-state-cluster', 'crs-ce-session-fixation-epoch'), ('v2.hebrok25-server-auth-bypass', 'crs-ce-tls-ticket-cross-vhost'),
 ('v2.agentgateway-referencegrant', 'gap.agentgateway'), ('cc.result-redb', 'sdg-redb'), ('cc.result-fjall', 'sdg-fjall'),
 ('cc.result-sqlite', 'sdg-sqlite-wal'), ('cc.result-heed-lmdb', 'sdg-lmdb-heed'), ('cc.ranking-negative', 'sdg-embedded-store-selection'),
 ('cc.l5-crash-harness-spec', 'sdg-l5-crash-harness'), ('cc.fsync-guarantees', 'sdg-fsyncgate'),
 ('vfg-kani-footprint-and-gate-failures', 'proof-kani-verify-rust-std'), ('wasmtime-advisory-share-by-config', 'wasmtime-ghsa-record-2021-2026'),
 ('wasmtime-minimal-config-pin', 'wasmtime-memory64-spectre-config'), ('canonical-abi-cost-measured', 'wasmtime-pooling-local-bench'),
 ('zygote-sandbox-recipe-measured', 'landlock-seccomp-self-sandbox'), ('w02.handshake-pq-cost', 'crate-rustls-pq'),
 ('w02.pingora-tokio-panic', 'gap.pingora'), ('abuse-wba-interplay', 'j-webbotauth'), ('r2e11.cdn-tsunami', 'rec60-header-accordions-qpack'),
 ('l4-quic-stack-window-defaults', 'crate-quinn'), ('l4-h2-budget-mechanics-0.4.20', 'crate-hyper-h2'),
 ('dpf-agent-db-tool-bypass-cluster', 'sdg-sql-allowlist-bypass'), ('vfg-policy-tristate-failclosed-invariant', 'inv-decision-determinism-failclosed'),
 ('vfg-policy-tristate-failclosed-invariant', 'cedar-skip-on-error-semantics'),
]
CONTRADICTS = [  # (src, dst, note)
 ('v2.calif-h2bomb-ratios', 'v.http2-bomb-cve-2026-49975', 'CVE-2026-49975 is Apache mod_h2 only; Envoy fix is GHSA-22m2 (no CVE in primary post)'),
 ('ops.fips-module-boundary-pin', 'crate-aws-lc-rs', 'byte-identical-to-cert pin: explorer 05 says aws-lc-rs 1.15.3/fips-sys 0.13.11; r1 node says 1.17.x (1.17.4 uses 0.13.17 on v3.6.0 source); unresolved'),
 ('fin.spec-absent-origin', 'j-mcp-2026-07-28', 'spec gap: absent Origin unspecified (not permitted) while MUST-validate is stated'),
 ('fin.stateless-not-sufficient', 'j-mcp-stateless-no-sessions', 'statelessness removes session class but not Origin/parser/audience/SSRF; requestState adds a new class'),
 ('cc.result-fjall', 'sdg-fjall', 'Buffer mode loses acks on SIGKILL in replay; #329 says process crashes unaffected - recheck replay semantics'),
 ('r2e11.cloudflare-2025-11-18', 'rust-type-system-not-adversarial-boundary', 'not a contradiction of the claim: a Rust proxy failed by unwrap() on oversized generated config (availability, not memory safety)'),
 ('skeptic-small-reservation-pooling-recipe', 'wasmtime-memory64-spectre-config', 'density tuning (guard 0, reservation==max<4GiB) re-opens GHSA-6wgr/394w'),
 ('w02.L5-lean-budget', 'crate-aws-lc-rs', 'aws-lc-sys bundles 1.5M C/asm LOC: lean budget must carry the crypto provider as a separate TCB line'),
 ('fail-verifier-soundness-bugs', 'cedar-lean-proofs-2026-10', 'cvc5 #12926/#12927 unsoundness sits in the SymCC analysis path'),
 ('crs-ce-hpack-shared-context', 'l5-structural-controls-implied', 'authenticated-but-shared compression context breaks the r1 bridge invariant as stated'),
]
BRIDGES = [  # integrator cross-explorer edges (type, note) - these are the round-2 bridges
 ('dpf-empty-means-all-pattern', 'vfg-policy-tristate-failclosed-invariant', 'supports', 'BRIDGE fail-closed construction: empty policy = allow-all (data plane) <-> Error/timeout = Deny (authz)'),
 ('r2e11.litellm-failopen', 'vfg-policy-tristate-failclosed-invariant', 'supports', 'BRIDGE fail-closed construction: KEV-listed auth error -> default principal'),
 ('abuse-L5-budget-invariants', 'vfg-policy-tristate-failclosed-invariant', 'related', 'BRIDGE fail-closed construction: I7 no fail-open admission stage'),
 ('l5.invariant-list', 'dpf-empty-means-all-pattern', 'related', 'BRIDGE fail-closed construction (agent gateway invariant 6)'),
 ('r2e11.cloudflare-2025-11-18', 'dpf-l5-allowlist-generation', 'supports', 'BRIDGE generated config is untrusted input: validate limits at build, fail soft to last-known-good'),
 ('crs-ce-hpack-shared-context', 'r2e11.h3-proxy-qpack-sidechannel', 'supported_by', 'BRIDGE principal partitioning: RFC 7541 hazard demonstrated for QPACK on pooled backend H3'),
 ('dpf-redis-valkey', 'crs-ce-pool-reuse-incomplete-key', 'supports', 'BRIDGE never share a backend connection across tenants (Valkey response-stream injection) = CRS C8'),
 ('crs-l5-keying-table', 'dpf-l5-op-capability-ir', 'related', 'BRIDGE scope tuple sigma == tenant-handle resource: one scope type for caches, pools and data ops'),
 ('crs-ce-dns-rebinding-toctou', 'l5.invariant-list', 'supports', 'BRIDGE egress-resolved invariant (rank 1 in agent gateway) = CRS DNS time-of-use binding'),
 ('crs-ce-idempotency-key-scope', 'sdg-l5-idempotency-store', 'constrains', 'principal must be in the key'),
 ('r2e11.h2-stalled-flowcontrol', 'l4-temporal-stall-liveness', 'supports', 'BRIDGE TBI-8 stall deadline: CERT VU#885548 is the advisory instance; hyper/h2 status unknown'),
 ('r2e11.cdn-tsunami', 'l4-field-memory-vs-rfc-accounting', 'supports', 'translation tier amplification = decoded-vs-accounted gap'),
 ('r2e11.haproxy-cve-2026-33555', 'w02.ingress-design-verdict', 'supports', 'primary-ish evidence for the H3->H1 seam (replaces weak secondary sources)'),
 ('r2e11.opossum', 'w02.ingress-design-verdict', 'constrains', 'one TLS mode per port; no Upgrade: TLS in the normalization core'),
 ('vfg-kani-footprint-and-gate-failures', 'l5-kani-harness-spec-tbi', 'constrains', 'TBI Kani gate must pin Kani >= #4910 and treat CBMC abnormal exit/OOM as FAIL'),
 ('vfg-kani-footprint-and-gate-failures', 'l5-ci-gate-tbi', 'constrains', 'same'),
 ('vfg-toolchain-pin-footprint-table', 'l5-tbi-tool-assignment', 'constrains', 'Verus 3.2 GB / Kani 2 GB are CI-only; laptop set is Lean core + TLC (~1.1 GB)'),
 ('vfg-native-axiom-tcb', 'cedar-lean-proofs-2026-10', 'constrains', 'Cedar uses 10 native_decide: Lean compiler enters TCB; golden gate bans it'),
 ('ops.systemd-baseline-score', 'wasmtime-minimal-config-pin', 'constrains', 'MemoryDenyWriteExecute incompatible with Cranelift JIT: Wasm worker needs its own unit, or precompiled .cwasm no-compiler runtime'),
 ('w02.feature-cost-unused', 'dpf-l5-adapter-isolation', 'supports', 'BRIDGE modularity: cargo features add zero when off; compiler-bearing/C-binding modules go out of process'),
 ('zygote-sandbox-recipe-measured', 'dpf-l5-adapter-isolation', 'quantifies', 'process-sandbox cost 124us-1.5ms fork; install Landlock+seccomp once per worker'),
 ('canonical-abi-cost-measured', 'vfg-invariant-survival-table', 'quantifies', 'component boundary ABI floor ~85 ns; wasm codegen ~2x is the cost driver'),
 ('vfg-invariant-survival-table', 'dpf-l5-adapter-isolation', 'related', 'BRIDGE golden contract: only native per-tenant credentials survive a malicious adapter (I4 logical)'),
 ('runwasi-placeholder', 'runwasi-placeholder', 'x', ''),
 ('r2e11.runwasi-cve-2026-47218', 'w02.L5-feature-gate-rule', 'constrains', 'precompiled .cwasm path must MAC artifacts locally; never deserialize untrusted bytes'),
 ('cc.neg-ldpreload-rustix', 'as.dst-entropy-leak', 'related', 'BRIDGE interposition is unsound for Rust: rustix raw syscalls (crash harness) and aws-lc jitter/RDRAND (DST) both escape libc shims'),
 ('as.dst-entropy-leak', 'cc.harness-method', 'related', 'same lesson: use interposer-independent instruments (FUSE/dm-log-writes; deterministic CryptoProvider)'),
 ('w02.handshake-pq-cost', 'adv-rustls-pq-downgrade-2026-0349', 'related', 'PQ cost +17.5% CPU (rustls) is cheap enough that HRR-to-hybrid policy has no perf excuse'),
 ('abuse-L5-admission-pipeline-1vcpu', 'l5-transport-budget-invariant-tbi', 'related', 'BRIDGE budgets at two layers: per-connection TBI (transport) under per-identity cost budgets (admission)'),
 ('abuse-L5-budget-invariants', 'l5-transport-budget-invariant-tbi', 'related', 'same invariant family; one ledger type'),
 ('ops.audit-log-spec', 'vfg-invariant-survival-table', 'supports', 'I6 audit completeness for host-mediated effects needs the tlog append-only spec'),
 ('fin.toolhive-policy-bypass', 'r2e11.apisix-2026-advisories', 'related', 'BRIDGE parser-differential policy bypass: JSON dup/case/BOM (ToolHive) and path normalization (APISIX 94269)'),
 ('dpf-l5-allowlist-generation', 'sdg-l5-db-gate-invariants', 'generalizes', 'PG fingerprint allowlist becomes one family normalizer in the per-adapter lock'),
 ('dpf-rustls-pq-driver-inheritance', 'w02.handshake-pq-cost', 'related', 'driver-side PQ inherited from rustls defaults; server-side PQ unknown'),
 ('v2.awslc-rs-fips-crate-map', 'ops.rustls-fipsstatus-gate', 'constrains', 'FipsStatus::Certified must name the cert matching the pinned crate'),
]
BRIDGES = [b for b in BRIDGES if b[0] != 'runwasi-placeholder']

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

# explicit integrator revisions of round-1 nodes corrected by round-2 evidence (title unchanged, correction recorded)
def revise(i, **kw):
    rev = dict(G[i]); rev.update(kw); rev['revision_round'] = R; rev['revision_by'] = 'integrator-r2'; rev['last_verified'] = DATE
    revisions.append(rev)
revise('v.http2-bomb-cve-2026-49975', correction='CVE-2026-49975 is Apache mod_h2 2.0.41 only; Envoy fixed via GHSA-22m2-hvr2-xqc8; nginx 1.29.8 added max_headers; ratios nginx ~70:1, IIS ~68:1, Envoy ~5,700:1, Apache ~4,000:1 (Calif primary). See v2.calif-h2bomb-ratios, l4-cve-corpus-h2-h3-2023-2026.')
revise('crate-aws-lc-rs', correction='Which aws-lc-rs/aws-lc-fips-sys version is byte-identical to CMVP #5298/#5314 is unresolved: explorer 05 says 1.15.3/0.13.11; 1.17.4 uses 0.13.17 on v3.6.0 source. README: 3.0.x -> aws-lc-rs <1.18.0; pin exact. CMVP #5429 (2026-07-20) unaddressed.', evidence_grade='B', confidence=0.75)
revise('j-rmcp-sdk', correction='Licence Apache-2.0 per crates.io (GitHub NOASSERTION); README claims 2025-11-25 compatibility and the 2026-07-28 implementation claim is weakly evidenced (verifier r2); keeps initialize path. 7 GHSAs, 5 in 2026-06..10 plus 9g45/9pj6/4432/33f5.', evidence_grade='B', confidence=0.75)
revise('rec60-wasmtime-cranelift-crit-2026-10', correction='GHSA-897f affected 37.0.0-<43.0.0 has no backport for 37-42: acceptable pins are exactly >=36.0.19 on the 36 line or >=43. Only exploitable escape on the M0 minimal config (wasmtime-advisory-share-by-config).')

# ---------------- clusters / singletons ----------------
par = {i: i for i in ids_all}
def find(x):
    while par[x] != x: par[x] = par[par[x]]; x = par[x]
    return x
for a, b, _ in SAME_AS: par[find(a)] = find(b)
for e in edges:
    if e['type'] in ('same-as', 'same_as') and e['src'] in par and e['dst'] in par: par[find(e['src'])] = find(e['dst'])
for n in new_nodes:
    c = find(n['id']); n['cluster'] = c; n['merged_into'] = c if c != n['id'] else None
# singletons: round-2 new nodes found by exactly one explorer and matching nothing existing (no same-as to an existing id)
merged_new = [n for n in new_nodes if n['merged_into']]
cand = [n for n in new_nodes if not n['merged_into']]
singletons = cand  # no intra-round same-as clusters across explorers were found (max cross-explorer Jaccard 0.17)
xlinked = set()
all_new_edges = edges + [{'src': a, 'dst': b} for a, b in REFINES] + [{'src': a, 'dst': b} for a, b, _ in CONTRADICTS] + [{'src': a, 'dst': b} for a, b, _, _ in BRIDGES]
def grp(i):
    if i in G and i not in ids_new: return 'old'
    return explorer_of.get(i, '?')[:3]
for e in all_new_edges:
    if e['src'] in ids_all and e['dst'] in ids_all and grp(e['src']) != grp(e['dst']):
        xlinked.add(e['src']); xlinked.add(e['dst'])
strict_singletons = [n for n in singletons if n['id'] not in xlinked]

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

# ---------------- seen ----------------
urlmap = collections.defaultdict(lambda: {'explorers': set(), 'nodes': set(), 'raw': None})
for pre, (b, o) in files.items():
    acc = set(); walk_urls(o, acc)
    for u in acc:
        c = canon(u); urlmap[c]['explorers'].add(pre); urlmap[c]['raw'] = urlmap[c]['raw'] or u
for n in nodes:
    for u in n.get('urls', []):
        if not u: continue
        c = canon(u); urlmap[c]['nodes'].add(n['id']); urlmap[c]['raw'] = urlmap[c]['raw'] or u
        if n['explorer'].startswith('verifier'): urlmap[c]['explorers'].add(n['explorer'])
for vd in V.values():
    acc = set(); walk_urls(vd[3], acc)
    for u in acc: c = canon(u); urlmap[c]['explorers'].add('verifier'); urlmap[c]['raw'] = urlmap[c]['raw'] or u
VERIFIER_URLS = ['https://www.springlex.eu/en/packages/cra/cra-regulation/article-64/', 'https://digital-strategy.ec.europa.eu/en/policies/cra-open-source',
 'https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5298', 'https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5314',
 'https://raw.githubusercontent.com/FedRAMP/rules/main/fedramp-consolidated-rules.json', 'https://csrc.nist.gov/pubs/sp/800/218/r1/ipd', 'https://csrc.nist.gov/projects/ssdf/news',
 'https://raw.githubusercontent.com/instant-labs/instant-acme/main/Cargo.toml', 'https://docs.rs/crate/rustls-pki-types/1.15.1', 'https://nvd.nist.gov/vuln/detail/CVE-2026-33555',
 'https://arxiv.org/pdf/2607.26589', 'https://thehackernews.com/2026/08/cdn-tsunami-attack-abuses-http3.html', 'https://cryptoslate.com/31-newly-discovered-vulnerabilities-expose-99-of-x402-crypto-payments-to-asset-theft-and-free-shopping/',
 'https://nvd.nist.gov/vuln/detail/CVE-2026-34988', 'https://rustsec.org/advisories/RUSTSEC-2026-0091', 'https://kernelnewbies.org/Linux_6.11',
 'https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/transports/streamable-http.mdx',
 'https://github.com/modelcontextprotocol/go-sdk/pull/842', 'https://github.com/modelcontextprotocol/go-sdk/pull/906', 'https://github.com/modelcontextprotocol/python-sdk/pull/3032',
 'https://cveawg.mitre.org/api/cve/CVE-2025-59152', 'https://cveawg.mitre.org/api/cve/CVE-2026-54738', 'https://cveawg.mitre.org/api/cve/CVE-2026-55501',
 'https://cveawg.mitre.org/api/cve/CVE-2026-73497', 'https://cveawg.mitre.org/api/cve/CVE-2026-53708', 'https://cveawg.mitre.org/api/cve/CVE-2026-55391',
 'https://cveawg.mitre.org/api/cve/CVE-2026-48524', 'https://cveawg.mitre.org/api/cve/CVE-2026-101917', 'https://cveawg.mitre.org/api/cve/CVE-2016-5419']
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
LABEL2PILLAR = {'data-plane-backend-families-mediation': 'W-DATA-GATE', 'lean-footprint-measured-vs-incumbents': 'W-PERF+W-GAP',
 'verification-footprint-and-golden-contract': 'W-FORMAL+W-ASSURE', 'abuse-admission-control-under-swarms': 'W-ABUSE',
 'ops-compliance-government-adoptability': 'W-OPS', 'h2-h3-budget-invariant-and-harness': 'W-TRANSPORT+W-FORMAL',
 'isolation-decision-inputs-measured': 'W-ISOLATION', 'state-crash-consistency-experiment': 'W-STATE',
 'agent-gateway-cves-to-invariants': 'W-AGENT-PROTOCOL+W-THREAT', 'cross-request-state-invariant-counterexamples': 'W-BRIDGE',
 'talks-nonenglish-adjacent-field-scan': 'W-UNKNOWN', 'two-sided-calibration-load-bearing-numbers': 'K-CALIBRATION'}
prior_q = [toks(q.get('query', '')) for q in jl(ST + '/queries.jsonl')]
prior_cells = {q.get('cell') for q in jl(ST + '/queries.jsonl')}
Q = []
for line in open(RAW + '/_queries.log', errors='replace'):
    p = line.rstrip('\n').split('\t')
    if len(p) < 2 or not p[1].strip(): continue
    lab, q, axes = p[0], p[1], (p[2] if len(p) > 2 else '')
    src, stance, era, vocab, scale = classify(q, axes)
    if lab == 'talks-nonenglish-adjacent-field-scan' and src == 'web-other': src = 'talk'
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
    Q[i]['max_prior_round_jaccard'] = round(max((jac(tq[i], pq) for pq in prior_q), default=0), 2)
cells = collections.Counter(x['cell'] for x in Q)
cells5 = collections.Counter(x['cell5'] for x in Q)
direction_diversity = len(cells) / len(Q)
direction_diversity5 = len(cells5) / len(Q)
new_cells = [c for c in cells if c not in prior_cells]

yl = {}
for lab in LABEL2PILLAR:
    nq = sum(1 for x in Q if x['label'] == lab)
    nn = [n for n in new_nodes if n['explorer'].endswith(lab)]
    revs = sum(1 for r in revisions if str(r.get('revision_by', '')).endswith(lab))
    l45 = sum(1 for n in nn if n.get('layer') in ('L4', 'L5') and not n['merged_into'])
    yl[lab] = (nq, len(nn), l45, (round(l45 / nq, 2) if nq else None), revs)

# ---------------- frontier queue ----------------
Qold = jl(ST + '/frontier_queue.jsonl')
DONE_IDS = {  # id: (status, resolved_by)
 'q1-001': ('done', 'dpf-family-matrix, dpf-uniform-abstraction-comparison, dpf-l5-op-capability-ir, dpf-l5-allowlist-generation, dpf-l5-adapter-isolation'),
 'q1-002': ('partial', 'w02.size-deps-table, w02.idle-rss-table, w02.feature-cost-unused, w02.ingress-design-verdict (normalization copy cost and IPC cost unmeasured)'),
 'q1-003': ('done', 'adv.corpus-r2-09, l5.invariant-list, v2.agentgateway-referencegrant'),
 'q1-004': ('done', 'vfg-toolchain-pin-footprint-table, vfg-obligation-to-tool-map (Verus/Kani RAM still a spike)'),
 'q1-005': ('done', 'l5-transport-budget-invariant-tbi, l5-tbi-tool-assignment, l5-kani-harness-spec-tbi (harnesses not yet run: implementation spike)'),
 'q1-006': ('done', 'wasmtime-advisory-share-by-config, wasmtime-minimal-config-pin'),
 'q1-007': ('done', 'vfg-invariant-survival-table, vfg-conformance-suite-outline'),
 'q1-008': ('done', 'abuse-* (22 nodes)'),
 'q1-010': ('done', 'canonical-abi-cost-measured'),
 'q1-011': ('partial', 'w02.handshake-pq-cost (loopback, contended host; $5 VPS / 64-core / quinn not measured)'),
 'q1-015': ('done', 'ops.* (12 nodes)'),
 'q1-016': ('partial', 'canonical-abi-cost-measured, w02.handshake-pq-cost (io_uring vs epoll and thread-per-core still unmeasured)'),
 'q1-021': ('done', 'l4-transport-harness-census-2026-10'),
 'q1-024': ('partial', 'std-rfc10024-ecdhe-mlkem r2 revision: SecP384r1MLKEM1024 absent in rustls 0.23.46 and 0.24.0-dev.2; FIPS pure ML-KEM-1024 open'),
 'q1-027': ('done', 'l5.conformance-manifest'),
 'q1-029': ('partial', 'as.dst-entropy-leak r2 revision (aws-lc jitter+RDRAND not interceptable); deterministic CryptoProvider spike open'),
 'q1-033': ('partial', 'wasmtime-advisory-share-by-config (cm-async removes 14/65)'),
 'q1-042': ('done', 'zygote-sandbox-recipe-measured'),
 'q1-046': ('partial', 'ops.fips-module-boundary-pin (AWS-LC 4 in Comment Resolution 2026-10-22; AWS-LC 5 Pending Review)'),
 'q1-047': ('done', 'l4-no-verified-hpack-qpack-decoder (none exists)'),
 'q1-048': ('partial', 'ops.systemd-baseline-score (@system-service filter); exact syscall profile open'),
 'q1-056': ('partial', 'cc.kernel-atomic-writes'),
 'q1-057': ('partial', 'l4-quic-stack-window-defaults, l5-config-pin-table-transport (h3 #377/#378 still open 2026-10-25)'),
 'q1-065': ('partial', 'cc.harness-method (logical replay); real dm-log-writes rig open'),
 'q1-066': ('done', 'fin.rmcp-3.7.0 / j-rmcp-sdk revision'),
 'q1-069': ('done', 'canonical-abi-cost-measured, zygote-sandbox-recipe-measured, isolation-decision-inputs-table'),
 'q1-070': ('done', 'l4-no-verified-hpack-qpack-decoder, vfg-lean-std-http-unknown'),
 'q1-072': ('done', 'seccomp-per-syscall-overhead-measured'),
 'q1-075': ('partial', 'j-rmcp-sdk revision (licence Apache-2.0 per crates.io)'),
 'q1-076': ('partial', 'as.mutants-gate r2 revision (equivalent-mutant triage needed)'),
 'q1-089': ('partial', 'fail-spec-fidelity-studies r2 revision (Verus-SpecGym verified)'),
 'q1-094': ('partial', 'cc.* crash harness (single-crash); fsync-EIO stage still open'),
 'q1-095': ('done', 'wasmtime-advisory-share-by-config'),
 'q1-096': ('done', 'abuse-privacy-pass-rfcs, abuse-arc-act'),
 'q1-100': ('done', 'w02.handshake-pq-cost, dpf-rustls-pq-driver-inheritance'),
 'q1-107': ('partial', 'r2e11.* (BH/DEF CON items, several only via media root URL)'),
 'q1-108': ('partial', 'r2e11.sosp26-lion-verified-async, r2e11.osdi26-ote-policy'),
 'q1-112': ('partial', 'wasmtime-advisory-share-by-config (81 GHSAs snapshot 2026-10-25)'),
 'q1-120': ('done', 'cedar-lean-proofs-2026-10 and l5-authz-stack-recommendation r2 revisions'),
 'q1-132': ('partial', 'w02.pingora-tokio-panic (tokio 1.54 breaking change)'),
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
 ('Implementation spike: out-of-process module/adapter IPC cost (UDS + postcard or WIT canonical ABI) vs in-process, per op and RSS, for a redis GET, a scylla prepared SELECT, an S3 presign and a wasmtime helper call, 1 core, under heavy.sh', 'L4', 'W-PERF', .8, 'Decides the in-process vs out-of-process threshold used by dpf-l5-adapter-isolation and w02.L5-feature-gate-rule (01+02 seeds)'),
 ('Implementation spike: run the TBI Kani harnesses H1-H5 (Kani >= #4910) and the Verus twin on a 4-vCPU/16 GB runner; record wall time and peak RAM', 'L5', 'W-FORMAL', .65, 'TBI gate feasibility; Verus/Kani RAM never measured (03+06)'),
 ('Window-0 / stalled flow-control harness (CERT VU#885548) against hyper 1.12.0 + h2 0.4.20 golden pins: RSS growth and whether any timer fires', 'L5', 'W-TRANSPORT', .7, 'TBI-8 stall clause has no implementation in hyper/h2; 06+11'),
 ('Does rustls (server) bind TLS 1.3 tickets to SNI/cert chain internally, what are default Ticketer rotation/lifetime, and is resumption psk_ke or psk_dhe_ke with X25519MLKEM768 (PQ forward secrecy on resumption)?', 'L4', 'W-PQC', .7, 'CRS C1/C2 wrapper vs fork; resumed-session PQ property (10 seeds + verifier)'),
]
for q, l, d, g, r in INTEGRATOR_SEEDS:
    items.append({'question': q, 'layer': l, 'domain': d, 'expected_info_gain': g, 'reason': r, 'sources': ['integrator'], 'kind': 'integrator'})
qold_t = [(m, toks(m['question'] + ' ' + ' '.join(m.get('dup_questions', [])[:2]))) for m in Qold]
merged = []
n_into_old = 0
for it in items:
    t = toks(it['question'])
    hit = None
    for m in merged:
        if jac(t, m['_t']) >= .45: hit = m; break
    if not hit:
        for m, mt in qold_t:
            if m['status'] in ('open', 'partial') and jac(t, toks(m['question'])) >= .45:
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
        k += 1; m['id'] = f'q2-{k:03d}'

# ---------------- predictions ----------------
PRED = [
 ('pred-pingora-tokio154', 'A Pingora release (>0.9.0) that serves requests with tokio >= 1.54 (BufStream zero-capacity fix, PR #1060 or equivalent) is published by 2026-12-31', '2026-12-31', 'crates.io pingora-core versions + cloudflare/pingora#1059 status', .8, 'w02.pingora-tokio-panic'),
 ('pred-kani-release-4910', 'A tagged Kani release containing PR #4910 (fail on abnormal CBMC exit) is published by 2026-12-31', '2026-12-31', 'github.com/model-checking/kani/releases', .85, 'vfg-kani-footprint-and-gate-failures'),
 ('pred-mcp-conformance-server-classes', 'modelcontextprotocol/conformance adds server-side scenarios for >=3 of: text/plain no-preflight rejection, 413 body cap, cross-origin redirect header strip, server-side token audience rejection, by 2027-04-30', '2027-04-30', 'repo scenarios directory', .4, 'fin.conformance-gap'),
 ('pred-ssdf-r1-final', 'NIST SP 800-218 Rev 1 (SSDF 1.2) is published final by 2027-06-30', '2027-06-30', 'csrc.nist.gov/pubs/sp/800/218/r1', .55, 'ops.ssdf-12-ci-gates'),
 ('pred-wasmtime-m0-escape', 'Another Wasmtime advisory exploitable as a sandbox escape under the M0 config (x86_64, Cranelift, core wasm only, defaults otherwise) is published between 2026-10-25 and 2027-04-30', '2027-04-30', 'gh api repos/bytecodealliance/wasmtime/security-advisories; classify by preconditions', .45, 'wasmtime-advisory-share-by-config'),
 ('pred-hyper-h2-stall-or-count-cap', 'hyper or h2 ships a stream stall/send timeout or a header field-count cap in a release by 2027-06-30', '2027-06-30', 'hyper/h2 CHANGELOG', .35, 'l4-h2-budget-mechanics-0.4.20'),
 ('pred-redb-5-release', 'redb 5.0.0 (SingleWriter always 2PC, Durability::None refused) is released by 2027-03-31', '2027-03-31', 'crates.io redb versions', .6, 'cc.result-redb'),
 ('pred-privacypass-batched-rfc', 'draft-ietf-privacypass-batched-tokens is published as an RFC by 2027-06-30', '2027-06-30', 'datatracker.ietf.org/doc/draft-ietf-privacypass-batched-tokens', .6, 'abuse-privacy-pass-rfcs'),
 ('pred-curl-reuse-cves', 'curl publishes >=5 additional connection/session/credential-reuse CVEs between 2026-10-25 and 2027-04-30', '2027-04-30', 'curl.se/docs/vuln.json filtered by reuse/session keywords', .6, 'crs-ce-pool-reuse-incomplete-key'),
 ('pred-supavisor-stable-210', 'Supavisor stable v2.10.0 (transaction-mode SET handling from PR #1113) is released by 2027-01-31', '2027-01-31', 'github.com/supabase/supavisor/releases', .7, 'sdg-txn-pooling-session-leak'),
 ('pred-lean-paranoid-checker-arena', 'Kernel Arena shows a bundled Lean checker (official, nanoda or lean4lean) accepting >=1 bad proof after 2026-10-25 (new soundness bug) by 2027-06-30', '2027-06-30', 'arena.lean-lang.org + lean4 PRs labelled soundness', .45, 'vfg-lean-kernel-soundness-bugs-2026'),
]
old_pid = {p['id'] for p in jl(ST + '/predictions.jsonl')}
PRED = [p for p in PRED if p[0] not in old_pid]

# ---------------- write ----------------
by_layer = collections.Counter(n.get('layer') for n in new_nodes)
by_pl = collections.Counter((n['pillar'], n.get('layer')) for n in new_nodes)
grades = collections.Counter(n['evidence_grade'] for n in new_nodes)
dirs = collections.Counter(n['verify']['direction'] for n in nodes)
summary = dict(new_nodes=len(new_nodes), explorer_new=len([n for n in new_nodes if not n['explorer'].startswith('verifier')]),
               verifier_nodes=len(VM['vnodes']), revisions=len(revisions), merged_same_as=len(merged_new), edges=len(edges),
               singletons=len(singletons), strict_singletons=len(strict_singletons), by_layer=dict(by_layer), grades=dict(grades),
               verify_dirs=dict(dirs), sampled=sum(1 for n in nodes if n['verify']['status'] == 'two-sided'), urls_total=len(urlmap),
               urls_new=len(seen_new), urls_reseen=len(seen_re), queries=len(Q), cells=len(cells), new_cells=len(new_cells),
               direction_diversity=round(direction_diversity, 3), direction_diversity_5axis=round(direction_diversity5, 3),
               queue=len(allq), queue_open=sum(1 for m in allq if m['status'] == 'open'), queue_partial=sum(1 for m in allq if m['status'] == 'partial'),
               queue_done=sum(1 for m in allq if m['status'] == 'done'), queue_absorbed=sum(1 for m in allq if m['status'] == 'absorbed'),
               merged_into_old_queue=n_into_old, predictions=len(PRED), yields=yl,
               axis_counts={k: dict(collections.Counter(x[k] for x in Q)) for k in ('source_type', 'stance', 'era', 'pillar', 'vocab', 'scale')},
               by_pillar_layer={f'{a}|{b}': c for (a, b), c in sorted(by_pl.items())}, cross_near_dups=[p for p in nd_pairs if p[0] != p[1]],
               prior_round_near_dups=sum(1 for x in Q if x['max_prior_round_jaccard'] >= .5), top_cells=cells.most_common(12),
               reused_ids_in_raw=[r['id'] for r in revisions if str(r.get('revision_by', '')).startswith('12-')])
json.dump(summary, open(SCR + '/r2_summary.json', 'w'), indent=1, default=list)
json.dump({'cells': dict(cells), 'cells5': dict(cells5), 'new_cells': new_cells}, open(SCR + '/r2_cells.json', 'w'), indent=1)
json.dump([{k: m.get(k) for k in ('id', 'score', 'status', 'question', 'resolved_by', 'sources', 'layer', 'domain')} for m in allq], open(SCR + '/r2_queue_view.json', 'w'), indent=1)
if DRY:
    print(json.dumps({k: v for k, v in summary.items() if k not in ('by_pillar_layer', 'cross_near_dups')}, indent=1, default=list)); sys.exit(0)
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
print(json.dumps({k: v for k, v in summary.items() if k not in ('by_pillar_layer', 'cross_near_dups')}, indent=1, default=list))
