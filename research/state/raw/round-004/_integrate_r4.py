#!/usr/bin/env python3
"""AEGIS round-4 integrator: dedup vs rounds 1-3 state, verifier grades, append graph/edges/seen/queries,
rebuild frontier queue, predictions (+ score fields from explorer 12's scorecard). Deterministic.
Inputs: raw/round-004/[0-9][0-9]-*.json, _verify_r4_verdicts.json, _verify_r4_missed.json (both re-keyed by the
integrator from the workflow journal), _queries.log.
Run once:  python3 -I _integrate_r4.py [--dry]  (refuses to run twice: checks graph for round-4 records).
Derived from _integrate_r3.py."""
import json, glob, os, re, sys, collections, tempfile
sys.path.insert(0, '/home/patrickd/aegis/research/tools')
from novelty_gate import toks, jac  # same tokenizer as the gate

R = 4
DATE = '2026-10-24'          # per integrator brief (last_verified value); wall clock is 2026-10-25
ROOT = '/home/patrickd/aegis/research'
ST = ROOT + '/state'
RAW = ST + '/raw/round-004'
SCR = '/tmp/claude-1000/-home-patrickd/b4045317-3a36-45b5-8cfe-a4b20991f0b0/scratchpad/r4'
DRY = '--dry' in sys.argv

from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
def canon(u):  # META §8 form (gh:owner/repo for repo roots), identical to rounds 1-3
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

def write_atomic(path, lines):
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix='.tmp_')
    with os.fdopen(fd, 'w') as f:
        for x in lines: f.write(json.dumps(x, ensure_ascii=False) + '\n')
    os.replace(tmp, path)

PMAP = {'W-DATA': 'W-DATA-GATE', 'W-AGENT': 'W-AGENT-PROTOCOL', 'W-ISOLATE': 'W-ISOLATION', 'W-AUTH': 'W-AUTHZ',
        'W-PARSE': 'W-TRANSPORT', 'W-WASM': 'W-ISOLATION', 'W-PROOF': 'W-FORMAL', 'W-BRIDGE': 'W-BRIDGE'}
def pillar(dom):
    dom = dom or ''
    if dom.startswith('C-CRYPTO'): return 'W-PQC'
    if dom.startswith('K-CALIBRATION'): return 'K-CALIBRATION'
    if dom.startswith('T-SAFETY-CERT'): return 'T-SAFETY-CERT'
    if dom.startswith('R+S'): return 'R-HISTORY'
    m = re.search(r'W-[A-Z]+(?:-[A-Z]+)*', dom)
    if not m: return 'W-?' + dom
    p = m.group(0)
    for k, v in PMAP.items():
        if p == k or p.startswith(k + '-') and k in ('W-DATA', 'W-AGENT'): return v
    return PMAP.get(p, p)

# ---------------- load existing state ----------------
G = {}
for n in jl(ST + '/graph.jsonl'): G[n['id']] = n          # last record wins
if any(n.get('first_seen_round') == R or n.get('revision_round') == R for n in G.values()):
    sys.exit('round 4 already integrated; refusing to append twice')
E_old = jl(ST + '/edges.jsonl')
E_keys = {(e['src'], e['dst'], e['type']) for e in E_old}
seen_old = {}
for s in jl(ST + '/seen.jsonl'): seen_old[s['canon']] = s

# ---------------- load round-4 explorer output ----------------
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

V = json.load(open(RAW + '/_verify_r4_verdicts.json'))
VM = json.load(open(RAW + '/_verify_r4_missed.json'))
for vn in VM['vnodes']:
    n = dict(vn); n['domain'] = vn['pillar']; n['explorer'] = vn['found_by']; n['specifics'] = ''
    n['overclaim_risk'] = 'Verifier-sourced; single verification pass; integrator did not re-fetch.'; n['underclaim_risk'] = ''
    explorer_of[n['id']] = 'V' + vn['found_by'][-2:]
    nodes.append(n)

# ---------------- integrator dedup decisions ----------------
SAME_AS = [  # (round-4 node, canonical node, note)
 ('sc.lean-kernel-soundness-2026', 'r4e01.lean-kernel-soundness-2026-record', 'same subject (2026 Lean kernel soundness record: #14576/#14577, 4.32.1/4.32.2 fixes) found by explorers 01 and 09; 09 adds the oss-security 2026-08-02 advisory (CVSS 7.1, fix first in nightly-2026-07-29, nanoda+leanchecker also accepted)'),
 ('r4i04.m0-escape-rate-denominators', 'wasmtime-advisory-share-by-config', 'same recomputation (12 M0 escapes / 5.43 y = 2.21/yr, 0.36/yr 2024-26) done independently by explorers 04 and 12; 12 adds the aarch64 critical GHSA-mghf'),
 ('r4tri.cmvp-pin-carries-advisories', 'ops.fips-module-boundary-pin', 'same finding (fips-sys 0.13.11 inside RUSTSEC-2026-0042/0043; reachability via rustls nil by source reading) found by explorers 03 and 12'),
]
REFINES = [
 ('r4e01.lean-kernel-soundness-2026-record', 'vfg-lean-kernel-soundness-bugs-2026'), ('sc.lean-kernel-soundness-2026', 'vfg-lean-kernel-soundness-bugs-2026'),
 ('l4.releases-snapshot-2026-10-25', 'r3e11.osv-snapshot-2026-10-25'), ('l4.mcp-spec-latest-revision-2026-10-25', 'rec60-mcp-2026-07-28'),
 ('r4tri.tested-env-only-al2023', 'fips-cmvp-mlkem-modules'), ('r4tri.golden-lock-no-pq-feature', 'dpf-rustls-pq-driver-inheritance'),
 ('sdg-rls-plan-cache-family', 'sdg-sje-rls-2026'), ('dx.r4-prior-art-capability-crates', 'v3.typed-authz-ctx-prior-art'),
 ('uu11.cfg-push-class', 'r2e11.cloudflare-2025-11-18'), ('r4i04.wasmtime-serve-reuse-defaults', 'wasmtime-minimal-config-pin'),
 ('v4.cooldown-holds-vulnerable-webpki', 'sc3.l5-cooldown-security-bypass'), ('v4.pingora-userinfo-authority-reject', 'r4e07.invariant-canon-one-owner'),
 ('v4.mcp-conformance-suite-open-gaps', 'l4.conformance-suite-gap-origin-only'), ('v4.mcp-default-off-dns-rebinding-cves', 'l4.defaults-vs-configurable-matrix'),
 ('v4.lake-check-sorryax-manifest', 'r4e01.l5-proof-ci-gate'), ('v4.native-decide-unverifiable-external', 'r4e01.native-decide-aux-axiom-naming'),
 ('v4.pg-onconflict-rls-second-report', 'wpo-pg-onconflict-where-peek'), ('v4.cve-2017-15099-onconflict-precedent', 'wpo-pg-onconflict-where-peek'),
 ('v4.redis-acl-side-channels-search-prefix', 'wpo-redis-write-path-acl'), ('v4.rustls-024-dev-and-awslc-window-detail', 'r4tri.separate-fips-lock-decision'),
 ('v4.wasmtime-panic-abort-toolchain-split', 'r4i04.wasmtime-guest-host-abort-rate'), ('v4.nginx-rift-conditional-exploitability', 'econ.security-incident-no-switch'),
 ('v4.pq-hybrid-invisible-default', 'econ.differentiators-absent'), ('v4.ingress-migration-distro-channel', 'econ.who-switches-first'),
 ('v4.pikeos-eal5plus-ceiling', 'sc.cc-eal6-eal7-real-evals'), ('v4.whatwg-914-bidi-deno-divergence', 'r4e07.whatwg-914-rust-url-divergence'),
 ('v4.lean-soundness-threat-is-build-supply-chain', 'r4e01.lean-kernel-soundness-2026-record'),
]
CONTRADICTS = [
 ('r4tri.yanked-1.17.2', 'ops.fips-module-boundary-pin', 'the r4 calibration revision states aws-lc-rs 1.15.1-1.17.2; 1.17.2 is yanked (2026-07-17) and fails to compile with fips-sys <=0.13.15, so the 0.13.11 window is 1.15.2-1.17.1 (verifier: crates.io)'),
 ('r4e10.golden-tls-kex-profiles', 'r4tri.fips-handshake-verdicts', 'FIPS-KX-1 = [SECP256R1MLKEM768, SECP256R1, SECP384R1] lacks SecP384r1MLKEM1024 (0x11ED), the group r4e10 picks as the universal compliance group (ASD rejects 768 after 2030; BSI intends 0x11EB/0x11ED); the FIPS listener list gains 0x11ED once rustls supports it'),
 ('r4e01.lake-check-paranoid-six-kernels', 'v4.lean-checker-disagreement-15908', '"all 6 checkers accept" holds for our own prelude only; on the #15908 adversarial export the checkers disagreed, so acceptance is not evidence of independence'),
 ('v4.lean-checker-disagreement-15908', 'r4e01.from-export-prelude-trust-hole', 'overstated: lean4lean, con-leche and con-ron also rejected the exploit, not only comparator-style prelude matching'),
 ('econ.security-incident-no-switch', 'v4.nginx-rift-conditional-exploitability', 'confounder: Rift needs a non-default rewrite config + ASLR bypass, and the thread contained switching-interest comments'),
]
BRIDGES = [  # (src, dst, type, note): integrator cross-explorer edges, round 4
 ('r4e01.exact-vs-refines-not-witness', 'wpo-pg-onconflict-where-peek', 'related', 'BRIDGE engine bugs break the adapter contract from both sides: PG BUG #19645 (partition pruning drops matching rows = completeness) and ON CONFLICT WHERE evaluated before RLS (side-effect soundness) are engine-level; the two-sided DRT (leak=0 AND miss=0) and the write oracle re-run on every engine bump, and upsert WHERE carries no user expressions'),
 ('r4e01.not-absent-permits-spec-gap', 'wpo-inv-write-subset', 'related', 'BRIDGE one three-valued reference: the absent-field NOT widening (Mongo $ne) and the write pre/post-image W1 Pred clause need the same Option-Bool reference evaluator; make the IR reference three-valued before freezing W1-W7'),
 ('r4tri.fips-handshake-verdicts', 'r4e10.rustls-secp384r1mlkem1024-gap', 'constrains', 'BRIDGE FIPS x jurisdiction: the FIPS provider does not refuse X25519MLKEM768, so every compliance profile is an explicit kx_groups allowlist; the one group all non-China regimes accept (0x11ED) is missing from rustls 0.23.46, so a custom SupportedKxGroup or upstream PR is on the critical path for gov profiles'),
 ('r4tri.no-co-resolvable-lock', 'r4c12.repo-ghsa-osv-blindspot', 'related', 'BRIDGE audit gates: the cmvp lock fails cargo-audit by design (0042/0043/0349) while repo-only GHSAs pass every lock; the advisory gate needs both a reachability-justified expiring ignore list and a repo-GHSA poll (G10)'),
 ('v4.cmvp-lock-carries-rustsec-0349', 'r3pq.hrr-acceptance-test', 'constrains', 'BRIDGE: the cmvp lock (rustls 0.23.43) predates the 0349 fix; server-side pq-required kx_groups plus frozen HRR verdicts are its only mitigation, so the HRR acceptance test runs against both lock profiles'),
 ('r4e01.native-decide-aux-axiom-naming', 'sc.implication-checker-qualification-arguments', 'supports', 'BRIDGE proof-gate qualification: axiom allowlist (not denylist), native_decide ban, known-false-proof corpus (#14484/#14576/#15908) and the 6-checker paranoid run form one TQL-5-style qualification argument for the Lean checker'),
 ('r4e01.l5-proof-ci-gate', 'sc.do330-tql-verification-tools', 'related', 'BRIDGE: an executed CI gate with PASS on the golden and FAIL on a negative control, logs kept, is the TQL-5 user-context evidence DO-330 asks of a verification tool whose output replaces other verification'),
 ('r4i04.gray-failure-fdleak', 'uu11.worker-exhaustion-class', 'supports', 'BRIDGE durability: the measured fd-leak gray failure (68 healthy failures per fault; liveness never trips) is the lab twin of the 10.6% field class (ProxySQL LimitNOFILE clamp, php-fpm worker exhaustion); rlimit preflight (UP-4) + per-request resource ledger + recycling + success-rate SLO cover both'),
 ('r4i04.crash-loop-damping-baselines', 'uu11.l5-pool-floor-and-rule-guards', 'related', 'BRIDGE one control-plane floor: per-principal crash budgets, zygote re-exec escalation and the OPS-1 min-healthy floor are one rule: neither crash recovery nor operator action may drop below ceil(f*N) healthy workers'),
 ('r4i04.kernelctf-reachability-under-allowlist', 'io-uring-security-record', 'constrains', 'BRIDGE kernel surface: kTLS (CONFIG_TLS, 11 kernelCTF LPEs), BPF (7) and io_uring (3) must be unreachable from sandboxed workers; kTLS offload is at most a front-process option, never inside a worker sandbox'),
 ('r4e07.hyper-h2-authority-host-unchecked', 'l4.defaults-vs-configurable-matrix', 'related', 'BRIDGE listener gate = CANON-6: MCP SDKs ship Host/Origin checks default-off or absent and hyper/h2 never compare Host with :authority; one core authority canonicalizer + binding check (421/400) serves both, regardless of SDK defaults'),
 ('r4e07.origin-allowlist-tuple', 'l4.ts-modern-vs-legacy-transport-gap', 'related', 'BRIDGE: the modern stateless MCP handler drops Origin middleware; the core Origin owner (parsed tuple vs configured tuples, no regex) sits below every handler era'),
 ('r4e07.json-parser-dup-key-matrix', 'l5.listener-gate-delta-2026-07-28', 'related', 'BRIDGE header/body consistency (-32020) needs one JSON owner: simd-json/sonic-rs first-wins vs serde last-wins lets body method and header disagree across parsers; parse once with a duplicate-rejecting visitor'),
 ('econ.differentiators-absent', 'r4e10.matrix-jurisdiction-requirements', 'related', 'BRIDGE demand: PQ/formal are absent from forum selection criteria but mandated top-down by BSI/ANSSI/ASD/EO 14412 dates; position assurance as invisible defaults for builders and as profile evidence for regulated buyers'),
 ('econ.security-incident-no-switch', 'uu11.negative-result-ledger-completeness', 'related', 'BRIDGE: critical CVEs did not produce stated switching (0/101) and no coded outage cause was memory corruption (0/160); adoption rides on migration parity and ops ergonomics, durability on operational invariants'),
 ('sc.cc-formal-requirements', 'r4e01.l5-theorem-status-table', 'related', 'BRIDGE buyer credit: CC EAL7 and SP 800-53 SA-17(1) credit a formal policy model + correspondence argument, which is what the checked Lean models (Combine, Token T1-T5, Lowering T1-T5) are; code-level proofs exceed what regulators credit'),
 ('dx.r4-async-cancel-neutralization', 'ac.l5-inv-nomut-c', 'related', 'BRIDGE: the SDK Tx Drop guard neutralizes timeout/select! cancels, but mem::forget defeats it and async rollback cannot run in Drop; host-side NC3 discard-on-cancel at pool checkin is the backstop the SDK guard cannot be'),
 ('r4i04.state-leak-c8-measured', 'crs-l5-invariant-text', 'supports', 'BRIDGE CRS C8 measured: any reused long-lived context leaks to nearly all later requests (native 820, Wasm reuse 383 wrong answers per poisoning at 0.1%); a fresh instance per request is the only zero; pin wasmtime serve reuse to 1'),
 ('r4e01.combine-failclosed-first-check', 'r4c12.stale-grade-list-2026-10-25', 'supports', 'BRIDGE epistemics: r2 graded combine_failclosed A with no Lean file, and the draft carried 9 stale grade tags; rule: no proof claim above C without file path + gate log, and the integrator greps draft tags on every downgrade'),
 ('r4i04.seccomp-clone-flag-gap', 'r4e01.bwrap-apparmor-blocks-lake-check', 'related', 'BRIDGE userns both ways: Ubuntu 24.04 restricts unprivileged userns (blocking the lake sandbox) and 72% of kernelCTF LPEs need userns; workers deny CLONE_NEW*, while CI provisions a bwrap AppArmor profile rather than running unsandboxed'),
 ('uu11.l5-config-lkg-canary-rule', 'r4e07.ci-gate-canon-property', 'related', 'BRIDGE totality: CFG-1 (config parse never panics) and CANON (canonicalizer total + idempotent, reject not repair) are the same proof obligation shape on two inputs (operator-fed and attacker-fed): Kani totality harness + fuzz, one rung'),
]

ids_new = {n['id'] for n in nodes}
ids_all = set(G) | ids_new
for a, b, _ in SAME_AS: assert a in ids_new and b in ids_all, (a, b)
for a, b in REFINES: assert a in ids_all and b in ids_all, (a, b)
for a, b, _ in CONTRADICTS: assert a in ids_all and b in ids_all, (a, b)
for a, b, _, _ in BRIDGES: assert a in ids_all and b in ids_all, (a, b)
miss_v = [k for k in V if k not in ids_new]
assert not miss_v, miss_v
for m in VM['missed']:
    assert not m['absorbed'] or m['absorbed'] in ids_all, m['absorbed']

# ---------------- apply verdicts; split new vs revision of existing ids ----------------
new_nodes, revisions = [], []
for n in nodes:
    n['grade_explorer'] = n.get('evidence_grade'); n['confidence_explorer'] = n.get('confidence')
    if n['id'] in V:
        g, c, d, note, vurls = V[n['id']]
        n['evidence_grade'] = g; n['confidence'] = c; n['verify'] = {'status': 'two-sided', 'direction': d, 'note': note, 'round': R}
        if vurls: n['verify']['urls'] = vurls
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
    rev = dict(base)
    if base not in revisions:
        rev['grade_before_revision'] = base.get('evidence_grade'); rev['confidence_before_revision'] = base.get('confidence')
    if 'correction' in kw and base in revisions and base.get('correction') and base.get('revision_round') == R:
        kw['correction'] = base['correction'] + ' || ' + kw['correction']
    rev.update(kw); rev['revision_round'] = R
    rev['revision_by'] = (base.get('revision_by') + '+integrator-r4') if base in revisions else 'integrator-r4'
    rev['last_verified'] = DATE
    if base in revisions: revisions.remove(base)
    revisions.append(rev)

revise('irl-l5-lean-lowering-theorems', evidence_grade='A', confidence=0.9, correction='r4 executed under Lean 4.35.0@eb6cafb: the as-written r3 draft had 3 elaboration errors besides its declared sorry; with proofs fixed (definitions byte-identical) T1-T5 check, lower_sound_full is closed (axioms propext/Classical.choice/Quot.sound; 6 checkers accept). Grade A is for the MODEL only: one row, mini WHERE, no joins/casts/NULL literals; Exact is a hypothesis real engines violate (PG BUG #19645). See r4e01.lower-sound-full-proved, r4e01.lowering-r3-draft-failed-check, r4e01.l5-theorem-status-table.')
revise('vfg-policy-tristate-failclosed-invariant', confidence=0.9, correction='r4: no Lean file existed behind the r2 "proven in Lean" grade; Combine.lean was first written and checked in r4 (4 theorems: empty=>deny, any error=>deny, allow iff unanimous, never returns error; r4e01.combine-failclosed-first-check). Grade A now rests on the r4 gate log; mapping module crash/timeout to Error is a host obligation (DST).')
revise('r3e05.l5-token-wire-format-lean', evidence_grade='A', confidence=0.9, correction='r4: transcribed and checked in core Lean (16 theorems): T1-T5 checked, HMAC a universally quantified parameter (no axiom); T6 only from an assumed codec roundtrip; verify does not check mint shape (WellMinted hypothesis). Forced spec decisions D1 segment-prefix resources (/t1 vs /t10), D2 op-bitmask subset, D3 depth checked at verify time (caveats after mint prefix <= minted depth), D4 missing argument denies. A for the model; Rust verifier, CBOR codec, constant-time compare and EUF-CMA are outside (r4e01.token-T1-T6-checked, r4e01.token-spec-sharpenings).')
revise('r3e05.l5-token-decision', correction='r4: the token model behind Tier L is checked in Lean (T1-T5); D1/D3/D4 need ratification at spec freeze; fuzz target F6 (append beyond depth) added (r4e01.token-spec-sharpenings).')
revise('vfg-proof-ci-gate-spec', correction='r4: executed as ci/gate.sh + ci/axiom_audit.py (PASS on golden 245 s/1.0 GB, FAIL on negative control). The ofReduceBool/trustCompiler grep denylist is stale: Lean 4.35 deleted both (PR #14953) and native_decide now adds per-theorem <thm>._native.native_decide.ax_N_M axioms, so only an allowlist {propext, Classical.choice, Quot.sound} works; ban native_decide outright (external checkers cannot check native evaluation). The kernel accepts sorryAx, so the axiom audit is the sorry gate; lake check needs a lake-manifest.json; Ubuntu 24.04 AppArmor blocks the bwrap sandbox (exit 1 looks like a proof rejection). See r4e01.l5-proof-ci-gate, r4e01.native-decide-aux-axiom-naming, v4.lake-check-sorryax-manifest.')
revise('vfg-toolchain-pin-footprint-table', correction='r4 measured: with lakefile.toml and zero requires the golden needs only an Init-only Lean subset (712 MB + elan 13 MB; lakefile.lean pulls Lean+Lake oleans, +1.46 GB); Std/Batteries not needed; cold build 2.23 s / 546 MB, lake check 72.6 s / 1.0 GB, lake check --paranoid 228-245 s / ~1.0 GB over 58,609 declarations (CI only; a 1 GB VPS cannot run it). Carving is unsupported upstream: re-verify per pin (r4e01.lakefile-toml-init-only, r4e01.lean-build-footprint-measured).')
revise('vfg-lean-multikernel-paranoid-check', correction='r4: all 6 checkers (paranoid kernel, lean4lean via export, nanoda, con-leche, con-ron, default kernel) accept the golden package; the r2 lean4lean "incompatible header" arises only when run on .olean directly. On the #15908 adversarial export the checkers DISAGREED (3 rejected, 2 accepted): acceptance is evidence only for our own prelude; --from-export only on exports we built; third-party proofs via comparator with our own challenge file (r4e01.lake-check-paranoid-six-kernels, v4.lean-checker-disagreement-15908).')
revise('cedar-lean-proofs-2026-10', correction='r4: the TPE soundness import closure is 159 modules / 41,282 LOC and includes Cedar.Data.Int64 (native_decide x2); 26 native_decide uses repo-wide (16 UnitTest, 8 SymCC Ext, 2 Int64); Cedar CI runs only lake build, no axiom audit; #print axioms after a build is still an over-budget spike (r4e01.cedar-tpe-closure-native-decide, B).')
revise('isolation-decision-table-by-provenance', correction='r4 amended by measurement (r4i04.provenance-substrate-decision-table, B; r4i04.blast-radius-table): direction unchanged. P1 native + catch_unwind + resource ledger + no mutable globals + supervisor-held socket + crash budget; P2 fresh M0 Wasm instance per request (reuse 1, fuel 10-50 ms, 16 MiB) inside a PER-TENANT cordon with seccomp+Landlock, dumpable=0, exec-spawned; P2 handling several principals or native libs = fork-per-request from an exec-spawned zygote; reversal conditions R1-R5.')
revise('hist-php-sharednothing-mechanism', evidence_grade='B', confidence=0.75, correction='r4: first measured numbers (own experiment): PHP-FPM 0 healthy failures for all 7 fault classes at 1% and 5%; segv/abort p99 x1.3-2.0, oom p99 x9-18, loop throughput x0.025 (r4i04.php-fpm-measured-control). The "no public crash-isolation measurements" gap is closed by our own control, not by literature.')
revise('zygote-sandbox-recipe-measured', correction='r4: the base allowlist passes clone/clone3 unfiltered, so children could create user namespaces (72% of kernelCTF LPEs need userns): filter clone flags (no CLONE_NEW*), clone3 -> ENOSYS, deny unshare/setns, stack a no-fork child filter; and spawn workers/zygotes by exec, because respawn-without-exec keeps the layout and makes a zero-blast fork server a BROP crash oracle (r4i04.seccomp-clone-flag-gap, r4i04.crash-oracle-respawn).')
revise('r3pq.cnsa2-tls-profile', correction='r4: pure ML-KEM-1024 is NON-CONFORMANT in France (ANSSI-PG-083 v3.00, 2026-03-20) and only hybrid-recommended by BSI TR-02102 (2026-01) and ECCG ACM v3 draft, so the pure CNSA profile is an opt-in US-NSS profile, not the golden default; universal gov group = SecP384r1MLKEM1024 (r4e10.golden-tls-kex-profiles, r4e10.anssi-pg083-pure-nonconformant).')
revise('crate-rustls-pq', correction='r4: rustls 0.23.46 aws_lc_rs::kx_group lacks SECP384R1MLKEM1024 (0x11ED), the hybrid every non-China jurisdiction accepts (r4e10.rustls-secp384r1mlkem1024-gap, B; check rustls-post-quantum / later releases).')
revise('v3.aws-lc-rs-fips-sys-range', correction='r4: aws-lc-rs 1.17.2 is yanked (2026-07-17) and does not compile with fips-sys <=0.13.15; the window for fips-sys 0.13.11 is 1.15.2-1.17.1; safest pin =1.15.3 (contemporaneous with 0.13.11; 1.15.4 exists) (r4tri.yanked-1.17.2, A).')
revise('ops.fips-module-boundary-pin', correction='r4 integrator: the aws-lc-rs range in the r4 calibration revision (1.15.1-1.17.2) is superseded by r4tri.yanked-1.17.2 (1.15.2-1.17.1). No lock satisfies rustls >=0.23.44 together with fips-sys 0.13.11 (r4tri.no-co-resolvable-lock, A): the cmvp lock is rustls =0.23.43 + aws-lc-rs =1.15.3 + fips-sys =0.13.11 and carries RUSTSEC-2026-0042/0043 (fips-sys 0.13.0-0.13.11), 0349 (PQ downgrade, client side), 0285/0346/0348 and webpki 0382; a direct fips-sys pin beside rustls 0.23.46 yields a silent decoy lock (r4tri.fips-sys-decoy-lock); CMVP #5298/#5314 tested OEs are Amazon Linux 2023 only (r4tri.tested-env-only-al2023).')
revise('dx.l5-decision-sdk-shape', superseded_by='dx.r4-l5-decision-update', correction='r4: superseded by measurement on real axum 0.8.9 + tokio 1.54.1: the scoped-adapter form (B2: Routes-only registration, for<\'r> ScopedHandler<\'r,E>, borrowed Ctx<\'r>) compile-rejects 25/32 mutants vs owned extractors 16/32 and plain axum 3/32; owned FromRequestParts handles are \'static+Send and escape by spawn/static/leak (8/8). Residual after lint: B2 {M15,M16} semantic. Streaming/SSE/WS/body extraction and a Detached capability remain open (dx.r4-l5-decision-update, B).')
revise('irl-l5-backend-refinement-contract', correction='r4: Refines is insufficient once Not is in the IR (checked counterexample neverEq; real instance PG BUG #19645, partition pruning with a nondeterministic collation drops matching rows). Contract becomes two-sided for any adapter exposing negation: leak_cases=0 AND miss_cases=0, else the IR type check rejects Not for that adapter; the schema gate refuses partition keys whose opclass/collation differs from the column (r4e01.exact-vs-refines-not-witness, A).')
revise('irl-l5-unsound-lowering-denylist', correction='r4: write path executed (PG 17.11/19rc1, SQLite 3.45.3, Valkey 9.1.2, Redis 8.10.2): upsert/REPLACE/MERGE on a non-tenant arbiter captured other tenants\' rows 261/300; SET tenant 110-113/300; SQLite authorizer misses REPLACE implicit deletes; ON CONFLICT WHERE runs before RLS. Extended by wpo-l5-write-denylist (B) and INV-WRITE-SUBSET W1-W7.')
revise('gap.unserved-combination', correction='r4 demand side: PQ, formal assurance and compliance are not stated switching criteria in 56 practitioner selection threads (econ.differentiators-absent, C; confounded by PQ already being an invisible library default); agent-infra builders are the only segment stating hardening criteria (econ.who-switches-first, D). The gap stands; positioning must lead with migration parity, ops ergonomics and credential isolation, with assurance as an invisible default.')
revise('threat-ledger-middle-tier-2023-2026', correction='r4: non-adversarial counterpart coded from 160 known-cause middle-tier outages (uu11.outage-class-frequency-table, C): config/data push 17.5%, latent bug 12.5%, fd/worker exhaustion 10.6%, capacity 9.4%, retry storm 6.9%, dependency 6.9%, DNS 6.2%, reload 5%, cert 5%; 0 memory-corruption or parser-differential causes. Durability needs operational invariants the attacker ledger does not list.')
revise('sdg-pgdoc-rls-caveats', correction='r4: executed on 17.11/19rc1: ON CONFLICT DO UPDATE WHERE f(t.col) evaluates a non-leakproof function on another tenant\'s row before the RLS conflict check, contradicting the docs claim that policy quals run before user quals; two independent pgsql-hackers reports (2026-09-25, 2026-10-06 with patch); precedent CVE-2017-15099 (wpo-pg-onconflict-where-peek, v4.pg-onconflict-rls-second-report).')

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
for k, v in V.items():
    for u in v[4]:
        c = canon(u); urlmap[c]['explorers'].add('verifier'); urlmap[c]['raw'] = urlmap[c]['raw'] or u
seen_new = [c for c in urlmap if c not in seen_old]
seen_re = [c for c in urlmap if c in seen_old]

# ---------------- queries ----------------
def classify(q, axes):
    t = (q + ' ' + axes).lower()
    src = ('paper' if re.search(r'arxiv|paper|osdi|sosp|usenix|pldi|popl|ccs|ndss|icse|thesis|\bpdf\b|vldb|eprint', t) else
           'spec-rfc' if re.search(r'rfc|draft|spec|datatracker|ietf|w3c|nist|fips|standard|cnsa|sep-|primary-law|eur-lex|regulation|do-178|do-33|tr-02102|ism|itsp', t) else
           'repo-advisory' if re.search(r'ghsa|advisor|github|issue|repo|crate|release|changelog|rustsec|gh ', t) else
           'cve-incident' if re.search(r'cve|kev|incident|exploit|attack|breach|oss-security|compromis|postmortem|outage', t) else
           'benchmark' if re.search(r'bench|latency|throughput|rps|measure|own-experiment|perf|rss', t) else
           'vendor-doc' if re.search(r'blog|vendor|docs|cloudflare|aws|google|microsoft|stripe', t) else
           'forum' if re.search(r'forum|reddit|hacker news|\bhn\b|lobste|lemmy|discussion|mailing|lkml|discourse', t) else
           'talk' if re.search(r'talk|slides|def ?con|black ?hat|conference', t) else 'web-other')
    stance = ('skeptic-negative' if re.search(r'contrarian|negative|skeptic|critique|fail|limit|overhype|bypass|pitfall|footgun|wrong|doesn.t|not |prosecutor', t) else
              'attacker' if re.search(r'attack|exploit|offens|escape|smuggl|poison|offsec', t) else 'proponent')
    era = ('last-60d' if re.search(r'last.?60|recen|oct 2026|sep 2026|aug 2026|2026-(08|09|10)|october|september', t) else
           'historical' if re.search(r'histor|20(0|1)\d|legacy|foundational|retrospect', t) else '2025-26')
    vocab = ('PL-formal' if re.search(r'pl-formal|formal|lean|verus|kani|proof|tla|smt|coq|f\*', t) else
             'cryptography' if re.search(r'crypto|pqc|mlkem|ml-kem|tls|fips|cmvp|stek|ticket', t) else
             'offensive' if re.search(r'offens|attack|exploit|offsec|cve|ghsa|bypass|smuggl', t) else
             'standards-policy' if re.search(r'standards|policy|gov|law|regulat|cra|fedramp|nist|ssdf|certif|do-178|eal', t) else
             'network-SRE' if re.search(r'sre|ops|systemd|kernel|network|queueing|cdn|load|outage|incident', t) else
             'economics' if re.search(r'econom|cost|pricing|market|payment|x402|switch|migrat|adopt', t) else
             'database' if re.search(r'database|db-|sql|redis|mongo|kafka|store|wal|fsync', t) else
             'web-dev' if re.search(r'web-dev|practitioner|api|browser|framework', t) else 'systems')
    scale = ('government' if re.search(r'gov|fedramp|fips|cnsa|nist|bsi|anssi|asd|cccs', t) else 'household' if re.search(r'household|vps|1 ?vcpu|laptop|selfhost|self-host|homelab', t) else
             'hyperscaler' if re.search(r'hyperscal|cloudflare|aws|google|cdn', t) else 'enterprise' if re.search(r'enterprise|k8s|kubernetes|ingress', t) else 'unspecified')
    return src, stance, era, vocab, scale
LABEL2PILLAR = {'lean-check-lowering-and-token-proofs': 'W-FORMAL', 'write-path-lowering-differential-oracle': 'W-DATA-GATE',
 'fips-golden-version-triangle-one-lock': 'W-PQC', 'isolation-crash-blast-radius-measured': 'W-ISOLATION',
 'dx-capability-sdk-mutants-real-axum-async': 'W-DX', 'mcp-gateway-conformance-corpus-executed': 'W-AGENT-PROTOCOL',
 'bridge-canonical-identity-one-owner': 'W-BRIDGE', 'switching-economics-practitioner-forums': 'W-GAP',
 'safety-critical-certification-assurance-historical': 'T-SAFETY-CERT', 'non-us-national-pqc-crypto-regimes': 'W-PQC',
 'uu-incident-dataset-outage-root-causes': 'W-THREAT', 'calibration-two-sided-top-findings-r3': 'K-CALIBRATION'}
prior_Q = jl(ST + '/queries.jsonl')
prior_q = [toks(q.get('query', '')) for q in prior_Q]
prior_cells = {q.get('cell') for q in prior_Q}
prior_cells5 = {q.get('cell5') for q in prior_Q if q.get('cell5')}
Q = []
for line in open(RAW + '/_queries.log', errors='replace'):
    p = line.rstrip('\n').split('\t')
    if len(p) < 2 or not p[1].strip(): continue
    lab, q, axes = p[0], p[1], (p[2] if len(p) > 2 else '')
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
per_label_cells = {lab: (sum(1 for x in Q if x['label'] == lab), len({x['cell'] for x in Q if x['label'] == lab}),
                         sum(1 for x in Q if x['label'] == lab and x['near_dup_of'])) for lab in LABEL2PILLAR}

yl = {}
for lab in sorted(LABEL2PILLAR):
    nq = sum(1 for x in Q if x['label'] == lab)
    nn = [n for n in new_nodes if n['explorer'].endswith(lab)]
    revs = sum(1 for r in revisions if lab in str(r.get('revision_by', '')))
    l45 = sum(1 for n in nn if n.get('layer') in ('L4', 'L5') and not n['merged_into'])
    yl[lab] = (nq, len(nn), l45, (round(l45 / nq, 2) if nq else None), revs)

# ---------------- frontier queue ----------------
Qold = jl(ST + '/frontier_queue.jsonl')
DONE_IDS = {  # id: (status, resolved_by)
 'q1-013': ('done', 'r4i04.blast-radius-table, r4i04.php-fpm-measured-control (7 fault classes x 7 substrates x 3 rates; laptop, counts robust, latency contaminated)'),
 'q2-008': ('done', 'l5.mcp-lc-corpus-runnable, l5.mcp-lc-passrate-matrix (43 cases vs py/ts/rmcp/agentgateway/docker-mcp)'),
 'q3-004': ('done', 'r4tri.no-co-resolvable-lock, r4tri.separate-fips-lock-decision (triangle empty at the floor; two lock profiles)'),
 'q3-006': ('partial', 'wpo-inv-write-subset, wpo-l5-write-oracle-harness, wpo-l5-write-denylist (PG/SQLite/Redis executed; Mongo updateMany and MySQL open as new seeds)'),
 'q3-012': ('done', 'dx.r4-real-axum-mutant-scores, dx.r4-owned-extractor-static-escape, dx.r4-scoped-adapter-hrtb'),
 'q3-020': ('done', 'r4e01.lower-sound-full-proved, r4e01.lean-build-footprint-measured (no Batteries needed)'),
 'q2-011': ('partial', 'r4e01.lower-sound-full-proved (model checked), irl-l5-differential-oracle-harness (refinement tested); per-adapter proof remains out of reach'),
 'q1-038': ('partial', 'econ.criteria-frequency, econ.deal-breakers (HN/Lemmy/GitHub/Discourse; reddit and lobste.rs walled)'),
 'q2-051': ('done', 'r4e01.lake-check-paranoid-six-kernels, r4e01.lean-build-footprint-measured (228-245 s / 1.0 GB over 58,609 declarations; lean4lean works via export)'),
 'q1-024': ('partial', 'r4e10.rustls-secp384r1mlkem1024-gap (absent in 0.23.46); pure ML-KEM-1024 under #5314 still open'),
 'q1-046': ('partial', 'r4tri.tested-env-only-al2023 (MIP 2026-10-24: AWS-LC 4 Comment Resolution, AWS-LC 5 Pending Review)'),
 'q3-067': ('partial', 'r4e01.cedar-tpe-closure-native-decide (closure includes Int64 native_decide; #print axioms over budget)'),
 'q3-045': ('partial', 'r4e07.diff-corpus-executed (matchit on raw path misses /admin/), r4e07.invariant-canon-one-owner (authz on matched route id)'),
 'q3-060': ('partial', 'uu11.cfg-push-class, uu11.lifecycle-operator-class (Fastly 2021 / GCP 2025 Service Control not individually fetched)'),
 'q2-070': ('partial', 'v4.mcp-default-off-dns-rebinding-cves (Ruby SDK CVE-2026-63118, Java SDK CVE-2026-35568)'),
 'q3-100': ('done', 'r4e01.l5-pinned-toolchain-lakefile (v4.35.0 @ eb6cafb, tarball sha256 pinned)'),
 'q1-048': ('partial', 'r4i04.kernelctf-reachability-under-allowlist, r4i04.seccomp-clone-flag-gap'),
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
    items.append({'question': mm['text'], 'layer': 'L4', 'domain': mm.get('domain', ''), 'expected_info_gain': float(mm.get('eig', .35)),
                  'reason': 'verifier missed-list', 'sources': [f"verifier-{mm['explorer']}"], 'kind': 'missed', 'absorbed_into': mm.get('absorbed')})
INTEGRATOR_SEEDS = [
 ('Two-sided lowering oracle: add a miss oracle (miss_cases) and re-run SQLite/PG/Redis hardened lowerings, including PG 18.6 partition pruning with a nondeterministic collation (BUG #19645); does any hardened lowering miss rows?', 'L5', 'W-DATA-GATE', .55, 'Bridge 01x02: the two-sided R-DB-7 contract has no executed miss oracle yet (integrator)'),
 ('Add slow-upstream (10x latency), oversize-config and retry-storm faults to the r4 isolation fault harness so UP-1..6 and CFG-1..4 are gated on the same substrate matrix and 1-core box', 'L5', 'W-ASSURE', .5, 'Bridge 04x11: one fault harness for crash and outage classes (integrator)'),
 ('Known-false-proof regression corpus for the Lean gate (#14484, #14576, #15908 export, a native_decide control, a sorry control): 100% rejected on every toolchain bump, run in CI', 'L5', 'W-FORMAL', .5, 'Bridge 01x09: TQL-5-style qualification evidence (integrator)'),
 ('Run the r4 identity differential (07-work/diffh) against the MCP SDK listener paths (rmcp, TS createMcpHandler, py) to measure Host/:authority/Origin canonicalization disagreements end to end', 'L4', 'W-AGENT-PROTOCOL', .45, 'Bridge 06x07: listener gate and CANON-6 share one owner (integrator)'),
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
        k += 1; m['id'] = f'q4-{k:03d}'

# ---------------- predictions ----------------
PRED = [
 ('pred-pg-onconflict-rls-order-fix', 'PostgreSQL commits a fix that evaluates the ON CONFLICT DO UPDATE/SELECT WHERE clause only after the RLS conflict check (or fixes the PG19 DO SELECT view exposure) by 2027-01-31', '2027-01-31', 'git log REL_19_STABLE/master for nodeModifyTable.c ExecOnConflictUpdate/Select; pgsql-hackers threads', .65, 'wpo-pg-onconflict-where-peek'),
 ('pred-rustls-secp384r1mlkem1024', 'A rustls crates.io release exposes SECP384R1MLKEM1024 (0x11ED) in its aws-lc-rs kx_group module by 2027-06-30', '2027-06-30', 'docs.rs rustls latest crypto::aws_lc_rs::kx_group', .6, 'r4e10.rustls-secp384r1mlkem1024-gap'),
 ('pred-bsi-tr02102-2027-hybrid-groups', 'The 2027 edition of BSI TR-02102-2 lists SecP256r1MLKEM768 and SecP384r1MLKEM1024 as recommended TLS 1.3 groups (and not X25519MLKEM768) by 2027-03-31', '2027-03-31', 'bsi.bund.de TR-02102-2 PDF', .7, 'r4e10.bsi-tr02102-2026'),
 ('pred-osv-cedar-ghsa-m84h', 'OSV returns GHSA-m84h-6f26-p3p7 (cedar-policy >=4.3,<4.13) with affected crates.io ranges by 2026-11-30', '2026-11-30', 'curl https://api.osv.dev/v1/vulns/GHSA-m84h-6f26-p3p7', .6, 'r4c12.repo-ghsa-osv-blindspot'),
 ('pred-simd-json-481-fix', 'simd-json publishes a crates.io release fixing lone-surrogate decoding to U+0000 (issue #481 / PR #482) by 2027-01-31', '2027-01-31', 'simd-lite/simd-json releases and issue #481', .65, 'r4e07.json-parser-dup-key-matrix'),
 ('pred-mcp-conformance-32020-failure', 'The MCP conformance suite grades a -32020 header/body mismatch violation as a FAILURE (issue #553 / PR #555 merged) by 2027-01-31', '2027-01-31', 'github.com/modelcontextprotocol/conformance issue 553', .7, 'v4.mcp-conformance-suite-open-gaps'),
 ('pred-wasmtime-m0-3in12', 'At least 3 M0-class (x86_64 Cranelift core-Wasm, default config) Wasmtime sandbox escapes are published between 2026-10-25 and 2027-10-25', '2027-10-25', 'gh api repos/bytecodealliance/wasmtime/security-advisories, classify per r2 M0 rules', .15, 'wasmtime-advisory-share-by-config'),
 ('pred-ngcc-round2', 'China NICCS announces NGCC public-key round-2 candidates by 2027-06-30', '2027-06-30', 'niccs.org.cn NGCC notices', .55, 'r4e10.china-ngcc-round1'),
 ('pred-ingress-nginx-traefik-share', 'RKE2 stable ships Traefik (not ingress-nginx) as the default ingress controller by 2027-03-31', '2027-03-31', 'rancher/rke2 release notes', .7, 'v4.ingress-migration-distro-channel'),
]
old_preds = jl(ST + '/predictions.jsonl')
old_pid = {p['id'] for p in old_preds}
PRED = [p for p in PRED if p[0] not in old_pid]
SC = {s['id']: s for s in json.load(open(RAW + '/12-calibration-two-sided-top-findings-r3.json')).get('predictions_scorecard', [])}
n_scored = 0
for p in old_preds:
    s = SC.get(p['id'])
    if s:
        p['status'] = s.get('status_2026_10_25'); p['last_checked'] = '2026-10-25'; p['suggested_p'] = s.get('suggested_p')
        p['score_evidence'] = s.get('evidence'); p['scored_round'] = R; n_scored += 1
new_preds = [{'id': pid, 'claim': claim, 'resolve_by': by, 'how_to_check': how, 'p': p, 'source_node': src, 'made_round': R, 'made_date': '2026-10-25', 'status': 'pending', 'last_checked': '2026-10-25'} for pid, claim, by, how, p, src in PRED]

# ---------------- write ----------------
by_layer = collections.Counter(n.get('layer') for n in new_nodes)
by_pl = collections.Counter((n['pillar'], n.get('layer')) for n in new_nodes)
grades = collections.Counter(n['evidence_grade'] for n in new_nodes)
dirs = collections.Counter(n['verify']['direction'] for n in nodes if n['verify']['status'] == 'two-sided')
summary = dict(new_nodes=len(new_nodes), explorer_new=len([n for n in new_nodes if not n['explorer'].startswith('verifier')]),
               verifier_nodes=len(VM['vnodes']), revisions=len(revisions), revision_ids=[r['id'] for r in revisions], merged_same_as=len(merged_new), edges=len(edges), bridges=n_bridges,
               edges_by_origin=dict(collections.Counter(e['origin'].split('-')[0] for e in edges)),
               singletons=len(singletons), strict_singletons=len(strict_singletons), strict_ids=[n['id'] for n in strict_singletons], by_layer=dict(by_layer), grades=dict(grades),
               verify_dirs=dict(dirs), sampled=sum(1 for n in nodes if n['verify']['status'] == 'two-sided'), urls_total=len(urlmap),
               urls_new=len(seen_new), urls_reseen=len(seen_re), queries=len(Q), cells=len(cells), new_cells=len(new_cells), cells5=len(cells5), new_cells5=len(new_cells5),
               q_share_in_new_cells=round(q_in_new_cells, 3),
               direction_diversity=round(direction_diversity, 3), direction_diversity_5axis=round(direction_diversity5, 3),
               queue=len(allq), queue_open=sum(1 for m in allq if m['status'] == 'open'), queue_partial=sum(1 for m in allq if m['status'] == 'partial'),
               queue_done=sum(1 for m in allq if m['status'] == 'done'), queue_absorbed=sum(1 for m in allq if m['status'] == 'absorbed'),
               merged_into_old_queue=n_into_old, predictions_new=len(new_preds), predictions_scored=n_scored, yields=yl, per_label_cells=per_label_cells,
               axis_counts={k: dict(collections.Counter(x[k] for x in Q)) for k in ('source_type', 'stance', 'era', 'pillar', 'vocab', 'scale')},
               by_pillar_layer={f'{a}|{b}': c for (a, b), c in sorted(by_pl.items())}, cross_near_dups=[p for p in nd_pairs if p[0] != p[1]],
               intra_near_dups=len([p for p in nd_pairs if p[0] == p[1]]),
               prior_round_near_dups=[(x['label'], x['max_prior_round_jaccard'], x['query'], x.get('prior_round_near_dup_of')) for x in Q if x['max_prior_round_jaccard'] >= .5],
               top_cells=cells.most_common(15), xdup_nodes=xdup[:15])
os.makedirs(SCR, exist_ok=True)
json.dump(summary, open(SCR + '/r4_summary.json', 'w'), indent=1, default=list)
json.dump({'cells': dict(cells), 'cells5': dict(cells5), 'new_cells': new_cells}, open(SCR + '/r4_cells.json', 'w'), indent=1)
json.dump([{k: m.get(k) for k in ('id', 'score', 'status', 'question', 'resolved_by', 'sources', 'layer', 'domain')} for m in allq], open(SCR + '/r4_queue_view.json', 'w'), indent=1)
if DRY:
    print(json.dumps({k: v for k, v in summary.items() if k not in ('by_pillar_layer', 'cross_near_dups', 'axis_counts', 'revision_ids', 'strict_ids', 'prior_round_near_dups', 'per_label_cells')}, indent=1, default=list)); sys.exit(0)
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
write_atomic(ST + '/frontier_queue.jsonl', allq)
write_atomic(ST + '/predictions.jsonl', old_preds + new_preds)
print(json.dumps({k: v for k, v in summary.items() if k not in ('by_pillar_layer', 'cross_near_dups', 'axis_counts', 'revision_ids', 'strict_ids', 'prior_round_near_dups', 'per_label_cells')}, indent=1, default=list))
