#!/usr/bin/env python3
"""Deterministic dedup / novelty gate for the AEGIS research track (directive §0d).

No LLM judgment: canonical-URL set membership plus token-set Jaccard over queries, node titles and target briefs.
Ground truth is every earlier round's raw output (state/raw/round-NNN/*.json, _queries.log) plus the integrator's
state files (graph.jsonl, seen.jsonl, queries.jsonl) when present. The current round's live files count as "earlier"
for sibling dedup.

Usage (run from anywhere; python3 -I recommended):
  novelty_gate.py query "<search query>" [...]      -> NOVEL / NEAR-DUP / DUP per query (vs all logged queries)
  novelty_gate.py url <url> [...]                   -> NEW / SEEN per canonical URL
  novelty_gate.py topic "<text>"                    -> top existing nodes to REUSE (ids) and a NOVEL/COVERED verdict
  novelty_gate.py target "<brief>"                  -> similarity to every prior target label/brief and node cluster
  novelty_gate.py coverage                          -> domain x layer node counts, axis-cell query counts, thin cells
  novelty_gate.py metrics --round N                 -> mechanical novelty of round N vs rounds < N (JSON)
Exit code 0 always (it is a gate the agent must read, not a crash).
"""
import json, re, sys, os, glob
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = os.path.join(ROOT, 'state')
RAW = os.path.join(STATE, 'raw')
STOP = set('a an the of and or for to in on with by from at as is are be vs via into over under than that this these those what which how why when '
           'its it their our your using use based new 2023 2024 2025 2026 rust http https www com org'.split())
DUP_Q, NEAR_Q = 0.75, 0.5      # query thresholds (Jaccard on token sets)
COVERED_T = 0.6                # topic/node coverage threshold (title Jaccard or token containment)


def toks(s):
    out = set()
    for w in re.findall(r'[a-z0-9][a-z0-9_.+#-]*', (s or '').lower()):
        w = w.strip('.-')
        if len(w) < 2 or w in STOP:
            continue
        if len(w) > 4 and w.endswith('s') and not w.endswith('ss'):
            w = w[:-1]
        out.add(w)
    return out


def jac(a, b):
    return len(a & b) / len(a | b) if a and b else 0.0


def canon(u):
    try:
        p = urlsplit(u.strip())
    except ValueError:
        return u.strip()
    host = (p.hostname or '').lower()
    if host.startswith('www.'):
        host = host[4:]
    if host == 'arxiv.org':  # abs/html/pdf + version -> one id
        m = re.search(r'(\d{4}\.\d{4,5})', p.path)
        if m:
            return 'arxiv:' + m.group(1)
    q = [(k, v) for k, v in parse_qsl(p.query) if not k.lower().startswith(('utm_', 'ref', 'fbclid', 'gclid'))]
    path = re.sub(r'/+$', '', p.path) or '/'
    return urlunsplit(('https', host, path, urlencode(sorted(q)), ''))


def rnum(path):
    m = re.search(r'round-(\d{3})', path)
    return int(m.group(1)) if m else 0


def walk_urls(o, acc):
    if isinstance(o, str):
        for u in re.findall(r'https?://[^\s"\'<>)\]]+', o):
            acc.add(canon(u.rstrip('.,;')))
    elif isinstance(o, dict):
        for v in o.values():
            walk_urls(v, acc)
    elif isinstance(o, list):
        for v in o:
            walk_urls(v, acc)


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def jsonl(path):
    out = []
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        pass
    return out


def corpus(before_round=None):
    """Collect queries, urls, nodes, targets from raw rounds (< before_round if given) + integrator state."""
    Q, U, N, T = [], set(), [], []
    for d in sorted(glob.glob(os.path.join(RAW, 'round-*'))):
        r = rnum(d)
        if before_round is not None and r >= before_round:
            continue
        ql = os.path.join(d, '_queries.log')
        if os.path.exists(ql):
            for line in open(ql, errors='replace'):
                parts = line.rstrip('\n').split('\t')
                if len(parts) >= 2:
                    Q.append({'round': r, 'label': parts[0], 'q': parts[1], 'axes': parts[2] if len(parts) > 2 else ''})
        for jf in glob.glob(os.path.join(d, '*.json')):
            o = load_json(jf)
            if o is None:
                continue
            walk_urls(o, U)
            label = re.sub(r'^\d+-', '', os.path.basename(jf)[:-5])
            T.append({'round': r, 'label': label})
            for n in (o.get('nodes') or []) if isinstance(o, dict) else []:
                if isinstance(n, dict):
                    N.append({'round': r, 'id': n.get('id'), 'domain': n.get('domain', ''), 'layer': n.get('layer', ''),
                              'text': f"{n.get('title', '')} {n.get('summary', '')}", 'title': n.get('title', '')})
    if before_round is None:  # integrator state (deduped, cross-round)
        for n in jsonl(os.path.join(STATE, 'graph.jsonl')):
            N.append({'round': n.get('first_seen_round', 0), 'id': n.get('id'), 'domain': n.get('domain', ''),
                      'layer': n.get('layer', ''), 'text': f"{n.get('title', '')} {n.get('summary', '')}", 'title': n.get('title', '')})
        for s in jsonl(os.path.join(STATE, 'seen.jsonl')):
            walk_urls(s, U)
        for q in jsonl(os.path.join(STATE, 'queries.jsonl')):
            Q.append({'round': q.get('round', 0), 'label': q.get('label', ''), 'q': q.get('query') or q.get('q', ''), 'axes': str(q.get('axes', ''))})
    return Q, U, N, T


def cmd_query(args):
    Q, _, _, _ = corpus()
    qt = [(x, toks(x['q'])) for x in Q]
    for q in args:
        t = toks(q)
        best = max(((jac(t, b), x) for x, b in qt), key=lambda z: z[0], default=(0, None))
        v = 'DUP' if best[0] >= DUP_Q else 'NEAR-DUP' if best[0] >= NEAR_Q else 'NOVEL'
        near = f" ~ r{best[1]['round']} [{best[1]['label']}] \"{best[1]['q']}\"" if best[1] else ''
        print(f"{v}\t{best[0]:.2f}\t{q}{near}")
    print('Rule: DUP -> do not run; NEAR-DUP -> change vocabulary/source type/stance before running; NOVEL -> run and log it.')


def cmd_url(args):
    _, U, _, _ = corpus()
    for u in args:
        print(f"{'SEEN' if canon(u) in U else 'NEW'}\t{canon(u)}")
    print('Rule: SEEN URLs may be re-read only to verify a claim; they do not count toward your source floor or novelty.')


def contain(q, n):
    return len(q & n) / len(q) if q else 0.0


def nscore(t, n):
    # a node covers a topic if it matches the title closely or contains most of the topic's tokens
    return max(jac(t, toks(n['title'])), contain(t, toks(n['text'])) * min(1.0, len(t) / 4))


def ranked_nodes(text, N, k=8):
    t = toks(text)
    sc = sorted(((nscore(t, n), n) for n in N), key=lambda z: -z[0])
    seen, out = set(), []
    for s, n in sc:
        if n['id'] in seen:
            continue
        seen.add(n['id'])
        out.append((s, n))
        if len(out) >= k:
            break
    return out


def cmd_topic(args):
    _, _, N, _ = corpus()
    text = ' '.join(args)
    top = ranked_nodes(text, N)
    cov = top and top[0][0] >= COVERED_T
    print(f"{'COVERED' if cov else 'NOVEL'}\tbest={top[0][0]:.2f}" if top else 'NOVEL\t(empty map)')
    for s, n in top:
        print(f"  {s:.2f}\tr{n['round']}\t{n['id']}\t{n['layer']}\t{n['title'][:110]}")
    print('Rule: COVERED -> reuse those ids and only add strictly new specifics (L4/L5, newer date, contrary evidence); otherwise move to another axis.')


def cmd_target(args):
    Q, _, N, T = corpus()
    text = ' '.join(args)
    t = toks(text)
    labels = {}
    for x in T:
        labels.setdefault(x['label'], x['round'])
    lab = sorted(((max(jac(t, toks(l.replace('-', ' '))), contain(toks(l.replace('-', ' ')), t)), l, r) for l, r in labels.items()), key=lambda z: -z[0])[:5]
    print('Closest prior targets:')
    for s, l, r in lab:
        print(f"  {s:.2f}\tr{r}\t{l}")
    print('Closest existing nodes:')
    for s, n in ranked_nodes(text, N, 6):
        print(f"  {s:.2f}\tr{n['round']}\t{n['id']}\t{n['title'][:100]}")
    qs = sorted(((jac(t, toks(x['q'])), x) for x in Q), key=lambda z: -z[0])[:5]
    print('Closest prior queries:')
    for s, x in qs:
        print(f"  {s:.2f}\tr{x['round']}\t{x['q'][:100]}")
    print('Rule: a target whose closest prior target/node is >= 0.45 must be a DESCEND that changes the instrument (survey -> defect hunt -> '
          'measurement/experiment -> L5 artifact) or move to an empty axis cell; restating a covered area is rejected.')


def axes_of(x):
    return frozenset(a.strip().lower() for a in re.split(r'[,;/|]', x.get('axes', '')) if a.strip())


def cmd_coverage(_args):
    Q, U, N, T = corpus()
    from collections import Counter
    dl = Counter((re.sub(r'\s+.*', '', (n['domain'] or '?')), n['layer'] or '?') for n in {n['id']: n for n in N}.values())
    ax = Counter(a for x in Q for a in axes_of(x))
    print(f"nodes={len({n['id'] for n in N})} urls={len(U)} queries={len(Q)} targets={len({x['label'] for x in T})}")
    print('domain x layer (node counts):')
    for (d, l), c in sorted(dl.items()):
        print(f"  {d:28s} {l:4s} {c}")
    print('axis values used in queries (count) — thin values are where new directions are cheapest:')
    for a, c in sorted(ax.items(), key=lambda z: z[1]):
        print(f"  {c:4d}  {a}")


def cmd_metrics(args):
    if '--round' not in args:
        print('need --round N'); return
    R = int(args[args.index('--round') + 1])
    Qp, Up, Np, _ = corpus(before_round=R)
    Qa, _, Na, _ = corpus(before_round=R + 1)
    Qr = [x for x in Qa if x['round'] == R]
    Nr = [n for n in Na if n['round'] == R]
    Ur = set()
    for d in glob.glob(os.path.join(RAW, f'round-{R:03d}', '*.json')):
        o = load_json(d)
        if o is not None:
            walk_urls(o, Ur)
    prior_q = [toks(x['q']) for x in Qp]
    def novel_frac(items, prior, thr):
        if not items:
            return None
        if not prior:
            return 1.0
        return sum(1 for t in items if max((jac(t, p) for p in prior), default=0) < thr) / len(items)
    prior_cells = {axes_of(x) for x in Qp}
    cells_r = [axes_of(x) for x in Qr]
    out = {
        'round': R,
        'queries': len(Qr), 'urls': len(Ur), 'nodes': len(Nr),
        'url_novelty': (len(Ur - Up) / len(Ur)) if Ur else None,
        'query_novelty': novel_frac([toks(x['q']) for x in Qr], prior_q, NEAR_Q),
        'node_novelty': (sum(1 for n in Nr if max((nscore(toks(n['title']), p) for p in Np), default=0) < COVERED_T) / len(Nr)) if Nr else None,
        'axis_cell_novelty': (sum(1 for c in cells_r if c and c not in prior_cells) / len(cells_r)) if cells_r else None,
        'intra_round_query_dup_rate': None,
    }
    if Qr:
        ts = [toks(x['q']) for x in Qr]
        dup = sum(1 for i, t in enumerate(ts) if any(jac(t, ts[j]) >= DUP_Q for j in range(i)))
        out['intra_round_query_dup_rate'] = dup / len(ts)
    vals = [v for k, v in out.items() if k.endswith('_novelty') and v is not None]
    out['mechanical_novelty'] = min(vals) if vals else None  # conservative: the least-novel dimension
    print(json.dumps(out, indent=1))


if __name__ == '__main__':
    cmds = {'query': cmd_query, 'url': cmd_url, 'topic': cmd_topic, 'target': cmd_target, 'coverage': cmd_coverage, 'metrics': cmd_metrics}
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        print(__doc__); sys.exit(0)
    cmds[sys.argv[1]](sys.argv[2:])
