#!/usr/bin/env python3
"""AEGIS crash harness (oracle for INV-DURABLE). Run as `python3 -I crashsim.py`, normally via ./run.

Port of research round-002 `crashsim.py` (ALICE-style logical-op replay over an LD_PRELOAD trace), with:
  * the workload owned by the oracle and subjects reduced to a line protocol (README "Subject protocol");
  * crash points = every post-ack instant + a seeded random sample + end of trace;
  * stage EIO   : the k-th fsync fails with EIO (fsyncgate model: that file's unsynced writes become limbo, never
                  promoted by a later fsync); rule: no ack may follow an fsync error (fail-stop), plus crash images;
  * stage DOUBLE: crash during recovery: a first-crash image is reopened under the tracer, and every crash point of
                  that recovery is replayed over the first image as the durable base;
  * fail-closed coverage audit: unmodelled ops (link, exchange-rename, copy_file_range, writable mmap other than
    SQLite's non-durable -shm) or a trace without the expected op kinds make the run FAIL.

Persistence model at cut k (after op k; acked = last ack marker <= k): image = durable data (fsync/fdatasync/O_DSYNC
before k) + survivors among unsynced data ops (policy) + namespace per regime.
  policies: dropall | all (SIGKILL: page cache intact) | subset (each 4 KiB page of each unsynced write survives
            w.p. 1/2, arbitrary reorder) | prefix (random prefix in issue order, last write torn at 512 B)
  regimes:  full (SIGKILL) | fsfile (create durable at fsync(file); rename/unlink need dir fsync) |
            journal (random prefix of ns ops since the last fsync of anything) | strict (ns op durable only after
            fsync of its parent dir; otherwise survives w.p. 1/2)
NOT modelled: mmap stores, sub-sector tearing, bit rot, misdirected writes, raw syscalls that bypass LD_PRELOAD.
"""
import argparse, collections, concurrent.futures as cf, json, os, random, re, shlex, shutil, subprocess, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
TGT = os.environ.get('AEGIS_CRASH_TARGET', os.path.join(HERE, 'rust', 'target', 'release'))
REFSTORE = os.path.join(TGT, 'refstore')
PRELOAD = os.path.join(TGT, 'libaegis_crash_open.so') + ':' + os.path.join(TGT, 'libaegis_crash_shim.so')
PAGE, SECT = 4096, 512
POLICIES = [('dropall', 'journal'), ('dropall', 'fsfile'), ('dropall', 'strict'), ('all', 'full'),
            ('subset', 'journal'), ('subset', 'fsfile'), ('subset', 'strict'),
            ('prefix', 'journal'), ('prefix', 'fsfile'), ('prefix', 'strict')]
CTR_KEY = b'ctr'.hex()

# ------------------------------------------------------------------ workload (identical to research wl::ops)
M64 = (1 << 64) - 1
def val(i):
    n = 64 + (i % 7) * 300
    s = ((i * 0x9E3779B97F4A7C15) & M64) | 1
    out = bytearray(i.to_bytes(8, 'big') + n.to_bytes(4, 'big'))
    for _ in range(n):
        s ^= (s << 13) & M64; s ^= s >> 7; s ^= (s << 17) & M64
        out.append((s >> 24) & 0xff)
    return bytes(out)
def ops(i):
    return [(0, b'ctr', i.to_bytes(8, 'big')), (0, b'a%03d' % (i % 50), val(i)), (0, b'g%08d' % i, val(i)),
            (1, b'ctr', i.to_bytes(8, 'big')), (1, b'b%03d' % (i % 50), val(i + 1000))]
class Expected:
    # The verify pool calls get() from several threads; unlocked, two threads could both append state i and shift
    # every later index by one, so a correct image was compared with the wrong expected state (Phase 8, p8-sqlite).
    def __init__(s): s.states = [{}]; s.lock = threading.Lock()
    def get(s, c):
        with s.lock:
            while len(s.states) <= c:
                i = len(s.states); d = dict(s.states[-1])
                for t, k, v in ops(i): d[(t, k.hex())] = v.hex()
                s.states.append(d)
            return s.states[c]
EXP = Expected()

# ------------------------------------------------------------------ subjects
class Subject:
    def __init__(s, name, argv, mutations=(), env=None):
        s.name, s.argv, s.mut, s.env = name, list(argv), list(mutations), dict(env or {})
    def cmd(s, d):
        a = [x.replace('{dir}', d) for x in s.argv]
        if not any('{dir}' in x for x in s.argv): a.append(d)
        return a + s.mut
def ref(store, cfg, *mut, env=None):
    return Subject(f'{store}:{cfg}' + ''.join(f' {m}' for m in mut), [REFSTORE, 'serve', store, cfg, '{dir}'], mut, env)

def _killer(p, secs):
    t = threading.Timer(secs, lambda: p.poll() is None and p.kill()); t.daemon = True; t.start(); return t

def run_trace(subj, root, log, n, extra_env=None, script=None, timeout=600):
    """Start the subject under the tracer in `root`; drive n txns (or a fixed `script`). Returns a dict."""
    env = dict(os.environ, AEGIS_LOG=log, AEGIS_ROOT=root, LD_PRELOAD=PRELOAD, **subj.env, **(extra_env or {}))
    errf = open(log + '.stderr', 'w')
    p = subprocess.Popen(subj.cmd(root), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errf, env=env, text=True, bufsize=1)
    k = _killer(p, timeout); r = {'acked': 0, 'failed_at': None, 'ready': None, 'err': None, 'out': []}
    try:
        line = p.stdout.readline().rstrip('\n'); r['ready'] = line
        if not line.startswith('READY'):
            r['err'] = 'no READY: ' + line[:200]
        elif script is not None:
            p.stdin.write(script); p.stdin.flush(); p.stdin.close()
            r['out'] = p.stdout.read().splitlines()
        else:
            for i in range(1, n + 1):
                p.stdin.write(f'BEGIN {i}\n'); p.stdin.flush()
                b = p.stdout.readline().strip()
                if b != f'BEGUN {i}': r['err'] = f'bad BEGIN reply {b[:80]!r}'; break
                p.stdin.write(''.join(f'PUT {t} {kk.hex()} {v.hex()}\n' for t, kk, v in ops(i)) + f'COMMIT {i}\n'); p.stdin.flush()
                c = p.stdout.readline().strip()
                if c.startswith('OK '):
                    r['acked'] = int(c.split()[1])
                    if r['acked'] != i: r['err'] = f'ack for wrong txn {c!r}'; break
                else:
                    r['failed_at'] = i; r['err'] = 'commit: ' + c[:200]; break
            p.stdin.write('QUIT\n'); p.stdin.flush(); p.stdin.close()
            p.stdout.read()
    except (BrokenPipeError, OSError) as e:
        r['err'] = r['err'] or f'pipe: {e}'
    p.wait(); k.cancel(); errf.close(); r['rc'] = p.returncode
    return r

def verify(subj, d, acked, timeout=60):
    try:
        p = subprocess.run(subj.cmd(d), input='DUMP\nCHECK\nQUIT\n', capture_output=True, text=True, timeout=timeout, env=dict(os.environ, **subj.env))
    except subprocess.TimeoutExpired:
        return 'timeout', 'hang'
    lines = p.stdout.splitlines()
    if not lines or not lines[0].startswith('READY'):
        if p.returncode < 0: return f'crash_sig{-p.returncode}', (lines[:1] or [''])[0][:160]
        return 'open_fail', ((lines[:1] or [''])[0] + ' ' + (p.stderr.strip().splitlines() or [''])[-1])[:200]
    dump, integ, i = {}, None, 1
    while i < len(lines):
        ln = lines[i]; i += 1
        if ln.startswith('KV '):
            _, t, k, v = ln.split(' ')
            dump[(int(t), k)] = v
        elif ln == 'END': continue
        elif ln.startswith('ERR dump'): return 'read_fail', ln[:200]
        elif ln.startswith('INTEGRITY '): integ = ln
    if integ is None:
        return (f'crash_sig{-p.returncode}' if p.returncode < 0 else f'crash_rc{p.returncode}'), (p.stderr.strip().splitlines() or [''])[-1][:160]
    def ctr(t):
        v = dump.get((t, CTR_KEY))
        return int(v[:16], 16) if v and len(v) >= 16 else 0
    c, c1 = ctr(0), ctr(1)
    info = f'c={c} acked={acked} | {integ[10:120]}'
    if c > 10**6: return 'corrupt_ctr', info
    if c != c1: return 'atomicity', f'ctrA={c} ctrB={c1} ' + info
    if dump != EXP.get(c): return 'state_mismatch', info + ' | ' + state_diff(dump, EXP.get(c))
    if c < acked: return 'lost_ack', info
    if not integ.startswith('INTEGRITY ok'): return 'integrity_fail', info
    return 'ok', info

def state_diff(dump, exp):
    """Key-level difference of a recovered dump from the expected state (diagnostics only; the verdict is unchanged).
    A changed value is shown by the txn number its first 8 bytes encode (workload `val`)."""
    name = lambda t, k: f'{t}:{bytes.fromhex(k).decode("latin-1")}'
    txn = lambda v: int(v[:16], 16) if len(v) >= 16 else -1
    miss = sorted(name(*k) for k in exp if k not in dump); extra = sorted(name(*k) for k in dump if k not in exp)
    chg = sorted(f'{name(*k)} got={txn(dump[k])} want={txn(exp[k])}' for k in exp if k in dump and dump[k] != exp[k])
    cap = lambda l: ','.join(l[:6]) + (f',+{len(l) - 6}' if len(l) > 6 else '')
    return f'diff missing={len(miss)}[{cap(miss)}] extra={len(extra)}[{cap(extra)}] changed={len(chg)}[{cap(chg)}]'

# ------------------------------------------------------------------ trace
def parse(log):
    out = []
    for ln in open(log):
        p = ln.rstrip('\n').split(' ')
        c = p[0]
        if c == 'W': out.append(('W', p[1], int(p[2]), bytes.fromhex(p[4]) if len(p) > 4 else b''))
        elif c == 'S': out.append(('S', p[1], len(p) > 2 and p[2] == 'ds'))
        elif c in ('E', 'U', 'D', 'X'): out.append((c, p[1]))
        elif c == 'O': out.append(('O', p[1], int(p[2])))
        elif c == 'T': out.append(('T', p[1], int(p[2])))
        elif c == 'A': out.append(('A', p[1], int(p[2]), int(p[3]), int(p[4])))
        elif c == 'R': out.append(('R', p[1], p[2]))
        elif c in ('M', 'B'): out.append((c, int(p[1])))
        elif c == 'MMAPW': out.append(('MMAPW', p[1]))
        elif c == 'MSYNC': out.append(('MSYNC',))
        elif c == 'Q': out.append(('Q', ' '.join(p[1:])))
        else: out.append(('Q', 'unknown record ' + c))
    return out

def audit(trace, expect_acks):
    """Fail-closed coverage audit of the interposer and the model. Returns a list of problems."""
    probs, kinds = [], collections.Counter(o[0] for o in trace)
    for o in trace:
        if o[0] == 'Q': probs.append('unmodelled op: ' + o[1][:120])
        if o[0] == 'MMAPW' and not o[1].endswith('-shm'): probs.append('writable shared mmap (not modelled): ' + os.path.basename(o[1]))
    if expect_acks is not None:
        if kinds['M'] != expect_acks: probs.append(f'ack markers {kinds["M"]} != acked {expect_acks} (protocol replies not seen by the tracer)')
        if expect_acks and not (kinds['O'] and kinds['W'] and kinds['S']):
            probs.append(f'trace lacks O/W/S records ({dict(kinds)}): interposer not effective (raw syscalls? static binary?)')
    return probs

def eio_rule(trace):
    """fsyncgate rule: once an fsync has failed, no ack may follow (the store must fail-stop)."""
    seen = None
    for k, o in enumerate(trace, 1):
        if o[0] == 'E' and seen is None: seen = (k, o[1])
        if o[0] == 'M' and seen is not None:
            return f'ack M{o[1]} at op {k} after fsync EIO on {os.path.basename(seen[1])} at op {seen[0]}'
    return None

def apply(buf, op):
    if op[1] == 'w':
        off, d = op[2], op[3]
        if off < 0: return
        if len(buf) < off: buf.extend(b'\0' * (off - len(buf)))
        buf[off:off + len(d)] = d
    elif op[1] == 'x':
        if len(buf) < op[2]: buf.extend(b'\0' * (op[2] - len(buf)))
    else:
        n = op[2]
        if n < len(buf): del buf[n:]
        else: buf.extend(b'\0' * (n - len(buf)))

def ns_apply(ns, o):
    if o[1] == 'C': ns[o[2]] = o[3]
    elif o[1] == 'R':
        if o[2] in ns: ns[o[3]] = ns.pop(o[2])
    elif o[1] == 'U': ns.pop(o[2], None)

def page_split(q, o, rng, surv, i):
    off, d = o[2], o[3]
    if not d: return
    for pg in range(off // PAGE, (off + len(d) - 1) // PAGE + 1):
        if rng.random() < .5:
            a = max(off, pg * PAGE); b = min(off + len(d), (pg + 1) * PAGE)
            surv.append((q, i, (q, 'w', a, d[a - off:b - off])))

class Sim:
    def __init__(s, root, seed_files=None, seed_dirs=()):
        s.root = root; s.nid = 0; s.vis = {}; s.last = {}; s.dirs = {root} | set(seed_dirs); s.seq = 0; s.acked = 0
        s.dur = {}; s.pend = {}; s.durlog = {}  # durlog[ino] = [('base', bytes) | ('D', ops) | ('L', ops)] once an EIO hit ino
        s.durJ = {}; s.pendJ = []; s.durS = {}; s.pendS = []; s.durF = {}; s.pendF = []; s.allns = {}
        for p, b in (seed_files or {}).items():
            s.nid += 1; i = s.nid; s.vis[p] = i; s.last[p] = i; s.dur[i] = bytearray(b); s.pend[i] = []
            for ns in (s.durJ, s.durS, s.durF, s.allns): ns[p] = i
    def res(s, p):
        if p.endswith(' (deleted)'): return s.last.get(p[:-10])
        return s.vis.get(p) or s.last.get(p)
    def nsop(s, o):
        s.pendJ.append(o); s.pendS.append(o); s.pendF.append(o); ns_apply(s.allns, o)
    @staticmethod
    def _paths(o): return [o[2]] + ([o[3]] if o[1] == 'R' else [])
    def step(s, op):
        c = op[0]; s.seq += 1; q = s.seq
        if c == 'D': s.dirs.add(op[1])
        elif c == 'O':
            p = op[1]
            if p in s.dirs: return
            if p not in s.vis:
                s.nid += 1; i = s.nid; s.vis[p] = i; s.last[p] = i; s.dur[i] = bytearray(); s.pend[i] = []; s.nsop((q, 'C', p, i))
            elif op[2]: s.pend[s.vis[p]].append((q, 't', 0))
        elif c == 'W':
            i = s.res(op[1])
            if i: s.pend[i].append((q, 'w', op[2], op[3]))
        elif c == 'T':
            i = s.res(op[1])
            if i: s.pend[i].append((q, 't', op[2]))
        elif c == 'A':
            i = s.res(op[1])
            if i and (op[2] & 1) == 0: s.pend[i].append((q, 'x', op[3] + op[4]))
        elif c == 'S':
            p = op[1]
            if p in s.dirs:
                for attr_p, attr_d in (('pendS', s.durS), ('pendF', s.durF)):
                    keep = []
                    for o in getattr(s, attr_p):
                        if any(os.path.dirname(x) == p for x in s._paths(o)): ns_apply(attr_d, o)
                        else: keep.append(o)
                    setattr(s, attr_p, keep)
            else:
                i = s.res(p)
                if i:
                    if i in s.durlog: s.durlog[i].append(('D', s.pend[i]))
                    for o in s.pend[i]: apply(s.dur[i], o)
                    s.pend[i] = []
                    keep = []
                    for o in s.pendF:
                        if o[1] == 'C' and o[3] == i: ns_apply(s.durF, o)
                        else: keep.append(o)
                    s.pendF = keep
            for o in s.pendJ: ns_apply(s.durJ, o)
            s.pendJ = []
        elif c == 'E':
            # fsyncgate: the failed fsync's dirty pages may or may not have reached disk and are marked clean, so a
            # later successful fsync does NOT make them durable. They become limbo: per-image choice, never promoted.
            i = None if op[1] in s.dirs else s.res(op[1])
            if i and s.pend[i]:
                if i not in s.durlog: s.durlog[i] = [('base', bytes(s.dur[i]))]
                s.durlog[i].append(('L', s.pend[i])); s.pend[i] = []
        elif c == 'R':
            a, b = op[1], op[2]
            if a in s.vis: i = s.vis.pop(a); s.vis[b] = i; s.last[b] = i; s.nsop((q, 'R', a, b))
        elif c in ('U', 'X'):
            if op[1] in s.vis: s.vis.pop(op[1]); s.nsop((q, 'U', op[1]))
        elif c == 'M': s.acked = op[1]
    def _limbo_choice(s, policy, ops_, rng):
        if policy == 'all': return list(ops_)
        if policy == 'dropall': return []
        out = []
        for o in ops_:
            if o[1] == 'w' and policy == 'subset':
                tmp = []; page_split(o[0], o, rng, tmp, 0); out += [x[2] for x in tmp]
            elif rng.random() < .5: out.append(o)
        return out
    def image(s, policy, regime, rng):
        cand = sorted(((o[0], i, o) for i, l in s.pend.items() for o in l), key=lambda x: x[0])
        surv = []
        if policy == 'all': surv = cand
        elif policy == 'prefix':
            k = rng.randint(0, len(cand)); surv = cand[:k]
            if surv and surv[-1][2][1] == 'w':
                q, i, o = surv[-1]; n = len(o[3]); keep = rng.randint(0, (n + SECT - 1) // SECT) * SECT
                surv[-1] = (q, i, (o[0], 'w', o[2], o[3][:min(keep, n)]))
        elif policy == 'subset':
            for q, i, o in cand:
                if o[1] == 'w': page_split(q, o, rng, surv, i)
                elif rng.random() < .5: surv.append((q, i, o))
        if regime == 'journal':
            ns = dict(s.durJ)
            for o in s.pendJ[:rng.randint(0, len(s.pendJ))]: ns_apply(ns, o)
        elif regime == 'fsfile':
            ns = dict(s.durF)
            for o in s.pendF:
                if rng.random() < .5: ns_apply(ns, o)
        elif regime == 'full': ns = dict(s.allns)
        else:
            ns = dict(s.durS)
            for o in s.pendS:
                if rng.random() < .5: ns_apply(ns, o)
        data = {}
        for i, b in s.dur.items():
            if i in s.durlog:
                buf = bytearray()
                for kind, x in s.durlog[i]:
                    if kind == 'base': buf = bytearray(x)
                    elif kind == 'D':
                        for o in x: apply(buf, o)
                    else:
                        for o in s._limbo_choice(policy, x, rng): apply(buf, o)
                data[i] = buf
            else:
                data[i] = bytearray(b)
        for q, i, o in surv: apply(data[i], o)
        return {p: bytes(data[i]) for p, i in ns.items()}

def materialize(img, root, dst, dirs=()):
    os.makedirs(dst, exist_ok=True)
    for dd in dirs:
        if dd.startswith(root): os.makedirs(dst + dd[len(root):], exist_ok=True)
    for p, b in img.items():
        t = dst + p[len(root):]; os.makedirs(os.path.dirname(t), exist_ok=True)
        with open(t, 'wb') as f: f.write(b)

# ------------------------------------------------------------------ engine
FAILS_KEPT = 8  # failing images re-materialized (pre-recovery bytes) under .work/fails/ for diagnosis
_fails_lock = threading.Lock(); _fails = [0]

def keep_failure(src, d, c, b):
    """Re-materialize a failing image from the model (verification ran recovery on `d`, so its bytes changed)."""
    img, root, dirs = src
    with _fails_lock:
        if _fails[0] >= FAILS_KEPT: return None
        _fails[0] += 1
    dst = os.path.join(HERE, '.work', 'fails', os.path.basename(d) + '-' + c)
    shutil.rmtree(dst, ignore_errors=True); materialize(img, root, dst, dirs)
    with open(dst + '.txt', 'w') as f: f.write(f'{c}: {b}\n')
    return dst

class Pool:
    """Bounded verify pool: images are materialized just before submission and deleted after verification."""
    def __init__(s, jobs):
        s.ex = cf.ThreadPoolExecutor(jobs); s.fut = collections.deque(); s.cap = jobs * 4; s.res = []
    def submit(s, subj, d, acked, tag, src=None):
        def job():
            c, b = verify(subj, d, acked); shutil.rmtree(d, ignore_errors=True)
            if c != 'ok' and src is not None and not tag[0].endswith('~init'):
                kept = keep_failure(src, d, c, b)
                if kept: b = f'{b} [image kept: {os.path.relpath(kept, HERE)}]'
            return tag, c, b
        s.fut.append(s.ex.submit(job))
        while len(s.fut) > s.cap: s.res.append(s.fut.popleft().result())
    def drain(s):
        while s.fut: s.res.append(s.fut.popleft().result())
        r, s.res = s.res, []; return r

def replay(trace, sim, cuts, pool, subj, base, tag0, rng, policies, keep_images=None, bootstrapped=False):
    """Replay `trace`, emitting images at `cuts`. Cuts before the first BEGUN marker fall inside bootstrap (the subject
    never printed READY-and-served); their failures are tagged `init` and reported, not counted (research precedent)."""
    n = 0
    first_b = 0 if bootstrapped else next((k for k, o in enumerate(trace, 1) if o[0] == 'B'), len(trace) + 1)
    for k, op in enumerate(trace, 1):
        sim.step(op)
        if k in cuts:
            tag = tag0 + ('~init' if k < first_b else '')
            for pol, reg in policies:
                img = sim.image(pol, reg, rng); d = f'{base}/img-{tag0}-{k}-{pol}-{reg}'
                materialize(img, sim.root, d, sim.dirs); pool.submit(subj, d, sim.acked, (tag, k, pol, reg, sim.acked), (img, sim.root, set(sim.dirs))); n += 1
                if keep_images is not None and (k, pol, reg) in keep_images:
                    keep_images[(k, pol, reg)] = (img, sim.acked, set(sim.dirs))
    return n

def pick_cuts(trace, n_random, rng, start=1):
    m = len(trace)
    post_ack = {k for k, o in enumerate(trace, 1) if o[0] == 'M' and k >= start}
    pool_ = range(start, m + 1)
    rnd = set(rng.sample(pool_, min(n_random, len(pool_)))) if len(pool_) else set()
    return post_ack | rnd | {m}, len(post_ack)

def tally(results):
    t = collections.defaultdict(collections.Counter); ex = {}; warn = collections.Counter()
    for (tag, k, pol, reg, ack), c, b in results:
        if tag.endswith('~init'):
            tag = tag[:-5]
            if c != 'ok': c = 'init_' + c; warn[c] += 1
        t[f'{tag}/{pol}/{reg}'][c] += 1
        if c != 'ok' and not c.startswith('init_') and (tag, c) not in ex: ex[(tag, c)] = f'{c}: {tag} cut={k} {pol}/{reg} acked={ack}: {b}'
    return t, ex, warn

def run_subject(subj, cfg, log):
    """All stages for one subject. Returns a summary dict with 'violations' (list of str) and image counts."""
    rng = random.Random(cfg.seed); base = os.path.join(cfg.work, re.sub(r'[^A-Za-z0-9]+', '_', subj.name) + f'-s{cfg.seed}')
    shutil.rmtree(base, ignore_errors=True); os.makedirs(base)
    pool = Pool(cfg.jobs); viol = []; summ = {'subject': subj.name, 'seed': cfg.seed, 'stages': {}}
    t0 = time.time()
    # ---------------- stage MAIN
    root = os.path.realpath(base) + '/orig'; os.makedirs(root); tl = base + '/trace.log'
    r = run_trace(subj, root, tl, cfg.txns)
    if r['err'] or r['acked'] != cfg.txns:
        viol.append(f'main run failed: {r["err"]} (acked {r["acked"]}/{cfg.txns}, rc={r["rc"]})')
        summ['violations'] = viol; return summ
    trace = parse(tl); viol += audit(trace, cfg.txns)
    cuts, npost = pick_cuts(trace, cfg.cuts, rng)
    sel = {}
    post = sorted(k for k, o in enumerate(trace, 1) if o[0] == 'M')
    rot = [('dropall', 'strict'), ('prefix', 'journal'), ('subset', 'fsfile'), ('dropall', 'journal')]
    if cfg.double and post:
        step = max(1, len(post) // cfg.double)
        for j, k in enumerate(post[::step][:cfg.double]): sel[(k, *rot[j % len(rot)])] = None
    n_main = replay(trace, Sim(root), cuts, pool, subj, base, 'main', rng, cfg.policies, keep_images=sel)
    res_main = pool.drain()
    summ['stages']['main'] = {'ops': len(trace), 'cuts': len(cuts), 'post_ack_cuts': npost, 'images': n_main,
                              'fsyncs': sum(1 for o in trace if o[0] == 'S' and not o[2]),
                              'mmapw': sorted({os.path.basename(o[1]) for o in trace if o[0] == 'MMAPW'})}
    allres = list(res_main)
    # ---------------- stage EIO
    if cfg.eio:
        syncs = [k for k, o in enumerate(trace, 1) if o[0] == 'S' and not o[2]]
        begins = {o[1]: k for k, o in enumerate(trace, 1) if o[0] == 'B'}
        targets = []
        if syncs:
            mid_b = begins.get(max(1, cfg.txns // 2), 0)
            mid = next((j for j, k in enumerate(syncs, 1) if k > mid_b), len(syncs))
            first_commit = next((j for j, k in enumerate(syncs, 1) if k > begins.get(1, 0)), 1)
            targets = sorted({1, first_commit, mid, len(syncs)})[:cfg.eio]
        st = {'positions': targets, 'images': 0, 'runs': []}
        for j, at in enumerate(targets):
            eroot = os.path.realpath(base) + f'/eio{j}'; os.makedirs(eroot); el = base + f'/eio{j}.log'
            er = run_trace(subj, eroot, el, cfg.txns, extra_env={'AEGIS_EIO_AT': str(at), **cfg.eio_env})
            et = parse(el)
            epos = next((k for k, o in enumerate(et, 1) if o[0] == 'E'), None)
            st['runs'].append({'fsync_no': at, 'eio_op': epos, 'acked': er['acked'], 'failed_at': er['failed_at'], 'ready': er['ready'][:40]})
            if epos is None:
                viol.append(f'eio: fsync #{at} never reached (subject issued fewer fsyncs than in the main run)'); continue
            viol += [f'eio#{at}: ' + p for p in audit(et, None)]
            rule = eio_rule(et)
            if rule: viol.append(f'eio#{at} ack_after_eio: {rule}')
            ecuts, _ = pick_cuts(et, max(4, cfg.cuts // 8), rng, start=epos)
            st['images'] += replay(et, Sim(eroot), ecuts, pool, subj, base, f'eio{at}', rng, cfg.policies)
        allres += pool.drain(); summ['stages']['eio'] = st
    # ---------------- stage DOUBLE (crash during recovery)
    if cfg.double:
        st = {'first_images': 0, 'images': 0, 'recovery_ops': []}
        for j, ((k, pol, reg), v) in enumerate(sorted(sel.items(), key=lambda x: x[0][0])):
            if v is None: continue
            img, acked1, dirs1 = v
            droot = os.path.realpath(base) + f'/dbl{j}'
            # rebase first image under droot
            img2 = {droot + p[len(root):]: b for p, b in img.items()}
            dirs2 = {droot + d[len(root):] for d in dirs1 if d.startswith(root)}
            materialize(img2, droot, droot, dirs2)
            dl = base + f'/dbl{j}.log'
            rr = run_trace(subj, droot, dl, 0, script='DUMP\nCHECK\nQUIT\n')
            if rr['err']:
                continue  # first image does not open: already reported by stage MAIN for this cut
            dt = parse(dl); viol += [f'double#{j}: ' + p for p in audit(dt, None)]
            st['first_images'] += 1; st['recovery_ops'].append(len(dt))
            if not dt: continue
            m = len(dt)
            dcuts = set(range(1, m + 1)) if m <= cfg.double_cuts else set(rng.sample(range(1, m + 1), cfg.double_cuts)) | {m}
            sim2 = Sim(droot, seed_files=img2, seed_dirs=dirs2); sim2.acked = acked1
            st['images'] += replay(dt, sim2, dcuts, pool, subj, base, f'dbl{j}', rng, cfg.policies, bootstrapped=True)
        allres += pool.drain(); summ['stages']['double'] = st
    t, ex, warn = tally(allres)
    summ['init_warnings'] = dict(warn)
    summ['images'] = len(allres); summ['tally'] = {k: dict(v) for k, v in sorted(t.items())}
    isbad = lambda c: c != 'ok' and not c.startswith('init_')
    summ['bad'] = {k: {c: n for c, n in v.items() if isbad(c)} for k, v in summ['tally'].items() if any(isbad(c) for c in v)}
    viol += [ex[k] for k in sorted(ex)]
    summ['violations'] = viol; summ['secs'] = round(time.time() - t0, 1)
    if not cfg.keep: shutil.rmtree(base, ignore_errors=True)
    return summ

def report(summ, out=sys.stdout):
    st = summ.get('stages', {})
    parts = [f"{k}={v.get('images', 0)}" for k, v in st.items()]
    print(f"  {summ['subject']:<28} seed={summ['seed']} images={summ.get('images', 0)} ({', '.join(parts)}) "
          f"violations={len(summ['violations'])} {summ.get('secs', '')}s", file=out)
    for v in summ['violations'][:8]: print(f"      ! {v}", file=out)
    if summ.get('init_warnings'): print(f"      (bootstrap-window, not counted: {summ['init_warnings']})", file=out)
    for k, v in summ.get('bad', {}).items(): print(f"      {k}: {v}", file=out)

# ------------------------------------------------------------------ CLI
def make_cfg(a, **over):
    c = argparse.Namespace(**vars(a)); c.policies = POLICIES; c.eio_env = {}
    for k, v in over.items(): setattr(c, k, v)
    return c

def subject_from_cli(cmd):
    argv = shlex.split(cmd)
    return Subject('custom:' + os.path.basename(argv[0]), argv)

def main():
    ap = argparse.ArgumentParser(prog='oracles/crash-harness/run', description=__doc__.split('\n')[0])
    ap.add_argument('--subject', help="command speaking the subject protocol; '{dir}' is replaced by the store dir (appended if absent)")
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--full', action='store_true', help='research-size run: 300 txns, 400 random cuts (+ every post-ack cut), seeds 1-3, 20 double-fault bases')
    ap.add_argument('--txns', type=int); ap.add_argument('--cuts', type=int); ap.add_argument('--seeds', default=None)
    ap.add_argument('--eio', type=int, default=4, help='EIO positions per subject (0 disables)')
    ap.add_argument('--double', type=int, help='first-crash bases for the double-fault stage (0 disables)')
    ap.add_argument('--double-cuts', type=int, default=60)
    ap.add_argument('--jobs', type=int, default=max(1, min(8, (os.cpu_count() or 2) // 2)))
    ap.add_argument('--keep', action='store_true', help='keep the work dir (.work/)')
    a = ap.parse_args()
    a.txns = a.txns or (300 if a.full else 150); a.cuts = a.cuts or (400 if a.full else 200)
    a.double = a.double if a.double is not None else (20 if a.full else 10)
    seeds = [int(x) for x in (a.seeds or ('1,2,3' if a.full else '1')).split(',')]
    a.work = os.path.join(HERE, '.work'); os.makedirs(a.work, exist_ok=True); a.seed = seeds[0]
    if not os.path.exists(REFSTORE) and not a.subject:
        print('CRASH-HARNESS: FAIL (reference build missing; use ./run, which builds via ci/heavy.sh)'); return 1
    t0 = time.time(); results = []
    global FAILS_KEPT
    if a.self_test:
        FAILS_KEPT = 0  # mutants fail by design; keep nothing (and leave a previous run's kept images alone)
        return self_test(a, seeds)
    shutil.rmtree(os.path.join(a.work, 'fails'), ignore_errors=True)
    subjects = [subject_from_cli(a.subject)] if a.subject else [ref('sqlite', 'wal-full'), ref('redb', '2pc'), ref('wal', 'crc')]
    print(f'crash-harness: txns={a.txns} random_cuts={a.cuts} seeds={seeds} eio_positions={a.eio} double_bases={a.double} jobs={a.jobs}')
    for s in seeds:
        for subj in subjects:
            summ = run_subject(subj, make_cfg(a, seed=s), None); results.append(summ); report(summ); sys.stdout.flush()
    total = sum(r.get('images', 0) for r in results); bad = [r for r in results if r['violations']]
    json.dump({'mode': 'run', 'results': results, 'secs': round(time.time() - t0, 1)}, open(os.path.join(a.work, 'last-run.json'), 'w'), indent=1)
    by_stage = collections.Counter()
    for r in results:
        for k, v in r.get('stages', {}).items(): by_stage[k] += v.get('images', 0)
    stages = ' '.join(f'{k}={v}' for k, v in by_stage.items())
    if bad:
        print(f"CRASH-HARNESS: FAIL ({len(bad)} subject-runs violated INV-DURABLE; images={total} [{stages}]; first: {bad[0]['subject']}: {bad[0]['violations'][0][:160]})")
        return 1
    print(f'CRASH-HARNESS: PASS (images={total} [{stages}], subjects={len(subjects)}, seeds={len(seeds)}, {round(time.time() - t0)}s)')
    return 0

def self_test(a, seeds):
    """Each mutation must be caught (>= 1 violation of the expected kind)."""
    small = dict(seed=seeds[0], txns=min(a.txns, 40), cuts=min(a.cuts, 40), double=0, eio=0)
    muts = [
        ('sqlite WAL synchronous=NORMAL (dropall model)', ref('sqlite', 'wal-normal'), dict(), 'lost_ack'),
        ('ack before fsync', ref('sqlite', 'wal-full', '--ack-early'), dict(), 'lost_ack'),
        ('skip parent-dir fsync at bootstrap', ref('redb', '2pc', '--no-dirsync'), dict(), 'lost_ack'),
        ('fsync EIO treated as success', ref('wal', 'crc'), dict(eio=4, eio_env={'AEGIS_EIO_SWALLOW': '1'}), 'ack_after_eio'),
        ('extra: redb Durability::None', ref('redb', 'none'), dict(), 'lost_ack'),
        ('extra: own log without fsync', ref('wal', 'naive'), dict(), 'lost_ack'),
        # q2-007 assertion 1 (journal_mode re-check after the first write), as found by the EIO stage: EIO on fsync #1
        # makes SQLite fall back to the rollback journal silently; without the re-check the store serves and acks
        ('no journal_mode re-check after first write (EIO k=1)', ref('sqlite', 'wal-full', '--no-mode-recheck'), dict(eio=1), 'ack_after_eio|lost_ack'),
    ]
    if a.subject:
        cs = subject_from_cli(a.subject)
        muts.append(('subject: fsync EIO treated as success', cs, dict(eio=4, eio_env={'AEGIS_EIO_SWALLOW': '1'}), 'ack_after_eio'))
        probe = run_trace(cs, *_probe_dirs(a), 0, script='QUIT\n')
        advertised = re.search(r'mutations=(\S+)', probe.get('ready') or '')
        adv = advertised.group(1).split(',') if advertised else []
        if 'ack-early' in adv: muts.append(('subject: ack before fsync', Subject(cs.name + ' --ack-early', cs.argv, ['--ack-early']), dict(), 'lost_ack'))
        if 'no-dirsync' in adv: muts.append(('subject: skip parent-dir fsync', Subject(cs.name + ' --no-dirsync', cs.argv, ['--no-dirsync']), dict(), 'lost_ack'))
        if 'no-mode-recheck' in adv: muts.append(('subject: no journal_mode re-check (EIO k=1)', Subject(cs.name + ' --no-mode-recheck', cs.argv, ['--no-mode-recheck']), dict(eio=1), 'ack_after_eio|lost_ack'))
    print(f"crash-harness self-test: txns={small['txns']} random_cuts={small['cuts']} seed={small['seed']}")
    caught, missed, total = 0, [], 0
    for desc, subj, over, want in muts:
        cfg = make_cfg(a, **small); [setattr(cfg, k, v) for k, v in over.items()]
        summ = run_subject(subj, cfg, None); total += summ.get('images', 0)
        wants = want.split('|')                        # 'a|b': any of the listed violation kinds counts as caught
        hit = any(w in v for v in summ['violations'] for w in wants)
        n_want = sum(n for k, v in summ.get('bad', {}).items() for c, n in v.items() if c in wants) or sum(any(w in v for w in wants) for v in summ['violations'])
        print(f"  [{'caught' if hit else 'MISSED'}] {desc}: {want} x{n_want or ''} ({len(summ['violations'])} violations, {summ.get('images', 0)} images)")
        if hit: caught += 1
        else: missed.append(desc)
    if missed:
        print(f"CRASH-HARNESS SELF-TEST: FAIL (missed: {'; '.join(missed)})"); return 1
    print(f'CRASH-HARNESS SELF-TEST: PASS ({caught}/{len(muts)} mutations caught; images={total})'); return 0

def _probe_dirs(a):
    d = os.path.realpath(os.path.join(a.work, 'probe')); shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
    return d, d + '.log'

if __name__ == '__main__':
    sys.exit(main())
