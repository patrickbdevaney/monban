#!/usr/bin/env python3
"""Monban sdk-host oracle: the F7b streaming host obligations left to monban-adapter-host (spikes/APPLIED.md q4-001,
sdk/monban-sdk/src/host.rs module doc, DEVIATIONS X-11). Run as `python3 -I sdk_host.py`, normally via ./run.

The oracle drives a host subject over the JSON-lines protocol in README.md ("Subject protocol"), one process per
seed, keeps its own model of sessions, streams, budgets, the pool and the job store, and compares every op's event
list with the model's prediction exactly. A seed stops at its first divergence (the model can no longer predict the
subject); the divergence is classified into the clause it breaks.
"""
import argparse, collections, json, os, random, select, shlex, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
REF = f"python3 -I -B {shlex.quote(os.path.join(HERE, 'ref_subject.py'))}"
KINDS = ('select', 'insert', 'update', 'delete', 'upsert')
POOL = 2
TIMEOUT = 20.0
POOL_TIMEOUT = 5.0          # a hold/step while the pool is full must be answered promptly (rejected, never queued)

# mutation -> clause that must go red (reference subject implements all; a --subject must implement REQUIRED)
MUTATIONS = {
    'mint-once-per-session':        'GRANT-FRESH',
    'revoked-stream-keeps-serving': 'REVOKE',
    'step-retry-double-mint':       'MINT',
    'job-ignores-revocation':       'JOB-REVOKE',
    'drop-jobs-on-error':           'JOB-KEEP',
    'detach-before-commit':         'DETACH-COMMIT',
    'no-idle-budget':               'IDLE-BUDGET',
    'no-step-budget':               'STEP-BUDGET',
    'unbounded-pool':               'POOL',
    'inline-handler':               'POOL',
    'queueing-pool':                'POOL',
}
# every mutation a host can express; detach-before-commit is optional (the frozen SDK makes it inexpressible in Rust)
REQUIRED_SUBJECT_MUTATIONS = tuple(m for m in MUTATIONS if m != 'detach-before-commit')


class ProtoError(Exception): pass


class Diverged(Exception): pass


class Proc:
    def __init__(s, argv):
        s.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        s.buf = b''
    def line(s, timeout=TIMEOUT):
        t_end = time.time() + timeout
        while b'\n' not in s.buf:
            left = t_end - time.time()
            if left <= 0: raise TimeoutError
            r, _, _ = select.select([s.p.stdout], [], [], left)
            if not r: continue
            chunk = os.read(s.p.stdout.fileno(), 65536)
            if not chunk: raise ProtoError(f'subject closed stdout (exit {s.p.poll()}) {s.err_tail()}')
            s.buf += chunk
        ln, s.buf = s.buf.split(b'\n', 1)
        return ln.decode('utf-8', 'replace').strip()
    def send(s, obj):
        try:
            s.p.stdin.write((json.dumps(obj, separators=(',', ':')) + '\n').encode()); s.p.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise ProtoError(f'subject pipe closed: {e}')
    def err_tail(s):
        try:
            r, _, _ = select.select([s.p.stderr], [], [], 0)
            if r: return os.read(s.p.stderr.fileno(), 65536).decode('utf-8', 'replace').strip().splitlines()[-1:]
        except Exception:
            pass
        return ''
    def close(s):
        try:
            s.send({'op': 'quit'}); s.p.stdin.close(); s.p.wait(3)
        except Exception:
            pass
        if s.p.poll() is None:
            s.p.kill(); s.p.wait()
        for f in (s.p.stdout, s.p.stderr):
            try: f.close()
            except Exception: pass


# ------------------------------------------------------------------------------------------------ model
class MSess:
    def __init__(s, tenant, permits): s.tenant, s.permits, s.live, s.fail_commit = tenant, set(permits), True, False


def interp(call, sess, script, jobsdef):
    """Expected events of one app callback with a freshly minted Ctx on a live session (README "App semantics").
    Returns (events, result, accepted_jobs)."""
    ev = [{'ev': 'minted', 'call': call, 'tenant': sess.tenant}]
    caps, open_, committed, acc, res = set(), False, False, [], None
    for a in script:
        if a.startswith('grant:'):
            k = a[6:]; ok = sess.live and k in sess.permits
            ev.append({'ev': 'decision', 'cap': k, 'result': 'granted' if ok else 'denied'})
            if ok: caps.add(k)
        elif a == 'begin':
            if open_: res = ('err', 'conflict'); break
            ev.append({'ev': 'backend', 'call': 'begin'}); open_ = True
        elif a.startswith('run:'):
            k = a[4:]
            if k not in caps or not open_: res = ('err', 'denied'); break
            ev.append({'ev': 'backend', 'call': 'run', 'kind': k, 'tenant': sess.tenant})
        elif a == 'commit':
            if not open_: res = ('err', 'denied'); break
            open_ = False
            if sess.fail_commit:
                sess.fail_commit = False
                ev += [{'ev': 'backend', 'call': 'commit', 'ok': False}, {'ev': 'backend', 'call': 'rollback'}]
                res = ('err', 'unavailable'); break
            ev.append({'ev': 'backend', 'call': 'commit', 'ok': True}); committed = True
        elif a.startswith('detach:'):
            j = a[7:]
            if committed:
                acc.append((j, list(jobsdef.get(j, ['ok']))))
                ev.append({'ev': 'detach', 'job': j, 'result': 'accepted'})
            else:
                ev.append({'ev': 'detach', 'job': j, 'result': 'refused'})
        elif a.startswith('err:'):
            res = ('err', a[4:]); break
        else:
            res = ('ok', a); break
    if res is None: res = ('ok', 'ok')
    if open_: ev.append({'ev': 'backend', 'call': 'rollback'})
    ev.append({'ev': 'result', res[0]: res[1]})
    return ev, res, acc


def segs(evs, key):
    """Split a run_jobs reply into per-job segments, each ending with its {'ev':'job'} terminator."""
    out, cur = [], []
    for e in evs:
        cur.append(e)
        if e.get('ev') == key: out.append(cur); cur = []
    return out, cur


class Seed:
    def __init__(s, cmd, seed, mutate=None, tail=60):
        s.argv = shlex.split(cmd) + (['--mutate', mutate] if mutate else [])
        s.seed, s.tail = seed, tail
        s.rng = random.Random(seed)
        s.stats = collections.Counter()
        s.V = None
        s.seq = 0
        s.sess, s.streams, s.jobs, s.holds = {}, {}, [], set()
        s.refused = set()          # job names whose detach was refused or whose scope's commit failed
        s.nj = s.ns = s.nst = s.nh = 0
        s.proc = None; s.mutations = []

    # ------------------------------------------------------------------ plumbing
    def fail(s, clause, msg):
        s.V = (clause, f'seed={s.seed}: {msg}'); raise Diverged

    def exchange(s, msg, timeout=TIMEOUT):
        s.seq += 1; msg = dict(msg, seq=s.seq)
        s.proc.send(msg); evs = []
        while True:
            try:
                ln = s.proc.line(timeout)
            except TimeoutError:
                return msg, None
            try:
                e = json.loads(ln)
            except ValueError:
                s.fail('PROTO', f'non-JSON line {ln[:120]!r} for {msg["op"]}')
            if not isinstance(e, dict): s.fail('PROTO', f'non-object line {ln[:120]!r}')
            if e.get('ev') == 'end':
                if e.get('seq') != s.seq: s.fail('PROTO', f'end seq {e.get("seq")} != {s.seq}')
                return msg, evs
            if e.get('ev') == 'error': s.fail('PROTO', f'subject error on {msg["op"]}: {e.get("msg")}')
            evs.append(e)

    def pool_full(s): return len(s.holds) >= POOL

    def expect(s, msg, exp, ctx_clause=None, allow_revoke_close=None, timeout=TIMEOUT):
        msg, got = s.exchange(msg, timeout)
        if got is None:
            if ctx_clause == 'POOL' or s.pool_full() or msg['op'] == 'hold':
                s.fail('POOL', f'{msg["op"]} {msg.get("stream") or msg.get("call") or ""} not answered within {timeout}s '
                               f'with {len(s.holds)}/{POOL} pool slots held: queued instead of rejected')
            s.fail('PROTO', f'{msg["op"]} timed out')
        if got == exp: return got
        if allow_revoke_close and got == exp + [{'ev': 'closed', 'stream': allow_revoke_close, 'reason': 'revoked'}]:
            s.streams[allow_revoke_close]['closed'] = 'revoked'; return got
        s.fail(s.classify(msg, exp, got, ctx_clause), f'{s.describe(msg)}: expected {s.short(exp)} got {s.short(got)}')

    @staticmethod
    def short(evs):
        def one(e):
            d = dict(e); ev = d.pop('ev', '?'); d.pop('tenant', None)
            return ev + ('(' + ','.join(f'{v}' for v in d.values()) + ')' if d else '')
        t = ' '.join(one(e) for e in evs)
        return '[' + (t if len(t) < 260 else t[:257] + '...') + ']'

    @staticmethod
    def describe(m):
        keys = [k for k in ('stream', 'call', 'session', 'kind') if k in m]
        return f"op {m['op']}#{m['seq']} " + ' '.join(f'{k}={m[k]}' for k in keys) + \
            (f" script={m['script']}" if 'script' in m else '') + (' msg' if 'msg' in m else '')

    def classify(s, m, exp, got, hint):
        def n(evs, key, **kw): return [e for e in evs if e.get('ev') == key and all(e.get(a) == b for a, b in kw.items())]
        if bool(n(exp, 'rejected')) != bool(n(got, 'rejected')) or n(exp, 'held') != n(got, 'held'): return 'POOL'
        if m['op'] == 'run_jobs':
            ej, eg = segs(exp, 'job')[0], segs(got, 'job')[0]
            want = [(x[-1]['job'], x[-1]['result']) for x in ej]
            have = [(x[-1].get('job'), x[-1].get('result')) for x in eg]
            for j, r in have:
                if (j, r) in want: continue
                if j in s.refused: return 'DETACH-COMMIT'
                if r == 'ran' and (j, 'denied') in want: return 'JOB-REVOKE'
            if len(have) < len(want) or [j for j, _ in have] != [j for j, _ in want]:
                return 'JOB-KEEP'
            for x, y in zip(ej, eg):
                if x != y: return s.classify({'op': 'job'}, x, y, hint)
            return 'PROTO'
        sess = s.sess.get(m.get('session')) or (s.streams.get(m.get('stream'), {}).get('sess'))
        if sess is not None and not sess.live and (n(got, 'minted') or any(e.get('ok') for e in n(got, 'result'))):
            return 'JOB-REVOKE' if m['op'] == 'job' else 'REVOKE'
        if len(n(exp, 'minted')) != len(n(got, 'minted')): return 'MINT'
        if n(exp, 'decision') != n(got, 'decision'): return 'GRANT-FRESH'
        if n(exp, 'detach') != n(got, 'detach'): return 'DETACH-COMMIT'
        ce, cg = n(exp, 'closed'), n(got, 'closed')
        if ce != cg:
            rs = {e.get('reason') for e in ce + cg}
            if 'idle_budget' in rs: return 'IDLE-BUDGET'
            if 'step_budget' in rs: return 'STEP-BUDGET'
        if [e.get('tenant') for e in n(got, 'minted') + n(got, 'backend')] != \
           [e.get('tenant') for e in n(exp, 'minted') + n(exp, 'backend')]: return 'TENANT'
        return hint or 'PROTO'

    # ------------------------------------------------------------------ ops (each sends one op and checks it)
    def config(s):
        s.expect({'op': 'config', 'pool': POOL}, [])

    def new_session(s, permits=None, name=None):
        s.ns += 1; name = name or f'S{s.ns}'
        tenant = '%016x' % s.rng.randrange(1, 1 << 64)
        permits = list(permits) if permits is not None else s.rng.sample(KINDS, s.rng.randint(1, 4))
        s.expect({'op': 'session', 'session': name, 'tenant': tenant, 'permits': permits}, [])
        s.sess[name] = MSess(tenant, permits); return name

    def revoke(s, name):
        s.expect({'op': 'revoke', 'session': name}, [])
        s.sess[name].live = False; s.stats['revokes'] += 1

    def bump(s, name, permits):
        s.expect({'op': 'bump_epoch', 'session': name, 'permits': list(permits)}, [])
        s.sess[name].permits = set(permits); s.stats['epoch_bumps'] += 1

    def fail_commit(s, name):
        s.expect({'op': 'fail_commit', 'session': name}, [])
        s.sess[name].fail_commit = True

    def queue(s, sname, acc, script):
        for j in acc: s.jobs.append((j, sname))
        for a in script:   # names detached but not accepted (refused, or never reached after a failed commit)
            if a.startswith('detach:') and a[7:] not in [x for x, _ in acc]: s.refused.add(a[7:])

    def jobs_for(s, script):
        return {a[7:]: s.job_script() for a in script if a.startswith('detach:')}

    def open(s, kind, sname, script, idle_budget, step_budget, jobs=None):
        s.nst += 1; name = f'{kind}{s.nst}'; sess = s.sess[sname]
        jobs = jobs if jobs is not None else s.jobs_for(script)
        msg = {'op': 'open', 'stream': name, 'kind': kind, 'session': sname, 'idle_budget': idle_budget,
               'step_budget': step_budget, 'script': script, 'jobs': jobs}
        if s.pool_full():
            s.expect(msg, [{'ev': 'rejected', 'reason': 'pool_full'}], 'POOL', timeout=POOL_TIMEOUT)
            s.stats['rejected'] += 1; return name
        if not sess.live:
            s.expect(msg, [{'ev': 'result', 'err': 'denied'}], 'REVOKE'); s.stats['denied_open'] += 1; return name
        ev, res, acc = interp('open', sess, script, jobs)
        s.expect(msg, ev); s.queue(sname, acc, script); s.stats['mints'] += 1
        if res[0] == 'ok':
            s.streams[name] = dict(kind=kind, sess=sess, idle_budget=idle_budget, step_budget=step_budget,
                                   steps=0, idle=0, closed=None)
            s.stats['opened:' + kind] += 1
        return name

    def step(s, name, script=None, msg_text=None, tick=False):
        st = s.streams.get(name)
        m = {'op': 'step', 'stream': name}
        ws = st is not None and st['kind'] == 'ws'
        if not tick:
            if script is None: script = s.step_script('ws' if ws else 'gen')
            m['script'] = script; m['jobs'] = s.jobs_for(script)
            if ws: m['msg'] = msg_text or 'm%d' % s.rng.randrange(1000)
        if st is None or st['closed']:
            s.expect(m, [{'ev': 'result', 'err': 'closed'}]); s.stats['closed_steps'] += 1; return
        if ws and tick:
            st['idle'] += 1; exp = []
            if st['idle'] >= st['idle_budget']:
                st['closed'] = 'idle_budget'; exp = [{'ev': 'closed', 'stream': name, 'reason': 'idle_budget'}]
                s.stats['closed:idle_budget'] += 1
            s.expect(m, exp, 'IDLE-BUDGET'); s.stats['ticks'] += 1; return
        sess = st['sess']
        if s.pool_full():
            s.expect(m, [{'ev': 'rejected', 'reason': 'pool_full'}], 'POOL', timeout=POOL_TIMEOUT)
            s.stats['rejected'] += 1; return
        if not sess.live:
            s.expect(m, [{'ev': 'result', 'err': 'unavailable'}], 'REVOKE', allow_revoke_close=name)
            s.stats['unavailable_steps'] += 1; return
        ev, res, acc = interp('msg' if ws else 'step', sess, script, m['jobs'])
        st['steps'] += 1; hint = None
        if res[0] == 'err':
            st['closed'] = 'error'
        elif res[1] in ('done', 'close'):
            st['closed'] = 'done'
        elif res[1] == 'idle':
            st['idle'] += 1
            if st['idle'] >= st['idle_budget']: st['closed'] = 'idle_budget'; hint = 'IDLE-BUDGET'
        else:
            st['idle'] = 0
        if not st['closed'] and st['steps'] >= st['step_budget']: st['closed'] = 'step_budget'; hint = 'STEP-BUDGET'
        if st['closed']:
            ev.append({'ev': 'closed', 'stream': name, 'reason': st['closed']}); s.stats['closed:' + st['closed']] += 1
        s.expect(m, ev, hint); s.queue(sess_name(s, sess), acc, script)
        s.stats['mints'] += 1; s.stats['steps:' + ('msg' if ws else 'gen') + ':' + str(res[1])] += 1

    def call(s, sname, script, jobs=None):
        s.nh += 1; jobs = jobs if jobs is not None else s.jobs_for(script)
        m = {'op': 'call', 'call': f'c{s.nh}', 'session': sname, 'script': script, 'jobs': jobs}
        sess = s.sess[sname]
        if s.pool_full():
            s.expect(m, [{'ev': 'rejected', 'reason': 'pool_full'}], 'POOL', timeout=POOL_TIMEOUT)
            s.stats['rejected'] += 1; return
        if not sess.live:
            s.expect(m, [{'ev': 'result', 'err': 'denied'}], 'REVOKE'); return
        ev, res, acc = interp('call', sess, script, jobs)
        s.expect(m, ev); s.queue(sname, acc, script); s.stats['mints'] += 1
        if res[0] == 'err' and acc: s.stats['jobs_from_errored_scope'] += len(acc)

    def run_jobs(s):
        assert not s.pool_full()
        q, s.jobs = s.jobs, []; exp = []
        for (j, script), sname in q:
            sess = s.sess[sname]
            if sess.live:
                ev, res, acc = interp('job', sess, script, {})
                exp += ev + [{'ev': 'job', 'job': j, 'result': 'ran'}]; s.stats['jobs_ran'] += 1; s.stats['mints'] += 1
            else:
                exp += [{'ev': 'result', 'err': 'denied'}, {'ev': 'job', 'job': j, 'result': 'denied'}]
                s.stats['jobs_denied'] += 1
        s.expect({'op': 'run_jobs'}, exp, 'JOB-KEEP')

    def hold(s, sname):
        s.nh += 1; c = f'h{s.nh}'; sess = s.sess[sname]
        m = {'op': 'hold', 'call': c, 'session': sname}
        if s.pool_full():
            s.expect(m, [{'ev': 'rejected', 'reason': 'pool_full'}], 'POOL', timeout=POOL_TIMEOUT)
            s.stats['rejected'] += 1; return None
        s.expect(m, [{'ev': 'minted', 'call': 'hold', 'tenant': sess.tenant}, {'ev': 'held', 'call': c}], 'POOL',
                 timeout=POOL_TIMEOUT)
        s.holds.add(c); s.stats['holds'] += 1; s.stats['mints'] += 1; return c

    def release(s, c):
        s.expect({'op': 'release', 'call': c}, [{'ev': 'result', 'ok': 'ok'}], 'POOL'); s.holds.discard(c)

    # ------------------------------------------------------------------ random scripts
    def job_name(s):
        s.nj += 1; return f'J{s.nj}'

    def job_script(s):
        r = s.rng; k = r.choice(KINDS)
        sc = [f'grant:{k}', 'begin', f'run:{k}']
        if r.random() < .8: sc.append('commit')
        if r.random() < .1: sc.append('err:' + r.choice(('denied', 'conflict', 'unavailable')))
        return sc + ['ok']

    def body_script(s, allow_detach=True):
        r = s.rng; sc = []; granted = []
        for k in r.sample(KINDS, r.randint(0, 2)):
            sc.append(f'grant:{k}'); granted.append(k)
        if r.random() < .6:
            sc.append('begin')
            for _ in range(r.randint(0, 2)):
                sc.append('run:' + (r.choice(granted) if granted and r.random() < .85 else r.choice(KINDS)))
            if r.random() < .05: sc.append('begin')
            if r.random() < .8: sc.append('commit')
        if allow_detach and r.random() < .35:
            sc.insert(r.randint(0, len(sc)), 'detach:' + s.job_name())
            if r.random() < .3: sc.append('detach:' + s.job_name())
        if r.random() < .08: sc.append('err:' + r.choice(('denied', 'conflict', 'unavailable')))
        return sc

    def step_script(s, kind):
        r = s.rng; sc = s.body_script()
        if kind == 'ws': return sc + [r.choices(('send', 'close'), (9, 1))[0]]
        return sc + [r.choices(('item', 'idle', 'done'), (5, 4, 1))[0]]

    # ------------------------------------------------------------------ scenario
    def prelude(s):
        s.config()
        A = s.new_session(['select', 'insert'], 'A'); B = s.new_session(['select'], 'B')
        ins = ['grant:insert', 'begin', 'run:insert', 'commit']
        jobw = lambda k='insert': [f'grant:{k}', 'begin', f'run:{k}', 'commit', 'ok']
        # jobs: queued only after commit; kept when the handler errors after commit; refused before commit
        s.call(A, ins + ['detach:J1', 'ok'], {'J1': jobw()})
        s.call(A, ins + ['detach:J2', 'err:conflict'], {'J2': jobw()})
        s.call(A, ['grant:insert', 'begin', 'run:insert', 'detach:J3', 'commit', 'ok'], {'J3': jobw()})
        s.fail_commit(A)
        s.call(A, ins + ['detach:J4', 'ok'], {'J4': jobw()})
        s.run_jobs()
        # per-step minting with fresh grants; idle budget (3)
        s1 = s.open('sse', A, ['grant:select', 'ok'], 3, 20, {})
        s.step(s1, ['grant:select', 'item'])
        s.step(s1, ['idle']); s.step(s1, ['idle'])
        s.step(s1, ['grant:select', 'begin', 'run:select', 'commit', 'item'])
        s.bump(A, ['select'])
        s.step(s1, ['grant:insert', 'grant:select', 'item'])      # insert dropped by the epoch bump -> denied
        s.step(s1, ['idle']); s.step(s1, ['idle']); s.step(s1, ['idle'])   # 3rd consecutive Idle closes
        s.step(s1, ['item'])                                       # closed: no mint
        # step budget (3)
        b1 = s.open('body', A, ['ok'], 5, 3, {})
        for _ in range(4): s.step(b1, ['grant:select', 'item'])
        # WebSocket: messages mint, ticks do not; idle budget (2)
        w1 = s.open('ws', A, ['grant:select', 'ok'], 2, 10, {})
        s.step(w1, ['grant:select', 'send'], 'hello'); s.step(w1, tick=True)
        s.step(w1, ['send'], 'again'); s.step(w1, tick=True); s.step(w1, tick=True)
        s.step(w1, ['send'], 'late')
        # bounded blocking pool (2): third hold and every handler call while full are rejected, never queued
        s2 = s.open('sse', A, ['ok'], 4, 20, {})
        h1 = s.hold(A); h2 = s.hold(A)
        s.hold(A)
        s.step(s2, ['grant:select', 'item'])
        s.call(A, ['ok'], {})
        s.release(h1)
        s.step(s2, ['grant:select', 'item'])
        s.release(h2)
        # revocation mid-stream: Unavailable, no mint; open denied; queued job of the revoked session denied
        s3 = s.open('sse', B, ['grant:select', 'ok'], 4, 20, {})
        w2 = s.open('ws', B, ['ok'], 4, 20, {})
        s.step(s3, ['grant:select', 'item'])
        s.call(B, ['grant:select', 'begin', 'run:select', 'commit', 'detach:J5', 'ok'], {'J5': jobw('select')})
        s.call(A, ['grant:select', 'begin', 'run:select', 'commit', 'detach:J6', 'ok'], {'J6': jobw('select')})
        s.revoke(B)
        s.step(s3, ['grant:select', 'begin', 'run:select', 'commit', 'item'])
        s.step(w2, ['grant:select', 'send'], 'after-revoke')
        s.open('body', B, ['ok'], 4, 20, {})
        s.run_jobs()
        s.nj = 100

    def random_tail(s):
        r = s.rng
        for _ in range(s.tail):
            live = [n for n, x in s.sess.items() if x.live]
            if len(live) < 2: s.new_session(); continue
            x = r.random(); allsess = list(s.sess)
            open_streams = [n for n, st in s.streams.items() if not st['closed']]
            if x < .05:
                s.new_session()
            elif x < .08:
                s.revoke(r.choice(live))
            elif x < .14:
                s.bump(r.choice(live), r.sample(KINDS, r.randint(0, 4)))
            elif x < .18:
                s.fail_commit(r.choice(live))
            elif x < .30:
                kind = r.choice(('sse', 'body', 'ws'))
                sn = r.choice(allsess) if r.random() < .2 else r.choice(live)
                s.open(kind, sn, s.body_script() + ['ok'], r.randint(1, 4), r.randint(2, 8))
            elif x < .66 and (open_streams or s.streams):
                name = r.choice(open_streams) if open_streams and r.random() < .9 else r.choice(list(s.streams))
                st = s.streams[name]
                s.step(name, tick=(st['kind'] == 'ws' and r.random() < .35))
            elif x < .78:
                s.call(r.choice(live) if r.random() < .9 else r.choice(allsess), s.body_script() + ['ok'])
            elif x < .86 and not s.pool_full():
                s.run_jobs()
            elif x < .94:
                if s.holds and r.random() < .5: s.release(r.choice(sorted(s.holds)))
                else: s.hold(r.choice(live))
            else:
                if s.holds: s.release(r.choice(sorted(s.holds)))
                else: s.new_session()

    def finish(s):
        for c in sorted(s.holds): s.release(c)
        s.run_jobs()

    def go(s):
        try:
            s.proc = Proc(s.argv)
            try:
                rd = json.loads(s.proc.line())
            except (ValueError, TimeoutError):
                raise ProtoError('no READY line')
            if not isinstance(rd, dict) or rd.get('ready') is not True: raise ProtoError(f'not ready: {rd}')
            s.mutations = list(rd.get('mutations') or [])
            s.prelude(); s.random_tail(); s.finish()
        except Diverged:
            pass
        except ProtoError as e:
            s.V = ('PROTO', f'seed={s.seed}: {e}')
        finally:
            if s.proc: s.proc.close()
        return s.V


def sess_name(s, sess):
    for n, x in s.sess.items():
        if x is sess: return n
    return None


def sweep(cmd, seeds, mutate=None, tail=60, stop_on=None):
    stats = collections.Counter(); viol = collections.Counter(); first = {}; ex = {}; muts = []
    for seed in seeds:
        r = Seed(cmd, seed, mutate, tail); v = r.go(); stats.update(r.stats); stats['seeds'] += 1; muts = r.mutations
        if v:
            c, m = v; viol[c] += 1
            if c not in first: first[c] = seed; ex[c] = m
            if stop_on and c in stop_on: break
    return stats, viol, first, ex, muts


VACUITY = ('mints', 'revokes', 'epoch_bumps', 'jobs_ran', 'jobs_denied', 'jobs_from_errored_scope', 'holds', 'rejected',
           'unavailable_steps', 'denied_open', 'closed:idle_budget', 'closed:step_budget', 'ticks', 'closed_steps')


def main():
    ap = argparse.ArgumentParser(prog='oracles/sdk-host/run')
    ap.add_argument('--subject', help='command speaking the subject protocol (README); --mutate <m> is appended for mutants')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--seeds', type=int, default=200, help='seeds 1..N (default 200)')
    ap.add_argument('--tail', type=int, default=60, help='random ops per seed after the scripted prelude')
    ap.add_argument('--mutate', help='run the reference (or subject) with this mutation, for diagnosis')
    a = ap.parse_args()
    if a.self_test: return self_test(a)
    cmd = a.subject or REF; t0 = time.time()
    stats, viol, first, ex, _ = sweep(cmd, range(1, a.seeds + 1), a.mutate, a.tail)
    label = ('reference' if not a.subject else a.subject) + (f' +{a.mutate}' if a.mutate else '')
    print(f"sdk-host: subject={label} seeds={stats['seeds']} {time.time() - t0:.1f}s")
    print('  ' + ' '.join(f'{k}={stats[k]}' for k in VACUITY))
    print('  steps: ' + ' '.join(f'{k[6:]}={v}' for k, v in sorted(stats.items()) if k.startswith('steps:')))
    for c in sorted(first): print(f'  {c}: {viol[c]} seed(s) red; first {ex[c][:300]}')
    vac = [k for k in VACUITY if not stats[k]] if not viol else []
    if viol:
        print('SDK-HOST: FAIL (' + ', '.join(f'{c}={viol[c]}' for c in sorted(viol)) + ')'); return 1
    if vac:
        print(f'SDK-HOST: FAIL (vacuous: no {", ".join(vac)})'); return 1
    print(f"SDK-HOST: PASS (MINT GRANT-FRESH REVOKE JOB-REVOKE JOB-KEEP DETACH-COMMIT IDLE-BUDGET STEP-BUDGET POOL over "
          f"{stats['seeds']} seeds, {stats['mints']} mints, {stats['jobs_ran']}+{stats['jobs_denied']} jobs ran/denied)")
    return 0


def self_test(a):
    print('sdk-host self-test (reference subject' + (', and --subject' if a.subject else '') + ')')
    missed, n = [], 0
    stats, viol, first, ex, _ = sweep(REF, range(1, 6), None, a.tail)
    if viol:
        print(f'  [BROKEN] unmutated reference fails: {ex[min(first, key=first.get)][:240]}')
        print('SDK-HOST SELF-TEST: FAIL (unmutated reference subject is red)'); return 1
    print(f"  [clean] reference: 5 seeds, {stats['mints']} mints, 0 violations")
    plan = [('reference', REF, list(MUTATIONS))]
    if a.subject:
        stats, viol, first, ex, adv = sweep(a.subject, range(1, 6), None, a.tail)
        if viol:
            print(f'  [RED] unmutated subject fails: {ex[min(first, key=first.get)][:240]}')
            missed.append('subject:clean')
        else:
            print(f"  [clean] subject: 5 seeds, {stats['mints']} mints, 0 violations")
        want = list(REQUIRED_SUBJECT_MUTATIONS) + [m for m in adv if m in MUTATIONS and m not in REQUIRED_SUBJECT_MUTATIONS]
        plan.append(('subject', a.subject, want))
    for label, cmd, muts in plan:
        for mut in muts:
            n += 1; clause = MUTATIONS[mut]
            _, viol, first, ex, _ = sweep(cmd, range(1, 11), mut, a.tail, stop_on=(clause,))
            if clause in first:
                print(f'  [caught] {label}:{mut}: {clause} red at seed {first[clause]}; {ex[clause][:200]}')
            else:
                print(f'  [MISSED] {label}:{mut}: {clause} not red within 10 seeds (other: {sorted(first)})')
                missed.append(f'{label}:{mut}')
    if missed:
        print(f"SDK-HOST SELF-TEST: FAIL (missed: {', '.join(missed)})"); return 1
    print(f"SDK-HOST SELF-TEST: PASS ({n}/{n} mutations caught, each red on its own clause within 10 seeds)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
