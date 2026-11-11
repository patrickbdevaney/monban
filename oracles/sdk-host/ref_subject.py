#!/usr/bin/env python3
"""Reference subject for oracles/sdk-host (stdlib only, `python3 -I`). Speaks the README "Subject protocol".

Three layers, mirroring the Rust split so that every mutation below is a *host* mutation (or, for
detach-before-commit, a break of the SDK's committed-proof check that the frozen Rust SDK makes inexpressible):

  SDK   `scope` / `HostDb` / `run_job`: a port of sdk/monban-sdk/src/host.rs (liveness gate, one Ctx per scope,
        rollback of a transaction left open, jobs returned in Driven.jobs, detach only with a committed proof).
  APP   `app_call`: the scripted test application (an interpreter of the per-call action script).
  HOST  `Host`: what monban-adapter-host owns: sessions, streams with idle/step budgets, the bounded blocking pool,
        the job store and run_jobs. This is the code under test in host-subject.

Usage: ref_subject.py [--mutate <name>]
"""
import json, sys, threading, time

MUTATIONS = (
    'mint-once-per-session',         # host caches the open-time Ctx/grant snapshot (live + permits) for every step
    'revoked-stream-keeps-serving',  # host checks liveness only at open (permits read fresh)
    'step-retry-double-mint',        # host pulls the generator again when it answered Idle
    'job-ignores-revocation',        # host runs jobs with the liveness/permits captured when they were queued
    'drop-jobs-on-error',            # host discards Driven.jobs when Driven.result is an error
    'detach-before-commit',          # JobQueue accepts a job without a committed-transaction proof
    'no-idle-budget',                # host never closes an idle stream
    'no-step-budget',                # host never closes a stream at its step budget
    'unbounded-pool',                # pool admission never refuses (a thread per call)
    'inline-handler',                # non-hold handler calls run on the I/O loop, bypassing the pool
    'queueing-pool',                 # admission waits for a free slot (spawn_blocking-style queue) instead of refusing
)
KINDS = ('select', 'insert', 'update', 'delete', 'upsert')


class Err(Exception):
    def __init__(s, code): s.code = code


# ------------------------------------------------------------------------------------------------ host-side state
class Sess:
    def __init__(s, tenant, permits):
        s.tenant, s.permits, s.live, s.fail_commit = tenant, set(permits), True, False


class LiveView:
    """The correct `Session` the host hands the SDK: reads current state on every call."""
    def __init__(s, sess): s.sess = sess
    def live(s): return s.sess.live
    def permits(s, k): return k in s.sess.permits


class SnapView:
    """A stale `Session` (mutations only)."""
    def __init__(s, sess, live=True, permits=True):
        s.sess = sess
        s._live = sess.live if live else None
        s._perm = set(sess.permits) if permits else None
    def live(s): return s.sess.live if s._live is None else s._live
    def permits(s, k): return (k in s.sess.permits) if s._perm is None else (k in s._perm)


class Backend:
    """Instrumented backend bound to one session's tenant; emits backend events."""
    def __init__(s, sess, sink): s.sess, s.sink = sess, sink
    def begin(s): s.sink.append({'ev': 'backend', 'call': 'begin'})
    def run(s, kind, tenant): s.sink.append({'ev': 'backend', 'call': 'run', 'kind': kind, 'tenant': tenant})
    def commit(s):
        if s.sess.fail_commit:
            s.sess.fail_commit = False
            s.sink.append({'ev': 'backend', 'call': 'commit', 'ok': False}); raise Err('unavailable')
        s.sink.append({'ev': 'backend', 'call': 'commit', 'ok': True})
    def rollback(s): s.sink.append({'ev': 'backend', 'call': 'rollback'})


# ------------------------------------------------------------------------------------------------ SDK (host.rs port)
class Ctx:
    def __init__(s, tenant, view): s.tenant, s.view = tenant, view
    def grant(s, k):
        if s.view.live() and s.view.permits(k): return ('granted', k)
        raise Err('denied')


class HostDb:
    def __init__(s, backend, tenant, mut):
        s.backend, s.tenant, s.open, s.jobs, s.mut = backend, tenant, False, [], mut
    def begin(s):
        if s.open: raise Err('conflict')
        s.backend.begin(); s.open = True; return 'tx-open'
    def run(s, tx, cap, kind):
        if not s.open or tx != 'tx-open' or cap != ('granted', kind): raise Err('denied')
        s.backend.run(kind, s.tenant)          # Op::tenant overwritten with the principal's tenant
    def commit(s, tx):
        if not s.open or tx != 'tx-open': raise Err('denied')
        s.open = False
        try:
            s.backend.commit()
        except Err:
            s.backend.rollback(); raise
        return 'tx-committed'
    def detach(s, after, job):
        if after != 'tx-committed' and s.mut != 'detach-before-commit': raise Err('denied')
        s.jobs.append(job)


def scope(sess, view, sink, not_live, f, mut):
    """One minted scope. Returns (result, jobs); result = ('ok', v) | ('err', code)."""
    if not view.live(): return ('err', not_live), []
    db = HostDb(Backend(sess, sink), sess.tenant, mut)
    try:
        res = ('ok', f(Ctx(sess.tenant, view), db))
    except Err as e:
        res = ('err', e.code)
    if db.open:
        db.open = False; db.backend.rollback()
    return res, db.jobs


# ------------------------------------------------------------------------------------------------ APP (scripted)
def app_call(call, ctx, db, script, jobsdef, sink):
    """Interprets one action script with a freshly handed Ctx. Returns the terminal string or raises Err."""
    sink.append({'ev': 'minted', 'call': call, 'tenant': ctx.tenant})
    caps, tx, committed = {}, None, None
    for a in script:
        if a.startswith('grant:'):
            k = a[6:]
            try:
                caps[k] = ctx.grant(k); sink.append({'ev': 'decision', 'cap': k, 'result': 'granted'})
            except Err:
                sink.append({'ev': 'decision', 'cap': k, 'result': 'denied'})
        elif a == 'begin':
            tx = db.begin()
        elif a.startswith('run:'):
            k = a[4:]
            if k not in caps or tx != 'tx-open': raise Err('denied')
            db.run(tx, caps[k], k)
        elif a == 'commit':
            if tx != 'tx-open': raise Err('denied')
            t, tx = tx, None
            committed = db.commit(t)
        elif a.startswith('detach:'):
            j = a[7:]
            try:
                db.detach(committed, (j, list(jobsdef.get(j, ['ok']))))
                sink.append({'ev': 'detach', 'job': j, 'result': 'accepted'})
            except Err:
                sink.append({'ev': 'detach', 'job': j, 'result': 'refused'})
        elif a.startswith('err:'):
            raise Err(a[4:])
        else:
            return a
    return 'ok'


# ------------------------------------------------------------------------------------------------ HOST (under test)
class Host:
    def __init__(s, mut):
        s.mut = mut
        s.sessions, s.streams, s.jobs = {}, {}, []
        s.cap, s.active, s.lock = 1, 0, threading.Lock()
        s.holds = {}

    # --- bounded blocking pool (X-11): fixed capacity, admission-rejected when full, never queued
    def admit(s):
        while s.mut == 'queueing-pool':
            with s.lock:
                if s.active < s.cap: s.active += 1; return True
            time.sleep(0.01)
        with s.lock:
            if s.active >= s.cap and s.mut != 'unbounded-pool': return False
            s.active += 1; return True
    def leave(s):
        with s.lock: s.active -= 1
    def pooled(s, fn):
        """Run fn on a pool thread and wait for it; None if rejected."""
        if s.mut == 'inline-handler': return fn()
        if not s.admit(): return None
        box = {}
        def work():
            try: box['r'] = fn()
            finally: s.leave()
        t = threading.Thread(target=work, daemon=True); t.start(); t.join()
        return box['r']

    def keep_jobs(s, sess, view, res, jobs):
        if res[0] == 'err' and s.mut == 'drop-jobs-on-error': return
        for j in jobs:
            jview = SnapView(sess) if s.mut == 'job-ignores-revocation' else LiveView(sess)
            s.jobs.append((j, sess, jview))

    @staticmethod
    def result(sink, res):
        sink.append({'ev': 'result', res[0]: res[1]})

    def handle(s, m, out):
        op = m.get('op')
        if op == 'config':
            s.cap = int(m['pool'])
        elif op == 'session':
            s.sessions[m['session']] = Sess(m['tenant'], m['permits'])
        elif op == 'revoke':
            s.sessions[m['session']].live = False
        elif op == 'bump_epoch':
            s.sessions[m['session']].permits = set(m['permits'])
        elif op == 'fail_commit':
            s.sessions[m['session']].fail_commit = True
        elif op == 'open':
            s.open(m, out)
        elif op == 'step':
            s.step(m, out)
        elif op == 'call':
            sess = s.sessions[m['session']]; view = LiveView(sess); sink = []
            r = s.pooled(lambda: scope(sess, view, sink, 'denied',
                                       lambda c, d: app_call('call', c, d, m['script'], m.get('jobs', {}), sink), s.mut))
            if r is None: out.append({'ev': 'rejected', 'reason': 'pool_full'}); return
            res, jobs = r; s.keep_jobs(sess, view, res, jobs); out += sink; s.result(out, res)
        elif op == 'run_jobs':
            q, s.jobs = s.jobs, []
            for (name, script), sess, view in q:
                sink = []
                r = s.pooled(lambda: scope(sess, view, sink, 'denied',
                                           lambda c, d: app_call('job', c, d, script, {}, sink), s.mut))
                if r is None:
                    out.append({'ev': 'rejected', 'reason': 'pool_full'}); s.jobs.append(((name, script), sess, view))
                    continue
                res, jobs = r
                s.keep_jobs(sess, view, res, jobs)
                ran = bool(sink)        # minted => the job ran
                out += sink; s.result(out, res)
                out.append({'ev': 'job', 'job': name, 'result': 'ran' if ran else 'denied'})
        elif op == 'hold':
            s.hold(m, out)
        elif op == 'release':
            h = s.holds.pop(m['call'])
            h['go'].set(); h['t'].join()
            s.result(out, h['box']['res'][0])
        else:
            raise ValueError(f'unknown op {op!r}')

    def hold(s, m, out):
        sess = s.sessions[m['session']]; view = LiveView(sess); sink = []
        if not s.admit(): out.append({'ev': 'rejected', 'reason': 'pool_full'}); return
        started, go, box = threading.Event(), threading.Event(), {}
        def handler(c, d):
            sink.append({'ev': 'minted', 'call': 'hold', 'tenant': c.tenant}); started.set(); go.wait(); return 'ok'
        def work():
            try: box['res'] = scope(sess, view, [], 'denied', handler, s.mut)
            finally:
                started.set(); s.leave()
        t = threading.Thread(target=work, daemon=True); t.start(); started.wait()
        s.holds[m['call']] = {'go': go, 't': t, 'box': box}
        out += sink; out.append({'ev': 'held', 'call': m['call']})

    def open(s, m, out):
        name, kind = m['stream'], m['kind']
        sess = s.sessions[m['session']]; view = LiveView(sess); sink = []
        r = s.pooled(lambda: scope(sess, view, sink, 'denied',
                                   lambda c, d: app_call('open', c, d, m['script'], m.get('jobs', {}), sink), s.mut))
        if r is None: out.append({'ev': 'rejected', 'reason': 'pool_full'}); return
        res, jobs = r; s.keep_jobs(sess, view, res, jobs); out += sink; s.result(out, res)
        if res[0] != 'ok': return
        sview = view
        if s.mut == 'mint-once-per-session': sview = SnapView(sess)
        elif s.mut == 'revoked-stream-keeps-serving': sview = SnapView(sess, live=True, permits=False)
        s.streams[name] = dict(kind=kind, sess=sess, view=sview, idle_budget=int(m['idle_budget']),
                               step_budget=int(m['step_budget']), steps=0, idle=0, closed=None)

    def close(s, st, name, why, out):
        st['closed'] = why; out.append({'ev': 'closed', 'stream': name, 'reason': why})

    def step(s, m, out):
        name = m['stream']; st = s.streams.get(name)
        if st is None or st['closed']:
            out.append({'ev': 'result', 'err': 'closed'}); return
        sess, view = st['sess'], st['view']
        if st['kind'] == 'ws' and 'msg' not in m:          # idle tick: no SDK call
            st['idle'] += 1
            if st['idle'] >= st['idle_budget'] and s.mut != 'no-idle-budget': s.close(st, name, 'idle_budget', out)
            return
        call = 'msg' if st['kind'] == 'ws' else 'step'
        def pull():
            sink = []
            r = scope(sess, view, sink, 'unavailable',
                      lambda c, d: app_call(call, c, d, m['script'], m.get('jobs', {}), sink), s.mut)
            return sink, r
        def body():
            sink, (res, jobs) = pull()
            if s.mut == 'step-retry-double-mint' and res == ('ok', 'idle'):
                s.keep_jobs(sess, view, res, jobs)
                sink2, (res, jobs) = pull(); sink += sink2
            return sink, (res, jobs)
        r = s.pooled(body)
        if r is None: out.append({'ev': 'rejected', 'reason': 'pool_full'}); return
        sink, (res, jobs) = r
        s.keep_jobs(sess, view, res, jobs); out += sink; s.result(out, res)
        if not sink:                       # not live: the SDK did not call the stream (Unavailable)
            return
        st['steps'] += 1
        if res[0] == 'err': s.close(st, name, 'error', out); return
        v = res[1]
        if v in ('done', 'close'): s.close(st, name, 'done', out); return
        if v in ('idle',):
            st['idle'] += 1
            if st['idle'] >= st['idle_budget'] and s.mut != 'no-idle-budget':
                s.close(st, name, 'idle_budget', out); return
        else:
            st['idle'] = 0
        if st['steps'] >= st['step_budget'] and s.mut != 'no-step-budget':
            s.close(st, name, 'step_budget', out)


def main():
    mut = None
    a = sys.argv[1:]
    if a[:1] == ['--mutate'] and len(a) >= 2:
        mut = a[1]
        if mut not in MUTATIONS:
            print(json.dumps({'ready': False, 'error': f'unknown mutation {mut}'}), flush=True); return 2
    h = Host(mut)
    w = sys.stdout
    w.write(json.dumps({'ready': True, 'mutations': list(MUTATIONS)}) + '\n'); w.flush()
    for ln in sys.stdin:
        ln = ln.strip()
        if not ln: continue
        try:
            m = json.loads(ln)
        except ValueError:
            w.write(json.dumps({'ev': 'end', 'seq': None, 'error': 'bad json'}) + '\n'); w.flush(); continue
        if m.get('op') == 'quit': break
        out = []
        try:
            h.handle(m, out)
        except Exception as e:                      # protocol error: reported, the oracle counts it as PROTO
            out.append({'ev': 'error', 'msg': f'{type(e).__name__}: {e}'})
        for e in out: w.write(json.dumps(e, separators=(',', ':')) + '\n')
        w.write(json.dumps({'ev': 'end', 'seq': m.get('seq')}, separators=(',', ':')) + '\n'); w.flush()
    return 0


if __name__ == '__main__':
    sys.exit(main())
