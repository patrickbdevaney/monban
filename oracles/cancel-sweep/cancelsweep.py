#!/usr/bin/env python3
"""Monban cancel sweep (oracle for INV-NOMUT-C NC1/NC2/NC3/NC5, plus NC4 and CRS C5). Run as `python3 -I`, via ./run.

Specified, never executed, in research round-003/06 (node ac.l5-cancel-sweep-harness): cancellation can only happen at
await points, so for each seed the oracle runs the request uncancelled to count its await points K, then re-runs it
with CancelAt<N> for every N in 0..K-1 and every mode, and checks invariants on the resulting event stream.

The checkers consume ONLY events (see README "Subject event protocol"). The event producer is either the in-process
reference model below (a host with a size-1 DB pool, a pgwire-level DB fake, an upstream pool, authz stages, a
limiter and an idempotency row) or an external `--subject <cmd>` speaking the same protocol. The reference model is
also runnable as a subject (`--as-subject`), which exercises the protocol path end to end.
"""
import argparse, collections, json, os, random, shlex, subprocess, sys, time

MODES = ['drop', 'rst', 'timeout', 'stage_timeout', 'crash']   # m1, m3, m5, stage-level timeout, m8
MUTATIONS = {
    'always-reusable':     'pool checkin predicate returns "reusable" for every connection (plan self-test)',
    'pool-key-no-epoch':   'upstream pool key omits the config/auth epoch (plan self-test, CRS C5)',
    'checkin-ignores-txn': 'checkin checks ReadyForQuery + outstanding replies but not txn status (sqlx #4393 shape)',
    'checkin-ignores-objects': 'checkin ignores server objects created by the request (tokio-postgres #1374 shape)',
    'no-cp-latch':         'commit runs inside the cancellable handler future: a cancel after COMMIT-sent is treated as failure',
    'authz-fail-open':     'a timed-out authz stage is skipped (Error => Allow) instead of Error => Deny',
    'debit-after-work':    'budget debited after the work (post-hoc) instead of before',
    # NC3 recovery (spike q3-008)
    'reuse-after-cancelrequest': 'recovery sends a CancelRequest to speed up the drain and then checks the connection back in; the cancel is not statement-bound and lands on the next request',
    'recovery-no-discard-all':   'recovery drains and rolls back but skips DISCARD ALL (session state and server objects survive)',
    'quarantine-not-charged':    'quarantine time and the discard are not charged to the cancelling principal (NC4)',
    # NC3 widened (BACKLOG 2026-10-25): every resource a cancelled request touched is quarantined
    'cancelled-session-no-discard': 'pre-widening NC3: a cancelled connection that passes the checkin predicate gets the ordinary checkin, so its session state (SET) reaches the next principal without DISCARD ALL',
}
DISCARD_COST = 3          # NC4 charge for a discarded connection (backend fork + auth of its replacement, q3-008)

# ============================================================================ reference model: harness DB fake
class Conn:
    """A pgwire-ish session. Server side executes a message on arrival and queues its reply; the client side tracks
    what it has read (ReadyForQuery status, outstanding replies, server objects it created)."""
    def __init__(s, db, cid):
        s.db, s.id = db, cid
        s.txn, s.writes, s.objects, s.queue, s.closed = 'I', {}, set(), collections.deque(), False
        s.session = {}            # session-level state (SET); survives COMMIT/ROLLBACK, cleared by RESET / DISCARD ALL
        s.stray = None            # a CancelRequest that has not reached the backend yet (q3-008 stray-cancel race)
        s.durs = collections.deque()   # server time of each queued reply, in op-budget ticks
        s.stmt_ticks = 1
        s.c_txn, s.c_out, s.c_objects = 'I', 0, set()
        s.gen = 0                 # driver-side statement/type cache generation
    def send(s, msg):
        k = msg[0]; db = s.db
        if s.stray is not None:   # the late CancelRequest cancels whatever runs next on this backend
            s.stray = None
            if s.txn == 'T': s.txn = 'E'
            s.queue.append(('ERROR', '57014', s.txn)); s.durs.append(0); s.c_out += 1
            return
        if s.txn == 'E' and k not in ('ROLLBACK', 'COMMIT'):
            rep = ('ERROR', '25P02')                            # in failed transaction block
        elif k == 'BEGIN':
            if s.txn == 'I': s.txn = 'T'
            rep = ('BEGIN',)
        elif k in ('EXEC', 'EXECP'):
            key, v = msg[-2], msg[-1]
            if s.txn == 'E': rep = ('ERROR', '25P02')
            elif s.txn == 'T': s.writes[key] = v; rep = ('EXEC', 1)
            else: db.rows[key] = v; rep = ('EXEC', 1)           # autocommit outside a txn
        elif k == 'SELECT':
            if s.txn == 'E': rep = ('ERROR', '25P02')
            else: rep = ('ROWS', {key: s.writes.get(key, db.rows.get(key)) for key in msg[1]})
        elif k == 'PARSE': s.objects.add('stmt:' + msg[1]); s.c_objects.add('stmt:' + msg[1]); rep = ('PARSE',)
        elif k == 'BIND': s.objects.add('portal:' + msg[1]); s.c_objects.add('portal:' + msg[1]); rep = ('BIND',)
        elif k == 'CLOSE': s.objects -= {'stmt:' + msg[1], 'portal:' + msg[1]}; rep = ('CLOSE', msg[1])
        elif k == 'SAVEPOINT':
            if s.txn == 'T': s.objects.add('sp:' + msg[1])
            s.c_objects.add('sp:' + msg[1]); rep = ('SAVEPOINT',)
        elif k == 'RELEASE': s.objects.discard('sp:' + msg[1]); rep = ('RELEASE', msg[1])
        elif k == 'COMMIT':
            rep = ('ROLLBACK',) if s.txn == 'E' else ('COMMIT',)  # COMMIT of a failed txn rolls back (PG)
            if s.txn == 'T': db.rows.update(s.writes)
            s.writes, s.txn = {}, 'I'; s.objects = {o for o in s.objects if not o.startswith('sp:')}
        elif k == 'ROLLBACK':
            s.writes, s.txn = {}, 'I'; s.objects = {o for o in s.objects if not o.startswith('sp:')}; rep = ('ROLLBACK',)
        elif k == 'SET': s.session[msg[1]] = msg[2]; rep = ('SET',)
        elif k == 'RESET': s.session = {}; rep = ('RESET',)
        elif k == 'SHOW': rep = ('ROWS', dict(s.session))
        elif k == 'DISCARD':                                     # DISCARD ALL
            if s.txn != 'I': s.txn = 'E'; rep = ('ERROR', '25001')   # cannot run inside a transaction block
            else: s.objects, s.session = set(), {}; rep = ('DISCARD',)
        else: rep = ('ERROR', 'unknown')
        s.queue.append(rep + (s.txn,)); s.c_out += 1
        s.durs.append(s.stmt_ticks if k in ('EXEC', 'EXECP', 'SELECT') else 0)
    def cancel_request(s):
        """CancelRequest over a separate socket. It is not bound to a statement: the model delivers it late, to the
        next message the backend executes (observed in q3-008: 3 of 24,997 race cycles hit the NEXT request)."""
        if not s.closed: s.stray = True
    def recv(s):
        rep = s.queue.popleft(); s.c_out -= 1; s.c_txn = rep[-1]; s.last_dur = s.durs.popleft()
        if rep[0] in ('CLOSE',): s.c_objects -= {'stmt:' + rep[1], 'portal:' + rep[1]}
        if rep[0] == 'RELEASE': s.c_objects.discard('sp:' + rep[1])
        if rep[0] in ('COMMIT', 'ROLLBACK'): s.c_objects = {o for o in s.c_objects if not o.startswith('sp:')}
        if rep[0] == 'DISCARD': s.c_objects = set()
        return rep
    def close(s):
        s.writes, s.txn, s.objects, s.closed, s.session, s.stray = {}, 'I', set(), True, {}, None
        s.queue.clear(); s.durs.clear()
    def truth(s):
        return {'txn': s.txn, 'queued': len(s.queue), 'objects': sorted(s.objects), 'session': dict(s.session)}

class DB:
    def __init__(s, rows): s.rows = dict(rows); s.n = 0
    def connect(s): s.n += 1; return Conn(s, f'db{s.n}')

class UpConn:
    def __init__(s, cid, key): s.id, s.key, s.unread = cid, key, False

# ============================================================================ reference model: host + handler
class Cancelled(Exception): pass
class QueryError(Exception): pass
class HandlerAbort(Exception): pass      # the handler itself returns an error (NC1 "return/error"), no cancellation

class Host:
    def __init__(s, world, mut, emit):
        s.db = DB(world); s.mut = set(mut); s.emit = emit
        s.pool = []                     # DB pool, size 1
        s.up = collections.defaultdict(list); s.up_n = 0; s.epoch = 0
        s.budget = collections.Counter()

    # ---------------- accounting (NC4)
    def debit(s, r, cost, reason):
        s.budget[r['principal']] += cost; s.emit(ev='debit', req=r['id'], principal=r['principal'], cost=cost, reason=reason)

    # ---------------- DB pool (NC3)
    def reusable(s, c):
        if 'always-reusable' in s.mut: return True
        ok_txn = True if 'checkin-ignores-txn' in s.mut else c.c_txn == 'I'
        ok_obj = True if 'checkin-ignores-objects' in s.mut else not c.c_objects
        return c.c_out == 0 and ok_txn and ok_obj
    def checkin(s, r, c):
        if s.reusable(c) and len(s.pool) < 1:
            c.c_objects = set(); s.pool.append(c); s.emit(ev='checkin', req=r['id'], conn=c.id, truth=c.truth())
        else:
            s.discard(r, c)
    def discard(s, r, c):
        # NC3: discard sends a CancelRequest so the orphan backend stops; the connection is closed, never reused
        c.cancel_request(); s.emit(ev='cancel_request', req=r['id'], conn=c.id)
        c.close(); s.emit(ev='discard', req=r['id'], conn=c.id)

    def release_cancelled(s, r, c, cancelled=True):
        """NC3 (q3-008, widened): a connection that a cancelled request touched, or that was left mid-protocol, is
        quarantined, then recovered within T_recover = op budget, else discarded. Recovery = drain every outstanding
        reply to ReadyForQuery WITHOUT a CancelRequest, ROLLBACK if the server-reported txn status is not I, DISCARD
        ALL, cache-generation bump. Quarantine time and a discard are charged to the cancelling principal (NC4).
        `cancelled=False` is a handler that returned an error: only the "left mid-protocol" disjunct applies there, and
        the checkin predicate decides it."""
        if s.reusable(c) and (not cancelled or 'cancelled-session-no-discard' in s.mut):
            s.checkin(r, c); return                       # not touched by a cancel, not mid-protocol: ordinary checkin
        s.emit(ev='quarantine', req=r['id'], conn=c.id)
        budget, ticks, ok = r.get('op_budget', 4), 0, True
        if 'reuse-after-cancelrequest' in s.mut:
            c.cancel_request(); s.emit(ev='cancel_request', req=r['id'], conn=c.id)
            stray, c.stray = c.stray, None                # in flight; reaches the backend after the recovery
        while ok and c.c_out:                             # drain (the in-flight statement is bounded by the budget)
            rep = c.recv(); ticks += c.last_dur
            s.emit(ev='reply', req=r['id'], conn=c.id, msg=rep[0], drain=True)
            ok = ticks <= budget
        def stmt(msg):
            nonlocal ticks, ok
            c.send((msg,)); s.emit(ev='wire', req=r['id'], conn=c.id, msg=msg)
            rep = c.recv(); ticks += 1; s.emit(ev='reply', req=r['id'], conn=c.id, msg=rep[0])
            ok = ok and rep[0] != 'ERROR' and ticks <= budget          # any error or timeout => discard
        if ok and c.c_txn != 'I': stmt('ROLLBACK')
        if ok and 'recovery-no-discard-all' not in s.mut: stmt('DISCARD')
        if ok:
            c.gen += 1; s.emit(ev='gen_bump', req=r['id'], conn=c.id, gen=c.gen)
        charge = max(1, min(ticks, budget))
        if 'quarantine-not-charged' not in s.mut: s.debit(r, charge, 'quarantine')
        s.emit(ev='recover', req=r['id'], conn=c.id, ticks=charge, completed=ok)
        if ok and s.reusable(c) and len(s.pool) < 1:
            if 'reuse-after-cancelrequest' in s.mut: c.stray = stray
            c.c_objects = set(); s.pool.append(c); s.emit(ev='checkin', req=r['id'], conn=c.id, truth=c.truth())
        else:
            s.discard(r, c)
            if 'quarantine-not-charged' not in s.mut: s.debit(r, DISCARD_COST, 'discard')

    # ---------------- upstream pool (CRS C3/C5): key = derive(Hash, Eq) over the whole config incl. epoch
    def up_key(s, r):
        k = (r['authority'], r['principal'], 'bearer')
        return k if 'pool-key-no-epoch' in s.mut else k + (s.epoch,)
    def bump(s):
        s.epoch += 1; s.emit(ev='epoch_bump', epoch=s.epoch)

    def run(s, r, cancel_at=None, mode=None, cp_cancel_hook=None):
        """Execute request r; CancelAt<cancel_at> under `mode`. Returns nothing; everything observable is an event."""
        st = {'conn': None, 'ups': [], 'cp': False, 'stage': None, 'stage_timeout': False, 'status': None}
        gen = handler(s, r, st)
        n = 0; site = None
        try:
            site = next(gen)
            while True:
                s.emit(ev='await', req=r['id'], n=n, site=site)
                if cancel_at is not None and n == cancel_at:
                    s.emit(ev='cancel', req=r['id'], n=n, site=site, mode=mode)
                    if mode == 'stage_timeout' and site.startswith('authz.'):
                        # only the stage future is dropped; the stage evaluates to Error (handled in stage_end)
                        st['stage_timeout'] = True; n += 1; site = gen.send(None); continue
                    raise Cancelled()
                n += 1; site = gen.send(None)
        except StopIteration:
            return
        except HandlerAbort as e:
            # the handler returned an error before CP (NC1): Failed / 500; the connection is quarantined iff it was
            # left mid-protocol (the checkin predicate decides; NC3 second disjunct)
            if st['conn'] is not None: s.release_cancelled(r, st['conn'], cancelled=False)
            s.emit(ev='outcome', req=r['id'], outcome='Failed', error=str(e)); s.emit(ev='response', req=r['id'], status=500)
            return
        except QueryError as e:
            # a server error fails the request: drain, roll back, ordinary checkin, Failed / 500
            c = st['conn']
            if c is not None:
                while c.c_out: c.recv()
                if c.c_txn != 'I': c.send(('ROLLBACK',)); s.emit(ev='wire', req=r['id'], conn=c.id, msg='ROLLBACK'); c.recv()
                s.checkin(r, c)
            s.emit(ev='outcome', req=r['id'], outcome='Failed', error=str(e)); s.emit(ev='response', req=r['id'], status=500)
            return
        except Cancelled:
            pass
        # ---- termination at an await (the handler future is dropped; only host-owned cleanup runs)
        if mode == 'crash':
            s.emit(ev='crash', req=r['id'])
            for c in [st['conn']] + s.pool:
                if c: c.close()
            s.pool = []; s.up.clear(); return
        if st['cp'] and 'no-cp-latch' not in s.mut:
            # NC2: past the commit point the rest runs to completion in a runtime-owned task; status from the commit
            s.emit(ev='latched', req=r['id']); st['latched'] = mode   # client is gone or timed out: no 200 to it
            for site in gen: s.emit(ev='await', req=r['id'], n=None, site=site, detached=True)
            if mode in ('timeout', 'stage_timeout'): s.emit(ev='response', req=r['id'], status=202, note='pending; retrieve by idempotency key')
            return
        gen.close()
        if site and site.startswith('authz.'):
            s.emit(ev='authz', req=r['id'], stage=site[6:], decision='deny', cancelled=True)   # NC5
        if st['conn'] is not None: s.release_cancelled(r, st['conn'])
        for u in st['ups']:
            if u.unread: s.emit(ev='upstream_close', req=r['id'], conn=u.id)
            else: s.up[u.key].append(u); s.emit(ev='upstream_release', req=r['id'], conn=u.id)
        s.debit(r, 1, 'cancel')                                                                   # NC4
        s.emit(ev='outcome', req=r['id'], outcome='Failed')
        if mode in ('timeout', 'stage_timeout'): s.emit(ev='response', req=r['id'], status=408)

def q(h, r, st, c, msg):
    """send-before-yield (the real-world shape that creates the hazard), one Pending, then read the reply."""
    c.send(msg); h.emit(ev='wire', req=r['id'], conn=c.id, msg=msg[0])
    yield f'db.{msg[0]}'
    rep = c.recv(); h.emit(ev='reply', req=r['id'], conn=c.id, msg=rep[0])
    if rep[0] == 'ERROR': raise QueryError(f'{msg[0]}: SQLSTATE {rep[1]}')
    return rep

def handler(h, r, st):
    if 'debit-after-work' not in h.mut: h.debit(r, r['cost'], 'admission')
    yield 'limiter.debit'
    for stage in r['authz']:
        st['stage_timeout'] = False
        yield f'authz.{stage}'
        if st['stage_timeout']:
            if 'authz-fail-open' in h.mut:
                h.emit(ev='authz', req=r['id'], stage=stage, decision='allow', cancelled=True)
                continue
            h.emit(ev='authz', req=r['id'], stage=stage, decision='deny', cancelled=True)
            h.debit(r, 1, 'cancel'); h.emit(ev='outcome', req=r['id'], outcome='Failed'); h.emit(ev='response', req=r['id'], status=403)
            return
        h.emit(ev='authz', req=r['id'], stage=stage, decision='allow', cancelled=False)
    yield 'pool.acquire'
    if h.pool:
        c = h.pool.pop(); h.emit(ev='conn_acquire', req=r['id'], conn=c.id, reused=True)
    else:
        c = h.db.connect(); h.emit(ev='conn_acquire', req=r['id'], conn=c.id, reused=False)
    st['conn'] = c; c.stmt_ticks = r.get('stmt_ticks', 1)
    if r.get('pre_prepare'):
        # session-level named statement prepared before the txn (statement-cache shape, tokio-postgres #1374): it
        # outlives the txn, so a cancel in the following non-DB await leaves txn I + no replies + an open object
        yield from q(h, r, st, c, ('PARSE', 'cached'))
        yield 'stmtcache.insert'
    if r.get('abort') == 'before_begin':
        raise HandlerAbort('handler error after the statement-cache insert (txn I, server object open)')
    if r.get('session_set'):
        # session-level state (e.g. a GUC set for this principal) outside the txn; reset after commit. Only
        # DISCARD ALL removes it if the request is cancelled in between.
        yield from q(h, r, st, c, ('SET', 'app.principal', r['principal']))
        # a non-DB host call after the SET reply was read: a cancel here leaves a protocol-clean connection (txn I,
        # nothing outstanding) that still carries session state -- the NC3-widening window (BACKLOG 2026-10-25)
        yield 'session.ready'
    yield from q(h, r, st, c, ('BEGIN',))
    idem = f"idem:{r['principal']}:{r['idem_key']}"
    yield from q(h, r, st, c, ('EXEC', idem, 'in_flight'))
    for step in r['steps']:
        k = step[0]
        if k == 'read':
            rep = yield from q(h, r, st, c, ('SELECT', step[1]))
            h.emit(ev='result', req=r['id'], rows=rep[1] if rep[0] == 'ROWS' else {'error': rep[1:]})
        elif k == 'write':
            yield from q(h, r, st, c, ('EXEC', step[1], step[2]))
        elif k == 'prepared':
            _, name, key, v = step
            yield from q(h, r, st, c, ('PARSE', name)); yield from q(h, r, st, c, ('BIND', name))
            yield from q(h, r, st, c, ('EXECP', name, key, v)); yield from q(h, r, st, c, ('CLOSE', name))
        elif k == 'savepoint':
            _, name, key, v = step
            yield from q(h, r, st, c, ('SAVEPOINT', name)); yield from q(h, r, st, c, ('EXEC', key, v))
            yield from q(h, r, st, c, ('RELEASE', name))
        elif k == 'show':
            rep = yield from q(h, r, st, c, ('SHOW',))
            h.emit(ev='result', req=r['id'], rows=rep[1], kind='session')
        elif k == 'upstream':
            key = h.up_key(r)
            yield 'upstream.acquire'
            if h.up[key]:
                u = h.up[key].pop(); h.emit(ev='upstream_acquire', req=r['id'], conn=u.id, reused=True)
            else:
                h.up_n += 1; u = UpConn(f'up{h.up_n}', key); h.emit(ev='upstream_connect', req=r['id'], conn=u.id)
                h.emit(ev='upstream_acquire', req=r['id'], conn=u.id, reused=False)
            st['ups'].append(u); u.unread = True
            yield 'upstream.response'
            u.unread = False; st['ups'].remove(u); h.up[key].append(u); h.emit(ev='upstream_release', req=r['id'], conn=u.id)
    if r.get('abort') == 'in_txn':
        raise HandlerAbort('handler error inside the txn (txn T, nothing outstanding)')
    yield from q(h, r, st, c, ('EXEC', idem, 'done:200'))        # outcome record inside the txn (NC2)
    # ---- commit point: COMMIT handed to the wire
    c.send(('COMMIT',)); h.emit(ev='wire', req=r['id'], conn=c.id, msg='COMMIT'); st['cp'] = True; h.emit(ev='cp', req=r['id'])
    yield 'db.COMMIT'
    rep = c.recv(); h.emit(ev='reply', req=r['id'], conn=c.id, msg=rep[0])
    if r.get('pre_prepare'): yield from q(h, r, st, c, ('CLOSE', 'cached'))
    if r.get('session_set'): yield from q(h, r, st, c, ('RESET',))
    st['conn'] = None; h.checkin(r, c)
    if 'debit-after-work' in h.mut: h.debit(r, r['cost'], 'admission')
    h.emit(ev='outcome', req=r['id'], outcome='Committed' if rep[0] == 'COMMIT' else 'Failed')
    if not st.get('latched'): h.emit(ev='response', req=r['id'], status=200 if rep[0] == 'COMMIT' else 500)

def reference_run(job, mut):
    """One scenario run on the reference model. Returns the event list."""
    evs = []
    def emit(**e): evs.append(e)
    h = Host(job['world'], mut, emit)
    emit(ev='durable', at='start', rows=dict(h.db.rows))
    for idx, r in enumerate(job['requests']):
        if idx in job['bumps_before']: h.bump()
        tgt = idx == job['target']
        h.run(r, job['cancel_at'] if tgt else None, job['mode'] if tgt else None)
        emit(ev='durable', at='after:' + r['id'], rows=dict(h.db.rows))
    emit(ev='end')
    return evs

# ============================================================================ scenarios
def scenario(seed):
    rng = random.Random(seed)
    A, B = 'alice', 'bob'
    world = {f'u:{p}:{k}': f'{p}-{k}-0' for p in (A, B) for k in ('x', 'y', 'z')}
    def steps_for(p, tag, n):
        kinds = ['read', 'write', 'prepared', 'savepoint', 'upstream']
        out = []
        for j in range(n):
            k = rng.choice(kinds); key = f'u:{p}:{rng.choice("xyz")}'; v = f'{p}-{tag}-{j}'
            if k == 'read': out.append(['read', sorted({key, f'u:{p}:x'})])
            elif k == 'write': out.append(['write', key, v])
            elif k == 'prepared': out.append(['prepared', f's{j}', key, v])
            elif k == 'savepoint': out.append(['savepoint', f'sp{j}', key, v])
            else: out.append(['upstream'])
        if not any(s[0] in ('write', 'prepared', 'savepoint') for s in out): out.append(['write', f'u:{p}:z', f'{p}-{tag}-w'])
        if rng.random() < .6 and not any(s[0] == 'upstream' for s in out): out.insert(rng.randint(0, len(out)), ['upstream'])
        return out
    def req(rid, p, role, steps, authz):
        return {'id': rid, 'principal': p, 'role': role, 'idem_key': f'{rid}-{seed}', 'cost': rng.randint(1, 5),
                'authority': 'api.internal', 'authz': authz, 'steps': steps, 'pre_prepare': rid == 'R0' and rng.random() < .5,
                'session_set': rid == 'R0' and rng.random() < .7,
                'op_budget': rng.randint(2, 5), 'stmt_ticks': rng.randint(1, 3)}
    reqs = [req('W0', A, 'warmup', [['upstream'], ['write', f'u:{A}:x', f'{A}-W0']], ['authn.verify']),
            req('R0', A, 'target', steps_for(A, 'R0', rng.randint(2, 5)), rng.choice([['authn.verify'], ['authn.verify', 'authz.policy']]))]
    for j in (1, 2, 3):   # O2: three follow-ups from a DIFFERENT principal on the size-1 pool
        reqs.append(req(f'F{j}', B, 'followup', [['read', [f'u:{B}:x', f'u:{B}:y']], ['show'], ['write', f'u:{B}:y', f'{B}-F{j}']], ['authn.verify']))
    reqs.append(req('F4', A, 'followup-same', [['upstream'], ['read', [f'u:{A}:z']], ['write', f'u:{A}:y', f'{A}-F4']], ['authn.verify']))
    bumps = [2] if (seed % 2 == 0 or rng.random() < .5) else []   # auth/config change right after R0
    # NC3 second disjunct ("left mid-protocol", no cancel): two alice requests whose handler returns an error, then a
    # bob follow-up. E1 errors with txn I + an open session-level statement, E2 inside its txn. The checkin predicate
    # decides quarantine here, which keeps the predicate mutations observable now that every cancelled connection is
    # quarantined. Appended after all earlier draws, so W0..F4 are unchanged per seed.
    e1 = req('E1', A, 'error', [['write', f'u:{A}:x', f'{A}-E1']], ['authn.verify']); e1.update(pre_prepare=True, session_set=False, abort='before_begin')
    e2 = req('E2', A, 'error', [['write', f'u:{A}:z', f'{A}-E2']], ['authn.verify']); e2.update(pre_prepare=False, session_set=False, abort='in_txn')
    reqs += [e1, e2, req('F5', B, 'followup', [['read', [f'u:{B}:x', f'u:{B}:y']], ['show'], ['write', f'u:{B}:x', f'{B}-F5']], ['authn.verify'])]
    return {'seed': seed, 'world': world, 'requests': reqs, 'bumps_before': bumps, 'target': 1}

# ============================================================================ checkers (events only)
USER = ('u:', 'idem:')
def expected_writes(r):
    w = {}
    for s in r['steps']:
        if s[0] == 'write': w[s[1]] = s[2]
        elif s[0] in ('prepared', 'savepoint'): w[s[2]] = s[3]
    w[f"idem:{r['principal']}:{r['idem_key']}"] = 'done:200'
    return w

def delta(before, after):
    d = {}
    for k in set(before) | set(after):
        if k.startswith(USER) and before.get(k) != after.get(k): d[k] = after.get(k)
    return d

def check(job, evs):
    """Returns a list of (clause, message)."""
    V = []; reqs = {r['id']: r for r in job['requests']}
    by = collections.defaultdict(list); durable = {}; order = []
    epoch = 0; up_epoch = {}; up_owner = {}
    quar = {}            # conn -> {'req', 'discard_all', 'gen_bump', 'cancel_request', 'recover'} while quarantined
    cancelled_conns = set()   # conns that got a CancelRequest (stay unusable forever)
    for i, e in enumerate(evs):
        e = dict(e, _i=i)
        if e['ev'] == 'durable': durable[e['at']] = e['rows']; order.append(e['at']); continue
        if e['ev'] == 'epoch_bump': epoch = e['epoch']; continue
        if e['ev'] == 'end': continue
        rid = e.get('req'); by[rid].append(e)
        # CRS C5 / C2: an upstream connection is used only at the epoch and by the principal it was created for
        if e['ev'] == 'upstream_connect': up_epoch[e['conn']] = epoch; up_owner[e['conn']] = reqs[rid]['principal']
        if e['ev'] == 'upstream_acquire' and e.get('reused'):
            ce = up_epoch.get(e['conn'])
            if ce is None: V.append(('C5', f"{rid}: reused upstream {e['conn']} never seen connecting"))
            elif ce != epoch: V.append(('C5', f"{rid}: upstream {e['conn']} created at epoch {ce} reused at epoch {epoch} (no epoch revocation)"))
            if up_owner.get(e['conn']) != reqs[rid]['principal']:
                V.append(('C2', f"{rid}: upstream {e['conn']} of {up_owner.get(e['conn'])} reused for {reqs[rid]['principal']}"))
        # NC3 (q3-008) quarantine / recovery discipline, from events
        cn = e.get('conn')
        if e['ev'] == 'quarantine': quar[cn] = {'req': rid, 'discard_all': False, 'gen_bump': False, 'recover': None}
        if e['ev'] == 'cancel_request': cancelled_conns.add(cn)
        if cn in quar:
            qq = quar[cn]
            if e['ev'] == 'wire' and e.get('msg') == 'DISCARD': qq['discard_all'] = True
            if e['ev'] == 'gen_bump': qq['gen_bump'] = True
            if e['ev'] == 'recover': qq['recover'] = e
            if e['ev'] == 'conn_acquire':
                V.append(('NC3', f"{rid}: acquired {cn} while it is quarantined by {qq['req']}"))
        if e['ev'] == 'checkin' and cn in cancelled_conns:
            V.append(('NC3', f"{rid}: {cn} checked back in after a CancelRequest was sent on it (stray cancel can hit the next request)"))
        if e['ev'] == 'checkin' and cn in quar:
            qq = quar.pop(cn); rec = qq['recover']; budget = reqs[qq['req']].get('op_budget', 4)
            if not rec or not rec.get('completed'): V.append(('NC3', f"{rid}: quarantined {cn} checked in without a completed recovery"))
            elif rec.get('ticks', 0) > budget: V.append(('NC3', f"{rid}: recovery of {cn} took {rec['ticks']} > op budget {budget}"))
            if not qq['discard_all']: V.append(('NC3', f"{rid}: quarantined {cn} checked in without DISCARD ALL"))
            if not qq['gen_bump']: V.append(('NC3', f"{rid}: quarantined {cn} checked in without a cache-generation bump"))
        if e['ev'] == 'discard':
            quar.pop(cn, None)
            if cn not in cancelled_conns: V.append(('NC3', f"{rid}: {cn} discarded without a CancelRequest (orphan backend keeps running)"))
        # NC3 / O2 server-truth hygiene: a connection goes back to the pool only if idle, txn I, nothing queued, no
        # objects, and (q3-008: DISCARD ALL) no session state
        if e['ev'] == 'checkin':
            t = e['truth']
            if t['txn'] != 'I': V.append(('NC3', f"{rid}: checkin of {e['conn']} with server txn status {t['txn']} (idle in transaction)"))
            if t['queued']: V.append(('NC3', f"{rid}: checkin of {e['conn']} with {t['queued']} unread replies"))
            if t['objects']: V.append(('NC3', f"{rid}: checkin of {e['conn']} with open server objects {t['objects']}"))
            if t.get('session'): V.append(('NC3', f"{rid}: checkin of {e['conn']} with session state {t['session']}"))
    prev = 'start'
    for rid in [r['id'] for r in job['requests']]:
        r = reqs[rid]; E = by.get(rid, []); kinds = [e['ev'] for e in E]
        before, after = durable.get(prev, {}), durable.get('after:' + rid, {}); prev = 'after:' + rid
        d = delta(before, after); exp = expected_writes(r)
        cp = next((e for e in E if e['ev'] == 'cp'), None)
        cancel = next((e for e in E if e['ev'] == 'cancel'), None)
        outcome = [e['outcome'] for e in E if e['ev'] == 'outcome']
        resp = [e['status'] for e in E if e['ev'] == 'response']
        mode = cancel['mode'] if cancel else None
        crashed = 'crash' in kinds
        deny = any(e['ev'] == 'authz' and e['decision'] == 'deny' for e in E)
        # ---- NC1: no commit point => Failed, no durable user-row change, no 2xx
        if cp is None:
            if d: V.append(('NC1', f"{rid}: terminated before CP ({mode or 'no cancel'}) but durable rows changed: {sorted(d)[:4]}"))
            if outcome and outcome[-1] != 'Failed': V.append(('NC1', f"{rid}: no CP but outcome {outcome[-1]}"))
            if any(200 <= s < 300 for s in resp): V.append(('NC1', f"{rid}: no CP but status {resp}"))
            if not cancel and not deny and not r.get('abort'): V.append(('NC1', f"{rid}: uncancelled request never reached CP"))
            if r.get('abort') and not crashed and (outcome != ['Failed'] or resp != [500]):
                V.append(('NC1', f"{rid}: handler error before CP but outcome {outcome} status {resp}"))
        else:
            # ---- NC2: from CP on, latched: commit completes, outcome Committed, status only 200/202
            if crashed:
                if d and d != exp: V.append(('NC2', f"{rid}: crash after CP left a partial commit {sorted(d)[:4]}"))
            else:
                if d != exp: V.append(('NC2', f"{rid}: reached CP but durable delta {sorted(d)} != expected {sorted(exp)}"))
                if outcome != ['Committed']: V.append(('NC2', f"{rid}: reached CP ({mode or 'no cancel'} at {cancel and cancel['site']}) but outcome {outcome}"))
                bad = [s for s in resp if s not in (200, 202)]
                if bad: V.append(('NC2', f"{rid}: status {bad} after CP (observed failure != actual outcome)"))
                if mode in ('timeout', 'stage_timeout') and cancel['_i'] > cp['_i'] and resp != [202]:
                    V.append(('NC2', f"{rid}: timer after CP must yield 202, got {resp}"))
                if not cancel and resp != [200]: V.append(('NC2', f"{rid}: uncancelled request status {resp}"))
        # ---- NC3 widened: every DB connection a cancelled request touched (cancel before CP) is quarantined before it
        # can be checked in, even if it passes the checkin predicate (session state is invisible to the predicate)
        if cancel and cp is None and not crashed:
            touched = {e['conn'] for e in E if e['ev'] == 'conn_acquire' and e['_i'] < cancel['_i']}
            quarantined = {e['conn'] for e in E if e['ev'] == 'quarantine' and e['_i'] > cancel['_i']}
            for e in E:
                if e['ev'] == 'checkin' and e['_i'] > cancel['_i'] and e['conn'] in touched and e['conn'] not in quarantined:
                    V.append(('NC3', f"{rid}: {e['conn']} touched by a request cancelled at {cancel['site']} checked in without quarantine (no DISCARD ALL)"))
        # ---- NC5: a cancelled / timed-out authz stage => Deny and nothing past authz
        work = [e for e in E if e['ev'] in ('conn_acquire', 'wire', 'upstream_acquire', 'cp')]
        if cancel and cancel['site'].startswith('authz.'):
            stage = cancel['site'][6:]
            dec = [e for e in E if e['ev'] == 'authz' and e['stage'] == stage and e.get('cancelled')]
            if not crashed and (not dec or dec[0]['decision'] != 'deny'):
                V.append(('NC5', f"{rid}: authz stage {stage} cancelled ({mode}) but decision {[x['decision'] for x in dec] or 'none recorded'}"))
            if [w for w in work if w['_i'] > cancel['_i']]: V.append(('NC5', f"{rid}: work after cancelled authz stage {stage}: {[w['ev'] for w in work if w['_i'] > cancel['_i']][:3]}"))
            if any(200 <= s < 300 for s in resp): V.append(('NC5', f"{rid}: 2xx after cancelled authz stage"))
        allowed = {e['stage'] for e in E if e['ev'] == 'authz' and e['decision'] == 'allow' and not e.get('cancelled')}
        if work and not set(r['authz']) <= allowed:
            V.append(('NC5', f"{rid}: work admitted without an Allow decision for every stage {r['authz']} (had {sorted(allowed)})"))
        # ---- NC4: debit before work; cancels charged; never refunded
        debits = [e for e in E if e['ev'] == 'debit']
        if work and (not debits or debits[0]['_i'] > work[0]['_i']): V.append(('NC4', f"{rid}: work before the budget debit"))
        if cancel and not crashed and cp is None and not any(x['reason'] == 'cancel' for x in debits):
            V.append(('NC4', f"{rid}: cancellation not charged"))
        if any(x['cost'] <= 0 for x in debits): V.append(('NC4', f"{rid}: refund/zero debit"))
        if any(x['principal'] != r['principal'] for x in debits): V.append(('NC4', f"{rid}: debit charged to another principal"))
        # q3-008: quarantine time and discards are charged to the cancelling principal
        for rec in (e for e in E if e['ev'] == 'recover'):
            if not any(x['cost'] == rec.get('ticks') for x in debits if x['reason'] == 'quarantine'):
                V.append(('NC4', f"{rid}: quarantine of {rec['conn']} ({rec.get('ticks')} ticks) not charged to {r['principal']}"))
        qconns = {e['conn'] for e in E if e['ev'] == 'quarantine'}
        if any(e['ev'] == 'discard' and e['conn'] in qconns for e in E) and not any(x['reason'] == 'discard' for x in debits):
            V.append(('NC4', f"{rid}: discard of a quarantined connection not charged to {r['principal']}"))
        # ---- O2 functional: follow-ups (other principal, size-1 pool) get their own results and commit only their writes
        if r['role'].startswith('followup'):
            for e in E:
                if e['ev'] == 'result' and e.get('kind') == 'session':
                    if e['rows']: V.append(('O2', f"{rid} ({r['principal']}): session state {e['rows']} inherited from another request"))
                elif e['ev'] == 'result':
                    want = {k: before.get(k) for k in e['rows']} if 'error' not in e['rows'] else None
                    if e['rows'] != want: V.append(('O2', f"{rid} ({r['principal']}): read {str(e['rows'])[:90]} expected {str(want)[:90]} (stale reply / foreign txn)"))
            if outcome != ['Committed'] or resp != [200]: V.append(('O2', f"{rid}: follow-up outcome {outcome} status {resp}"))
            if d != exp: V.append(('O2', f"{rid}: follow-up committed {sorted(set(d) ^ set(exp))[:4]} beyond/short of its own writes (leaked txn)"))
    return V

# ============================================================================ subject plumbing
class ExternalSubject:
    def __init__(s, cmd):
        s.p = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        s.p.stdin.write(json.dumps({'op': 'hello'}) + '\n'); s.p.stdin.flush()
        s.hello = json.loads(s.p.stdout.readline())
        if s.hello.get('ev') != 'hello': raise SystemExit(f'CANCEL-SWEEP: FAIL (subject did not answer hello: {s.hello})')
        # X-11 (D6): "async" = cancellation points are Pendings of the handler future; "sync" = handlers run on a
        # bounded blocking pool and cancellation points are host-call boundaries (README "Synchronous host")
        if s.hello.get('host', 'async') not in ('async', 'sync'):
            raise SystemExit(f"CANCEL-SWEEP: FAIL (subject hello has unknown host kind {s.hello.get('host')!r}; expected async|sync)")
    def run(s, job):
        s.p.stdin.write(json.dumps(dict(job, op='run')) + '\n'); s.p.stdin.flush()
        evs = []
        while True:
            ln = s.p.stdout.readline()
            if not ln: raise SystemExit('CANCEL-SWEEP: FAIL (subject exited mid-run)')
            e = json.loads(ln); evs.append(e)
            if e.get('ev') == 'end': return evs
    def close(s):
        try: s.p.stdin.write(json.dumps({'op': 'quit'}) + '\n'); s.p.stdin.close(); s.p.wait(10)
        except Exception: s.p.kill()

class RefSubject:
    def __init__(s, mut): s.mut = mut; s.hello = {'impl': 'reference-model', 'host': 'async', 'mutations': list(mut)}
    def run(s, job): return reference_run(job, s.mut)
    def close(s): pass

def as_subject(mut):
    """Serve the reference model over the subject protocol (stdin/stdout JSON lines)."""
    for ln in sys.stdin:
        m = json.loads(ln)
        if m['op'] == 'hello': print(json.dumps({'ev': 'hello', 'impl': 'monban-cancel-sweep reference model', 'host': 'async', 'modes': MODES, 'mutations': mut}), flush=True)
        elif m['op'] == 'run':
            for e in reference_run(m, mut): print(json.dumps(e), flush=True)
        elif m['op'] == 'quit': break
    return 0

# ============================================================================ sweep
def sweep(subj, seeds, modes, stop_on=None, quiet=False):
    """Returns dict with counts, violations by clause, first failing seed per clause."""
    stats = collections.Counter(); first = {}; examples = {}; sites = collections.Counter(); cancelled_sites = set()
    for seed in seeds:
        sc = scenario(seed)
        base = dict(sc, cancel_at=None, mode=None)
        evs = subj.run(base); stats['runs'] += 1
        K = sum(1 for e in evs if e.get('ev') == 'await' and e.get('req') == 'R0' and not e.get('detached'))
        for e in evs:
            if e.get('ev') == 'await' and e.get('req') == 'R0': sites[e['site']] += 0
        stats['await_points'] += K
        jobs = [(None, None, evs)] + [(n, m, None) for n in range(K) for m in modes]
        for n, m, pre in jobs:
            job = dict(sc, cancel_at=n, mode=m)
            ev2 = pre if pre is not None else subj.run(job)
            if pre is None: stats['runs'] += 1
            if n is not None:
                site = next((e['site'] for e in ev2 if e.get('ev') == 'cancel'), None)
                if site: cancelled_sites.add(site)
            for e in ev2:
                if e.get('ev') == 'quarantine': stats['quarantined'] += 1
                elif e.get('ev') == 'recover': stats['recovered' if e.get('completed') else 'recovery_failed'] += 1
            for clause, msg in check(job, ev2):
                stats['viol'] += 1; stats['viol:' + clause] += 1
                if clause not in first: first[clause] = seed; examples[clause] = f'seed={seed} cancel_at={n} mode={m}: {msg}'
        stats['seeds'] += 1
        if stop_on and any(c in first for c in stop_on): break
    seen_sites = {e for e in sites}
    return {'stats': stats, 'first': first, 'examples': examples, 'sites': sorted(seen_sites), 'uncovered': sorted(seen_sites - cancelled_sites)}

def main():
    ap = argparse.ArgumentParser(prog='oracles/cancel-sweep/run')
    ap.add_argument('--subject', help='command speaking the subject event protocol (README)')
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--seeds', type=int, default=200, help='seeds 1..N (PR gate 200; nightly 20000)')
    ap.add_argument('--modes', default=','.join(MODES))
    ap.add_argument('--as-subject', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--mutate', action='append', default=[], choices=sorted(MUTATIONS), help='(reference model) apply a mutation')
    a = ap.parse_args()
    if a.as_subject: return as_subject(a.mutate)
    modes = a.modes.split(',')
    if a.self_test: return self_test(a, modes)
    t0 = time.time()
    subj = ExternalSubject(a.subject) if a.subject else RefSubject(a.mutate)
    res = sweep(subj, range(1, a.seeds + 1), modes); subj.close()
    s = res['stats']
    print(f"cancel-sweep: subject={subj.hello.get('impl')} host={subj.hello.get('host', 'async')} seeds={s['seeds']} modes={len(modes)} runs={s['runs']} "
          f"await_points={s['await_points']} sites={len(res['sites'])} uncovered_sites={res['uncovered'] or 0} {time.time() - t0:.1f}s")
    print(f"  NC3 quarantine: {s['quarantined']} quarantined, {s['recovered']} recovered within the op budget, "
          f"{s['recovery_failed']} over budget or failed => discarded")
    for c, ex in sorted(res['examples'].items()): print(f"  {c}: {s['viol:' + c]} violations; first {ex[:220]}")
    if res['uncovered']:
        print(f"CANCEL-SWEEP: FAIL (coverage: await sites never cancelled: {res['uncovered']})"); return 1
    if s['viol']:
        print(f"CANCEL-SWEEP: FAIL ({s['viol']} violations: " + ', '.join(f"{c}={s['viol:' + c]}" for c in sorted(res['first'])) + ")"); return 1
    print(f"CANCEL-SWEEP: PASS (NC1 NC2 NC3(quarantine/recovery) NC4 NC5 O2 C5 over {s['runs']} runs, {s['await_points']} await points, {s['seeds']} seeds x {len(modes)} modes)")
    return 0

def self_test(a, modes):
    """Every mutation must turn its clause red; the plan's two named ones within 100 seeds."""
    plan = [('always-reusable', ('O2', 'NC3'), 100), ('pool-key-no-epoch', ('C5',), 100),
            ('checkin-ignores-txn', ('O2', 'NC1', 'NC3'), 100), ('checkin-ignores-objects', ('NC3',), 100),
            ('no-cp-latch', ('NC2',), 100), ('authz-fail-open', ('NC5',), 100), ('debit-after-work', ('NC4',), 100),
            ('reuse-after-cancelrequest', ('O2', 'NC3'), 100), ('recovery-no-discard-all', ('O2', 'NC3'), 100),
            ('quarantine-not-charged', ('NC4',), 100), ('cancelled-session-no-discard', ('NC3', 'O2'), 100)]
    print(f"cancel-sweep self-test (reference model{', and --subject' if a.subject else ''}; modes={','.join(modes)})")
    missed = []
    for mut, clauses, budget in plan:
        if a.subject:
            subj = ExternalSubject(a.subject + ' ' + ' '.join(f'--mutate {m}' for m in [mut]))
        else:
            subj = RefSubject([mut])
        res = sweep(subj, range(1, budget + 1), modes, stop_on=clauses); subj.close()
        hit = {c: res['first'][c] for c in clauses if c in res['first']}
        if hit:
            c0 = min(hit, key=hit.get)
            print(f"  [caught] {mut}: {c0} red at seed {hit[c0]} (<= {budget}); {res['examples'][c0][:150]}")
        else:
            print(f"  [MISSED] {mut}: none of {clauses} red within {budget} seeds (other: {sorted(res['first'])})"); missed.append(mut)
    if missed:
        print(f"CANCEL-SWEEP SELF-TEST: FAIL (missed: {', '.join(missed)})"); return 1
    print(f"CANCEL-SWEEP SELF-TEST: PASS ({len(plan)}/{len(plan)} mutations caught within 100 seeds each, incl. the plan's always-reusable, pool-key-no-epoch, q3-008's reuse-after-cancelrequest and the NC3-widening cancelled-session-no-discard)")
    return 0

if __name__ == '__main__':
    sys.exit(main())
