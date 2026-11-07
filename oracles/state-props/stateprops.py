#!/usr/bin/env python3
"""AEGIS state-props (oracle for INV-IDEMP, NC2 commit-point latch, NC6 outbox; plus NC1 for the idempotency row and
INV-DURABLE across SIGKILL). Run as `python3 -I stateprops.py`, normally via ./run.

The oracle drives a subject store over a line protocol (README "Subject protocol"), one process per store life:
it SIGKILLs the subject between protocol steps (and inside COMMIT / DELIVER), restarts it on the same directory and
checks every reply against its own model. The oracle is also the outbox's external sink: an effect is "visible" when
the subject prints an EFF line for it.
"""
import argparse, collections, os, random, re, select, shlex, shutil, signal, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
REF = f"python3 -I {shlex.quote(os.path.join(HERE, 'ref_subject.py'))} {{dir}}"
MUTATIONS = {
    'idem-key-without-principal': 'INV-IDEMP',
    'replay-reexecutes':          'INV-IDEMP',
    'effect-before-commit':       'NC6',
    'outbox-drop-on-restart':     'NC6',
    'latch-returns-408':          'NC2',
    'dedupe-unstable':            'NC6',   # extra: not in the unit's list
}
# IDEMP-R (Phase 8, P8-hardening-001): mutations judged by the retention scenario (RetentionRun).
RETENTION_MUTATIONS = {
    'retention-ignored':        'IDEMP-R',
    'retention-early':          'IDEMP-R',
    'retention-in-memory':      'IDEMP-R',
    'purge-noop':               'IDEMP-R',
    'retention-absent-expires': 'IDEMP-R',
}
T0 = 1_800_000_000
REQUIRED_SUBJECT_MUTATIONS = ('idem-key-without-principal', 'replay-reexecutes')   # P4-state-002 acceptance
TIMEOUT = 20.0


class ProtoError(Exception): pass


class Proc:
    """One life of the subject. Line I/O with a timeout (select on the raw fd)."""
    def __init__(s, argv, env):
        s.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        s.buf = b''; s.err = b''
        s.ready = s.line()
    def line(s, timeout=TIMEOUT):
        t_end = time.time() + timeout
        while b'\n' not in s.buf:
            left = t_end - time.time()
            if left <= 0: raise ProtoError('subject timed out')
            r, _, _ = select.select([s.p.stdout], [], [], left)
            if not r: continue
            chunk = os.read(s.p.stdout.fileno(), 65536)
            if not chunk:
                raise ProtoError('subject closed stdout (exit %s) %s' % (s.p.poll(), s.stderr_tail()))
            s.buf += chunk
        ln, s.buf = s.buf.split(b'\n', 1)
        return ln.decode('utf-8', 'replace').rstrip('\r')
    def send(s, ln):
        try:
            s.p.stdin.write((ln + '\n').encode()); s.p.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise ProtoError(f'subject pipe closed: {e}')
    def ask(s, ln):
        s.send(ln); return s.line()
    def kill(s):
        if s.p.poll() is None:
            s.p.send_signal(signal.SIGKILL)
        s.p.wait()
        for f in (s.p.stdin, s.p.stdout, s.p.stderr):
            try: f.close()
            except Exception: pass
    def quit(s):
        try:
            s.send('QUIT'); s.p.stdin.close(); s.p.wait(10)
        except Exception:
            pass
        s.kill()
    def stderr_tail(s):
        try:
            r, _, _ = select.select([s.p.stderr], [], [], 0)
            if r: s.err += os.read(s.p.stderr.fileno(), 65536)
        except Exception:
            pass
        return s.err.decode('utf-8', 'replace').strip().splitlines()[-1:] or ''


class Run:
    """One seed: a scripted prelude that touches every property, then a seeded random tail, then a final restart,
    drain and dump. Violations are (clause, message)."""
    def __init__(s, cmd, d, seed, extra=(), tail=40):
        s.cmd, s.d, s.seed, s.extra, s.tail = cmd, d, seed, list(extra), tail
        s.rng = random.Random(seed)
        s.V = []; s.stats = collections.Counter()
        s.completed = {}     # (p, k) -> {'digest', 'status', 'body', 'rid'}
        s.inflight = {}      # rid -> {'p', 'k', 'digest', 'writes': [], 'effects': []}
        s.held = {}          # (p, k) -> rid
        s.rows = {}          # committed user rows (model)
        s.expected_eff = {}  # payload -> rid   (committed effects: must be delivered at least once)
        s.uncommitted_eff = {}  # payload -> rid (effects of requests not committed (yet))
        s.delivered = collections.defaultdict(set)   # payload -> {dedupe}
        s.dedupe_of = {}     # dedupe -> payload
        s.ambiguous = []     # rids whose COMMIT was interrupted by SIGKILL
        s.n = 0; s.proc = None; s.mutations = []
    # ---------------------------------------------------------------- plumbing
    def v(s, clause, msg):
        s.V.append((clause, f'seed={s.seed}: {msg}'))
    def argv(s):
        a = shlex.split(s.cmd.replace('{dir}', shlex.quote(s.d))) if '{dir}' in s.cmd else shlex.split(s.cmd) + [s.d]
        return a + s.extra
    def start(s):
        s.proc = Proc(s.argv(), dict(os.environ))
        r = s.proc.ready
        if not r.startswith('READY'):
            raise ProtoError(f'no READY: {r[:160]!r}')
        m = re.search(r'mutations=(\S+)', r); s.mutations = m.group(1).split(',') if m else []
        s.stats['lives'] += 1
    def kill(s, why='between steps'):
        s.proc.kill(); s.stats['kills'] += 1
        # pre-CP state of every open request is gone (NC1): the model forgets it
        for rid, r in list(s.inflight.items()):
            s.held.pop((r['p'], r['k']), None)
            for pl in r['effects']: s.uncommitted_eff.setdefault(pl, rid)
        s.inflight.clear()
        s.start()
        s.resolve_ambiguous()
    def rid(s):
        s.n += 1; return f'r{s.n}'
    def hexval(s, nbytes=None):
        return bytes(s.rng.randrange(256) for _ in range(nbytes or s.rng.randint(1, 24))).hex()
    # ---------------------------------------------------------------- operations
    def expect_begin(s, p, k, dg):
        c = s.completed.get((p, k))
        if c: return ('REPLAY', c) if c['digest'] == dg else ('CONFLICT', c)
        if (p, k) in s.held:
            r = s.inflight[s.held[(p, k)]]
            return ('INFLIGHT', None) if r['digest'] == dg else ('INFLIGHT|CONFLICT', None)
        return ('NEW', None)
    def begin(s, p, k, dg=None, probe=False):
        dg = dg or s.digest_for(p, k)
        rid = s.rid(); want, c = s.expect_begin(p, k, dg)
        got = s.proc.ask(f'BEGIN {rid} {p} {k} {dg}').split()
        s.stats['begin:' + want] += 1
        kind = got[0] if got else ''
        others = sorted(q for (q, kk) in list(s.completed) + list(s.held) if kk == k and q != p)
        ctx = f"BEGIN ({p},{k},{dg[:8]}) expected {want}"
        if got[1:2] != [rid] and kind in ('NEW', 'REPLAY', 'CONFLICT', 'INFLIGHT'):
            s.v('PROTO', f'{ctx}: reply for another rid {got}'); return None
        if want == 'REPLAY':
            if kind == 'NEW':
                s.v('INV-IDEMP', f'{ctx}: completed key re-executed (NEW) instead of returning the stored outcome of {c["rid"]}')
                s.inflight[rid] = dict(p=p, k=k, digest=dg, writes=[], effects=[]); s.held[(p, k)] = rid
                return rid
            if kind != 'REPLAY' or got[2:] != [str(c['status']), c['body']]:
                s.v('INV-IDEMP', f'{ctx}: replay must return the stored outcome {c["status"]} {c["body"][:16]}.. byte-identically, got {" ".join(got)[:80]}')
            return None
        if want == 'CONFLICT':
            if kind != 'CONFLICT':
                s.v('INV-IDEMP', f'{ctx}: same key, different request digest must conflict, got {" ".join(got)[:80]}')
            if kind == 'NEW':
                s.inflight[rid] = dict(p=p, k=k, digest=dg, writes=[], effects=[]); s.held[(p, k)] = rid; return rid
            return None
        if want.startswith('INFLIGHT'):
            if kind not in want.split('|'):
                s.v('INV-IDEMP', f'{ctx}: key in flight ({s.held[(p, k)]}) must answer 409-class INFLIGHT, got {" ".join(got)[:80]}')
            if kind == 'NEW':
                s.inflight[rid] = dict(p=p, k=k, digest=dg, writes=[], effects=[]); s.held[(p, k)] = rid; return rid
            return None
        # want NEW
        if kind != 'NEW':
            why = (f'same key held by another principal {others}: keys are (principal, key)' if others
                   else 'fresh key (or one whose request ended before CP)')
            s.v('INV-IDEMP' if others or kind != 'ERR' else 'PROTO', f'{ctx}: {why}, got {" ".join(got)[:80]}')
            return None
        s.inflight[rid] = dict(p=p, k=k, digest=dg, writes=[], effects=[]); s.held[(p, k)] = rid
        return rid
    def digest_for(s, p, k):
        c = s.completed.get((p, k))
        return c['digest'] if c else hashlib_hex(f'{p}/{k}/{s.seed}')
    def write(s, rid):
        k = f'u{s.rng.randrange(6)}'; val = s.hexval()
        got = s.proc.ask(f'WRITE {rid} {k} {val}')
        if got != f'OK {rid}': s.v('PROTO', f'WRITE {rid}: {got[:80]}')
        s.inflight[rid]['writes'].append((k, val))
    def effect(s, rid):
        pl = f'{s.seed:04x}{int(rid[1:]):04x}{len(s.inflight[rid]["effects"]):02x}' + s.hexval(6)
        got = s.proc.ask(f'EFFECT {rid} {pl}')
        if got != f'OK {rid}': s.v('PROTO', f'EFFECT {rid}: {got[:80]}')
        s.inflight[rid]['effects'].append(pl); s.uncommitted_eff[pl] = rid
    def _committed(s, rid, r, status, body):
        s.completed[(r['p'], r['k'])] = dict(digest=r['digest'], status=status, body=body, rid=rid)
        for k, val in r['writes']: s.rows[k] = val
        for pl in r['effects']:
            s.uncommitted_eff.pop(pl, None); s.expected_eff[pl] = rid
        s.stats['committed'] += 1
    def commit(s, rid, timer=None, mid_kill=False):
        r = s.inflight[rid]; status = s.rng.choice([200, 201]); body = s.hexval()
        timer = (s.rng.random() < .3) if timer is None else timer
        if mid_kill:
            # SIGKILL with COMMIT in flight: either outcome is legal, but all or nothing (resolved after restart)
            s.proc.send(f'COMMIT {rid} {status} {body} {int(timer)}')
            if s.rng.random() < .5: time.sleep(s.rng.random() * 0.01)
            s.inflight.pop(rid); s.held.pop((r['p'], r['k']), None)
            s.ambiguous.append((rid, r, status, body)); s.stats['mid_commit_kills'] += 1
            s.kill('inside COMMIT'); return
        got = s.proc.ask(f'COMMIT {rid} {status} {body} {int(timer)}').split()
        s.inflight.pop(rid); s.held.pop((r['p'], r['k']), None)
        if got[:2] != ['RESP', rid]:
            s.v('PROTO', f'COMMIT {rid}: {" ".join(got)[:80]}'); return
        if timer:
            s.stats['timer_after_cp'] += 1
            if got[2:3] != ['202']:
                s.v('NC2', f'COMMIT {rid}: timer after CP must answer 202 (outcome latched, retrieve by key), got {got[2:3]}')
        elif got[2:] != [str(status), body]:
            s.v('NC2', f'COMMIT {rid}: response {got[2:]} != committed outcome {status} {body[:16]}..')
        s._committed(rid, r, status, body)
        if timer:   # retrieval by idempotency key returns the latched outcome
            s.begin(r['p'], r['k'], r['digest'])
    def abort(s, rid):
        r = s.inflight.pop(rid); s.held.pop((r['p'], r['k']), None)
        got = s.proc.ask(f'ABORT {rid}')
        if got != f'OK {rid}': s.v('PROTO', f'ABORT {rid}: {got[:80]}')
        s.stats['aborted'] += 1
    def resolve_ambiguous(s):
        amb, s.ambiguous = s.ambiguous, []
        for rid, r, status, body in amb:
            probe = s.rid()
            got = s.proc.ask(f'BEGIN {probe} {r["p"]} {r["k"]} {r["digest"]}').split()
            if got[:2] == ['REPLAY', probe]:
                if got[2:] != [str(status), body]:
                    s.v('INV-IDEMP', f'{rid} (COMMIT cut by SIGKILL): replay {got[2:]} is not the outcome it committed')
                s._committed(rid, r, status, body); s.stats['mid_commit:committed'] += 1
            elif got[:2] == ['NEW', probe]:
                s.proc.ask(f'ABORT {probe}'); s.stats['mid_commit:rolled_back'] += 1
                for pl in r['effects']: s.uncommitted_eff.setdefault(pl, rid)
            else:
                s.v('INV-IDEMP', f'{rid} (COMMIT cut by SIGKILL): probe got {" ".join(got)[:60]}, expected REPLAY or NEW')
    def deliver(s, mid_kill=False):
        s.proc.send('DELIVER'); n = 0
        while True:
            ln = s.proc.line().split()
            if ln == ['END']: break
            if len(ln) != 3 or ln[0] != 'EFF': s.v('PROTO', f'DELIVER: {" ".join(ln)[:80]}'); break
            _, dd, pl = ln; n += 1; s.stats['deliveries'] += 1
            if pl not in s.expected_eff:
                owner = s.uncommitted_eff.get(pl)
                s.v('NC6', f'effect {pl[:16]}.. visible before its request committed ({owner or "unknown request"})')
            prev = s.dedupe_of.setdefault(dd, pl)
            if prev != pl: s.v('NC6', f'dedupe key {dd} reused for two different effects')
            if s.delivered[pl] and dd not in s.delivered[pl]:
                s.v('NC6', f'effect {pl[:16]}.. redelivered with a different dedupe key ({sorted(s.delivered[pl])[0]} -> {dd})')
            if s.delivered[pl]: s.stats['redeliveries'] += 1
            s.delivered[pl].add(dd)
            if mid_kill:
                s.stats['mid_deliver_kills'] += 1; s.kill('inside DELIVER'); return   # this EFF is never ACKed
            s.proc.send('ACK')
        if mid_kill: s.kill('after DELIVER')
    def dump_check(s, when):
        s.proc.send('DUMP'); got = {}
        while True:
            ln = s.proc.line().split()
            if ln == ['END']: break
            if len(ln) != 3 or ln[0] != 'ROW': s.v('PROTO', f'DUMP: {" ".join(ln)[:80]}'); break
            got[ln[1]] = ln[2]
        if got != s.rows:
            diff = sorted(k for k in set(got) | set(s.rows) if got.get(k) != s.rows.get(k))
            s.v('NC1/DURABLE', f'{when}: user rows differ from exactly the committed requests at {diff[:4]}')
    # ---------------------------------------------------------------- scenario
    def prelude(s):
        A, B = 'alice', 'bob'
        # INV-IDEMP replay + NC6 no effect before commit
        r = s.begin(A, 'k1')
        s.write(r); s.effect(r); s.deliver()                   # nothing committed yet: nothing may be visible
        s.commit(r, timer=False)
        s.begin(A, 'k1')                                       # replay, byte-identical
        # (principal, key): the same key under another principal is independent
        r = s.begin(B, 'k1')
        if r: s.write(r); s.effect(r); s.commit(r, timer=False)
        s.begin(A, 'k1', 'ffff' + s.hexval(4))                # same key, other digest -> conflict
        # in flight -> 409-class; NC2 timer after CP -> 202, then retrieval returns the latched outcome
        r = s.begin(A, 'k2')
        s.begin(A, 'k2')
        if r: s.effect(r); s.commit(r, timer=True)
        # NC1: a request ended before CP frees its key and leaves nothing
        r = s.begin(B, 'k3')
        if r: s.write(r); s.effect(r); s.abort(r)
        r = s.begin(B, 'k3')
        if r:
            s.effect(r); s.kill()                              # SIGKILL before CP: forgotten
        r = s.begin(B, 'k3')
        # NC6: committed, undelivered effects survive a SIGKILL restart
        if r: s.effect(r); s.commit(r, timer=False)
        s.kill(); s.dump_check('after restart')
        s.begin(A, 'k1')                                       # replay after restart
        s.deliver(mid_kill=True)                               # SIGKILL after the first EFF line: the rest (and maybe it) again
        s.deliver()
    def random_tail(s):
        P = ['alice', 'bob']; keys = [f'k{i}' for i in range(1, 4)]
        for _ in range(s.tail):
            x = s.rng.random(); open_ = list(s.inflight)
            if x < .30 and len(open_) < 3:
                p = s.rng.choice(P)
                if s.rng.random() < .4: keys.append(f'k{len(keys) + 1}')
                k = s.rng.choice(keys)
                dg = s.digest_for(p, k) if s.rng.random() < .8 else 'ffff' + s.hexval(4)
                s.begin(p, k, dg)
            elif x < .72 and open_:
                rid = s.rng.choice(open_); y = s.rng.random()
                if y < .35: s.write(rid)
                elif y < .65: s.effect(rid)
                elif y < .9: s.commit(rid)
                else: s.abort(rid)
            elif x < .84:
                s.deliver(mid_kill=s.rng.random() < .3)
            elif x < .90 and open_:
                s.commit(s.rng.choice(open_), mid_kill=True)
            elif x < .95:
                s.kill()
            else:
                s.dump_check('mid-run')
    def finish(s):
        s.kill(); s.dump_check('final restart')
        s.deliver(); s.deliver()
        missing = [pl for pl in s.expected_eff if not s.delivered.get(pl)]
        if missing:
            s.v('NC6', f'{len(missing)} committed effect(s) never delivered across SIGKILL restarts, e.g. {missing[0][:16]}.. of {s.expected_eff[missing[0]]}')
    def go(s):
        try:
            s.start(); s.prelude(); s.random_tail(); s.finish()
        except ProtoError as e:
            s.v('PROTO', str(e))
        finally:
            if s.proc: s.proc.quit()
        return s.V


class RetentionRun(Run):
    """IDEMP-R (SPEC_INVARIANTS §F, F8 state.idempotency_retention_s; PREFLIGHT R12). The subject runs with
    `--idempotency-retention R` and an oracle-driven clock (`CLOCK <unix_s>`, re-sent after every restart). Model: a
    completed key replays (or conflicts) while 0 <= now - committed_at < R, and is forgotten (NEW, for any digest)
    once now - committed_at >= R; a record from the future (clock set back) is kept; PURGE deletes exactly the
    expired records not held by an open request and answers their number; without the flag nothing ever expires.
    Every violation in this scenario is clause IDEMP-R."""
    def __init__(s, cmd, d, seed, extra=(), tail=40):
        super().__init__(cmd, d, seed, extra, tail)
        s.R = s.rng.choice([60, 61, 3600, 86400, 2_592_000, s.rng.randint(60, 2_592_000)])
        s.base_extra = list(extra)
        s.extra = s.base_extra + ['--idempotency-retention', str(s.R)]
        s.clock = T0 + seed * 1000
        s.at = {}            # (p, k) -> committed_at (model)
    def v(s, clause, msg):
        s.V.append(('IDEMP-R' if clause != 'PROTO' else clause, f'seed={s.seed} R={s.R}: {msg}'))
    def start(s):
        try:
            super().start()
        except ProtoError as e:
            s.V.append(('IDEMP-R', f'seed={s.seed}: subject did not start with --idempotency-retention {s.R}: {e}'))
            raise
        if not re.search(r'features=\S*\bretention\b', s.proc.ready):
            s.V.append(('IDEMP-R', f'seed={s.seed}: subject does not advertise features=retention (READY line {s.proc.ready[:80]!r})'))
            raise ProtoError('no retention support (--idempotency-retention, CLOCK, PURGE)')
        s.set_clock(s.clock)
    def set_clock(s, t):
        s.clock = t
        got = s.proc.ask(f'CLOCK {t}')
        if got != 'OK clock': s.v('PROTO', f'CLOCK {t}: {got[:80]}')
    def expired(s, key):
        t = s.at.get(key)
        return s.R is not None and t is not None and s.clock >= t and s.clock - t >= s.R
    def expect_begin(s, p, k, dg):
        if (p, k) in s.completed and s.expired((p, k)):
            if (p, k) in s.held:
                r = s.inflight[s.held[(p, k)]]
                return ('INFLIGHT', None) if r['digest'] == dg else ('INFLIGHT|CONFLICT', None)
            return ('NEW', None)
        return super().expect_begin(p, k, dg)
    def _committed(s, rid, r, status, body):
        super()._committed(rid, r, status, body)
        s.at[(r['p'], r['k'])] = s.clock
    def window(s, key):
        t = s.at.get(key)
        return f'committed_at={t} now={s.clock} age={s.clock - t if t is not None else "-"}'
    def probe(s, p, k, dg=None, why=''):
        n0 = len(s.V)
        rid = s.begin(p, k, dg)
        if len(s.V) > n0:
            s.V[-1] = (s.V[-1][0], s.V[-1][1] + f' [{why}; {s.window((p, k))}]')
        if rid: s.abort(rid)
    def purge(s):
        want = [key for key in s.completed if s.expired(key) and key not in s.held]
        got = s.proc.ask('PURGE').split()
        if got[:1] != ['PURGED'] or len(got) != 2 or not got[1].isdigit():
            s.v('PROTO', f'PURGE: {" ".join(got)[:80]}'); return
        if int(got[1]) != len(want):
            s.v('IDEMP-R', f'PURGE deleted {got[1]} records, the model has {len(want)} expired and not held ({want[:3]})')
        for key in want:
            s.completed.pop(key, None); s.at.pop(key, None)
        s.stats['purged'] += len(want)
    def put(s, p, k, dg=None):
        rid = s.begin(p, k, dg)
        if rid: s.write(rid); s.commit(rid, timer=False)
    def prelude(s):
        A, B, R, T = 'alice', 'bob', s.R, s.clock
        s.put(A, 'k1')                                            # committed_at = T
        s.set_clock(T + R - 1)
        s.probe(A, 'k1', why='last second inside the window: replay')
        s.probe(A, 'k1', 'ffff' + s.hexval(4), why='inside the window, other digest: conflict')
        s.put(B, 'k2')                                            # committed_at = T + R - 1
        s.kill()                                                  # timestamps must be durable
        s.probe(A, 'k1', why='after restart, inside the window: replay')
        s.set_clock(T + R)
        s.probe(A, 'k1', why='window over: forgotten (NEW)')
        s.probe(A, 'k1', 'ffff' + s.hexval(4), why='expired record must not conflict')
        s.probe(B, 'k2', why='younger key still inside its window')
        s.purge(); s.purge()
        s.put(A, 'k1')                                            # fresh outcome, fresh window
        s.probe(A, 'k1', why='re-used key replays its new outcome')
        s.set_clock(T)                                            # clock set back: nothing from the future expires
        s.probe(A, 'k1', why='record from the future is kept'); s.probe(B, 'k2', why='clock set back')
        s.purge()
    def random_tail(s):
        P = ['alice', 'bob', 'carol']; keys = [f'k{i}' for i in range(1, 4)]
        for _ in range(s.tail):
            x = s.rng.random()
            if x < .25:
                step = s.rng.choice([0, 1, s.R - 1, s.R, s.R + 1, s.rng.randint(0, 2 * s.R)])
                s.set_clock(s.clock + step)
            elif x < .55:
                if s.rng.random() < .3: keys.append(f'k{len(keys) + 1}')
                s.put(s.rng.choice(P), s.rng.choice(keys))
            elif x < .80:
                p, k = s.rng.choice(P), s.rng.choice(keys)
                dg = None if s.rng.random() < .8 else 'ffff' + s.hexval(4)
                s.probe(p, k, dg, why='random probe')
            elif x < .90:
                s.purge()
            else:
                s.kill()
    def finish(s):
        s.kill()
        for (p, k) in sorted(s.completed):
            s.probe(p, k, why='final restart')
        s.purge()
        # Absent retention: the same store without the flag never expires anything (pre-Phase-8 meaning).
        s.R = None; s.extra = list(s.base_extra); s.kill()
        s.set_clock(s.clock + 10 ** 8)
        for (p, k) in sorted(s.completed):
            s.probe(p, k, why='no --idempotency-retention: never expires')
        got = s.proc.ask('PURGE').split()
        if got != ['PURGED', '0']:
            s.v('IDEMP-R', f'PURGE without a retention deleted records: {" ".join(got)[:40]}')
    def go(s):
        try:
            s.start(); s.prelude(); s.random_tail(); s.finish()
        except ProtoError as e:
            s.v('PROTO', str(e))
        finally:
            if s.proc: s.proc.quit()
        return s.V


def hashlib_hex(t):
    import hashlib
    return hashlib.sha256(t.encode()).hexdigest()[:16]


def sweep(cmd, seeds, extra=(), stop_on=None, tail=40, kind=Run):
    stats = collections.Counter(); first = {}; examples = {}; viol = collections.Counter()
    root = tempfile.mkdtemp(prefix='state-props-')
    try:
        for seed in seeds:
            d = os.path.join(root, f's{seed}'); os.makedirs(d)
            run = kind(cmd, d, seed, extra, tail)
            V = run.go(); stats.update(run.stats); stats['seeds'] += 1
            for c, m in V:
                viol[c] += 1
                if c not in first: first[c] = seed; examples[c] = m
            shutil.rmtree(d, ignore_errors=True)
            if stop_on and any(c in first for c in stop_on): break
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return stats, viol, first, examples


def probe_mutations(cmd):
    d = tempfile.mkdtemp(prefix='state-props-probe-')
    try:
        r = Run(cmd, d, 0); r.start(); muts = r.mutations; r.proc.quit(); return muts
    except ProtoError as e:
        return ['<probe failed: %s>' % e]
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(prog='oracles/state-props/run')
    ap.add_argument('--subject', help="command speaking the subject protocol; '{dir}' is replaced by the store dir (appended if absent)")
    ap.add_argument('--self-test', action='store_true')
    ap.add_argument('--seeds', type=int, default=60, help='seeds 1..N (PR size 60)')
    ap.add_argument('--tail', type=int, default=40, help='random actions per seed after the scripted prelude')
    a = ap.parse_args()
    if a.self_test: return self_test(a)
    cmd = a.subject or REF; t0 = time.time()
    stats, viol, first, ex = sweep(cmd, range(1, a.seeds + 1), tail=a.tail)
    print(f"state-props: subject={'reference' if not a.subject else a.subject} seeds={stats['seeds']} lives={stats['lives']} "
          f"kills={stats['kills']} (mid-COMMIT {stats['mid_commit_kills']}: committed {stats['mid_commit:committed']}, "
          f"rolled back {stats['mid_commit:rolled_back']}; mid-DELIVER {stats['mid_deliver_kills']}) {time.time() - t0:.1f}s")
    print(f"  BEGIN replies expected: NEW={stats['begin:NEW']} REPLAY={stats['begin:REPLAY']} CONFLICT={stats['begin:CONFLICT']} "
          f"INFLIGHT={stats['begin:INFLIGHT'] + stats['begin:INFLIGHT|CONFLICT']}; committed={stats['committed']} "
          f"aborted={stats['aborted']} timer-after-CP={stats['timer_after_cp']}; deliveries={stats['deliveries']} "
          f"(redeliveries {stats['redeliveries']})")
    rstats, rviol, rfirst, rex = sweep(cmd, range(1, a.seeds + 1), tail=a.tail, kind=RetentionRun)
    print(f"  retention (IDEMP-R): seeds={rstats['seeds']} lives={rstats['lives']} kills={rstats['kills']} "
          f"BEGIN expected NEW={rstats['begin:NEW']} REPLAY={rstats['begin:REPLAY']} CONFLICT={rstats['begin:CONFLICT']}; "
          f"committed={rstats['committed']} purged={rstats['purged']}")
    for c in sorted(first): print(f"  {c}: {viol[c]} violations; first {ex[c][:220]}")
    for c in sorted(rfirst): print(f"  retention {c}: {rviol[c]} violations; first {rex[c][:260]}")
    viol = viol + rviol
    if viol:
        print('STATE-PROPS: FAIL (' + ', '.join(f'{c}={viol[c]}' for c in sorted(viol)) + ')'); return 1
    print(f"STATE-PROPS: PASS (INV-IDEMP NC1 NC2 NC6 over {stats['seeds']} seeds, {stats['lives']} store lives, "
          f"{stats['kills']} SIGKILLs, {stats['deliveries']} deliveries; IDEMP-R over {rstats['seeds']} seeds, "
          f"{rstats['purged']} purged)")
    return 0


def self_test(a):
    # dedupe-unstable shows only on a redelivery, which needs a SIGKILL to land between an EFF line and the subject's
    # delivered mark: timing-dependent, so under machine load 10 seeds can pass with no redelivery at all. It gets the
    # full PR seed budget (60); the others are caught deterministically by the scripted prelude.
    plan = [(m, c, 60 if m == 'dedupe-unstable' else 10, Run) for m, c in MUTATIONS.items()]
    plan += [(m, c, 10, RetentionRun) for m, c in RETENTION_MUTATIONS.items()]
    cmds = [('reference', REF)] + ([('subject', a.subject)] if a.subject else [])
    print('state-props self-test (reference subject' + (', and --subject' if a.subject else '') + ')')
    missed, n = [], 0
    # the unmutated reference must pass first (a mutant caught by a broken oracle proves nothing)
    _, viol, first, ex = sweep(REF, range(1, 4), tail=a.tail)
    _, rviol, rfirst, rex = sweep(REF, range(1, 4), tail=a.tail, kind=RetentionRun)
    if rviol:
        print(f"  [BROKEN] unmutated reference fails the retention scenario: {rex[min(rfirst, key=rfirst.get)][:200]}")
        print('STATE-PROPS SELF-TEST: FAIL (unmutated reference subject is red)'); return 1
    if viol:
        print(f"  [BROKEN] unmutated reference fails: {ex[min(first, key=first.get)][:200]}")
        print('STATE-PROPS SELF-TEST: FAIL (unmutated reference subject is red)'); return 1
    for label, cmd in cmds:
        adv = {**MUTATIONS, **RETENTION_MUTATIONS} if label == 'reference' else probe_mutations(cmd)
        if label == 'subject':
            lacking = [m for m in REQUIRED_SUBJECT_MUTATIONS if m not in adv]
            if lacking:
                print(f"  [MISSED] subject does not advertise required mutations {lacking} (READY ... mutations=...; got {adv})")
                missed += [f'subject:{m}' for m in lacking]
        for mut, clause, budget, kind in plan:
            if mut not in adv: continue
            n += 1
            stats, viol, first, ex = sweep(cmd, range(1, budget + 1), extra=['--mutate', mut], stop_on=(clause,),
                                           tail=a.tail, kind=kind)
            if clause in first:
                print(f"  [caught] {label}:{mut}: {clause} red at seed {first[clause]} (<= {budget}); {ex[clause][:170]}")
            else:
                print(f"  [MISSED] {label}:{mut}: {clause} not red within {budget} seeds (other: {sorted(first)}; redeliveries observed {stats['redeliveries']})")
                missed.append(f'{label}:{mut}')
    if missed:
        print(f"STATE-PROPS SELF-TEST: FAIL (missed: {', '.join(missed)})"); return 1
    print(f"STATE-PROPS SELF-TEST: PASS ({n}/{n} mutations caught within their seed budgets (10; dedupe-unstable 60): "
          f"{', '.join(list(MUTATIONS) + list(RETENTION_MUTATIONS))}{'; subject-advertised ones too' if a.subject else ''})")
    return 0


if __name__ == '__main__':
    sys.exit(main())
