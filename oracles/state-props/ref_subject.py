#!/usr/bin/env python3
"""Reference subject for oracles/state-props (README "Subject protocol"). Run as `python3 -I ref_subject.py <dir>
[--mutate <name>]...`. Stdlib only: SQLite (WAL, synchronous=FULL, single writer) through the `sqlite3` module.

It is the shape P4-state-002 is expected to take in aegis-state: an idempotency table keyed by (principal, key) whose
outcome row commits in the same transaction as the request's user rows and its outbox rows (NC2 commit point, NC6
outbox), an in-memory in-flight set (pre-CP state is never durable, so a SIGKILL frees the key: NC1), and an outbox
relay that marks a row delivered only after its EFF line was written (at-least-once).

Mutations (self-test; each must turn a clause red):
  idem-key-without-principal  the idempotency key is the client key alone (principal dropped)
  replay-reexecutes           a completed key with the same digest is executed again instead of replayed
  effect-before-commit        EFFECT writes the outbox row immediately (autocommit), before the commit point
  outbox-drop-on-restart      on open, undelivered outbox rows are dropped
  latch-returns-408           a timer after the commit point answers 408 instead of 202
  dedupe-unstable             (extra) a fresh dedupe key on every delivery, so a redelivery carries a new one
"""
import hashlib, os, sqlite3, sys

MUTATIONS = ('idem-key-without-principal', 'replay-reexecutes', 'effect-before-commit', 'outbox-drop-on-restart',
             'latch-returns-408', 'dedupe-unstable')


def out(line):
    sys.stdout.write(line + '\n'); sys.stdout.flush()


def main(argv):
    if len(argv) < 2:
        out('ERR open usage: ref_subject.py <dir> [--mutate <name>]...'); return 2
    d = argv[1]; mut = set()
    i = 2
    while i < len(argv):
        if argv[i] == '--mutate' and i + 1 < len(argv) and argv[i + 1] in MUTATIONS:
            mut.add(argv[i + 1]); i += 2
        else:
            out(f'ERR open bad argument {argv[i]!r}'); return 2
    try:
        db = sqlite3.connect(os.path.join(d, 'state.db'), isolation_level=None)
        if db.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower() != 'wal':
            raise sqlite3.Error('journal_mode=WAL not in effect')
        db.execute('PRAGMA synchronous=FULL')
        db.executescript(
            'CREATE TABLE IF NOT EXISTS idem(principal TEXT NOT NULL, key TEXT NOT NULL, digest TEXT NOT NULL,'
            ' status INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY(principal, key));'
            'CREATE TABLE IF NOT EXISTS rows(k TEXT PRIMARY KEY, v TEXT NOT NULL);'
            'CREATE TABLE IF NOT EXISTS outbox(seq INTEGER PRIMARY KEY AUTOINCREMENT, dedupe TEXT NOT NULL UNIQUE,'
            ' payload TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0);')
        if db.execute('PRAGMA journal_mode').fetchone()[0].lower() != 'wal':
            raise sqlite3.Error('journal_mode=WAL not in effect after the schema write')
        if 'outbox-drop-on-restart' in mut:
            db.execute('DELETE FROM outbox WHERE delivered = 0')       # MUTATION
    except sqlite3.Error as e:
        out(f'ERR open {e}'); return 3
    out('READY state-props reference subject (sqlite3 WAL FULL) mutations=' + ','.join(MUTATIONS))
    inflight = {}      # rid -> {'ik', 'digest', 'writes', 'effects'}
    held = {}          # ik -> rid
    for line in sys.stdin:
        a = line.split()
        if not a: continue
        cmd = a[0]
        if cmd == 'BEGIN' and len(a) == 5:
            rid, p, k, dg = a[1:]
            ik = ('*' if 'idem-key-without-principal' in mut else p, k)          # MUTATION: principal dropped
            if rid in inflight: out(f'ERR {rid} duplicate rid'); continue
            row = db.execute('SELECT digest, status, body FROM idem WHERE principal=? AND key=?', ik).fetchone()
            if row and row[0] != dg: out(f'CONFLICT {rid}'); continue
            if row and 'replay-reexecutes' not in mut: out(f'REPLAY {rid} {row[1]} {row[2]}'); continue
            if ik in held: out(f'INFLIGHT {rid}'); continue
            inflight[rid] = {'ik': ik, 'digest': dg, 'writes': [], 'effects': []}; held[ik] = rid
            out(f'NEW {rid}')
        elif cmd == 'WRITE' and len(a) == 4 and a[1] in inflight:
            inflight[a[1]]['writes'].append((a[2], a[3])); out(f'OK {a[1]}')
        elif cmd == 'EFFECT' and len(a) == 3 and a[1] in inflight:
            r = inflight[a[1]]
            # dedupe key: stable across redelivery, derived from the idempotency key and the effect's position
            dd = hashlib.sha256(f"{r['ik'][0]}\0{r['ik'][1]}\0{len(r['effects'])}".encode()).hexdigest()[:32]
            r['effects'].append((dd, a[2]))
            if 'effect-before-commit' in mut:                                    # MUTATION
                db.execute('INSERT OR IGNORE INTO outbox(dedupe, payload) VALUES(?, ?)', (dd, a[2]))
            out(f'OK {a[1]}')
        elif cmd == 'COMMIT' and len(a) == 5 and a[1] in inflight:
            rid, status, body, timer = a[1], int(a[2]), a[3], a[4] == '1'
            r = inflight.pop(rid); held.pop(r['ik'], None)
            try:
                db.execute('BEGIN IMMEDIATE')
                for k, v in r['writes']:
                    db.execute('INSERT OR REPLACE INTO rows(k, v) VALUES(?, ?)', (k, v))
                db.execute('INSERT OR REPLACE INTO idem(principal, key, digest, status, body) VALUES(?, ?, ?, ?, ?)',
                           (*r['ik'], r['digest'], status, body))
                for dd, pl in r['effects']:
                    db.execute('INSERT OR IGNORE INTO outbox(dedupe, payload) VALUES(?, ?)', (dd, pl))
                db.execute('COMMIT')
            except sqlite3.Error as e:
                out(f'ERR {rid} commit {e}'); return 4                      # fail-stop
            if timer:
                out(f"RESP {rid} {408 if 'latch-returns-408' in mut else 202} -")
            else:
                out(f'RESP {rid} {status} {body}')
        elif cmd == 'ABORT' and len(a) == 2 and a[1] in inflight:
            r = inflight.pop(a[1]); held.pop(r['ik'], None); out(f'OK {a[1]}')
        elif cmd == 'DELIVER':
            for seq, dd, pl in db.execute('SELECT seq, dedupe, payload FROM outbox WHERE delivered = 0 ORDER BY seq').fetchall():
                if 'dedupe-unstable' in mut: dd = dd[:24] + os.urandom(4).hex()          # MUTATION
                out(f'EFF {dd} {pl}')                                            # send first ...
                db.execute('UPDATE outbox SET delivered = 1 WHERE seq = ?', (seq,))   # ... then mark (at-least-once)
            out('END')
        elif cmd == 'DUMP':
            for k, v in db.execute('SELECT k, v FROM rows ORDER BY k').fetchall():
                out(f'ROW {k} {v}')
            out('END')
        elif cmd == 'QUIT':
            break
        else:
            out(f"ERR {a[1] if len(a) > 1 else '-'} bad command {line.strip()[:60]!r}")
    db.close()
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
