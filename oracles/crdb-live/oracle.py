#!/usr/bin/env python3
"""crdb-live: monban-bin with adapter-crdb against a live CockroachDB (unit P8-oracle-001; PREFLIGHT R8). Stdlib only;
run as `python3 -I oracle.py`. Contract and check list: README.md.

The subject serves apps/notes on one CockroachDB backend. The oracle:
- forces serialization failures (40001) with a contention workload: while the subject holds a write inside its open
  transaction (the notes `hold_ms` field), the oracle commits a conflicting write at PRIORITY HIGH, which aborts the
  subject's transaction (ABORT_REASON_ABORT_SPAN at COMMIT, SQLSTATE 40001), and then judges that the subject never
  answered wrong: a 2xx means the durable row is what the subject answered; anything else means no effect;
- blocks one of the subject's statements on a lock the oracle holds, with a short `monban-deadline-ms`, and judges
  that the answer comes within the deadline, that the statement stops running on the server (CancelRequest, or the
  connection closed), that the pooled connection is reset (no open transaction) or retired, and that the pool still
  serves correct answers afterwards.
Durable state, sessions and running queries are read directly from CockroachDB as root, never through the subject.
"""

import argparse
import json
import os
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
NE = os.path.join(REPO, "oracles", "native-e2e")
sys.path.insert(0, NE)
import e2e as ne  # noqa: E402  (F5 minting, the TLS client, Resp)
import wire  # noqa: E402

NAME = "CRDB-LIVE"
MUTANTS = ["crdb-40001-as-success", "crdb-cancel-ignored", "crdb-no-reset"]
VHOST = ne.VHOST
APP_USER = "monban_app"
HOLD_MS = 1200          # the subject holds its write this long inside the open transaction
PUSH_AT = 0.35          # s after the request: the oracle's conflicting PRIORITY HIGH write
PUSH_FAST = 0.8         # s: the conflicting write must commit faster than this (it aborted the subject, not waited)
DEADLINE_MS = 800       # monban-deadline-ms on the request whose statement blocks
DEADLINE_SLACK = 0.7    # s: the answer may come this much after the deadline
SETTLE = 1.0            # s after the answer: the statement must have stopped, the connection reset or retired
LOCK_HOLD = 4.0         # s: how long the oracle holds the lock the subject's statement waits on
OP_BUDGET_MS = 5000
NOTES_DDL = ("CREATE TABLE public.notes (tenant STRING NOT NULL, id STRING NOT NULL, body STRING NOT NULL, "
             "PRIMARY KEY (tenant, id))")
# monban-bin CRDB_IDEM_DDL (crates/monban-bin/src/native/adapters.rs): accepted only in exactly this shape
IDEM_DDL = ("CREATE TABLE public.monban_idem (tenant STRING NOT NULL, principal STRING NOT NULL, "
            "k STRING NOT NULL, status INT8 NOT NULL, body STRING NOT NULL, PRIMARY KEY (principal, k))")
q = wire.pg_quote


def app_dsn(root):
    u = urllib.parse.urlsplit(root)
    host = u.hostname or "127.0.0.1"
    netloc = f"{APP_USER}@{host}" + (f":{u.port}" if u.port else "")
    return urllib.parse.urlunsplit((u.scheme, netloc, u.path or "/defaultdb", u.query, ""))


class Db:
    """Root view of the cluster (CockroachDB `--insecure` loopback throwaway: root needs no password)."""

    def __init__(self, dsn):
        self.dsn = dsn

    def run(self, *stmts):
        c = wire.PgConn(self.dsn)
        try:
            out = None
            for s in stmts:
                out = c.query(s)
            return out
        finally:
            c.close()

    def provision(self):
        self.run("DROP TABLE IF EXISTS public.notes", "DROP TABLE IF EXISTS public.monban_idem",
                 f"DROP USER IF EXISTS {APP_USER}", NOTES_DDL, IDEM_DDL, f"CREATE USER {APP_USER}",
                 f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.notes TO {APP_USER}",
                 f"GRANT SELECT, INSERT ON public.monban_idem TO {APP_USER}")

    def teardown(self):
        try:
            self.run("DROP TABLE IF EXISTS public.notes", "DROP TABLE IF EXISTS public.monban_idem",
                     f"DROP USER IF EXISTS {APP_USER}")
        except (OSError, wire.DbError):
            pass

    def get(self, t, i):
        r = self.run(f"SELECT body FROM public.notes WHERE tenant = {q(f'{t:016x}')} AND id = {q(i)}")
        return r[0][0] if r else None

    def put(self, t, i, b):
        self.run(f"UPSERT INTO public.notes (tenant, id, body) VALUES ({q(f'{t:016x}')}, {q(i)}, {q(b)})")

    def aborts(self):
        r = self.run("SELECT value FROM crdb_internal.node_metrics WHERE name = 'txn.restarts.txnaborted'")
        return int(float(r[0][0])) if r else 0

    def subject_queries(self):
        return self.run(f"SELECT query FROM [SHOW CLUSTER QUERIES] WHERE user_name = {q(APP_USER)}")

    def subject_open_txns(self):
        return self.run(f"SELECT session_id, last_active_query FROM crdb_internal.cluster_sessions "
                        f"WHERE user_name = {q(APP_USER)} AND kv_txn IS NOT NULL")

    def version(self):
        return self.run("SELECT version()")[0][0]


class Run:
    def __init__(self, cmd, dsn, env_extra=None, verbose=False):
        self.cmd, self.db, self.env_extra, self.verbose = cmd, Db(dsn), env_extra or {}, verbose
        self.dir = tempfile.mkdtemp(prefix="monban-crdb-live-")
        self.failures, self.passed, self.notes = [], 0, []
        self.proc = None
        rnd = secrets.SystemRandom()
        self.TA = rnd.randrange(1, 1 << 63)
        self.kid = b"crdb-" + secrets.token_hex(3).encode()
        self.master = secrets.token_bytes(32)
        self.app_dsn = app_dsn(dsn)

    def check(self, name, ok, detail=""):
        if ok:
            self.passed += 1
            if self.verbose:
                print(f"  ok   {name}", flush=True)
        else:
            self.failures.append(name)
            print(f"  FAIL {name}: {detail}", flush=True)
        return ok

    # ---------------------------------------------------------------- subject
    def config(self):
        return {
            "v": 1,
            "listeners": [{"name": "pub", "bind": f"127.0.0.1:{self.port}", "profile": "P-PUBLIC-WEB",
                           "alpn": ["http/1.1"]}],
            "admin": {"bind": f"127.0.0.1:{self.aport}"},
            "data": {"backends": [{"id": "cr", "engine": "crdb", "dsn_ref": "env:AEGIS_E2E_CRDB_DSN", "pin": "crdb",
                                   "op_budget_ms": OP_BUDGET_MS}]},
            "vhosts": [{"host": VHOST, "routes": [
                {"id": 1, "path": "/cr/", "to": {"upstream": "app:notes"}, "authz": "allow-all",
                 "data": [{"backend": "cr", "collection": "notes",
                           "ops": ["select", "insert", "update", "delete", "upsert"], "columns": ["id", "body"]}]}]}],
        }

    def start(self):
        key, crt = os.path.join(self.dir, "key.pem"), os.path.join(self.dir, "cert.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-keyout", key, "-out", crt, "-days", "30", "-subj", f"/CN={VHOST}",
                        "-addext", f"subjectAltName=DNS:{VHOST}"], check=True, capture_output=True, timeout=30)
        kr = os.path.join(self.dir, "token-keyring.json")
        with open(kr, "w") as f:
            json.dump({"keys": [{"kid": self.kid.hex(), "key": self.master.hex()}]}, f)
        os.chmod(kr, 0o600)
        cfg = os.path.join(self.dir, "monban.json")
        with open(cfg, "w") as f:
            json.dump(self.config(), f)
        env = dict(os.environ)
        for k in ("NOTIFY_SOCKET", "AEGIS_UPGRADE_DIR", "AEGIS_E2E_MUTANT"):
            env.pop(k, None)
        env["AEGIS_E2E_CRDB_DSN"] = self.app_dsn
        env.update(self.env_extra)
        os.makedirs(os.path.join(self.dir, "run"), exist_ok=True)
        self.log = open(os.path.join(self.dir, "subject.log"), "ab")
        self.proc = subprocess.Popen(self.cmd + ["--config", cfg, "--cert", crt, "--key", key,
                                                "--audit-dir", os.path.join(self.dir, "audit"),
                                                "--runtime-dir", os.path.join(self.dir, "run"),
                                                "--token-keyring", kr],
                                     stdout=self.log, stderr=subprocess.STDOUT, env=env)
        until = time.time() + 30
        while time.time() < until:
            if self.proc.poll() is not None:
                raise RuntimeError(f"subject exited {self.proc.returncode} at start: {self.tail()}")
            try:
                with socket.create_connection(("127.0.0.1", self.aport), timeout=1) as c:
                    c.sendall(b"GET /healthz HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
                    if c.recv(64).split(b" ")[1:2] == [b"200"]:
                        break
            except OSError:
                pass
            time.sleep(0.1)
        else:
            raise RuntimeError("subject did not become healthy within 30 s")
        self.c = ne.Client(self.port, crt)
        self.tok = ne.mint(self.master, self.kid, self.TA)

    def tail(self):
        try:
            with open(os.path.join(self.dir, "subject.log"), "rb") as f:
                return f.read()[-1500:].decode(errors="replace")
        except OSError:
            return ""

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def run(self):
        try:
            self.db.provision()
            self.port, self.aport = ne.free_port(), ne.free_port()
            self.start()
            self.baseline()
            self.contention()
            self.cancellation()
        except Exception as e:  # noqa: BLE001
            self.check("harness", False, f"{e!r}; subject log: {self.tail()}")
            if self.verbose:
                traceback.print_exc()
        finally:
            self.stop()
            self.db.teardown()
            shutil.rmtree(self.dir, ignore_errors=True)
        return not self.failures

    # ---------------------------------------------------------------- helpers
    def k(self):
        return "k" + secrets.token_hex(8)

    def path(self, nid=""):
        return f"/cr/{self.TA:016x}/{nid}"

    def req(self, method, nid, body=None, key=None, deadline=None):
        return self.c.h1(method, self.path(nid), self.tok, body, key, deadline=deadline)

    @staticmethod
    def body_of(r):
        jj = r.json() if r is not None else None
        return jj.get("body") if isinstance(jj, dict) else None

    # ---------------------------------------------------------------- baseline
    def baseline(self):
        r = self.req("POST", "", {"id": "b1", "body": "one"}, self.k())
        self.check("baseline.insert.201", r.status == 201 and self.db.get(self.TA, "b1") == "one", r)
        r = self.req("GET", "b1")
        self.check("baseline.select.200", r.status == 200 and self.body_of(r) == "one", r)
        r = self.req("PATCH", "b1", {"body": "two"}, self.k())
        self.check("baseline.update.200", r.status == 200 and self.db.get(self.TA, "b1") == "two", r)

    # ---------------------------------------------------------------- 40001 under contention
    def push(self, stmt):
        """The oracle's conflicting write, committed at PRIORITY HIGH. Returns its duration (s) or the error."""
        c = wire.PgConn(self.db.dsn)
        t = time.monotonic()
        try:
            c.query("BEGIN TRANSACTION PRIORITY HIGH")
            c.query(stmt)
            c.query("COMMIT")
            return time.monotonic() - t
        except wire.DbError as e:
            return f"error {e.args}"
        finally:
            c.close()

    def contended(self, name, method, nid, body, stmt):
        """Send the subject's write with a hold, push the conflicting write at PUSH_AT, return (response, push
        result, key)."""
        key, res = self.k(), {}
        b = dict(body or {}, hold_ms=HOLD_MS)
        th = threading.Thread(target=lambda: res.setdefault("r", self.req(method, nid, b, key)))
        th.start()
        time.sleep(PUSH_AT)
        pushed = self.push(stmt)
        th.join(30)
        r = res.get("r")
        self.check(f"contention.{name}.forced-abort", isinstance(pushed, float) and pushed < PUSH_FAST,
                   f"the PRIORITY HIGH write took {pushed} (it must abort the subject's open transaction, not wait)")
        return r, key

    def contention(self):
        ta = self.TA
        a0 = self.db.aborts()
        rounds = 0
        upd = lambda nid, v: (f"UPDATE public.notes SET body = {q(v)} WHERE tenant = {q(f'{ta:016x}')} "  # noqa: E731
                              f"AND id = {q(nid)}")
        for name, method in (("update", "PATCH"), ("upsert", "PUT")):
            for i in range(2):
                nid = f"c-{name}-{i}"
                self.db.put(ta, nid, "seed")
                mine, theirs = f"subject-{name}-{i}", f"oracle-{name}-{i}"
                r, key = self.contended(f"{name}{i}", method, nid, {"body": mine}, upd(nid, theirs))
                rounds += 1
                time.sleep(0.2)
                row = self.db.get(ta, nid)
                self.judge(f"{name}{i}", r, row, mine, theirs)
                self.replay(f"{name}{i}", r, method, nid, {"body": mine}, key, mine)
        # delete: answered 200 only if the row is gone
        nid = "c-delete"
        self.db.put(ta, nid, "seed")
        r, key = self.contended("delete", "DELETE", nid, None, upd(nid, "oracle-delete"))
        rounds += 1
        time.sleep(0.2)
        row = self.db.get(ta, nid)
        ok = r is not None and ((r.status == 200 and row is None) or
                                (r.status is not None and not 200 <= r.status < 300 and row == "oracle-delete"))
        self.check("contention.delete.never-wrong", ok, f"answered {r}, durable row {row!r}")
        # insert: the oracle inserts the same (tenant, id) first; a 201 would be a stale answer
        nid = "c-insert"
        r, key = self.contended("insert", "POST", "", {"id": nid, "body": "subject-insert"},
                                f"INSERT INTO public.notes (tenant, id, body) VALUES ({q(f'{ta:016x}')}, {q(nid)}, "
                                f"'oracle-insert')")
        rounds += 1
        time.sleep(0.2)
        row = self.db.get(ta, nid)
        ok = r is not None and r.status is not None and ((r.status == 201 and row == "subject-insert") or
                                                         (not 200 <= r.status < 300 and row == "oracle-insert"))
        self.check("contention.insert.never-wrong", ok and not (r.status == 201 and row != "subject-insert"),
                   f"answered {r}, durable row {row!r}")
        time.sleep(0.5)
        aborted = self.db.aborts() - a0
        # Each round's forced-abort check already shows that round's transaction was aborted (the PRIORITY HIGH write
        # committed over the subject's live intent). The server-side counter confirms 40001s were produced at all; it
        # is not per-round exact (CockroachDB files some aborts under other txn.restarts.* reasons).
        self.check("contention.produced-40001", aborted >= 1,
                   f"txn.restarts.txnaborted rose by {aborted} over {rounds} contended requests")
        self.notes.append(f"{aborted} transaction aborts forced over {rounds} contended writes")

    def judge(self, name, r, row, mine, theirs):
        if r is None or r.status is None:
            self.check(f"contention.{name}.never-wrong", False, f"no response ({r}), durable row {row!r}")
            return
        if 200 <= r.status < 300:
            self.check(f"contention.{name}.never-wrong", row == mine and self.body_of(r) == mine,
                       f"answered {r} but the durable row is {row!r} (a 2xx must mean the answered write is durable)")
        else:
            self.check(f"contention.{name}.never-wrong", row == theirs,
                       f"answered {r.status} (no effect allowed) but the durable row is {row!r}")

    def replay(self, name, r, method, nid, body, key, mine):
        """INV-IDEMP after a contended request: a 2xx is latched (the replay returns it); a failure before CP is
        not, so the replay executes now (no contention) and succeeds."""
        if r is None or r.status is None:
            return
        r2 = self.req(method, nid, body, key)
        if 200 <= r.status < 300:
            self.check(f"contention.{name}.replay-latched", (r2.status, r2.body) == (r.status, r.body), (r, r2))
        else:
            self.check(f"contention.{name}.replay-executes", r2.status == 200 and self.db.get(self.TA, nid) == mine,
                       (r, r2, self.db.get(self.TA, nid)))

    # ---------------------------------------------------------------- CancelRequest on a slow statement
    def cancellation(self):
        ta = f"{self.TA:016x}"
        for name, method, body in (("update", "PATCH", {"body": "subject-late"}), ("select", "GET", None)):
            nid = f"x-{name}"
            self.db.put(self.TA, nid, "pre")
            lock = wire.PgConn(self.db.dsn)
            try:
                lock.query("BEGIN")
                lock.query(f"UPDATE public.notes SET body = 'locked' WHERE tenant = {q(ta)} AND id = {q(nid)}")
                t0 = time.monotonic()
                r = self.req(method, nid, body, self.k() if method != "GET" else None, deadline=DEADLINE_MS)
                took = time.monotonic() - t0
                self.check(f"cancel.{name}.answer-within-deadline",
                           r is not None and r.status == 504 and took <= DEADLINE_MS / 1000 + DEADLINE_SLACK,
                           f"answered {r} after {took:.2f} s (deadline {DEADLINE_MS} ms + {DEADLINE_SLACK} s slack, "
                           f"504 expected while the row is locked)")
                time.sleep(max(0.0, DEADLINE_MS / 1000 + SETTLE - took))
                running = self.db.subject_queries()
                self.check(f"cancel.{name}.statement-stopped", not running,
                           f"still running on the server {SETTLE} s after the answer: {running}")
                open_txns = self.db.subject_open_txns()
                self.check(f"cancel.{name}.connection-reset-or-retired", not open_txns,
                           f"subject sessions with an open transaction: {open_txns}")
                time.sleep(max(0.0, LOCK_HOLD - (time.monotonic() - t0)))
            finally:
                try:
                    lock.query("ROLLBACK")
                finally:
                    lock.close()
            time.sleep(SETTLE)
            self.check(f"cancel.{name}.no-late-effect", self.db.get(self.TA, nid) == "pre",
                       f"durable row {self.db.get(self.TA, nid)!r} after the lock was released")
            bad = []
            for i in range(6):
                v = f"after-{name}-{i}"
                r1 = self.req("PATCH", nid, {"body": v}, self.k())
                r2 = self.req("GET", nid)
                if not (r1.status == 200 and r2.status == 200 and self.body_of(r2) == v):
                    bad.append((i, r1, r2))
            self.check(f"cancel.{name}.pool-serves-after", not bad, f"wrong answers after the cancel: {bad[:2]}")


# ------------------------------------------------------------------------------------------------ main
def subject_cmd(s):
    if s.endswith(".py"):
        return [sys.executable, "-I", os.path.abspath(s)]
    parts = shlex.split(s)
    parts[0] = os.path.abspath(parts[0]) if os.path.exists(parts[0]) else parts[0]
    return parts


def summary(r):
    return f"{r.passed} checks" + ("; " + "; ".join(r.notes) if r.notes else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", required=True, help="CockroachDB root DSN (inside ci/engines.sh with crdb: @crdb)")
    ap.add_argument("--binary", "--subject", dest="binary", default=None,
                    help="monban built with --features adapter-crdb (default: the reference, native-e2e/ref_subject.py)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    if not a.dsn.startswith(("postgresql://", "postgres://")):
        print(f"{NAME}: FAIL (--dsn must be postgresql://...)")
        return 1
    try:
        ver = Db(a.dsn).version()
    except (OSError, wire.DbError) as e:
        print(f"{NAME}: FAIL (cannot reach CockroachDB at --dsn: {e})")
        return 1
    if "CockroachDB" not in ver:
        print(f"{NAME}: FAIL (--dsn is not CockroachDB: {ver[:60]})")
        return 1
    ref = os.path.join(NE, "ref_subject.py")
    if not a.self_test:
        if a.binary and not os.access(a.binary, os.X_OK):
            print(f"{NAME}: FAIL (binary {a.binary} is absent or not executable)")
            return 1
        if not a.binary:
            print("subject: reference (oracles/native-e2e/ref_subject.py)")
        r = Run(subject_cmd(a.binary or ref), a.dsn, verbose=a.verbose)
        if r.run():
            print(f"{NAME}: PASS ({summary(r)}; {ver.split(' (')[0]})")
            return 0
        print(f"{NAME}: FAIL ({len(r.failures)} failed: {', '.join(r.failures[:10])})")
        return 1
    r = Run(subject_cmd(ref), a.dsn, verbose=a.verbose)
    if not r.run():
        print(f"{NAME} SELF-TEST: FAIL (the reference must pass first: {r.failures[:6]})")
        return 1
    print(f"  reference: PASS ({summary(r)})", flush=True)
    caught = []
    for m in MUTANTS:
        rr = Run(subject_cmd(ref), a.dsn, env_extra={"AEGIS_E2E_MUTANT": m})
        if rr.run():
            print(f"{NAME} SELF-TEST: FAIL (mutant {m} was not caught)")
            return 1
        print(f"  mutant {m}: caught by {len(rr.failures)} checks, e.g. {', '.join(rr.failures[:5])}", flush=True)
        caught.append(m)
    print(f"{NAME} SELF-TEST: PASS (reference green; {len(caught)}/{len(MUTANTS)} mutants caught: {', '.join(caught)}; "
          f"{ver.split(' (')[0]})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
