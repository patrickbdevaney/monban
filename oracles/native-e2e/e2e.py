#!/usr/bin/env python3
"""native-e2e: black-box oracle for native handlers + data plane (IMPLEMENTATION_PLAN §7 modes A and D).

Boots a subject (the reference `ref_subject.py`, or aegis via --subject) with an oracle-written F8 config that binds
apps/notes routes to SQLite (always), PostgreSQL (--pg) and Valkey/Redis (--kv) backends, mints F5 Tier-L tokens
for two random tenants, drives the subject over TLS (HTTP/1.1, and HTTP/2 for RST_STREAM), and judges every
outcome against durable state read directly from the engines. Contract and check list: README.md.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import random
import secrets
import shlex
import shutil
import signal
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import wire  # noqa: E402

NAME = "NATIVE-E2E"
MUTANTS = ["tenant-from-path", "commit-despite-cancel", "body-before-cp", "empty-caps-means-all", "no-drain",
           "ack-then-drop"]
VHOST = "aegis.test"
HOLD = 1.2        # s: hold_ms the app sleeps inside the open transaction (before CP) or after CP
CUT = 0.35        # s: when the client cancels after sending the request
SETTLE = 1.0      # s: after the hold ends, before inspecting durable state
DEADLINE_MS = 400
T_DRAIN = 10.0    # s: NC8 bound from SIGTERM to process exit
OP_BUDGET_MS = 5000
NC7_SLACK = 0.15  # s: first response byte may precede the end of the hold by at most this (scheduling slack)
MISSING = "zz-none"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def j(obj):
    return json.dumps(obj, separators=(",", ":")).encode()


# ------------------------------------------------------------------------------------------------ F5 Tier-L minting


def cbor(v):
    def head(mt, n):
        if n < 24:
            return bytes([(mt << 5) | n])
        for ai, w in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * w):
                return bytes([(mt << 5) | ai]) + n.to_bytes(w, "big")
        raise ValueError(n)
    if isinstance(v, bool):
        raise TypeError("bool")
    if isinstance(v, int):
        return head(0, v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    return head(4, len(v)) + b"".join(cbor(x) for x in v)


def hkdf_k_aud(master, aud, kid):
    """F5: K_aud = HKDF-SHA256(ikm=K, salt="", info="aegis-cap-v1" || be16|aud| || aud || be16|kid| || kid)."""
    prk = hmac.new(b"", master, hashlib.sha256).digest()
    a = aud.encode()
    info = b"aegis-cap-v1" + struct.pack("!H", len(a)) + a + struct.pack("!H", len(kid)) + kid
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def mint(master, kid, tenant, aud=VHOST, ops=31, exp_delta=600, with_tenant=True, tamper=False):
    now = int(time.time())
    nonce = secrets.token_bytes(16)
    cavs = [[0, aud], [1, now + exp_delta], [8, 2], [3, ops]]
    if with_tenant:
        cavs.append([6, tenant])
    t = hmac.new(hkdf_k_aud(master, aud, kid), kid + nonce, hashlib.sha256).digest()
    for c in cavs:
        t = hmac.new(t, cbor(c), hashlib.sha256).digest()
    if tamper:
        t = t[:-1] + bytes([t[-1] ^ 1])
    raw = cbor([1, kid, nonce, cavs, t])
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# ------------------------------------------------------------------------------------------------ durable state


# PostgreSQL provisioning (P4-oracle-schema-001 / R-DB-7 live schema gate). The table must pass
# aegis_adapter_pg::check_live_schema: tenant text COLLATE "C", (tenant, id) the only unique index, ENABLE + FORCE
# ROW LEVEL SECURITY, and permissive policies whose USING and WITH CHECK are exactly the tenant guard. The policy is
# the statement list of aegis_adapter_pg::rls_policy(Some("public"), "notes", "tenant", "aegis_app", "aegis.tenant").
# The role and the setting are aegis-bin's fixed names (PG_RLS_ROLE / PG_TENANT_SETTING). The role is a plain login
# role: NOSUPERUSER, NOBYPASSRLS, owns nothing (every table is owned by the provisioning superuser, so the role
# cannot ALTER ... NO FORCE ROW LEVEL SECURITY), no CREATE on any schema.
PG_ROLE = "aegis_app"
PG_SETTING = "aegis.tenant"
PG_GUARD = f"(\"tenant\" = current_setting('{PG_SETTING}', true) COLLATE \"C\")"


def pg_rls_policy(table):
    t = f'"public"."{table}"'
    return [f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY",
            f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY",
            f'CREATE POLICY aegis_tenant ON {t} AS PERMISSIVE FOR ALL TO "{PG_ROLE}" USING {PG_GUARD} '
            f"WITH CHECK {PG_GUARD}"]


def pg_teardown():
    # DROP OWNED also revokes the role's grants and removes anything a previous (crashed) subject left behind.
    return ['DROP TABLE IF EXISTS "public"."notes", "public"."aegis_idem"',
            f'DO $$BEGIN IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = {wire.pg_quote(PG_ROLE)}) THEN '
            f'DROP OWNED BY "{PG_ROLE}"; DROP ROLE "{PG_ROLE}"; END IF; END$$']


def pg_provision(password):
    return pg_teardown() + [
        f'CREATE ROLE "{PG_ROLE}" LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT '
        f"PASSWORD {wire.pg_quote(password)}",
        'CREATE TABLE "public"."notes"(tenant text COLLATE "C" NOT NULL, id text COLLATE "C" NOT NULL, '
        "body text NOT NULL, PRIMARY KEY (tenant, id))",
        *pg_rls_policy("notes"),
        f'GRANT SELECT, INSERT, UPDATE, DELETE ON "public"."notes" TO "{PG_ROLE}"',
        # aegis-bin's in-band idempotency table (D14). A subject creates it at boot only if it is missing, which
        # would need CREATE on public and would make the RLS role its owner; provisioned here by the superuser
        # instead, under the same RLS shape. A subject that keeps idempotency elsewhere ignores it.
        'CREATE TABLE "public"."aegis_idem"(tenant text COLLATE "C" NOT NULL, principal text COLLATE "C" NOT NULL, '
        'k text COLLATE "C" NOT NULL, status integer NOT NULL, body text NOT NULL, PRIMARY KEY (principal, k))',
        *pg_rls_policy("aegis_idem"),
        f'GRANT SELECT, INSERT ON "public"."aegis_idem" TO "{PG_ROLE}"',
    ]


def pg_role_dsn(dsn, user, password):
    u = urllib.parse.urlsplit(dsn)
    host = u.hostname or "127.0.0.1"
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{urllib.parse.quote(user, safe='')}:{urllib.parse.quote(password, safe='')}@{host}"
    if u.port:
        netloc += f":{u.port}"
    return urllib.parse.urlunsplit((u.scheme, netloc, u.path, u.query, u.fragment))


class Store:
    """Direct view of one backend's durable rows (never through the subject)."""

    def __init__(self, bid, engine, target):
        self.bid, self.engine, self.target = bid, engine, target
        self.app_dsn = None
        if engine == "postgres":
            # `target` is the superuser DSN: provisioning and the oracle's own reads (a superuser is never subject to
            # RLS). The subject gets `app_dsn`, which logs in as the RLS role with a fresh per-run password.
            self.app_pw = secrets.token_hex(16)
            self.app_dsn = pg_role_dsn(target, PG_ROLE, self.app_pw)

    def setup(self):
        if self.engine == "sqlite":
            c = sqlite3.connect(self.target, isolation_level=None)
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("CREATE TABLE notes(tenant TEXT NOT NULL COLLATE BINARY, id TEXT NOT NULL COLLATE BINARY, "
                      "body TEXT NOT NULL, PRIMARY KEY(tenant, id)) WITHOUT ROWID")
            c.close()
        elif self.engine == "postgres":
            c = wire.PgConn(self.target)
            try:
                for q in pg_provision(self.app_pw):
                    c.query(q)
                # The oracle's own precondition: the subject's login role can bypass nothing.
                r = c.query(f"SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_catalog.pg_roles "
                            f"WHERE rolname = {wire.pg_quote(PG_ROLE)}")
                if r != [["f", "f", "t"]]:
                    raise wire.DbError(f"role {PG_ROLE} provisioned wrongly: {r!r}")
            finally:
                c.close()
        else:
            wire.KvConn(self.target).close()

    def get(self, t, i):
        th = f"{t:016x}"
        if self.engine == "sqlite":
            c = sqlite3.connect(self.target, timeout=10)
            try:
                r = c.execute("SELECT body FROM notes WHERE tenant=? AND id=?", (th, i)).fetchone()
            finally:
                c.close()
            return r[0] if r else None
        if self.engine == "postgres":
            c = wire.PgConn(self.target)
            try:
                r = c.query(f"SELECT body FROM notes WHERE tenant={wire.pg_quote(th)} AND id={wire.pg_quote(i)}")
            finally:
                c.close()
            return r[0][0] if r else None
        c = wire.KvConn(self.target)
        try:
            return c.cmd("GET", f"t:{{{th}}}:notes:{i}")
        finally:
            c.close()

    def cleanup(self, tenants):
        try:
            if self.engine == "postgres":
                c = wire.PgConn(self.target)
                for q in pg_teardown():
                    c.query(q)
                c.close()
            elif self.engine in ("valkey", "redis"):
                c = wire.KvConn(self.target)
                for t in tenants:
                    keys = c.cmd("KEYS", f"t:{{{t:016x}}}:*") or []
                    if keys:
                        c.cmd("DEL", *keys)
                c.close()
        except (OSError, wire.DbError):
            pass


# ------------------------------------------------------------------------------------------------ clients


class Resp:
    def __init__(self, status, headers, body, t_first):
        self.status, self.headers, self.body, self.t_first = status, headers, body, t_first

    def json(self):
        try:
            return json.loads(self.body)
        except ValueError:
            return None

    def __repr__(self):
        return f"<{self.status} {self.body[:120]!r}>"


class Client:
    def __init__(self, port, cafile):
        self.port = port
        self.ctx1 = ssl.create_default_context(cafile=cafile)
        self.ctx1.set_alpn_protocols(["http/1.1"])
        self.ctx2 = ssl.create_default_context(cafile=cafile)
        self.ctx2.set_alpn_protocols(["h2"])

    def h1(self, method, path, token=None, body=None, key=None, deadline=None, cut=None, rst=False,
           on_first=None, timeout=20, extra=()):
        """One request on a fresh TLS connection. cut=s: cancel s seconds after sending (FIN, or TCP RST if rst);
        returns None then. on_first(t) runs when the first response byte arrives (t since the request was sent)."""
        raw = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        s = self.ctx1.wrap_socket(raw, server_hostname=VHOST)
        data = j(body) if isinstance(body, dict) else (body or b"")
        h = [f"{method} {path} HTTP/1.1", f"host: {VHOST}", "connection: close", f"content-length: {len(data)}"]
        if body is not None:
            h.append("content-type: application/json")
        if token:
            h.append(f"authorization: Bearer {token}")
        if key:
            h.append(f"idempotency-key: {key}")
        if deadline is not None:
            h.append(f"aegis-deadline-ms: {deadline}")
        h += list(extra)
        t0 = time.monotonic()
        s.sendall(("\r\n".join(h) + "\r\n\r\n").encode() + data)
        if cut is not None:
            time.sleep(cut)
            if rst:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                s.close()
            else:
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                s.close()
            return None
        buf, t_first = b"", None
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    break
                if t_first is None:
                    t_first = time.monotonic() - t0
                    if on_first:
                        on_first(t_first)
                buf += d
                if b"\r\n\r\n" in buf:
                    head, rest = buf.split(b"\r\n\r\n", 1)
                    cl = [ln for ln in head.split(b"\r\n") if ln.lower().startswith(b"content-length:")]
                    if cl and len(rest) >= int(cl[0].split(b":", 1)[1]):
                        break
        except (OSError, ssl.SSLError):
            pass
        finally:
            s.close()
        if b"\r\n\r\n" not in buf:
            return Resp(None, {}, b"", t_first)
        head, rest = buf.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        try:
            status = int(lines[0].split(" ")[1])
        except (IndexError, ValueError):
            status = None
        hdrs = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()
        return Resp(status, hdrs, rest, t_first)

    def h2(self, method, path, token, body, key, rst_after=None, keep_open=0.0, timeout=20):
        """One HTTP/2 stream (HPACK literals without indexing, no Huffman). rst_after=s: RST_STREAM(CANCEL) s seconds
        after sending, keeping the connection open keep_open more seconds (a stream-level cancel, not a disconnect).
        Returns 'no-h2' | 'reset' | 'timeout' | 'closed-without-response' | 'complete:<response DATA bytes>' (HPACK response headers are not
        decoded; the body and the durable row are what is judged)."""
        raw = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        s = self.ctx2.wrap_socket(raw, server_hostname=VHOST)
        if s.selected_alpn_protocol() != "h2":
            s.close()
            return "no-h2"
        s = wire.LockedTLS(s, timeout)
        ended = []
        wl = threading.Lock()
        done = threading.Event()
        got = []

        def frame(ftype, flags, sid, payload=b""):
            with wl:
                s.sendall(struct.pack("!I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack("!I", sid)
                          + payload)

        def reader():
            try:
                buf = b""
                while True:
                    while len(buf) < 9:
                        d = s.recv(65536)
                        if not d:
                            return
                        buf += d
                    ln = int.from_bytes(buf[:3], "big")
                    while len(buf) < 9 + ln:
                        d = s.recv(65536)
                        if not d:
                            return
                        buf += d
                    ftype, flags, sid = buf[3], buf[4], int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
                    payload, buf = buf[9:9 + ln], buf[9 + ln:]
                    if ftype == 4 and not flags & 1:
                        frame(4, 1, 0)
                    elif ftype == 6 and not flags & 1:
                        frame(6, 1, 0, payload)
                    elif sid == 1 and ftype in (0, 1):
                        if ftype == 0:
                            got.append(payload)
                        if flags & 1:
                            ended.append(True)
                            done.set()
                    elif (sid == 1 and ftype == 3) or ftype == 7:
                        done.set()
            except (OSError, ssl.SSLError, ValueError):
                pass
            finally:
                done.set()

        data = j(body)
        hdrs = [(":method", method), (":scheme", "https"), (":authority", VHOST), (":path", path),
                ("content-type", "application/json"), ("content-length", str(len(data))),
                ("authorization", f"Bearer {token}"), ("idempotency-key", key)]
        block = b"".join(hp_lit(k, v) for k, v in hdrs)
        th = threading.Thread(target=reader, daemon=True)
        try:
            s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            frame(4, 0, 0)
            th.start()
            frame(1, 0x4, 1, block)
            frame(0, 0x1, 1, data)
            if rst_after is not None:
                time.sleep(rst_after)
                frame(3, 0, 1, struct.pack("!I", 0x8))
                time.sleep(keep_open)
                return "reset"
            if not done.wait(timeout):
                return "timeout"
            if not ended:
                return "closed-without-response"
            return "complete:" + b"".join(got).decode(errors="replace")
        except (OSError, ssl.SSLError):
            return "reset" if rst_after is not None else "timeout"
        finally:
            s.close()


def hp_lit(k, v):
    def s(x):
        x = x.encode()
        n = len(x)
        if n < 127:
            return bytes([n]) + x
        out, n = [127], n - 127
        while n >= 128:
            out.append((n & 0x7F) | 0x80)
            n >>= 7
        out.append(n)
        return bytes(out) + x
    return b"\x00" + s(k) + s(v)


# ------------------------------------------------------------------------------------------------ the run


class Run:
    def __init__(self, cmd, pg=None, kv=None, env_extra=None, verbose=False):
        self.cmd = cmd
        self.env_extra = env_extra or {}
        self.verbose = verbose
        self.lock = threading.Lock()
        self.failures, self.passed, self.notes = [], 0, []
        self.dir = tempfile.mkdtemp(prefix="aegis-native-e2e-")
        self.proc = None
        rnd = random.SystemRandom()
        self.TA = rnd.randrange(1, 1 << 63) | 1
        self.TB = self.TA + 1  # adjacent tenants: same text prefix up to the last digit
        self.TC = rnd.randrange(1, 1 << 64)
        self.kid = b"ne2e-" + secrets.token_hex(3).encode()
        self.master = secrets.token_bytes(32)
        self.stores = {"sq": Store("sq", "sqlite", os.path.join(self.dir, "notes.db"))}
        self.backends = [{"id": "sq", "engine": "sqlite", "dsn_ref": f"path:{self.stores['sq'].target}",
                          "pin": "sqlite", "op_budget_ms": OP_BUDGET_MS}]
        self.env = {}
        if pg:
            self.stores["pg"] = Store("pg", "postgres", pg)
            self.backends.append({"id": "pg", "engine": "postgres", "dsn_ref": "env:AEGIS_E2E_PG_DSN",
                                  "pin": pg_pin(pg), "op_budget_ms": OP_BUDGET_MS})
            self.env["AEGIS_E2E_PG_DSN"] = self.stores["pg"].app_dsn  # the RLS role, never the superuser
        if kv:
            eng = kv_engine(kv)
            self.stores["kv"] = Store("kv", eng, kv)
            self.backends.append({"id": "kv", "engine": eng, "dsn_ref": "env:AEGIS_E2E_KV_URL", "pin": eng,
                                  "op_budget_ms": OP_BUDGET_MS})
            self.env["AEGIS_E2E_KV_URL"] = kv

    # ---------------------------------------------------------------- bookkeeping
    def check(self, name, ok, detail=""):
        with self.lock:
            if ok:
                self.passed += 1
                if self.verbose:
                    print(f"  ok   {name}", flush=True)
            else:
                self.failures.append(name)
                print(f"  FAIL {name}: {detail}", flush=True)
        return ok

    def note(self, s):
        with self.lock:
            self.notes.append(s)

    # ---------------------------------------------------------------- subject
    def cert(self):
        if not shutil.which("openssl"):
            raise RuntimeError("openssl CLI not found (needed to mint the test certificate)")
        self.key_pem, self.crt = os.path.join(self.dir, "key.pem"), os.path.join(self.dir, "cert.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-keyout", self.key_pem, "-out", self.crt, "-days", "30", "-subj", f"/CN={VHOST}",
                        "-addext", f"subjectAltName=DNS:{VHOST}"], check=True, capture_output=True, timeout=30)

    def keyring(self):
        p = os.path.join(self.dir, "token-keyring.json")
        with open(p, "w") as f:
            json.dump({"keys": [{"kid": self.kid.hex(), "key": self.master.hex()}]}, f)
        os.chmod(p, 0o600)
        return p

    def config(self, mutate=None):
        caps = lambda b, ops: [{"backend": b, "collection": "notes", "ops": ops,  # noqa: E731
                                "columns": ["id", "body"]}]
        allops = ["select", "insert", "update", "delete", "upsert"]
        routes, rid = [], 1
        for b in self.backends:
            routes.append({"id": rid, "path": f"/{b['id']}/", "to": {"upstream": "app:notes"}, "authz": "allow-all",
                           "data": caps(b["id"], allops)})
            rid += 1
        routes.append({"id": 90, "path": "/nocap/", "to": {"upstream": "app:notes"}, "authz": "allow-all"})
        routes.append({"id": 91, "path": "/ro/", "to": {"upstream": "app:notes"}, "authz": "allow-all",
                       "data": caps("sq", ["select"])})
        doc = {
            "v": 1,
            "listeners": [{"name": "pub", "bind": f"127.0.0.1:{self.port}", "profile": "P-PUBLIC-WEB",
                           "alpn": ["h2", "http/1.1"]}],
            "admin": {"bind": f"127.0.0.1:{self.aport}"},
            "data": {"backends": self.backends},
            "vhosts": [{"host": VHOST, "routes": routes}],
        }
        if mutate:
            mutate(doc)
        return doc

    def argv(self, cfg_path):
        return self.cmd + ["--config", cfg_path, "--cert", self.crt, "--key", self.key_pem,
                           "--audit-dir", os.path.join(self.dir, "audit"),
                           "--runtime-dir", os.path.join(self.dir, "run"),
                           "--token-keyring", self.kr]

    def subject_env(self):
        env = dict(os.environ)
        for k in ("NOTIFY_SOCKET", "AEGIS_UPGRADE_DIR", "AEGIS_E2E_MUTANT"):
            env.pop(k, None)
        env.update(self.env)
        env.update(self.env_extra)
        return env

    def start(self):
        os.makedirs(os.path.join(self.dir, "run"), exist_ok=True)
        self.log = open(os.path.join(self.dir, "subject.log"), "ab")
        self.proc = subprocess.Popen(self.argv(self.cfg_path), stdout=self.log, stderr=subprocess.STDOUT,
                                     env=self.subject_env())
        until = time.time() + 30
        while time.time() < until:
            if self.proc.poll() is not None:
                raise RuntimeError(f"subject exited {self.proc.returncode} at start: {self.tail()}")
            try:
                with socket.create_connection(("127.0.0.1", self.aport), timeout=1) as c:
                    c.sendall(b"GET /healthz HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
                    if c.recv(64).split(b" ")[1:2] == [b"200"]:
                        return
            except OSError:
                pass
            time.sleep(0.1)
        raise RuntimeError("subject did not become healthy within 30 s")

    def tail(self):
        try:
            with open(os.path.join(self.dir, "subject.log"), "rb") as f:
                return f.read()[-1500:].decode(errors="replace")
        except OSError:
            return ""

    def kill(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(15)
            except subprocess.TimeoutExpired:
                self.kill()

    # ---------------------------------------------------------------- driver
    def run(self):
        try:
            self.cert()
            self.kr = self.keyring()
            self.port, self.aport = free_port(), free_port()
            for st in self.stores.values():
                st.setup()
            self.cfg_path = os.path.join(self.dir, "aegis.json")
            with open(self.cfg_path, "w") as f:
                json.dump(self.config(), f)
            self.boot_checks()
            self.start()
            self.c = Client(self.port, self.crt)
            self.tok = {t: mint(self.master, self.kid, t) for t in (self.TA, self.TB)}
            self.tok_ro = mint(self.master, self.kid, self.TA, ops=1)
            threads, errs = [], []
            for bid in self.stores:
                def suite(bid=bid):
                    try:
                        self.backend_suite(bid)
                    except Exception as e:  # noqa: BLE001
                        errs.append(f"{bid}: {e!r}")
                        if self.verbose:
                            traceback.print_exc()
                threads.append(threading.Thread(target=suite))
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            for e in errs:
                self.check(f"suite-error {e}", False, e)
            self.cap_suite()
            self.drain_suite()
        except Exception as e:  # noqa: BLE001
            self.check("harness", False, f"{e!r}; subject log: {self.tail()}")
            if self.verbose:
                traceback.print_exc()
        finally:
            self.kill()
            for st in self.stores.values():
                st.cleanup([self.TA, self.TB, self.TC])
            shutil.rmtree(self.dir, ignore_errors=True)
        return not self.failures

    # ---------------------------------------------------------------- boot (INV-NONEMPTY, fail closed)
    def boot_refused(self, name, mutate):
        p = os.path.join(self.dir, f"bad-{name}.json")
        with open(p, "w") as f:
            json.dump(self.config(mutate), f)
        proc = subprocess.Popen(self.argv(p), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env=self.subject_env())
        listened = False
        until = time.time() + 10
        while time.time() < until and proc.poll() is None:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                listened = True
            except OSError:
                pass
            time.sleep(0.05)
        if proc.poll() is None:
            proc.kill()
            proc.wait()
            return self.check(f"boot.{name}.exit78", False, "subject booted")
        self.check(f"boot.{name}.exit78", proc.returncode == 78, f"exit {proc.returncode}")
        self.check(f"boot.{name}.never-listened", not listened, "accepted a connection")

    def boot_checks(self):
        def empty_caps(d):
            d["vhosts"][0]["routes"][0]["data"] = []

        def undeclared(d):
            d["vhosts"][0]["routes"][0]["data"][0]["backend"] = "nope"

        self.boot_refused("empty-data-list", empty_caps)
        self.boot_refused("undeclared-backend", undeclared)

    # ---------------------------------------------------------------- per-backend suite
    def backend_suite(self, bid):
        st, c, P = self.stores[bid], self.c, f"/{bid}/"
        TA, TB, TC = self.TA, self.TB, self.TC
        ta, tb, tc = f"{TA:016x}", f"{TB:016x}", f"{TC:016x}"
        A, B = self.tok[TA], self.tok[TB]
        k = lambda: "k" + secrets.token_hex(8)  # noqa: E731
        n = lambda s: f"{bid}-{s}"  # noqa: E731

        def ok_note(r, nid, body, status):
            jj = r.json() if r else None
            return r is not None and r.status == status and isinstance(jj, dict) and jj.get("id") == nid \
                and jj.get("body") == body

        # --- own-tenant CRUD, checked against durable rows
        r = c.h1("POST", f"{P}{ta}/", A, {"id": n("n1"), "body": "a1"}, k())
        self.check(f"{bid}.crud.insert.201", ok_note(r, n("n1"), "a1", 201), r)
        self.check(f"{bid}.crud.insert.durable", st.get(TA, n("n1")) == "a1", st.get(TA, n("n1")))
        r = c.h1("GET", f"{P}{ta}/{n('n1')}", A)
        self.check(f"{bid}.crud.select.200", ok_note(r, n("n1"), "a1", 200), r)
        r = c.h1("POST", f"{P}{ta}/", A, {"id": n("n1"), "body": "dup"}, k())
        self.check(f"{bid}.crud.insert-dup.409", r.status == 409 and st.get(TA, n("n1")) == "a1", r)
        r = c.h1("PATCH", f"{P}{ta}/{n('n1')}", A, {"body": "a2"}, k())
        self.check(f"{bid}.crud.update.200", ok_note(r, n("n1"), "a2", 200) and st.get(TA, n("n1")) == "a2", r)
        r = c.h1("PUT", f"{P}{ta}/{n('n2')}", A, {"body": "u1"}, k())
        self.check(f"{bid}.crud.upsert-new.200", ok_note(r, n("n2"), "u1", 200) and st.get(TA, n("n2")) == "u1", r)
        r = c.h1("PUT", f"{P}{ta}/{n('n2')}", A, {"body": "u2"}, k())
        self.check(f"{bid}.crud.upsert-replace.200", ok_note(r, n("n2"), "u2", 200) and st.get(TA, n("n2")) == "u2",
                   r)
        r = c.h1("DELETE", f"{P}{ta}/{n('n2')}", A, None, k())
        self.check(f"{bid}.crud.delete.200", r.status == 200 and st.get(TA, n("n2")) is None, r)
        miss = {m: c.h1(m, f"{P}{ta}/{MISSING}", A, b if b else None, k() if m != "GET" else None)
                for m, b in (("GET", None), ("PATCH", {"body": "x"}), ("DELETE", None))}
        self.check(f"{bid}.crud.missing.404", all(x.status == 404 for x in miss.values()), miss)
        r = c.h1("DELETE", f"{P}{ta}/{n('n2')}", A, None, k())
        self.check(f"{bid}.crud.delete-gone.uniform", (r.status, r.body) == (miss["DELETE"].status,
                                                                             miss["DELETE"].body), r)

        # --- idempotency (INV-IDEMP): key = (principal, Idempotency-Key)
        k1 = k()
        r1 = c.h1("POST", f"{P}{ta}/", A, {"id": n("n3"), "body": "orig"}, k1)
        r2 = c.h1("POST", f"{P}{ta}/", A, {"id": n("n3"), "body": "orig"}, k1)
        self.check(f"{bid}.idem.replay.same-outcome", r1.status == 201 and (r2.status, r2.body) == (r1.status, r1.body),
                   (r1, r2))
        c.h1("PATCH", f"{P}{ta}/{n('n3')}", A, {"body": "changed"}, k())
        r3 = c.h1("POST", f"{P}{ta}/", A, {"id": n("n3"), "body": "orig"}, k1)
        self.check(f"{bid}.idem.replay.stored-not-reexecuted", (r3.status, r3.body) == (r1.status, r1.body)
                   and st.get(TA, n("n3")) == "changed", r3)
        r = c.h1("POST", f"{P}{tb}/", B, {"id": n("n3"), "body": "bee"}, k1)
        self.check(f"{bid}.idem.key-scoped-by-principal", ok_note(r, n("n3"), "bee", 201)
                   and st.get(TB, n("n3")) == "bee", r)
        r = c.h1("POST", f"{P}{ta}/", A, {"id": n("n4"), "body": "nokey"})
        self.check(f"{bid}.idem.mutation-without-key.428", r.status == 428 and st.get(TA, n("n4")) is None, r)

        # --- cross-tenant (F7 logical isolation, W6 uniform failure). B owns xb, xb3.
        secret = "secret-" + secrets.token_hex(6)
        for nid in ("xb", "xb3"):
            c.h1("POST", f"{P}{tb}/", B, {"id": n(nid), "body": secret}, k())
        self.check(f"{bid}.xt.seed", st.get(TB, n("xb")) == secret and st.get(TB, n("xb3")) == secret, "seed failed")
        same = lambda r, m: (r.status, r.body) == (m.status, m.body)  # noqa: E731
        r = c.h1("GET", f"{P}{ta}/{n('xb')}", A)
        self.check(f"{bid}.xt.select-foreign-id.uniform", same(r, miss["GET"]) and secret.encode() not in r.body, r)
        r = c.h1("PATCH", f"{P}{ta}/{n('xb')}", A, {"body": "pwn"}, k())
        self.check(f"{bid}.xt.update-foreign-id.uniform", same(r, miss["PATCH"]) and st.get(TB, n("xb")) == secret, r)
        r = c.h1("DELETE", f"{P}{ta}/{n('xb')}", A, None, k())
        self.check(f"{bid}.xt.delete-foreign-id.uniform", same(r, miss["DELETE"]) and st.get(TB, n("xb")) == secret,
                   r)
        # path names tenant B, token is tenant A: uniform denial, compared with a missing id under B's path
        for m, body in (("GET", None), ("PATCH", {"body": "pwn"}), ("DELETE", None), ("PUT", {"body": "pwn"})):
            kk = None if m == "GET" else k()
            r = c.h1(m, f"{P}{tb}/{n('xb')}", A, body, kk)
            base = c.h1(m, f"{P}{tb}/{MISSING}", A, body, None if m == "GET" else k())
            self.check(f"{bid}.xt.path-tenant-B.{m}.denied",
                       r.status is not None and not 200 <= r.status < 300 and secret.encode() not in r.body, r)
            self.check(f"{bid}.xt.path-tenant-B.{m}.uniform", same(r, base), (r, base))
            self.check(f"{bid}.xt.path-tenant-B.{m}.no-effect",
                       st.get(TB, n("xb")) == secret and st.get(TB, MISSING) is None, st.get(TB, n("xb")))
        r = c.h1("POST", f"{P}{tb}/", A, {"id": n("xb2"), "body": "pwn"}, k())
        self.check(f"{bid}.xt.path-tenant-B.POST.denied", r.status is not None and not 200 <= r.status < 300
                   and st.get(TB, n("xb2")) is None and st.get(TA, n("xb2")) is None, r)
        r = c.h1("GET", f"{P}{tc}/{n('xb')}", A)
        self.check(f"{bid}.xt.path-tenant-C.uniform", same(r, c.h1("GET", f"{P}{tb}/{n('xb')}", A)), r)
        r = c.h1("PUT", f"{P}{ta}/{n('xb')}", A, {"body": "mine"}, k())
        self.check(f"{bid}.xt.upsert-same-id-own-row", ok_note(r, n("xb"), "mine", 200) and st.get(TA, n("xb")) ==
                   "mine" and st.get(TB, n("xb")) == secret, r)
        r = c.h1("POST", f"{P}{ta}/", A, {"id": n("xb3"), "body": "mine3"}, k())
        self.check(f"{bid}.xt.insert-same-id-no-existence-oracle", ok_note(r, n("xb3"), "mine3", 201)
                   and st.get(TB, n("xb3")) == secret, r)

        # --- token-carried authority (F5 ops caveat, D-D4) and authentication failures
        r = c.h1("POST", f"{P}{ta}/", self.tok_ro, {"id": n("r1"), "body": "ro"}, k())
        self.check(f"{bid}.auth.ops-caveat-select-only.write-denied",
                   r.status in (401, 403, 404) and st.get(TA, n("r1")) is None, r)
        r = c.h1("GET", f"{P}{ta}/{n('n1')}", self.tok_ro)
        self.check(f"{bid}.auth.ops-caveat-select-only.read-ok", ok_note(r, n("n1"), "a2", 200), r)
        bad = {"none": None, "tampered": mint(self.master, self.kid, TA, tamper=True),
               "wrong-aud": mint(self.master, self.kid, TA, aud="other.test"),
               "expired": mint(self.master, self.kid, TA, exp_delta=-5),
               "no-tenant": mint(self.master, self.kid, TA, with_tenant=False),
               "unknown-key": mint(secrets.token_bytes(32), b"other-kid", TA)}
        for name, tok in bad.items():
            r = c.h1("GET", f"{P}{ta}/{n('n1')}", tok)
            self.check(f"{bid}.auth.{name}.read-refused", r.status in (401, 403) and b"a2" not in r.body, r)
            r = c.h1("PUT", f"{P}{ta}/{n('a-' + name)}", tok, {"body": "x"}, k())
            self.check(f"{bid}.auth.{name}.write-refused", r.status in (401, 403)
                       and st.get(TA, n("a-" + name)) is None, r)

        # --- NC1: termination before CP leaves no durable rows
        hold = int(HOLD * 1000)
        wait = HOLD + SETTLE
        c.h1("POST", f"{P}{ta}/", A, {"id": n("c1"), "body": "x", "hold_ms": hold}, k(), cut=CUT)
        time.sleep(wait)
        self.check(f"{bid}.nc1.h1-close-before-cp.no-row", st.get(TA, n("c1")) is None, st.get(TA, n("c1")))
        c.h1("POST", f"{P}{ta}/", A, {"id": n("c2"), "body": "x", "hold_ms": hold}, k(), cut=CUT, rst=True)
        time.sleep(wait)
        self.check(f"{bid}.nc1.tcp-rst-before-cp.no-row", st.get(TA, n("c2")) is None, st.get(TA, n("c2")))
        res = c.h2("POST", f"{P}{ta}/", A, {"id": n("c3"), "body": "x", "hold_ms": hold}, k(), rst_after=CUT,
                   keep_open=wait)
        if res == "no-h2":
            self.check(f"{bid}.nc1.h2-alpn", False, "subject did not negotiate h2")
        else:
            self.check(f"{bid}.nc1.h2-rst-stream-before-cp.no-row", st.get(TA, n("c3")) is None, st.get(TA, n("c3")))
            res = c.h2("POST", f"{P}{ta}/", A, {"id": n("c4"), "body": "x", "hold_ms": hold}, k())
            time.sleep(0.2)
            self.check(f"{bid}.nc1.h2-control.row", res.startswith("complete:") and st.get(TA, n("c4")) == "x", res)
        r = c.h1("POST", f"{P}{ta}/", A, {"id": n("c5"), "body": "x", "hold_ms": hold}, k(), deadline=DEADLINE_MS)
        self.check(f"{bid}.nc1.deadline-before-cp.504", r.status == 504, r)
        time.sleep(max(0.0, wait - DEADLINE_MS / 1000))
        self.check(f"{bid}.nc1.deadline-before-cp.no-row", st.get(TA, n("c5")) is None, st.get(TA, n("c5")))
        c.h1("PUT", f"{P}{ta}/{n('n1')}", A, {"body": "overwritten", "hold_ms": hold}, k(), cut=CUT)
        time.sleep(wait)
        self.check(f"{bid}.nc1.upsert-close-before-cp.pre-image-kept", st.get(TA, n("n1")) == "a2",
                   st.get(TA, n("n1")))

        # --- NC7: no response byte before CP (and an ack implies a durable effect)
        seen = {}

        def at_first(t):
            seen["t"], seen["row"] = t, st.get(TA, n("c6"))

        r = c.h1("POST", f"{P}{ta}/", A, {"id": n("c6"), "body": "x", "hold_ms": hold}, k(), on_first=at_first)
        self.check(f"{bid}.nc7.control.201", r.status == 201 and st.get(TA, n("c6")) == "x", r)
        self.check(f"{bid}.nc7.no-byte-before-cp", seen.get("t", 0) >= HOLD - NC7_SLACK,
                   f"first byte after {seen.get('t')} s, hold {HOLD} s")
        self.check(f"{bid}.nc7.durable-at-first-byte", seen.get("row") == "x", seen.get("row"))

        # --- NC2: from CP on, not cancellable; a timer after CP yields 202 + idempotency retrieval
        kd = k()
        body = {"id": n("d1"), "body": "late", "hold_after_ms": hold}
        got = {}
        r = c.h1("POST", f"{P}{ta}/", A, body, kd, deadline=DEADLINE_MS,
                 on_first=lambda t: got.setdefault("row", st.get(TA, n("d1"))))
        self.check(f"{bid}.nc2.timer-after-cp.202", r.status == 202, r)
        self.check(f"{bid}.nc2.timer-after-cp.durable-at-202", got.get("row") == "late", got.get("row"))
        early = c.h1("POST", f"{P}{ta}/", A, body, kd)
        self.check(f"{bid}.nc2.retrieval-while-pending", early.status in (201, 202) and st.get(TA, n("d1")) == "late",
                   early)
        time.sleep(wait)
        r = c.h1("POST", f"{P}{ta}/", A, {"id": n("d1"), "body": "late"}, kd)
        self.check(f"{bid}.nc2.retrieval.stored-outcome", ok_note(r, n("d1"), "late", 201), r)
        k2 = k()
        c.h1("POST", f"{P}{ta}/", A, {"id": n("d2"), "body": "latched", "hold_after_ms": hold}, k2, cut=CUT)
        time.sleep(wait)
        self.check(f"{bid}.nc2.close-after-cp.latched", st.get(TA, n("d2")) == "latched", st.get(TA, n("d2")))
        r = c.h1("POST", f"{P}{ta}/", A, {"id": n("d2"), "body": "latched"}, k2)
        self.check(f"{bid}.nc2.close-after-cp.retrieval", ok_note(r, n("d2"), "latched", 201), r)

    # ---------------------------------------------------------------- capability endowment (INV-NONEMPTY, F4 CapSet)
    def cap_suite(self):
        c, st, A, ta = self.c, self.stores["sq"], self.tok[self.TA], f"{self.TA:016x}"
        k = lambda: "k" + secrets.token_hex(8)  # noqa: E731
        n1 = "sq-n1"  # exists in sq with body "a2"
        r = c.h1("GET", f"/nocap/{ta}/{n1}", A)
        self.check("cap.nocap.select.denied", r.status in (403, 404) and b"a2" not in r.body, r)
        for m, path, body in (("PUT", f"/nocap/{ta}/nc1", {"body": "x"}), ("POST", f"/nocap/{ta}/", {"id": "nc1",
                              "body": "x"}), ("PATCH", f"/nocap/{ta}/{n1}", {"body": "x"}),
                              ("DELETE", f"/nocap/{ta}/{n1}", None)):
            r = c.h1(m, path, A, body, k())
            self.check(f"cap.nocap.{m}.denied", r.status in (403, 404), r)
        self.check("cap.nocap.no-effect", all(s.get(self.TA, "nc1") is None for s in self.stores.values())
                   and st.get(self.TA, n1) == "a2", "row changed")
        r = c.h1("GET", f"/ro/{ta}/{n1}", A)
        self.check("cap.ro.select.200", r.status == 200 and (r.json() or {}).get("body") == "a2", r)
        for m, body in (("PUT", {"body": "x"}), ("PATCH", {"body": "x"}), ("DELETE", None)):
            r = c.h1(m, f"/ro/{ta}/{n1}", A, body, k())
            base = c.h1(m, f"/ro/{ta}/{MISSING}", A, body, k())
            self.check(f"cap.ro.{m}.denied", r.status in (403, 404) and st.get(self.TA, n1) == "a2", r)
            self.check(f"cap.ro.{m}.uniform", (r.status, r.body) == (base.status, base.body), (r, base))
        r = c.h1("POST", f"/ro/{ta}/", A, {"id": "ro1", "body": "x"}, k())
        self.check("cap.ro.POST.denied", r.status in (403, 404) and st.get(self.TA, "ro1") is None, r)

    # ---------------------------------------------------------------- NC8: SIGTERM drain
    def drain_suite(self):
        c, ta = self.c, f"{self.TA:016x}"
        A = self.tok[self.TA]
        reqs, results = [], {}
        for bid in self.stores:
            for i in range(2):
                reqs.append((bid, f"{bid}-g{i}", "k" + secrets.token_hex(8)))

        def go(bid, nid, key):
            try:
                results[nid] = c.h1("POST", f"/{bid}/{ta}/", A, {"id": nid, "body": "drain", "hold_ms": 1000}, key)
            except OSError as e:
                results[nid] = Resp(None, {}, repr(e).encode(), None)

        ths = [threading.Thread(target=go, args=r) for r in reqs]
        for t in ths:
            t.start()
        time.sleep(CUT)
        t0 = time.monotonic()
        self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(T_DRAIN)
            exit_s = time.monotonic() - t0
            rc = self.proc.returncode
        except subprocess.TimeoutExpired:
            exit_s, rc = None, None
            self.kill()
        for t in ths:
            t.join(20)
        self.check("nc8.exit-within-T_drain", exit_s is not None, f"still running {T_DRAIN} s after SIGTERM")
        self.check("nc8.exit-status-0", rc == 0, f"exit {rc}")
        acked, unacked = [], []
        for bid, nid, key in reqs:
            r = results.get(nid)
            row = self.stores[bid].get(self.TA, nid)
            if r is not None and r.status is not None and 200 <= r.status < 300:
                acked.append(nid)
                self.check(f"nc8.{nid}.acked-implies-durable", row == "drain", f"acked {r} but row {row!r}")
            else:
                unacked.append((bid, nid, key, row))
        if exit_s is not None:
            self.note(f"drain {exit_s:.2f} s, {len(acked)}/{len(reqs)} in-flight completed")
        # restart on the same dirs: acked rows survive; an unacked request whose row exists must be latched
        # (replay with its key returns the stored success, never a re-execution or a conflict)
        self.port_reuse_wait()
        self.start()
        for bid, nid, key in reqs:
            if nid in acked:
                r = c.h1("GET", f"/{bid}/{ta}/{nid}", A)
                self.check(f"nc8.{nid}.durable-after-restart", r.status == 200, r)
        for bid, nid, key, row in unacked:
            if row is None:
                self.check(f"nc8.{nid}.unacked-no-row", True)
                continue
            r = c.h1("POST", f"/{bid}/{ta}/", A, {"id": nid, "body": "drain", "hold_ms": 1000}, key)
            self.check(f"nc8.{nid}.unacked-row-is-latched", r.status == 201, r)
        self.stop()

    def port_reuse_wait(self):
        until = time.time() + 5
        while time.time() < until:
            try:
                s = socket.socket()
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", self.port))
                s.close()
                return
            except OSError:
                time.sleep(0.1)


# ------------------------------------------------------------------------------------------------ engines


def pg_pin(dsn):
    c = wire.PgConn(dsn)
    try:
        v = c.query("SHOW server_version")[0][0]
    finally:
        c.close()
    return "pg" + v.split(".")[0].split(" ")[0].rstrip("abcdefghijklmnopqrstuvwxyz")


def kv_engine(url):
    c = wire.KvConn(url)
    try:
        info = c.cmd("INFO", "server") or ""
    finally:
        c.close()
    return "valkey" if "valkey_version" in info else "redis"


# ------------------------------------------------------------------------------------------------ main


def subject_cmd(s):
    if s.endswith(".py"):
        return [sys.executable, "-I", os.path.abspath(s)]
    parts = shlex.split(s)
    parts[0] = os.path.abspath(parts[0]) if os.path.exists(parts[0]) else parts[0]
    return parts


def build_mutant_subject():
    target = os.path.join(REPO, "target", "native-mutants")   # D17: the data plane is feature `native`
    binp = os.path.join(target, "release", "aegis")
    env = dict(os.environ, CARGO_TARGET_DIR=target)
    print(f"building the negative-control subject ({binp}) through ci/heavy.sh ...", flush=True)
    p = subprocess.run([os.path.join(REPO, "ci", "heavy.sh"), "cargo", "build", "--release", "--locked", "-q", "-p",
                        "aegis-bin", "--features", "native,e2e-mutants"], cwd=REPO, env=env)
    return binp if p.returncode == 0 and os.access(binp, os.X_OK) else None


def summary(r):
    return f"{r.passed} checks; backends {'+'.join(s.engine for s in r.stores.values())}" + \
        ("; " + "; ".join(r.notes) if r.notes else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--subject", default=None, help="subject command (default: the reference ref_subject.py)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--mutant-subject", default=None, help="e2e-mutants build for --self-test --subject")
    ap.add_argument("--pg", default=os.environ.get("AEGIS_E2E_PG"), help="postgres DSN (e.g. @pg17 via engines.sh)")
    ap.add_argument("--kv", default=os.environ.get("AEGIS_E2E_KV"), help="valkey/redis URL")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    ref = os.path.join(HERE, "ref_subject.py")

    if not a.self_test:
        cmd = subject_cmd(a.subject or ref)
        if not a.subject:
            print("subject: reference (ref_subject.py)")
        r = Run(cmd, a.pg, a.kv, verbose=a.verbose)
        ok = r.run()
        if ok:
            print(f"{NAME}: PASS ({summary(r)})")
            return 0
        print(f"{NAME}: FAIL ({len(r.failures)} failed: {', '.join(r.failures[:8])})")
        return 1

    if a.subject:
        subj = a.mutant_subject or os.path.join(REPO, "target", "native-mutants", "release", "aegis")
        if not os.access(subj, os.X_OK):
            subj = build_mutant_subject()
            if not subj:
                print(f"{NAME} SELF-TEST: FAIL (could not build the e2e-mutants subject)")
                return 1
        cmd = subject_cmd(subj)
    else:
        subj, cmd = "reference ref_subject.py", subject_cmd(ref)
    print(f"self-test subject: {subj}", flush=True)
    r = Run(cmd, a.pg, a.kv, verbose=a.verbose)
    if not r.run():
        print(f"{NAME} SELF-TEST: FAIL (the unmutated subject must pass first: {r.failures[:6]})")
        return 1
    print(f"  baseline (no mutant): PASS ({summary(r)})", flush=True)
    caught = []
    for m in MUTANTS:
        r = Run(cmd, a.pg, a.kv, env_extra={"AEGIS_E2E_MUTANT": m})
        if r.run():
            print(f"{NAME} SELF-TEST: FAIL (mutant {m} was not caught)")
            return 1
        print(f"  mutant {m}: caught by {len(r.failures)} checks, e.g. {', '.join(r.failures[:5])}", flush=True)
        caught.append(m)
    print(f"{NAME} SELF-TEST: PASS ({len(caught)}/{len(MUTANTS)} mutants caught: {', '.join(caught)}; "
          f"backends {'+'.join(s.engine for s in r.stores.values())})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
