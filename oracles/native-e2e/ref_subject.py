#!/usr/bin/env python3
"""native-e2e reference subject: a small stdlib-Python server that follows the native-e2e contract (README.md,
"Subject contract") so the oracle can be shown to PASS on a correct subject and go red on each mutant before
monban-bin has a data plane (P4-bin-001). Not a model of monban internals: only its observable behaviour matters.

    ref_subject.py --config <f8.json> --cert <pem> --key <pem> [--audit-dir d] [--runtime-dir d] [--token-keyring f]

Negative controls: AEGIS_E2E_MUTANT = tenant-from-path | commit-despite-cancel | body-before-cp |
empty-caps-means-all | no-drain | ack-then-drop (the same names monban-bin's `e2e-mutants` feature must implement).
"""

import base64
import hashlib
import hmac
import json
import os
import re
import select
import signal
import socket
import sqlite3
import ssl
import struct
import sys
import threading
import time
import tomllib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import wire  # noqa: E402
import mywire  # noqa: E402

MUTANT = os.environ.get("AEGIS_E2E_MUTANT", "")
EX_CONFIG = 78
APP_NOTES = "app:notes"
ALLOW_ALL = "allow-all"
PG_ROLE = "monban_app"          # monban-bin PG_RLS_ROLE
PG_SETTING = "monban.tenant"     # monban-bin PG_TENANT_SETTING
OP_BIT = {"select": 1, "insert": 2, "update": 4, "delete": 8, "upsert": 16}
METHOD_OP = {"GET": "select", "POST": "insert", "PATCH": "update", "DELETE": "delete", "PUT": "upsert"}
TENANT_RE = re.compile(r"^[0-9a-f]{16}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
IDEM_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MAX_HOLD_MS = 10000
DRAIN_S = 8.0
NOTES_COLUMNS = {"id", "body"}


def log(m):
    print(f"ref-subject: {m}", file=sys.stderr, flush=True)


def jbody(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()


NOT_FOUND = (404, jbody({"error": "not_found"}))


class Cancelled(Exception):
    pass


# ------------------------------------------------------------------------------------------------ config


class ConfigError(Exception):
    pass


def load_pins():
    with open(os.path.join(REPO, "supply-chain", "engine-pins.toml"), "rb") as f:
        return tomllib.load(f)


def pin_family(pins, name):
    if name == "sqlite" and "sqlite" in pins:
        return "sqlite"
    e = pins.get("engines", {}).get(name)
    return e and e.get("kind")


def load_config(path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
        if len(raw) > 1 << 20:
            raise ConfigError("config over 1 MiB")
        cfg = json.loads(raw)
    except (OSError, ValueError) as e:
        raise ConfigError(f"cannot read config: {e}")
    if cfg.get("v") != 1 or not cfg.get("listeners") or not cfg.get("vhosts"):
        raise ConfigError("v/listeners/vhosts")
    pins = load_pins()
    backends = {}
    for b in (cfg.get("data") or {}).get("backends", []):
        bid, eng, dsn, pin = b.get("id"), b.get("engine"), b.get("dsn_ref", ""), b.get("pin")
        if bid in backends or eng not in ("sqlite", "postgres", "redis", "valkey", "mariadb", "crdb"):
            raise ConfigError(f"backend {bid}")
        fam = pin_family(pins, pin)
        if fam != eng:
            raise ConfigError(f"backend {bid}: pin {pin} is not a {eng} pin")
        if eng == "sqlite":
            if not dsn.startswith("path:/"):
                raise ConfigError(f"backend {bid}: sqlite needs path:")
            target = dsn[5:]
        else:
            if not dsn.startswith("env:"):
                raise ConfigError(f"backend {bid}: only env: dsn_ref in the reference")
            target = os.environ.get(dsn[4:])
            if not target:
                raise ConfigError(f"backend {bid}: {dsn} unset")
        budget = int(b.get("op_budget_ms", 5000))
        if not 10 <= budget <= 60000:
            raise ConfigError("op_budget_ms")
        backends[bid] = {"id": bid, "engine": eng, "target": target, "budget_ms": budget}
    vhosts = {}
    for v in cfg["vhosts"]:
        routes = []
        for r in v["routes"]:
            to = r.get("to", {})
            if to.get("upstream") != APP_NOTES:
                raise ConfigError(f"route {r.get('id')}: the reference serves only {APP_NOTES} routes")
            data = r.get("data", None)
            caps = None  # None = no data capability
            if data == "unrestricted":
                raise ConfigError("unrestricted is out of scope for the reference")
            if data is not None:
                if not isinstance(data, list):
                    raise ConfigError("data")
                if not data and MUTANT != "empty-caps-means-all":
                    raise ConfigError(f"route {r.get('id')}: empty data list (INV-NONEMPTY)")
                caps = []
                for c in data:
                    if c.get("backend") not in backends:
                        raise ConfigError(f"route {r.get('id')}: undeclared backend {c.get('backend')}")
                    if c.get("collection") != "notes" or not set(c.get("columns", [])) <= NOTES_COLUMNS:
                        raise ConfigError(f"route {r.get('id')}: unknown collection/column")
                    ops = c.get("ops", [])
                    if not ops or any(o not in OP_BIT for o in ops):
                        raise ConfigError("ops")
                    caps.append({"backend": c["backend"], "ops": set(ops)})
                if len({c["backend"] for c in caps}) > 1:
                    raise ConfigError(f"route {r.get('id')}: a notes route names exactly one backend")
                if not caps:  # mutant only: [] read as "all"
                    caps = None
                    data = None
            if data is None and MUTANT == "empty-caps-means-all" and backends:
                caps = [{"backend": next(iter(backends)), "ops": set(OP_BIT)}]
            routes.append({"id": r["id"], "path": r["path"], "prefix": r["path"].endswith("/"),
                           "authz": r.get("authz"), "caps": caps})
        vhosts[v["host"]] = routes
    return cfg, backends, vhosts


# ------------------------------------------------------------------------------------------------ tokens (F5 Tier L)


def cbor_dec(b, i=0, depth=0):
    if depth > 8 or i >= len(b):
        raise ValueError("cbor")
    ib = b[i]
    mt, ai = ib >> 5, ib & 31
    i += 1
    if ai < 24:
        n = ai
    elif ai in (24, 25, 26, 27):
        w = 1 << (ai - 24)
        if i + w > len(b):
            raise ValueError("cbor")
        n = int.from_bytes(b[i:i + w], "big")
        i += w
    else:
        raise ValueError("cbor")
    if mt == 0:
        return n, i
    if mt in (2, 3):
        if i + n > len(b):
            raise ValueError("cbor")
        s = b[i:i + n]
        return (bytes(s) if mt == 2 else s.decode()), i + n
    if mt == 4:
        if n > 64:
            raise ValueError("cbor")
        out = []
        for _ in range(n):
            v, i = cbor_dec(b, i, depth + 1)
            out.append(v)
        return out, i
    raise ValueError("cbor")


def cbor_enc(v):
    def head(mt, n):
        if n < 24:
            return bytes([mt << 5 | n])
        for ai, w in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * w):
                return bytes([mt << 5 | ai]) + n.to_bytes(w, "big")
        raise ValueError("int")
    if isinstance(v, int):
        return head(0, v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        e = v.encode()
        return head(3, len(e)) + e
    return head(4, len(v)) + b"".join(cbor_enc(x) for x in v)


def k_aud(master, aud, kid):
    prk = hmac.new(b"\0" * 32, master, hashlib.sha256).digest()
    a = aud.encode()
    info = b"aegis-cap-v1" + len(a).to_bytes(2, "big") + a + len(kid).to_bytes(2, "big") + kid
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


class AuthError(Exception):
    def __init__(self, status):
        super().__init__(status)
        self.status = status


def verify_token(keyring, bearer, aud, op_bit, segs):
    """Returns (tenant_int, principal_str). AuthError(401) on malformed/bad MAC/shape; AuthError(403) on a caveat."""
    try:
        raw = base64.urlsafe_b64decode(bearer + "=" * (-len(bearer) % 4))
        tok, end = cbor_dec(raw)
        if end != len(raw) or len(raw) > 4096:
            raise ValueError("trailing")
        ver, kid, nonce, cavs, tag = tok
        if ver != 1 or not isinstance(kid, bytes) or not isinstance(nonce, bytes) or len(nonce) != 16:
            raise ValueError("shape")
        if not isinstance(cavs, list) or not 1 <= len(cavs) <= 64 or not isinstance(tag, bytes):
            raise ValueError("shape")
    except (ValueError, TypeError):
        raise AuthError(401)
    master = keyring.get(kid)
    if master is None:
        raise AuthError(401)
    t = hmac.new(k_aud(master, aud, kid), kid + nonce, hashlib.sha256).digest()
    for c in cavs:
        t = hmac.new(t, cbor_enc(c), hashlib.sha256).digest()
    if not hmac.compare_digest(t, tag):
        raise AuthError(401)
    if len(cavs) < 3 or [c[0] for c in cavs[:3]] != [0, 1, 8]:
        raise AuthError(401)
    depth = min(c[1] for c in cavs if c[0] == 8)
    if len(cavs) - 3 > depth:
        raise AuthError(401)
    tenants = [c[1] for c in cavs if c[0] == 6]
    if not tenants:
        raise AuthError(401)
    tenant, now = tenants[0], int(time.time())
    for c in cavs:
        k = c[0]
        ok = {
            0: lambda: c[1] == aud,
            1: lambda: now < c[1],
            2: lambda: now >= c[1],
            3: lambda: op_bit & ~c[1] == 0,
            4: lambda: list(c[1]) == segs[:len(c[1])],
            6: lambda: c[1] == tenant,
            8: lambda: True,
        }.get(k, lambda: False)()
        if not ok:
            raise AuthError(403)
    return tenant, kid.hex() + ":" + nonce.hex()


def load_keyring(path):
    ring = {}
    if not path:
        return ring
    with open(path) as f:
        doc = json.load(f)
    for k in doc["keys"]:
        key = bytes.fromhex(k["key"])
        if len(key) != 32:
            raise ConfigError("keyring: key must be 32 bytes")
        ring[bytes.fromhex(k["kid"])] = key
    return ring


# ------------------------------------------------------------------------------------------------ backends


class SqliteTx:
    def __init__(self, path, write):
        self.c = sqlite3.connect(path, timeout=10, isolation_level=None, check_same_thread=False)
        self.c.execute("PRAGMA synchronous=FULL")
        self.c.execute("BEGIN IMMEDIATE" if write else "BEGIN")

    def select(self, t, i):
        r = self.c.execute("SELECT body FROM notes WHERE tenant=? AND id=?", (t, i)).fetchone()
        return r and r[0]

    def insert(self, t, i, b):
        try:
            self.c.execute("INSERT INTO notes(tenant,id,body) VALUES(?,?,?)", (t, i, b))
            return True
        except sqlite3.IntegrityError:
            return False

    def update(self, t, i, b):
        return self.c.execute("UPDATE notes SET body=? WHERE tenant=? AND id=?", (b, t, i)).rowcount > 0

    def delete(self, t, i):
        return self.c.execute("DELETE FROM notes WHERE tenant=? AND id=?", (t, i)).rowcount > 0

    def upsert(self, t, i, b):
        self.c.execute("INSERT INTO notes(tenant,id,body) VALUES(?,?,?) "
                       "ON CONFLICT(tenant,id) DO UPDATE SET body=excluded.body", (t, i, b))
        return True

    def commit(self):
        self.c.execute("COMMIT")
        self.c.close()

    def rollback(self):
        try:
            self.c.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        self.c.close()


class PgTx:
    """Runs as the RLS role with the tenant bound per transaction (monban_adapter_pg::rls_bind): SET LOCAL ROLE and a
    transaction-local `monban.tenant`, both set before the transaction's first statement."""

    def __init__(self, dsn, write):
        self.c = wire.PgConn(dsn)
        self.c.query("BEGIN")
        self.bound = None

    def _bind(self, t):
        if self.bound is None:
            self.c.query(f'SET LOCAL ROLE "{PG_ROLE}"')
            self.c.query(f"SELECT pg_catalog.set_config({wire.pg_quote(PG_SETTING)}, {wire.pg_quote(t)}, true)")
            self.bound = t
        elif self.bound != t:
            raise wire.DbError("one tenant per transaction")

    def select(self, t, i):
        self._bind(t)
        r = self.c.query(f"SELECT body FROM notes WHERE tenant={wire.pg_quote(t)} AND id={wire.pg_quote(i)}")
        return r[0][0] if r else None

    def insert(self, t, i, b):
        q = wire.pg_quote
        self._bind(t)
        return bool(self.c.query(f"INSERT INTO notes(tenant,id,body) VALUES({q(t)},{q(i)},{q(b)}) "
                                 "ON CONFLICT (tenant,id) DO NOTHING RETURNING id"))

    def update(self, t, i, b):
        q = wire.pg_quote
        self._bind(t)
        return bool(self.c.query(f"UPDATE notes SET body={q(b)} WHERE tenant={q(t)} AND id={q(i)} RETURNING id"))

    def delete(self, t, i):
        q = wire.pg_quote
        self._bind(t)
        return bool(self.c.query(f"DELETE FROM notes WHERE tenant={q(t)} AND id={q(i)} RETURNING id"))

    def upsert(self, t, i, b):
        q = wire.pg_quote
        self._bind(t)
        self.c.query(f"INSERT INTO notes(tenant,id,body) VALUES({q(t)},{q(i)},{q(b)}) "
                     "ON CONFLICT (tenant,id) DO UPDATE SET body=EXCLUDED.body")
        return True

    def commit(self):
        self.c.query("COMMIT")
        self.c.close()

    def rollback(self):
        try:
            self.c.query("ROLLBACK")
        except (wire.DbError, OSError):
            pass
        self.c.close()


class KvTx:
    """Writes are buffered and applied with MULTI/EXEC at commit, so nothing is visible before CP."""

    def __init__(self, url, write):
        self.c = wire.KvConn(url)
        self.view = {}
        self.cmds = []

    @staticmethod
    def key(t, i):
        return f"t:{{{t}}}:notes:{i}"

    def _get(self, t, i):
        k = self.key(t, i)
        return self.view[k] if k in self.view else self.c.cmd("GET", k)

    def select(self, t, i):
        return self._get(t, i)

    def insert(self, t, i, b):
        if self._get(t, i) is not None:
            return False
        self.view[self.key(t, i)] = b
        self.cmds.append(("SET", self.key(t, i), b, "NX"))
        return True

    def update(self, t, i, b):
        if self._get(t, i) is None:
            return False
        self.view[self.key(t, i)] = b
        self.cmds.append(("SET", self.key(t, i), b, "XX"))
        return True

    def delete(self, t, i):
        if self._get(t, i) is None:
            return False
        self.view[self.key(t, i)] = None
        self.cmds.append(("DEL", self.key(t, i)))
        return True

    def upsert(self, t, i, b):
        self.view[self.key(t, i)] = b
        self.cmds.append(("SET", self.key(t, i), b))
        return True

    def commit(self):
        if self.cmds:
            out = self.c.pipeline([("MULTI",)] + self.cmds + [("EXEC",)])
            if any(isinstance(x, Exception) for x in out):
                self.c.close()
                raise wire.DbError("EXEC failed")
        self.c.close()

    def rollback(self):
        self.c.close()


CURRENT = threading.local()   # the Exchange whose worker thread is running (crdb cancel watch)


class CrdbPool:
    """CockroachDB (P8-oracle-001, oracle crdb-live): a small LIFO pool, so the connection a cancelled request used is
    the next one handed out. Negative controls: `crdb-40001-as-success` (a 40001 at COMMIT answered as the success
    the handler computed), `crdb-cancel-ignored` (no CancelRequest when the request is cancelled or its deadline
    passes: the statement keeps running), `crdb-no-reset` (a connection whose transaction failed goes back to the
    pool without ROLLBACK)."""

    MAX_IDLE = 4

    def __init__(self, b):
        self.dsn, self.idle, self.lock = b["target"], [], threading.Lock()

    def get(self):
        with self.lock:
            if self.idle:
                return self.idle.pop()
        return wire.PgConn(self.dsn)

    def put(self, c):
        with self.lock:
            if len(self.idle) < self.MAX_IDLE:
                self.idle.append(c)
                return
        c.close()

    def tx(self, write):
        return CrdbTx(self, getattr(CURRENT, "ex", None))

    def check_schema(self):
        c = wire.PgConn(self.dsn)
        try:
            cols = {r[0] for r in c.query("SELECT column_name FROM information_schema.columns WHERE "
                                          "table_schema = 'public' AND table_name = 'notes'")}
            idem = c.query("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND "
                           "table_name = 'monban_idem'")
        finally:
            c.close()
        if not {"tenant", "id", "body"} <= cols or idem != [["1"]]:
            raise ConfigError("crdb backend: public.notes(tenant,id,body) and public.monban_idem must exist")


class CrdbTx:
    """No RLS on CockroachDB: the tenant conjunct is the isolation. SERIALIZABLE; a 40001 is retried by the caller
    (execute) as a whole transaction; a cancelled request's running statement is cancelled with CancelRequest, and
    the connection is reset (ROLLBACK) before it goes back to the pool, or retired if that fails."""

    def __init__(self, pool, ex):
        self.pool, self.ex = pool, ex
        self.c = pool.get()
        try:
            self.c.query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        except (wire.DbError, OSError):
            self._release(reset=False, retire=True)
            raise

    def q(self, sql):
        stop = threading.Event()
        ex = self.ex

        def watch():
            while not stop.is_set():
                if ex is not None and ex.cancel_ev.wait(0.02):
                    if MUTANT != "crdb-cancel-ignored" and not stop.is_set():
                        self.c.cancel()
                    return
                if ex is None:
                    return
        threading.Thread(target=watch, daemon=True).start()
        try:
            return self.c.query(sql)
        finally:
            stop.set()

    def select(self, t, i):
        q = wire.pg_quote
        r = self.q(f"SELECT body FROM public.notes WHERE tenant = {q(t)} AND id = {q(i)}")
        return r[0][0] if r else None

    def insert(self, t, i, b):
        q = wire.pg_quote
        return bool(self.q(f"INSERT INTO public.notes (tenant, id, body) VALUES ({q(t)}, {q(i)}, {q(b)}) "
                           "ON CONFLICT (tenant, id) DO NOTHING RETURNING id"))

    def update(self, t, i, b):
        q = wire.pg_quote
        return bool(self.q(f"UPDATE public.notes SET body = {q(b)} WHERE tenant = {q(t)} AND id = {q(i)} RETURNING id"))

    def delete(self, t, i):
        q = wire.pg_quote
        return bool(self.q(f"DELETE FROM public.notes WHERE tenant = {q(t)} AND id = {q(i)} RETURNING id"))

    def upsert(self, t, i, b):
        q = wire.pg_quote
        self.q(f"INSERT INTO public.notes (tenant, id, body) VALUES ({q(t)}, {q(i)}, {q(b)}) "
               "ON CONFLICT (tenant, id) DO UPDATE SET body = excluded.body")
        return True

    def _release(self, reset, retire=False):
        c, self.c = self.c, None
        if c is None:
            return
        if retire:
            c.close()
            return
        if reset and MUTANT != "crdb-no-reset":
            try:
                c.query("ROLLBACK")
            except (wire.DbError, OSError):
                c.close()
                return
        self.pool.put(c)

    def commit(self):
        try:
            self.c.query("COMMIT")
        except wire.DbError as e:
            if MUTANT == "crdb-40001-as-success" and e.args[1:2] == ("40001",):
                self._release(reset=True)
                return   # mutant: the failed commit is treated as committed
            self._release(reset=True)
            raise
        except OSError:
            self._release(reset=False, retire=True)
            raise
        self._release(reset=False)

    def rollback(self):
        self._release(reset=True)


class MyTx:
    """MariaDB (P8-oracle-001): no RLS, so the tenant conjunct in every statement is the isolation. Mutant
    `drop-tenant` drops that conjunct (the oracle line "native-e2e mariadb: drop-tenant reference -> red")."""

    def __init__(self, url, write):
        self.c = mywire.My(url)
        self.c.simple("START TRANSACTION")
        self.drop = MUTANT == "drop-tenant"

    def _where(self, t, i):
        return ("id = ?", (i,)) if self.drop else ("tenant = ? AND id = ?", (t, i))

    def select(self, t, i, lock=False):
        w, p = self._where(t, i)
        _, rows = self.c.query(f"SELECT body FROM notes WHERE {w}" + (" FOR UPDATE" if lock else ""), p)
        return rows[0][0] if rows else None

    def insert(self, t, i, b):
        try:
            self.c.query("INSERT INTO notes (tenant, id, body) VALUES (?, ?, ?)", (t, i, b))
            return True
        except mywire.MyError as e:
            if e.code == 1062:
                return False
            raise

    def update(self, t, i, b):
        if self.select(t, i, lock=True) is None:
            return False
        w, p = self._where(t, i)
        self.c.query(f"UPDATE notes SET body = ? WHERE {w}", (b, *p))
        return True

    def delete(self, t, i):
        if self.select(t, i, lock=True) is None:
            return False
        w, p = self._where(t, i)
        self.c.query(f"DELETE FROM notes WHERE {w}", p)
        return True

    def upsert(self, t, i, b):
        self.c.query("INSERT INTO notes (tenant, id, body) VALUES (?, ?, ?) "
                     "ON DUPLICATE KEY UPDATE body = VALUES(body)", (t, i, b))
        return True

    def commit(self):
        self.c.simple("COMMIT")
        self.c.close()

    def rollback(self):
        try:
            self.c.simple("ROLLBACK")
        except (mywire.MyError, OSError):
            pass
        self.c.close()


def open_tx(b, write):
    if b["engine"] == "sqlite":
        return SqliteTx(b["target"], write)
    if b["engine"] == "postgres":
        return PgTx(b["target"], write)
    if b["engine"] == "mariadb":
        return MyTx(b["target"], write)
    if b["engine"] == "crdb":
        return b["pool"].tx(write)
    return KvTx(b["target"], write)


def check_backend(b):
    """Boot-time schema/connectivity check (fail closed)."""
    if b["engine"] == "sqlite":
        if not os.path.exists(b["target"]):
            raise ConfigError(f"backend {b['id']}: no database file")
        c = sqlite3.connect(b["target"])
        cols = {r[1] for r in c.execute("PRAGMA table_info(notes)")}
        c.close()
        if not {"tenant", "id", "body"} <= cols:
            raise ConfigError(f"backend {b['id']}: notes(tenant,id,body) missing")
    elif b["engine"] == "postgres":
        c = wire.PgConn(b["target"])
        cols = {r[0] for r in c.query("SELECT column_name FROM information_schema.columns WHERE table_name='notes'")}
        rls = c.query("SELECT relrowsecurity, relforcerowsecurity FROM pg_catalog.pg_class "
                      "WHERE oid = 'public.notes'::regclass")
        c.close()
        if not {"tenant", "id", "body"} <= cols:
            raise ConfigError(f"backend {b['id']}: notes(tenant,id,body) missing")
        if rls != [["t", "t"]]:
            raise ConfigError(f"backend {b['id']}: schema gate: RlsNotForced")
    elif b["engine"] == "mariadb":
        # the live schema gate's MariaDB rules that this oracle exercises (monban_adapter_mysql::check_live_schema):
        # InnoDB, tenant/id byte-compared (VARBINARY or *_nopad_bin), (tenant, id) the only unique key
        c = mywire.My(b["target"])
        try:
            _, eng = c.query("SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() "
                             "AND TABLE_NAME = 'notes'")
            _, cols = c.query("SELECT COLUMN_NAME, COALESCE(COLLATION_NAME, ''), DATA_TYPE FROM "
                              "information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'notes'")
            _, keys = c.query("SELECT INDEX_NAME, GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) FROM "
                              "information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'notes' "
                              "AND NON_UNIQUE = 0 GROUP BY INDEX_NAME")
        finally:
            c.close()
        cmap = {r[0]: (r[1], r[2]) for r in cols}
        if not {"tenant", "id", "body"} <= set(cmap):
            raise ConfigError(f"backend {b['id']}: notes(tenant,id,body) missing")
        if [r[0] for r in eng] != ["InnoDB"]:
            raise ConfigError(f"backend {b['id']}: schema gate: NonTransactionalEngine")
        for col in ("tenant", "id"):
            coll, typ = cmap[col]
            if not (typ == "varbinary" or coll.endswith("_nopad_bin")):
                raise ConfigError(f"backend {b['id']}: schema gate: {col} collation {coll} is not byte equality")
        if [tuple(k) for k in keys] != [("PRIMARY", "tenant,id")]:
            raise ConfigError(f"backend {b['id']}: schema gate: (tenant, id) must be the only unique key")
    elif b["engine"] == "crdb":
        b["pool"] = CrdbPool(b)
        b["pool"].check_schema()
    else:
        c = wire.KvConn(b["target"])
        c.cmd("PING")
        c.close()


# ------------------------------------------------------------------------------------------------ idempotency store


class IdemStore:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.c = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.c.execute("PRAGMA journal_mode=WAL")
        self.c.execute("PRAGMA synchronous=FULL")
        self.c.execute("CREATE TABLE IF NOT EXISTS idem(principal TEXT, k TEXT, status INT, body BLOB, "
                       "PRIMARY KEY(principal,k))")
        self.inflight = set()

    def get(self, principal, k):
        with self.lock:
            r = self.c.execute("SELECT status, body FROM idem WHERE principal=? AND k=?", (principal, k)).fetchone()
            return (r[0], bytes(r[1])) if r else None

    def claim(self, principal, k):
        with self.lock:
            if (principal, k) in self.inflight:
                return False
            self.inflight.add((principal, k))
            return True

    def release(self, principal, k):
        with self.lock:
            self.inflight.discard((principal, k))

    def put(self, principal, k, status, body):
        with self.lock:
            self.c.execute("INSERT OR REPLACE INTO idem VALUES(?,?,?,?)", (principal, k, status, body))


# ------------------------------------------------------------------------------------------------ exchange


class Exchange:
    """One request: a worker thread runs host + app logic; the responder (connection) thread waits for the outcome,
    the deadline or a client cancel. `lock` makes CP and cancel mutually exclusive (NC2 latch)."""

    def __init__(self, srv, method, path, headers, body):
        self.srv, self.method, self.path, self.headers, self.body = srv, method, path, headers, body
        self.lock = threading.Lock()
        self.state = "running"
        self.cancel_ev = threading.Event()
        self.done_ev = threading.Event()
        self.result = None
        self.early = None
        self.idem_key = None
        self.t0 = time.monotonic()
        self.deadline = self.t0 + 60.0
        self.worker_done = threading.Event()
        srv.track(self, +1)
        threading.Thread(target=self._work, daemon=True).start()

    def _work(self):
        try:
            r = self.srv.process(self)
        except Cancelled:
            r = None
        except Exception as e:  # noqa: BLE001 - reference: any failure is a 503, never a crash
            log(f"worker error: {e!r}")
            r = (503, jbody({"error": "unavailable"}))
        with self.lock:
            if r is not None and self.result is None:
                self.result = r
        self.done_ev.set()
        self.worker_done.set()
        self.srv.track(self, -1)

    def cancel(self):
        with self.lock:
            if self.state == "running":
                self.state = "cancelled"
        self.cancel_ev.set()

    def commit_point(self, tx):
        with self.lock:
            if self.state == "cancelled" and MUTANT != "commit-despite-cancel":
                tx.rollback()
                raise Cancelled()
            tx.commit()
            self.state = "committed"

    def await_response(self, gone):
        """Returns (status, body, extra_headers) to send, or None if the client is gone."""
        while True:
            if self.done_ev.wait(0.01):
                with self.lock:
                    r = self.result
                if r is not None:
                    return r[0], r[1], []
                return 503, jbody({"error": "unavailable"}), []
            with self.lock:
                if self.early is not None:
                    e, self.early = self.early, None
                    return e[0], e[1], []
            if self.srv.dropping:  # ack-then-drop mutant: fabricated success during shutdown
                return 201, jbody({"status": "ok"}), []
            if time.monotonic() >= self.deadline:
                with self.lock:
                    if self.state == "committed":
                        hdr = [("idempotency-key", self.idem_key)] if self.idem_key else []
                        return 202, jbody({"status": "accepted"}), hdr
                    self.state = "cancelled"
                self.cancel_ev.set()
                return 504, jbody({"error": "deadline"}), []
            if gone():
                self.cancel()
                return None


# ------------------------------------------------------------------------------------------------ server


class Server:
    def __init__(self, args):
        self.args = args
        self.cfg, self.backends, self.vhosts = load_config(args["config"])
        for b in self.backends.values():
            check_backend(b)
        self.keyring = load_keyring(args.get("token-keyring"))
        rd = args.get("runtime-dir") or args.get("audit-dir")
        if not rd:
            raise ConfigError("--runtime-dir is required for the idempotency store")
        os.makedirs(rd, exist_ok=True)
        self.idem = IdemStore(os.path.join(rd, "ref-idem.db"))
        self.tlock = threading.Lock()
        self.active = set()
        self.stopping = False
        self.dropping = False

    def track(self, ex, d):
        with self.tlock:
            if d > 0:
                self.active.add(ex)
            else:
                self.active.discard(ex)

    def route(self, host, path):
        routes = self.vhosts.get(host)
        if routes is None:
            return None, (421, jbody({"error": "misdirected"}))
        best = None
        for r in routes:
            if path == r["path"] or (r["prefix"] and path.startswith(r["path"])):
                if best is None or len(r["path"]) > len(best["path"]):
                    best = r
        if best is None:
            return None, (404, jbody({"error": "no_route"}))
        return best, None

    def process(self, ex):
        host = (ex.headers.get(":authority") or ex.headers.get("host") or "").lower()
        host = host.rsplit(":", 1)[0] if ":" in host and not host.endswith("]") else host
        path = ex.path.split("?", 1)[0]
        r, err = self.route(host, path)
        if err:
            return err
        if r["authz"] != ALLOW_ALL:
            return 403, jbody({"error": "forbidden"})
        op = METHOD_OP.get(ex.method)
        if op is None:
            return 405, jbody({"error": "method"})
        segs = [s for s in path.split("/")[1:]]
        if segs and segs[-1] == "":
            segs = segs[:-1]
        auth = ex.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return 401, jbody({"error": "unauthenticated"})
        try:
            tenant, principal = verify_token(self.keyring, auth[7:].strip(), host, OP_BIT[op], segs)
        except AuthError as e:
            return e.status, jbody({"error": "unauthenticated" if e.status == 401 else "forbidden"})
        rest = path[len(r["path"]):]
        parts = rest.split("/")
        if op == "insert":
            if len(parts) != 2 or parts[1] != "":
                return NOT_FOUND
            nid = None
        else:
            if len(parts) != 2 or not ID_RE.match(parts[1]):
                return NOT_FOUND
            nid = parts[1]
        ptenant = parts[0]
        if not TENANT_RE.match(ptenant):
            return NOT_FOUND
        ttext = f"{tenant:016x}"
        if MUTANT == "tenant-from-path":
            ttext = ptenant
        elif ptenant != ttext:
            return NOT_FOUND
        caps = r["caps"]
        cap = None
        for c in caps or []:
            if op in c["ops"]:
                cap = c
        if cap is None:
            return NOT_FOUND  # SdkError::Denied: uniform with "does not exist" (W6)
        backend = self.backends[cap["backend"]]
        ex.deadline = min(ex.deadline, ex.t0 + backend["budget_ms"] / 1000.0)
        req = {}
        if op in ("insert", "update", "upsert"):
            try:
                req = json.loads(ex.body or b"null")
                if not isinstance(req, dict):
                    raise ValueError
            except ValueError:
                return 400, jbody({"error": "bad_body"})
            if not isinstance(req.get("body"), str) or len(req["body"]) > 4096 or "\0" in req["body"]:
                return 400, jbody({"error": "bad_body"})
            if op == "insert":
                nid = req.get("id")
                if not isinstance(nid, str) or not ID_RE.match(nid):
                    return 400, jbody({"error": "bad_body"})
        holds = []
        for h in ("hold_ms", "hold_after_ms"):
            v = req.get(h, 0)
            if not isinstance(v, int) or not 0 <= v <= MAX_HOLD_MS:
                return 400, jbody({"error": "bad_body"})
            holds.append(v / 1000.0)
        key = ex.headers.get("idempotency-key")
        mutating = op != "select"
        if mutating:
            if not key or not IDEM_RE.match(key):
                return 428, jbody({"error": "idempotency_key_required"})
            ex.idem_key = key
            stored = self.idem.get(principal, key)
            if stored is not None:
                return stored
            if not self.idem.claim(principal, key):
                return 409, jbody({"error": "in_progress"})
        try:
            return self.execute(ex, backend, op, ttext, nid, req.get("body"), holds, principal, key)
        finally:
            if mutating:
                self.idem.release(principal, key)

    def execute(self, ex, backend, op, t, nid, body, holds, principal, key):
        """CockroachDB: a 40001 (serialization failure, here an abort by a higher-priority writer) is retried as a
        whole transaction, handler included, while the request is live; never answered as a success."""
        CURRENT.ex = ex
        attempt = 0
        while True:
            try:
                return self.execute_once(ex, backend, op, t, nid, body, holds, principal, key)
            except wire.DbError as e:
                attempt += 1
                if backend["engine"] != "crdb" or e.args[1:2] != ("40001",) or attempt > 3 or ex.cancel_ev.is_set():
                    raise
                log(f"crdb 40001, retrying the transaction (attempt {attempt + 1})")

    def execute_once(self, ex, backend, op, t, nid, body, holds, principal, key):
        tx = open_tx(backend, op != "select")
        try:
            if op == "select":
                b = tx.select(t, nid)
                out = (200, jbody({"id": nid, "body": b})) if b is not None else NOT_FOUND
            elif op == "insert":
                out = (201, jbody({"id": nid, "body": body})) if tx.insert(t, nid, body) \
                    else (409, jbody({"error": "conflict"}))
            elif op == "update":
                out = (200, jbody({"id": nid, "body": body})) if tx.update(t, nid, body) else NOT_FOUND
            elif op == "delete":
                out = (200, jbody({"deleted": True, "id": nid})) if tx.delete(t, nid) else NOT_FOUND
            else:
                tx.upsert(t, nid, body)
                out = (200, jbody({"id": nid, "body": body}))
        except Exception:
            tx.rollback()
            raise
        if MUTANT == "body-before-cp":
            with ex.lock:
                ex.early = out
        if holds[0]:
            ex.cancel_ev.wait(holds[0])
        if self.dropping:
            tx.rollback()
            raise Cancelled()
        ex.commit_point(tx)  # CP: raises Cancelled (after rollback) if the request was cancelled first
        if key:
            self.idem.put(principal, key, out[0], out[1])
        if holds[1]:
            time.sleep(holds[1])
        return out


# ------------------------------------------------------------------------------------------------ HTTP/1.1


def recv_head(tls):
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = tls.recv(4096)
        if not d:
            return None, b""
        buf += d
        if len(buf) > 65536:
            return None, b""
    head, rest = buf.split(b"\r\n\r\n", 1)
    return head, rest


def gone_h1(tls):
    def check():
        try:
            r, _, _ = select.select([tls], [], [], 0)
        except (OSError, ValueError):
            return True
        if not r:
            return False
        prev = tls.gettimeout()
        tls.setblocking(False)
        try:
            return tls.recv(1024) == b""
        except (ssl.SSLWantReadError, BlockingIOError):
            return False
        except (ssl.SSLError, OSError):
            return True
        finally:
            tls.settimeout(prev)
    return check


def serve_h1(srv, tls):
    head, rest = recv_head(tls)
    if head is None:
        return
    lines = head.decode("latin-1").split("\r\n")
    try:
        method, target, _ = lines[0].split(" ", 2)
    except ValueError:
        return
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    n = int(headers.get("content-length", "0") or 0)
    if n > 1 << 20:
        return
    body = rest
    while len(body) < n:
        d = tls.recv(min(65536, n - len(body)))
        if not d:
            return
        body += d
    if srv.stopping:
        resp = (503, jbody({"error": "draining"}), [])
    else:
        dl = headers.get("monban-deadline-ms")
        if dl is not None and not (dl.isdigit() and 1 <= int(dl) <= 60000):
            resp = (400, jbody({"error": "bad_deadline"}), [])
        else:
            ex = Exchange(srv, method, target, headers, body[:n])
            if dl is not None:
                ex.deadline = min(ex.deadline, ex.t0 + int(dl) / 1000.0)
            resp = ex.await_response(gone_h1(tls))
            if resp is None:
                return
    status, rbody, extra = resp
    hdr = [f"HTTP/1.1 {status} X", "content-type: application/json", f"content-length: {len(rbody)}",
           "connection: close"] + [f"{k}: {v}" for k, v in extra]
    try:
        tls.sendall(("\r\n".join(hdr) + "\r\n\r\n").encode() + rbody)
    except OSError:
        pass


# ------------------------------------------------------------------------------------------------ HTTP/2 (subset)


def hp_int(b, i, prefix):
    m = (1 << prefix) - 1
    v = b[i] & m
    i += 1
    if v < m:
        return v, i
    shift = 0
    while True:
        c = b[i]
        i += 1
        v += (c & 0x7F) << shift
        shift += 7
        if not c & 0x80:
            return v, i


def hp_str(b, i):
    if b[i] & 0x80:
        raise ValueError("huffman not supported by the reference")
    n, i = hp_int(b, i, 7)
    return b[i:i + n].decode("latin-1"), i + n


def hpack_decode_subset(block):
    """Literal header fields without indexing / never indexed, new names, no Huffman: exactly what the oracle's
    h2 client sends. Anything else is a protocol error for the reference."""
    out, i = [], 0
    while i < len(block):
        if block[i] & 0xE0 != 0 or block[i] & 0x0F != 0:
            raise ValueError("hpack representation not supported by the reference")
        i += 1
        k, i = hp_str(block, i)
        v, i = hp_str(block, i)
        out.append((k, v))
    return out


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


class H2Conn:
    def __init__(self, srv, tls):
        self.srv, self.tls = srv, wire.LockedTLS(tls, 3600.0)
        self.wlock = threading.Lock()
        self.streams = {}
        self.closed = False

    def send(self, ftype, flags, sid, payload=b""):
        with self.wlock:
            self.tls.sendall(struct.pack("!I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack("!I", sid)
                             + payload)

    def recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            d = self.tls.recv(n - len(buf))
            if not d:
                raise ConnectionError("eof")
            buf += d
        return buf

    def run(self):
        try:
            if self.recv_exact(24) != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n":
                return
            self.send(4, 0, 0)
            while True:
                h = self.recv_exact(9)
                ln = int.from_bytes(h[:3], "big")
                ftype, flags, sid = h[3], h[4], int.from_bytes(h[5:9], "big") & 0x7FFFFFFF
                p = self.recv_exact(ln) if ln else b""
                if ftype == 4 and not flags & 1:
                    self.send(4, 1, 0)
                elif ftype == 6 and not flags & 1:
                    self.send(6, 1, 0, p)
                elif ftype == 1:
                    if flags & 0x8:
                        pad = p[0]
                        p = p[1:len(p) - pad]
                    if flags & 0x20:
                        p = p[5:]
                    if not flags & 0x4:
                        self.send(7, 0, 0, struct.pack("!II", sid, 1))
                        return
                    st = {"headers": dict(hpack_decode_subset(p)), "body": b"", "reset": False, "ex": None}
                    self.streams[sid] = st
                    if flags & 0x1:
                        self.dispatch(sid)
                elif ftype == 0:
                    if flags & 0x8:
                        pad = p[0]
                        p = p[1:len(p) - pad]
                    st = self.streams.get(sid)
                    if st is not None:
                        st["body"] += p
                        if p:
                            self.send(8, 0, 0, struct.pack("!I", len(p)))
                        if flags & 0x1:
                            self.dispatch(sid)
                elif ftype == 3:
                    st = self.streams.get(sid)
                    if st is not None:
                        st["reset"] = True
                elif ftype == 7:
                    return
        except (OSError, ValueError, ConnectionError, IndexError):
            return
        finally:
            self.closed = True
            for st in self.streams.values():
                st["reset"] = True

    def dispatch(self, sid):
        threading.Thread(target=self.respond, args=(sid,), daemon=True).start()

    def respond(self, sid):
        st = self.streams[sid]
        h = st["headers"]
        if self.srv.stopping:
            resp = (503, jbody({"error": "draining"}), [])
        else:
            ex = Exchange(self.srv, h.get(":method", ""), h.get(":path", "/"), h, st["body"])
            dl = h.get("monban-deadline-ms")
            if dl and dl.isdigit():
                ex.deadline = min(ex.deadline, ex.t0 + int(dl) / 1000.0)
            resp = ex.await_response(lambda: st["reset"] or self.closed)
            if resp is None:
                return
        status, body, extra = resp
        block = hp_lit(":status", str(status)) + hp_lit("content-type", "application/json") + \
            hp_lit("content-length", str(len(body))) + b"".join(hp_lit(k, v) for k, v in extra)
        try:
            self.send(1, 0x4, sid, block)
            self.send(0, 0x1, sid, body)
        except OSError:
            pass


# ------------------------------------------------------------------------------------------------ main


class Admin(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/healthz":
            b = b"ok\n"
            self.send_response(200)
        else:
            b = b"not found\n"
            self.send_response(404)
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


def hostport(s):
    h, p = s.rsplit(":", 1)
    return h.strip("[]"), int(p)


def parse_args(argv):
    out, it = {}, iter(argv)
    for a in it:
        if a in ("--config", "--cert", "--key", "--audit-dir", "--runtime-dir", "--token-keyring"):
            out[a[2:]] = next(it, None)
        else:
            raise ConfigError(f"unknown option {a}")
    if not out.get("config"):
        raise ConfigError("--config is required")
    return out


def main():
    try:
        args = parse_args(sys.argv[1:])
        srv = Server(args)
    except (ConfigError, wire.DbError, OSError, KeyError, ValueError, TypeError) as e:
        log(f"refusing to start: {e}")
        return EX_CONFIG
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args["cert"], args["key"])
    lst = srv.cfg["listeners"][0]
    ctx.set_alpn_protocols(lst.get("alpn", ["http/1.1"]))
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(hostport(lst["bind"]))
    ls.listen(128)
    ls.settimeout(0.1)
    admin = ThreadingHTTPServer(hostport((srv.cfg.get("admin") or {}).get("bind", "127.0.0.1:9464")), Admin)
    threading.Thread(target=admin.serve_forever, daemon=True).start()

    term = threading.Event()

    def on_term(_s, _f):
        if MUTANT == "no-drain":
            log("SIGTERM ignored (mutant no-drain)")
            return
        term.set()

    signal.signal(signal.SIGTERM, on_term)

    def conn(raw):
        try:
            raw.settimeout(10)
            tls = ctx.wrap_socket(raw, server_side=True)
        except (OSError, ssl.SSLError):
            raw.close()
            return
        try:
            if tls.selected_alpn_protocol() == "h2":
                H2Conn(srv, tls).run()
            else:
                serve_h1(srv, tls)
        finally:
            try:
                tls.close()
            except OSError:
                pass

    while not term.is_set():
        try:
            c, _ = ls.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=conn, args=(c,), daemon=True).start()
    ls.close()
    srv.stopping = True
    if MUTANT == "ack-then-drop":
        srv.dropping = True
        time.sleep(0.3)
        os._exit(0)
    until = time.monotonic() + DRAIN_S
    while time.monotonic() < until:
        with srv.tlock:
            if not srv.active:
                break
        time.sleep(0.02)
    time.sleep(0.2)  # let responders flush the last bytes
    os._exit(0)


if __name__ == "__main__":
    sys.exit(main())
