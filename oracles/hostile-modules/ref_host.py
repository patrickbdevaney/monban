#!/usr/bin/env python3
"""Reference P2 supervisor for oracles/hostile-modules (host level). Stdlib only.

A small stand-in for monban (feature p2) that follows the host-level subject contract in README.md: the same command
line as monban, F8 config subset (listener, admin, data.backends sqlite, vhosts/routes with to.wasm and data caps,
p2 block), TLS HTTP/1.1, F5 Tier-L tokens, F9 audit events in C2SP tlog-tiles entry bundles, the F14 supervisor
obligations (Part 3: I5 re-serialization, I1 decode/overwrite/authorize, I6-host audit before effect, I7 tri-state
mapping, D7 crash budget), and the worker command line (`<worker> compile|zygote|cordon`).

Negative controls (AEGIS_P2_MUTANT): raw-passthrough, double-response-accepted, audit-after-effect,
no-audit-on-trap, trap-maps-to-allow, data-run-skips-authorize, tenant-not-overwritten.
Not a product: one SQLite connection behind a lock, sequential requests per cordon, a fork child that must die on
a decode failure is disconnected rather than SIGKILLed (the reference does not learn the child's pid).
"""

import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
import secrets
import signal
import socket
import socketserver
import sqlite3
import ssl
import struct
import subprocess
import sys
import threading
import time
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import f14  # noqa: E402

MUT = os.environ.get("AEGIS_P2_MUTANT", "")
VHOST = "monban.test"
GRACE_S = 2.0
DENY = b"HTTP/1.1 403 Forbidden\r\ncontent-type: text/plain\r\ncontent-length: 7\r\nconnection: close\r\n\r\ndenied\n"
TOO_MANY = (b"HTTP/1.1 429 Too Many Requests\r\ncontent-type: text/plain\r\ncontent-length: 13\r\n"
            b"connection: close\r\n\r\ncrash budget\n")
UNAUTH = b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
NOTFOUND = b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
UNAVAIL = b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
NOTES_FIELDS = {"tenant": 0, "id": 1, "body": 2}
FIELD_NAMES = {0: "tenant", 1: "id", 2: "body"}
BANNED = {b"content-length", b"transfer-encoding", b"connection", b"keep-alive", b"upgrade", b"te", b"trailer"}
TCHAR = set(b"abcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~")


def die(code, msg):
    print(f"ref_host: {msg}", file=sys.stderr, flush=True)
    os._exit(code)


# ------------------------------------------------------------------------------------------------ audit (F9 + tiles)
def enc_index(n):
    groups = []
    while True:
        groups.append(n % 1000)
        n //= 1000
        if n == 0:
            break
    groups.reverse()
    return "/".join(("x" if i < len(groups) - 1 else "") + f"{g:03d}" for i, g in enumerate(groups))


class Audit:
    def __init__(self, base, config_hash):
        self.dir = os.path.join(base, f"{int(time.time() * 1000)}-{os.getpid()}")
        os.makedirs(self.dir, exist_ok=True)
        self.leaves = []
        self.lock = threading.Lock()
        self.config_hash = config_hash

    def append(self, actor, action, obj, outcome, req_id, detail=None):
        with self.lock:
            ev = {"v": 1, "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                  "seq": len(self.leaves), "actor": actor, "action": action, "object": obj[:512], "outcome": outcome,
                  "req_id": req_id, "config_hash": self.config_hash, "fips_status": "none"}
            if detail:
                ev["detail"] = detail
            self.leaves.append(json.dumps(ev, separators=(",", ":"), sort_keys=True).encode())
            n = len(self.leaves)
            idx = (n - 1) // 256
            bundle = self.leaves[idx * 256:n]
            rel = f"tile/entries/{enc_index(idx)}" + ("" if len(bundle) == 256 else f".p/{len(bundle)}")
            data = b"".join(struct.pack(">H", len(x)) + x for x in bundle)
            path = os.path.join(self.dir, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + f".tmp{threading.get_ident()}"
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.rename(tmp, path)
            dfd = os.open(os.path.dirname(path), os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)


# ------------------------------------------------------------------------------------------------ tokens (F5 Tier-L)
def cbor_dec(b, i=0):
    ib = b[i]
    mt, ai = ib >> 5, ib & 31
    i += 1
    if ai < 24:
        n = ai
    elif ai in (24, 25, 26, 27):
        w = 1 << (ai - 24)
        n = int.from_bytes(b[i:i + w], "big")
        i += w
    else:
        raise ValueError("cbor ai")
    if mt == 0:
        return n, i
    if mt in (2, 3):
        s = b[i:i + n]
        if len(s) != n:
            raise ValueError("cbor short")
        return (s if mt == 2 else s.decode()), i + n
    if mt == 4:
        out = []
        for _ in range(n):
            v, i = cbor_dec(b, i)
            out.append(v)
        return out, i
    raise ValueError("cbor type")


def cbor_enc(v):
    def head(mt, n):
        if n < 24:
            return bytes([(mt << 5) | n])
        for ai, w in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * w):
                return bytes([(mt << 5) | ai]) + n.to_bytes(w, "big")
        raise ValueError(n)
    if isinstance(v, int):
        return head(0, v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        return head(3, len(v.encode())) + v.encode()
    return head(4, len(v)) + b"".join(cbor_enc(x) for x in v)


def k_aud(master, aud, kid):
    prk = hmac.new(b"", master, hashlib.sha256).digest()
    a = aud.encode()
    info = b"aegis-cap-v1" + struct.pack("!H", len(a)) + a + struct.pack("!H", len(kid)) + kid
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


class Tokens:
    def __init__(self, path):
        with open(path) as f:
            self.keys = {bytes.fromhex(k["kid"]): bytes.fromhex(k["key"]) for k in json.load(f)["keys"]}

    def verify(self, tok):
        """Returns (tenant, subject) or None."""
        try:
            raw = base64.urlsafe_b64decode(tok + "=" * (-len(tok) % 4))
            v, end = cbor_dec(raw)
            if end != len(raw) or not isinstance(v, list) or len(v) != 5 or v[0] != 1:
                return None
            _, kid, nonce, cavs, tag = v
            master = self.keys.get(kid)
            if master is None:
                return None
            t = hmac.new(k_aud(master, VHOST, kid), kid + nonce, hashlib.sha256).digest()
            for c in cavs:
                t = hmac.new(t, cbor_enc(c), hashlib.sha256).digest()
            if not hmac.compare_digest(t, tag):
                return None
            cv = {c[0]: c[1] for c in cavs}
            if cv.get(0) != VHOST or cv.get(1, 0) < time.time() or not isinstance(cv.get(6), int) or cv[6] < 1:
                return None
            return cv[6], kid.hex()
        except (ValueError, IndexError, TypeError, KeyError):
            return None


# ------------------------------------------------------------------------------------------------ workers
class Spawned:
    """A worker process (zygote or cordon) holding our listening SOCK_SEQPACKET socket on fd 3."""

    def __init__(self, worker, mode, mod, rundir):
        self.sock_path = os.path.join(rundir, f"{mode}-{mod['id']}-{secrets.token_hex(4)}.sock")
        self.lsock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.lsock.bind(self.sock_path)
        self.lsock.listen(64)
        fd = self.lsock.fileno()
        env = dict(os.environ)
        self.proc = subprocess.Popen([worker, mode, "--module", mod["cwasm"], "--sha256", mod["digest"]],
                                     stdin=subprocess.DEVNULL, env=env, pass_fds=(fd, 3),
                                     preexec_fn=lambda: os.dup2(fd, 3))
        self.digest = mod["digest"]
        self.conn = None
        self.lock = threading.Lock()

    def connect(self):
        c = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        c.settimeout(10)
        c.connect(self.sock_path)
        f = c.recv(70000)
        d = f14.dec_w2s(f)  # DecodeError propagates: a bad ready frame is a decode failure
        if d["t"] != "ready" or d["ver"] != 1 or d["sha256"] != self.digest:
            c.close()
            raise f14.DecodeError("ready frame with the wrong digest")
        return c

    def alive(self):
        return self.proc.poll() is None

    def kill(self):
        try:
            self.proc.kill()
            self.proc.wait(5)
        except (OSError, subprocess.TimeoutExpired):
            pass
        for s in (self.conn, self.lsock):
            try:
                s and s.close()
            except OSError:
                pass
        try:
            os.unlink(self.sock_path)
        except OSError:
            pass


class DecodeFailure(Exception):
    pass


# ------------------------------------------------------------------------------------------------ supervisor
class Supervisor:
    def __init__(self, cfg, args):
        self.cfg = cfg
        self.args = args
        raw = json.dumps(cfg, sort_keys=True).encode()
        self.audit = Audit(args.audit_dir, hashlib.sha256(raw).hexdigest())
        self.tokens = Tokens(args.token_keyring)
        p2 = cfg.get("p2") or {}
        self.p2 = p2
        self.worker = p2.get("worker")
        self.iso = p2.get("isolation", "forkwasm")
        self.limits_default = {"fuel": p2.get("fuel", 15_000_000), "wall_ms": p2.get("wall_ms", 100),
                               "memory_mib": p2.get("memory_mib", 16),
                               "max_host_calls": p2.get("max_host_calls", 10_000),
                               "max_data_runs": p2.get("max_data_runs", 64),
                               "max_data_bytes": p2.get("max_data_bytes", 4_194_304),
                               "max_resp_bytes": p2.get("max_resp_bytes", 1_048_576),
                               "max_log_bytes": p2.get("max_log_bytes", 65_536)}
        self.frame_max = p2.get("frame_max_bytes", 65536)
        cb = p2.get("crash_budget") or {}
        self.cb = (cb.get("crashes", 3), cb.get("window_s", 60), cb.get("penalty_s", 600))
        self.crashes = {}
        self.penalty = {}
        self.cb_lock = threading.Lock()
        self.cache = p2.get("cache_dir") or os.path.join(args.runtime_dir, "p2")
        os.makedirs(self.cache, exist_ok=True)
        self.modules = {}
        for m in p2.get("modules", []):
            self.compile(m)
        self.routes = []
        for vh in cfg.get("vhosts", []):
            for r in vh.get("routes", []):
                tgt = r.get("to", {})
                if "wasm" in tgt and tgt["wasm"] not in self.modules:
                    die(78, f"route {r.get('id')}: unknown module {tgt['wasm']}")
                self.routes.append(r)
        self.routes.sort(key=lambda r: -len(r["path"]))
        self.zygotes = {}
        self.cordons = {}
        self.wlock = threading.Lock()
        if self.iso == "forkwasm":
            for mid in self.modules:
                self.zygotes[mid] = Spawned(self.worker, "zygote", self.modules[mid], args.runtime_dir)
        self.db = None
        backends = (cfg.get("data") or {}).get("backends", [])
        for b in backends:
            if b.get("engine") == "sqlite":
                path = b["dsn_ref"].split(":", 1)[1]
                self.db = sqlite3.connect(path, timeout=b.get("op_budget_ms", 5000) / 1000.0,
                                          check_same_thread=False, isolation_level=None)
        self.dblock = threading.Lock()
        self.rid = 0
        self.rid_lock = threading.Lock()

    def compile(self, m):
        if not self.worker or not os.path.exists(self.worker):
            die(78, "p2.worker missing")
        with open(m["path"], "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() != m["sha256"]:
                die(78, f"module {m['id']}: digest mismatch")
        out = os.path.join(self.cache, f"{m['id']}.cwasm")
        r = subprocess.run([self.worker, "compile", "--in", m["path"], "--out", out], capture_output=True,
                           timeout=300)
        if r.returncode != 0:
            die(78, f"module {m['id']}: refused by compile: {r.stderr.decode(errors='replace')[-200:]}")
        with open(out, "rb") as f:
            dig = hashlib.sha256(f.read()).hexdigest()
        self.modules[m["id"]] = dict(m, cwasm=out, digest=dig)

    # ---------------------------------------------------------------- crash budget (D7)
    def penalized(self, principal):
        with self.cb_lock:
            until = self.penalty.get(principal)
            return until is not None and time.monotonic() < until

    def charge(self, principal):
        n, window, pen = self.cb
        now = time.monotonic()
        with self.cb_lock:
            q = self.crashes.setdefault(principal, deque())
            q.append(now)
            while q and q[0] < now - window:
                q.popleft()
            if len(q) >= n:
                self.penalty[principal] = now + pen

    # ---------------------------------------------------------------- routing
    def route_for(self, path):
        for r in self.routes:
            if path.startswith(r["path"]):
                return r
        return None

    def handle_http(self, method, path, headers, body):
        r = self.route_for(path)
        if r is None or "wasm" not in r.get("to", {}):
            return NOTFOUND
        auth = headers.get(b"authorization", b"").decode(errors="replace")
        if not auth.startswith("Bearer "):
            return UNAUTH
        who = self.tokens.verify(auth[7:].strip())
        if who is None:
            return UNAUTH
        tenant, subject = who
        principal = (tenant, subject)
        if self.penalized(principal):
            return TOO_MANY
        return self.p2_request(r, self.modules[r["to"]["wasm"]], principal, tenant, method, path, body)

    def next_rid(self):
        with self.rid_lock:
            self.rid += 1
            return self.rid

    def worker_conn(self, mod, principal):
        """forkwasm: a fresh connection to the module's zygote (one fork child). cordon: the principal's cordon."""
        if self.iso == "forkwasm" and mod.get("tenancy", "multi") == "multi":
            with self.wlock:
                z = self.zygotes[mod["id"]]
                if not z.alive():
                    z.kill()
                    z = self.zygotes[mod["id"]] = Spawned(self.worker, "zygote", mod, self.args.runtime_dir)
            return None, z.connect()
        key = (mod["id"], principal)  # the cordon key is the principal (never shared)
        with self.wlock:
            c = self.cordons.get(key)
            if c is None or not c.alive():
                if c:
                    c.kill()
                c = self.cordons[key] = Spawned(self.worker, "cordon", mod, self.args.runtime_dir)
        if c.conn is None:
            c.conn = c.connect()
        return c, c.conn

    def p2_request(self, route, mod, principal, tenant, method, path, body):
        limits = dict(self.limits_default)
        for k in ("fuel", "wall_ms", "memory_mib"):
            if k in mod:
                limits[k] = mod[k]
        cordon = None
        try:
            cordon, conn = self.worker_conn(mod, principal)
        except (OSError, f14.DecodeError):
            self.charge(principal)
            return UNAVAIL
        lock = cordon.lock if cordon else threading.Lock()
        with lock:
            pending = []
            try:
                outcome, head, chunks = self.exchange(conn, route, tenant, principal, limits, method, path, body,
                                                      pending)
            except DecodeFailure:
                outcome, head, chunks = ("decode-failure", None), None, []
            if MUT == "no-audit-on-trap":
                # MUTANT: authorized data_runs are audited only when the request completes without a trap
                if outcome[0] not in ("trap", "decode-failure", "died"):
                    for ev in pending:
                        self.audit.append(*ev)
            kind = outcome[0]
            if cordon is None:
                try:
                    conn.close()  # a fork child serves exactly one request
                except OSError:
                    pass
            if kind in ("decode-failure", "died", "timeout"):
                # F14: kill the worker (the cordon; a fork child is disconnected), charge the principal
                if cordon:
                    cordon.kill()
                    with self.wlock:
                        self.cordons.pop((mod["id"], principal), None)
                self.charge(principal)
                return DENY
            if kind == "trap":
                self.charge(principal)
                if MUT == "trap-maps-to-allow":
                    return self.serialize(head or (200, []), chunks)  # MUTANT: trap treated as Allow
                return DENY
            if kind == "code" and outcome[1] == 0:
                return self.serialize(head or (200, []), chunks)
            return DENY  # Deny (1) or Error (any other code): I7 tri-state, Error => Deny

    def headers_ok(self, status, hs):
        if not (200 <= status <= 599):
            return False
        if len(hs) > 128:
            return False
        total = 0
        for n, v in hs:
            if not (1 <= len(n) <= 64) or any(b not in TCHAR for b in n):
                return False
            if n in BANNED or n.startswith(b"proxy-"):
                return False
            if any(not (b in (0x20, 0x09) or 0x21 <= b <= 0x7E) for b in v):
                return False
            if v[:1] in (b" ", b"\t") or v[-1:] in (b" ", b"\t"):
                return False
            total += len(n) + len(v) + 32
        return total <= 16384

    def exchange(self, conn, route, tenant, principal, limits, method, path, body, pending):
        rid = self.next_rid()
        req_id = secrets.token_hex(16)
        conn.send(f14.f_request(rid, limits, f14.req_head(method, path.split("?")[0], None, [], len(body))))
        conn.send(f14.f_body(rid, body, True))
        head, chunks, nbody, nlog, druns, dbytes = None, [], 0, 0, 0, 0
        deadline = time.monotonic() + limits["wall_ms"] / 1000.0 + GRACE_S
        while True:
            f = self.recv(conn, deadline)
            if f is None:
                return ("timeout",), None, []
            if f == b"":
                return ("died",), None, []
            if len(f) > self.frame_max:
                raise DecodeFailure("oversized frame")
            try:
                d = f14.dec_w2s(f)
            except f14.DecodeError as e:
                raise DecodeFailure(str(e))
            if d.get("rid") != rid:
                raise DecodeFailure("unknown req-id")
            t = d["t"]
            if t == "resp-head":
                if head is not None and MUT != "double-response-accepted":
                    raise DecodeFailure("second resp-head")
                hs = d["headers"]
                if MUT != "raw-passthrough" and not self.headers_ok(d["status"], hs):
                    raise DecodeFailure("resp-head fails the I5 rules")
                head = (d["status"], hs)  # MUTANT double-response-accepted: the later head replaces the first
                chunks = [] if MUT == "double-response-accepted" else chunks
            elif t == "resp-body":
                if head is None:
                    raise DecodeFailure("resp-body before resp-head")
                nbody += len(d["chunk"])
                if nbody > limits["max_resp_bytes"]:
                    raise DecodeFailure("response byte quota")
                chunks.append(d["chunk"])
            elif t == "log":
                nlog += len(d["data"])
                if nlog > limits["max_log_bytes"]:
                    raise DecodeFailure("log byte quota")
            elif t == "data-run":
                if d["seq"] != druns:
                    raise DecodeFailure("data-run out of order")
                druns += 1
                dbytes += len(d["op"])
                if druns > limits["max_data_runs"] or dbytes > limits["max_data_bytes"]:
                    raise DecodeFailure("data_run quota")
                result = self.data_run(d["op"], route, tenant, req_id, pending)
                dbytes += len(result)
                conn.send(f14.f_data_reply(rid, d["seq"], result))
            elif t == "resp-end":
                end = d["end"]
                if end[0] == "trap" and MUT == "double-response-accepted":
                    late = self.late(conn, rid)  # MUTANT: frames after resp-end are still accepted
                    if late:
                        return ("code", 0), late[0], late[1]
                return end, head, chunks
            else:
                raise DecodeFailure(f"unexpected frame {t}")

    def late(self, conn, rid):
        head, chunks = None, []
        deadline = time.monotonic() + 0.3
        while True:
            f = self.recv(conn, deadline)
            if not f:
                return None
            try:
                d = f14.dec_w2s(f)
            except f14.DecodeError:
                return None
            if d["t"] == "resp-head":
                head = (d["status"], d["headers"])
            elif d["t"] == "resp-body":
                chunks.append(d["chunk"])
            elif d["t"] == "resp-end":
                return (head, chunks) if d["end"] == ("code", 0) and head else None

    def recv(self, conn, deadline):
        left = deadline - time.monotonic()
        if left <= 0:
            return None
        conn.settimeout(left)
        try:
            return conn.recv(self.frame_max + 1)
        except socket.timeout:
            return None
        except OSError:
            return b""

    def serialize(self, head, chunks):
        status, hs = head
        body = b"".join(chunks)
        out = [f"HTTP/1.1 {status} OK".encode()]
        for n, v in hs:
            out.append(n + b": " + v)  # validated in exchange(); MUTANT raw-passthrough skips that check
        out.append(f"content-length: {len(body)}".encode())
        out.append(b"connection: close")
        return b"\r\n".join(out) + b"\r\n\r\n" + body

    # ---------------------------------------------------------------- data_run (I1, I6-host)
    def authorize(self, route, op):
        caps = route.get("data")
        if not isinstance(caps, list) or not caps:
            return False  # INV-NONEMPTY: no data key = no capability
        fields = [f for f, _ in op["writes"]] + list(op["returning"]) + pred_fields(op["filter"])
        if any(f == 0 for f, _ in op["writes"]):
            return False  # TenantFieldWritten
        for c in caps:
            if c.get("collection") != op["collection"] or op["kind"] not in c.get("ops", []):
                continue
            permitted = {NOTES_FIELDS[n] for n in c.get("columns", []) if n in NOTES_FIELDS}
            if all(f in permitted for f in fields):
                return True
        return False

    def data_run(self, opb, route, tenant, req_id, pending):
        try:
            op = f14.dec_op(opb)
        except (f14.DecodeError, RecursionError):
            raise DecodeFailure("malformed data_run op")
        if MUT != "tenant-not-overwritten":
            op["tenant"] = tenant  # the route-bound tenant replaces the module's placeholder
        actor = {"kind": "principal", "tenant": tenant}
        detail = {"kind": op["kind"], "collection": op["collection"][:64]}
        allowed = True if MUT == "data-run-skips-authorize" else self.authorize(route, op)
        if not allowed:
            self.audit.append(actor, "p2.data_run", op["collection"], "deny", req_id, detail)
            return f14.result_err(1)
        ev = (actor, "p2.data_run", op["collection"], "allow", req_id, detail)
        if MUT == "audit-after-effect":
            res = self.execute(op)
            self.audit.append(*ev)  # MUTANT: audit after the effect
            return res
        if MUT == "no-audit-on-trap":
            pending.append(ev)
            return self.execute(op)
        self.audit.append(*ev)  # audit before effect (durable: fsynced)
        return self.execute(op)

    def execute(self, op):
        if self.db is None:
            return f14.result_err(1)
        t = f"{op['tenant']:016x}"
        try:
            where, params = pred_sql(op["filter"])
        except (KeyError, ValueError):
            return f14.result_err(1)
        try:
            cols = [FIELD_NAMES[f] for f in op["returning"]]
            w = {FIELD_NAMES[f]: v for f, v in op["writes"]}
        except KeyError:
            return f14.result_err(1)
        if op["collection"] != "notes":
            return f14.result_err(1)
        with self.dblock:
            try:
                k = op["kind"]
                if k == "select":
                    rows = self.db.execute(f"SELECT {', '.join(cols) or '1'} FROM notes WHERE tenant = ? AND "
                                           f"({where})", [t] + params).fetchall()
                    return f14.result_rows([list(r) if cols else [] for r in rows])
                if k == "insert":
                    self.db.execute("INSERT INTO notes(tenant, id, body) VALUES(?, ?, ?)",
                                    (t, w.get("id"), w.get("body")))
                elif k == "upsert":
                    self.db.execute("INSERT INTO notes(tenant, id, body) VALUES(?, ?, ?) ON CONFLICT(tenant, id) "
                                    "DO UPDATE SET body = excluded.body", (t, w.get("id"), w.get("body")))
                elif k == "update":
                    sets = ", ".join(f"{c} = ?" for c in w)
                    self.db.execute(f"UPDATE notes SET {sets} WHERE tenant = ? AND ({where})",
                                    list(w.values()) + [t] + params)
                elif k == "delete":
                    self.db.execute(f"DELETE FROM notes WHERE tenant = ? AND ({where})", [t] + params)
                return f14.result_rows([])
            except sqlite3.Error:
                return f14.result_err(1)


def pred_fields(p):
    k = p[0]
    if k in ("tt", "ff"):
        return []
    if k in ("and", "or"):
        return pred_fields(p[1]) + pred_fields(p[2])
    if k == "not":
        return pred_fields(p[1])
    return [p[1]]


def pred_sql(p):
    k = p[0]
    if k == "tt":
        return "1", []
    if k == "ff":
        return "0", []
    if k == "eq":
        return f"{FIELD_NAMES[p[1]]} = ?", [p[2]]
    if k == "in":
        if not p[2]:
            return "0", []
        return f"{FIELD_NAMES[p[1]]} IN ({', '.join('?' * len(p[2]))})", list(p[2])
    if k == "range":
        return f"{FIELD_NAMES[p[1]]} BETWEEN ? AND ?", [p[2], p[3]]
    if k == "pfx":
        return f"substr({FIELD_NAMES[p[1]]}, 1, ?) = ?", [len(p[2]), p[2]]
    if k in ("and", "or"):
        a, pa = pred_sql(p[1])
        b, pb = pred_sql(p[2])
        return f"({a}) {'AND' if k == 'and' else 'OR'} ({b})", pa + pb
    if k == "not":
        a, pa = pred_sql(p[1])
        return f"NOT ({a})", pa
    raise ValueError(k)


# ------------------------------------------------------------------------------------------------ HTTP front
def read_request(s):
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d:
            return None
        buf += d
        if len(buf) > 65536:
            return None
    head, rest = buf.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ")
    if len(parts) != 3:
        return None
    hs = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            hs[k.strip().lower()] = v.strip()
    n = int(hs.get(b"content-length", b"0") or 0)
    while len(rest) < n:
        d = s.recv(65536)
        if not d:
            return None
        rest += d
    return parts[0].decode(), parts[1].decode(errors="replace"), hs, rest[:n]


def main():
    ap = argparse.ArgumentParser()
    for k in ("config", "cert", "key", "audit-dir", "runtime-dir", "token-keyring"):
        ap.add_argument(f"--{k}", required=True)
    args = ap.parse_args()
    try:
        with open(args.config) as f:
            cfg = json.load(f)
    except (OSError, ValueError) as e:
        die(78, f"config: {e}")
    os.makedirs(args.runtime_dir, exist_ok=True)
    sup = Supervisor(cfg, args)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    ctx.set_alpn_protocols(["http/1.1"])

    class H(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                s = ctx.wrap_socket(self.request, server_side=True)
            except (ssl.SSLError, OSError):
                return
            try:
                s.settimeout(30)
                req = read_request(s)
                if req is None:
                    return
                s.sendall(sup.handle_http(*req))
            except (OSError, ssl.SSLError):
                pass
            finally:
                try:
                    s.close()
                except OSError:
                    pass

    class Admin(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                self.request.recv(4096)
                self.request.sendall(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\nconnection: close\r\n\r\nok\n")
            except OSError:
                pass

    class TS(socketserver.ThreadingMixIn, socketserver.TCPServer):
        daemon_threads = True
        allow_reuse_address = True

    lst = cfg["listeners"][0]["bind"].rsplit(":", 1)
    adm = cfg["admin"]["bind"].rsplit(":", 1)
    srv = TS((lst[0], int(lst[1])), H)
    asrv = TS((adm[0], int(adm[1])), Admin)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def term(*_):
        for z in list(sup.zygotes.values()) + list(sup.cordons.values()):
            z.kill()
        os._exit(0)
    signal.signal(signal.SIGTERM, term)
    asrv.serve_forever()


if __name__ == "__main__":
    main()
