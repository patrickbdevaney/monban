"""Host level of the hostile-modules oracle (gate p2-hostile-host).

Boots the subject (the real monban binary with feature p2, or the reference supervisor ref_host.py) with an
oracle-written F8 config, drives it over TLS (HTTP/1.1) with F5 Tier-L tokens, and judges by
  - response bytes (I5: no module byte before an Allow completion, host re-serialization; I7: every failure equals
    the host's explicit-Deny response),
  - the F9 audit log in --audit-dir (tlog-tiles entry bundles; I6-host: audit before effect, trap still audited),
  - the SQLite effect sink notes.db, read directly (I1: capability and tenant overwrite; audit-vs-effect diff).
Subject contract: README.md "Host level".
"""

import base64
import copy
import hashlib
import hmac
import json
import os
import random
import secrets
import signal
import socket
import sqlite3
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

import f14
import guests

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
VHOST = "monban.test"
OP_BUDGET_MS = 5000
GRACE_MS = 2000
HOLD_S = 0.8          # audit-order: how long the oracle holds the SQLite write lock at most
VICTIM_SECRET = "VICTIM-SECRET"
HOST_MUTANTS = {
    # mutant (AEGIS_P2_MUTANT on the supervisor) -> cases of which at least one must be red (README "Self-test")
    "raw-passthrough": ["e-i5-crlf-header", "e-i5-obs-text-header", "e-i5-framing-header", "e-i5-status-range"],
    "double-response-accepted": ["e-i5-double-head", "e-i5-late-response"],
    "audit-after-effect": ["h-i6-audit-before-effect"],
    "no-audit-on-trap": ["h-i6-trap-after-effect"],
    "trap-maps-to-allow": ["h-i7-trap-after-response", "h-i7-trap", "h-i5-partial-body-then-trap"],
    "data-run-skips-authorize": ["h-i1-cap-none", "h-i1-cap-readonly", "h-i1-cap-column", "h-i1-cap-collection"],
    "tenant-not-overwritten": ["h-i1-ctx-insert", "h-i1-ctx-select"],
}
BOOTS = [("real", "forkwasm"), ("real", "cordon"), ("escaped", "forkwasm"), ("escaped", "cordon")]


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ------------------------------------------------------------------------------------------------ F5 Tier-L minting
# Same construction as oracles/native-e2e/e2e.py (P4-oracle-e2e-001), copied so this oracle stays self-contained.
def cbor(v):
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
        b = v.encode()
        return head(3, len(b)) + b
    return head(4, len(v)) + b"".join(cbor(x) for x in v)


def hkdf_k_aud(master, aud, kid):
    prk = hmac.new(b"", master, hashlib.sha256).digest()
    a = aud.encode()
    info = b"aegis-cap-v1" + struct.pack("!H", len(a)) + a + struct.pack("!H", len(kid)) + kid
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def mint(master, kid, tenant, aud=VHOST, ops=31, exp_delta=600):
    now = int(time.time())
    nonce = secrets.token_bytes(16)
    cavs = [[0, aud], [1, now + exp_delta], [8, 2], [3, ops], [6, tenant]]
    t = hmac.new(hkdf_k_aud(master, aud, kid), kid + nonce, hashlib.sha256).digest()
    for c in cavs:
        t = hmac.new(t, cbor(c), hashlib.sha256).digest()
    raw = cbor([1, kid, nonce, cavs, t])
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# ------------------------------------------------------------------------------------------------ client
class Resp:
    def __init__(self, raw, elapsed):
        self.raw, self.elapsed = raw, elapsed
        self.status, self.headers, self.body = None, [], b""
        if b"\r\n\r\n" in raw:
            head, self.body = raw.split(b"\r\n\r\n", 1)
            lines = head.split(b"\r\n")
            try:
                self.status = int(lines[0].split(b" ")[1])
            except (IndexError, ValueError):
                pass
            for ln in lines[1:]:
                if b":" in ln:
                    k, v = ln.split(b":", 1)
                    self.headers.append((k.strip().lower(), v.strip()))

    def header(self, name):
        return [v for k, v in self.headers if k == name.encode()]

    def __repr__(self):
        return f"<{self.status} {self.raw[:160]!r}>"


def h1(port, cafile, method, path, token=None, body=b"", timeout=20):
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.set_alpn_protocols(["http/1.1"])
    t0 = time.monotonic()
    raw = b""
    try:
        s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=timeout), server_hostname=VHOST)
    except (OSError, ssl.SSLError) as e:
        r = Resp(b"", 0)
        r.error = str(e)
        return r
    h = [f"{method} {path} HTTP/1.1", f"host: {VHOST}", "connection: close", f"content-length: {len(body)}"]
    if token:
        h.append(f"authorization: Bearer {token}")
    try:
        s.sendall(("\r\n".join(h) + "\r\n\r\n").encode() + body)
        while True:
            d = s.recv(65536)
            if not d:
                break
            raw += d
    except (OSError, ssl.SSLError):
        pass
    finally:
        s.close()
    return Resp(raw, time.monotonic() - t0)


# ------------------------------------------------------------------------------------------------ audit log reader
def read_audit(audit_dir):
    """All F9 events in every log under audit_dir (C2SP tlog-tiles entry bundles: big-endian u16-prefixed leaves;
    a full bundle tile/entries/<N>, partial ones tile/entries/<N>.p/<width>; the widest file per index wins)."""
    events = []
    if not os.path.isdir(audit_dir):
        return events
    for log in sorted(os.listdir(audit_dir)):
        root = os.path.join(audit_dir, log, "tile", "entries")
        if not os.path.isdir(root):
            continue
        best = {}  # index path -> (width, file)
        for dp, _, fns in os.walk(root):
            for fn in fns:
                if fn.startswith("."):
                    continue
                full = os.path.join(dp, fn)
                rel = os.path.relpath(full, root)
                parts = rel.split(os.sep)
                if len(parts) >= 2 and parts[-2].endswith(".p"):
                    idx = os.sep.join(parts[:-2] + [parts[-2][:-2]])
                    try:
                        w = int(parts[-1])
                    except ValueError:
                        continue
                else:
                    idx, w = rel, 256
                if idx not in best or w > best[idx][0]:
                    best[idx] = (w, full)
        for idx in sorted(best, key=lambda x: int(x.replace("x", "").replace(os.sep, "") or 0)):
            try:
                data = open(best[idx][1], "rb").read()
            except OSError:
                continue
            off = 0
            while off + 2 <= len(data):
                n = int.from_bytes(data[off:off + 2], "big")
                leaf = data[off + 2:off + 2 + n]
                off += 2 + n
                try:
                    events.append(json.loads(leaf))
                except ValueError:
                    events.append({"_undecodable": leaf[:80].hex()})
    return events


def dr_events(events, tenant):
    out = {"allow": 0, "deny": 0}
    for e in events:
        if e.get("action") == "p2.data_run" and (e.get("actor") or {}).get("tenant") == tenant:
            if e.get("outcome") == "allow":
                out["allow"] += 1
            elif e.get("outcome") == "deny":
                out["deny"] += 1
    return out


def subst(obj, rowid, victim):
    if isinstance(obj, dict):
        return {k: subst(v, rowid, victim) for k, v in obj.items()}
    if isinstance(obj, list):
        return [subst(v, rowid, victim) for v in obj]
    if obj == "{victim}":
        return victim
    if obj == "{rowid}":
        return rowid
    return obj


def tenant_text(t):
    return f"{t:016x}"


# ------------------------------------------------------------------------------------------------ one boot
class Boot:
    def __init__(self, cmd, worker, isolation, cases, env_extra, workdir, verbose, label):
        self.cmd, self.worker, self.iso = cmd, worker, isolation
        self.cases = cases
        self.env_extra = env_extra
        self.verbose = verbose
        self.label = label
        self.dir = tempfile.mkdtemp(prefix="hb-", dir=workdir)
        self.failures, self.passed = [], 0
        self.proc = None
        rnd = random.SystemRandom()
        self.victim = rnd.randrange(1 << 40, 1 << 62)
        self.tenants = {}
        for c in cases:
            self.tenants[c["id"]] = rnd.randrange(1 << 40, 1 << 62)
        self.kid = b"hm-" + secrets.token_hex(3).encode()
        self.master = secrets.token_bytes(32)
        self.deny = None

    def check(self, name, reason):
        name = f"{self.label}:{name}"
        if reason is None:
            self.passed += 1
            if self.verbose:
                print(f"  ok   {name}", flush=True)
        else:
            self.failures.append(name)
            print(f"  FAIL {name}: {reason}", flush=True)

    # ---------------------------------------------------------------- setup
    def setup(self):
        d = self.dir
        self.key_pem, self.crt = os.path.join(d, "key.pem"), os.path.join(d, "cert.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-keyout", self.key_pem, "-out", self.crt, "-days", "30", "-subj", f"/CN={VHOST}",
                        "-addext", f"subjectAltName=DNS:{VHOST}"], check=True, capture_output=True, timeout=30)
        self.kr = os.path.join(d, "token-keyring.json")
        with open(self.kr, "w") as f:
            json.dump({"keys": [{"kid": self.kid.hex(), "key": self.master.hex()}]}, f)
        os.chmod(self.kr, 0o600)
        self.db = os.path.join(d, "notes.db")
        c = sqlite3.connect(self.db)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("CREATE TABLE notes(tenant TEXT NOT NULL COLLATE BINARY, id TEXT NOT NULL COLLATE BINARY, "
                  "body TEXT NOT NULL, PRIMARY KEY(tenant,id)) WITHOUT ROWID")
        c.execute("INSERT INTO notes VALUES(?,?,?)", (tenant_text(self.victim), "victim", VICTIM_SECRET))
        c.commit()
        c.close()
        self.audit = os.path.join(d, "audit")
        self.run_dir = os.path.join(d, "run")
        self.cache = os.path.join(d, "cache")
        os.makedirs(self.run_dir)
        os.makedirs(self.cache, mode=0o700)
        mods, routes = [], []
        self.route = {}
        for i, c in enumerate(self.cases):
            rowid = f"r-{c['id']}"
            args = subst(copy.deepcopy(c.get("args") or {}), rowid, self.victim)
            wasm = guests.build(c["builder"], args)
            wp = os.path.join(d, f"m{i}.wasm")
            with open(wp, "wb") as f:
                f.write(wasm)
            m = {"id": f"m{i}", "path": wp, "sha256": hashlib.sha256(wasm).hexdigest()}
            if c.get("wall_ms"):
                m["wall_ms"] = c["wall_ms"]
            mods.append(m)
            r = {"id": i + 1, "path": f"/c{i}/", "to": {"wasm": f"m{i}"}, "authz": "allow-all"}
            cap = c.get("cap", "none")
            if cap != "none":
                ops = ["select"] if cap == "ro" else ["select", "insert", "update", "delete", "upsert"]
                r["data"] = [{"backend": "sq", "collection": "notes", "ops": ops, "columns": ["id", "body"]}]
            routes.append(r)
            self.route[c["id"]] = f"/c{i}/x"
        self.port, self.aport = free_port(), free_port()
        self.cfg = {
            "v": 1,
            "listeners": [{"name": "pub", "bind": f"127.0.0.1:{self.port}", "profile": "P-PUBLIC-WEB",
                           "alpn": ["h2", "http/1.1"]}],
            "admin": {"bind": f"127.0.0.1:{self.aport}"},
            "data": {"backends": [{"id": "sq", "engine": "sqlite", "dsn_ref": f"path:{self.db}", "pin": "sqlite",
                                   "op_budget_ms": OP_BUDGET_MS}]},
            "p2": {"worker": self.worker, "cache_dir": self.cache, "isolation": self.iso, "modules": mods},
            "vhosts": [{"host": VHOST, "routes": routes}],
        }
        self.cfg_path = os.path.join(d, "monban.json")
        with open(self.cfg_path, "w") as f:
            json.dump(self.cfg, f, indent=1)

    def start(self):
        env = dict(os.environ)
        for k in ("NOTIFY_SOCKET", "AEGIS_UPGRADE_DIR", "AEGIS_P2_MUTANT", "HOSTILE_ESCAPED"):
            env.pop(k, None)
        env.update(self.env_extra)
        self.log = open(os.path.join(self.dir, "subject.log"), "ab")
        argv = self.cmd + ["--config", self.cfg_path, "--cert", self.crt, "--key", self.key_pem,
                           "--audit-dir", self.audit, "--runtime-dir", self.run_dir, "--token-keyring", self.kr]
        self.proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT,
                                     env=env, start_new_session=True)
        until = time.time() + 60
        while time.time() < until:
            if self.proc.poll() is not None:
                raise RuntimeError(f"subject exited {self.proc.returncode} at boot: {self.tail()}")
            try:
                with socket.create_connection(("127.0.0.1", self.aport), timeout=1) as c:
                    c.sendall(b"GET /healthz HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
                    if c.recv(64).split(b" ")[1:2] == [b"200"]:
                        return
            except OSError:
                pass
            time.sleep(0.1)
        raise RuntimeError(f"subject did not become healthy within 60 s: {self.tail()}")

    def tail(self):
        try:
            with open(os.path.join(self.dir, "subject.log"), "rb") as f:
                return f.read()[-1200:].decode(errors="replace")
        except OSError:
            return ""

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(10)
            except (subprocess.TimeoutExpired, ProcessLookupError, PermissionError):
                pass
        if self.proc:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)  # explicit pgid of the session we started (workers too)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                pass

    # ---------------------------------------------------------------- driving
    def token(self, cid):
        return mint(self.master, self.kid, self.tenants[cid])

    def req(self, cid, token=None, path=None):
        return h1(self.port, self.crt, "GET", path or self.route[cid], token or self.token(cid))

    def rows(self, where, args):
        c = sqlite3.connect(self.db, timeout=10)
        try:
            return c.execute(f"SELECT tenant, id, body FROM notes WHERE {where}", args).fetchall()
        finally:
            c.close()

    def audit_counts(self, tenant, want=None, wait=2.0):
        """Polls until `want(counts)` holds or `wait` s pass (audit appends are durable before the effect, but a
        deny event may be written after the reply)."""
        t_end = time.monotonic() + wait
        while True:
            cnt = dr_events(read_audit(self.audit), tenant)
            if want is None or want(cnt) or time.monotonic() >= t_end:
                return cnt
            time.sleep(0.05)

    def run(self):
        self.setup()
        try:
            self.start()
        except RuntimeError as e:
            for c in self.cases:
                self.check(c["id"], f"boot failed: {e}")
            return
        try:
            order = sorted(self.cases, key=lambda c: (not c.get("defines_deny"), c["id"]))
            for c in order:
                try:
                    reason = self.run_case(c)
                except Exception as e:  # an oracle-side error is a failure, never a pass
                    reason = f"oracle error: {type(e).__name__}: {e}"
                self.check(c["id"], reason)
            self.check("audit-vs-effect-diff", self.audit_diff())
            if self.proc.poll() is not None:
                self.check("supervisor-alive", f"the supervisor exited ({self.proc.returncode}): {self.tail()}")
            else:
                self.check("supervisor-alive", None)
        finally:
            self.stop()

    def is_deny(self, r, absent):
        if r.status is None:
            return f"no HTTP response ({getattr(r, 'error', 'connection closed')})"
        low = r.raw.lower()
        for m in absent:
            if m.lower().encode() in low:
                return f"module bytes {m!r} reached the client: {r!r}"
        if self.deny is None:
            return "no explicit-Deny reference response (h-control-deny failed)"
        if (r.status, r.body) != self.deny:
            return f"response {r.status} {r.body[:60]!r} differs from the host's Deny response {self.deny[0]} " \
                   f"{self.deny[1][:60]!r} (Error/trap/timeout must map to Deny)"
        return None

    def run_case(self, c):
        cid = c["id"]
        T = self.tenants[cid]
        exp = c["expect"]
        if exp == "crash-budget":
            return self.crash_budget(c)
        if c.get("audit_order"):
            return self.audit_order(c)
        r = self.req(cid)
        if c.get("defines_deny"):
            if r.status is None or 200 <= r.status < 400:
                return f"explicit Deny answered {r!r} (must be a non-2xx/3xx host response)"
            low = r.raw.lower()
            for m in c.get("absent", []):
                if m.lower().encode() in low:
                    return f"module bytes {m!r} reached the client on Deny: {r!r}"
            self.deny = (r.status, r.body)
            return None
        reason = None
        if exp == "deny":
            reason = self.is_deny(r, c.get("absent", []))
            if reason is None and c.get("max_ms") and r.elapsed * 1000 > c["max_ms"]:
                reason = f"deny took {r.elapsed * 1000:.0f} ms > {c['max_ms']} ms"
        elif exp == "allow":
            reason = self.is_allow(r, c)
        if reason:
            return reason
        return self.effects(c, T)

    def is_allow(self, r, c):
        if r.status != 200:
            return f"expected the module's 200, got {r!r}"
        if r.header("x-mod") != [b"1"]:
            return f"module header x-mod missing or altered: {r.headers}"
        cl = r.header("content-length")
        if r.header("transfer-encoding") or cl != [str(len(r.body)).encode()]:
            return f"framing not host-computed (content-length {cl}, body {len(r.body)} bytes)"
        if c.get("body") is not None and r.body != c["body"].encode():
            return f"body {r.body[:60]!r} != {c['body']!r}"
        if c.get("result"):
            try:
                kind, val = f14.dec_result(r.body)
            except f14.DecodeError as e:
                return f"module body is not an F10 result ({e}): {r.body[:40]!r}"
            if kind != c["result"]:
                return f"data_run result {kind} {val!r}, expected {c['result']}"
            if c.get("victim_secret_absent") and VICTIM_SECRET in json.dumps(val):
                return "the select returned the victim tenant's row (tenant not overwritten)"
        return None

    def effects(self, c, T):
        e = c.get("effect", {})
        rowid = f"r-{c['id']}"
        if "own_rows" in e:
            n = len(self.rows("tenant = ? AND id = ?", (tenant_text(T), rowid)))
            if n != e["own_rows"]:
                return f"{n} rows under the caller's tenant, expected {e['own_rows']}"
        if "rowid_rows" in e:
            rs = self.rows("id = ?", (rowid,))
            if len(rs) != e["rowid_rows"] or any(t != tenant_text(T) for t, _, _ in rs):
                return f"rows with this case's id: {rs} (expected {e['rowid_rows']} under {tenant_text(T)})"
        a = c.get("audit")
        if a:
            def ok(cnt):
                return (cnt["allow"] == a.get("allow", cnt["allow"]) and cnt["allow"] >= a.get("allow_min", 0)
                        and cnt["deny"] >= a.get("deny_min", 0))
            cnt = self.audit_counts(T, ok)
            if not ok(cnt):
                return f"audit p2.data_run events for the tenant {cnt}, expected {a}"
        if c.get("rows_le_audit"):
            n = len(self.rows("tenant = ? AND id = ?", (tenant_text(T), rowid)))
            cnt = self.audit_counts(T)
            if n > cnt["allow"]:
                return f"{n} effects but {cnt['allow']} allow audit events (effect without audit)"
        return None

    def audit_order(self, c):
        cid = c["id"]
        T = self.tenants[cid]
        lock = sqlite3.connect(self.db, isolation_level=None, timeout=10)
        lock.execute("BEGIN IMMEDIATE")
        out = {}
        th = threading.Thread(target=lambda: out.setdefault("r", self.req(cid)), daemon=True)
        held = True
        try:
            th.start()
            t_end = time.monotonic() + HOLD_S
            seen = False
            while time.monotonic() < t_end:
                if dr_events(read_audit(self.audit), T)["allow"] >= 1:
                    seen = True
                    break
                time.sleep(0.02)
            pre_rows = len(self.rows("tenant = ? AND id = ?", (tenant_text(T), f"r-{cid}")))
            lock.execute("ROLLBACK")
            held = False
        finally:
            if held:
                lock.execute("ROLLBACK")
            lock.close()
        th.join(OP_BUDGET_MS / 1000 + 10)
        if pre_rows:
            return "the effect was visible while the oracle held the write lock (oracle error)"
        if not seen:
            return f"no p2.data_run audit event while the effect was blocked for {HOLD_S} s (audit after effect)"
        return self.effects(c, T)

    def crash_budget(self, c):
        cid = c["id"]
        tok = self.token(cid)
        for i in range(3):
            r = self.req(cid, tok)
            reason = self.is_deny(r, [])
            if reason:
                return f"trap {i + 1}/3: {reason}"
        healthy = self.route.get("h-control-allow")
        if not healthy:
            return "h-control-allow is not in this boot (oracle error)"
        r = self.req(cid, tok, healthy)
        if r.status != 429:
            return f"after 3 crash-attributable faults in the window the principal's next request got {r!r}, not 429"
        other = mint(self.master, self.kid, random.SystemRandom().randrange(1 << 40, 1 << 62))
        r = self.req(cid, other, healthy)
        if r.status != 200:
            return f"another principal was affected by this principal's crash budget: {r!r}"
        return None

    def audit_diff(self):
        """Every row in the effect sink (except the seeded victim row) has at least as many allow audit events
        for its tenant as it has rows: no effect without an audit event (I6-host)."""
        ev = read_audit(self.audit)
        bad = [e for e in ev if "_undecodable" in e]
        if bad:
            return f"{len(bad)} audit leaves are not JSON"
        per = {}
        for t, i, _ in self.rows("1", ()):
            if (t, i) == (tenant_text(self.victim), "victim"):
                continue
            per[t] = per.get(t, 0) + 1
        for t, n in per.items():
            a = dr_events(ev, int(t, 16))["allow"]
            if n > a:
                return f"tenant {t}: {n} rows but {a} allow audit events (effect without audit)"
        return None


# ------------------------------------------------------------------------------------------------ level driver
def escaped_wrapper(ref_worker, workdir):
    p = os.path.join(workdir, "escaped-worker")
    with open(p, "w") as f:
        f.write(f"#!/bin/sh\n# compromised reference worker (HOSTILE_ESCAPED=1), README 'escaped worker'\n"
                f"HOSTILE_ESCAPED=1 exec {ref_worker} \"$@\"\n")
    os.chmod(p, stat.S_IRWXU)
    return p


def host_run(cmd, worker, escaped, env_extra, workdir, verbose, label, only=None):
    cases = json.load(open(os.path.join(HERE, "corpus", "host.json")))["cases"]
    if only:
        keep = set(only) | {"h-control-deny", "h-control-allow"}
        cases = [c for c in cases if c["id"] in keep]
    fails, passed = [], 0
    for wk, iso in BOOTS:
        cs = [c for c in cases if c["worker"] == wk]
        if wk == "escaped":
            cs = [c for c in cases if c.get("defines_deny")] + cs
        if not cs:
            continue
        b = Boot(cmd, worker if wk == "real" else escaped, iso, cs, env_extra, workdir, verbose, f"{wk}/{iso}")
        b.run()
        fails += b.failures
        passed += b.passed
    return fails, passed


def case_of(fail):
    return fail.split(":", 1)[1]


def run_level(a, ref_worker, workdir):
    if a.subject:
        cmd = [os.path.abspath(a.subject)] if os.path.exists(a.subject) else a.subject.split()
        if not a.worker:
            return False, "--level host --subject needs --worker"
        worker = os.path.abspath(a.worker)
    else:
        cmd = [sys.executable, "-I", os.path.join(HERE, "ref_host.py")]
        worker = ref_worker
    if ref_worker is None:
        return False, "the escaped-worker cases need the reference worker build"
    escaped = escaped_wrapper(ref_worker, workdir)
    only = a.only.split(",") if a.only else None
    if not a.self_test:
        fails, passed = host_run(cmd, worker, escaped, {}, workdir, a.verbose, "subject", only)
        ok = not fails and not only
        return ok, f"{passed} cells ok, {len(fails)} failed over {len(BOOTS)} boots (forkwasm, cordon; real and escaped worker)"
    if a.subject:
        if not (a.mutant_subject and a.mutant_worker):
            return False, "--self-test --level host --subject needs --mutant-subject and --mutant-worker"
        mcmd = [os.path.abspath(a.mutant_subject)]
        mworker = os.path.abspath(a.mutant_worker)
    else:
        mcmd, mworker = cmd, ref_worker
    notes = []
    print(f"[host] control: {' '.join(cmd)}", flush=True)
    fails, passed = host_run(cmd, worker, escaped, {}, workdir, a.verbose, "control", only)
    ok = not fails
    notes.append(f"control {'green' if ok else 'RED'} ({passed} cells ok, {len(fails)} failed)")
    for m, expected in HOST_MUTANTS.items():
        print(f"[host] mutant {m} (AEGIS_P2_MUTANT={m})", flush=True)
        mf, _ = host_run(mcmd, mworker, escaped, {"AEGIS_P2_MUTANT": m}, workdir, False, m, only)
        hit = sorted({case_of(f) for f in mf} & set(expected))
        if hit:
            notes.append(f"{m} red ({len(mf)} cells; {','.join(hit)})")
        else:
            ok = False
            notes.append(f"{m} NOT caught (red: {mf[:4]})")
    return ok, "; ".join(notes)
