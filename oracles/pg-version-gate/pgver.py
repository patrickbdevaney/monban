#!/usr/bin/env python3
"""PG-VERSION-GATE oracle (P4-oracle-pgver-001). Stdlib only, run as `python3 -I`.

Backs gates pg-version-floor and pg19-blocked (owner P4-pg-001). Spec: ARCHITECTURE §3.8 R-DB-1 (PG >= 18.6 / 17.11,
CVE-2026-14666; recycle pooled connections after a minor upgrade) and R-DB-8 (every 19.x refused until a named fix).
Truth comes from supply-chain/engine-pins.toml; semantics follow aegis-data-ir EnginePin::admit (blocked major ->
refuse; major without floor -> refuse; numeric (major, minor) < floor -> refuse) plus the pins file rule that
pre-releases never satisfy a floor.

  pgver.py [--subject CMD] [--pins FILE]                         offline: fake PG v3 servers over the version matrix
  pgver.py --live --refuse DSN... --accept DSN... [--subject CMD] real engines (DSNs from ci/engines.sh)
  pgver.py --self-test [--live --refuse DSN --accept DSN]         reference passes, every mutant goes red
  pgver.py serve [--mutant NAME]                                  reference subject (JSON lines on stdin/stdout)

Subject protocol: one JSON object per line. Request {"v":1,"id":N,"op":"connect","dsn":"postgresql://..."}.
Reply {"id":N,"ok":true,"server_version":"<leading token>"} or {"id":N,"refuse":"<reason>"}.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import select
import shlex
import socket
import struct
import subprocess
import sys
import threading
import time
import tomllib
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
NAME = "PG-VERSION-GATE"
DEFAULT_PINS = os.path.join(REPO, "supply-chain", "engine-pins.toml")
U32 = 0xFFFFFFFF


# =================================================================== truth (from engine-pins.toml) ==================
class Policy:
    """floors: {major: minor} for policy=allow postgres pins; blocked: majors of policy=blocked postgres pins."""

    def __init__(self, path):
        with open(path, "rb") as f:
            pins = tomllib.load(f)
        self.path = path
        self.floors, self.blocked, self.pinned = {}, set(), {}
        for name, e in (pins.get("engines") or {}).items():
            if e.get("kind") != "postgres":
                continue
            self.pinned[name] = e["version"]
            if e["policy"] == "allow":
                m = re.fullmatch(r"(\d+)\.(\d+)", e["floor"], re.ASCII)
                if not m:
                    raise SystemExit(f"{path}: engines.{name}.floor {e['floor']!r} is not major.minor")
                maj, mnr = int(m.group(1)), int(m.group(2))
                self.floors[maj] = max(self.floors.get(maj, 0), mnr)  # same major twice: the higher floor applies
            elif e["policy"] == "blocked":
                m = re.match(r"(\d+)", e["version"], re.ASCII)
                if not m:
                    raise SystemExit(f"{path}: engines.{name}.version {e['version']!r} has no major")
                self.blocked.add(int(m.group(1)))
            else:
                raise SystemExit(f"{path}: engines.{name}.policy {e['policy']!r}")
        if not self.floors or not self.blocked:
            raise SystemExit(f"{path}: expected at least one allowed and one blocked postgres pin")
        overlap = self.blocked & set(self.floors)
        if overlap:
            raise SystemExit(f"{path}: majors both allowed and blocked: {sorted(overlap)}")

    def truth(self, server_version):
        """(accept, why). server_version is the ParameterStatus value or None when it was not reported."""
        if server_version is None:
            return False, "no server_version"
        tok = server_version.split(" ", 1)[0]
        m = re.fullmatch(r"([0-9]+)\.([0-9]+)", tok, re.ASCII)
        if m:
            maj, mnr = int(m.group(1)), int(m.group(2))
            if maj > U32 or mnr > U32:
                return False, "component overflows u32"
            if maj in self.blocked:
                return False, f"major {maj} blocked"
            if maj not in self.floors:
                return False, f"major {maj} has no floor"
            if mnr < self.floors[maj]:
                return False, f"{maj}.{mnr} below floor {maj}.{self.floors[maj]}"
            return True, "at or above floor"
        m = re.fullmatch(r"([0-9]+)(alpha|beta|rc|devel)[0-9]*", tok, re.ASCII)
        if m:
            return False, f"pre-release (major {m.group(1)}{' blocked' if int(m.group(1)) in self.blocked else ''})"
        return False, "unparseable"


# =================================================================== PG v3 wire helpers ============================
def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


def msg(t, p):
    return t + struct.pack("!i", len(p) + 4) + p


def read_msg(s):
    t = recv_exact(s, 1)
    (ln,) = struct.unpack("!i", recv_exact(s, 4))
    if ln < 4 or ln > 1 << 20:
        raise ConnectionError(f"bad message length {ln}")
    return t, recv_exact(s, ln - 4)


def parse_dsn(dsn):
    u = urllib.parse.urlsplit(dsn)
    if u.scheme not in ("postgresql", "postgres") or not u.hostname or not u.port:
        raise ValueError(f"unsupported dsn {dsn!r}")
    return (u.hostname, u.port, urllib.parse.unquote(u.username or "postgres"),
            urllib.parse.unquote(u.password or ""), (u.path or "/postgres").lstrip("/") or "postgres")


def pg_startup(dsn, timeout=10.0):
    """Connect + startup + auth (trust or SCRAM-SHA-256; cleartext/MD5 refused). Returns (socket, params dict).
    The socket is left open after ReadyForQuery."""
    host, port, user, password, db = parse_dsn(dsn)
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.settimeout(timeout)
        body = struct.pack("!i", 196608) + b"user\0" + user.encode() + b"\0database\0" + db.encode() + b"\0\0"
        s.sendall(struct.pack("!i", len(body) + 4) + body)
        params, nonce, cfb, auth_msg, salted = {}, None, None, None, None
        while True:
            t, p = read_msg(s)
            if t == b"E":
                raise ConnectionError("server error: " + p.decode(errors="replace")[:200])
            if t == b"R":
                (code,) = struct.unpack("!i", p[:4])
                if code == 0:
                    continue
                if code == 10:
                    if b"SCRAM-SHA-256" not in p[4:].split(b"\0"):
                        raise ConnectionError("no SCRAM-SHA-256")
                    nonce = base64.b64encode(secrets.token_bytes(18)).decode()
                    cfb = f"n=,r={nonce}"
                    data = ("n,," + cfb).encode()
                    s.sendall(msg(b"p", b"SCRAM-SHA-256\0" + struct.pack("!i", len(data)) + data))
                    continue
                if code == 11:
                    sf = p[4:].decode()
                    kv = dict(x.split("=", 1) for x in sf.split(","))
                    if not kv["r"].startswith(nonce):
                        raise ConnectionError("SCRAM nonce mismatch")
                    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(kv["s"]), int(kv["i"]))
                    ck = hmac.new(salted, b"Client Key", "sha256").digest()
                    cfwp = f"c=biws,r={kv['r']}"
                    auth_msg = f"{cfb},{sf},{cfwp}".encode()
                    sig = hmac.new(hashlib.sha256(ck).digest(), auth_msg, "sha256").digest()
                    proof = base64.b64encode(bytes(a ^ b for a, b in zip(ck, sig))).decode()
                    s.sendall(msg(b"p", f"{cfwp},p={proof}".encode()))
                    continue
                if code == 12:
                    sk = hmac.new(salted, b"Server Key", "sha256").digest()
                    want = base64.b64encode(hmac.new(sk, auth_msg, "sha256").digest()).decode()
                    if p[4:].decode() != f"v={want}":
                        raise ConnectionError("SCRAM server signature mismatch")
                    continue
                raise ConnectionError(f"refusing auth method {code}")
            if t == b"S":
                k, _, v = p.rstrip(b"\0").partition(b"\0")
                params[k.decode(errors="replace")] = v.decode(errors="replace")
            elif t == b"Z":
                return s, params
    except BaseException:
        s.close()
        raise


# =================================================================== reference subject ==============================
MUTANTS = {
    "string-compare-version": "compares server_version to the floor as strings ('17.9' > '17.11')",
    "no-floor": "admits any minor of a major that has a floor (floor ignored)",
    "pg19-allowed": "19.x not blocked: every 19 version (incl. rc/beta) admitted",
    "pg19-ga-allowed": "19 refusal broken: pre-releases refused, 19.0+ admitted as if the block were lifted at GA",
    "wrong-field": "derives the version from server_version_num instead of server_version",
    "no-recheck-on-reconnect": "pooled DSN: version cached at first connect, not re-read/compared on reconnect",
    "unknown-major-allowed": "a major with no floor (16.x, 20.x) is admitted",
    "missing-version-accepted": "no/unparseable server_version is admitted (fail open)",
    "u32-wrap": "parses components with u32 wrap-around (17.4294967307 reads as 17.11)",
}


class RefSubject:
    def __init__(self, policy, mutant=""):
        if mutant and mutant not in MUTANTS:
            raise SystemExit(f"unknown mutant {mutant}")
        self.p, self.mut, self.pool = policy, mutant, {}

    def version_of(self, params):
        if self.mut == "wrong-field":
            n = params.get("server_version_num")
            if n is None or not n.isascii() or not n.isdigit():
                return None
            return f"{int(n) // 10000}.{int(n) % 10000}"
        return params.get("server_version")

    def admit(self, sv):
        if sv is None:
            return (True, "") if self.mut == "missing-version-accepted" else (False, "server did not report server_version")
        tok = sv.split(" ", 1)[0]
        floors, blocked = dict(self.p.floors), set(self.p.blocked)
        if self.mut in ("pg19-allowed", "pg19-ga-allowed"):
            blocked.discard(19)
            floors[19] = 0
        m = re.fullmatch(r"([0-9]+)\.([0-9]+)", tok, re.ASCII)
        pre = re.fullmatch(r"([0-9]+)(alpha|beta|rc|devel)[0-9]*", tok, re.ASCII)
        if pre:
            maj = int(pre.group(1))
            if self.mut == "pg19-allowed" and maj == 19:
                return True, ""
            return False, f"pre-release {tok} never satisfies a floor" + (" (major blocked, R-DB-8)" if maj in blocked else "")
        if not m:
            return (True, "") if self.mut == "missing-version-accepted" else (False, f"unparseable server_version {sv!r}")
        maj, mnr = int(m.group(1)), int(m.group(2))
        if self.mut == "u32-wrap":
            maj, mnr = maj & U32, mnr & U32
        elif maj > U32 or mnr > U32:
            return False, f"version component overflows u32: {tok}"
        if maj in blocked:
            return False, f"major {maj} blocked (R-DB-8: ON CONFLICT WHERE before RLS)"
        if maj not in floors:
            return (True, "") if self.mut == "unknown-major-allowed" else (False, f"major {maj} has no floor")
        if self.mut == "no-floor":
            return True, ""
        if self.mut == "string-compare-version":
            ok = tok >= f"{maj}.{floors[maj]}"
        else:
            ok = (maj, mnr) >= (maj, floors[maj])
        return (True, "") if ok else (False, f"{maj}.{mnr} below floor {maj}.{floors[maj]} (CVE-2026-14666)")

    @staticmethod
    def alive(s):
        try:
            s.setblocking(False)
            try:
                data = s.recv(1, socket.MSG_PEEK)
            finally:
                s.setblocking(True)
            del data  # EOF (b"") or unsolicited bytes (FATAL 57P01 on shutdown): either way not reusable
            return False
        except BlockingIOError:
            return True
        except OSError:
            return False

    def connect(self, dsn):
        entry = self.pool.get(dsn)
        if entry is not None:
            sock, pinned = entry
            if self.alive(sock):
                return {"ok": True, "server_version": pinned}
            sock.close()
        try:
            sock, params = pg_startup(dsn)
        except (OSError, ConnectionError, ValueError) as e:
            self.pool.pop(dsn, None)
            return {"refuse": f"connect failed: {e}"}
        sv = self.version_of(params)
        tok = None if sv is None else sv.split(" ", 1)[0]
        if entry is not None:
            if self.mut == "no-recheck-on-reconnect":
                self.pool[dsn] = (sock, entry[1])
                return {"ok": True, "server_version": entry[1]}
            if tok != entry[1]:
                del self.pool[dsn]
                sock.close()
                return {"refuse": f"server version changed {entry[1]} -> {tok} on reconnect; pool recycled (R-DB-1)"}
        ok, why = self.admit(sv)
        if not ok:
            self.pool.pop(dsn, None)
            sock.close()
            return {"refuse": why}
        self.pool[dsn] = (sock, tok)
        return {"ok": True, "server_version": tok}


def serve(argv):
    mutant, pins = "", DEFAULT_PINS
    it = iter(argv)
    for a in it:
        if a == "--mutant":
            mutant = next(it)
        elif a == "--pins":
            pins = next(it)
        else:
            raise SystemExit(f"serve: unknown argument {a}")
    subj = RefSubject(Policy(pins), mutant)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            continue
        rid = req.get("id")
        if req.get("op") == "connect":
            out = subj.connect(req.get("dsn", ""))
        elif req.get("op") == "hello":
            out = {"ok": True, "subject": "reference", "mutant": mutant}
        else:
            out = {"refuse": f"unknown op {req.get('op')!r}"}
        out["id"] = rid
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()
    return 0


# =================================================================== fake PG v3 server ==============================
class FakePG:
    """Listener on 127.0.0.1:<random>. Answers SSLRequest/GSSENCRequest with 'N', startup with AuthenticationOk,
    ParameterStatus (server_version / server_version_num as configured; None = omitted), BackendKeyData,
    ReadyForQuery('I'). Idle afterwards; restart(...) sends FATAL 57P01 to every open connection, closes it and
    changes the reported version, as a minor upgrade does."""

    def __init__(self, server_version, server_version_num="auto"):
        self.lock = threading.Lock()
        self.set_version(server_version, server_version_num)
        self.conns, self.startups = [], 0
        self.ls = socket.socket()
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(32)
        self.port = self.ls.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def set_version(self, sv, num="auto"):
        if num == "auto":
            num = None
            m = re.fullmatch(r"([0-9]+)\.([0-9]+)", (sv or "").split(" ", 1)[0], re.ASCII)
            pre = re.fullmatch(r"([0-9]+)(alpha|beta|rc|devel)[0-9]*", (sv or "").split(" ", 1)[0], re.ASCII)
            if m and int(m.group(2)) < 10000:
                num = str(int(m.group(1)) * 10000 + int(m.group(2)))
            elif pre:
                num = str(int(pre.group(1)) * 10000)
        with self.lock:
            self.sv, self.num = sv, num

    def dsn(self, tag):
        return f"postgresql://postgres:fake@127.0.0.1:{self.port}/{tag}"

    def _accept(self):
        while True:
            try:
                c, _ = self.ls.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            c.settimeout(30)
            while True:
                (ln,) = struct.unpack("!i", recv_exact(c, 4))
                if ln < 8 or ln > 10000:
                    return
                body = recv_exact(c, ln - 4)
                (code,) = struct.unpack("!i", body[:4])
                if code in (80877103, 80877104):  # SSLRequest, GSSENCRequest
                    c.sendall(b"N")
                    continue
                if code != 196608:
                    return
                break
            with self.lock:
                sv, num = self.sv, self.num
                self.startups += 1
                self.conns.append(c)
            out = msg(b"R", struct.pack("!i", 0))
            ps = [("application_name", ""), ("client_encoding", "UTF8"), ("DateStyle", "ISO, MDY"),
                  ("integer_datetimes", "on"), ("is_superuser", "off"), ("server_encoding", "UTF8")]
            if sv is not None:
                ps.append(("server_version", sv))
            if num is not None:
                ps.append(("server_version_num", num))
            ps += [("session_authorization", "postgres"), ("standard_conforming_strings", "on"), ("TimeZone", "UTC")]
            for k, v in ps:
                out += msg(b"S", k.encode() + b"\0" + v.encode() + b"\0")
            out += msg(b"K", struct.pack("!ii", 4242, 1717)) + msg(b"Z", b"I")
            c.sendall(out)
            c.settimeout(None)
            while True:
                t, _ = read_msg(c)
                if t == b"X":
                    return
                c.sendall(msg(b"E", b"SERROR\0C0A000\0Mfake server: queries unsupported\0\0") + msg(b"Z", b"I"))
        except (OSError, ConnectionError, struct.error):
            return
        finally:
            with self.lock:
                if c in self.conns:
                    self.conns.remove(c)
            try:
                c.close()
            except OSError:
                pass

    def restart(self, sv, num="auto", settle=0.05):
        with self.lock:
            conns = list(self.conns)
        for c in conns:
            try:
                c.sendall(msg(b"E", b"SFATAL\0C57P01\0Mterminating connection due to administrator command\0\0"))
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.set_version(sv, num)
        time.sleep(settle)  # let FIN reach the peer before the next request

    def close(self):
        self.ls.close()
        self.restart(None, None, settle=0)


# =================================================================== subject driver ================================
class Subject:
    def __init__(self, cmd, timeout=20.0):
        self.cmd, self.timeout, self.n = cmd, timeout, 0
        self.p = subprocess.Popen(shlex.split(cmd), cwd=REPO, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, bufsize=1)

    def connect(self, dsn):
        self.n += 1
        try:
            self.p.stdin.write(json.dumps({"v": 1, "id": self.n, "op": "connect", "dsn": dsn}) + "\n")
            self.p.stdin.flush()
        except OSError as e:
            return {"error": f"subject stdin: {e}"}
        r, _, _ = select.select([self.p.stdout], [], [], self.timeout)
        if not r:
            return {"error": "subject timeout"}
        line = self.p.stdout.readline()
        if not line:
            return {"error": "subject exited"}
        try:
            rep = json.loads(line)
        except ValueError:
            return {"error": f"subject sent non-JSON {line[:80]!r}"}
        if not isinstance(rep, dict) or rep.get("id") != self.n:
            return {"error": f"bad reply id {line[:80]!r}"}
        if rep.get("ok") is True and isinstance(rep.get("server_version"), str) and "refuse" not in rep:
            return {"ok": True, "server_version": rep["server_version"]}
        if isinstance(rep.get("refuse"), str) and rep.get("ok") is not True:
            return {"refuse": rep["refuse"]}
        return {"error": f"malformed reply {line[:80]!r}"}

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            self.p.kill()


def ref_cmd(mutant="", pins=None):
    c = f"python3 -I {shlex.quote(os.path.abspath(__file__))} serve"
    if pins:
        c += f" --pins {shlex.quote(pins)}"
    return c + (f" --mutant {mutant}" if mutant else "")


# =================================================================== offline matrix ================================
MATRIX = [  # (label, server_version or None, server_version_num: "auto" | None (omitted) | str)
    ("14.24", "14.24", "auto"), ("15.19", "15.19", "auto"), ("16.4", "16.4", "auto"), ("16.15", "16.15", "auto"),
    ("17.0", "17.0", "auto"), ("17.9", "17.9", "auto"), ("17.10", "17.10", "auto"), ("17.11", "17.11", "auto"),
    ("17.12", "17.12", "auto"), ("17.20", "17.20", "auto"),
    ("17.11-debian", "17.11 (Debian 17.11-1.pgdg13+1)", "auto"),
    ("17.10-debian", "17.10 (Debian 17.10-1.pgdg13+1)", "auto"),
    ("18.0", "18.0", "auto"), ("18.5", "18.5", "auto"), ("18.6", "18.6", "auto"), ("18.7", "18.7", "auto"),
    ("18.10", "18.10", "auto"), ("18.6-ubuntu", "18.6 (Ubuntu 18.6-1.pgdg24.04+1)", "auto"),
    ("18beta1", "18beta1", "auto"), ("18rc1", "18rc1", "auto"), ("18devel", "18devel", "auto"),
    ("19beta3", "19beta3", "auto"), ("19rc1", "19rc1", "auto"), ("19.0", "19.0", "auto"), ("19.1", "19.1", "auto"),
    ("19.12", "19.12", "auto"), ("20.0", "20.0", "auto"), ("9.6.24", "9.6.24", "90624"),
    ("garbage", "garbage", None), ("empty", "", None), ("17.x", "17.x", None), ("17.", "17.", None),
    (".11", ".11", None), ("v18.6", "v18.6", None), ("17.11garbage", "17.11garbage", None),
    ("fullwidth-17.11", "１７.１１", None),
    ("u32-wrap-minor", "17.4294967307", None), ("u32-wrap-major", "4294967313.11", None),
    ("missing", None, "170011"), ("missing-both", None, None),
    ("num-omitted-17.11", "17.11", None), ("num-omitted-18.6", "18.6", None),
    ("num-decoy-17.10/170011", "17.10", "170011"), ("num-decoy-18.6/180005", "18.6", "180005"),
    ("num-decoy-19.0/180006", "19.0", "180006"),
]

# Reconnect scenarios: server at A, subject connects (pooled); server restarts reporting B; subject connects twice.
# Expected: A per truth; then refuse iff B differs from A (pooled connection recycled), else truth(B); then truth(B).
RECONNECT = [
    ("17.11->17.10", "17.11", "17.10"), ("17.11->17.12", "17.11", "17.12"), ("18.6->19.0", "18.6", "19.0"),
    ("17.11->18.6", "17.11", "18.6"), ("17.11->17.11", "17.11", "17.11"), ("18.6->18.5", "18.6", "18.5"),
    ("18.6->missing", "18.6", None),
]


def tok_of(sv):
    return None if sv is None else sv.split(" ", 1)[0]


def judge(case, expect_ok, sent_sv, rep):
    """Return None if rep matches the expectation, else a mismatch string."""
    if "error" in rep:
        return f"{case}: {rep['error']}"
    if expect_ok and "ok" in rep:
        if rep["server_version"] != tok_of(sent_sv):
            return f"{case}: accepted but reported server_version {rep['server_version']!r}, server sent {tok_of(sent_sv)!r}"
        return None
    if not expect_ok and "refuse" in rep:
        return None
    return f"{case}: expected {'accept' if expect_ok else 'refuse'}, got {'accept' if 'ok' in rep else 'refuse'}"


def run_offline(policy, cmd):
    fails, n = [], 0
    subj = Subject(cmd)
    servers = []
    try:
        for label, sv, num in MATRIX:
            fs = FakePG(sv, num)
            servers.append(fs)
            exp, _ = policy.truth(sv)
            n += 1
            err = judge(f"matrix {label}", exp, sv, subj.connect(fs.dsn("m" + str(n))))
            if err:
                fails.append(err)
            if fs.startups < 1 and not err:
                fails.append(f"matrix {label}: verdict returned without a startup handshake")
        for label, a, b in RECONNECT:
            fs = FakePG(a)
            servers.append(fs)
            dsn = fs.dsn("r" + str(n))
            exp_a, _ = policy.truth(a)
            n += 1
            err = judge(f"reconnect {label} #1", exp_a, a, subj.connect(dsn))
            if err:
                fails.append(err)
                continue
            if not exp_a:
                fails.append(f"reconnect {label}: scenario start {a} must be admitted (bad scenario)")
                continue
            before = fs.startups
            fs.restart(b)
            exp_b, _ = policy.truth(b)
            exp2 = exp_b if tok_of(a) == tok_of(b) else False
            rep2 = subj.connect(dsn)
            err = judge(f"reconnect {label} #2", exp2, b, rep2)
            if err:
                fails.append(err)
                continue
            if fs.startups == before:
                fails.append(f"reconnect {label} #2: verdict without re-reading the restarted server's startup")
                continue
            err = judge(f"reconnect {label} #3", exp_b, b, subj.connect(dsn))
            if err:
                fails.append(err)
    finally:
        subj.close()
        for fs in servers:
            fs.close()
    return n, fails


# =================================================================== live =========================================
def run_live(policy, cmd, refuse, accept):
    """Independent oracle probe first (target must be what the flag claims per the pins), then the subject."""
    fails, seen = [], []
    targets = [(d, False) for d in refuse] + [(d, True) for d in accept]
    if not targets:
        return [], ["--live needs at least one --refuse or --accept DSN"]
    probed = {}
    for dsn, want in targets:
        try:
            s, params = pg_startup(dsn)
            s.sendall(msg(b"X", b""))
            s.close()
        except (OSError, ConnectionError, ValueError) as e:
            fails.append(f"live probe {redact(dsn)}: {e}")
            continue
        sv = params.get("server_version")
        truth, why = policy.truth(sv)
        probed[dsn] = sv
        seen.append(f"{tok_of(sv)}={'accept' if want else 'refuse'}")
        if truth != want:
            fails.append(f"live target {redact(dsn)} reports {sv!r}: pins say {'accept' if truth else 'refuse'} ({why}),"
                         f" flag says {'accept' if want else 'refuse'} (misconfigured run)")
    if fails:
        return seen, fails
    subj = Subject(cmd)
    try:
        for dsn, want in targets:
            sv = probed[dsn]
            for i in (1, 2) if want else (1,):  # accept target twice: pooled reuse must stay accepted
                err = judge(f"live {tok_of(sv)} #{i}", want, sv, subj.connect(dsn))
                if err:
                    fails.append(err)
    finally:
        subj.close()
    return seen, fails


def seen_raw(seen):
    for s in seen:
        tok, _, verdict = s.rpartition("=")
        yield tok, verdict == "accept"


def redact(dsn):
    try:
        u = urllib.parse.urlsplit(dsn)
        return f"{u.scheme}://{u.username or ''}:***@{u.hostname}:{u.port}{u.path}"
    except ValueError:
        return "<dsn>"


# =================================================================== self-test ====================================
REQUIRED_OFFLINE = ["string-compare-version", "no-floor", "pg19-allowed", "pg19-ga-allowed", "wrong-field",
                    "no-recheck-on-reconnect", "unknown-major-allowed", "missing-version-accepted", "u32-wrap"]


def truth_selfcheck(policy):
    """The truth function itself, against the pins it read (relative to each floor, so a pin bump stays valid)."""
    errs = []
    for maj, mnr in policy.floors.items():
        for v, want in ((f"{maj}.{mnr}", True), (f"{maj}.{mnr + 1}", True), (f"{maj}.{mnr + 10}", True),
                        (f"{maj}rc1", False), (f"{maj}.{mnr} (Debian)", True)):
            if policy.truth(v)[0] != want:
                errs.append(f"truth({v}) != {want}")
        if mnr > 0 and policy.truth(f"{maj}.{mnr - 1}")[0]:
            errs.append(f"truth({maj}.{mnr - 1}) accepted below floor")
    for maj in policy.blocked:
        for v in (f"{maj}.0", f"{maj}.1", f"{maj}.99", f"{maj}rc1", f"{maj}beta3"):
            if policy.truth(v)[0]:
                errs.append(f"truth({v}) accepted a blocked major")
    for v in (None, "", "garbage", "17.4294967307"):
        if policy.truth(v)[0]:
            errs.append(f"truth({v!r}) accepted")
    # The matrix must contain the values the plan names (16.x, 17.10, 17.11, 18.5, 18.6, 19beta, 19rc1, 19.0, garbage,
    # missing) and a pair where string and numeric order disagree, else the string-compare mutant is untested.
    labels = {m[0] for m in MATRIX}
    for need in ("16.4", "17.10", "17.11", "18.5", "18.6", "19beta3", "19rc1", "19.0", "garbage", "missing", "17.9"):
        if need not in labels:
            errs.append(f"matrix lacks {need}")
    if not policy.blocked & {19}:
        errs.append("pins no longer block 19 (R-DB-8): lifting needs a spec change, this oracle must be revisited")
    return errs


def selftest(policy, pins, live, refuse, accept):
    errs = truth_selfcheck(policy)
    if errs:
        print(f"{NAME} SELF-TEST: FAIL (truth: {'; '.join(errs)})")
        return 1
    n, fails = run_offline(policy, ref_cmd(pins=pins))
    if fails:
        for f in fails:
            print("  ref:", f)
        print(f"{NAME} SELF-TEST: FAIL (reference subject not clean offline: {len(fails)} mismatches)")
        return 1
    print(f"positive control: reference subject via process protocol, {n} offline cases clean")
    survived = []
    for m in REQUIRED_OFFLINE:
        _, f = run_offline(policy, ref_cmd(m, pins))
        print(f"  mutant {m:26s} {'RED' if f else 'survived'} ({len(f)} mismatches{'; first: ' + f[0] if f else ''})")
        if not f:
            survived.append(m)
    if survived:
        print(f"{NAME} SELF-TEST: FAIL (mutants survived offline: {', '.join(survived)})")
        return 1
    summary = f"offline: reference clean on {n} cases, {len(REQUIRED_OFFLINE)}/{len(REQUIRED_OFFLINE)} mutants red"
    if live:
        seen, fails = run_live(policy, ref_cmd(pins=pins), refuse, accept)
        if fails:
            for f in fails:
                print("  live ref:", f)
            print(f"{NAME} SELF-TEST: FAIL (reference subject not clean live)")
            return 1
        print(f"positive control live: reference clean on {' '.join(seen)}")
        blocked_live = any(not want and int(re.match(r"[0-9]*", tok or "").group() or -1) in policy.blocked
                           for tok, want in seen_raw(seen))
        need_live = ["pg19-allowed"] if blocked_live else []
        red_live = []
        for m in REQUIRED_OFFLINE:
            _, f = run_live(policy, ref_cmd(m, pins), refuse, accept)
            print(f"  live mutant {m:26s} {'RED' if f else 'survived (not distinguishable on these targets)'}"
                  f"{'; first: ' + f[0] if f else ''}")
            if f:
                red_live.append(m)
        missing = [m for m in need_live if m not in red_live]
        if missing or not red_live:
            print(f"{NAME} SELF-TEST: FAIL (live mutants not caught: {', '.join(missing) or 'none red'})")
            return 1
        summary += f"; live {' '.join(seen)}: reference clean, mutants red: {','.join(red_live)}"
    print(f"{NAME} SELF-TEST: PASS ({summary})")
    return 0


# =================================================================== main =========================================
def main(argv):
    if argv[:1] == ["serve"]:
        return serve(argv[1:])
    subject, pins, live, st, refuse, accept = None, DEFAULT_PINS, False, False, [], []
    it = iter(argv)
    try:
        for a in it:
            if a == "--subject":
                subject = next(it)
            elif a == "--pins":
                pins = next(it)
            elif a == "--live":
                live = True
            elif a == "--self-test":
                st = True
            elif a == "--refuse":
                refuse.append(next(it))
            elif a == "--accept":
                accept.append(next(it))
            elif a in ("-h", "--help"):
                print(__doc__)
                return 0
            else:
                print(f"{NAME}: FAIL (unknown argument {a})")
                return 2
    except StopIteration:
        print(f"{NAME}: FAIL (missing value for last option)")
        return 2
    if (refuse or accept) and not live:
        print(f"{NAME}: FAIL (--refuse/--accept need --live)")
        return 2
    for d in refuse + accept:
        if d.startswith("@"):
            print(f"{NAME}: FAIL (unsubstituted engine reference {d}: run under ci/engines.sh with ...)")
            return 2
    policy = Policy(pins)
    if st:
        return selftest(policy, pins, live, refuse, accept)
    cmd = subject or ref_cmd(pins=pins)
    who = "subject" if subject else "reference"
    if live:
        seen, fails = run_live(policy, cmd, refuse, accept)
        for f in fails:
            print("  ", f)
        if fails:
            print(f"{NAME}: FAIL (live, {who}: {len(fails)} mismatches; first: {fails[0]})")
            return 1
        print(f"{NAME}: PASS (live, {who}: {' '.join(seen)}; floors {fmt_floors(policy)}, blocked {sorted(policy.blocked)})")
        return 0
    n, fails = run_offline(policy, cmd)
    for f in fails:
        print("  ", f)
    if fails:
        print(f"{NAME}: FAIL ({who}: {len(fails)}/{n} mismatches; first: {fails[0]})")
        return 1
    print(f"{NAME}: PASS ({who}: {n} cases ({len(MATRIX)} matrix + {len(RECONNECT)} reconnect); "
          f"floors {fmt_floors(policy)}, blocked {sorted(policy.blocked)})")
    return 0


def fmt_floors(policy):
    return ",".join(f"{k}.{v}" for k, v in sorted(policy.floors.items()))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
