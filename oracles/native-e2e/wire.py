"""Stdlib-only database wire clients shared by the native-e2e oracle (to inspect durable state) and its reference
subject (to run the notes app). Infrastructure only: no contract logic lives here.

PgConn: PostgreSQL v3 simple-query protocol, SCRAM-SHA-256 (or trust), refuses cleartext/MD5.
KvConn: RESP2 client for Valkey/Redis.
"""

import base64
import hashlib
import hmac
import secrets
import socket
import struct
import urllib.parse


class DbError(Exception):
    pass


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


def parse_pg_dsn(dsn):
    u = urllib.parse.urlsplit(dsn)
    if u.scheme not in ("postgres", "postgresql"):
        raise ValueError(f"not a postgres DSN: {u.scheme}")
    return {
        "host": u.hostname or "127.0.0.1",
        "port": u.port or 5432,
        "user": urllib.parse.unquote(u.username or "postgres"),
        "password": urllib.parse.unquote(u.password or ""),
        "db": (u.path or "/postgres").lstrip("/") or "postgres",
    }


def pg_quote(v):
    """SQL literal for the simple-query protocol (standard_conforming_strings = on)."""
    if v is None:
        return "NULL"
    s = str(v)
    if "\0" in s:
        raise ValueError("NUL in literal")
    return "'" + s.replace("'", "''") + "'"


class PgConn:
    def __init__(self, dsn, timeout=10.0):
        p = parse_pg_dsn(dsn)
        self.addr = (p["host"], p["port"])
        self.s = socket.create_connection(self.addr, timeout=timeout)
        self.s.settimeout(timeout)
        self.params = {}
        self.txn_status = b"I"
        self.backend_key = None  # (process id, secret key) from BackendKeyData, for CancelRequest
        self._startup(p["user"], p["password"], p["db"])

    def _msg(self):
        t = _recv_exact(self.s, 1)
        (ln,) = struct.unpack("!i", _recv_exact(self.s, 4))
        return t, _recv_exact(self.s, ln - 4)

    def _send(self, t, payload):
        self.s.sendall(t + struct.pack("!i", len(payload) + 4) + payload)

    def _startup(self, user, password, db):
        body = struct.pack("!i", 196608) + b"user\0" + user.encode() + b"\0database\0" + db.encode() + b"\0\0"
        self.s.sendall(struct.pack("!i", len(body) + 4) + body)
        nonce = cfb = auth_msg = salted = None
        while True:
            t, p = self._msg()
            if t == b"E":
                raise DbError("startup: " + _err_text(p))
            if t == b"R":
                (code,) = struct.unpack("!i", p[:4])
                if code == 0:
                    continue
                if code == 10:
                    if b"SCRAM-SHA-256" not in p[4:].split(b"\0"):
                        raise DbError("no SCRAM-SHA-256")
                    nonce = base64.b64encode(secrets.token_bytes(18)).decode()
                    cfb = f"n=,r={nonce}"
                    data = ("n,," + cfb).encode()
                    self._send(b"p", b"SCRAM-SHA-256\0" + struct.pack("!i", len(data)) + data)
                    continue
                if code == 11:
                    sf = p[4:].decode()
                    kv = dict(x.split("=", 1) for x in sf.split(","))
                    if not kv["r"].startswith(nonce):
                        raise DbError("SCRAM nonce mismatch")
                    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(kv["s"]), int(kv["i"]))
                    ck = hmac.new(salted, b"Client Key", "sha256").digest()
                    cfwp = f"c=biws,r={kv['r']}"
                    auth_msg = f"{cfb},{sf},{cfwp}".encode()
                    sig = hmac.new(hashlib.sha256(ck).digest(), auth_msg, "sha256").digest()
                    proof = base64.b64encode(bytes(a ^ b for a, b in zip(ck, sig))).decode()
                    self._send(b"p", f"{cfwp},p={proof}".encode())
                    continue
                if code == 12:
                    sk = hmac.new(salted, b"Server Key", "sha256").digest()
                    want = base64.b64encode(hmac.new(sk, auth_msg, "sha256").digest()).decode()
                    if p[4:].decode() != f"v={want}":
                        raise DbError("SCRAM server signature mismatch")
                    continue
                raise DbError(f"refusing auth method {code}")
            if t == b"S":
                k, v = p[:-1].split(b"\0", 1)
                self.params[k.decode()] = v.decode()
            elif t == b"K" and len(p) >= 8:
                self.backend_key = struct.unpack("!ii", p[:8])
            elif t == b"Z":
                self.txn_status = p[:1]
                return

    def query(self, sql):
        """Runs one simple query (may hold several statements). Returns rows of the last result set (lists of
        str|None). Raises DbError on a server error (after draining to ReadyForQuery)."""
        self._send(b"Q", sql.encode() + b"\0")
        rows, err = [], None
        while True:
            t, p = self._msg()
            if t == b"T":
                rows = []
            elif t == b"D":
                (n,) = struct.unpack("!h", p[:2])
                off, row = 2, []
                for _ in range(n):
                    (ln,) = struct.unpack("!i", p[off:off + 4])
                    off += 4
                    if ln < 0:
                        row.append(None)
                    else:
                        row.append(p[off:off + ln].decode())
                        off += ln
                rows.append(row)
            elif t == b"E":
                err = _err_fields(p)
            elif t == b"Z":
                self.txn_status = p[:1]
                if err is not None:
                    raise DbError(err.get("M", "error"), err.get("C", ""))
                return rows

    def cancel(self):
        """PG CancelRequest (protocol 3.0 section 53.2.7) on a fresh connection to the same server: asks it to cancel
        whatever this session is running. Returns False if the server sent no BackendKeyData."""
        if self.backend_key is None:
            return False
        try:
            with socket.create_connection(self.addr, timeout=5) as c:
                c.sendall(struct.pack("!iiii", 16, 80877102, *self.backend_key))
        except OSError:
            return False
        return True

    def close(self):
        try:
            self._send(b"X", b"")
        except OSError:
            pass
        try:
            self.s.close()
        except OSError:
            pass


def _err_fields(p):
    out = {}
    for part in p.split(b"\0"):
        if part:
            out[chr(part[0])] = part[1:].decode(errors="replace")
    return out


def _err_text(p):
    f = _err_fields(p)
    return f"{f.get('C', '')} {f.get('M', '')}"


class KvConn:
    def __init__(self, url, timeout=10.0):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("redis", "valkey"):
            raise ValueError(f"not a redis URL: {u.scheme}")
        self.s = socket.create_connection((u.hostname or "127.0.0.1", u.port or 6379), timeout=timeout)
        self.s.settimeout(timeout)
        self.f = self.s.makefile("rb")
        if u.password:
            self.cmd("AUTH", urllib.parse.unquote(u.username or "default"), urllib.parse.unquote(u.password))

    def _send(self, *args):
        out = [f"*{len(args)}\r\n".encode()]
        for a in args:
            b = a if isinstance(a, bytes) else str(a).encode()
            out.append(f"${len(b)}\r\n".encode() + b + b"\r\n")
        self.s.sendall(b"".join(out))

    def _read(self):
        line = self.f.readline()
        if not line:
            raise ConnectionError("eof")
        t, rest = line[:1], line[1:-2]
        if t == b"+":
            return rest.decode()
        if t == b"-":
            raise DbError(rest.decode())
        if t == b":":
            return int(rest)
        if t == b"$":
            n = int(rest)
            if n < 0:
                return None
            data = self.f.read(n + 2)
            return data[:-2].decode()
        if t == b"*":
            n = int(rest)
            if n < 0:
                return None
            return [self._read() for _ in range(n)]
        raise DbError(f"bad RESP type {t!r}")

    def cmd(self, *args):
        self._send(*args)
        return self._read()

    def pipeline(self, cmds):
        for c in cmds:
            self._send(*c)
        out = []
        for _ in cmds:
            try:
                out.append(self._read())
            except DbError as e:
                out.append(e)
        return out

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


class LockedTLS:
    """Serializes reads and writes on one ssl.SSLSocket shared by a reader thread and writer threads (an OpenSSL
    SSL object must not be read and written concurrently). Reads poll with a short select so writers get the lock."""

    def __init__(self, sock, timeout=30.0):
        import threading
        self.s = sock
        self.lock = threading.Lock()
        self.timeout = timeout
        sock.settimeout(timeout)

    def recv(self, n):
        import select
        import ssl
        while True:
            if self.s.fileno() < 0:
                return b""
            if not self.s.pending():
                try:
                    r, _, _ = select.select([self.s], [], [], 0.02)
                except (OSError, ValueError):
                    return b""
                if not r:
                    continue
            with self.lock:
                self.s.setblocking(False)
                try:
                    return self.s.recv(n)
                except (ssl.SSLWantReadError, BlockingIOError):
                    continue
                finally:
                    self.s.settimeout(self.timeout)

    def sendall(self, data):
        with self.lock:
            self.s.sendall(data)

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass
