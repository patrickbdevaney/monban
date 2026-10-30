"""Minimal PostgreSQL v3 frontend for the schema-gate oracle and its reference subject.

Verbatim copy of class PgError/Pg from oracles/lowering-read/lowir.py lines 570-700 (in-repo, reviewed there;
sha256 of lowir.py in README.md). Stdlib only."""
import base64, hashlib, hmac, os, socket, struct, urllib.parse

class PgError(Exception):
    pass

class Pg:
    """Minimal PostgreSQL v3 frontend: startup, auth (trust/cleartext/md5/SCRAM-SHA-256), simple and extended
    query with text-format parameters (type OID 0 = inferred by the server) and text results."""
    def __init__(self, dsn, timeout=30):
        u = urllib.parse.urlparse(dsn)
        if u.scheme not in ("postgres", "postgresql"): raise ValueError("dsn must be postgresql://user:pw@host:port/db")
        self.user = urllib.parse.unquote(u.username or "postgres")
        self.pw = urllib.parse.unquote(u.password or "")
        self.db = (u.path or "/postgres")[1:] or "postgres"
        self.s = socket.create_connection((u.hostname or "127.0.0.1", u.port or 5432), timeout=timeout)
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.f = self.s.makefile("rb")
        self.params = {}
        body = struct.pack("!i", 196608) + b"user\0" + self.user.encode() + b"\0database\0" + self.db.encode() + b"\0\0"
        self.s.sendall(struct.pack("!i", len(body) + 4) + body)
        self._auth()

    def _msg(self):
        h = self.f.read(5)
        if len(h) < 5: raise PgError("connection closed")
        t, n = h[:1], struct.unpack("!i", h[1:])[0]
        return t, self.f.read(n - 4)

    def _send(self, t, body=b""):
        self.s.sendall(t + struct.pack("!i", len(body) + 4) + body)

    @staticmethod
    def _err(body):
        fields = {}
        for part in body.split(b"\0"):
            if part: fields[part[:1]] = part[1:].decode("utf-8", "replace")
        return f"{fields.get(b'S', 'ERROR')} {fields.get(b'C', '')}: {fields.get(b'M', '')}"

    def _auth(self):
        nonce = state = None
        while True:
            t, b = self._msg()
            if t == b"E": raise PgError(self._err(b))
            if t == b"R":
                code = struct.unpack("!i", b[:4])[0]
                if code == 0: continue
                if code == 3:
                    self._send(b"p", self.pw.encode() + b"\0")
                elif code == 5:
                    inner = hashlib.md5(self.pw.encode() + self.user.encode()).hexdigest().encode()
                    self._send(b"p", b"md5" + hashlib.md5(inner + b[4:8]).hexdigest().encode() + b"\0")
                elif code == 10:
                    if b"SCRAM-SHA-256" not in b[4:].split(b"\0"): raise PgError("no supported SASL mechanism")
                    nonce = base64.b64encode(os.urandom(18)).decode()
                    first_bare = f"n=,r={nonce}"
                    msg = ("n,," + first_bare).encode()
                    self._send(b"p", b"SCRAM-SHA-256\0" + struct.pack("!i", len(msg)) + msg)
                    state = first_bare
                elif code == 11:
                    sf = b[4:].decode()
                    kv = dict(x.split("=", 1) for x in sf.split(","))
                    if not kv["r"].startswith(nonce): raise PgError("SCRAM nonce mismatch")
                    salted = hashlib.pbkdf2_hmac("sha256", self.pw.encode(), base64.b64decode(kv["s"]), int(kv["i"]))
                    ckey = hmac.new(salted, b"Client Key", "sha256").digest()
                    stored = hashlib.sha256(ckey).digest()
                    final_wo = f"c=biws,r={kv['r']}"
                    auth_msg = f"{state},{sf},{final_wo}".encode()
                    sig = hmac.new(stored, auth_msg, "sha256").digest()
                    proof = base64.b64encode(bytes(a ^ c for a, c in zip(ckey, sig))).decode()
                    self._send(b"p", f"{final_wo},p={proof}".encode())
                elif code == 12:
                    pass
                else:
                    raise PgError(f"unsupported auth method {code}")
            elif t == b"S":
                k, v = b.split(b"\0")[:2]; self.params[k.decode()] = v.decode()
            elif t == b"Z":
                return

    def _collect(self):
        cols, rows, err, types = None, [], None, []
        while True:
            t, b = self._msg()
            if t == b"T":
                n = struct.unpack("!h", b[:2])[0]; off = 2; cols = []; types = []
                for _ in range(n):
                    e = b.index(b"\0", off); cols.append(b[off:e].decode()); off = e + 1
                    _tbl, _att, typ, _len, _mod, _fmt = struct.unpack("!ihihih", b[off:off + 18]); off += 18
                    types.append(typ)
            elif t == b"D":
                n = struct.unpack("!h", b[:2])[0]; off = 2; row = []
                for i in range(n):
                    ln = struct.unpack("!i", b[off:off + 4])[0]; off += 4
                    if ln < 0: row.append(None); continue
                    raw = b[off:off + ln]; off += ln
                    typ = types[i] if i < len(types) else 25
                    if typ in (20, 21, 23): row.append(int(raw))
                    elif typ == 16: row.append(raw == b"t")
                    else: row.append(raw.decode("utf-8"))
                rows.append(tuple(row))
            elif t == b"E":
                err = self._err(b)
            elif t == b"Z":
                if err: raise PgError(err)
                return cols, rows
            # 1 2 n C N S s I: ignore

    def simple(self, sql):
        self._send(b"Q", sql.encode() + b"\0")
        return self._collect()

    def query(self, sql, params=()):
        body = b"\0" + sql.encode() + b"\0" + struct.pack("!h", 0)
        bb = b"\0\0" + struct.pack("!h", 0) + struct.pack("!h", len(params))
        for v in params:
            if v is None:
                bb += struct.pack("!i", -1)
            else:
                if type(v) is bool: raise ValueError("bool param")
                raw = str(v).encode("utf-8")
                bb += struct.pack("!i", len(raw)) + raw
        bb += struct.pack("!h", 0)
        msg = b"".join(t + struct.pack("!i", len(b) + 4) + b for t, b in (
            (b"P", body), (b"B", bb), (b"D", b"P\0"), (b"E", b"\0" + struct.pack("!i", 0)), (b"S", b"")))
        self.s.sendall(msg)          # one write: avoids Nagle/delayed-ACK stalls (40 ms per query otherwise)
        return self._collect()

    def close(self):
        try:
            self._send(b"X"); self.s.close()
        except Exception:
            pass

