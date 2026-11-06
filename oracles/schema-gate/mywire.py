"""Minimal MySQL/MariaDB client/server protocol client for the schema-gate oracle (stdlib only, python3 -I).

Verbatim copy of section 1 (class MyError .. class My) of oracles/lowering-read/lowmy.py, itself ported from
spikes/q4-005/mywire.py (reviewed there). The schema-gate directory stays self-contained, like pgwire.py.
"""
import hashlib, socket, struct, urllib.parse

class MyError(Exception):
    def __init__(self, code, state, msg):
        super().__init__(f"{code} ({state}): {msg}"); self.code, self.state = code, state

CAP = (0x1 | 0x4 | 0x8 | 0x200 | 0x2000 | 0x8000 | 0x20000 | 0x40000 | 0x80000 | 0x200000)
CHARSET_UTF8MB4_GENERAL_CI = 45
MAX_PACKET = 64 << 20          # a reply larger than this is refused (oracle-side memory bound)

def _lenenc_int(b, o):
    c = b[o]
    if c < 0xfb: return c, o + 1
    if c == 0xfb: return None, o + 1
    if c == 0xfc: return struct.unpack_from("<H", b, o + 1)[0], o + 3
    if c == 0xfd: return int.from_bytes(b[o + 1:o + 4], "little"), o + 4
    return struct.unpack_from("<Q", b, o + 1)[0], o + 9

def _lenenc_str(b, o):
    n, o = _lenenc_int(b, o)
    if n is None: return None, o
    return b[o:o + n], o + n

def _enc_lenenc(n):
    if n < 0xfb: return bytes([n])
    if n < 1 << 16: return b"\xfc" + struct.pack("<H", n)
    if n < 1 << 24: return b"\xfd" + n.to_bytes(3, "little")
    return b"\xfe" + struct.pack("<Q", n)

def native_scramble(pw, salt):
    if not pw: return b""
    h1 = hashlib.sha1(pw).digest(); h2 = hashlib.sha1(h1).digest()
    h3 = hashlib.sha1(salt + h2).digest()
    return bytes(a ^ b for a, b in zip(h1, h3))

def sha2_scramble(pw, salt):
    if not pw: return b""
    h1 = hashlib.sha256(pw).digest(); h2 = hashlib.sha256(h1).digest()
    h3 = hashlib.sha256(h2 + salt).digest()
    return bytes(a ^ b for a, b in zip(h1, h3))

INT_TYPES = {1: ("<b", 1), 2: ("<h", 2), 3: ("<i", 4), 9: ("<i", 4), 8: ("<q", 8), 13: ("<h", 2)}

class My:
    def __init__(self, url, timeout=30, charset=CHARSET_UTF8MB4_GENERAL_CI):
        u = urllib.parse.urlparse(url)
        if u.scheme not in ("mysql", "mariadb"): raise ValueError("url must be mysql://user:pw@host:port/db")
        self.url = url
        self.user = urllib.parse.unquote(u.username or "root").encode()
        self.pw = urllib.parse.unquote(u.password or "").encode()
        self.db = (u.path or "/")[1:].encode()
        self.s = socket.create_connection((u.hostname or "127.0.0.1", u.port or 3306), timeout=timeout)
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.f = self.s.makefile("rb")
        self.seq = 0
        self._handshake(charset)

    # ---- framing
    def _read(self):
        h = self.f.read(4)
        if len(h) < 4: raise MyError(0, "08S01", "connection closed")
        n = int.from_bytes(h[:3], "little"); self.seq = (h[3] + 1) & 0xff
        b = self.f.read(n)
        while n == 0xffffff:
            if len(b) > MAX_PACKET: raise MyError(0, "08S01", "packet over the oracle cap")
            h = self.f.read(4); n = int.from_bytes(h[:3], "little"); self.seq = (h[3] + 1) & 0xff; b += self.f.read(n)
        if len(b) < 1: raise MyError(0, "08S01", "empty packet")
        return b

    def _write(self, payload, reset=False):
        if reset: self.seq = 0
        out = b""
        while True:
            chunk, payload = payload[:0xffffff], payload[0xffffff:]
            out += len(chunk).to_bytes(3, "little") + bytes([self.seq]) + chunk
            self.seq = (self.seq + 1) & 0xff
            if len(chunk) < 0xffffff: break
        self.s.sendall(out)

    @staticmethod
    def _err(b):
        code = struct.unpack_from("<H", b, 1)[0]
        if b[3:4] == b"#": return MyError(code, b[4:9].decode(), b[9:].decode("utf-8", "replace"))
        return MyError(code, "HY000", b[3:].decode("utf-8", "replace"))

    # ---- connect
    def _handshake(self, charset):
        b = self._read()
        if b[0] == 0xff: raise self._err(b)
        if b[0] != 10: raise MyError(0, "08S01", f"protocol {b[0]}")
        e = b.index(b"\0", 1); self.server_version = b[1:e].decode(); o = e + 1
        self.conn_id = struct.unpack_from("<I", b, o)[0]; o += 4
        salt = b[o:o + 8]; o += 9
        caps = struct.unpack_from("<H", b, o)[0]; o += 2
        o += 1 + 2
        caps |= struct.unpack_from("<H", b, o)[0] << 16; o += 2
        alen = b[o]; o += 1 + 10
        n2 = max(13, alen - 8)
        salt += b[o:o + n2].rstrip(b"\0"); o += n2
        plugin = b[o:b.index(b"\0", o)].decode() if b"\0" in b[o:] else "mysql_native_password"
        self.salt = salt[:20]
        auth = self._scr(plugin, self.salt)
        resp = (struct.pack("<IIB", CAP & (caps | 0x8), 1 << 24, charset) + b"\0" * 23 + self.user + b"\0" +
                _enc_lenenc(len(auth)) + auth + self.db + b"\0" + plugin.encode() + b"\0")
        self._write(resp)
        self._auth_loop()

    def _scr(self, plugin, salt):
        if plugin == "mysql_native_password": return native_scramble(self.pw, salt)
        if plugin == "caching_sha2_password": return sha2_scramble(self.pw, salt)
        raise MyError(0, "28000", f"unsupported auth plugin {plugin}")

    def _auth_loop(self):
        while True:
            b = self._read()
            if b[0] == 0x00: return
            if b[0] == 0xff: raise self._err(b)
            if b[0] == 0xfe:      # auth switch
                e = b.index(b"\0", 1); plugin = b[1:e].decode(); salt = b[e + 1:].rstrip(b"\0")[:20]
                self._write(self._scr(plugin, salt)); continue
            if b[0] == 0x01:      # caching_sha2 more data
                if b[1:2] == b"\x03": continue
                raise MyError(0, "28000", "caching_sha2 full authentication needs TLS/RSA (not supported)")
            raise MyError(0, "08S01", f"unexpected auth packet {b[:1]!r}")

    # ---- results
    def _coldefs(self, n):
        cols = []
        for _ in range(n):
            b = self._read(); o = 0
            for _ in range(4): _, o = _lenenc_str(b, o)
            name, o = _lenenc_str(b, o); _, o = _lenenc_str(b, o)
            _, o = _lenenc_int(b, o)
            cs, ln, typ, flags, dec = struct.unpack_from("<HIBHB", b, o)
            cols.append((name.decode(), cs, typ, flags))
        if n:
            b = self._read()
            if b[0] != 0xfe: raise MyError(0, "08S01", "expected EOF after column defs")
        return cols

    @staticmethod
    def _conv_text(raw, col):
        if raw is None: return None
        _, cs, typ, _ = col
        if typ in INT_TYPES: return int(raw)
        if cs == 63: return bytes(raw)
        return raw.decode("utf-8")

    def _result(self, binary):
        """Read one result (OK / ERR / result set). Returns (cols, rows, more_results)."""
        b = self._read()
        if b[0] == 0xff: raise self._err(b)
        if b[0] == 0x00:
            _, o = _lenenc_int(b, 1); _, o = _lenenc_int(b, o)
            st = struct.unpack_from("<H", b, o)[0]
            return None, [], bool(st & 0x8)
        n, _ = _lenenc_int(b, 0)
        cols = self._coldefs(n)
        rows = []
        while True:
            b = self._read()
            if b[0] == 0xfe and len(b) < 9:
                st = struct.unpack_from("<H", b, 3)[0]
                return [c[0] for c in cols], rows, bool(st & 0x8)
            if b[0] == 0xff: raise self._err(b)
            rows.append(self._row_bin(b, cols) if binary else self._row_text(b, cols))

    def _row_text(self, b, cols):
        o, row = 0, []
        for c in cols:
            raw, o = _lenenc_str(b, o); row.append(self._conv_text(raw, c))
        return tuple(row)

    def _row_bin(self, b, cols):
        nb = (len(cols) + 7 + 2) // 8
        bitmap = b[1:1 + nb]; o = 1 + nb; row = []
        for i, c in enumerate(cols):
            bit = i + 2
            if bitmap[bit // 8] & (1 << (bit % 8)): row.append(None); continue
            _, cs, typ, flags = c
            if typ in INT_TYPES:
                fmt, w = INT_TYPES[typ]
                if flags & 0x20: fmt = fmt.upper()
                row.append(struct.unpack_from(fmt, b, o)[0]); o += w
            elif typ in (4, 5):
                w = 4 if typ == 4 else 8; row.append(struct.unpack_from("<f" if w == 4 else "<d", b, o)[0]); o += w
            else:
                raw, o = _lenenc_str(b, o)
                row.append(bytes(raw) if cs == 63 else raw.decode("utf-8"))
        return tuple(row)

    def _drain(self, binary):
        cols, rows, more = self._result(binary)
        out = (cols, rows)
        err = None
        while more:
            try:
                c2, r2, more = self._result(binary)
                if c2 is not None and out[0] is None: out = (c2, r2)
            except MyError as e:
                err = e; more = False
        if err: raise err
        return out

    # ---- API
    def simple(self, sql):
        self._write(b"\x03" + sql.encode("utf-8"), reset=True)
        return self._drain(False)

    def query(self, sql, params=()):
        """Prepared statement (binary protocol) when there are parameters; never text interpolation."""
        if not params: return self.simple(sql)
        self._write(b"\x16" + sql.encode("utf-8"), reset=True)
        b = self._read()
        if b[0] == 0xff: raise self._err(b)
        sid, ncol, npar = struct.unpack_from("<IHH", b, 1)
        if npar: self._coldefs(npar)
        if ncol: self._coldefs(ncol)
        try:
            if npar != len(params): raise MyError(0, "07001", f"statement has {npar} params, {len(params)} given")
            nullmap = bytearray((npar + 7) // 8); types = b""; vals = b""
            for i, v in enumerate(params):
                if v is None:
                    nullmap[i // 8] |= 1 << (i % 8); types += b"\x06\x00"
                elif type(v) is int:
                    types += b"\x08\x00"; vals += struct.pack("<q", v)
                elif type(v) is str:
                    raw = v.encode("utf-8"); types += b"\xfd\x00"; vals += _enc_lenenc(len(raw)) + raw
                elif type(v) is bytes:
                    types += b"\xfc\x00"; vals += _enc_lenenc(len(v)) + v
                else:
                    raise MyError(0, "07006", f"param type {type(v)}")
            self._write(b"\x17" + struct.pack("<IBI", sid, 0, 1) + bytes(nullmap) + b"\x01" + types + vals, reset=True)
            return self._drain(True)
        finally:
            self._write(b"\x19" + struct.pack("<I", sid), reset=True)

    def close(self):
        try:
            self._write(b"\x01", reset=True); self.s.close()
        except Exception:
            pass
