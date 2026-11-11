#!/usr/bin/env python3
"""lowmy.py -- MariaDB and CockroachDB dialects for the Monban lowering oracles (stdlib only, run with python3 -I).

Copied byte-identically into oracles/lowering-read/ and oracles/lowering-write/ (like lowir.py; both READMEs record
its sha256). It imports lowir.py UNMODIFIED: the IR, the Lean model, the reference renderer and the PG wire client
stay there; this file only adds two dialects and the engine access they need (unit P7-oracle-adapters-001, D-P7.8).

Contents (ported from spikes/q4-005, reviewed there; protocol updated from the spike's pre-D4 v1 to v2):
  1. My -- MySQL/MariaDB client/server protocol client (spikes/q4-005/mywire.py): handshake v10,
     mysql_native_password incl. auth switch, caching_sha2_password fast path only (full auth needs TLS/RSA: refused),
     COM_QUERY (text rows) and COM_STMT_PREPARE/EXECUTE (binary protocol, bound parameters). Plaintext loopback only.
  2. MariaRenderer, dialect "mariadb" (spikes/q4-005/q4005.py MariaRenderer) -- the q4-005 mandated forms:
       atoms    strings CAST(c AS BINARY) <op> CAST(? AS BINARY); prefix LEFT(CAST(c AS BINARY), <utf8 bytes>) =
                CAST(? AS BINARY); ints c = ? on int columns only; class mismatch -> FALSE; NULL column -> NULL
       UPDATE   UPDATE .. SET .. WHERE lowerQ (MariaDB has no UPDATE .. RETURNING); a requested RETURNING is the
                reply's "returning_select": SELECT <post-image projection> FROM t WHERE lowerQ FOR UPDATE, run by the
                host immediately before the UPDATE in the same transaction
       DELETE   DELETE .. WHERE lowerQ RETURNING <permitted>
       INSERT   INSERT .. VALUES .. RETURNING <permitted>
       UPSERT   update cols: INSERT .. VALUES .. ON DUPLICATE KEY UPDATE c = IF(CAST(t AS BINARY) =
                CAST(VALUES(t) AS BINARY), VALUES(c), c) RETURNING ..; no update cols: INSERT .. SELECT .. FROM DUAL
                WHERE NOT EXISTS (SELECT 1 FROM t WHERE <own key, binary>) RETURNING ..; never REPLACE / IGNORE.
                Only behind the W3 schema gate (ODKU's arbiter is ANY unique key; on a foreign arbiter match ODKU
                RETURNING still returns the foreign row, q4-005).
  3. CrdbRenderer, dialect "crdb" -- the reference postgres forms with the q4-005 CockroachDB upsert-guard fix
     (`t.tenant::text = excluded.tenant::text COLLATE "C"`: on CockroachDB the left operand's column collation wins
     over an explicit COLLATE on the right, so the postgres guard is case-insensitive on a collated tenant column).
  4. ExtRenderer (dispatches on the request's dialect; sqlite / postgres / kv / rls go to lowir.Renderer unchanged),
     ExtLocalSubject, and `python3 -I lowmy.py serve [--mutant M ...]` (the reference subject for these engines).
"""
import hashlib, json, os, socket, struct, sys, urllib.parse

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lowir as L  # noqa: E402

# =========================================================================================== 1. MySQL wire client
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

# Session pinning the adapter must also do (q4-005 denylist): strict sql_mode, so a too-long tenant is an error, never
# a silent truncation (INSERT IGNORE / sql_mode='' truncated 'acmeEVIL' to 'acme', W2).
MY_SESSION = "set session sql_mode = 'STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION,ERROR_FOR_DIVISION_BY_ZERO'"

def my_connect(url):
    my = My(url)
    my.simple(MY_SESSION)
    return my

def my_version(my):
    """'11.8.9-MariaDB-ubu2404' (or the legacy '5.5.5-11.8.9-MariaDB...') -> '11.8.9'."""
    v = my.server_version
    if v.startswith("5.5.5-"): v = v[len("5.5.5-"):]
    return v.split("-")[0]

def crdb_version(pg):
    """`select version()` -> 'CockroachDB CCL v25.4.19 (x86_64-...)' -> '25.4.19' (server_version says 13.0.0)."""
    v = pg.simple("select version()")[1][0][0]
    if not v.startswith("CockroachDB"): raise ValueError(f"not a CockroachDB server: {v[:60]!r}")
    tok = v.split()[2]
    return tok[1:] if tok.startswith("v") else tok

def is_crdb(dsn):
    pg = L.Pg(dsn)
    try:
        return pg.simple("select version()")[1][0][0].startswith("CockroachDB")
    finally:
        pg.close()

def split_dsns(dsns, engines):
    """--dsn values -> {"pg": [...], "crdb": [...], "mariadb": [...]}: mysql:// is MariaDB; a postgresql:// DSN is
    CockroachDB iff its server says so (`select version()`), so `--engine pg --dsn A --engine crdb --dsn B` pairs."""
    out = {"pg": [], "crdb": [], "mariadb": []}
    for d in dsns:
        sch = urllib.parse.urlparse(d).scheme
        if sch in ("mysql", "mariadb"):
            out["mariadb"].append(d)
        elif sch in ("postgres", "postgresql"):
            want = [e for e in ("pg", "crdb") if e in engines]
            if len(want) == 1: out[want[0]].append(d)
            elif want: out["crdb" if is_crdb(d) else "pg"].append(d)
        else:
            raise ValueError(f"unknown DSN scheme {sch!r}")
    return out

# =========================================================================================== 2. MariaDB renderer
def bq(name):
    return "`" + str(name).replace("`", "``") + "`"

MY_MUTANTS = {
    "my-column-collation": "string atoms compared under the column collation (c = ?), no binary cast",
    "my-bin-padspace": "string atoms compared with COLLATE utf8mb4_bin (binary but PAD SPACE: 'acme ' = 'acme')",
    "my-odku-unguarded": "ON DUPLICATE KEY UPDATE c = VALUES(c) without the tenant IF guard (naive MariaDB upsert)",
    "my-update-returning-naive": "UPDATE RETURNING emulated by SELECT .. WHERE pred: no FOR UPDATE and no tenant conjunct",
}
CRDB_MUTANTS = {
    "crdb-upsert-stmt": "upsert rendered as UPSERT INTO (primary-key arbiter, no guard possible)",
    "crdb-column-collation": "string equality atoms compared under the column collation (no ::text .. COLLATE \"C\")",
    "crdb-reference-guard": "the postgres upsert guard verbatim (t.tenant = excluded.tenant COLLATE \"C\"), without the q4-005 cast fix",
}

class MariaRenderer(L.Renderer):
    """Hardened MariaDB forms (module docstring). MariaDB >= 10.5 has RETURNING on INSERT/REPLACE/DELETE only."""
    def __init__(self, mutants=()):
        super().__init__([m for m in mutants if m in L.MUTANTS])
        self.my = {m for m in mutants if m in MY_MUTANTS}

    class Ctx(L.Renderer.Ctx):
        def __init__(self, req):
            super().__init__(dict(req, dialect="sqlite"))      # base ctor validates only; ph/col overridden
            self.dialect = "mariadb"
        def ph(self, v):
            self.params.append(v); return "?"
        def col(self, f, alias=None):
            a = self.alias if alias is None else alias
            return (bq(a) + "." if a else "") + bq(f)

    def handle(self, req):
        if req.get("op") in ("update", "delete", "upsert", "insert", "read") and req.get("dialect") != "mariadb":
            raise ValueError("MariaRenderer serves dialect mariadb only")
        if req.get("op") in ("rls_policy", "rls_bind"):
            raise ValueError("refused: no row level security on mariadb")
        return super().handle(req)

    def tt(self, ctx): return "TRUE"
    def ff(self, ctx): return "FALSE"

    def _s(self, c, ph):
        if "my-column-collation" in self.my: return c, ph
        if "my-bin-padspace" in self.my: return c, f"{ph} COLLATE utf8mb4_bin"
        return f"CAST({c} AS BINARY)", f"CAST({ph} AS BINARY)"

    def eq_test(self, f, v, ctx, alias=None):
        c = ctx.col(f, alias)
        if "naive-bound" in self.m: return f"{c} = {ctx.ph(v)}"
        cc = L.col_class(ctx.columns.get(f))
        if cc is not type(v): return "FALSE"
        if type(v) is int:
            return "FALSE" if not self._int_ok(v) else f"({c} = {ctx.ph(v)})"
        a, b = self._s(c, ctx.ph(v))
        return f"({a} = {b})"

    def range_test(self, f, lo, hi, ctx):
        c = ctx.col(f)
        lt, gt = ("<", ">") if "range-exclusive" in self.m else ("<=", ">=")
        if "naive-bound" in self.m: return f"({c} >= {ctx.ph(lo)} AND {c} <= {ctx.ph(hi)})"
        cc = L.col_class(ctx.columns.get(f))
        if type(lo) is not type(hi) or cc is not type(lo): return "FALSE"
        if type(lo) is int:
            if lo > L.INT64_MAX or hi < L.INT64_MIN: return "FALSE"
            lo, hi = max(lo, L.INT64_MIN), min(hi, L.INT64_MAX)
            return f"({c} {gt} {ctx.ph(lo)} AND {c} {lt} {ctx.ph(hi)})"
        a, b1 = self._s(c, ctx.ph(lo)); _, b2 = self._s(c, ctx.ph(hi))
        return f"({a} {gt} {b1} AND {a} {lt} {b2})"

    def pfx_test(self, f, s, ctx):
        c = ctx.col(f)
        if "like-prefix" in self.m or "naive-bound" in self.m:
            return f"({c} LIKE {ctx.ph(s + '%')})"
        if L.col_class(ctx.columns.get(f)) is not str: return "FALSE"
        if "my-column-collation" in self.my or "my-bin-padspace" in self.my:
            a, b = self._s(f"LEFT({c}, {ctx.ph(len(s))})", ctx.ph(s))
            return f"({a} = {b})"
        n = len(s.encode("utf-8"))
        return f"(LEFT(CAST({c} AS BINARY), {ctx.ph(n)}) = CAST({ctx.ph(s)} AS BINARY))"

    def write(self, req):
        op = req["op"]
        ctx = self.Ctx(req); ctx.alias = None
        table, tf = req["table"], req["tenant_field"]
        cols = req.get("columns") or {}
        t = self.tenant(req)
        key = list(req.get("key") or [])
        ret = list(req.get("returning") or [])
        for c in ret:
            if c not in cols: raise ValueError(f"returning unknown column {c!r}")
        self._constraints(req, op, tf, key)
        retcols = list(cols) if "returning-star" in self.m else ret
        retsql = (" RETURNING *" if "returning-star" in self.m else
                  (" RETURNING " + ", ".join(bq(c) for c in ret) if ret else ""))
        if op == "update":
            sets = req.get("set") or {}
            if not sets: raise ValueError("empty SET")
            for c, v in sets.items():
                if c not in cols: raise ValueError(f"unknown column {c!r}")
                if (c == tf or c in key) and "set-tenant-passthrough" not in self.m:
                    raise ValueError(f"refused: SET of tenant/key column {c!r}")
                L.check_value(v)
            out = {}
            if retcols:
                sctx = self.Ctx(req); sctx.alias = None
                proj = [f"{sctx.ph(sets[c])} AS {bq(c)}" if c in sets else bq(c) for c in retcols]
                if "my-update-returning-naive" in self.my:
                    validate_fields = set(cols) or L._AnyFields()
                    L.validate(req["pred"], validate_fields)
                    w = self.render(req["pred"], sctx)
                    out["returning_select"] = {"sql": f"SELECT {', '.join(proj)} FROM {bq(table)} WHERE {w}", "params": sctx.params}
                else:
                    w = self.where(req, sctx)
                    out["returning_select"] = {"sql": f"SELECT {', '.join(proj)} FROM {bq(table)} WHERE {w} FOR UPDATE",
                                               "params": sctx.params}
            setsql = ", ".join(f"{bq(c)} = {ctx.ph(v)}" for c, v in sets.items())
            w = self.where(req, ctx)
            pre = "WITH s AS (SELECT 1) " if "update-via-cte" in self.m else ""
            out.update({"sql": f"{pre}UPDATE {bq(table)} SET {setsql} WHERE {w}", "params": ctx.params})
            return out
        if op == "delete":
            w = self.where(req, ctx)
            return {"sql": f"DELETE FROM {bq(table)} WHERE {w}{retsql}", "params": ctx.params}
        # insert / upsert
        row = dict(req.get("row") or {})
        upd = list(req.get("update") or []) if op == "upsert" else []
        for c in list(row) + upd:
            if c not in cols: raise ValueError(f"unknown column {c!r}")
        if tf in row and "upsert-tenant-from-row" not in self.m:
            raise ValueError("refused: request row carries the tenant column")
        for c in upd:
            if c == tf or c in key: raise ValueError(f"refused: update of tenant/key column {c!r}")
        for v in row.values(): L.check_value(v)
        vals = dict(row)
        if "upsert-tenant-from-row" not in self.m or tf not in vals:
            vals[tf] = t
        names = [tf] + [c for c in vals if c != tf]
        collist = ", ".join(bq(c) for c in names)
        if op == "insert":
            for c in key:
                if c != tf and c not in row: raise ValueError(f"insert row lacks key column {c!r}")
            ph = ", ".join(ctx.ph(vals[c]) for c in names)
            return {"sql": f"INSERT INTO {bq(table)} ({collist}) VALUES ({ph}){retsql}", "params": ctx.params}
        if "replace-into" in self.m:
            ph = ", ".join(ctx.ph(vals[c]) for c in names)
            return {"sql": f"REPLACE INTO {bq(table)} ({collist}) VALUES ({ph}){retsql}", "params": ctx.params}
        if "upsert-global-arbiter" in self.m:
            ph = ", ".join(ctx.ph(vals[c]) for c in names)
            sets = ", ".join(f"{bq(c)} = VALUES({bq(c)})" for c in upd) or f"{bq('id')} = {bq('id')}"
            return {"sql": f"INSERT INTO {bq(table)} ({collist}) VALUES ({ph}) ON DUPLICATE KEY UPDATE {sets}{retsql}",
                    "params": ctx.params}
        if tf not in key:
            raise ValueError("refused: upsert arbiter must include the tenant column (composite key required)")
        if "insert-global-key" not in self.m:
            for u in (req.get("unique") or [key]):
                if tf not in u:
                    raise ValueError(f"refused: unique key {u} lacks the tenant column (W3: the arbiter must be the only unique key)")
        for c in key:
            if c != tf and c not in row: raise ValueError(f"upsert row lacks key column {c!r}")
        if "upsert-as-merge" in self.m:
            ph = ", ".join(ctx.ph(vals[c]) for c in names)
            on = " AND ".join(f"{bq(table)}.{bq(c)} = s.{bq(c)}" for c in key)
            return {"sql": f"MERGE INTO {bq(table)} USING (SELECT {ph}) AS s ON {on} WHEN NOT MATCHED THEN INSERT ({collist}) "
                           f"VALUES ({', '.join('s.' + bq(c) for c in names)})", "params": ctx.params}
        if not upd:
            # insert-if-absent; never INSERT IGNORE (downgrades errors to warnings, truncates: W2)
            ph = ", ".join(ctx.ph(vals[c]) for c in names)
            conds = []
            for c in key:
                if type(vals[c]) is str:
                    conds.append(f"CAST({bq(c)} AS BINARY) = CAST({ctx.ph(vals[c])} AS BINARY)")
                else:
                    conds.append(f"{bq(c)} = {ctx.ph(vals[c])}")
            return {"sql": f"INSERT INTO {bq(table)} ({collist}) SELECT {ph} FROM DUAL WHERE NOT EXISTS "
                           f"(SELECT 1 FROM {bq(table)} WHERE {' AND '.join(conds)}){retsql}", "params": ctx.params}
        ph = ", ".join(ctx.ph(vals[c]) for c in names)
        if "my-odku-unguarded" in self.my:
            sets = ", ".join(f"{bq(c)} = VALUES({bq(c)})" for c in upd)
        else:
            g = f"CAST({bq(tf)} AS BINARY) = CAST(VALUES({bq(tf)}) AS BINARY)"
            sets = ", ".join(f"{bq(c)} = IF({g}, VALUES({bq(c)}), {bq(c)})" for c in upd)
        return {"sql": f"INSERT INTO {bq(table)} ({collist}) VALUES ({ph}) ON DUPLICATE KEY UPDATE {sets}{retsql}",
                "params": ctx.params}

# =========================================================================================== 3. CockroachDB renderer
class CrdbRenderer(L.Renderer):
    """The reference postgres-dialect forms under dialect "crdb", with the q4-005 upsert-guard cast fix."""
    def __init__(self, mutants=()):
        super().__init__([m for m in mutants if m in L.MUTANTS])
        self.cr = {m for m in mutants if m in CRDB_MUTANTS}

    class Ctx(L.Renderer.Ctx):
        def __init__(self, req):
            super().__init__(dict(req, dialect="postgres"))   # CockroachDB speaks the postgres forms ($n, ::text)

    def handle(self, req):
        if req.get("op") in ("update", "delete", "upsert", "insert", "read") and req.get("dialect") != "crdb":
            raise ValueError("CrdbRenderer serves dialect crdb only")
        if req.get("op") in ("rls_policy", "rls_bind"):
            raise ValueError("refused: row level security is not part of the crdb dialect")
        return super().handle(req)

    def eq_test(self, f, v, ctx, alias=None):
        if ("crdb-column-collation" in self.cr and type(v) is str and L.col_class(ctx.columns.get(f)) is str
                and "naive-bound" not in self.m):
            return f"({ctx.col(f, alias)} = {ctx.ph(v)})"     # compares under the column collation
        return super().eq_test(f, v, ctx, alias)

    def write(self, req):
        if "crdb-upsert-stmt" in self.cr and req["op"] == "upsert":
            t = self.tenant(req)
            row = dict(req.get("row") or {}); row[req["tenant_field"]] = t
            names = [req["tenant_field"]] + [c for c in row if c != req["tenant_field"]]
            ret = req.get("returning") or []
            sql = (f"UPSERT INTO {L.qi(req['table'])} ({', '.join(L.qi(c) for c in names)}) VALUES "
                   f"({', '.join(f'${i + 1}' for i in range(len(names)))})" +
                   (" RETURNING " + ", ".join(L.qi(c) for c in ret) if ret else ""))
            return {"sql": sql, "params": [row[c] for c in names]}
        out = super().write(req)
        if req["op"] == "upsert" and "sql" in out and "crdb-reference-guard" not in self.cr:
            t, tf = L.qi(req["table"]), L.qi(req["tenant_field"])
            old = f' WHERE {t}.{tf} = excluded.{tf} COLLATE "C"'
            new = f' WHERE {t}.{tf}::text = excluded.{tf}::text COLLATE "C"'
            out["sql"] = out["sql"].replace(old, new)
        return out

# =========================================================================================== 4. dispatcher + protocol
ALL_MUTANTS = dict(L.MUTANTS, **MY_MUTANTS, **CRDB_MUTANTS)

class ExtRenderer:
    """lowir.Renderer for sqlite / postgres / kv / rls requests (unchanged), MariaRenderer for dialect "mariadb",
    CrdbRenderer for dialect "crdb"."""
    def __init__(self, mutants=()):
        bad = set(mutants) - set(ALL_MUTANTS)
        if bad: raise ValueError(f"unknown mutants {sorted(bad)}")
        self.m = set(mutants)
        self.base = L.Renderer([m for m in mutants if m in L.MUTANTS])
        self.maria, self.crdb = MariaRenderer(mutants), CrdbRenderer(mutants)
    def handle(self, req):
        if req.get("op") == "hello" and "refuse-all" not in self.m:
            return {"name": "monban-reference-renderer(lowmy.py)", "mutants": sorted(self.m), "protocol": L.PROTOCOL}
        d = req.get("dialect")
        if d == "mariadb": return self.maria.handle(req)
        if d == "crdb": return self.crdb.handle(req)
        return self.base.handle(req)

class ExtLocalSubject(L.LocalSubject):
    def __init__(self, mutants=()):
        self.r = ExtRenderer(mutants)
        self.name = "reference-ext" + (f"[{','.join(sorted(mutants))}]" if mutants else "")

def reference_cmd(here):
    return f"{sys.executable} -I {os.path.join(here, 'lowmy.py')} serve"

def serve(argv):
    muts, i = [], 0
    while i < len(argv):
        if argv[i] == "--mutant" and i + 1 < len(argv):
            muts.append(argv[i + 1]); i += 2
        else:
            raise SystemExit(f"serve: unknown argument {argv[i]!r}")
    r = ExtRenderer(muts)
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        rid = None
        try:
            req = json.loads(line); rid = req.get("id")
            out = r.handle(req)
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as e:
            out = {"refuse": str(e)}
        out["id"] = rid; out["v"] = L.PROTOCOL
        sys.stdout.write(json.dumps(out, ensure_ascii=True) + "\n"); sys.stdout.flush()

if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "serve":
        serve(sys.argv[2:])
    else:
        print(__doc__)
        print("usage: python3 -I lowmy.py serve [--mutant NAME ...]\nmutants (plus every lowir.py mutant):")
        for k, v in dict(MY_MUTANTS, **CRDB_MUTANTS).items(): print(f"  {k:26s} {v}")
