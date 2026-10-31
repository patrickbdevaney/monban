"""F14 worker<->supervisor frames and the F10 op/result values, in the F10 encoding rule (postcard positional:
unsigned varints, zigzag signed varints, length-prefixed tstr/bstr/arrays, choices as a varint discriminant,
bool one byte, option = 0 | 1 value). Stdlib only. Decoders are total: they raise DecodeError, never anything else.
"""


class DecodeError(Exception):
    pass


# ------------------------------------------------------------------------------------------------ primitives
def u(n):
    if n < 0:
        raise ValueError(n)
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def zz(n):
    return u((n << 1) ^ (n >> 63) if n < 0 else n << 1)


def bs(b):
    return u(len(b)) + bytes(b)


def ts(s):
    return bs(s.encode() if isinstance(s, str) else s)


def seq(items):
    return u(len(items)) + b"".join(items)


class Dec:
    def __init__(self, b):
        self.b, self.i = bytes(b), 0

    def u(self):
        v = 0
        for k in range(10):
            if self.i >= len(self.b):
                raise DecodeError("truncated varint")
            x = self.b[self.i]
            self.i += 1
            v |= (x & 0x7F) << (7 * k)
            if not x & 0x80:
                return v
        raise DecodeError("varint too long")

    def z(self):
        v = self.u()
        return (v >> 1) ^ -(v & 1)

    def bytes(self):
        n = self.u()
        if n > len(self.b) - self.i:
            raise DecodeError("truncated bytes")
        s = self.b[self.i:self.i + n]
        self.i += n
        return s

    def text(self):
        try:
            return self.bytes().decode("utf-8")
        except UnicodeDecodeError:
            raise DecodeError("tstr not utf-8")

    def byte(self):
        if self.i >= len(self.b):
            raise DecodeError("truncated")
        x = self.b[self.i]
        self.i += 1
        return x

    def boolean(self):
        x = self.byte()
        if x > 1:
            raise DecodeError("bad bool")
        return bool(x)

    def rest(self):
        r = self.b[self.i:]
        self.i = len(self.b)
        return r

    def done(self):
        if self.i != len(self.b):
            raise DecodeError("trailing bytes")


# ------------------------------------------------------------------------------------------------ F10 values
def value(v):
    if isinstance(v, int):
        return u(0) + zz(v)
    return u(1) + ts(v)


def pred(p):
    """p: ("tt",) ("ff",) ("eq", f, v) ("in", f, [v]) ("range", f, a, b) ("pfx", f, s) ("and", p, q) ("or", p, q)
    ("not", p)"""
    k = p[0]
    if k == "tt":
        return u(0)
    if k == "ff":
        return u(1)
    if k == "eq":
        return u(2) + u(p[1]) + value(p[2])
    if k == "in":
        return u(3) + u(p[1]) + seq([value(x) for x in p[2]])
    if k == "range":
        return u(4) + u(p[1]) + value(p[2]) + value(p[3])
    if k == "pfx":
        return u(5) + u(p[1]) + ts(p[2])
    if k in ("and", "or"):
        return u(6 if k == "and" else 7) + pred(p[1]) + pred(p[2])
    if k == "not":
        return u(8) + pred(p[1])
    raise ValueError(k)


KINDS = ["select", "insert", "update", "delete", "upsert"]


def op(tenant, collection, kind, filt=("tt",), writes=(), returning=()):
    return (u(tenant) + ts(collection) + u(KINDS.index(kind)) + pred(filt)
            + seq([u(f) + value(v) for f, v in writes]) + seq([u(f) for f in returning]))


MAX_PRED_DEPTH = 64  # F4 aegis_data_ir::lower::MAX_PRED_DEPTH


def dec_value(d):
    t = d.u()
    if t == 0:
        return d.z()
    if t == 1:
        return d.text()
    raise DecodeError("bad value tag")


def dec_pred(d, depth=0):
    if depth > MAX_PRED_DEPTH:
        raise DecodeError("pred too deep")
    t = d.u()
    if t == 0:
        return ("tt",)
    if t == 1:
        return ("ff",)
    if t == 2:
        return ("eq", d.u(), dec_value(d))
    if t == 3:
        f = d.u()
        n = d.u()
        if n > 4096:
            raise DecodeError("isIn too long")
        return ("in", f, [dec_value(d) for _ in range(n)])
    if t == 4:
        return ("range", d.u(), dec_value(d), dec_value(d))
    if t == 5:
        return ("pfx", d.u(), d.text())
    if t in (6, 7):
        return ("and" if t == 6 else "or", dec_pred(d, depth + 1), dec_pred(d, depth + 1))
    if t == 8:
        return ("not", dec_pred(d, depth + 1))
    raise DecodeError("bad pred tag")


def dec_op(b):
    d = Dec(b)
    tenant = d.u()
    if tenant == 0:
        raise DecodeError("tenant must be > 0")
    coll = d.text()
    kind = d.u()
    if kind > 4:
        raise DecodeError("bad kind")
    filt = dec_pred(d)
    n = d.u()
    if n > 256:
        raise DecodeError("too many writes")
    writes = [(d.u(), dec_value(d)) for _ in range(n)]
    n = d.u()
    if n > 256:
        raise DecodeError("too many returning")
    ret = [d.u() for _ in range(n)]
    d.done()
    return {"tenant": tenant, "collection": coll, "kind": KINDS[kind], "filter": filt, "writes": writes,
            "returning": ret}


def result_rows(rows):
    out = []
    for r in rows:
        out.append(seq([(u(0) if v is None else u(1) + value(v)) for v in r]))
    return u(0) + seq(out)


def result_err(code):
    return u(1) + u(code)


def dec_result(b):
    d = Dec(b)
    t = d.u()
    if t == 0:
        rows = []
        for _ in range(d.u()):
            row = []
            for _ in range(d.u()):
                row.append(None if d.u() == 0 else dec_value(d))
            rows.append(row)
        d.done()
        return ("rows", rows)
    if t == 1:
        c = d.u()
        d.done()
        return ("err", c)
    raise DecodeError("bad result tag")


# ------------------------------------------------------------------------------------------------ F14 values
def req_head(method="GET", path="/", query=None, headers=(), body_len=None):
    q = u(0) + bs(query or b"")
    h = seq([ts(n) + bs(v) for n, v in headers])
    bl = u(0) if body_len is None else u(1) + u(body_len)
    return ts(method) + ts(path) + q + h + bl


def resp_headers(hs):
    """hs: [(name bytes|str, value bytes|str)] encoded verbatim (the corpus uses it to build hostile headers)."""
    def b(x):
        return x.encode() if isinstance(x, str) else x
    return seq([bs(b(n)) + bs(b(v)) for n, v in hs])


LIMIT_KEYS = ["fuel", "wall_ms", "memory_mib", "max_host_calls", "max_data_runs", "max_data_bytes",
              "max_resp_bytes", "max_log_bytes"]
DEFAULT_LIMITS = {"fuel": 15_000_000, "wall_ms": 100, "memory_mib": 16, "max_host_calls": 10_000,
                  "max_data_runs": 64, "max_data_bytes": 4_194_304, "max_resp_bytes": 1_048_576,
                  "max_log_bytes": 65_536}


def f_request(rid, limits, head):
    return u(0) + u(rid) + b"".join(u(limits[k]) for k in LIMIT_KEYS) + head


def f_body(rid, chunk, last):
    return u(1) + u(rid) + bs(chunk) + bytes([1 if last else 0])


def f_data_reply(rid, sq, result):
    return u(2) + u(rid) + u(sq) + result


def f_cancel(rid):
    return u(3) + u(rid)


TRAPS = {1: "fuel", 2: "wall", 3: "memory/table", 4: "wasm-trap", 5: "handle", 6: "quota", 7: "abi-misuse",
         8: "host-fault"}


def dec_w2s(b):
    """Decode one worker->supervisor frame fully (F14 Part 2). Returns a dict; raises DecodeError."""
    d = Dec(b)
    tag = d.u()
    if tag == 16:
        z = d.u()
        ver = d.u()
        dig = d.bytes()
        d.done()
        if z != 0 or len(dig) != 32:
            raise DecodeError("bad ready")
        return {"t": "ready", "ver": ver, "sha256": dig.hex()}
    rid = d.u()
    if tag == 17:
        status = d.u()
        n = d.u()
        if n > 4096:
            raise DecodeError("too many headers")
        hs = [(d.bytes(), d.bytes()) for _ in range(n)]
        d.done()
        return {"t": "resp-head", "rid": rid, "status": status, "headers": hs}
    if tag == 18:
        c = d.bytes()
        d.done()
        return {"t": "resp-body", "rid": rid, "chunk": c}
    if tag == 19:
        e = d.u()
        if e == 0:
            end = ("code", d.u())
        elif e == 1:
            tr = d.u()
            if tr not in TRAPS:
                raise DecodeError("bad trap code")
            end = ("trap", tr)
        else:
            raise DecodeError("bad end")
        fuel = d.u()
        d.done()
        return {"t": "resp-end", "rid": rid, "end": end, "fuel": fuel}
    if tag == 20:
        sq = d.u()
        o = d.bytes()
        d.done()
        return {"t": "data-run", "rid": rid, "seq": sq, "op": o}
    if tag == 21:
        lvl = d.u()
        data = d.bytes()
        d.done()
        if lvl > 4:
            raise DecodeError("bad level")
        return {"t": "log", "rid": rid, "level": lvl, "data": data}
    if tag == 22:
        base = d.u()
        pid = d.u()
        d.done()
        return {"t": "layout", "base": base, "pid": pid}
    raise DecodeError(f"unknown tag {tag}")
