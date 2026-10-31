"""Stdlib-only helpers shared by the p2-e2e oracle and its reference (mock) subject.

- postcard (F10 encoding rule, applied by F14): unsigned LEB128 varints, length-prefixed tstr/bstr/sequences, a choice
  as a varint discriminant plus its fields, an option as 0 / 1 + value, a record (CDDL array of named fields) as its
  fields in order with no prefix.
- F14 `req-head`: encode (the mock supervisor) and a strict, total decode (the oracle judges echoed answers).
- Wasm core binary: section walk, export rewrite (keep `memory`, rename one function export to `handle`), F14 import
  allowlist check, and a minimal stub module for the reference subject.
Infrastructure only: no verdict logic lives here.
"""

# ------------------------------------------------------------------------------------------------ postcard


def uvarint(n):
    if n < 0:
        raise ValueError("negative varint")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


class Reader:
    def __init__(self, b):
        self.b, self.i = bytes(b), 0

    def varint(self, max_bytes=10):
        n, shift = 0, 0
        for k in range(max_bytes):
            if self.i >= len(self.b):
                raise ValueError("truncated varint")
            c = self.b[self.i]
            self.i += 1
            n |= (c & 0x7F) << shift
            if not c & 0x80:
                if k > 0 and c == 0:
                    raise ValueError("non-minimal varint")
                return n
            shift += 7
        raise ValueError("varint too long")

    def take(self, n):
        if n > len(self.b) - self.i:
            raise ValueError("truncated bytes")
        v = self.b[self.i:self.i + n]
        self.i += n
        return v

    def bstr(self):
        return self.take(self.varint())

    def tstr(self):
        return self.bstr().decode("utf-8")  # strict: invalid UTF-8 raises

    def end(self):
        if self.i != len(self.b):
            raise ValueError(f"{len(self.b) - self.i} trailing bytes")


def enc_bstr(b):
    return uvarint(len(b)) + bytes(b)


def enc_tstr(s):
    return enc_bstr(s.encode())


# F14 request header allowlist (fixed, not configurable).
REQ_HEADER_ALLOW = ("accept", "accept-language", "content-type", "if-match", "if-modified-since", "if-none-match",
                    "if-unmodified-since", "range")


def encode_req_head(method, path, query_bytes, headers, body_len):
    """headers: [(name lower, value bytes)] already filtered to the allowlist; body_len: int or None."""
    out = enc_tstr(method) + enc_tstr(path) + uvarint(0) + enc_bstr(query_bytes) + uvarint(len(headers))
    for n, v in headers:
        out += enc_tstr(n) + enc_bstr(v)
    out += uvarint(0) if body_len is None else uvarint(1) + uvarint(body_len)
    return out


def decode_req_head(b):
    """Strict decode of an F14 req-head. Returns a dict; raises ValueError on any deviation."""
    r = Reader(b)
    method = r.tstr()
    path = r.tstr()
    qd = r.varint()
    if qd == 0:
        query = ("opaque", r.bstr())
    elif qd == 1:
        query = ("typed", [(r.tstr(), r.tstr()) for _ in range(r.varint())])
    else:
        raise ValueError(f"query discriminant {qd}")
    headers = [(r.tstr(), r.bstr()) for _ in range(r.varint())]
    bd = r.varint()
    if bd == 0:
        body_len = None
    elif bd == 1:
        body_len = r.varint()
    else:
        raise ValueError(f"body-len discriminant {bd}")
    r.end()
    return {"method": method, "path": path, "query": query, "headers": headers, "body_len": body_len}


# ------------------------------------------------------------------------------------------------ wasm binary

WASM_MAGIC = b"\0asm\x01\0\0\0"
I32 = 0x7F

# F14 Part 1: module "aegis" allowlist, (params, results) in Wasm value types.
F14_IMPORTS = {
    ("aegis", "req_head"): ((I32, I32), (I32,)),
    ("aegis", "req_body_read"): ((I32, I32), (I32,)),
    ("aegis", "resp_head"): ((I32, I32, I32), (I32,)),
    ("aegis", "resp_write"): ((I32, I32), (I32,)),
    ("aegis", "log"): ((I32, I32, I32), (I32,)),
    ("aegis", "data_run"): ((I32, I32), (I32,)),
    ("aegis", "result_read"): ((I32, I32, I32), (I32,)),
    ("aegis", "handle_drop"): ((I32,), ()),
}
F14_TEST_IMPORT = {("env", "host_fault"): ((I32,), ())}


def sections(wasm):
    if wasm[:8] != WASM_MAGIC:
        raise ValueError("not a wasm core module (magic/version)")
    r = Reader(wasm)
    r.i = 8
    out = []
    while r.i < len(r.b):
        sid = r.take(1)[0]
        size = r.varint(5)
        out.append((sid, r.take(size)))
    return out


def _types(secs):
    for sid, p in secs:
        if sid == 1:
            r = Reader(p)
            ts = []
            for _ in range(r.varint()):
                if r.take(1) != b"\x60":
                    raise ValueError("type is not a func type")
                params = tuple(r.take(r.varint()))
                results = tuple(r.take(r.varint()))
                ts.append((params, results))
            r.end()
            return ts
    return []


def imports(wasm):
    """[(module, name, kind, desc)]; desc = func type (params, results) for kind 0."""
    secs = sections(wasm)
    ts = _types(secs)
    out = []
    for sid, p in secs:
        if sid == 2:
            r = Reader(p)
            for _ in range(r.varint()):
                m, n = r.tstr(), r.tstr()
                kind = r.take(1)[0]
                if kind == 0:
                    desc = ts[r.varint()]
                else:
                    desc = None  # table/memory/global: never allowed by F14, contents irrelevant
                    return out + [(m, n, kind, None)]
                out.append((m, n, kind, desc))
            r.end()
    return out


def func_import_count(secs):
    n = 0
    for sid, p in secs:
        if sid == 2:
            r = Reader(p)
            for _ in range(r.varint()):
                r.tstr()
                r.tstr()
                if r.take(1)[0] != 0:
                    raise ValueError("non-function import")
                r.varint()
                n += 1
    return n


def exports(wasm):
    out = []
    for sid, p in sections(wasm):
        if sid == 7:
            r = Reader(p)
            for _ in range(r.varint()):
                n = r.tstr()
                kind = r.take(1)[0]
                out.append((n, kind, r.varint()))
            r.end()
    return out


def func_type(wasm, fidx):
    secs = sections(wasm)
    ts = _types(secs)
    ni = func_import_count(secs)
    if fidx < ni:
        raise ValueError("export of an imported function")
    for sid, p in secs:
        if sid == 3:
            r = Reader(p)
            idx = [r.varint() for _ in range(r.varint())]
            return ts[idx[fidx - ni]]
    raise ValueError("no function section")


def select_handle(wasm, export_name):
    """Rewrite the export section to exactly [memory, handle], where handle = the function exported as export_name.
    Every other section is copied byte for byte."""
    ex = {n: (k, i) for n, k, i in exports(wasm)}
    if "memory" not in ex or ex["memory"][0] != 2:
        raise ValueError("no memory export")
    if export_name not in ex or ex[export_name][0] != 0:
        raise ValueError(f"no function export {export_name}")
    body = uvarint(2) + enc_tstr("memory") + b"\x02" + uvarint(ex["memory"][1]) + \
        enc_tstr("handle") + b"\x00" + uvarint(ex[export_name][1])
    out = bytearray(WASM_MAGIC)
    for sid, p in sections(wasm):
        if sid == 7:
            p = body
        out += bytes([sid]) + uvarint(len(p)) + p
    return bytes(out)


def check_f14(wasm, allow_test_import=False):
    """Raise ValueError unless the module has exactly the F14 exports and only allowlisted imports (exact types)."""
    allow = dict(F14_IMPORTS)
    if allow_test_import:
        allow.update(F14_TEST_IMPORT)
    for m, n, kind, desc in imports(wasm):
        if kind != 0 or (m, n) not in allow or allow[(m, n)] != desc:
            raise ValueError(f"import {m}.{n} (kind {kind}, type {desc}) is not in the F14 allowlist")
    ex = exports(wasm)
    names = sorted(n for n, _, _ in ex)
    if names != ["handle", "memory"]:
        raise ValueError(f"exports {names} != [handle, memory]")
    fidx = [i for n, k, i in ex if n == "handle"][0]
    if func_type(wasm, fidx) != ((), (I32,)):
        raise ValueError("handle is not () -> i32")
    return True


def stub_module(kind):
    """A minimal valid core module carrying only a custom section `aegis-e2e-ref` = kind. Used with the reference
    (mock) worker, which reads the kind instead of executing Wasm; a real worker would refuse it (no exports)."""
    name = enc_tstr("aegis-e2e-ref")
    payload = name + kind.encode()
    return WASM_MAGIC + b"\x00" + uvarint(len(payload)) + payload


def stub_kind(wasm):
    for sid, p in sections(wasm):
        if sid == 0:
            r = Reader(p)
            if r.tstr() == "aegis-e2e-ref":
                return r.b[r.i:].decode()
    return None
