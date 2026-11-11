"""Hostile (and control) F14 guest modules, built with wasmgen. Each builder takes the case's `args` dict and
returns the module bytes. corpus/*.json names a builder per case; README.md describes every case.

Memory layout of every guest: constants from 1024, scratch buffer BUF at 65536, memory min 4 pages unless a case
says otherwise. Locals: 0 = handle, 1 = loop counter, 2 = length.
"""

import f14
from wasmgen import I, I32, Module

BUF = 65536
IMPORTS = [
    ("req_head", [I32, I32], [I32]),
    ("req_body_read", [I32, I32], [I32]),
    ("resp_head", [I32, I32, I32], [I32]),
    ("resp_write", [I32, I32], [I32]),
    ("log", [I32, I32, I32], [I32]),
    ("data_run", [I32, I32], [I32]),
    ("result_read", [I32, I32, I32], [I32]),
    ("handle_drop", [I32], []),
]


def hexb(s):
    return bytes.fromhex(s) if s else b""


def enc_value(v):
    """corpus JSON value: str, or {"hex": "..."} for raw bytes."""
    if isinstance(v, dict):
        return hexb(v["hex"])
    return v.encode()


class G:
    """A guest under construction: all eight F14 imports, memory 0 exported, constants allocator."""

    def __init__(self, mem_pages=4, mem_max=None, imports=True, memory=True):
        self.m = Module()
        self.f = {}
        if imports:
            for nm, ps, rs in IMPORTS:
                self.f[nm] = self.m.import_func("monban", nm, ps, rs)
        if memory:
            self.m.mem(mem_pages, mem_max)
            self.m.export_memory()
        self.next = 1024

    def const(self, data):
        off = self.next
        self.m.put(off, data)
        self.next += (len(data) + 15) & ~15
        assert self.next < BUF, "constants overflow"
        return off, len(data)

    def call(self, nm, *args, keep=False):
        out = [I.i32(a) if isinstance(a, int) else a for a in args] + [I.call(self.f[nm])]
        if not keep and nm != "handle_drop":
            out.append(I.drop)
        return out

    def head(self, status=200, headers=(("x-mod", "1"),)):
        hp, hl = self.const(f14.resp_headers(list(headers)))
        return self.call("resp_head", status, hp, hl)

    def write(self, data):
        p, n = self.const(data)
        return self.call("resp_write", p, n)

    def respond(self, body=b"hello-from-module", status=200, headers=(("x-mod", "1"),)):
        return [self.head(status, headers), self.write(body)]

    def finish(self, body, nlocals=3, params=(), handle_name="handle", results=(I32,)):
        h = self.m.func(list(params), list(results), body, nlocals)
        self.m.export_func(handle_name, h)
        return self.m.encode()


def op_bytes(a):
    o = a.get("op", {})
    if "deep_not" in o:
        filt = ("eq", 1, "x")
        for _ in range(o["deep_not"]):
            filt = ("not", filt)
        return f14.op(o.get("tenant", 1), "notes", o.get("kind", "select"), filt, [], o.get("returning", [1]))
    return f14.op(o.get("tenant", 1), o.get("collection", "notes"), o.get("kind", "insert"),
                  tuple(o["filter"]) if "filter" in o else ("tt",),
                  [tuple(w) for w in o.get("writes", [[1, "row"], [2, "body"]])], o.get("returning", [1, 2]))


# ------------------------------------------------------------------------------------------------ controls / I7 / I5
def b_ok(a):
    g = G()
    return g.finish([g.respond(a.get("body", "hello-from-module").encode()), I.i32(0)])


def b_respond_then(a):
    """Writes a full response, then returns `code` (1 = Deny, other non-0 = Error)."""
    g = G()
    return g.finish([g.respond(a.get("body", "SECRET-MODULE-BODY").encode()), I.i32(a["code"])])


def b_respond_then_trap(a):
    g = G()
    body = a.get("body", "SECRET-PARTIAL").encode() * a.get("body_repeat", 1)
    return g.finish([g.respond(body), I.unreachable, I.i32(0)])


def b_trap(a):
    g = G()
    return g.finish([I.unreachable, I.i32(0)])


def b_loop(a):
    g = G()
    pre = g.respond(b"SECRET-LOOP") if a.get("respond_first") else []
    return g.finish([pre, I.loop(), I.br(0), I.end, I.i32(0)])


def b_header(a):
    """resp_head with the case's header list (values may be raw bytes via {"hex": ...}), then a body."""
    g = G()
    hs = [(enc_value(n), enc_value(v)) for n, v in a["headers"]]
    return g.finish([g.head(a.get("status", 200), hs), g.write(b"BAD-HEADER-BODY"), I.i32(0)])


def b_many_headers(a):
    g = G()
    hs = [(f"x-h{i}".encode(), b"v" * a.get("value_len", 8)) for i in range(a["n"])]
    return g.finish([g.head(200, hs), g.write(b"MANY-HEADERS-BODY"), I.i32(0)])


def b_double_head(a):
    g = G()
    return g.finish([g.head(200, [("x-first", "1")]), g.head(a.get("status2", 200), [("x-second", "SECOND-HEAD")]),
                     g.write(b"DOUBLE-HEAD-BODY"), I.i32(0)])


def b_big_write(a):
    """One resp_write call of n bytes (a compromised worker forwards it as one oversized frame)."""
    g = G(mem_pages=8)
    return g.finish([g.head(), g.call("resp_write", BUF, a["n"]), I.i32(0)])


# ------------------------------------------------------------------------------------------------ I1 imports/exports
def b_extra_import(a):
    """The eight F14 imports plus one more (function, memory, table or global)."""
    g = G()
    k = a.get("kind", "func")
    if k == "func":
        idx = g.m.import_func(a["module"], a["name"], a.get("params", []), a.get("results", []))
        g.f["extra"] = idx
    elif k == "global":
        g.m.import_global(a["module"], a["name"])
    elif k == "table":
        g.m.import_table(a["module"], a["name"], 1)
    body = [g.respond(b"EXTRA-IMPORT-INSTANTIATED")]
    if k == "func" and a.get("call"):
        body.append([I.i32(x) for x in a["call"]] + [I.call(g.f["extra"])])
        if a.get("results"):
            body.append(I.drop)
    return g.finish(body + [I.i32(0)])


def b_wrong_type_import(a):
    """An allowlisted name with another signature (replaces the right one)."""
    g = G(imports=False)
    for nm, ps, rs in IMPORTS:
        if nm == a["name"]:
            g.f[nm] = g.m.import_func("monban", nm, a["params"], a["results"])
        else:
            g.f[nm] = g.m.import_func("monban", nm, ps, rs)
    return g.finish([I.i32(0)])


def b_import_memory(a):
    g = G(memory=False)
    g.m.import_memory("monban", "memory", 1)
    g.m.export_memory()
    return g.finish([I.i32(0)])


def b_exports(a):
    v = a["variant"]
    if v == "no-memory":
        g = G(memory=False)
        return g.finish([I.i32(0)])
    g = G()
    if v == "no-handle":
        return g.finish([I.i32(0)], handle_name="run")
    if v == "extra-export":
        f = g.m.func([], [I32], [I.i32(0)])
        g.m.export_func("other", f)
        return g.finish([I.i32(0)])
    if v == "handle-type":
        return g.finish([I.i32(0)], params=(I32,))
    raise ValueError(v)


# ------------------------------------------------------------------------------------------------ I1 handles
def b_handle(a):
    """data_run, then exercise the handle per `action`."""
    g = G()
    op_p, op_n = g.const(op_bytes(a))
    act = a["action"]
    dr = g.call("data_run", op_p, op_n, keep=True) + [I.set(0)]
    if act == "valid":
        body = [dr, g.call("result_read", I.get(0), BUF, 4096, keep=True), I.set(2), g.call("handle_drop", I.get(0)),
                g.head(), g.call("resp_write", BUF, I.get(2)), I.i32(0)]
    elif act == "emit":
        body = [dr, I.i32(BUF), I.get(0), I.store(), g.head(), g.call("resp_write", BUF, 4), I.i32(0)]
    elif act in ("forged", "zero", "foreign"):
        h = {"forged": [I.get(0), I.i32(1), I.i32_add], "zero": [I.i32(0)],
             "foreign": [I.get(0), I.i32(0x10000), I.i32_xor]}[act]
        body = [dr, g.call("result_read", h, 0, 0), g.respond(f"{act.upper()}-HANDLE-READ".encode()), I.i32(0)]
    elif act == "dropped":
        body = [dr, g.call("handle_drop", I.get(0)), g.call("result_read", I.get(0), 0, 0),
                g.respond(b"DROPPED-HANDLE-READ"), I.i32(0)]
    elif act == "double-drop":
        body = [dr, g.call("handle_drop", I.get(0)), g.call("handle_drop", I.get(0)),
                g.respond(b"DOUBLE-DROP-OK"), I.i32(0)]
    else:
        raise ValueError(act)
    return g.finish(body)


def b_handle_present(a):
    """Empty request body: data_run and answer the handle (u32 LE), without dropping it. Otherwise: read a 4-byte
    handle from the body (one issued to an earlier request) and use it."""
    g = G()
    op_p, op_n = g.const(op_bytes(a))
    emit = [g.call("data_run", op_p, op_n, keep=True), I.set(0), I.i32(BUF), I.get(0), I.store(), g.head(),
            g.call("resp_write", BUF, 4)]
    present = [g.call("result_read", I.i32(BUF), I.load(), 0, 0), g.respond(b"STALE-HANDLE-READ")]
    return g.finish([g.call("req_body_read", BUF, 4, keep=True), I.i32_eqz, I.if_(), emit, I.else_, present, I.end,
                     I.i32(0)])


def b_data_run(a):
    """data_run with the case's op, then respond with the raw F10 result bytes (or trap / deny after it)."""
    g = G()
    op_p, op_n = g.const(hexb(a["op_hex"]) if "op_hex" in a else op_bytes(a))
    then = a.get("then", "respond")
    body = [g.call("data_run", op_p, op_n, keep=True), I.set(0)]
    if then == "trap":
        return g.finish(body + [I.unreachable, I.i32(0)])
    body += [g.call("result_read", I.get(0), BUF, 32768, keep=True), I.set(2), g.head(),
             g.call("resp_write", BUF, I.get(2))]
    return g.finish(body + [I.i32(0)])


# ------------------------------------------------------------------------------------------------ I2
def b_mem_bomb(a):
    """Grows memory one page at a time until refused or `stop_pages`; answers the final page count (u32 LE)."""
    g = G(mem_pages=2)
    stop = a.get("stop_pages", 1024)
    body = [I.block(), I.loop(),
            I.i32(1), I.memory_grow, I.i32(-1), I.i32_eq, I.br_if(1),
            I.memory_size, I.i32(stop), I.i32_lt_u, I.br_if(0),
            I.end, I.end,
            I.i32(BUF), I.memory_size, I.store(), g.head(), g.call("resp_write", BUF, 4), I.i32(0)]
    return g.finish(body)


def b_mem_initial(a):
    g = G(mem_pages=a["pages"])
    return g.finish([g.respond(b"BIG-MEMORY-INSTANTIATED"), I.i32(0)])


def b_table_bomb(a):
    g = G()
    g.m.tab(1)
    return g.finish([I.ref_null_func, I.i32(a["n"]), I.table_grow(0), I.i32(-1), I.i32_eq, I.if_(), I.unreachable,
                     I.end, g.respond(b"TABLE-GROWN"), I.i32(0)])


def b_recursion(a):
    g = G()
    # function index of the recursive helper = imports + 0 (defined first)
    f = g.m.n_func_imports
    g.m.func([], [], [I.call(f)])
    return g.finish([I.call(f), I.i32(0)])


def b_hostcall_flood(a):
    g = G()
    n = a["n"]
    return g.finish([I.block(), I.loop(), g.call("req_head", 0, 0),
                     I.get(1), I.i32(1), I.i32_add, I.tee(1), I.i32(n), I.i32_lt_u, I.br_if(0), I.end, I.end,
                     g.respond(b"HOSTCALL-FLOOD-DONE"), I.i32(0)])


def b_datarun_flood(a):
    g = G()
    op_p, op_n = g.const(op_bytes(a))
    n = a["n"]
    return g.finish([I.block(), I.loop(), g.call("data_run", op_p, op_n),
                     I.get(1), I.i32(1), I.i32_add, I.tee(1), I.i32(n), I.i32_lt_u, I.br_if(0), I.end, I.end,
                     g.respond(b"DATARUN-FLOOD-DONE"), I.i32(0)])


def b_write_flood(a):
    """resp_write (or log) `chunk` bytes `n` times."""
    g = G(mem_pages=4)
    n, c = a["n"], a["chunk"]
    if a.get("what", "resp") == "resp":
        pre, call = g.head(), g.call("resp_write", BUF, c)
    else:
        pre, call = [], g.call("log", 2, BUF, c)
    return g.finish([pre, I.block(), I.loop(), call,
                     I.get(1), I.i32(1), I.i32_add, I.tee(1), I.i32(n), I.i32_lt_u, I.br_if(0), I.end, I.end,
                     g.respond(b"WRITE-FLOOD-DONE") if a.get("what") == "log" else [], I.i32(0)])


def b_fuel_burn(a):
    g = G()
    n = a["n"]
    return g.finish([I.block(), I.loop(),
                     I.get(1), I.i32(1), I.i32_add, I.tee(1), I.i32(n), I.i32_lt_u, I.br_if(0), I.end, I.end,
                     g.respond(b"FUEL-BURN-DONE"), I.i32(0)])


def b_ptr_oob(a):
    g = G()
    return g.finish([g.head(), g.call("resp_write", 0x7FFFFF00, 4096), g.write(b"OOB-OK"), I.i32(0)])


def b_log_level(a):
    g = G()
    p, n = g.const(b"log")
    return g.finish([g.call("log", a["level"], p, n), g.respond(b"BAD-LEVEL-OK"), I.i32(0)])


BUILDERS = {k[2:].replace("_", "-"): v for k, v in globals().items() if k.startswith("b_")}


def build(builder, args):
    return BUILDERS[builder](args or {})
