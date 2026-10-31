"""Minimal WebAssembly binary encoder (core spec 1.0 + bulk/reference-types table.grow), stdlib only.

The hostile corpus is built from this so every module is readable Python next to its case, with no wat parser
and no build toolchain. Only what the corpus needs is supported: function types, function/memory/table/global
imports, functions with i32 locals, one memory, one table, exports, data segments, an optional start function.
"""

I32, I64 = 0x7F, 0x7E
FUNCREF = 0x70


def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if (n == 0 and not b & 0x40) or (n == -1 and b & 0x40):
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def vec(items):
    return uleb(len(items)) + b"".join(items)


def name(s):
    b = s.encode()
    return uleb(len(b)) + b


# ------------------------------------------------------------------------------------------------ instructions
class I:
    """Instruction helpers returning bytes. Compose function bodies as lists (flattened by Module.func)."""
    unreachable = b"\x00"
    nop = b"\x01"
    end = b"\x0b"
    ret = b"\x0f"
    drop = b"\x1a"
    i32_eqz = b"\x45"
    i32_eq = b"\x46"
    i32_ne = b"\x47"
    i32_lt_u = b"\x49"
    i32_gt_u = b"\x4b"
    i32_le_u = b"\x4d"
    i32_add = b"\x6a"
    i32_sub = b"\x6b"
    i32_mul = b"\x6c"
    i32_and = b"\x71"
    i32_or = b"\x72"
    i32_xor = b"\x73"
    i32_shl = b"\x74"
    i32_shr_u = b"\x76"
    memory_size = b"\x3f\x00"
    memory_grow = b"\x40\x00"
    ref_null_func = b"\xd0\x70"

    @staticmethod
    def i32(v):
        if v >= 1 << 31:
            v -= 1 << 32
        return b"\x41" + sleb(v)

    @staticmethod
    def call(f):
        return b"\x10" + uleb(f)

    @staticmethod
    def get(i):
        return b"\x20" + uleb(i)

    @staticmethod
    def set(i):
        return b"\x21" + uleb(i)

    @staticmethod
    def tee(i):
        return b"\x22" + uleb(i)

    @staticmethod
    def gget(i):
        return b"\x23" + uleb(i)

    @staticmethod
    def gset(i):
        return b"\x24" + uleb(i)

    @staticmethod
    def load(off=0):
        return b"\x28\x02" + uleb(off)

    @staticmethod
    def store(off=0):
        return b"\x36\x02" + uleb(off)

    @staticmethod
    def block():
        return b"\x02\x40"

    @staticmethod
    def loop():
        return b"\x03\x40"

    @staticmethod
    def if_():
        return b"\x04\x40"

    else_ = b"\x05"

    @staticmethod
    def br(d):
        return b"\x0c" + uleb(d)

    @staticmethod
    def br_if(d):
        return b"\x0d" + uleb(d)

    @staticmethod
    def table_grow(t=0):
        return b"\xfc\x0f" + uleb(t)


def flat(xs):
    out = bytearray()
    for x in xs:
        if isinstance(x, (bytes, bytearray)):
            out += x
        else:
            out += flat(x)
    return bytes(out)


# ------------------------------------------------------------------------------------------------ module
class Module:
    def __init__(self):
        self.types = []          # (params, results)
        self.imports = []        # bytes entries
        self.n_func_imports = 0
        self.funcs = []          # (type index, locals count, body bytes)
        self.memory = None       # (min, max|None)
        self.table = None        # (min, max|None)
        self.globals = []        # bytes entries
        self.exports = []        # bytes entries
        self.data = []           # (offset, bytes)
        self.start = None

    def type(self, params, results):
        t = (tuple(params), tuple(results))
        if t not in self.types:
            self.types.append(t)
        return self.types.index(t)

    def import_func(self, mod, nm, params, results):
        assert not self.funcs, "imports must precede functions"
        ti = self.type(params, results)
        self.imports.append(name(mod) + name(nm) + b"\x00" + uleb(ti))
        self.n_func_imports += 1
        return self.n_func_imports - 1

    def import_memory(self, mod, nm, mn, mx=None):
        lim = (b"\x00" + uleb(mn)) if mx is None else (b"\x01" + uleb(mn) + uleb(mx))
        self.imports.append(name(mod) + name(nm) + b"\x02" + lim)

    def import_global(self, mod, nm, vt=I32, mut=False):
        self.imports.append(name(mod) + name(nm) + b"\x03" + bytes([vt, 1 if mut else 0]))

    def import_table(self, mod, nm, mn):
        self.imports.append(name(mod) + name(nm) + b"\x01" + bytes([FUNCREF]) + b"\x00" + uleb(mn))

    def func(self, params, results, body, nlocals=0):
        ti = self.type(params, results)
        self.funcs.append((ti, nlocals, flat(body) + I.end))
        return self.n_func_imports + len(self.funcs) - 1

    def mem(self, mn, mx=None):
        self.memory = (mn, mx)

    def tab(self, mn, mx=None):
        self.table = (mn, mx)

    def glob(self, vt, mut, init_i32):
        self.globals.append(bytes([vt, 1 if mut else 0]) + I.i32(init_i32) + I.end)
        return len(self.globals) - 1

    def export_func(self, nm, idx):
        self.exports.append(name(nm) + b"\x00" + uleb(idx))

    def export_memory(self, nm="memory"):
        self.exports.append(name(nm) + b"\x02" + uleb(0))

    def export_global(self, nm, idx):
        self.exports.append(name(nm) + b"\x03" + uleb(idx))

    def put(self, offset, data):
        self.data.append((offset, bytes(data)))
        return offset

    def encode(self):
        def sec(i, payload):
            return bytes([i]) + uleb(len(payload)) + payload

        def limits(l):
            mn, mx = l
            return (b"\x00" + uleb(mn)) if mx is None else (b"\x01" + uleb(mn) + uleb(mx))

        out = b"\x00asm\x01\x00\x00\x00"
        out += sec(1, vec([b"\x60" + vec([bytes([p]) for p in ps]) + vec([bytes([r]) for r in rs])
                           for ps, rs in self.types]))
        if self.imports:
            out += sec(2, vec(self.imports))
        if self.funcs:
            out += sec(3, vec([uleb(t) for t, _, _ in self.funcs]))
        if self.table:
            out += sec(4, vec([bytes([FUNCREF]) + limits(self.table)]))
        if self.memory:
            out += sec(5, vec([limits(self.memory)]))
        if self.globals:
            out += sec(6, vec(self.globals))
        if self.exports:
            out += sec(7, vec(self.exports))
        if self.start is not None:
            out += sec(8, uleb(self.start))
        if self.funcs:
            bodies = []
            for _, nl, body in self.funcs:
                loc = vec([uleb(nl) + bytes([I32])]) if nl else vec([])
                b = loc + body
                bodies.append(uleb(len(b)) + b)
            out += sec(10, vec(bodies))
        if self.data:
            out += sec(11, vec([b"\x00" + I.i32(off) + I.end + uleb(len(d)) + d for off, d in self.data]))
        return out
