#!/usr/bin/env python3
"""lowir.py -- shared reference model for the AEGIS lowering oracles (stdlib only, run with python3 -I).

This file is copied byte-identically into oracles/lowering-read/ and oracles/lowering-write/ (each oracle dir is
self-contained); both READMEs record its sha256.

Contents
  1. IR (Pred) exactly as spec/AegisIR/Lowering.lean: tt ff eq in range pfx and or not, plus andN/orN which
     desugar as Pred.andN [] = tt, Pred.orN [] = ff.  Values are int | str (Lean `Value`), nothing else.
  2. eval (two-valued policy semantics; absent/NULL field => atom false), lower, lowerQ, sql3 (Kleene 3VL,
     NULL column => UNKNOWN), keeps, refQ -- line-for-line ports of the Lean definitions.
  3. The reference renderer (the "subject" until aegis-data-ir / aegis-adapter-* exist): SQLite and Postgres
     dialects for read filters (lowerQ) and write statements (UPDATE / DELETE / composite-arbiter UPSERT), and a
     Redis/Valkey key-namespace renderer.  Mutants (deliberately broken renderers) for the self-tests.
  4. The line-oriented JSON subject protocol (see README.md) -- `python3 -I lowir.py serve [--mutant M ...]`
     runs the reference renderer as an out-of-process subject.
  5. Engine access without third-party drivers: sqlite3 (stdlib), a minimal PostgreSQL v3 wire client (trust /
     cleartext / md5 / SCRAM-SHA-256; extended protocol with text parameters) and a RESP2 client.
  6. A line-for-line port of stringmatchlen_impl (redis 8.10.2 src/util.c; same algorithm in valkey 9.1.2),
     reviewed from research/state/raw/round-003/01-work/oracle.py.
"""
import base64, hashlib, hmac, json, os, shlex, socket, struct, subprocess, sys, urllib.parse

INT64_MIN, INT64_MAX = -(2 ** 63), 2 ** 63 - 1

# =========================================================================================== 1. IR + values
def is_val(v):
    return type(v) is int or type(v) is str

def check_value(v):
    if not is_val(v):
        raise ValueError(f"IR value must be int or str (Lean Value), got {type(v).__name__}")
    return v

def validate(p, fields):
    """Raise ValueError unless p is a well-formed Pred over `fields`."""
    if not isinstance(p, list) or not p or not isinstance(p[0], str):
        raise ValueError(f"malformed pred {p!r}")
    k, n = p[0], len(p)
    def fld(f):
        if f not in fields:
            raise ValueError(f"unknown field {f!r}")
    if k in ("tt", "ff"):
        if n != 1: raise ValueError(k)
    elif k == "eq":
        if n != 3: raise ValueError(k)
        fld(p[1]); check_value(p[2])
    elif k == "in":
        if n != 3 or not isinstance(p[2], list): raise ValueError(k)
        fld(p[1]); [check_value(v) for v in p[2]]
    elif k == "range":
        if n != 4: raise ValueError(k)
        fld(p[1]); check_value(p[2]); check_value(p[3])
    elif k == "pfx":
        if n != 3 or type(p[2]) is not str: raise ValueError(k)
        fld(p[1])
    elif k in ("and", "or"):
        if n != 3: raise ValueError(k)
        validate(p[1], fields); validate(p[2], fields)
    elif k == "not":
        if n != 2: raise ValueError(k)
        validate(p[1], fields)
    elif k in ("andN", "orN"):
        if n != 2 or not isinstance(p[1], list): raise ValueError(k)
        for q in p[1]: validate(q, fields)
    else:
        raise ValueError(f"unknown pred constructor {k!r}")
    return p

def desugar_n(p):
    """Pred.andN / Pred.orN exactly as Lean: [] => tt/ff ; p :: ps => and/or p (andN/orN ps)."""
    k, ps = p[0], p[1]
    if not ps:
        return ["tt"] if k == "andN" else ["ff"]
    return ["and" if k == "andN" else "or", ps[0], [k, ps[1:]]]

def veq(x, v):          # decide (x = v) on Lean Value; a stored non-Value (REAL/BLOB) equals nothing
    return type(x) is type(v) and is_val(x) and x == v

def ref_le(a, b):       # refLe: same storage class only; ints numerically, strings by code point list
    if type(a) is int and type(b) is int: return a <= b
    if type(a) is str and type(b) is str: return a <= b       # Python str order == code-point lexicographic
    return False

def ref_range(lo, hi, x): return ref_le(lo, x) and ref_le(x, hi)

def ref_prefix(s, x): return type(x) is str and x.startswith(s)

def ev(row, p):
    """Lean `eval`: two-valued, absent (None) field => atom false."""
    k = p[0]
    if k == "tt": return True
    if k == "ff": return False
    if k == "eq":
        x = row.get(p[1]); return x is not None and veq(x, p[2])
    if k == "in":
        x = row.get(p[1]); return x is not None and any(veq(x, v) for v in p[2])
    if k == "range":
        x = row.get(p[1]); return x is not None and ref_range(p[2], p[3], x)
    if k == "pfx":
        x = row.get(p[1]); return x is not None and ref_prefix(p[2], x)
    if k == "and": return ev(row, p[1]) and ev(row, p[2])
    if k == "or": return ev(row, p[1]) or ev(row, p[2])
    if k == "not": return not ev(row, p[1])
    if k in ("andN", "orN"): return ev(row, desugar_n(p))
    raise ValueError(k)

def refQ(tf, t, row, p):
    return ev(row, ["and", ["eq", tf, t], p])

# ---- Lean SqlExpr / lower / sql3
def lower(p):
    k = p[0]
    if k == "tt": return ("lit", True)
    if k == "ff": return ("lit", False)
    if k == "eq": return ("cmpEq", p[1], p[2])
    if k == "in": return ("inList", p[1], list(p[2]))
    if k == "range": return ("between", p[1], p[2], p[3])
    if k == "pfx": return ("pfx", p[1], p[2])
    if k in ("and", "or"): return (k, lower(p[1]), lower(p[2]))
    if k == "not": return ("not", lower(p[1]))
    if k in ("andN", "orN"): return lower(desugar_n(p))
    raise ValueError(k)

def lowerQ(tf, t, p):
    return ("and", ("cmpEq", tf, t), lower(p))

def k3and(a, b):
    if a is False or b is False: return False
    if a is True and b is True: return True
    return None

def k3or(a, b):
    if a is True or b is True: return True
    if a is False and b is False: return False
    return None

def k3not(a):
    return None if a is None else (not a)

class Backend:
    def __init__(self, beq, brange, bpfx): self.beq, self.brange, self.bpfx = beq, brange, bpfx

EXACT = Backend(veq, ref_range, ref_prefix)   # the Backend.Exact instance the reference renderer claims

def any_eq(B, x, vs):
    return any(B.beq(x, v) for v in vs)

def sql3(B, row, e):
    k = e[0]
    if k == "lit": return e[1]
    if k == "cmpEq":
        x = row.get(e[1]); return None if x is None else B.beq(x, e[2])
    if k == "inList":
        x = row.get(e[1]); return None if x is None else any_eq(B, x, e[2])
    if k == "between":
        x = row.get(e[1]); return None if x is None else B.brange(e[2], e[3], x)
    if k == "pfx":
        x = row.get(e[1]); return None if x is None else B.bpfx(e[2], x)
    if k == "and": return k3and(sql3(B, row, e[1]), sql3(B, row, e[2]))
    if k == "or": return k3or(sql3(B, row, e[1]), sql3(B, row, e[2]))
    if k == "not": return k3not(sql3(B, row, e[1]))
    raise ValueError(k)

def keeps(B, row, e):
    return sql3(B, row, e) is True

# =========================================================================================== 3. reference renderer
MUTANTS = {
    # read / shared
    "drop-tenant":        "lowerQ omits the mandatory tenant conjunct",
    "two-valued-not":     "atoms are FALSE (not UNKNOWN) on NULL/absent fields (research StrictTyped form), so NOT widens",
    "or-precedence":      "and/or rendered without parentheses (tenant AND a OR b)",
    "like-prefix":        "prefix rendered as col LIKE s||'%' without escaping %/_ (and LIKE is ASCII-case-insensitive)",
    "empty-or-true":      "orN [] rendered TRUE (SQLAlchemy or_() / go-sqlbuilder family)",
    "naive-bound":        "research NaiveBound: bound params, plain =, LIKE prefix, empty junction TRUE, no type/collation guard",
    "no-collate-binary":  "typeof guard + unary + but no COLLATE BINARY (NOCASE column collation survives unary +)",
    "no-affinity-guard":  "no typeof guard / unary + (bound param gets column affinity)",
    "range-exclusive":    "range rendered with < and > (incompleteness; must show up as MISS)",
    "nul-prefix":         "research hardened prefix substr(+col,1,n)=? (stops at NUL: MISS, not leak)",
    "selfjoin-alias":     "tenant conjunct always qualified with alias a (other alias of a self-join unconstrained)",
    "pg-no-collate-c":    "Postgres text comparisons under the column collation instead of COLLATE \"C\"",
    "refuse-all":         "refuses every request (fail-closed; must show up as MISS / effect violation)",
    # write
    "upsert-global-arbiter": "upsert ON CONFLICT (id) DO UPDATE without tenant in arbiter or guard",
    "replace-into":       "upsert rendered as INSERT OR REPLACE (REPLACE family: implicit delete of the conflicting row)",
    "returning-star":     "RETURNING * (wider than the permitted projection; includes secret column)",
    "set-tenant-passthrough": "UPDATE SET list passes a tenant assignment through",
    "upsert-tenant-from-row": "upsert takes the tenant value from the request row instead of the host handle",
    # kv
    "kv-naive":           "Redis key t:<raw tenant>:<suffix>, MATCH t:<raw tenant>:*",
    "kv-escaped-colon":   "Redis key t:<raw tenant>:<suffix>, MATCH t:<glob-escaped tenant>:*",
}

def qi(name):
    return '"' + str(name).replace('"', '""') + '"'

SQLITE_TYPEOF = {int: "integer", str: "text"}

def col_class(decl):
    """Declared column type -> IR storage class for typed dialects (Postgres); None = untyped (SQLite)."""
    d = (decl or "").lower()
    if any(w in d for w in ("int",)): return int
    if any(w in d for w in ("text", "char", "citext", "clob")): return str
    return None

class Renderer:
    def __init__(self, mutants=()):
        bad = set(mutants) - set(MUTANTS)
        if bad: raise ValueError(f"unknown mutants {sorted(bad)}")
        self.m = set(mutants)

    # ------------------------------------------------------------------ protocol entry
    def handle(self, req):
        if "refuse-all" in self.m:
            return {"refuse": "mutant refuse-all"}
        op = req.get("op")
        if op == "hello":
            return {"name": "aegis-reference-renderer(lowir.py)", "mutants": sorted(self.m), "protocol": 1}
        if op == "read":
            return self.read(req)
        if op in ("update", "delete", "upsert"):
            return self.write(req)
        if op in ("kv_key", "kv_set", "kv_del", "kv_get", "kv_scan"):
            return self.kv(req)
        raise ValueError(f"unknown op {op!r}")

    # ------------------------------------------------------------------ SQL helpers
    class Ctx:
        def __init__(self, req):
            self.dialect = req.get("dialect", "sqlite")
            if self.dialect not in ("sqlite", "postgres"): raise ValueError("dialect")
            self.alias = req.get("alias")
            self.offset = int(req.get("param_offset", 0))
            self.columns = req.get("columns") or {}
            self.params = []
        def ph(self, v):
            self.params.append(v)
            return "?" if self.dialect == "sqlite" else f"${self.offset + len(self.params)}"
        def col(self, f, alias=None):
            a = self.alias if alias is None else alias
            return (qi(a) + "." if a else "") + qi(f)

    def atom(self, c, test, ctx):
        """Lean sql3: a NULL column makes every comparison UNKNOWN (k3 none), otherwise the exact boolean."""
        if "two-valued-not" in self.m or "naive-bound" in self.m:
            return test
        return f"(CASE WHEN {c} IS NULL THEN NULL ELSE {test} END)"

    def _int_ok(self, v): return INT64_MIN <= v <= INT64_MAX

    def eq_test(self, f, v, ctx, alias=None):
        c = ctx.col(f, alias)
        m = self.m
        if ctx.dialect == "sqlite":
            if "naive-bound" in m: return f"{c} = {ctx.ph(v)}"
            if type(v) is int and not self._int_ok(v): return "0"
            if "no-affinity-guard" in m:
                return f"({c} = {ctx.ph(v)}" + (" COLLATE BINARY)" if type(v) is str else ")")
            coll = "" if ("no-collate-binary" in m or type(v) is int) else " COLLATE BINARY"
            return f"(typeof({c}) = '{SQLITE_TYPEOF[type(v)]}' AND +{c} = {ctx.ph(v)}{coll})"
        # postgres: typed columns; class mismatch can never be equal
        cc = col_class(ctx.columns.get(f))
        if "naive-bound" in m: return f"{c} = {ctx.ph(v if type(v) is str else str(v))}"
        if cc is not type(v): return "false"
        if type(v) is int:
            return "false" if not self._int_ok(v) else f"({c} = {ctx.ph(v)}::bigint)"
        if "pg-no-collate-c" in m: return f"({c}::text = {ctx.ph(v)}::text)"
        return f"({c}::text = {ctx.ph(v)}::text COLLATE \"C\")"

    def range_test(self, f, lo, hi, ctx):
        c = ctx.col(f)
        m = self.m
        lt, gt = ("<", ">") if "range-exclusive" in m else ("<=", ">=")
        if ctx.dialect == "sqlite":
            if "naive-bound" in m: return f"({c} >= {ctx.ph(lo)} AND {c} <= {ctx.ph(hi)})"
            if type(lo) is not type(hi): return "0"
            if type(lo) is int:
                if lo > INT64_MAX or hi < INT64_MIN: return "0"
                lo, hi = max(lo, INT64_MIN), min(hi, INT64_MAX)
            if "no-affinity-guard" in m:
                coll = " COLLATE BINARY" if type(lo) is str else ""
                return f"({c} {gt} {ctx.ph(lo)}{coll} AND {c} {lt} {ctx.ph(hi)}{coll})"
            coll = "" if ("no-collate-binary" in m or type(lo) is int) else " COLLATE BINARY"
            return (f"(typeof({c}) = '{SQLITE_TYPEOF[type(lo)]}' AND +{c} {gt} {ctx.ph(lo)}{coll} "
                    f"AND +{c} {lt} {ctx.ph(hi)}{coll})")
        cc = col_class(ctx.columns.get(f))
        if "naive-bound" in m:
            return f"({c} >= {ctx.ph(str(lo))} AND {c} <= {ctx.ph(str(hi))})"
        if type(lo) is not type(hi) or cc is not type(lo): return "false"
        if type(lo) is int:
            if lo > INT64_MAX or hi < INT64_MIN: return "false"
            lo, hi = max(lo, INT64_MIN), min(hi, INT64_MAX)
            return f"({c} {gt} {ctx.ph(lo)}::bigint AND {c} {lt} {ctx.ph(hi)}::bigint)"
        coll = "" if "pg-no-collate-c" in m else ' COLLATE "C"'
        return f"({c}::text {gt} {ctx.ph(lo)}::text{coll} AND {c}::text {lt} {ctx.ph(hi)}::text{coll})"

    def pfx_test(self, f, s, ctx):
        c = ctx.col(f)
        m = self.m
        like = "naive-bound" in m or "like-prefix" in m
        if ctx.dialect == "sqlite":
            if like:
                t = f"{c} LIKE {ctx.ph(s + '%')}"
                return t if "naive-bound" in m else f"(typeof({c}) = 'text' AND {t})"
            if "nul-prefix" in m:
                return f"(typeof({c}) = 'text' AND substr(+{c},1,{ctx.ph(len(s))}) = {ctx.ph(s)} COLLATE BINARY)"
            # UTF-8 is prefix-free, so a byte prefix of the encoding == a code-point prefix (refPrefix); BLOB
            # substr counts bytes and does not stop at NUL (text substr does: see README divergence D4).
            n = len(s.encode("utf-8"))
            # SQLite returns NULL (not x'') for substr/CAST of a zero-length BLOB, hence the COALESCEs (D5).
            return (f"(typeof({c}) = 'text' AND coalesce(substr(CAST(+{c} AS BLOB),1,{ctx.ph(n)}), x'') = "
                    f"coalesce(CAST({ctx.ph(s)} AS BLOB), x''))")
        cc = col_class(ctx.columns.get(f))
        if like:
            return f"({c}::text LIKE {ctx.ph(s + '%')})"
        if cc is not str: return "false"
        coll = "" if "pg-no-collate-c" in m else ' COLLATE "C"'
        return f"(left({c}::text, {ctx.ph(len(s))}::int) = {ctx.ph(s)}::text{coll})"

    def tt(self, ctx): return "(1=1)" if ctx.dialect == "sqlite" else "true"
    def ff(self, ctx): return "(1=0)" if ctx.dialect == "sqlite" else "false"

    def render(self, p, ctx):
        k = p[0]
        bare = "or-precedence" in self.m
        if k == "tt": return self.tt(ctx)
        if k == "ff": return self.ff(ctx)
        if k == "eq":
            return self.atom(ctx.col(p[1]), self.eq_test(p[1], p[2], ctx), ctx)
        if k == "in":
            if not p[2]:
                return self.atom(ctx.col(p[1]), self.ff(ctx), ctx)   # Lean: inList f [] => (r f).map (fun _ => false)
            tests = [self.eq_test(p[1], v, ctx) for v in p[2]]
            return self.atom(ctx.col(p[1]), "(" + " OR ".join(tests) + ")", ctx)
        if k == "range":
            return self.atom(ctx.col(p[1]), self.range_test(p[1], p[2], p[3], ctx), ctx)
        if k == "pfx":
            return self.atom(ctx.col(p[1]), self.pfx_test(p[1], p[2], ctx), ctx)
        if k in ("and", "or"):
            a, b = self.render(p[1], ctx), self.render(p[2], ctx)
            j = " AND " if k == "and" else " OR "
            return f"{a}{j}{b}" if bare else f"({a}{j}{b})"
        if k == "not":
            return f"(NOT {self.render(p[1], ctx)})"
        if k in ("andN", "orN"):
            if not p[1]:
                if k == "orN" and ("empty-or-true" in self.m or "naive-bound" in self.m): return self.tt(ctx)
                if k == "andN": return self.tt(ctx)
                return self.ff(ctx)
            parts = [self.render(q, ctx) for q in p[1]]
            j = " AND " if k == "andN" else " OR "
            return j.join(parts) if bare else "(" + j.join(parts) + ")"
        raise ValueError(k)

    def where(self, req, ctx):
        tf = req["tenant_field"]
        t = check_value(req["tenant"])
        fields = set(req.get("columns") or {}) or None
        p = req["pred"]
        validate(p, fields if fields else _AnyFields())
        if "drop-tenant" in self.m:
            return self.render(p, ctx)
        talias = "a" if ("selfjoin-alias" in self.m and ctx.alias) else None
        tc = ctx.col(tf, talias)
        tatom = self.atom(tc, self.eq_test(tf, t, ctx, talias), ctx)
        body = self.render(p, ctx)
        return f"{tatom} AND {body}" if "or-precedence" in self.m else f"({tatom} AND {body})"

    def read(self, req):
        ctx = self.Ctx(req)
        sql = self.where(req, ctx)
        return {"sql": sql, "params": ctx.params}

    # ------------------------------------------------------------------ writes
    def write(self, req):
        op = req["op"]
        ctx = self.Ctx(req)
        ctx.alias = None
        table, tf = req["table"], req["tenant_field"]
        cols = req.get("columns") or {}
        t = check_value(req["tenant"])
        key = list(req.get("key") or [])
        ret = list(req.get("returning") or [])
        for c in ret:
            if c not in cols: raise ValueError(f"returning unknown column {c!r}")
        retsql = ""
        if "returning-star" in self.m:
            retsql = " RETURNING *"
        elif ret:
            retsql = " RETURNING " + ", ".join(qi(c) for c in ret)
        if op in ("update", "delete"):
            sets = req.get("set") or {}
            if op == "update":
                if not sets: raise ValueError("empty SET")
                for c, v in sets.items():
                    if c not in cols: raise ValueError(f"unknown column {c!r}")
                    if (c == tf or c in key) and "set-tenant-passthrough" not in self.m:
                        raise ValueError(f"refused: SET of tenant/key column {c!r}")
                    check_value(v)
            setsql = ", ".join(f"{qi(c)} = {ctx.ph(v)}" for c, v in sets.items()) if op == "update" else ""
            w = self.where(req, ctx)
            if op == "update":
                return {"sql": f"UPDATE {qi(table)} SET {setsql} WHERE {w}{retsql}", "params": ctx.params}
            return {"sql": f"DELETE FROM {qi(table)} WHERE {w}{retsql}", "params": ctx.params}
        # upsert
        row = dict(req.get("row") or {})
        upd = list(req.get("update") or [])
        for c in list(row) + upd:
            if c not in cols: raise ValueError(f"unknown column {c!r}")
        if tf in row and "upsert-tenant-from-row" not in self.m:
            raise ValueError("refused: request row carries the tenant column (tenant comes from the host handle)")
        for c in upd:
            if c == tf or c in key: raise ValueError(f"refused: DO UPDATE of tenant/key column {c!r}")
        for v in row.values(): check_value(v)
        vals = dict(row)
        if "upsert-tenant-from-row" not in self.m or tf not in vals:
            vals[tf] = t
        names = [tf] + [c for c in vals if c != tf]
        ph = ", ".join(ctx.ph(vals[c]) for c in names)
        ins = f"INSERT INTO {qi(table)} ({', '.join(qi(c) for c in names)}) VALUES ({ph})"
        if "replace-into" in self.m:
            if ctx.dialect != "sqlite": raise ValueError("REPLACE is SQLite/MySQL only")
            return {"sql": "INSERT OR REPLACE" + ins[len("INSERT"):] + retsql, "params": ctx.params}
        if "upsert-global-arbiter" in self.m:
            arb = [c for c in key if c != tf] or ["id"]
            sets = ", ".join(f"{qi(c)} = excluded.{qi(c)}" for c in upd) or f"{qi(arb[0])} = excluded.{qi(arb[0])}"
            return {"sql": f"{ins} ON CONFLICT ({', '.join(qi(c) for c in arb)}) DO UPDATE SET {sets}{retsql}",
                    "params": ctx.params}
        # hardened: composite arbiter (tenant, key...) + tenant guard without user expressions (W3)
        if tf not in key:
            raise ValueError("refused: upsert arbiter must include the tenant column (composite key required)")
        for c in key:
            if c != tf and c not in row: raise ValueError(f"upsert row lacks key column {c!r}")
        arb = ", ".join(qi(c) for c in key)
        coll = " COLLATE BINARY" if ctx.dialect == "sqlite" else ' COLLATE "C"'
        guard = f" WHERE {qi(table)}.{qi(tf)} = excluded.{qi(tf)}" + (coll if type(t) is str else "")
        if upd:
            action = "DO UPDATE SET " + ", ".join(f"{qi(c)} = excluded.{qi(c)}" for c in upd) + guard
        else:
            action = "DO NOTHING"
        return {"sql": f"{ins} ON CONFLICT ({arb}) {action}{retsql}", "params": ctx.params}

    # ------------------------------------------------------------------ Redis / Valkey key namespace
    def kv(self, req):
        t = req["tenant"]
        if type(t) is not str: raise ValueError("kv tenant handle must be a string")
        tb = t.encode("utf-8")
        suffix = bytes.fromhex(req.get("suffix_hex", ""))
        naive = "kv-naive" in self.m or "kv-escaped-colon" in self.m
        if naive:
            prefix = b"t:" + tb + b":"
        else:
            prefix = b"t:{" + tb.hex().encode() + b"}:"      # alphabet [0-9a-f], '}' terminator, pins the slot
        key = prefix + suffix
        op = req["op"]
        h = lambda b: (b if isinstance(b, bytes) else str(b).encode()).hex()
        if op == "kv_key":
            return {"key_hex": key.hex()}
        if op == "kv_set":
            return {"commands": [[h(b"SET"), key.hex(), req.get("value_hex", "")]]}
        if op == "kv_del":
            return {"commands": [[h(b"DEL"), key.hex()]]}
        if op == "kv_get":
            return {"commands": [[h(b"GET"), key.hex()]]}
        if op == "kv_scan":
            if "kv-naive" in self.m:
                pat = b"t:" + tb + b":*"
            elif "kv-escaped-colon" in self.m:
                pat = b"t:" + glob_escape(tb) + b":*"
            else:
                pat = prefix + b"*"
            return {"pattern_hex": pat.hex()}
        raise ValueError(op)

class _AnyFields:
    def __contains__(self, x): return isinstance(x, str)

def glob_escape(s: bytes) -> bytes:
    out = bytearray()
    for b in s:
        if b in b"*?[]\\^-": out += b"\\"
        out.append(b)
    return bytes(out)

# =========================================================================================== 4. subject protocol
def _roundtrip(obj):
    return json.loads(json.dumps(obj, ensure_ascii=True))

class LocalSubject:
    """In-process reference renderer; requests and replies go through JSON exactly like the wire protocol."""
    def __init__(self, mutants=()):
        self.r = Renderer(mutants)
        self.name = "reference" + (f"[{','.join(sorted(mutants))}]" if mutants else "")
    def call(self, req):
        req = _roundtrip(req)
        try:
            out = self.r.handle(req)
        except (ValueError, KeyError, TypeError) as e:
            out = {"refuse": str(e)}
        out["id"] = req.get("id")
        return _roundtrip(out)
    def close(self): pass

class ProcSubject:
    """Out-of-process subject speaking the line protocol on stdin/stdout (one JSON object per line)."""
    def __init__(self, cmd):
        self.name = cmd
        self.p = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  text=True, encoding="utf-8", bufsize=1)
        self.n = 0
    def call(self, req):
        self.n += 1
        req = dict(req, id=self.n, v=1)
        self.p.stdin.write(json.dumps(req, ensure_ascii=True) + "\n")
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        if not line:
            raise RuntimeError(f"subject {self.name!r} closed its stdout (exit {self.p.poll()})")
        out = json.loads(line)
        if out.get("id") != self.n:
            raise RuntimeError(f"subject reply id {out.get('id')!r} != request id {self.n}")
        return out
    def close(self):
        try:
            self.p.stdin.close(); self.p.wait(timeout=10)
        except Exception:
            self.p.kill()

def make_subject(cmd, mutants=()):
    return ProcSubject(cmd) if cmd else LocalSubject(mutants)

def serve(argv):
    muts = []
    i = 0
    while i < len(argv):
        if argv[i] == "--mutant":
            muts.append(argv[i + 1]); i += 2
        else:
            raise SystemExit(f"serve: unknown argument {argv[i]!r}")
    r = Renderer(muts)
    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        rid = None
        try:
            req = json.loads(line); rid = req.get("id")
            out = r.handle(req)
        except (ValueError, KeyError, TypeError) as e:
            out = {"refuse": str(e)}
        out["id"] = rid; out["v"] = 1
        sys.stdout.write(json.dumps(out, ensure_ascii=True) + "\n"); sys.stdout.flush()

def placeholders_qmark_to_dollar(sql, offset=0):
    """Only used for oracle-composed harness SQL (never for subject output)."""
    out, n, q = [], offset, None
    for ch in sql:
        if q:
            out.append(ch)
            if ch == q: q = None
        elif ch in "'\"":
            q = ch; out.append(ch)
        elif ch == "?":
            n += 1; out.append(f"${n}")
        else:
            out.append(ch)
    return "".join(out)

# =========================================================================================== 5a. Postgres wire client
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

# =========================================================================================== 5b. RESP2 client
class Resp:
    """RESP2 client (reviewed port of research rd_run.py class C)."""
    def __init__(self, url, timeout=30):
        u = urllib.parse.urlparse(url)
        if u.scheme not in ("redis", "valkey"): raise ValueError("url must be redis://[user:pw@]host:port[/db]")
        self.s = socket.create_connection((u.hostname or "127.0.0.1", u.port or 6379), timeout=timeout)
        self.f = self.s.makefile("rb")
        if u.password:
            r = self.cmd(b"AUTH", *( [u.username.encode()] if u.username else [] ), u.password.encode())
            if isinstance(r, RespError): raise r
        self.db = int((u.path or "/0")[1:] or 0)
    def cmd(self, *a):
        b = b"*%d\r\n" % len(a)
        for x in a:
            x = x if isinstance(x, bytes) else str(x).encode()
            b += b"$%d\r\n%s\r\n" % (len(x), x)
        self.s.sendall(b)
        return self.read()
    def read(self):
        l = self.f.readline().rstrip(b"\r\n"); t, r = l[:1], l[1:]
        if t == b"+": return r
        if t == b":": return int(r)
        if t == b"-": return RespError(r.decode("utf-8", "replace"))
        if t == b"$":
            n = int(r)
            if n < 0: return None
            return self.f.read(n + 2)[:-2]
        if t == b"*":
            n = int(r)
            return None if n < 0 else [self.read() for _ in range(n)]
        raise RuntimeError(f"unexpected RESP type {t!r}")
    def close(self):
        try: self.s.close()
        except Exception: pass

class RespError(Exception):
    pass

# =========================================================================================== 6. stringmatchlen port
def stringmatchlen(pattern: bytes, string: bytes, nocase=False):
    """Line-for-line port of stringmatchlen_impl() from redis 8.10.2 src/util.c (same in valkey 9.1.2).
    Reviewed copy of research round-003/01-work/oracle.py; out-of-range index on a trailing '[' guarded."""
    skip = [0]
    def lower(c): return c + 32 if nocase and 65 <= c <= 90 else c
    def impl(pi, si, nesting):
        P, S = pattern, string
        if nesting > 1000: return 0
        plen, slen = len(P) - pi, len(S) - si
        while plen and slen:
            c = P[pi]
            if c == ord('*'):
                while plen and pi + 1 < len(P) and P[pi + 1] == ord('*'):
                    pi += 1; plen -= 1
                if plen == 1: return 1
                while slen:
                    if impl(pi + 1, si, nesting + 1): return 1
                    if skip[0]: return 0
                    si += 1; slen -= 1
                skip[0] = 1; return 0
            elif c == ord('?'):
                si += 1; slen -= 1
            elif c == ord('['):
                pi += 1; plen -= 1
                neg = plen and P[pi] == ord('^')
                if neg: pi += 1; plen -= 1
                match = 0
                while True:
                    if plen >= 2 and P[pi] == ord('\\'):
                        pi += 1; plen -= 1
                        if P[pi] == S[si]: match = 1
                    elif plen == 0:
                        pi -= 1; plen += 1; break
                    elif P[pi] == ord(']'):
                        break
                    elif plen >= 3 and P[pi + 1] == ord('-'):
                        st, en, ch = P[pi], P[pi + 2], S[si]
                        if st > en: st, en = en, st
                        if nocase: st, en, ch = lower(st), lower(en), lower(ch)
                        pi += 2; plen -= 2
                        if st <= ch <= en: match = 1
                    else:
                        if lower(P[pi]) == lower(S[si]): match = 1
                    pi += 1; plen -= 1
                if neg: match = not match
                if not match: return 0
                si += 1; slen -= 1
            else:
                if c == ord('\\') and plen >= 2:
                    pi += 1; plen -= 1
                if lower(P[pi]) != lower(S[si]): return 0
                si += 1; slen -= 1
            pi += 1; plen -= 1
            if slen == 0:
                while plen and P[pi] == ord('*'):
                    pi += 1; plen -= 1
                break
        return 1 if (plen == 0 and slen == 0) else 0
    return bool(impl(0, 0, 0))

if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "serve":
        serve(sys.argv[2:])
    else:
        print(__doc__)
        print("usage: python3 -I lowir.py serve [--mutant NAME ...]\nmutants:")
        for k, v in MUTANTS.items(): print(f"  {k:24s} {v}")
