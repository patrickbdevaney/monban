#!/usr/bin/env python3
"""AEGIS read-lowering differential oracle (SPEC_INVARIANTS E: lowering soundness; Lowering.lean lowerQ/sql3).

For every (DB state, tenant handle t, Pred p) the subject renders lowerQ(t, p) as a SQL boolean expression; the
oracle runs it on the engine and compares the returned row ids with reference sets computed over the rows AS STORED
(read back after insert, so affinity conversions are attributed to the state, not the query). Policy semantics are
three-valued (SPEC_INVARIANTS E as amended by spike q4-004; spec/AegisIR/ThreeValued.lean):
    permit = { r | refQ3 t r p }                             Lean `refQ3` (policy: eval3, absent field => atom
                                                             UNKNOWN, Kleene connectives, permitted iff some true)
    model  = { r | keeps EXACT r (lowerQ t p) }              Lean `sql3` over an exact backend; = permit by
                                                             `lowerQ_exact3` (checked row by row on the port)
    permit2= { r | refQ t r p }                              the old two-valued reference (absent => atom false)
    got    = rows returned by the engine
    LEAK  = got - permit      (unsound: row the 3VL policy rejects)                     must be 0
    WIDEN = got - model       (row the Lean lowering drops)                             must be 0
    MISS  = (permit | model) - got  (Backend.Exact violated / incomplete renderer)      must be 0
    GAP   = permit2 - permit  (rows 2VL permits and 3VL denies: NOT over an absent field, `not_absent_gap`);
                              information only (fails only with --miss-vs-2vl, which reproduces the old D1 wording)
Also checked on every evaluated row (guards the Python port itself): lower_exact3 (sql3 EXACT (lower p) = eval3 p),
lower_sound_full (sql3 = some b -> eval = b) and eval3_sound (eval3 = some b -> eval = b).
"""
import argparse, json, os, random, sqlite3, sys, time, unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)
import lowir as L  # noqa: E402

NAME = "LOWERING-READ"
SEEDS = [1, 2, 3, 20261025]           # research seeds; the 4th was only ever run pre-fix (calibration r4c12)
NFD = lambda s: unicodedata.normalize("NFD", s)

# =========================================================================================== research replay
# Verbatim port of the research generator (round-003/01-work/oracle.py gen_rows/gen_pred + main's case list) so
# the 4 research seeds replay the exact same rows/cases.  Research predicates are n-ary ("and",[..]) and may hold
# float literals; floats are not Lean Values, so such cases are counted as skipped_float (rows may still STORE
# floats; a stored REAL is a non-Value that no literal equals).
R_TENANTS = ["acme", "ACME", "Acme", "acme ", "acmé", NFD("acmé"), "1", "01", "a%", "a_",
             "a\\", "évil", "ǅ", "ß", "ss"]
R_FIELD_VALUES = [0, 1, 2, 10, -1, 1.0, 2.5, "1", "10", "2", "a", "A", "ab", "AB", "a%b", "a_b", "ä",
                  NFD("ä"), "", " ", "z", None]

def _rcls(v):
    if v is None: return None
    if isinstance(v, bool): return "int"
    if isinstance(v, int): return "int"
    if isinstance(v, float): return "float"
    if isinstance(v, str): return "str"
    return type(v).__name__

def r_gen_rows(rng, n):
    return [{"id": i, "tenant": rng.choice(R_TENANTS), "x": rng.choice(R_FIELD_VALUES), "y": rng.choice(R_FIELD_VALUES)}
            for i in range(n)]

def r_gen_pred(rng, depth=0):
    r = rng.random()
    f = rng.choice(["x", "y"])
    scal = [v for v in R_FIELD_VALUES if v is not None]
    if depth > 2 or r < 0.45:
        k = rng.choice(["eq", "eq", "in", "range", "prefix"])
        if k == "eq": return ("eq", f, rng.choice(scal))
        if k == "in": return ("in", f, list(rng.sample(scal, rng.choice([0, 1, 2, 3]))))
        if k == "range":
            c = rng.choice(["int", "str", "float"])
            pool = [v for v in scal if _rcls(v) == c]
            a, b = sorted([rng.choice(pool), rng.choice(pool)])
            return ("range", f, a, b)
        return ("prefix", f, rng.choice(["a", "A", "1", "a%", "a_", "", "ä"]))
    k = rng.choice(["and", "or"])
    return (k, [r_gen_pred(rng, depth + 1) for _ in range(rng.choice([0, 1, 2, 3]))])

def r_to_lean(p):
    """research tuple pred -> Lean JSON pred; None if it holds a float literal."""
    k = p[0]
    def ok(v): return type(v) in (int, str)
    if k == "eq": return ["eq", p[1], p[2]] if ok(p[2]) else None
    if k == "in": return ["in", p[1], list(p[2])] if all(ok(v) for v in p[2]) else None
    if k == "range": return ["range", p[1], p[2], p[3]] if ok(p[2]) and ok(p[3]) else None
    if k == "prefix": return ["pfx", p[1], p[2]]
    subs = [r_to_lean(q) for q in p[1]]
    if any(s is None for s in subs): return None
    return ["andN" if k == "and" else "orN", subs]

def research_corpus(seed, nrows=400, ncases=3000):
    rng = random.Random(seed)
    rows = r_gen_rows(rng, nrows)
    raw = [(rng.choice(R_TENANTS), r_gen_pred(rng)) for _ in range(ncases)]
    cases, skipped = [], 0
    for t, p in raw:
        q = r_to_lean(p)
        if q is None: skipped += 1
        else: cases.append((t, q))
    return rows, cases, skipped

# =========================================================================================== Lean-faithful generator
G_TENANTS = R_TENANTS + ["acme\x00evil", 1, 0, "01"]
G_VALUES = [0, 1, 2, 10, -1, 2 ** 62, -(2 ** 63), "1", "10", "2", "a", "A", "ab", "AB", "a%b", "a_b",
            "ä", NFD("ä"), "", " ", "z", "acme\x00evil", "a\x00", " 1", "1e1", "10.0", "0x10", None, None, 1.0, 2.5]
G_LITS = [v for v in G_VALUES if type(v) in (int, str)] + [2 ** 64, -(2 ** 70)]
G_PFX = ["a", "A", "1", "a%", "a_", "", "ä", NFD("ä")[:1], "a\x00", "acme\x00", "ab", "\\"]

def g_rows(rng, n, tenants=G_TENANTS, values=G_VALUES):
    return [{"id": i + 1, "tenant": rng.choice(tenants + [None]), "x": rng.choice(values), "y": rng.choice(values)}
            for i in range(n)]

def g_pred(rng, fields=("x", "y"), depth=0, lits=G_LITS, pfx=G_PFX):
    f = rng.choice(list(fields) + ["tenant"] if rng.random() < 0.08 else list(fields))
    r = rng.random()
    if depth >= 3 or r < 0.40:
        k = rng.choice(["eq", "eq", "in", "range", "range", "pfx", "tt", "ff"] if r < 0.38 else ["eq", "in"])
        if k == "tt": return ["tt"]
        if k == "ff": return ["ff"]
        if k == "eq": return ["eq", f, rng.choice(lits)]
        if k == "in": return ["in", f, rng.sample(lits, rng.choice([0, 1, 2, 3]))]
        if k == "range":
            if rng.random() < 0.1:
                return ["range", f, rng.choice(lits), rng.choice(lits)]          # mixed class / any order
            c = rng.choice([int, str])
            pool = [v for v in lits if type(v) is c]
            a, b = sorted([rng.choice(pool), rng.choice(pool)])
            if rng.random() < 0.05: a, b = b, a
            return ["range", f, a, b]
        return ["pfx", f, rng.choice(pfx)]
    k = rng.choice(["and", "or", "not", "not", "andN", "orN"])
    if k == "not": return ["not", g_pred(rng, fields, depth + 1, lits, pfx)]
    if k in ("and", "or"): return [k, g_pred(rng, fields, depth + 1, lits, pfx), g_pred(rng, fields, depth + 1, lits, pfx)]
    return [k, [g_pred(rng, fields, depth + 1, lits, pfx) for _ in range(rng.choice([0, 1, 2, 3]))]]

def lean_corpus(seed, nrows, ncases, nul=True):
    rng = random.Random(seed * 7919 + 17)
    tenants = G_TENANTS if nul else [t for t in G_TENANTS if not (type(t) is str and "\x00" in t)]
    values = G_VALUES if nul else [v for v in G_VALUES if not (type(v) is str and "\x00" in v)]
    lits = [v for v in G_LITS if nul or not (type(v) is str and "\x00" in v)]
    pfx = [s for s in G_PFX if nul or "\x00" not in s]
    rows = g_rows(rng, nrows, tenants, values)
    cases = [(rng.choice(tenants), g_pred(rng, lits=lits, pfx=pfx)) for _ in range(ncases)]
    return rows, cases

# =========================================================================================== cex corpus (research 78)
# The 15 SQLite single-cause cases of round-003/01-work/cex.py (+ the NUL probe of probe_nul.json).  Each: (name,
# ddl, (tenant, x, y), tenant handle, pred, research naive-bound verdict).  The 11 PG cases are in PG_CEX.
TXT = "create table t(id integer primary key, tenant text, x text, y text)"
NUM = "create table t(id integer primary key, tenant text, x numeric, y numeric)"
NOC = "create table t(id integer primary key, tenant text collate nocase, x text collate nocase, y text)"
UNT = "create table t(id integer primary key, tenant, x, y)"
CEX = [
    ("collation: tenant column COLLATE NOCASE", NOC, ("ACME", "v", None), "acme", ["andN", []], "LEAK"),
    ("collation: field COLLATE NOCASE eq", NOC, ("acme", "SECRET", None), "acme", ["eq", "x", "secret"], "LEAK"),
    ("affinity: int literal vs TEXT column", TXT, ("acme", "1", None), "acme", ["eq", "x", 1], "LEAK"),
    ("affinity: text literal vs NUMERIC column (stored int)", NUM, ("acme", 10, None), "acme", ["eq", "x", "10"], "LEAK"),
    ("affinity: text range bound coerced to number on NUMERIC col", NUM, ("acme", "", None), "acme", ["range", "x", "10", "z"], "LEAK"),
    ("numeric: int 1 vs real 1.0 (untyped col)", UNT, ("acme", 1.0, None), "acme", ["eq", "x", 1], "LEAK"),
    ("LIKE prefix: ASCII case-insensitive", TXT, ("acme", "ADMIN-x", None), "acme", ["pfx", "x", "admin"], "LEAK"),
    ("LIKE prefix: '_' wildcard in value", TXT, ("acme", "aXb", None), "acme", ["pfx", "x", "a_"], "LEAK"),
    ("LIKE prefix: '%' wildcard in value", TXT, ("acme", "aZZ", None), "acme", ["pfx", "x", "a%"], "LEAK"),
    ("empty Or([]) rendered TRUE", TXT, ("acme", "z", None), "acme", ["orN", []], "LEAK"),
    ("empty In(f,[])", TXT, ("acme", "z", None), "acme", ["in", "x", []], "ok"),
    ("NULL: x NULL vs Eq (3VL)", TXT, ("acme", None, None), "acme", ["eq", "x", "a"], "ok"),
    ("unicode: NFC literal vs NFD stored (BINARY)", TXT, ("acme", NFD("ä"), None), "acme", ["eq", "x", "ä"], "ok"),
    ("unicode: NOCASE non-ASCII (É vs é)", NOC, ("acme", "É", None), "acme", ["eq", "x", "é"], "ok"),
    ("trailing space: 'acme ' vs 'acme'", TXT, ("acme ", "v", None), "acme", ["andN", []], "ok"),
    ("probe_nul: 'acme\\0evil' LIKE 'acme' (prefix)", TXT, ("acme", "acme\x00evil", None), "acme", ["pfx", "x", "acme"], "ok"),
    ("probe_nul: tenant 'acme\\0evil' vs handle 'acme'", TXT, ("acme\x00evil", "v", None), "acme", ["tt"], "ok"),
    # new in-repo regressions (post-fix seeds of this port; see README)
    ("3VL: NOT Eq over NULL field (not_absent_permits witness)", TXT, ("acme", None, None), "acme", ["not", ["eq", "x", "a"]], "ok"),
    ("3VL: NOT In(f,[]) over NULL field", TXT, ("acme", None, None), "acme", ["not", ["in", "x", []]], "ok"),
    ("NUL in prefix: substr stops at NUL", TXT, ("acme", "a\x00bc", None), "acme", ["pfx", "x", "a\x00b"], "ok"),
    ("OR precedence: tenant AND (a OR b)", TXT, ("evil", "a", None), "acme", ["or", ["eq", "x", "zz"], ["eq", "x", "a"]], "ok"),
    ("int64 bounds: range clamps huge bounds", UNT, ("acme", 5, None), "acme", ["range", "x", -(2 ** 70), 2 ** 64], "ok"),
]

PG_CEX_SCHEMAS = {
    "T": "create table t(id int primary key, tenant text, x text, y text)",
    "CI": "create table t(id int primary key, tenant text collate ci_nd, x text collate ci_nd, y text)",
    "NC": "create table t(id int primary key, tenant text collate nd_canon, x text collate nd_canon, y text)",
    "CT": "create table t(id int primary key, tenant citext, x citext, y text)",
}
PG_CEX = [
    ("collation: nondeterministic ICU ks-level2 tenant (case)", "CI", ("ACME", "v", None), "acme", ["andN", []]),
    ("collation: nondeterministic ICU 'und' tenant (NFC vs NFD canonical eq)", "NC", (NFD("acmé"), "v", None), "acmé", ["andN", []]),
    ("collation: nondeterministic ICU field eq NFD", "NC", ("acme", NFD("ä"), None), "acme", ["eq", "x", "ä"]),
    ("citext tenant", "CT", ("ACME", "v", None), "acme", ["andN", []]),
    ("LIKE prefix on nondeterministic collation", "CI", ("acme", "ADMIN-x", None), "acme", ["pfx", "x", "admin"]),
    ("LIKE prefix '_' wildcard", "T", ("acme", "aXb", None), "acme", ["pfx", "x", "a_"]),
    ("LIKE prefix backslash escape in value", "T", ("acme", "a\\x", None), "acme", ["pfx", "x", "a\\"]),
    ("empty Or([]) rendered TRUE", "T", ("acme", "z", None), "acme", ["orN", []]),
    ("NULL x vs Eq", "T", ("acme", None, None), "acme", ["eq", "x", "a"]),
    ("default collation range (en_US.utf8 vs code point)", "T", ("acme", "B", None), "acme", ["range", "x", "a", "b"]),
    ("glibc en_US.utf8 range: 'A' in ['a','b']", "T", ("acme", "A", None), "acme", ["range", "x", "a", "b"]),
]

# =========================================================================================== engines
SQLITE_SCHEMAS = {   # name -> (ddl, declared column types sent to the subject)
    "untyped(BLOB affinity)": ("create table t(id integer primary key, tenant, x, y)",
                               {"id": "integer", "tenant": "", "x": "", "y": ""}),
    "TEXT tenant, NUMERIC x,y": ("create table t(id integer primary key, tenant text, x numeric, y numeric)",
                                 {"id": "integer", "tenant": "text", "x": "numeric", "y": "numeric"}),
    "NOCASE tenant,x; TEXT y": ("create table t(id integer primary key, tenant text collate nocase, x text collate nocase, y text)",
                                {"id": "integer", "tenant": "text collate nocase", "x": "text collate nocase", "y": "text"}),
    "STRICT ANY": ("create table t(id integer primary key, tenant text, x any, y any) strict",
                   {"id": "integer", "tenant": "text", "x": "any", "y": "any"}),
    "STRICT typed (x TEXT, y INTEGER)": ("create table t(id integer primary key, tenant any, x text, y integer) strict",
                                         {"id": "integer", "tenant": "any", "x": "text", "y": "integer"}),
}
RESEARCH_SCHEMAS = ["untyped(BLOB affinity)", "TEXT tenant, NUMERIC x,y", "NOCASE tenant,x; TEXT y", "STRICT ANY"]

def coerce_for_strict(ddl, row):
    """STRICT tables reject mismatched values; coerce like research oracle_typed (x->text, y->int or NULL)."""
    if "x text, y integer) strict" not in ddl: return row
    x, y = row["x"], row["y"]
    return {**row, "x": None if x is None else (x if type(x) is str else str(x)),
            "y": y if type(y) is int else None}

class SqliteDB:
    dialect = "sqlite"
    def __init__(self, ddl, rows):
        self.c = sqlite3.connect(":memory:")
        self.c.execute(ddl)
        for r in rows:
            r = coerce_for_strict(ddl, r)
            self.c.execute("insert into t(id,tenant,x,y) values (?,?,?,?)", (r["id"], r["tenant"], r["x"], r["y"]))
        self.stored = {i: {"id": i, "tenant": t, "x": x, "y": y}
                       for (i, t, x, y) in self.c.execute("select id,tenant,x,y from t")}
    def ids(self, sql, params):
        return [r for r in self.c.execute(sql, params)]
    def ph(self, n): return "?"

class PgDB:
    dialect = "postgres"
    def __init__(self, pg, ddl, rows, coerce):
        self.pg = pg
        pg.simple("drop table if exists t")
        pg.simple(ddl)
        for r in rows:
            r = coerce(r)
            pg.query("insert into t(id,tenant,x,y) values ($1,$2,$3,$4)", (r["id"], r["tenant"], r["x"], r["y"]))
        _, got = pg.query("select id, tenant::text, x::text, y from t")
        self.stored = {i: {"id": i, "tenant": t, "x": x, "y": y} for (i, t, x, y) in got}
    def ids(self, sql, params):
        return self.pg.query(sql, params)[1]

def pg_setup(pg):
    pg.simple("create extension if not exists citext")
    pg.simple("do $$ begin if not exists (select 1 from pg_collation where collname='ci_nd') then "
              "create collation ci_nd (provider = icu, locale = 'und-u-ks-level2', deterministic = false); end if; "
              "if not exists (select 1 from pg_collation where collname='nd_canon') then "
              "create collation nd_canon (provider = icu, locale = 'und', deterministic = false); end if; end $$;")

PG_SCHEMAS = {   # tenant text, x text, y bigint (typed); collation variants from research
    "deterministic default collation": "create table t(id int primary key, tenant text, x text, y bigint)",
    "nondeterministic ICU ks-level2": "create table t(id int primary key, tenant text collate ci_nd, x text collate ci_nd, y bigint)",
    "nondeterministic ICU und (NFC==NFD)": "create table t(id int primary key, tenant text collate nd_canon, x text collate nd_canon, y bigint)",
    "citext tenant,x": "create table t(id int primary key, tenant citext, x citext, y bigint)",
}
PG_COLS = {"id": "int", "tenant": "text", "x": "text", "y": "bigint"}

def pg_coerce(r):
    def s(v): return None if v is None else (v if type(v) is str else (str(int(v)) if isinstance(v, float) and v == int(v) else str(v)))
    t = r["tenant"]
    return {"id": r["id"], "tenant": None if t is None else str(t), "x": s(r["x"]),
            "y": r["y"] if type(r["y"]) is int and L.INT64_MIN <= r["y"] <= L.INT64_MAX else None}

# =========================================================================================== core check
class Stats(dict):
    KEYS = ("cases", "rows_evaluated", "leak", "widen", "miss", "gap", "leak_rows", "miss_rows", "refused",
            "errors", "theorem_violations")
    def __init__(self):
        super().__init__({k: 0 for k in self.KEYS}); self["examples"] = []
    def add(self, o):
        for k in self.KEYS: self[k] += o[k]
        self["examples"] += o["examples"][: max(0, 3 - len(self["examples"]))]

def tkey(v):
    return (type(v).__name__, v)

def index_by_tenant(stored):
    idx = {}
    for i, r in stored.items():
        t = r["tenant"]
        if L.is_val(t): idx.setdefault(tkey(t), []).append(r)
    return idx

# ---- Lean ThreeValued.eval3 / refQ3 (spec/AegisIR/ThreeValued.lean), line-for-line. Kept here, not in lowir.py,
# because lowir.py must stay byte-identical with oracles/lowering-write/lowir.py.
def eval3(row, p):
    """Lean `eval3`: Option Bool (None = UNKNOWN); an absent/NULL field makes every atom UNKNOWN; Kleene and/or/not."""
    k = p[0]
    if k == "tt": return True
    if k == "ff": return False
    if k in ("eq", "in", "range", "pfx"):
        x = row.get(p[1])
        if x is None: return None
        if k == "eq": return L.veq(x, p[2])
        if k == "in": return any(L.veq(x, v) for v in p[2])          # vs.contains x; [] => FALSE when present
        if k == "range": return L.ref_range(p[2], p[3], x)
        return L.ref_prefix(p[2], x)
    if k == "and": return L.k3and(eval3(row, p[1]), eval3(row, p[2]))
    if k == "or": return L.k3or(eval3(row, p[1]), eval3(row, p[2]))
    if k == "not": return L.k3not(eval3(row, p[1]))
    if k in ("andN", "orN"): return eval3(row, L.desugar_n(p))
    raise ValueError(k)

def refQ3(tf, t, row, p):
    return eval3(row, ["and", ["eq", tf, t], p]) is True

def model_sets(rows_for_t, t, p, st, tf="tenant"):
    """permit (refQ3) / model (sql3 EXACT) / permit2 (2VL refQ) over the candidate rows (all rows whose tenant
    equals t; the tenant conjunct drops every other row in all three)."""
    lp, lq = L.lower(p), L.lowerQ(tf, t, p)
    permit, model, permit2 = set(), set(), set()
    for r in rows_for_t:
        e = L.ev(r, p)
        e3 = eval3(r, p)
        m = L.sql3(L.EXACT, r, lp)
        st["rows_evaluated"] += 1
        if m != e3:
            st["theorem_violations"] += 1                # lower_exact3 violated by the port itself
        if (m is not None and m != e) or (e3 is not None and e3 != e):
            st["theorem_violations"] += 1                # lower_sound_full / eval3_sound violated by the port
        p3, k = refQ3(tf, t, r, p), L.keeps(L.EXACT, r, lq)
        if p3 != k:
            st["theorem_violations"] += 1                # lowerQ_exact3 violated by the port
        if p3: permit.add(r["id"])
        if k: model.add(r["id"])
        if L.refQ(tf, t, r, p): permit2.add(r["id"])
    return permit, model, permit2

def note(st, kind, ex):
    if len(st["examples"]) < 3: st["examples"].append(dict(kind=kind, **ex))

def check_case(subject, db, cols, t, p, st, miss_vs_2vl=False):
    st["cases"] += 1
    req = {"op": "read", "dialect": db.dialect, "table": "t", "alias": None, "param_offset": 0,
           "tenant_field": "tenant", "columns": cols, "tenant": t, "pred": p}
    rep = subject.call(req)
    cand = db.idx.get(tkey(t), []) if L.is_val(t) else []
    permit, model, permit2 = model_sets(cand, t, p, st)
    if "refuse" in rep:
        st["refused"] += 1
        got = set()
    else:
        try:
            got = {r[0] for r in db.ids(f"select id from t where {rep['sql']}", rep["params"])}
        except Exception as e:  # engine error = fail-closed, but a renderer emitting invalid SQL fails the gate
            st["errors"] += 1
            note(st, "error", {"tenant": t, "pred": p, "sql": rep.get("sql"), "error": str(e)[:200]})
            got = set()
    leak = got - permit; widen = got - model; miss = (permit | model) - got; gap = permit2 - permit
    if miss_vs_2vl: miss = miss | (gap - got)
    if leak:
        st["leak"] += 1; st["leak_rows"] += len(leak)
        note(st, "LEAK", {"tenant": t, "pred": p, "sql": rep.get("sql"), "params": rep.get("params"),
                          "row": db.stored[min(leak)]})
    if widen: st["widen"] += 1; (not leak) and note(st, "WIDEN", {"tenant": t, "pred": p, "sql": rep.get("sql"), "row": db.stored[min(widen)]})
    if miss: st["miss"] += 1; st["miss_rows"] += len(miss); note(st, "MISS", {"tenant": t, "pred": p, "sql": rep.get("sql"), "row": db.stored[min(miss)]})
    if gap - got: st["gap"] += 1

# ----- self-join family: same table twice (PG dca6a9e32 self-join-elimination RLS class; calibration r4c12)
def check_selfjoin(subject, db, cols, t, pa, pb, shape, st):
    st["cases"] += 1
    ra = subject.call({"op": "read", "dialect": db.dialect, "table": "t", "alias": "a", "param_offset": 0,
                       "tenant_field": "tenant", "columns": cols, "tenant": t, "pred": pa})
    off = len(ra.get("params", []))
    rb = subject.call({"op": "read", "dialect": db.dialect, "table": "t", "alias": "b", "param_offset": off,
                       "tenant_field": "tenant", "columns": cols, "tenant": t, "pred": pb})
    cand = db.idx.get(tkey(t), []) if L.is_val(t) else []
    pma, mma, _ = model_sets(cand, t, pa, st)
    pmb, mmb, _ = model_sets(cand, t, pb, st)
    ids = sorted(db.stored)
    if shape == "join":
        model = {(a, b) for a in mma for b in mmb if a % 7 == b % 7}
        permit_ok = lambda pr: pr[0] in pma and pr[1] in pmb
        sql_tpl = "select a.id, b.id from t as a join t as b on (a.id % 7) = (b.id % 7) where {wa} and {wb}"
    else:
        model = {(a,) for a in mma if (a + 1) in mmb}
        permit_ok = lambda pr: pr[0] in pma and (pr[0] + 1) in pmb
        sql_tpl = "select a.id from t as a where {wa} and exists (select 1 from t as b where b.id = a.id + 1 and {wb})"
    if "refuse" in ra or "refuse" in rb:
        st["refused"] += 1; got = set()
    else:
        sql = sql_tpl.format(wa=ra["sql"], wb=rb["sql"])
        try:
            got = {tuple(r) for r in db.ids(sql, ra["params"] + rb["params"])}
        except Exception as e:
            st["errors"] += 1; note(st, "error", {"sql": sql, "error": str(e)[:200]}); got = set()
    leak = {g for g in got if not permit_ok(g)}
    widen, miss = got - model, model - got
    if leak: st["leak"] += 1; st["leak_rows"] += len(leak); note(st, "LEAK(self-join)", {"tenant": t, "pa": pa, "pb": pb, "pair": min(leak)})
    if widen: st["widen"] += 1
    if miss: st["miss"] += 1; st["miss_rows"] += len(miss)

# ----- Redis / Valkey key namespace family (read side: SCAN MATCH must return only own keys, all of them)
R_REDIS_TENANTS = ["acme", "acme:x", "a*", "a?", "a[b]", "[ab]", "a\\", "a\\*", "ab", "abc", "a", "", "*", "a:b:c",
                   "x]", "^", "a-c", "ACME", "acmé"]
KV_SUFFIXES = [b"k1", b"x:2*", b"k3", b"x:4*", b"}:x", b":", b"b:c", b"x:b:c", b""]

def kv_family(subject, st, live=None):
    keys = {}
    collisions = 0
    for t in R_REDIS_TENANTS:
        for s in KV_SUFFIXES:
            rep = subject.call({"op": "kv_key", "tenant": t, "suffix_hex": s.hex()})
            if "refuse" in rep: st["refused"] += 1; continue
            k = bytes.fromhex(rep["key_hex"])
            if k in keys and keys[k] != t: collisions += 1; note(st, "LEAK(key collision)", {"key": k.decode("latin1"), "owners": [keys[k], t]})
            keys.setdefault(k, t)
    if live is not None:
        live.cmd(b"SELECT", live.db); live.cmd(b"FLUSHDB")
        for k, o in keys.items(): live.cmd(b"SET", k, b"v")
    for t in R_REDIS_TENANTS:
        st["cases"] += 1
        rep = subject.call({"op": "kv_scan", "tenant": t})
        if "refuse" in rep: st["refused"] += 1; continue
        pat = bytes.fromhex(rep["pattern_hex"])
        if live is None:
            got = {k for k in keys if L.stringmatchlen(pat, k)}
        else:
            got, cur = set(), b"0"
            while True:
                r = live.cmd(b"SCAN", cur, b"MATCH", pat, b"COUNT", b"1000")
                cur, batch = r[0], r[1]; got |= set(batch)
                if cur == b"0": break
        own = {k for k, o in keys.items() if o == t}
        leak, miss = {k for k in got if keys.get(k) != t}, own - got
        st["rows_evaluated"] += len(keys)
        if leak: st["leak"] += 1; st["leak_rows"] += len(leak); note(st, "LEAK(scan)", {"tenant": t, "pattern": pat.decode("latin1"), "key": min(leak).decode("latin1")})
        if miss: st["miss"] += 1; st["miss_rows"] += len(miss)
    if collisions: st["leak"] += collisions; st["leak_rows"] += collisions
    if live is not None: live.cmd(b"FLUSHDB")

# =========================================================================================== drivers
def run_sqlite(subject, cfg, log):
    fam = {}
    def fs(name):
        return fam.setdefault(name, Stats())
    # F1 cex single-cause corpus
    st = fs("cex(research 78-case corpus, SQLite part + in-repo regressions)")
    for (name, ddl, (tn, x, y), t, p, _naive) in CEX:
        db = SqliteDB(ddl, [{"id": 1, "tenant": tn, "x": x, "y": y}])
        cols = {"id": "integer", "tenant": "", "x": "", "y": ""}
        db.idx = index_by_tenant(db.stored)
        check_case(subject, db, cols, t, p, st, cfg.miss_vs_2vl)
    # F2 research replay on the 4 research seeds, research schemas, 400 rows x 3000 cases
    skipped = 0
    if cfg.research:
        for seed in cfg.seeds:
            rows, cases, sk = research_corpus(seed, 400, cfg.research_cases)
            skipped += sk
            for sname in RESEARCH_SCHEMAS:
                ddl, cols = SQLITE_SCHEMAS[sname]
                db = SqliteDB(ddl, rows); db.idx = index_by_tenant(db.stored)
                st = fs(f"research-replay | {sname}")
                for t, p in cases: check_case(subject, db, cols, t, p, st, cfg.miss_vs_2vl)
        log(f"  research replay: {skipped} cases skipped (float literal, not a Lean Value)")
    # F3 Lean-faithful generated corpus (NOT, tt/ff, n-ary, mixed-class ranges, NUL, int64 edges) x 5 schemas
    for seed in cfg.seeds:
        rows, cases = lean_corpus(seed, cfg.rows, cfg.cases)
        for sname, (ddl, cols) in SQLITE_SCHEMAS.items():
            db = SqliteDB(ddl, rows); db.idx = index_by_tenant(db.stored)
            st = fs(f"lean-generated | {sname}")
            for t, p in cases: check_case(subject, db, cols, t, p, st, cfg.miss_vs_2vl)
    # F4 self-join family (60-row table)
    for seed in cfg.seeds:
        rng = random.Random(seed + 4242)
        rows, _ = lean_corpus(seed + 1, 60, 0)
        cases = [(rng.choice(G_TENANTS), g_pred(rng), g_pred(rng), rng.choice(["join", "exists"])) for _ in range(cfg.selfjoin)]
        for sname, (ddl, cols) in SQLITE_SCHEMAS.items():
            db = SqliteDB(ddl, rows); db.idx = index_by_tenant(db.stored)
            st = fs(f"self-join | {sname}")
            for t, pa, pb, shape in cases: check_selfjoin(subject, db, cols, t, pa, pb, shape, st)
    return fam, skipped

def run_pg(subject, cfg, log):
    pg = L.Pg(cfg.dsn)
    _, v = pg.simple("show server_version")
    log(f"  postgres server_version {v[0][0]}")
    pg_setup(pg)
    fam = {}
    st = fam.setdefault("pg cex (research 78-case corpus, PG part)", Stats())
    for (name, sk, (tn, x, y), t, p) in PG_CEX:
        db = PgDB(pg, PG_CEX_SCHEMAS[sk], [{"id": 1, "tenant": tn, "x": x, "y": y}], lambda r: r)
        db.idx = index_by_tenant(db.stored)
        check_case(subject, db, {"id": "int", "tenant": "text", "x": "text", "y": "text"}, t, p, st, cfg.miss_vs_2vl)
    for seed in cfg.seeds:
        rows, cases = lean_corpus(seed, cfg.rows, cfg.pg_cases, nul=False)
        for sname, ddl in PG_SCHEMAS.items():
            db = PgDB(pg, ddl, rows, pg_coerce); db.idx = index_by_tenant(db.stored)
            st = fam.setdefault(f"pg lean-generated | {sname}", Stats())
            for t, p in cases: check_case(subject, db, PG_COLS, t, p, st, cfg.miss_vs_2vl)
        rng = random.Random(seed + 4242)
        rows2, _ = lean_corpus(seed + 1, 60, 0, nul=False)
        nn = lambda v: not (type(v) is str and "\x00" in v)
        lits, pf = [v for v in G_LITS if nn(v)], [v for v in G_PFX if nn(v)]
        sj = [(rng.choice([x for x in G_TENANTS if nn(x)]), g_pred(rng, lits=lits, pfx=pf), g_pred(rng, lits=lits, pfx=pf),
               rng.choice(["join", "exists"])) for _ in range(max(1, cfg.selfjoin // 2))]
        db = PgDB(pg, PG_SCHEMAS["deterministic default collation"], rows2, pg_coerce); db.idx = index_by_tenant(db.stored)
        st = fam.setdefault("pg self-join | deterministic default collation", Stats())
        for t, pa, pb, shape in sj:
            check_selfjoin(subject, db, PG_COLS, t, pa, pb, shape, st)
    pg.simple("drop table if exists t")
    pg.close()
    return fam

def evaluate(subject, cfg, log=print):
    t0 = time.time()
    fams = {}
    skipped = 0
    if "sqlite" in cfg.engines:
        f, skipped = run_sqlite(subject, cfg, log); fams.update(f)
    if "pg" in cfg.engines:
        fams.update(run_pg(subject, cfg, log))
    st = fams.setdefault("redis keyspace (stringmatchlen model)" if "redis" not in cfg.engines else "redis keyspace (live SCAN MATCH)", Stats())
    live = L.Resp(cfg.url) if "redis" in cfg.engines else None
    kv_family(subject, st, live)
    if live: live.close()
    tot = Stats()
    for s in fams.values(): tot.add(s)
    return fams, tot, skipped, time.time() - t0

def verdict(tot, cfg, min_cases):
    bad = {k: tot[k] for k in ("leak", "widen", "miss", "errors", "refused", "theorem_violations") if tot[k]}
    if tot["cases"] < min_cases: bad["too_few_cases"] = tot["cases"]
    return bad

class Cfg:
    def __init__(self, a):
        self.seeds = a.seeds
        self.cases = a.cases_per_seed
        self.rows = a.rows
        self.research = not a.no_research
        self.research_cases = 3000
        self.selfjoin = a.selfjoin
        self.engines = set(a.engine)
        self.dsn, self.url = a.dsn, a.url
        self.pg_cases = a.pg_cases
        self.miss_vs_2vl = a.miss_vs_2vl

def print_report(fams, tot, skipped, wall, log=print, quiet=False):
    if not quiet:
        log(f"{'family':72s} {'cases':>7s} {'leak':>5s} {'widen':>5s} {'miss':>5s} {'gap':>5s} {'err':>4s} {'ref':>4s}")
        for n, s in fams.items():
            log(f"{n[:72]:72s} {s['cases']:7d} {s['leak']:5d} {s['widen']:5d} {s['miss']:5d} {s['gap']:5d} {s['errors']:4d} {s['refused']:4d}")
            for ex in s["examples"][:1]:
                if s["leak"] or s["widen"] or s["miss"] or s["errors"]:
                    log("    e.g. " + json.dumps(ex, ensure_ascii=True, default=str)[:400])
    log(f"total: cases={tot['cases']} rows_evaluated={tot['rows_evaluated']} leak={tot['leak']} widen={tot['widen']} "
        f"miss={tot['miss']} gap_vs_2vl(not_absent_gap, info)={tot['gap']} errors={tot['errors']} refused={tot['refused']} "
        f"theorem_violations={tot['theorem_violations']} research_skipped_float={skipped} wall={wall:.1f}s")

# =========================================================================================== self-test
# q4-004 mutants: renderers that are only wrong under the three-valued policy (both pass the old 2VL `refQ` leak
# check, because 2VL permits NOT over an absent field). Defined here as Renderer subclasses so that lowir.py stays
# byte-identical with oracles/lowering-write/lowir.py.
class InNilConstFalse(L.Renderer):
    """`In f []` rendered as constant FALSE (research `(1=0)`, Lowering.lean's old comment): under NOT on a NULL
    column it yields TRUE where eval3 is UNKNOWN (`inList_nil_not_const_false`)."""
    def render(self, p, ctx):
        if p[0] == "in" and not p[2]:
            return self.ff(ctx)
        return super().render(p, ctx)

class TwoValuedNotAbsent(L.Renderer):
    """2VL NOT: UNKNOWN is collapsed to FALSE before negation (absent field => NOT p is TRUE), i.e. the old
    two-valued `eval` rendered literally; `not_absent_gap` says refQ3 denies these rows."""
    def render(self, p, ctx):
        if p[0] == "not":
            f = "0" if ctx.dialect == "sqlite" else "false"
            return f"(NOT COALESCE({self.render(p[1], ctx)}, {f}))"
        return super().render(p, ctx)

LOCAL_MUTANTS = {"in-nil-const-false": InNilConstFalse, "two-valued-not-absent": TwoValuedNotAbsent}

def mutant_subject(mut):
    if mut in LOCAL_MUTANTS:
        s = L.LocalSubject()
        s.r = LOCAL_MUTANTS[mut]()
        s.name = f"reference[{mut}]"
        return s
    return L.LocalSubject([mut])

SELFTEST_MUTANTS = [   # (mutant, counter that must become non-zero)
    ("drop-tenant", "leak"),
    ("two-valued-not", "leak"),
    ("in-nil-const-false", "leak"),
    ("two-valued-not-absent", "leak"),
    ("or-precedence", "leak"),
    ("like-prefix", "leak"),
    ("empty-or-true", "leak"),
    ("naive-bound", "leak"),
    ("no-collate-binary", "leak"),
    ("no-affinity-guard", "leak"),
    ("range-exclusive", "miss"),
    ("nul-prefix", "miss"),
    ("selfjoin-alias", "leak"),
    ("refuse-all", "miss"),
    ("kv-naive", "leak"),
    ("kv-escaped-colon", "leak"),
]

def self_test(a):
    small = argparse.Namespace(**vars(a))
    small.seeds = [20261025]; small.cases_per_seed = 600; small.rows = 120; small.no_research = True
    small.selfjoin = 120; small.engine = ["sqlite"]
    cfg = Cfg(small)
    caught, lines = 0, []
    for mut, counter in SELFTEST_MUTANTS:
        fams, tot, _, wall = evaluate(mutant_subject(mut), cfg, log=lambda *x: None)
        bad = verdict(tot, cfg, 1)
        ok = bool(bad) and tot.get(counter, 0) > 0
        caught += ok
        lines.append(f"  mutant {mut:21s} expect {counter:6s}>0: leak={tot['leak']} widen={tot['widen']} miss={tot['miss']} "
                     f"errors={tot['errors']} -> {'CAUGHT' if ok else 'NOT CAUGHT'} ({wall:.1f}s)")
        print(lines[-1], flush=True)
    # naive-bound must reproduce every research LEAK verdict of the 78-case corpus (SQLite part), case by case
    naive = L.LocalSubject(["naive-bound"])
    repro_ok = True
    for (name, ddl, (tn, x, y), t, p, want) in CEX:
        if want != "LEAK": continue
        db = SqliteDB(ddl, [{"id": 1, "tenant": tn, "x": x, "y": y}]); db.idx = index_by_tenant(db.stored)
        st = Stats(); check_case(naive, db, {"id": "integer", "tenant": "", "x": "", "y": ""}, t, p, st)
        if not st["leak"]:
            repro_ok = False; print(f"  research cex not reproduced by naive-bound: {name}")
    print(f"  naive-bound reproduces all {sum(1 for c in CEX if c[5] == 'LEAK')} research SQLite LEAK verdicts: {repro_ok}")
    # Lean counter-theorem refines_necessary: a coarser equality (NOCASE) on the tenant column must leak (model check)
    coarse = L.Backend(lambda x, v: L.veq(x.lower() if type(x) is str else x, v.lower() if type(v) is str else v), L.ref_range, L.ref_prefix)
    row = {"tenant": "ACME"}
    rn_ok = L.keeps(coarse, row, L.lowerQ("tenant", "acme", ["tt"])) and not refQ3("tenant", "acme", row, ["tt"])
    # the gate is refQ3, not the 2VL refQ: the two q4-004 witnesses must separate them (not_absent_gap,
    # inList_nil_not_const_false) -- a NULL x with NOT (x = v) / NOT (x in []) is 2VL-permitted and 3VL-denied
    nul = {"tenant": "acme", "x": None}
    gap_ok = all(L.refQ("tenant", "acme", nul, q) and not refQ3("tenant", "acme", nul, q)
                 for q in (["not", ["eq", "x", "a"]], ["not", ["in", "x", []]]))
    print(f"  refQ3 vs refQ witnesses (not_absent_gap, NOT In [] on NULL: 2VL permits, 3VL denies): {gap_ok}")
    rn_ok = rn_ok and gap_ok
    print(f"  refines_necessary witness (NOCASE backend keeps a row refQ rejects): {rn_ok}")
    # positive control through the out-of-process protocol (reference renderer served by lowir.py)
    cmd = f"{sys.executable} -I {os.path.join(HERE, 'lowir.py')} serve"
    sub = L.ProcSubject(cmd)
    fams, tot, _, wall = evaluate(sub, cfg, log=lambda *x: None); sub.close()
    pos_ok = not verdict(tot, cfg, 1)
    print(f"  positive control (reference via --subject protocol): cases={tot['cases']} leak={tot['leak']} widen={tot['widen']} "
          f"miss={tot['miss']} errors={tot['errors']} -> {'PASS' if pos_ok else 'FAIL'} ({wall:.1f}s)")
    # and one mutant through the protocol, to prove --subject output is really checked
    sub = L.ProcSubject(cmd + " --mutant drop-tenant")
    _, tot2, _, _ = evaluate(sub, cfg, log=lambda *x: None); sub.close()
    proc_mut_ok = tot2["leak"] > 0
    print(f"  drop-tenant via --subject protocol: leak={tot2['leak']} -> {'CAUGHT' if proc_mut_ok else 'NOT CAUGHT'}")
    n = len(SELFTEST_MUTANTS)
    # optional live backends: the same gate must go red on the engine-specific mutants
    for eng, muts in (("pg", [("pg-no-collate-c", "leak"), ("naive-bound", "leak"), ("like-prefix", "leak"),
                              ("two-valued-not", "widen"), ("drop-tenant", "leak")]),
                      ("redis", [("kv-naive", "leak"), ("kv-escaped-colon", "leak")])):
        if eng not in (a.engine or []): continue
        e2 = argparse.Namespace(**vars(small)); e2.engine = [eng]; e2.pg_cases = 400; e2.selfjoin = 40
        c2 = Cfg(e2)
        _, tot, _, _ = evaluate(L.LocalSubject(), c2, log=lambda *x: None)
        ok = not verdict(tot, c2, 1)
        print(f"  [{eng}] positive control: cases={tot['cases']} leak={tot['leak']} widen={tot['widen']} miss={tot['miss']} -> {'PASS' if ok else 'FAIL'}")
        pos_ok = pos_ok and ok
        for mut, counter in muts:
            _, tot, _, _ = evaluate(L.LocalSubject([mut]), c2, log=lambda *x: None)
            okm = tot.get(counter, 0) > 0
            n += 1; caught += okm
            print(f"  [{eng}] mutant {mut:16s} expect {counter}>0: leak={tot['leak']} widen={tot['widen']} miss={tot['miss']} errors={tot['errors']} -> {'CAUGHT' if okm else 'NOT CAUGHT'}")
    if caught == n and repro_ok and pos_ok and proc_mut_ok and rn_ok:
        print(f"{NAME} SELF-TEST: PASS ({caught}/{n} mutants caught; research naive LEAKs reproduced; positive control PASS)")
        return 0
    print(f"{NAME} SELF-TEST: FAIL ({caught}/{n} mutants caught; repro={repro_ok}; positive_control={pos_ok}; proc_mutant={proc_mut_ok}; refines_necessary={rn_ok})")
    return 1

# =========================================================================================== main
def main():
    ap = argparse.ArgumentParser(prog="run", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--subject", help="command speaking the line protocol (README.md); default: in-process reference renderer")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--engine", action="append", choices=["sqlite", "pg", "redis"], help="repeatable; default sqlite")
    ap.add_argument("--dsn", help="postgresql://user:pw@host:port/db (throwaway database: tables are dropped)")
    ap.add_argument("--url", help="redis://host:port/db (throwaway db: it is FLUSHDB'ed)")
    ap.add_argument("--seeds", type=lambda s: [int(x) for x in s.split(",")], default=SEEDS)
    ap.add_argument("--cases-per-seed", type=int, default=3000)
    ap.add_argument("--big", action="store_true", help="25000 generated cases per seed (>=100k with the default 4 seeds)")
    ap.add_argument("--rows", type=int, default=200)
    ap.add_argument("--selfjoin", type=int, default=250, help="self-join cases per seed")
    ap.add_argument("--pg-cases", type=int, default=1500)
    ap.add_argument("--no-research", action="store_true", help="skip the research-replay family")
    ap.add_argument("--miss-vs-2vl", action="store_true",
                    help="information: count GAP (permitted by the old two-valued refQ, denied by refQ3) as MISS")
    ap.add_argument("--json", help="write the full report here")
    a = ap.parse_args()
    if not a.engine: a.engine = ["sqlite"]
    if "pg" in a.engine and not a.dsn: ap.error("--engine pg needs --dsn")
    if "redis" in a.engine and not a.url: ap.error("--engine redis needs --url")
    if a.big: a.cases_per_seed = 25000
    if a.self_test:
        sys.exit(self_test(a))
    cfg = Cfg(a)
    subject = L.make_subject(a.subject)
    print(f"{NAME}: subject={subject.name} engines={sorted(cfg.engines)} sqlite={sqlite3.sqlite_version} seeds={cfg.seeds} "
          f"cases/seed={cfg.cases} rows={cfg.rows}", flush=True)
    fams, tot, skipped, wall = evaluate(subject, cfg)
    subject.close()
    print_report(fams, tot, skipped, wall)
    # the default gate needs >=10k unique generated cases (4 seeds x 3000); smaller ad-hoc runs only need >0
    min_cases = 1
    gen = sum(s["cases"] for n, s in fams.items() if n.startswith("lean-generated"))
    bad = verdict(tot, cfg, min_cases)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"families": fams, "total": tot, "skipped_float": skipped, "wall_s": wall, "bad": bad},
                      fh, indent=1, ensure_ascii=True, default=str)
    uniq = cfg.cases * len(cfg.seeds) if "sqlite" in cfg.engines else 0
    upg = cfg.pg_cases * len(cfg.seeds) if "pg" in cfg.engines else 0
    summary = (f"cases={tot['cases']} generated_unique_sqlite={uniq} (x{len(SQLITE_SCHEMAS)} schemas={gen}) "
               f"generated_unique_pg={upg} (x{len(PG_SCHEMAS)} schemas) leak={tot['leak']} widen={tot['widen']} miss={tot['miss']} "
               f"gap_vs_2vl(info)={tot['gap']} errors={tot['errors']}")
    if bad:
        print(f"{NAME}: FAIL ({', '.join(f'{k}={v}' for k, v in bad.items())}; {summary})")
        sys.exit(1)
    print(f"{NAME}: PASS ({summary})")

if __name__ == "__main__":
    main()
