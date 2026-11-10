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
Tenant handles are the D4 encoding (TenantId u64 as 16 lower-case hex digits); stored tenant values additionally
include non-canonical confusers (upper case, trailing space, NUL suffix, unpadded, ints) that a coarse comparison
would equate with a handle. Non-canonical handles must be refused (UNREFUSED otherwise).
"""
import argparse, json, os, random, sqlite3, sys, time, unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)
import lowir as L  # noqa: E402
import lowmy as M  # noqa: E402  (MariaDB / CockroachDB dialects; lowir.py stays byte-identical and unmodified)

NAME = "LOWERING-READ"
SEEDS = [1, 2, 3, 20261025]           # research seeds; the 4th was only ever run pre-fix (calibration r4c12)
NFD = lambda s: unicodedata.normalize("NFD", s)
T = L.tenant_text

# =========================================================================================== D4 tenant corpus
A, B, ONE = T(0xacce55), T(0xacce56), T(1)

def up_first(s):
    i = next(i for i, c in enumerate(s) if c.isalpha())
    return s[:i] + s[i].upper() + s[i + 1:]

# research tenant -> (stored value, handle). Canonical research tenants become distinct TenantIds; the research
# confusers ("ACME", "Acme", "acme ", NFD, "01") become non-canonical stored values that a coarse comparison would
# equate with the base tenant's canonical text (NOCASE, PAD SPACE, ICU ks-level2 width folding, numeric affinity),
# and their handle is the base tenant (handles must be canonical).
R_TENANT_MAP = {
    "acme": (A, A), "ACME": (A.upper(), A), "Acme": (up_first(A), A), "acme ": (A + " ", A),
    "acmé": (B, B), NFD("acmé"): (B[:-1] + "６", B),      # FULLWIDTH DIGIT SIX: tertiary (width) difference
    "1": (ONE, ONE), "01": ("1", ONE), "a%": (T(0xa25), T(0xa25)), "a_": (T(0xa5f), T(0xa5f)),
    "a\\": (T(0xa5c), T(0xa5c)), "évil": (T(0xe1), T(0xe1)), "ǅ": (T(0x1c5), T(0x1c5)), "ß": (T(0xdf), T(0xdf)),
    "ss": (T(0x55), T(0x55)),
    # used by the cex corpus only
    "acme\x00evil": (A + "\x00evil", A), "evil": (T(0xe1), T(0xe1)),
}
def S(t): return R_TENANT_MAP[t][0] if type(t) is str and t in R_TENANT_MAP else t
def H(t): return R_TENANT_MAP[t][1]

# =========================================================================================== research replay
# Verbatim port of the research generator (round-003/01-work/oracle.py gen_rows/gen_pred + main's case list) so
# the 4 research seeds replay the exact same rows/cases (tenant values then mapped through R_TENANT_MAP, D4).
# Research predicates are n-ary ("and",[..]) and may hold float literals; floats are not Lean Values, so such cases
# are counted as skipped_float (rows may still STORE floats; a stored REAL is a non-Value that no literal equals).
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
    for r in rows: r["tenant"] = S(r["tenant"])
    cases, skipped = [], 0
    for t, p in raw:
        q = r_to_lean(p)
        if q is None: skipped += 1
        else: cases.append((H(t), q))
    return rows, cases, skipped

# =========================================================================================== Lean-faithful generator
G_STORED = [R_TENANT_MAP[t][0] for t in R_TENANTS] + [
    A + "\x00evil", 1, 0, "1", "0" * 16, A[1:], " " + A[1:], A + "\n", 0xacce55]
G_HANDLES = sorted({R_TENANT_MAP[t][1] for t in R_TENANTS} | {T(2 ** 64 - 1), T(2 ** 63)})
G_VALUES = [0, 1, 2, 10, -1, 2 ** 62, -(2 ** 63), "1", "10", "2", "a", "A", "ab", "AB", "a%b", "a_b",
            "ä", NFD("ä"), "", " ", "z", "acme\x00evil", "a\x00", " 1", "1e1", "10.0", "0x10", None, None, 1.0, 2.5,
            A, A.upper()]
G_LITS = [v for v in G_VALUES if type(v) in (int, str)] + [2 ** 64, -(2 ** 70)]
G_PFX = ["a", "A", "1", "a%", "a_", "", "ä", NFD("ä")[:1], "a\x00", "acme\x00", "ab", "\\", A[:10]]
_nn = lambda v: not (type(v) is str and "\x00" in v)

def g_rows(rng, n, tenants=G_STORED, values=G_VALUES):
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
    tenants = G_STORED if nul else [t for t in G_STORED if _nn(t)]
    values = G_VALUES if nul else [v for v in G_VALUES if _nn(v)]
    lits = [v for v in G_LITS if nul or _nn(v)]
    pfx = [s for s in G_PFX if nul or _nn(s)]
    rows = g_rows(rng, nrows, tenants, values)
    cases = [(rng.choice(G_HANDLES), g_pred(rng, lits=lits, pfx=pfx)) for _ in range(ncases)]
    return rows, cases

# =========================================================================================== cex corpus (research 78)
# The 15 SQLite single-cause cases of round-003/01-work/cex.py (+ the NUL probe of probe_nul.json).  Each: (name,
# ddl, (tenant, x, y), tenant handle, pred, research naive-bound verdict).  Tenants go through R_TENANT_MAP (D4):
# stored value S(..), handle H(..).  The 11 PG cases are in PG_CEX.
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
    ("collation: nondeterministic ICU 'und' tenant (width variant)", "NC", (NFD("acmé"), "v", None), "acmé", ["andN", []]),
    ("collation: nondeterministic ICU ks-level2 tenant (width variant)", "CI", (NFD("acmé"), "v", None), "acmé", ["andN", []]),
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

# Non-canonical tenant handles: every one must be refused (the adapter only ever binds tenant_text(TenantId)).
BAD_HANDLES = [A.upper(), up_first(A), A + " ", " " + A[1:], A[1:], A + "0", "0" * 16, A + "\x00", "", "acme",
               "0x" + A[2:], "g" * 16, A.replace("a", "ａ"), 0xacce55, 1, A + "\n"]

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
    """STRICT tables reject mismatched values; coerce like research oracle_typed (x->text, y->int or NULL); the
    STRICT TEXT tenant of 'STRICT ANY' stores ints as text."""
    if "tenant text, x any, y any) strict" in ddl and type(row["tenant"]) is int:
        row = {**row, "tenant": str(row["tenant"])}
    if "x text, y integer) strict" not in ddl: return row
    x, y = row["x"], row["y"]
    return {**row, "x": None if x is None else (x if type(x) is str else str(x)),
            "y": y if type(y) is int else None}

def sqlite_connect(cfg):
    return cfg.exec.connect() if cfg.exec else sqlite3.connect(":memory:")

class SqliteDB:
    dialect = "sqlite"
    def __init__(self, ddl, rows, conn):
        self.c = conn
        self.c.execute(ddl)
        for r in rows:
            r = coerce_for_strict(ddl, r)
            self.c.execute("insert into t(id,tenant,x,y) values (?,?,?,?)", (r["id"], r["tenant"], r["x"], r["y"]))
        self.stored = {i: {"id": i, "tenant": t, "x": x, "y": y}
                       for (i, t, x, y) in self.c.execute("select id,tenant,x,y from t")}
    def ids(self, sql, params):
        return [r for r in self.c.execute(sql, params)]
    def close(self):
        self.c.close()

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
    def close(self): pass

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

# ----- MariaDB (P7-oracle-adapters-001, D-P7.8; q4-005). Columns are declared to the subject as IR types (text / int)
# whatever the physical collation: the adversarial collations below are what the CAST(.. AS BINARY) atoms must defeat.
MY_TAIL = "default charset=utf8mb4 engine=innodb"
MY_SCHEMAS = {
    "default utf8mb4_uca1400_ai_ci tenant,x (case+accent-insensitive, PAD SPACE)":
        f"create table t(id int primary key, tenant varchar(64), x varchar(64), y bigint) {MY_TAIL}",
    "utf8mb4_general_ci tenant,x":
        f"create table t(id int primary key, tenant varchar(64) collate utf8mb4_general_ci, x varchar(64) collate utf8mb4_general_ci, y bigint) {MY_TAIL}",
    "utf8mb4_bin tenant,x (binary but PAD SPACE)":
        f"create table t(id int primary key, tenant varchar(64) collate utf8mb4_bin, x varchar(64) collate utf8mb4_bin, y bigint) {MY_TAIL}",
    "VARBINARY tenant, utf8mb4_nopad_bin x":
        f"create table t(id int primary key, tenant varbinary(64), x varchar(64) collate utf8mb4_nopad_bin, y bigint) {MY_TAIL}",
}
MY_CEX_SCHEMAS = {
    "T": f"create table t(id int primary key, tenant varchar(64), x varchar(64), y varchar(64)) {MY_TAIL}",
    "GCI": f"create table t(id int primary key, tenant varchar(64) collate utf8mb4_general_ci, x varchar(64) collate utf8mb4_general_ci, y varchar(64)) {MY_TAIL}",
    "BIN": f"create table t(id int primary key, tenant varchar(64) collate utf8mb4_bin, x varchar(64) collate utf8mb4_bin, y varchar(64)) {MY_TAIL}",
}
MY_CEX = [   # q4-005 confusers: each would leak under a column-collation / LIKE / coercing comparison
    ("collation: tenant uca1400_ai_ci (case)", "T", ("ACME", "v", None), "acme", ["andN", []]),
    ("collation: tenant utf8mb4_general_ci (case)", "GCI", ("ACME", "v", None), "acme", ["andN", []]),
    ("PAD SPACE: tenant 'acme ' under utf8mb4_bin", "BIN", ("acme ", "v", None), "acme", ["andN", []]),
    ("PAD SPACE: tenant 'acme ' under uca1400_ai_ci", "T", ("acme ", "v", None), "acme", ["andN", []]),
    ("PAD SPACE: field 'a ' = 'a' under utf8mb4_bin", "BIN", ("acme", "a ", None), "acme", ["eq", "x", "a"]),
    ("accent-insensitive: 'ä' = 'a' under uca1400_ai_ci", "T", ("acme", "ä", None), "acme", ["eq", "x", "a"]),
    ("expansion: 'ß' = 'ss' under uca1400_ai_ci", "T", ("acme", "ß", None), "acme", ["eq", "x", "ss"]),
    ("LIKE prefix: case-insensitive", "T", ("acme", "ADMIN-x", None), "acme", ["pfx", "x", "admin"]),
    ("LIKE prefix: '_' wildcard", "BIN", ("acme", "aXb", None), "acme", ["pfx", "x", "a_"]),
    ("LIKE prefix: backslash escape", "BIN", ("acme", "a\\x", None), "acme", ["pfx", "x", "a\\"]),
    ("coercion: int literal vs VARCHAR '1'", "T", ("acme", "1", None), "acme", ["eq", "x", 1]),
    ("coercion: int literal vs VARCHAR '1e0'", "T", ("acme", "1e0", None), "acme", ["eq", "x", 1]),
    ("collation range: 'B' in ['a','b'] under uca1400_ai_ci", "T", ("acme", "B", None), "acme", ["range", "x", "a", "b"]),
    ("empty Or([]) rendered TRUE", "T", ("acme", "z", None), "acme", ["orN", []]),
    ("NULL x vs Eq", "T", ("acme", None, None), "acme", ["eq", "x", "a"]),
    ("NUL: tenant 'acme\\0evil' vs handle 'acme'", "BIN", ("acme\x00evil", "v", None), "acme", ["tt"]),
]
MY_COLS = {"id": "int", "tenant": "text", "x": "text", "y": "bigint"}

def _my_norm(v):
    return v.decode("utf-8", "surrogateescape") if isinstance(v, (bytes, bytearray)) else v

class MyDB:
    dialect = "mariadb"
    def __init__(self, my, ddl, rows, coerce):
        self.my = my
        my.simple("drop table if exists t")
        my.simple(ddl)
        for r in rows:
            r = coerce(r)
            my.query("insert into t(id,tenant,x,y) values (?,?,?,?)", (r["id"], r["tenant"], r["x"], r["y"]))
        got = my.simple("select id, tenant, x, y from t")[1]
        self.stored = {i: {"id": i, "tenant": _my_norm(t), "x": _my_norm(x), "y": _my_norm(y)} for (i, t, x, y) in got}
    def ids(self, sql, params):
        return [tuple(_my_norm(c) for c in r) for r in self.my.query(sql, params)[1]]
    def close(self): pass

# ----- CockroachDB (dialect "crdb": postgres forms; q4-005 collated-column findings)
CRDB_SCHEMAS = {
    "STRING (byte order) tenant,x; INT8 y": "create table t(id int primary key, tenant string, x string, y int8)",
    "collated en_u_ks_level2 tenant,x (case-insensitive)":
        "create table t(id int primary key, tenant string collate en_u_ks_level2, x string collate en_u_ks_level2, y int8)",
    "collated en_u_ks_level1 tenant,x (case+accent-insensitive)":
        "create table t(id int primary key, tenant string collate en_u_ks_level1, x string collate en_u_ks_level1, y int8)",
}
CRDB_CEX_SCHEMAS = {
    "T": "create table t(id int primary key, tenant string, x string, y string)",
    "CI": "create table t(id int primary key, tenant string collate en_u_ks_level2, x string collate en_u_ks_level2, y string)",
    "AI": "create table t(id int primary key, tenant string collate en_u_ks_level1, x string collate en_u_ks_level1, y string)",
}
CRDB_CEX = [
    ("collation: tenant en_u_ks_level2 (case)", "CI", ("ACME", "v", None), "acme", ["andN", []]),
    ("collation: tenant en_u_ks_level1 (case, accent)", "AI", ("Acme", "v", None), "acme", ["andN", []]),
    ("collation: field en_u_ks_level2 eq (case)", "CI", ("acme", "SECRET", None), "acme", ["eq", "x", "secret"]),
    ("collation: field en_u_ks_level1 eq (accent)", "AI", ("acme", "ä", None), "acme", ["eq", "x", "a"]),
    ("collation range: 'A' in ['a','b'] under en_u_ks_level2", "CI", ("acme", "A", None), "acme", ["range", "x", "a", "b"]),
    ("LIKE prefix '_' wildcard", "T", ("acme", "aXb", None), "acme", ["pfx", "x", "a_"]),
    ("LIKE prefix backslash escape", "T", ("acme", "a\\x", None), "acme", ["pfx", "x", "a\\"]),
    ("trailing space: 'acme ' vs 'acme'", "T", ("acme ", "v", None), "acme", ["andN", []]),
    ("empty Or([]) rendered TRUE", "T", ("acme", "z", None), "acme", ["orN", []]),
    ("NULL x vs Eq", "T", ("acme", None, None), "acme", ["eq", "x", "a"]),
]

# =========================================================================================== core check
class Stats(dict):
    KEYS = ("cases", "rows_evaluated", "leak", "widen", "miss", "gap", "leak_rows", "miss_rows", "refused",
            "errors", "theorem_violations", "unrefused")
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

def bad_handle_family(subject, dialect, cols, st):
    """Every non-canonical tenant handle must be refused (D4: the adapter binds only tenant_text(TenantId))."""
    for h in BAD_HANDLES:
        st["cases"] += 1
        rep = subject.call({"op": "read", "dialect": dialect, "table": "t", "alias": None, "param_offset": 0,
                            "tenant_field": "tenant", "columns": cols, "tenant": h, "pred": ["tt"]})
        if "refuse" not in rep:
            st["unrefused"] += 1; note(st, "UNREFUSED(non-canonical handle)", {"tenant": h, "sql": rep.get("sql")})

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

# ----- Redis / Valkey keyspace family (aegis_data_ir::kv_plan read side: Select Eq -> GET, Tt/Pfx -> SCAN MATCH).
# Logical rows (tenant, collection, key) -> value; the subject's kv_key answers give the physical keys (encoding-
# independent). A SCAN must return exactly the physical keys of the tenant's rows in that collection whose key starts
# with the prefix; a GET must return exactly the row's value. Keys must be injective (a physical key shared by two
# logical rows is a leak), non-canonical handles, invalid collections and over-long keys must be refused.
KV_HANDLES = [T(0x2), T(0x2a), T(0xa), T(0xab), T(1), A, T(2 ** 64 - 1), T(2 ** 63)]
KV_COLLS = ["c", "ac", "cc", "bc", "notes", "_x9"]       # 2 + "ac" == 2a + "c" without a delimiter (kv-naive)
KV_BAD_COLLS = ["a:b", "", "C", "1a", "a*", "a b", "x" * 64, "é", "a-b", "a}", "c:"]
KV_FIXED_KEYS = ["k1", "x:2*", "}:x", ":", "b:c", "", "*", "?", "[ab]", "\\", "a\\*", "k1*", "^", "a-c", "é", "k"]
KV_ALPHA = "ab*?[]\\:}{-^ x1"
KV_LONG_OK = "L" * 900                                   # accepted (< 1024 with any sane prefix)
KV_LONG_BAD = "L" * 1100                                 # must be refused (> KV_MAX_KEY_BYTES whatever the prefix)

class KvModel:
    """Offline string keyspace: GET / SET / SCAN MATCH via the stringmatchlen port."""
    def __init__(self): self.d = {}
    def set(self, k, v): self.d[k] = v
    def get(self, k): return self.d.get(k)
    def scan(self, pat):
        lit = L.glob_literal_prefix(pat)
        return {k for k in self.d if k.startswith(lit) and L.stringmatchlen(pat, k)}
    def flush(self): self.d = {}
    def close(self): pass

class KvLive:
    def __init__(self, url):
        self.r = L.Resp(url); self.r.cmd(b"SELECT", self.r.db); self.r.cmd(b"FLUSHDB")
        self.kind, self.version = L.kv_version(self.r)
    def set(self, k, v): self.r.cmd(b"SET", k, v)
    def get(self, k): return self.r.cmd(b"GET", k)
    def scan(self, pat):
        got, cur = set(), b"0"
        while True:
            r = self.r.cmd(b"SCAN", cur, b"MATCH", pat, b"COUNT", b"1000")
            cur, batch = r[0], r[1]; got |= set(batch)
            if cur == b"0": return got
    def flush(self): self.r.cmd(b"FLUSHDB")
    def close(self): self.flush(); self.r.close()

def kv_rand(rng, n_max=4):
    return "".join(rng.choice(KV_ALPHA) for _ in range(rng.randint(0, n_max)))

def kv_family(subject, st, store, seeds, ncases, uniq_counter=None):
    def must_refuse(req, what):
        st["cases"] += 1
        rep = subject.call(req)
        if "refuse" not in rep:
            st["unrefused"] += 1; note(st, f"UNREFUSED({what})", {"req": req, "reply": rep})
    # refusals: non-canonical handles, invalid collections, over-long keys / patterns
    for h in BAD_HANDLES:
        must_refuse({"op": "kv_scan", "tenant": h, "collection": "c", "prefix_hex": None}, "non-canonical handle")
        must_refuse({"op": "kv_key", "tenant": h, "collection": "c", "key_hex": b"k1".hex()}, "non-canonical handle")
    for c in KV_BAD_COLLS:
        must_refuse({"op": "kv_key", "tenant": A, "collection": c, "key_hex": b"k1".hex()}, "invalid collection")
        must_refuse({"op": "kv_scan", "tenant": A, "collection": c, "prefix_hex": None}, "invalid collection")
    must_refuse({"op": "kv_key", "tenant": A, "collection": "c", "key_hex": KV_LONG_BAD.encode().hex()}, "key > 1024 bytes")
    must_refuse({"op": "kv_get", "tenant": A, "collection": "c", "key_hex": KV_LONG_BAD.encode().hex()}, "key > 1024 bytes")
    must_refuse({"op": "kv_scan", "tenant": A, "collection": "c", "prefix_hex": KV_LONG_BAD.encode().hex()}, "pattern > 1024 bytes")
    for seed in seeds:
        rng = random.Random(seed * 31 + 7)
        store.flush()
        rows = {}                                          # (t, c, k) -> value
        for t in KV_HANDLES:
            for c in KV_COLLS:
                for k in rng.sample(KV_FIXED_KEYS, 6) + [kv_rand(rng, 5) for _ in range(6)]:
                    rows.setdefault((t, c, k), f"v{len(rows)}".encode())
        rows.setdefault((A, "c", KV_LONG_OK), b"vlong")
        phys, owners, refused_rows = {}, {}, set()
        for lr in rows:
            t, c, k = lr
            rep = subject.call({"op": "kv_key", "tenant": t, "collection": c, "key_hex": k.encode().hex()})
            if "refuse" in rep:
                st["refused"] += 1; refused_rows.add(lr); note(st, "REFUSED(kv_key)", {"row": lr, "reply": rep}); continue
            pk = bytes.fromhex(rep["key_hex"])
            phys[lr] = pk; owners.setdefault(pk, set()).add(lr)
        for pk, ls in owners.items():
            if len(ls) > 1:
                st["leak"] += 1; st["leak_rows"] += len(ls) - 1
                note(st, "LEAK(key collision)", {"key": pk.decode("latin1"), "rows": sorted(ls)[:2]})
        for lr, pk in phys.items(): store.set(pk, rows[lr])
        # cases: unique (kind, t, c, arg)
        seen = set(); attempts = 0
        by_tc = {}
        for (t, c, k) in rows: by_tc.setdefault((t, c), []).append(k)
        all_keys = [k for (_, _, k) in rows]
        while len(seen) < ncases and attempts < ncases * 20:
            attempts += 1
            t, c = rng.choice(KV_HANDLES), rng.choice(KV_COLLS)
            kind = rng.choice(["scan", "scan", "get", "get", "tt"])
            r = rng.random()
            if kind == "tt": arg = None
            elif r < 0.5:
                k = rng.choice(by_tc[(t, c)]); arg = k[:rng.randint(0, len(k))] if kind == "scan" else k
            elif r < 0.75:
                k = rng.choice(all_keys); arg = k[:rng.randint(0, len(k))] if kind == "scan" else k
            else:
                arg = kv_rand(rng)
            ck = (kind, t, c, arg)
            if ck in seen: continue
            seen.add(ck)
            st["cases"] += 1
            if kind in ("scan", "tt"):
                p = "" if arg is None else arg
                rep = subject.call({"op": "kv_scan", "tenant": t, "collection": c,
                                    "prefix_hex": None if arg is None else arg.encode().hex()})
                if "refuse" in rep: st["refused"] += 1; note(st, "REFUSED(kv_scan)", {"case": ck}); continue
                pat = bytes.fromhex(rep["pattern_hex"])
                got = store.scan(pat)
                sat = lambda l: l[0] == t and l[1] == c and l[2].startswith(p)
                permit = {pk for pk, ls in owners.items() if all(sat(l) for l in ls)}
                want = {phys[l] for l in phys if sat(l)}
                leak, miss = got - permit, want - got
                st["rows_evaluated"] += len(phys)
                if leak: st["leak"] += 1; st["leak_rows"] += len(leak); note(st, "LEAK(scan)", {"case": ck, "pattern": pat.decode("latin1"), "key": min(leak).decode("latin1")})
                if miss: st["miss"] += 1; st["miss_rows"] += len(miss); note(st, "MISS(scan)", {"case": ck, "pattern": pat.decode("latin1")})
            else:
                rep = subject.call({"op": "kv_get", "tenant": t, "collection": c, "key_hex": arg.encode().hex()})
                if "refuse" in rep: st["refused"] += 1; note(st, "REFUSED(kv_get)", {"case": ck}); continue
                cmds = [[bytes.fromhex(x) for x in cm] for cm in rep.get("commands", [])]
                if len(cmds) != 1 or len(cmds[0]) != 2 or cmds[0][0].upper() != b"GET":
                    st["errors"] += 1; note(st, "error(kv_get must be one GET <key>)", {"case": ck, "reply": rep}); continue
                got = store.get(cmds[0][1])
                want = rows.get((t, c, arg)) if (t, c, arg) not in refused_rows else None
                st["rows_evaluated"] += 1
                if got is not None and got != want:
                    st["leak"] += 1; st["leak_rows"] += 1; note(st, "LEAK(get)", {"case": ck, "got": got.decode("latin1")})
                elif got is None and want is not None:
                    st["miss"] += 1; st["miss_rows"] += 1; note(st, "MISS(get)", {"case": ck})
        if uniq_counter is not None: uniq_counter[0] += len(seen)
    store.flush()

# =========================================================================================== drivers
def run_sqlite(subject, cfg, log):
    fam = {}
    def fs(name):
        return fam.setdefault(name, Stats())
    tag = f"sqlite {cfg.sqlite_version}"
    # F0 non-canonical handles
    bad_handle_family(subject, "sqlite", {"id": "integer", "tenant": "text", "x": "", "y": ""}, fs(f"{tag} non-canonical tenant handles (must refuse)"))
    # F1 cex single-cause corpus
    st = fs(f"{tag} cex(research 78-case corpus, SQLite part + in-repo regressions)")
    for (name, ddl, (tn, x, y), t, p, _naive) in CEX:
        db = SqliteDB(ddl, [{"id": 1, "tenant": S(tn), "x": x, "y": y}], sqlite_connect(cfg))
        cols = {"id": "integer", "tenant": "", "x": "", "y": ""}
        db.idx = index_by_tenant(db.stored)
        check_case(subject, db, cols, H(t), p, st, cfg.miss_vs_2vl)
        db.close()
    # F2 research replay on the 4 research seeds, research schemas, 400 rows x 3000 cases
    skipped = 0
    if cfg.research:
        for seed in cfg.seeds:
            rows, cases, sk = research_corpus(seed, 400, cfg.research_cases)
            skipped += sk
            for sname in RESEARCH_SCHEMAS:
                ddl, cols = SQLITE_SCHEMAS[sname]
                db = SqliteDB(ddl, rows, sqlite_connect(cfg)); db.idx = index_by_tenant(db.stored)
                st = fs(f"{tag} research-replay | {sname}")
                for t, p in cases: check_case(subject, db, cols, t, p, st, cfg.miss_vs_2vl)
                db.close()
        log(f"  research replay: {skipped} cases skipped (float literal, not a Lean Value)")
    # F3 Lean-faithful generated corpus (NOT, tt/ff, n-ary, mixed-class ranges, NUL, int64 edges) x 5 schemas
    for seed in cfg.seeds:
        rows, cases = lean_corpus(seed, cfg.rows, cfg.cases)
        for sname, (ddl, cols) in SQLITE_SCHEMAS.items():
            db = SqliteDB(ddl, rows, sqlite_connect(cfg)); db.idx = index_by_tenant(db.stored)
            st = fs(f"{tag} lean-generated | {sname}")
            for t, p in cases: check_case(subject, db, cols, t, p, st, cfg.miss_vs_2vl)
            db.close()
    # F4 self-join family (60-row table)
    for seed in cfg.seeds:
        rng = random.Random(seed + 4242)
        rows, _ = lean_corpus(seed + 1, 60, 0)
        cases = [(rng.choice(G_HANDLES), g_pred(rng), g_pred(rng), rng.choice(["join", "exists"])) for _ in range(cfg.selfjoin)]
        for sname, (ddl, cols) in SQLITE_SCHEMAS.items():
            db = SqliteDB(ddl, rows, sqlite_connect(cfg)); db.idx = index_by_tenant(db.stored)
            st = fs(f"{tag} self-join | {sname}")
            for t, pa, pb, shape in cases: check_selfjoin(subject, db, cols, t, pa, pb, shape, st)
            db.close()
    return fam, skipped

def run_pg(subject, cfg, dsn, log, versions):
    pg = L.Pg(dsn)
    v = L.pg_version(pg)
    versions.append(("postgres", v, dsn))
    log(f"  postgres server_version {v}")
    pg_setup(pg)
    tag = f"pg{v}"
    fam = {}
    bad_handle_family(subject, "postgres", PG_COLS, fam.setdefault(f"{tag} non-canonical tenant handles (must refuse)", Stats()))
    st = fam.setdefault(f"{tag} cex (research 78-case corpus, PG part)", Stats())
    for (name, sk, (tn, x, y), t, p) in PG_CEX:
        db = PgDB(pg, PG_CEX_SCHEMAS[sk], [{"id": 1, "tenant": S(tn), "x": x, "y": y}], lambda r: r)
        db.idx = index_by_tenant(db.stored)
        check_case(subject, db, {"id": "int", "tenant": "text", "x": "text", "y": "text"}, H(t), p, st, cfg.miss_vs_2vl)
    for seed in cfg.seeds:
        rows, cases = lean_corpus(seed, cfg.rows, cfg.pg_cases, nul=False)
        for sname, ddl in PG_SCHEMAS.items():
            db = PgDB(pg, ddl, rows, pg_coerce); db.idx = index_by_tenant(db.stored)
            st = fam.setdefault(f"{tag} lean-generated | {sname}", Stats())
            for t, p in cases: check_case(subject, db, PG_COLS, t, p, st, cfg.miss_vs_2vl)
        rng = random.Random(seed + 4242)
        rows2, _ = lean_corpus(seed + 1, 60, 0, nul=False)
        lits, pf = [v for v in G_LITS if _nn(v)], [v for v in G_PFX if _nn(v)]
        sj = [(rng.choice(G_HANDLES), g_pred(rng, lits=lits, pfx=pf), g_pred(rng, lits=lits, pfx=pf),
               rng.choice(["join", "exists"])) for _ in range(max(1, cfg.selfjoin // 2))]
        db = PgDB(pg, PG_SCHEMAS["deterministic default collation"], rows2, pg_coerce); db.idx = index_by_tenant(db.stored)
        st = fam.setdefault(f"{tag} self-join | deterministic default collation", Stats())
        for t, pa, pb, shape in sj:
            check_selfjoin(subject, db, PG_COLS, t, pa, pb, shape, st)
    pg.simple("drop table if exists t")
    pg.close()
    return fam

def run_sqlx(subject, cfg, engine, dsn, log, versions):
    """MariaDB (engine "mariadb") or CockroachDB (engine "crdb"): non-canonical handles, the engine's cex corpus, the
    Lean-generated corpus over every schema (cfg.my_cases / cfg.crdb_cases per seed) and the self-join family."""
    fam = {}
    if engine == "mariadb":
        conn = M.my_connect(dsn); v = M.my_version(conn); versions.append(("mariadb", v, dsn)); tag = f"mariadb{v}"
        mk = lambda ddl, rows, co: MyDB(conn, ddl, rows, co)
        schemas, cex_schemas, cex, ncases, nul, cols = MY_SCHEMAS, MY_CEX_SCHEMAS, MY_CEX, cfg.my_cases, True, MY_COLS
        cexcols = {"id": "int", "tenant": "text", "x": "text", "y": "text"}
    else:
        conn = L.Pg(dsn); v = M.crdb_version(conn); versions.append(("crdb", v, dsn)); tag = f"crdb{v}"
        mk = lambda ddl, rows, co: PgDB(conn, ddl, rows, co)
        schemas, cex_schemas, cex, ncases, nul, cols = CRDB_SCHEMAS, CRDB_CEX_SCHEMAS, CRDB_CEX, cfg.crdb_cases, False, PG_COLS
        cexcols = {"id": "int", "tenant": "text", "x": "text", "y": "text"}
    log(f"  {engine} version {v}")
    dialect = engine
    bad_handle_family(subject, dialect, cols, fam.setdefault(f"{tag} non-canonical tenant handles (must refuse)", Stats()))
    st = fam.setdefault(f"{tag} cex (q4-005 collation / PAD SPACE / LIKE / coercion confusers)", Stats())
    for (name, sk, (tn, x, y), t, p) in cex:
        db = mk(cex_schemas[sk], [{"id": 1, "tenant": S(tn), "x": x, "y": y}], lambda r: r)
        db.dialect = dialect; db.idx = index_by_tenant(db.stored)
        check_case(subject, db, cexcols, H(t), p, st, cfg.miss_vs_2vl)
    lits, pf = [v_ for v_ in G_LITS if nul or _nn(v_)], [v_ for v_ in G_PFX if nul or _nn(v_)]
    for seed in cfg.seeds:
        rows, cases = lean_corpus(seed, cfg.rows, ncases, nul=nul)
        for sname, ddl in schemas.items():
            db = mk(ddl, rows, pg_coerce); db.dialect = dialect; db.idx = index_by_tenant(db.stored)
            st = fam.setdefault(f"{tag} lean-generated | {sname}", Stats())
            for t, p in cases: check_case(subject, db, cols, t, p, st, cfg.miss_vs_2vl)
        rng = random.Random(seed + 4242)
        rows2, _ = lean_corpus(seed + 1, 60, 0, nul=nul)
        sj = [(rng.choice(G_HANDLES), g_pred(rng, lits=lits, pfx=pf), g_pred(rng, lits=lits, pfx=pf),
               rng.choice(["join", "exists"])) for _ in range(max(1, cfg.selfjoin // 2))]
        sname = next(iter(schemas))
        db = mk(schemas[sname], rows2, pg_coerce); db.dialect = dialect; db.idx = index_by_tenant(db.stored)
        st = fam.setdefault(f"{tag} self-join | {sname}", Stats())
        for t, pa, pb, shape in sj:
            check_selfjoin(subject, db, cols, t, pa, pb, shape, st)
    (conn.simple("drop table if exists t"), conn.close())
    return fam

def evaluate(subject, cfg, log=print):
    t0 = time.time()
    fams, versions, counts = {}, [], {"sqlite": 0, "pg": 0, "redis": 0, "mariadb": 0, "crdb": 0}
    skipped = 0
    if "sqlite" in cfg.engines:
        f, skipped = run_sqlite(subject, cfg, log); fams.update(f)
        versions.append(("sqlite", cfg.sqlite_version, None))
        counts["sqlite"] = cfg.cases * len(cfg.seeds)
    if "pg" in cfg.engines:
        for dsn in cfg.dsns:
            fams.update(run_pg(subject, cfg, dsn, log, versions))
        counts["pg"] = cfg.pg_cases * len(cfg.seeds)
    for eng, dsns, n in (("mariadb", cfg.my_dsns, cfg.my_cases), ("crdb", cfg.crdb_dsns, cfg.crdb_cases)):
        if eng in cfg.engines:
            for dsn in dsns:
                fams.update(run_sqlx(subject, cfg, eng, dsn, log, versions))
            counts[eng] = n * len(cfg.seeds)
    if "redis" in cfg.engines:
        per = []
        for url in cfg.urls:
            store = KvLive(url)
            versions.append((store.kind, store.version, url))
            uc = [0]
            kv_family(subject, fams.setdefault(f"{store.kind}{store.version} keyspace (live GET / SCAN MATCH)", Stats()),
                      store, cfg.seeds, cfg.kv_cases, uc)
            store.close(); per.append(uc[0])
        counts["redis"] = min(per) if per else 0
    elif "sqlite" in cfg.engines:
        uc = [0]
        kv_family(subject, fams.setdefault("redis keyspace (offline stringmatchlen model)", Stats()), KvModel(),
                  cfg.seeds, cfg.kv_cases, uc)
        counts["redis_model"] = uc[0]
    tot = Stats()
    for s in fams.values(): tot.add(s)
    return fams, tot, skipped, time.time() - t0, versions, counts

def verdict(tot, cfg, min_cases):
    bad = {k: tot[k] for k in ("leak", "widen", "miss", "errors", "refused", "theorem_violations", "unrefused") if tot[k]}
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
        self.engines = set(a.engine) - ({"sqlite"} if a.skip_sqlite else set())
        sp = M.split_dsns(list(a.dsn or []), self.engines)
        self.dsns, self.urls = sp["pg"], list(a.url or [])
        self.my_dsns, self.crdb_dsns = sp["mariadb"], sp["crdb"]
        self.my_cases, self.crdb_cases = a.my_cases, a.crdb_cases
        self.pg_cases = a.pg_cases
        self.kv_cases = a.kv_cases
        self.miss_vs_2vl = a.miss_vs_2vl
        self.exec = getattr(a, "_exec", None)
        self.sqlite_version = self.exec.version if self.exec else sqlite3.sqlite_version

def print_report(fams, tot, skipped, wall, log=print, quiet=False):
    if not quiet:
        log(f"{'family':76s} {'cases':>7s} {'leak':>5s} {'widen':>5s} {'miss':>5s} {'gap':>5s} {'err':>4s} {'ref':>4s} {'unref':>5s}")
        for n, s in fams.items():
            log(f"{n[:76]:76s} {s['cases']:7d} {s['leak']:5d} {s['widen']:5d} {s['miss']:5d} {s['gap']:5d} {s['errors']:4d} {s['refused']:4d} {s['unrefused']:5d}")
            for ex in s["examples"][:1]:
                if s["leak"] or s["widen"] or s["miss"] or s["errors"] or s["unrefused"] or s["refused"]:
                    log("    e.g. " + json.dumps(ex, ensure_ascii=True, default=str)[:400])
    log(f"total: cases={tot['cases']} rows_evaluated={tot['rows_evaluated']} leak={tot['leak']} widen={tot['widen']} "
        f"miss={tot['miss']} gap_vs_2vl(not_absent_gap, info)={tot['gap']} errors={tot['errors']} refused={tot['refused']} "
        f"unrefused={tot['unrefused']} theorem_violations={tot['theorem_violations']} research_skipped_float={skipped} wall={wall:.1f}s")

def pin_results(versions, pins_path):
    pins = L.load_pins(pins_path)
    return [L.pin_check(pins, kind, ver, url) for kind, ver, url in versions]

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
    ("lenient-handle", "unrefused"),
    ("kv-no-escape", "leak"),
    ("kv-no-keycap", "unrefused"),
    ("kv-collection-colon", "unrefused"),
]
ENGINE_MUTANTS = {
    "pg": [("pg-no-collate-c", "leak"), ("naive-bound", "leak"), ("like-prefix", "leak"), ("two-valued-not", "widen"),
           ("drop-tenant", "leak"), ("lenient-handle", "unrefused")],
    "redis": [("kv-naive", "leak"), ("kv-escaped-colon", "leak"), ("kv-no-escape", "leak"), ("drop-tenant", "leak")],
    # P7-oracle-adapters-001: every SQL-renderer mutant of the SQLite / PG lists that the dialect can express, plus the
    # q4-005 engine-specific ones
    "mariadb": [("drop-tenant", "leak"), ("two-valued-not", "widen"), ("or-precedence", "leak"), ("like-prefix", "leak"),
                ("empty-or-true", "leak"), ("naive-bound", "leak"), ("range-exclusive", "miss"), ("selfjoin-alias", "leak"),
                ("refuse-all", "miss"), ("lenient-handle", "unrefused"),
                ("my-column-collation", "leak"), ("my-bin-padspace", "leak")],
    "crdb": [("drop-tenant", "leak"), ("two-valued-not", "widen"), ("or-precedence", "leak"), ("like-prefix", "leak"),
             ("empty-or-true", "leak"), ("naive-bound", "leak"), ("range-exclusive", "miss"), ("selfjoin-alias", "leak"),
             ("refuse-all", "miss"), ("lenient-handle", "unrefused"), ("crdb-column-collation", "leak")],
}
EXT_ENGINES = ("mariadb", "crdb")

def pin_selftest():
    """--engine-pin logic: a matching allow pin passes; a version mismatch, an unknown version and a blocked pin fail."""
    pins = {"sqlite": {"version": "3.54.1"}, "engines": {
        "pg17": {"kind": "postgres", "version": "17.11", "policy": "allow"},
        "pg19rc1": {"kind": "postgres", "version": "19rc1", "policy": "blocked", "blocked_reason": "R-DB-8"},
        "valkey": {"kind": "valkey", "version": "9.1.2", "policy": "allow"},
        "mariadb": {"kind": "mariadb", "version": "11.8.9", "policy": "allow"},
        "crdb": {"kind": "crdb", "version": "25.4.19", "policy": "allow"}}}
    env = {"AEGIS_ENGINE_PG17": "postgresql://x@127.0.0.1:1/postgres"}
    checks = [
        (L.pin_check(pins, "sqlite", "3.54.1")[0], True),
        (L.pin_check(pins, "sqlite", sqlite3.sqlite_version)[0], sqlite3.sqlite_version == "3.54.1"),
        (L.pin_check(pins, "postgres", "17.11", "postgresql://x@127.0.0.1:1/postgres", env)[0], True),
        (L.pin_check(pins, "postgres", "17.10", "postgresql://x@127.0.0.1:1/postgres", env)[0], False),
        (L.pin_check(pins, "postgres", "18.6", "postgresql://other", env)[0], False),
        (L.pin_check(pins, "postgres", "19rc1", "postgresql://other", env)[0], False),
        (L.pin_check(pins, "redis", "9.1.2", "redis://other", env)[0], False),
        (L.pin_check(pins, "valkey", "9.1.2", "redis://other", env)[0], True),
        (L.pin_check(pins, "mariadb", "11.8.9", "mysql://other", env)[0], True),
        (L.pin_check(pins, "mariadb", "11.8.8", "mysql://other", env)[0], False),
        (L.pin_check(pins, "crdb", "25.4.19", "postgresql://other", env)[0], True),
        (L.pin_check(pins, "postgres", "25.4.19", "postgresql://other", env)[0], False),
    ]
    return all(got == want for got, want in checks), len(checks)

def small_ns(a, engines):
    s = argparse.Namespace(**vars(a))
    s.seeds = [20261025]; s.cases_per_seed = 600; s.rows = 120; s.no_research = True
    s.selfjoin = 120; s.engine = engines; s.pg_cases = 400; s.kv_cases = 400; s.skip_sqlite = False
    s.my_cases = s.crdb_cases = 400
    return s

def self_test(a):
    live = [e for e in (a.engine or []) if e in ("pg", "redis") + EXT_ENGINES]
    use_sqlite = not a.skip_sqlite
    if not use_sqlite and not live:
        print(f"{NAME} SELF-TEST: FAIL (--skip-sqlite without any --engine pg/redis/mariadb/crdb leaves nothing to test)"); return 1
    ref = lambda muts=(), eng=None: M.ExtLocalSubject(muts) if eng in EXT_ENGINES else L.LocalSubject(muts)
    caught, n, lines = 0, 0, []
    repro_ok = rn_ok = True
    if use_sqlite:
        cfg = Cfg(small_ns(a, ["sqlite"]))
        for mut, counter in SELFTEST_MUTANTS:
            fams, tot, _, wall, _, _ = evaluate(mutant_subject(mut), cfg, log=lambda *x: None)
            bad = verdict(tot, cfg, 1)
            ok = bool(bad) and tot.get(counter, 0) > 0
            caught += ok; n += 1
            print(f"  mutant {mut:21s} expect {counter:9s}>0: leak={tot['leak']} widen={tot['widen']} miss={tot['miss']} "
                  f"errors={tot['errors']} unrefused={tot['unrefused']} -> {'CAUGHT' if ok else 'NOT CAUGHT'} ({wall:.1f}s)", flush=True)
        # naive-bound must reproduce every research LEAK verdict of the 78-case corpus (SQLite part), case by case
        naive = L.LocalSubject(["naive-bound"])
        for (name, ddl, (tn, x, y), t, p, want) in CEX:
            if want != "LEAK": continue
            db = SqliteDB(ddl, [{"id": 1, "tenant": S(tn), "x": x, "y": y}], sqlite3.connect(":memory:")); db.idx = index_by_tenant(db.stored)
            st = Stats(); check_case(naive, db, {"id": "integer", "tenant": "", "x": "", "y": ""}, H(t), p, st)
            if not st["leak"]:
                repro_ok = False; print(f"  research cex not reproduced by naive-bound: {name}")
        print(f"  naive-bound reproduces all {sum(1 for c in CEX if c[5] == 'LEAK')} research SQLite LEAK verdicts: {repro_ok}")
        # Lean counter-theorem refines_necessary: a coarser equality (NOCASE) on the tenant column must leak (model check)
        coarse = L.Backend(lambda x, v: L.veq(x.lower() if type(x) is str else x, v.lower() if type(v) is str else v), L.ref_range, L.ref_prefix)
        row = {"tenant": A.upper()}
        rn_ok = L.keeps(coarse, row, L.lowerQ("tenant", A, ["tt"])) and not refQ3("tenant", A, row, ["tt"])
        # the gate is refQ3, not the 2VL refQ: the two q4-004 witnesses must separate them (not_absent_gap,
        # inList_nil_not_const_false) -- a NULL x with NOT (x = v) / NOT (x in []) is 2VL-permitted and 3VL-denied
        nul = {"tenant": A, "x": None}
        gap_ok = all(L.refQ("tenant", A, nul, q) and not refQ3("tenant", A, nul, q)
                     for q in (["not", ["eq", "x", "a"]], ["not", ["in", "x", []]]))
        print(f"  refQ3 vs refQ witnesses (not_absent_gap, NOT In [] on NULL: 2VL permits, 3VL denies): {gap_ok}")
        rn_ok = rn_ok and gap_ok
        print(f"  refines_necessary witness (NOCASE backend keeps a row refQ rejects): {rn_ok}")
    # optional live backends: the same gate must go red on the engine-specific mutants
    pos_ok = True
    for eng in live:
        c2 = Cfg(small_ns(a, [eng]))
        _, tot, _, _, vers, _ = evaluate(ref((), eng), c2, log=lambda *x: None)
        ok = not verdict(tot, c2, 1)
        print(f"  [{eng} {' '.join(v for _, v, _ in vers)}] positive control (reference): cases={tot['cases']} leak={tot['leak']} "
              f"widen={tot['widen']} miss={tot['miss']} -> {'PASS' if ok else 'FAIL'}")
        pos_ok = pos_ok and ok
        for mut, counter in ENGINE_MUTANTS[eng]:
            _, tot, _, _, _, _ = evaluate(ref([mut], eng), c2, log=lambda *x: None)
            okm = tot.get(counter, 0) > 0
            n += 1; caught += okm
            print(f"  [{eng}] mutant {mut:16s} expect {counter}>0: leak={tot['leak']} widen={tot['widen']} miss={tot['miss']} "
                  f"errors={tot['errors']} unrefused={tot['unrefused']} -> {'CAUGHT' if okm else 'NOT CAUGHT'}")
    # positive control through the out-of-process --subject protocol (the given --subject, else lowir.py serve),
    # and the same command with --mutant drop-tenant must go red (proves the subject path is really checked)
    ctl = Cfg(small_ns(a, (["sqlite"] if use_sqlite else []) + live))
    cmd = a.subject or (M.reference_cmd(HERE) if set(live) & set(EXT_ENGINES) else L.reference_cmd(HERE))
    sub = L.ProcSubject(cmd)
    _, tot, _, wall, _, _ = evaluate(sub, ctl, log=lambda *x: None); sub.close()
    ok = not verdict(tot, ctl, 1)
    pos_ok = pos_ok and ok
    print(f"  positive control via --subject {cmd!r}: cases={tot['cases']} leak={tot['leak']} widen={tot['widen']} "
          f"miss={tot['miss']} errors={tot['errors']} refused={tot['refused']} unrefused={tot['unrefused']} -> {'PASS' if ok else 'FAIL'} ({wall:.1f}s)")
    sub = L.ProcSubject(cmd + " --mutant drop-tenant")
    _, tot2, _, _, _, _ = evaluate(sub, ctl, log=lambda *x: None); sub.close()
    proc_mut_ok = tot2["leak"] > 0
    print(f"  {cmd + ' --mutant drop-tenant'!r} via --subject: leak={tot2['leak']} -> {'CAUGHT' if proc_mut_ok else 'NOT CAUGHT'}")
    pin_ok, npin = pin_selftest()
    print(f"  --engine-pin logic ({npin} fixtures: match passes; mismatch / unknown / blocked / wrong kind fail): {pin_ok}")
    if caught == n and repro_ok and pos_ok and proc_mut_ok and rn_ok and pin_ok:
        print(f"{NAME} SELF-TEST: PASS ({caught}/{n} mutants caught; research naive LEAKs reproduced; positive control PASS; "
              f"subject drop-tenant caught; pin fixtures {npin}/{npin})")
        return 0
    print(f"{NAME} SELF-TEST: FAIL ({caught}/{n} mutants caught; repro={repro_ok}; positive_control={pos_ok}; "
          f"subject_drop_tenant={proc_mut_ok}; refines_necessary={rn_ok}; pin={pin_ok})")
    return 1

# =========================================================================================== main
def main():
    ap = argparse.ArgumentParser(prog="run", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--subject", help="command speaking the line protocol (README.md); default: in-process reference renderer")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--engine", action="append", choices=["sqlite", "pg", "redis", "mariadb", "crdb"], help="repeatable; default sqlite")
    ap.add_argument("--dsn", action="append", help="postgresql://user:pw@host:port/db (pg, crdb) or mysql://user:pw@host:port/db "
                    "(mariadb), repeatable (throwaway databases: tables are dropped); a postgresql DSN is CockroachDB iff the "
                    "server's version() says so")
    ap.add_argument("--url", action="append", help="redis://host:port/db, repeatable (throwaway db: it is FLUSHDB'ed)")
    ap.add_argument("--skip-sqlite", action="store_true", help="no SQLite families (kv-only or pg-only subjects); also in --self-test")
    ap.add_argument("--engine-pin", action="store_true", help="check every engine against supply-chain/engine-pins.toml and "
                    "put the versions in the PASS line (implies --sqlite-exec when SQLite runs)")
    ap.add_argument("--sqlite-exec", action="store_true", help="run SQLite at the adapter pin through rust/sqlite-exec "
                    "(built via ci/heavy.sh, target deleted afterwards) instead of Python's sqlite3")
    ap.add_argument("--pins", default=os.path.join(L.repo_root(HERE), "supply-chain", "engine-pins.toml"))
    ap.add_argument("--seeds", type=lambda s: [int(x) for x in s.split(",")], default=SEEDS)
    ap.add_argument("--cases-per-seed", type=int, default=3000)
    ap.add_argument("--big", action="store_true", help="25000 generated cases per seed for SQLite, PG and Redis "
                    "(>=100k unique per engine with the default 4 seeds)")
    ap.add_argument("--rows", type=int, default=200)
    ap.add_argument("--selfjoin", type=int, default=250, help="self-join cases per seed")
    ap.add_argument("--pg-cases", type=int, default=1500)
    ap.add_argument("--kv-cases", type=int, default=2500, help="unique Redis keyspace cases per seed")
    ap.add_argument("--my-cases", type=int, default=25000, help="MariaDB generated cases per seed (default: >=100k per engine)")
    ap.add_argument("--crdb-cases", type=int, default=25000, help="CockroachDB generated cases per seed (default: >=100k per engine)")
    ap.add_argument("--no-research", action="store_true", help="skip the research-replay family")
    ap.add_argument("--miss-vs-2vl", action="store_true",
                    help="information: count GAP (permitted by the old two-valued refQ, denied by refQ3) as MISS")
    ap.add_argument("--json", help="write the full report here")
    a = ap.parse_args()
    if not a.engine: a.engine = ["sqlite"]
    if "pg" in a.engine and not a.dsn: ap.error("--engine pg needs --dsn")
    if "redis" in a.engine and not a.url: ap.error("--engine redis needs --url")
    for e in EXT_ENGINES:
        if e in a.engine and not a.dsn: ap.error(f"--engine {e} needs --dsn")
    if a.big: a.cases_per_seed = a.pg_cases = a.kv_cases = 25000
    if a.self_test:
        sys.exit(self_test(a))
    cleanup = None
    a._exec = None
    try:
        if (a.sqlite_exec or a.engine_pin) and "sqlite" in a.engine and not a.skip_sqlite:
            binary, cleanup = L.build_sqlite_exec(HERE)
            a._exec = L.SqliteExec(binary)
        cfg = Cfg(a)
        subject = L.make_subject(a.subject) if (a.subject or not set(cfg.engines) & set(EXT_ENGINES)) else M.ExtLocalSubject()
        print(f"{NAME}: subject={subject.name} engines={sorted(cfg.engines)} sqlite={cfg.sqlite_version}"
              f"{' (sqlite-exec helper)' if cfg.exec else ' (python stdlib)'} seeds={cfg.seeds} "
              f"cases/seed={cfg.cases} rows={cfg.rows} pg_cases/seed={cfg.pg_cases} kv_cases/seed={cfg.kv_cases}", flush=True)
        fams, tot, skipped, wall, versions, counts = evaluate(subject, cfg)
        subject.close()
    finally:
        if a._exec: a._exec.close()
        if cleanup: cleanup()
    print_report(fams, tot, skipped, wall)
    bad = verdict(tot, cfg, 1)
    pins_txt = ""
    if a.engine_pin:
        res = pin_results(versions, a.pins)
        for ok, label in res:
            print(f"  engine-pin: {label} -> {'OK' if ok else 'MISMATCH'}")
        if not all(ok for ok, _ in res): bad["engine_pin"] = "; ".join(l for ok, l in res if not ok)
        pins_txt = " engine_pin=[" + ", ".join(l for _, l in res) + "]"
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"families": fams, "total": tot, "skipped_float": skipped, "wall_s": wall, "bad": bad,
                       "versions": versions, "unique_cases": counts}, fh, indent=1, ensure_ascii=True, default=str)
    gen = sum(s["cases"] for n, s in fams.items() if " lean-generated | " in n and n.startswith("sqlite"))
    uniq = " ".join(f"{k}={v}" for k, v in counts.items() if k in ("sqlite", "pg", "redis", "mariadb", "crdb") and v or k == "redis_model")
    summary = (f"cases={tot['cases']} generated_unique[{uniq}] (sqlite x{len(SQLITE_SCHEMAS)} schemas={gen}; pg x{len(PG_SCHEMAS)} schemas "
               f"x{len(cfg.dsns) if 'pg' in cfg.engines else 0} engines) leak={tot['leak']} widen={tot['widen']} miss={tot['miss']} "
               f"gap_vs_2vl(info)={tot['gap']} errors={tot['errors']} unrefused={tot['unrefused']}{pins_txt}")
    if bad:
        print(f"{NAME}: FAIL ({', '.join(f'{k}={v}' for k, v in bad.items())}; {summary})")
        sys.exit(1)
    print(f"{NAME}: PASS ({summary})")

if __name__ == "__main__":
    main()
