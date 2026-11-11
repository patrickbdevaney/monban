#!/usr/bin/env python3
"""Monban write-path differential oracle: INV-WRITE-SUBSET W1/W2/W4/W6 (+W3 via W1, +W7 for Redis), SPEC_INVARIANTS E.

Per case the subject renders ONE statement (UPDATE / DELETE / INSERT / UPSERT, or Redis commands); the oracle runs
it in a transaction that is rolled back, diffs the WHOLE table (all tenants) pre vs post, and checks
  W1  every changed key's pre-image has tenant t and (update/delete) satisfies Pred (Lean `eval`)
  W2  every changed key's post-image has tenant t; for UPDATE, columns outside SET are unchanged
  W3  (upsert) the arbiter never selects a foreign row -- observed as a W1 violation on the foreign pre-image
  W4  RETURNING columns are within the permitted projection and every returned row is a tenant-t pre/post image
  W6  uniform failure: an INSERT's outcome (ok / error class / RETURNING / own rows) is identical whether or not
      another tenant holds a row with the same key or the referenced parent (no existence oracle)
  W7  (Redis) replies contain no key or value of another tenant
  E   effect: the post-state and RETURNING set equal what the Lean model predicts for a correct renderer
  FORM mandated forms: one statement starting with the op's verb; no MERGE, no WITH (CTE), no REPLACE / IGNORE /
      INSERT OR ..., no ';'; an upsert names its conflict key (ON CONFLICT (...)).
  BIND (PG RLS family) the per-request tenant binding is gone after COMMIT/ROLLBACK (pool checkin)
  ACL  (Redis kv_acl family) the per-tenant ACL user holds only t:{<hex>}:* and refuses every hostile command
  REFUSE requests that must be refused (non-canonical tenant handle, merge/cte/replace/raw_sql ops, invalid KV
      collection, KV key > 1024 bytes) were answered.
Ill-formed requests (SET of the tenant column, a request row carrying a tenant, upsert without a composite key) must
be refused or be W-safe; they get W checks but no effect check.  Engine errors count as blocked (fail-closed); a
blocked or refused WELL-FORMED request is an effect violation.
Tenant handles are the D4 encoding (TenantId u64 as 16 lower-case hex digits).
"""
import argparse, json, os, random, re, sqlite3, sys, time, urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)
import lowir as L  # noqa: E402
import lowmy as M  # noqa: E402  (MariaDB / CockroachDB dialects; lowir.py stays byte-identical and unmodified)

NAME = "LOWERING-WRITE"
SEEDS = [1, 2, 3, 20261025]
COLS = ["id", "tenant", "grp", "x", "y", "secret"]
PERMITTED = ["id", "tenant", "grp", "x", "y"]          # `secret` is never in a permitted projection
T = L.tenant_text
A = T(0xacce55)
# research wporacle.TEN mapped to D4: canonical tenants are handles; the confusers (ACME, Acme, 'acme ') are stored
# values that NOCASE / PAD SPACE would equate with A (never handles).
TEN_HANDLES = [A, T(0xa25), T(0xe1), T(0x55), T(0xdf)]
TEN = TEN_HANDLES + [A.upper(), "0000000000Acce55", A + " "]

def mkrows(rng, n=60):    # research wporacle.mkrows + secret column
    return [dict(id=i + 1, tenant=rng.choice(TEN), grp=rng.choice(["g1", "g2", "g3"]),
                 x=rng.choice(["a", "A", "ab", "1", "10", "", "a%b", "ä", "z", None]), y=str(rng.choice([0, 1, 2, 10])),
                 secret=f"s{i + 1}") for i in range(n)]

LITS = ["a", "A", "ab", "1", "10", "", "a%b", "ä", "z", "g1", "g2", "0", "2", 1, 10, 0]
PFX = ["a", "A", "", "1", "a%", "a_", "g"]
BAD_HANDLES = [A.upper(), A + " ", A[1:], "0" * 16, A + "\x00", "", "acme", "g" * 16, 0xacce55]

def gpred(rng, depth=0):
    f = rng.choice(["x", "y", "grp"])
    if depth >= 3 or rng.random() < 0.45:
        k = rng.choice(["eq", "eq", "in", "range", "pfx", "tt"])
        if k == "tt": return ["tt"]
        if k == "eq": return ["eq", f, rng.choice(LITS)]
        if k == "in": return ["in", f, rng.sample(LITS, rng.choice([0, 1, 2, 3]))]
        if k == "range":
            c = rng.choice([int, str]); pool = [v for v in LITS if type(v) is c]
            a, b = sorted([rng.choice(pool), rng.choice(pool)]); return ["range", f, a, b]
        return ["pfx", f, rng.choice(PFX)]
    k = rng.choice(["and", "or", "not", "andN", "orN"])
    if k == "not": return ["not", gpred(rng, depth + 1)]
    if k in ("and", "or"): return [k, gpred(rng, depth + 1), gpred(rng, depth + 1)]
    return [k, [gpred(rng, depth + 1) for _ in range(rng.choice([0, 1, 2]))]]

# =========================================================================================== engines
SQ = {  # name -> (ddl, key)
    "plain id PK": ("create table t(id integer primary key, tenant text not null, grp text, x text, y text, secret text)", ["id"]),
    "composite PK (tenant,id)": ("create table t(id integer, tenant text not null, grp text, x text, y text, secret text, primary key (tenant,id))", ["tenant", "id"]),
    "NOCASE tenant, id PK": ("create table t(id integer primary key, tenant text collate nocase not null, grp text, x text, y text, secret text)", ["id"]),
    "STRICT composite PK": ("create table t(id integer, tenant text not null, grp text, x text, y text, secret text, primary key (tenant,id)) strict", ["tenant", "id"]),
    "untyped composite PK": ("create table t(id, tenant not null, grp, x, y, secret, primary key (tenant,id))", ["tenant", "id"]),
}
SQ_GATE_ONLY = {  # schemas the adapter schema gate must refuse; run for information, never part of the verdict
    "NOCASE tenant composite PK (schema gate must refuse)": ("create table t(id integer, tenant text collate nocase not null, grp text, x text, y text, secret text, primary key (tenant,id))", ["tenant", "id"]),
}
# W6 schemas: (ddl list, key, unique keys, fks). Parent table p holds the referenced groups.
W6_SQ = {   # name -> (ddl list, key, unique keys, fks, unique key has tenant, fk has tenant)
    "composite PK + composite FK (tenant,grp)->p(tenant,gid)": (
        ["create table p(tenant text not null, gid text not null, primary key (tenant,gid))",
         "create table t(id integer, tenant text not null, grp text, x text, y text, secret text, primary key (tenant,id), "
         "foreign key (tenant,grp) references p(tenant,gid))"],
        ["tenant", "id"], [["tenant", "id"]],
        [{"columns": ["tenant", "grp"], "ref_table": "p", "ref_columns": ["tenant", "gid"], "ref_tenant_field": "tenant"}], True, True),
    "global id PK + composite FK": (
        ["create table p(tenant text not null, gid text not null, primary key (tenant,gid))",
         "create table t(id integer primary key, tenant text not null, grp text, x text, y text, secret text, "
         "foreign key (tenant,grp) references p(tenant,gid))"],
        ["id"], [["id"]],
        [{"columns": ["tenant", "grp"], "ref_table": "p", "ref_columns": ["tenant", "gid"], "ref_tenant_field": "tenant"}], False, True),
    "composite PK + global FK grp->p(gid)": (
        ["create table p(tenant text not null, gid text primary key)",
         "create table t(id integer, tenant text not null, grp text, x text, y text, secret text, primary key (tenant,id), "
         "foreign key (grp) references p(gid))"],
        ["tenant", "id"], [["tenant", "id"]],
        [{"columns": ["grp"], "ref_table": "p", "ref_columns": ["gid"], "ref_tenant_field": "tenant"}], True, False),
}
PG = {
    "plain id PK": ("create table t(id int primary key, tenant text not null, grp text, x text, y text, secret text)", ["id"]),
    "composite PK (tenant,id)": ("create table t(id int, tenant text not null, grp text, x text, y text, secret text, primary key (tenant,id))", ["tenant", "id"]),
    "nondeterministic ICU tenant, id PK": ("create table t(id int primary key, tenant text collate ci_nd not null, grp text, x text, y text, secret text)", ["id"]),
}
PG_GATE_ONLY = {
    "nondeterministic ICU tenant composite PK (schema gate must refuse)": ("create table t(id int, tenant text collate ci_nd not null, grp text, x text, y text, secret text, primary key (tenant,id))", ["tenant", "id"]),
}
W6_PG = {k: ([d.replace("integer", "int") for d in v[0]],) + v[1:] for k, v in W6_SQ.items()}

# ----- MariaDB (P7-oracle-adapters-001, D-P7.8; spikes/q4-005). x/y/grp keep the server default collation
# (utf8mb4_uca1400_ai_ci: case- AND accent-insensitive, PAD SPACE), deliberately adversarial for the atoms.
MY_ENG = "default charset=utf8mb4 engine=innodb"
MY_T = "tenant varchar(32)"
MY_REST = "grp varchar(16), x varchar(16), y varchar(16), secret varchar(16)"
MARIA = {
    "plain id PK, tenant utf8mb4_general_ci": (f"create table t(id int primary key, {MY_T} collate utf8mb4_general_ci not null, {MY_REST}) {MY_ENG}", ["id"]),
    "plain id PK, tenant default uca1400_ai_ci": (f"create table t(id int primary key, {MY_T} not null, {MY_REST}) {MY_ENG}", ["id"]),
    "composite PK, tenant utf8mb4_nopad_bin": (f"create table t(id int, {MY_T} collate utf8mb4_nopad_bin not null, {MY_REST}, primary key (tenant,id)) {MY_ENG}", ["tenant", "id"]),
    "composite PK, tenant VARBINARY": (f"create table t(id int, tenant varbinary(64) not null, {MY_REST}, primary key (tenant,id)) {MY_ENG}", ["tenant", "id"]),
}
MARIA_GATE_ONLY = {   # q4-005 W3 counterexamples: the schema gate must refuse them; information only
    "composite PK, tenant utf8mb4_bin (PAD SPACE; schema gate must refuse)": (f"create table t(id int, {MY_T} collate utf8mb4_bin not null, {MY_REST}, primary key (tenant,id)) {MY_ENG}", ["tenant", "id"]),
    "composite PK, tenant utf8mb4_general_ci (schema gate must refuse)": (f"create table t(id int, {MY_T} collate utf8mb4_general_ci not null, {MY_REST}, primary key (tenant,id)) {MY_ENG}", ["tenant", "id"]),
    "composite PK, tenant default uca1400_ai_ci (schema gate must refuse)": (f"create table t(id int, {MY_T} not null, {MY_REST}, primary key (tenant,id)) {MY_ENG}", ["tenant", "id"]),
    "composite PK nopad_bin + second UNIQUE(id) (schema gate must refuse)": (f"create table t(id int, {MY_T} collate utf8mb4_nopad_bin not null, {MY_REST}, primary key (tenant,id), unique key (id)) {MY_ENG}", ["tenant", "id"]),
}
_NB = "collate utf8mb4_nopad_bin"
W6_MY = {
    "composite PK + composite FK (tenant,grp)->p(tenant,gid)": (
        [f"create table p(tenant varchar(32) {_NB} not null, gid varchar(16) {_NB} not null, primary key (tenant,gid)) {MY_ENG}",
         f"create table t(id int, tenant varchar(32) {_NB} not null, grp varchar(16) {_NB}, x varchar(16), y varchar(16), secret varchar(16), "
         f"primary key (tenant,id), foreign key (tenant,grp) references p(tenant,gid)) {MY_ENG}"],) + W6_SQ["composite PK + composite FK (tenant,grp)->p(tenant,gid)"][1:],
    "global id PK + composite FK": (
        [f"create table p(tenant varchar(32) {_NB} not null, gid varchar(16) {_NB} not null, primary key (tenant,gid)) {MY_ENG}",
         f"create table t(id int primary key, tenant varchar(32) {_NB} not null, grp varchar(16) {_NB}, x varchar(16), y varchar(16), secret varchar(16), "
         f"foreign key (tenant,grp) references p(tenant,gid)) {MY_ENG}"],) + W6_SQ["global id PK + composite FK"][1:],
    "composite PK + global FK grp->p(gid)": (
        [f"create table p(tenant varchar(32) {_NB} not null, gid varchar(16) {_NB} primary key) {MY_ENG}",
         f"create table t(id int, tenant varchar(32) {_NB} not null, grp varchar(16) {_NB}, x varchar(16), y varchar(16), secret varchar(16), "
         f"primary key (tenant,id), foreign key (grp) references p(gid)) {MY_ENG}"],) + W6_SQ["composite PK + global FK grp->p(gid)"][1:],
}
# ----- CockroachDB (dialect "crdb"; spikes/q4-005)
CRDB = {
    "plain id PK": ("create table t(id int primary key, tenant string not null, grp string, x string, y string, secret string)", ["id"]),
    "composite PK (tenant,id)": ("create table t(id int, tenant string not null, grp string, x string, y string, secret string, primary key (tenant,id))", ["tenant", "id"]),
    "collated tenant en_u_ks_level2, id PK": ("create table t(id int primary key, tenant string collate en_u_ks_level2 not null, grp string, x string, y string, secret string)", ["id"]),
}
CRDB_GATE_ONLY = {
    "composite PK, tenant collate en_u_ks_level2 (schema gate must refuse)": ("create table t(id int, tenant string collate en_u_ks_level2 not null, grp string, x string, y string, secret string, primary key (tenant,id))", ["tenant", "id"]),
    "composite PK + second UNIQUE(id) (schema gate must refuse)": ("create table t(id int, tenant string not null, grp string, x string, y string, secret string, primary key (tenant,id), unique (id))", ["tenant", "id"]),
}
W6_CRDB = W6_PG

class SqliteEng:
    dialect = "sqlite"
    def __init__(self, ddl, rows, conn, parents=None):
        self.c = conn
        self.c.execute("pragma foreign_keys = on")
        for d in (ddl if isinstance(ddl, list) else [ddl]): self.c.execute(d)
        for (t, g) in (parents or []): self.c.execute("insert into p(tenant,gid) values (?,?)", (t, g))
        for r in rows:
            self.c.execute("insert into t(id,tenant,grp,x,y,secret) values (?,?,?,?,?,?)", tuple(r[c] for c in COLS))
        self.decl = {r[1]: (r[2] or "") for r in self.c.execute("pragma table_info(t)")}
    def snap(self):
        return [dict(zip(COLS, r)) for r in self.c.execute("select id,tenant,grp,x,y,secret from t")]
    def begin(self): self.c.execute("begin")
    def rollback(self): self.c.execute("rollback")
    def exec(self, sql, params): self.c.execute(sql, params)
    def run(self, sql, params):
        cur = self.c.execute(sql, params)
        if cur.description is None: return [], []
        names = [d[0] for d in cur.description]
        return names, [tuple(r) for r in cur.fetchall()]
    def errclass(self, e): return "integrity" if "constraint" in str(e).lower() else type(e).__name__
    def close(self): self.c.close()

class PgEng:
    dialect = "postgres"
    def __init__(self, pg, ddl, rows, parents=None):
        self.pg = pg
        pg.simple("drop table if exists t"); pg.simple("drop table if exists p")
        for d in (ddl if isinstance(ddl, list) else [ddl]): pg.simple(d)
        for (t, g) in (parents or []): pg.query("insert into p(tenant,gid) values ($1,$2)", (t, g))
        for r in rows:
            pg.query("insert into t(id,tenant,grp,x,y,secret) values ($1,$2,$3,$4,$5,$6)", tuple(r[c] for c in COLS))
        self.decl = {"id": "int", "tenant": "text", "grp": "text", "x": "text", "y": "text", "secret": "text"}
    def snap(self):
        return [dict(zip(COLS, r)) for r in self.pg.query("select id,tenant,grp,x,y,secret from t")[1]]
    def begin(self): self.pg.simple("begin")
    def rollback(self): self.pg.simple("rollback")
    def exec(self, sql, params): self.pg.query(L.placeholders_qmark_to_dollar(sql), params)
    def run(self, sql, params):
        names, rows = self.pg.query(sql, params)
        return (names or []), rows
    def errclass(self, e): return getattr(e, "sqlstate", "") or type(e).__name__
    def close(self): pass

def _my_norm(v):
    return v.decode("utf-8", "surrogateescape") if isinstance(v, (bytes, bytearray)) else v

class MariaEng:
    dialect = "mariadb"
    def __init__(self, my, ddl, rows, parents=None):
        self.my = my
        my.simple("drop table if exists t"); my.simple("drop table if exists p")
        for d in (ddl if isinstance(ddl, list) else [ddl]): my.simple(d)
        for (t, g) in (parents or []): my.query("insert into p(tenant,gid) values (?,?)", (t, g))
        for r in rows:
            my.query("insert into t(id,tenant,grp,x,y,secret) values (?,?,?,?,?,?)", tuple(r[c] for c in COLS))
        self.decl = {"id": "int", "tenant": "text", "grp": "text", "x": "text", "y": "text", "secret": "text"}
    def snap(self):
        return [dict(zip(COLS, map(_my_norm, r))) for r in self.my.query("select id,tenant,grp,x,y,secret from t")[1]]
    def begin(self): self.my.simple("begin")
    def rollback(self): self.my.simple("rollback")
    def exec(self, sql, params): self.my.query(sql, params)
    def run(self, sql, params):
        names, rows = self.my.query(sql, params)
        return (names or []), [tuple(map(_my_norm, r)) for r in rows]
    def run_reply(self, rep):
        """MariaDB has no UPDATE .. RETURNING: a requested RETURNING arrives as rep["returning_select"] (SELECT ..
        FOR UPDATE with the same lowered WHERE), run immediately before the statement in the same transaction; its
        rows are the statement's RETURNING rows (checked by W4 / E like any RETURNING)."""
        rs = rep.get("returning_select")
        if rs:
            names, rows = self.run(rs["sql"], rs.get("params") or [])
            self.run(rep["sql"], rep["params"])
            return names, rows
        return self.run(rep["sql"], rep["params"])
    def errclass(self, e): return getattr(e, "state", "") or type(e).__name__
    def close(self): pass

class CrdbEng(PgEng):
    dialect = "crdb"

# =========================================================================================== checks
class Stats(dict):
    KEYS = ("cases", "W1", "W2", "W4", "W6", "W7", "E", "FORM", "REFUSE", "BIND", "ACL", "blocked", "refused", "illformed", "errors_wellformed")
    def __init__(self):
        super().__init__({k: 0 for k in self.KEYS}); self["examples"] = []
    def add(self, o):
        for k in self.KEYS: self[k] += o[k]
        self["examples"] += o["examples"][: max(0, 3 - len(self["examples"]))]
    def viol(self, kind, ex):
        self[kind] += 1
        if len(self["examples"]) < 3: self["examples"].append(ex)

def kf(key):
    return lambda r: tuple(r[c] for c in key)

def model_keeps(t, p, r):
    return L.keeps(L.EXACT, r, L.lowerQ("tenant", t, p))

VERB = {"update": "UPDATE", "delete": "DELETE", "insert": "INSERT", "upsert": "INSERT"}
FORBIDDEN_WORDS = {"MERGE", "WITH", "REPLACE", "IGNORE", "RULE"}

def form_violation(op, sql, dialect=None, req=None):
    """Mandated forms (SPEC E): one statement, verb first, no MERGE / CTE / REPLACE / IGNORE / INSERT OR, ON CONFLICT
    names its key. Returns a reason or None."""
    w = L.sql_words(sql)
    if not w or w[0] != VERB[op]: return f"statement does not start with {VERB[op]}"
    if ";" in w: return "';' (more than one statement)"
    bad = FORBIDDEN_WORDS & set(w)
    if bad: return f"forbidden keyword(s) {sorted(bad)}"
    if w[0] == "INSERT" and len(w) > 1 and w[1] == "OR": return "INSERT OR ... (REPLACE/IGNORE family)"
    for i in range(len(w) - 1):
        if w[i] == "ON" and w[i + 1] == "CONFLICT" and (i + 2 >= len(w) or w[i + 2] != "("):
            return "ON CONFLICT without a named conflict key"
    if op == "upsert" and "CONFLICT" not in w and dialect != "mariadb": return "upsert without ON CONFLICT"
    if dialect == "mariadb": return my_form(op, sql, req or {})
    if dialect == "crdb": return crdb_form(op, sql, req or {})
    return None

# ----- dialect forms (P7-oracle-adapters-001; q4-005 mandated forms and denylist). Token-level, outside literals.
def sql_tokens(sql):
    """Like lowir.sql_words, but quoted identifiers keep their name as "I:<name>"; bare words are upper-cased."""
    out, i, n = [], 0, len(sql)
    while i < n:
        c = sql[i]
        if c in "'\"`":
            j = i + 1
            while j < n:
                if sql[j] == c:
                    if j + 1 < n and sql[j + 1] == c: j += 2; continue
                    break
                j += 1
            out.append("<lit>" if c == "'" else "I:" + sql[i + 1:j].replace(c + c, c)); i = j + 1
        elif sql.startswith("--", i):
            j = sql.find("\n", i); i = n if j < 0 else j + 1
        elif sql.startswith("/*", i):
            j = sql.find("*/", i + 2); i = n if j < 0 else j + 2
        elif c.isalpha() or c == "_":
            j = i
            while j < n and (sql[j].isalnum() or sql[j] in "_$"): j += 1
            out.append(sql[i:j].upper()); i = j
        elif c.isspace():
            i += 1
        else:
            out.append(c); i += 1
    return out

def _is_id(tok, name):
    return tok == "I:" + name or tok == str(name).upper()

def _split_top(toks, sep=","):
    parts, cur, depth = [], [], 0
    for t in toks:
        if t == "(": depth += 1
        elif t == ")": depth -= 1
        if t == sep and depth == 0: parts.append(cur); cur = []
        else: cur.append(t)
    parts.append(cur)
    return parts

def _top_index(toks, word, start=0):
    depth = 0
    for i in range(len(toks)):
        t = toks[i]
        if t == "(": depth += 1
        elif t == ")": depth -= 1
        elif i >= start and depth == 0 and t == word: return i
    return -1

def my_form(op, sql, req):
    """MariaDB mandated forms: no ON CONFLICT (not MariaDB) and no UPDATE .. RETURNING (use returning_select); an
    upsert with update columns is ON DUPLICATE KEY UPDATE whose EVERY assignment is the tenant-guarded
    `c = IF(CAST(t AS BINARY) = CAST(VALUES(t) AS BINARY), VALUES(c), c)`; an upsert without update columns is
    `INSERT .. SELECT .. FROM DUAL WHERE NOT EXISTS (SELECT ..)` (never INSERT IGNORE)."""
    tk = sql_tokens(sql)
    w = [x for x in tk if not x.startswith("I:")]
    if "CONFLICT" in w: return "ON CONFLICT is not a MariaDB form"
    if op == "update" and "RETURNING" in w: return "UPDATE .. RETURNING (MariaDB has none; requested RETURNING goes in returning_select)"
    if op != "upsert": return None
    tf, key = req.get("tenant_field", "tenant"), list(req.get("key") or [])
    if req.get("update"):
        i = next((k for k in range(len(tk) - 3) if tk[k:k + 4] == ["ON", "DUPLICATE", "KEY", "UPDATE"]), -1)
        if i < 0: return "upsert with update columns without ON DUPLICATE KEY UPDATE"
        tail = tk[i + 4:]
        r = _top_index(tail, "RETURNING")
        if r >= 0: tail = tail[:r]
        for a in _split_top(tail):
            if len(a) != 28 or a[1] != "=": return "ON DUPLICATE KEY UPDATE assignment is not the tenant-guarded IF(..) form"
            c = a[0]
            if any(_is_id(c, k) for k in [tf] + key): return "ON DUPLICATE KEY UPDATE assigns the tenant / a key column"
            want = ["IF", "(", "CAST", "(", None, "AS", "BINARY", ")", "=", "CAST", "(", "VALUES", "(", None, ")", "AS",
                    "BINARY", ")", ",", "VALUES", "(", c, ")", ",", c, ")"]
            got = a[2:]
            if not all((x is None and _is_id(y, tf)) or x == y for x, y in zip(want, got)):
                return "ON DUPLICATE KEY UPDATE assignment lacks the CAST(t AS BINARY) = CAST(VALUES(t) AS BINARY) guard"
        return None
    if "DUPLICATE" in w: return "upsert without update columns must not use ON DUPLICATE KEY UPDATE"
    if not any(tk[k:k + 7] == ["FROM", "DUAL", "WHERE", "NOT", "EXISTS", "(", "SELECT"] for k in range(len(tk))):
        return "upsert without update columns is not INSERT .. SELECT .. FROM DUAL WHERE NOT EXISTS (SELECT ..)"
    return None

def crdb_form(op, sql, req):
    """CockroachDB: never the UPSERT statement (primary-key arbiter, no guard); DO UPDATE must carry exactly the q4-005
    guard `WHERE <table>.<tenant>::text = excluded.<tenant>::text COLLATE "C"` (the postgres guard without the casts
    is case-insensitive on a collated tenant column on CockroachDB)."""
    tk = sql_tokens(sql)
    if "UPSERT" in tk: return "UPSERT statement (CockroachDB denylist)"
    if op != "upsert": return None
    k = next((j for j in range(len(tk) - 1) if tk[j:j + 2] == ["DO", "UPDATE"]), -1)
    if k < 0: return None
    j = _top_index(tk, "WHERE", k)
    if j < 0: return "ON CONFLICT DO UPDATE without the tenant guard"
    g = tk[j + 1:]
    r = _top_index(g, "RETURNING")
    if r >= 0: g = g[:r]
    tf, tbl = req.get("tenant_field", "tenant"), req.get("table", "t")
    want = [("id", tbl), ".", ("id", tf), ":", ":", "TEXT", "=", "EXCLUDED", ".", ("id", tf), ":", ":", "TEXT", "COLLATE", "I:C"]
    if len(g) != len(want) or not all((_is_id(y, x[1]) if isinstance(x, tuple) else x == y) for x, y in zip(want, g)):
        return 'upsert guard is not <t>.<tenant>::text = excluded.<tenant>::text COLLATE "C" (q4-005 CockroachDB fix)'
    return None

def reply_form(op, rep, req):
    """FORM over a whole reply: the statement, plus MariaDB's returning_select (SELECT .. FOR UPDATE, update only)."""
    d = req.get("dialect")
    fv = form_violation(op, rep["sql"], d, req)
    if fv: return fv
    rs = rep.get("returning_select")
    if rs is None: return None
    if d != "mariadb" or op != "update": return "returning_select is only the MariaDB UPDATE RETURNING emulation"
    if not isinstance(rs, dict) or not isinstance(rs.get("sql"), str): return "malformed returning_select"
    w = L.sql_words(rs["sql"])
    if not w or w[0] != "SELECT": return "returning_select does not start with SELECT"
    if ";" in w or FORBIDDEN_WORDS & set(w): return "returning_select: ';' or forbidden keyword"
    if w[-2:] != ["FOR", "UPDATE"]: return "returning_select is not ... FOR UPDATE (rows must be locked before the UPDATE)"
    return None

def expected(op, t, req, pre, key):
    """Post-state and RETURNING rows a correct renderer produces (Lean model over an exact backend)."""
    k = kf(key)
    post = {k(r): dict(r) for r in pre}
    ret = []
    proj = lambda r: tuple(r[c] for c in req["returning"])
    if op == "update":
        for kk, r in list(post.items()):
            if model_keeps(t, req["pred"], r):
                r.update(req["set"]); ret.append(proj(r))
    elif op == "delete":
        for kk, r in list(post.items()):
            if model_keeps(t, req["pred"], r):
                ret.append(proj(r)); del post[kk]
    else:
        row = dict(req["row"], tenant=t)
        nk = tuple(row[c] for c in key)
        if nk in post:
            if op == "upsert" and req["update"]:
                post[nk].update({c: row[c] for c in req["update"]}); ret.append(proj(post[nk]))
        else:
            new = {c: row.get(c) for c in COLS}; post[nk] = new; ret.append(proj(new))
    return post, sorted(ret, key=repr)

def check(st, op, t, req, wellformed, pre, post, names, rows, key, ex):
    k = kf(key)
    preI = {k(r): r for r in pre}; postI = {k(r): r for r in post}
    viol = []
    for kk in set(preI) | set(postI):
        a, b = preI.get(kk), postI.get(kk)
        if a == b: continue
        if a is not None:
            if not L.veq(a["tenant"], t): viol.append(("W1", f"changed foreign pre-image tenant={a['tenant']!r} id={a['id']}"))
            elif op in ("update", "delete") and not L.ev(a, req["pred"]): viol.append(("W1", f"pre-image outside Pred id={a['id']}"))
        if b is not None:
            if not L.veq(b["tenant"], t): viol.append(("W2", f"post-image tenant={b['tenant']!r} id={b['id']}"))
            elif op == "update" and a is not None:
                for c in COLS:
                    if c not in req["set"] and a[c] != b[c]: viol.append(("W2", f"column {c} outside SET changed id={b['id']}")); break
    # W4: permitted projection and tenant-owned images only
    perm = set(req.get("returning") or [])
    extra = [n for n in names if n not in perm]
    if extra: viol.append(("W4", f"RETURNING columns beyond permitted: {extra}"))
    imgs = [r for r in pre if L.veq(r["tenant"], t)] + [r for r in post if L.veq(r["tenant"], t)]
    for row in rows:
        d = dict(zip(names, row))
        if "tenant" in d and not L.veq(d["tenant"], t): viol.append(("W4", f"RETURNING row of tenant {d['tenant']!r}")); continue
        if not any(all(img.get(n) == v for n, v in d.items() if n in img) for img in imgs):
            viol.append(("W4", "RETURNING row is not a tenant-t pre/post image"))
    if wellformed:
        epost, eret = expected(op, t, req, pre, key)
        got_ret = sorted(rows, key=repr) if names == list(req["returning"]) else None
        if postI != epost or (got_ret is not None and got_ret != eret) or (rows and got_ret is None):
            viol.append(("E", "effect differs from the Lean model (post-state or RETURNING set)"))
    seen = set()
    for kind, msg in viol:
        if kind in seen: continue
        seen.add(kind); st.viol(kind, dict(ex, violation=f"{kind}: {msg}"))
    return viol

def run_case(st, eng, subject, op, t, req, wellformed, key):
    st["cases"] += 1
    if not wellformed: st["illformed"] += 1
    rep = subject.call(req)
    pre = eng.snap()
    ex = {"op": op, "tenant": t, "req": {k: v for k, v in req.items() if k not in ("columns",)}}
    if "refuse" in rep:
        st["refused"] += 1
        if wellformed:
            check(st, op, t, req, True, pre, pre, [], [], key, dict(ex, refused=rep["refuse"]))
        return
    ex["sql"] = rep["sql"]
    fv = reply_form(op, rep, req)
    if fv: st.viol("FORM", dict(ex, violation=f"FORM: {fv}"))
    eng.begin()
    try:
        names, rows = eng.run_reply(rep) if hasattr(eng, "run_reply") else eng.run(rep["sql"], rep["params"])
        post = eng.snap()
    except Exception as e:
        st["blocked"] += 1
        try: eng.rollback()
        except Exception: pass
        if wellformed:
            st["errors_wellformed"] += 1
            check(st, op, t, req, True, pre, pre, [], [], key, dict(ex, error=str(e)[:200]))
        return
    eng.rollback()
    check(st, op, t, req, wellformed, pre, post, names, rows, key, ex)

def sql_families(eng_factory, dialect, schemas, subject, cfg, fams, prefix=""):
    for sname, (ddl, key) in schemas.items():
        composite = "tenant" in key
        for seed in cfg.seeds:
            rng = random.Random(seed)
            rows = mkrows(random.Random(20261025 + seed), 60)
            eng = eng_factory(ddl, rows)
            base = {"dialect": dialect, "table": "t", "tenant_field": "tenant", "key": key, "unique": [key], "columns": eng.decl}
            # U: update with lowered Pred; 10% hostile SET tenant
            st = fams.setdefault(f"{prefix}U update SET .. WHERE lowerQ RETURNING | {sname}", Stats())
            for _ in range(cfg.n):
                t = rng.choice(TEN_HANDLES); p = gpred(rng)
                sets = {"x": rng.choice(["U", "a", ""])} if rng.random() < 0.7 else {"x": "U", "y": "u"}
                hostile = rng.random() < 0.1
                if hostile: sets = dict(sets, tenant=rng.choice([x for x in TEN_HANDLES if x != t]))
                req = dict(base, op="update", tenant=t, pred=p, set=sets, returning=rng.choice([["id", "tenant", "x"], ["id", "x"], ["id"]]))
                run_case(st, eng, subject, "update", t, req, not hostile, key)
            st = fams.setdefault(f"{prefix}D delete WHERE lowerQ RETURNING | {sname}", Stats())
            for _ in range(cfg.n):
                t = rng.choice(TEN_HANDLES); p = gpred(rng)
                req = dict(base, op="delete", tenant=t, pred=p, returning=rng.choice([["id", "tenant", "x", "y"], ["id"]]))
                run_case(st, eng, subject, "delete", t, req, True, key)
            fam = "UP upsert composite arbiter (tenant,id)" if composite else "UPG upsert on global-key table (must refuse or be W-safe)"
            st = fams.setdefault(f"{prefix}{fam} | {sname}", Stats())
            for _ in range(cfg.n):
                t = rng.choice(TEN_HANDLES)
                row = {"id": rng.randint(1, 70), "grp": "g1", "x": "N", "y": "n"}
                hostile = rng.random() < 0.1
                if hostile: row["tenant"] = rng.choice([x for x in TEN_HANDLES if x != t])
                upd = rng.choice([["x"], ["x", "y"], []])
                req = dict(base, op="upsert", tenant=t, row=row, update=upd, returning=rng.choice([["id", "tenant", "x"], ["id", "x"]]))
                run_case(st, eng, subject, "upsert", t, req, composite and not hostile, key)
            if hasattr(eng, "close"): eng.close()

# ----- W6 uniform failure: run the same rendered INSERT on S0 (no foreign row with that key / parent) and S1 (a
# foreign tenant holds it); the outcomes must be indistinguishable. Inserted ids/groups are fresh, so the own
# outcome is fixed by the own rows alone.
def outcome(eng, sql, params, extra, t):
    eng.begin()
    try:
        for s, ps in extra: eng.exec(s, ps)
        names, rows = eng.run(sql, params)
        own = sorted((tuple(r[c] for c in COLS) for r in eng.snap() if L.veq(r["tenant"], t)), key=repr)
        res = ("ok", tuple(names), tuple(sorted(rows, key=repr)), tuple(own))
    except Exception as e:
        res = ("err", eng.errclass(e))
    try: eng.rollback()
    except Exception: pass
    return res

def w6_family(eng_factory, dialect, schemas, subject, cfg, fams, prefix=""):
    for sname, (ddl, key, uniq, fks, ucomp, fcomp) in schemas.items():
        composite = ucomp and fcomp           # the reference accepts (and E applies) only when both carry the tenant
        st = fams.setdefault(f"{prefix}W6 insert, foreign key / existence uniform | {sname}", Stats())
        for seed in cfg.seeds:
            rng = random.Random(seed + 66)
            rows = mkrows(random.Random(20261025 + seed), 40)
            groups = ["g1", "g2", "g3"]
            parents = sorted({(r["tenant"], r["grp"]) for r in rows}) if fcomp else [(A, g) for g in groups]
            eng = eng_factory(ddl, rows, parents)
            base = {"dialect": dialect, "table": "t", "tenant_field": "tenant", "key": key, "unique": uniq,
                    "fks": fks, "columns": eng.decl}
            for i in range(cfg.n):
                st["cases"] += 1
                t = rng.choice(TEN_HANDLES); v = rng.choice([x for x in TEN_HANDLES if x != t])
                nid = 1000 + i
                if rng.random() < 0.5:   # unique-key existence: foreign row with the same id in S1
                    g = next((pg for (pt, pg) in parents if pt == t), None) if fcomp else "g1"
                    row = {"id": nid, "grp": g, "x": "N", "y": "n"}
                    extra = [("insert into t(id,tenant,grp,x,y,secret) values (?,?,?,?,?,?)",
                              [nid, v, next((pg for (pt, pg) in parents if pt == v), None) if fcomp else "g1", "F", "f", "sF"])]
                else:                    # FK existence: a foreign parent for a fresh group exists in S1 only
                    g = f"gx{i}"
                    row = {"id": nid, "grp": g, "x": "N", "y": "n"}
                    extra = [("insert into p(tenant,gid) values (?,?)", [v, g])]
                if g is None: st["cases"] -= 1; continue
                req = dict(base, op="insert", tenant=t, row=row, returning=["id", "x"])
                rep = subject.call(req)
                ex = {"op": "insert", "schema": sname, "tenant": t, "row": row}
                if "refuse" in rep:
                    st["refused"] += 1
                    if composite and not g.startswith("gx"):
                        st.viol("E", dict(ex, violation="E: well-formed insert refused", refused=rep["refuse"]))
                    continue
                fv = reply_form("insert", rep, req)
                if fv: st.viol("FORM", dict(ex, violation=f"FORM: {fv}", sql=rep["sql"]))
                o0 = outcome(eng, rep["sql"], rep["params"], [], t)
                o1 = outcome(eng, rep["sql"], rep["params"], extra, t)
                if o0 != o1:
                    st.viol("W6", dict(ex, violation=f"W6: outcome depends on another tenant's row: {o0[:2]} vs {o1[:2]}", sql=rep["sql"]))
                # effect on S0: an own parent exists (composite) and the id is fresh -> must succeed with the row
                if composite and not g.startswith("gx"):
                    want = (nid, t, g, "N", "n", None)
                    if o0[0] != "ok" or want not in o0[3]:
                        st.viol("E", dict(ex, violation=f"E: well-formed insert did not insert the row: {o0[:2]}"))
            eng.close()

# ----- requests that must be refused: non-canonical handles, merge / data-modifying CTE / replace / raw SQL ops
def refusal_family(subject, dialect, st):
    base = {"dialect": dialect, "table": "t", "tenant_field": "tenant", "key": ["tenant", "id"], "unique": [["tenant", "id"]],
            "columns": {c: "text" for c in COLS}, "returning": ["id"]}
    reqs = []
    for h in BAD_HANDLES:
        reqs.append(dict(base, op="update", tenant=h, pred=["tt"], set={"x": "U"}))
        reqs.append(dict(base, op="upsert", tenant=h, row={"id": 1, "x": "N"}, update=["x"]))
    for op in L.REFUSED_OPS:
        reqs.append(dict(base, op=op, tenant=A, pred=["tt"], set={"x": "U"}, row={"id": 1, "x": "N"}, update=["x"],
                         sql="DELETE FROM t"))
    for r in reqs:
        st["cases"] += 1
        rep = subject.call(r)
        if "refuse" not in rep:
            st.viol("REFUSE", {"op": r["op"], "tenant": r["tenant"], "violation": f"REFUSE: answered {str(rep)[:160]}"})

# =========================================================================================== Redis / Valkey
KV_TEN = [T(0x2), T(0x2a), T(0xa), T(0xab), A, T(2 ** 64 - 1)]
KV_COLLS = ["c", "ac", "cc"]
KV_KEYS = ["k1", "k2", "b:c", "x:b:c", "}:x", "*", "", "x:k1", "?", "[a]"]
KV_BAD_COLLS = ["a:b", "", "C", "a*", "c:"]

class KVModel:
    """Offline model of the string subset of the Redis keyspace (SET [NX|XX] GET DEL)."""
    def __init__(self): self.d = {}
    def cmd(self, *a):
        c = a[0].upper()
        if c == b"SET":
            opt = {x.upper() for x in a[3:]}
            if b"NX" in opt and a[1] in self.d: return None
            if b"XX" in opt and a[1] not in self.d: return None
            self.d[a[1]] = a[2]; return b"OK"
        if c == b"GET": return self.d.get(a[1])
        if c in (b"DEL", b"UNLINK"):
            n = 0
            for k in a[1:]:
                if k in self.d: del self.d[k]; n += 1
            return n
        return L.RespError(f"model: unsupported command {c!r}")
    def snap(self): return dict(self.d)
    def keys(self): return list(self.d)
    def scan(self, pat):
        lit = L.glob_literal_prefix(pat)
        return {k for k in self.d if k.startswith(lit) and L.stringmatchlen(pat, k)}
    def restore(self, before): self.d = dict(before)
    def close(self): pass

class KVLive:
    def __init__(self, url):
        self.r = L.Resp(url); self.r.cmd(b"SELECT", self.r.db); self.r.cmd(b"FLUSHDB")
        self.kind, self.version = L.kv_version(self.r)
    def cmd(self, *a): return self.r.cmd(*a)
    def snap(self):
        return {k: self.r.cmd(b"GET", k) for k in self.r.cmd(b"KEYS", b"*")}
    def scan(self, pat):
        got, cur = set(), b"0"
        while True:
            r = self.r.cmd(b"SCAN", cur, b"MATCH", pat, b"COUNT", b"1000"); cur = r[0]; got |= set(r[1])
            if cur == b"0": return got
    def restore(self, before):
        now = self.snap()
        for k in now:
            if k not in before: self.r.cmd(b"DEL", k)
        for k, v in before.items():
            if now.get(k) != v: self.r.cmd(b"SET", k, v)
    def close(self): self.r.cmd(b"FLUSHDB"); self.r.close()

def kv_family(subject, cfg, st, eng):
    cmds = lambda rep: [[bytes.fromhex(x) for x in c] for c in rep["commands"]]
    def must_refuse(req, what):
        st["cases"] += 1
        rep = subject.call(req)
        if "refuse" not in rep: st.viol("REFUSE", {"req": req, "violation": f"REFUSE: {what} answered"})
    for h in BAD_HANDLES:
        must_refuse({"op": "kv_set", "tenant": h, "collection": "c", "key_hex": b"k1".hex(), "value_hex": b"x".hex()}, "non-canonical handle")
    for c in KV_BAD_COLLS:
        must_refuse({"op": "kv_set", "tenant": A, "collection": c, "key_hex": b"k1".hex(), "value_hex": b"x".hex()}, "invalid collection")
    must_refuse({"op": "kv_set", "tenant": A, "collection": "c", "key_hex": (b"L" * 1100).hex(), "value_hex": b"x".hex()}, "key > 1024 bytes")
    owner, val_owner, phys = {}, {}, {}
    for i, t in enumerate(KV_TEN):
        for c in KV_COLLS:
            for j, s in enumerate(KV_KEYS):
                v = f"v:{i}:{c}:{j}".encode()
                req = {"op": "kv_set", "tenant": t, "collection": c, "key_hex": s.encode().hex(), "value_hex": v.hex()}
                rep = subject.call(req)
                if "refuse" in rep: st["refused"] += 1; continue
                for cm in cmds(rep): eng.cmd(*cm)
                kr = subject.call({"op": "kv_key", "tenant": t, "collection": c, "key_hex": s.encode().hex()})
                if "refuse" in kr: st["refused"] += 1; continue
                k = bytes.fromhex(kr["key_hex"])
                if k in owner and owner[k] != t:
                    st.viol("W1", {"violation": f"W1: key collision {k!r} owners {owner[k]!r}/{t!r}"})
                owner[k] = t; val_owner[v] = t; phys[(t, c, s)] = k
    pats = {}
    for t in KV_TEN:
        for c in KV_COLLS:
            rep = subject.call({"op": "kv_scan", "tenant": t, "collection": c, "prefix_hex": None})
            pats[(t, c)] = bytes.fromhex(rep["pattern_hex"]) if "pattern_hex" in rep else None
    own_pats = lambda t: [p for (tt, _), p in pats.items() if tt == t and p is not None]
    for seed in cfg.seeds:
        rng = random.Random(seed)
        for _ in range(cfg.n):
            st["cases"] += 1
            t, c = rng.choice(KV_TEN), rng.choice(KV_COLLS)
            s = rng.choice(KV_KEYS + ["x" + rng.choice(KV_KEYS)])
            op = rng.choice(["kv_set", "kv_setnx", "kv_setxx", "kv_del", "kv_get", "kv_scan"])
            viol = []
            if op == "kv_scan":
                p = rng.choice(["", "k", "x:", "*", "?", "["])
                rep = subject.call({"op": "kv_scan", "tenant": t, "collection": c, "prefix_hex": p.encode().hex()})
                if "refuse" in rep: st["refused"] += 1; viol.append(("E", "well-formed SCAN refused"))
                else:
                    got = eng.scan(bytes.fromhex(rep["pattern_hex"]))
                    for k in got:
                        if owner.get(k) != t: viol.append(("W7", f"SCAN reply holds foreign key {k!r} (owner {owner.get(k)!r})"))
                    want = {k for (tt, cc, ss), k in phys.items() if tt == t and cc == c and ss.startswith(p)}
                    if got != want and not any(v[0] == "W7" for v in viol):
                        viol.append(("E", "SCAN result differs from the tenant's keys with that prefix"))
            else:
                nv = f"n:{seed}:{st['cases']}".encode()
                req = {"op": op, "tenant": t, "collection": c, "key_hex": s.encode().hex(), "value_hex": nv.hex()}
                rep = subject.call(req)
                if "refuse" in rep: st["refused"] += 1; st.viol("E", {"req": req, "violation": "E: well-formed kv op refused"}); continue
                kr = subject.call({"op": "kv_key", "tenant": t, "collection": c, "key_hex": s.encode().hex()})
                K = bytes.fromhex(kr["key_hex"]) if "key_hex" in kr else None
                pre = eng.snap()
                replies = [eng.cmd(*cm) for cm in cmds(rep)]
                post = eng.snap()
                exp = dict(pre)
                if op == "kv_set" or (op == "kv_setnx" and K not in pre) or (op == "kv_setxx" and K in pre): exp[K] = nv
                if op == "kv_del": exp.pop(K, None)
                for k in set(pre) | set(post):
                    if pre.get(k) == post.get(k): continue
                    if k in pre and owner.get(k, t) != t: viol.append(("W1", f"changed key of tenant {owner.get(k)!r}: {k!r}"))
                    if k in post and k not in owner:
                        if not any(L.stringmatchlen(pt, k) for pt in own_pats(t)): viol.append(("W2", f"new key {k!r} outside own namespace"))
                        others = [o for (o, _), pt in pats.items() if o != t and pt is not None and L.stringmatchlen(pt, k)]
                        if others: viol.append(("W2", f"new key {k!r} inside namespace of {others[0]!r}"))
                for r in replies:
                    if isinstance(r, bytes) and r in val_owner and val_owner[r] != t:
                        viol.append(("W7", f"reply carries value of tenant {val_owner[r]!r}"))
                if post != exp or (op == "kv_get" and replies != [pre.get(K)]):
                    viol.append(("E", "effect / reply differs from the kv_plan model"))
                eng.restore(pre)
            seen = set()
            for kind, msg in viol:
                if kind in seen: continue
                seen.add(kind); st.viol(kind, {"tenant": t, "op": op, "key": s, "violation": f"{kind}: {msg}"})

# =========================================================================================== Redis / Valkey kv_acl
# The subject's kv_acl rules define a per-tenant ACL user. Required: its only key pattern is t:{<16hex>}:*, no
# pub/sub channel, no credential tokens (the host owns `reset on >password`), and every hostile command below is
# refused (ACL DRYRUN denies it AND, executed live as that user, it returns an error and changes nothing), while
# the subject's own kv_plan commands (GET / SET / SET NX / SET XX / DEL on own keys) still work as that user.
ACL_CRED_TOKENS = ("on", "off", "nopass", "reset", "resetpass", "skip-sanitize-payload", "sanitize-payload")
KV_ACL_EMITTED = {"get", "set", "del"}           # the commands kv_plan emits for Get / Set / SetNx / SetXx / Del
FROZEN_RESP_DENY = ["EVAL", "EVALSHA", "EVAL_RO", "EVALSHA_RO", "FCALL", "FCALL_RO", "FUNCTION", "SCRIPT", "FLUSHALL",
                    "FLUSHDB", "SWAPDB", "KEYS", "SORT", "SORT_RO", "MOVE", "COPY", "RENAME", "RENAMENX", "MIGRATE",
                    "SELECT", "CLIENT", "ACL", "CONFIG", "DEBUG", "MODULE", "MONITOR"]

def resp_denylist():
    """The frozen RESP denylist (monban_data_ir::denylist, crates/monban-data-ir/src/ir.rs RESP_DENY); the embedded
    copy is used only when the oracle runs outside the repo. Every item must be covered by the hostile corpus."""
    p = os.path.join(L.repo_root(HERE), "crates", "monban-data-ir", "src", "ir.rs")
    try:
        src = open(p, encoding="utf-8").read()
    except OSError:
        return list(FROZEN_RESP_DENY), "embedded copy"
    i = src.find("const RESP_DENY")
    block = src[i:src.find("];", i)] if i >= 0 else ""
    items = re.findall(r'item:\s*"([A-Z_]+)"', block)
    return (items or list(FROZEN_RESP_DENY)), p

def hostile_corpus(T, O):
    """(label, argv) hostile commands for tenant hex T against tenant hex O. Keys use the reference encoding."""
    own, fk = f"t:{{{T}}}:c:k1", f"t:{{{O}}}:c:k1"
    lua = "#!lua name=monbanlib\nredis.register_function('monbanf', function(keys, args) return 1 end)"
    c = [
        ("FLUSHALL", ["FLUSHALL"]), ("FLUSHALL ASYNC", ["FLUSHALL", "ASYNC"]), ("FLUSHDB", ["FLUSHDB"]),
        ("KEYS *", ["KEYS", "*"]), ("KEYS foreign", ["KEYS", f"t:{{{O}}}:*"]), ("KEYS own", ["KEYS", f"t:{{{T}}}:*"]),
        ("CONFIG GET", ["CONFIG", "GET", "*"]), ("CONFIG SET", ["CONFIG", "SET", "maxmemory-policy", "noeviction"]),
        ("CONFIG RESETSTAT", ["CONFIG", "RESETSTAT"]), ("CONFIG REWRITE", ["CONFIG", "REWRITE"]),
        ("EVAL declared own key", ["EVAL", "return redis.call('GET', KEYS[1])", "1", own]),
        ("EVAL undeclared foreign key", ["EVAL", f"return redis.call('GET', '{fk}')", "0"]),
        ("EVAL_RO", ["EVAL_RO", "return 1", "0"]),
        ("EVALSHA", ["EVALSHA", "e0e1f9fabfc9d4800c877a703b823ac0578ff8db", "0"]),
        ("EVALSHA_RO", ["EVALSHA_RO", "e0e1f9fabfc9d4800c877a703b823ac0578ff8db", "0"]),
        ("SCRIPT LOAD", ["SCRIPT", "LOAD", "return 1"]), ("SCRIPT FLUSH", ["SCRIPT", "FLUSH"]),
        ("SCRIPT EXISTS", ["SCRIPT", "EXISTS", "e0e1f9fabfc9d4800c877a703b823ac0578ff8db"]),
        ("FUNCTION LOAD", ["FUNCTION", "LOAD", lua]), ("FUNCTION LIST", ["FUNCTION", "LIST"]),
        ("FUNCTION FLUSH", ["FUNCTION", "FLUSH"]), ("FCALL", ["FCALL", "monbanf", "0"]), ("FCALL_RO", ["FCALL_RO", "monbanf", "0"]),
        ("MODULE LIST", ["MODULE", "LIST"]), ("MODULE LOAD", ["MODULE", "LOAD", "/nonexistent/monban.so"]),
        ("DEBUG SLEEP", ["DEBUG", "SLEEP", "0"]), ("DEBUG OBJECT", ["DEBUG", "OBJECT", own]),
        ("MIGRATE own key", ["MIGRATE", "127.0.0.1", "1", own, "0", "10"]),
        ("MIGRATE KEYS foreign", ["MIGRATE", "127.0.0.1", "1", "", "0", "10", "KEYS", fk]),
        ("SWAPDB", ["SWAPDB", "0", "1"]), ("MOVE own key to db 1", ["MOVE", own, "1"]),
        ("COPY own->foreign", ["COPY", own, fk]), ("COPY foreign->own", ["COPY", fk, own, "REPLACE"]),
        ("COPY own to db 1", ["COPY", own, own, "DB", "1"]),
        ("RENAME own->foreign", ["RENAME", own, fk]), ("RENAME foreign->own", ["RENAME", fk, own]),
        ("RENAMENX own->foreign", ["RENAMENX", own, fk]),
        ("SORT BY/GET foreign", ["SORT", own, "BY", f"t:{{{O}}}:*", "GET", f"t:{{{O}}}:*"]),
        ("SORT STORE foreign", ["SORT", own, "STORE", fk]), ("SORT_RO BY foreign", ["SORT_RO", own, "BY", f"t:{{{O}}}:*"]),
        ("SELECT 1", ["SELECT", "1"]), ("CLIENT LIST", ["CLIENT", "LIST"]),
        ("CLIENT KILL ID", ["CLIENT", "KILL", "ID", "999999999"]), ("CLIENT KILL ADDR", ["CLIENT", "KILL", "ADDR", "192.0.2.1:1"]),
        ("CLIENT SETNAME", ["CLIENT", "SETNAME", "x"]), ("CLIENT NO-EVICT", ["CLIENT", "NO-EVICT", "on"]),
        ("ACL WHOAMI", ["ACL", "WHOAMI"]), ("ACL LIST", ["ACL", "LIST"]), ("ACL GETUSER default", ["ACL", "GETUSER", "default"]),
        ("ACL SETUSER self +@all", ["ACL", "SETUSER", f"monban_kv_{T}", "+@all", "~*"]),
        ("ACL DELUSER", ["ACL", "DELUSER", "monban_nonexistent"]), ("ACL LOG", ["ACL", "LOG"]),
        ("MONITOR", ["MONITOR"]),
        ("PUBLISH", ["PUBLISH", f"t:{{{O}}}:ch", "m"]), ("SPUBLISH", ["SPUBLISH", f"t:{{{O}}}:ch", "m"]),
        ("SUBSCRIBE", ["SUBSCRIBE", f"t:{{{O}}}:ch"]), ("PSUBSCRIBE", ["PSUBSCRIBE", "*"]),
        ("SSUBSCRIBE", ["SSUBSCRIBE", f"t:{{{O}}}:ch"]), ("PUBSUB CHANNELS", ["PUBSUB", "CHANNELS"]),
        ("SCAN no MATCH", ["SCAN", "0"]), ("SCAN MATCH *", ["SCAN", "0", "MATCH", "*"]),
        ("SCAN MATCH foreign", ["SCAN", "0", "MATCH", f"t:{{{O}}}:*", "COUNT", "1000"]),
        ("SCAN MATCH foreign TYPE", ["SCAN", "0", "MATCH", f"t:{{{O}}}:c:*", "TYPE", "string"]),
        ("GET foreign", ["GET", fk]), ("SET foreign", ["SET", fk, "x"]), ("SET foreign NX", ["SET", fk, "x", "NX"]),
        ("SET foreign XX", ["SET", fk, "x", "XX"]), ("DEL foreign", ["DEL", fk]), ("DEL own+foreign", ["DEL", own, fk]),
        ("SET foreign GET", ["SET", fk, "x", "GET"]),
        ("MGET own+foreign", ["MGET", own, fk]), ("EXISTS foreign", ["EXISTS", fk]), ("TYPE foreign", ["TYPE", fk]),
        ("DUMP foreign", ["DUMP", fk]), ("OBJECT ENCODING foreign", ["OBJECT", "ENCODING", fk]),
        ("UNLINK foreign", ["UNLINK", fk]), ("GETDEL foreign", ["GETDEL", fk]), ("APPEND foreign", ["APPEND", fk, "x"]),
        ("EXPIRE foreign", ["EXPIRE", fk, "1"]), ("TOUCH foreign", ["TOUCH", fk]),
        ("SAVE", ["SAVE"]), ("BGSAVE", ["BGSAVE"]), ("BGREWRITEAOF", ["BGREWRITEAOF"]),
        ("REPLICAOF NO ONE", ["REPLICAOF", "NO", "ONE"]), ("SHUTDOWN", ["SHUTDOWN", "NOSAVE"]),
        ("FAILOVER ABORT", ["FAILOVER", "ABORT"]), ("WAIT", ["WAIT", "0", "1"]),
        ("INFO", ["INFO"]), ("DBSIZE", ["DBSIZE"]), ("RANDOMKEY", ["RANDOMKEY"]), ("OBJECT FREQ own", ["OBJECT", "FREQ", own]),
        ("MEMORY USAGE foreign", ["MEMORY", "USAGE", fk]), ("LATENCY RESET", ["LATENCY", "RESET"]),
        ("SLOWLOG GET", ["SLOWLOG", "GET"]), ("JSON.GET foreign (redis module)", ["JSON.GET", fk]), ("FT._LIST (redis module)", ["FT._LIST"]),
    ]
    # out-of-namespace neighbours of the tenant's own namespace t:{T}:* (a pattern missing a brace or the ':'
    # delimiter, or without braces, reaches them)
    for k in (f"t:{{{T}}}", f"t:{{{T}}}x:k1", f"t:{{{T}0}}:c:k1", f"t:{T}:c:k1", f"t:{{{T}", "k1"):
        c.append((f"GET neighbour {k!r}", ["GET", k]))
        c.append((f"SET neighbour {k!r}", ["SET", k, "x"]))
    return c

def acl_static(rules, t):
    """Offline structural check of kv_acl rules (no engine): returns [(counter, message)]. Category grants (+@cat)
    cannot be verified without the server's category table, so they are violations here (live mode uses DRYRUN)."""
    out, keys, chans, cmds = [], set(), set(), set()
    deny = {d.lower() for d in resp_denylist()[0]}
    hostile = {argv[0].lower() for _, argv in hostile_corpus(t, A if t != A else T(0x2))} - KV_ACL_EMITTED
    for tok in rules:
        if type(tok) is not str: out.append(("FORM", f"non-string rule token {tok!r}")); continue
        lo = tok.lower()
        if lo in ACL_CRED_TOKENS or tok[:1] in (">", "<", "#", "!"):
            out.append(("FORM", f"credential/state token {tok!r} (the host owns reset/on/password)")); continue
        if lo == "resetkeys": keys.clear()
        elif lo == "allkeys": keys.add("*")
        elif re.match(r"^(%[RW]+)?~", tok): keys.add(tok.split("~", 1)[1])
        elif lo == "resetchannels": chans.clear()
        elif lo == "allchannels" or tok.startswith("&"): chans.add(tok)
        elif lo in ("allcommands", "+@all"): cmds.add("@all")
        elif lo in ("nocommands", "-@all"): cmds.clear()
        elif tok.startswith("+@"): cmds.add(lo[1:])
        elif tok.startswith("+"): cmds.add(lo[1:].split("|")[0])
        elif tok.startswith("-"): cmds.discard(lo[1:].split("|")[0])
        elif tok.startswith("(") or tok.startswith("%"): out.append(("ACL", f"selector / unsupported token {tok!r}"))
        else: out.append(("ACL", f"unknown rule token {tok!r}"))
    want = f"t:{{{t}}}:*"
    if keys != {want}: out.append(("ACL", f"key patterns {sorted(keys)} != only {want!r}"))
    if chans: out.append(("ACL", f"pub/sub channels granted {sorted(chans)}"))
    cats = sorted(c for c in cmds if c.startswith("@"))
    if cats: out.append(("ACL", f"category grant(s) {cats} include denylisted / hostile commands"))
    bad = sorted(c for c in cmds if c in deny or c in hostile)
    if bad: out.append(("ACL", f"hostile command(s) granted {bad}"))
    return out

def kv_acl_refusals(subject, st):
    for h in BAD_HANDLES:
        st["cases"] += 1
        rep = subject.call({"op": "kv_acl", "tenant": h})
        if "refuse" not in rep: st.viol("REFUSE", {"tenant": h, "violation": f"REFUSE: kv_acl answered for non-canonical handle {h!r}"})

def kv_acl_static_family(subject, st):
    kv_acl_refusals(subject, st)
    for t in KV_TEN:
        st["cases"] += 1
        rep = subject.call({"op": "kv_acl", "tenant": t})
        if "refuse" in rep or not isinstance(rep.get("rules"), list):
            st["refused"] += 1; st.viol("E", {"tenant": t, "violation": f"E: kv_acl refused / malformed: {str(rep)[:160]}"}); continue
        for kind, msg in acl_static(rep["rules"], t):
            st.viol(kind, {"tenant": t, "rules": rep["rules"], "violation": f"{kind}: {msg}"})

def _b(x): return x if isinstance(x, bytes) else str(x).encode()

def kv_acl_family(subject, cfg, st, eng, url):
    """Live: per tenant, create the subject's ACL user and run the hostile corpus as that user."""
    deny, deny_src = resp_denylist()
    admin = eng.r
    db1 = L.Resp(url); db1.cmd(b"SELECT", b"1")
    kv_acl_refusals(subject, st)
    covered = {argv[0].upper() for _, argv in hostile_corpus(T(1), T(2))}
    for d in deny:
        if d.upper() not in covered:
            st.viol("ACL", {"violation": f"ACL: oracle corpus lacks denylisted command {d} ({deny_src})"})
    def keyspace():
        return ({k: admin.cmd(b"DUMP", k) for k in admin.cmd(b"KEYS", b"*")},
                {k: db1.cmd(b"DUMP", k) for k in db1.cmd(b"KEYS", b"*")})
    def seed():
        admin.cmd(b"FLUSHALL")
        for tt in KV_TEN:
            for kk in ("k1", "k2"):
                kr = subject.call({"op": "kv_key", "tenant": tt, "collection": "c", "key_hex": kk.encode().hex()})
                if "key_hex" in kr: admin.cmd(b"SET", bytes.fromhex(kr["key_hex"]), f"v:{tt}:{kk}".encode())
            for k in (f"t:{{{tt}}}", f"t:{{{tt}}}x:k1", f"t:{{{tt}0}}:c:k1", f"t:{tt}:c:k1", f"t:{{{tt}", "k1"):
                admin.cmd(b"SET", k.encode(), b"neighbour")
        admin.cmd(b"SCRIPT", b"LOAD", b"return 1")
        return keyspace()
    base = seed()
    for i, t in enumerate(KV_TEN):
        o = KV_TEN[(i + 1) % len(KV_TEN)]
        user = f"monban_kv_{t}"; pw = os.urandom(12).hex()
        rep = subject.call({"op": "kv_acl", "tenant": t})
        st["cases"] += 1
        if "refuse" in rep or not isinstance(rep.get("rules"), list):
            st["refused"] += 1; st.viol("E", {"tenant": t, "violation": f"E: kv_acl refused / malformed: {str(rep)[:160]}"}); continue
        rules = rep["rules"]
        for kind, msg in acl_static(rules, t):
            if kind == "FORM": st.viol("FORM", {"tenant": t, "rules": rules, "violation": f"FORM: {msg}"})
        r = admin.cmd(b"ACL", b"SETUSER", user.encode(), b"reset", b"on", b">" + pw.encode(), *[_b(x) for x in rules])
        if isinstance(r, L.RespError):
            st.viol("E", {"tenant": t, "rules": rules, "violation": f"E: ACL SETUSER rejected the rules: {r}"}); continue
        # key patterns as the server holds them: exactly one, t:{<hex>}:*
        info = admin.cmd(b"ACL", b"GETUSER", user.encode())
        d = dict(zip(info[0::2], info[1::2])) if isinstance(info, list) else {}
        kp = d.get(b"keys", b"")
        kp = kp.decode() if isinstance(kp, bytes) else " ".join(x.decode() for x in kp or [])
        sel = d.get(b"selectors") or []
        if kp.split() != [f"~t:{{{t}}}:*"] or sel:
            st.viol("ACL", {"tenant": t, "rules": rules, "violation": f"ACL: server key patterns {kp!r} selectors={len(sel)} != only '~t:{{{t}}}:*'"})
        ch = d.get(b"channels", b"")
        ch = ch.decode() if isinstance(ch, bytes) else " ".join(x.decode() for x in ch or [])
        if ch.strip():
            st.viol("ACL", {"tenant": t, "violation": f"ACL: pub/sub channels granted {ch!r}"})
        # positive: the subject's own kv_plan commands work as this user
        u = L.Resp(url, user=user, password=pw)
        nk = "kacl"
        seq = [("kv_set", b"OK"), ("kv_get", f"n:{t}".encode()), ("kv_setxx", b"OK"), ("kv_setnx", None), ("kv_del", 1), ("kv_get", None)]
        for op, want in seq:
            st["cases"] += 1
            q = subject.call({"op": op, "tenant": t, "collection": "c", "key_hex": nk.encode().hex(), "value_hex": f"n:{t}".encode().hex()})
            if "refuse" in q: st.viol("E", {"tenant": t, "op": op, "violation": "E: own kv op refused"}); continue
            got = [u.cmd(*[bytes.fromhex(x) for x in cm]) for cm in q["commands"]]
            if got[-1:] != [want]:
                st.viol("E", {"tenant": t, "op": op, "violation": f"E: own kv op as the ACL user replied {got!r}, want {want!r}"})
        u.close()
        if keyspace() != base: base = seed()
        # hostile corpus
        for label, argv in hostile_corpus(t, o):
            st["cases"] += 1
            args = [_b(x) for x in argv]
            dr = admin.cmd(b"ACL", b"DRYRUN", user.encode(), *args)
            if dr == b"OK":
                st.viol("ACL", {"tenant": t, "cmd": label, "violation": f"ACL: DRYRUN permits {label} for the tenant user"})
                continue                   # never executed live when the ACL already permits it (engine safety)
            u = L.Resp(url, user=user, password=pw, timeout=10)
            try:
                rr = u.cmd(*args)
            except Exception as e:
                rr = L.RespError(f"connection: {e}")
            u.close()
            if not isinstance(rr, L.RespError):
                st.viol("ACL", {"tenant": t, "cmd": label, "violation": f"ACL: executed as the tenant user: {str(rr)[:120]}"})
            now = keyspace()
            if now != base:
                st.viol("W1", {"tenant": t, "cmd": label, "violation": "W1: keyspace changed by a hostile command"})
                base = seed()
        admin.cmd(b"ACL", b"DELUSER", user.encode())
    db1.cmd(b"FLUSHDB"); db1.close()
    admin.cmd(b"SCRIPT", b"FLUSH")

# =========================================================================================== Postgres RLS-native
# Defence in depth behind the renderer (R-DB-1, R-DB-8): the subject's rls_policy statements are applied by the
# table owner, its rls_bind statements open each request transaction, and ORACLE-composed statements (no tenant
# conjunct, hostile SET tenant / foreign INSERT / column-free writes / global-arbiter upserts; research
# wp_run2/wp_run3) run under them. Checks: W1/W2/W4 on the whole table (read through a SECURITY DEFINER snapshot
# function inside the transaction), E for well-formed own-tenant statements, FORM on the catalog (ENABLE + FORCE,
# every permissive policy carries USING and an explicit WITH CHECK on the tenant column vs current_setting(S)),
# BIND (after COMMIT/ROLLBACK -- the checkin -- the connection is back to the login role with the setting empty),
# and the owner path (owner login with the setting bound but no role switch: FORCE must stop the owner bypass).
RLS_ROLE, RLS_LOGIN, RLS_SETTING = "monban_rls_app", "monban_rls_login", "monban.tenant"
RLS_COLS = ["id", "tenant", "peer", "grp", "x", "y", "secret"]
RLS_DECL = {"id": "int", "tenant": "text", "peer": "text", "grp": "text", "x": "text", "y": "text", "secret": "text"}
RLS_SNAP = "select id, tenant, peer, grp, x, y, secret from monban_rls_snap()"
RLS_KINDS = ["sel", "upd", "del", "updall", "delall", "inso", "move", "movew", "insf", "upg", "upgt"]
RLS_WELLFORMED = {"sel", "upd", "del", "updall", "delall", "inso"}

def login_dsn(dsn, user, pw):
    u = urllib.parse.urlparse(dsn)
    host = u.hostname or "127.0.0.1"
    return f"postgresql://{user}:{pw}@{host}:{u.port or 5432}{u.path or '/postgres'}"

def rls_setup(admin, dsn, rows):
    pw = os.urandom(12).hex()
    for r in (RLS_LOGIN, RLS_ROLE):
        if admin.query("select 1 from pg_roles where rolname = $1", (r,))[1]:
            admin.simple(f"drop owned by {r} cascade")
    admin.simple("drop table if exists rt cascade")
    admin.simple("drop function if exists monban_rls_snap()")
    for r in (RLS_LOGIN, RLS_ROLE):
        admin.simple(f"drop role if exists {r}")
    admin.simple(f"create role {RLS_ROLE} nologin")
    # NOINHERIT: policies TO monban_rls_app must not apply to the owner login implicitly (else a binding without
    # SET LOCAL ROLE, mutant rls-no-role, would be indistinguishable from a correct one)
    admin.simple(f"create role {RLS_LOGIN} login noinherit nosuperuser nobypassrls password '{pw}'")
    admin.simple(f"grant {RLS_ROLE} to {RLS_LOGIN}")
    admin.simple(f"grant usage on schema public to {RLS_ROLE}, {RLS_LOGIN}")
    admin.simple("create table rt(id int primary key, tenant text not null, peer text, grp text, x text, y text, secret text)")
    for r in rows:
        admin.query("insert into rt(id,tenant,peer,grp,x,y,secret) values ($1,$2,$3,$4,$5,$6,$7)", tuple(r[c] for c in RLS_COLS))
    admin.simple(f"alter table rt owner to {RLS_LOGIN}")
    admin.simple(f"grant select, insert, update, delete on rt to {RLS_ROLE}")
    # superuser-owned SECURITY DEFINER snapshot: sees the whole table, including this transaction's own changes
    admin.simple("create function monban_rls_snap() returns setof rt language sql security definer "
                 "set search_path = public as $$ select * from rt $$")
    admin.simple("revoke all on function monban_rls_snap() from public")
    admin.simple(f"grant execute on function monban_rls_snap() to {RLS_ROLE}, {RLS_LOGIN}")
    return L.Pg(login_dsn(dsn, RLS_LOGIN, pw))

def _strip_literals(s):
    return re.sub(r"'(?:[^']|'')*'", "''", s or "")

def rls_catalog_form(admin, setting, tf):
    """[(msg)] violations of the mandated RLS form, read from the catalog (not from the subject's SQL text)."""
    out = []
    r = admin.query("select relrowsecurity, relforcerowsecurity from pg_class where oid = 'rt'::regclass")[1]
    if not r or r[0][0] is not True: out.append("row level security not ENABLEd")
    if not r or r[0][1] is not True: out.append("row level security not FORCEd (owner bypass)")
    pols = admin.query("select polname::text, polpermissive, polcmd::text, pg_get_expr(polqual, polrelid), "
                       "pg_get_expr(polwithcheck, polrelid) from pg_policy where polrelid = 'rt'::regclass")[1]
    perm = [p for p in pols if p[1] is True]
    if not perm: out.append("no permissive policy")
    cover = {p[2] for p in perm}
    if "*" not in cover and not {"r", "a", "w", "d"} <= cover: out.append(f"permissive policies cover only {sorted(cover)}")
    others = [c for c in RLS_COLS if c != tf]
    def guard_ok(e):
        if e is None: return False
        if not re.search(r"current_setting\('" + re.escape(setting) + r"'", e): return False
        bare = _strip_literals(e)
        if not re.search(r'(?<![\w"])"?' + re.escape(tf) + r'"?(?![\w"])', bare): return False
        return not any(re.search(r'(?<![\w"])"?' + re.escape(c) + r'"?(?![\w"])', bare) for c in others)
    for name, _p, cmd, qual, chk in perm:
        if cmd in ("*", "r", "w", "d") and not guard_ok(qual):
            out.append(f"policy {name} ({cmd}) USING {qual!r} is not tenant_field = current_setting({setting!r})")
        if cmd in ("*", "a", "w"):
            if chk is None: out.append(f"policy {name} ({cmd}) has no explicit WITH CHECK")
            elif not guard_ok(chk): out.append(f"policy {name} ({cmd}) WITH CHECK {chk!r} is not tenant_field = current_setting({setting!r})")
    return out

def rls_statement(kind, rng, t, other, p, nid):
    """Oracle-composed statement (no tenant conjunct: RLS alone must confine it) -> (sql, params)."""
    ctx = L.Renderer.Ctx({"dialect": "postgres", "columns": RLS_DECL, "param_offset": 1})
    if kind == "sel":
        ctx.offset = 0; w = L.Renderer().render(p, ctx)
        return f"SELECT id, tenant, x FROM rt WHERE {w}", ctx.params
    if kind == "upd":
        w = L.Renderer().render(p, ctx)
        return f"UPDATE rt SET x = $1 WHERE {w} RETURNING id, tenant, x", ["U"] + ctx.params
    if kind == "del":
        ctx.offset = 0; w = L.Renderer().render(p, ctx)
        return f"DELETE FROM rt WHERE {w} RETURNING id, tenant", ctx.params
    if kind == "updall": return "UPDATE rt SET x = $1", ["U"]
    if kind == "delall": return "DELETE FROM rt", []
    if kind == "inso":
        return "INSERT INTO rt(id, tenant, peer, grp, x, y, secret) VALUES ($1, $2, $3, 'g1', 'N', 'n', NULL)", [nid, t, other]
    if kind == "move": return "UPDATE rt SET tenant = $1", [other]
    if kind == "movew": return "UPDATE rt SET tenant = $1 WHERE id > 0 RETURNING id", [other]
    if kind == "insf":
        return "INSERT INTO rt(id, tenant, peer, grp, x, y, secret) VALUES ($1, $2, $3, 'g1', 'F', 'f', NULL)", [nid, other, t]
    if kind == "upg":
        return ("INSERT INTO rt(id, tenant, x) VALUES ($1, $2, 'N') ON CONFLICT (id) DO UPDATE SET x = excluded.x",
                [rng.randint(1, 70), t])
    if kind == "upgt":
        return ("INSERT INTO rt(id, tenant, x) VALUES ($1, $2, 'N') ON CONFLICT (id) DO UPDATE SET tenant = excluded.tenant, "
                "x = excluded.x RETURNING id, tenant, x", [rng.randint(1, 70), t])
    raise ValueError(kind)

def rls_expected(kind, t, p, pre, nid, other):
    """(post-state by id, returned rows multiset) for a well-formed statement under a correct tenant-t policy."""
    post = {r["id"]: dict(r) for r in pre}
    own = lambda r: L.veq(r["tenant"], t)
    hit = lambda r: own(r) and L.keeps(L.EXACT, r, L.lower(p))
    ret = []
    if kind == "sel": ret = [(r["id"], r["tenant"], r["x"]) for r in pre if hit(r)]
    elif kind == "upd":
        for r in post.values():
            if hit(r): r["x"] = "U"; ret.append((r["id"], r["tenant"], "U"))
    elif kind == "del":
        for r in pre:
            if hit(r): ret.append((r["id"], r["tenant"])); del post[r["id"]]
    elif kind == "updall":
        for r in post.values():
            if own(r): r["x"] = "U"
    elif kind == "delall":
        for r in pre:
            if own(r): del post[r["id"]]
    elif kind == "inso":
        post[nid] = dict(id=nid, tenant=t, peer=other, grp="g1", x="N", y="n", secret=None)
    return post, sorted(ret, key=repr)

def rls_check(st, kind, t, pre, post, rows, wellformed, exp, ex):
    preI = {r["id"]: r for r in pre}; postI = {r["id"]: r for r in post}
    viol = []
    for k in set(preI) | set(postI):
        a, b = preI.get(k), postI.get(k)
        if a == b: continue
        if a is not None and not L.veq(a["tenant"], t): viol.append(("W1", f"changed foreign row tenant={a['tenant']!r} id={k}"))
        if b is not None and not L.veq(b["tenant"], t): viol.append(("W2", f"post-image tenant={b['tenant']!r} id={k}"))
    for row in rows:
        if len(row) > 1 and not L.veq(row[1], t): viol.append(("W4", f"returned row of tenant {row[1]!r}"))
        elif len(row) == 1 and row[0] in preI and not L.veq(preI[row[0]]["tenant"], t) and not (row[0] in postI and L.veq(postI[row[0]]["tenant"], t)):
            viol.append(("W4", f"returned id {row[0]} of a foreign row"))
    if wellformed:
        epost, eret = exp
        if postI != epost or sorted(rows, key=repr) != eret:
            viol.append(("E", "effect differs from the tenant-t model (post-state or returned rows)"))
    seen = set()
    for kind_, msg in viol:
        if kind_ in seen: continue
        seen.add(kind_); st.viol(kind_, dict(ex, violation=f"{kind_}: {msg}"))

def rls_family(admin, dsn, subject, cfg, fams, tag):
    st = fams.setdefault(f"{tag}RLS native (FORCE, WITH CHECK, per-request bind, owner path) | rt global id PK", Stats())
    for h in BAD_HANDLES[:4]:
        st["cases"] += 1
        rep = subject.call({"op": "rls_bind", "dialect": "postgres", "tenant": h, "role": RLS_ROLE, "setting": RLS_SETTING})
        if "refuse" not in rep: st.viol("REFUSE", {"tenant": h, "violation": f"REFUSE: rls_bind answered for {h!r}"})
    for seed in cfg.seeds:
        rng = random.Random(seed + 77)
        rows = [dict(r, peer=rng.choice(TEN_HANDLES)) for r in mkrows(random.Random(20261025 + seed), 60)]
        login = rls_setup(admin, dsn, rows)
        st["cases"] += 1
        pol = subject.call({"op": "rls_policy", "dialect": "postgres", "table": "rt", "tenant_field": "tenant",
                            "role": RLS_ROLE, "setting": RLS_SETTING, "columns": RLS_DECL})
        if "refuse" in pol or not isinstance(pol.get("statements"), list):
            st["refused"] += 1; st.viol("E", {"violation": f"E: rls_policy refused / malformed: {str(pol)[:160]}"}); login.close(); continue
        try:
            for s in pol["statements"]: login.simple(s)        # applied by the table owner (no superuser needed)
        except L.PgError as e:
            st.viol("E", {"violation": f"E: rls_policy statement failed as the table owner: {e}"}); login.close(); continue
        for msg in rls_catalog_form(admin, RLS_SETTING, "tenant"):
            st.viol("FORM", {"policy": pol["statements"], "violation": f"FORM: {msg}"})
        nid = 1000
        for i in range(cfg.n):
            st["cases"] += 1
            kind = RLS_KINDS[i % len(RLS_KINDS)] if i < len(RLS_KINDS) else rng.choice(RLS_KINDS)
            t = rng.choice(TEN_HANDLES); other = rng.choice([x for x in TEN_HANDLES if x != t]); p = gpred(rng)
            nid += 1
            wf = kind in RLS_WELLFORMED
            if not wf: st["illformed"] += 1
            sql, params = rls_statement(kind, rng, t, other, p, nid)
            ex = {"kind": kind, "tenant": t, "sql": sql}
            b = subject.call({"op": "rls_bind", "dialect": "postgres", "tenant": t, "role": RLS_ROLE, "setting": RLS_SETTING})
            if "refuse" in b or not isinstance(b.get("statements"), list):
                st["refused"] += 1; st.viol("E", dict(ex, violation=f"E: rls_bind refused / malformed: {str(b)[:160]}")); continue
            login.simple("begin")
            try:
                for s in b["statements"]: login.query(s["sql"], s.get("params") or [])
                pre = [dict(zip(RLS_COLS, r)) for r in login.query(RLS_SNAP)[1]]
            except L.PgError as e:
                login.simple("rollback"); st["blocked"] += 1
                st.viol("E", dict(ex, violation=f"E: binding failed: {e}")); continue
            try:
                names, got = login.query(sql, params)
                post = [dict(zip(RLS_COLS, r)) for r in login.query(RLS_SNAP)[1]]
                login.simple("commit" if kind == "sel" else "rollback")     # read-only requests check in after COMMIT
                rls_check(st, kind, t, pre, post, got if names else [], wf, rls_expected(kind, t, p, pre, nid, other), ex)
            except L.PgError as e:
                login.simple("rollback"); st["blocked"] += 1
                if wf:
                    st["errors_wellformed"] += 1; st.viol("E", dict(ex, violation=f"E: well-formed statement blocked: {str(e)[:160]}"))
            # checkin: no reset is issued by the pool; the binding must be gone with the transaction
            who = login.query(f"select current_user::text, coalesce(current_setting('{RLS_SETTING}', true), '')")[1][0]
            if who != (RLS_LOGIN, ""):
                n_seen = login.query("select count(*) from rt")[1][0][0]
                st.viol("BIND", dict(ex, violation=f"BIND: after checkin current_user={who[0]!r} {RLS_SETTING}={who[1]!r}; "
                                                   f"an unbound statement on this pooled connection sees {n_seen} row(s)"))
                login.simple(f"reset role; select set_config('{RLS_SETTING}', '', false)")
        # owner path: the owner login with the tenant setting bound but no role switch
        for i in range(max(1, cfg.n // 5)):
            st["cases"] += 1; st["illformed"] += 1
            kind = rng.choice(["sel", "updall", "delall", "move", "insf", "upg"])
            t = rng.choice(TEN_HANDLES); other = rng.choice([x for x in TEN_HANDLES if x != t]); p = gpred(rng)
            nid += 1
            sql, params = rls_statement(kind, rng, t, other, p, nid)
            ex = {"kind": "owner-path " + kind, "tenant": t, "sql": sql}
            login.simple("begin")
            try:
                login.query("select set_config($1, $2, true)", [RLS_SETTING, t])
                pre = [dict(zip(RLS_COLS, r)) for r in login.query(RLS_SNAP)[1]]
                names, got = login.query(sql, params)
                post = [dict(zip(RLS_COLS, r)) for r in login.query(RLS_SNAP)[1]]
                rls_check(st, kind, t, pre, post, got if names else [], False, None, ex)
            except L.PgError:
                st["blocked"] += 1
            login.simple("rollback")
        login.close()
    admin.simple("drop table if exists rt cascade"); admin.simple("drop function if exists monban_rls_snap()")

# =========================================================================================== PG ON CONFLICT information run
INFO_NAME = "LOWERING-WRITE PG-ONCONFLICT-INFO"

def pg_onconflict_info(dsns, subject):
    """Information only (never a gate): does ON CONFLICT DO UPDATE ... WHERE <user function> evaluate the function on
    another tenant's row before RLS rejects the update (R-DB-8, research wpo-pg-onconflict-where-peek)? Plus the
    hardened composite arbiter, plain UPDATE/DELETE/MERGE/SELECT controls and PG19's ON CONFLICT DO SELECT."""
    A_, B_ = TEN_HANDLES[0], TEN_HANDLES[1]
    summary = []
    for dsn in dsns:
        admin = L.Pg(dsn); v = L.pg_version(admin)
        print(f"  [pg {v}] tenant A={A_} binds; tenant B={B_} owns row id 2 (x='secretB'); FORCE RLS policy from the subject")
        rows = [dict(id=1, tenant=A_, peer=B_, grp="g1", x="secretA", y="0", secret="s1"),
                dict(id=2, tenant=B_, peer=A_, grp="g1", x="secretB", y="0", secret="s2")]
        login = rls_setup(admin, dsn, rows)
        admin.simple(f"create table rt2(tenant text not null, id int not null, x text, primary key (tenant, id))")
        admin.simple(f"insert into rt2 values ('{A_}', 1, 'secretA'), ('{B_}', 2, 'secretB')")
        admin.simple(f"alter table rt2 owner to {RLS_LOGIN}"); admin.simple(f"grant select, insert, update, delete on rt2 to {RLS_ROLE}")
        admin.simple("create or replace function monban_peek(text) returns boolean language plpgsql as "
                     "$$ begin raise notice 'AEGIS_PEEK %', $1; return true; end $$")
        admin.simple(f"grant execute on function monban_peek(text) to {RLS_ROLE}")
        admin.simple(f"create view rtv with (security_barrier = true) as select * from rt where tenant = current_setting('{RLS_SETTING}', true)")
        admin.simple(f"grant select, insert on rtv to {RLS_ROLE}")
        for tbl in ("rt", "rt2"):
            pol = subject.call({"op": "rls_policy", "dialect": "postgres", "table": tbl, "tenant_field": "tenant",
                                "role": RLS_ROLE, "setting": RLS_SETTING})
            for s in pol.get("statements", []): login.simple(s)
        probes = [
            ("P1 ON CONFLICT (id) DO UPDATE .. WHERE peek(t.x), global arbiter, foreign id 2",
             "INSERT INTO rt(id, tenant, x) VALUES (2, $1, 'n') ON CONFLICT (id) DO UPDATE SET x = excluded.x WHERE monban_peek(rt.x)"),
            ("P2 hardened: composite arbiter (tenant,id) .. WHERE peek(t.x), id 2",
             "INSERT INTO rt2(tenant, id, x) VALUES ($1, 2, 'n') ON CONFLICT (tenant, id) DO UPDATE SET x = excluded.x WHERE monban_peek(rt2.x)"),
            ("P3 control UPDATE .. WHERE peek(x)", "UPDATE rt SET x = 'z' WHERE monban_peek(x) AND $1::text IS NOT NULL"),
            ("P4 control DELETE .. WHERE peek(x)", "DELETE FROM rt WHERE monban_peek(x) AND $1::text IS NOT NULL"),
            ("P5 control MERGE .. WHEN MATCHED AND peek(t.x)",
             "MERGE INTO rt USING (SELECT 2 AS id, $1::text AS t) s ON rt.id = s.id WHEN MATCHED AND monban_peek(rt.x) THEN UPDATE SET x = 'm'"),
            ("P6 control SELECT .. WHERE peek(x)", "SELECT id FROM rt WHERE monban_peek(x) AND $1::text IS NOT NULL"),
            ("P7 ON CONFLICT (id) DO SELECT RETURNING (PG19 syntax), RLS table",
             "INSERT INTO rt(id, tenant, x) VALUES (2, $1, 'n') ON CONFLICT (id) DO SELECT RETURNING id, tenant, x"),
            ("P8 ON CONFLICT (id) DO SELECT via security_barrier view (view tenancy, not RLS)",
             "INSERT INTO rtv(id, tenant, x) VALUES (2, $1, 'n') ON CONFLICT (id) DO SELECT RETURNING id, tenant, x"),
        ]
        res = {}
        bind = subject.call({"op": "rls_bind", "dialect": "postgres", "tenant": A_, "role": RLS_ROLE, "setting": RLS_SETTING})
        for label, sql in probes:
            login.notices.clear(); login.simple("begin")
            try:
                for s in bind["statements"]: login.query(s["sql"], s.get("params") or [])
                _, got = login.query(sql, [A_])
                outcome = f"ok rows={got}"
            except L.PgError as e:
                outcome = f"error {e.sqlstate}: {str(e).split(': ', 1)[-1][:90]}"
            login.simple("rollback")
            seen = [n for n in login.notices if "secretB" in n]
            leak = bool(seen) or "secretB" in outcome
            res[label[:2]] = leak
            if "42601" in outcome: res[label[:2]] = None          # syntax not in this major (DO SELECT is PG19)
            print(f"    {label}: foreign row {'SEEN' if leak else 'not seen'}; {outcome}"
                  + (f"; notices={seen}" if seen else ""))
        login.close()
        for o in ("view if exists rtv", "table if exists rt2", "function if exists monban_peek(text)"):
            admin.simple(f"drop {o}")
        admin.simple("drop table if exists rt cascade"); admin.simple("drop function if exists monban_rls_snap()")
        admin.close()
        word = lambda k: "n/a" if res.get(k) is None else "LEAKS" if res[k] else "clean"
        summary.append(f"pg{v}: P1 foreign-row peek {'REPRODUCES' if res.get('P1') else 'does not reproduce'}, "
                       f"P2 hardened {word('P2')}, P7 DO SELECT/RLS {word('P7')}, "
                       f"P8 DO SELECT/view {word('P8')}, controls P3-P6 "
                       f"{'LEAK' if any(res.get(k) for k in ('P3', 'P4', 'P5', 'P6')) else 'clean'}")
    print(f"{INFO_NAME} (information only, not a gate): " + "; ".join(summary))
    return 0

# =========================================================================================== driver
class Cfg:
    def __init__(self, a):
        self.seeds, self.n = a.seeds, a.n
        self.engines = set(a.engine) - ({"sqlite"} if a.skip_sqlite else set())
        self.skip_kv = bool(getattr(a, "skip_kv", False))
        sp = M.split_dsns(list(a.dsn or []), self.engines)
        self.dsns, self.urls = sp["pg"], list(a.url or [])
        self.my_dsns, self.crdb_dsns = sp["mariadb"], sp["crdb"]
        self.gate_only = not a.no_gate_demo
        self.exec = getattr(a, "_exec", None)
        self.sqlite_version = self.exec.version if self.exec else sqlite3.sqlite_version

def evaluate(subject, cfg, log=print):
    t0 = time.time()
    fams, info, versions = {}, {}, []
    if "sqlite" in cfg.engines:
        conn = lambda: cfg.exec.connect() if cfg.exec else sqlite3.connect(":memory:", isolation_level=None)
        mk = lambda d, r: SqliteEng(d, r, conn())
        tag = f"sqlite{cfg.sqlite_version} "
        versions.append(("sqlite", cfg.sqlite_version, None))
        refusal_family(subject, "sqlite", fams.setdefault(f"{tag}refusals (non-canonical handle, merge/cte/replace/raw_sql)", Stats()))
        sql_families(mk, "sqlite", SQ, subject, cfg, fams, tag)
        w6_family(lambda d, r, p: SqliteEng(d, r, conn(), p), "sqlite", W6_SQ, subject, cfg, fams, tag)
        if cfg.gate_only: sql_families(mk, "sqlite", SQ_GATE_ONLY, subject, cfg, info, tag)
    if "pg" in cfg.engines:
        for dsn in cfg.dsns:
            pg = L.Pg(dsn)
            v = L.pg_version(pg); versions.append(("postgres", v, dsn))
            log(f"  postgres server_version {v}")
            pg.simple("do $$ begin if not exists (select 1 from pg_collation where collname='ci_nd') then "
                      "create collation ci_nd (provider = icu, locale = 'und-u-ks-level2', deterministic = false); end if; end $$;")
            tag = f"pg{v} "
            refusal_family(subject, "postgres", fams.setdefault(f"{tag}refusals (non-canonical handle, merge/cte/replace/raw_sql)", Stats()))
            sql_families(lambda d, r: PgEng(pg, d, r), "postgres", PG, subject, cfg, fams, tag)
            w6_family(lambda d, r, p: PgEng(pg, d, r, p), "postgres", W6_PG, subject, cfg, fams, tag)
            if cfg.gate_only: sql_families(lambda d, r: PgEng(pg, d, r), "postgres", PG_GATE_ONLY, subject, cfg, info, tag)
            rls_family(pg, dsn, subject, cfg, fams, tag)
            pg.simple("drop table if exists t"); pg.simple("drop table if exists p"); pg.close()
    if "mariadb" in cfg.engines:
        for dsn in cfg.my_dsns:
            my = M.my_connect(dsn)
            v = M.my_version(my); versions.append(("mariadb", v, dsn))
            log(f"  mariadb {v} collation_connection={my.simple('select @@collation_connection')[1][0][0]}")
            tag = f"mariadb{v} "
            mk = lambda d, r: MariaEng(my, d, r)
            refusal_family(subject, "mariadb", fams.setdefault(f"{tag}refusals (non-canonical handle, merge/cte/replace/raw_sql)", Stats()))
            sql_families(mk, "mariadb", MARIA, subject, cfg, fams, tag)
            w6_family(lambda d, r, p: MariaEng(my, d, r, p), "mariadb", W6_MY, subject, cfg, fams, tag)
            if cfg.gate_only: sql_families(mk, "mariadb", MARIA_GATE_ONLY, subject, cfg, info, tag)
            my.simple("drop table if exists t"); my.simple("drop table if exists p"); my.close()
    if "crdb" in cfg.engines:
        for dsn in cfg.crdb_dsns:
            pg = L.Pg(dsn)
            v = M.crdb_version(pg); versions.append(("crdb", v, dsn))
            log(f"  cockroach {v}; isolation={pg.simple('show transaction isolation level')[1][0][0]}")
            tag = f"crdb{v} "
            refusal_family(subject, "crdb", fams.setdefault(f"{tag}refusals (non-canonical handle, merge/cte/replace/raw_sql)", Stats()))
            sql_families(lambda d, r: CrdbEng(pg, d, r), "crdb", CRDB, subject, cfg, fams, tag)
            w6_family(lambda d, r, p: CrdbEng(pg, d, r, p), "crdb", W6_CRDB, subject, cfg, fams, tag)
            if cfg.gate_only: sql_families(lambda d, r: CrdbEng(pg, d, r), "crdb", CRDB_GATE_ONLY, subject, cfg, info, tag)
            pg.simple("drop table if exists t"); pg.simple("drop table if exists p"); pg.close()
    if "redis" in cfg.engines:
        for url in cfg.urls:
            eng = KVLive(url); versions.append((eng.kind, eng.version, url))
            kv_family(subject, cfg, fams.setdefault(f"{eng.kind}{eng.version} kv (live)", Stats()), eng)
            kv_acl_family(subject, cfg, fams.setdefault(f"{eng.kind}{eng.version} kv_acl hostile commands as the tenant ACL user (live)", Stats()), eng, url)
            eng.close()
    elif "sqlite" in cfg.engines and not cfg.skip_kv:
        kv_family(subject, cfg, fams.setdefault("redis kv (model)", Stats()), KVModel())
        kv_acl_static_family(subject, fams.setdefault("redis kv_acl rules (static, offline)", Stats()))
    tot = Stats()
    for s in fams.values(): tot.add(s)
    return fams, info, tot, time.time() - t0, versions

BAD_KEYS = ("W1", "W2", "W4", "W6", "W7", "E", "FORM", "REFUSE", "BIND", "ACL", "errors_wellformed")
def bad_of(tot):
    return {k: tot[k] for k in BAD_KEYS if tot.get(k)}

def report(fams, info, tot, wall, log=print):
    log(f"{'family':84s} {'cases':>6s} {'W1':>4s} {'W2':>4s} {'W4':>4s} {'W6':>4s} {'W7':>4s} {'E':>4s} {'FORM':>4s} {'REF!':>4s} {'BIND':>4s} {'ACL':>4s} {'blk':>4s} {'ref':>4s}")
    for title, group in (("", fams), ("[schema-gate demo, not in verdict] ", info)):
        for n, s in group.items():
            log(f"{(title + n)[:84]:84s} {s['cases']:6d} {s['W1']:4d} {s['W2']:4d} {s['W4']:4d} {s['W6']:4d} {s['W7']:4d} {s['E']:4d} "
                f"{s['FORM']:4d} {s['REFUSE']:4d} {s['BIND']:4d} {s['ACL']:4d} {s['blocked']:4d} {s['refused']:4d}")
            if any(s.get(k) for k in BAD_KEYS) and s["examples"]:
                log("    e.g. " + json.dumps(s["examples"][0], ensure_ascii=True, default=str)[:420])
    log(f"total: cases={tot['cases']} W1={tot['W1']} W2={tot['W2']} W4={tot['W4']} W6={tot['W6']} W7={tot['W7']} E={tot['E']} "
        f"FORM={tot['FORM']} REFUSE={tot['REFUSE']} BIND={tot['BIND']} ACL={tot['ACL']} blocked={tot['blocked']} refused={tot['refused']} illformed={tot['illformed']} wall={wall:.1f}s")

SELFTEST_MUTANTS = [
    ("drop-tenant", "W1"),
    ("or-precedence", "W1"),
    ("upsert-global-arbiter", "W1"),
    ("replace-into", "W1"),
    ("returning-star", "W4"),
    ("set-tenant-passthrough", "W2"),
    ("upsert-tenant-from-row", "W2"),
    ("two-valued-not", "E"),
    ("like-prefix", "W1"),
    ("refuse-all", "E"),
    ("kv-naive", "W1"),
    ("kv-escaped-colon", "W7"),
    ("lenient-handle", "REFUSE"),
    ("insert-global-key", "W6"),
    ("fk-global", "W6"),
    ("upsert-as-merge", "FORM"),
    ("update-via-cte", "FORM"),
    ("accept-merge", "REFUSE"),
    ("kv-no-escape", "E"),
    ("kv-no-keycap", "REFUSE"),
    ("kv-collection-colon", "REFUSE"),
    ("kv-acl-all", "ACL"),
    ("kv-acl-allkeys", "ACL"),
    ("kv-acl-no-brace", "ACL"),
    ("kv-acl-eval", "ACL"),
]
ENGINE_MUTANTS = {
    "pg": [("drop-tenant", "W1"), ("upsert-global-arbiter", "W1"), ("returning-star", "W4"), ("set-tenant-passthrough", "W2"),
           ("pg-no-collate-c", "W1"), ("insert-global-key", "W6"), ("fk-global", "W6"), ("upsert-as-merge", "FORM"),
           ("update-via-cte", "FORM"),
           ("rls-no-force", "W1"), ("rls-check-true", "W2"), ("rls-split-update-true", "W1"), ("rls-no-role", "E"),
           ("rls-no-check", "FORM"), ("rls-wrong-column", "W4"), ("rls-session-setting", "BIND")],
    "redis": [("kv-naive", "W1"), ("kv-escaped-colon", "W7"), ("kv-no-escape", "E"), ("drop-tenant", "W1"),
              ("kv-acl-all", "ACL"), ("kv-acl-allkeys", "ACL"), ("kv-acl-no-brace", "ACL"), ("kv-acl-eval", "ACL")],
    # P7-oracle-adapters-001: every SQL write mutant of the SQLite / PG lists (RLS and kv mutants need PG RLS / Redis
    # ACLs, which these dialects do not have), plus the q4-005 engine-specific ones
    "mariadb": [("drop-tenant", "W1"), ("or-precedence", "W1"), ("upsert-global-arbiter", "W1"), ("replace-into", "W1"),
                ("returning-star", "W4"), ("set-tenant-passthrough", "W2"), ("upsert-tenant-from-row", "W2"),
                ("like-prefix", "W1"), ("refuse-all", "E"), ("lenient-handle", "REFUSE"), ("insert-global-key", "W6"),
                ("fk-global", "W6"), ("upsert-as-merge", "FORM"), ("update-via-cte", "FORM"), ("accept-merge", "REFUSE"),
                ("my-column-collation", "W1"), ("my-bin-padspace", "W1"), ("my-update-returning-naive", "W4"),
                ("my-odku-unguarded", "FORM")],
    "crdb": [("drop-tenant", "W1"), ("or-precedence", "W1"), ("upsert-global-arbiter", "W1"), ("returning-star", "W4"),
             ("set-tenant-passthrough", "W2"), ("upsert-tenant-from-row", "W2"), ("like-prefix", "W1"), ("refuse-all", "E"),
             ("lenient-handle", "REFUSE"), ("insert-global-key", "W6"), ("fk-global", "W6"), ("upsert-as-merge", "FORM"),
             ("update-via-cte", "FORM"), ("accept-merge", "REFUSE"),
             ("crdb-upsert-stmt", "W1"), ("crdb-column-collation", "W1"), ("crdb-reference-guard", "FORM")],
}
EXT_ENGINES = ("mariadb", "crdb")

def small_ns(a, engines, n=150):
    s = argparse.Namespace(**vars(a)); s.seeds = [20261025]; s.n = n; s.engine = engines; s.no_gate_demo = True; s.skip_sqlite = False; s.skip_kv = False
    return s

def self_test(a):
    live = [e for e in (a.engine or []) if e in ("pg", "redis") + EXT_ENGINES]
    use_sqlite = not a.skip_sqlite
    if not use_sqlite and not live:
        print(f"{NAME} SELF-TEST: FAIL (--skip-sqlite without any --engine pg/redis/mariadb/crdb leaves nothing to test)"); return 1
    ref = lambda muts=(), eng=None: M.ExtLocalSubject(muts) if eng in EXT_ENGINES else L.LocalSubject(muts)
    caught = n = 0
    if use_sqlite:
        cfg = Cfg(small_ns(a, ["sqlite"]))
        for mut, counter in SELFTEST_MUTANTS:
            _, _, tot, wall, _ = evaluate(L.LocalSubject([mut]), cfg, log=lambda *x: None)
            ok = bool(bad_of(tot)) and tot.get(counter, 0) > 0
            caught += ok; n += 1
            print(f"  mutant {mut:24s} expect {counter:6s}>0: " + " ".join(f"{k}={tot[k]}" for k in BAD_KEYS[:8]) +
                  f" -> {'CAUGHT' if ok else 'NOT CAUGHT'} ({wall:.1f}s)", flush=True)
    pos = True
    for eng in live:
        c2 = Cfg(small_ns(a, [eng], 100))
        _, _, tot, _, vers = evaluate(ref((), eng), c2, log=lambda *x: None)
        ok = not bad_of(tot); pos = pos and ok
        print(f"  [{eng} {' '.join(v for _, v, _ in vers)}] positive control (reference): cases={tot['cases']} " +
              " ".join(f"{k}={tot[k]}" for k in BAD_KEYS) + f" -> {'PASS' if ok else 'FAIL'}")
        for mut, counter in ENGINE_MUTANTS[eng]:
            _, _, tot, _, _ = evaluate(ref([mut], eng), c2, log=lambda *x: None)
            okm = tot.get(counter, 0) > 0; n += 1; caught += okm
            print(f"  [{eng}] mutant {mut:24s} expect {counter}>0: " + " ".join(f"{k}={tot[k]}" for k in BAD_KEYS[:10]) +
                  f" -> {'CAUGHT' if okm else 'NOT CAUGHT'}")
    ctl = Cfg(small_ns(a, (["sqlite"] if use_sqlite else []) + live, 100))
    ctl.skip_kv = bool(getattr(a, "skip_kv", False))   # subject-side only: the reference mutants above keep every family
    cmd = a.subject or (M.reference_cmd(HERE) if set(live) & set(EXT_ENGINES) else L.reference_cmd(HERE))
    sub = L.ProcSubject(cmd); _, _, tot, wall, _ = evaluate(sub, ctl, log=lambda *x: None); sub.close()
    ok = not bad_of(tot); pos = pos and ok
    print(f"  positive control via --subject {cmd!r}: cases={tot['cases']} " + " ".join(f"{k}={tot[k]}" for k in BAD_KEYS) +
          f" -> {'PASS' if ok else 'FAIL'} ({wall:.1f}s)")
    sub = L.ProcSubject(cmd + " --mutant drop-tenant"); _, _, tot2, _, _ = evaluate(sub, ctl, log=lambda *x: None); sub.close()
    pm = bool(bad_of(tot2)) and (tot2["W1"] > 0 or tot2["W7"] > 0)
    print(f"  {cmd + ' --mutant drop-tenant'!r} via --subject: W1={tot2['W1']} W7={tot2['W7']} -> {'CAUGHT' if pm else 'NOT CAUGHT'}")
    pm2 = True
    if not a.subject and use_sqlite:
        sub = L.ProcSubject(cmd + " --mutant upsert-global-arbiter"); _, _, tot3, _, _ = evaluate(sub, ctl, log=lambda *x: None); sub.close()
        pm2 = tot3["W1"] > 0
        print(f"  upsert-global-arbiter via --subject protocol: W1={tot3['W1']} -> {'CAUGHT' if pm2 else 'NOT CAUGHT'}")
    if caught == n and pos and pm and pm2:
        print(f"{NAME} SELF-TEST: PASS ({caught}/{n} mutants caught; positive control PASS; subject drop-tenant caught)"); return 0
    print(f"{NAME} SELF-TEST: FAIL ({caught}/{n} mutants caught; positive_control={pos}; subject_drop_tenant={pm}; proc_mutant={pm2})"); return 1

def main():
    ap = argparse.ArgumentParser(prog="run", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--subject"); ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--engine", action="append", choices=["sqlite", "pg", "redis", "mariadb", "crdb"])
    ap.add_argument("--dsn", action="append", help="postgresql:// (pg, crdb: CockroachDB iff its version() says so) or "
                    "mysql:// (mariadb); repeatable; throwaway (tables t and p are dropped)")
    ap.add_argument("--url", action="append")
    ap.add_argument("--skip-sqlite", action="store_true", help="no SQLite families (kv-only or pg-only subjects); also in --self-test")
    ap.add_argument("--skip-kv", action="store_true", help="no offline Redis-model families for a SQL-only subject (the Redis gates "
                    "cover them with the KV renderer); applies to --subject runs only, never to the oracle's reference mutants")
    ap.add_argument("--engine-pin", action="store_true", help="check every engine against supply-chain/engine-pins.toml "
                    "(implies --sqlite-exec when SQLite runs)")
    ap.add_argument("--sqlite-exec", action="store_true", help="run SQLite at the adapter pin through rust/sqlite-exec")
    ap.add_argument("--pins", default=os.path.join(L.repo_root(HERE), "supply-chain", "engine-pins.toml"))
    ap.add_argument("--seeds", type=lambda s: [int(x) for x in s.split(",")], default=SEEDS)
    ap.add_argument("--n", type=int, default=300, help="cases per family per schema per seed (research: 300)")
    ap.add_argument("--no-gate-demo", action="store_true", help="skip schemas the schema gate must refuse")
    ap.add_argument("--json")
    ap.add_argument("--pg-onconflict-info", action="store_true", help="information run (never a gate): ON CONFLICT WHERE "
                    "vs RLS on every --dsn (e.g. ci/engines.sh with pg19rc1 -- run --pg-onconflict-info --dsn @pg19rc1); exit 0")
    a = ap.parse_args()
    if a.pg_onconflict_info:
        if not a.dsn: ap.error("--pg-onconflict-info needs --dsn")
        sub = L.make_subject(a.subject); rc = pg_onconflict_info(a.dsn, sub); sub.close(); sys.exit(rc)
    if not a.engine: a.engine = ["sqlite"]
    if "pg" in a.engine and not a.dsn: ap.error("--engine pg needs --dsn")
    if "redis" in a.engine and not a.url: ap.error("--engine redis needs --url")
    for e in EXT_ENGINES:
        if e in a.engine and not a.dsn: ap.error(f"--engine {e} needs --dsn")
    if a.self_test: sys.exit(self_test(a))
    cleanup = None; a._exec = None
    try:
        if (a.sqlite_exec or a.engine_pin) and "sqlite" in a.engine and not a.skip_sqlite:
            binary, cleanup = L.build_sqlite_exec(HERE)
            a._exec = L.SqliteExec(binary)
        cfg = Cfg(a)
        subject = L.make_subject(a.subject) if (a.subject or not set(cfg.engines) & set(EXT_ENGINES)) else M.ExtLocalSubject()
        print(f"{NAME}: subject={subject.name} engines={sorted(cfg.engines)} sqlite={cfg.sqlite_version}"
              f"{' (sqlite-exec helper)' if cfg.exec else ' (python stdlib)'} seeds={cfg.seeds} n/family/schema/seed={cfg.n}", flush=True)
        fams, info, tot, wall, versions = evaluate(subject, cfg)
        subject.close()
    finally:
        if a._exec: a._exec.close()
        if cleanup: cleanup()
    report(fams, info, tot, wall)
    bad = bad_of(tot)
    pins_txt = ""
    if a.engine_pin:
        pins = L.load_pins(a.pins)
        res = [L.pin_check(pins, k, v, u) for k, v, u in versions]
        for ok, label in res: print(f"  engine-pin: {label} -> {'OK' if ok else 'MISMATCH'}")
        if not all(ok for ok, _ in res): bad["engine_pin"] = "; ".join(l for ok, l in res if not ok)
        pins_txt = " engine_pin=[" + ", ".join(l for _, l in res) + "]"
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"families": fams, "schema_gate_demo": info, "total": tot, "wall_s": wall, "bad": bad, "versions": versions},
                      fh, indent=1, default=str)
    summary = (f"cases={tot['cases']} families={len(fams)} W1={tot['W1']} W2={tot['W2']} W4={tot['W4']} W6={tot['W6']} "
               f"W7={tot['W7']} E={tot['E']} FORM={tot['FORM']} REFUSE={tot['REFUSE']} BIND={tot['BIND']} ACL={tot['ACL']}{pins_txt}")
    if bad or tot["cases"] == 0:
        print(f"{NAME}: FAIL ({', '.join(f'{k}={v}' for k, v in bad.items()) or 'no cases'}; {summary})"); sys.exit(1)
    print(f"{NAME}: PASS ({summary})")

if __name__ == "__main__":
    main()
