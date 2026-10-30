#!/usr/bin/env python3
"""AEGIS write-path differential oracle: INV-WRITE-SUBSET W1/W2/W4/W6 (+W3 via W1, +W7 for Redis), SPEC_INVARIANTS E.

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
  REFUSE requests that must be refused (non-canonical tenant handle, merge/cte/replace/raw_sql ops, invalid KV
      collection, KV key > 1024 bytes) were answered.
Ill-formed requests (SET of the tenant column, a request row carrying a tenant, upsert without a composite key) must
be refused or be W-safe; they get W checks but no effect check.  Engine errors count as blocked (fail-closed); a
blocked or refused WELL-FORMED request is an effect violation.
Tenant handles are the D4 encoding (TenantId u64 as 16 lower-case hex digits).
"""
import argparse, json, os, random, sqlite3, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)
import lowir as L  # noqa: E402

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

# =========================================================================================== checks
class Stats(dict):
    KEYS = ("cases", "W1", "W2", "W4", "W6", "W7", "E", "FORM", "REFUSE", "blocked", "refused", "illformed", "errors_wellformed")
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

def form_violation(op, sql):
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
    if op == "upsert" and "CONFLICT" not in w: return "upsert without ON CONFLICT"
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
    fv = form_violation(op, rep["sql"])
    if fv: st.viol("FORM", dict(ex, violation=f"FORM: {fv}"))
    eng.begin()
    try:
        names, rows = eng.run(rep["sql"], rep["params"])
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
                fv = form_violation("insert", rep["sql"])
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

# =========================================================================================== driver
class Cfg:
    def __init__(self, a):
        self.seeds, self.n = a.seeds, a.n
        self.engines = set(a.engine) - ({"sqlite"} if a.skip_sqlite else set())
        self.dsns, self.urls = list(a.dsn or []), list(a.url or [])
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
            pg.simple("drop table if exists t"); pg.simple("drop table if exists p"); pg.close()
    if "redis" in cfg.engines:
        for url in cfg.urls:
            eng = KVLive(url); versions.append((eng.kind, eng.version, url))
            kv_family(subject, cfg, fams.setdefault(f"{eng.kind}{eng.version} kv (live)", Stats()), eng)
            eng.close()
    elif "sqlite" in cfg.engines:
        kv_family(subject, cfg, fams.setdefault("redis kv (model)", Stats()), KVModel())
    tot = Stats()
    for s in fams.values(): tot.add(s)
    return fams, info, tot, time.time() - t0, versions

BAD_KEYS = ("W1", "W2", "W4", "W6", "W7", "E", "FORM", "REFUSE", "errors_wellformed")
def bad_of(tot):
    return {k: tot[k] for k in BAD_KEYS if tot.get(k)}

def report(fams, info, tot, wall, log=print):
    log(f"{'family':84s} {'cases':>6s} {'W1':>4s} {'W2':>4s} {'W4':>4s} {'W6':>4s} {'W7':>4s} {'E':>4s} {'FORM':>4s} {'REF!':>4s} {'blk':>4s} {'ref':>4s}")
    for title, group in (("", fams), ("[schema-gate demo, not in verdict] ", info)):
        for n, s in group.items():
            log(f"{(title + n)[:84]:84s} {s['cases']:6d} {s['W1']:4d} {s['W2']:4d} {s['W4']:4d} {s['W6']:4d} {s['W7']:4d} {s['E']:4d} "
                f"{s['FORM']:4d} {s['REFUSE']:4d} {s['blocked']:4d} {s['refused']:4d}")
            if any(s.get(k) for k in BAD_KEYS) and s["examples"]:
                log("    e.g. " + json.dumps(s["examples"][0], ensure_ascii=True, default=str)[:420])
    log(f"total: cases={tot['cases']} W1={tot['W1']} W2={tot['W2']} W4={tot['W4']} W6={tot['W6']} W7={tot['W7']} E={tot['E']} "
        f"FORM={tot['FORM']} REFUSE={tot['REFUSE']} blocked={tot['blocked']} refused={tot['refused']} illformed={tot['illformed']} wall={wall:.1f}s")

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
]
ENGINE_MUTANTS = {
    "pg": [("drop-tenant", "W1"), ("upsert-global-arbiter", "W1"), ("returning-star", "W4"), ("set-tenant-passthrough", "W2"),
           ("pg-no-collate-c", "W1"), ("insert-global-key", "W6"), ("fk-global", "W6"), ("upsert-as-merge", "FORM"),
           ("update-via-cte", "FORM")],
    "redis": [("kv-naive", "W1"), ("kv-escaped-colon", "W7"), ("kv-no-escape", "E"), ("drop-tenant", "W1")],
}

def small_ns(a, engines, n=150):
    s = argparse.Namespace(**vars(a)); s.seeds = [20261025]; s.n = n; s.engine = engines; s.no_gate_demo = True; s.skip_sqlite = False
    return s

def self_test(a):
    live = [e for e in (a.engine or []) if e in ("pg", "redis")]
    use_sqlite = not a.skip_sqlite
    if not use_sqlite and not live:
        print(f"{NAME} SELF-TEST: FAIL (--skip-sqlite without any --engine pg/redis leaves nothing to test)"); return 1
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
        _, _, tot, _, vers = evaluate(L.LocalSubject(), c2, log=lambda *x: None)
        ok = not bad_of(tot); pos = pos and ok
        print(f"  [{eng} {' '.join(v for _, v, _ in vers)}] positive control (reference): cases={tot['cases']} " +
              " ".join(f"{k}={tot[k]}" for k in BAD_KEYS) + f" -> {'PASS' if ok else 'FAIL'}")
        for mut, counter in ENGINE_MUTANTS[eng]:
            _, _, tot, _, _ = evaluate(L.LocalSubject([mut]), c2, log=lambda *x: None)
            okm = tot.get(counter, 0) > 0; n += 1; caught += okm
            print(f"  [{eng}] mutant {mut:24s} expect {counter}>0: " + " ".join(f"{k}={tot[k]}" for k in BAD_KEYS[:8]) +
                  f" -> {'CAUGHT' if okm else 'NOT CAUGHT'}")
    ctl = Cfg(small_ns(a, (["sqlite"] if use_sqlite else []) + live, 100))
    cmd = a.subject or L.reference_cmd(HERE)
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
    ap.add_argument("--engine", action="append", choices=["sqlite", "pg", "redis"])
    ap.add_argument("--dsn", action="append"); ap.add_argument("--url", action="append")
    ap.add_argument("--skip-sqlite", action="store_true", help="no SQLite families (kv-only or pg-only subjects); also in --self-test")
    ap.add_argument("--engine-pin", action="store_true", help="check every engine against supply-chain/engine-pins.toml "
                    "(implies --sqlite-exec when SQLite runs)")
    ap.add_argument("--sqlite-exec", action="store_true", help="run SQLite at the adapter pin through rust/sqlite-exec")
    ap.add_argument("--pins", default=os.path.join(L.repo_root(HERE), "supply-chain", "engine-pins.toml"))
    ap.add_argument("--seeds", type=lambda s: [int(x) for x in s.split(",")], default=SEEDS)
    ap.add_argument("--n", type=int, default=300, help="cases per family per schema per seed (research: 300)")
    ap.add_argument("--no-gate-demo", action="store_true", help="skip schemas the schema gate must refuse")
    ap.add_argument("--json")
    a = ap.parse_args()
    if not a.engine: a.engine = ["sqlite"]
    if "pg" in a.engine and not a.dsn: ap.error("--engine pg needs --dsn")
    if "redis" in a.engine and not a.url: ap.error("--engine redis needs --url")
    if a.self_test: sys.exit(self_test(a))
    cleanup = None; a._exec = None
    try:
        if (a.sqlite_exec or a.engine_pin) and "sqlite" in a.engine and not a.skip_sqlite:
            binary, cleanup = L.build_sqlite_exec(HERE)
            a._exec = L.SqliteExec(binary)
        cfg = Cfg(a)
        subject = L.make_subject(a.subject)
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
               f"W7={tot['W7']} E={tot['E']} FORM={tot['FORM']} REFUSE={tot['REFUSE']}{pins_txt}")
    if bad or tot["cases"] == 0:
        print(f"{NAME}: FAIL ({', '.join(f'{k}={v}' for k, v in bad.items()) or 'no cases'}; {summary})"); sys.exit(1)
    print(f"{NAME}: PASS ({summary})")

if __name__ == "__main__":
    main()
