#!/usr/bin/env python3
"""AEGIS write-path differential oracle: INV-WRITE-SUBSET W1/W2/W4 (+W3 via W1, +W7 for Redis), SPEC_INVARIANTS E.

Per case the subject renders ONE statement (UPDATE / DELETE / UPSERT, or Redis commands); the oracle runs it in a
transaction that is rolled back, diffs the WHOLE table (all tenants) pre vs post, and checks
  W1  every changed key's pre-image has tenant t and (update/delete) satisfies Pred (Lean `eval`)
  W2  every changed key's post-image has tenant t; for UPDATE, columns outside SET are unchanged
  W3  (upsert) the arbiter never selects a foreign row -- observed as a W1 violation on the foreign pre-image
  W4  RETURNING columns are within the permitted projection and every returned row is a tenant-t pre/post image
  W7  (Redis) replies contain no key or value of another tenant
  E   effect: the post-state and RETURNING set equal what the Lean model predicts for a correct renderer
      (rows kept by sql3/lowerQ over an exact backend get SET applied / are deleted; composite upsert inserts or
      updates (t, key)).  Catches lazy or over-eager renderers that W1/W2/W4 alone would let through.
Ill-formed requests (SET of the tenant column, a request row carrying a tenant, upsert without a composite key) must
be refused or be W-safe; they get W checks but no effect check.  Engine errors count as blocked (fail-closed); a
blocked or refused WELL-FORMED request is an effect violation.
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
TEN = ["acme", "ACME", "Acme", "acme ", "a%", "evil", "ss", "ß"]   # research wporacle.TEN

def mkrows(rng, n=60):    # research wporacle.mkrows + secret column
    return [dict(id=i + 1, tenant=rng.choice(TEN), grp=rng.choice(["g1", "g2", "g3"]),
                 x=rng.choice(["a", "A", "ab", "1", "10", "", "a%b", "ä", "z", None]), y=str(rng.choice([0, 1, 2, 10])),
                 secret=f"s{i + 1}") for i in range(n)]

LITS = ["a", "A", "ab", "1", "10", "", "a%b", "ä", "z", "g1", "g2", "0", "2", 1, 10, 0]
PFX = ["a", "A", "", "1", "a%", "a_", "g"]

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
SQ = {  # name -> (ddl, key, informational?)
    "plain id PK": ("create table t(id integer primary key, tenant text not null, grp text, x text, y text, secret text)", ["id"]),
    "composite PK (tenant,id)": ("create table t(id integer, tenant text not null, grp text, x text, y text, secret text, primary key (tenant,id))", ["tenant", "id"]),
    "NOCASE tenant, id PK": ("create table t(id integer primary key, tenant text collate nocase not null, grp text, x text, y text, secret text)", ["id"]),
    "STRICT composite PK": ("create table t(id integer, tenant text not null, grp text, x text, y text, secret text, primary key (tenant,id)) strict", ["tenant", "id"]),
    "untyped composite PK": ("create table t(id, tenant not null, grp, x, y, secret, primary key (tenant,id))", ["tenant", "id"]),
}
SQ_GATE_ONLY = {  # schemas the adapter schema gate must refuse; run for information, never part of the verdict
    "NOCASE tenant composite PK (schema gate must refuse)": ("create table t(id integer, tenant text collate nocase not null, grp text, x text, y text, secret text, primary key (tenant,id))", ["tenant", "id"]),
}

class SqliteEng:
    dialect = "sqlite"
    def __init__(self, ddl, rows):
        self.c = sqlite3.connect(":memory:", isolation_level=None)
        self.c.execute(ddl)
        for r in rows:
            self.c.execute("insert into t(id,tenant,grp,x,y,secret) values (?,?,?,?,?,?)", tuple(r[c] for c in COLS))
        self.decl = {r[1]: (r[2] or "") for r in self.c.execute("pragma table_info(t)")}
    def snap(self):
        return [dict(zip(COLS, r)) for r in self.c.execute("select id,tenant,grp,x,y,secret from t")]
    def begin(self): self.c.execute("begin")
    def rollback(self): self.c.execute("rollback")
    def run(self, sql, params):
        cur = self.c.execute(sql, params)
        if cur.description is None: return [], []
        names = [d[0] for d in cur.description]
        return names, [tuple(r) for r in cur.fetchall()]

class PgEng:
    dialect = "postgres"
    def __init__(self, pg, ddl, rows):
        self.pg = pg
        pg.simple("drop table if exists t")
        pg.simple(ddl)
        for r in rows:
            pg.query("insert into t(id,tenant,grp,x,y,secret) values ($1,$2,$3,$4,$5,$6)", tuple(r[c] for c in COLS))
        self.decl = {"id": "int", "tenant": "text", "grp": "text", "x": "text", "y": "text", "secret": "text"}
    def snap(self):
        return [dict(zip(COLS, r)) for r in self.pg.query("select id,tenant,grp,x,y,secret from t")[1]]
    def begin(self): self.pg.simple("begin")
    def rollback(self): self.pg.simple("rollback")
    def run(self, sql, params):
        names, rows = self.pg.query(sql, params)
        return (names or []), rows

PG = {
    "plain id PK": ("create table t(id int primary key, tenant text not null, grp text, x text, y text, secret text)", ["id"]),
    "composite PK (tenant,id)": ("create table t(id int, tenant text not null, grp text, x text, y text, secret text, primary key (tenant,id))", ["tenant", "id"]),
    "nondeterministic ICU tenant, id PK": ("create table t(id int primary key, tenant text collate ci_nd not null, grp text, x text, y text, secret text)", ["id"]),
}
PG_GATE_ONLY = {
    "nondeterministic ICU tenant composite PK (schema gate must refuse)": ("create table t(id int, tenant text collate ci_nd not null, grp text, x text, y text, secret text, primary key (tenant,id))", ["tenant", "id"]),
}

# =========================================================================================== checks
class Stats(dict):
    KEYS = ("cases", "W1", "W2", "W4", "E", "blocked", "refused", "illformed", "errors_wellformed")
    def __init__(self):
        super().__init__({k: 0 for k in self.KEYS}); self["examples"] = []
    def add(self, o):
        for k in self.KEYS: self[k] += o[k]
        self["examples"] += o["examples"][: max(0, 3 - len(self["examples"]))]

def kf(key):
    return lambda r: tuple(r[c] for c in key)

def model_keeps(t, p, r):
    return L.keeps(L.EXACT, r, L.lowerQ("tenant", t, p))

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
            if req["update"]:
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
        seen.add(kind); st[kind] += 1
        if len(st["examples"]) < 3: st["examples"].append(dict(ex, violation=f"{kind}: {msg}"))
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
            base = {"dialect": dialect, "table": "t", "tenant_field": "tenant", "key": key, "columns": eng.decl}
            # U: update with lowered Pred; 10% hostile SET tenant
            st = fams.setdefault(f"{prefix}U update SET .. WHERE lowerQ RETURNING | {sname}", Stats())
            for _ in range(cfg.n):
                t = rng.choice(TEN); p = gpred(rng)
                sets = {"x": rng.choice(["U", "a", ""])} if rng.random() < 0.7 else {"x": "U", "y": "u"}
                hostile = rng.random() < 0.1
                if hostile: sets = dict(sets, tenant=rng.choice([x for x in TEN if x != t]))
                req = dict(base, op="update", tenant=t, pred=p, set=sets, returning=rng.choice([["id", "tenant", "x"], ["id", "x"], ["id"]]))
                run_case(st, eng, subject, "update", t, req, not hostile, key)
            st = fams.setdefault(f"{prefix}D delete WHERE lowerQ RETURNING | {sname}", Stats())
            for _ in range(cfg.n):
                t = rng.choice(TEN); p = gpred(rng)
                req = dict(base, op="delete", tenant=t, pred=p, returning=rng.choice([["id", "tenant", "x", "y"], ["id"]]))
                run_case(st, eng, subject, "delete", t, req, True, key)
            fam = "UP upsert composite arbiter (tenant,id)" if composite else "UPG upsert on global-key table (must refuse or be W-safe)"
            st = fams.setdefault(f"{prefix}{fam} | {sname}", Stats())
            for _ in range(cfg.n):
                t = rng.choice(TEN)
                row = {"id": rng.randint(1, 70), "grp": "g1", "x": "N", "y": "n"}
                hostile = rng.random() < 0.1
                if hostile: row["tenant"] = rng.choice([x for x in TEN if x != t])
                upd = rng.choice([["x"], ["x", "y"], []])
                req = dict(base, op="upsert", tenant=t, row=row, update=upd, returning=rng.choice([["id", "tenant", "x"], ["id", "x"]]))
                run_case(st, eng, subject, "upsert", t, req, composite and not hostile, key)

# =========================================================================================== Redis / Valkey
KV_TEN = ["acme", "acme:x", "a*", "a?", "a[b]", "ab", "a", "a:b", "x]", "ACME", "acmé", ""]
KV_SUF = [b"k1", b"k2", b"b:c", b"x:b:c", b"c", b"}:x", b"*", b"", b"x:k1"]

class KVModel:
    """Offline model of the string subset of the Redis keyspace (SET GET DEL EXISTS)."""
    def __init__(self): self.d = {}
    def cmd(self, *a):
        c = a[0].upper()
        if c == b"SET": self.d[a[1]] = a[2]; return b"OK"
        if c == b"GET": return self.d.get(a[1])
        if c in (b"DEL", b"UNLINK"):
            n = 0
            for k in a[1:]:
                if k in self.d: del self.d[k]; n += 1
            return n
        if c == b"EXISTS": return sum(1 for k in a[1:] if k in self.d)
        return L.RespError(f"model: unsupported command {c!r}")
    def snap(self): return dict(self.d)
    def keys(self): return list(self.d)

class KVLive:
    def __init__(self, url):
        self.r = L.Resp(url); self.r.cmd(b"SELECT", self.r.db)
        if self.r.cmd(b"DBSIZE"): self.r.cmd(b"FLUSHDB")
    def cmd(self, *a): return self.r.cmd(*a)
    def snap(self):
        return {k: self.r.cmd(b"GET", k) for k in self.r.cmd(b"KEYS", b"*")}
    def restore(self, before):
        now = self.snap()
        for k in now:
            if k not in before: self.r.cmd(b"DEL", k)
        for k, v in before.items():
            if now.get(k) != v: self.r.cmd(b"SET", k, v)

def kv_family(subject, cfg, st, live_url=None):
    eng = KVLive(live_url) if live_url else KVModel()
    owner, val_owner = {}, {}
    cmds = lambda rep: [[bytes.fromhex(x) for x in c] for c in rep["commands"]]
    for i, t in enumerate(KV_TEN):
        for j, s in enumerate(KV_SUF):
            v = f"v:{i}:{j}".encode()
            rep = subject.call({"op": "kv_set", "tenant": t, "suffix_hex": s.hex(), "value_hex": v.hex()})
            if "refuse" in rep: st["refused"] += 1; continue
            for c in cmds(rep): eng.cmd(*c)
            kr = subject.call({"op": "kv_key", "tenant": t, "suffix_hex": s.hex()})
            k = bytes.fromhex(kr["key_hex"])
            if k in owner and owner[k] != t:
                st["W1"] += 1
                if len(st["examples"]) < 3: st["examples"].append({"violation": f"W1: key collision {k!r} owners {owner[k]!r}/{t!r}"})
            owner[k] = t; val_owner[v] = t
    pats = {}
    for t in KV_TEN:
        rep = subject.call({"op": "kv_scan", "tenant": t})
        pats[t] = bytes.fromhex(rep["pattern_hex"]) if "pattern_hex" in rep else None
    base = eng.snap()
    for seed in cfg.seeds:
        rng = random.Random(seed)
        for _ in range(cfg.n):
            st["cases"] += 1
            t = rng.choice(KV_TEN); s = rng.choice(KV_SUF + [b"x" + rng.choice(KV_SUF)])
            op = rng.choice(["kv_set", "kv_del", "kv_get", "kv_scan"])
            viol = []
            if op == "kv_scan":
                pat = pats[t]
                if pat is None: st["refused"] += 1; continue
                if live_url:
                    got, cur = set(), b"0"
                    while True:
                        r = eng.cmd(b"SCAN", cur, b"MATCH", pat, b"COUNT", b"1000"); cur = r[0]; got |= set(r[1])
                        if cur == b"0": break
                else:
                    got = {k for k in eng.keys() if L.stringmatchlen(pat, k)}
                for k in got:
                    if owner.get(k) != t: viol.append(("W7", f"SCAN reply holds foreign key {k!r} (owner {owner.get(k)!r})"))
                own = {k for k, o in owner.items() if o == t}
                if own - got: viol.append(("E", "SCAN misses own keys"))
            else:
                nv = f"n:{seed}:{st['cases']}".encode()
                req = {"op": op, "tenant": t, "suffix_hex": s.hex(), "value_hex": nv.hex()}
                rep = subject.call(req)
                if "refuse" in rep: st["refused"] += 1; continue
                pre = eng.snap()
                replies = [eng.cmd(*c) for c in cmds(rep)]
                post = eng.snap()
                for k in set(pre) | set(post):
                    if pre.get(k) == post.get(k): continue
                    if k in pre and owner.get(k, t) != t: viol.append(("W1", f"changed key of tenant {owner.get(k)!r}: {k!r}"))
                    if k in post and k not in owner:
                        others = [b for b, pt in pats.items() if b != t and pt is not None and L.stringmatchlen(pt, k)]
                        if others: viol.append(("W2", f"new key {k!r} inside namespace of {others[0]!r}"))
                        if pats[t] is not None and not L.stringmatchlen(pats[t], k): viol.append(("W2", f"new key {k!r} outside own namespace"))
                for r in replies:
                    if isinstance(r, bytes) and r in val_owner and val_owner[r] != t:
                        viol.append(("W7", f"reply carries value of tenant {val_owner[r]!r}"))
                if live_url: eng.restore(pre)
                else: eng.d = pre
            seen = set()
            for kind, msg in viol:
                if kind in seen: continue
                seen.add(kind); st[kind] = st.get(kind, 0) + 1
                if len(st["examples"]) < 3: st["examples"].append({"tenant": t, "op": op, "suffix": s.decode("latin1"), "violation": f"{kind}: {msg}"})
    if live_url: eng.cmd(b"FLUSHDB")

# =========================================================================================== driver
class Cfg:
    def __init__(self, a):
        self.seeds, self.n = a.seeds, a.n
        self.engines = set(a.engine); self.dsn, self.url = a.dsn, a.url
        self.gate_only = not a.no_gate_demo

def evaluate(subject, cfg, log=print):
    t0 = time.time()
    fams, info = {}, {}
    if "sqlite" in cfg.engines:
        sql_families(SqliteEng, "sqlite", SQ, subject, cfg, fams, "sqlite ")
        if cfg.gate_only: sql_families(SqliteEng, "sqlite", SQ_GATE_ONLY, subject, cfg, info, "sqlite ")
    if "pg" in cfg.engines:
        pg = L.Pg(cfg.dsn)
        log(f"  postgres server_version {pg.simple('show server_version')[1][0][0]}")
        pg.simple("do $$ begin if not exists (select 1 from pg_collation where collname='ci_nd') then "
                  "create collation ci_nd (provider = icu, locale = 'und-u-ks-level2', deterministic = false); end if; end $$;")
        sql_families(lambda d, r: PgEng(pg, d, r), "postgres", PG, subject, cfg, fams, "pg ")
        if cfg.gate_only: sql_families(lambda d, r: PgEng(pg, d, r), "postgres", PG_GATE_ONLY, subject, cfg, info, "pg ")
        pg.simple("drop table if exists t"); pg.close()
    st = fams.setdefault("redis kv " + ("(live)" if "redis" in cfg.engines else "(model)"), Stats())
    st["W7"] = 0
    kv_family(subject, cfg, st, cfg.url if "redis" in cfg.engines else None)
    tot = Stats(); tot["W7"] = 0
    for s in fams.values():
        tot.add(s); tot["W7"] += s.get("W7", 0)
    return fams, info, tot, time.time() - t0

def bad_of(tot):
    return {k: tot[k] for k in ("W1", "W2", "W4", "W7", "E", "errors_wellformed") if tot.get(k)}

def report(fams, info, tot, wall, log=print):
    log(f"{'family':84s} {'cases':>6s} {'W1':>4s} {'W2':>4s} {'W4':>4s} {'W7':>4s} {'E':>4s} {'blk':>4s} {'ref':>4s}")
    for title, group in (("", fams), ("[schema-gate demo, not in verdict] ", info)):
        for n, s in group.items():
            log(f"{(title + n)[:84]:84s} {s['cases']:6d} {s['W1']:4d} {s['W2']:4d} {s['W4']:4d} {s.get('W7', 0):4d} {s['E']:4d} {s['blocked']:4d} {s['refused']:4d}")
            if any(s.get(k) for k in ("W1", "W2", "W4", "W7", "E")) and s["examples"]:
                log("    e.g. " + json.dumps(s["examples"][0], ensure_ascii=True, default=str)[:420])
    log(f"total: cases={tot['cases']} W1={tot['W1']} W2={tot['W2']} W4={tot['W4']} W7={tot['W7']} E={tot['E']} "
        f"blocked={tot['blocked']} refused={tot['refused']} illformed={tot['illformed']} wall={wall:.1f}s")

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
]

def self_test(a):
    small = argparse.Namespace(**vars(a)); small.seeds = [20261025]; small.n = 150; small.engine = ["sqlite"]; small.no_gate_demo = True
    cfg = Cfg(small)
    caught = 0
    for mut, counter in SELFTEST_MUTANTS:
        _, _, tot, wall = evaluate(L.LocalSubject([mut]), cfg, log=lambda *x: None)
        ok = bool(bad_of(tot)) and tot.get(counter, 0) > 0
        caught += ok
        print(f"  mutant {mut:24s} expect {counter:3s}>0: W1={tot['W1']} W2={tot['W2']} W4={tot['W4']} W7={tot['W7']} E={tot['E']} "
              f"-> {'CAUGHT' if ok else 'NOT CAUGHT'} ({wall:.1f}s)", flush=True)
    cmd = f"{sys.executable} -I {os.path.join(HERE, 'lowir.py')} serve"
    sub = L.ProcSubject(cmd); _, _, tot, wall = evaluate(sub, cfg, log=lambda *x: None); sub.close()
    pos = not bad_of(tot)
    print(f"  positive control (reference via --subject protocol): cases={tot['cases']} W1={tot['W1']} W2={tot['W2']} "
          f"W4={tot['W4']} W7={tot['W7']} E={tot['E']} -> {'PASS' if pos else 'FAIL'} ({wall:.1f}s)")
    sub = L.ProcSubject(cmd + " --mutant upsert-global-arbiter"); _, _, tot2, _ = evaluate(sub, cfg, log=lambda *x: None); sub.close()
    pm = tot2["W1"] > 0
    print(f"  upsert-global-arbiter via --subject protocol: W1={tot2['W1']} -> {'CAUGHT' if pm else 'NOT CAUGHT'}")
    n = len(SELFTEST_MUTANTS)
    for eng, muts in (("pg", [("drop-tenant", "W1"), ("upsert-global-arbiter", "W1"), ("returning-star", "W4"),
                              ("set-tenant-passthrough", "W2"), ("pg-no-collate-c", "W1")]),
                      ("redis", [("kv-naive", "W1"), ("kv-escaped-colon", "W7")])):
        if eng not in (a.engine or []): continue
        e2 = argparse.Namespace(**vars(small)); e2.engine = [eng]; e2.n = 100
        c2 = Cfg(e2)
        _, _, tot, _ = evaluate(L.LocalSubject(), c2, log=lambda *x: None)
        ok = not bad_of(tot); pos = pos and ok
        print(f"  [{eng}] positive control: cases={tot['cases']} W1={tot['W1']} W2={tot['W2']} W4={tot['W4']} W7={tot['W7']} E={tot['E']} -> {'PASS' if ok else 'FAIL'}")
        for mut, counter in muts:
            _, _, tot, _ = evaluate(L.LocalSubject([mut]), c2, log=lambda *x: None)
            okm = tot.get(counter, 0) > 0; n += 1; caught += okm
            print(f"  [{eng}] mutant {mut:24s} expect {counter}>0: W1={tot['W1']} W2={tot['W2']} W4={tot['W4']} W7={tot['W7']} E={tot['E']} -> {'CAUGHT' if okm else 'NOT CAUGHT'}")
    if caught == n and pos and pm:
        print(f"{NAME} SELF-TEST: PASS ({caught}/{n} mutants caught; positive control PASS)"); return 0
    print(f"{NAME} SELF-TEST: FAIL ({caught}/{n} mutants caught; positive_control={pos}; proc_mutant={pm})"); return 1

def main():
    ap = argparse.ArgumentParser(prog="run", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--subject"); ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--engine", action="append", choices=["sqlite", "pg", "redis"])
    ap.add_argument("--dsn"); ap.add_argument("--url")
    ap.add_argument("--seeds", type=lambda s: [int(x) for x in s.split(",")], default=SEEDS)
    ap.add_argument("--n", type=int, default=300, help="cases per family per schema per seed (research: 300)")
    ap.add_argument("--no-gate-demo", action="store_true", help="skip schemas the schema gate must refuse")
    ap.add_argument("--json")
    a = ap.parse_args()
    if not a.engine: a.engine = ["sqlite"]
    if "pg" in a.engine and not a.dsn: ap.error("--engine pg needs --dsn")
    if "redis" in a.engine and not a.url: ap.error("--engine redis needs --url")
    if a.self_test: sys.exit(self_test(a))
    cfg = Cfg(a)
    subject = L.make_subject(a.subject)
    print(f"{NAME}: subject={subject.name} engines={sorted(cfg.engines)} sqlite={sqlite3.sqlite_version} seeds={cfg.seeds} n/family/schema/seed={cfg.n}", flush=True)
    fams, info, tot, wall = evaluate(subject, cfg)
    subject.close()
    report(fams, info, tot, wall)
    bad = bad_of(tot)
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"families": fams, "schema_gate_demo": info, "total": tot, "wall_s": wall, "bad": bad}, fh, indent=1, default=str)
    summary = f"cases={tot['cases']} families={len(fams)} W1={tot['W1']} W2={tot['W2']} W4={tot['W4']} W7={tot['W7']} E={tot['E']}"
    if bad or tot["cases"] == 0:
        print(f"{NAME}: FAIL ({', '.join(f'{k}={v}' for k, v in bad.items()) or 'no cases'}; {summary})"); sys.exit(1)
    print(f"{NAME}: PASS ({summary})")

if __name__ == "__main__":
    main()
