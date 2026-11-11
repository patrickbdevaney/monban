#!/usr/bin/env python3
"""q4-005: INV-WRITE-SUBSET write-path differential on MariaDB and CockroachDB (python3 -I, stdlib only).

Reuses oracles/lowering-write unmodified (imported read-only): row generator, Pred generator, Lean-model effect
prediction, W1/W2/W4/E checks, the family driver (`sql_families`) and the reference renderer (`lowir.Renderer`,
postgres dialect, used as-is for CockroachDB). Adds here:
  * mywire.My          -- MySQL/MariaDB wire client (binary prepared statements)
  * MariaRenderer      -- the hardened MariaDB write forms (dialect "mariadb") + MariaDB mutants
  * engines            -- MariaEng / CrdbEng (CockroachDB over lowir.Pg)
Usage:
  python3 -I q4005.py --maria mysql://root:x@127.0.0.1:55721/monban --crdb postgresql://root@127.0.0.1:55722/defaultdb
          [--n 300] [--seeds 1,2,3,20261025] [--json out.json] [--self-test]
"""
import argparse, json, os, random, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
ORACLE = os.path.normpath(os.path.join(HERE, "..", "..", "oracles", "lowering-write"))
sys.dont_write_bytecode = True
sys.path.insert(0, ORACLE)
sys.path.insert(0, HERE)
import lowir as L            # noqa: E402  (oracle, read-only)
import write_oracle as W     # noqa: E402  (oracle, read-only)
from mywire import My        # noqa: E402

COLS = W.COLS

# =========================================================================================== MariaDB renderer
def bq(name):
    return "`" + str(name).replace("`", "``") + "`"

MY_MUTANTS = {
    "my-column-collation": "string atoms compared under the column collation (c = ?), no binary cast",
    "my-bin-padspace": "string atoms compared with COLLATE utf8mb4_bin (binary but PAD SPACE: 'acme ' = 'acme')",
    "my-odku-unguarded": "ON DUPLICATE KEY UPDATE c = VALUES(c) without the tenant IF guard",
    "my-update-returning-naive": "UPDATE emulated RETURNING via SELECT without FOR UPDATE and without tenant (SELECT id,.. WHERE pred)",
}

class MariaRenderer(L.Renderer):
    """Hardened MariaDB (>= 10.5 RETURNING on INSERT/DELETE; no UPDATE RETURNING, verified on 11.8.9) forms.

    atoms     : strings  CAST(c AS BINARY) <op> CAST(? AS BINARY)  (byte order of UTF-8 = code-point order,
                byte prefix = code-point prefix; VARBINARY compares NO PAD), ints  c = ? on int columns only,
                class mismatch -> FALSE (MariaDB would coerce '1' = 1), NULL column -> NULL (Lean sql3)
    UPDATE    : UPDATE .. SET .. WHERE lowerQ  (no RETURNING in MariaDB); requested RETURNING is emulated by a
                preceding SELECT <post-image projection> .. WHERE lowerQ FOR UPDATE in the same transaction
    DELETE    : DELETE .. WHERE lowerQ RETURNING <permitted cols>
    UPSERT    : INSERT .. VALUES .. ON DUPLICATE KEY UPDATE c = IF(CAST(t AS BINARY) = CAST(VALUES(t) AS BINARY),
                VALUES(c), c) RETURNING ..   (update=[]: INSERT .. SELECT .. FROM DUAL WHERE NOT EXISTS (own key))
                refused unless the key contains the tenant (arbiter of ODKU = ANY unique key: schema gate must
                ensure the composite PK is the ONLY unique index and tenant/key columns are NO PAD binary)
    never     : REPLACE, INSERT IGNORE, multi-table UPDATE/DELETE
    """
    def __init__(self, mutants=()):
        my = [m for m in mutants if m in MY_MUTANTS]
        super().__init__([m for m in mutants if m not in MY_MUTANTS])
        self.my = set(my)

    class Ctx(L.Renderer.Ctx):
        def __init__(self, req):
            r = dict(req, dialect="sqlite")      # base ctor only validates; we override ph/col
            super().__init__(r)
            self.dialect = "mariadb"
        def ph(self, v):
            self.params.append(v); return "?"
        def col(self, f, alias=None):
            a = self.alias if alias is None else alias
            return (bq(a) + "." if a else "") + bq(f)

    def handle(self, req):
        if req.get("op") in ("update", "delete", "upsert", "read") and req.get("dialect") != "mariadb":
            raise ValueError("MariaRenderer serves dialect mariadb only")
        return super().handle(req)

    def tt(self, ctx): return "TRUE"
    def ff(self, ctx): return "FALSE"

    def _s(self, c, ph):
        if "my-column-collation" in self.my: return c, ph
        if "my-bin-padspace" in self.my: return c, f"{ph} COLLATE utf8mb4_bin"
        return f"CAST({c} AS BINARY)", f"CAST({ph} AS BINARY)"

    def eq_test(self, f, v, ctx, alias=None):
        c = ctx.col(f, alias)
        cc = L.col_class(ctx.columns.get(f))
        if cc is not type(v): return "FALSE"
        if type(v) is int:
            return "FALSE" if not self._int_ok(v) else f"({c} = {ctx.ph(v)})"
        a, b = self._s(c, ctx.ph(v))
        return f"({a} = {b})"

    def range_test(self, f, lo, hi, ctx):
        c = ctx.col(f)
        cc = L.col_class(ctx.columns.get(f))
        if type(lo) is not type(hi) or cc is not type(lo): return "FALSE"
        if type(lo) is int:
            if lo > L.INT64_MAX or hi < L.INT64_MIN: return "FALSE"
            lo, hi = max(lo, L.INT64_MIN), min(hi, L.INT64_MAX)
            return f"({c} >= {ctx.ph(lo)} AND {c} <= {ctx.ph(hi)})"
        a, b1 = self._s(c, ctx.ph(lo)); _, b2 = self._s(c, ctx.ph(hi))
        return f"({a} >= {b1} AND {a} <= {b2})"

    def pfx_test(self, f, s, ctx):
        c = ctx.col(f)
        if L.col_class(ctx.columns.get(f)) is not str: return "FALSE"
        if "like-prefix" in self.m:
            return f"({c} LIKE {ctx.ph(s + '%')})"
        if "my-column-collation" in self.my or "my-bin-padspace" in self.my:
            a, b = self._s(f"LEFT({c}, {ctx.ph(len(s))})", ctx.ph(s))
            return f"({a} = {b})"
        n = len(s.encode("utf-8"))
        return f"(LEFT(CAST({c} AS BINARY), {ctx.ph(n)}) = CAST({ctx.ph(s)} AS BINARY))"

    def write(self, req):
        op = req["op"]
        ctx = self.Ctx(req); ctx.alias = None
        table, tf = req["table"], req["tenant_field"]
        cols = req.get("columns") or {}
        t = L.check_value(req["tenant"])
        key = list(req.get("key") or [])
        ret = list(req.get("returning") or [])
        for c in ret:
            if c not in cols: raise ValueError(f"returning unknown column {c!r}")
        retcols = list(cols) if "returning-star" in self.m else ret
        retsql = (" RETURNING *" if "returning-star" in self.m else
                  (" RETURNING " + ", ".join(bq(c) for c in ret) if ret else ""))
        if op == "update":
            sets = req.get("set") or {}
            if not sets: raise ValueError("empty SET")
            for c, v in sets.items():
                if c not in cols: raise ValueError(f"unknown column {c!r}")
                if (c == tf or c in key) and "set-tenant-passthrough" not in self.m:
                    raise ValueError(f"refused: SET of tenant/key column {c!r}")
                L.check_value(v)
            stmts = []
            if retcols:
                sctx = self.Ctx(req); sctx.alias = None
                proj = []
                for c in retcols:
                    proj.append(f"{sctx.ph(sets[c])} AS {bq(c)}" if c in sets else bq(c))
                if "my-update-returning-naive" in self.my:
                    w = self.render(req["pred"], sctx)
                    stmts.append({"sql": f"SELECT {', '.join(proj)} FROM {bq(table)} WHERE {w}", "params": sctx.params, "ret": True})
                else:
                    w = self.where(req, sctx)
                    stmts.append({"sql": f"SELECT {', '.join(proj)} FROM {bq(table)} WHERE {w} FOR UPDATE",
                                  "params": sctx.params, "ret": True})
            setsql = ", ".join(f"{bq(c)} = {ctx.ph(v)}" for c, v in sets.items())
            w = self.where(req, ctx)
            stmts.append({"sql": f"UPDATE {bq(table)} SET {setsql} WHERE {w}", "params": ctx.params, "ret": False})
            return {"sql": stmts, "params": []}
        if op == "delete":
            w = self.where(req, ctx)
            return {"sql": f"DELETE FROM {bq(table)} WHERE {w}{retsql}", "params": ctx.params}
        # upsert
        row = dict(req.get("row") or {})
        upd = list(req.get("update") or [])
        for c in list(row) + upd:
            if c not in cols: raise ValueError(f"unknown column {c!r}")
        if tf in row and "upsert-tenant-from-row" not in self.m:
            raise ValueError("refused: request row carries the tenant column")
        for c in upd:
            if c == tf or c in key: raise ValueError(f"refused: update of tenant/key column {c!r}")
        for v in row.values(): L.check_value(v)
        vals = dict(row)
        if "upsert-tenant-from-row" not in self.m or tf not in vals:
            vals[tf] = t
        names = [tf] + [c for c in vals if c != tf]
        collist = ", ".join(bq(c) for c in names)
        if "replace-into" in self.m:
            ph = ", ".join(ctx.ph(vals[c]) for c in names)
            return {"sql": f"REPLACE INTO {bq(table)} ({collist}) VALUES ({ph}){retsql}", "params": ctx.params}
        if "upsert-global-arbiter" in self.m:
            ph = ", ".join(ctx.ph(vals[c]) for c in names)
            sets = ", ".join(f"{bq(c)} = VALUES({bq(c)})" for c in upd) or f"{bq('id')} = {bq('id')}"
            return {"sql": f"INSERT INTO {bq(table)} ({collist}) VALUES ({ph}) ON DUPLICATE KEY UPDATE {sets}{retsql}",
                    "params": ctx.params}
        if tf not in key:
            raise ValueError("refused: upsert arbiter must include the tenant column (composite key required)")
        for c in key:
            if c != tf and c not in row: raise ValueError(f"upsert row lacks key column {c!r}")
        if not upd:
            # DO NOTHING: insert-if-absent; never INSERT IGNORE (downgrades errors to warnings)
            ph = ", ".join(ctx.ph(vals[c]) for c in names)
            conds = []
            for c in key:
                if type(vals[c]) is str:
                    conds.append(f"CAST({bq(c)} AS BINARY) = CAST({ctx.ph(vals[c])} AS BINARY)")
                else:
                    conds.append(f"{bq(c)} = {ctx.ph(vals[c])}")
            return {"sql": f"INSERT INTO {bq(table)} ({collist}) SELECT {ph} FROM DUAL WHERE NOT EXISTS "
                           f"(SELECT 1 FROM {bq(table)} WHERE {' AND '.join(conds)}){retsql}", "params": ctx.params}
        ph = ", ".join(ctx.ph(vals[c]) for c in names)
        if "my-odku-unguarded" in self.my:
            sets = ", ".join(f"{bq(c)} = VALUES({bq(c)})" for c in upd)
        else:
            g = f"CAST({bq(tf)} AS BINARY) = CAST(VALUES({bq(tf)}) AS BINARY)"
            sets = ", ".join(f"{bq(c)} = IF({g}, VALUES({bq(c)}), {bq(c)})" for c in upd)
        return {"sql": f"INSERT INTO {bq(table)} ({collist}) VALUES ({ph}) ON DUPLICATE KEY UPDATE {sets}{retsql}",
                "params": ctx.params}

# =========================================================================================== Cockroach mutant
class CrdbRenderer(L.Renderer):
    """The oracle's postgres-dialect reference renderer with one CockroachDB change (upsert guard casts both sides
    to text); mutants crdb-upsert-stmt (UPSERT INTO), crdb-column-collation, crdb-reference-guard (oracle PG guard)."""
    def __init__(self, mutants=()):
        self.up = "crdb-upsert-stmt" in mutants
        self.nocast = "crdb-column-collation" in mutants
        self.refguard = "crdb-reference-guard" in mutants
        super().__init__([m for m in mutants if m not in ("crdb-upsert-stmt", "crdb-column-collation", "crdb-reference-guard")])
    def eq_test(self, f, v, ctx, alias=None):
        if self.nocast and type(v) is str and L.col_class(ctx.columns.get(f)) is str:
            return f"({ctx.col(f, alias)} = {ctx.ph(v)})"     # compares under the column collation
        return super().eq_test(f, v, ctx, alias)
    def write(self, req):
        if self.up and req["op"] == "upsert":
            row = dict(req["row"]); row[req["tenant_field"]] = req["tenant"]
            names = [req["tenant_field"]] + [c for c in row if c != req["tenant_field"]]
            ret = req.get("returning") or []
            sql = (f"UPSERT INTO {L.qi(req['table'])} ({', '.join(L.qi(c) for c in names)}) VALUES "
                   f"({', '.join(f'${i + 1}' for i in range(len(names)))})" +
                   (" RETURNING " + ", ".join(L.qi(c) for c in ret) if ret else ""))
            return {"sql": sql, "params": [row[c] for c in names]}
        out = super().write(req)
        if req["op"] == "upsert" and "sql" in out and not self.refguard:
            # CockroachDB: `collated = (x COLLATE "C")` is evaluated under the LEFT operand's collation (probe
            # collated-composite-pk), so the oracle's postgres guard is case-insensitive there. Cast both sides.
            t, tf = L.qi(req["table"]), L.qi(req["tenant_field"])
            old = f' WHERE {t}.{tf} = excluded.{tf} COLLATE "C"'
            new = f' WHERE {t}.{tf}::text = excluded.{tf}::text COLLATE "C"'
            if old in out["sql"]: out["sql"] = out["sql"].replace(old, new)
        return out

class Subject:
    def __init__(self, renderer, name):
        self.r, self.name = renderer, name
    def call(self, req):
        req = L._roundtrip(req)
        try:
            out = self.r.handle(req)
        except (ValueError, KeyError, TypeError) as e:
            out = {"refuse": str(e)}
        return L._roundtrip(out)
    def close(self): pass

# =========================================================================================== engines
DECL = {"id": "int", "tenant": "text", "grp": "text", "x": "text", "y": "text", "secret": "text"}

def _norm(v):
    return v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else v

class MariaEng:
    dialect = "mariadb"
    def __init__(self, my, ddl, rows):
        self.my = my
        my.simple("drop table if exists t")
        my.simple(ddl)
        for r in rows:
            my.query("insert into t(id,tenant,grp,x,y,secret) values (?,?,?,?,?,?)", tuple(r[c] for c in COLS))
        self.decl = dict(DECL)
    def snap(self):
        return [dict(zip(COLS, map(_norm, r))) for r in self.my.query("select id,tenant,grp,x,y,secret from t")[1]]
    def begin(self): self.my.simple("begin")
    def rollback(self): self.my.simple("rollback")
    def run(self, sql, params):
        if isinstance(sql, list):          # multi-statement reply (UPDATE + emulated RETURNING)
            names, rows = [], []
            for st in sql:
                n, r = self.my.query(st["sql"], st["params"])
                if st.get("ret"): names, rows = (n or []), [tuple(map(_norm, x)) for x in r]
            return names, rows
        names, rows = self.my.query(sql, params)
        return (names or []), [tuple(map(_norm, r)) for r in rows]

class CrdbEng(W.PgEng):
    dialect = "postgres"

# MariaDB: x/y/grp keep the server default collation (utf8mb4_uca1400_ai_ci: case- AND accent-insensitive).
MY_TAIL = "grp varchar(16), x varchar(16), y varchar(16), secret varchar(16)"
MARIA = {
    "plain id PK, tenant utf8mb4_general_ci": (f"create table t(id int primary key, tenant varchar(16) collate utf8mb4_general_ci not null, {MY_TAIL}) engine=innodb", ["id"]),
    "composite PK, tenant utf8mb4_nopad_bin": (f"create table t(id int, tenant varchar(16) collate utf8mb4_nopad_bin not null, {MY_TAIL}, primary key (tenant,id)) engine=innodb", ["tenant", "id"]),
    "composite PK, tenant VARBINARY": (f"create table t(id int, tenant varbinary(64) not null, {MY_TAIL}, primary key (tenant,id)) engine=innodb", ["tenant", "id"]),
}
MARIA_GATE_ONLY = {
    "composite PK, tenant utf8mb4_bin (PAD SPACE)": (f"create table t(id int, tenant varchar(16) collate utf8mb4_bin not null, {MY_TAIL}, primary key (tenant,id)) engine=innodb", ["tenant", "id"]),
    "composite PK, tenant utf8mb4_general_ci": (f"create table t(id int, tenant varchar(16) collate utf8mb4_general_ci not null, {MY_TAIL}, primary key (tenant,id)) engine=innodb", ["tenant", "id"]),
    "composite PK, tenant default uca1400_ai_ci": (f"create table t(id int, tenant varchar(16) not null, {MY_TAIL}, primary key (tenant,id)) engine=innodb", ["tenant", "id"]),
    "composite PK nopad_bin + second UNIQUE(id)": (f"create table t(id int, tenant varchar(16) collate utf8mb4_nopad_bin not null, {MY_TAIL}, primary key (tenant,id), unique key (id)) engine=innodb", ["tenant", "id"]),
}
CRDB = {
    "plain id PK": ("create table t(id int primary key, tenant string not null, grp string, x string, y string, secret string)", ["id"]),
    "composite PK (tenant,id)": ("create table t(id int, tenant string not null, grp string, x string, y string, secret string, primary key (tenant,id))", ["tenant", "id"]),
    "collated tenant en_u_ks_level2, id PK": ("create table t(id int primary key, tenant string collate en_u_ks_level2 not null, grp string, x string, y string, secret string)", ["id"]),
}
CRDB_GATE_ONLY = {
    "composite PK, tenant collate en_u_ks_level2": ("create table t(id int, tenant string collate en_u_ks_level2 not null, grp string, x string, y string, secret string, primary key (tenant,id))", ["tenant", "id"]),
    "composite PK + second UNIQUE(id)": ("create table t(id int, tenant string not null, grp string, x string, y string, secret string, primary key (tenant,id), unique (id))", ["tenant", "id"]),
}

class Cfg:
    def __init__(self, seeds, n): self.seeds, self.n = seeds, n

def run_engine(name, eng_factory, dialect, schemas, gate, subject, cfg):
    fams, info = {}, {}
    W.sql_families(eng_factory, dialect, schemas, subject, cfg, fams, name + " ")
    if gate: W.sql_families(eng_factory, dialect, gate, subject, cfg, info, name + " ")
    return fams, info

def total(fams):
    tot = W.Stats(); tot["W7"] = 0
    for s in fams.values(): tot.add(s)
    return tot

def evaluate(a, which, maria_mut=(), crdb_mut=(), gate=True, cfg=None, log=print):
    cfg = cfg or Cfg(a.seeds, a.n)
    out = {}
    if "maria" in which:
        my = My(a.maria)
        my.simple("set session sql_mode = 'STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION,ERROR_FOR_DIVISION_BY_ZERO'")
        log(f"  mariadb {my.server_version}; collation_connection={my.simple('select @@collation_connection')[1][0][0]}")
        sub = Subject(MariaRenderer(maria_mut), "maria" + str(list(maria_mut)))
        out["mariadb"] = run_engine("mariadb", lambda d, r: MariaEng(my, d, r), "mariadb", MARIA,
                                    MARIA_GATE_ONLY if gate else None, sub, cfg)
        my.simple("drop table if exists t"); my.close()
    if "crdb" in which:
        pg = L.Pg(a.crdb)
        log(f"  cockroach {pg.simple('select version()')[1][0][0][:40]}; isolation={pg.simple('show transaction isolation level')[1][0][0]}")
        sub = Subject(CrdbRenderer(crdb_mut), "crdb" + str(list(crdb_mut)))
        out["cockroachdb"] = run_engine("crdb", lambda d, r: CrdbEng(pg, d, r), "postgres", CRDB,
                                        CRDB_GATE_ONLY if gate else None, sub, cfg)
        pg.simple("drop table if exists t"); pg.close()
    return out

MY_SELFTEST = [("drop-tenant", "W1"), ("upsert-global-arbiter", "W1"), ("replace-into", "W1"), ("returning-star", "W4"),
               ("set-tenant-passthrough", "W2"), ("upsert-tenant-from-row", "W2"), ("like-prefix", "W1"),
               ("my-column-collation", "W1"), ("my-bin-padspace", "W1"), ("my-update-returning-naive", "W4"),
               ("refuse-all", "E")]
CR_SELFTEST = [("drop-tenant", "W1"), ("upsert-global-arbiter", "W1"), ("returning-star", "W4"),
               ("set-tenant-passthrough", "W2"), ("upsert-tenant-from-row", "W2"), ("crdb-upsert-stmt", "W1"),
               ("crdb-column-collation", "W1"), ("refuse-all", "E")]
# informational (run incl. schema-gate-demo schemas, not in the verdict): pg-no-collate-c is equivalent on CockroachDB
# (::text drops a collated string's locale); crdb-reference-guard = the oracle's PG upsert guard verbatim.
CR_INFO = [("pg-no-collate-c", "W1"), ("crdb-reference-guard", "W1")]

def self_test(a):
    cfg = Cfg([20261025], 100)
    res = {}
    ok_all = True
    for eng, muts, key in (("maria", MY_SELFTEST, "mariadb"), ("crdb", CR_SELFTEST, "cockroachdb"),
                           ("crdb", CR_INFO, "cockroachdb (informational, not in verdict)")):
        if not getattr(a, eng): continue
        info = "informational" in key
        for mut, counter in muts:
            kw = {"maria_mut": [mut]} if eng == "maria" else {"crdb_mut": [mut]}
            out = evaluate(a, {eng}, gate=info, cfg=cfg, log=lambda *x: None, **kw)
            fams, gi = out["mariadb" if eng == "maria" else "cockroachdb"]
            tot = total(dict(fams, **{"gate " + k: v for k, v in gi.items()}))
            caught = tot.get(counter, 0) > 0
            res[f"{key}:{mut}"] = {"expect": counter, "W1": tot["W1"], "W2": tot["W2"], "W4": tot["W4"], "E": tot["E"], "caught": caught}
            if not info: ok_all &= caught
            print(f"  [{key}] mutant {mut:28s} expect {counter}>0: W1={tot['W1']} W2={tot['W2']} W4={tot['W4']} E={tot['E']} -> {'CAUGHT' if caught else 'NOT CAUGHT'}", flush=True)
    print(f"q4-005 SELF-TEST: {'PASS' if ok_all else 'FAIL'}")
    return res, ok_all

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--maria"); ap.add_argument("--crdb")
    ap.add_argument("--seeds", type=lambda s: [int(x) for x in s.split(",")], default=W.SEEDS)
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--json"); ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        res, ok = self_test(a)
        if a.json:
            with open(a.json, "w") as fh: json.dump(res, fh, indent=1)
        sys.exit(0 if ok else 1)
    which = {e for e in ("maria", "crdb") if getattr(a, e)}
    t0 = time.time()
    out = evaluate(a, which)
    js = {}
    bad_any = False
    for eng, (fams, info) in out.items():
        print(f"== {eng}")
        tot = total(fams)
        W.report(fams, info, tot, time.time() - t0)
        bad = W.bad_of(tot)
        bad_any |= bool(bad)
        print(f"{eng}: {'FAIL ' + str(bad) if bad else 'PASS'} (cases={tot['cases']} families={len(fams)})")
        js[eng] = {"families": fams, "schema_gate_demo": info, "total": tot, "bad": bad}
    if a.json:
        with open(a.json, "w") as fh: json.dump(js, fh, indent=1, default=str)
    print(f"wall {time.time() - t0:.1f}s")
    sys.exit(1 if bad_any else 0)

if __name__ == "__main__":
    main()
