#!/usr/bin/env python3
"""Reference subject for the schema-gate oracle (stdlib only, run as `python3 -I refsubject.py serve [--mutant M]`).

It answers the schema-gate protocol (README.md) the way aegis-data-ir / aegis-adapter-sqlite / aegis-adapter-pg must:

* static: a port of F4 `check_schema` (crates/aegis-data-ir/src/ir.rs) applied to the admission probe
  Op{collection = schema.collection, kind = Upsert, filter = Tt, writes = [], returning = []} at Fidelity::Exact;
* sqlite / pg: introspect the LIVE catalog (never the declared Schema), fill an F4 Schema from it, run the same
  F4 checks, plus the live-only checks (W5 closure / D8, D7, FORCE RLS, partition key, tenant type).

`--mutant` switches off one check (negative controls for --self-test). The reference is the positive control.
"""
import json, re, sqlite3, sys, urllib.parse

import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pgwire import Pg, PgError  # noqa: E402

MUTANTS = [
    "refuse-all",                 # refuses everything (golden rejected -> red)
    "accept-all",                 # accepts everything
    "ignore-collation",           # no collation / citext / char(n) check on tenant and key columns (columns + indexes)
    "ignore-index-collation",     # column collations checked, unique-index key collations not
    "ignore-second-unique",       # admits when ANY unique index is (t,key)
    "ignore-prefix-index",        # prefix / partial / expression flags ignored
    "ignore-nullable-tenant",     # tenant NULL-ability not checked
    "ignore-triggers",            # triggers on the collection not checked
    "ignore-rules",               # PG rewrite rules not checked
    "ignore-fk-actions",          # FK ON DELETE/UPDATE actions not checked
    "ignore-generated",           # generated tenant column admitted
    "ignore-tenant-type",         # tenant affinity / type not checked
    "ignore-rowid-alias",         # SQLite INTEGER PRIMARY KEY rowid alias not counted as a unique key
    "ignore-exclusion",           # PG exclusion constraints not counted as arbiters
    "ignore-rls",                 # PG RLS enable/force/policy not checked
    "ignore-partition",           # PG partition key opclass/collation not checked
    "ignore-not-a-table",         # views / virtual tables admitted as collections
    "declared-not-introspected",  # trusts the declared Schema instead of the catalog
    "class-blind",                # right accept/refuse decisions, constant refusal class
]


class Refuse(Exception):
    pass


# ---------------------------------------------------------------------------------------------- F4 static check
COLLATIONS = ("Binary", "PadSpace", "CaseInsensitive", "Nondeterministic")


def parse_schema(j):
    """F4 Schema JSON (field names as in ir.rs). Raises ValueError on a malformed document."""
    if not isinstance(j, dict):
        raise ValueError("schema not an object")
    cols = []
    for c in j["columns"]:
        if c["collation"] not in COLLATIONS:
            raise ValueError("bad collation")
        cols.append({"field": int(c["field"]), "name": str(c["name"]), "nullable": bool(c["nullable"]),
                     "collation": c["collation"], "key": bool(c["key"])})
    return {"collection": str(j["collection"]), "tenant_field": int(j["tenant_field"]), "columns": cols,
            "permitted": [int(f) for f in j["permitted"]],
            "unique_indexes": [{"fields": [int(f) for f in u["fields"]], "prefix": bool(u["prefix"])}
                               for u in j["unique_indexes"]]}


def check_schema_probe(s, m):
    """F4 check_schema(probe, s, Exact) for the admission probe (an Upsert with no writes, no returning, filter Tt).
    Order of the checks is the order in ir.rs."""
    tf = s["tenant_field"]
    if m != "ignore-nullable-tenant" and any(c["field"] == tf and c["nullable"] for c in s["columns"]):
        raise Refuse("TenantFieldNullable")
    if m != "ignore-collation":
        for c in s["columns"]:
            if (c["field"] == tf or c["key"]) and c["collation"] != "Binary":
                raise Refuse(f"NonBinaryCollation({c['field']})")
    want = sorted(c["field"] for c in s["columns"] if c["key"] or c["field"] == tf)
    ux = s["unique_indexes"]

    def fits(u):
        got = sorted(u["fields"])
        return (m == "ignore-prefix-index" or not u["prefix"]) and got == want and tf in got and len(got) >= 2
    if m == "ignore-second-unique":
        ok = any(fits(u) for u in ux)
    else:
        ok = len(ux) == 1 and fits(ux[0])
    if not ok:
        raise Refuse("UpsertArbiterNotTenantScoped")


# ---------------------------------------------------------------------------------------------- SQLite (live)
def sqlite_affinity(decl):
    """SQLite datatype affinity rules (https://sqlite.org/datatype3.html §3.1), in order."""
    t = (decl or "").upper()
    if "INT" in t:
        return "INTEGER"
    if "CHAR" in t or "CLOB" in t or "TEXT" in t:
        return "TEXT"
    if "BLOB" in t or t == "":
        return "BLOB"
    if "REAL" in t or "FLOA" in t or "DOUB" in t:
        return "REAL"
    return "NUMERIC"


def qi(name):
    return '"' + name.replace('"', '""') + '"'


def sqlite_col_collation(db, table, col):
    """Collation the engine actually applies to `col = ?` (read from the compiled program, so it reflects the
    declared COLLATE clause without parsing CREATE TABLE text). Unknown (application-defined) collations make
    preparation fail, which is reported as None."""
    # The comparison sits in the result list so no index seek replaces it (a WHERE on a PK prefix compiles to a seek).
    try:
        rows = db.execute(f"EXPLAIN SELECT {qi(col)} = ?1 FROM main.{qi(table)}", ("x",)).fetchall()
    except sqlite3.Error:
        return None
    for r in rows:
        if r[1] in ("Eq", "Ne"):
            # P4 is the collating sequence; a rowid alias compares as an integer (no collating sequence).
            return r[5].rsplit("-", 1)[0] if isinstance(r[5], str) else "BINARY"
    return None


def sqlite_check(req, m):
    coll = req["collection"]
    declared = parse_schema(req["declared"])
    if m == "declared-not-introspected":
        return check_schema_probe(declared, m)
    db = sqlite3.connect("file:" + urllib.parse.quote(req["path"]) + "?mode=ro", uri=True)
    try:
        row = db.execute("SELECT type, sql FROM main.sqlite_schema WHERE name = ?1 AND type IN ('table','view')",
                         (coll,)).fetchone()
        if row is None:
            raise Refuse("NotATable")
        if m != "ignore-not-a-table" and (row[0] != "table" or re.match(r"\s*CREATE\s+VIRTUAL\b", row[1] or "", re.I)):
            raise Refuse("NotATable")
        tl = db.execute("SELECT strict, wr FROM pragma_table_list WHERE schema = 'main' AND name = ?1",
                        (coll,)).fetchone()
        strict, without_rowid = bool(tl and tl[0]), bool(tl and tl[1])
        info = db.execute(f"PRAGMA main.table_xinfo({qi(coll)})").fetchall()  # cid,name,type,notnull,dflt,pk,hidden
        live = {r[1]: r for r in info}
        name_of = {c["field"]: c["name"] for c in declared["columns"]}
        tname = name_of.get(declared["tenant_field"])
        s = {"collection": coll, "tenant_field": declared["tenant_field"], "columns": [],
             "permitted": declared["permitted"], "unique_indexes": []}
        for c in declared["columns"]:
            r = live.get(c["name"])
            if r is None:
                raise Refuse(f"UnknownField({c['field']})")
            cs = sqlite_col_collation(db, coll, c["name"])
            col = "Binary" if cs == "BINARY" else ("PadSpace" if cs == "RTRIM" else
                                                   ("CaseInsensitive" if cs == "NOCASE" else "Nondeterministic"))
            s["columns"].append({"field": c["field"], "name": c["name"], "nullable": r[3] == 0, "collation": col,
                                 "key": c["key"]})
        tr = live.get(tname)
        if tr is None:
            raise Refuse("UnknownField")
        field_of = {c["name"]: c["field"] for c in declared["columns"]}
        # unique keys: every unique index (incl. PK autoindex / WITHOUT ROWID pk) + the rowid alias
        for _seq, iname, unique, _origin, partial in db.execute(f"PRAGMA main.index_list({qi(coll)})").fetchall():
            if not unique:
                continue
            fields, prefix = [], bool(partial)
            for _seqno, cid, cname, _desc, icoll, key in db.execute(f"PRAGMA main.index_xinfo({qi(iname)})"):
                if not key:
                    continue
                if cid == -2:            # expression key part
                    prefix = True
                    continue
                if cname in field_of:
                    f = field_of[cname]
                    fields.append(f)
                    is_gov = f == s["tenant_field"] or any(c["key"] and c["field"] == f for c in s["columns"])
                    if is_gov and (icoll or "").upper() != "BINARY" and m not in ("ignore-collation", "ignore-index-collation"):
                        raise Refuse(f"NonBinaryCollation({f})")
                else:
                    fields.append(-1 - cid)  # an undeclared column: never matches (t,key)
            if m == "ignore-prefix-index":
                prefix = False
            s["unique_indexes"].append({"fields": fields, "prefix": prefix})
        pk = [r for r in info if r[5] > 0]
        if (m != "ignore-rowid-alias" and not without_rowid and len(pk) == 1 and (pk[0][2] or "").upper() == "INTEGER"):
            f = field_of.get(pk[0][1], -1000)
            s["unique_indexes"].append({"fields": [f], "prefix": False})
        check_schema_probe(s, m)
        # live-only checks
        if m != "ignore-generated" and tr[6] in (2, 3):
            raise Refuse("GeneratedTenant")
        if m != "ignore-tenant-type":
            aff = (tr[2] or "").upper() if strict else sqlite_affinity(tr[2])
            if aff != "TEXT":
                raise Refuse("TenantNotText")
        if m != "ignore-triggers":
            if db.execute("SELECT count(*) FROM main.sqlite_schema WHERE type = 'trigger' AND tbl_name = ?1 COLLATE NOCASE",
                          (coll,)).fetchone()[0]:
                raise Refuse("TriggerOnCollection")
        if m != "ignore-fk-actions":
            safe = ("NO ACTION", "RESTRICT")
            for _id, _seq, _tbl, _f, _t, on_upd, on_del, _match in db.execute(f"PRAGMA main.foreign_key_list({qi(coll)})"):
                if on_upd.upper() not in safe or on_del.upper() not in safe:
                    raise Refuse("ForeignKeyAction")
            for (other,) in db.execute("SELECT name FROM main.sqlite_schema WHERE type = 'table'").fetchall():
                for fk in db.execute(f"PRAGMA main.foreign_key_list({qi(other)})").fetchall():
                    if fk[2].lower() == coll.lower() and (fk[5].upper() not in safe or fk[6].upper() not in safe):
                        raise Refuse("ForeignKeyAction")
    finally:
        db.close()


# ---------------------------------------------------------------------------------------------- PostgreSQL (live)
def pg_check(req, m):
    declared = parse_schema(req["declared"])
    if m == "declared-not-introspected":
        return check_schema_probe(declared, m)
    pg = Pg(req["dsn"])
    try:
        return _pg_check(pg, req, declared, m)
    finally:
        pg.close()


def _pg_check(pg, req, declared, m):
    nsp, coll = req["namespace"], req["collection"]
    _, rows = pg.query("SELECT c.oid::int8, c.relkind::text, c.relrowsecurity, c.relforcerowsecurity "
                       "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                       "WHERE n.nspname = $1 AND c.relname = $2", (nsp, coll))
    if not rows:
        raise Refuse("NotATable")
    oid, relkind, rls, force = rows[0]
    if relkind not in ("r", "p") and m != "ignore-not-a-table":
        raise Refuse("NotATable")
    _, drow = pg.query("SELECT datcollate, datlocprovider::text FROM pg_database WHERE datname = current_database()")
    db_default_c = drow[0][0] in ("C", "POSIX") and drow[0][1] == "c"

    def binary_coll(coll_oid, collname, provider):
        if collname in ("C", "POSIX") and provider in ("c", "d"):
            return True
        return collname == "default" and db_default_c

    _, crow = pg.query(
        "SELECT a.attnum::int, a.attname::text, a.attnotnull, a.attgenerated::text, t.typname::text, a.atttypid::int8, "
        "a.attcollation::int8, coalesce(co.collname::text, ''), coalesce(co.collprovider::text, '') "
        "FROM pg_attribute a JOIN pg_type t ON t.oid = a.atttypid LEFT JOIN pg_collation co ON co.oid = a.attcollation "
        "WHERE a.attrelid = $1 AND a.attnum > 0 AND NOT a.attisdropped", (oid,))
    live = {r[1]: r for r in crow}
    by_num = {r[0]: r for r in crow}
    field_of = {c["name"]: c["field"] for c in declared["columns"]}
    s = {"collection": coll, "tenant_field": declared["tenant_field"], "columns": [],
         "permitted": declared["permitted"], "unique_indexes": []}
    tname = None
    for c in declared["columns"]:
        r = live.get(c["name"])
        if r is None:
            raise Refuse(f"UnknownField({c['field']})")
        typ = r[4]
        if typ == "citext":
            col = "CaseInsensitive"
        elif typ == "bpchar":
            col = "PadSpace"
        elif r[6] == 0:
            col = "Binary"        # non-collatable type (int, bigint, uuid, bytea): byte-exact equality
        else:
            col = "Binary" if binary_coll(r[6], r[7], r[8]) else "Nondeterministic"
        if c["field"] == declared["tenant_field"]:
            tname = c["name"]
        s["columns"].append({"field": c["field"], "name": c["name"], "nullable": not r[2], "collation": col,
                             "key": c["key"]})
    gov = {c["field"] for c in s["columns"] if c["key"] or c["field"] == s["tenant_field"]}
    # unique indexes (incl. PK), exclusion constraints
    _, irows = pg.query("SELECT i.indkey::text, i.indexprs IS NOT NULL, i.indpred IS NOT NULL, i.indcollation::text, "
                        "i.indnkeyatts::int FROM pg_index i WHERE i.indrelid = $1 AND i.indisunique", (oid,))
    _, cmap = pg.query("SELECT oid::int8, collname::text, collprovider::text FROM pg_collation")
    cinfo = {r[0]: (r[1], r[2]) for r in cmap}
    for indkey, has_expr, has_pred, indcoll, nkey in irows:
        keys = [int(x) for x in indkey.split()][:nkey]
        colls = [int(x) for x in indcoll.split()][:nkey]
        fields, prefix = [], bool(has_expr or has_pred)
        for k, co in zip(keys, colls):
            if k == 0:
                prefix = True
                continue
            r = by_num.get(k)
            f = field_of.get(r[1]) if r else None
            if f is None:
                fields.append(-1 - k)
                continue
            fields.append(f)
            if f in gov and co != 0 and m not in ("ignore-collation", "ignore-index-collation"):
                cn, cp = cinfo.get(co, ("?", "?"))
                if not binary_coll(co, cn, cp):
                    raise Refuse(f"NonBinaryCollation({f})")
        if m == "ignore-prefix-index":
            prefix = False
        s["unique_indexes"].append({"fields": fields, "prefix": prefix})
    if m != "ignore-exclusion":
        _, xr = pg.query("SELECT count(*)::int FROM pg_constraint WHERE conrelid = $1 AND contype = 'x'", (oid,))
        s["unique_indexes"].extend({"fields": [], "prefix": True} for _ in range(xr[0][0]))
    check_schema_probe(s, m)
    tr = live[tname]
    if m != "ignore-generated" and tr[3] != "":
        raise Refuse("GeneratedTenant")
    if m != "ignore-tenant-type" and tr[4] not in ("text", "varchar"):
        raise Refuse("TenantNotText")
    # the collection plus every partition (pg_partition_tree returns nothing for an ordinary table)
    tree = f"(SELECT {int(oid)}::oid UNION SELECT relid FROM pg_partition_tree({int(oid)}::regclass))"
    if m != "ignore-triggers":
        _, t = pg.query(f"SELECT count(*)::int FROM pg_trigger WHERE tgrelid IN {tree} AND NOT tgisinternal")
        if t[0][0]:
            raise Refuse("TriggerOnCollection")
    if m != "ignore-rules":
        _, t = pg.query(f"SELECT count(*)::int FROM pg_rewrite WHERE ev_class IN {tree} AND rulename <> '_RETURN'")
        if t[0][0]:
            raise Refuse("RuleOnCollection")
    if m != "ignore-fk-actions":
        _, t = pg.query(f"SELECT count(*)::int FROM pg_constraint WHERE contype = 'f' AND (conrelid IN {tree} OR "
                        f"confrelid IN {tree}) AND (confupdtype NOT IN ('a','r') OR confdeltype NOT IN ('a','r'))")
        if t[0][0]:
            raise Refuse("ForeignKeyAction")
    if m != "ignore-partition" and relkind == "p":
        _, pr = pg.query("SELECT partstrat::text, partattrs::text, partclass::text, partcollation::text, "
                         "partexprs IS NOT NULL FROM pg_partitioned_table WHERE partrelid = $1", (oid,))
        strat, attrs, classes, pcolls, pexpr = pr[0]
        if pexpr:
            raise Refuse("PartitionKeyMismatch")
        am = "hash" if strat == "h" else "btree"
        for a, cl, pc in zip(attrs.split(), classes.split(), pcolls.split()):
            r = by_num.get(int(a))
            if r is None:
                raise Refuse("PartitionKeyMismatch")
            _, d = pg.query("SELECT opc.oid::int8 FROM pg_opclass opc JOIN pg_am am ON am.oid = opc.opcmethod "
                            "WHERE opc.opcintype = $1 AND opc.opcdefault AND am.amname = $2", (r[5], am))
            if not d or d[0][0] != int(cl) or int(pc) != r[6]:
                raise Refuse("PartitionKeyMismatch")
    if m != "ignore-rls":
        if not (rls and force):
            raise Refuse("RlsNotForced")
        _, pols = pg.query("SELECT polcmd::text, polpermissive, pg_get_expr(polqual, polrelid), "
                           "pg_get_expr(polwithcheck, polrelid) FROM pg_policy WHERE polrelid = $1", (oid,))
        if not pols:
            raise Refuse("RlsNotForced")
        for cmd, permissive, qual, check in pols:
            if cmd in ("*", "a", "w") and check is None:
                raise Refuse("RlsPolicyWithoutCheck")
            if permissive:
                for e in (qual, check):
                    if e is not None and not tenant_scoped(e, tname):
                        raise Refuse("RlsPolicyNotTenantScoped")


def tenant_scoped(expr, tname):
    """Heuristic (README known limits): the expression compares the tenant column with current_setting(...) and
    has no OR / constant-true escape."""
    e = expr.lower()
    return (re.search(r'(^|[^a-z0-9_])"?' + re.escape(tname.lower()) + r'"?([^a-z0-9_]|$)', e) is not None
            and "current_setting(" in e and re.search(r"\b(or|true)\b", e) is None)


# ---------------------------------------------------------------------------------------------- serve loop
def handle(req, m):
    if req.get("op") != "schema":
        return {"error": "unknown op"}
    if m == "refuse-all":
        return {"refuse": "TenantFieldNullable"}
    if m == "accept-all":
        return {"ok": True}
    mode = req.get("mode")
    try:
        if mode == "static":
            check_schema_probe(parse_schema(req["schema"]), m)
        elif mode == "sqlite":
            sqlite_check(req, m)
        elif mode == "pg":
            pg_check(req, m)
        else:
            return {"error": f"unknown mode {mode!r}"}
    except Refuse as r:
        return {"refuse": "NonBinaryCollation" if m == "class-blind" else str(r)}
    except (KeyError, ValueError, TypeError) as e:
        return {"refuse": f"Malformed({type(e).__name__})"}
    except (sqlite3.Error, PgError, OSError) as e:
        return {"error": f"{type(e).__name__}: {e}"}
    return {"ok": True}


def main():
    a = sys.argv[1:]
    if not a or a[0] != "serve":
        print("usage: refsubject.py serve [--mutant NAME]", file=sys.stderr)
        return 2
    m = ""
    if len(a) == 3 and a[1] == "--mutant" and a[2] in MUTANTS:
        m = a[2]
    elif len(a) != 1:
        print(f"bad arguments; mutants: {' '.join(MUTANTS)}", file=sys.stderr)
        return 2
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
        except ValueError:
            print(json.dumps({"v": 1, "error": "bad json"}), flush=True)
            continue
        out = handle(req, m)
        out.update({"v": 1, "id": req.get("id")})
        print(json.dumps(out, ensure_ascii=True), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
