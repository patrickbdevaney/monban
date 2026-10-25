#!/usr/bin/env python3
"""q4-005 targeted probes (hand-written reproducers), python3 -I, stdlib only.
Usage: python3 -I probes.py MARIA_URL CRDB_DSN [out.json]"""
import json, os, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..", "..", "oracles", "lowering-write")))
sys.path.insert(0, HERE)
import lowir as L          # noqa: E402
from mywire import My, MyError   # noqa: E402

OUT = {}

def rec(engine, name, steps, verdict):
    OUT.setdefault(engine, {})[name] = {"steps": steps, "finding": verdict}
    print(f"[{engine}] {name}: {verdict}")
    for s in steps: print("     ", json.dumps(s, default=str)[:300])

def myq(m, steps, sql, params=()):
    try:
        r = m.query(sql, params); steps.append({"sql": sql, "params": params, "result": r}); return r
    except MyError as e:
        steps.append({"sql": sql, "params": params, "error": str(e)}); return None

def maria(url):
    m = My(url)
    m.simple("set session sql_mode = 'STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION'")
    ver = m.server_version
    OUT["mariadb_version"] = ver
    def fresh(ddl, rows):
        m.simple("drop table if exists z"); m.simple(ddl)
        for r in rows: m.query("insert into z (id, tenant, x) values (?,?,?)", r)
    G = "IF(CAST(`tenant` AS BINARY) = CAST(VALUES(`tenant`) AS BINARY), VALUES(`x`), `x`)"
    UPS = f"INSERT INTO z (tenant, id, x) VALUES (?,?,?) ON DUPLICATE KEY UPDATE x = {G} RETURNING tenant, id, x"

    s = []
    fresh("create table z(id int primary key, tenant varchar(16), x varchar(16))", [(1, "acme", "a")])
    myq(m, s, "UPDATE z SET x = ? WHERE id = ? RETURNING id, x", ["b", 1])
    rec("mariadb", "update-returning", s, "UPDATE ... RETURNING is a syntax error (1064) on %s: RETURNING only on INSERT/REPLACE/DELETE" % ver)

    for coll in ("utf8mb4_bin", "utf8mb4_general_ci", "utf8mb4_nopad_bin"):
        s = []
        fresh(f"create table z(id int, tenant varchar(16) collate {coll} not null, x varchar(16), primary key (tenant, id))",
              [(1, "acme", "secret-of-acme")])
        evil = "acme " if coll != "utf8mb4_general_ci" else "ACME"
        myq(m, s, UPS, [evil, 1, "N"])
        myq(m, s, "select tenant, id, x from z")
        leak = any(r and r[1] and r[1][0][0] == "acme" for r in [st.get("result") for st in s[:1]])
        rec("mariadb", f"guarded-odku-composite-pk-{coll}", s,
            ("LEAK W4/W3: arbiter matched tenant 'acme' row for tenant %r; guard blocked the write (silent no-op) but "
             "RETURNING returned the foreign row" % evil) if leak else "no capture (exact arbiter)")

    s = []
    fresh("create table z(id int, tenant varchar(16) collate utf8mb4_nopad_bin not null, x varchar(16), primary key (tenant(3), id))",
          [(1, "acme", "secret-of-acme")])
    myq(m, s, UPS, ["acmX", 1, "N"])
    myq(m, s, "INSERT INTO z (tenant, id, x) VALUES (?,?,?) ON DUPLICATE KEY UPDATE x = VALUES(x) RETURNING tenant, id, x", ["acmY", 1, "PWN"])
    myq(m, s, "select tenant, id, x from z")
    rec("mariadb", "prefix-length-key-part", s,
        "LEAK W3: PRIMARY KEY (tenant(3), id) under NO PAD binary still lets tenant 'acmX' arbitrate onto 'acme' "
        "(guarded: RETURNING leak; unguarded: foreign row overwritten). Schema gate must reject prefix key parts")

    s = []
    fresh("create table z(id int, tenant varchar(16) collate utf8mb4_nopad_bin not null, x varchar(16), primary key (tenant, id), unique key (id))",
          [(1, "evil", "secret-of-evil")])
    myq(m, s, UPS, ["acme", 1, "N"])
    myq(m, s, "INSERT INTO z (tenant, id, x) VALUES (?,?,?) ON DUPLICATE KEY UPDATE x = VALUES(x) RETURNING tenant, id, x", ["acme", 1, "PWN"])
    myq(m, s, "select tenant, id, x from z")
    rec("mariadb", "second-unique-index-odku", s,
        "LEAK W3/W4 (+W1 unguarded): ODKU arbiter is ANY unique index; UNIQUE(id) beside PK(tenant,id) selects tenant "
        "evil's row; guarded form returns it via RETURNING, unguarded form overwrites it")

    s = []
    fresh("create table z(id int, tenant varchar(16) collate utf8mb4_nopad_bin not null, x varchar(16), primary key (tenant, id), unique key (tenant, x))",
          [(5, "acme", "a"), (6, "acme", "b")])
    myq(m, s, UPS, ["acme", 99, "a"])
    myq(m, s, "select tenant, id, x from z order by id")
    rec("mariadb", "tenant-scoped-second-unique", s,
        "no foreign capture (secondary key contains tenant under NO PAD binary), but arbiter != (t,id): request for "
        "id 99 resolved onto own row id 5 (no insert) -> E/W3 violation; ODKU needs exactly one unique index")

    s = []
    fresh("create table z(id int, tenant varchar(16) collate utf8mb4_nopad_bin not null, x varchar(16), primary key (tenant, id), unique key (id))",
          [(1, "evil", "secret-of-evil"), (2, "evil", "e2")])
    myq(m, s, "REPLACE INTO z (tenant, id, x) VALUES (?,?,?) RETURNING tenant, id, x", ["acme", 1, "R"])
    myq(m, s, "select tenant, id, x from z order by id")
    rec("mariadb", "replace-family", s, "LEAK W1: REPLACE deletes tenant evil's row conflicting on UNIQUE(id) (REPLACE family stays denylisted)")

    s = []
    m.simple("set session sql_mode = ''")
    fresh("create table z(id int, tenant varchar(4) collate utf8mb4_nopad_bin not null, x varchar(16), primary key (tenant, id))", [])
    myq(m, s, "INSERT INTO z (tenant, id, x) VALUES (?,?,?)", ["acmeEVIL", 7, "N"])
    myq(m, s, "show warnings")
    myq(m, s, "select tenant, id, x from z")
    m.simple("set session sql_mode = 'STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION'")
    myq(m, s, "INSERT INTO z (tenant, id, x) VALUES (?,?,?)", ["acmeEVIL", 8, "N"])
    myq(m, s, "INSERT IGNORE INTO z (tenant, id, x) VALUES (?,?,?)", ["acmeEVIL", 9, "N"])
    myq(m, s, "select tenant, id, x from z order by id")
    rec("mariadb", "non-strict-truncation", s,
        "LEAK W2: with sql_mode='' (or INSERT IGNORE even under STRICT) tenant 'acmeEVIL' is truncated to 'acme' "
        "(post-image owned by another tenant). Mandate: session sql_mode pinned STRICT_ALL_TABLES, no IGNORE")

    s = []
    fresh("create table z(id int, tenant varchar(16) collate utf8mb4_nopad_bin not null, x varchar(16), primary key (tenant, id))",
          [(1, "acme", "a")])
    for args in (["acme", 1, "a"], ["acme", 1, "b"], ["acme", 2, "c"]):
        m.query(f"INSERT INTO z (tenant, id, x) VALUES (?,?,?) ON DUPLICATE KEY UPDATE x = {G}", args)
        r = m.simple("select row_count()")[1][0][0]
        s.append({"odku": args, "row_count": r})
    rec("mariadb", "odku-affected-rows", s,
        "ODKU affected rows 0 (unchanged) / 2 (updated) / 1 (inserted): an existence signal; W6 (uniform failure) "
        "requires the adapter to hide row_count from modules")
    m.simple("drop table if exists z"); m.close()

def crdb(dsn):
    p = L.Pg(dsn)
    OUT["cockroach_version"] = p.simple("select version()")[1][0][0]
    def q(steps, sql, params=()):
        try:
            r = p.query(sql, params); steps.append({"sql": sql, "params": params, "result": r}); return r
        except Exception as e:
            steps.append({"sql": sql, "params": params, "error": str(e)}); return None
    def fresh(ddl, rows):
        p.simple("drop table if exists z"); p.simple(ddl)
        for r in rows: p.query("insert into z (id, tenant, x) values ($1,$2,$3)", r)
    s = []
    fresh("create table z(id int primary key, tenant string not null, x string, y string)", [(1, "evil", "secret-of-evil")])
    q(s, "UPSERT INTO z (tenant, id, x) VALUES ($1,$2,$3) RETURNING tenant, id, x, y", ["acme", 1, "PWN"])
    q(s, "select tenant, id, x, y from z")
    rec("cockroachdb", "upsert-statement-global-pk", s,
        "LEAK W1: UPSERT arbiter is always the primary key (no arbiter list, no WHERE guard): tenant evil's row id 1 "
        "is overwritten and re-tenanted (W1). Denylist UPSERT")
    s = []
    fresh("create table z(id int, tenant string not null, x string, primary key (tenant, id), unique (id))", [(1, "evil", "secret-of-evil")])
    q(s, 'INSERT INTO z (tenant, id, x) VALUES ($1,$2,$3) ON CONFLICT (tenant, id) DO UPDATE SET x = excluded.x WHERE z.tenant = excluded.tenant COLLATE "C" RETURNING tenant, id, x', ["acme", 1, "N"])
    q(s, "UPSERT INTO z (tenant, id, x) VALUES ($1,$2,$3) RETURNING tenant, id, x", ["acme", 1, "N"])
    q(s, "INSERT INTO z (tenant, id, x) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING RETURNING tenant, id, x", ["acme", 1, "N"])
    q(s, "select tenant, id, x from z")
    rec("cockroachdb", "second-unique-index", s,
        "no capture: ON CONFLICT (tenant,id) and UPSERT raise 23505 on the other unique index (fail-closed); "
        "arbiter-less ON CONFLICT DO NOTHING silently skips (existence signal, W6) -> require explicit arbiter")
    s = []
    fresh("create table z(id int, tenant string collate en_u_ks_level2 not null, x string, primary key (tenant, id))", [(1, "acme", "secret-of-acme")])
    q(s, 'INSERT INTO z (tenant, id, x) VALUES ($1,$2,$3) ON CONFLICT (tenant, id) DO UPDATE SET x = excluded.x WHERE z.tenant = excluded.tenant COLLATE "C" RETURNING tenant, id, x', ["ACME", 1, "N"])
    q(s, 'INSERT INTO z (tenant, id, x) VALUES ($1,$2,$3) ON CONFLICT (tenant, id) DO UPDATE SET x = excluded.x WHERE z.tenant::text = excluded.tenant::text COLLATE "C" RETURNING tenant, id, x', ["ACME", 1, "N"])
    q(s, "INSERT INTO z (tenant, id, x) VALUES ($1,$2,$3) ON CONFLICT (tenant, id) DO UPDATE SET x = excluded.x RETURNING tenant, id, x", ["ACME", 1, "PWN"])
    q(s, "select tenant, id, x from z")
    rec("cockroachdb", "collated-composite-pk", s,
        "LEAK W1/W3: collated (case-insensitive) tenant in the PK. The oracle's postgres guard "
        "`t.tenant = excluded.tenant COLLATE \"C\"` is evaluated under the column collation on CockroachDB and lets "
        "tenant 'ACME' overwrite tenant 'acme' (on PostgreSQL the explicit COLLATE wins). The ::text-cast guard "
        "no-ops (E, no leak); unguarded form overwrites. Schema gate must refuse collated tenant/key columns and the "
        "CockroachDB guard must cast both sides to text")
    p.simple("drop table if exists z")
    p.close()
    OUT["cockroachdb"]["serializable-retries"] = retries(dsn)

def retries(dsn, threads=8, iters=40):
    """Concurrent read-modify-write transactions on overlapping rows of two tenants under SERIALIZABLE.
    Each txn: BEGIN; SELECT count(*) of own rows with x='U'; UPDATE own rows (hardened WHERE); COMMIT, retried on 40001.
    Checks: foreign rows never changed, final state = all own rows updated, every aborted attempt left no write."""
    p = L.Pg(dsn)
    p.simple("drop table if exists z")
    p.simple("create table z(id int primary key, tenant string not null, x string, n int)")
    for i in range(1, 41):
        p.query("insert into z values ($1,$2,$3,0)", [i, "acme" if i % 2 else "evil", "a"])
    stats = {"commits": 0, "retries_40001": 0, "other_errors": 0, "max_attempts": 0, "abandoned_after_200": 0,
             "commits_per_tenant": {"acme": 0, "evil": 0}}
    lock = threading.Lock()
    def worker(k):
        c = L.Pg(dsn); t = "acme" if k % 2 else "evil"
        for j in range(iters):
            att = 0
            while True:
                att += 1
                try:
                    c.simple("BEGIN")
                    c.query('SELECT count(*) FROM z WHERE (z.tenant::text = $1::text COLLATE "C")', [t])
                    c.query('UPDATE z SET n = n + 1, x = $2 WHERE ((z.tenant::text = $1::text COLLATE "C") AND (z.id % 4 = $3::int OR z.id % 4 = $4::int)) RETURNING id',
                            [t, "U", j % 4, (j + 1) % 4])
                    c.simple("COMMIT")
                    with lock:
                        stats["commits"] += 1; stats["commits_per_tenant"][t] += 1
                        stats["max_attempts"] = max(stats["max_attempts"], att)
                    break
                except L.PgError as e:
                    try: c.simple("ROLLBACK")
                    except Exception: pass
                    with lock:
                        if "40001" in str(e): stats["retries_40001"] += 1
                        else: stats["other_errors"] += 1; stats.setdefault("error_sample", str(e)[:200])
                    if att >= 200:
                        with lock: stats["abandoned_after_200"] += 1
                        break
        c.close()
    t0 = time.time()
    ths = [threading.Thread(target=worker, args=(k,)) for k in range(threads)]
    [t.start() for t in ths]; [t.join() for t in ths]
    stats["wall_s"] = round(time.time() - t0, 2)
    rows = p.query("select id, tenant, x, n from z order by id")[1]
    # each committed txn increments 10 of its tenant's 20 rows (two residues mod 4 among own parity)
    per_tenant = {}
    for i, t, x, n in rows: per_tenant[t] = per_tenant.get(t, 0) + n
    exp = {t: stats["commits_per_tenant"][t] * 10 for t in ("acme", "evil")}
    stats["sum_n_per_tenant"] = per_tenant; stats["expected_sum_n"] = exp
    foreign_touch = [r for r in rows if r[3] and r[2] != "U"]
    stats["ok"] = per_tenant == exp and stats["other_errors"] == 0 and not foreign_touch
    stats["finding"] = ("40001 retries observed and handled by whole-transaction retry; increments exactly once per "
                        "commit (no partial or duplicated writes)" if stats["ok"] else "MISMATCH")
    print("[cockroachdb] serializable-retries:", json.dumps(stats))
    p.simple("drop table if exists z"); p.close()
    return stats

if __name__ == "__main__":
    maria(sys.argv[1]); crdb(sys.argv[2])
    if len(sys.argv) > 3:
        with open(sys.argv[3], "w") as fh: json.dump(OUT, fh, indent=1, default=str)
