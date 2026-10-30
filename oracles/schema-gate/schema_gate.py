#!/usr/bin/env python3
"""SCHEMA-GATE oracle (P4-oracle-schema-001). See README.md. Stdlib only; run through ./run (python3 -I).

PASS iff, in every selected mode, every counterexample schema is refused with its expected class AND every golden
schema is accepted. Modes: --static (F4 Schema JSON), --engine sqlite (DDL on a throwaway file), --engine pg
(DDL on a throwaway PostgreSQL; the namespace `aegis_sg` is dropped and recreated per case).
"""
import argparse, json, os, queue, shlex, sqlite3, subprocess, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from pgwire import Pg, PgError  # noqa: E402

NAME = "SCHEMA-GATE"
REF = [sys.executable, "-I", os.path.join(HERE, "refsubject.py"), "serve"]
NS = "aegis_sg"
COLL = "notes"

# ================================================================================================ declared schemas
def col(field, name, key=False, nullable=False, collation="Binary"):
    return {"field": field, "name": name, "nullable": nullable, "collation": collation, "key": key}


def schema(cols, uniques, tenant_field=0, collection=COLL, permitted=None):
    return {"collection": collection, "tenant_field": tenant_field, "columns": cols,
            "permitted": permitted if permitted is not None else [c["field"] for c in cols if c["field"] != tenant_field],
            "unique_indexes": [{"fields": f, "prefix": p} for f, p in uniques]}


def base_cols(**over):
    """tenant(0) id(1, key) x(2) y(3); keyword overrides replace one column."""
    cols = [col(0, "tenant"), col(1, "id", key=True), col(2, "x", nullable=True), col(3, "y", nullable=True)]
    for k, v in over.items():
        cols[{"tenant": 0, "id": 1, "x": 2, "y": 3}[k]] = v
    return cols


GOOD_UQ = [([0, 1], False)]
# The declared Schema an F8 config would give for every live case: honest intent, all Binary, one (tenant,id)
# arbiter. The live catalog is what differs; a subject that checks this instead of the catalog accepts everything.
DECLARED = schema(base_cols(), GOOD_UQ)

# ================================================================================================ static corpus
# (name, F4 Schema JSON, expected classes or None for golden). Provenance in README (q4-005 = spikes/q4-005).
STATIC = [
    ("golden: (tenant,id) arbiter, all Binary", schema(base_cols(), GOOD_UQ), None),
    ("golden: arbiter listed as (id,tenant)", schema(base_cols(), [([1, 0], False)]), None),
    ("golden: non-key data column CaseInsensitive (NOCASE x)",
     schema(base_cols(x=col(2, "x", nullable=True, collation="CaseInsensitive")), GOOD_UQ), None),
    ("golden: non-key data column Nondeterministic (ICU y)",
     schema(base_cols(y=col(3, "y", nullable=True, collation="Nondeterministic")), GOOD_UQ), None),
    ("golden: two key columns (tenant,grp,id)",
     schema(base_cols(x=col(2, "grp", key=True)), [([0, 2, 1], False)]), None),
    ("golden: tenant at field 3",
     schema([col(0, "id", key=True), col(1, "x", nullable=True), col(2, "y", nullable=True), col(3, "tenant")],
            [([3, 0], False)], tenant_field=3), None),
    ("golden: tenant flagged key too", schema(base_cols(tenant=col(0, "tenant", key=True)), GOOD_UQ), None),
    ("nullable tenant", schema(base_cols(tenant=col(0, "tenant", nullable=True)), GOOD_UQ), {"TenantFieldNullable"}),
    ("tenant CaseInsensitive (NOCASE / *_ci / citext)",
     schema(base_cols(tenant=col(0, "tenant", collation="CaseInsensitive")), GOOD_UQ), {"NonBinaryCollation"}),
    ("tenant Nondeterministic (ICU level2, q4-005 en_u_ks_level2)",
     schema(base_cols(tenant=col(0, "tenant", collation="Nondeterministic")), GOOD_UQ), {"NonBinaryCollation"}),
    ("tenant PadSpace (MariaDB utf8mb4_bin, q4-005)",
     schema(base_cols(tenant=col(0, "tenant", collation="PadSpace")), GOOD_UQ), {"NonBinaryCollation"}),
    ("key column CaseInsensitive",
     schema(base_cols(id=col(1, "id", key=True, collation="CaseInsensitive")), GOOD_UQ), {"NonBinaryCollation"}),
    ("key column PadSpace", schema(base_cols(id=col(1, "id", key=True, collation="PadSpace")), GOOD_UQ),
     {"NonBinaryCollation"}),
    ("PK without tenant (id only)", schema(base_cols(), [([1], False)]), {"UpsertArbiterNotTenantScoped"}),
    ("second unique index UNIQUE(id) (q4-005)", schema(base_cols(), [([0, 1], False), ([1], False)]),
     {"UpsertArbiterNotTenantScoped"}),
    ("second unique index UNIQUE(tenant,x) (q4-005 reproducer 5)", schema(base_cols(), [([0, 1], False), ([0, 2], False)]),
     {"UpsertArbiterNotTenantScoped"}),
    ("prefix unique index tenant(3) (q4-005)", schema(base_cols(), [([0, 1], True)]),
     {"UpsertArbiterNotTenantScoped"}),
    ("no unique index", schema(base_cols(), []), {"UpsertArbiterNotTenantScoped"}),
    ("arbiter wider than (t,key): (tenant,id,x)", schema(base_cols(), [([0, 1, 2], False)]),
     {"UpsertArbiterNotTenantScoped"}),
    ("arbiter = (tenant) only, no key columns",
     schema(base_cols(id=col(1, "id", nullable=True)), [([0], False)]), {"UpsertArbiterNotTenantScoped"}),
]

# ================================================================================================ SQLite corpus
# (name, DDL script, expected classes or None). Every table is `notes`; DECLARED is sent with each request.
SQ = [
    ("golden: untyped data columns, PK(tenant,id)",
     "create table notes(tenant text not null, id integer not null, x, y, primary key(tenant,id))", None),
    ("golden: NUMERIC data columns",
     "create table notes(tenant text not null, id integer not null, x numeric, y numeric, primary key(tenant,id))", None),
    ("golden: NOCASE data column x (non-key) + plain index on x",
     "create table notes(tenant text not null, id integer not null, x text collate nocase, y text, primary key(tenant,id));"
     "create index notes_x on notes(x)", None),
    ("golden: STRICT ANY data columns",
     "create table notes(tenant text not null, id integer not null, x any, y any, primary key(tenant,id)) strict", None),
    ("golden: STRICT typed (x TEXT, y INTEGER)",
     "create table notes(tenant text not null, id integer not null, x text, y integer, primary key(tenant,id)) strict", None),
    ("golden: composite PK WITHOUT ROWID, explicit COLLATE BINARY, text key",
     "create table notes(tenant text not null collate binary, id text not null collate binary, x text, y text, "
     "primary key(tenant,id)) without rowid", None),
    ("golden: sole arbiter is a unique index (no PK)",
     "create table notes(tenant text not null, id text not null, x text, y text);"
     "create unique index notes_tk on notes(tenant,id)", None),
    ("golden: varchar(16) tenant",
     "create table notes(tenant varchar(16) not null, id integer not null, x, y, primary key(tenant,id))", None),
    ("nullable tenant (no NOT NULL, unique index)",
     "create table notes(tenant text, id integer not null, x, y); create unique index notes_tk on notes(tenant,id)",
     {"TenantFieldNullable"}),
    ("PK(tenant,id) in a rowid table without NOT NULL (SQLite PK admits NULL)",
     "create table notes(tenant text, id integer not null, x, y, primary key(tenant,id))", {"TenantFieldNullable"}),
    ("tenant COLLATE NOCASE",
     "create table notes(tenant text not null collate nocase, id integer not null, x, y, primary key(tenant,id))",
     {"NonBinaryCollation"}),
    ("tenant COLLATE RTRIM (PAD SPACE analogue)",
     "create table notes(tenant text not null collate rtrim, id integer not null, x, y, primary key(tenant,id))",
     {"NonBinaryCollation"}),
    ("tenant with an application-defined collation (per-connection registration, D7)",
     "create table notes(tenant text not null collate appci, id integer not null, x, y, primary key(tenant,id))",
     {"NonBinaryCollation"}),
    ("WITHOUT ROWID + NOCASE key column in PK",
     "create table notes(tenant text not null, id text not null collate nocase, x, y, primary key(tenant,id)) without rowid",
     {"NonBinaryCollation"}),
    ("sole unique index with COLLATE NOCASE on tenant (column BINARY)",
     "create table notes(tenant text not null, id integer not null, x, y);"
     "create unique index notes_tk on notes(tenant collate nocase, id)", {"NonBinaryCollation"}),
    ("tenant INTEGER affinity ('00000000000001e5' = '0000000000100000')",
     "create table notes(tenant integer not null, id integer not null, x, y, primary key(tenant,id))", {"TenantNotText"}),
    ("tenant declared ANY in a non-STRICT table (NUMERIC affinity)",
     "create table notes(tenant any not null, id integer not null, x, y, primary key(tenant,id))", {"TenantNotText"}),
    ("PK without tenant (id INTEGER PRIMARY KEY)",
     "create table notes(tenant text not null, id integer primary key, x, y)", {"UpsertArbiterNotTenantScoped"}),
    ("rowid alias id INTEGER PRIMARY KEY + UNIQUE(tenant,id) (two unique keys)",
     "create table notes(tenant text not null, id integer primary key, x, y);"
     "create unique index notes_tk on notes(tenant,id)", {"UpsertArbiterNotTenantScoped"}),
    ("second unique index UNIQUE(id)",
     "create table notes(tenant text not null, id integer not null, x, y, primary key(tenant,id));"
     "create unique index notes_id on notes(id)", {"UpsertArbiterNotTenantScoped"}),
    ("prefix analogue: sole unique index (tenant, substr(id,1,3))",
     "create table notes(tenant text not null, id text not null, x, y);"
     "create unique index notes_tk on notes(tenant, substr(id,1,3))", {"UpsertArbiterNotTenantScoped"}),
    ("expression index as arbiter: sole unique index (lower(tenant), id)",
     "create table notes(tenant text not null, id text not null, x, y);"
     "create unique index notes_tk on notes(lower(tenant), id)", {"UpsertArbiterNotTenantScoped"}),
    ("partial unique index (tenant,id) WHERE x IS NOT NULL",
     "create table notes(tenant text not null, id text not null, x, y);"
     "create unique index notes_tk on notes(tenant,id) where x is not null", {"UpsertArbiterNotTenantScoped"}),
    ("trigger on the collection (W5, D8)",
     "create table notes(tenant text not null, id integer not null, x, y, primary key(tenant,id));"
     "create table audit(v);"
     "create trigger notes_ai after insert on notes begin insert into audit values (new.x); end",
     {"TriggerOnCollection"}),
    ("FK from another table into the collection ON DELETE CASCADE (D8)",
     "create table notes(tenant text not null, id integer not null, x, y, primary key(tenant,id));"
     "create table child(tenant text, nid integer, foreign key(tenant,nid) references notes(tenant,id) on delete cascade)",
     {"ForeignKeyAction"}),
    ("FK from the collection to a parent ON UPDATE SET NULL (D8)",
     "create table parent(k text primary key);"
     "create table notes(tenant text not null, id integer not null, x text references parent(k) on update set null, y, "
     "primary key(tenant,id))", {"ForeignKeyAction"}),
    ("generated tenant column (VIRTUAL, from raw)",
     "create table notes(raw text not null, tenant text not null generated always as (substr(raw,1,16)) virtual, "
     "id integer not null, x, y); create unique index notes_tk on notes(tenant,id)", {"GeneratedTenant"}),
    ("view as collection",
     "create table base(tenant text not null, id integer not null, x, y, primary key(tenant,id));"
     "create view notes as select * from base", {"NotATable"}),
    ("virtual table (fts5 module, per-connection registration) as collection",
     "create virtual table notes using fts5(tenant, id, x, y)", {"NotATable"}),
]

# ================================================================================================ PostgreSQL corpus
POL = "tenant = current_setting('aegis.tenant')"


def rls(policy=f"create policy p on notes using ({POL}) with check ({POL})", force=True, enable=True):
    s = ""
    if enable:
        s += "alter table notes enable row level security;"
    if force:
        s += "alter table notes force row level security;"
    return s + policy + ";"


T = 'tenant text collate "C" not null'
PK = "primary key (tenant, id)"
PG_SETUP = ("create extension if not exists citext;"
            "do $$ begin if not exists (select 1 from pg_collation where collname = 'ci_nd') then "
            "create collation ci_nd (provider = icu, locale = 'und-u-ks-level2', deterministic = false); end if; end $$;"
            "do $$ begin if not exists (select 1 from pg_collation where collname = 'nd_canon') then "
            "create collation nd_canon (provider = icu, locale = 'und', deterministic = false); end if; end $$;")
PG = [
    ("golden: deterministic default on data columns, y bigint",
     f"create table notes({T}, id int not null, x text, y bigint, {PK});" + rls(), None),
    ("golden: nondeterministic ICU ks-level2 on data column x",
     f"create table notes({T}, id int not null, x text collate ci_nd, y bigint, {PK});" + rls(), None),
    ("golden: nondeterministic ICU und on data column x + plain index",
     f"create table notes({T}, id int not null, x text collate nd_canon, y bigint, {PK});"
     "create index notes_y on notes(y);" + rls(), None),
    ("golden: citext data column x",
     f"create table notes({T}, id int not null, x citext, y bigint, {PK});" + rls(), None),
    ("golden: text key collate C, varchar tenant collate C",
     'create table notes(tenant varchar(16) collate "C" not null, id text collate "C" not null, x text, y bigint, '
     f"{PK});" + rls(), None),
    ("golden: sole unique index instead of PK, separate SELECT and INSERT policies",
     f"create table notes({T}, id int not null, x text, y bigint); create unique index notes_tk on notes(tenant,id);"
     + rls(f"create policy ps on notes for select using ({POL}); create policy pi on notes for insert with check ({POL})"),
     None),
    ("golden: partitioned by list(tenant), one partition",
     f"create table notes({T}, id int not null, x text, y bigint, {PK}) partition by list (tenant);"
     "create table notes_p1 partition of notes for values in ('0000000000000001');" + rls(), None),
    ("nullable tenant", f'create table notes(tenant text collate "C", id int not null, x text, y bigint);'
     "create unique index notes_tk on notes(tenant,id);" + rls(), {"TenantFieldNullable"}),
    ("tenant citext", f"create table notes(tenant citext not null, id int not null, x text, y bigint, {PK});" + rls(),
     {"NonBinaryCollation"}),
    ("tenant nondeterministic ICU (und-u-ks-level2)",
     f"create table notes(tenant text collate ci_nd not null, id int not null, x text, y bigint, {PK});" + rls(),
     {"NonBinaryCollation"}),
    ("tenant deterministic but non-C collation (und-x-icu)",
     f'create table notes(tenant text collate "und-x-icu" not null, id int not null, x text, y bigint, {PK});' + rls(),
     {"NonBinaryCollation"}),
    ("tenant char(16) (bpchar: PAD SPACE semantics)",
     f"create table notes(tenant char(16) not null, id int not null, x text, y bigint, {PK});"
     + rls(f"create policy p on notes using (tenant = current_setting('aegis.tenant')::bpchar) "
           f"with check (tenant = current_setting('aegis.tenant')::bpchar)"), {"NonBinaryCollation"}),
    ("key column nondeterministic ICU",
     f"create table notes({T}, id text collate ci_nd not null, x text, y bigint, {PK});" + rls(), {"NonBinaryCollation"}),
    ("sole unique index with COLLATE ci_nd on tenant (column C)",
     f"create table notes({T}, id int not null, x text, y bigint);"
     "create unique index notes_tk on notes(tenant collate ci_nd, id);" + rls(), {"NonBinaryCollation"}),
    ("tenant bigint", f"create table notes(tenant bigint not null, id int not null, x text, y bigint, {PK});"
     + rls(f"create policy p on notes using (tenant = current_setting('aegis.tenant')::bigint) "
           f"with check (tenant = current_setting('aegis.tenant')::bigint)"), {"TenantNotText"}),
    ("PK without tenant", f"create table notes({T}, id int primary key, x text, y bigint);" + rls(),
     {"UpsertArbiterNotTenantScoped"}),
    ("second unique index UNIQUE(id)",
     f"create table notes({T}, id int not null, x text, y bigint, {PK}); create unique index notes_id on notes(id);"
     + rls(), {"UpsertArbiterNotTenantScoped"}),
    ("prefix analogue: sole unique index (tenant, left(id,3))",
     f"create table notes({T}, id text collate \"C\" not null, x text, y bigint);"
     "create unique index notes_tk on notes(tenant, left(id,3));" + rls(), {"UpsertArbiterNotTenantScoped"}),
    ("expression index as arbiter: sole unique index (lower(tenant), id)",
     f"create table notes({T}, id int not null, x text, y bigint);"
     "create unique index notes_tk on notes(lower(tenant), id);" + rls(), {"UpsertArbiterNotTenantScoped"}),
    ("expression index beside the PK: unique (tenant, lower(x))",
     f"create table notes({T}, id int not null, x text, y bigint, {PK});"
     "create unique index notes_tx on notes(tenant, lower(x));" + rls(), {"UpsertArbiterNotTenantScoped"}),
    ("partial unique index (tenant,id) WHERE x IS NOT NULL",
     f"create table notes({T}, id int not null, x text, y bigint);"
     "create unique index notes_tk on notes(tenant,id) where x is not null;" + rls(), {"UpsertArbiterNotTenantScoped"}),
    ("exclusion constraint on id (arbiter for ON CONFLICT DO NOTHING)",
     f"create table notes({T}, id int not null, x text, y bigint, {PK}, exclude using btree (id with =));" + rls(),
     {"UpsertArbiterNotTenantScoped"}),
    ("partition key opclass != column's (hash text_pattern_ops)",
     f"create table notes({T}, id int not null, x text, y bigint, {PK}) partition by hash (tenant text_pattern_ops);"
     + rls(), {"PartitionKeyMismatch"}),
    ("trigger on the collection (W5, D8)",
     f"create table notes({T}, id int not null, x text, y bigint, {PK});"
     "create function aegis_sg.tf() returns trigger language plpgsql as $f$ begin return new; end $f$;"
     "create trigger notes_bi before insert on notes for each row execute function aegis_sg.tf();" + rls(),
     {"TriggerOnCollection"}),
    ("trigger on a partition of a partitioned collection",
     f"create table notes({T}, id int not null, x text, y bigint, {PK}) partition by list (tenant);"
     "create table notes_p1 partition of notes for values in ('0000000000000001');"
     "create function aegis_sg.tf() returns trigger language plpgsql as $f$ begin return new; end $f$;"
     "create trigger p1_bi before insert on notes_p1 for each row execute function aegis_sg.tf();" + rls(),
     {"TriggerOnCollection"}),
    ("rewrite rule on the collection (DO ALSO INSERT; W5, D8)",
     f"create table notes({T}, id int not null, x text, y bigint, {PK}); create table audit(v text);"
     "create rule notes_r as on insert to notes do also insert into audit values (new.x);" + rls(),
     {"RuleOnCollection"}),
    ("FK from another table into the collection ON DELETE CASCADE (D8)",
     f"create table notes({T}, id int not null, x text, y bigint, {PK});"
     'create table child(tenant text collate "C", nid int, foreign key (tenant, nid) references notes(tenant, id) '
     "on delete cascade);" + rls(), {"ForeignKeyAction"}),
    ("FK from the collection to a parent ON UPDATE SET NULL (D8)",
     "create table parent(k text primary key);"
     f"create table notes({T}, id int not null, x text references parent(k) on update set null, y bigint, {PK});" + rls(),
     {"ForeignKeyAction"}),
    ("generated tenant column (STORED, from raw)",
     'create table notes(raw text not null, tenant text collate "C" generated always as (left(raw,16)) stored not null, '
     f"id int not null, x text, y bigint, {PK});" + rls(), {"GeneratedTenant"}),
    ("no row level security", f"create table notes({T}, id int not null, x text, y bigint, {PK});"
     f"create policy p on notes using ({POL}) with check ({POL});", {"RlsNotForced"}),
    ("RLS enabled but not FORCEd (owner bypasses)",
     f"create table notes({T}, id int not null, x text, y bigint, {PK});" + rls(force=False), {"RlsNotForced"}),
    ("policy FOR ALL without WITH CHECK",
     f"create table notes({T}, id int not null, x text, y bigint, {PK});"
     + rls(f"create policy p on notes using ({POL})"), {"RlsPolicyWithoutCheck"}),
    ("policy USING (true) WITH CHECK (true)",
     f"create table notes({T}, id int not null, x text, y bigint, {PK});"
     + rls("create policy p on notes using (true) with check (true)"), {"RlsPolicyNotTenantScoped"}),
    ("extra permissive SELECT policy USING (true) beside a good one",
     f"create table notes({T}, id int not null, x text, y bigint, {PK});"
     + rls(f"create policy p on notes using ({POL}) with check ({POL}); "
           "create policy leak on notes for select using (true)"), {"RlsPolicyNotTenantScoped"}),
    ("policy with OR escape (tenant = setting OR x IS NULL)",
     f"create table notes({T}, id int not null, x text, y bigint, {PK});"
     + rls(f"create policy p on notes using ({POL} or x is null) with check ({POL})"), {"RlsPolicyNotTenantScoped"}),
    ("view as collection",
     f"create table base({T}, id int not null, x text, y bigint, {PK}); create view notes as select * from base;",
     {"NotATable"}),
]
# Included only when the database default collation is not C/POSIX (the postgres images default to en_US.utf8).
PG_DEFAULT_COLL = ("tenant with the database default collation (non-C)",
                   f"create table notes(tenant text not null, id int not null, x text, y bigint, {PK});" + rls(),
                   {"NonBinaryCollation"})

# ================================================================================================ mutants per mode
COMMON_MUT = ["refuse-all", "accept-all", "ignore-collation", "ignore-second-unique", "ignore-prefix-index",
              "ignore-nullable-tenant", "class-blind"]
LIVE_MUT = ["ignore-index-collation", "ignore-triggers", "ignore-fk-actions", "ignore-generated", "ignore-tenant-type",
            "ignore-not-a-table", "declared-not-introspected"]
MUTANTS = {
    "static": COMMON_MUT,
    "sqlite": COMMON_MUT + LIVE_MUT + ["ignore-rowid-alias"],
    "pg": COMMON_MUT + LIVE_MUT + ["ignore-rules", "ignore-exclusion", "ignore-rls", "ignore-partition"],
}


# ================================================================================================ subject process
class Subject:
    def __init__(self, argv, timeout=60):
        self.timeout = timeout
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr, text=True,
                                  encoding="utf-8", bufsize=1)
        self.q = queue.Queue()
        self.n = 0
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.p.stdout:
            self.q.put(line)
        self.q.put(None)

    def ask(self, req):
        """Returns ('ok', None) | ('refuse', class) | ('protocol', reason)."""
        self.n += 1
        req = dict(req, v=1, id=self.n)
        try:
            self.p.stdin.write(json.dumps(req, ensure_ascii=True) + "\n")
            self.p.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            return "protocol", f"subject stdin closed ({e})"
        try:
            line = self.q.get(timeout=self.timeout)
        except queue.Empty:
            return "protocol", "timeout"
        if line is None:
            return "protocol", "subject exited"
        try:
            r = json.loads(line)
        except ValueError:
            return "protocol", f"bad json {line[:80]!r}"
        if not isinstance(r, dict) or r.get("id") != self.n:
            return "protocol", "id not echoed"
        if r.get("ok") is True and "refuse" not in r:
            return "ok", None
        if isinstance(r.get("refuse"), str) and "ok" not in r:
            return "refuse", r["refuse"].split("(", 1)[0].strip()
        return "protocol", f"reply neither ok nor refuse: {line.strip()[:120]}"

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=10)
        except Exception:
            self.p.kill()


def verdict(name, expected, got, detail):
    """One case result line, or None if the case passed."""
    if expected is None:
        if got == "ok":
            return None
        return f"golden rejected: {name}: {got} {detail or ''}".rstrip()
    if got == "refuse" and detail in expected:
        return None
    if got == "refuse":
        return f"wrong class: {name}: got {detail}, want {'|'.join(sorted(expected))}"
    return f"counterexample accepted: {name}: {got} {detail or ''}".rstrip()


# ================================================================================================ mode drivers
def run_static(subj, log):
    fails = []
    for name, s, exp in STATIC:
        got, det = subj.ask({"op": "schema", "mode": "static", "schema": s})
        v = verdict(name, exp, got, det)
        if v:
            fails.append(v)
        log(f"  static  {'FAIL' if v else 'ok  '} {name}: {got} {det or ''}")
    return fails, len(STATIC)


def make_sqlite(path, ddl):
    db = sqlite3.connect(path)
    db.create_collation("appci", lambda a, b: (a.lower() > b.lower()) - (a.lower() < b.lower()))
    db.executescript(ddl)
    db.commit()
    db.close()


def run_sqlite(subj, log, tmp):
    fails = []
    for i, (name, ddl, exp) in enumerate(SQ):
        path = os.path.join(tmp, f"case{i:02d}.sqlite")
        if os.path.exists(path):
            os.unlink(path)
        try:
            make_sqlite(path, ddl)
        except sqlite3.Error as e:
            raise SystemExit(f"{NAME}: FAIL (oracle setup error in sqlite case {name!r}: {e})")
        got, det = subj.ask({"op": "schema", "mode": "sqlite", "path": path, "collection": COLL, "declared": DECLARED})
        v = verdict(name, exp, got, det)
        if v:
            fails.append(v)
        log(f"  sqlite  {'FAIL' if v else 'ok  '} {name}: {got} {det or ''}")
    return fails, len(SQ)


def pg_corpus(dsn):
    pg = Pg(dsn)
    try:
        pg.simple(PG_SETUP)
        _, r = pg.simple("select datcollate, datlocprovider::text, current_setting('server_version') from pg_database "
                         "where datname = current_database()")
    finally:
        pg.close()
    corpus = list(PG)
    if not (r[0][0] in ("C", "POSIX") and r[0][1] == "c"):
        corpus.append(PG_DEFAULT_COLL)
    return corpus, r[0][2]


def run_pg(subj, log, dsn):
    fails = []
    corpus, _ver = pg_corpus(dsn)
    pg = Pg(dsn)
    try:
        for name, ddl, exp in corpus:
            try:
                pg.simple(f"drop schema if exists {NS} cascade; create schema {NS}; set search_path = {NS}, public; " + ddl)
            except PgError as e:
                raise SystemExit(f"{NAME}: FAIL (oracle setup error in pg case {name!r}: {e})")
            got, det = subj.ask({"op": "schema", "mode": "pg", "dsn": dsn, "namespace": NS, "collection": COLL,
                                 "declared": DECLARED})
            v = verdict(name, exp, got, det)
            if v:
                fails.append(v)
            log(f"  pg      {'FAIL' if v else 'ok  '} {name}: {got} {det or ''}")
        pg.simple(f"drop schema if exists {NS} cascade")
    finally:
        pg.close()
    return fails, len(corpus)


def run_modes(argv, modes, dsn, log):
    """Run the corpus of every mode against one subject process. Returns (fails, counts)."""
    subj = Subject(argv)
    fails, counts = [], {}
    try:
        with tempfile.TemporaryDirectory(prefix="schema-gate-") as tmp:
            for m in modes:
                if m == "static":
                    f, n = run_static(subj, log)
                elif m == "sqlite":
                    f, n = run_sqlite(subj, log, tmp)
                else:
                    f, n = run_pg(subj, log, dsn)
                fails += [f"[{m}] {x}" for x in f]
                counts[m] = n
    finally:
        subj.close()
    return fails, counts


# ================================================================================================ self-test
def witnesses():
    """Show that two SQLite counterexamples are real hazards, not taste: (1) INTEGER affinity makes two distinct
    16-hex tenants collide in the arbiter; (2) a NOCASE arbiter makes tenant 'ACME...' conflict with 'acme...'."""
    out = []
    db = sqlite3.connect(":memory:")
    db.execute("create table a(tenant integer not null, id integer not null, x, primary key(tenant,id))")
    db.execute("insert into a values (?,?,?)", ("00000000000001e5", 1, "secret"))
    n = db.execute("insert into a values (?,?,?) on conflict(tenant,id) do update set x = excluded.x returning x",
                   ("0000000000100000", 1, "evil")).fetchall()
    if db.execute("select x from a").fetchall() != [("evil",)] or n != [("evil",)]:
        out.append("affinity witness did not reproduce")
    db.execute("create table b(tenant text not null collate nocase, id integer not null, x, primary key(tenant,id))")
    db.execute("insert into b values (?,?,?)", ("00000000000000ab", 1, "secret"))
    db.execute("insert into b values (?,?,?) on conflict(tenant,id) do update set x = excluded.x",
               ("00000000000000AB", 1, "evil"))
    if db.execute("select tenant, x from b").fetchall() != [("00000000000000ab", "evil")]:
        out.append("NOCASE witness did not reproduce")
    db.close()
    return out


def self_test(modes, dsn, verbose):
    quiet = (lambda s: print(s)) if verbose else (lambda s: None)
    problems, caught, total = [], 0, 0
    # positive control: the reference through the process protocol
    f, counts = run_modes(REF, modes, dsn, quiet)
    if f:
        problems.append(f"positive control (reference) failed: {f[:3]}")
    print(f"{NAME} self-test: reference {'PASS' if not f else 'FAIL'} {counts}", flush=True)
    for mode in modes:
        for mut in MUTANTS[mode]:
            total += 1
            f, _ = run_modes(REF + ["--mutant", mut], [mode], dsn, quiet)
            ok = bool(f)
            caught += ok
            print(f"{NAME} self-test: [{mode}] mutant {mut}: {'caught' if ok else 'NOT CAUGHT'} "
                  f"({len(f)} failing cases{'; e.g. ' + f[0] if f else ''})", flush=True)
            if not ok:
                problems.append(f"[{mode}] mutant {mut} not caught")
    # protocol: a subject that dies must fail the oracle
    f, _ = run_modes([sys.executable, "-I", "-c", "import sys"], [modes[0]], dsn, quiet)
    if not f:
        problems.append("dead subject not caught")
    print(f"{NAME} self-test: dead subject {'caught' if f else 'NOT CAUGHT'}", flush=True)
    if "sqlite" in modes:
        w = witnesses()
        problems += w
        print(f"{NAME} self-test: sqlite hazard witnesses {'reproduced' if not w else w}", flush=True)
    return problems, caught, total


# ================================================================================================ main
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--subject", help="subject command (shell-split); default: the reference refsubject.py")
    ap.add_argument("--static", action="store_true", help="static mode (F4 Schema JSON)")
    ap.add_argument("--engine", action="append", choices=["sqlite", "pg"], default=[], help="live engine mode")
    ap.add_argument("--dsn", help="throwaway PostgreSQL DSN for --engine pg (namespace aegis_sg is dropped)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true")
    a = ap.parse_args()
    modes = (["static"] if a.static else []) + [m for m in ("sqlite", "pg") if m in a.engine]
    if not modes:
        modes = ["static", "sqlite"]
    if "pg" in modes and not a.dsn:
        print(f"{NAME}: FAIL (--engine pg needs --dsn)")
        return 1
    t0 = time.time()
    if a.self_test:
        if a.subject:
            print(f"{NAME} SELF-TEST: FAIL (--self-test runs the reference and its mutants; no --subject)")
            return 1
        problems, caught, total = self_test(modes, a.dsn, a.verbose)
        if problems:
            print(f"{NAME} SELF-TEST: FAIL ({'; '.join(problems)})")
            return 1
        print(f"{NAME} SELF-TEST: PASS ({caught}/{total} mutants caught over {'+'.join(modes)}; reference passes "
              f"through the subject protocol; dead subject caught; {time.time() - t0:.1f}s)")
        return 0
    argv = shlex.split(a.subject) if a.subject else REF
    log = (lambda s: print(s)) if a.verbose else (lambda s: None)
    fails, counts = run_modes(argv, modes, a.dsn, log)
    for x in fails:
        print(x)
    summary = " ".join(f"{m}={n}" for m, n in counts.items())
    if fails:
        print(f"{NAME}: FAIL ({len(fails)} failing cases; {summary})")
        return 1
    print(f"{NAME}: PASS (every counterexample refused with its class, every golden accepted; {summary}; "
          f"{time.time() - t0:.1f}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
