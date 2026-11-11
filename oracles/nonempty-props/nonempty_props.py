"""NONEMPTY-PROPS oracle: INV-NONEMPTY property check over seeded (capset, op) pairs, per adapter.

Invoke through ./run (python3 -I -B, stdlib only). README.md has the subject protocol and the pass criterion.

The generator labels every case when it builds it (covering / unrestricted must allow; empty / absent / null /
malformed / non-covering must deny), and checks each label against cover(), which restates the spec here. The
checker judges a subject only from its replies. The reference subject (ref_subject.py) is the default subject;
its decision logic is not used for labels.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import random
import shlex
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
NAME = "NONEMPTY-PROPS"

ADAPTERS = ("sqlite", "pg", "redis", "oop")
KINDS = ("select", "insert", "update", "delete", "upsert")
KV_KINDS = ("select", "insert", "upsert", "delete")
SQL_COLLS = ("notes", "files", "audit_log", "notes_archive")
KV_COLLS = ("sessions", "cache", "sess")
DENY_CATS = ("empty", "absent", "null", "malformed", "noncovering")
ALLOW_CATS = ("covering", "unrestricted")
CATS = ALLOW_CATS + DENY_CATS
CAT_WEIGHTS = (("covering", 30), ("noncovering", 30), ("malformed", 16), ("empty", 6), ("absent", 6),
               ("null", 6), ("unrestricted", 6))
# mutants every subject (reference or --subject) must implement behind --mutate, and must be caught
REQUIRED_MUTANTS = ("empty-means-all", "missing-capset-means-all", "deny-everything", "unrestricted-implicit",
                    "render-on-deny")
# extra mutants only the reference implements
EXTRA_MUTANTS = ("empty-columns-means-all", "absent-field-means-all", "wildcard", "cap-union", "name-prefix-match",
                 "case-insensitive", "lenient-parse")
SELF_TEST_CASES = 10000      # per mutant, total over the four adapters ("caught within 1e4 cases")


def _load(modname, fname):
    sp = importlib.util.spec_from_file_location(modname, os.path.join(HERE, fname))
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


# ----------------------------------------------------------------------------------------------- spec restated

def reads(p, out):
    t = p[0]
    if t in (2, 3, 4, 5):
        out.add(p[1])
    elif t in (6, 7):
        reads(p[1], out)
        reads(p[2], out)
    elif t == 8:
        reads(p[1], out)


def touched(op):
    s = set()
    reads(op["filter"], s)
    for f, _ in op["writes"]:
        s.add(f)
    s.update(op["returning"])
    return s


def well_formed_cap(c):
    return (isinstance(c, dict) and set(c) == {"adapter", "collection", "ops", "columns"}
            and isinstance(c["adapter"], str) and isinstance(c["collection"], str)
            and isinstance(c["ops"], list) and all(isinstance(k, str) and k in KINDS for k in c["ops"])
            and isinstance(c["columns"], list)
            and all(isinstance(x, int) and not isinstance(x, bool) and 0 <= x <= 0xFFFFFFFF for x in c["columns"]))


def cover(c, adapter, op):
    """Spec: one well-formed cap covers op iff exact adapter, exact collection, kind in ops, touched <= columns."""
    return (well_formed_cap(c) and c["adapter"] == adapter and c["collection"] == op["collection"]
            and op["kind"] in c["ops"] and touched(op) <= set(c["columns"]))


# ----------------------------------------------------------------------------------------------- generator

def tenant_hex(r):
    t = r.choice((1, 2, 0xff, 0x100000000, (1 << 63), (1 << 64) - 1, r.randrange(1, 1 << 64)))
    return "%016x" % t


def gen_value(r):
    if r.random() < 0.5:
        return r.randrange(-(1 << 53) + 1, 1 << 53)
    return "".join(r.choice("abcxyz019_-%*") for _ in range(r.randrange(0, 6)))


def gen_pred(r, fields, depth):
    roll = r.random()
    if depth <= 0 or roll < 0.55:
        f = r.choice(fields)
        a = r.randrange(4)
        if a == 0:
            return [2, f, gen_value(r)]
        if a == 1:
            return [3, f, [gen_value(r) for _ in range(r.randrange(0, 4))]]
        if a == 2:
            return [4, f, gen_value(r), gen_value(r)]
        return [5, f, "".join(r.choice("ab%_*") for _ in range(r.randrange(0, 4)))]
    if roll < 0.62:
        return [r.choice((0, 1))]
    return [r.choice((6, 7)), gen_pred(r, fields, depth - 1), gen_pred(r, fields, depth - 1)]


def schema_for(adapter, coll):
    n = 3 if adapter == "redis" else 6
    return {"collection": coll, "tenant_field": 0,
            "columns": [{"field": i, "name": "c%d" % i, "nullable": False, "collation": "binary", "key": i == 1}
                        for i in range(n)],
            "permitted": list(range(1, n)),
            "unique_indexes": [{"fields": [0, 1], "prefix": False}]}


def gen_op(r, adapter):
    """A schema-valid op (Refines fidelity: no Not, tenant field never touched) touching >= 1 column."""
    if adapter == "redis":
        coll = r.choice(KV_COLLS)
        kind = r.choice(KV_KINDS)
        key = "".join(r.choice("abk:*?[]") for _ in range(r.randrange(1, 6)))
        if kind in ("select", "delete"):
            filt = [2, 1, key] if r.random() < 0.6 else [5, 1, key]
            writes = []
            returning = [2] if (kind == "select" and r.random() < 0.7) else []
        else:
            filt = [0]
            writes = [[1, key], [2, gen_value(r)]]
            returning = []
    else:
        coll = r.choice(SQL_COLLS)
        kind = r.choice(KINDS)
        filt = gen_pred(r, [1, 2, 3, 4, 5], r.randrange(0, 3)) if kind != "insert" else [0]
        writes = []
        if kind in ("insert", "upsert"):
            writes = [[1, gen_value(r)]] + [[f, gen_value(r)] for f in sorted(r.sample([2, 3, 4, 5], r.randrange(0, 3)))]
        elif kind == "update":
            writes = [[f, gen_value(r)] for f in sorted(r.sample([2, 3, 4, 5], r.randrange(1, 3)))]
        returning = sorted(r.sample([1, 2, 3, 4, 5], r.randrange(0, 3)))
    op = {"tenant": tenant_hex(r), "collection": coll, "kind": kind, "filter": filt, "writes": writes,
          "returning": returning}
    if not touched(op):
        op["returning"] = [1]
    return op


def other_adapters(adapter):
    return [a for a in ADAPTERS if a != adapter] + [adapter.upper(), adapter.capitalize(), adapter + " ", "", "*"]


def near_colls(coll, adapter):
    pool = KV_COLLS if adapter == "redis" else SQL_COLLS
    return [c for c in pool if c != coll] + [coll[:-1], coll + "_x", coll + " ", coll.upper(), coll.capitalize(),
                                             "", "*"]


def all_cols(adapter):
    return list(range(1, 3 if adapter == "redis" else 6))


def covering_cap(r, adapter, op):
    ops = sorted(set([op["kind"]] + r.sample(KINDS, r.randrange(0, 3))))
    cols = sorted(touched(op) | set(r.sample(all_cols(adapter), r.randrange(0, 3))))
    return {"adapter": adapter, "collection": op["collection"], "ops": ops, "columns": cols}


def noncovering_cap(r, adapter, op):
    """A well-formed cap that fails exactly one cover condition (or two in the split pair)."""
    c = covering_cap(r, adapter, op)
    how = r.randrange(7)
    t = sorted(touched(op))
    if how == 0:
        c["adapter"] = r.choice(other_adapters(adapter))
        return [c], "adapter"
    if how == 1:
        c["collection"] = r.choice(near_colls(op["collection"], adapter))
        return [c], "collection"
    if how == 2:
        c["ops"] = sorted(k for k in c["ops"] if k != op["kind"])
        if not c["ops"]:
            c["ops"] = [k for k in KINDS if k != op["kind"]][:1 + r.randrange(2)]
        return [c], "kind"
    if how == 3:
        drop = r.choice(t)
        c["columns"] = sorted(x for x in c["columns"] if x != drop)
        if not c["columns"]:
            c["columns"] = [x for x in all_cols(adapter) if x != drop][:1]
        return [c], "column"
    if how == 4:
        c["columns"] = []
        return [c], "empty-columns"
    if how == 5:
        c["ops"] = []
        return [c], "empty-ops"
    # split pair: A has the kind but lacks column d; B has column d but lacks the kind (no single cap covers)
    d = r.choice(t)
    a = dict(c, columns=sorted(set(all_cols(adapter)) - {d}) or [0])
    b = dict(c, ops=[k for k in KINDS if k != op["kind"]], columns=sorted(set(all_cols(adapter))))
    return [a, b], "split"


def decoys(r, adapter, op, k):
    out = []
    for _ in range(k):
        out.extend(noncovering_cap(r, adapter, op)[0])
    return out


MALFORMED_SCALARS = ("*", "all", "Unrestricted", "UNRESTRICTED", " unrestricted", "unrestricted ", "none", "",
                     {}, {"unrestricted": True}, True, False, 0, 1, ["unrestricted"], ["*"], [None], [{}], [[]],
                     [True])


def broken_cap(r, adapter, op):
    """A covering cap broken in one field so it no longer parses; `sub` names the break."""
    c = covering_cap(r, adapter, op)
    sub = r.choice(("no-ops", "no-columns", "no-adapter", "no-collection", "ops-star", "cols-star", "ops-all", "ops-upper", "ops-string", "cols-null", "cols-string-ids",
                    "cols-negative", "extra-key", "cols-bool"))
    if sub == "no-ops":
        del c["ops"]
    elif sub == "no-columns":
        del c["columns"]
    elif sub == "no-adapter":
        del c["adapter"]
    elif sub == "no-collection":
        del c["collection"]
    elif sub == "ops-star":
        c["ops"] = ["*"]
    elif sub == "cols-star":
        c["columns"] = ["*"]
    elif sub == "ops-all":
        c["ops"] = ["all"]
    elif sub == "ops-upper":
        c["ops"] = [k.upper() for k in c["ops"]]
    elif sub == "ops-string":
        c["ops"] = op["kind"]
    elif sub == "cols-null":
        c["columns"] = None
    elif sub == "cols-string-ids":
        c["columns"] = [str(x) for x in c["columns"]]
    elif sub == "cols-negative":
        c["columns"] = c["columns"] + [-1]
    elif sub == "extra-key":
        c["unrestricted"] = True
    elif sub == "cols-bool":
        c["columns"] = True
    return c, sub


def gen_case(r, adapter, cat, idx):
    op = gen_op(r, adapter)
    msg = {"op": "authorize", "case": idx, "adapter": adapter, "schema": schema_for(adapter, op["collection"]),
           "data_op": op}
    sub = cat
    if cat == "covering":
        caps = [covering_cap(r, adapter, op)] + decoys(r, adapter, op, r.randrange(0, 4))
        r.shuffle(caps)
        msg["capset"] = caps
    elif cat == "unrestricted":
        msg["capset"] = "unrestricted"
    elif cat == "empty":
        msg["capset"] = []
    elif cat == "null":
        msg["capset"] = None
    elif cat == "absent":
        pass
    elif cat == "noncovering":
        caps, sub = noncovering_cap(r, adapter, op)
        caps = caps + decoys(r, adapter, op, r.randrange(0, 3))
        r.shuffle(caps)
        msg["capset"] = caps
        sub = "noncovering/" + sub
    elif cat == "malformed":
        roll = r.randrange(3)
        if roll == 0:
            v = r.choice(MALFORMED_SCALARS)
            msg["capset"] = json.loads(json.dumps(v))
            sub = "malformed/scalar"
        elif roll == 1:
            bc, s = broken_cap(r, adapter, op)
            caps = [bc] + decoys(r, adapter, op, r.randrange(0, 3))
            r.shuffle(caps)
            msg["capset"] = caps
            sub = "malformed/near-cover/" + s
        else:
            bc, s = broken_cap(r, adapter, op)
            caps = [covering_cap(r, adapter, op), bc]
            r.shuffle(caps)
            msg["capset"] = caps
            sub = "malformed/with-cover/" + s
    # the label must agree with the restated spec
    want = cat in ALLOW_CATS
    cs = msg.get("capset", "<absent>")
    if cat == "covering":
        assert any(cover(c, adapter, op) for c in cs)
    elif cat == "noncovering":
        assert all(well_formed_cap(c) for c in cs) and not any(cover(c, adapter, op) for c in cs), msg
    elif cat == "malformed":
        assert not (isinstance(cs, list) and cs and all(well_formed_cap(c) for c in cs)), msg
        assert cs != "unrestricted"
    return msg, want, sub


def pick_cat(r):
    x = r.randrange(sum(w for _, w in CAT_WEIGHTS))
    for c, w in CAT_WEIGHTS:
        if x < w:
            return c
        x -= w
    return CAT_WEIGHTS[-1][0]


def generate(cases_per_adapter, seed):
    """-> list of (msg, want_allow, label). Case ids are global and dense."""
    out = []
    idx = 0
    for ai, adapter in enumerate(ADAPTERS):
        r = random.Random("%d/%s" % (seed, adapter))
        # the first len(CATS) cases of each adapter cover every category once, so small runs are never vacuous
        for k in range(cases_per_adapter):
            cat = CATS[k] if k < len(CATS) else pick_cat(r)
            msg, want, sub = gen_case(r, adapter, cat, idx)
            out.append((msg, want, sub))
            idx += 1
    return out


# ----------------------------------------------------------------------------------------------- subjects

def replies_reference(cases, mutation):
    ref = _load("monban_nonempty_ref", "ref_subject.py")
    return [ref.decide(m, mutation) for m, _, _ in cases]


class SubjectError(Exception):
    pass


def replies_subject(cases, cmd, mutation=None, chunk=5000, timeout=600):
    argv = shlex.split(cmd) + (["--mutate", mutation] if mutation else [])
    out = []
    for i in range(0, len(cases), chunk):
        part = cases[i:i + chunk]
        data = "".join(json.dumps(m, separators=(",", ":")) + "\n" for m, _, _ in part)
        try:
            p = subprocess.run(argv, input=data, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise SubjectError("cannot run subject %r: %s" % (argv, e))
        if p.returncode != 0:
            raise SubjectError("subject %r exited %d: %s" % (argv, p.returncode, p.stderr.strip()[-400:]))
        lines = [l for l in p.stdout.splitlines() if l.strip()]
        if len(lines) != len(part):
            raise SubjectError("subject emitted %d replies for %d requests" % (len(lines), len(part)))
        for l in lines:
            try:
                out.append(json.loads(l))
            except ValueError:
                out.append({"_bad": l[:200]})
    return out


# ----------------------------------------------------------------------------------------------- checker

class Report:
    def __init__(self):
        self.viol = {}          # kind -> count
        self.first = {}         # kind -> (case index, detail)
        self.cov = {a: {c: 0 for c in CATS} for a in ADAPTERS}
        self.allow_rendered = {a: 0 for a in ADAPTERS}
        self.subs = {}
        self.digest = hashlib.sha256()
        self.n = 0

    def bad(self, kind, idx, detail):
        self.viol[kind] = self.viol.get(kind, 0) + 1
        if kind not in self.first:
            self.first[kind] = (idx, detail)

    def total(self):
        return sum(self.viol.values())

    def vacuity(self):
        miss = ["%s/%s" % (a, c) for a in ADAPTERS for c in CATS if self.cov[a][c] == 0]
        miss += ["%s/allow+rendered" % a for a in ADAPTERS if self.allow_rendered[a] == 0]
        return miss


def check(cases, replies):
    rep = Report()
    for (msg, want, sub), rp in zip(cases, replies):
        idx, ad = msg["case"], msg["adapter"]
        cat = sub.split("/")[0]
        rep.n += 1
        rep.cov[ad][cat] += 1
        rep.subs[sub] = rep.subs.get(sub, 0) + 1
        if not isinstance(rp, dict):
            rp = {"_bad": rp}
        dec, ren = rp.get("decision"), rp.get("rendered")
        if rp.get("case") != idx or dec not in ("allow", "deny") or not isinstance(ren, bool):
            rep.bad("PROTO", idx, "bad reply %s" % json.dumps(rp)[:200])
            continue
        rep.digest.update(("%d:%s:%d\n" % (idx, dec, ren)).encode())
        if dec == "allow" and not want:
            rep.bad("ALLOW-ON-" + cat.upper(), idx, "%s %s capset=%s op=%s" % (
                ad, sub, json.dumps(msg.get("capset", "<absent>"))[:300], json.dumps(msg["data_op"])[:200]))
        elif dec == "deny" and want:
            rep.bad("DENY-ON-" + cat.upper(), idx, "%s %s (non-vacuity)" % (ad, sub))
        if dec == "deny" and ren:
            rep.bad("RENDER-ON-DENY", idx, "%s %s: render reached on a deny" % (ad, sub))
        if dec == "allow" and ren:
            rep.allow_rendered[ad] += 1
    if len(replies) != len(cases):
        rep.bad("PROTO", -1, "%d replies for %d cases" % (len(replies), len(cases)))
    return rep


def evaluate(cases_per_adapter, seed, subject=None, mutation=None):
    cases = generate(cases_per_adapter, seed)
    if subject:
        replies = replies_subject(cases, subject, mutation)
    else:
        replies = replies_reference(cases, mutation)
    return check(cases, replies)


def summary(rep):
    return ", ".join("%s=%d" % kv for kv in sorted(rep.viol.items())) or "0 violations"


# ----------------------------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(prog="nonempty-props/run")
    ap.add_argument("--subject", help="command speaking the authorize protocol on stdin/stdout (README.md)")
    ap.add_argument("--cases", type=int, default=100000, help="generated (capset, op) pairs per adapter")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--mutate", dest="mutation", help="run the reference (or subject) with this mutation")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test(a)
    if a.cases < 1:
        print("%s: FAIL (--cases must be >= 1)" % NAME)
        return 1
    t0 = time.time()
    try:
        rep = evaluate(a.cases, a.seed, subject=a.subject, mutation=a.mutation)
    except SubjectError as e:
        print("%s: FAIL (subject error: %s)" % (NAME, e))
        return 1
    label = "subject" if a.subject else "reference"
    if a.mutation:
        label += "+" + a.mutation
    for k, (i, d) in sorted(rep.first.items()):
        print("  first %s: case %d: %s" % (k, i, d))
    allows = {ad: rep.cov[ad]["covering"] + rep.cov[ad]["unrestricted"] for ad in ADAPTERS}
    print("  %s: %d cases (%d/adapter, seed %d) in %.1fs; digest %s" % (
        label, rep.n, a.cases, a.seed, time.time() - t0, rep.digest.hexdigest()[:16]))
    for ad in ADAPTERS:
        print("  %-6s %s; allow+rendered=%d (must-allow %d)" % (
            ad, " ".join("%s=%d" % (c, rep.cov[ad][c]) for c in CATS), rep.allow_rendered[ad], allows[ad]))
    vac = rep.vacuity()
    if rep.total() or vac:
        why = summary(rep) if rep.total() else "0 violations"
        if vac:
            why += "; vacuous: " + " ".join(vac)
        print("%s: FAIL (%s, %s)" % (NAME, label, why))
        return 1
    print("%s: PASS (%s, %d cases/adapter x %d adapters, seed %d; 0 allows on empty/absent/null/malformed/"
          "non-covering, 0 denies on covering/unrestricted, 0 renders on deny)" % (
              NAME, label, a.cases, len(ADAPTERS), a.seed))
    return 0


# which violation kinds each mutant must raise (any one suffices)
EXPECT = {
    "empty-means-all": ("ALLOW-ON-EMPTY",),
    "missing-capset-means-all": ("ALLOW-ON-NULL", "ALLOW-ON-ABSENT"),
    "unrestricted-implicit": ("ALLOW-ON-ABSENT",),
    "deny-everything": ("DENY-ON-COVERING", "DENY-ON-UNRESTRICTED"),
    "render-on-deny": ("RENDER-ON-DENY",),
    "empty-columns-means-all": ("ALLOW-ON-NONCOVERING",),
    "absent-field-means-all": ("ALLOW-ON-MALFORMED",),
    "wildcard": ("ALLOW-ON-MALFORMED", "ALLOW-ON-NONCOVERING"),
    "cap-union": ("ALLOW-ON-NONCOVERING",),
    "name-prefix-match": ("ALLOW-ON-NONCOVERING",),
    "case-insensitive": ("ALLOW-ON-NONCOVERING", "ALLOW-ON-MALFORMED"),
    "lenient-parse": ("ALLOW-ON-MALFORMED",),
}


def self_test(a):
    per = SELF_TEST_CASES // len(ADAPTERS)
    seed = a.seed
    ok = True
    caught = []

    def run(mut, subject):
        try:
            return evaluate(per, seed, subject=subject, mutation=mut), None
        except SubjectError as e:
            return None, str(e)

    def judge(where, mut, subject):
        nonlocal ok
        rep, err = run(mut, subject)
        if rep is None:
            ok = False
            print("  %s %-26s NOT CAUGHT (subject error: %s)" % (where, mut, err))
            return
        hit = [k for k in EXPECT[mut] if rep.viol.get(k)]
        if hit:
            k = hit[0]
            caught.append(mut)
            print("  %s %-26s caught: %s (first at case %d of %d)" % (where, mut, summary(rep), rep.first[k][0],
                                                                      rep.n))
        else:
            ok = False
            print("  %s %-26s NOT CAUGHT (%s)" % (where, mut, summary(rep)))

    if a.subject:
        # an external subject: it must be clean and its own --mutate variants must be caught
        rep, err = run(None, a.subject)
        clean = rep is not None and not rep.total() and not rep.vacuity()
        print("  subject clean at %d cases: %s" % (per * len(ADAPTERS), "yes" if clean else
                                                    (err or summary(rep) + " " + " ".join(rep.vacuity()))))
        ok &= clean
        for m in REQUIRED_MUTANTS:
            judge("subject", m, a.subject)
        n = len(REQUIRED_MUTANTS)
    else:
        rep, _ = run(None, None)
        clean = not rep.total() and not rep.vacuity()
        print("  reference clean at %d cases: %s; digest %s" % (rep.n, "yes" if clean else summary(rep),
                                                                rep.digest.hexdigest()[:16]))
        ok &= clean
        ref_digest = rep.digest.hexdigest()
        for m in REQUIRED_MUTANTS + EXTRA_MUTANTS:
            judge("ref", m, None)
        # the --subject plumbing: ref_subject over stdin/stdout must agree with in-process, and its mutants caught
        sub = "%s -I -B %s" % (shlex.quote(sys.executable), shlex.quote(os.path.join(HERE, "ref_subject.py")))
        rp, err = run(None, sub)
        same = rp is not None and rp.digest.hexdigest() == ref_digest and not rp.total()
        print("  protocol: ref_subject over stdin/stdout digest=%s in-process=%s %s" % (
            rp.digest.hexdigest()[:16] if rp else err, ref_digest[:16], "OK" if same else "MISMATCH"))
        ok &= same
        for m in REQUIRED_MUTANTS:
            judge("proto", m, sub)
        n = len(REQUIRED_MUTANTS) * 2 + len(EXTRA_MUTANTS)
    if ok:
        print("%s SELF-TEST: PASS (%d/%d mutants caught within %d cases each: %s)" % (
            NAME, len(caught), n, per * len(ADAPTERS), " ".join(dict.fromkeys(caught))))
        return 0
    print("%s SELF-TEST: FAIL (%d/%d mutants caught; see above)" % (NAME, len(caught), n))
    return 1


if __name__ == "__main__":
    sys.exit(main())
