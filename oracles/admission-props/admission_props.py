"""ADMISSION-PROPS oracle: property checks I1, I2, I4, I5, I7, I8, I11 (+S0 caps) over seeded random traces.

Invoke through ./run (python3 -I -B, stdlib only). See README.md for the event protocol and pass criterion.

The checker below is written independently of the pipeline logic in admission_ref.py: it re-states the spec
(classification, bucket keys, GCRA algebra, LRU residency, debit cap) and judges a subject only from the
decisions it emits. The reference pipeline is used only as the default subject.
"""
import argparse
import hashlib
import heapq
import importlib.util
import json
import math
import os
import random
import shlex
import subprocess
import sys
import time
from collections import OrderedDict, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
NAME = "ADMISSION-PROPS"


def _load(modname, fname):
    sp = importlib.util.spec_from_file_location(modname, os.path.join(HERE, fname))
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


REF = _load("aegis_admission_ref", "admission_ref.py")

U64 = (1 << 64) - 1
CAP_NS = 600 * 10**9
MS = 10**6
S = 10**9
STAGE_IDX = {"S0": 0, "S1": 1, "S2": 2, "S3": 3, "S3A": 3.5, "S4": 4, "S5": 5, "S6": 6}
OK_REJECT = (401, 429, 503)
FAULT_STAGES = ("S0", "S1", "S2", "S3", "S4", "S5", "S6")
FAMILIES = ("mixed", "swarm", "isolation", "churn", "overrun", "faults", "mixed", "swarm", "churn", "overrun",
            "isolation", "mixed")

# ----------------------------------------------------------------------------------------------- spec restated

def spec_class(ev, cfg):
    cred = ev.get("cred") or {}
    k = cred.get("kind", "none")
    if k == "verified":
        return "verified"
    if k == "cookie":
        age = ev["t"] - cred.get("minted", 0)
        if age < 0:
            return "anon"
        return "established" if (age >= cfg["fresh_age_ns"] and cred.get("promoted", False)) else "fresh"
    return "anon"


def spec_bucket(ev, cls):
    cred = ev.get("cred") or {}
    if cls == "verified":
        return ("v", cred["id"]), "verified"
    if cls in ("established", "fresh"):
        return ("s", cred["id"]), "session"
    return ("a", ev["ip"]), "anon"


def spec_group(cls, cost, cfg):
    if cost < cfg["exp_cost"]:
        return None
    return {"fresh": "F", "anon": "F", "established": "E"}.get(cls)


def gcra_ok(tat, now, T, b, cost):
    base = max(tat, now)
    new = base + cost * T
    if new > U64 or new - now > b * T:
        return None
    return new


def window_excess(series, T, b):
    """series: [(t, units)] in trace order. Returns the max over windows [ti, tj] of
    sum*T - (b*T + tj - ti) (> 0 means the bound sum <= b + (tj-ti)/T is violated), and the window."""
    best, arg = -1, None
    pref = 0
    mn, mn_t = None, None
    for t, u in series:
        cand = pref * T - t           # value for a window starting here
        if mn is None or cand < mn:
            mn, mn_t = cand, t
        pref += u
        ex = (pref * T - t) - mn - b * T
        if ex > best:
            best, arg = ex, (mn_t, t)
    return best, arg


class SpecLRU:
    def __init__(self, cap):
        self.cap = cap
        self.d = OrderedDict()

    def touch(self, key, init):
        """returns (entry, inserted)"""
        if key in self.d:
            self.d.move_to_end(key)
            return self.d[key], False
        while len(self.d) >= self.cap:
            self.d.popitem(last=False)
        e = init()
        self.d[key] = e
        return e, True


# ----------------------------------------------------------------------------------------------- trace generator

class Builder:
    def __init__(self, rng, cfg):
        self.rng, self.cfg = rng, cfg
        self.heap, self.seq, self.nid, self.ncid = [], 0, 0, 0

    def _push(self, t, ev):
        self.seq += 1
        heapq.heappush(self.heap, (t, self.seq, ev))

    def arrive(self, who, t, cost, fault=None, actual=None, dur=None, pow_=None, lane=None, newconn=None,
               cancelled=False):
        r = self.rng
        rid = self.nid
        self.nid += 1
        if newconn is None:
            newconn = (not who["conns"]) or r.random() < 0.15
        if newconn or not who["conns"]:
            self.ncid += 1
            cid = "c%d" % self.ncid
            who["conns"].append(cid)
            newconn = True
        else:
            cid = r.choice(who["conns"])
        if pow_ is None:
            pow_ = 16 if r.random() < 0.5 else r.choice((0, 8))
        if lane is None:
            lane = "accessible" if r.random() < 0.05 else "std"
        ev = {"type": "arrive", "id": rid, "t": t, "ip": who["ip"], "prefix": who["prefix"], "conn": cid,
              "newconn": newconn, "cred": who["cred"], "cost": cost, "pow": pow_, "lane": lane, "fault": fault,
              "_who": who["name"]}
        self._push(t, ev)
        if dur is None:
            dur = r.randint(0, 50 * MS)
        self._push(t + dur, {"type": "done", "id": rid, "t": t + dur,
                             "actual_cost": cost if actual is None else actual, "cancelled": cancelled,
                             "_who": who["name"]})
        return rid

    def close(self, who, t):
        if who["conns"]:
            cid = who["conns"].pop(self.rng.randrange(len(who["conns"])))
            self._push(t, {"type": "close", "conn": cid, "t": t, "_who": who["name"]})

    def events(self):
        return [e for _, _, e in sorted(self.heap, key=lambda x: (x[0], x[1]))]


def base_cfg(rng):
    b_anon = rng.randint(10, 120)
    rf, re_ = rng.randint(100, 600), rng.randint(100, 800)
    return {
        "type": "config",
        "s1_T": rng.choice((10, 50, 100)) * MS, "s1_b": rng.randint(5, 60),
        "s1_store": 1 << 16, "s3_store": 1 << 16,
        "cls": {"anon": {"T": rng.choice((50, 100, 200)) * MS, "b": b_anon},
                "session": {"T": rng.choice((20, 50, 100)) * MS, "b": rng.randint(b_anon, 400)},
                "verified": {"T": rng.choice((10, 25, 50)) * MS, "b": rng.randint(b_anon, 800)}},
        "agg": {"F": {"T": -(-S // rf), "b": rng.randint(100, 600)},
                "E": {"T": -(-S // re_), "b": rng.randint(100, 800)}},
        "exp_cost": 20, "stepup_cost": 100, "stepup_bits": 16,
        "L": rng.randint(4, 32), "max_conns": rng.randint(16, 2048), "prefix_cap": rng.randint(2, 32),
        "fresh_age_ns": 60 * S,
    }


def mk_ident(rng, name, kind, ip, prefix, t0):
    if kind == "anon":
        cred = {"kind": "none"}
    elif kind == "verified":
        cred = {"kind": "verified", "id": "vk-" + name}
    elif kind == "established":
        cred = {"kind": "cookie", "id": "ck-" + name, "minted": t0 - rng.randint(61, 3600) * S, "promoted": True}
    else:  # fresh (may age into established mid-trace if promoted)
        cred = {"kind": "cookie", "id": "ck-" + name, "minted": t0 - rng.randint(0, 50) * S,
                "promoted": rng.random() < 0.5}
    return {"name": name, "kind": kind, "ip": ip, "prefix": prefix, "cred": cred, "conns": []}


def pick_cost(rng, mix):
    x, a = rng.random(), 0.0
    for c, p in mix:
        a += p
        if x < a:
            return c
    return mix[-1][0]


def gen_mixed(rng, fault_p):
    cfg = base_cfg(rng)
    t0 = rng.randint(0, 1 << 62)
    b = Builder(rng, cfg)
    ids, ips = [], []
    for i in range(rng.randint(2, 12)):
        kind = rng.choices(("anon", "fresh", "established", "verified"), (35, 20, 25, 20))[0]
        if ips and rng.random() < 0.2:
            ip = rng.choice(ips)                       # shared IP (NAT)
        else:
            ip = "ip%d" % len(ips)
            ips.append(ip)
        ids.append(mk_ident(rng, "m%d" % i, kind, ip, "p%d" % (ips.index(ip) // 3), t0))
    wts = [rng.random() ** 2 + 0.05 for _ in ids]
    t = t0
    mix = ((1, .4), (5, .3), (20, .2), (100, .1))
    for _ in range(rng.randint(50, 250)):
        if rng.random() >= 0.3:
            t += int(rng.expovariate(1.0) * 20 * MS)
        if rng.random() < 0.01:
            t += rng.randint(1, 700) * S
        who = rng.choices(ids, wts)[0]
        cost = rng.randint(101, 3000) if rng.random() < 0.02 else pick_cost(rng, mix)
        fault = rng.choice(FAULT_STAGES) if rng.random() < fault_p else None
        x = rng.random()
        actual = None
        if x < 0.10:
            actual = cost + rng.randint(1, 2000)
        elif x < 0.11:
            actual = rng.randint(1 << 40, U64)
        canc = rng.random() < 0.02
        if canc:
            actual = rng.randint(0, cost)
        b.arrive(who, t, cost, fault=fault, actual=actual, cancelled=canc)
        if rng.random() < 0.05:
            b.close(who, t)
    return cfg, b.events(), {}


def gen_swarm(rng):
    cfg = base_cfg(rng)
    cfg.update(s1_T=10 * MS, s1_b=100, L=10**6, max_conns=10**7, prefix_cap=10**6)
    b_anon = rng.randint(20, 120)
    cfg["cls"]["anon"] = {"T": 100 * MS, "b": b_anon}
    cfg["cls"]["session"]["b"] = max(cfg["cls"]["session"]["b"], b_anon)
    cfg["cls"]["verified"]["b"] = max(cfg["cls"]["verified"]["b"], b_anon)
    BF = cfg["agg"]["F"]["b"]
    n = min(600, math.ceil(BF / b_anon) * rng.randint(1, 4))
    t0 = rng.randint(0, 1 << 62)
    bld = Builder(rng, cfg)
    sw = []
    for i in range(n):
        kind = "anon" if rng.random() < 0.6 else "fresh"
        sw.append(mk_ident(rng, "s%d" % i, kind, "sip%d" % i, "sp%d" % i, t0))
        sw[-1]["cred"] = dict(sw[-1]["cred"], promoted=False) if kind == "fresh" else sw[-1]["cred"]
    est = [mk_ident(rng, "e%d" % i, "established", "eip%d" % i, "ep%d" % i, t0) for i in range(rng.randint(1, 4))]
    span = rng.randint(0, 2000) * MS
    instants = sorted(t0 + rng.randint(0, span) for _ in range(rng.randint(3, 40)))
    for who in sw:
        for _ in range(rng.randint(1, 3)):
            bld.arrive(who, rng.choice(instants), rng.choice((20, 20, 100)), pow_=16, lane="std",
                       dur=rng.randint(0, 5 * MS))
    for who in est:
        for _ in range(rng.randint(5, 40)):
            bld.arrive(who, rng.choice(instants), rng.choice((20, 100)), dur=rng.randint(0, 5 * MS))
    meta = {"swarm_n": n, "nonbinding": n * b_anon >= BF}
    return cfg, bld.events(), meta


def inflate(cfg):
    c = json.loads(json.dumps(cfg))
    for k in ("anon", "session", "verified"):
        c["cls"][k] = {"T": max(1, c["cls"][k]["T"] // 1000), "b": c["cls"][k]["b"] * 1000}
    c["s1_b"] = 10**6
    return c


def gen_isolation(rng):
    cfg = base_cfg(rng)
    cfg.update(s1_T=1 * MS, s1_b=10**4, L=10**6, max_conns=10**7, prefix_cap=10**6)
    cfg["agg"] = {"F": {"T": 1, "b": 10**12}, "E": {"T": 1, "b": 10**12}}
    t0 = rng.randint(0, 1 << 62)
    kind = rng.choice(("anon", "fresh", "established", "verified"))
    ids = [mk_ident(rng, "i%d" % i, kind, "iip%d" % i, "ipf%d" % i, t0) for i in range(rng.randint(2, 5))]
    bld = Builder(rng, cfg)
    t = t0
    wts = [0.4] + [0.6 / (len(ids) - 1)] * (len(ids) - 1)
    for _ in range(rng.randint(60, 200)):
        if rng.random() >= 0.3:
            t += int(rng.expovariate(1.0) * 15 * MS)
        who = rng.choices(ids, wts)[0]
        cost = rng.randint(1, 19)
        actual = cost + rng.randint(1, 500) if rng.random() < 0.05 else None
        bld.arrive(who, t, cost, actual=actual, pow_=16)
    return cfg, bld.events(), {"target": ids[0]["name"], "others": [i["name"] for i in ids[1:]]}


def gen_churn(rng):
    cfg = base_cfg(rng)
    m = rng.randint(3, 24)
    b_anon = rng.randint(5, 30)
    cfg.update(s1_store=m, s3_store=m, s1_T=1 * MS, s1_b=rng.randint(200, 500), L=10**6, max_conns=10**7,
               prefix_cap=10**6)
    cfg["cls"] = {"anon": {"T": 200 * MS, "b": b_anon},
                  "session": {"T": 100 * MS, "b": b_anon * rng.randint(2, 6)},
                  "verified": {"T": 50 * MS, "b": b_anon * rng.randint(4, 10)}}
    t0 = rng.randint(0, 1 << 62)
    bld = Builder(rng, cfg)
    targets = [mk_ident(rng, "t%d" % i, k, "tip%d" % i, "tp%d" % i, t0)
               for i, k in enumerate(["anon"] * rng.randint(1, 3) + ["verified", "established"])]
    t = t0
    bv = cfg["cls"]["verified"]["b"]
    for rnd in range(rng.randint(3, 8)):
        for who in targets:
            t += rng.randint(1, 20) * MS
            tot = 0
            while tot < bv + 5:                       # same-instant burst up to the verified burst
                c = rng.randint(1, 5)
                tot += c
                bld.arrive(who, t, c, dur=0, pow_=16, lane="std")
        for j in range(m + rng.randint(0, 6)):        # churn flood evicts the targets (LRU)
            t += rng.randint(1, 5) * MS
            f = mk_ident(rng, "f%d_%d" % (rnd, j), "anon", "fip%d_%d" % (rnd, j % (m + 2)), "fp%d" % j, t0)
            bld.arrive(f, t, 1, dur=0)
    return cfg, bld.events(), {}


def gen_overrun(rng):
    cfg = base_cfg(rng)
    cfg.update(s1_T=10 * MS, s1_b=100, L=10**6, max_conns=10**7, prefix_cap=10**6)
    t0 = rng.randint(0, 1 << 62)
    bld = Builder(rng, cfg)
    kinds = ("anon", "fresh", "established", "verified")
    ids = [mk_ident(rng, "o%d" % i, rng.choice(kinds), "oip%d" % i, "op%d" % i, t0) for i in range(rng.randint(1, 4))]
    t = t0
    for who in ids:
        t += rng.randint(1, 100) * MS
        cost = rng.randint(1, 5)
        big = rng.choice((cost + rng.randint(1, 10**4), rng.randint(1 << 32, 1 << 50), rng.randint(1 << 60, U64), U64))
        dur = rng.randint(0, 1 * MS)
        bld.arrive(who, t, cost, actual=big, dur=dur, pow_=16)
        td = t + dur
        for dt in (rng.randint(1, 10) * MS + dur, rng.randint(1, 590) * S,
                   CAP_NS - rng.randint(1, 10) * S, CAP_NS + rng.randint(1, 5000) * MS,
                   CAP_NS + rng.randint(5, 60) * S):
            bld.arrive(who, td + dt, 1, pow_=16, dur=0)
    return cfg, bld.events(), {}


def gen_trace(seed, idx):
    rng = random.Random("admission-props:%s:%d" % (seed, idx))
    fam = FAMILIES[idx % len(FAMILIES)]
    if fam == "mixed":
        cfg, ev, meta = gen_mixed(rng, 0.03)
    elif fam == "faults":
        cfg, ev, meta = gen_mixed(rng, 0.4)
    elif fam == "swarm":
        cfg, ev, meta = gen_swarm(rng)
    elif fam == "isolation":
        cfg, ev, meta = gen_isolation(rng)
    elif fam == "churn":
        cfg, ev, meta = gen_churn(rng)
    else:
        cfg, ev, meta = gen_overrun(rng)
    cfg["trace"] = idx
    runs = [{"trace": idx, "fam": fam, "role": "main", "cfg": cfg, "events": ev, "meta": meta}]
    if fam == "isolation":
        y = rng.choice(meta["others"])
        pert = [e for e in ev if e.get("_who") != y]
        runs.append({"trace": idx, "fam": fam, "role": "perturbed", "cfg": cfg, "events": pert,
                     "meta": dict(meta, removed=y)})
    if fam == "swarm":
        runs.append({"trace": idx, "fam": fam, "role": "inflated", "cfg": dict(inflate(cfg), trace=idx),
                     "events": ev, "meta": meta})
    return runs


# ----------------------------------------------------------------------------------------------- subjects

def wire(ev):
    return json.dumps({k: v for k, v in ev.items() if not k.startswith("_")}, separators=(",", ":"))


def decide_ref(runs, mutation=None):
    return [REF.run_trace(r["cfg"], r["events"], mutation) for r in runs]


def decide_subject(runs, cmd, chunk=200, timeout=600):
    argv = shlex.split(cmd)
    out = []
    for i in range(0, len(runs), chunk):
        part = runs[i:i + chunk]
        lines = []
        for r in part:
            lines.append(wire(r["cfg"]))
            lines.extend(wire(e) for e in r["events"])
        p = subprocess.run(argv, input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0:
            raise RuntimeError("subject exited %d: %s" % (p.returncode, p.stderr[-500:]))
        dec = [json.loads(x) for x in p.stdout.splitlines() if x.strip()]
        k = 0
        for r in part:
            n = sum(1 for e in r["events"] if e["type"] == "arrive")
            out.append(dec[k:k + n])
            k += n
        if k != len(dec):
            raise RuntimeError("subject emitted %d decisions, expected %d" % (len(dec), k))
    return out


# ----------------------------------------------------------------------------------------------- checks

class Report:
    def __init__(self):
        self.viol = defaultdict(list)       # prop -> first few messages
        self.nviol = defaultdict(int)       # prop -> violation count
        self.checked = defaultdict(int)     # prop -> number of checked items
        self.cov = defaultdict(int)         # coverage / vacuity counters

    def bad(self, prop, run, msg):
        self.nviol[prop] += 1
        if len(self.viol[prop]) < 5:
            self.viol[prop].append("trace %d (%s/%s): %s" % (run["trace"], run["fam"], run["role"], msg))


def check_run(run, decs, rep):
    cfg, events = run["cfg"], run["events"]
    arr = [e for e in events if e["type"] == "arrive"]
    if len(decs) != len(arr):
        rep.bad("PROTO", run, "%d decisions for %d arrivals" % (len(decs), len(arr)))
        return None
    D = {}
    for e, d in zip(arr, decs):
        if not isinstance(d, dict) or d.get("id") != e["id"] or d.get("decision") not in ("admit", "reject") \
                or d.get("stage") not in STAGE_IDX or not isinstance(d.get("status"), int):
            rep.bad("PROTO", run, "malformed/misordered decision %r for id %d" % (d, e["id"]))
            return None
        D[e["id"]] = d
    # ---- I7: no fail-open; never 200 for a reject
    for e in arr:
        d = D[e["id"]]
        rep.checked["I7"] += 1
        if e["fault"]:
            rep.cov["fault_" + e["fault"]] += 1
            if d["decision"] != "reject":
                rep.bad("I7", run, "fault at %s on id %d but decision admit" % (e["fault"], e["id"]))
        if d["decision"] == "reject" and d["status"] not in OK_REJECT:
            rep.bad("I7", run, "reject id %d answered with status %d" % (e["id"], d["status"]))
        if d["decision"] == "admit" and (d["status"] != 200 or d["stage"] != "S6"):
            rep.bad("I7", run, "admit id %d with status %d stage %s" % (e["id"], d["status"], d["stage"]))
    # ---- shadows: S0 conns, S1 LRU+GCRA, S3 LRU+GCRA(+debit cap), aggregates
    conns, pfx_open = {}, defaultdict(int)
    s1 = SpecLRU(cfg["s1_store"])
    s3 = SpecLRU(cfg["s3_store"])
    seg_id = defaultdict(int)           # bucket key -> current residency segment number
    series_s1 = defaultdict(list)       # (ip, seg) -> [(t, 1)]
    series_s3 = defaultdict(list)       # (key, seg) -> [(t, units)]
    seg_meta = {}                       # (key, seg) -> (pname, insertion time)
    s1_seg = defaultdict(int)
    series_agg = {"F": [], "E": []}
    admitted = {}                       # id -> bucket key (for debits)
    b_anon = cfg["cls"]["anon"]["b"]
    for e in events:
        ty, now = e["type"], e["t"]
        if ty == "close":
            p = conns.pop(e["conn"], None)
            if p is not None:
                pfx_open[p] -= 1
            continue
        if ty == "done":
            rec = admitted.pop(e["id"], None)
            if rec is None:
                continue
            key, cost = rec
            if e["actual_cost"] - cost > 0 and key in s3.d:      # resident only; no insert, no LRU touch
                apply_debit(s3.d[key], key, e["actual_cost"] - cost, now, cfg, rep)
            continue
        d = D[e["id"]]
        st = STAGE_IDX[d["stage"]] if d["decision"] == "reject" else 7
        f = e["fault"]
        # S0
        if e["newconn"] and e["conn"] not in conns and st > 0:
            conns[e["conn"]] = e["prefix"]
            pfx_open[e["prefix"]] += 1
            rep.checked["S0"] += 1
            if len(conns) > cfg["max_conns"] or pfx_open[e["prefix"]] > cfg["prefix_cap"]:
                rep.bad("S0", run, "conn cap exceeded at id %d (%d open, prefix %d)" %
                        (e["id"], len(conns), pfx_open[e["prefix"]]))
        # S1 (lookup happens unless rejected earlier or faulted at S1)
        if st > 1 or (st == 1 and f != "S1"):
            ent, ins = s1.touch(e["ip"], lambda: {"tat": now})
            if ins:
                s1_seg[e["ip"]] += 1
            new = gcra_ok(ent["tat"], now, cfg["s1_T"], cfg["s1_b"], 1)
            rep.checked["I1"] += 1
            if st > 1:
                if new is None:
                    rep.bad("I1", run, "S1 passed non-conforming request id %d" % e["id"])
                else:
                    ent["tat"] = new
                series_s1[(e["ip"], s1_seg[e["ip"]])].append((now, 1))
            elif d["status"] == 429:
                rep.cov["s1_429"] += 1
                if new is not None:
                    rep.bad("I2", run, "S1 rejected conforming request id %d (spurious limiter state)" % e["id"])
        if st <= 2:
            continue
        cls = spec_class(e, cfg)
        key, pname = spec_bucket(e, cls)
        T, b = cfg["cls"][pname]["T"], cfg["cls"][pname]["b"]
        # S3 lookup unless faulted at S3
        if st == 3 and f == "S3":
            continue
        ent, ins = s3.touch(key, lambda: {"tat": now + (b - min(b, b_anon)) * T, "tat_u": now + (b - min(b, b_anon)) * T,
                                          "debited": False})
        if ins:
            seg_id[key] += 1
            seg_meta[(key, seg_id[key])] = (pname, now)
            if seg_id[key] > 1:
                rep.cov["s3_reinsert"] += 1
        cost = e["cost"]
        new = gcra_ok(ent["tat"], now, T, b, cost)
        new_u = max(ent["tat_u"], now) + cost * T
        new_u = new_u if new_u - now <= b * T else None
        charged = st >= 4
        if st == 3 and d["status"] == 429:
            rep.cov["s3_429"] += 1
            rep.checked["I5"] += 1
            if new is not None:
                if new_u is None:
                    rep.bad("I5", run, "S3 lockout of id %d: capped TAT conforms, subject still rejects "
                            "(debit not capped at now+10min)" % e["id"])
                else:
                    rep.bad("I2", run, "S3 rejected conforming request id %d of %r (foreign TAT?)" % (e["id"], key))
        if charged:
            rep.checked["I1"] += 1
            if new is None:
                prop = "I5" if ent["debited"] else "I1"
                rep.bad(prop, run, "S3 charged non-conforming request id %d of %r%s" %
                        (e["id"], key, " after a post-hoc debit (debit lost/overflowed)" if ent["debited"] else ""))
            else:
                ent["tat"] = new
            ent["tat_u"] = new_u if new_u is not None else max(ent["tat_u"], now) + cost * T
            series_s3[(key, seg_id[key])].append((now, cost))
            g = spec_group(cls, cost, cfg)
            if g:
                series_agg[g].append((now, cost))
            if st == 7:
                admitted[e["id"]] = (key, cost)
        if st == 3.5:
            rep.cov["s3a_reject"] += 1
    # ---- I1 windows: per S1 key segment and per S3 bucket segment
    for (ip, _), ser in series_s1.items():
        ex, w = window_excess(ser, cfg["s1_T"], cfg["s1_b"])
        if ex > 0:
            rep.bad("I1", run, "S1 key %s admitted beyond b + rW in window %s" % (ip, w))
    for (key, sg), ser in series_s3.items():
        pname, t_ins = seg_meta[(key, sg)]
        T, b = cfg["cls"][pname]["T"], cfg["cls"][pname]["b"]
        rep.checked["I1"] += 1
        ex, w = window_excess(ser, T, b)
        if ex > 0:
            rep.bad("I1", run, "bucket %r charged beyond b + rW (excess %.3g units) in window %s" % (key, ex / T, w))
        # I4: a (re-)inserted entry starts with at most the anonymous burst; anon never exceeds b_anon per instant
        first = sum(u for t, u in ser if t == t_ins)
        rep.checked["I4"] += 1
        rep.cov["i4_insert_bursts"] += first > 0
        if first > min(b, b_anon):
            rep.bad("I4", run, "bucket %r segment %d charged %d units at insertion > min(b, b_anon)=%d%s" %
                    (key, sg, first, min(b, b_anon), " (after eviction)" if sg > 1 else ""))
        if pname == "anon":
            per_t = defaultdict(int)
            for t, u in ser:
                per_t[t] += u
            mx = max(per_t.values())
            if mx > b_anon:
                rep.bad("I4", run, "anon bucket %r charged %d units in one instant > b_anon=%d" % (key, mx, b_anon))
    # ---- I8 aggregate windows (identity-count independent)
    for g in ("F", "E"):
        if series_agg[g]:
            rep.checked["I11" if run["role"] == "inflated" else "I8"] += 1
            a = cfg["agg"][g]
            ex, w = window_excess(series_agg[g], a["T"], a["b"])
            if ex > 0:
                prop = "I11" if run["role"] == "inflated" else "I8"
                rep.bad(prop, run, "expensive-tier %s aggregate exceeded A*W + burst by %.3g units in window %s"
                        "%s" % (g, ex / a["T"], w, (" (%d swarm identities)" % run["meta"]["swarm_n"])
                                if "swarm_n" in run["meta"] else ""))
    return D


def apply_debit(ent, key, d, now, cfg, rep):
    pname = {"v": "verified", "s": "session", "a": "anon"}[key[0]]
    T = cfg["cls"][pname]["T"]
    raw = max(ent["tat"], now) + d * T
    if raw > now + CAP_NS:
        rep.cov["debit_capped"] += 1
    if raw > U64:
        rep.cov["debit_overflow"] += 1
    ent["tat"] = min(raw, U64, now + CAP_NS)
    ent["tat_u"] = max(ent["tat_u"], now) + d * T
    ent["debited"] = True


def check_all(runs, decisions, rep):
    by_trace = {}
    for run, decs in zip(runs, decisions):
        D = check_run(run, decs, rep)
        by_trace.setdefault(run["trace"], {})[run["role"]] = (run, D)
        if run["role"] == "inflated":
            rep.cov["i11_runs"] += 1
            rep.cov["i11_nonbinding"] += run["meta"]["nonbinding"]
            rep.cov["i11_agg_binds"] += sum(1 for d in (D or {}).values() if d["stage"] == "S3A")
        if run["role"] == "main" and run["fam"] == "swarm" and run["meta"]["nonbinding"]:
            rep.cov["i8_nonbinding_traces"] += 1
    # ---- I2 metamorphic: removing another identity's events never changes the target's decisions
    for tr, roles in by_trace.items():
        if "perturbed" not in roles:
            continue
        (run, D0), (_, D1) = roles["main"], roles["perturbed"]
        if D0 is None or D1 is None:
            continue
        tgt = run["meta"]["target"]
        rep.cov["i2_pairs"] += 1
        for e in run["events"]:
            if e["type"] == "arrive" and e["_who"] == tgt:
                rep.checked["I2"] += 1
                a, b = D0[e["id"]], D1[e["id"]]
                if (a["decision"], a["stage"], a["status"]) != (b["decision"], b["stage"], b["status"]):
                    rep.cov["i2_metamorphic_fail"] += 1
                    rep.bad("I2", run, "target %s id %d: %s/%s with identity %s present vs %s/%s without" %
                            (tgt, e["id"], a["decision"], a["stage"], run["meta"]["others"] and
                             roles["perturbed"][0]["meta"]["removed"], b["decision"], b["stage"]))
                    break


VACUITY = ("fault_S0", "fault_S1", "fault_S2", "fault_S3", "fault_S4", "fault_S5", "fault_S6", "s1_429", "s3_429",
           "s3a_reject", "s3_reinsert", "debit_capped", "debit_overflow", "i2_pairs", "i4_insert_bursts",
           "i8_nonbinding_traces", "i11_runs", "i11_nonbinding", "i11_agg_binds")
PROPS = ("PROTO", "I1", "I2", "I4", "I5", "I7", "I8", "I11", "S0")


def evaluate(n_traces, seed, subject=None, mutation=None, quiet=False):
    runs = []
    for i in range(n_traces):
        runs.extend(gen_trace(seed, i))
    t0 = time.time()
    if subject:
        decisions = decide_subject(runs, subject)
    else:
        decisions = decide_ref(runs, mutation)
    t1 = time.time()
    rep = Report()
    check_all(runs, decisions, rep)
    h = hashlib.sha256()
    for decs in decisions:
        for d in decs:
            h.update(("%d%s%s%d;" % (d["id"], d["decision"], d["stage"], d["status"])).encode())
    rep.digest = h.hexdigest()[:16]
    rep.n_runs = len(runs)
    rep.n_events = sum(len(r["events"]) for r in runs)
    rep.times = (t1 - t0, time.time() - t1)
    return rep


def summarize(rep, label):
    lines = ["[%s] runs=%d events=%d decide=%.1fs check=%.1fs decisions-sha256/16=%s" %
             (label, rep.n_runs, rep.n_events, rep.times[0], rep.times[1], rep.digest)]
    for p in PROPS:
        v = rep.viol.get(p, [])
        lines.append("  %-5s checked=%-8d violations=%d" % (p, rep.checked.get(p, 0), rep.nviol.get(p, 0)))
        for m in [x for x in v if x][:3]:
            lines.append("        - " + m)
    vac = [k for k in VACUITY if rep.cov.get(k, 0) == 0]
    lines.append("  coverage: " + " ".join("%s=%d" % (k, rep.cov.get(k, 0)) for k in VACUITY))
    return lines, vac


EXPECT = {   # mutation -> properties any one of which must fire
    "tat_shared": ("I2",), "fail_open": ("I7",), "no_burst_cap": ("I1",), "evict_mint_verified": ("I4",),
    "tat_overflow": ("I5", "I1"), "no_debit_cap": ("I5",), "no_aggregate": ("I8", "I11"), "reject_200": ("I7",),
}


def main():
    ap = argparse.ArgumentParser(prog="oracles/admission-props/run")
    ap.add_argument("--subject", help="command speaking the event protocol on stdin/stdout (README.md)")
    ap.add_argument("--traces", type=int, default=10000)
    ap.add_argument("--seed", default="1")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--mutation", choices=REF.MUTATIONS, help="run against a mutated reference (debug)")
    a = ap.parse_args()
    if a.traces < 1:
        print("%s: FAIL (--traces must be >= 1)" % NAME)
        return 1
    if a.self_test:
        return self_test(a)
    rep = evaluate(a.traces, a.seed, subject=a.subject, mutation=a.mutation)
    label = "subject" if a.subject else ("ref+" + a.mutation if a.mutation else "reference")
    lines, vac = summarize(rep, label)
    print("\n".join(lines))
    nviol = sum(rep.nviol.get(p, 0) for p in PROPS)
    if nviol:
        bad = ",".join("%s=%d" % (p, rep.nviol[p]) for p in PROPS if rep.viol.get(p))
        print("%s: FAIL (%s over %d traces, seed %s)" % (NAME, bad, a.traces, a.seed))
        return 1
    if vac:
        print("%s: FAIL (vacuous: no coverage for %s)" % (NAME, ",".join(vac)))
        return 1
    print("%s: PASS (%d traces, seed %s, %d events; I1 I2 I4 I5 I7 I8 I11 S0 hold, 0 violations)" %
          (NAME, a.traces, a.seed, rep.n_events))
    return 0


def self_test(a):
    n = min(a.traces, 2400)
    print("self-test: %d traces per mutant, seed %s" % (n, a.seed))
    ok = True
    rep = evaluate(n, a.seed)
    base_viol = sum(rep.nviol.get(p, 0) for p in PROPS)
    print("  reference: violations=%d %s" % (base_viol, "ok" if base_viol == 0 else "UNEXPECTED"))
    ok &= base_viol == 0
    caught = []
    for m in REF.MUTATIONS:
        r = evaluate(n, a.seed, mutation=m)
        fired = [p for p in PROPS if r.viol.get(p)]
        hit = any(p in fired for p in EXPECT[m])
        if m == "tat_shared":      # the black-box metamorphic I2 check must catch it on its own, not only the shadow
            hit = hit and r.cov.get("i2_metamorphic_fail", 0) > 0
            print("        metamorphic I2 (remove another identity) failures: %d" % r.cov.get("i2_metamorphic_fail", 0))
        ok &= hit
        caught.append(m) if hit else None
        ex = next((x for p in EXPECT[m] for x in r.viol.get(p, []) if x), "")
        print("  mutant %-20s fired=%-22s expected one of %-10s %s" %
              (m, ",".join("%s:%d" % (p, r.nviol[p]) for p in fired) or "-", "/".join(EXPECT[m]),
               "CAUGHT" if hit else "MISSED"))
        if ex:
            print("        e.g. " + ex[:180])
    # the --subject plumbing must catch a mutant served over the protocol, and agree with in-process ref
    sub = "%s -I -B %s" % (shlex.quote(sys.executable), shlex.quote(os.path.join(HERE, "ref_subject.py")))
    k = min(n, 300)
    rp = evaluate(k, a.seed, subject=sub)
    rr = evaluate(k, a.seed)
    agree = rp.digest == rr.digest and not any(rp.viol.get(p) for p in PROPS)
    print("  protocol: ref_subject over stdin/stdout digest=%s in-process=%s %s" %
          (rp.digest, rr.digest, "agree" if agree else "DISAGREE"))
    ok &= agree
    rm = evaluate(k, a.seed, subject=sub + " --mutate tat_shared")
    pm = bool(rm.viol.get("I2"))
    print("  protocol: ref_subject --mutate tat_shared -> I2 violations=%d %s" %
          (rm.nviol.get("I2", 0), "CAUGHT" if pm else "MISSED"))
    ok &= pm
    if ok:
        print("%s SELF-TEST: PASS (%d/%d mutants caught: %s; protocol path caught tat_shared; reference clean)" %
              (NAME, len(caught), len(REF.MUTATIONS), ",".join(caught)))
        return 0
    print("%s SELF-TEST: FAIL (mutants caught %d/%d; see above)" % (NAME, len(caught), len(REF.MUTATIONS)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
