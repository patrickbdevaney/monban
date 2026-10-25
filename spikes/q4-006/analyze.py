#!/usr/bin/env python3
"""Aggregate q4-006 jsonl (medians over trials; counts pooled). usage: analyze.py <data_dir> [prefix]"""
import json, sys, statistics as st, collections, os
d = sys.argv[1]
pre = sys.argv[2] if len(sys.argv) > 2 else ""
def load(name):
    p = os.path.join(d, pre + name)
    return [json.loads(l) for l in open(p)] if os.path.exists(p) else []
def med(xs):
    xs = [x for x in xs if x is not None]
    return round(st.median(xs), 1) if xs else None
out = {}
for ph in ("loop", "fi", "lan"):
    rows = load(ph + ".jsonl")
    if not rows: continue
    g = collections.defaultdict(list)
    for r in rows: g[(r["variant"], r["fault"], r["rate"])].append(r)
    base = {v: med([x["rps"] for x in rs]) for (v, f, r), rs in g.items() if f == "none"}
    basep99 = {v: med([x["p99_us"] for x in rs]) for (v, f, r), rs in g.items() if f == "none"}
    res = {}
    for (v, f, r), rs in sorted(g.items()):
        errs = [x for x in rs if "error" in x]
        ok = [x for x in rs if "error" not in x]
        inj = sum(x["injected"] for x in ok); hf = sum(x["healthy_fail"] for x in ok)
        e = dict(trials=len(rs), driver_errors=len(errs), injected=inj, healthy_fail=hf,
                 blast_per_fault=round(hf / inj, 4) if inj else 0.0, wrong=sum(x["healthy_wrong"] for x in ok),
                 p50_us=med([x["p50_us"] for x in ok]), p99_us=med([x["p99_us"] for x in ok]),
                 rps=med([x["rps"] for x in ok]), recovery_p99_us_max=max([x["recovery_p99_us"] or 0 for x in ok], default=None),
                 recovery_p99_us_med=med([x["recovery_p99_us"] for x in ok]),
                 unrecovered=sum(x["unrecovered"] for x in ok), restarts=sum(x["restarts"] for x in ok),
                 censored=sum(x.get("censored", 0) for x in ok))
        pooled = sorted(v for x in ok for v in x.get("recovery_us", []))
        if pooled:
            e["recovery_p99_us_pooled"] = pooled[round((len(pooled) - 1) * 0.99)]
            e["recovery_p50_us_pooled"] = pooled[round((len(pooled) - 1) * 0.5)]
        e["loadavg1_range"] = [min(float(x["loadavg"].split()[0]) for x in ok), max(float(x["loadavg"].split()[0]) for x in ok)] if ok else None
        if base.get(v): e["rps_x"] = round(e["rps"] / base[v], 3)
        if basep99.get(v) and e["p99_us"]: e["p99_x"] = round(e["p99_us"] / basep99[v], 2)
        res["%s|%s|%s" % (v, f, r)] = e
    for x in rows: x.pop("recovery_us", None)
    out[ph] = res
fc = load("forkcost.jsonl")
if fc:
    agg = {}
    for pool in (False, True):
        for comp in (True, False):
            rs = [x for x in fc if x["pool"] == pool and x.get("compiled_in_zygote", True) == comp]
            if not rs: continue
            key = ("pool" if pool else "ondemand") + ("/compiled-in-zygote" if comp else "/cwasm")
            agg[key] = {k: {q: med([x[k][q] for x in rs]) for q in ("p50", "p99")}
                for k in ("inproc_fresh_instance_us", "fork_exit_wait_us", "fork_wasm_us", "fork_overhead_vs_fresh_us")}
            agg[key]["zygote_vmrss_kb"] = med([float(x["zygote_vmrss_kb"]) for x in rs])
    out["forkcost"] = agg
json.dump(out, sys.stdout, indent=1)
