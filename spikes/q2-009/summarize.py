#!/usr/bin/env python3
"""Summarize raw/*.rss.csv + raw/*.stat.csv into results.md (Markdown tables) and results.json."""
import csv, glob, json, os, sys

here = os.path.dirname(os.path.abspath(__file__))
raw = os.path.join(here, "raw")
MiB = 1024.0


def load(path):
    with open(path) as f:
        return [r for r in csv.DictReader(f)]


def at(rows, key, t_ms, tcol="t_ms"):
    """value of `key` at the last sample with t <= t_ms"""
    v = None
    for r in rows:
        if int(r[tcol]) <= t_ms:
            v = r[key]
    return v


runs = []
for rss_path in sorted(glob.glob(os.path.join(raw, "*.rss.csv"))):
    tag = os.path.basename(rss_path)[: -len(".rss.csv")]
    impl, shape, c = tag.split("__")
    conns = int(c[1:].split("-")[0])
    rss = [r for r in load(rss_path) if int(r["rss_kib"]) > 0]
    st_path = os.path.join(raw, tag + ".stat.csv")
    st = load(st_path) if os.path.exists(st_path) else []
    if not rss:
        continue
    idle = int(rss[0]["rss_kib"])
    peak = max(int(r["rss_kib"]) for r in rss)
    log = open(os.path.join(raw, tag + ".log")).read() if os.path.exists(os.path.join(raw, tag + ".log")) else ""
    curve = {}
    for t in (2, 5, 9, 12, 15, 20, 26, 30, 40, 50):
        v = at(rss, "rss_kib", t * 1000)
        if v is not None and t * 1000 <= int(rss[-1]["t_ms"]):
            curve[t] = round(int(v) / MiB, 1)
    streams = {}
    for t in (5, 9, 12, 20, 30, 45):
        v = at(st, "streams", t * 1000)
        if v is not None and st and t * 1000 <= int(st[-1]["t_ms"]):
            streams[t] = int(v)
    conns_live = {}
    for t in (20, 26, 35, 45):
        v = at(st, "conns", t * 1000)
        if v is not None and st and t * 1000 <= int(st[-1]["t_ms"]):
            conns_live[t] = int(v)
    peak_buf = max((int(r["buffered_kib_total"]) for r in st), default=0)
    max_conn_buf = max((int(r["max_conn_buffered_kib"]) for r in st), default=0)
    reaped = max((int(r["reaped"]) for r in st), default=0)
    runs.append(
        dict(
            tag=tag, impl=impl, shape=shape, conns=conns,
            idle_rss_mib=round(idle / MiB, 1), peak_rss_mib=round(peak / MiB, 1),
            peak_rss_delta_per_conn_mib=round((peak - idle) / MiB / conns, 2),
            peak_buffered_total_mib=round(peak_buf / MiB, 1),
            max_conn_buffered_mib=round(max_conn_buf / MiB, 2),
            reaped_streams=reaped, rss_curve_mib=curve, live_streams=streams, live_conns=conns_live,
            oom_or_died=("-1" in open(rss_path).read()),
            server_log_tail=[l for l in log.splitlines() if l and not l.startswith(("PID", "READY"))][-3:],
        )
    )

json.dump(runs, open(os.path.join(here, "results.json"), "w"), indent=1)

out = []
out.append("| run | conns | idle RSS | peak RSS | peak ΔRSS / conn | max buffered / conn (exact) | reaped | live streams @5/12/20 s |")
out.append("|---|---:|---:|---:|---:|---:|---:|---|")
for r in runs:
    ls = r["live_streams"]
    out.append(
        f"| {r['impl']} · {r['shape']}{(' ('+r['tag'].split('__c')[1].split('-',1)[1]+')') if '-' in r['tag'].split('__c')[1] else ''} | {r['conns']} | {r['idle_rss_mib']} MiB | {r['peak_rss_mib']} MiB"
        f" | {r['peak_rss_delta_per_conn_mib']} MiB | {r['max_conn_buffered_mib']} MiB | {r['reaped_streams']}"
        f" | {ls.get(5,'-')}/{ls.get(12,'-')}/{ls.get(20,'-')} |"
    )
out.append("")
out.append("RSS curve (MiB, seconds since server start; attack starts at ~1 s, client holds until ~26 s):")
out.append("")
ts = (2, 5, 9, 12, 15, 20, 26, 30, 40, 50)
out.append("| run | conns | " + " | ".join(f"{t}s" for t in ts) + " |")
out.append("|---|---:|" + "---:|" * len(ts))
for r in runs:
    if r["shape"] not in ("bigwin-noread", "window0", "slowread"):
        continue
    out.append(
        f"| {r['impl']} · {r['shape']}{(' ('+r['tag'].split('__c')[1].split('-',1)[1]+')') if '-' in r['tag'].split('__c')[1] else ''} | {r['conns']} | "
        + " | ".join(str(r["rss_curve_mib"].get(t, "")) for t in ts) + " |"
    )
open(os.path.join(here, "results.md"), "w").write("\n".join(out) + "\n")
print("\n".join(out))
