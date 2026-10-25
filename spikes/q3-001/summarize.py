#!/usr/bin/env python3
"""summarize.py RESULTS.jsonl -> band table (min..max across reps, median) per group x case; steal deltas."""
import json, sys, statistics as st
rows=[json.loads(l) for l in open(sys.argv[1])]
srv=[r for r in rows if r["kind"]=="server"]; cli=[r for r in rows if r["kind"]=="client"]
ctx=[r for r in rows if r["kind"]=="ctx"]
def steal(line): f=line.split(); return int(f[8]) if len(f)>8 else 0
for c in ctx: print(f'ctx {c["tag"]}: {c["host"]} {c["kernel"]} {c["model"]} gov={c["gov"]} load={c["loadavg"]} steal_all={steal(c["stat_cpu"])} steal_core={steal(c["stat_core"])}')
groups=["x25519","x25519mlkem768","p256mlkem768"]; cases=["full","resumed","reject","reject_notickets"]
res={}
print(f'{"group":16}{"case":18}{"hs/s band (median)":32}{"cpu us/hs band (median)":32}{"util min":>9}{"res%":>6}')
for g in groups:
  for c in cases:
    rs=[r for r in srv if r["group"]==g and r["case"]==c]
    if not rs: continue
    hs=[r["hs_per_s"] for r in rs]; us=[r["cpu_us_per_hs"] for r in rs]
    resf=sum(r["resumed"] for r in rs)/max(1,sum(r["resumed"]+r["full"] for r in rs))
    res[(g,c)]=(hs,us)
    print(f'{g:16}{c:18}{f"{min(hs):.0f}-{max(hs):.0f} ({st.median(hs):.0f})":32}{f"{min(us):.1f}-{max(us):.1f} ({st.median(us):.1f})":32}{min(r["cpu_util"] for r in rs):9.3f}{100*resf:6.1f}')
print("ratios of median cpu us/hs vs x25519 (band = min/max-ratio .. max/min-ratio):")
for g in groups[1:]:
  for c in cases:
    if (g,c) in res and ("x25519",c) in res:
      a=res[(g,c)][1]; b=res[("x25519",c)][1]
      print(f'  {g:16}{c:18} median {st.median(a)/st.median(b):.3f}  band {min(a)/max(b):.3f}..{max(a)/min(b):.3f}')
for c in cases[1:]:
  for g in groups:
    if (g,c) in res: print(f'  {c} / full  {g:16} {st.median(res[(g,c)][1])/st.median(res[(g,"full")][1]):.3f}')
st_core=[steal(r["core_stat_after"])-steal(r["core_stat_before"]) for r in srv]
print("per-run steal delta on server core (jiffies): max", max(st_core), "sum", sum(st_core))
print("client fails total", sum(r["fail"] for r in cli), "client ok total", sum(r["ok"] for r in cli))
print("server errs", sum(r["errs_total"] for r in srv), "hrr", sum(r["hrr_total"] for r in srv))
