#!/usr/bin/env python3
"""summarize.py RESULTS.jsonl -> bands (min..max over reps, median) per transport x placement x size."""
import json, sys, statistics as st
rows=[json.loads(l) for l in open(sys.argv[1])]
for c in [r for r in rows if r["kind"]=="ctx"]:
  f=c["stat_cpu"].split(); print(f'ctx {c["tag"]}: {c["host"]} {c["kernel"]} {c["model"]} gov={c["gov"]} load={c["loadavg"]} steal_all={f[8]} freq_a={c["freq_a_khz"]}')
L=[r for r in rows if r["kind"]=="lat"]
def band(xs,fmt="{:.1f}"): return f'{fmt.format(min(xs))}-{fmt.format(max(xs))} ({fmt.format(st.median(xs))})'
print(f'{"transport":14}{"place":7}{"size":>7}  {"p50 us":22}{"p99 us":22}{"calls/s (1 in flight)":26}{"cli+srv cpu us/call":22}{"budget 0.1/p50":>15}')
for t in ["uds-postcard","pipe-postcard"]:
  for pl in ["same","cross"]:
    for s in [64,65536]:
      rs=[r for r in L if r["transport"]==t and r["label"].startswith(pl) and r["size"]==s]
      if not rs: continue
      p50=[r["p50_ns"]/1e3 for r in rs]; p99=[r["p99_ns"]/1e3 for r in rs]; cps=[r["calls_per_s"] for r in rs]
      cpu=[r["client_cpu_us_per_call"]+r["server_cpu_us_per_call"] for r in rs]
      print(f'{t:14}{pl:7}{s:>7}  {band(p50):22}{band(p99):22}{band(cps,"{:.0f}"):26}{band(cpu):22}{0.1e6/st.median(p50):15.0f}')
