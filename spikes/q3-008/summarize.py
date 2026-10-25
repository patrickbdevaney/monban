#!/usr/bin/env python3
"""Markdown tables from suite jsonl files. usage: summarize.py raw/*.jsonl"""
import json, sys
for f in sys.argv[1:]:
    rows = [json.loads(l) for l in open(f) if l.strip()]
    meta = [r for r in rows if 'host' in r]
    print(f"\n### {f}\n")
    for m in meta: print(f"- host `{m['host']}`, CPU {m['cpu']}, kernel {m['kernel']}, governor {m['governor']}, image {m['image']}, client cpu {m['client_cpu']}, server cpu {m['server_cpu']}, loadavg at start {m['loadavg']}, {m['date']}")
    print("\n| run | auth/tls | mode | n | rate/s | p50 ms | p90 ms | p99 ms | p99.9 ms | client CPU µs/cycle | server CPU µs/cycle | err | reuse_fail |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        if 'mode' not in r: continue
        auth = ('trust' if r['user'] == 'trustu' else 'SCRAM') + '/' + ('plain' if r['tls'] == 'off' else 'TLS1.3-' + r['tls'])
        print(f"| {r['label']} c{r['conc']} | {auth} | {r['mode']} | {r['cycles']} | {r['rate_per_s']:.0f} | {r['p50_us']/1e3:.2f} | {r['p90_us']/1e3:.2f} | {r['p99_us']/1e3:.2f} | {r['p999_us']/1e3:.2f} | {r['client_cpu_us_per_cycle']} | {r['server_cpu_us_per_cycle']} | {r['errors']} | {r['reuse_fail']} |")
