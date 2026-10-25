#!/usr/bin/env python3
"""Print every crates.io package in harness/Cargo.lock published < 7 days before the reference date."""
import tomllib, json, urllib.request, datetime, sys, time
ref = datetime.datetime.fromisoformat(sys.argv[1] if len(sys.argv) > 1 else "2026-10-25T00:00:00+00:00")
lock = tomllib.load(open(__file__.rsplit('/', 1)[0] + '/harness/Cargo.lock', 'rb'))
young = n = 0
for p in lock['package']:
    if 'source' not in p: continue
    for attempt in range(5):
        try:
            req = urllib.request.Request(f"https://crates.io/api/v1/crates/{p['name']}/{p['version']}", headers={'User-Agent': 'aegis-ci'})
            d = json.load(urllib.request.urlopen(req, timeout=15))['version']['created_at']; break
        except Exception as e:
            time.sleep(2)
    else:
        print("UNCHECKED", p['name'], p['version']); young += 1; continue
    n += 1
    age = (ref - datetime.datetime.fromisoformat(d.replace('Z', '+00:00'))).total_seconds() / 86400
    if age < 7: print("YOUNG", p['name'], p['version'], d); young += 1
print(f"{n} checked, {young} young/unchecked")
