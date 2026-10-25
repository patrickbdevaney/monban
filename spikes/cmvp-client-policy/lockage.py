#!/usr/bin/env python3
"""Check every crates.io package in a Cargo.lock was published >= MIN days before TODAY (spike contract).
usage: python3 -I lockage.py <Cargo.lock> [--min 7] [--today 2026-10-25]  -> prints too-young packages, exit 1 if any.
Caches crates.io answers in <lock dir>/.lockage-cache.json (small)."""
import datetime, json, os, sys, tomllib, urllib.request

def main():
    a = sys.argv[1:]
    lock = a[0]
    mn = int(a[a.index("--min") + 1]) if "--min" in a else 7
    today = datetime.date.fromisoformat(a[a.index("--today") + 1]) if "--today" in a else datetime.date.today()
    cache_p = os.path.join(os.path.dirname(os.path.abspath(lock)), ".lockage-cache.json")
    cache = json.load(open(cache_p)) if os.path.exists(cache_p) else {}
    pkgs = [p for p in tomllib.load(open(lock, "rb"))["package"] if p.get("source", "").startswith("registry+")]
    bad, oldest_ok = [], None
    for p in pkgs:
        k = f"{p['name']}@{p['version']}"
        if k not in cache:
            req = urllib.request.Request(f"https://crates.io/api/v1/crates/{p['name']}/{p['version']}",
                                         headers={"User-Agent": "aegis-spike lockage (patrickbdevaney@gmail.com)"})
            v = json.load(urllib.request.urlopen(req, timeout=30))["version"]
            cache[k] = {"created": v["created_at"][:10], "yanked": v["yanked"]}
        c = cache[k]
        age = (today - datetime.date.fromisoformat(c["created"])).days
        if age < mn or c["yanked"]:
            bad.append(f"{k} published {c['created']} ({age} d){' YANKED' if c['yanked'] else ''}")
    json.dump(cache, open(cache_p, "w"), indent=0, sort_keys=True)
    print(f"lockage: {len(pkgs)} registry packages, min {mn} d, today {today}: {len(bad)} violations")
    for b in bad:
        print("  " + b)
    sys.exit(1 if bad else 0)

main()
