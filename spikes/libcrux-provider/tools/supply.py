#!/usr/bin/env python3
"""Supply-chain checks on the spike lock (P7-libcrux-001 gate step "supply").

usage: python3 -I supply.py lockage <Cargo.lock> [--min 7] [--today YYYY-MM-DD]
       python3 -I supply.py osv <Cargo.lock> <Cargo.toml> <deny.toml>
       python3 -I supply.py isolation <spike Cargo.lock> <shipped lock>...
lockage: every crates.io package published >= MIN days before TODAY and not yanked (crates.io API, User-Agent aegis-ci).
osv: OSV querybatch for EVERY crates.io package@version in the lock (not only the compiled graph). Any hit fails; there
  is no acceptance list (P6-cmvp-002 precedent: ledgering an advisory for a crate that is never compiled weakens the
  gate). Each hit is annotated with whether the package is compiled for any of deny.toml's `targets` (`cargo tree
  --all-features -e normal,build,dev --target <t>`), for the report only.
isolation: no package that exists only because of this spike (libcrux*, lcx-*, cfixture, hax-lib, core-models) is in a
shipped lock, and the spike lock is not the root lock.
Exit 1 on any violation; one summary line per mode.
"""
import datetime
import json
import os
import subprocess
import sys
import tomllib
import urllib.request

UA = {"User-Agent": "aegis-ci"}


def registry_pkgs(lock):
    return [p for p in tomllib.load(open(lock, "rb"))["package"] if p.get("source", "").startswith("registry+")]


def lockage(lock, args):
    mn = int(args[args.index("--min") + 1]) if "--min" in args else 7
    today = datetime.date.fromisoformat(args[args.index("--today") + 1]) if "--today" in args else datetime.date.today()
    bad = []
    pkgs = registry_pkgs(lock)
    for p in pkgs:
        req = urllib.request.Request(f"https://crates.io/api/v1/crates/{p['name']}/{p['version']}", headers=UA)
        v = json.load(urllib.request.urlopen(req, timeout=30))["version"]
        created = datetime.date.fromisoformat(v["created_at"][:10])
        age = (today - created).days
        if age < mn or v["yanked"]:
            bad.append(f"{p['name']}@{p['version']} published {created} ({age} d){' YANKED' if v['yanked'] else ''}")
    print(f"lockage: {len(pkgs)} registry packages, min {mn} d, today {today}: {len(bad)} violations")
    for b in bad:
        print("  " + b)
    return 1 if bad else 0


def compiled(manifest, deny):
    targets = tomllib.load(open(deny, "rb"))["graph"]["targets"]
    out = set()
    for t in targets:
        r = subprocess.run(["cargo", "tree", "--manifest-path", manifest, "--locked", "--workspace", "--all-features",
                            "-e", "normal,build,dev", "--target", t, "--prefix", "none", "--format", "{p}"],
                           capture_output=True, text=True, check=True)
        for ln in r.stdout.splitlines():
            f = ln.split()
            if len(f) >= 2 and f[1].startswith("v"):
                out.add(f"{f[0]}@{f[1][1:]}")
    return targets, out


def osv(lock, manifest, deny):
    pkgs = registry_pkgs(lock)
    queries = [{"package": {"name": p["name"], "ecosystem": "crates.io"}, "version": p["version"]} for p in pkgs]
    req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=json.dumps({"queries": queries}).encode(),
                                 headers={**UA, "Content-Type": "application/json"})
    res = json.load(urllib.request.urlopen(req, timeout=60))["results"]
    if len(res) != len(pkgs):
        print(f"osv: FAIL (asked {len(pkgs)}, got {len(res)} results)")
        return 1
    targets, built = compiled(manifest, deny)
    hits = []
    for p, r in zip(pkgs, res):
        key = f"{p['name']}@{p['version']}"
        for v in r.get("vulns") or []:
            where = "COMPILED for a shipped target" if key in built else f"not compiled for any of {', '.join(targets)}"
            hits.append(f"{key}: {v['id']} ({where})")
    print(f"osv: {len(pkgs)} lock packages queried ({len(built)} compiled for {len(targets)} shipped targets): "
          f"{len(hits)} advisories")
    for h in hits:
        print("  " + h)
    return 1 if hits else 0


def isolation(spike, shipped):
    if not os.path.exists(spike):
        print("isolation: FAIL (spike lock missing)")
        return 1
    bad = []
    for lock in shipped:
        if os.path.realpath(lock) == os.path.realpath(spike):
            bad.append(f"{lock} is the spike lock")
            continue
        names = {p["name"] for p in tomllib.load(open(lock, "rb"))["package"]}
        leaked = sorted(n for n in names if n.startswith(("libcrux", "lcx-")) or n in ("cfixture", "hax-lib", "core-models"))
        if leaked:
            bad.append(f"{lock}: {', '.join(leaked)}")
    print(f"isolation: {len(shipped)} shipped locks checked: {len(bad)} violations")
    for b in bad:
        print("  " + b)
    return 1 if bad else 0


if __name__ == "__main__":
    mode, rest = sys.argv[1], sys.argv[2:]
    if mode == "lockage":
        sys.exit(lockage(rest[0], rest[1:]))
    if mode == "osv":
        sys.exit(osv(*rest[:3]))
    if mode == "isolation":
        sys.exit(isolation(rest[0], rest[1:]))
    sys.exit("usage: supply.py lockage|osv|isolation ...")
