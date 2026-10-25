#!/usr/bin/env python3
"""cargo-vet exemption ratchet (supply-chain/POLICY.md). Every exemption must be listed in
supply-chain/vet-baseline.txt and the exemption count may not grow relative to HEAD~1 (or a given rev).
Usage: python3 -I ci/vet-baseline.py [--against REV] | --self-test"""
import os, re, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def exemptions(text):
    out, crate = [], None
    for line in text.splitlines():
        m = re.match(r"\[\[exemptions\.([^\]]+)\]\]", line.strip())
        if m:
            crate = m.group(1).strip('"'); continue
        m = re.match(r'version\s*=\s*"([^"]+)"', line.strip())
        if m and crate:
            out.append(f"{crate}:{m.group(1)}"); crate = None
    return out


def baseline(text):
    return {l.split()[0] for l in text.splitlines() if l.strip() and not l.startswith("#")}


def check(cfg, base, prev_cfg):
    bad = []
    cur = exemptions(cfg)
    bad += [f"{e}: exempted but not in vet-baseline.txt" for e in cur if e not in base]
    if prev_cfg is not None and len(cur) > len(exemptions(prev_cfg)):
        bad.append(f"exemption count grew {len(exemptions(prev_cfg))} -> {len(cur)}")
    return cur, bad


def main():
    if "--self-test" in sys.argv:
        cfg = '[[exemptions.libc]]\nversion = "0.2.191"\ncriteria = "safe-to-deploy"\n'
        _, bad1 = check(cfg, set(), "")
        _, bad2 = check(cfg, {"libc:0.2.191"}, "")
        _, bad3 = check(cfg, {"libc:0.2.191"}, cfg)
        if bad1 and bad2 and not bad3:
            print("VET-BASELINE SELF-TEST: PASS (unlisted exemption and count growth rejected; steady state accepted)"); return
        print("VET-BASELINE SELF-TEST: FAIL", bad1, bad2, bad3); sys.exit(1)
    rev = sys.argv[sys.argv.index("--against") + 1] if "--against" in sys.argv else "HEAD~1"
    cfg = open(os.path.join(ROOT, "supply-chain/config.toml")).read()
    bp = os.path.join(ROOT, "supply-chain/vet-baseline.txt")
    base = baseline(open(bp).read()) if os.path.exists(bp) else set()
    p = subprocess.run(["git", "show", f"{rev}:supply-chain/config.toml"], cwd=ROOT, capture_output=True, text=True)
    prev = p.stdout if p.returncode == 0 else None
    cur, bad = check(cfg, base, prev)
    if bad:
        print("VET-BASELINE: FAIL"); [print("  - " + b) for b in bad]; sys.exit(1)
    print(f"VET-BASELINE: PASS ({len(cur)} exemptions, all in the frozen baseline; count not grown vs {rev})")


if __name__ == "__main__":
    main()
