#!/usr/bin/env python3
"""Summarise a C-surface log written by tools/cc-log during one cargo build (P7-libcrux-001).

usage: python3 -I c_surface.py <label> <cc log> <target dir> <out.json>
Counts unique C/C++/assembly source files handed to the C compiler, split into
  crate sources  (inside a crate's source tree, e.g. ~/.cargo/registry/src/*/aws-lc-sys-*/aws-lc/...)
  generated      (inside the build's OUT_DIR, e.g. cc/cmake compiler-feature probes)
and grouped by crate; also lists native libraries the build scripts asked rustc to link (cargo:rustc-link-lib).
Prints one line `c-surface <label>: files=<n> (c=.. cxx=.. asm=..) crate_files=.. generated=.. invocations=..
crates=[..] native_libs=[..]` and writes the full JSON.
"""
import json
import os
import re
import sys


def kind(p):
    e = p.rsplit(".", 1)[-1]
    return {"c": "c", "cc": "cxx", "cpp": "cxx", "cxx": "cxx", "S": "asm", "s": "asm", "asm": "asm"}.get(e, "other")


def crate_of(p):
    m = re.search(r"/registry/src/[^/]+/([^/]+)/", p) or re.search(r"/spikes/libcrux-provider/([^/]+)/", p)
    return m.group(1) if m else ("OUT_DIR" if "/build/" in p and "/out/" in p else "other")


def main():
    label, log, target, out = sys.argv[1:5]
    inv, srcs = 0, set()
    if os.path.exists(log):
        for ln in open(log):
            t, _, v = ln.rstrip("\n").partition("\t")
            if t == "invoke":
                inv += 1
            elif t == "src":
                srcs.add(os.path.realpath(v) if os.path.isabs(v) else v)
    generated = sorted(s for s in srcs if "/build/" in s and "/out/" in s)
    crate_files = sorted(s for s in srcs if s not in set(generated))
    by_crate = {}
    for s in crate_files:
        by_crate.setdefault(crate_of(s), []).append(s)
    libs = set()
    for root, _dirs, files in os.walk(target):
        if "output" in files and os.path.basename(os.path.dirname(root)) == "build":
            for ln in open(os.path.join(root, "output"), errors="replace"):
                m = re.match(r"^cargo::?rustc-link-lib=(.+)$", ln.strip())
                if m:
                    libs.add(f"{os.path.basename(root).rsplit('-', 1)[0]}:{m.group(1)}")
    counts = {k: sum(1 for s in srcs if kind(s) == k) for k in ("c", "cxx", "asm")}
    res = {"label": label, "files": len(srcs), **counts, "crate_files": len(crate_files), "generated": len(generated),
           "invocations": inv, "by_crate": {k: len(v) for k, v in sorted(by_crate.items())},
           "native_libs": sorted(libs), "sources": sorted(srcs)}
    with open(out, "w") as f:
        json.dump(res, f, indent=1)
    print(f"c-surface {label}: files={len(srcs)} (c={counts['c']} cxx={counts['cxx']} asm={counts['asm']}) "
          f"crate_files={len(crate_files)} generated={len(generated)} invocations={inv} "
          f"crates={res['by_crate']} native_libs={res['native_libs']}")


main()
