#!/usr/bin/env python3
"""AEGIS Lean axiom allowlist gate (core-Lean only; no `import Lean` needed, so it runs on an Init-only toolchain).
Usage: python3 -I ci/axiom_audit.py <project_dir>
 1. forbids source tokens that bypass or extend the kernel's trust (sorry/admit/native_decide/ofReduceBool/...);
 2. emits `#print axioms` for EVERY theorem/lemma declared in the library roots and checks each against the
    allowlist {propext, Classical.choice, Quot.sound}; prints a per-theorem table; exit 1 on any violation."""
import os, re, subprocess, sys, tomllib
ALLOW = {"propext", "Classical.choice", "Quot.sound"}
FORBID = [r"\bsorry\b", r"\badmit\b", r"\bnative_decide\b", r"\bofReduceBool\b", r"\bofReduceNat\b",
          r"\btrustCompiler\b", r"\bimplemented_by\b", r"@\[extern", r"^\s*axiom\b", r"\bunsafe\b",
          r"debug\.skipKernelTC", r"\bbv_decide\b", r"\bopaque\b", r"set_option\s+maxRecDepth", r"\bdecide\s*:=\s*true"]
proj = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
cfg = tomllib.load(open(os.path.join(proj, "lakefile.toml"), "rb"))
man = os.path.join(proj, "lake-manifest.json")
fail = []
if os.path.exists(man):
    import json
    pk = json.load(open(man)).get("packages", [])
    if pk: fail.append(f"manifest has dependencies {[p.get('name') for p in pk]} (golden policy: none; Mathlib forbidden)")
roots = [r for lib in cfg["lean_lib"] for r in lib["roots"]]
# Scan EVERY .lean module in the package, not just the roots: an axiom or `sorry` in an imported helper module is
# still in the trusted closure (known-false-proofs case `hidden-axiom`).
mods = []
for dp, dn, fn in os.walk(proj):
    dn[:] = [d for d in dn if not d.startswith(".") and d != "negative-control"]
    for f in fn:
        if f.endswith(".lean") and not (dp == proj and f.startswith("lakefile")):
            mods.append(".".join(os.path.relpath(os.path.join(dp, f[:-5]), proj).split(os.sep)))
lib = os.path.join(proj, ".lake", "build", "lib", "lean")
for m in mods:
    if not os.path.exists(os.path.join(lib, *m.split(".")) + ".olean"):
        fail.append(f"{m}: module not in the build closure (make it a root or delete it; unbuilt sources are unaudited)")
names = []
for r in sorted(set(mods)):
    path = os.path.join(proj, *r.split(".")) + ".lean"
    src = open(path).read()
    nocomment = re.sub(r"/-.*?-/", "", src, flags=re.S)
    nocomment = re.sub(r"--[^\n]*", "", nocomment)
    for pat in FORBID:
        for m in re.finditer(pat, nocomment, flags=re.M):
            line = nocomment[:m.start()].count("\n") + 1
            fail.append(f"{r}: forbidden token /{pat}/ (comment-stripped line {line})")
    ns = []
    for line in nocomment.splitlines():
        m = re.match(r"\s*namespace\s+(\S+)", line)
        if m: ns.append(m.group(1)); continue
        m = re.match(r"\s*end\s+(\S+)", line)
        if m and ns and ns[-1] == m.group(1): ns.pop(); continue
        # Attributes, docstring-free modifiers and visibility may precede the keyword on the same line.
        m = re.match(r"\s*(?:@\[[^\]]*\]\s*)*(?:(?:private|protected|noncomputable|nonrec|partial)\s+)*(?:theorem|lemma)\s+([^\s(:{\[]+)", line)
        if m: names.append(((".".join(ns) + ".") if ns else "") + m.group(1))
audit = "\n".join(f"import {r}" for r in sorted(set(mods))) + "\n" + "\n".join(f"#print axioms {n}" for n in names) + "\n"
af = os.path.join(proj, ".lake", "Audit.lean"); os.makedirs(os.path.dirname(af), exist_ok=True)
open(af, "w").write(audit)
env = dict(os.environ, LEAN_PATH=os.path.join(proj, ".lake", "build", "lib", "lean"))
out = subprocess.run(["lean", af], capture_output=True, text=True, env=env)
text = out.stdout + out.stderr
if out.returncode != 0: fail.append("audit file failed to elaborate:\n" + text[-2000:])
rows = {}
for m in re.finditer(r"'([^']+)' (?:depends on axioms: \[([^\]]*)\]|does not depend on any axioms)", text):
    ax = [a.strip() for a in (m.group(2) or "").split(",") if a.strip()]
    rows[m.group(1)] = ax
print(f"{'theorem':55s} axioms")
for n in names:
    ax = rows.get(n)
    if ax is None: fail.append(f"{n}: no #print axioms output"); print(f"{n:55s} ??"); continue
    bad = [a for a in ax if a not in ALLOW]
    print(f"{n:55s} {', '.join(ax) if ax else '(none)'}{'   <-- NOT ALLOWED: ' + ','.join(bad) if bad else ''}")
    if bad: fail.append(f"{n}: unpermitted axioms {bad}")
print(f"\n{len(names)} theorems audited; allowlist = {sorted(ALLOW)}")
if fail:
    print("AXIOM GATE: FAIL"); [print("  - " + f) for f in fail]; sys.exit(1)
print("AXIOM GATE: PASS")
