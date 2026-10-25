#!/usr/bin/env python3
"""Frozen-interface manifest (F1-F13). Each listed file is hashed; any change needs a spec-change PR that
re-freezes the manifest (spec-author role) and re-runs every dependent gate.

Usage: python3 -I ci/interfaces.py freeze   # spec-author only; rewrites interfaces/MANIFEST.sha256
       python3 -I ci/interfaces.py check    # exit 1 on any missing/changed/unlisted interface file
       python3 -I ci/interfaces.py self-test  # mutates a temp copy of one file; check must fail
"""
import hashlib, os, shutil, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# (id, path, status). status "frozen" or "provisional:<spike>" (frozen now; the named spike may force a re-freeze).
IFACES = [
    ("F1", "spec/SPEC_INVARIANTS.md", "frozen"),
    ("F1", "spec/STATEMENTS.sha256", "frozen"),
    ("F2", "crates/aegis-types/src/lib.rs", "frozen"),
    ("F3", "crates/aegis-transport/src/exchange.rs", "frozen"),
    ("F4", "crates/aegis-data-ir/src/ir.rs", "provisional:q4-004"),
    ("F5", "interfaces/F5-token.cddl", "frozen"),
    ("F6", "crates/aegis-authz/src/combine.rs", "frozen"),
    ("F7", "sdk/aegis-sdk/src/surface.rs", "provisional:q4-001"),
    ("F8", "interfaces/F8-config.schema.json", "provisional:q4-008"),
    ("F9", "interfaces/F9-audit-event.schema.json", "frozen"),
    ("F10", "interfaces/F10-module-wire.cddl", "frozen"),
    ("F11", "interfaces/F11-upgrade-handover.cddl", "frozen"),
    ("F12", "tls/verdicts.toml", "provisional:q4-026"),
    ("F13", "interfaces/F13-conformance-report.schema.json", "frozen"),
]
MANIFEST = "interfaces/MANIFEST.sha256"


def sha(root, p):
    return hashlib.sha256(open(os.path.join(root, p), "rb").read()).hexdigest()


def check(root):
    m = os.path.join(root, MANIFEST)
    old = {}
    for line in open(m):
        h, fid, status, path = line.split()
        old[path] = (fid, status, h)
    bad = []
    for fid, path, status in IFACES:
        if not os.path.exists(os.path.join(root, path)):
            bad.append(f"{fid} {path}: missing")
        elif path not in old:
            bad.append(f"{fid} {path}: not in manifest (freeze it via a spec-change PR)")
        elif old[path][2] != sha(root, path):
            bad.append(f"{fid} {path}: changed since freeze")
    bad += [f"{p}: in manifest but no longer an interface" for p in old if p not in {x[1] for x in IFACES}]
    return bad


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "check"
    if mode == "freeze":
        with open(os.path.join(ROOT, MANIFEST), "w") as f:
            for fid, path, status in IFACES:
                f.write(f"{sha(ROOT, path)}  {fid:4s} {status:20s} {path}\n")
        print(f"froze {len(IFACES)} interface files -> {MANIFEST}")
        return
    if mode == "self-test":
        with tempfile.TemporaryDirectory() as d:
            for _, path, _ in IFACES + [("", MANIFEST, "")]:
                os.makedirs(os.path.dirname(os.path.join(d, path)), exist_ok=True)
                shutil.copy(os.path.join(ROOT, path), os.path.join(d, path))
            with open(os.path.join(d, "crates/aegis-authz/src/combine.rs"), "a") as f:
                f.write("\n// mutated: pretend someone loosened the combiner\n")
            bad = check(d)
        if any("combine.rs: changed" in b for b in bad):
            print("INTERFACES SELF-TEST: PASS (mutated F6 detected)"); return
        print("INTERFACES SELF-TEST: FAIL"); sys.exit(1)
    bad = check(ROOT)
    if bad:
        print("INTERFACES: FAIL"); [print("  - " + b) for b in bad]; sys.exit(1)
    print(f"INTERFACES: PASS ({len(IFACES)} frozen files unchanged)")


if __name__ == "__main__":
    main()
