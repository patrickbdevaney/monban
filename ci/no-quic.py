#!/usr/bin/env python3
"""Gate no-quic (PREFLIGHT D-P7.1): HTTP/3 and WebTransport are deferred with evidence, so no QUIC stack may arrive
by accident. FAIL if any QUIC / HTTP/3 / WebTransport crate is
  - a package of either shipped lock (Cargo.lock, profiles/cmvp/Cargo.lock; fuzz/Cargo.lock too when present), or
  - a node of the aegis-bin build graph (normal + build edges, every target platform) with default features or with
    --all-features (the union of every feature graph).
Banned names: quinn, quinn-*, h3, h3-*, wtransport, wtransport-*, web-transport, web-transport-*, quiche,
tokio-quiche, s2n-quic, s2n-quic-*, neqo-*, msquic, tquic. (`h3` is matched exactly or with a `-` suffix, so an
unrelated crate such as `h3o` is not flagged.) Re-check of the deferral: ci/h3-precondition.py (manual, network).

Also hosts the positive control of gate no-otel-in-bin (D-P7.6), whose check is the shell filter in
gates/phase-7.toml: --self-test-otel runs that exact filter (read from the gate file) on fixture trees.

Usage: python3 -I ci/no-quic.py                 the check (light: cargo tree --offline, no compile)
       python3 -I ci/no-quic.py --self-test     red on a fixture lock with quinn-proto 0.11.19, red on a fixture
                                                aegis-bin --all-features tree with h3 (and on each other banned
                                                family), green on the clean controls
       python3 -I ci/no-quic.py --self-test-otel  the no-otel-in-bin filter is red on fixture trees with prost /
                                                opentelemetry* / tonic and green on a clean tree
"""
import os
import re
import subprocess
import sys
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FX = os.path.join(ROOT, "ci", "fixtures", "no-quic")
LOCKS_REQUIRED = ("Cargo.lock", "profiles/cmvp/Cargo.lock")
LOCKS_OPTIONAL = ("fuzz/Cargo.lock",)
BANNED = re.compile(
    r"^(quinn(-.+)?|h3(-.+)?|wtransport(-.+)?|web-transport(-.+)?|quiche|tokio-quiche|s2n-quic(-.+)?|neqo-.+|msquic"
    r"|tquic)$"
)
TREE_ARGS = ["cargo", "tree", "--locked", "--offline", "-e", "normal,build", "--target", "all", "-p", "aegis-bin",
             "--prefix", "none", "--no-dedupe"]


def lock_packages(text):
    """(name, version) of every [[package]] in a Cargo.lock text."""
    out, cur = [], None
    for line in text.splitlines():
        s = line.strip()
        if s == "[[package]]":
            if cur:
                out.append(cur)
            cur = ["", ""]
            continue
        if s.startswith("["):
            if cur:
                out.append(cur)
            cur = None
            continue
        if cur is not None:
            m = re.match(r'^(name|version)\s*=\s*"([^"]*)"', s)
            if m:
                cur[0 if m.group(1) == "name" else 1] = m.group(2)
    if cur:
        out.append(cur)
    return [tuple(p) for p in out if p[0]]


def lock_hits(text):
    return sorted({f"{n} {v}" for n, v in lock_packages(text) if BANNED.match(n)})


def tree_nodes(text):
    """First token (crate name) and second (version) of every `cargo tree --prefix none` line."""
    out = []
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            out.append((parts[0], parts[1]))
    return out


def tree_hits(text):
    return sorted({f"{n} {v}" for n, v in tree_nodes(text) if BANNED.match(n)})


def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def check():
    bad, notes = [], []
    for rel in LOCKS_REQUIRED + LOCKS_OPTIONAL:
        p = os.path.join(ROOT, rel)
        if not os.path.exists(p):
            if rel in LOCKS_REQUIRED:
                bad.append(f"{rel}: missing")
            continue
        text = read(p)
        n = len(lock_packages(text))
        if n == 0:
            bad.append(f"{rel}: no packages parsed")
            continue
        hits = lock_hits(text)
        if hits:
            bad.append(f"{rel}: " + ", ".join(hits))
        notes.append(f"{rel} {n} pkgs")
    for label, extra in (("default", []), ("all-features", ["--all-features"])):
        r = subprocess.run(TREE_ARGS + extra, cwd=ROOT, capture_output=True, text=True)
        nodes = tree_nodes(r.stdout)
        if r.returncode != 0 or not nodes:
            bad.append(f"cargo tree aegis-bin ({label}) failed: {r.stderr.strip()[:300]}")
            continue
        hits = tree_hits(r.stdout)
        if hits:
            bad.append(f"aegis-bin graph ({label}): " + ", ".join(hits))
        notes.append(f"aegis-bin {label} {len(set(nodes))} nodes")
    return bad, notes


def self_test():
    """Mutants must go red; clean controls must stay green."""
    fails, shown = [], []
    red = {
        "lock-quinn-proto.lock": lock_hits,
        "tree-h3-all-features.txt": tree_hits,
        "tree-h3-quinn.txt": tree_hits,
        "tree-wtransport.txt": tree_hits,
        "tree-web-transport-quinn.txt": tree_hits,
        "tree-quinn-udp.txt": tree_hits,
        "tree-s2n-quic.txt": tree_hits,
        "tree-quiche.txt": tree_hits,
    }
    green = {"lock-clean.lock": lock_hits, "tree-clean.txt": tree_hits}
    for name, fn in red.items():
        p = os.path.join(FX, name)
        if not os.path.exists(p):
            fails.append(f"missing fixture {name}")
            continue
        hits = fn(read(p))
        if not hits:
            fails.append(f"mutant not rejected: {name}")
        else:
            shown.append(f"{name} -> {', '.join(hits)}")
    for name, fn in green.items():
        p = os.path.join(FX, name)
        if not os.path.exists(p):
            fails.append(f"missing fixture {name}")
            continue
        text = read(p)
        n = len(lock_packages(text)) if name.endswith(".lock") else len(tree_nodes(text))
        if n < 10:
            fails.append(f"clean control {name} parsed only {n} entries")
        if fn(text):
            fails.append(f"clean control rejected: {name}: {fn(text)}")
    # The mandatory mutants of unit P7-spec-001.
    q = os.path.join(FX, "lock-quinn-proto.lock")
    if os.path.exists(q) and "quinn-proto 0.11.19" not in lock_hits(read(q)):
        fails.append("lock-quinn-proto.lock does not carry quinn-proto 0.11.19")
    if fails:
        print("NO-QUIC SELF-TEST: FAIL")
        for f in fails:
            print("  - " + f)
        return 1
    for s in shown:
        print("  red " + s)
    print(f"NO-QUIC SELF-TEST: PASS ({len(red)} mutants rejected, {len(green)} clean controls accepted)")
    return 0


def otel_gate_cmd():
    gates = tomllib.load(open(os.path.join(ROOT, "gates", "phase-7.toml"), "rb"))
    for g in gates.get("gate", []):
        if g.get("name") == "no-otel-in-bin":
            return g.get("cmd", "")
    return None


def self_test_otel():
    """Run the gate's own filter (everything after the first ` | `) on fixture trees in place of cargo tree."""
    cmd = otel_gate_cmd()
    if not cmd:
        print("NO-OTEL SELF-TEST: FAIL (gate no-otel-in-bin not found in gates/phase-7.toml)")
        return 1
    head, sep, filt = cmd.partition(" | ")
    fails = []
    if not sep or not head.startswith("! "):
        fails.append(f"gate cmd is not of the form '! <cargo tree> | <filter>': {cmd!r}")
    for need in ("cargo tree", "-p aegis-bin", "--all-features", "--prefix none", "normal,build"):
        if need not in head:
            fails.append(f"gate cmd's tree lacks {need!r}")
    if fails:
        print("NO-OTEL SELF-TEST: FAIL")
        for f in fails:
            print("  - " + f)
        return 1
    cases = {
        "tree-prost.txt": False,
        "tree-opentelemetry.txt": False,
        "tree-tonic.txt": False,
        "tree-clean.txt": True,
    }
    for name, want_pass in cases.items():
        p = os.path.join(FX, name)
        if not os.path.exists(p):
            fails.append(f"missing fixture {name}")
            continue
        r = subprocess.run(["bash", "-c", f"! cat \"$1\" | {filt}", "no-otel", p], capture_output=True, text=True)
        passed = r.returncode == 0
        if passed != want_pass:
            fails.append(f"{name}: filter {'passed' if passed else 'failed'}, want {'pass' if want_pass else 'red'}")
        else:
            print(f"  {'green' if passed else 'red  '} {name}")
    if fails:
        print("NO-OTEL SELF-TEST: FAIL")
        for f in fails:
            print("  - " + f)
        return 1
    print(f"NO-OTEL SELF-TEST: PASS (gate filter {filt!r}: red on prost/opentelemetry/tonic trees, green on clean)")
    return 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    if "--self-test-otel" in argv:
        return self_test_otel()
    bad, notes = check()
    if bad:
        print("NO-QUIC: FAIL")
        for b in bad:
            print("  - " + b)
        return 1
    print(f"NO-QUIC: PASS (no QUIC/HTTP3/WebTransport crate; {'; '.join(notes)})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
