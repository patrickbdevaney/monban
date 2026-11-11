#!/usr/bin/env python3
"""Gate default-graph (P7-spec-002; PLAN-7, PREFLIGHT D-P7.3): Phase 7 must not move the default monban-bin build.

Usage: python3 -I ci/default-graph.py | --self-test

Checks, each with its own id in the failure lines:
  G1 baseline  the package set of `cargo tree -p monban-bin -e normal,build --target all --locked` (default features)
               equals ci/fixtures/default-graph/baseline.txt (recorded at e06550e) exactly: nothing added, removed or
               re-versioned.
  G2 forbidden none of the Phase 7 crates (io-uring, monban-wire, monban-uring, monban-adapter-mysql, monban-otlp) is in
               the default graph, nor in the `--features native` graph (the shipped native build).
  G3 features  every Phase 7 feature exists (monban-bin: proxy-protocol, l4, mtc, uring, adapter-mariadb,
               adapter-crdb; monban-tls: mtc; monban-adapter-pg: crdb) and none is reachable from that crate's
               `default` feature (closure over its own [features] table), read with `cargo metadata --no-deps`.
  G4 enabled   in the real resolved default and native graphs, no Phase 7 feature is enabled on monban-bin, monban-tls
               or monban-adapter-pg (cargo's feature resolver, `{f}` of cargo tree), so no other crate can switch one
               on behind monban-bin's back.

The budget limits themselves (§6: size, crates, unsafe lines) are the carried `budget` gate; this gate keeps its
input fixed. No network: cargo runs --offline first and only retries online if the offline resolve fails.

--self-test: fixture mutants under ci/fixtures/default-graph/ (io-uring in the default graph, monban-adapter-mysql in
the default graph, a changed default crate set, crdb enabled in the native graph) and feature-table mutants built
from features-clean.json must each FAIL with their own check id; the clean fixtures must PASS. Then three live
mutants run the real cargo resolver with `--features uring`, `--features adapter-mariadb` and `--features mtc`
fed to the default-graph check: each must FAIL G2 on the crate that feature pulls in.
"""
import json, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "ci", "fixtures", "default-graph")
BASELINE = os.path.join(FIX, "baseline.txt")

FORBIDDEN = ["io-uring", "monban-wire", "monban-uring", "monban-adapter-mysql", "monban-otlp"]
P7_FEATURES = {
    "monban-bin": ["proxy-protocol", "l4", "mtc", "uring", "adapter-mariadb", "adapter-crdb"],
    "monban-tls": ["mtc"],
    "monban-adapter-pg": ["crdb"],
}
TREE_FMT = "{p} |{f}|"
LINE = re.compile(r"^(\S+) v(\S+)(?: \([^)]*\))?(?: \|([^|]*)\|)?")


def parse_tree(text):
    """{(name, version)} and {name: set(enabled features)} from `cargo tree --prefix none -f '{p} |{f}|'` output
    (or the fixture form `name vVERSION [|features|]`)."""
    pkgs, feats = set(), {}
    for line in text.splitlines():
        m = LINE.match(line.strip())
        if not m:
            continue
        name, ver, f = m.group(1), m.group(2), m.group(3)
        pkgs.add((name, ver))
        if f is not None:
            feats.setdefault(name, set()).update(x for x in f.split(",") if x)
    return pkgs, feats


def parse_baseline(text):
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, ver = line.split()[:2]
        out.add((name, ver))
    return out


def closure(table, start):
    """Feature names reachable from `start` inside one package's [features] table."""
    seen, todo = set(), [start]
    while todo:
        f = todo.pop()
        for v in table.get(f, []):
            if v.startswith("dep:") or "/" in v:
                continue
            if v not in seen:
                seen.add(v)
                todo.append(v)
    return seen


def check_graph(pkgs, base, label="default"):
    v = []
    if base is not None:
        for n, ver in sorted(pkgs - base):
            v.append(f"G1 baseline: {label} graph gained {n} {ver}")
        for n, ver in sorted(base - pkgs):
            v.append(f"G1 baseline: {label} graph lost {n} {ver}")
    names = {n for n, _ in pkgs}
    for c in FORBIDDEN:
        if c in names:
            v.append(f"G2 forbidden: {c} is in the {label} monban-bin graph")
    return v


def check_features(tables):
    v = []
    for pkg, want in P7_FEATURES.items():
        table = tables.get(pkg)
        if table is None:
            v.append(f"G3 features: package {pkg} not found")
            continue
        on = closure(table, "default")
        for f in want:
            if f not in table:
                v.append(f"G3 features: {pkg} has no feature {f}")
            elif f in on:
                v.append(f"G3 features: {pkg}/{f} is reachable from default")
    return v


def check_enabled(feats, label):
    v = []
    for pkg, want in P7_FEATURES.items():
        for f in sorted(feats.get(pkg, set()) & set(want)):
            v.append(f"G4 enabled: {pkg}/{f} is on in the {label} graph")
    return v


def cargo(args):
    for extra in (["--offline"], []):
        r = subprocess.run(["cargo", *args, "--locked", *extra], cwd=ROOT, capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout
    raise RuntimeError(f"cargo {' '.join(args)} failed: {r.stderr.strip()[-600:]}")


def tree(features=None):
    args = ["tree", "-p", "monban-bin", "-e", "normal,build", "--target", "all", "--prefix", "none", "-f", TREE_FMT]
    if features:
        args += ["--features", features]
    return cargo(args)


def feature_tables():
    meta = json.loads(cargo(["metadata", "--format-version", "1", "--no-deps"]))
    return {p["name"]: p.get("features", {}) for p in meta["packages"] if p["name"] in P7_FEATURES}


def live():
    base = parse_baseline(open(BASELINE).read())
    d_pkgs, d_feats = parse_tree(tree())
    n_pkgs, n_feats = parse_tree(tree("native"))
    v = check_graph(d_pkgs, base)
    v += check_graph(n_pkgs, None, "native")
    v += check_features(feature_tables())
    v += check_enabled(d_feats, "default") + check_enabled(n_feats, "native")
    return v, len(d_pkgs), len(n_pkgs)


def fixture(name):
    return open(os.path.join(FIX, name)).read()


def self_test():
    base = parse_baseline(open(BASELINE).read())
    errs = []

    def expect(label, v, want):
        """want None: must pass; else every id in `want` must appear and no other id."""
        ids = {x.split(":")[0] for x in v}
        if want is None:
            if v:
                errs.append(f"{label}: clean control failed: {v}")
            else:
                print(f"self-test {label}: PASS (clean)")
            return
        missing = [w for w in want if not any(x.startswith(w) for x in v)]
        extra = ids - {w.split(":")[0] for w in want}
        if missing or extra:
            errs.append(f"{label}: wanted {want}, got {v}")
        else:
            print(f"self-test {label}: FAIL as expected ({'; '.join(v)})")

    # Clean controls.
    clean_pkgs, clean_feats = parse_tree(fixture("clean.tree"))
    if clean_pkgs != base:
        errs.append("clean.tree is not the baseline package set")
    expect("clean default", check_graph(clean_pkgs, base) + check_enabled(clean_feats, "default"), None)
    nat_pkgs, nat_feats = parse_tree(fixture("native-clean.tree"))
    expect("clean native", check_graph(nat_pkgs, None, "native") + check_enabled(nat_feats, "native"), None)
    tables = json.loads(fixture("features-clean.json"))
    expect("clean features", check_features(tables), None)

    # Mutant 1: monban-bin default features pull io-uring (through monban-uring).
    p, f = parse_tree(fixture("mutant-io-uring.tree"))
    expect("mutant io-uring in default", check_graph(p, base) + check_enabled(f, "default"),
           ["G1 baseline: default graph gained monban-uring", "G1 baseline: default graph gained io-uring",
            "G2 forbidden: io-uring", "G2 forbidden: monban-uring", "G4 enabled: monban-bin/uring"])
    # Mutant 2: monban-adapter-mysql in the default graph.
    p, f = parse_tree(fixture("mutant-adapter-mysql.tree"))
    expect("mutant monban-adapter-mysql in default", check_graph(p, base) + check_enabled(f, "default"),
           ["G1 baseline: default graph gained monban-adapter-mysql", "G2 forbidden: monban-adapter-mysql"])
    # Mutant 3: a changed default crate set (one crate re-versioned, one added) with no Phase 7 crate.
    p, f = parse_tree(fixture("mutant-changed-set.tree"))
    expect("mutant changed default set", check_graph(p, base) + check_enabled(f, "default"),
           ["G1 baseline: default graph gained tokio 1.54.1", "G1 baseline: default graph lost tokio 1.53.3",
            "G1 baseline: default graph gained want"])
    # Mutant 4: crdb enabled on monban-adapter-pg in the native graph by another crate.
    p, f = parse_tree(fixture("native-mutant-crdb.tree"))
    expect("mutant crdb on in native", check_graph(p, None, "native") + check_enabled(f, "native"),
           ["G4 enabled: monban-adapter-pg/crdb"])

    # Feature-table mutants.
    def mut(fn):
        t = json.loads(json.dumps(tables))
        fn(t)
        return t
    expect("mutant default = [uring]", check_features(mut(lambda t: t["monban-bin"].update(default=["uring"]))),
           ["G3 features: monban-bin/uring is reachable from default"])
    expect("mutant default -> native -> l4",
           check_features(mut(lambda t: (t["monban-bin"].update(default=["native"]),
                                         t["monban-bin"]["native"].append("l4")))),
           ["G3 features: monban-bin/l4 is reachable from default"])
    expect("mutant monban-tls default = [mtc]", check_features(mut(lambda t: t["monban-tls"].update(default=["mtc"]))),
           ["G3 features: monban-tls/mtc is reachable from default"])
    expect("mutant missing feature", check_features(mut(lambda t: t["monban-bin"].pop("adapter-crdb"))),
           ["G3 features: monban-bin has no feature adapter-crdb"])

    # Live mutants: the real resolver with one Phase 7 feature on, judged as if it were the default graph.
    for feat, crate in [("uring", "io-uring"), ("adapter-mariadb", "monban-adapter-mysql"), ("mtc", "monban-wire")]:
        try:
            p, f = parse_tree(tree(feat))
        except RuntimeError as e:
            errs.append(f"live --features {feat}: {e}")
            continue
        v = check_graph(p, base) + check_enabled(f, "default")
        if any(x.startswith(f"G2 forbidden: {crate} ") for x in v):
            print(f"self-test live --features {feat}: FAIL as expected (G2 {crate}; {len(v)} violations)")
        else:
            errs.append(f"live --features {feat}: G2 did not report {crate}: {v}")

    if errs:
        for e in errs:
            print(f"  {e}")
        print("DEFAULT-GRAPH SELF-TEST: FAIL")
        return 1
    print("DEFAULT-GRAPH SELF-TEST: PASS")
    return 0


def main():
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    if sys.argv[1:]:
        print(__doc__)
        sys.exit(2)
    try:
        v, nd, nn = live()
    except (RuntimeError, OSError, ValueError, KeyError) as e:
        print(f"DEFAULT-GRAPH: FAIL ({e})")
        sys.exit(1)
    for x in v:
        print(f"  {x}")
    if v:
        print(f"DEFAULT-GRAPH: FAIL ({len(v)} violations)")
        sys.exit(1)
    print(f"DEFAULT-GRAPH: PASS (default graph = e06550e baseline, {nd} packages; native graph {nn} packages; "
          f"no Phase 7 crate or feature in either)")


if __name__ == "__main__":
    main()
