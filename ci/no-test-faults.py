#!/usr/bin/env python3
"""Gate no-test-faults (P8-hardening-001; PREFLIGHT R11, PLAN-8): aegis-ops `acme::Faults` (deliberate ACME faults for
the acme-pebble oracle's self-test) exists only under aegis-ops feature `test-faults`, and no release graph enables it.

Usage: python3 -I ci/no-test-faults.py | --self-test

Checks, each with its own id in the failure lines:
  T1 feature   aegis-ops/Cargo.toml declares `test-faults`; it is not reachable from `default`, nor from any other
               aegis-ops feature (closure over its own [features] table), so turning on `acme` never turns it on.
  T2 enablers  across every manifest of the workspace (root [workspace.dependencies], crates/*, subjects/*, apps/*,
               sdk/*, xtask, fuzz/) only the packages in ALLOWED (acme-subject, an oracle subject never linked into
               aegis) enable `aegis-ops/test-faults`, through a dependency's `features` list or a [features] entry
               (`aegis-ops/test-faults`, `aegis-ops?/test-faults`).
  T3 resolved  cargo's feature resolver (`cargo tree -p aegis-bin -e normal,build --target all -f '{p} |{f}|'`) leaves
               `test-faults` off on aegis-ops in every release graph: aegis-bin default, `--features native`, each
               shipped feature alone (native, p2, proxy-protocol, l4, mtc, uring, adapter-mariadb, adapter-crdb), all of
               them together, and the cmvp build's flags (`--no-default-features --features cmvp`; the overlay lock
               changes versions, not feature resolution). Oracle-only features (e2e-mutants, p2-mutants) are not
               release graphs. Every aegis-bin feature must be classified here, so a new feature cannot slip past.
  T4 builds    the release build scripts (ci/repro.sh, ci/release/rebuild.sh, ci/release/jobs/build.sh,
               profiles/cmvp/build.sh) build aegis-bin in its own cargo invocation: no `--workspace`/`--all`, and no
               acme-subject, so feature unification cannot carry `test-faults` in from the oracle subject.
  T5 source    in crates/aegis-ops/src, every code line naming `Faults` or `faults` is gated: it sits in a module
               declared under `#[cfg(feature = "test-faults")]`, or carries that attribute (directly or among the
               attributes right above it). `pub struct Faults` must exist and be gated (a vacuous pass is a FAIL).

No network: cargo runs --offline first and only retries online if the offline resolve fails. Nothing is built.

--self-test: fixture mutants under ci/fixtures/no-test-faults/ (a tree where aegis-bin's graph has aegis-ops
|test-faults|, an aegis-bin manifest enabling aegis-ops/test-faults, an aegis-ops source with an ungated Faults, a
release script building --workspace) and in-memory manifest mutants (default -> test-faults, acme -> test-faults, the
workspace dependency carrying the feature, an unclassified aegis-bin feature) must each FAIL with their own check id;
the clean fixtures must PASS. A live mutant runs the real resolver on acme-subject (which does enable the feature) and
judges it as a release graph: it must FAIL T3.
"""
import json, os, re, subprocess, sys, tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "ci", "fixtures", "no-test-faults")

PKG = "aegis-ops"
FEAT = "test-faults"
ALLOWED = {"acme-subject"}
# aegis-bin features: release (shipped) vs oracle-only. T3 refuses an aegis-bin feature in neither list.
SHIPPED = ["native", "p2", "proxy-protocol", "l4", "mtc", "uring", "adapter-mariadb", "adapter-crdb"]
ORACLE_ONLY = ["e2e-mutants", "p2-mutants", "cmvp"]  # cmvp is judged as its own graph below
RELEASE_SCRIPTS = ["ci/repro.sh", "ci/release/rebuild.sh", "ci/release/jobs/build.sh", "profiles/cmvp/build.sh"]
ATTR = '#[cfg(feature = "test-faults")]'
TREE_FMT = "{p} |{f}|"
LINE = re.compile(r"^(\S+) v(\S+)(?: \([^)]*\))?(?: \|([^|]*)\|)?")
WORD = re.compile(r"(?<![-\w])(Faults|faults)\b")  # not the feature name test-faults


# ------------------------------------------------------------------------------------------------ T1 / T2 manifests

def closure(table, start):
    seen, todo = set(), [start]
    while todo:
        for v in table.get(todo.pop(), []):
            if v.startswith("dep:") or "/" in v:
                continue
            if v not in seen:
                seen.add(v)
                todo.append(v)
    return seen


def check_feature_table(table):
    v = []
    if FEAT not in table:
        return [f"T1 feature: {PKG} declares no feature {FEAT}"]
    for f in sorted(table):
        if f != FEAT and FEAT in closure(table, f):
            v.append(f"T1 feature: {PKG}/{FEAT} is reachable from {PKG}/{f}")
    return v


def enables(manifest):
    """Places in one parsed manifest that switch aegis-ops/test-faults on: [(where, text)]."""
    out = []
    sections = [("dependencies", manifest.get("dependencies", {})),
                ("build-dependencies", manifest.get("build-dependencies", {})),
                ("dev-dependencies", manifest.get("dev-dependencies", {})),
                ("workspace.dependencies", manifest.get("workspace", {}).get("dependencies", {}))]
    for tgt, t in manifest.get("target", {}).items():
        for k in ("dependencies", "build-dependencies", "dev-dependencies"):
            sections.append((f"target.{tgt}.{k}", t.get(k, {})))
    for where, deps in sections:
        for name, spec in deps.items():
            real = spec.get("package", name) if isinstance(spec, dict) else name
            if real == PKG and isinstance(spec, dict) and FEAT in spec.get("features", []):
                out.append((where, f"{name} features include {FEAT}"))
    for f, items in manifest.get("features", {}).items():
        for it in items:
            if re.fullmatch(rf"{re.escape(PKG)}\??/{re.escape(FEAT)}", it):
                out.append((f"features.{f}", it))
    return out


def manifest_paths():
    paths = [os.path.join(ROOT, "Cargo.toml"), os.path.join(ROOT, "fuzz", "Cargo.toml"),
             os.path.join(ROOT, "xtask", "Cargo.toml")]
    for d in ("crates", "subjects", "apps", "sdk"):
        base = os.path.join(ROOT, d)
        if os.path.isdir(base):
            for n in sorted(os.listdir(base)):
                p = os.path.join(base, n, "Cargo.toml")
                if os.path.isfile(p):
                    paths.append(p)
    return [p for p in paths if os.path.isfile(p)]


def load(p):
    with open(p, "rb") as f:
        return tomllib.load(f)


def check_enablers(manifests):
    """manifests: {label: parsed}. label = package name (or 'workspace-root')."""
    v = []
    for label, m in sorted(manifests.items()):
        for where, text in enables(m):
            if label not in ALLOWED:
                v.append(f"T2 enablers: {label} enables {PKG}/{FEAT} ({where}: {text})")
    return v


def live_manifests():
    out = {}
    for p in manifest_paths():
        m = load(p)
        label = m.get("package", {}).get("name")
        if label is None:
            label = "workspace-root" if os.path.dirname(p) == ROOT else os.path.relpath(p, ROOT)
        out[label] = m
    return out


# ------------------------------------------------------------------------------------------------ T3 resolved graphs

def parse_tree(text):
    feats = {}
    for line in text.splitlines():
        m = LINE.match(line.strip())
        if m and m.group(3) is not None:
            feats.setdefault(m.group(1), set()).update(x for x in m.group(3).split(",") if x)
    return feats


def check_graph(feats, label):
    if PKG not in feats:
        return [f"T3 resolved: {PKG} is not in the {label} graph (wrong package or a broken tree)"]
    if FEAT in feats[PKG]:
        return [f"T3 resolved: {PKG}/{FEAT} is on in the {label} graph ({','.join(sorted(feats[PKG]))})"]
    return []


def check_classified(bin_features):
    known = set(SHIPPED) | set(ORACLE_ONLY) | {"default"}
    return [f"T3 resolved: aegis-bin feature {f} is neither shipped nor oracle-only in ci/no-test-faults.py"
            for f in sorted(set(bin_features) - known)]


def cargo(args):
    r = None
    for extra in (["--offline"], []):
        r = subprocess.run(["cargo", *args, "--locked", *extra], cwd=ROOT, capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout
    raise RuntimeError(f"cargo {' '.join(args)} failed: {r.stderr.strip()[-600:]}")


def tree(pkg="aegis-bin", features=None, no_default=False):
    args = ["tree", "-p", pkg, "-e", "normal,build", "--target", "all", "--prefix", "none", "-f", TREE_FMT]
    if no_default:
        args.append("--no-default-features")
    if features:
        args += ["--features", features]
    return cargo(args)


def release_graphs():
    """[(label, tree kwargs)] for every release graph of aegis-bin."""
    g = [("default", {}), ("native", {"features": "native"})]
    g += [(f"--features {f}", {"features": f}) for f in SHIPPED if f != "native"]
    g.append(("all shipped features", {"features": ",".join(SHIPPED)}))
    g.append(("cmvp (--no-default-features --features cmvp)", {"features": "cmvp", "no_default": True}))
    return g


# ------------------------------------------------------------------------------------------------ T4 release scripts

def check_scripts(texts):
    """texts: {relpath: content}."""
    v = []
    for rel, t in sorted(texts.items()):
        if t is None:
            v.append(f"T4 builds: {rel} missing")
            continue
        for i, line in enumerate(t.splitlines(), 1):
            code = line.split("#", 1)[0] if not line.lstrip().startswith('"') else line
            if not re.search(r"\bbuild\b", code):
                continue
            if re.search(r"(^|\s|\")--(workspace|all)(\s|\"|$)", code):
                v.append(f"T4 builds: {rel}:{i} builds the whole workspace: {line.strip()[:120]}")
            if "acme-subject" in code:
                v.append(f"T4 builds: {rel}:{i} builds acme-subject with the release: {line.strip()[:120]}")
    return v


def live_scripts():
    out = {}
    for rel in RELEASE_SCRIPTS:
        p = os.path.join(ROOT, rel)
        out[rel] = open(p).read() if os.path.isfile(p) else None
    return out


# ------------------------------------------------------------------------------------------------ T5 source

def strip_comment(line):
    s = line.strip()
    if s.startswith("//"):
        return ""
    # Drop a trailing // comment when it is not inside a string literal (crude: even quote count before it).
    i = s.find("//")
    while i != -1:
        if s[:i].count('"') % 2 == 0:
            return s[:i].rstrip()
        i = s.find("//", i + 2)
    return s


def gated_modules(files):
    """Paths (relative to src) of module files declared under ATTR, plus everything below them."""
    gated = set()
    for rel, text in files.items():
        lines = [strip_comment(x) for x in text.splitlines()]
        for i, l in enumerate(lines):
            m = re.fullmatch(r"(?:pub(?:\([a-z]+\))? )?mod ([a-z_0-9]+);", l)
            if m and attr_above(lines, i):
                d = os.path.dirname(rel)
                if os.path.basename(rel) not in ("mod.rs", "lib.rs"):
                    d = os.path.join(d, os.path.splitext(os.path.basename(rel))[0])
                gated.add(os.path.normpath(os.path.join(d, m.group(1) + ".rs")))
                gated.add(os.path.normpath(os.path.join(d, m.group(1), "mod.rs")))
                gated.add(os.path.normpath(os.path.join(d, m.group(1))) + os.sep)
    return gated


def attr_above(lines, i):
    """True when line i carries ATTR or ATTR is among the attribute lines directly above it."""
    if lines[i].startswith(ATTR):
        return True
    j = i - 1
    while j >= 0:
        l = lines[j]
        if l == "":
            j -= 1
            continue
        if l.startswith("#[") or l.startswith("#!["):
            if l == ATTR:
                return True
            j -= 1
            continue
        return False
    return False


def check_source(files):
    """files: {path relative to aegis-ops/src: text}."""
    v = []
    gated = gated_modules(files)

    def is_gated_file(rel):
        rel = os.path.normpath(rel)
        return rel in gated or any(g.endswith(os.sep) and rel.startswith(g) for g in gated)

    struct_ok = False
    for rel, text in sorted(files.items()):
        in_gated = is_gated_file(rel)
        lines = [strip_comment(x) for x in text.splitlines()]
        for i, l in enumerate(lines):
            if not WORD.search(l):
                continue
            if re.search(r"\bpub struct Faults\b", l) and (in_gated or attr_above(lines, i)):
                struct_ok = True
            if in_gated or attr_above(lines, i):
                continue
            v.append(f"T5 source: {rel}:{i + 1} names Faults/faults outside {ATTR}: {l[:100]}")
    if not struct_ok:
        v.append("T5 source: no gated `pub struct Faults` found in aegis-ops/src")
    return v


def read_tree(base):
    out = {}
    for d, _, fs in os.walk(base):
        for f in fs:
            if f.endswith(".rs"):
                p = os.path.join(d, f)
                out[os.path.relpath(p, base)] = open(p).read()
    return out


# ------------------------------------------------------------------------------------------------ live + self-test

def live():
    v = []
    ops = load(os.path.join(ROOT, "crates", PKG, "Cargo.toml"))
    v += check_feature_table(ops.get("features", {}))
    v += check_enablers(live_manifests())
    binm = load(os.path.join(ROOT, "crates", "aegis-bin", "Cargo.toml"))
    v += check_classified(binm.get("features", {}).keys())
    graphs = release_graphs()
    for label, kw in graphs:
        v += check_graph(parse_tree(tree(**kw)), label)
    v += check_scripts(live_scripts())
    v += check_source(read_tree(os.path.join(ROOT, "crates", PKG, "src")))
    return v, len(graphs)


def fixture(*name):
    return open(os.path.join(FIX, *name)).read()


def self_test():
    errs = []

    def expect(label, v, want):
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

    # T3 fixture trees.
    expect("clean tree", check_graph(parse_tree(fixture("clean.tree")), "fixture"), None)
    expect("mutant tree: aegis-bin graph with aegis-ops test-faults",
           check_graph(parse_tree(fixture("mutant-bin-test-faults.tree")), "fixture"),
           ["T3 resolved: aegis-ops/test-faults is on"])
    expect("mutant tree: aegis-ops missing", check_graph(parse_tree(fixture("mutant-no-ops.tree")), "fixture"),
           ["T3 resolved: aegis-ops is not in"])

    # T1 feature-table mutants (from the live aegis-ops manifest).
    table = load(os.path.join(ROOT, "crates", PKG, "Cargo.toml")).get("features", {})
    if FEAT not in table:
        errs.append(f"live aegis-ops has no {FEAT} feature: the T1 mutants below would be meaningless")

    def mut(fn):
        t = json.loads(json.dumps(table))
        fn(t)
        return t
    expect("clean feature table", check_feature_table(table), None)
    expect("mutant default = [test-faults]", check_feature_table(mut(lambda t: t.update(default=[FEAT]))),
           ["T1 feature: aegis-ops/test-faults is reachable from aegis-ops/default"])
    expect("mutant acme -> test-faults", check_feature_table(mut(lambda t: t["acme"].append(FEAT))),
           ["T1 feature: aegis-ops/test-faults is reachable from aegis-ops/acme"])
    expect("mutant feature removed", check_feature_table(mut(lambda t: t.pop(FEAT))),
           ["T1 feature: aegis-ops declares no feature"])

    # T2: the fixture aegis-bin manifest, and in-memory mutants of the live set.
    mans = live_manifests()
    expect("clean manifests", check_enablers(mans), None)
    bad_bin = tomllib.loads(fixture("aegis-bin.enables.Cargo.toml"))
    expect("mutant fixture aegis-bin manifest enabling aegis-ops/test-faults",
           check_enablers({**mans, "aegis-bin": bad_bin}), ["T2 enablers: aegis-bin enables"])
    m2 = json.loads(json.dumps(mans))
    m2["workspace-root"]["workspace"]["dependencies"][PKG]["features"] = [FEAT]
    expect("mutant workspace dependency with test-faults", check_enablers(m2),
           ["T2 enablers: workspace-root enables"])
    m3 = json.loads(json.dumps(mans))
    m3["aegis-bin"].setdefault("features", {})["native"] = m3["aegis-bin"]["features"]["native"] + [f"{PKG}/{FEAT}"]
    expect("mutant aegis-bin native -> aegis-ops/test-faults", check_enablers(m3),
           ["T2 enablers: aegis-bin enables"])
    binf = load(os.path.join(ROOT, "crates", "aegis-bin", "Cargo.toml")).get("features", {})
    expect("clean aegis-bin feature classification", check_classified(binf.keys()), None)
    expect("mutant unclassified aegis-bin feature", check_classified(list(binf.keys()) + ["debug-hooks"]),
           ["T3 resolved: aegis-bin feature debug-hooks"])

    # T4 release scripts.
    expect("clean release scripts", check_scripts(live_scripts()), None)
    expect("mutant release script --workspace",
           check_scripts({"fixture/build.sh": fixture("mutant-release-workspace.sh")}),
           ["T4 builds: fixture/build.sh:3 builds the whole workspace",
            "T4 builds: fixture/build.sh:4 builds acme-subject"])

    # T5 source fixtures.
    expect("clean source fixture", check_source(read_tree(os.path.join(FIX, "src-clean"))), None)
    expect("mutant source: ungated Faults", check_source(read_tree(os.path.join(FIX, "src-ungated"))),
           ["T5 source: acme/mod.rs:"])
    expect("mutant source: no Faults at all", check_source({"lib.rs": "pub mod acme;\n"}),
           ["T5 source: no gated `pub struct Faults`"])

    # Live mutant: the real resolver on the one crate that does enable the feature, judged as a release graph.
    try:
        v = check_graph(parse_tree(tree("acme-subject")), "acme-subject (live mutant)")
        if any(x.startswith("T3 resolved: aegis-ops/test-faults is on") for x in v):
            print(f"self-test live acme-subject graph: FAIL as expected ({v[0]})")
        else:
            errs.append(f"live acme-subject graph: T3 did not report test-faults: {v}")
    except RuntimeError as e:
        errs.append(f"live acme-subject graph: {e}")

    if errs:
        for e in errs:
            print(f"  {e}")
        print("NO-TEST-FAULTS SELF-TEST: FAIL")
        return 1
    print("NO-TEST-FAULTS SELF-TEST: PASS")
    return 0


def main():
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    if sys.argv[1:]:
        print(__doc__)
        sys.exit(2)
    try:
        v, n = live()
    except (RuntimeError, OSError, ValueError, KeyError, tomllib.TOMLDecodeError) as e:
        print(f"NO-TEST-FAULTS: FAIL ({e})")
        sys.exit(1)
    for x in v:
        print(f"  {x}")
    if v:
        print(f"NO-TEST-FAULTS: FAIL ({len(v)} violations)")
        sys.exit(1)
    print(f"NO-TEST-FAULTS: PASS ({PKG}/{FEAT} off in {n} release graphs of aegis-bin; enabled only by "
          f"{','.join(sorted(ALLOWED))}; release scripts build aegis-bin alone; Faults code gated)")


if __name__ == "__main__":
    main()
