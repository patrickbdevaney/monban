#!/usr/bin/env python3
"""Wasmtime pin and effective-config check (gate wasmtime-config; ARCHITECTURE §3.6 R-ISO-2, PLAN D4 + D11).

  python3 -I ci/wasmtime-config.py check --worker PATH [--expect FILE] [--root DIR] [--tree FILE] [--lock FILE]
                                         [--config-json FILE --config-json-mpk FILE] [--static-only]
  python3 -I ci/wasmtime-config.py --self-test

Expectation: supply-chain/wasmtime-config.toml (frozen; the advisory shapes of GHSA-6wgr-89rj-399p and
GHSA-394w-hwhg-8vgm are quoted there verbatim with URL and read date).

check, static half (no build needed):
  - `cargo tree --offline --locked -e features -p aegis-p2` (or --tree FILE): the wasmtime feature nodes equal the
    frozen set exactly; wasmtime and every wasmtime-* crate is at the pinned version; no forbidden crate
    (wasmtime-wasi, wasmtime-wasi-http, winch, fiber, ...).
  - Cargo.lock (or --lock FILE): exactly one `wasmtime` package, at the pin; wasmtime-* at the pin; no wasi crates.
  - Source scan of crates/ and subjects/: exactly one Module/Component deserialize call, under crates/aegis-wasm/src/.
check, runtime half (needs the aegis-p2 binary):
  - `<worker> config --json` equals [effective] exactly; `<worker> config --json --mpk` equals [effective] with only
    [effective_mpk] keys changed. Both are also judged by named rules (GHSA shapes, reservation, guard, memory64,
    gc, threads, component model, epoch, fuel, MPK value) so a failure names its cause.
  - --static-only skips the runtime half and says so; it is never the gate command.
The expectation file itself is judged against hard floors held in this script, so weakening the toml is red.

--self-test: the clean fixture (ci/fixtures/wasmtime-config/clean) must PASS against the real expectation, and every
mutant in ci/fixtures/wasmtime-config/mutants.json must FAIL with its named rule(s).
Last line: `WASMTIME-CONFIG: PASS (...)` or `WASMTIME-CONFIG: FAIL (...)`; exit 0 only on PASS.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NAME = "WASMTIME-CONFIG"
EXPECT = os.path.join(ROOT, "supply-chain", "wasmtime-config.toml")
FIX = os.path.join(ROOT, "ci", "fixtures", "wasmtime-config")

GIB4 = 4 << 30
GUARD = 32 << 20
# Hard floors: the expectation file may never say less than this (R-ISO-2, D11).
FLOOR_EFFECTIVE = {
    "allocation_strategy": "pooling",
    "memory_reservation": GIB4,
    "memory_guard_size": GUARD,
    "guard_before_linear_memory": True,
    "signals_based_traps": True,
    "memory_protection_keys": "no",
    "wasm_memory64": False,
    "wasm_gc": False,
    "wasm_threads": False,
    "wasm_component_model": False,
    "epoch_interruption": True,
    "consume_fuel": True,
}
FLOOR_FORBIDDEN_CRATES = ("wasmtime-wasi", "wasmtime-wasi-http")
FLOOR_FORBIDDEN_FEATURES = ("gc", "threads", "winch", "component-model", "component-model-async", "async",
                            "wmemcheck", "default")
FLOOR_PIN = "50.0.1"

CRATE_RE = re.compile(r"(?:^|[\s─│├└])([A-Za-z0-9_][A-Za-z0-9_-]*) v(\d+\.\d+\.\d+[^\s]*)")
FEAT_RE = re.compile(r"(?:^|[\s─│├└])([A-Za-z0-9_][A-Za-z0-9_-]*) feature \"([^\"]+)\"")


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


# ---------------------------------------------------------------- expectation

def load_expect(path):
    with open(path, "rb") as f:
        return tomllib.load(f)


def judge_expect(exp):
    """The frozen file must not be weaker than the hard floors."""
    out = []
    if exp.get("schema") != 1:
        out.append(("expect-invalid:schema", "schema must be 1"))
    pin = exp.get("pin", {})
    if pin.get("crate") != "wasmtime" or pin.get("version") != FLOOR_PIN:
        out.append(("expect-invalid:pin", f"pin must be wasmtime {FLOOR_PIN}, got {pin}"))
    eff = exp.get("effective", {})
    for k, v in FLOOR_EFFECTIVE.items():
        if k not in eff or type(eff[k]) is not type(v) or eff[k] != v:
            out.append((f"expect-invalid:{k}", f"[effective].{k} must be {v!r}, got {eff.get(k)!r}"))
    mx = eff.get("pooling_max_memory_size")
    if not is_int(mx) or not (0 < mx < GIB4):
        out.append(("expect-invalid:pooling_max_memory_size", f"must be an integer in (0, 4 GiB), got {mx!r}"))
    mpk = exp.get("effective_mpk", {})
    if mpk != {"memory_protection_keys": "yes"}:
        out.append(("expect-invalid:effective_mpk", f"[effective_mpk] must change only memory_protection_keys to "
                                                    f"'yes', got {mpk}"))
    tree = exp.get("cargo_tree", {})
    feats = set(tree.get("wasmtime_features", []))
    for f in FLOOR_FORBIDDEN_FEATURES:
        if f in feats:
            out.append((f"expect-invalid:feature:{f}", f"wasmtime feature {f} may never be expected"))
    for f in sorted(feats - set(FLOOR_FORBIDDEN_FEATURES)):
        if f.startswith("gc") or f.startswith("component-model") or f.startswith("wasi") or f == "winch":
            out.append((f"expect-invalid:feature:{f}", f"wasmtime feature {f} may never be expected"))
    for c in FLOOR_FORBIDDEN_CRATES:
        if c not in tree.get("forbidden_crates", []):
            out.append((f"expect-invalid:forbidden:{c}", f"{c} must stay forbidden"))
    de = exp.get("deserialize", {})
    if de.get("expected_sites") != 1 or de.get("site_prefix") != "crates/aegis-wasm/src/":
        out.append(("expect-invalid:deserialize", "exactly one deserialize site, in crates/aegis-wasm/src/"))
    return out


# ---------------------------------------------------------------- static half

def tree_facts(text):
    crates = {}
    feats = set()
    for line in text.splitlines():
        for m in CRATE_RE.finditer(line):
            crates.setdefault(m.group(1), set()).add(m.group(2))
        for m in FEAT_RE.finditer(line):
            if m.group(1) == "wasmtime":
                feats.add(m.group(2))
    return crates, feats


def forbidden(name, exact, prefixes):
    return name in exact or any(name.startswith(p) for p in prefixes)


def judge_tree(text, exp):
    out = []
    pin = exp["pin"]["version"]
    t = exp["cargo_tree"]
    crates, feats = tree_facts(text)
    if "wasmtime" not in crates:
        return [("tree:wasmtime-absent", "no `wasmtime vX` node in the cargo tree of aegis-p2")]
    for name, vers in sorted(crates.items()):
        if name == "wasmtime" or name.startswith("wasmtime-"):
            for v in sorted(vers):
                if v != pin:
                    out.append(("pin:tree", f"cargo tree has {name} v{v}, pinned {pin}"))
        if forbidden(name, t.get("forbidden_crates", []), t.get("forbidden_crate_prefixes", [])):
            out.append((f"crate-forbidden:{name}", f"cargo tree contains forbidden crate {name}"))
    want = set(t["wasmtime_features"])
    for f in sorted(feats - want):
        out.append((f"feature-forbidden:{f}", f"wasmtime feature \"{f}\" is enabled but not in the frozen set"))
    for f in sorted(want - feats):
        out.append((f"feature-missing:{f}", f"wasmtime feature \"{f}\" is in the frozen set but not enabled"))
    return out


def judge_lock(text, exp):
    out = []
    pin = exp["pin"]["version"]
    try:
        lock = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        return [("lock:unparsable", str(e))]
    pk = lock.get("package", [])
    wt = [p for p in pk if p.get("name") == "wasmtime"]
    if len(wt) != 1:
        out.append(("pin:lock", f"Cargo.lock has {len(wt)} wasmtime packages ({[p.get('version') for p in wt]}), "
                                f"want exactly one at {pin}"))
    for p in pk:
        n, v = p.get("name", ""), p.get("version", "")
        if (n == "wasmtime" or n.startswith("wasmtime-")) and v != pin:
            out.append(("pin:lock", f"Cargo.lock has {n} {v}, pinned {pin}"))
        if forbidden(n, [], exp.get("lock", {}).get("forbidden_crate_prefixes", [])):
            out.append((f"crate-forbidden:{n}", f"Cargo.lock contains forbidden crate {n}"))
    return out


def strip_comments(src):
    src = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def deserialize_sites(root, exp):
    d = exp["deserialize"]
    sites = []
    for sr in d["scan_roots"]:
        base = os.path.join(root, sr)
        for dp, dn, fn in os.walk(base):
            dn[:] = sorted(x for x in dn if x != "target" and not x.startswith("."))
            for f in sorted(fn):
                if not f.endswith(".rs"):
                    continue
                p = os.path.join(dp, f)
                rel = os.path.relpath(p, root).replace(os.sep, "/")
                with open(p, encoding="utf-8", errors="replace") as fh:
                    src = strip_comments(fh.read())
                recv = {"Module", "Component"}
                for m in re.finditer(r"\b(?:Module|Component)\s+as\s+([A-Za-z_]\w*)", src):
                    recv.add(m.group(1))
                rx = re.compile(r"\b(?:(?:%s)\s*::\s*deserialize\w*|deserialize_(?:file|raw|open_file))\s*\("
                                % "|".join(sorted(recv)))
                for m in rx.finditer(src):
                    line = src.count("\n", 0, m.start()) + 1
                    sites.append(f"{rel}:{line}")
    return sites


def judge_sites(sites, exp):
    d = exp["deserialize"]
    out = []
    if len(sites) != d["expected_sites"]:
        out.append(("deserialize-count", f"{len(sites)} deserialize sites, want exactly {d['expected_sites']}: "
                                         f"{sites}"))
    for s in sites:
        if not s.startswith(d["site_prefix"]):
            out.append(("deserialize-outside-aegis-wasm", f"deserialize site outside {d['site_prefix']}: {s}"))
    return out


# ---------------------------------------------------------------- runtime half

def rules(cfg, tag):
    """Named rules on one effective config object. tag is '' or 'mpk:'."""
    out = []
    r = cfg.get("memory_reservation")
    g = cfg.get("memory_guard_size")
    mx = cfg.get("pooling_max_memory_size")
    if not (is_int(r) and is_int(g) and is_int(mx)):
        return [(tag + "schema:types", "memory_reservation, memory_guard_size, pooling_max_memory_size must be "
                                       "integers")]
    if cfg.get("allocation_strategy") == "pooling" and g == 0 and r < GIB4 and mx == r:
        out.append((tag + "ghsa-6wgr-shape", f"GHSA-6wgr-89rj-399p shape: pooling, guard 0, reservation {r} < 4 GiB, "
                                             f"max_memory_size == reservation"))
    if r < GIB4 and g == 0:
        out.append((tag + "ghsa-394w-shape", f"GHSA-394w-hwhg-8vgm shape: reservation {r} < 4 GiB with no guard"))
    if r < GIB4:
        out.append((tag + "reservation-below-4gib", f"memory_reservation {r} < {GIB4}"))
    if g < GUARD:
        out.append((tag + "guard-shrunk", f"memory_guard_size {g} < {GUARD}"))
    if cfg.get("guard_before_linear_memory") is not True:
        out.append((tag + "guard-before-off", "guard_before_linear_memory is not true"))
    if mx >= r:
        out.append((tag + "max-memory-size-ge-reservation", f"pooling_max_memory_size {mx} >= reservation {r}"))
    for k, rid in (("wasm_memory64", "memory64-on"), ("wasm_gc", "gc-on"), ("wasm_threads", "threads-on"),
                   ("wasm_component_model", "component-model-on")):
        if cfg.get(k) is not False:
            out.append((tag + rid, f"{k} is {cfg.get(k)!r}, must be false"))
    if cfg.get("epoch_interruption") is not True:
        out.append((tag + "epoch-off", "epoch_interruption is not true"))
    if cfg.get("consume_fuel") is not True:
        out.append((tag + "fuel-off", "consume_fuel is not true"))
    want_mpk = "yes" if tag else "no"
    if cfg.get("memory_protection_keys") != want_mpk:
        out.append((tag + "mpk-value", f"memory_protection_keys is {cfg.get('memory_protection_keys')!r}, "
                                       f"want {want_mpk!r}"))
    return out


def judge_config(base, mpk, exp):
    out = []
    eff = dict(exp["effective"])
    eff_mpk = dict(eff, **exp["effective_mpk"])
    for cfg, want, tag in ((base, eff, ""), (mpk, eff_mpk, "mpk:")):
        if not isinstance(cfg, dict):
            out.append((tag + "schema:not-object", "config --json did not print a JSON object"))
            continue
        for k in sorted(set(cfg) - set(want)):
            out.append((tag + f"schema:extra:{k}", f"unexpected key {k}"))
        for k in sorted(set(want) - set(cfg)):
            out.append((tag + f"schema:missing:{k}", f"missing key {k}"))
        for k in sorted(set(want) & set(cfg)):
            if type(cfg[k]) is not type(want[k]) or cfg[k] != want[k]:
                out.append((tag + f"frozen:{k}", f"{k} = {cfg[k]!r}, frozen {want[k]!r}"))
        out += rules(cfg, tag)
    if isinstance(base, dict) and isinstance(mpk, dict):
        for k in sorted((set(base) | set(mpk)) - set(exp["effective_mpk"])):
            if base.get(k, None) != mpk.get(k, None) or type(base.get(k)) is not type(mpk.get(k)):
                out.append((f"mpk-changed:{k}", f"--mpk changed {k}: {base.get(k)!r} -> {mpk.get(k)!r}"))
    return out


def run_worker(worker, extra):
    cmd = [worker, "config", "--json"] + extra
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"{' '.join(cmd)}: {e}"
    if p.returncode != 0:
        return None, f"{' '.join(cmd)}: exit {p.returncode}: {p.stderr.strip()[:400]}"
    try:
        return json.loads(p.stdout), None
    except json.JSONDecodeError as e:
        return None, f"{' '.join(cmd)}: not JSON: {e}"


# ---------------------------------------------------------------- driver

def evaluate(exp, root, tree_text, lock_text, base, mpk, static_only=False):
    f = judge_expect(exp)
    if f:
        return f
    f += judge_tree(tree_text, exp) if tree_text is not None else []
    f += judge_lock(lock_text, exp) if lock_text is not None else []
    f += judge_sites(deserialize_sites(root, exp), exp)
    if not static_only:
        f += judge_config(base, mpk, exp)
    return f


def read(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


def check(argv):
    import argparse
    ap = argparse.ArgumentParser(prog="wasmtime-config.py check")
    ap.add_argument("--worker")
    ap.add_argument("--expect", default=EXPECT)
    ap.add_argument("--root", default=ROOT)
    ap.add_argument("--tree")
    ap.add_argument("--lock")
    ap.add_argument("--config-json")
    ap.add_argument("--config-json-mpk")
    ap.add_argument("--static-only", action="store_true")
    a = ap.parse_args(argv)
    exp = load_expect(a.expect)
    findings = []
    if a.tree:
        tree_text = read(a.tree)
    else:
        cmd = exp.get("cargo_tree", {}).get("command", [])
        try:
            p = subprocess.run(cmd, cwd=a.root, capture_output=True, text=True, timeout=300)
            tree_text = p.stdout if p.returncode == 0 else None
            if p.returncode != 0:
                findings.append(("tree:failed", f"{' '.join(cmd)}: exit {p.returncode}: {p.stderr.strip()[:400]}"))
        except (OSError, subprocess.TimeoutExpired) as e:
            tree_text = None
            findings.append(("tree:failed", f"{' '.join(cmd)}: {e}"))
    lp = a.lock or os.path.join(a.root, "Cargo.lock")
    lock_text = read(lp) if os.path.exists(lp) else None
    if lock_text is None:
        findings.append(("lock:missing", lp))
    base = mpk = None
    if not a.static_only:
        if a.config_json and a.config_json_mpk:
            base, mpk = json.loads(read(a.config_json)), json.loads(read(a.config_json_mpk))
        elif a.worker:
            base, err = run_worker(a.worker, [])
            if err:
                findings.append(("runtime:worker", err))
            mpk, err = run_worker(a.worker, ["--mpk"])
            if err:
                findings.append(("mpk:runtime:worker", err))
        else:
            findings.append(("runtime:no-worker", "no --worker given (use --static-only to skip the runtime half)"))
    findings += evaluate(exp, a.root, tree_text, lock_text, base, mpk, a.static_only)
    for rid, msg in findings:
        print(f"  RED {rid}: {msg}")
    half = "static half only, runtime half NOT run" if a.static_only else "static + runtime"
    if findings:
        print(f"{NAME}: FAIL ({len(findings)} findings; {half})")
        return 1
    print(f"{NAME}: PASS (pin {exp['pin']['version']}, {len(exp['cargo_tree']['wasmtime_features'])} features exact, "
          f"1 deserialize site; {half})")
    return 0


def apply_case(case, work):
    for op in case.get("ops", []):
        p = os.path.join(work, op["file"])
        kind = op["op"]
        if kind == "write":
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(op["text"])
        elif kind == "delete":
            os.remove(p)
        elif kind in ("replace", "json"):
            txt = read(p)
            if kind == "replace":
                if txt.count(op["old"]) < 1:
                    raise ValueError(f"case {case['name']}: replace target not found in {op['file']}")
                txt = txt.replace(op["old"], op["new"], op.get("count", 1))
            else:
                obj = json.loads(txt)
                obj.update(op["set"])
                txt = json.dumps(obj, indent=2) + "\n"
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(txt)
        else:
            raise ValueError(f"unknown op {kind}")


def run_fixture(work, expect_path):
    exp = load_expect(expect_path)
    base = json.loads(read(os.path.join(work, "config.json")))
    mpk = json.loads(read(os.path.join(work, "config-mpk.json")))
    return evaluate(exp, os.path.join(work, "src"), read(os.path.join(work, "tree.txt")),
                    read(os.path.join(work, "Cargo.lock")), base, mpk)


def self_test():
    clean = os.path.join(FIX, "clean")
    with open(os.path.join(FIX, "mutants.json"), encoding="utf-8") as fh:
        cases = json.load(fh)["mutants"]
    bad = 0
    tmp = tempfile.mkdtemp(prefix="wtcfg-")
    try:
        f = run_fixture(clean, EXPECT)
        if f:
            bad += 1
            print(f"  clean: RED (must be green): {f}")
        else:
            print("  clean: green")
        for case in cases:
            work = os.path.join(tmp, case["name"])
            shutil.copytree(clean, work)
            exp_path = EXPECT
            if case.get("expect_ops"):
                exp_path = os.path.join(work, "expect.toml")
                shutil.copy(EXPECT, exp_path)
                apply_case({"name": case["name"], "ops": [dict(o, file="expect.toml") for o in case["expect_ops"]]},
                           work)
            apply_case(case, work)
            fired = {rid for rid, _ in run_fixture(work, exp_path)}
            need = set(case["red"])
            must_not = set(case.get("must_not", []))
            ok = bool(fired) and need <= fired and not (must_not & fired)
            print(f"  {case['name']}: {'red' if fired else 'GREEN'}"
                  f"{'' if ok else ' (WRONG: want ' + str(sorted(need)) + ', not ' + str(sorted(must_not)) + ')'}"
                  f" [{', '.join(sorted(fired))}]")
            bad += 0 if ok else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    n = len(cases)
    if bad:
        print(f"{NAME}: FAIL (self-test: {bad} of {n + 1} fixtures wrong)")
        return 1
    print(f"{NAME}: PASS (self-test: clean green, {n}/{n} mutants red with their named rules)")
    return 0


def main(argv):
    if argv[:1] == ["--self-test"]:
        return self_test()
    if argv[:1] == ["check"]:
        return check(argv[1:])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
