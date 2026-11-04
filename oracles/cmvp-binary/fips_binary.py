#!/usr/bin/env python3
"""cmvp-binary `run`: the fips-binary gate (PLAN-6 D2, PREFLIGHT P2, BACKLOG G2b binary half + G6).

  run --binary PATH [--metadata FILE] [--expect floor]   judge one binary
  run --self-test                                        fixtures + mutants (see selftest.py)

Checks (cmvp, the default expectation):
  F1  the binary carries the contiguous bytes `AWS-LC FIPS 3.1.0` (>= 1 occurrence). Never a split match: if the
      bytes are not contiguous that is an INFEASIBLE report (PREFLIGHT P2), not a weaker check.
  F2  no other module identity in the binary: no `AWS-LC FIPS x.y.z` with another version and no non-FIPS
      `AWS-LC x.y.z` (aws-lc-sys's awslc_version_string, e.g. the floor's `AWS-LC 5.11.0`).
  F3  resolve graph of the overlaid cmvp tree (`profiles/cmvp/build.sh --metadata`, cargo metadata --locked):
      exactly one aws-lc-fips-sys node, at the pins.toml version; every aws-lc-rs node has feature `fips` and
      depends on that node; no registry aws-lc-sys node (only the void path crate, which has no build script).
  F4  runtime module identity: `<binary> --fips-check` (empty env, cwd /, stdin /dev/null, 20 s) exits 0 and its
      stdout is exactly one line, byte for byte:
          FIPS-CHECK: module="AWS-LC FIPS 3.1.0" fips_mode=true config_fips=true
--expect floor (negative control; the floor build must NOT look like cmvp):
  F1' no `AWS-LC FIPS` bytes at all;  F4' `--fips-check` prints exactly
          FIPS-CHECK: module=none fips_mode=false config_fips=false
      (F2/F3 are not judged for floor: the floor legitimately links aws-lc-sys).
Last line `CMVP-BINARY: PASS (...)` or `CMVP-BINARY: FAIL (...)`; exit 0 only on PASS (2 = cannot judge, also red).
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
MODULE = b"AWS-LC FIPS 3.1.0"
CMVP_LINE = 'FIPS-CHECK: module="AWS-LC FIPS 3.1.0" fips_mode=true config_fips=true'
FLOOR_LINE = "FIPS-CHECK: module=none fips_mode=false config_fips=false"
ANY_FIPS_ID = re.compile(rb"AWS-LC FIPS [0-9]+\.[0-9]+\.[0-9]+")
NONFIPS_ID = re.compile(rb"AWS-LC [0-9]+\.[0-9]+\.[0-9]+")


def arg(name, default=None):
    a = sys.argv[1:]
    for i, x in enumerate(a):
        if x == name and i + 1 < len(a):
            return a[i + 1]
    return default


def pinned_fips_sys():
    for line in open(os.path.join(ROOT, "profiles/cmvp/pins.toml")):
        m = re.match(r'^aws-lc-fips-sys = "(.*)"$', line.strip())
        if m:
            return m.group(1)
    return None


def scan_strings(data):
    """F1/F2 over the raw bytes (stripped binaries keep .rodata)."""
    ids = sorted({m.group(0).decode() for m in ANY_FIPS_ID.finditer(data)})
    nonfips = sorted({m.group(0).decode() for m in NONFIPS_ID.finditer(data)})
    return data.count(MODULE), ids, nonfips, data.count(b"AWS-LC FIPS")


def check_metadata(meta, pin):
    """F3 on cargo metadata JSON; returns a list of violations."""
    bad = []
    pk = {p["id"]: p for p in meta.get("packages", [])}
    nodes = {n["id"]: n for n in meta.get("resolve", {}).get("nodes", [])}
    if not nodes:
        return ["F3: metadata has no resolve graph"]
    fsys = [i for i in nodes if pk[i]["name"] == "aws-lc-fips-sys"]
    if len(fsys) != 1:
        bad.append(f"F3: {len(fsys)} aws-lc-fips-sys nodes (need exactly 1): "
                   + ", ".join(pk[i]["version"] for i in fsys))
    elif pin and pk[fsys[0]]["version"] != pin:
        bad.append(f"F3: aws-lc-fips-sys {pk[fsys[0]]['version']} != pins.toml {pin}")
    rs = [i for i in nodes if pk[i]["name"] == "aws-lc-rs"]
    if not rs:
        bad.append("F3: no aws-lc-rs node")
    for i in rs:
        if "fips" not in nodes[i].get("features", []):
            bad.append(f"F3: aws-lc-rs {pk[i]['version']} without feature fips")
        if not fsys or not any(d.get("pkg") in fsys for d in nodes[i].get("deps", [])):
            bad.append(f"F3: aws-lc-rs {pk[i]['version']} does not link aws-lc-fips-sys")
    for i in nodes:
        p = pk[i]
        if p["name"] != "aws-lc-sys":
            continue
        if p.get("source") is not None:
            bad.append(f"F3: registry aws-lc-sys {p['version']} in the cmvp graph ({p['source']})")
        elif any(t.get("kind") == ["custom-build"] for t in p.get("targets", [])):
            bad.append(f"F3: path aws-lc-sys {p['version']} has a build script (not the void crate)")
    return bad


def fips_check(binp):
    try:
        r = subprocess.run([binp, "--fips-check"], capture_output=True, timeout=20, env={}, cwd="/",
                           stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return None, "timeout after 20 s", b""
    except OSError as e:
        return None, f"cannot execute: {e}", b""
    return r.returncode, None, r.stdout


def judge(binp, expect="cmvp", meta_path=None, quiet=False):
    """Returns (verdict, [violations], info-lines). verdict in PASS/FAIL/ERROR."""
    info, bad = [], []
    if not os.path.isfile(binp):
        return "ERROR", [f"binary not found: {binp}"], info
    data = open(binp, "rb").read()
    n, ids, nonfips, n_prefix = scan_strings(data)
    info.append(f"F1 strings: {n} x 'AWS-LC FIPS 3.1.0'; FIPS identities {ids or 'none'}; "
                f"non-FIPS identities {nonfips or 'none'}; 'AWS-LC FIPS' prefix x{n_prefix}")
    rc, err, out = fips_check(binp)
    lines = out.decode(errors="replace").splitlines()
    info.append(f"F4 --fips-check: exit {rc if err is None else err}; stdout {lines[:3]!r}")
    want = CMVP_LINE if expect == "cmvp" else FLOOR_LINE
    f4_ok = err is None and rc == 0 and out == (want + "\n").encode()
    if expect == "floor":
        if n_prefix:
            bad.append(f"F1': floor binary carries 'AWS-LC FIPS' bytes x{n_prefix} ({ids})")
        if not f4_ok:
            bad.append(f"F4': --fips-check != '{want}' (exit {rc}, err {err}, stdout {lines[:3]!r})")
        return ("PASS" if not bad else "FAIL"), bad, info
    if n == 0:
        bad.append("F1: no contiguous 'AWS-LC FIPS 3.1.0' in the binary"
                   + (" (prefix present: split or other version; split = INFEASIBLE, PREFLIGHT P2)" if n_prefix else ""))
    other = [i for i in ids if i != MODULE.decode()]
    if other:
        bad.append(f"F2: other FIPS module identities in the binary: {other}")
    if nonfips:
        bad.append(f"F2: non-FIPS AWS-LC module identities in the binary: {nonfips}")
    if not f4_ok:
        bad.append(f"F4: --fips-check != '{want}' (exit {rc}, err {err}, stdout {lines[:3]!r})")
    pin = pinned_fips_sys()
    try:
        if meta_path:
            meta = json.load(open(meta_path))
            src = meta_path
        else:
            r = subprocess.run([os.path.join(ROOT, "profiles/cmvp/build.sh"), "--metadata"], capture_output=True,
                               text=True, timeout=600)
            if r.returncode != 0:
                return "ERROR", bad + [f"F3: profiles/cmvp/build.sh --metadata failed: {r.stderr.strip()[-400:]}"], info
            meta, src = json.loads(r.stdout), "profiles/cmvp/build.sh --metadata"
    except (OSError, ValueError, subprocess.TimeoutExpired) as e:
        return "ERROR", bad + [f"F3: cannot read metadata: {e}"], info
    mb = check_metadata(meta, pin)
    info.append(f"F3 graph ({src}): pin aws-lc-fips-sys {pin}; {len(mb)} violations")
    bad += mb
    return ("PASS" if not bad else "FAIL"), bad, info


def main():
    if "--self-test" in sys.argv:
        sys.path.insert(0, HERE)
        import selftest
        return selftest.fips_binary_selftest()
    binp = arg("--binary")
    if not binp:
        print("usage: run --binary PATH [--metadata FILE] [--expect cmvp|floor] | run --self-test", file=sys.stderr)
        print("CMVP-BINARY: FAIL (usage)")
        return 2
    expect = arg("--expect", "cmvp")
    if expect not in ("cmvp", "floor"):
        print("CMVP-BINARY: FAIL (--expect must be cmvp or floor)")
        return 2
    v, bad, info = judge(binp, expect, arg("--metadata"))
    for line in info:
        print(line)
    for b in bad:
        print("  violation:", b)
    if v == "PASS":
        what = ('module "AWS-LC FIPS 3.1.0" contiguous, sole identity, one fips-sys node, --fips-check matches'
                if expect == "cmvp" else "floor negative control: no FIPS identity, --fips-check module=none")
        print(f"CMVP-BINARY: PASS ({what})")
        return 0
    print(f"CMVP-BINARY: FAIL ({v}: {len(bad)} violations: {'; '.join(bad)[:600]})")
    return 1 if v == "FAIL" else 2


if __name__ == "__main__":
    sys.exit(main())
