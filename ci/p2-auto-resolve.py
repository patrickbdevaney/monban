#!/usr/bin/env python3
"""Which P2 path does the default config (`p2.isolation` absent = "auto") resolve to on this host? (PLAN-5 D23(b))

Usage: python3 -I ci/p2-auto-resolve.py --subject target/p2/release/aegis --expect cordon|forkwasm|host
       python3 -I ci/p2-auto-resolve.py --self-test

Writes a minimal F8 config with one wasm route and a p2 block that omits `isolation`, runs
`<subject> check-config <cfg> --print-effective`, and judges the dump: `p2.isolation` must be "auto",
`p2.usable_cpus` must equal this process's affinity-set size (`os.sched_getaffinity`, inherited by the subject), and
`p2.isolation_effective` must be the expected path. `--expect host` derives it from the rule (cordon below 8 usable
CPUs, else forkwasm). Prints the host facts and the verdict; last line `P2-AUTO-RESOLVE: PASS|FAIL (...)`.
The self-test runs the judge against fake subjects (truthful, auto-ignores-cpus, wrong CPU count, configured value
rewritten, no dump) and requires PASS only for the truthful one.
"""
import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile

NAME = "P2-AUTO-RESOLVE"
AUTO_CORDON_BELOW = 8
SHA = "0" * 64
CONFIG = {
    "v": 1,
    "listeners": [{"name": "pub", "bind": "127.0.0.1:8443", "profile": "P-PUBLIC-WEB"}],
    "vhosts": [{"host": "aegis.test", "routes": [{"id": 1, "path": "/a/", "to": {"wasm": "m"}, "authz": "allow-all"}]}],
    "p2": {"worker": "/opt/aegis-p2", "modules": [{"id": "m", "path": "/srv/p2/m.wasm", "sha256": SHA}]},
}


def judge(subject, expect):
    cpus = len(os.sched_getaffinity(0))
    want = expect if expect != "host" else ("cordon" if cpus < AUTO_CORDON_BELOW else "forkwasm")
    with tempfile.TemporaryDirectory(prefix="aegis-auto-") as d:
        cfg = os.path.join(d, "aegis.json")
        with open(cfg, "w") as f:
            json.dump(CONFIG, f)
        try:
            r = subprocess.run(subject + ["check-config", cfg, "--print-effective"], capture_output=True, text=True,
                               timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            return False, f"cannot run {subject[0]}: {e}"
    doc = None
    for ln in r.stdout.splitlines():
        if ln.strip().startswith("{"):
            try:
                doc = json.loads(ln)
            except ValueError:
                pass
    if r.returncode != 0 or not isinstance(doc, dict):
        return False, f"check-config exit {r.returncode}, no JSON dump: {r.stderr.strip()[-300:]}"
    p2 = doc.get("p2") or {}
    got = (p2.get("isolation"), p2.get("isolation_effective"), p2.get("usable_cpus"))
    print(f"host: {cpus} usable CPUs (affinity); expected path: {want}; dump (isolation, isolation_effective, "
          f"usable_cpus) = {got!r}", flush=True)
    bad = []
    if got[0] != "auto":
        bad.append(f"configured isolation {got[0]!r}, want 'auto' (the default)")
    if got[2] != cpus:
        bad.append(f"usable_cpus {got[2]!r}, want {cpus} (the affinity set)")
    if got[1] != want:
        bad.append(f"isolation_effective {got[1]!r}, want {want!r}")
    if bad:
        return False, "; ".join(bad)
    return True, f"default isolation auto -> {want} at {cpus} usable CPUs"


FAKE = r'''
import json, os, sys
mode = os.environ["FAKE_MODE"]
n = len(os.sched_getaffinity(0))
eff = "cordon" if n < 8 else "forkwasm"
p2 = {"isolation": "auto", "isolation_effective": eff, "usable_cpus": n}
if mode == "ignores-cpus":
    p2["isolation_effective"] = "forkwasm" if eff == "cordon" else "cordon"
elif mode == "wrong-count":
    p2["usable_cpus"] = n + 1
elif mode == "rewritten":
    p2["isolation"] = eff
elif mode == "no-dump":
    sys.exit(78)
print(json.dumps({"v": 1, "p2": p2}))
'''


def self_test():
    with tempfile.TemporaryDirectory(prefix="aegis-auto-st-") as d:
        fake = os.path.join(d, "fake.py")
        with open(fake, "w") as f:
            f.write(FAKE)
        subj = [sys.executable, "-I", fake]
        bad = []
        for mode, should_pass in (("truthful", True), ("ignores-cpus", False), ("wrong-count", False),
                                  ("rewritten", False), ("no-dump", False)):
            os.environ["FAKE_MODE"] = mode
            ok, why = judge(subj, "host")
            print(f"  fake {mode}: {'PASS' if ok else 'FAIL'} ({why})", flush=True)
            if ok != should_pass:
                bad.append(mode)
        # a fixed expectation that contradicts the host must be red even for the truthful fake
        os.environ["FAKE_MODE"] = "truthful"
        n = len(os.sched_getaffinity(0))
        ok, _ = judge(subj, "forkwasm" if n < AUTO_CORDON_BELOW else "cordon")
        if ok:
            bad.append("contradicting --expect")
    if bad:
        print(f"{NAME} SELF-TEST: FAIL (judge wrong on: {', '.join(bad)})")
        return 1
    print(f"{NAME} SELF-TEST: PASS (truthful fake green; 4 broken fakes and a contradicting expectation red)")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--subject")
    ap.add_argument("--expect", choices=["cordon", "forkwasm", "host"], default="host")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not a.subject:
        ap.error("--subject is required")
    ok, why = judge(shlex.split(a.subject), a.expect)
    print(f"{NAME}: {'PASS' if ok else 'FAIL'} ({why})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
