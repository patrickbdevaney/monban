#!/usr/bin/env python3
"""Release builds are panic = abort (evidence gate for the block-buffer GHSA-qwgh-2vcv-g2f7 ledger entry).

Checks the workspace Cargo.toml: [profile.release] panic == "abort", and every custom profile that inherits from
release (directly or through another profile) does not set panic to anything else. Also checks the cmvp overlay does
not touch [profile.*]. Prints `PANIC-ABORT: PASS` / `PANIC-ABORT: FAIL (...)`.
Usage: ci/panic-abort.py [--self-test]
"""
import os
import sys
import tempfile
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def check(cargo_toml, overlay):
    errs = []
    d = tomllib.load(open(cargo_toml, "rb"))
    prof = d.get("profile", {})
    if prof.get("release", {}).get("panic") != "abort":
        errs.append(f"[profile.release] panic = {prof.get('release', {}).get('panic')!r}, want 'abort'")

    def from_release(name, seen=()):
        if name == "release":
            return True
        p = prof.get(name, {})
        inh = p.get("inherits")
        return bool(inh) and inh not in seen and from_release(inh, seen + (name,))

    for name, p in prof.items():
        if name not in ("release", "dev", "test", "bench") and from_release(name) and p.get("panic", "abort") != "abort":
            errs.append(f"[profile.{name}] inherits release but sets panic = {p['panic']!r}")
    if os.path.exists(overlay):
        o = tomllib.load(open(overlay, "rb"))
        if "profile" in o:
            errs.append(f"{os.path.relpath(overlay, ROOT)} sets [profile.*]")
    return errs


def main():
    cargo, overlay = os.path.join(ROOT, "Cargo.toml"), os.path.join(ROOT, "profiles/cmvp/overlay.toml")
    if "--self-test" in sys.argv:
        src = open(cargo).read()
        if check(cargo, overlay):
            print("PANIC-ABORT SELF-TEST: FAIL (clean tree rejected)")
            return 1
        mutants = {
            "release unwind": src.replace('[profile.release]\n', '[profile.release]\npanic = "unwind"\n', 1)
            .replace('panic = "abort"\nstrip', 'strip', 1),
            "derived profile unwind": src + '\n[profile.dist]\ninherits = "release"\npanic = "unwind"\n',
        }
        with tempfile.TemporaryDirectory() as t:
            for name, body in mutants.items():
                p = os.path.join(t, "Cargo.toml")
                open(p, "w").write(body)
                if not check(p, overlay):
                    print(f"PANIC-ABORT SELF-TEST: FAIL (mutant not rejected: {name})")
                    return 1
            ov = os.path.join(t, "overlay.toml")
            open(ov, "w").write('[profile.release]\npanic = "unwind"\n')
            if not check(cargo, ov):
                print("PANIC-ABORT SELF-TEST: FAIL (mutant not rejected: overlay sets profile)")
                return 1
        print(f"PANIC-ABORT SELF-TEST: PASS (clean green; {len(mutants) + 1}/{len(mutants) + 1} mutants red)")
        return 0
    errs = check(cargo, overlay)
    if errs:
        print("PANIC-ABORT: FAIL (" + "; ".join(errs) + ")")
        return 1
    print("PANIC-ABORT: PASS (release builds panic = abort; no derived profile or cmvp overlay overrides it)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
