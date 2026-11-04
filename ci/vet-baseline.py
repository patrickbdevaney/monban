#!/usr/bin/env python3
"""cargo-vet exemption ratchet (supply-chain/POLICY.md). Every exemption must be listed in
supply-chain/vet-baseline.txt and the exemption count may not grow relative to HEAD~1 (or a given rev).
Usage: python3 -I ci/vet-baseline.py [--against REV] | --self-test

Frozen mode (PLAN-6 D12, the cmvp lock; DEVIATIONS X-16):
  python3 -I ci/vet-baseline.py --frozen-failures VET.json --baseline FILE [--against REV]
VET.json is `cargo vet --locked --output-format json` of a tree whose supply-chain/ store carries no exemption for
the failing crates (the cmvp overlay tree: the root store, unchanged). FILE lists `crate:version criteria [reason]`.
Rules, same spirit as POLICY.md §cargo-vet but frozen (no intake after the first commit of FILE):
  - every vet failure `crate:version` is in FILE and every missing criterion is the one FILE lists for it;
  - FILE may only shrink: an entry absent from FILE at REV (default HEAD~1) fails, unless FILE did not exist at REV;
  - an entry that is no longer a vet failure (audited or imported since, or gone from the lock) must be removed,
    so the baseline ratchets down with the coverage."""
import json, os, re, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def exemptions(text):
    out, crate = [], None
    for line in text.splitlines():
        m = re.match(r"\[\[exemptions\.([^\]]+)\]\]", line.strip())
        if m:
            crate = m.group(1).strip('"'); continue
        m = re.match(r'version\s*=\s*"([^"]+)"', line.strip())
        if m and crate:
            out.append(f"{crate}:{m.group(1)}"); crate = None
    return out


def baseline(text):
    return {l.split()[0] for l in text.splitlines() if l.strip() and not l.startswith("#")}


def check(cfg, base, prev_cfg, prev_base=None):
    """Growth is allowed only for exemptions that are also NEW baseline entries in the same change (the
    dependency-intake commit); any other growth, or any exemption outside the baseline, fails."""
    bad = []
    cur = exemptions(cfg)
    bad += [f"{e}: exempted but not in vet-baseline.txt" for e in cur if e not in base]
    if prev_cfg is not None:
        prev = set(exemptions(prev_cfg))
        newly_based = base - (prev_base or set())
        grown = [e for e in cur if e not in prev and e not in newly_based]
        bad += [f"{e}: new exemption without a same-change baseline entry" for e in grown]
    return cur, bad


def frozen_baseline(text):
    """{crate:version: criteria} of a frozen baseline file."""
    out = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        f = line.split()
        out[f[0]] = f[1] if len(f) > 1 else ""
    return out


def vet_failures(vet_json):
    """{crate:version: set(missing criteria)} from `cargo vet --output-format json`."""
    d = json.loads(vet_json)
    concl = d.get("conclusion", "")
    if concl not in ("success", "fail (vetting)"):
        raise ValueError(f"cargo vet conclusion {concl!r} (expected success or fail (vetting))")
    return {f"{f['name']}:{f['version']}": set(f.get("missing_criteria", [])) for f in d.get("failures", [])}


def check_frozen(failures, base, prev_base):
    """failures: {crate:version: set(criteria)}; base / prev_base: {crate:version: criteria}; prev_base None = FILE
    absent at REV (the intake commit)."""
    bad = []
    for e, crit in sorted(failures.items()):
        if e not in base:
            bad.append(f"{e}: unvetted and not in the frozen baseline (audit or import it; the baseline is frozen)")
        elif not crit <= {base[e]}:
            bad.append(f"{e}: missing {sorted(crit)} but the baseline covers only {base[e]!r}")
    if prev_base is not None:
        bad += [f"{e}: baseline entry added after the freeze" for e in sorted(base) if e not in prev_base]
        bad += [f"{e}: baseline criteria changed after the freeze" for e in sorted(base)
                if e in prev_base and base[e] != prev_base[e]]
    bad += [f"{e}: no longer a vet failure; remove it from the baseline (monotone down)" for e in sorted(base)
            if e not in failures]
    return bad


def frozen_self_test():
    f = {"a:1.0.0": {"safe-to-deploy"}, "b:2.0.0": {"safe-to-deploy"}}
    base = {"a:1.0.0": "safe-to-deploy", "b:2.0.0": "safe-to-deploy"}
    cases = [
        ("clean (steady state)", f, base, base, False),
        ("clean (intake commit, no previous file)", f, base, None, False),
        ("unvetted crate not in the baseline", {**f, "c:3.0.0": {"safe-to-deploy"}}, base, base, True),
        ("missing criterion not covered", {**f, "a:1.0.0": {"safe-to-run"}}, base, base, True),
        ("baseline grew after the freeze", {**f, "c:3.0.0": {"safe-to-deploy"}},
         {**base, "c:3.0.0": "safe-to-deploy"}, base, True),
        ("baseline criteria changed after the freeze", {**f, "a:1.0.0": {"safe-to-run"}},
         {**base, "a:1.0.0": "safe-to-run"}, base, True),
        ("stale entry (crate now audited)", {"a:1.0.0": {"safe-to-deploy"}}, base, base, True),
    ]
    wrong = [n for n, fa, b, pb, want_bad in cases if bool(check_frozen(fa, b, pb)) != want_bad]
    try:
        vet_failures('{"conclusion":"fail (cycle)"}')
        wrong.append("unknown vet conclusion accepted")
    except ValueError:
        pass
    if vet_failures('{"conclusion":"success"}') != {}:
        wrong.append("success conclusion parsed as failures")
    return len(cases) + 2, wrong


def frozen_main():
    arg = lambda f: sys.argv[sys.argv.index(f) + 1]
    rev = arg("--against") if "--against" in sys.argv else "HEAD~1"
    bp = arg("--baseline")
    rel = os.path.relpath(os.path.abspath(bp), ROOT)
    try:
        failures = vet_failures(open(arg("--frozen-failures")).read())
        base = frozen_baseline(open(bp).read())
    except (OSError, ValueError, KeyError) as e:
        print(f"VET-FROZEN: FAIL ({e})"); sys.exit(1)
    q = subprocess.run(["git", "show", f"{rev}:{rel}"], cwd=ROOT, capture_output=True, text=True)
    prev = frozen_baseline(q.stdout) if q.returncode == 0 else None
    bad = check_frozen(failures, base, prev)
    if bad:
        print(f"VET-FROZEN ({rel}): FAIL"); [print("  - " + b) for b in bad]; sys.exit(1)
    print(f"VET-FROZEN ({rel}): PASS ({len(failures)} unvetted crates, all in the frozen baseline; "
          f"{'intake (no baseline at ' + rev + ')' if prev is None else 'no growth vs ' + rev}; no stale entries)")


def main():
    if "--frozen-failures" in sys.argv:
        return frozen_main()
    if "--self-test" in sys.argv:
        cfg = '[[exemptions.libc]]\nversion = "0.2.191"\ncriteria = "safe-to-deploy"\n'
        _, bad1 = check(cfg, set(), "")                                   # not in baseline
        _, bad2 = check(cfg, {"libc:0.2.191"}, "", {"libc:0.2.191"})      # growth, baseline entry not new
        _, bad3 = check(cfg, {"libc:0.2.191"}, cfg, {"libc:0.2.191"})     # steady state
        _, bad4 = check(cfg, {"libc:0.2.191"}, "", set())                 # intake commit
        n, wrong = frozen_self_test()
        if bad1 and bad2 and not bad3 and not bad4 and not wrong:
            print("VET-BASELINE SELF-TEST: PASS (unlisted exemption and unbaselined growth rejected; steady state and intake accepted; "
                  f"frozen mode {n}/{n} cases)"); return
        print("VET-BASELINE SELF-TEST: FAIL", bad1, bad2, bad3, wrong); sys.exit(1)
    rev = sys.argv[sys.argv.index("--against") + 1] if "--against" in sys.argv else "HEAD~1"
    cfg = open(os.path.join(ROOT, "supply-chain/config.toml")).read()
    bp = os.path.join(ROOT, "supply-chain/vet-baseline.txt")
    base = baseline(open(bp).read()) if os.path.exists(bp) else set()
    p = subprocess.run(["git", "show", f"{rev}:supply-chain/config.toml"], cwd=ROOT, capture_output=True, text=True)
    prev = p.stdout if p.returncode == 0 else None
    q = subprocess.run(["git", "show", f"{rev}:supply-chain/vet-baseline.txt"], cwd=ROOT, capture_output=True, text=True)
    prev_base = baseline(q.stdout) if q.returncode == 0 else set()
    cur, bad = check(cfg, base, prev, prev_base)
    if bad:
        print("VET-BASELINE: FAIL"); [print("  - " + b) for b in bad]; sys.exit(1)
    print(f"VET-BASELINE: PASS ({len(cur)} exemptions, all in the frozen baseline; no unbaselined growth vs {rev})")


if __name__ == "__main__":
    main()
