#!/usr/bin/env python3
"""Phase gate runner. Reads gates/phase-N.toml, runs every gate and its self-test (negative control), and writes a
hash-chained journal to gates/out/phase-N.json plus per-step logs. Exit 0 only on go.

Usage: python3 -I ci/run-gates.py --phase 0 [--only name,name] [--skip-heavy]
Gate semantics: `cmd` must exit 0; `selftest` must exit 0 (it exits 0 only when a mutated input was rejected).
`remote = true` runs the gate on the LAN build box through ci/remote.sh (timing-sensitive gates; the laptop is shared
with other projects); `remote = "<host>"` runs it on that ssh host instead (e.g. "quiet", the dedicated quiet runner).
Set AEGIS_NO_REMOTE=1 to force local execution.
"""
import argparse, hashlib, json, os, shlex, subprocess, sys, time, tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sh(cmd, log):
    env = dict(os.environ)
    env["PATH"] = os.path.expanduser("~/.cache/aegis-tools/bin") + os.pathsep + env.get("PATH", "")
    t = time.monotonic()
    p = subprocess.run(["bash", "-o", "pipefail", "-c", cmd], cwd=ROOT, env=env, capture_output=True, text=True)
    out = p.stdout + p.stderr
    with open(log, "w") as f:
        f.write(f"$ {cmd}\n{out}\n[exit {p.returncode}]\n")
    tail = [l for l in out.strip().splitlines() if l.strip()][-1:] or [""]
    return p.returncode, round(time.monotonic() - t, 1), hashlib.sha256(out.encode()).hexdigest(), tail[0][:200]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase", type=int, required=True)
    ap.add_argument("--only", default="")
    ap.add_argument("--skip-heavy", action="store_true")
    a = ap.parse_args()
    spec = tomllib.load(open(os.path.join(ROOT, f"gates/phase-{a.phase}.toml"), "rb"))
    outdir = os.path.join(ROOT, "gates", "out"); os.makedirs(os.path.join(outdir, "logs"), exist_ok=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain", "--", ".", ":!gates/out"], cwd=ROOT,
                                capture_output=True, text=True).stdout.strip())
    # Run-start marker: gates that consume another gate's log from this run (exception-ledger, conformance) reject
    # any log older than it (PLAN-6 D10).
    with open(os.path.join(outdir, "logs", ".run-start"), "w") as f:
        f.write(head + "\n")
    only =set(filter(None, a.only.split(",")))
    results, prev, ok = [], "0" * 64, True
    for g in spec["gate"]:
        if only and g["name"] not in only:
            continue
        if a.skip_heavy and g.get("heavy"):
            results.append({"name": g["name"], "status": "skipped-heavy"}); ok = False; continue
        for step in ("cmd", "selftest"):
            if step not in g:
                continue
            log = os.path.join(outdir, "logs", f"phase{a.phase}-{g['name']}-{step}.log")
            cmd = g[step]
            if g.get("remote") and os.environ.get("AEGIS_NO_REMOTE") != "1":
                host = g["remote"] if isinstance(g["remote"], str) else None
                cmd = "ci/remote.sh " + (f"--host {shlex.quote(host)} " if host else "") + "bash -c " + shlex.quote(cmd)
            rc, secs, h, tail = sh(cmd, log)
            passed = rc == 0
            ok &= passed
            entry = {"name": g["name"], "step": step, "pass": passed, "exit": rc, "secs": secs, "log_sha256": h, "tail": tail, "prev": prev}
            prev = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
            entry["hash"] = prev
            results.append(entry)
            print(f"{'PASS' if passed else 'FAIL'}  {g['name']:18s} {step:8s} {secs:7.1f}s  {tail}", flush=True)
    go = ok and not only and not dirty
    journal = {"phase": a.phase, "git_head": head, "dirty_tree": dirty, "partial": bool(only) or a.skip_heavy,
               "go": go, "results": results, "chain_head": prev}
    with open(os.path.join(outdir, f"phase-{a.phase}.json"), "w") as f:
        json.dump(journal, f, indent=1)
    verdict = "GO" if go else ("NO-GO" if not ok else "PASS (not a go: partial run or dirty tree)")
    print(f"PHASE {a.phase}: {verdict}  (journal gates/out/phase-{a.phase}.json, chain {prev[:12]})")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
