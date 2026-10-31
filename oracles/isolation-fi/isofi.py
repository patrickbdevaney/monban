#!/usr/bin/env python3
"""isolation-fi oracle: Phase-5 P2 isolation fault-injection gates (stdlib only; run as python3 -I).

Drives a P2 isolation subject (a server that inherits a listening Unix socket on fd 3 and runs the oracle's guest
module per request) through the Phase-5 fault classes and checks, per path:
  G0 baseline: 0 healthy failures with no faults
  G1 crash-attributable healthy failures per injected fault <= 0.05 at 1% (each gated class)
  G2 0 wrong answers in every cell (includes poison: a poisoned instance must never serve a later request)
  G3 recovery p99 <= 5 ms per fault cell and no unrecovered fault
  G4 healthy throughput at 1% loop >= 0.5x the no-fault baseline
Two host-fault classes model guest-triggerable host bugs: hostabort (the host process aborts) and hostpoison (host
state is silently corrupted for the rest of the process's life). They are gated for the fork+Wasm path, whose
containment claim covers them, and only reported for the cordon path (a per-tenant cordon accepts cordon-local
damage by design; a cordon shared by principals does not, see spikes/q4-006).

Phase-5 additions (unit P5-oracle-fi-001, PLAN D10/D14):
  --trials N          pool N driver runs per cell (counts summed, recovery samples concatenated, throughput = total
                      requests / total wall time); D14: 3 at GO, 1 on PR checks
  --record <json>     write per-cell metrics (merged by path into an existing record file)
  --reference <json>  print current/reference ratios per timing metric and flag any shift >2x (either direction);
                      report only: the verdict is computed before the reference is read and never sees it
  --mutant-subject    with --self-test --subject --path: the real subject's `mutants` build, selected per mutant with
                      AEGIS_P2_MUTANT; must be red on every mutant while --subject (and the mutants build unmutated)
                      passes
"""
import argparse, json, os, platform, subprocess, sys, tempfile, time

NAME = "ISOLATION-FI"
GATED = ["panic", "abort", "segv", "loop", "oom", "poison"]
HOST = ["hostabort", "hostpoison"]
# Reference budget: fuel units for ~2 ms of guest CPU on the calibration host (spikes/q4-006/README.md);
# epoch / ITIMER_REAL wall-clock backstop 100 ms.
REF_FUEL = 15_000_000
REF = {
    "cordon": "{bin} serve cordon --guest {guest} --data {data} --threads 64 --budget fuel:%d --epoch-ms 100" % REF_FUEL,
    "forkwasm": "{bin} serve forkwasm --guest {guest} --data {data} --budget fuel:%d --epoch-ms 100" % REF_FUEL,
}
MUTATIONS = [
    # (label, path, subject template, cells that must turn the verdict red)
    ("shared-store (one Store/Instance across requests)", "cordon",
     REF["cordon"] + " --mutation shared-store", ["poison"]),
    ("recycle50 (instance reused for 50 requests)", "cordon",
     REF["cordon"] + " --mutation recycle50", ["poison"]),
    ("no-deadline (no fuel, no epoch deadline) cordon", "cordon",
     REF["cordon"].replace("--budget fuel:%d" % REF_FUEL, "--budget none"), ["loop"]),
    ("no-fork (zygote serves in-process)", "forkwasm",
     REF["forkwasm"] + " --mutation no-fork", ["hostabort", "hostpoison"]),
    ("no-deadline (no fuel, no itimer) fork+Wasm", "forkwasm",
     REF["forkwasm"].replace("--budget fuel:%d" % REF_FUEL, "--budget none"), ["loop"]),
    # Phase 5: reference counterparts of the real subject's new mutants
    ("epoch-only-4 (research E4: epoch-only, 4 threads)", "cordon",
     REF["cordon"] + " --mutation epoch-only-4", ["loop"]),
    ("reuse-instance (fork child serves 50 more requests)", "forkwasm",
     REF["forkwasm"] + " --mutation reuse-instance", ["poison"]),
]
# The real subject's `mutants` build (feature p2-subject/mutants) selects one mutant with AEGIS_P2_MUTANT=<name>
# (gates/phase-5.toml p2-fault-forkwasm / p2-fault-cordon). Every self-test cell is driven for every mutant.
P2_MUTANTS = {
    "forkwasm": ["no-fork", "no-deadline", "reuse-instance"],
    "cordon": ["shared-store", "recycle50", "no-deadline", "epoch-only-4"],
}
SELFTEST_CELLS = ["poison", "loop"] + HOST


def subject_env(mutant):
    """Environment for the subject: AEGIS_P2_MUTANT only when a mutant is asked for, never inherited."""
    env = {k: v for k, v in os.environ.items() if k != "AEGIS_P2_MUTANT"}
    if mutant:
        env["AEGIS_P2_MUTANT"] = mutant
    return env


def drive(bin_, guest, data, subject, fault, rate, n, seed, workdir, core, clients, conc, mutant=None):
    pre = os.path.join(workdir, "%s-%s-%s-%s-%s" % (abs(hash(subject)) % 10**8, mutant or "m0", fault, rate, seed))
    cmd = [bin_, "drive", "--server", subject.replace("{bin}", bin_), "--guest", guest, "--data", data,
           "--fault", fault, "--rate", str(rate), "--n", str(n), "--conc", str(conc), "--seed", str(seed),
           "--prefix", pre, "--server-core", core, "--client-cores", clients, "--max-seconds", "90",
           "--sockdir", workdir]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=200, env=subject_env(mutant))
        line = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""
        d = json.loads(line) if line else {"error": p.stderr[-300:]}
    except subprocess.TimeoutExpired:
        d = {"error": "driver timeout"}
    except json.JSONDecodeError:
        d = {"error": "bad driver output"}
    d.setdefault("fault", fault)
    return d


def pctl(v, p):
    """Same percentile rule as the driver (rust/host pct): nearest rank on (len-1)*p, rounded."""
    if not v:
        return None
    v = sorted(v)
    return v[int(round((len(v) - 1) * p))]


def pool(trials):
    """Pool N driver summaries of one cell (PLAN D14). Counts are summed; G1 blast = sum healthy failures / sum
    injected; G3 recovery percentiles are recomputed over the concatenated per-fault samples; throughput = total
    requests / total wall time; latency p99 = worst trial (no per-request latencies cross the JSON boundary)."""
    if len(trials) == 1:
        d = dict(trials[0])
        d["trials"] = 1
        return d
    errs = [t for t in trials if "error" in t]
    if errs:
        d = dict(errs[0])
        d["trials"] = len(trials)
        return d
    s = lambda k: sum(t.get(k, 0) or 0 for t in trials)
    rec = [x for t in trials for x in t.get("recovery_us", [])]
    inj, wall = s("injected"), s("wall_us")
    return {
        "fault": trials[0].get("fault"), "rate": trials[0].get("rate"), "cmd": trials[0].get("cmd"),
        "trials": len(trials), "seeds": [t.get("seed") for t in trials],
        "issued": s("issued"), "injected": inj, "injected_ok": s("injected_ok"), "healthy": s("healthy"),
        "healthy_fail": s("healthy_fail"), "healthy_wrong": s("healthy_wrong"),
        "blast_per_fault": (s("healthy_fail") / inj) if inj else 0.0,
        "p50_us": pctl([t["p50_us"] for t in trials if t.get("p50_us") is not None], 0.5),
        "p99_us": max([t["p99_us"] for t in trials if t.get("p99_us") is not None], default=None),
        "recovery_p50_us": pctl(rec, 0.5), "recovery_p99_us": pctl(rec, 0.99),
        "unrecovered": s("unrecovered"), "censored": s("censored"), "recovery_us": rec,
        "restarts": s("restarts"), "watchdog": s("watchdog"), "wall_us": wall,
        "rps": (s("issued") / (wall / 1e6)) if wall else 0.0,
    }


def drive_cell(a, subject, f, rate, n, seed, mutant=None):
    trials = [drive(a.bin, a.guest, a.data, subject, f, rate, n, seed + 1000 * k, a.workdir, a.server_core,
                    a.client_cores, a.conc, mutant) for k in range(max(1, a.trials))]
    return pool(trials), trials


# Timing criteria (G3 recovery p99, G4 loop throughput) are only meaningful on a quiet runner (IMPLEMENTATION_PLAN
# Phase 5: "re-run on a quiet VPS-class runner"). AEGIS_TIMING_GATES=advisory reports them without gating, for
# shared build boxes; correctness criteria (G0, G1 blast, G2 wrong answers, unrecovered requests) stay gated.
# Never applied to --self-test (its no-deadline mutants are caught through timing). Default: gated.
TIMING_ADVISORY = False


def cell_fails(path, f, d, base):
    """Gate failures of one fault cell (G1-G4)."""
    gated = GATED + (HOST if path == "forkwasm" else [])
    if f not in gated:
        return []  # reported only
    fails = []
    if "error" in d:
        return ["%s: driver error %s" % (f, d["error"])]
    if d.get("healthy_wrong", 0) != 0:
        fails.append("G2 %s wrong_answers=%d" % (f, d["healthy_wrong"]))
    if d.get("injected", 0) == 0:
        return fails + ["%s: no fault injected" % f]
    if d["blast_per_fault"] > 0.05:
        fails.append("G1 %s blast=%.3f>0.05" % (f, d["blast_per_fault"]))
    rp = d.get("recovery_p99_us")
    if d.get("unrecovered", 0) > 0 or rp is None:
        fails.append("G3 %s recovery_p99=%sus unrecovered=%s" % (f, rp, d.get("unrecovered")))
    elif rp > 5000 and not TIMING_ADVISORY:
        fails.append("G3 %s recovery_p99=%sus unrecovered=%s" % (f, rp, d.get("unrecovered")))
    if f == "loop" and base.get("rps") and not TIMING_ADVISORY:
        ratio = d["rps"] / base["rps"]
        if ratio < 0.5:
            fails.append("G4 loop throughput x%.3f<0.5" % ratio)
    return fails


def evaluate(path, cells):
    """cells: {fault: summary}. Returns list of failure strings (empty = pass)."""
    base = cells.get("none", {})
    if "error" in base:
        return ["baseline error: %s" % base["error"]]
    fails = []
    if base.get("healthy_fail", 1) != 0 or base.get("healthy_wrong", 1) != 0:
        fails.append("G0 baseline healthy_fail=%s wrong=%s" % (base.get("healthy_fail"), base.get("healthy_wrong")))
    for f, d in cells.items():
        if f != "none":
            fails += cell_fails(path, f, d, base)
    return fails


def line(path, f, d, base):
    if "error" in d:
        return "  %-9s %-9s ERROR %s" % (path, f, d["error"])
    tp = d["rps"] / base["rps"] if base.get("rps") else float("nan")
    return ("  %-9s %-9s inj=%-3d hfail=%-3d blast=%.3f wrong=%d p50=%sus p99=%sus rec_p99=%sus restarts=%d rps=%d (x%.2f)"
            % (path, f, d["injected"], d["healthy_fail"], d["blast_per_fault"], d["healthy_wrong"], d["p50_us"],
               d["p99_us"], d["recovery_p99_us"], d["restarts"], d["rps"], tp))


def run_path(a, path, subject, faults, n, out, mutant=None):
    cells = {}
    for i, f in enumerate(["none"] + faults):
        rate = 0.0 if f == "none" else a.rate
        cells[f], trials = drive_cell(a, subject, f, rate, n, a.seed + i, mutant)
        if out is not None:
            for t in trials:
                out.write(json.dumps(dict(t, path=path)) + "\n")
    base = cells["none"]
    # Noise defence for the timing gates only (shared laptop): a cell whose only failures are G3/G4 is re-driven
    # once and the better attempt is kept. Count gates (G0-G2: blast, wrong answers) are never retried.
    for i, f in enumerate(faults):
        fl = cell_fails(path, f, cells[f], base)
        if fl and all(x.startswith(("G3", "G4")) for x in fl):
            d2, trials = drive_cell(a, subject, f, a.rate, n, a.seed + 100 + i, mutant)
            d2["retried"] = True
            if len(cell_fails(path, f, d2, base)) < len(fl):
                cells[f] = d2
            if out is not None:
                for t in trials:
                    out.write(json.dumps(dict(t, path=path, retried=True)) + "\n")
    for f, d in cells.items():
        print(line(path, f, d, base) + ("  (retried)" if d.get("retried") else ""), flush=True)
    return cells


# ------------------------------------------------------------------------------------------- record / reference
RECORD_FORMAT = "isolation-fi-record/1"
# Timing metrics compared against a reference runner (PLAN D10). Count metrics (G0-G2) are never ratioed: they are
# judged at fixed thresholds on every runner.
TIMING_METRICS = ["p50_us", "p99_us", "recovery_p50_us", "recovery_p99_us", "rps", "rps_vs_baseline"]
FLAG_RATIO = 2.0


def cell_metrics(d, base):
    if "error" in d:
        return {"error": d["error"]}
    keep = ["trials", "issued", "injected", "healthy", "healthy_fail", "healthy_wrong", "blast_per_fault", "p50_us",
            "p99_us", "recovery_p50_us", "recovery_p99_us", "unrecovered", "censored", "restarts", "rps"]
    m = {k: d.get(k) for k in keep}
    m["rps_vs_baseline"] = (d["rps"] / base["rps"]) if base.get("rps") and d.get("rps") is not None else None
    return m


def host_facts():
    la = ""
    try:
        with open("/proc/loadavg") as f:
            la = f.read().strip()
    except OSError:
        pass
    return {"kernel": platform.release(), "machine": platform.machine(), "nproc": os.cpu_count(), "loadavg": la}


def write_record(a, results):
    """results: {path: (subject, cells, fails)}. Merges by path into an existing record of the same format, so both
    paths can be recorded into one reference file."""
    rec = {"format": RECORD_FORMAT, "paths": {}}
    try:
        with open(a.record) as f:
            old = json.load(f)
        if isinstance(old, dict) and old.get("format") == RECORD_FORMAT and isinstance(old.get("paths"), dict):
            rec["paths"] = old["paths"]
    except (OSError, ValueError):
        pass
    for path, (subject, cells, fails) in results.items():
        base = cells.get("none", {})
        rec["paths"][path] = {
            "recorded_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "host": host_facts(),
            "subject": subject, "trials": a.trials, "n": a.n, "rate": a.rate, "conc": a.conc,
            "server_core": a.server_core, "client_cores": a.client_cores, "timing": a.timing,
            "verdict": "PASS" if not fails else "FAIL", "failures": fails,
            "cells": {f: cell_metrics(d, base) for f, d in cells.items()},
        }
    os.makedirs(os.path.dirname(os.path.abspath(a.record)), exist_ok=True)
    tmp = a.record + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rec, f, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(tmp, a.record)


def load_reference(paths):
    """Merged {path: {fault: metrics}} from one or more record files. Any problem is reported, never fatal."""
    ref, notes = {}, []
    for p in paths:
        try:
            with open(p) as f:
                r = json.load(f)
        except (OSError, ValueError) as e:
            notes.append("reference %s unreadable (%s)" % (p, e))
            continue
        if not isinstance(r, dict) or r.get("format") != RECORD_FORMAT or not isinstance(r.get("paths"), dict):
            notes.append("reference %s is not %s" % (p, RECORD_FORMAT))
            continue
        for path, v in r["paths"].items():
            if isinstance(v, dict) and isinstance(v.get("cells"), dict):
                ref[path] = v["cells"]
    return ref, notes


def ratio_report(cur_cells, ref_cells):
    """[(fault, metric, current, reference, ratio, flagged)] for every timing metric present on both sides.
    ratio = current / reference; flagged when the shift exceeds FLAG_RATIO in either direction."""
    rows = []
    for f, rm in sorted(ref_cells.items()):
        cm = cur_cells.get(f)
        if not isinstance(cm, dict) or not isinstance(rm, dict):
            continue
        for k in TIMING_METRICS:
            c, r = cm.get(k), rm.get(k)
            if isinstance(c, bool) or isinstance(r, bool):
                continue
            if not isinstance(c, (int, float)) or not isinstance(r, (int, float)) or c <= 0 or r <= 0:
                continue
            ratio = c / r
            rows.append((f, k, c, r, ratio, max(ratio, 1 / ratio) > FLAG_RATIO))
    return rows


def print_reference(a, results):
    ref, notes = load_reference(a.reference)
    for n_ in notes:
        print("  reference: %s" % n_)
    flagged = []
    for path, (_subject, cells, _fails) in results.items():
        base = cells.get("none", {})
        cur = {f: cell_metrics(d, base) for f, d in cells.items()}
        if path not in ref:
            print("  reference: no %s cells in the reference file(s); nothing compared" % path)
            continue
        rows = ratio_report(cur, ref[path])
        print("  reference %s: this runner / reference, %d timing metrics (flag >%.0fx either way; report only)"
              % (path, len(rows), FLAG_RATIO))
        for f, k, c, r, ratio, fl in rows:
            print("    %-9s %-10s %-16s %12.1f / %12.1f = x%.2f%s" % (path, f, k, c, r, ratio, "  FLAG >2x" if fl else ""))
            if fl:
                flagged.append("%s/%s/%s x%.2f" % (path, f, k, ratio))
    print("  reference: %d flagged >2x%s (thresholds unchanged; a per-runner threshold needs an integrator Decision, "
          "PLAN D10)" % (len(flagged), (": " + ", ".join(flagged)) if flagged else ""))
    return flagged


def reference_selftest():
    """Offline checks of the ratio report and of verdict independence (no subject needed). Returns failures."""
    bad = []
    ref = {"none": {"rps": 1000.0, "p99_us": 1000.0}, "loop": {"recovery_p99_us": 1000.0, "rps_vs_baseline": 0.8}}
    cur = {"none": {"rps": 1000.0 / 2.1, "p99_us": 1900.0},
           "loop": {"recovery_p99_us": 2100.0, "rps_vs_baseline": 0.8 / 1.9}}
    got = {(f, k): fl for f, k, _c, _r, _x, fl in ratio_report(cur, ref)}
    want = {("none", "rps"): True, ("none", "p99_us"): False, ("loop", "recovery_p99_us"): True,
            ("loop", "rps_vs_baseline"): False}
    if got != want:
        bad.append("ratio report: got %s want %s" % (got, want))
    # A red cell set (poison wrong answers, slow recovery) judged before and after loading a mutated reference that
    # mirrors the red values and carries fake loose thresholds: the verdict comes from the cells alone.
    red = {"none": {"injected": 0, "healthy_fail": 0, "healthy_wrong": 0, "rps": 1000.0, "recovery_p99_us": None},
           "poison": {"injected": 30, "healthy_fail": 0, "healthy_wrong": 917, "blast_per_fault": 0.0,
                      "recovery_p99_us": 9000, "unrecovered": 0, "rps": 1000.0}}
    v1 = evaluate("cordon", red)
    mutated = {"format": RECORD_FORMAT, "thresholds": {"wrong": 10**6, "recovery_p99_us": 10**9, "blast": 1e9},
               "paths": {"cordon": {"verdict": "PASS", "failures": [], "cells": json.loads(json.dumps(red))}}}
    with tempfile.TemporaryDirectory() as td:
        rp = os.path.join(td, "ref.json")
        with open(rp, "w") as f:
            json.dump(mutated, f)
        ref2, _ = load_reference([rp])
        v2 = evaluate("cordon", red)
        rows = ratio_report({k: cell_metrics(d, red["none"]) for k, d in red.items()}, ref2.get("cordon", {}))
    if not v1 or v1 != v2:
        bad.append("verdict changed with a mutated reference: %s -> %s" % (v1, v2))
    if any(r[5] for r in rows):
        bad.append("identical cells flagged")
    return bad


def mutant_subject_selftest(a, t0):
    """--self-test --subject S --mutant-subject M --path P: S (the golden build) and M with AEGIS_P2_MUTANT unset
    must pass every self-test cell; M with AEGIS_P2_MUTANT=<m> must be red for each mutant of the path."""
    if a.path not in P2_MUTANTS or not a.subject:
        print("%s SELF-TEST: FAIL (--mutant-subject needs --subject and --path cordon|forkwasm)" % NAME)
        return 1
    path = a.path
    ok = True
    for label, subj in [("subject", a.subject), ("mutants build, AEGIS_P2_MUTANT unset", a.mutant_subject)]:
        cells = run_path(a, path, subj, SELFTEST_CELLS, 1000, None)
        fl = evaluate(path, cells)
        print("  control %s (%s): %s" % (path, label, "PASS" if not fl else "FAIL " + "; ".join(fl)), flush=True)
        ok &= not fl
    caught, missed = [], []
    for m in P2_MUTANTS[path]:
        cells = run_path(a, path, a.mutant_subject, SELFTEST_CELLS, 1000, None, mutant=m)
        fl = evaluate(path, cells)
        # A mutant that cannot even serve the no-fault baseline is broken, not caught.
        real = [x for x in fl if not x.startswith("baseline error")]
        (caught if real else missed).append(m)
        print("  mutant AEGIS_P2_MUTANT=%-14s %s" % (m, ("CAUGHT: " + "; ".join(real)) if real else
                                                    ("MISSED" + (" (" + "; ".join(fl) + ")" if fl else ""))), flush=True)
    if ok and not missed:
        print("%s SELF-TEST: PASS (%s real subject: %d/%d mutants caught (%s); subject and unmutated mutants build "
              "pass; %.0fs)" % (NAME, path, len(caught), len(P2_MUTANTS[path]), ", ".join(caught), time.time() - t0))
        return 0
    why = ("missed: " + ", ".join(missed)) if missed else "a control failed (oracle would be red on a correct subject)"
    print("%s SELF-TEST: FAIL (%s)" % (NAME, why))
    return 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True)
    ap.add_argument("--guest", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--subject", help="server command template ({guest} {data} substituted; listening socket on fd 3)")
    ap.add_argument("--path", default="both", choices=["cordon", "forkwasm", "both"])
    ap.add_argument("--n", type=int, default=3000)
    ap.add_argument("--rate", type=float, default=0.01)
    ap.add_argument("--conc", type=int, default=16)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--server-core", default="2")
    ap.add_argument("--client-cores", default="4,5,6,7")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--timing", choices=["gate", "advisory"], default=os.environ.get("AEGIS_TIMING_GATES", "gate"))
    ap.add_argument("--trials", type=int, default=1, help="driver runs pooled per cell (PLAN D14: 3 at GO)")
    ap.add_argument("--record", help="write per-cell metrics to this JSON file (merged by path)")
    ap.add_argument("--reference", action="append", default=[],
                    help="record file(s) of the reference runner: print ratios, flag >2x (never changes the verdict)")
    ap.add_argument("--mutant-subject", help="with --self-test --subject --path: the subject's mutants build")
    a = ap.parse_args()
    if a.trials < 1:
        ap.error("--trials must be >= 1")
    global TIMING_ADVISORY
    TIMING_ADVISORY = (a.timing == "advisory") and not a.self_test
    os.makedirs(a.workdir, exist_ok=True)
    t0 = time.time()
    faults = GATED + HOST
    if a.self_test and a.mutant_subject:
        return mutant_subject_selftest(a, t0)
    if a.self_test and a.subject:
        print("%s SELF-TEST: FAIL (--self-test --subject needs --mutant-subject)" % NAME)
        return 1
    if a.self_test:
        caught, missed = [], []
        rbad = reference_selftest()
        print("reference/record checks (2.1x flagged, 1.9x not, verdict independent of a mutated reference): %s"
              % ("PASS" if not rbad else "FAIL " + "; ".join(rbad)), flush=True)
        print("control: unmutated reference subjects on the self-test cells")
        ctrl_ok = True
        for path in ["cordon", "forkwasm"]:
            cells = run_path(a, path, REF[path], SELFTEST_CELLS, 1000, None)
            fl = evaluate(path, cells)
            print("  control %s: %s" % (path, "PASS" if not fl else "FAIL " + "; ".join(fl)))
            ctrl_ok &= not fl
        for label, path, subj, fs in MUTATIONS:
            cells = run_path(a, path, subj, fs, 1000, None)
            fl = evaluate(path, cells)
            (caught if fl else missed).append(label)
            print("  mutation %-52s %s" % (label, "CAUGHT: " + "; ".join(fl) if fl else "MISSED"))
        if ctrl_ok and not missed and not rbad:
            print("%s SELF-TEST: PASS (%d/%d mutations caught; unmutated control passes; reference checks pass; %.0fs)"
                  % (NAME, len(caught), len(MUTATIONS), time.time() - t0))
            return 0
        why = ("missed: " + ", ".join(missed)) if missed else (
            "reference checks failed" if rbad else "unmutated control failed (oracle would be red on a correct subject)")
        print("%s SELF-TEST: FAIL (%s)" % (NAME, why))
        return 1
    subjects = []
    if a.subject:
        subjects = [(a.path if a.path != "both" else "cordon", a.subject)]
    else:
        subjects = [(p, REF[p]) for p in (["cordon", "forkwasm"] if a.path == "both" else [a.path])]
    allfails, results = [], {}
    with open(os.path.join(a.workdir, "results.jsonl"), "a") as out:
        for path, subj in subjects:
            cells = run_path(a, path, subj, faults, a.n, out)
            fl = evaluate(path, cells)
            print("  %s: %s" % (path, "PASS" if not fl else "FAIL " + "; ".join(fl)), flush=True)
            allfails += ["%s: %s" % (path, x) for x in fl]
            results[path] = (subj, cells, fl)
    # The verdict (allfails) is fixed above. Recording and the reference comparison only report.
    if a.record:
        write_record(a, results)
        print("  record: %s (%s)" % (a.record, ", ".join(results)))
    if a.reference:
        print_reference(a, results)
    if allfails:
        print("%s: FAIL (%s)" % (NAME, "; ".join(allfails)))
        return 1
    mode = "; timing ADVISORY (not judged: shared runner)" if TIMING_ADVISORY else ""
    print("%s: PASS (%s; %d fault classes at %.0f%%; %d trial(s) per cell; %.0fs%s)"
          % (NAME, ", ".join(p for p, _ in subjects), len(faults), a.rate * 100, a.trials, time.time() - t0, mode))
    return 0


if __name__ == "__main__":
    sys.exit(main())
