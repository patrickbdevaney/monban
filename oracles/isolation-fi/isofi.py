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
"""
import argparse, json, os, subprocess, sys, time

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
]


def drive(bin_, guest, data, subject, fault, rate, n, seed, workdir, core, clients, conc):
    pre = os.path.join(workdir, "%s-%s-%s" % (abs(hash(subject)) % 10**8, fault, rate))
    cmd = [bin_, "drive", "--server", subject.replace("{bin}", bin_), "--guest", guest, "--data", data,
           "--fault", fault, "--rate", str(rate), "--n", str(n), "--conc", str(conc), "--seed", str(seed),
           "--prefix", pre, "--server-core", core, "--client-cores", clients, "--max-seconds", "90",
           "--sockdir", workdir]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=200)
        line = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""
        d = json.loads(line) if line else {"error": p.stderr[-300:]}
    except subprocess.TimeoutExpired:
        d = {"error": "driver timeout"}
    except json.JSONDecodeError:
        d = {"error": "bad driver output"}
    d.setdefault("fault", fault)
    return d


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


def run_path(a, path, subject, faults, n, out):
    cells = {}
    for i, f in enumerate(["none"] + faults):
        rate = 0.0 if f == "none" else a.rate
        cells[f] = drive(a.bin, a.guest, a.data, subject, f, rate, n, a.seed + i, a.workdir, a.server_core,
                         a.client_cores, a.conc)
        if out is not None:
            out.write(json.dumps(dict(cells[f], path=path)) + "\n")
    base = cells["none"]
    # Noise defence for the timing gates only (shared laptop): a cell whose only failures are G3/G4 is re-driven
    # once and the better attempt is kept. Count gates (G0-G2: blast, wrong answers) are never retried.
    for i, f in enumerate(faults):
        fl = cell_fails(path, f, cells[f], base)
        if fl and all(x.startswith(("G3", "G4")) for x in fl):
            d2 = drive(a.bin, a.guest, a.data, subject, f, a.rate, n, a.seed + 100 + i, a.workdir, a.server_core,
                       a.client_cores, a.conc)
            d2["retried"] = True
            if len(cell_fails(path, f, d2, base)) < len(fl):
                cells[f] = d2
            if out is not None:
                out.write(json.dumps(dict(d2, path=path)) + "\n")
    for f, d in cells.items():
        print(line(path, f, d, base) + ("  (retried)" if d.get("retried") else ""), flush=True)
    return cells


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
    a = ap.parse_args()
    global TIMING_ADVISORY
    TIMING_ADVISORY = (a.timing == "advisory") and not a.self_test
    os.makedirs(a.workdir, exist_ok=True)
    t0 = time.time()
    faults = GATED + HOST
    if a.self_test:
        caught, missed = [], []
        print("control: unmutated reference subjects on the self-test cells")
        ctrl_ok = True
        for path in ["cordon", "forkwasm"]:
            cells = run_path(a, path, REF[path], ["poison", "loop"] + HOST, 1000, None)
            fl = evaluate(path, cells)
            print("  control %s: %s" % (path, "PASS" if not fl else "FAIL " + "; ".join(fl)))
            ctrl_ok &= not fl
        for label, path, subj, fs in MUTATIONS:
            cells = run_path(a, path, subj, fs, 1000, None)
            fl = evaluate(path, cells)
            (caught if fl else missed).append(label)
            print("  mutation %-52s %s" % (label, "CAUGHT: " + "; ".join(fl) if fl else "MISSED"))
        if ctrl_ok and not missed:
            print("%s SELF-TEST: PASS (%d/%d mutations caught; unmutated control passes; %.0fs)"
                  % (NAME, len(caught), len(MUTATIONS), time.time() - t0))
            return 0
        why = ("missed: " + ", ".join(missed)) if missed else "unmutated control failed (oracle would be red on a correct subject)"
        print("%s SELF-TEST: FAIL (%s)" % (NAME, why))
        return 1
    subjects = []
    if a.subject:
        subjects = [(a.path if a.path != "both" else "cordon", a.subject)]
    else:
        subjects = [(p, REF[p]) for p in (["cordon", "forkwasm"] if a.path == "both" else [a.path])]
    allfails = []
    with open(os.path.join(a.workdir, "results.jsonl"), "a") as out:
        for path, subj in subjects:
            cells = run_path(a, path, subj, faults, a.n, out)
            fl = evaluate(path, cells)
            print("  %s: %s" % (path, "PASS" if not fl else "FAIL " + "; ".join(fl)), flush=True)
            allfails += ["%s: %s" % (path, x) for x in fl]
    if allfails:
        print("%s: FAIL (%s)" % (NAME, "; ".join(allfails)))
        return 1
    mode = "; timing ADVISORY (not judged: shared runner)" if TIMING_ADVISORY else ""
    print("%s: PASS (%s; %d fault classes at %.0f%%; %.0fs%s)" % (NAME, ", ".join(p for p, _ in subjects), len(faults),
                                                              a.rate * 100, time.time() - t0, mode))
    return 0


if __name__ == "__main__":
    sys.exit(main())
