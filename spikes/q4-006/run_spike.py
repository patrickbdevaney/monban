#!/usr/bin/env python3
"""q4-006 measurement runner (stdlib; python3 -I). Run under ci/heavy.sh via ./measure.sh.

usage: run_spike.py <bin> <guest> <data> <outdir> <phase: loop|fi|forkcost|lan> [trials] [server_core] [client_cores]
Each driver cell is one `isofi drive` (closed loop, conc 16) against one isofi server pinned to server_core.
"""
import json, os, random, subprocess, sys, time

bin_, guest, data, out, phase = sys.argv[1:6]
trials = int(sys.argv[6]) if len(sys.argv) > 6 else 3
core = sys.argv[7] if len(sys.argv) > 7 else "2"
clients = sys.argv[8] if len(sys.argv) > 8 else "4,5,6,7"
os.makedirs(out, exist_ok=True)
logs = os.path.join(out, "logs")
os.makedirs(logs, exist_ok=True)
work = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".work")  # sockets + cwasm cache (deleted)
os.makedirs(work, exist_ok=True)
N = 3000

cal = json.load(open(os.path.join(out, "calibrate.json"))) if os.path.exists(os.path.join(out, "calibrate.json")) else None
FPM = cal["loop_fuel_per_ms"] if cal else 3_000_000
F2, F10 = 15_000_000, 75_000_000  # ~2 ms and ~10 ms of guest work on the laptop (calibrate.json: ~7.4M fuel/ms)
S = bin_ + " serve "
V = {
    "E4": S + "cordon --guest {guest} --data {data} --threads 4 --budget epoch --epoch-ms 100",
    "E64": S + "cordon --guest {guest} --data {data} --threads 64 --budget epoch --epoch-ms 100",
    "F4-2": S + "cordon --guest {guest} --data {data} --threads 4 --budget fuel:%d --epoch-ms 100" % F2,
    "F64-10": S + "cordon --guest {guest} --data {data} --threads 64 --budget fuel:%d --epoch-ms 100" % F10,
    "F64-2": S + "cordon --guest {guest} --data {data} --threads 64 --budget fuel:%d --epoch-ms 100" % F2,
    "FW-E": S + "forkwasm --guest {guest} --data {data} --budget epoch --epoch-ms 100",
    "FW-F10": S + "forkwasm --guest {guest} --data {data} --budget fuel:%d --epoch-ms 100" % F10,
    "FW-F2": S + "forkwasm --guest {guest} --data {data} --budget fuel:%d --epoch-ms 100" % F2,
}


def drive(var, fault, rate, trial, i):
    pre = os.path.join(logs, "%s-t%d-%s-%s-%s" % (phase, trial, var, fault, rate))
    cmd = [bin_, "drive", "--server", V[var], "--guest", guest, "--data", data, "--fault", fault, "--rate", str(rate),
           "--n", str(N), "--conc", "16", "--seed", str(trial * 7919 + i), "--prefix", pre, "--server-core", core,
           "--client-cores", clients, "--max-seconds", "120", "--sockdir", work]
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        d = json.loads(p.stdout.strip().splitlines()[-1])
    except Exception as e:  # noqa: BLE001 - recorded, not hidden
        d = {"error": repr(e)[:300]}
    d.update(variant=var, fault=fault, rate=rate, trial=trial, phase=phase, elapsed_s=round(time.time() - t0, 2))
    d.pop("cmd", None)
    try:
        os.remove(pre + ".req.tsv")  # keep the repo small; summaries carry the numbers
    except OSError:
        pass
    return d


def matrix(cells):
    with open(os.path.join(out, "%s.jsonl" % phase), "a") as res:
        for t in range(1, trials + 1):
            cs = list(cells)
            random.Random(1000 + t).shuffle(cs)
            for i, (v, f, r) in enumerate(cs):
                d = drive(v, f, r, t, i)
                res.write(json.dumps(d) + "\n")
                res.flush()
                print(phase, t, v, f, r, "inj", d.get("injected"), "hfail", d.get("healthy_fail"), "wrong",
                      d.get("healthy_wrong"), "p50", d.get("p50_us"), "p99", d.get("p99_us"), "rps", d.get("rps"),
                      "rec99", d.get("recovery_p99_us"), "rst", d.get("restarts"), d.get("error", ""), flush=True)


if phase == "loop":
    vs = ["E4", "E64", "F4-2", "F64-10", "F64-2", "FW-E", "FW-F10", "FW-F2"]
    matrix([(v, "none", 0.0) for v in vs] + [(v, "loop", r) for v in vs for r in (0.01, 0.05)])
elif phase == "fi":
    fs = ["panic", "abort", "segv", "loop", "oom", "poison", "hostabort", "hostpoison"]
    vs = ["F64-2", "FW-F2"]
    matrix([(v, "none", 0.0) for v in vs] + [(v, f, r) for v in vs for f in fs for r in (0.01, 0.05)])
elif phase == "lan":
    vs = ["F64-2", "FW-F2", "E4"]
    matrix([(v, "none", 0.0) for v in vs] + [(v, f, 0.01) for v in vs for f in ("loop", "hostabort", "hostpoison", "abort", "poison")])
elif phase == "forkcost":
    with open(os.path.join(out, "forkcost.jsonl"), "a") as res:
        for t in range(1, trials + 1):
            # zygote_mode: "compiled" = module compiled inside the zygote; "cwasm" = zygote loads the cached
            # precompiled module (the AEGIS design). The first run of each pool mode fills the cache.
            for pool, zmode in (("ondemand", "compiled"), ("ondemand", "cwasm"), ("pool", "compiled"), ("pool", "cwasm")):
                cache = os.path.join(work, "fc-cache-" + pool)
                if zmode == "compiled":
                    subprocess.run(["rm", "-rf", cache])
                os.makedirs(cache, exist_ok=True)
                env = dict(os.environ, ISOFI_CWASM_DIR=cache)
                p = subprocess.run(["taskset", "-c", core, bin_, "forkcost", "--guest", guest, "--n", "3000", "--pool",
                                    pool, "--fuel", str(F2)], capture_output=True, text=True, timeout=600, env=env)
                d = json.loads(p.stdout.strip().splitlines()[-1])
                d.update(trial=t)
                res.write(json.dumps(d) + "\n")
                print(json.dumps(d), flush=True)
