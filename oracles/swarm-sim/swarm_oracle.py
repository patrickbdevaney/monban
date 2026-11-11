"""SWARM-SIM oracle (ADVISORY, record_only, every number grade D): runs the ported round-3 swarm simulator over the
C1..C12 acceptance panel, checks that the simulation is deterministic (same seed => same output hash, across two
fresh interpreter processes), and prints the acceptance table. Invoke through ./run (python3 -I -B, stdlib only).

PASS means only: the simulation completed and is deterministic. The acceptance table is recorded, never gated,
until q3-005 (v2 on held-out traffic traces) calibrates it. See README.md.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
NAME = "SWARM-SIM"


def _load(modname, fname):
    sp = importlib.util.spec_from_file_location(modname, os.path.join(HERE, fname))
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


SIM = _load("monban_swarm_sim", "swarm_sim.py")
SCENARIOS = tuple(SIM.SCEN)          # baseline, swarm_naive_1k, ..., mixed (research order)
DUR = SIM.P0["T"] - SIM.P0["warm"]   # 100 s measured window
CAPACITY_UNITS_S = 3333              # 1 vCPU / 30 ms * 100 units (research C4 derivation)
C4_LIMIT = 667                       # 20% of capacity


# ------------------------------------------------------------------------------------------------ worker (emit)

def emit(configs, seeds, scenarios, mutate):
    out = {}
    for cname in configs:
        base = SIM.CONFIGS[cname]
        out[cname] = {}
        for scn in scenarios:
            rs = []
            for sd in seeds:
                o = dict(base)
                o["seed"] = sd
                rs.append(SIM.run(o, mutate=mutate, name=scn, **SIM.SCEN[scn]))
            out[cname][scn] = rs
    return out


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def spawn_workers(configs, seeds, scenarios, mutate=None, n=2, timeout=1500):
    """Run the same panel in n fresh interpreter processes concurrently; return [(rc, stdout, stderr)]."""
    argv = [sys.executable, "-I", "-B", os.path.join(HERE, "swarm_oracle.py"), "--emit",
            "--configs", ",".join(configs), "--seeds", ",".join(map(str, seeds)), "--scenarios", ",".join(scenarios)]
    if mutate:
        argv += ["--mutate", mutate]
    procs = [subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(n)]
    res = []
    for p in procs:
        try:
            so, se = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            so, se = p.communicate()
            res.append((124, so, se))
            continue
        res.append((p.returncode, so, se))
    return res


def determinism(results):
    """-> (ok, [sha256...], reason)"""
    hs = []
    for rc, so, se in results:
        if rc != 0:
            return False, hs, "worker exited %d: %s" % (rc, se.strip()[-300:])
        hs.append(hashlib.sha256(so.encode()).hexdigest())
    if len(set(hs)) != 1:
        return False, hs, "same seeds gave different output hashes"
    return True, hs, ""


# ------------------------------------------------------------------------------------------------ acceptance

def _fp(r):
    return min(1.0, r["human"]["fp_rate"])


def _sub_fp(r, tag):
    return min(1.0, r.get(tag, {}).get("fp_rate", 0))


def _exp_units(scn, r):
    """attacker-admitted *expensive* (cost >= 20) units/s; cheap floods contribute 0."""
    sc = SIM.scenario(scn, **SIM.SCEN[scn])
    u = 0.0
    if "swarm" in r and sc["swarm_cost"] >= 20:
        u += r["swarm"]["admitted_units_s"]
    if "heavy" in r and sc["heavy_cost"] >= 20:
        u += r["heavy"]["admitted_units_s"]
    return u


def _all_units(r):
    return r.get("swarm", {}).get("admitted_units_s", 0) + r.get("heavy", {}).get("admitted_units_s", 0)


def panel_stats(panel):
    """research panel.py statistics per scenario (worst seed + means), for reproduction comparison."""
    st = {}
    for scn, rs in panel.items():
        p99 = [r["human_srv_p99_ms"] for r in rs if r["human_srv_p99_ms"] is not None]
        st[scn] = dict(
            h_fp=round(sum(_fp(r) for r in rs) / len(rs), 4),
            fp_max=max(_fp(r) for r in rs), p99_max=max(p99) if p99 else None,
            h_srv_p99=round(sum(p99) / len(p99), 4) if p99 else None,
            ver_min=min(r["verified"]["ok_rate"] for r in rs),
            units_s_max=max(_all_units(r) for r in rs),
            exp_units_s_max=max(_exp_units(scn, r) for r in rs),
            nat_fp_max=max(_sub_fp(r, "hnat") for r in rs), acc_fp_max=max(_sub_fp(r, "hacc") for r in rs),
            cpu_max=max(r["cpu_ovh_util_last"] for r in rs),
            hv_ok_exp_s_max=max(r.get("heavy", {}).get("ok_exp", 0) / DUR for r in rs),
            sw_solved=sum(r.get("swarm", {}).get("solved", 0) for r in rs),
            h_solved=sum(r["human"].get("solved", 0) for r in rs),
            usd_per_ok_exp=[r["swarm"]["usd_per_ok_exp"] for r in rs if "swarm" in r],
        )
    return st


def acceptance(st):
    """C1..C12 rows: (id, criterion, measured, verdict). Thresholds from r3e07-L5-swarm-acceptance-criteria."""
    rows = []
    have = set(st)
    attack = [s for s in st if s != "baseline"]

    def worst(key, scns, fn=max):
        vals = [(st[s][key], s) for s in scns if st[s][key] is not None]
        return fn(vals) if vals else (None, None)

    def failing(key, scns, lim, ge=False):
        return [s for s in scns if st[s][key] is not None and ((st[s][key] < lim) if ge else (st[s][key] > lim))]

    v = lambda ok: "PASS" if ok else "FAIL"
    scns = sorted(have, key=SCENARIOS.index)
    f = failing("fp_max", scns, 0.02)
    w = worst("fp_max", scns)
    rows.append(("C1", "human failure <= 2% (worst seed, every scenario)",
                 "max %.2f%% (%s)%s" % (100 * w[0], w[1], "; fails: " + ",".join(f) if f else ""), v(not f)))
    if "baseline" in have:
        unl = st["baseline"]["h_srv_p99"]
        f = failing("p99_max", scns, 3 * unl)
        w = worst("p99_max", scns)
        rows.append(("C2", "human server p99 <= 3x unloaded (%.1f ms -> %.0f ms)" % (unl, 3 * unl),
                     "max %.1f ms (%s)%s" % (w[0], w[1], "; fails: " + ",".join(f) if f else ""), v(not f)))
    else:
        rows.append(("C2", "human server p99 <= 3x unloaded", "baseline not in panel", "n/a"))
    f = failing("ver_min", scns, 0.99, ge=True)
    w = worst("ver_min", scns, min)
    rows.append(("C3", "verified agents >= 99% admitted", "min %.2f%% (%s)%s" %
                 (100 * w[0], w[1], "; fails: " + ",".join(f) if f else ""), v(not f)))
    f = failing("exp_units_s_max", attack, C4_LIMIT)
    w = worst("exp_units_s_max", attack) if attack else (None, None)
    rows.append(("C4", "attacker expensive units/s <= %d (20%% of %d)" % (C4_LIMIT, CAPACITY_UNITS_S),
                 ("max %.0f (%s)%s" % (w[0], w[1], "; fails: " + ",".join(f) if f else "")) if attack else "no attack",
                 v(not f) if attack else "n/a"))
    f = [s for s in attack if st[s]["nat_fp_max"] > 0.05 or st[s]["acc_fp_max"] > 0.05]
    w1, w2 = worst("nat_fp_max", attack), worst("acc_fp_max", attack)
    rows.append(("C5", "CG-NAT and no-JS human FP <= 5% under load",
                 ("NAT max %.1f%% (%s), no-JS max %.1f%% (%s)%s" % (100 * w1[0], w1[1], 100 * w2[0], w2[1],
                                                                   "; fails: " + ",".join(f) if f else ""))
                 if attack else "no attack", v(not f) if attack else "n/a"))

    def one(cid, text, scn, fn):
        if scn not in have:
            rows.append((cid, text, "%s not in panel" % scn, "n/a"))
        else:
            m, ok = fn(st[scn])
            rows.append((cid, text, m, v(ok)))
    one("C6", "cheap flood: human FP <= 2%", "cheap_flood",
        lambda s: ("FP max %.2f%%, p99 max %.0f ms" % (100 * s["fp_max"], s["p99_max"]), s["fp_max"] <= 0.02))
    one("C7", "aged-cookie swarm: FP <= 5% and units <= 667", "aged_swarm",
        lambda s: ("FP max %.2f%%, units max %.0f" % (100 * s["fp_max"], s["exp_units_s_max"]),
                   s["fp_max"] <= 0.05 and s["exp_units_s_max"] <= C4_LIMIT))
    one("C8", "heavy hitter 300 rps: FP <= 1% and <= 1 ok_exp/s", "heavy_only",
        lambda s: ("FP max %.2f%%, %.2f ok_exp/s" % (100 * s["fp_max"], s["hv_ok_exp_s_max"]),
                   s["fp_max"] <= 0.01 and s["hv_ok_exp_s_max"] <= 1.0))
    one("C9", "baseline humans only: FP <= 1%", "baseline",
        lambda s: ("FP max %.2f%%" % (100 * s["fp_max"]), s["fp_max"] <= 0.01))
    w = worst("cpu_max", scns)
    f = failing("cpu_max", scns, 0.85)
    rows.append(("C10", "accept-window overhead utilisation <= 85% (last window)",
                 "max %.2f (%s)%s" % (w[0], w[1], "; fails: " + ",".join(f) if f else ""), v(not f)))
    rows.append(("C11", "no-fail-open + key-churn memory bound", "not simulated; gated by oracles/admission-props "
                 "(I7, I4)", "n/a"))
    if "swarm_solver_1k" in have:
        s = st["swarm_solver_1k"]
        tot = s["sw_solved"] + s["h_solved"]
        share = s["sw_solved"] / tot if tot else 0.0
        rows.append(("C12", "PoW-solved share (solver swarm); >50% => PoW layer ineffective",
                     "attacker %.1f%% of solved challenges" % (100 * share),
                     "RECORD: PoW ineffective (CONFIRMED)" if share > 0.5 else "RECORD: PoW effective"))
    else:
        rows.append(("C12", "PoW-solved share", "swarm_solver_1k not in panel", "n/a"))
    return rows


def reproduce(cname, st, seeds):
    """compare against the research panel (seeds 1..10 only). -> (n_compared, [mismatch strings])"""
    if list(seeds) != list(range(1, 11)):
        return 0, []
    ref = json.load(open(os.path.join(HERE, "research_panel.json")))["panels"].get(cname)
    if not ref:
        return 0, []
    n, bad = 0, []
    for scn, r in ref.items():
        if scn not in st:
            continue
        for k in ("h_fp", "fp_max", "p99_max", "ver_min", "units_s_max", "nat_fp_max", "acc_fp_max"):
            n += 1
            a, b = st[scn][k], r[k]
            if a is None or b is None:
                if a != b:
                    bad.append("%s/%s %s: ours %s research %s" % (cname, scn, k, a, b))
            elif abs(a - b) > 1e-6 * max(1.0, abs(b)):
                bad.append("%s/%s %s: ours %s research %s" % (cname, scn, k, a, b))
    return n, bad


def cost_lines():
    cm = _load("monban_cost_model", "cost_model.py").out
    s = cm["saturate_one_vcpu"]
    out = ["cost model (prices 2026-10-25 snapshot; stage costs B/C/D/E per row; D overall):"]
    for k, r in s.items():
        out.append("  %-60s %8.1f rps saturates 1 vCPU; attacker $%.2f/h at $4/GB" %
                   (k[:60], r["rps_to_saturate_one_vcpu"], r["attacker_usd_per_hour_mid_payg"]))
    return out, hashlib.sha256(canon(cm).encode()).hexdigest()


def print_table(cname, rows):
    print("acceptance C1..C12 [%s] -- every number grade D (uncalibrated, fitted in-sample); record_only" % cname)
    for cid, crit, meas, verd in rows:
        print("  %-4s %-56s %-9s %s" % (cid, crit[:56], verd if len(verd) <= 9 else "RECORD", meas))
        if len(verd) > 9:
            print("  %-4s %-56s %s" % ("", "", verd))


# ------------------------------------------------------------------------------------------------ modes

def mode_run(a):
    configs = a.configs.split(",")
    seeds = [int(x) for x in a.seeds.split(",")] if "," in a.seeds else list(range(1, int(a.seeds) + 1))
    scns = a.scenarios.split(",") if a.scenarios else list(SCENARIOS)
    print("swarm-sim: configs=%s seeds=%s scenarios=%d (two fresh interpreters, concurrent)" %
          (",".join(configs), "%d..%d" % (seeds[0], seeds[-1]) if len(seeds) > 1 else seeds[0], len(scns)))
    res = spawn_workers(configs, seeds, scns, mutate=a.mutate)
    ok, hs, why = determinism(res)
    for i, h in enumerate(hs):
        print("  run %d output sha256 %s" % (i + 1, h))
    if not ok:
        print("%s: FAIL (nondeterministic or crashed: %s)" % (NAME, why))
        return 1
    data = json.loads(res[0][1])
    tot_n, tot_bad = 0, []
    for cname in configs:
        st = panel_stats(data[cname])
        print_table(cname, acceptance(st))
        n, bad = reproduce(cname, st, seeds)
        tot_n += n
        tot_bad += bad
        npass = sum(1 for r in acceptance(st) if r[3] == "PASS")
        nfail = sum(1 for r in acceptance(st) if r[3] == "FAIL")
        print("  [%s] acceptance: %d PASS, %d FAIL of C1..C10 (advisory)" % (cname, npass, nfail))
    if tot_n:
        print("reproduction vs research panels (seeds 1..10): %d/%d statistics identical%s" %
              (tot_n - len(tot_bad), tot_n, "" if not tot_bad else "; differ: " + "; ".join(tot_bad[:6])))
    cl, ch = cost_lines()
    print("\n".join(cl))
    print("deterministic: yes (2 processes, sha256 %s; cost model sha256 %s)" % (hs[0][:16], ch[:16]))
    print("%s: PASS (advisory: record_only)" % NAME)
    return 0


def mode_self_test(a):
    ok = True
    small_scn, small_seeds = ["baseline", "mixed"], [1, 2]
    d, hs, why = determinism(spawn_workers(["TUNED"], small_seeds, small_scn))
    print("  control (no mutation): deterministic=%s %s" % (d, why))
    ok &= d
    caught = []
    for m in SIM.MUTATIONS:
        d, hs, why = determinism(spawn_workers(["TUNED"], small_seeds, small_scn, mutate=m))
        print("  mutant %-5s determinism check -> %s (%s)" % (m, "FAIL = CAUGHT" if not d else "pass = MISSED",
                                                             why or "hashes equal"))
        ok &= not d
        if not d:
            caught.append(m)
    # broken defence must obviously fail acceptance; the tuned control on the same panel must not
    seeds = [1, 2, 3]
    good = panel_stats(emit(["TUNED"], seeds, ["mixed"], None)["TUNED"])
    bad = panel_stats(emit(["BROKEN"], seeds, ["mixed"], None)["BROKEN"])
    rg = {r[0]: r for r in acceptance(good)}
    rb = {r[0]: r for r in acceptance(bad)}
    print("  control TUNED  mixed: C1 %s (%s); C4 %s (%s)" % (rg["C1"][3], rg["C1"][2], rg["C4"][3], rg["C4"][2]))
    print("  mutant  BROKEN mixed: C1 %s (%s); C4 %s (%s)" % (rb["C1"][3], rb["C1"][2], rb["C4"][3], rb["C4"][2]))
    broken_caught = rb["C1"][3] == "FAIL" and rg["C1"][3] == "PASS"
    print("  broken defence (no aggregates, no fresh class, no expensive cap): %s" %
          ("CAUGHT by C1" if broken_caught else "MISSED"))
    ok &= broken_caught
    if ok:
        print("%s SELF-TEST: PASS (determinism check caught %s nondeterminism; broken defence fails C1 %s; "
              "control deterministic and tuned passes C1)" % (NAME, "+".join(caught), rb["C1"][2]))
        return 0
    print("%s SELF-TEST: FAIL (see above)" % NAME)
    return 1


def main():
    ap = argparse.ArgumentParser(prog="oracles/swarm-sim/run")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--configs", default="TUNED", help="comma list of %s" % ",".join(SIM.CONFIGS))
    ap.add_argument("--seeds", default="10", help="N (=1..N) or comma list")
    ap.add_argument("--scenarios", default="", help="comma list (default: all 10)")
    ap.add_argument("--mutate", choices=SIM.MUTATIONS, help="inject nondeterminism (debug)")
    ap.add_argument("--subject", help="reserved: the Rust admission pipeline under the sim (not yet available)")
    ap.add_argument("--emit", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.subject:
        print("%s: FAIL (--subject not supported yet: the simulator models the pipeline in Python; plugging the "
              "Rust crates in is q3-005 v2 work, see README.md)" % NAME)
        return 1
    for c in a.configs.split(","):
        if c not in SIM.CONFIGS:
            print("%s: FAIL (unknown config %s)" % (NAME, c))
            return 1
    if a.emit:
        seeds = [int(x) for x in a.seeds.split(",")]
        sys.stdout.write(canon(emit(a.configs.split(","), seeds, a.scenarios.split(","), a.mutate)))
        return 0
    if a.self_test:
        return mode_self_test(a)
    return mode_run(a)


if __name__ == "__main__":
    sys.exit(main())
