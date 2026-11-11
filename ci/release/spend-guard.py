#!/usr/bin/env python3
"""Real-money tripwire for the Monban GCP project (operator request 2026-11-06: "stop us from spending real cc money").

The billing budget "aegis tripwire: any real-money spend" (USD 1, creditTypesTreatment INCLUDE_ALL_CREDITS) measures
spend net of the trial/promotional credit and publishes its state to Pub/Sub topic `aegis-budget` several times a day.
This script drains subscription `aegis-budget-guard`, keeps the newest state in ~/.cache/aegis-tools/gcp-budget.json,
and trips when the net cost of the current period is above zero. That happens when the credit is used up or has
expired.

  spend-guard.py check     exit 0 if no real-money spend is known, exit 3 if tripped (for vm.sh / scaling before a start)
  spend-guard.py enforce   check, and on a trip stop every RUNNING instance in the project (cron, every 30 min)
  spend-guard.py selftest  the trip logic on synthetic notifications (no gcloud)

Limits, stated: budget evaluation lags actual usage by hours, so a trip can follow some real spend (at Monban rates,
cents to a few dollars). A stopped VM's disk is still billed (cents/day). The guard covers instances only. Billing
emails go to the billing account's admins as well (default IAM recipients).
"""
import base64, json, os, subprocess, sys

PROJECT = "project-333565b3-9b4b-4ae4-b75"
SUB = "aegis-budget-guard"
STATE = os.path.expanduser("~/.cache/aegis-tools/gcp-budget.json")
TRIP_EPS = 0.005  # USD; costAmount is a float, net of credits


def gcloud(*args):
    p = subprocess.run(["gcloud", *args, "--project", PROJECT, "--format=json"], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip().splitlines()[-1] if p.stderr.strip() else f"gcloud exit {p.returncode}")
    return json.loads(p.stdout or "[]")


def newest(state, msgs):
    """Fold notifications into the newest-known state. A notification is {publishTime, data:{costAmount,...}}."""
    for m in msgs:
        if state is None or m["publishTime"] > state["publishTime"]:
            state = m
    return state


def tripped(state):
    return state is not None and float(state["data"].get("costAmount", 0.0)) > TRIP_EPS


def drain():
    msgs = []
    for r in gcloud("pubsub", "subscriptions", "pull", SUB, "--auto-ack", "--limit=100"):
        m = r["message"]
        msgs.append({"publishTime": m["publishTime"], "data": json.loads(base64.b64decode(m["data"]))})
    state = None
    if os.path.exists(STATE):
        state = json.load(open(STATE))
    state = newest(state, msgs)
    if state is not None:
        os.makedirs(os.path.dirname(STATE), exist_ok=True)
        json.dump(state, open(STATE + ".tmp", "w")); os.replace(STATE + ".tmp", STATE)
    return state


def check():
    try:
        state = drain()
    except Exception as e:  # cannot read the budget state: fail closed for starts
        print(f"spend-guard: cannot read budget state ({e}); refusing", file=sys.stderr); return 3, None
    if state is None:
        print("spend-guard: no budget notification received yet (first one can take hours); allowing", file=sys.stderr)
        return 0, None
    d = state["data"]
    if tripped(state):
        print(f"spend-guard: TRIPPED: net cost {d.get('costAmount')} {d.get('currencyCode','USD')} since "
              f"{d.get('costIntervalStart')} (credit exhausted or expired); refusing", file=sys.stderr)
        return 3, state
    print(f"spend-guard: ok, net cost {d.get('costAmount')} as of {state['publishTime']}", file=sys.stderr)
    return 0, state


def enforce():
    rc, _ = check()
    if rc == 0:
        return 0
    stopped = []
    try:
        for i in gcloud("compute", "instances", "list", "--filter=status=RUNNING"):
            zone = i["zone"].rsplit("/", 1)[-1]
            subprocess.run(["gcloud", "compute", "instances", "stop", i["name"], "--zone", zone, "--project", PROJECT,
                            "--quiet"], capture_output=True, text=True)
            stopped.append(i["name"])
    except Exception as e:
        print(f"spend-guard: stopping instances failed: {e}", file=sys.stderr)
    print(f"spend-guard: stopped {stopped or 'nothing (none running)'}", file=sys.stderr)
    return 3


def selftest():
    n = lambda t, c: {"publishTime": t, "data": {"costAmount": c}}
    ok = True
    s = newest(None, [n("2026-11-07T01:00:00Z", 0.0), n("2026-11-07T02:00:00Z", 0.0)])
    ok &= not tripped(s)                                                   # credit covers everything
    s = newest(s, [n("2026-11-08T01:00:00Z", 0.42)])
    ok &= tripped(s)                                                       # MUTANT: net spend must trip
    ok &= tripped(newest(s, [n("2026-11-07T03:00:00Z", 0.0)]))             # an older message must not untrip
    ok &= not tripped(None)                                                # no data yet
    ok &= not tripped(n("t", 0.004))                                       # rounding noise
    print("SPEND-GUARD SELF-TEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    sys.exit({"check": lambda: check()[0], "enforce": enforce, "selftest": selftest}[cmd]())
