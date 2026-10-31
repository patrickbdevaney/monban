#!/usr/bin/env python3
"""syscall-negative oracle driver (Phase-5 p2-syscall-negative). stdlib only, run as `python3 -I`.

For every probe it first runs an unfiltered control (the oracle's own synprobe with --path none), records the host
facts, then runs the subject on each stage (cordon, forkwasm zygote, forkwasm child) and judges the outcome against
the filter's own signature: SIGSYS (SECCOMP_RET_KILL_PROCESS), ENOSYS for clone3, EACCES (Landlock) or SIGSYS for
the Landlock probes. EPERM never passes. See README.md for the probe protocol.
"""
import argparse
import json
import os
import shlex
import signal
import socket
import subprocess
import sys

SIGSYS = 31
ENOSYS, EACCES = 38, 13

# (probe, kind). kinds: allow (must succeed under the sandbox: vacuity), dumpable (PR_GET_DUMPABLE must read 0),
# kill (SIGSYS only), enosys (errno ENOSYS only), landlock (EACCES or SIGSYS).
PROBES = [
    ("noop", "allow"),
    ("open_inside", "allow"),
    ("dumpable", "dumpable"),
    ("clone_newuser", "kill"),
    ("unshare_newuser", "kill"),
    ("unshare_newnet", "kill"),
    ("setns", "kill"),
    ("clone3", "enosys"),
    ("socket_inet", "kill"),
    ("socket_inet6", "kill"),
    ("socket_unix", "kill"),
    ("socket_netlink", "kill"),
    ("socketpair", "kill"),
    ("tcp_ulp", "kill"),
    ("bpf", "kill"),
    ("io_uring_setup", "kill"),
    ("perf_event_open", "kill"),
    ("ptrace", "kill"),
    ("process_vm_readv", "kill"),
    ("userfaultfd", "kill"),
    ("keyctl", "kill"),
    ("mount", "kill"),
    ("execve", "kill"),
    ("fork", "kill"),
    ("open_outside", "landlock"),
    ("connect_tcp", "landlock"),
]
# stage id -> (--path, --stage or None). The zygote must fork, so `fork` is not probed at the zygote stage.
STAGES = [("cordon", "cordon", None), ("forkwasm-child", "forkwasm", None), ("forkwasm-zygote", "forkwasm", "zygote")]
SKIP = {("forkwasm-zygote", "fork")}

# self-test: mutant -> stage:probe cells of which at least one must be among the failures (caught for the right reason)
MUTANTS = {
    "no-clone-flag-filter": ["forkwasm-zygote:clone_newuser", "cordon:unshare_newuser", "forkwasm-child:unshare_newuser"],
    "no-denylist": ["cordon:socket_inet", "forkwasm-child:socket_inet"],
    "eperm-instead-of-kill": ["cordon:bpf", "forkwasm-child:bpf"],
    "clone3-allowed": ["cordon:clone3", "forkwasm-child:clone3"],
    "dumpable-1": ["cordon:dumpable", "forkwasm-zygote:dumpable", "forkwasm-child:dumpable"],
    "no-landlock": ["cordon:open_outside", "forkwasm-child:open_outside"],
    "no-child-filter": ["forkwasm-child:fork"],
}

SYSCTLS = [
    "kernel/apparmor_restrict_unprivileged_userns",
    "kernel/apparmor_restrict_unprivileged_unconfined",
    "kernel/unprivileged_userns_clone",
    "user/max_user_namespaces",
    "kernel/unprivileged_bpf_disabled",
    "kernel/io_uring_disabled",
    "kernel/perf_event_paranoid",
    "vm/unprivileged_userfaultfd",
    "kernel/yama/ptrace_scope",
]


class Env:
    def __init__(self, workdir):
        self.allowed = os.path.join(workdir, "allowed")
        self.outside = os.path.join(workdir, "outside")
        os.makedirs(self.allowed, exist_ok=True)
        os.makedirs(self.outside, exist_ok=True)
        self.inside_file = os.path.join(self.allowed, "module.bin")
        self.outside_file = os.path.join(self.outside, "secret.txt")
        for p in (self.inside_file, self.outside_file):
            with open(p, "w") as f:
                f.write("syscall-negative\n")
        self.lst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lst.bind(("127.0.0.1", 0))
        self.lst.listen(1024)
        self.port = self.lst.getsockname()[1]

    def drain(self):
        # accept and drop queued connections so the backlog never fills
        self.lst.setblocking(False)
        try:
            while True:
                c, _ = self.lst.accept()
                c.close()
        except (BlockingIOError, OSError):
            pass
        self.lst.setblocking(True)


def run_one(argv, probe, env, stage_is_child):
    """Run one probe process. Returns an outcome dict."""
    extra, fds, socks = [], [], []
    if probe == "tcp_ulp":
        s = socket.create_connection(("127.0.0.1", env.port))  # pre-opened, established TCP fd
        socks.append(s)
        fds.append(s.fileno())
        extra = ["--fd", str(s.fileno())]
    elif probe == "connect_tcp":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # pre-opened, unconnected TCP fd
        socks.append(s)
        fds.append(s.fileno())
        extra = ["--fd", str(s.fileno()), "--port", str(env.port)]
    elif probe == "open_inside":
        extra = ["--target", env.inside_file]
    elif probe == "open_outside":
        extra = ["--target", env.outside_file]
    cmd = argv + ["--probe", probe, "--allow-dir", env.allowed] + extra
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=fds, start_new_session=True)
    except OSError as e:
        return {"kind": "error", "why": f"spawn: {e}"}
    try:
        so, se = p.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)  # our own child's process group, by explicit pgid
        except OSError:
            pass
        p.communicate()
        return {"kind": "error", "why": "timeout"}
    finally:
        for s in socks:
            s.close()
        env.drain()
    lines = []
    for ln in so.decode(errors="replace").splitlines():
        try:
            lines.append(json.loads(ln))
        except ValueError:
            pass
    err = se.decode(errors="replace").strip().splitlines()[-1:] or [""]
    armed = [x for x in lines if x.get("event") == "armed" and x.get("probe") == probe]
    results = [x for x in lines if x.get("event") == "result" and x.get("probe") == probe]
    rc = p.returncode
    if stage_is_child:
        ce = [x for x in lines if x.get("event") == "child-exit"]
        if rc != 0 or not ce:
            return {"kind": "error", "why": f"zygote rc={rc}, no child-exit line ({err[0]})"}
        ce = ce[-1]
        if not armed:
            return {"kind": "error", "why": f"child died before the armed line ({err[0]})"}
        if ce.get("signal") is not None:
            return {"kind": "killed", "signal": ce["signal"]}
        if results:
            return {"kind": "returned", "ret": results[-1]["ret"], "errno": results[-1]["errno"]}
        if probe == "execve" and ce.get("code") == 0:
            return {"kind": "execd"}
        return {"kind": "error", "why": f"child exit code={ce.get('code')} without a result line"}
    if rc is not None and rc < 0:
        if not armed:
            return {"kind": "error", "why": f"killed by signal {-rc} before the armed line (sandbox install?)"}
        return {"kind": "killed", "signal": -rc}
    if results:
        return {"kind": "returned", "ret": results[-1]["ret"], "errno": results[-1]["errno"]}
    if probe == "execve" and rc == 0 and armed:
        return {"kind": "execd"}
    return {"kind": "error", "why": f"rc={rc}, armed={bool(armed)}, no result line ({err[0]})"}


def fmt(o):
    k = o["kind"]
    if k == "killed":
        return "SIGSYS" if o["signal"] == SIGSYS else f"signal {o['signal']}"
    if k == "returned":
        return f"ret={o['ret']}" if o["ret"] >= 0 else f"errno={o['errno']}"
    if k == "execd":
        return "exec ok"
    return f"error({o['why']})"


def control_class(o):
    if o["kind"] == "execd" or (o["kind"] == "returned" and o["ret"] >= 0):
        return "permitted", None
    if o["kind"] == "returned":
        return "masked", o["errno"]
    return "broken", None


def judge(kind, ctl, sub):
    """Returns (ok, reason)."""
    cc, cerr = control_class(ctl)
    if cc == "broken":
        return False, "unfiltered control did not run cleanly; cannot judge"
    if kind == "allow":
        if cc != "permitted":
            return False, "control masked: the positive probe is vacuous here"
        return (sub["kind"] == "returned" and sub["ret"] >= 0), "must succeed under the sandbox"
    if kind == "dumpable":
        return (sub["kind"] == "returned" and sub["ret"] == 0), "PR_GET_DUMPABLE must read 0"
    if kind == "kill":
        return (sub["kind"] == "killed" and sub["signal"] == SIGSYS), "only SIGSYS (KILL_PROCESS) passes"
    if kind == "enosys":
        if cerr == ENOSYS:
            return False, "control already ENOSYS: filter signature indistinguishable"
        return (sub["kind"] == "returned" and sub["ret"] < 0 and sub["errno"] == ENOSYS), "only ENOSYS passes"
    if kind == "landlock":
        if sub["kind"] == "killed" and sub["signal"] == SIGSYS:
            return True, ""
        if cerr == EACCES:
            return False, "control already EACCES: only SIGSYS is distinguishable"
        return (sub["kind"] == "returned" and sub["ret"] < 0 and sub["errno"] == EACCES), "only EACCES (Landlock) or SIGSYS passes"
    return False, "unknown kind"


def host_facts(bin_):
    f = {"kernel": os.uname().release}
    for s in SYSCTLS:
        try:
            with open("/proc/sys/" + s) as fh:
                f[s.split("/")[-1]] = fh.read().strip()
        except OSError:
            f[s.split("/")[-1]] = "absent"
    try:
        out = subprocess.run([bin_, "--facts"], capture_output=True, timeout=10).stdout.decode()
        f["landlock_abi"] = json.loads(out.strip().splitlines()[-1])["landlock_abi"]
    except (OSError, ValueError, IndexError, KeyError, subprocess.TimeoutExpired):
        f["landlock_abi"] = "unknown"
    return f


def controls(bin_, env):
    return {p: run_one([bin_, "--path", "none"], p, env, False) for p, _ in PROBES}


def evaluate(subject_argv, ctl, env, quiet=False):
    """Runs every stage x probe. Returns list of failing 'stage:probe' cells and the row list."""
    fails, rows = [], []
    for sid, path, stage in STAGES:
        argv = subject_argv + ["--path", path] + (["--stage", stage] if stage else [])
        for probe, kind in PROBES:
            if (sid, probe) in SKIP:
                continue
            sub = run_one(argv, probe, env, path == "forkwasm" and stage is None)
            ok, why = judge(kind, ctl[probe], sub)
            rows.append((sid, probe, kind, fmt(ctl[probe]), fmt(sub), ok, why))
            if not ok:
                fails.append(f"{sid}:{probe}")
    if not quiet:
        for sid, probe, kind, c, s, ok, why in rows:
            print(f"  {'ok  ' if ok else 'FAIL'} {sid:16} {probe:17} {kind:9} control={c:14} subject={s}"
                  + ("" if ok else f"   [{why}]"))
    return fails, rows


def print_controls(ctl, facts):
    print("host facts: " + json.dumps(facts, sort_keys=True))
    masked = []
    for p, _ in PROBES:
        cc, e = control_class(ctl[p])
        tag = {"permitted": "permitted", "masked": f"masked (errno {e})", "broken": "BROKEN"}[cc]
        if cc == "masked":
            masked.append(p)
        print(f"  control {p:17} {fmt(ctl[p]):14} -> {tag}")
    return masked


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True, help="reference synprobe (also the unfiltered control)")
    ap.add_argument("--subject", default=None, help="subject command; the oracle appends --path ... --probe ...")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--json-out", default=None)
    a = ap.parse_args()
    env = Env(a.workdir)
    facts = host_facts(a.bin)
    ctl = controls(a.bin, env)
    masked = print_controls(ctl, facts)
    broken = [p for p, _ in PROBES if control_class(ctl[p])[0] == "broken"]
    ncells = sum(1 for sid, _, _ in STAGES for p, _ in PROBES if (sid, p) not in SKIP)

    if a.self_test:
        problems = []
        print("self-test: reference (unmutated) must pass")
        f0, _ = evaluate([a.bin], ctl, env)
        if f0:
            problems.append(f"reference failed {len(f0)} cells: {', '.join(f0[:6])}")
        caught = 0
        for m, expect in MUTANTS.items():
            fm, _ = evaluate([a.bin, "--mutant", m], ctl, env, quiet=True)
            hit = [c for c in expect if c in fm]
            if fm and hit:
                caught += 1
                print(f"  mutant {m:22} RED ({len(fm)} failing cells; expected cell(s) hit: {', '.join(hit)})")
            else:
                problems.append(f"mutant {m} not caught for the right reason (failing: {fm[:6]}, expected any of {expect})")
                print(f"  mutant {m:22} NOT CAUGHT (failing: {fm[:6]})")
        if broken:
            problems.append(f"broken controls: {broken}")
        if problems:
            print("SYSCALL-NEGATIVE SELF-TEST: FAIL (" + "; ".join(problems) + ")")
            return 1
        print(f"SYSCALL-NEGATIVE SELF-TEST: PASS ({caught}/{len(MUTANTS)} mutants red, reference green on "
              f"{ncells} cells, {len(masked)} masked controls: {','.join(masked)})")
        return 0

    subj = shlex.split(a.subject) if a.subject else [a.bin]
    print(f"subject: {' '.join(subj)}")
    fails, rows = evaluate(subj, ctl, env)
    if a.json_out:
        with open(a.json_out, "w") as fh:
            json.dump({"facts": facts, "controls": {p: ctl[p] for p, _ in PROBES},
                       "cells": [dict(zip(["stage", "probe", "kind", "control", "subject", "ok", "why"], r)) for r in rows]},
                      fh, indent=1)
    if fails or broken:
        why = f"{len(fails)}/{ncells} cells failed: {', '.join(fails[:8])}" if fails else f"broken controls {broken}"
        print(f"SYSCALL-NEGATIVE: FAIL ({why})")
        return 1
    print(f"SYSCALL-NEGATIVE: PASS ({ncells} cells on 3 stages, {len(masked)} masked controls, "
          f"kernel {facts['kernel']}, landlock ABI {facts['landlock_abi']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
