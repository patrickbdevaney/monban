#!/usr/bin/env python3
"""hostile-modules oracle (Phase 5, unit P5-oracle-hostile-001; gates p2-hostile-worker and p2-hostile-host).

Worker level: the oracle is the mock supervisor. It compiles each corpus module with `<worker> compile`, starts
`<worker> zygote|cordon` on a listening SOCK_SEQPACKET socket (fd 3), speaks F14 frames, answers data_run, and judges
the frames that come back (I1 imports and handles, I2 budgets and quotas).
Host level (host.py): boots the real aegis binary (feature p2) with an oracle-written F8 config and judges response
bytes, the F9 audit log and the SQLite effect sink (I1 capabilities, I5, I6-host, I7).
Contract, cases and expected outcomes: README.md and corpus/*.json.
"""

import argparse
import json
import os
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import f14  # noqa: E402
import guests  # noqa: E402

NAME = "HOSTILE-MODULES"
FRAME_MAX = 65536
GRACE_MS = 2000  # wall_ms + GRACE_MS is the per-request deadline (shared, loaded hosts: record load average)
WORKER_MUTANTS = {
    # mutant -> cases of which at least one must be red (README "Self-test")
    "extra-import": ["w-i1-import-host-fault"],
    "handle-not-cleared": ["w-i1-handle-previous-request"],
    "no-hostcall-quota": ["w-i2-hostcall-flood"],
    "no-fuel-no-epoch": ["w-i2-fuel", "w-i2-loop"],
    "no-limiter": ["w-i2-memory-bomb", "w-i2-memory-initial", "w-i2-table-bomb"],
}
PATHS = ["zygote", "cordon"]


def load_corpus(level):
    with open(os.path.join(HERE, "corpus", f"{level}.json")) as f:
        c = json.load(f)
    ids = set()
    for case in c["cases"]:
        assert case["id"] not in ids, case["id"]
        ids.add(case["id"])
        assert case["invariant"] in ("I1", "I2", "I5", "I6-host", "I7", "control"), case
    return c["cases"]


def loadavg():
    try:
        return open("/proc/loadavg").read().split()[0]
    except OSError:
        return "?"


# ------------------------------------------------------------------------------------------------ worker process
class WorkerProc:
    """One `<worker> zygote|cordon` process holding the oracle's listening socket on fd 3."""

    def __init__(self, cmd, path, cwasm, digest, workdir, env):
        self.sock_path = os.path.join(workdir, f"w-{os.getpid()}-{time.monotonic_ns()}.sock")
        self.lsock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.lsock.bind(self.sock_path)
        self.lsock.listen(64)
        fd = self.lsock.fileno()
        self.log = tempfile.TemporaryFile()
        self.proc = subprocess.Popen(cmd + [path, "--module", cwasm, "--sha256", digest], stdin=subprocess.DEVNULL,
                                     stdout=self.log, stderr=self.log, env=env, start_new_session=True,
                                     pass_fds=(fd, 3), preexec_fn=lambda: os.dup2(fd, 3))
        self.digest = digest
        self.conn = None

    def connect(self, timeout=10.0):
        c = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        c.settimeout(timeout)
        c.connect(self.sock_path)
        f = c.recv(FRAME_MAX + 1)
        d = f14.dec_w2s(f)
        if d["t"] != "ready" or d["ver"] != 1 or d["sha256"] != self.digest:
            raise f14.DecodeError(f"bad ready frame {d}")
        return c

    def alive(self):
        return self.proc.poll() is None

    def tail(self):
        try:
            self.log.seek(0)
            return self.log.read()[-600:].decode(errors="replace")
        except (OSError, ValueError):
            return ""

    def kill(self):
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)  # explicit pgid of the session we started
        except (ProcessLookupError, PermissionError):
            pass
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            pass
        for s in (self.conn, self.lsock):
            try:
                s and s.close()
            except OSError:
                pass
        try:
            os.unlink(self.sock_path)
        except OSError:
            pass


def exchange(conn, rid, limits, body, case, deadline_s, first_on_conn=True):
    """Mock supervisor for one request. Returns a record of what the worker sent.

    A test-hooks/mutants worker sends one D8 `layout` frame after `ready` on each connection (F14 Part 2). It is
    accepted only in the first exchange of a connection (`first_on_conn`), only once, and only before any other
    frame; every other frame type outside the request's own frames is still a protocol violation."""
    rec = {"frames": [], "end": None, "died": False, "timeout": False, "protocol": None, "data_runs": [],
           "resp_head": None, "body": b"", "log_bytes": 0}
    try:
        conn.send(f14.f_request(rid, limits, f14.req_head(body_len=len(body))))
        conn.send(f14.f_body(rid, body, True))
    except OSError:
        rec["died"] = True
        return rec
    t_end = time.monotonic() + deadline_s
    reply = reply_for(case)
    while True:
        left = t_end - time.monotonic()
        if left <= 0:
            rec["timeout"] = True
            return rec
        conn.settimeout(left)
        try:
            f = conn.recv(FRAME_MAX + 1)
        except socket.timeout:
            rec["timeout"] = True
            return rec
        except OSError:
            rec["died"] = True
            return rec
        if not f:
            rec["died"] = True
            return rec
        if len(f) > FRAME_MAX:
            rec["protocol"] = f"oversized frame ({len(f)} bytes)"
            return rec
        try:
            d = f14.dec_w2s(f)
        except f14.DecodeError as e:
            rec["protocol"] = f"undecodable frame: {e}"
            return rec
        if d["t"] == "layout" and first_on_conn and not rec["frames"] and not rec.get("layout"):
            rec["layout"] = True
            continue
        rec["frames"].append(d["t"])
        if d.get("rid") != rid:
            rec["protocol"] = f"frame for unknown req-id {d.get('rid')}"
            return rec
        t = d["t"]
        if t == "data-run":
            if d["seq"] != len(rec["data_runs"]):
                rec["protocol"] = "data-run seq out of order"
                return rec
            rec["data_runs"].append(d["op"])
            try:
                conn.send(f14.f_data_reply(rid, d["seq"], reply))
            except OSError:
                rec["died"] = True
                return rec
        elif t == "resp-head":
            if rec["resp_head"] is not None:
                rec["protocol"] = "second resp-head"
                return rec
            rec["resp_head"] = d
        elif t == "resp-body":
            if rec["resp_head"] is None:
                rec["protocol"] = "resp-body before resp-head"
                return rec
            rec["body"] += d["chunk"]
        elif t == "log":
            rec["log_bytes"] += len(d["data"])
        elif t == "resp-end":
            rec["end"] = d["end"]
            return rec
        else:
            rec["protocol"] = f"unexpected frame {t}"
            return rec


def reply_for(case):
    if "reply_bytes" in case:
        return f14.result_rows([["x" * case["reply_bytes"]]])
    return f14.result_rows(case.get("reply_rows", [["row", "body"]]))


def judge(case, rec, extra=None):
    """Returns None if the outcome matches the case's expectation, else a reason."""
    exp = case["expect"]
    end = rec["end"]
    if rec["protocol"]:
        return f"F14 protocol violation by the worker: {rec['protocol']}"
    if rec["timeout"]:
        return "no resp-end within the deadline (unbounded request)"
    for k, lim in (("max_data_run_frames", len(rec["data_runs"])), ("max_resp_body", len(rec["body"])),
                   ("max_log_bytes", rec["log_bytes"])):
        if k in case and lim > case[k]:
            return f"{k}: {lim} > {case[k]} (quota not enforced before forwarding)"
    if case.get("op_verbatim"):
        want = guests.op_bytes(case["args"])
        if rec["data_runs"] != [want]:
            return "data-run op bytes differ from what the guest passed (the worker must forward them verbatim)"
    ok_end = end == ("code", 0)
    trapped = end is not None and end[0] == "trap"
    if exp == "ok" or (exp == "ok-or-fail" and ok_end):
        if not ok_end:
            return f"expected success, got {end_text(rec)}"
        if case.get("body") is not None and rec["body"] != case["body"].encode():
            return f"body {rec['body'][:60]!r} != {case['body']!r}"
        if case.get("body_is_result") and rec["body"] != reply_for(case):
            return "result_read did not return the supervisor's result bytes"
        if "max_pages" in case:
            pages = int.from_bytes(rec["body"][:4], "little") if len(rec["body"]) >= 4 else None
            if pages is None or pages > case["max_pages"]:
                return f"memory grew to {pages} pages > {case['max_pages']} (limiter not enforced)"
        return None
    if exp in ("fail", "ok-or-fail", "refused-or-fail"):
        if ok_end:
            return f"expected a failed request, got success (body {rec['body'][:40]!r})"
        if trapped:
            if case.get("traps") and end[1] not in case["traps"]:
                return f"trap code {end[1]} not in {case['traps']}"
            return None
        if end is not None:
            return f"expected a trap, got handle() code {end[1]}"
        if rec["died"] and case.get("death_ok"):
            return None
        return f"expected resp-end with a trap, got {end_text(rec)}"
    return f"bad expectation {exp}"


def end_text(rec):
    if rec["end"]:
        return f"{rec['end'][0]} {rec['end'][1]}"
    if rec["died"]:
        return "worker closed the connection without resp-end"
    return "nothing"


class WorkerLevel:
    def __init__(self, subject_cmd, env_extra, workdir, verbose=False, paths=PATHS, label="subject"):
        self.cmd = subject_cmd
        self.env = dict(os.environ)
        self.env.pop("AEGIS_P2_MUTANT", None)
        self.env.pop("HOSTILE_ESCAPED", None)
        self.env.update(env_extra)
        self.dir = tempfile.mkdtemp(prefix="wl-", dir=workdir)
        self.verbose = verbose
        self.paths = paths
        self.label = label
        self.failures = []
        self.passed = 0

    def compile(self, case):
        wasm = guests.build(case["builder"], case.get("args"))
        wp = os.path.join(self.dir, case["id"] + ".wasm")
        cp = os.path.join(self.dir, case["id"] + ".cwasm")
        with open(wp, "wb") as f:
            f.write(wasm)
        try:
            r = subprocess.run(self.cmd + ["compile", "--in", wp, "--out", cp], env=self.env,
                               capture_output=True, timeout=120)
            code = r.returncode
        except subprocess.TimeoutExpired:
            code = None
        if code == 0 and os.path.exists(cp):
            with open(cp, "rb") as f:
                return cp, hashlib.sha256(f.read()).hexdigest(), None
        return None, None, code

    def check(self, name, reason):
        if reason is None:
            self.passed += 1
            if self.verbose:
                print(f"  ok   {name}", flush=True)
        else:
            self.failures.append(name)
            print(f"  FAIL {name}: {reason}", flush=True)

    def run(self, cases):
        for case in cases:
            cp, dig, code = self.compile(case)
            exp = case["expect"]
            if cp is None:
                if code is None:
                    reason = "compile hung (> 120 s)"
                elif exp in ("refused", "refused-or-fail"):
                    reason = None
                else:
                    reason = f"compile refused a module it must accept (exit {code})"
                for p in self.paths:
                    self.check(f"{p}:{case['id']}", reason)
                continue
            if exp == "refused":
                for p in self.paths:
                    self.check(f"{p}:{case['id']}", "compile accepted a module outside F14 (static import/export "
                                                    "check missing): it must be refused before instantiation")
                continue
            for p in self.paths:
                self.check(f"{p}:{case['id']}", self.run_case(case, p, cp, dig))

    def run_case(self, case, path, cp, dig):
        limits = dict(f14.DEFAULT_LIMITS)
        limits.update(case.get("limits", {}))
        deadline = (limits["wall_ms"] + case.get("deadline_ms", GRACE_MS)) / 1000.0
        w = WorkerProc(self.cmd, path, cp, dig, self.dir, self.env)
        try:
            try:
                conn = w.connect()
            except (OSError, f14.DecodeError) as e:
                return f"worker did not come up with a valid ready frame ({e}): {w.tail()}"
            w.conn = conn
            body = b""
            if case.get("previous_handle"):
                first = exchange(conn, 1, limits, b"", {"reply_rows": [["row", "body"]]}, deadline)
                if first["end"] != ("code", 0) or len(first["body"]) != 4:
                    return f"previous-handle setup request failed: {end_text(first)} {first['protocol']}"
                body = first["body"]
                if path == "zygote":
                    conn.close()
                    conn = w.connect()
                    w.conn = conn
            fresh = not case.get("previous_handle") or path == "zygote"
            rec = exchange(conn, 2, limits, body, case, deadline, first_on_conn=fresh)
            reason = judge(case, rec)
            if reason is None and path == "zygote" and not w.alive():
                reason = f"the zygote died (a request must only ever take down its fork child): {w.tail()}"
            return reason
        finally:
            w.kill()

    def summary(self):
        return f"{self.passed} cells ok, {len(self.failures)} failed"


# ------------------------------------------------------------------------------------------------ build
def build_reference():
    """Builds rust/ (hostref) under ci/heavy.sh into rust/target; returns the binary path or None."""
    t = os.path.join(HERE, "rust", "target")
    r = subprocess.run([os.path.join(REPO, "ci", "heavy.sh"), os.path.join(HERE, "rust", "build.sh"), t],
                       stdout=sys.stderr, stderr=sys.stderr)
    b = os.path.join(t, "release", "hostref")
    return b if r.returncode == 0 and os.path.exists(b) else None


def split(s):
    return shlex.split(s)


def worker_selftest(subject, mutant_subject, workdir, verbose):
    """Unmutated subject must PASS; each worker mutant must turn at least one of its expected cases red."""
    cases = load_corpus("worker")
    ok = True
    notes = []
    print(f"[worker] control: {' '.join(subject)} (load {loadavg()})", flush=True)
    wl = WorkerLevel(subject, {}, workdir, verbose)
    wl.run(cases)
    if wl.failures:
        ok = False
        notes.append(f"control red ({len(wl.failures)} cells)")
    else:
        notes.append(f"control green ({wl.passed} cells)")
    for m, expected in WORKER_MUTANTS.items():
        print(f"[worker] mutant {m} (AEGIS_P2_MUTANT={m}, load {loadavg()})", flush=True)
        ml = WorkerLevel(mutant_subject, {"AEGIS_P2_MUTANT": m}, workdir, False)
        ml.run(cases)
        hit = sorted({f.split(":", 1)[1] for f in ml.failures} & set(expected))
        if hit:
            notes.append(f"{m} red ({len(ml.failures)} cells; {','.join(hit)})")
        else:
            ok = False
            notes.append(f"{m} NOT caught (red cells: {ml.failures[:5]})")
    return ok, notes


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--level", choices=["worker", "host", "both"], default=None)
    ap.add_argument("--subject", help="worker level: the aegis-p2 command; host level: the aegis binary")
    ap.add_argument("--worker", help="host level: the aegis-p2 binary named in the F8 p2 block")
    ap.add_argument("--mutant-subject")
    ap.add_argument("--mutant-worker")
    ap.add_argument("--paths", default="zygote,cordon", help="worker level paths (default both)")
    ap.add_argument("--only", help="comma-separated case ids (debugging; a partial run never prints PASS)")
    ap.add_argument("--verbose", "-v", action="store_true")
    a = ap.parse_args()
    level = a.level or ("both" if not a.subject else None)
    if level is None:
        print(f"{NAME}: FAIL (--subject needs --level worker|host)")
        return 1
    if a.subject and level == "both":
        print(f"{NAME}: FAIL (--subject judges one level: pass --level worker or --level host)")
        return 1
    workdir = tempfile.mkdtemp(prefix="aegis-hostile-")
    print(f"{NAME}: load average {loadavg()} at start", flush=True)
    try:
        # the host level always needs the reference worker: its escaped-worker cases run it as the compromised worker
        need_ref = not a.subject or level in ("host", "both")
        ref = None
        if need_ref or level == "both":
            ref = build_reference()
            if ref is None:
                print(f"{NAME}: FAIL (build of the reference worker failed)")
                return 1
        tag = f"{NAME} SELF-TEST" if a.self_test else NAME
        results, notes = [], []
        if a.self_test:
            # the README must list every case with its invariant and expected outcome (unit acceptance)
            readme = open(os.path.join(HERE, "README.md")).read()
            missing = [c["id"] for lv in ("worker", "host") for c in load_corpus(lv) if f"`{c['id']}`" not in readme]
            results.append(not missing)
            notes.append(f"README lists every case" if not missing else f"README misses {missing[:5]}")
        if level in ("worker", "both"):
            subj = split(a.subject) if a.subject else [ref]
            if a.self_test:
                msub = split(a.mutant_subject) if a.mutant_subject else ([ref] if not a.subject else None)
                if msub is None:
                    print(f"{tag}: FAIL (--self-test --subject needs --mutant-subject)")
                    return 1
                ok, n = worker_selftest(subj, msub, workdir, a.verbose)
                results.append(ok)
                notes.append("worker: " + "; ".join(n))
            else:
                cases = load_corpus("worker")
                if a.only:
                    cases = [c for c in cases if c["id"] in a.only.split(",")]
                wl = WorkerLevel(subj, {}, workdir, a.verbose, paths=a.paths.split(","))
                wl.run(cases)
                results.append(not wl.failures and not a.only)
                notes.append(f"worker: {wl.summary()} on {','.join(wl.paths)}")
        if level in ("host", "both"):
            import host  # noqa: E402
            ok, n = host.run_level(a, ref, workdir)
            results.append(ok)
            notes.append("host: " + n)
        verdict = "PASS" if results and all(results) else "FAIL"
        print(f"{tag}: {verdict} ({' | '.join(notes)}; load {loadavg()})")
        return 0 if verdict == "PASS" else 1
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
