#!/usr/bin/env python3
"""oracles/pdp-dst: deterministic fault injection on the Cedar PDP channel (INV-FAILCLOSED host mapping, X-8).

Topology (lockstep, one request in flight):

    client driver  --SEQPACKET-->  fault proxy  --SEQPACKET-->  aegis-pdp serve --listen
    (aegis-pdp-probe, or the                                     (restarted after every kill)
     reference/mutant Python client)

For each of the three example policy sets (policies/<set>/):
  1. startup: `check` passes; the PDP refuses to start on invalid.cedar (exit != 0, socket never bound).
  2. reference: every case is decided by Cedar through its own JSON parsers (`aegis-pdp eval`); the answer must
     equal the hand-written `expect` (Cedar's answer with the AEGIS mapping: request/schema error or any policy
     evaluation error => ERROR).
  3. unfaulted: every case through driver -> proxy -> PDP must give exactly that answer, and combine() must give
     ALLOW only for ALLOW.
  4. faulted: each fault below is applied to every ALLOW case and one DENY case, each followed by an unfaulted
     recovery case; every faulted decision must be ERROR and combine to DENY (never ALLOW), every recovery case must
     still match the reference.
  5. stdio mode: a socketpair end passed as fd 0 (`serve --stdio`) answers like the listener.

Faults: delay (reply held past the deadline), drop (never answered), kill_before (PDP SIGKILLed after it got the
request, client sees EOF), kill_mid (half a reply, then SIGKILL + EOF), truncate, empty, garble (magic, version, kind,
decision byte), oversize (13, 64, 70000 bytes), swap_id (+1, -1, top bit), replay (an earlier ALLOW reply), and on
the request path req_trailing, req_truncate, req_magic, req_oversize. Every reply-path fault that still sends bytes
first sets the decision byte to ALLOW, so a lenient client shows up as ALLOW.

--self-test runs the same harness with the Python reference client (must PASS) and with mutants that must FAIL:
timeout-allow (timeout => ALLOW), ignore-id (no request-id check), accept-oversize (reads the first 12 bytes of a
long packet), no-reset (keeps the connection after a fault).
"""

import argparse
import json
import os
import random
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

NAME = "PDP-DST"
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
SETS = ["rbac", "tenant", "deny-overrides"]

MAGIC, VERSION, K_REQ, K_REP = 0xCD, 1, 0, 1
HEADER_LEN, REPLY_LEN, MAX_REQUEST = 11, 12, 64 * 1024
BIG = 1 << 18
DEC = {0: "ALLOW", 1: "DENY", 2: "ERROR"}

REPLY_FAULTS = {
    "delay": [None], "drop": [None], "kill_before": [None], "kill_mid": [None],
    "truncate": [1, 6, 11], "empty": [None],
    "garble": ["magic", "version", "kind", "decision"],
    "oversize": [13, 64, 70000], "swap_id": ["+1", "-1", "top"], "replay": [None],
}
REQUEST_FAULTS = {"req_trailing": [None], "req_truncate": [None], "req_magic": [None], "req_oversize": [None]}
FAULTS = {**REPLY_FAULTS, **REQUEST_FAULTS}


# ------------------------------------------------------------------------------------------- PDP-1 encoder (Python)

def _str(s):
    b = s.encode("utf-8")
    if len(b) > 0xFFFF:
        raise ValueError("string too long")
    return len(b).to_bytes(2, "big") + b


def _uid(u):
    return _str(u[0]) + _str(u[1])


def _value(v):
    if v is True:
        return b"\x01"
    if v is False:
        return b"\x00"
    if isinstance(v, int):
        return b"\x02" + v.to_bytes(8, "big", signed=True)
    if isinstance(v, str):
        return b"\x03" + _str(v)
    if isinstance(v, dict) and "__entity" in v:
        return b"\x04" + _uid(v["__entity"])
    if isinstance(v, dict) and "__set" in v:
        items = sorted(_value(x) for x in v["__set"])
        if len(set(items)) != len(items):
            raise ValueError("duplicate set element")
        return b"\x05" + len(items).to_bytes(2, "big") + b"".join(items)
    if isinstance(v, dict):
        return _record(v)
    raise ValueError(f"unencodable value {v!r}")


def _record(d):
    keys = sorted(d, key=lambda k: k.encode("utf-8"))
    return b"\x06" + len(keys).to_bytes(2, "big") + b"".join(_str(k) + _value(d[k]) for k in keys)


def _entity(e):
    parents = sorted(_uid(p) for p in e["parents"])
    return _uid(e["uid"]) + _record(e["attrs"]) + len(parents).to_bytes(2, "big") + b"".join(parents)


def encode_body(c):
    ents = sorted(_entity(e) for e in c["entities"])
    return (_uid(c["p"]) + _uid(c["a_uid"]) + _uid(c["r"]) + _record(c["ctx"])
            + len(ents).to_bytes(2, "big") + b"".join(ents))


def frame(rid, body):
    return bytes([MAGIC, VERSION, K_REQ]) + rid.to_bytes(8, "big") + body


def reply_frame(rid, dec_byte):
    return bytes([MAGIC, VERSION, K_REP]) + (rid % (1 << 64)).to_bytes(8, "big") + bytes([dec_byte])


# ------------------------------------------------------------------------------------------- Cedar JSON (reference)

def _cj(v):
    if isinstance(v, dict) and "__entity" in v:
        return {"__entity": {"type": v["__entity"][0], "id": v["__entity"][1]}}
    if isinstance(v, dict) and "__set" in v:
        return [_cj(x) for x in v["__set"]]
    if isinstance(v, dict):
        return {k: _cj(x) for k, x in v.items()}
    return v


def _lit(u):
    return u[0] + "::" + json.dumps(u[1])


def eval_line(c):
    ents = [{"uid": {"type": e["uid"][0], "id": e["uid"][1]}, "attrs": _cj(e["attrs"]),
             "parents": [{"type": p[0], "id": p[1]} for p in e["parents"]]} for e in c["entities"]]
    return "\t".join([_lit(c["p"]), _lit(c["a_uid"]), _lit(c["r"]), json.dumps(_cj(c["ctx"])), json.dumps(ents)])


def load_set(name):
    d = os.path.join(HERE, "policies", name)
    spec = json.load(open(os.path.join(d, "cases.json")))
    ns = spec["base_entities"][0]["uid"][0].split("::")[0]
    cases = []
    for c in spec["cases"]:
        ents = {tuple(e["uid"]): e for e in spec["base_entities"]}
        for e in c.get("replace", []) + c.get("add", []):
            ents[tuple(e["uid"])] = e
        c = dict(c, entities=list(ents.values()), a_uid=[ns + "::Action", c["a"]])
        c["body"] = encode_body(c)
        cases.append(c)
    return d, cases


# ------------------------------------------------------------------------------------------- PDP process + proxy

class Pdp:
    def __init__(self, subject, setdir, tmp, log):
        self.subject, self.setdir, self.tmp, self.log = subject, setdir, tmp, log
        self.proc, self.path, self.n = None, None, 0
        self.restarts = 0

    def start(self):
        self.n += 1
        self.path = os.path.join(self.tmp, f"pdp{self.n}.sock")
        self.proc = subprocess.Popen(
            [self.subject, "serve", "--policies", os.path.join(self.setdir, "policies.cedar"),
             "--schema", os.path.join(self.setdir, "schema.cedarschema"), "--listen", self.path],
            stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log)
        t0 = time.monotonic()
        while time.monotonic() - t0 < 15:
            if self.proc.poll() is not None:
                raise RuntimeError(f"aegis-pdp exited at startup ({self.proc.returncode})")
            if os.path.exists(self.path):
                try:
                    s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                    s.connect(self.path)
                    s.close()
                    return
                except OSError:
                    pass
            time.sleep(0.01)
        raise RuntimeError("aegis-pdp did not start listening within 15 s")

    def kill(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGKILL)
            self.proc.wait()
        if self.path and os.path.exists(self.path):
            os.unlink(self.path)

    def restart(self):
        self.kill()
        self.restarts += 1
        self.start()


class Proxy:
    """Fault-injecting SEQPACKET proxy. `arm(fault, arg)` sets the fault for every frame until the next arm;
    `done` is set once the frame's fault handling (including any PDP restart) has finished."""

    def __init__(self, path, pdp, deadline_s):
        self.pdp, self.deadline = pdp, deadline_s
        self.fault, self.arg = "none", None
        self.done = threading.Event()
        self.frames = 0
        self.last_allow = None
        self.lock = threading.Lock()
        self.ls = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.ls.bind(path)
        self.ls.listen(16)
        threading.Thread(target=self._accept, daemon=True).start()

    def arm(self, fault, arg):
        with self.lock:
            self.fault, self.arg, self.frames = fault, arg, 0
            self.done.clear()

    def _accept(self):
        while True:
            try:
                c, _ = self.ls.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _up(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        s.connect(self.pdp.path)
        s.settimeout(10)
        return s

    def _handle(self, c):
        up = None
        try:
            while True:
                try:
                    req = c.recv(BIG)
                except OSError:
                    return
                if not req:
                    return
                with self.lock:
                    fault, arg = self.fault, self.arg
                    self.frames += 1
                rid = int.from_bytes(req[3:11], "big") if len(req) >= HEADER_LEN else 0
                try:
                    up = self._serve_one(c, up, req, rid, fault, arg)
                finally:
                    self.done.set()
                if up is None:
                    return
        finally:
            for s in (c, up):
                try:
                    s and s.close()
                except OSError:
                    pass

    def _serve_one(self, c, up, req, rid, fault, arg):
        """Handle one frame; returns the upstream socket to keep, or None to close the client connection."""
        if fault == "req_trailing":
            req = req + b"\x00"
        elif fault == "req_truncate":
            req = req[:-1]
        elif fault == "req_magic":
            req = b"\x00" + req[1:]
        elif fault == "req_oversize":
            req = req + b"\x00" * (MAX_REQUEST + 100 - len(req))
        if up is None:
            up = self._up()
        up.send(req)
        if fault == "kill_before":
            self.pdp.kill()
            c.close()
            self.pdp.restart()
            return None
        try:
            rep = up.recv(BIG)
        except OSError:
            rep = b""
        if fault == "none" or fault in REQUEST_FAULTS:
            if not rep:  # the PDP closed (e.g. bad header): mirror the EOF
                return None
            c.send(rep)
            if fault == "none" and len(rep) == REPLY_LEN and rep[11] == 0:
                self.last_allow = rep
            return up
        allow = bytearray(rep[:REPLY_LEN] if len(rep) >= REPLY_LEN else reply_frame(rid, 0))
        allow[11] = 0  # every lenient reading of what follows says ALLOW
        if fault == "delay":
            time.sleep(3 * self.deadline)
            try:
                c.send(bytes(allow))
            except OSError:
                pass
            return up
        if fault == "drop":
            return up
        if fault == "kill_mid":
            c.send(bytes(allow[:5]))
            self.pdp.kill()
            c.close()
            self.pdp.restart()
            return None
        if fault == "truncate":
            c.send(bytes(allow[:arg]))
        elif fault == "empty":
            c.send(b"")
        elif fault == "garble":
            g = bytearray(allow)
            if arg == "magic":
                g[0] ^= 0xFF
            elif arg == "version":
                g[1] = 2
            elif arg == "kind":
                g[2] = K_REQ
            else:
                g[11] = 3 + (rid % 253)
            c.send(bytes(g))
        elif fault == "oversize":
            c.send(bytes(allow) + b"\x00" * (arg - REPLY_LEN))
        elif fault == "swap_id":
            other = {"+1": rid + 1, "-1": rid - 1, "top": rid ^ (1 << 63)}[arg]
            c.send(reply_frame(other, 0))
        elif fault == "replay":
            old = self.last_allow
            if old is None or int.from_bytes(old[3:11], "big") == rid:
                old = reply_frame(rid - 1, 0)
            c.send(old)
        return up


# ------------------------------------------------------------------------------------------- driver handling

class Driver:
    def __init__(self, argv):
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, bufsize=1)

    def ask(self, body, timeout=10.0):
        try:
            self.p.stdin.write(body.hex() + "\n")
            self.p.stdin.flush()
        except (BrokenPipeError, OSError):
            return None
        r, _, _ = select.select([self.p.stdout], [], [], timeout)
        if not r:
            return None
        line = self.p.stdout.readline().split()
        return line if len(line) == 2 else None

    def close(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            self.p.wait(5)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()


def run_set(name, subject, driver_argv, deadline_ms, seed, fail_fast, out):
    """Returns (violations, stats)."""
    setdir, cases = load_set(name)
    v = []
    stats = {"cases": len(cases), "faulted": 0, "recovery": 0, "restarts": 0}
    with tempfile.TemporaryDirectory(prefix="pdpdst") as tmp, open(os.path.join(tmp, "pdp.log"), "w") as log:
        # 1. startup validation
        pol, sch = os.path.join(setdir, "policies.cedar"), os.path.join(setdir, "schema.cedarschema")
        r = subprocess.run([subject, "check", "--policies", pol, "--schema", sch], capture_output=True, text=True)
        if r.returncode != 0:
            return [f"{name}: check refused the valid policy set: {r.stderr.strip()[:300]}"], stats
        bad_sock = os.path.join(tmp, "bad.sock")
        try:
            r = subprocess.run([subject, "serve", "--policies", os.path.join(setdir, "invalid.cedar"),
                                "--schema", sch, "--listen", bad_sock], capture_output=True, text=True, timeout=20)
            if r.returncode == 0 or os.path.exists(bad_sock):
                v.append(f"{name}: PDP started on invalid.cedar")
        except subprocess.TimeoutExpired:
            v.append(f"{name}: PDP kept running on invalid.cedar (did not refuse)")
        # 2. reference answers (Cedar JSON path)
        r = subprocess.run([subject, "eval", "--policies", pol, "--schema", sch],
                           input="".join(eval_line(c) + "\n" for c in cases), capture_output=True, text=True)
        ref = r.stdout.splitlines()
        if r.returncode != 0 or len(ref) != len(cases):
            return v + [f"{name}: eval failed ({r.returncode}): {r.stderr.strip()[:300]}"], stats
        for c, line in zip(cases, ref):
            word = line.split()[0]
            if word != c["expect"]:
                v.append(f"{name}/{c['name']}: Cedar reference says {line!r}, case expects {c['expect']}")
            if "cedar_raw" in c and c["cedar_raw"] not in line:
                v.append(f"{name}/{c['name']}: Cedar raw {line!r} lacks {c['cedar_raw']}")
        if v:
            return v, stats
        # 3-4. through the proxy
        pdp = Pdp(subject, setdir, tmp, log)
        pdp.start()
        proxy_path = os.path.join(tmp, "proxy.sock")
        proxy = Proxy(proxy_path, pdp, deadline_ms / 1000.0)
        drv = Driver(driver_argv(proxy_path))
        try:
            schedule = [(i, "none", None) for i in range(len(cases))]
            rng = random.Random(f"{seed}/{name}")
            allow_idx = [i for i, c in enumerate(cases) if c["expect"] == "ALLOW"]
            deny_idx = [i for i, c in enumerate(cases) if c["expect"] == "DENY"]
            pairs = []
            for f, args in FAULTS.items():
                targets = allow_idx + deny_idx[:1]
                for k, t in enumerate(targets):
                    pairs.append([(t, f, args[k % len(args)]), (rng.randrange(len(cases)), "none", None)])
            rng.shuffle(pairs)
            schedule += [x for p in pairs for x in p]
            prev_faulted = False
            for i, f, arg in schedule:
                c = cases[i]
                proxy.arm(f, arg)
                got = drv.ask(c["body"])
                if not proxy.done.wait(max(10.0, 6 * deadline_ms / 1000.0)):
                    v.append(f"{name}/{c['name']} [{f}]: driver sent no frame")
                if got is None:
                    v.append(f"{name}/{c['name']} [{f}]: driver gave no answer (crashed or hung)")
                    break
                raw, comb = got
                if f == "none":
                    want_comb = "ALLOW" if c["expect"] == "ALLOW" else "DENY"
                    if raw != c["expect"] or comb != want_comb:
                        v.append(f"{name}/{c['name']} [unfaulted{' after fault' if prev_faulted else ''}]: "
                                 f"got {raw} {comb}, Cedar says {c['expect']}")
                    if prev_faulted:
                        stats["recovery"] += 1
                else:
                    stats["faulted"] += 1
                    if raw != "ERROR" or comb != "DENY":
                        v.append(f"{name}/{c['name']} [{f}{'' if arg is None else ':' + str(arg)}]: "
                                 f"got {raw} {comb}, want ERROR DENY")
                prev_faulted = f != "none"
                if fail_fast and v:
                    break
            stats["restarts"] = pdp.restarts
        finally:
            drv.close()
            pdp.kill()
            proxy.ls.close()
        # 5. stdio (socketpair fd) mode
        if not (fail_fast and v):
            v += stdio_check(name, subject, pol, sch, cases)
    print(f"  {name}: {stats['cases']} cases, {stats['faulted']} faulted, {stats['recovery']} recovery, "
          f"{stats['restarts']} PDP restarts, {len(v)} violations", file=out)
    return v, stats


def stdio_check(name, subject, pol, sch, cases):
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    p = subprocess.Popen([subject, "serve", "--policies", pol, "--schema", sch, "--stdio"], stdin=b.fileno(),
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    b.close()
    a.settimeout(10)
    v = []
    try:
        for k, c in enumerate(cases, start=1):
            a.send(frame(k, c["body"]))
            rep = a.recv(64)
            if len(rep) != REPLY_LEN or rep[:3] != bytes([MAGIC, VERSION, K_REP]) \
                    or int.from_bytes(rep[3:11], "big") != k or DEC.get(rep[11]) != c["expect"]:
                v.append(f"{name}/{c['name']} [stdio]: reply {rep.hex()} != {c['expect']}")
    except OSError as e:
        v.append(f"{name} [stdio]: {e}")
    finally:
        a.close()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()
            v.append(f"{name} [stdio]: PDP did not exit on EOF")
    return v


def run_all(subject, driver_argv, deadline_ms, seed, fail_fast, out):
    allv, total = [], {"cases": 0, "faulted": 0, "recovery": 0, "restarts": 0}
    for s in SETS:
        v, st = run_set(s, subject, driver_argv, deadline_ms, seed, fail_fast, out)
        allv += v
        for k in total:
            total[k] += st.get(k, 0)
        if fail_fast and allv:
            break
    return allv, total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--subject", help="aegis-pdp binary (default: default-subject)")
    ap.add_argument("--probe", help="client driver (default: aegis-pdp-probe next to the subject)")
    ap.add_argument("--deadline-ms", type=int, default=300)
    ap.add_argument("--seed", default="aegis-pdp-dst-1")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    subject = a.subject or os.path.join(REPO, open(os.path.join(HERE, "default-subject")).readline().strip())
    subject = os.path.abspath(subject)
    if not os.access(subject, os.X_OK):
        print(f"{NAME}{' SELF-TEST' if a.self_test else ''}: FAIL (subject {subject} not built)")
        return 1
    dl = a.deadline_ms
    pyclient = os.path.join(HERE, "pyclient.py")

    def py(mutant):
        return lambda sock: [sys.executable, "-I", pyclient, "--connect", sock, "--deadline-ms", str(dl),
                             "--mutant", mutant]

    if a.self_test:
        print(f"{NAME} self-test: subject {subject}, deadline {dl} ms")
        v, t = run_all(subject, py("none"), dl, a.seed, False, sys.stdout)
        if v:
            for x in v[:20]:
                print("  violation:", x)
            print(f"{NAME} SELF-TEST: FAIL (reference client violated the oracle: {len(v)})")
            return 1
        caught = []
        for m in ["timeout-allow", "ignore-id", "accept-oversize", "no-reset"]:
            v, _ = run_all(subject, py(m), dl, a.seed, True, open(os.devnull, "w"))
            print(f"  mutant {m}: {'caught: ' + v[0] if v else 'NOT CAUGHT'}")
            if not v:
                print(f"{NAME} SELF-TEST: FAIL (mutant {m} passed)")
                return 1
            caught.append(m)
        print(f"{NAME} SELF-TEST: PASS (reference client passes {t['faulted']} faulted + {t['cases']} cases; "
              f"mutants caught: {', '.join(caught)})")
        return 0

    probe = a.probe or os.path.join(os.path.dirname(subject), "aegis-pdp-probe")
    if not os.access(probe, os.X_OK):
        print(f"{NAME}: FAIL (probe {probe} not built)")
        return 1
    print(f"{NAME}: subject {subject}, driver {probe}, deadline {dl} ms, seed {a.seed}")
    v, t = run_all(subject, lambda sock: [probe, "--connect", sock, "--deadline-ms", str(dl)], dl, a.seed, False,
                   sys.stdout)
    if v:
        for x in v[:40]:
            print("  violation:", x)
        print(f"{NAME}: FAIL ({len(v)} violations)")
        return 1
    print(f"{NAME}: PASS ({t['cases']} cases match Cedar, {t['faulted']} faulted exchanges all ERROR->DENY, "
          f"{t['recovery']} recoveries, {t['restarts']} PDP kills, 3 invalid policy sets refused, stdio mode ok)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
