#!/usr/bin/env python3
"""p2-e2e: black-box oracle for the P2 supervisor end to end (Phase-5 gate p2-e2e, unit P5-oracle-e2e-001).

Boots a subject (the reference ref_subject.py + ref_worker.py, or aegis with feature p2 + the aegis-p2 worker) with
oracle-written F8 configs whose routes target {"wasm": <id>}, drives it over TLS with F5 Tier-L tokens for several
principals, and judges the outcomes plus the process tree under the subject (/proc), the F14 layout reports of a
test-hooks worker, and the effective-config dump. Families and the subject contract: README.md.
"""

import argparse
import base64
import concurrent.futures
import hashlib
import hmac
import json
import os
import random
import secrets
import shlex
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.dont_write_bytecode = True  # keep the oracle directory clean
import p2wire  # noqa: E402

NAME = "P2-E2E"
VHOST = "aegis.test"
# mutant -> check-name prefix that must be among its failures (a mutant caught only by unrelated noise is not caught)
MUTANTS = {
    "shared-cordon": "cordon.per-principal",
    "fork-respawn": "respawn.zygote.load-base",
    "global-crash-budget": "budget.other-principal",
    "no-crash-budget": "budget.exhausted",
    "budget-counts-healthy": "budget.healthy-not-counted",
    "dumpable-1": "dumpable.",
    "no-reload-switch": "reload.",
    "boot-without-landlock-accepted": "boot.landlock-abi3",
    "auto-ignores-cpus": "auto.small.",
}
# kind -> (route path, module id, export in the guest build, needs the fault build)
KINDS = {
    "echo_a": ("/a/", "echo-a", "h_echo_a", False),
    "echo_b": ("/b/", "echo-b", "h_echo_b", False),
    "trap": ("/trap/", "trap", "h_trap", False),
    "deny": ("/deny/", "deny", "h_deny", False),
    "spin": ("/spin/", "spin", "h_spin", False),
    "abort": ("/abort/", "abort", "h_abort", True),
}
GOLDEN_KINDS = ["echo_a", "echo_b", "trap", "deny", "spin"]
# Scaled crash budget (D7 knobs at their bounded minimum side). penalty > window so that expired crashes never
# re-trigger a penalty; both are long enough for 3 sequential traps on a loaded laptop.
CB_SCALED = {"crashes": 3, "window_s": 4, "penalty_s": 5}
CB_LOOSE = {"crashes": 100, "window_s": 1, "penalty_s": 1}
DEFAULTS = {"isolation": "auto", "fuel": 15000000, "wall_ms": 100, "memory_mib": 16, "mpk": False,
            "crash_budget": {"crashes": 3, "window_s": 60, "penalty_s": 600}}
SPIN = {"fuel": 1000000000, "wall_ms": 1000}
# PLAN-5 D23 option (b): p2.isolation "auto" (the default) = cordon below this many usable CPUs, else forkwasm.
AUTO_CORDON_BELOW = 8
SMALL_CPUS = 4  # the VPS-class shape (kamrui: 4 cores), as `taskset -c 0-3`
DROP_ENV = ("NOTIFY_SOCKET", "AEGIS_UPGRADE_DIR", "AEGIS_P2_MUTANT", "AEGIS_P2_TEST_LANDLOCK_ABI",
            "AEGIS_REF_TEST_HOOKS", "AEGIS_E2E_MUTANT")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ------------------------------------------------------------------------------------------------ F5 Tier-L minting


def cbor(v):
    def head(mt, n):
        if n < 24:
            return bytes([(mt << 5) | n])
        for ai, w in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * w):
                return bytes([(mt << 5) | ai]) + n.to_bytes(w, "big")
        raise ValueError(n)
    if isinstance(v, int):
        return head(0, v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    return head(4, len(v)) + b"".join(cbor(x) for x in v)


def mint(master, kid, tenant, ops=31, exp_delta=900):
    """F5 Tier-L token with caveats [aud, exp, depth 2, ops, tenant] (as oracles/native-e2e)."""
    now = int(time.time())
    nonce = secrets.token_bytes(16)
    cavs = [[0, VHOST], [1, now + exp_delta], [8, 2], [3, ops], [6, tenant]]
    prk = hmac.new(b"", master, hashlib.sha256).digest()
    a = VHOST.encode()
    info = b"aegis-cap-v1" + struct.pack("!H", len(a)) + a + struct.pack("!H", len(kid)) + kid
    t = hmac.new(hmac.new(prk, info + b"\x01", hashlib.sha256).digest(), kid + nonce, hashlib.sha256).digest()
    for c in cavs:
        t = hmac.new(t, cbor(c), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(cbor([1, kid, nonce, cavs, t])).rstrip(b"=").decode()


# ------------------------------------------------------------------------------------------------ /proc


def proc_table():
    out = {}
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/stat") as f:
                rest = f.read().rsplit(")", 1)[1].split()
            out[int(d)] = (int(rest[1]), rest[0])  # (ppid, state)
        except (OSError, IndexError, ValueError):
            pass
    return out


def descendants(root, table=None):
    t = table or proc_table()
    kids = {}
    for pid, (pp, st) in t.items():
        if st not in ("Z", "X"):
            kids.setdefault(pp, []).append(pid)
    out, todo = set(), [root]
    while todo:
        for c in kids.get(todo.pop(), []):
            if c not in out:
                out.add(c)
                todo.append(c)
    return out


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
    except OSError:
        return False


def nondumpable(pid):
    """True / False / None (process gone). Non-dumpable: the per-pid entries are root-owned and maps is unreadable
    (the /proc/<pid> directory itself keeps the task's euid since Linux 4.11; README 'Known limits')."""
    try:
        owners = {n: os.stat(f"/proc/{pid}/{n}").st_uid for n in ("status", "maps", "environ", "fd")}
        try:
            with open(f"/proc/{pid}/maps", "rb") as f:
                f.read(1)
            readable = True
        except PermissionError:
            readable = False
    except FileNotFoundError:
        return None
    return all(u == 0 for u in owners.values()) and not readable


# ------------------------------------------------------------------------------------------------ client


class Resp:
    def __init__(self, status, body):
        self.status, self.body = status, body

    def __repr__(self):
        return f"<{self.status} {self.body[:80]!r}>"


class Client:
    def __init__(self, port, cafile):
        self.port = port
        self.ctx = ssl.create_default_context(cafile=cafile)
        self.ctx.set_alpn_protocols(["http/1.1"])

    def get(self, path, token=None, timeout=20):
        try:
            raw = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
            s = self.ctx.wrap_socket(raw, server_hostname=VHOST)
        except (OSError, ssl.SSLError) as e:
            return Resp(None, repr(e).encode())
        h = [f"GET {path} HTTP/1.1", f"host: {VHOST}", "connection: close", "accept: text/plain"]
        if token:
            h.append(f"authorization: Bearer {token}")
        buf = b""
        try:
            s.sendall(("\r\n".join(h) + "\r\n\r\n").encode())
            while True:
                d = s.recv(65536)
                if not d:
                    break
                buf += d
                if b"\r\n\r\n" in buf:
                    head, rest = buf.split(b"\r\n\r\n", 1)
                    cl = [ln for ln in head.split(b"\r\n") if ln.lower().startswith(b"content-length:")]
                    if cl and len(rest) >= int(cl[0].split(b":", 1)[1]):
                        break
        except (OSError, ssl.SSLError):
            pass
        finally:
            s.close()
        if b"\r\n\r\n" not in buf:
            return Resp(None, b"")
        head, rest = buf.split(b"\r\n\r\n", 1)
        try:
            status = int(head.split(b"\r\n")[0].split(b" ")[1])
        except (IndexError, ValueError):
            status = None
        return Resp(status, rest)


# ------------------------------------------------------------------------------------------------ guests


def build_guests():
    """Real subjects: build the Rust guests through ci/heavy.sh and derive one F14 module per kind."""
    tdir = tempfile.mkdtemp(prefix="aegis-p2-e2e-guest-")
    try:
        p = subprocess.run([os.path.join(REPO, "ci", "heavy.sh"), os.path.join(HERE, "guest", "build.sh"), tdir],
                           cwd=REPO)
        if p.returncode != 0:
            raise RuntimeError("guest build failed")
        rel = os.path.join("wasm32-unknown-unknown", "release", "p2e2e_guest.wasm")
        with open(os.path.join(tdir, "plain", rel), "rb") as f:
            plain = f.read()
        with open(os.path.join(tdir, "fault", rel), "rb") as f:
            fault = f.read()
    finally:
        shutil.rmtree(tdir, ignore_errors=True)
    out = {}
    for kind, (_, _, export, needs_fault) in KINDS.items():
        m = p2wire.select_handle(fault if needs_fault else plain, export)
        p2wire.check_f14(m, allow_test_import=needs_fault)
        out[kind] = m
    return out


def ref_guests():
    return {kind: p2wire.stub_module(kind) for kind in KINDS}


# ------------------------------------------------------------------------------------------------ the run


class Subject:
    def __init__(self, run, cfg, env_extra=None, worker_env=None, pin=None):
        self.run, self.cfg = run, cfg
        self.pin = pin  # CPU list: start the subject under `taskset -c <list>` (D23 auto family)
        self.port = int(cfg["listeners"][0]["bind"].rsplit(":", 1)[1])
        self.aport = int(cfg["admin"]["bind"].rsplit(":", 1)[1])
        self.cfg_path = os.path.join(run.dir, f"aegis-{secrets.token_hex(4)}.json")
        self.write(cfg)
        self.env_extra = env_extra or {}
        self.proc = None
        self.log_path = os.path.join(run.dir, f"subject-{secrets.token_hex(4)}.log")
        self.c = Client(self.port, run.crt)
        self.seen = set()

    def write(self, cfg):
        self.cfg = cfg
        with open(self.cfg_path, "w") as f:
            json.dump(cfg, f)

    def start(self, wait=True):
        self.log = open(self.log_path, "ab")
        self.proc = subprocess.Popen(taskset(self.pin) + self.run.argv(self.cfg_path), stdout=self.log, stderr=subprocess.STDOUT,
                                     env=self.run.subject_env(self.env_extra), start_new_session=True)
        self.run.started.append(self)
        if wait:
            until = time.time() + 30
            while time.time() < until:
                if self.proc.poll() is not None:
                    raise RuntimeError(f"subject exited {self.proc.returncode} at start: {self.tail()}")
                if self.healthy():
                    return
                time.sleep(0.1)
            raise RuntimeError("subject did not become healthy within 30 s")

    def admin_get(self, path):
        try:
            with socket.create_connection(("127.0.0.1", self.aport), timeout=2) as c:
                c.sendall(f"GET {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n".encode())
                buf = b""
                while True:
                    d = c.recv(65536)
                    if not d:
                        break
                    buf += d
                return buf
        except OSError:
            return b""

    def healthy(self):
        return self.admin_get("/healthz").split(b" ")[1:2] == [b"200"]

    def reloads(self):
        for ln in self.admin_get("/metrics").split(b"\n"):
            # OpenMetrics renders a counter sample as <family>_total (aegis-metrics; proxy-e2e reads that form); the
            # reference subject prints the bare family name.
            if ln.startswith(b"aegis_proxy_config_reloads ") or ln.startswith(b"aegis_proxy_config_reloads_total "):
                try:
                    return int(float(ln.split()[1]))
                except (IndexError, ValueError):
                    return None
        return None

    def reload(self, cfg):
        before = self.reloads()
        self.write(cfg)
        self.proc.send_signal(signal.SIGHUP)
        until = time.time() + 20
        while time.time() < until:
            n = self.reloads()
            if n is not None and before is not None and n > before:
                return True
            time.sleep(0.1)
        return False

    def tail(self):
        try:
            with open(self.log_path, "rb") as f:
                return f.read()[-1500:].decode(errors="replace")
        except OSError:
            return ""

    def text(self):
        try:
            with open(self.log_path, "rb") as f:
                return f.read().decode(errors="replace")
        except OSError:
            return ""

    def log_offset(self):
        try:
            return os.path.getsize(self.log_path)
        except OSError:
            return 0

    def layouts(self, since=0):
        out = []
        try:
            with open(self.log_path, "rb") as f:
                f.seek(since)
                data = f.read().decode(errors="replace")
        except OSError:
            return out
        for ln in data.splitlines():
            i = ln.find("aegis-p2-layout ")
            if i < 0:
                continue
            try:
                o = json.loads(ln[i + len("aegis-p2-layout "):].strip())
                out.append((int(o["pid"]), int(o["load_base"])))
            except (ValueError, KeyError, TypeError):
                pass
        return out

    def workers(self):
        if not self.proc:
            return set()
        d = descendants(self.proc.pid)
        self.seen |= d
        return d

    def kill(self):
        if self.proc is None:
            return
        pids = self.workers() | self.seen
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        for p in pids:
            try:
                os.kill(p, signal.SIGKILL)
            except OSError:
                pass
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)  # explicit pgid of the session this oracle created
        except OSError:
            pass
        try:
            self.log.close()
        except (OSError, AttributeError):
            pass

    def stop(self):
        if self.proc and self.proc.poll() is None:
            pids = self.workers()
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(15)
            except subprocess.TimeoutExpired:
                pass
            self.seen |= pids
        self.kill()


class Run:
    def __init__(self, cmd, worker, test_worker, guests, env_extra=None, verbose=False, quiet=False,
                 families=None):
        self.cmd, self.worker, self.test_worker, self.guests = cmd, worker, test_worker, guests
        self.env_extra = env_extra or {}
        self.verbose, self.quiet = verbose, quiet
        self.families = families
        self.lock = threading.Lock()
        self.failures, self.passed, self.notes = [], 0, []
        self.dir = tempfile.mkdtemp(prefix="aegis-p2-e2e-")
        self.started = []
        self.kid = b"p2e2e-" + secrets.token_hex(3).encode()
        self.master = secrets.token_bytes(32)
        self.rnd = random.SystemRandom()

    # ---------------------------------------------------------------- bookkeeping
    def check(self, name, ok, detail=""):
        with self.lock:
            if ok:
                self.passed += 1
                if self.verbose:
                    print(f"  ok   {name}", flush=True)
            else:
                self.failures.append(name)
                if not self.quiet:
                    print(f"  FAIL {name}: {detail}", flush=True)
        return ok

    def note(self, s):
        with self.lock:
            self.notes.append(s)

    def tenant(self):
        return self.rnd.randrange(1, 1 << 63)

    def token(self, t):
        return mint(self.master, self.kid, t)

    # ---------------------------------------------------------------- setup
    def setup(self):
        if os.geteuid() == 0:
            raise RuntimeError("running as root: root may read any /proc entry, so dumpable=0 cannot be judged")
        if not shutil.which("openssl"):
            raise RuntimeError("openssl CLI not found (needed to mint the test certificate)")
        self.key_pem, self.crt = os.path.join(self.dir, "key.pem"), os.path.join(self.dir, "cert.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-keyout", self.key_pem, "-out", self.crt, "-days", "30", "-subj", f"/CN={VHOST}",
                        "-addext", f"subjectAltName=DNS:{VHOST}"], check=True, capture_output=True, timeout=30)
        self.kr = os.path.join(self.dir, "token-keyring.json")
        with open(self.kr, "w") as f:
            json.dump({"keys": [{"kid": self.kid.hex(), "key": self.master.hex()}]}, f)
        os.chmod(self.kr, 0o600)
        mdir = os.path.join(self.dir, "mod")
        os.makedirs(mdir)
        self.mods = {}
        for kind, b in self.guests.items():
            p = os.path.join(mdir, KINDS[kind][1] + ".wasm")
            with open(p, "wb") as f:
                f.write(b)
            os.chmod(p, 0o644)
            self.mods[kind] = (p, hashlib.sha256(b).hexdigest())
        self.cache = os.path.join(self.dir, "p2cache")
        os.makedirs(self.cache, mode=0o700)
        for d in ("audit", "run"):
            os.makedirs(os.path.join(self.dir, d))

    def argv(self, cfg_path):
        return self.cmd + ["--config", cfg_path, "--cert", self.crt, "--key", self.key_pem,
                           "--audit-dir", os.path.join(self.dir, "audit"),
                           "--runtime-dir", os.path.join(self.dir, "run"),
                           "--token-keyring", self.kr]

    def subject_env(self, extra=None):
        env = dict(os.environ)
        for k in DROP_ENV:
            env.pop(k, None)
        env.update(self.env_extra)
        env.update(extra or {})
        return env

    def config(self, kinds, isolation="forkwasm", cb=None, worker=None, omit_defaults=False):
        """isolation=None omits only `p2.isolation` (its default, `auto`, applies); omit_defaults omits both."""
        routes, mods = [], []
        for i, k in enumerate(kinds):
            path, mid, _, _ = KINDS[k]
            routes.append({"id": 10 + i, "path": path, "to": {"wasm": mid}, "authz": "allow-all"})
            m = {"id": mid, "path": self.mods[k][0], "sha256": self.mods[k][1]}
            if k == "spin":
                m.update(SPIN)
            mods.append(m)
        p2 = {"worker": worker or self.worker, "cache_dir": self.cache, "modules": mods}
        if not omit_defaults:
            if isolation is not None:
                p2["isolation"] = isolation
            p2["crash_budget"] = dict(cb or CB_SCALED)
        return {
            "v": 1,
            "listeners": [{"name": "pub", "bind": f"127.0.0.1:{free_port()}", "profile": "P-PUBLIC-WEB",
                           "alpn": ["h2", "http/1.1"]}],
            "admin": {"bind": f"127.0.0.1:{free_port()}"},
            "vhosts": [{"host": VHOST, "routes": routes}],
            "p2": p2,
        }

    def want(self, fam):
        return self.families is None or fam in self.families

    # ---------------------------------------------------------------- driver
    def run(self):
        try:
            self.setup()
            fams = [("boot", self.boot_family), ("main", self.main_family), ("cordon", self.cordon_family),
                    ("auto", self.auto_family), ("respawn", self.respawn_family)]
            for fam, fn in fams:
                if not self.want(fam):
                    continue
                try:
                    fn()
                except Exception as e:  # noqa: BLE001
                    tails = "; ".join(s.tail()[-600:] for s in self.started[-1:])
                    self.check(f"{fam}.harness", False, f"{e!r}; subject log: {tails}")
                    if self.verbose:
                        traceback.print_exc()
                finally:
                    for s in self.started:
                        s.kill()
                    self.started = []
        except Exception as e:  # noqa: BLE001
            self.check("harness", False, repr(e))
        finally:
            for s in self.started:
                s.kill()
            shutil.rmtree(self.dir, ignore_errors=True)
        return not self.failures

    # ---------------------------------------------------------------- helpers
    def answer(self, s, name, kind, t, tok=None):
        """GET the echo route as principal t and judge the answer (F14 req-head echoed by the guest)."""
        route = KINDS[kind][0]
        marker = b"A" if kind == "echo_a" else b"B"
        nonce = secrets.token_hex(6)
        path = f"{route}{nonce}"
        r = s.c.get(f"{path}?n={nonce}", tok or self.token(t))
        if r.status != 200:
            return self.check(name, False, f"status {r.status} {r.body[:80]!r}")
        if r.body[:1] != marker:
            return self.check(name, False, f"answer from the wrong module: marker {r.body[:1]!r} != {marker!r}")
        try:
            h = p2wire.decode_req_head(r.body[1:])
        except (ValueError, UnicodeDecodeError) as e:
            return self.check(name, False, f"echoed req-head does not decode: {e}")
        names = [n for n, _ in h["headers"]]
        q_ok = h["query"] == ("opaque", f"n={nonce}".encode()) or h["query"] == ("typed", [("n", nonce)])
        bad = []
        if h["method"] != "GET":
            bad.append(f"method {h['method']!r}")
        if h["path"] not in (path, route):
            bad.append(f"path {h['path']!r}")
        if not q_ok:
            bad.append(f"query {h['query']!r}")
        if any(n not in p2wire.REQ_HEADER_ALLOW for n in names) or ("accept", b"text/plain") not in h["headers"]:
            bad.append(f"headers {names!r}")
        if h["body_len"] not in (None, 0):
            bad.append(f"body-len {h['body_len']}")
        return self.check(name, not bad, "; ".join(bad))

    def answers(self, s, label, tenants, kinds=("echo_a", "echo_b"), per=2):
        jobs = [(t, k) for t in tenants for k in kinds for _ in range(per)]
        with concurrent.futures.ThreadPoolExecutor(6) as ex:
            res = list(ex.map(lambda tk: self.answer(s, f"{label}.answer", tk[1], tk[0]), jobs))
        return all(res)

    def status(self, s, name, route, t, want):
        r = s.c.get(f"{route}x", self.token(t))
        ok = r.status in want if isinstance(want, (tuple, set)) else r.status == want
        self.check(name, ok, f"status {r.status}, want {want}")
        return r.status

    def check_dumpable(self, name, pids):
        judged, bad = 0, []
        for p in sorted(pids):
            v = nondumpable(p)
            if v is False:
                time.sleep(0.2)  # a freshly exec'd worker may not have reached prctl yet
                v = nondumpable(p)
            if v is None:
                continue
            judged += 1
            if not v:
                bad.append(p)
        self.check(f"dumpable.{name}", judged > 0 and not bad,
                   f"no live worker to judge" if not judged else
                   f"pids {bad}: /proc/<pid> entries not root-owned or maps readable (PR_SET_DUMPABLE=0 missing)")
        return judged

    def find_zygote(self, s, t, tries=3):
        """Run a spin request and catch the fork child serving it: a process that did not exist before the request,
        whose parent is another worker (not the supervisor), and that is gone after the request while its parent
        lives on. That parent is the zygote. Returns ((zygote, child), (nondumpable(zygote), nondumpable(child)))."""
        for _ in range(tries):
            before = s.workers()
            done = threading.Event()

            tok = self.token(self.tenant() if t is None else t)

            def spin():
                s.c.get("/spin/x", tok)
                done.set()
            th = threading.Thread(target=spin)
            th.start()
            cands = {}
            until = time.time() + 5
            while not done.is_set() and time.time() < until:
                tab = proc_table()
                ws = descendants(s.proc.pid, tab)
                s.seen |= ws
                for p in ws - before:
                    pp = tab[p][0]
                    if pp != s.proc.pid and pp in ws and (pp, p) not in cands:
                        cands[(pp, p)] = (nondumpable(pp), nondumpable(p))
                time.sleep(0.005)
            th.join()
            time.sleep(0.3)
            for (pp, p), v in cands.items():
                if alive(pp) and not alive(p):
                    return (pp, p), v
        return (None, None), (None, None)

    def new_workers(self, s, before, settle=0.3):
        time.sleep(settle)
        return {p for p in s.workers() - before if alive(p)}

    # ---------------------------------------------------------------- family: boot (fail closed) + config dump
    def check_config(self, cfg, pin=None):
        p = os.path.join(self.dir, f"cc-{secrets.token_hex(3)}.json")
        with open(p, "w") as f:
            json.dump(cfg, f)
        r = subprocess.run(taskset(pin) + self.cmd + ["check-config", p, "--print-effective"], capture_output=True,
                           timeout=30, env=self.subject_env())
        doc = None
        for ln in r.stdout.decode(errors="replace").splitlines():
            ln = ln.strip()
            if ln.startswith("{"):
                try:
                    doc = json.loads(ln)
                except ValueError:
                    pass
        return r.returncode, doc

    def boot_refused(self, name, cfg, env=None):
        s = Subject(self, cfg, env_extra=env)
        s.start(wait=False)
        listened = False
        until = time.time() + 15
        while time.time() < until and s.proc.poll() is None:
            for port in (s.port, s.aport):
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                    listened = True
                except OSError:
                    pass
            time.sleep(0.05)
        if s.proc.poll() is None:
            self.check(f"boot.{name}.exit78", False, "subject booted (still running after 15 s)")
        else:
            self.check(f"boot.{name}.exit78", s.proc.returncode == 78, f"exit {s.proc.returncode}: {s.tail()[-300:]}")
        self.check(f"boot.{name}.never-listened", not listened, "accepted a connection")
        s.kill()

    def boot_family(self):
        # effective defaults (D7 3/60/600, D1 forkwasm, D6 fuel/wall/memory) read from the config dump
        rc, doc = self.check_config(self.config(["echo_a"], omit_defaults=True))
        p2 = (doc or {}).get("p2") or {}
        self.check("dump.defaults.exit0", rc == 0, f"check-config exit {rc}")
        for k, v in DEFAULTS.items():
            self.check(f"dump.defaults.{k}", p2.get(k) == v, f"effective p2.{k} = {p2.get(k)!r}, want {v!r}")
        rc, doc = self.check_config(self.config(["echo_a"], isolation="cordon", cb=CB_SCALED))
        p2 = (doc or {}).get("p2") or {}
        self.check("dump.scaled.crash_budget", rc == 0 and p2.get("crash_budget") == CB_SCALED,
                   f"exit {rc}, effective crash_budget {p2.get('crash_budget')!r}")
        self.check("dump.scaled.isolation", p2.get("isolation") == "cordon", f"{p2.get('isolation')!r}")

        def mut(fn, kinds=("echo_a",)):
            c = self.config(list(kinds))
            fn(c)
            return c

        self.boot_refused("missing-worker", mut(lambda c: c["p2"].__setitem__("worker", "/nonexistent/aegis-p2-e2e")))
        self.boot_refused("digest-mismatch",
                          mut(lambda c: c["p2"]["modules"][0].__setitem__("sha256", "0" * 64)))
        self.boot_refused("undeclared-module",
                          mut(lambda c: c["vhosts"][0]["routes"][0]["to"].__setitem__("wasm", "nope")))
        self.boot_refused("wasm-route-without-p2", mut(lambda c: c.pop("p2")))
        # F8 cannot express a cordon shared by principals (D1): every attempt is a refused config
        shared = {
            "p2-cordon-shared": lambda c: c["p2"].__setitem__("cordon", "shared"),
            "p2-shared-cordon-true": lambda c: c["p2"].__setitem__("shared_cordon", True),
            "p2-cordon-key-tenant": lambda c: c["p2"].__setitem__("cordon_key", "tenant"),
            "module-cordon-shared": lambda c: c["p2"]["modules"][0].__setitem__("cordon", "shared"),
            "module-tenancy-shared": lambda c: c["p2"]["modules"][0].__setitem__("tenancy", "shared"),
            "module-principals-any": lambda c: c["p2"]["modules"][0].__setitem__("principals", ["*"]),
            "route-p2-cordon": lambda c: c["vhosts"][0]["routes"][0].__setitem__("p2", {"cordon": "shared"}),
        }
        for n, fn in shared.items():
            self.boot_refused(f"shared-cordon.{n}", mut(fn))
        # Landlock ABI < 4 refuses P2 (D2), simulated through the test-hooks worker's ABI override
        if not self.test_worker:
            self.check("boot.landlock-abi3.exit78", False, "needs --test-worker (test-hooks aegis-p2)")
            return
        cfg = self.config(["echo_a"], worker=self.test_worker)
        self.boot_refused("landlock-abi3", cfg, env={"AEGIS_P2_TEST_LANDLOCK_ABI": "3"})
        s = Subject(self, self.config(["echo_a"], worker=self.test_worker),
                    env_extra={"AEGIS_P2_TEST_LANDLOCK_ABI": "4"})
        try:
            s.start()
            self.answer(s, "boot.landlock-abi4-control.serves", "echo_a", self.tenant())
        except RuntimeError as e:
            self.check("boot.landlock-abi4-control.serves", False, f"control boot (ABI 4) failed: {e}")
        s.stop()

    # ---------------------------------------------------------------- family: main (forkwasm, budget, reload switch)
    def main_family(self):
        cfg = self.config(GOLDEN_KINDS, isolation="forkwasm", cb=CB_SCALED)
        s = Subject(self, cfg)
        s.start()
        P = [self.tenant() for _ in range(4)]
        self.answers(s, "wasm.forkwasm", P)
        (zyg, child), (dz, dc) = self.find_zygote(s, None)
        if self.check("wasm.forkwasm.zygote-observed", zyg is not None, "no fork child of a worker seen during spin"):
            self.check("dumpable.forkwasm-zygote", dz is not False, f"zygote {zyg}")
            self.check("dumpable.forkwasm-child", dc is not False, f"fork child {child}")
        self.check_dumpable("forkwasm-workers", s.workers())
        self.budget(s, "forkwasm")

        # reload switches the default path: forkwasm -> cordon (no rebuild, same route)
        cfg2 = json.loads(json.dumps(cfg))
        cfg2["p2"]["isolation"] = "cordon"
        if not self.check("reload.to-cordon.applied", s.reload(cfg2), "reload counter did not advance"):
            return s.stop()
        Q = [self.tenant() for _ in range(3)]
        self.answers(s, "reload.to-cordon", Q)
        R = [self.tenant() for _ in range(3)]
        for i, t in enumerate(R):
            before = s.workers()
            self.answer(s, f"reload.to-cordon.fresh-principal.answer", "echo_a", t)
            new = self.new_workers(s, before)
            self.check(f"reload.to-cordon.cordon-per-principal.{i}", bool(new),
                       "no new long-lived worker for a new principal after switching to cordon")
        self.check_dumpable("cordon-workers-after-reload", s.workers())
        # and back: cordon -> forkwasm
        if not self.check("reload.to-forkwasm.applied", s.reload(cfg), "reload counter did not advance"):
            return s.stop()
        self.answers(s, "reload.to-forkwasm", P[:2] + Q[:1])
        (zyg2, _), _ = self.find_zygote(s, None)
        self.check("reload.to-forkwasm.zygote-observed", zyg2 is not None, "no fork child of a worker during spin")
        s.stop()

    def budget(self, s, label):
        """D7 with scaled knobs: per-principal, crash-attributable only, sliding window, penalty, expiry."""
        A, B = self.tenant(), self.tenant()
        W, PEN = CB_SCALED["window_s"], CB_SCALED["penalty_s"]
        for i in range(CB_SCALED["crashes"] + 1):
            self.status(s, f"budget.{label}.deny-is-403", "/deny/", A, 403)
        self.answer(s, f"budget.healthy-not-counted.{label}", "echo_a", A)
        t0 = time.monotonic()
        for _ in range(CB_SCALED["crashes"] - 1):
            self.status(s, f"budget.{label}.trap-is-deny", "/trap/", A, 403)
        self.answer(s, f"budget.{label}.below-threshold", "echo_a", A)
        time.sleep(max(0.0, t0 + W + 1.0 - time.monotonic()))
        self.status(s, f"budget.{label}.trap-is-deny", "/trap/", A, 403)
        self.answer(s, f"budget.{label}.sliding-window", "echo_a", A)
        t1 = time.monotonic()
        for _ in range(CB_SCALED["crashes"] - 1):
            self.status(s, f"budget.{label}.trap-is-deny", "/trap/", A, 403)
        t3 = time.monotonic()
        if t3 - t1 > W - 0.5:
            self.check(f"budget.{label}.timing", False, f"3 traps took {t3 - t1:.2f} s, window {W} s: cannot judge "
                       f"(load {os.getloadavg()[0]:.1f})")
        self.status(s, f"budget.exhausted-429.{label}", "/a/", A, 429)
        self.status(s, f"budget.exhausted-429.{label}.any-route", "/trap/", A, 429)
        self.answer(s, f"budget.other-principal-unaffected.{label}", "echo_a", B)
        self.status(s, f"budget.other-principal.{label}.trap-is-deny", "/trap/", B, 403)
        self.answer(s, f"budget.other-principal-own-count.{label}", "echo_a", B)
        time.sleep(max(0.0, t3 + PEN + 1.0 - time.monotonic()))
        self.answer(s, f"budget.penalty-expires.{label}", "echo_a", A)

    # ---------------------------------------------------------------- family: one cordon per principal
    def cordon_family(self):
        s = Subject(self, self.config(GOLDEN_KINDS, isolation="cordon", cb=CB_SCALED))
        s.start()
        P = [self.tenant() for _ in range(4)]
        owned = {}
        for i, t in enumerate(P):
            before = s.workers()
            self.answer(s, "wasm.cordon.answer", "echo_a", t)
            new = self.new_workers(s, before)
            owned[t] = new
            self.check(f"cordon.per-principal.{i}", bool(new),
                       f"principal {i}: no new cordon process (live workers {sorted(s.workers())})")
        self.answers(s, "wasm.cordon", P)
        self.check_dumpable("cordons", s.workers())
        live = s.workers()
        self.check("cordon.per-principal.count", all(owned[t] & live for t in P) and len(set().union(*owned.values()))
                   >= len(P), f"cordons {owned}")
        # killing one principal's cordon touches no other principal
        if owned[P[0]]:
            snap = s.workers()  # an eager respawn after the kill must still show up as a fresh pid
            for p in owned[P[0]]:
                os.kill(p, signal.SIGKILL)
            time.sleep(0.2)
            self.answer(s, "cordon.kill-isolated.other-serves", "echo_a", P[1])
            self.check("cordon.kill-isolated.other-cordon-intact", all(alive(p) for p in owned[P[1]]),
                       "another principal's cordon died when one cordon was killed")
            ok, until = False, time.time() + 10
            before = snap
            while not ok and time.time() < until:
                ok = s.c.get("/a/x?n=1", self.token(P[0])).status == 200
                if not ok:
                    time.sleep(0.2)
            self.check("cordon.respawn-after-kill.serves", ok, "killed principal's requests never recovered")
            new = self.new_workers(s, before)
            self.check("cordon.respawn-after-kill.new-process", bool(new) and not (new & owned[P[0]]),
                       f"no fresh cordon after kill (new {new})")
        # the budget is per principal on this path too
        A, B = P[2], P[3]
        for _ in range(CB_SCALED["crashes"]):
            self.status(s, "budget.cordon.trap-is-deny", "/trap/", A, 403)
        self.status(s, "budget.exhausted-429.cordon", "/a/", A, 429)
        self.answer(s, "budget.other-principal-unaffected.cordon", "echo_a", B)
        s.stop()

    # ---------------------------------------------------------------- family: isolation "auto" (PLAN-5 D23 option b)
    def auto_family(self):
        """The default `p2.isolation` ("auto") resolves from the usable CPU count (the affinity set): < 8 -> cordon,
        else forkwasm. Judged on the dump (configured and effective path, CPU count) at 1, 4, 7 and 8 CPUs, and on
        the serving process tree under `taskset` at 4 CPUs (cordon per principal, no zygote) and 8 CPUs (zygote)."""
        if not shutil.which("taskset"):
            self.check("auto.harness", False, "taskset (util-linux) not found: cannot pin the subject's CPU set")
            return
        aff = sorted(os.sched_getaffinity(0))
        cfg = self.config(["echo_a", "echo_b", "spin"], isolation=None, cb=CB_LOOSE)
        for n in (1, SMALL_CPUS, AUTO_CORDON_BELOW - 1, AUTO_CORDON_BELOW):
            want = "cordon" if n < AUTO_CORDON_BELOW else "forkwasm"
            label = "auto.small" if want == "cordon" else "auto.large"
            if n > len(aff):
                if want == "forkwasm" or n == SMALL_CPUS:
                    self.check(f"{label}.dump.cpus{n}", False,
                               f"this host gives the oracle only {len(aff)} usable CPUs; the {n}-CPU half of D23(b) "
                               f"cannot be judged here (run on the laptop or the desktop)")
                continue
            rc, doc = self.check_config(cfg, pin=aff[:n])
            p2 = (doc or {}).get("p2") or {}
            got = (p2.get("isolation"), p2.get("isolation_effective"), p2.get("usable_cpus"))
            self.check(f"{label}.dump.cpus{n}", rc == 0 and got == ("auto", want, n),
                       f"exit {rc}; (isolation, isolation_effective, usable_cpus) = {got!r}, want ('auto', {want!r}, "
                       f"{n})")
        # explicit values are used as written, whatever the host
        for iso, n in (("forkwasm", 1), ("cordon", len(aff))):
            rc, doc = self.check_config(self.config(["echo_a"], isolation=iso, cb=CB_LOOSE), pin=aff[:n])
            p2 = (doc or {}).get("p2") or {}
            self.check(f"auto.explicit-{iso}.dump", rc == 0 and p2.get("isolation") == iso and
                       p2.get("isolation_effective") == iso, f"exit {rc}; {p2.get('isolation')!r} -> "
                       f"{p2.get('isolation_effective')!r} at {n} CPUs")
        # serving, VPS-class shape: cordon per principal, no fork child of a worker
        if len(aff) >= SMALL_CPUS:
            self.auto_serve(aff[:SMALL_CPUS], "cordon")
        if len(aff) >= AUTO_CORDON_BELOW:
            self.auto_serve(aff[:AUTO_CORDON_BELOW], "forkwasm")
        else:
            self.check("auto.large.serve", False, f"this host gives the oracle only {len(aff)} usable CPUs; the "
                       f">= {AUTO_CORDON_BELOW}-CPU half of D23(b) cannot be judged here (FAIL, not skip)")

    def auto_serve(self, cpus, want):
        label = "auto.small" if want == "cordon" else "auto.large"
        n = len(cpus)
        s = Subject(self, self.config(["echo_a", "echo_b", "spin"], isolation=None, cb=CB_LOOSE), pin=cpus)
        s.start()
        log = s.text()
        self.check(f"{label}.boot-log", f"isolation auto -> {want}" in log and f"{n} usable CPUs" in log,
                   f"no 'isolation auto -> {want}' / '{n} usable CPUs' line in the subject log: {log[-400:]!r}")
        # warm-up by a throwaway principal: a subject may start its zygote lazily on the first request
        self.answer(s, f"{label}.answer", "echo_a", self.tenant())
        P = [self.tenant() for _ in range(3)]
        owned = {}
        for i, t in enumerate(P):
            before = s.workers()
            self.answer(s, f"{label}.answer", "echo_a", t)
            owned[t] = self.new_workers(s, before)
        self.answers(s, label, P)
        (zyg, _), _ = self.find_zygote(s, None)
        if want == "cordon":
            for i, t in enumerate(P):
                self.check(f"{label}.cordon-per-principal.{i}", bool(owned[t]),
                           f"{n} CPUs: principal {i}'s first request made no new long-lived worker (not cordon)")
            self.check(f"{label}.no-zygote", zyg is None,
                       f"{n} CPUs: a fork child of worker {zyg} served a spin request (forkwasm, want cordon)")
        else:
            self.check(f"{label}.zygote-observed", zyg is not None,
                       f"{n} CPUs: no fork child of a worker seen during spin (want forkwasm)")
            self.check(f"{label}.no-cordon-per-principal", not any(owned.values()),
                       f"{n} CPUs: new principals got new long-lived workers {owned} (cordon, want forkwasm)")
        self.check_dumpable(f"auto-{want}-workers", s.workers())
        s.stop()

    # ---------------------------------------------------------------- family: exec respawn (test-hooks worker)
    def respawn_family(self):
        if not self.test_worker:
            self.check("respawn.zygote.load-base-changed", False, "needs --test-worker (test-hooks aegis-p2)")
            return
        kinds = ["echo_a", "spin", "abort"]
        s = Subject(self, self.config(kinds, isolation="forkwasm", cb=CB_LOOSE, worker=self.test_worker))
        s.start()
        T = self.tenant()

        def base_after_echo(name):
            off = s.log_offset()
            self.answer(s, f"{name}.answer", "echo_a", T)
            time.sleep(0.1)
            ls = s.layouts(off)
            self.check(f"{name}.layout-reported", bool(ls), "no aegis-p2-layout line for the request")
            return ls[-1] if ls else None

        l1 = base_after_echo("respawn.zygote.before")
        (z1, _), (dz1, _) = self.find_zygote(s, T)
        if not self.check("respawn.zygote.observed", z1 is not None, "no zygote found"):
            return s.stop()
        os.kill(z1, signal.SIGKILL)
        ok, until = False, time.time() + 10
        while not ok and time.time() < until:
            ok = s.c.get("/a/x?n=1", self.token(T)).status == 200
            if not ok:
                time.sleep(0.1)
        self.check("respawn.zygote.serves-after-kill", ok, "no healthy answer within 10 s of the zygote's death")
        l2 = base_after_echo("respawn.zygote.after")
        (z2, _), (dz2, _) = self.find_zygote(s, T)
        self.check("respawn.zygote.pid-changed", z2 is not None and z2 != z1, f"zygote {z1} -> {z2}")
        self.check("respawn.zygote.old-gone", not alive(z1), f"old zygote {z1} still alive")
        self.check("respawn.zygote.load-base-changed", l1 is not None and l2 is not None and l1[1] != l2[1],
                   f"load base {l1} -> {l2} (a replacement must be a fresh execve, D8)")
        self.check("dumpable.respawned-zygote", dz2 is not False, f"zygote {z2}")
        self.status(s, "respawn.abort-is-deny", "/abort/", T, 403)
        (z3, _), _ = self.find_zygote(s, T)
        self.check("respawn.zygote.survives-child-abort", z3 is not None and z3 == z2, f"zygote {z2} -> {z3}")
        s.stop()

        s = Subject(self, self.config(["echo_a", "abort"], isolation="cordon", cb=CB_LOOSE, worker=self.test_worker))
        s.start()
        before = s.workers()
        off = s.log_offset()
        self.answer(s, "respawn.cordon.before.answer", "echo_a", T)
        c1 = self.new_workers(s, before, settle=0.2)
        ls1 = [x for x in s.layouts(off) if x[0] in c1]
        self.check("respawn.cordon.before.layout-reported", bool(ls1), f"no layout line from cordon {c1}")
        off = s.log_offset()
        before = s.workers()
        self.status(s, "respawn.abort-is-deny.cordon", "/abort/", T, 403)
        ok, until = False, time.time() + 10
        while not ok and time.time() < until:
            ok = s.c.get("/a/x?n=1", self.token(T)).status == 200
            if not ok:
                time.sleep(0.1)
        self.check("respawn.cordon.serves-after-death", ok, "no healthy answer within 10 s of the cordon's death")
        c2 = self.new_workers(s, before, settle=0.2)
        ls2 = [x for x in s.layouts(off) if x[0] in c2]
        self.check("respawn.cordon.pid-changed", bool(c2) and not (c2 & c1), f"cordon {c1} -> {c2}")
        self.check("respawn.cordon.old-gone", not any(alive(p) for p in c1), f"old cordon {c1} alive")
        self.check("respawn.cordon.load-base-changed", bool(ls1) and bool(ls2) and ls1[-1][1] != ls2[-1][1],
                   f"layout {ls1[-1:]} -> {ls2[-1:]}")
        self.check_dumpable("respawned-cordon", c2)
        s.stop()


# ------------------------------------------------------------------------------------------------ main


def taskset(cpus):
    """argv prefix that starts a process on exactly these CPUs (empty when not pinning)."""
    return ["taskset", "-c", ",".join(str(c) for c in cpus)] if cpus else []


def subject_cmd(s):
    if s.endswith(".py"):
        return [sys.executable, "-I", os.path.abspath(s)]
    parts = shlex.split(s)
    parts[0] = os.path.abspath(parts[0]) if os.path.exists(parts[0]) else parts[0]
    return parts


def ref_workers(d):
    """Wrappers for the reference worker: <d>/aegis-p2 (golden) and <d>/aegis-p2-test (test-hooks)."""
    os.makedirs(d, exist_ok=True)
    out = []
    for name, hooks in (("aegis-p2", False), ("aegis-p2-test", True)):
        p = os.path.join(d, name)
        with open(p, "w") as f:
            f.write("#!/bin/sh\n" + ("export AEGIS_REF_TEST_HOOKS=1\n" if hooks else "") +
                    f"exec {shlex.quote(sys.executable)} -I {shlex.quote(os.path.join(HERE, 'ref_worker.py'))} \"$@\"\n")
        os.chmod(p, 0o755)
        out.append(p)
    return out


def summary(r):
    return f"{r.passed} checks" + ("; " + "; ".join(r.notes) if r.notes else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--subject", default=None, help="aegis (feature p2); default: the reference ref_subject.py")
    ap.add_argument("--worker", default=None, help="aegis-p2 release worker (required with --subject)")
    ap.add_argument("--test-worker", default=None, help="aegis-p2 built with test-hooks (respawn + Landlock)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--mutant-subject", default=None)
    ap.add_argument("--mutant-worker", default=None)
    ap.add_argument("--mutant-test-worker", default=None, help="default: --mutant-worker (README 'Self-test')")
    ap.add_argument("--families", default=None, help="comma list of boot,main,cordon,auto,respawn (debugging only)")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    fams = set(a.families.split(",")) if a.families else None
    print(f"load average {os.getloadavg()[0]:.2f} {os.getloadavg()[1]:.2f} {os.getloadavg()[2]:.2f}", flush=True)
    wdir = tempfile.mkdtemp(prefix="aegis-p2-e2e-bin-")
    try:
        return _main(a, fams, wdir)
    finally:
        shutil.rmtree(wdir, ignore_errors=True)


def _main(a, fams, wdir):
    ref = os.path.join(HERE, "ref_subject.py")
    if not a.self_test:
        if a.subject:
            # ci/oracles.sh passes only --subject (default-subject): the workers default to the gate's build dirs.
            a.worker = a.worker or os.path.join(os.path.dirname(os.path.abspath(a.subject)), "aegis-p2")
            dflt_tw = os.path.join(REPO, "target", "p2-test", "release", "aegis-p2")
            a.test_worker = a.test_worker or (dflt_tw if os.access(dflt_tw, os.X_OK) else None)
            if not os.access(a.worker, os.X_OK):
                print(f"{NAME}: FAIL (worker {a.worker} missing; pass --worker)")
                return 1
            try:
                guests = build_guests()
            except (RuntimeError, ValueError, OSError) as e:
                print(f"{NAME}: FAIL (guests: {e})")
                return 1
            r = Run(subject_cmd(a.subject), os.path.abspath(a.worker),
                    os.path.abspath(a.test_worker) if a.test_worker else None, guests, verbose=a.verbose,
                    families=fams)
        else:
            print("subject: reference (ref_subject.py + ref_worker.py)")
            w, tw = ref_workers(wdir)
            r = Run(subject_cmd(ref), w, tw, ref_guests(), verbose=a.verbose, families=fams)
        if r.run():
            print(f"{NAME}: PASS ({summary(r)})")
            return 0
        print(f"{NAME}: FAIL ({len(r.failures)} failed: {', '.join(r.failures[:8])})")
        return 1

    if a.subject or a.mutant_subject:
        subj = a.mutant_subject or os.path.join(REPO, "target", "p2-mutants", "release", "aegis")
        wk = a.mutant_worker or os.path.join(REPO, "target", "p2-mutants", "release", "aegis-p2")
        twk = a.mutant_test_worker or wk
        for p in (subj, wk, twk):
            if not os.access(p, os.X_OK):
                print(f"{NAME} SELF-TEST: FAIL (missing negative-control build {p}; see gates/phase-5.toml selftest)")
                return 1
        try:
            guests = build_guests()
        except (RuntimeError, ValueError, OSError) as e:
            print(f"{NAME} SELF-TEST: FAIL (guests: {e})")
            return 1
        mk = lambda env=None, quiet=False: Run(subject_cmd(subj), os.path.abspath(wk), os.path.abspath(twk),  # noqa
                                               guests, env_extra=env, verbose=a.verbose, quiet=quiet, families=fams)
        label, parallel = f"{subj} + {wk}", 1
    else:
        w, tw = ref_workers(wdir)
        mk = lambda env=None, quiet=False: Run(subject_cmd(ref), w, tw, ref_guests(), env_extra=env,  # noqa: E731
                                               verbose=a.verbose, quiet=quiet, families=fams)
        label, parallel = "reference ref_subject.py + ref_worker.py", 3
    print(f"self-test subject: {label}", flush=True)
    r = mk()
    if not r.run():
        print(f"{NAME} SELF-TEST: FAIL (the unmutated subject must pass first: {r.failures[:6]})")
        return 1
    print(f"  baseline (no mutant): PASS ({summary(r)})", flush=True)

    def one(m):
        rr = mk({"AEGIS_P2_MUTANT": m}, quiet=True)
        rr.run()
        return m, rr
    bad = []
    with concurrent.futures.ThreadPoolExecutor(parallel) as ex:
        for m, rr in ex.map(one, list(MUTANTS)):
            exp = [f for f in rr.failures if f.startswith(MUTANTS[m])]
            if not rr.failures:
                print(f"  mutant {m}: NOT caught", flush=True)
                bad.append(m)
            elif not exp:
                print(f"  mutant {m}: red only on unexpected checks ({', '.join(rr.failures[:5])}); "
                      f"expected a {MUTANTS[m]}* failure", flush=True)
                bad.append(m)
            else:
                print(f"  mutant {m}: caught by {len(rr.failures)} checks, expected family: "
                      f"{', '.join(sorted(set(exp))[:4])}", flush=True)
    if bad:
        print(f"{NAME} SELF-TEST: FAIL (not caught as expected: {', '.join(bad)})")
        return 1
    print(f"{NAME} SELF-TEST: PASS ({len(MUTANTS)}/{len(MUTANTS)} mutants red on their expected checks, "
          f"baseline green on {r.passed} checks; subject {label})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
