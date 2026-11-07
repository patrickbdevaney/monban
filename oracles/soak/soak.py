"""AEGIS soak oracle (unit P8-soak-001, PREFLIGHT D-P8.4, F1 SOAK-1; gate `soak`). stdlib only; run through ./run.

Boots aegis (features native, proxy-protocol, mtc) with a config that turns on a PROXY v2 listener, the MTC
CredentialSelector (tls.credentials: one mtc + one x509 credential), a reverse-proxy route and a SQLite native route
(apps/notes; no crdb, no external engine), plus the aegis-otlp sidecar exporting to an in-process collector. It
measures the full path's throughput, then holds h2load at 50% of it for --hours, sampling RSS, open fds and tasks
(threads) of aegis and aegis-otlp from /proc every 10 s and the admin /metrics every 60 s. It passes when:

  rss.slope      Theil-Sen RSS slope <= 1 MiB/h per process, over the samples after the warm-up (15 min; a run
                 shorter than 1 h warms up for a quarter of its length);
  fds/tasks      open fds and tasks of each process are back to the post-warm-up baseline +-5 within 180 s after
                 load stops;
  errors         0: h2load failed/errored/timeout/non-2xx, PROXY shim errors, aegis admission rejects, proxy upstream
                 errors, canon rejects and authz denials (metrics deltas), aegis error log lines, a non-zero exit on
                 SIGTERM (aegis or aegis-otlp), a dead process;
  load           every h2load segment delivered >= 80% of the target rate;
  otlp           the collector received metrics exports in the last quarter of the load;
  audit          the aegis audit log verifies (oracles/tlog-verify, the independent Go verifier).

    run [--hours H] [--record FILE] [--aegis BIN --otlp BIN] [--aegis-cpus N] [--client-cpus N]
    run --hours 24                 record-only variant: last line SOAK: RECORD (...), exit 0 once the report is written
    run --self-test                negative controls on fake subjects in scaled time (no build, light)
"""
import argparse
import base64
import datetime
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
TAG = "SOAK"
MIB = 1 << 20
VHOST = "aegis.test"

# D-P8.4 thresholds (never moved by the runner or the duration).
RSS_SLOPE_MIB_H = 1.0
BASELINE_TOL = 5
WARMUP_S = 900.0
SETTLE_S = 180.0
SAMPLE_S = 10.0
METRICS_S = 60.0
LOAD_FLOOR = 0.80
LOAD_FRACTION = 0.50
MAX_STREAMS_PER_CONN = 100_000       # F8 limits.max_streams_per_conn maximum
PER_CONN_RPS = 200                   # soak connections are sized so one segment stays far below that cap
ERROR_COUNTERS = ("aegis_admission_rejects", "aegis_proxy_upstream_errors", "aegis_proxy_canon_rejects",
                  "aegis_proxy_authz_denied", "aegis_crash_budget_trips")
ERROR_LOG = re.compile(r"panic|error|fail|upstream |refused|denied", re.I)


def log(msg):
    print(f"{TAG}: {msg}", flush=True)


# ------------------------------------------------------------------------------------------------ clock

class Clock:
    """Virtual seconds since start. scale 1 is real time; the self-test runs the same code at scale > 1."""

    def __init__(self, scale=1.0):
        self.scale = float(scale)
        self.t0 = time.monotonic()

    def now(self):
        return (time.monotonic() - self.t0) * self.scale

    def sleep(self, v):
        if v > 0:
            time.sleep(v / self.scale)

    def real(self, v):
        return v / self.scale


# ------------------------------------------------------------------------------------------------ /proc + metrics

def proc_sample(pid):
    """(rss bytes, open fds, tasks) of a live pid; None once it is gone."""
    try:
        rss = None
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1]) * 1024
        fds = len(os.listdir(f"/proc/{pid}/fd"))
        tasks = len(os.listdir(f"/proc/{pid}/task"))
    except (OSError, ValueError):
        return None
    if rss is None:
        return None
    return rss, fds, tasks


def http_get(port, path, timeout=5):
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as c:
        c.sendall(f"GET {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n".encode())
        buf = b""
        while True:
            b = c.recv(65536)
            if not b:
                break
            buf += b
    head, _, body = buf.partition(b"\r\n\r\n")
    parts = head.split(b" ", 2)
    return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0, body.decode(errors="replace")


def counters(text):
    """{family: summed value} of every `<family>_total` sample in OpenMetrics text."""
    out = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        try:
            name, val = line.rsplit(" ", 1)
            v = float(val)
        except ValueError:
            continue
        fam = name.split("{", 1)[0]
        if fam.endswith("_total"):
            fam = fam[:-6]
            out[fam] = out.get(fam, 0.0) + v
    return out


# ------------------------------------------------------------------------------------------------ judge

def theil_sen(points, cap=1200):
    """Median of pairwise slopes (robust to allocator steps); points [(t, y)], subsampled to `cap` points."""
    if len(points) > cap:
        step = len(points) / cap
        points = [points[int(i * step)] for i in range(cap)]
    slopes = []
    n = len(points)
    for i in range(n):
        ti, yi = points[i]
        for k in range(i + 1, n):
            tk, yk = points[k]
            if tk != ti:
                slopes.append((yk - yi) / (tk - ti))
    if not slopes:
        return None
    slopes.sort()
    m = len(slopes)
    return slopes[m // 2] if m % 2 else (slopes[m // 2 - 1] + slopes[m // 2]) / 2


def ols(points):
    n = len(points)
    if n < 2:
        return None
    mt = sum(t for t, _ in points) / n
    my = sum(y for _, y in points) / n
    den = sum((t - mt) ** 2 for t, _ in points)
    return sum((t - mt) * (y - my) for t, y in points) / den if den else None


def warmup_for(load_s):
    return WARMUP_S if load_s >= 3600 else load_s / 4.0


def judge(rep):
    """Verdict from the report alone: (failures, notes). [] failures = PASS."""
    bad, notes = [], []
    ph = rep.get("phases") or {}
    t0, t1 = ph.get("load_start"), ph.get("load_end")
    if t0 is None or t1 is None or t1 <= t0:
        return ["harness: the load phase did not run"], notes
    w = warmup_for(t1 - t0)
    for name in ("aegis", "otlp"):
        s = (rep.get("samples") or {}).get(name) or []
        pts = [(t, rss / MIB) for t, rss, _, _ in s if t0 + w <= t <= t1]
        if len(pts) < 10:
            bad.append(f"rss.slope.{name}: {len(pts)} samples after the warm-up (< 10)")
            continue
        sl = theil_sen(pts)
        o = ols(pts)
        slope_h, ols_h = sl * 3600.0, (o or 0.0) * 3600.0
        notes.append(f"{name} RSS slope {slope_h:+.3f} MiB/h (OLS {ols_h:+.3f}) over {len(pts)} samples")
        if slope_h > RSS_SLOPE_MIB_H:
            bad.append(f"rss.slope.{name}: {slope_h:+.3f} MiB/h > {RSS_SLOPE_MIB_H} MiB/h")
        base = (rep.get("baseline") or {}).get(name)
        after = (rep.get("after") or {}).get(name)
        if not base or not after:
            bad.append(f"baseline.{name}: not measured")
            continue
        for k in ("fds", "tasks"):
            d = after[k] - base[k]
            notes.append(f"{name} {k} {base[k]} -> {after[k]}")
            if abs(d) > BASELINE_TOL:
                bad.append(f"{k}.{name}: {after[k]} after load vs baseline {base[k]} (|{d:+d}| > {BASELINE_TOL})")
    err = rep.get("errors") or {}
    total = sum(v for v in err.values() if isinstance(v, (int, float)))
    if total:
        bad.append("errors: " + ", ".join(f"{k}={v}" for k, v in sorted(err.items()) if v))
    for e in rep.get("faults") or []:
        bad.append(f"fault: {e}")
    segs = (rep.get("load") or {}).get("segments") or []
    target = (rep.get("load") or {}).get("target_rps") or 0
    if not segs:
        bad.append("load: no h2load segment ran")
    low = [(i, sg.get("req_s", 0)) for i, sg in enumerate(segs) if target and sg.get("req_s", 0) < LOAD_FLOOR * target]
    if low:
        bad.append(f"load.segment: {len(low)}/{len(segs)} segments below {LOAD_FLOOR:.0%} of target {target:.0f} "
                   f"req/s (first: #{low[0][0]} at {low[0][1]:.0f})")
    ot = rep.get("otlp") or {}
    if not ot.get("metrics_last_quarter"):
        bad.append(f"otlp: no metrics export in the last quarter of the load (total {ot.get('metrics_total', 0)})")
    au = rep.get("audit") or {}
    if not au.get("ok"):
        bad.append(f"audit: {au.get('detail', 'not verified')}")
    return bad, notes


# ------------------------------------------------------------------------------------------------ h2load

SUMMARY_RE = re.compile(r"requests: (\d+) total, (\d+) started, (\d+) done, (\d+) succeeded, (\d+) failed, "
                        r"(\d+) errored, (\d+) timeout")
STATUS_RE = re.compile(r"status codes: (\d+) 2xx, (\d+) 3xx, (\d+) 4xx, (\d+) 5xx")
FINISHED_RE = re.compile(r"finished in ([0-9.]+)(m?s), ([0-9.]+) req/s")


def parse_h2load(text):
    s, st, fin = SUMMARY_RE.search(text), STATUS_RE.search(text), FINISHED_RE.search(text)
    if not (s and st and fin):
        raise ValueError("h2load output not understood: " + text[-400:].replace("\n", " | "))
    total, started, done, ok, failed, errored, timeout = (int(x) for x in s.groups())
    s2, s3, s4, s5 = (int(x) for x in st.groups())
    secs = float(fin.group(1)) / (1000.0 if fin.group(2) == "ms" else 1.0)
    return {"req_s": round(s2 / secs, 1) if secs > 0 else 0.0, "secs": secs, "done": done, "status_2xx": s2,
            "non_2xx": s3 + s4 + s5, "failed": failed, "errored": errored, "timeout": timeout,
            "errors": max(failed + errored + timeout, s3 + s4 + s5)}


def h2load_fetch():
    root = os.path.join(os.environ.get("AEGIS_TOOLS") or os.path.expanduser("~/.cache/aegis-tools"),
                        "h2load-1.69.0")
    bin_, ld = os.path.join(root, "usr/bin/h2load"), os.path.join(root, "lib/ld-musl-x86_64.so.1")
    if not (os.path.exists(os.path.join(root, ".complete")) and os.access(ld, os.X_OK)):
        os.makedirs(root, exist_ok=True)
        with open(os.path.join(HERE, "h2load.lock")) as f:
            rows = [ln.split("\t") for ln in f.read().splitlines() if ln and not ln.startswith("#")]
        for name, sha, url in rows:
            req = urllib.request.Request(url, headers={"User-Agent": "aegis-ci"})
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read()
            if hashlib.sha256(data).hexdigest() != sha:
                raise RuntimeError(f"h2load.lock: sha256 mismatch for {name}")
            p = os.path.join(root, name + ".apk")
            with open(p, "wb") as f:
                f.write(data)
            with tarfile.open(p, "r:gz") as t:
                for m in t:
                    if not m.name.startswith("."):
                        t.extract(m, root, filter="data")
            os.remove(p)
        open(os.path.join(root, ".complete"), "w").close()
    return [ld, "--library-path", f"{root}/lib:{root}/usr/lib", bin_]


# ------------------------------------------------------------------------------------------------ helpers

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def cpu_order():
    """Allowed CPUs, ordered so the first k land on k distinct physical cores while possible."""
    allowed = sorted(os.sched_getaffinity(0))
    seen, keyed = {}, []
    for c in allowed:
        base = f"/sys/devices/system/cpu/cpu{c}/topology/"
        try:
            core = (int(open(base + "physical_package_id").read()), int(open(base + "core_id").read()))
        except (OSError, ValueError):
            core = (0, c)
        nth = seen.get(core, 0)
        seen[core] = nth + 1
        keyed.append(((nth, core), c))
    return [c for _, c in sorted(keyed)]


def cpus_str(c):
    return ",".join(str(x) for x in sorted(c))


class Child:
    """A process we started; signalled by its own PID only (never by pattern)."""

    def __init__(self, cmd, logpath, stdin=None, stdout=None, env=None):
        self.logf = open(logpath, "ab")
        e = {k: v for k, v in os.environ.items() if k not in ("NOTIFY_SOCKET", "AEGIS_UPGRADE_DIR",
                                                                "AEGIS_E2E_MUTANT")}
        e.update(env or {})
        self.p = subprocess.Popen(cmd, stdin=stdin, stdout=stdout if stdout is not None else self.logf,
                                  stderr=subprocess.STDOUT, env=e)
        self.pid = self.p.pid

    def alive(self):
        return self.p.poll() is None

    def term(self, wait=15.0):
        """SIGTERM, then the exit code (None if it had to be killed)."""
        if self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(wait)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait(5)
                return None
        return self.p.returncode


class Collector:
    """OTLP/HTTP JSON sink: counts POSTs per signal with their arrival time (virtual), answers 200 {}."""

    def __init__(self, clock):
        self.clock = clock
        self.metrics, self.logs, self.bad = [], [], 0
        col = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(n) if n else b""
                if self.path.endswith("/v1/metrics"):
                    col.metrics.append(col.clock.now())
                elif self.path.endswith("/v1/logs"):
                    col.logs.append(col.clock.now())
                else:
                    col.bad += 1
                del body
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class ProxyShim:
    """h2load -> shim -> aegis. Each accepted connection is re-originated from 127.0.0.2 (a trusted PROXY source)
    and starts with a PROXY v2 PROXY/TCP4 header naming the client's address; then bytes are copied both ways."""

    SIG = b"\r\n\r\n\x00\r\nQUIT\n"

    def __init__(self, target_port, src="127.0.0.2"):
        self.target, self.src = target_port, src
        self.errors = 0
        self.conns = 0
        self.ls = socket.socket()
        self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind(("127.0.0.1", 0))
        self.ls.listen(1024)
        self.port = self.ls.getsockname()[1]
        self.stop = False
        threading.Thread(target=self._accept, daemon=True).start()

    def header(self, c_addr, d_port):
        body = socket.inet_aton(c_addr[0]) + socket.inet_aton("127.0.0.1") + struct.pack("!HH", c_addr[1], d_port)
        return self.SIG + bytes([0x21, 0x11]) + struct.pack("!H", len(body)) + body

    def _accept(self):
        while not self.stop:
            try:
                c, addr = self.ls.accept()
            except OSError:
                return
            threading.Thread(target=self._conn, args=(c, addr), daemon=True).start()

    def _conn(self, c, addr):
        self.conns += 1
        u = socket.socket()
        try:
            u.bind((self.src, 0))
            u.connect(("127.0.0.1", self.target))
            for s in (c, u):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            u.sendall(self.header(addr, self.port))
        except OSError:
            self.errors += 1
            c.close()
            u.close()
            return
        t = threading.Thread(target=self._pipe, args=(u, c), daemon=True)
        t.start()
        self._pipe(c, u)
        t.join()
        c.close()
        u.close()

    @staticmethod
    def _pipe(a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except OSError:
            pass
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def close(self):
        self.stop = True
        self.ls.close()


# ------------------------------------------------------------------------------------------------ F5 token (Tier-L)

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


def mint(master, kid, tenant, exp_delta, ops=31, aud=VHOST):
    """F5 token-l (interfaces/F5-token.cddl; the same construction as oracles/native-e2e mint)."""
    prk = hmac.new(b"", master, hashlib.sha256).digest()
    a = aud.encode()
    info = b"aegis-cap-v1" + struct.pack("!H", len(a)) + a + struct.pack("!H", len(kid)) + kid
    k_aud = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    nonce = secrets.token_bytes(16)
    cavs = [[0, aud], [1, int(time.time()) + int(exp_delta)], [8, 2], [3, ops], [6, tenant]]
    t = hmac.new(k_aud, kid + nonce, hashlib.sha256).digest()
    for c in cavs:
        t = hmac.new(t, cbor(c), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(cbor([1, kid, nonce, cavs, t])).rstrip(b"=").decode()


# ------------------------------------------------------------------------------------------------ the real setup

class RealSetup:
    """aegis + aegis-otlp + upstream + PROXY shim on this host."""

    def __init__(self, args, clock, work):
        self.a, self.clock, self.d = args, clock, work
        self.children = []
        self.err_lines = []
        self.log_lines = 0
        self.faults = []
        self.notes = []

    # -- build / tools
    def build(self):
        heavy = os.path.join(REPO, "ci", "heavy.sh")
        env = dict(os.environ, CARGO_TARGET_DIR=os.path.join(REPO, "target", "soak"))
        if not (self.a.aegis and self.a.otlp):
            subprocess.run([heavy, "cargo", "build", "--release", "--locked", "-q", "-p", "aegis-bin", "--bin",
                            "aegis", "--features", "aegis-bin/native,aegis-bin/proxy-protocol,aegis-bin/mtc",
                            "-p", "aegis-otlp"], cwd=REPO, check=True, env=env)
            self.a.aegis = self.a.aegis or os.path.join(REPO, "target", "soak", "release", "aegis")
            self.a.otlp = self.a.otlp or os.path.join(REPO, "target", "soak", "release", "aegis-otlp")
        os.makedirs(os.path.join(REPO, "target", "soak"), exist_ok=True)
        self.upstream = os.path.join(REPO, "target", "soak", "soak-upstream")
        subprocess.run([heavy, "rustc", "-O", "--edition", "2021", "-o", self.upstream,
                        os.path.join(HERE, "upstream.rs")], cwd=REPO, check=True)
        self.h2load = self.a.h2load.split() if self.a.h2load else h2load_fetch()

    def cpus(self):
        order = cpu_order()
        need = self.a.aegis_cpus + self.a.client_cpus + 1
        if need > len(order):
            raise RuntimeError(f"{self.a.aegis_cpus} aegis + {self.a.client_cpus} h2load + 1 aux CPUs > "
                               f"{len(order)} CPUs (pass --aegis-cpus/--client-cpus for a smaller host)")
        self.cs = {"aegis": order[:self.a.aegis_cpus],
                   "h2load": order[len(order) - self.a.client_cpus:],
                   "aux": order[self.a.aegis_cpus:len(order) - self.a.client_cpus]}
        return {k: cpus_str(v) for k, v in self.cs.items()}

    # -- config
    def files(self):
        d = self.d
        self.crt, self.key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
        for crt, key, cn in ((self.crt, self.key, VHOST), (os.path.join(d, "mtc-key-cert.pem"),
                                                          os.path.join(d, "mtc.key"), "mtc")):
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                            "-nodes", "-keyout", key, "-out", crt, "-days", "30", "-subj", f"/CN={cn}",
                            "-addext", f"subjectAltName=DNS:{cn}"], check=True, capture_output=True, timeout=60)
        # The mtc credential is an opaque operator blob (D-P7.4): aegis neither parses nor verifies it.
        with open(os.path.join(d, "mtc.chain"), "wb") as f:
            f.write(b"\x00\x01opaque-mtc-for-soak" + secrets.token_bytes(64))
        self.kid, self.master = secrets.token_bytes(8), secrets.token_bytes(32)
        self.keyring = os.path.join(d, "token-keyring.json")
        with open(self.keyring, "w") as f:
            json.dump({"keys": [{"kid": self.kid.hex(), "key": self.master.hex()}]}, f)
        os.chmod(self.keyring, 0o600)
        self.tenant = secrets.randbits(63) | 1
        self.t_hex = f"{self.tenant:016x}"
        import sqlite3
        db = sqlite3.connect(os.path.join(d, "notes.db"))
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE notes(tenant TEXT NOT NULL COLLATE BINARY, id TEXT NOT NULL COLLATE BINARY, "
                   "body TEXT NOT NULL, PRIMARY KEY(tenant,id)) WITHOUT ROWID")
        db.commit()
        db.close()

    def config(self, worker_threads=None):
        cols = ["id", "body"]
        doc = {
            "v": 1,
            "listeners": [{"name": "pub", "bind": f"127.0.0.1:{self.port}", "profile": "P-PUBLIC-WEB",
                           "alpn": ["h2", "http/1.1"], "proxy_protocol": {"trusted": ["127.0.0.2/32"]}}],
            "admin": {"bind": f"127.0.0.1:{self.aport}"},
            "admission": {"per_ip": {"rate_per_s": 1000000, "burst": 10000000}},
            "limits": {"max_streams_per_conn": MAX_STREAMS_PER_CONN},
            "tls": {"credentials": [
                {"id": "mtc-soak", "kind": "mtc", "trust_anchor_id": "32473.1.7",
                 "chain": "path:" + os.path.join(self.d, "mtc.chain"), "key": "path:" + os.path.join(self.d, "mtc.key"),
                 "listeners": ["pub"]},
                {"id": "x509-soak", "kind": "x509", "chain": "path:" + self.crt, "key": "path:" + self.key,
                 "listeners": ["pub"]}]},
            "data": {"backends": [{"id": "sq", "engine": "sqlite", "dsn_ref": "path:" + os.path.join(self.d, "notes.db"),
                                   "pin": "sqlite", "op_budget_ms": 5000}]},
            "vhosts": [{"host": VHOST, "routes": [
                {"id": 1, "path": "/px/", "to": {"upstream": f"127.0.0.1:{self.up_port}"}, "authz": "allow-all"},
                {"id": 2, "path": "/sq/", "to": {"upstream": "app:notes"}, "authz": "allow-all",
                 "data": [{"backend": "sq", "collection": "notes", "ops": ["select", "insert", "update", "delete",
                                                                         "upsert"], "columns": cols}]}]}]}
        if worker_threads:
            doc["runtime"] = {"worker_threads": worker_threads}
        return doc

    def check_config(self, doc):
        p = os.path.join(self.d, "probe.json")
        with open(p, "w") as f:
            json.dump(doc, f)
        r = subprocess.run([self.a.aegis, "check-config", p], capture_output=True, text=True, timeout=60)
        return r.returncode == 0, (r.stdout + r.stderr).strip()[-400:]

    # -- start
    def start(self):
        self.files()
        self.port, self.aport, self.up_port = free_port(), free_port(), free_port()
        doc = self.config()
        ok, msg = self.check_config(doc)
        if not ok:
            raise RuntimeError(f"aegis check-config refused the soak config: {msg}")
        # F8 runtime.worker_threads (D-P8.3) where the binary has it: aegis then uses every CPU it is pinned to.
        wt = self.config(worker_threads=len(self.cs["aegis"]))
        ok, _ = self.check_config(wt)
        if ok:
            doc = wt
            self.notes.append(f"runtime.worker_threads={len(self.cs['aegis'])}")
        else:
            self.notes.append("runtime.worker_threads not in this F8 (binary default)")
        self.cfg = os.path.join(self.d, "aegis.json")
        with open(self.cfg, "w") as f:
            json.dump(doc, f)
        aux = cpus_str(self.cs["aux"])
        self.children.append(Child(["taskset", "-c", aux, self.upstream, str(self.up_port)],
                                   os.path.join(self.d, "upstream.log")))
        self.audit_dir = os.path.join(self.d, "audit")
        os.makedirs(os.path.join(self.d, "run"), exist_ok=True)
        self.aegis = Child(["taskset", "-c", cpus_str(self.cs["aegis"]), self.a.aegis, "--config", self.cfg,
                            "--cert", self.crt, "--key", self.key, "--audit-dir", self.audit_dir,
                            "--runtime-dir", os.path.join(self.d, "run"), "--token-keyring", self.keyring],
                           os.path.join(self.d, "aegis.log"), stdout=subprocess.PIPE)
        self.children.append(self.aegis)
        self.collector = Collector(self.clock)
        self.otlp = Child(["taskset", "-c", aux, self.a.otlp, "--scrape", f"http://127.0.0.1:{self.aport}/metrics",
                           "--endpoint", f"http://127.0.0.1:{self.collector.port}/", "--service-name", "aegis-soak",
                           "--interval-ms", "5000"], os.path.join(self.d, "otlp.log"), stdin=subprocess.PIPE)
        self.children.append(self.otlp)
        threading.Thread(target=self._pump, daemon=True).start()
        until = time.time() + 30
        while True:
            if not self.aegis.alive():
                raise RuntimeError(f"aegis exited {self.aegis.p.returncode} at start: {self.tail('aegis.log')}")
            try:
                if http_get(self.aport, "/healthz")[0] == 200:
                    break
            except OSError:
                pass
            if time.time() > until:
                raise RuntimeError("aegis not healthy within 30 s")
            time.sleep(0.2)
        self.shim = ProxyShim(self.port)
        self.prefill()

    def _pump(self):
        """aegis stdout+stderr -> its log file and aegis-otlp stdin; error-looking lines are counted."""
        out, sink = self.aegis.p.stdout, self.otlp.p.stdin
        for line in iter(out.readline, b""):
            self.aegis.logf.write(line)
            self.aegis.logf.flush()
            self.log_lines += 1
            if self.counting and ERROR_LOG.search(line.decode(errors="replace")):
                self.err_lines.append(line.decode(errors="replace").strip()[:300])
            try:
                sink.write(line)
                sink.flush()
            except (OSError, ValueError):
                pass
        try:
            sink.close()
        except (OSError, ValueError):
            pass

    counting = False

    def prefill(self):
        """Ten notes for the read mix, written directly (127.0.0.1 is not a trusted PROXY source, so no header)."""
        ctx = ssl.create_default_context(cafile=self.crt)
        tok = mint(self.master, self.kid, self.tenant, 600)
        for i in range(10):
            body = json.dumps({"id": f"n{i}", "body": f"soak note {i}"}).encode()
            req = (f"POST /sq/{self.t_hex}/ HTTP/1.1\r\nhost: {VHOST}\r\nauthorization: Bearer {tok}\r\n"
                   f"idempotency-key: prefill-{i}\r\ncontent-type: application/json\r\n"
                   f"content-length: {len(body)}\r\nconnection: close\r\n\r\n").encode() + body
            with socket.create_connection(("127.0.0.1", self.port), timeout=10) as raw:
                with ctx.wrap_socket(raw, server_hostname=VHOST) as s:
                    s.sendall(req)
                    resp = b""
                    while True:
                        b = s.recv(65536)
                        if not b:
                            break
                        resp += b
            st = resp.split(b" ", 2)[1:2]
            if st != [b"201"]:
                raise RuntimeError(f"prefill POST n{i}: {resp[:200]!r}")

    # -- load
    def urls(self):
        base = f"https://{VHOST}:{self.port}"
        return [f"{base}/px/soak", f"{base}/sq/{self.t_hex}/n3"]

    def h2load(self, conns, streams, dur_s, rps=None, warmup=None):
        tok = mint(self.master, self.kid, self.tenant, dur_s + 300)
        t = min(len(self.cs["h2load"]), conns)
        cmd = ["taskset", "-c", cpus_str(self.cs["h2load"])] + self.h2load + [
            f"--connect-to=127.0.0.1:{self.shim.port}", "-t", str(t), "-c", str(conns), "-m", str(streams),
            "-D", str(int(math.ceil(dur_s))), "-H", f"authorization: Bearer {tok}"]
        if rps:
            cmd += ["--rps", str(rps)]
        if warmup:
            cmd += ["--warm-up-time", str(warmup)]
        p = subprocess.run(cmd + self.urls(), capture_output=True, text=True, timeout=dur_s + (warmup or 0) + 120)
        out = p.stdout + p.stderr
        if p.returncode != 0 and not SUMMARY_RE.search(out):
            raise RuntimeError(f"h2load exit {p.returncode}: {out[-400:]}")
        return parse_h2load(out)

    def metrics(self):
        try:
            st, body = http_get(self.aport, "/metrics")
            return counters(body) if st == 200 else None
        except OSError:
            return None

    def pids(self):
        return {"aegis": self.aegis.pid, "otlp": self.otlp.pid}

    def shim_errors(self):
        return self.shim.errors

    def tail(self, name):
        try:
            with open(os.path.join(self.d, name), "rb") as f:
                return f.read()[-800:].decode(errors="replace")
        except OSError:
            return ""

    # -- stop + audit
    def stop(self):
        rc = {"aegis": self.aegis.term(15.0)}
        time.sleep(2.0)   # let the pump hand the last lines to aegis-otlp before it is stopped
        rc["otlp"] = self.otlp.term(10.0)
        for c in self.children:
            c.term(5.0)
        self.shim.close()
        self.collector.close()
        return rc

    def audit(self):
        logs = sorted(x for x in os.listdir(self.audit_dir) if os.path.isdir(os.path.join(self.audit_dir, x)))
        if len(logs) != 1:
            return {"ok": False, "detail": f"{len(logs)} log directories under the audit dir (want 1)"}
        r = subprocess.run([os.path.join(REPO, "oracles", "tlog-verify", "run"), "--subject",
                            f"{os.path.join(HERE, 'audit-copy')} {os.path.join(self.audit_dir, logs[0])}"],
                           capture_output=True, text=True, cwd=REPO, timeout=3600)
        last = ((r.stdout + r.stderr).strip().splitlines() or [""])[-1]
        return {"ok": r.returncode == 0 and last.startswith("TLOG-VERIFY: PASS"), "detail": last[:300]}

    def cleanup(self):
        for c in self.children:
            c.term(5.0)


# ------------------------------------------------------------------------------------------------ the run

def run_soak(setup, clock, hours, record=None, meta=None):
    """Drive one soak against `setup` (RealSetup or the self-test's FakeSetup). Returns the report."""
    load_s = hours * 3600.0
    rep = {"unit": "P8-soak-001", "spec": "PREFLIGHT D-P8.4, F1 SOAK-1", "hours": hours, "scale": clock.scale,
           "thresholds": {"rss_slope_mib_h": RSS_SLOPE_MIB_H, "baseline_tol": BASELINE_TOL,
                          "warmup_s": warmup_for(load_s), "settle_s": SETTLE_S, "load_floor": LOAD_FLOOR,
                          "load_fraction": LOAD_FRACTION},
           "samples": {"aegis": [], "otlp": []}, "metrics": [], "phases": {}, "errors": {}, "faults": [],
           "load": {"segments": []}}
    rep.update(meta or {})
    pids = setup.pids()
    stop_sampling = threading.Event()
    lock = threading.Lock()
    gone = set()

    def sample_once():
        now = clock.now()
        row = {}
        for name, pid in pids.items():
            s = proc_sample(pid)
            if s is None:
                with lock:
                    if name not in gone:
                        gone.add(name)
                        rep["faults"].append(f"{name} not running at t={now:.0f}s")
                continue
            row[name] = s
            with lock:
                rep["samples"][name].append([round(now, 3), s[0], s[1], s[2]])
        return row

    def sampler():
        next_m = 0.0
        while not stop_sampling.is_set():
            sample_once()
            if clock.now() >= next_m:
                m = setup.metrics()
                if m is not None:
                    with lock:
                        rep["metrics"].append([round(clock.now(), 1), {k: m.get(k, 0) for k in ERROR_COUNTERS}])
                next_m = clock.now() + METRICS_S
            stop_sampling.wait(clock.real(SAMPLE_S))

    def settle(stable_n=3, limit=120.0, against=None):
        """Poll every 5 s. Baseline (against None): until fds and tasks are unchanged over stable_n polls.
        After load: until every process is within +-BASELINE_TOL of `against`. Returns the last values."""
        hist, t_end = [], clock.now() + limit
        while True:
            row = sample_once()
            cur = {k: {"fds": v[1], "tasks": v[2], "rss": v[0], "t": round(clock.now(), 1)} for k, v in row.items()}
            hist.append(cur)
            if against is None:
                if len(hist) >= stable_n and all(
                        all(h.get(k, {}).get(f) == cur.get(k, {}).get(f) for h in hist[-stable_n:])
                        for k in pids for f in ("fds", "tasks")):
                    return cur
            elif all(k in cur and abs(cur[k]["fds"] - against[k]["fds"]) <= BASELINE_TOL
                     and abs(cur[k]["tasks"] - against[k]["tasks"]) <= BASELINE_TOL for k in against):
                return cur
            if clock.now() >= t_end:
                return cur
            clock.sleep(5.0)

    # 1. Calibrate: the full path's throughput at full speed (30 s after a 5 s warm-up).
    cal = setup.h2load(conns=64, streams=8, dur_s=clock.real(30.0), warmup=clock.real(5.0))
    rep["load"]["calibration"] = cal
    if cal["errors"] or cal["status_2xx"] == 0:
        rep["faults"].append(f"calibration: {cal['errors']} errors, {cal['status_2xx']} 2xx")
    target = LOAD_FRACTION * cal["req_s"]
    conns = max(8, int(math.ceil(target / PER_CONN_RPS)))
    rps = max(1, int(round(target / conns)))
    seg_s = min(300.0, 0.5 * MAX_STREAMS_PER_CONN / rps)
    rep["load"].update({"target_rps": rps * conns, "conns": conns, "rps_per_conn": rps, "segment_s": seg_s,
                        "streams": 4})
    log(f"calibration {cal['req_s']:.0f} req/s; soak target {rps * conns} req/s ({conns} conns x {rps}/s), "
        f"{hours} h in segments of {seg_s:.0f} s")

    # 2. Baseline after the warm-up of pools and caches, idle.
    clock.sleep(30.0)
    m0 = setup.metrics() or {}
    rep["baseline"] = settle()
    rep["phases"]["baseline"] = clock.now()

    # 3. Steady load in segments; the sampler runs throughout.
    setup.counting = True
    th = threading.Thread(target=sampler, daemon=True)
    th.start()
    rep["phases"]["load_start"] = clock.now()
    t_end = rep["phases"]["load_start"] + load_s
    while clock.now() < t_end - 1e-6:
        if pids and not all(proc_sample(p) for p in pids.values()):
            rep["faults"].append("a subject process died during the load")
            break
        d = min(seg_s, t_end - clock.now())
        if d < 1.0:
            break
        try:
            seg = setup.h2load(conns=conns, streams=4, dur_s=clock.real(d), rps=rps)
        except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as e:
            rep["faults"].append(f"h2load segment: {str(e)[:300]}")
            break
        seg["t"] = round(clock.now(), 1)
        # Under a scaled clock the fake h2load reports real seconds: rates compare at the same scale.
        rep["load"]["segments"].append(seg)
        if len(rep["load"]["segments"]) % 6 == 1:
            log(f"t={clock.now() - rep['phases']['load_start']:.0f}s segment {len(rep['load']['segments'])}: "
                f"{seg['req_s']:.0f} req/s, errors {seg['errors']}")
    rep["phases"]["load_end"] = clock.now()
    setup.counting = False
    stop_sampling.set()
    th.join(timeout=30)

    # 4. Back to baseline?
    rep["after"] = settle(limit=SETTLE_S, against=rep["baseline"])
    rep["phases"]["settled"] = clock.now()
    m1 = setup.metrics() or {}

    # 5. Errors.
    e = rep["errors"]
    e["h2load"] = sum(s["errors"] for s in rep["load"]["segments"])
    e["proxy_shim"] = setup.shim_errors()
    for k in ERROR_COUNTERS:
        e[k] = int(m1.get(k, 0) - m0.get(k, 0)) if m1 else 0
    if not m1:
        rep["faults"].append("admin /metrics unreachable after the load")
    e["aegis_error_log_lines"] = len(setup.err_lines)
    rep["error_log_sample"] = setup.err_lines[:20]
    col = setup.collector
    t0, t1 = rep["phases"]["load_start"], rep["phases"]["load_end"]
    rep["otlp"] = {"metrics_total": len(col.metrics), "logs_total": len(col.logs),
                   "metrics_last_quarter": sum(1 for t in col.metrics if t1 - (t1 - t0) / 4 <= t <= t1 + SAMPLE_S),
                   "collector_bad_paths": col.bad}
    e["otlp_collector_bad_paths"] = col.bad

    # 6. Stop (SIGTERM drain) and verify the audit log.
    rc = setup.stop()
    rep["exit"] = rc
    for name, code in rc.items():
        if code != 0:
            e[f"{name}_exit"] = 1
            rep["faults"].append(f"{name} exit {code} on SIGTERM")
    rep["audit"] = setup.audit()
    rep["notes"] = list(getattr(setup, "notes", []))
    if record:
        os.makedirs(os.path.dirname(os.path.abspath(record)), exist_ok=True)
        with open(record + ".tmp", "w") as f:
            json.dump(rep, f, indent=1, sort_keys=True)
            f.write("\n")
        os.replace(record + ".tmp", record)
    return rep


def summary(rep):
    sg = rep["load"]["segments"]
    req = sum(s.get("done", 0) for s in sg)
    return (f"{rep['hours']} h, {len(sg)} segments, {req} requests at target {rep['load'].get('target_rps', 0)} req/s "
            f"(calibrated {rep['load'].get('calibration', {}).get('req_s', 0):.0f})")


def cmd_run(a):
    host = socket.gethostname().split(".")[0]
    work = tempfile.mkdtemp(prefix="aegis-soak-")
    clock = Clock(1.0)
    setup = RealSetup(a, clock, work)
    record = a.record or os.path.join(REPO, "target", "soak", "out",
                                      f"soak-{host}-{datetime.datetime.now(datetime.timezone.utc):%Y%m%dT%H%M%SZ}.json")
    try:
        try:
            setup.build()
            cpus = setup.cpus()
            setup.start()
        except (RuntimeError, OSError, subprocess.SubprocessError) as e:
            print(f"{TAG}: FAIL (harness: {str(e)[:500]})")
            return 1
        meta = {"host": host, "kernel": os.uname().release, "cpus": cpus, "host_cpus": len(cpu_order()),
                "date": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                "aegis": {"binary": a.aegis, "features": "native,proxy-protocol,mtc"}, "otlp": None,
                "config": "PROXY v2 listener (trusted 127.0.0.2/32, via shim), tls.credentials mtc+x509 "
                          "(selector), /px/ reverse proxy, /sq/ apps/notes on SQLite, aegis-otlp sidecar",
                "record_only": a.hours > 2}
        try:
            rep = run_soak(setup, clock, a.hours, record=record, meta=meta)
        except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as e:
            print(f"{TAG}: FAIL (harness: {str(e)[:500]})")
            return 1
    finally:
        setup.cleanup()
        if not a.keep:
            shutil.rmtree(work, ignore_errors=True)
    bad, notes = judge(rep)
    for n in notes + rep.get("notes", []):
        log(n)
    log(f"report {record}")
    if a.hours > 2:
        verdict = "criteria met" if not bad else "criteria NOT met: " + "; ".join(bad)
        print(f"{TAG}: RECORD (record-only {a.hours} h; {verdict}; {summary(rep)})")
        return 0
    if bad:
        print(f"{TAG}: FAIL ({'; '.join(bad)}; {summary(rep)})")
        return 1
    print(f"{TAG}: PASS ({summary(rep)}; 0 errors; RSS slope <= {RSS_SLOPE_MIB_H} MiB/h; fds/tasks at baseline "
          f"+-{BASELINE_TOL}; otlp exporting; audit log verifies)")
    return 0


# ------------------------------------------------------------------------------------------------ self-test

class FakeSetup:
    """fakes.py subject (admin /healthz /metrics, /proc-visible leaks) + fakes.py otlp + fakes.py h2load."""

    def __init__(self, clock, work, mutant):
        self.clock, self.d, self.mutant = clock, work, mutant
        self.err_lines, self.notes, self.counting = [], [], False
        self.fakes = [sys.executable, "-I", os.path.join(HERE, "fakes.py")]
        self.aport = free_port()
        self.collector = Collector(clock)
        env = {"SOAK_FAKE_MUTANT": mutant, "SOAK_FAKE_SCALE": str(clock.scale)}
        self.env = env
        self.subject = Child(self.fakes + ["subject", str(self.aport), self.d], os.path.join(work, "subject.log"),
                             env=env)
        self.otlp = Child(self.fakes + ["otlp", f"http://127.0.0.1:{self.collector.port}/", "0.2"],
                          os.path.join(work, "otlp.log"), env=env)
        until = time.time() + 20
        while True:
            try:
                if http_get(self.aport, "/healthz", timeout=1)[0] == 200:
                    break
            except OSError:
                pass
            if time.time() > until or not self.subject.alive():
                raise RuntimeError("fake subject not healthy")
            time.sleep(0.05)

    def h2load(self, conns, streams, dur_s, rps=None, warmup=None):
        cmd = self.fakes + ["h2load", str(self.aport), "-c", str(conns), "-m", str(streams), "-D", f"{dur_s:.3f}"]
        if rps:
            cmd += ["--rps", str(rps)]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=dur_s + 60,
                           env=dict(os.environ, **self.env))
        return parse_h2load(p.stdout + p.stderr)

    def metrics(self):
        try:
            st, body = http_get(self.aport, "/metrics", timeout=2)
            return counters(body) if st == 200 else None
        except OSError:
            return None

    def pids(self):
        return {"aegis": self.subject.pid, "otlp": self.otlp.pid}

    def shim_errors(self):
        return 0

    def stop(self):
        rc = {"aegis": self.subject.term(10.0), "otlp": self.otlp.term(10.0)}
        self.collector.close()
        return rc

    def audit(self):
        r = subprocess.run(self.fakes + ["verify", self.d], capture_output=True, text=True, timeout=30)
        last = ((r.stdout + r.stderr).strip().splitlines() or [""])[-1]
        return {"ok": r.returncode == 0, "detail": last}

    def cleanup(self):
        self.subject.term(5.0)
        self.otlp.term(5.0)


# mutant -> the criterion prefix that must be among the failures
MUTANTS = {
    "rss-leak": "rss.slope.aegis",       # 2 MiB per (virtual) hour of load, touched pages
    "fd-leak": "fds.aegis",              # 10 fds per load segment never closed
    "task-leak": "tasks.aegis",          # 6 threads per load segment never joined
    "one-error": "errors",               # one failed request in the last segment
    "audit-bad": "audit",                # the audit log does not verify
    "otlp-dead": "otlp",                 # the sidecar never exports
    "exit-nonzero": "errors",            # exit 1 on SIGTERM
    "slow-load": "load.segment",         # every soak segment delivers 70% of the asked rate
}


def self_test(a):
    scale, hours = a.scale, 1.0
    results, bad = {}, []
    cases = ["clean"] + list(MUTANTS) + ["clean"]
    for i, m in enumerate(cases):
        work = tempfile.mkdtemp(prefix=f"aegis-soak-st-{m}-")
        clock = Clock(scale)
        setup = None
        try:
            setup = FakeSetup(clock, work, "" if m == "clean" else m)
            rep = run_soak(setup, clock, hours)
            fails, notes = judge(rep)
        except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as e:
            fails, notes = [f"harness: {e}"], []
        finally:
            if setup:
                setup.cleanup()
            shutil.rmtree(work, ignore_errors=True)
        results[f"{m}#{i}"] = fails
        if m == "clean":
            ok = not fails
            print(f"  positive control {m}: {'PASS' if ok else 'FAIL'} " + ("; ".join(fails) or "; ".join(notes)),
                  flush=True)
        else:
            want = MUTANTS[m]
            ok = any(f.startswith(want) for f in fails) and not any(f.startswith("harness") for f in fails)
            print(f"  mutant {m}: {'caught' if ok else 'MISSED'} ({'; '.join(fails) or 'no failure'})", flush=True)
        if not ok:
            bad.append(m)
    # Judge-level controls on synthetic series (exact numbers, no process noise).
    jb = judge_controls()
    bad += jb
    n_mut = len(MUTANTS)
    if bad:
        print(f"{TAG} SELF-TEST: FAIL (wrong verdict for: {', '.join(bad)})")
        return 1
    print(f"{TAG} SELF-TEST: PASS ({n_mut}/{n_mut} subject mutants caught: {', '.join(MUTANTS)}; 2 clean controls "
          f"pass; {N_JUDGE_CONTROLS} judge controls; scale x{scale:g})")
    return 0


N_JUDGE_CONTROLS = 5


def judge_controls():
    """The judge alone on exact synthetic reports: 0.9 MiB/h passes, 1.1 MiB/h fails, a step during the warm-up
    passes, baseline +5 passes and +6 fails."""
    def rep(slope_mib_h, fds_after=100, step_in_warmup=False):
        t0, t1 = 100.0, 100.0 + 7200.0
        s = []
        for k in range(0, 721):
            t = t0 + k * 10.0
            rss = 50 * MIB + slope_mib_h * MIB * (t - t0) / 3600.0
            if step_in_warmup and t < t0 + 600:
                rss -= 30 * MIB
            s.append([t, rss, 100, 10])
        return {"phases": {"load_start": t0, "load_end": t1}, "samples": {"aegis": s, "otlp": s},
                "baseline": {"aegis": {"fds": 100, "tasks": 10}, "otlp": {"fds": 100, "tasks": 10}},
                "after": {"aegis": {"fds": fds_after, "tasks": 10}, "otlp": {"fds": 100, "tasks": 10}},
                "errors": {"h2load": 0}, "load": {"target_rps": 100, "segments": [{"req_s": 100}]},
                "otlp": {"metrics_last_quarter": 3}, "audit": {"ok": True}}
    wrong = []
    controls = (("slope0.9", rep(0.9), True), ("slope1.1", rep(1.1), False),
                ("warmup-step", rep(0.0, step_in_warmup=True), True),
                ("fds+5", rep(0.0, fds_after=105), True), ("fds+6", rep(0.0, fds_after=106), False))
    assert len(controls) == N_JUDGE_CONTROLS
    for name, r, want_pass in controls:
        fails, _ = judge(r)
        if (not fails) != want_pass:
            wrong.append(f"judge:{name}")
        print(f"  judge control {name}: {'pass' if not fails else 'fail'} (want {'pass' if want_pass else 'fail'})",
              flush=True)
    return wrong


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hours", type=float, default=2.0)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--scale", type=float, default=360.0, help="self-test time scale (virtual s per real s)")
    ap.add_argument("--record", help="report JSON path (default target/soak/out/soak-<host>-<utc>.json)")
    ap.add_argument("--aegis", help="prebuilt aegis (features native,proxy-protocol,mtc)")
    ap.add_argument("--otlp", help="prebuilt aegis-otlp")
    ap.add_argument("--subject", help="alias of --aegis (oracles/README.md contract)")
    ap.add_argument("--h2load", help="h2load command (default: the pinned nghttp2 1.69.0 from h2load.lock)")
    ap.add_argument("--aegis-cpus", type=int, default=4)
    ap.add_argument("--client-cpus", type=int, default=2)
    ap.add_argument("--keep", action="store_true", help="keep the work directory")
    a = ap.parse_args()
    if a.subject and not a.aegis:
        a.aegis = a.subject
    if a.self_test:
        return self_test(a)
    if not (0 < a.hours <= 48):
        print(f"{TAG}: FAIL (--hours must be in (0, 48])")
        return 2
    return cmd_run(a)


if __name__ == "__main__":
    sys.exit(main())
