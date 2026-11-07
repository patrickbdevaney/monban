#!/usr/bin/env python3
"""bin-residuals: the Phase-7 residuals of aegis-bin that no gate drove end to end (unit P8-oracle-001; PREFLIGHT
R6, R7). Stdlib only; run as `python3 -I oracle.py`. Contract and check list: README.md.

One aegis process built with `--features mtc,l4` and one oracle-written F8 config:
- SEL-1..3 through the binary: for each ClientHello the oracle reads which credential the server put in its
  Certificate message (tls13.py decrypts the server's first flight), or which alert it sent;
- L4 idle timeout after routing (`limits.idle_timeout_ms`, no byte either way), with activity in either direction
  keeping the splice open;
- R6: one malformed chunked request gets exactly one 400 and a close (oracles/proxy-e2e/oneresp.py).
"""

import argparse
import base64
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "oracles", "proxy-e2e"))
sys.path.insert(0, os.path.join(REPO, "oracles", "proxy-l4"))
import clienthello as ch  # noqa: E402
import oneresp  # noqa: E402
import tls13  # noqa: E402

NAME = "BIN-RESIDUALS"
MUTANTS = ["sel1-any-trust-anchor", "sel1-prefix-match", "sel2-mldsa-public", "sel3-other-listener",
           "ta-codepoint-lenient", "idle-ignored", "idle-absolute", "two-responses"]
VHOST = "aegis.test"
L4_SNI = "a.l4.test"
IDLE_MS = 1500                  # limits.idle_timeout_ms written into the config (schema minimum 1000)
IDLE_EARLY = 0.25               # s: a close this much before the idle bound is premature
IDLE_LATE = 1.25                # s: a close later than idle + this is "ignored" (the binary polls every 250 ms)
ACTIVE_FOR = 4.0                # s: activity window, > 2 x idle
TICK = 0.5                      # s: one byte every TICK during the activity window (< idle)
TA1 = "32473.1.7"               # pub's MTC trust anchor (dotted relative OID, F8 credential.trust_anchor_id)
TA2 = "32473.2.7"               # pub2's
PUB_SIG = [0x0403]
MLDSA_SIGS = [0x0904, 0x0905, 0x0906]


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def ta_wire(dotted):
    """F8 trust_anchor_id -> its binary form: DER RELATIVE-OID contents octets (base 128, big-endian)."""
    out = b""
    for comp in (int(x) for x in dotted.split(".")):
        grp = [comp & 0x7F]
        comp >>= 7
        while comp:
            grp.append(0x80 | (comp & 0x7F))
            comp >>= 7
        out += bytes(reversed(grp))
    return out


def pem_blocks(text, label="CERTIFICATE"):
    return [base64.b64decode("".join(m.group(1).split()))
            for m in re.finditer(rf"-----BEGIN {label}-----(.*?)-----END {label}-----", text, re.S)]


# ------------------------------------------------------------------------------------------------ upstreams
class L4Upstream:
    """Raw TCP upstream: every accepted connection is kept, with its received bytes and its EOF time."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.lock = threading.Lock()
        self.conns = []
        self.cv = threading.Condition(self.lock)
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            rec = {"sock": c, "data": bytearray(), "eof": None, "last_rx": time.monotonic()}
            with self.cv:
                self.conns.append(rec)
                self.cv.notify_all()
            threading.Thread(target=self._read, args=(rec,), daemon=True).start()

    def _read(self, rec):
        c = rec["sock"]
        while True:
            try:
                d = c.recv(65536)
            except OSError:
                d = b""
            with self.cv:
                if not d:
                    rec["eof"] = time.monotonic()
                    self.cv.notify_all()
                    return
                rec["data"] += d
                rec["last_rx"] = time.monotonic()
                self.cv.notify_all()

    def wait_conn(self, first, timeout=5.0):
        """The upstream connection whose received bytes start with `first` (each oracle connection sends a
        distinct ClientHello, so parallel cases never share one)."""
        def find():
            return next((r for r in self.conns if bytes(r["data"][:len(first)]) == first), None)
        with self.cv:
            self.cv.wait_for(lambda: find() is not None, timeout)
            return find()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
        with self.lock:
            for r in self.conns:
                try:
                    r["sock"].close()
                except OSError:
                    pass


class Counter:
    """HTTP upstream for the /api/ route: counts requests (R6 not-forwarded) and answers 200."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.n = 0
        self.lock = threading.Lock()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        c.settimeout(10)
        buf = b""
        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    d = c.recv(65536)
                    if not d:
                        return
                    buf += d
                head, _, buf = buf.partition(b"\r\n\r\n")
                m = re.search(rb"(?im)^content-length:\s*(\d+)", head)
                n = int(m.group(1)) if m else 0
                while len(buf) < n:
                    d = c.recv(65536)
                    if not d:
                        return
                    buf += d
                buf = buf[n:]
                with self.lock:
                    self.n += 1
                c.sendall(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
        except OSError:
            return
        finally:
            c.close()

    def count(self):
        with self.lock:
            return self.n

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ------------------------------------------------------------------------------------------------ the run
class Run:
    def __init__(self, cmd, env_extra=None, verbose=False, openssl="openssl", reference=False):
        self.cmd, self.env_extra, self.verbose, self.openssl = cmd, env_extra or {}, verbose, openssl
        self.reference = reference
        self.dir = tempfile.mkdtemp(prefix="aegis-bin-residuals-")
        os.chmod(self.dir, 0o700)
        self.failures, self.passed, self.notes = [], 0, []
        self.lock = threading.Lock()
        self.proc = None

    def check(self, name, ok, detail=""):
        with self.lock:
            if ok:
                self.passed += 1
                if self.verbose:
                    print(f"  ok   {name}", flush=True)
            else:
                self.failures.append(name)
                print(f"  FAIL {name}: {detail}", flush=True)
        return ok

    # ---------------------------------------------------------------- material
    def _ossl(self, *args, check=True):
        return subprocess.run([self.openssl, *args], capture_output=True, timeout=60, check=check)

    def ec_cred(self, name):
        k, c = os.path.join(self.dir, f"{name}.key"), os.path.join(self.dir, f"{name}.crt")
        self._ossl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                   "-keyout", k, "-out", c, "-days", "30", "-subj", f"/CN={VHOST}",
                   "-addext", f"subjectAltName=DNS:{VHOST}")
        os.chmod(k, 0o600)
        with open(c) as f:
            return c, k, pem_blocks(f.read())[0]

    def mtc_cred(self, name):
        """An MTC credential is an opaque operator blob (D-P7.4): here random bytes with a marker, never PEM, so the
        served certificate_list entry must be exactly the file. The key is an ordinary P-256 key (scheme 0x0403)."""
        _, k, _ = self.ec_cred(name + "-key")
        blob = b"AEGIS-ORACLE-OPAQUE-MTC/" + name.encode() + b"/" + secrets.token_bytes(96)
        p = os.path.join(self.dir, f"{name}.mtc")
        with open(p, "wb") as f:
            f.write(blob)
        return p, k, blob

    def mldsa_cred(self, name):
        k, c = os.path.join(self.dir, f"{name}.key"), os.path.join(self.dir, f"{name}.crt")
        r = self._ossl("genpkey", "-algorithm", "ML-DSA-44", "-out", k, check=False)
        if r.returncode == 0:
            self._ossl("req", "-x509", "-key", k, "-out", c, "-days", "30", "-subj", f"/CN={VHOST}")
            os.chmod(k, 0o600)
            with open(c) as f:
                return c, k, pem_blocks(f.read())[0], True
        if not self.reference:
            raise RuntimeError(f"{self.openssl} cannot mint an ML-DSA-44 key (needs OpenSSL >= 3.5; kamrui has "
                               f"3.5.3; pass --openssl): {r.stderr.decode(errors='replace')[:200]}")
        # Reference subject only: a stand-in (the reference never signs; it reads the scheme from the key's OID).
        oid = bytes.fromhex("0609608648016503040311")  # id-ml-dsa-44 2.16.840.1.101.3.4.3.17
        key_der = bytes.fromhex("3016020100300b") + oid + bytes.fromhex("0404") + secrets.token_bytes(4)
        cert_der = b"\x30\x82\x01\x00" + b"AEGIS-ORACLE-STANDIN-MLDSA44/" + secrets.token_bytes(64)
        with open(k, "w") as f:
            f.write("-----BEGIN PRIVATE KEY-----\n" + base64.b64encode(key_der).decode() + "\n-----END PRIVATE KEY-----\n")
        with open(c, "w") as f:
            f.write("-----BEGIN CERTIFICATE-----\n" + base64.b64encode(cert_der).decode() +
                    "\n-----END CERTIFICATE-----\n")
        os.chmod(k, 0o600)
        return c, k, cert_der, False

    def material(self):
        if not shutil.which(self.openssl) and not os.path.exists(self.openssl):
            raise RuntimeError("openssl CLI not found")
        self.web_crt, self.web_key, _ = self.ec_cred("web")
        c, k, self.der_pub_x509 = self.ec_cred("pub-x509")
        m1, mk1, self.blob1 = self.mtc_cred("pub-mtc")
        m2, mk2, self.blob2 = self.mtc_cred("pub2-mtc")
        pc, pk, self.der_pq_x509 = self.ec_cred("pq-x509")
        dc, dk, self.der_mldsa, self.mldsa_real = self.mldsa_cred("any-mldsa")
        self.creds = [
            {"id": "pub-mtc", "kind": "mtc", "trust_anchor_id": TA1, "chain": f"path:{m1}", "key": f"path:{mk1}",
             "listeners": ["pub"]},
            {"id": "pub-x509", "kind": "x509", "chain": f"path:{c}", "key": f"path:{k}", "listeners": ["pub"]},
            {"id": "pub2-mtc", "kind": "mtc", "trust_anchor_id": TA2, "chain": f"path:{m2}", "key": f"path:{mk2}",
             "listeners": ["pub2"]},
            {"id": "pq-x509", "kind": "x509", "chain": f"path:{pc}", "key": f"path:{pk}", "listeners": ["pq"]},
            # no `listeners`: serves every HTTP listener, including the P-PUBLIC-WEB ones (SEL-2 bait)
            {"id": "any-mldsa", "kind": "mldsa", "chain": f"path:{dc}", "key": f"path:{dk}"},
        ]
        self.leaf = {self.der_pub_x509: "pub-x509", self.blob1: "pub-mtc", self.blob2: "pub2-mtc",
                     self.der_pq_x509: "pq-x509", self.der_mldsa: "any-mldsa"}

    def config(self):
        b = lambda p: f"127.0.0.1:{p}"  # noqa: E731
        return {
            "v": 1,
            "listeners": [
                {"name": "pub", "bind": b(self.p_pub), "profile": "P-PUBLIC-WEB", "alpn": ["http/1.1"]},
                {"name": "pub2", "bind": b(self.p_pub2), "profile": "P-PUBLIC-WEB", "alpn": ["http/1.1"]},
                {"name": "pq", "bind": b(self.p_pq), "profile": "P-PQ-REQUIRED", "alpn": ["http/1.1"]},
                {"name": "web", "bind": b(self.p_web), "profile": "P-PUBLIC-WEB", "alpn": ["http/1.1"]},
                {"name": "l4", "bind": b(self.p_l4), "profile": "P-PUBLIC-WEB",
                 "l4": [{"sni": L4_SNI, "upstream": b(self.l4up.port)}]},
            ],
            "admin": {"bind": b(self.p_admin)},
            "limits": {"idle_timeout_ms": IDLE_MS},
            "tls": {"credentials": self.creds},
            "vhosts": [{"host": VHOST, "routes": [
                {"id": 1, "path": "/api/", "to": {"upstream": b(self.counter.port)}, "authz": "allow-all"}]}],
        }

    # ---------------------------------------------------------------- subject
    def env(self):
        env = dict(os.environ)
        for k in ("NOTIFY_SOCKET", "AEGIS_UPGRADE_DIR", "CREDENTIALS_DIRECTORY", "AEGIS_BR_MUTANT"):
            env.pop(k, None)
        env.update(self.env_extra)
        return env

    def start(self):
        self.log = open(os.path.join(self.dir, "subject.log"), "ab")
        argv = self.cmd + ["--config", self.cfg, "--cert", self.web_crt, "--key", self.web_key,
                           "--audit-dir", os.path.join(self.dir, "audit")]
        self.proc = subprocess.Popen(argv, stdout=self.log, stderr=subprocess.STDOUT, env=self.env())
        until = time.time() + 30
        while time.time() < until:
            if self.proc.poll() is not None:
                raise RuntimeError(f"subject exited {self.proc.returncode} at start: {self.tail()}")
            try:
                with socket.create_connection(("127.0.0.1", self.p_admin), timeout=1) as c:
                    c.sendall(b"GET /healthz HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")
                    if c.recv(64).split(b" ")[1:2] == [b"200"]:
                        return
            except OSError:
                pass
            time.sleep(0.1)
        raise RuntimeError("subject did not become healthy within 30 s")

    def tail(self):
        try:
            with open(os.path.join(self.dir, "subject.log"), "rb") as f:
                return f.read()[-1500:].decode(errors="replace")
        except OSError:
            return ""

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def run(self):
        self.l4up, self.counter = L4Upstream(), Counter()
        try:
            self.material()
            self.p_pub, self.p_pub2, self.p_pq, self.p_web, self.p_l4, self.p_admin = (free_port() for _ in range(6))
            self.cfg = os.path.join(self.dir, "aegis.json")
            with open(self.cfg, "w") as f:
                json.dump(self.config(), f)
            self.start()
            idle = threading.Thread(target=self.guard, args=(self.l4_suite,))
            idle.start()
            self.guard(self.sel_suite)
            self.guard(self.r6_suite)
            idle.join()
        except Exception as e:  # noqa: BLE001
            self.check("harness", False, f"{e!r}; subject log: {self.tail()}")
            if self.verbose:
                traceback.print_exc()
        finally:
            self.stop()
            self.l4up.close()
            self.counter.close()
            shutil.rmtree(self.dir, ignore_errors=True)
        return not self.failures

    def guard(self, fn):
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            self.check(f"{fn.__name__}.error", False, repr(e))
            if self.verbose:
                traceback.print_exc()

    # ---------------------------------------------------------------- SEL-1..3 through the binary
    def expect(self, name, port, want, sigalgs=PUB_SIG, tas=None, codepoint=ch.TRUST_ANCHORS_EXT):
        o = tls13.probe("127.0.0.1", port, VHOST, sigalgs, trust_anchors=tas, ta_codepoint=codepoint)
        if isinstance(want, int):
            got_cred = self.leaf.get(o.certs[0], "unknown-certificate") if o.kind == "certificate" and o.certs \
                else None
            self.check(name, o.kind == "alert" and o.alert == want,
                       f"want alert {want} ({tls13.ALERT_NAMES.get(want)}), got {o!r}"
                       + (f" serving {got_cred}" if got_cred else ""))
            return
        got = self.leaf.get(o.certs[0], "unknown-certificate") if o.kind == "certificate" and o.certs else repr(o)
        self.check(name, got == want, f"want {want}, got {got}")

    def sel_suite(self):
        t1, t2 = ta_wire(TA1), ta_wire(TA2)
        other = ta_wire("32473.9.7")
        P, P2 = self.p_pub, self.p_pub2
        # SEL-1: the mtc credential only when trust_anchors (0xCA34) names its id, byte for byte
        self.expect("sel1.match", P, "pub-mtc", tas=[t1])
        self.expect("sel1.second-in-list", P, "pub-mtc", tas=[other, t1])
        self.expect("sel1.no-extension", P, "pub-x509")
        self.expect("sel1.empty-list", P, "pub-x509", tas=[])
        self.expect("sel1.other-id", P, "pub-x509", tas=[other])
        self.expect("sel1.prefix", P, "pub-x509", tas=[t1[:-1]])
        self.expect("sel1.extended", P, "pub-x509", tas=[t1 + b"\x01"])
        self.expect("sel1.wrong-codepoint", P, "pub-x509", tas=[t1], codepoint=ch.TRUST_ANCHORS_EXT + 1)
        self.expect("sel1.other-listeners-id", P, "pub-x509", tas=[t2])
        # SEL-2: never the mldsa credential on a P-PUBLIC-WEB listener, even when it serves every listener and the
        # client offers its scheme first
        self.expect("sel2.mldsa-offered.pub", P, "pub-x509", sigalgs=MLDSA_SIGS + PUB_SIG)
        self.expect("sel2.mldsa-offered.pub-with-ta", P, "pub-mtc", sigalgs=MLDSA_SIGS + PUB_SIG, tas=[t1])
        self.expect("sel2.mldsa-offered.pub2-own-ta", P2, "pub2-mtc", sigalgs=MLDSA_SIGS + PUB_SIG, tas=[t2])
        # only ML-DSA offered: disjoint from the profile's F12 sigalgs -> F12 admission step 2, alert 49
        self.expect("sel2.mldsa-only.pub.alert49", P, 49, sigalgs=MLDSA_SIGS)
        # SEL-3: nothing among pub2's own credentials matches -> handshake_failure (40), never pub's credential
        self.expect("sel3.pub2-no-ta.alert40", P2, 40)
        self.expect("sel3.pub2-pubs-ta.alert40", P2, 40, tas=[t1])
        self.expect("sel3.pub2-mldsa-offered.alert40", P2, 40, sigalgs=MLDSA_SIGS + PUB_SIG)
        self.expect("sel3.pub2-own-ta.control", P2, "pub2-mtc", tas=[t2])
        self.pq_controls()

    def pq_controls(self):
        """Positive controls on the P-PQ-REQUIRED listener (X25519MLKEM768 only, so the stdlib probe cannot speak
        it): `openssl s_client` >= 3.5. They show the mldsa credential is loaded and servable, so SEL-2 above is not
        vacuous for the binary. Reference runs and older openssl: reported as skipped."""
        if self.reference or not self.mldsa_real:
            self.notes.append("pq controls skipped (" + ("reference" if self.reference else "openssl < 3.5") + ")")
            return
        for name, sig, want in (("pq.mldsa-control", "mldsa44", "any-mldsa"),
                                ("pq.x509-control", "ecdsa_secp256r1_sha256", "pq-x509")):
            p = subprocess.run([self.openssl, "s_client", "-connect", f"127.0.0.1:{self.p_pq}", "-servername", VHOST,
                                "-tls1_3", "-groups", "X25519MLKEM768", "-sigalgs", sig, "-showcerts"],
                               input=b"", capture_output=True, timeout=30)
            out = p.stdout.decode(errors="replace")
            blocks = pem_blocks(out)
            got = self.leaf.get(blocks[0], "unknown-certificate") if blocks else f"no certificate (rc {p.returncode})"
            self.check(name, got == want, f"want {want}, got {got}: {p.stderr.decode(errors='replace')[-200:]}")
        self.notes.append("pq controls via openssl s_client")

    # ---------------------------------------------------------------- L4 idle timeout after routing
    def l4_open(self):
        c = socket.create_connection(("127.0.0.1", self.p_l4), timeout=10)
        hello = ch.record(ch.build(sni=L4_SNI, seed=secrets.randbits(32)))
        c.sendall(hello)
        up = self.l4up.wait_conn(hello)
        return c, up, hello

    def wait_closed(self, c, up, since, cap):
        """Seconds from `since` until the client side sees EOF/RST, and until the upstream sees EOF (None = not
        within cap)."""
        c.settimeout(0.05)
        t_client = None
        until = since + cap
        while time.monotonic() < until and t_client is None:
            try:
                d = c.recv(65536)
                if not d:
                    t_client = time.monotonic() - since
            except (socket.timeout, TimeoutError):
                pass
            except OSError:
                t_client = time.monotonic() - since
        while time.monotonic() < until and up["eof"] is None:
            time.sleep(0.02)
        t_up = None if up["eof"] is None else up["eof"] - since
        return t_client, t_up

    def judge_close(self, name, t_client, t_up):
        lo, hi = IDLE_MS / 1000 - IDLE_EARLY, IDLE_MS / 1000 + IDLE_LATE
        self.check(f"{name}.client-closed-at-idle", t_client is not None and lo <= t_client <= hi,
                   f"client side closed after {t_client} s of silence, want within [{lo:.2f}, {hi:.2f}]")
        self.check(f"{name}.upstream-closed-at-idle", t_up is not None and lo <= t_up <= hi,
                   f"upstream side closed after {t_up} s of silence, want within [{lo:.2f}, {hi:.2f}]")

    def l4_suite(self):
        ths = [threading.Thread(target=self.guard, args=(f,)) for f in (self.l4_silent, self.l4_client_active,
                                                                        self.l4_upstream_active)]
        for t in ths:
            t.start()
        for t in ths:
            t.join()

    def l4_silent(self):
        c, up, hello = self.l4_open()
        try:
            if not self.check("l4.silent.routed", up is not None, "no upstream connection"):
                return
            t0 = time.monotonic()
            while time.monotonic() - t0 < 2 and len(up["data"]) < len(hello):
                time.sleep(0.02)
            self.check("l4.silent.hello-forwarded", bytes(up["data"]) == hello, "upstream bytes differ")
            since = max(up["last_rx"], t0)
            self.judge_close("l4.silent", *self.wait_closed(c, up, since, IDLE_MS / 1000 + 4))
        finally:
            c.close()

    def l4_client_active(self):
        c, up, hello = self.l4_open()
        try:
            if not self.check("l4.client-active.routed", up is not None, "no upstream connection"):
                return
            sent, alive = hello, True
            t0 = time.monotonic()
            while time.monotonic() - t0 < ACTIVE_FOR:
                time.sleep(TICK)
                b = secrets.token_bytes(1)
                try:
                    c.sendall(b)
                    sent += b
                except OSError:
                    alive = False
                    break
            last = time.monotonic()
            time.sleep(0.3)
            self.check("l4.client-active.stays-open", alive and up["eof"] is None,
                       f"closed during client->upstream activity at {time.monotonic() - t0:.2f} s")
            self.check("l4.client-active.bytes-forwarded", bytes(up["data"]) == sent,
                       f"upstream got {len(up['data'])} of {len(sent)} bytes")
            if alive:
                self.judge_close("l4.client-active.then-silent", *self.wait_closed(c, up, last, IDLE_MS / 1000 + 4))
        finally:
            c.close()

    def l4_upstream_active(self):
        c, up, hello = self.l4_open()
        try:
            if not self.check("l4.upstream-active.routed", up is not None, "no upstream connection"):
                return
            got, sent, alive = b"", b"", True
            c.settimeout(0.05)
            t_tx = time.monotonic()
            t0 = time.monotonic()
            next_tx = t0 + TICK
            while time.monotonic() - t0 < ACTIVE_FOR:
                if time.monotonic() >= next_tx:
                    b = secrets.token_bytes(1)
                    try:
                        up["sock"].sendall(b)
                        sent += b
                        t_tx = time.monotonic()
                    except OSError:
                        alive = False
                        break
                    next_tx += TICK
                try:
                    d = c.recv(65536)
                    if not d:
                        alive = False
                        break
                    got += d
                except (socket.timeout, TimeoutError):
                    pass
                except OSError:
                    alive = False
                    break
            last = t_tx
            deadline = time.monotonic() + 1.0
            while len(got) < len(sent) and time.monotonic() < deadline and alive:
                try:
                    d = c.recv(65536)
                    if not d:
                        alive = False
                        break
                    got += d
                except (socket.timeout, TimeoutError):
                    pass
                except OSError:
                    alive = False
            self.check("l4.upstream-active.stays-open", alive,
                       f"closed during upstream->client activity at {time.monotonic() - t0:.2f} s")
            self.check("l4.upstream-active.bytes-forwarded", got == sent, f"client got {len(got)} of {len(sent)}")
            if alive:
                self.judge_close("l4.upstream-active.then-silent", *self.wait_closed(c, up, last, IDLE_MS / 1000 + 4))
        finally:
            c.close()

    # ---------------------------------------------------------------- R6 through this build
    def r6_suite(self):
        oneresp.run_cases(self.check, self.p_web, VHOST, self.web_crt, f"{VHOST}:{self.p_web}", "/api/chunk",
                          upstream_count=self.counter.count, prefix="r6.")


# ------------------------------------------------------------------------------------------------ main
def subject_cmd(s):
    if s.endswith(".py"):
        return [sys.executable, "-I", os.path.abspath(s)]
    parts = shlex.split(s)
    parts[0] = os.path.abspath(parts[0]) if os.path.exists(parts[0]) else parts[0]
    return parts


def summary(r):
    return f"{r.passed} checks" + ("; " + "; ".join(r.notes) if r.notes else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", "--subject", dest="binary", default=None,
                    help="aegis built with --features mtc,l4 (default: the reference ref_server.py)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--openssl", default=os.environ.get("AEGIS_OPENSSL", "openssl"),
                    help="openssl CLI (>= 3.5 needed for the ML-DSA-44 credential of a real binary)")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    ref = os.path.join(HERE, "ref_server.py")
    if not a.self_test:
        if a.binary and not os.access(a.binary, os.X_OK):
            print(f"{NAME}: FAIL (binary {a.binary} is absent or not executable)")
            return 1
        if not a.binary:
            print("subject: reference (ref_server.py)")
        r = Run(subject_cmd(a.binary or ref), verbose=a.verbose, openssl=a.openssl, reference=not a.binary)
        if r.run():
            print(f"{NAME}: PASS ({summary(r)})")
            return 0
        print(f"{NAME}: FAIL ({len(r.failures)} failed: {', '.join(r.failures[:10])})")
        return 1
    r = Run(subject_cmd(ref), verbose=a.verbose, openssl=a.openssl, reference=True)
    if not r.run():
        print(f"{NAME} SELF-TEST: FAIL (the reference must pass first: {r.failures[:6]})")
        return 1
    print(f"  reference: PASS ({summary(r)})", flush=True)
    caught = []
    results = {}

    def one(m):
        rr = Run(subject_cmd(ref), env_extra={"AEGIS_BR_MUTANT": m}, openssl=a.openssl, reference=True)
        results[m] = (rr.run(), rr.failures)

    ths = [threading.Thread(target=one, args=(m,)) for m in MUTANTS]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    for m in MUTANTS:
        ok, fails = results[m]
        if ok:
            print(f"{NAME} SELF-TEST: FAIL (mutant {m} was not caught)")
            return 1
        print(f"  mutant {m}: caught by {len(fails)} checks, e.g. {', '.join(fails[:5])}", flush=True)
        caught.append(m)
    print(f"{NAME} SELF-TEST: PASS (reference green; {len(caught)}/{len(MUTANTS)} mutants caught: {', '.join(caught)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
