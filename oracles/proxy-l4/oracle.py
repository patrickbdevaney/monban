"""Monban oracle proxy-l4 (P7-oracle-proxy-001): PROXY v2 + L4 SNI passthrough, F1 PROXY-1..3 and L4-1..2.

Stdlib only; run as `python3 -I oracle.py` (via ./run). See README.md for the subject contract, the F8 config, the
receiver rules, every check and the self-test mutants.
"""

import argparse
import collections
import concurrent.futures
import http.client
import ipaddress
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import clienthello as ch  # noqa: E402
import proxyv2 as pp  # noqa: E402
import vectors_check  # noqa: E402
from tlsbio import Pump  # noqa: E402

NAME = "PROXY-L4"
STALL_MAX_S = 20.0  # L4-1 stall deadline bound (and the PROXY header read deadline): close within this
CLOSE_WAIT_S = 8.0  # a refused connection must be closed (EOF or RST) within this, with 0 bytes sent back
TRUSTED = ["127.0.0.2/32", "127.0.1.0/24"]
MATRIX = [("127.0.0.1", False), ("127.0.0.2", True), ("127.0.0.3", False), ("127.0.1.1", True),
          ("127.0.1.254", True), ("127.0.2.1", False), ("127.1.0.1", False)]
E2E_MUTANTS = ["proxy-untrusted-accept", "proxy-trust-by-header", "proxy-local-header-peer", "proxy-v1-accept",
               "proxy-len-537", "proxy-crc-skip", "proxy-tlv-lenient", "proxy-autodetect", "l4-default-upstream",
               "l4-http-parse", "l4-multi-record", "l4-no-stall-deadline", "l4-forward-proxy-header"]
VECTOR_MUTANTS = list(pp.MUTANTS) + list(ch.MUTANTS)


def free_port(fam=socket.AF_INET, host="127.0.0.1"):
    s = socket.socket(fam)
    s.bind((host, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def has_v6():
    try:
        s = socket.socket(socket.AF_INET6)
        s.bind(("::1", 0))
        s.close()
        return True
    except OSError:
        return False


def norm_ip(s):
    try:
        return str(ipaddress.ip_address(s))
    except (ValueError, TypeError):
        return repr(s)


def connect(port, src="127.0.0.1", host="127.0.0.1", fam=socket.AF_INET, timeout=10):
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.bind((src, 0))
    s.settimeout(timeout)
    s.connect((host, port))
    return s


def expect_closed(s, timeout=CLOSE_WAIT_S):
    """Read until EOF/RST or timeout. Returns (bytes received, closed?, seconds)."""
    t0 = time.monotonic()
    got = b""
    closed = False
    while True:
        left = timeout - (time.monotonic() - t0)
        if left <= 0:
            break
        s.settimeout(left)
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        except (ConnectionResetError, BrokenPipeError):
            closed = True
            break
        except OSError:
            closed = True
            break
        if not d:
            closed = True
            break
        got += d
    return got, closed, time.monotonic() - t0


def send_half_close(s, data, half_close=True):
    try:
        s.sendall(data)
        if half_close:
            s.shutdown(socket.SHUT_WR)
    except OSError:
        pass  # the server may already have closed: that is what a refusal looks like


# ------------------------------------------------------------------------------------------------ upstreams


class Recorder:
    """HTTP/1.1 upstream behind the HTTP listener: records request targets and answers 200."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(128)
        self.port = self.sock.getsockname()[1]
        self.lock = threading.Lock()
        self.targets = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        c.settimeout(20)
        buf = b""
        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    d = c.recv(65536)
                    if not d:
                        return
                    buf += d
                head, _, buf = buf.partition(b"\r\n\r\n")
                parts = head.split(b"\r\n")[0].split(b" ")
                with self.lock:
                    self.targets.append(parts[1] if len(parts) > 1 else b"")
                body = b"upstream-ok\n"
                c.sendall(b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: %d\r\n\r\n" % len(body) +
                          body)
        except OSError:
            return
        finally:
            c.close()

    def saw(self, target):
        with self.lock:
            return target in self.targets

    def close(self):
        self.sock.close()


class UpTLS:
    """TLS upstream behind the L4 listener. Records every raw byte it receives per connection (passthrough must be
    byte-exact), then answers one line with '<tag>:<line>' and closes."""

    def __init__(self, tag, cert, key):
        self.tag = tag
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(128)
        self.port = self.sock.getsockname()[1]
        self.lock = threading.Lock()
        self.conns = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            rec = {"raw": b"", "done": False}
            with self.lock:
                self.conns.append(rec)
            threading.Thread(target=self._serve, args=(c, rec), daemon=True).start()

    def _serve(self, c, rec):
        c.settimeout(15)
        p = Pump(c, self.ctx, server_side=True)
        try:
            p.handshake()
            line = b""
            while b"\n" not in line:
                d = p.read()
                if not d:
                    break
                line += d
            if line:
                p.write(self.tag.encode() + b":" + line)
            try:
                p.obj.unwrap()
            except (ssl.SSLError, ssl.SSLWantReadError):
                pass
            p._flush()
        except (OSError, ssl.SSLError, ConnectionError):
            pass
        finally:
            # drain what is left so `raw` is the complete client-to-upstream byte stream
            try:
                c.settimeout(1.0)
                while True:
                    d = c.recv(65536)
                    if not d:
                        break
                    p.recvd += d
            except OSError:
                pass
            rec["raw"] = bytes(p.recvd)
            rec["done"] = True
            c.close()

    def count(self):
        with self.lock:
            return len(self.conns)

    def find(self, raw, timeout=5.0):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            with self.lock:
                for r in self.conns:
                    if r["done"] and r["raw"] == raw:
                        return True
            time.sleep(0.05)
        return False

    def raws(self):
        with self.lock:
            return [r["raw"] for r in self.conns]

    def close(self):
        self.sock.close()


# ------------------------------------------------------------------------------------------------ harness


class Run:
    def __init__(self, subject_cmd, env_extra=None, verbose=False):
        self.cmd = subject_cmd
        self.env_extra = env_extra or {}
        self.verbose = verbose
        self.failures = []
        self.passed = 0
        self.lock = threading.Lock()
        self.dir = tempfile.mkdtemp(prefix="monban-proxy-l4-")
        self.proc = None
        self.expect_audit = collections.Counter()
        self.expect_up = {"a": 0, "b": 0}
        self.v6 = has_v6()
        self.notes = []

    def check(self, name, ok, detail=""):
        with self.lock:
            if ok:
                self.passed += 1
                if self.verbose:
                    print(f"  ok   {name}" + (f" ({detail})" if detail and self.verbose > 1 else ""), flush=True)
            else:
                self.failures.append(name)
                print(f"  FAIL {name}: {detail}", flush=True)

    def audit_proxy(self, lst, peer, via):
        with self.lock:
            self.expect_audit[("proxy.accept", lst, norm_ip(peer), norm_ip(via))] += 1

    def audit_l4(self, lst, sni, up, peer):
        with self.lock:
            self.expect_audit[("l4.route", lst, sni.lower(), up, norm_ip(peer))] += 1

    # -------------------------------------------------------------------------------------------- setup

    def mint(self, name, cn, sans):
        key, crt = os.path.join(self.dir, f"{name}.key"), os.path.join(self.dir, f"{name}.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-keyout", key, "-out", crt, "-days", "30", "-subj", f"/CN={cn}",
                        "-addext", "subjectAltName=" + ",".join(f"DNS:{s}" for s in sans)],
                       check=True, capture_output=True, timeout=30)
        return crt, key

    def config(self, mutate=None):
        ua, ub = f"127.0.0.1:{self.ua.port}", f"127.0.0.1:{self.ub.port}"
        routes = [{"sni": "a.l4.test", "upstream": ua}, {"sni": "b.l4.test", "upstream": ub}]
        lst = [
            {"name": "pub", "bind": f"127.0.0.1:{self.p_pub}", "profile": "P-PUBLIC-WEB", "alpn": ["http/1.1"],
             "proxy_protocol": {"trusted": list(TRUSTED)}},
            {"name": "plain", "bind": f"127.0.0.1:{self.p_plain}", "profile": "P-PUBLIC-WEB", "alpn": ["http/1.1"]},
            {"name": "l4", "bind": f"127.0.0.1:{self.p_l4}", "profile": "P-PUBLIC-WEB", "l4": routes},
            {"name": "l4p", "bind": f"127.0.0.1:{self.p_l4p}", "profile": "P-PUBLIC-WEB",
             "proxy_protocol": {"trusted": ["127.0.0.2/32"]}, "l4": [dict(r) for r in routes]},
        ]
        if self.v6:
            lst.append({"name": "pub6", "bind": f"[::1]:{self.p_pub6}", "profile": "P-PUBLIC-WEB",
                        "alpn": ["http/1.1"], "proxy_protocol": {"trusted": ["::1/128"]}})
        doc = {"v": 1, "listeners": lst, "admin": {"bind": f"127.0.0.1:{self.p_admin}"},
               "vhosts": [{"host": "monban.test", "routes": [
                   {"id": 1, "path": "/api/", "to": {"upstream": f"127.0.0.1:{self.rec.port}"},
                    "authz": "allow-all"}]}]}
        if mutate:
            mutate(doc)
        return doc

    def start(self, doc, audit_dir):
        path = os.path.join(self.dir, f"cfg-{time.monotonic_ns()}.json")
        with open(path, "w") as f:
            json.dump(doc, f, indent=1)
        env = dict(os.environ)
        for k in ("NOTIFY_SOCKET", "AEGIS_UPGRADE_DIR", "AEGIS_E2E_MUTANT", "AEGIS_PROXY_L4_REF_MUTANT"):
            env.pop(k, None)
        env.update(self.env_extra)
        log = open(os.path.join(self.dir, "subject.log"), "ab")
        return subprocess.Popen(self.cmd + ["--config", path, "--cert", self.crt, "--key", self.key,
                                            "--audit-dir", audit_dir], stdout=log, stderr=subprocess.STDOUT, env=env)

    def wait_healthy(self):
        until = time.time() + 30
        while time.time() < until:
            if self.proc.poll() is not None:
                raise RuntimeError(f"subject exited {self.proc.returncode} at start: {self.tail()}")
            try:
                c = http.client.HTTPConnection("127.0.0.1", self.p_admin, timeout=2)
                c.request("GET", "/healthz")
                if c.getresponse().status == 200:
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
            self.proc.send_signal(signal.SIGTERM)  # explicit PID only
            try:
                self.proc.wait(20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    # -------------------------------------------------------------------------------------------- clients

    def http_ctx(self):
        ctx = ssl.create_default_context(cafile=self.crt)
        ctx.set_alpn_protocols(["http/1.1"])
        return ctx

    def l4_ctx(self, which):
        if which is None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return ssl.create_default_context(cafile={"a": self.ca_a, "b": self.ca_b}[which])

    def https_get(self, port, target, prefix=b"", src="127.0.0.1", host="127.0.0.1", fam=socket.AF_INET):
        """TLS (prefix bytes coalesced in front of the ClientHello) + one HTTP/1.1 GET. Returns (status|None, pump,
        error)."""
        s = connect(port, src, host, fam)
        p = Pump(s, self.http_ctx(), server_hostname="monban.test", prefix=prefix)
        try:
            p.handshake()
            p.write(b"GET " + target + f" HTTP/1.1\r\nHost: monban.test:{port}\r\nConnection: close\r\n\r\n".encode())
            resp = p.read_all()
            line = resp.split(b"\r\n", 1)[0].split(b" ")
            return (int(line[1]) if len(line) > 1 and line[1].isdigit() else None), p, None
        except (OSError, ssl.SSLError, ConnectionError) as e:
            return None, p, e
        finally:
            s.close()

    def refused(self, name, port, data, src="127.0.0.1", half_close=True, host="127.0.0.1", fam=socket.AF_INET):
        try:
            s = connect(port, src, host, fam)
        except OSError as e:
            self.check(name, False, f"connect: {e}")
            return
        send_half_close(s, data, half_close)
        got, closed, dt = expect_closed(s)
        s.close()
        self.check(name, closed and not got,
                   f"{'closed' if closed else 'still open after %.0fs' % dt}, {len(got)} byte(s) back: {got[:40]!r}")

    def l4_session(self, port, sni, verify, prefix=b"", src="127.0.0.1"):
        s = connect(port, src)
        p = Pump(s, self.l4_ctx(verify), server_hostname=sni, prefix=prefix)
        try:
            p.handshake()
            p.write(b"hello-" + (sni or "none").encode() + b"\n")
            return p.read_all(), p, None
        except (OSError, ssl.SSLError, ConnectionError) as e:
            return None, p, e
        finally:
            s.close()

    # -------------------------------------------------------------------------------------------- run

    def run(self):
        try:
            if not shutil.which("openssl"):
                raise RuntimeError("openssl CLI not found (mints the throwaway certificates)")
            self.crt, self.key = self.mint("monban", "monban.test", ["monban.test"])
            self.ca_a, ka = self.mint("a", "a.l4.test", ["a.l4.test"])
            self.ca_b, kb = self.mint("b", "b.l4.test", ["b.l4.test"])
            self.rec = Recorder()
            self.ua, self.ub = UpTLS("A", self.ca_a, ka), UpTLS("B", self.ca_b, kb)
            self.p_pub, self.p_plain, self.p_l4, self.p_l4p, self.p_admin = (free_port() for _ in range(5))
            self.p_pub6 = free_port(socket.AF_INET6, "::1") if self.v6 else None
            self.audit_dir = os.path.join(self.dir, "audit")
            self.proc = self.start(self.config(), self.audit_dir)
            self.wait_healthy()
            stalls = self.start_stalls()
            self.vectors_static()
            self.proxy_checks()
            self.l4_checks()
            self.l4p_checks()
            for t in stalls:
                t.join(STALL_MAX_S + 15)
            self.stop()
            self.audit_checks()
            self.boot_checks()
        except Exception as e:  # noqa: BLE001 - any harness error is a FAIL with its reason
            self.failures.append(f"harness: {e}")
            print(f"  FAIL harness: {type(e).__name__}: {e}\n{self.tail()}", flush=True)
        finally:
            self.stop()
            for u in ("rec", "ua", "ub"):
                if hasattr(self, u):
                    getattr(self, u).close()
            shutil.rmtree(self.dir, ignore_errors=True)
        return not self.failures

    # -------------------------------------------------------------------------------------------- vectors

    def vectors_static(self):
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "gen_vectors.py"), "--check"],
                           capture_output=True, text=True, timeout=120)
        self.check("vectors.generated", r.returncode == 0, r.stdout.strip() or r.stderr.strip())
        dp, dc, pv, cv = vectors_check.check()
        self.pv, self.cv = pv, cv
        self.check("vectors.reference-proxy", not dp, "; ".join(dp[:5]))
        self.check("vectors.reference-client-hello", not dc, "; ".join(dc[:5]))
        self.check("vectors.hostile-count", pv["hostile"] >= 200, f"{pv['hostile']} hostile PROXY headers")

    # -------------------------------------------------------------------------------------------- stalls

    def start_stalls(self):
        hs = ch.record(ch.build(sni="a.l4.test", seed=11))

        def stall(name, port, src, first, dribble=None):
            try:
                s = connect(port, src)
                t0 = time.monotonic()
                s.sendall(first)
                got, closed = b"", False
                if dribble:
                    for b in dribble:
                        if time.monotonic() - t0 > STALL_MAX_S + 2:
                            break
                        try:
                            s.sendall(bytes([b]))
                        except OSError:
                            closed = True
                            break
                        s.settimeout(0.5)
                        try:
                            d = s.recv(65536)
                            if not d:
                                closed = True
                                break
                            got += d
                        except socket.timeout:
                            continue
                        except OSError:
                            closed = True
                            break
                if not closed:
                    g, closed, _ = expect_closed(s, STALL_MAX_S + 2 - (time.monotonic() - t0))
                    got += g
                dt = time.monotonic() - t0
                s.close()
                self.check(name, closed and not got and dt <= STALL_MAX_S + 1,
                           f"{'closed' if closed else 'open'} after {dt:.1f}s (bound {STALL_MAX_S:.0f}s), "
                           f"{len(got)} byte(s) back")
            except OSError as e:
                self.check(name, False, f"{e}")

        jobs = [("stall.l4.partial-record", self.p_l4, "127.0.0.1", hs[:20], None),
                ("stall.l4.dribble", self.p_l4, "127.0.0.1", hs[:5], hs[5:]),
                ("stall.proxy.partial-header", self.p_pub, "127.0.0.2", pp.SIG[:8], None),
                ("stall.l4p.after-header", self.p_l4p, "127.0.0.2",
                 pp.encode(src="198.51.100.250", dst="192.0.2.1") + hs[:10], None)]
        self.audit_proxy("l4p", "198.51.100.250", "127.0.0.2")  # header admitted, then the ClientHello stalls
        ts = []
        for j in jobs:
            t = threading.Thread(target=stall, args=j, daemon=True)
            t.start()
            ts.append(t)
        return ts

    # -------------------------------------------------------------------------------------------- PROXY (HTTP)

    def proxy_checks(self):
        hello = ch.record(ch.build(sni="monban.test", alpn=["http/1.1"], seed=3))
        P = self.p_pub
        # spec / trailing / policy vectors from a trusted source
        for v in self.pv["vectors"]:
            if v["group"] == "hostile":
                continue
            data = bytes.fromhex(v["hex"])[:v["consumed"]]
            if v["listener"] == "accept":
                tgt = f"/api/v/{v['id']}".encode()
                st, p, err = self.https_get(P, tgt, prefix=data, src="127.0.0.2")
                ok = st == 200 and self.rec.saw(tgt)
                self.check(f"proxy.vector.{v['id']}", ok, f"status {st} err {err!r} upstream saw it: {self.rec.saw(tgt)}")
                if ok:
                    self.audit_proxy("pub", v["src"] if v["peer"] == "src" else "127.0.0.2", "127.0.0.2")
            else:
                self.refused(f"proxy.vector.{v['id']}", P, data + hello, "127.0.0.2")

        # >= 200 hostile headers, each followed by a ClientHello (so a lenient parser would answer it)
        def hostile(v):
            data = bytes.fromhex(v["hex"])
            if v["e2e"] == "append-client-hello":
                data += hello
            self.refused(f"proxy.hostile.{v['id']}", P, data, "127.0.0.2")

        hv = [v for v in self.pv["vectors"] if v["group"] == "hostile"]
        with concurrent.futures.ThreadPoolExecutor(8) as ex:
            list(ex.map(hostile, hv))

        # trusted-CIDR matrix
        for i, (src, trusted) in enumerate(MATRIX):
            claimed = f"198.51.100.{10 + i}"
            hdr = pp.encode(src=claimed, dst="192.0.2.1", sport=40000 + i, dport=443)
            tgt = f"/api/m/{i}".encode()
            st, p, err = self.https_get(P, tgt, prefix=hdr, src=src)
            if trusted:
                ok = st == 200 and self.rec.saw(tgt)
                self.check(f"matrix.{src}.proxy-admitted", ok, f"status {st} err {err!r}")
                if ok:
                    self.audit_proxy("pub", claimed, src)
                st, p, err = self.https_get(P, tgt + b"/direct", src=src)
                self.check(f"matrix.{src}.no-header-refused", st is None and not p.recvd and
                           not self.rec.saw(tgt + b"/direct"),
                           f"status {st}, {len(p.recvd)} byte(s) back (PROXY is never auto-detected)")
            else:
                self.check(f"matrix.{src}.proxy-refused", st is None and not p.recvd and not self.rec.saw(tgt),
                           f"status {st}, {len(p.recvd)} byte(s) back (PROXY-1)")
                st, p, err = self.https_get(P, tgt + b"/direct", src=src)
                self.check(f"matrix.{src}.direct-served", st == 200 and self.rec.saw(tgt + b"/direct"),
                           f"status {st} err {err!r}")
                # PROXY-2: a header naming a trusted address does not make an untrusted source trusted
                hdr2 = pp.encode(src="127.0.0.2", dst="127.0.0.1", sport=1, dport=P)
                st, p, err = self.https_get(P, tgt + b"/spoof", prefix=hdr2, src=src)
                self.check(f"matrix.{src}.trusted-src-claim-refused", st is None and not p.recvd,
                           f"status {st}, {len(p.recvd)} byte(s) back")
                self.refused(f"matrix.{src}.local-refused", P, pp.encode(cmd=0, fam=0, proto=0, addr=b"") + hello,
                             src)
                self.refused(f"matrix.{src}.v1-refused", P, b"PROXY TCP4 198.51.100.1 192.0.2.1 1 443\r\n" + hello,
                             src)

        # absent proxy_protocol = today's behaviour: the header is not interpreted, so TLS cannot start on it
        hdr = pp.encode(src="198.51.100.66", dst="192.0.2.1")
        st, p, err = self.https_get(self.p_plain, b"/api/plain/hdr", prefix=hdr, src="127.0.0.2")
        self.check("plain.header-not-interpreted", st is None and not self.rec.saw(b"/api/plain/hdr"),
                   f"status {st} (a listener without proxy_protocol must not accept a PROXY header)")
        st, p, err = self.https_get(self.p_plain, b"/api/plain/direct", src="127.0.0.2")
        self.check("plain.direct-served", st == 200, f"status {st} err {err!r}")

        if self.v6:
            for vid, hdr, peer in [
                ("tcp6", pp.encode(fam=2, src="2001:db8::beef", dst="2001:db8::1", sport=5, dport=443),
                 "2001:db8::beef"),
                ("tcp4", pp.encode(src="198.51.100.99", dst="192.0.2.1"), "198.51.100.99")]:
                tgt = f"/api/v6/{vid}".encode()
                st, p, err = self.https_get(self.p_pub6, tgt, prefix=hdr, src="::1", host="::1", fam=socket.AF_INET6)
                ok = st == 200 and self.rec.saw(tgt)
                self.check(f"v6.trusted-{vid}", ok, f"status {st} err {err!r}")
                if ok:
                    self.audit_proxy("pub6", peer, "::1")
        else:
            self.notes.append("no ::1 on this host: IPv6 trusted-CIDR checks skipped")

    # -------------------------------------------------------------------------------------------- L4

    def l4_checks(self):
        P = self.p_l4
        ua, ub = f"127.0.0.1:{self.ua.port}", f"127.0.0.1:{self.ub.port}"
        ups = {"a": (self.ua, ua), "b": (self.ub, ub)}
        for vid, sni, which in [("python.a", "a.l4.test", "a"), ("python.b", "b.l4.test", "b"),
                                ("python.case", "A.L4.TEST", "a")]:
            out, p, err = self.l4_session(P, sni, which)
            up, addr = ups[which]
            want = which.upper().encode() + b":hello-" + sni.encode() + b"\n"
            self.check(f"l4.{vid}.routed", out == want, f"got {out!r} err {err!r}")
            if out == want:
                self.expect_up[which] += 1
                self.audit_l4("l4", sni, addr, "127.0.0.1")
                self.check(f"l4.{vid}.byte-exact", up.find(bytes(p.sent)),
                           "upstream did not receive exactly the client's bytes")
        if shutil.which("openssl"):
            try:
                r = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{P}", "-servername", "b.l4.test",
                                    "-CAfile", self.ca_b, "-verify_return_error", "-quiet"],
                                   input=b"ping-openssl\n", capture_output=True, timeout=20)
                ok = b"B:ping-openssl" in r.stdout
                self.check("l4.openssl.b.routed", ok, f"rc {r.returncode} out {r.stdout[-80:]!r}")
                if ok:
                    self.expect_up["b"] += 1
                    self.audit_l4("l4", "b.l4.test", ub, "127.0.0.1")
            except subprocess.TimeoutExpired:
                self.check("l4.openssl.b.routed", False, "openssl s_client timed out")
        for vid, sni in [("unknown-sni", "c.l4.test"), ("no-sni", None), ("suffix-sni", "x.a.l4.test")]:
            out, p, err = self.l4_session(P, sni, None)
            self.check(f"l4.{vid}.closed", out is None and not p.recvd,
                       f"{len(p.recvd)} byte(s) back, out {out!r} (L4-1: never a default upstream)")
        for vid, data in [("http-get", b"GET / HTTP/1.1\r\nHost: a.l4.test\r\n\r\n"),
                          ("http-connect", b"CONNECT a.l4.test:443 HTTP/1.1\r\nHost: a.l4.test\r\n\r\n"),
                          ("h2-preface", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")]:
            self.refused(f"l4.{vid}.not-http", P, data)
            self.refused(f"l4.{vid}.not-http-open", P, data, half_close=False)

        def vec(v):
            data = bytes.fromhex(v["hex"])
            name = f"l4.vector.{v['id']}"
            if v["route"] in ("a", "b"):
                s = connect(P)
                send_half_close(s, data)
                expect_closed(s, 10)
                s.close()
                up, addr = ups[v["route"]]
                ok = up.find(data)
                self.check(name, ok, f"upstream {v['route']} did not receive the record byte-exact")
                if ok:
                    with self.lock:
                        self.expect_up[v["route"]] += 1
                    self.audit_l4("l4", v["sni"], addr, "127.0.0.1")
            else:
                self.refused(name, P, data, half_close=True)

        with concurrent.futures.ThreadPoolExecutor(8) as ex:
            list(ex.map(vec, self.cv["vectors"]))

    def l4p_checks(self):
        P = self.p_l4p
        ua, ub = f"127.0.0.1:{self.ua.port}", f"127.0.0.1:{self.ub.port}"
        hdr = pp.encode(src="198.51.100.7", dst="192.0.2.1", sport=4242, dport=443, tlvs=[pp.tlv(3, None)])
        out, p, err = self.l4_session(P, "a.l4.test", "a", prefix=hdr, src="127.0.0.2")
        ok = out == b"A:hello-a.l4.test\n"
        self.check("l4p.trusted.routed", ok, f"got {out!r} err {err!r}")
        if ok:
            self.expect_up["a"] += 1
            self.audit_proxy("l4p", "198.51.100.7", "127.0.0.2")
            self.audit_l4("l4p", "a.l4.test", ua, "198.51.100.7")
            self.check("l4p.trusted.header-stripped-byte-exact", self.ua.find(bytes(p.sent[len(hdr):])),
                       "upstream must receive exactly the TLS bytes, never the PROXY header")
        local = pp.encode(cmd=0, fam=0, proto=0, addr=b"")
        out, p, err = self.l4_session(P, "b.l4.test", "b", prefix=local, src="127.0.0.2")
        ok = out == b"B:hello-b.l4.test\n"
        self.check("l4p.trusted-local.routed", ok, f"got {out!r} err {err!r}")
        if ok:
            self.expect_up["b"] += 1
            self.audit_proxy("l4p", "127.0.0.2", "127.0.0.2")
            self.audit_l4("l4p", "b.l4.test", ub, "127.0.0.2")
        n_a, n_b = self.ua.count(), self.ub.count()
        out, p, err = self.l4_session(P, "a.l4.test", "a", prefix=hdr, src="127.0.0.3")
        self.check("l4p.untrusted-header.refused", out is None and not p.recvd,
                   f"{len(p.recvd)} byte(s) back (PROXY-1)")
        out, p, err = self.l4_session(P, "b.l4.test", "b", src="127.0.0.3")
        ok = out == b"B:hello-b.l4.test\n"
        self.check("l4p.untrusted-direct.routed", ok, f"got {out!r} err {err!r}")
        if ok:
            self.expect_up["b"] += 1
            self.audit_l4("l4p", "b.l4.test", ub, "127.0.0.3")
        out, p, err = self.l4_session(P, "a.l4.test", "a", src="127.0.0.2")
        self.check("l4p.trusted-no-header.refused", out is None and not p.recvd,
                   f"{len(p.recvd)} byte(s) back (never auto-detected)")
        # the header is admitted (proxy.accept), then the L4 layer refuses what follows
        self.refused("l4p.trusted-header-then-http", P, hdr + b"GET / HTTP/1.1\r\nHost: a.l4.test\r\n\r\n",
                     "127.0.0.2")
        self.audit_proxy("l4p", "198.51.100.7", "127.0.0.2")
        self.refused("l4p.trusted-header-unknown-sni", P, hdr + ch.record(ch.build(sni="c.l4.test", seed=5)),
                     "127.0.0.2")
        self.audit_proxy("l4p", "198.51.100.7", "127.0.0.2")
        self.refused("l4p.trusted-v1", P, b"PROXY TCP4 198.51.100.1 192.0.2.1 1 443\r\n" +
                     ch.record(ch.build(sni="a.l4.test", seed=6)), "127.0.0.2")
        time.sleep(0.3)
        self.check("l4p.refusals-reach-no-upstream", self.ua.count() == n_a and self.ub.count() == n_b + 1,
                   f"upstream connections a +{self.ua.count() - n_a} b +{self.ub.count() - n_b} (expected a +0 b +1)")

    # -------------------------------------------------------------------------------------------- audit

    def read_audit(self):
        events = {}
        for root, _, files in os.walk(self.audit_dir):
            if f"{os.sep}tile{os.sep}entries" not in root + os.sep:
                continue
            proc = root.split(f"{os.sep}tile{os.sep}entries")[0]
            for fn in files:
                if fn.startswith(".tmp") or fn.endswith(".tmp"):
                    continue
                with open(os.path.join(root, fn), "rb") as f:
                    data = f.read()
                off = 0
                while off + 2 <= len(data):
                    n = int.from_bytes(data[off:off + 2], "big")
                    leaf = data[off + 2:off + 2 + n]
                    off += 2 + n
                    try:
                        ev = json.loads(leaf)
                    except ValueError:
                        raise RuntimeError(f"audit leaf is not JSON: {leaf[:80]!r}")
                    events[(proc, ev.get("seq"))] = ev
        return list(events.values())

    def audit_checks(self):
        self.check("upstream.a.connections", self.ua.count() == self.expect_up["a"],
                   f"{self.ua.count()} connections, expected {self.expect_up['a']} (refused traffic must reach none)")
        self.check("upstream.b.connections", self.ub.count() == self.expect_up["b"],
                   f"{self.ub.count()} connections, expected {self.expect_up['b']}")
        try:
            evs = self.read_audit()
        except (OSError, RuntimeError) as e:
            self.check("audit.read", False, str(e))
            return
        got = collections.Counter()
        bad = []
        for ev in evs:
            a, d = ev.get("action"), ev.get("detail") or {}
            if a == "proxy.accept":
                if ev.get("outcome") != "allow":
                    bad.append(f"proxy.accept outcome {ev.get('outcome')}")
                got[(a, ev.get("object"), norm_ip(d.get("peer")), norm_ip(d.get("via")))] += 1
            elif a == "l4.route":
                if ev.get("outcome") != "allow":
                    bad.append(f"l4.route outcome {ev.get('outcome')}")
                got[(a, ev.get("object"), str(d.get("sni", "")).lower(), d.get("upstream"),
                     norm_ip(d.get("peer")))] += 1
        self.check("audit.outcomes", not bad, "; ".join(bad[:5]))
        missing = self.expect_audit - got
        extra = got - self.expect_audit
        self.check("audit.proxy-and-l4-events", not missing and not extra,
                   f"missing {sorted(missing.items())[:6]} extra {sorted(extra.items())[:6]} "
                   f"({sum(got.values())} events read, {sum(self.expect_audit.values())} expected)")

    # -------------------------------------------------------------------------------------------- boot

    def boot_checks(self):
        def first_l4(d):
            return next(x for x in d["listeners"] if x["name"] == "l4")

        variants = [
            ("cidr-prefix-33", lambda d: d["listeners"][0]["proxy_protocol"].update(trusted=["127.0.0.0/33"])),
            ("cidr-garbage", lambda d: d["listeners"][0]["proxy_protocol"].update(trusted=["localhost"])),
            ("l4-duplicate-sni", lambda d: first_l4(d)["l4"][1].update(sni="A.L4.TEST")),
            ("l4-bad-upstream", lambda d: first_l4(d)["l4"][0].update(upstream="no-port")),
            ("l4-and-alpn", lambda d: first_l4(d).update(alpn=["http/1.1"])),
        ]
        for vid, mut in variants:
            self.p_pub, self.p_plain, self.p_l4, self.p_l4p, self.p_admin = (free_port() for _ in range(5))
            if self.v6:
                self.p_pub6 = free_port(socket.AF_INET6, "::1")
            proc = self.start(self.config(mut), os.path.join(self.dir, f"audit-boot-{vid}"))
            bound = False
            until = time.time() + 15
            while time.time() < until and proc.poll() is None:
                for port in (self.p_pub, self.p_l4):
                    try:
                        socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                        bound = True
                    except OSError:
                        pass
                time.sleep(0.1)
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                self.check(f"boot.{vid}.exit-78", False, "subject kept running on a config it must refuse")
            else:
                self.check(f"boot.{vid}.exit-78", proc.returncode == 78 and not bound,
                           f"exit {proc.returncode}, accepted a connection: {bound}")


# ------------------------------------------------------------------------------------------------ entry points


def subject_cmd(s):
    if s == "ref":
        return [sys.executable, "-I", os.path.join(HERE, "ref_server.py")]
    p = s if os.path.isabs(s) else os.path.join(os.getcwd(), s)
    return [p]


def run_once(subject, mutant=None, verbose=False):
    env = {"AEGIS_PROXY_L4_REF_MUTANT": mutant} if mutant else {}
    r = Run(subject_cmd(subject), env, verbose)
    ok = r.run()
    notes = ("; " + "; ".join(r.notes)) if r.notes else ""
    if ok:
        print(f"{NAME}: PASS ({r.passed} checks; {r.pv['count']} PROXY vectors incl. {r.pv['hostile']} hostile, "
              f"{r.cv['count']} ClientHello vectors{notes})")
    else:
        print(f"{NAME}: FAIL ({len(r.failures)} failed, {r.passed} passed: {', '.join(r.failures[:8])}"
              f"{' ...' if len(r.failures) > 8 else ''}{notes})")
    return ok


def self_test(jobs):
    lines = []
    ok_all = True
    dp, dc, pv, cv = vectors_check.check()
    base_ok = not dp and not dc
    print(f"  reference parsers vs vectors: {len(dp) + len(dc)} divergences ({pv['count']} PROXY, {cv['count']} "
          f"ClientHello)", flush=True)
    ok_all &= base_ok
    vcaught = []
    for m in VECTOR_MUTANTS:
        a, b, _, _ = vectors_check.check(m)
        n = len(a) + len(b)
        print(f"  vector mutant {m}: {n} divergences -> {'caught' if n else 'MISSED'}", flush=True)
        if n:
            vcaught.append(m)
        ok_all &= bool(n)
    me = [sys.executable, "-I", os.path.abspath(__file__)]
    runs = [("reference", [])] + [(m, ["--ref-mutant", m]) for m in E2E_MUTANTS]

    def child(item):
        name, extra = item
        r = subprocess.run(me + ["--subject", "ref"] + extra, capture_output=True, text=True, timeout=900)
        return name, r.returncode, r.stdout

    with concurrent.futures.ThreadPoolExecutor(jobs) as ex:
        results = list(ex.map(child, runs))
    ecaught = []
    for name, rc, out in results:
        last = out.strip().splitlines()[-1] if out.strip() else "(no output)"
        fails = [ln.strip()[5:].split(":")[0] for ln in out.splitlines() if ln.strip().startswith("FAIL ")]
        if name == "reference":
            print(f"  reference subject: {last}", flush=True)
            if rc != 0:
                print(out[-3000:])
            ok_all &= rc == 0
        else:
            caught = rc != 0
            print(f"  e2e mutant {name}: {'caught' if caught else 'MISSED'} by {len(fails)} check(s): "
                  f"{', '.join(fails[:4])}{' ...' if len(fails) > 4 else ''}", flush=True)
            if caught:
                ecaught.append(name)
            ok_all &= caught
    lines.append(f"{len(ecaught)}/{len(E2E_MUTANTS)} e2e mutants, {len(vcaught)}/{len(VECTOR_MUTANTS)} vector mutants "
                 "caught; reference PASS" if ok_all else "see above")
    print(f"{NAME} SELF-TEST: {'PASS' if ok_all else 'FAIL'} ({lines[-1]})")
    return ok_all


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", "--subject", dest="subject", help="monban binary (built with proxy-protocol,l4)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--ref-mutant", help=argparse.SUPPRESS)
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("-v", "--verbose", action="count", default=0)
    a = ap.parse_args()
    if a.self_test:
        return 0 if self_test(a.jobs) else 1
    subj = a.subject or "target/release/monban"
    if subj != "ref" and not os.path.exists(subj):
        print(f"{NAME}: FAIL (subject {subj} not found)")
        return 1
    return 0 if run_once(subj, a.ref_mutant, a.verbose) else 1


if __name__ == "__main__":
    sys.exit(main())
