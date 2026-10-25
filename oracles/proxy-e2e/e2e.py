"""AEGIS oracle: reverse-proxy end-to-end (P2-proxy-001). Stdlib only; run as `python3 -I e2e.py`.

Drives a real `aegis` binary over TLS against a recording upstream that stores exactly the bytes it receives,
and checks forwarding (CANON-4: upstream sees framing regenerated from Canon, never the client's bytes), the q4-008
per-clause outcomes (308 for `//`, trailing slash distinct, opaque query), CANON-6 421, INV-NONEMPTY (route without
authz => 403, upstream never sees it), the admin metrics endpoint (every golden family, counters move), CFG-3
last-known-good on a bad reload, CRS C5 (no upstream connection reuse across a config change) and the fail-closed
boot (exit 78, nothing bound). See README.md.
"""

import argparse
import http.client
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

NAME = "PROXY-E2E"
GOLDEN = [
    "aegis_admission_rejects",
    "aegis_budget_debits",
    "aegis_crash_budget_trips",
    "aegis_cert_seconds_to_expiry",
    "aegis_fips_status",
    "aegis_config_generation_hash",
    "aegis_config_lkg_fallbacks",
    "aegis_upgrade_forced_closes",
]
MUTANTS = ["raw-path", "skip-authz-deny", "skip-lkg"]
HOP = {b"connection", b"keep-alive", b"transfer-encoding", b"te", b"trailer", b"upgrade", b"proxy-connection"}


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ------------------------------------------------------------------------------------------------ recording upstream


class Recorder:
    """HTTP/1.1 upstream that records every request exactly as received (raw head, parsed fields, body, conn id)."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.lock = threading.Lock()
        self.reqs = []
        self.conns = 0
        self.stop = False
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self.stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with self.lock:
                self.conns += 1
                cid = self.conns
            threading.Thread(target=self._serve, args=(c, cid), daemon=True).start()

    def _serve(self, c, cid):
        c.settimeout(30)
        buf = b""
        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    d = c.recv(65536)
                    if not d:
                        return
                    buf += d
                head, _, buf = buf.partition(b"\r\n\r\n")
                lines = head.split(b"\r\n")
                method, target, version = (lines[0].split(b" ", 2) + [b"", b""])[:3]
                fields = []
                for ln in lines[1:]:
                    n, _, v = ln.partition(b":")
                    fields.append((n, v.strip(b" \t")))
                low = {n.lower(): v for n, v in fields}
                body = b""
                if b"transfer-encoding" in low:
                    body = b"<chunked: not allowed upstream>"
                    while b"0\r\n\r\n" not in buf:
                        d = c.recv(65536)
                        if not d:
                            break
                        buf += d
                    buf = b""
                elif b"content-length" in low:
                    n = int(low[b"content-length"])
                    while len(buf) < n:
                        d = c.recv(65536)
                        if not d:
                            return
                        buf += d
                    body, buf = buf[:n], buf[n:]
                rec = {"conn": cid, "head": head, "method": method, "target": target, "version": version,
                       "fields": fields, "body": body}
                with self.lock:
                    self.reqs.append(rec)
                    seq = len(self.reqs)
                extra = b""
                if target.startswith(b"/api/hop"):
                    extra = b"Connection: x-hop\r\nX-Hop: secret\r\nKeep-Alive: timeout=5\r\n"
                rb = b"upstream-ok %d\n" % seq
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Upstream: rec\r\n" + extra +
                          b"Content-Length: %d\r\n\r\n" % len(rb) + rb)
        except (OSError, ValueError):
            return
        finally:
            c.close()

    def count(self):
        with self.lock:
            return len(self.reqs)

    def last(self):
        with self.lock:
            return self.reqs[-1] if self.reqs else None

    def close(self):
        self.stop = True
        try:
            self.sock.close()
        except OSError:
            pass


# ------------------------------------------------------------------------------------------------ clients


class SNIConn(http.client.HTTPSConnection):
    """http.client over TLS to 127.0.0.1 with an explicit SNI (the Host header is set by the caller)."""

    def __init__(self, port, sni, ctx):
        super().__init__("127.0.0.1", port, context=ctx, timeout=15)
        self._sni = sni

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._sni)


class H1:
    def __init__(self, port, cafile):
        self.port = port
        self.ctx = ssl.create_default_context(cafile=cafile)
        self.ctx.set_alpn_protocols(["http/1.1"])

    def req(self, method, path, host, headers=(), body=None, sni="aegis.test", chunked=False, conn=None):
        own = conn is None
        c = conn or SNIConn(self.port, sni, self.ctx)
        c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        c.putheader("Host", host)
        for k, v in headers:
            c.putheader(k, v)
        if chunked:
            c.putheader("Transfer-Encoding", "chunked")
        elif body is not None:
            c.putheader("Content-Length", str(len(body)))
        c.endheaders()
        if body is not None:
            if chunked:
                for i in range(0, len(body), 4):
                    part = body[i:i + 4]
                    c.send(b"%x\r\n" % len(part) + part + b"\r\n")
                c.send(b"0\r\n\r\n")
            else:
                c.send(body)
        r = c.getresponse()
        data = r.read()
        out = (r.status, {k.lower(): v for k, v in r.getheaders()}, data)
        if own:
            c.close()
        return out

    def conn(self, sni="aegis.test"):
        return SNIConn(self.port, sni, self.ctx)


def curl_has_h2():
    if not shutil.which("curl"):
        return False
    try:
        out = subprocess.run(["curl", "-V"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return "HTTP2" in out


def curl_h2(port, cafile, path, host=None):
    url = f"https://aegis.test:{port}{path}"
    cmd = ["curl", "-sS", "--http2", "--cacert", cafile, "--resolve", f"aegis.test:{port}:127.0.0.1",
           "-o", "-", "-w", "\n%{http_code} %{http_version}", "-H", "X-H2:  spaced value ", url]
    if host:
        cmd += ["-H", f"Host: {host}"]
    p = subprocess.run(cmd, capture_output=True, timeout=20)
    body, _, tail = p.stdout.rpartition(b"\n")
    parts = tail.decode(errors="replace").split()
    code = int(parts[0]) if parts and parts[0].isdigit() else 0
    ver = parts[1] if len(parts) > 1 else "?"
    return code, ver, body


def admin_get(port, path):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        c.request("GET", path)
        r = c.getresponse()
        return r.status, r.read().decode(errors="replace")
    finally:
        c.close()


def metric(text, sample):
    for ln in text.splitlines():
        if ln.startswith(sample + " "):
            try:
                return float(ln.split()[-1])
            except ValueError:
                return None
    return None


# ------------------------------------------------------------------------------------------------ harness


class Run:
    def __init__(self, subject, env_extra=None, verbose=False):
        self.subject = subject
        self.env_extra = env_extra or {}
        self.verbose = verbose
        self.failures = []
        self.passed = 0
        self.notes = []
        self.dir = tempfile.mkdtemp(prefix="aegis-proxy-e2e-")
        self.proc = None
        self.up = None

    def check(self, name, ok, detail=""):
        if ok:
            self.passed += 1
            if self.verbose:
                print(f"  ok   {name}")
        else:
            self.failures.append(name)
            print(f"  FAIL {name}: {detail}")

    def cert(self):
        if not shutil.which("openssl"):
            raise RuntimeError("openssl CLI not found (needed to mint the test certificate)")
        key, crt = os.path.join(self.dir, "key.pem"), os.path.join(self.dir, "cert.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-keyout", key, "-out", crt, "-days", "30", "-subj", "/CN=aegis.test",
                        "-addext", "subjectAltName=DNS:aegis.test,DNS:other.test"],
                       check=True, capture_output=True, timeout=30)
        return crt, key

    def config(self, extra_route=False):
        u = f"127.0.0.1:{self.up.port}"
        routes = [
            {"id": 1, "path": "/api/", "to": {"upstream": u}, "authz": "allow-all"},
            {"id": 2, "path": "/exact", "to": {"upstream": u, "framing": "h1-regenerate"}, "authz": "allow-all"},
            {"id": 3, "path": "/noauthz/", "to": {"upstream": u}},
            {"id": 4, "path": "/cedar/", "to": {"upstream": u}, "authz": "some-cedar-policy-set"},
        ]
        if extra_route:
            routes.append({"id": 5, "path": "/new/", "to": {"upstream": u}, "authz": "allow-all"})
        return {
            "v": 1,
            "listeners": [{"name": "pub", "bind": f"127.0.0.1:{self.port}", "profile": "P-PUBLIC-WEB",
                           "alpn": ["h2", "http/1.1"]}],
            "admin": {"bind": f"127.0.0.1:{self.aport}"},
            "vhosts": [
                {"host": "aegis.test", "routes": routes},
                {"host": "other.test", "routes": [{"id": 1, "path": "/", "to": {"upstream": u}, "authz": "allow-all"}]},
            ],
        }

    def write_config(self, doc):
        with open(self.cfg_path, "w") as f:
            if isinstance(doc, str):
                f.write(doc)
            else:
                json.dump(doc, f)

    def start(self):
        env = dict(os.environ)
        env.pop("NOTIFY_SOCKET", None)
        env.pop("AEGIS_UPGRADE_DIR", None)
        env.pop("AEGIS_E2E_MUTANT", None)
        env.update(self.env_extra)
        self.log = open(os.path.join(self.dir, "aegis.log"), "wb")
        self.proc = subprocess.Popen([self.subject, "--config", self.cfg_path, "--cert", self.crt, "--key", self.key,
                                      "--audit-dir", os.path.join(self.dir, "audit")],
                                     stdout=self.log, stderr=subprocess.STDOUT, env=env)
        until = time.time() + 20
        while time.time() < until:
            if self.proc.poll() is not None:
                raise RuntimeError(f"subject exited {self.proc.returncode} at start: {self.tail()}")
            try:
                st, _ = admin_get(self.aport, "/healthz")
                if st == 200:
                    return
            except OSError:
                pass
            time.sleep(0.1)
        raise RuntimeError("subject did not become healthy within 20 s")

    def tail(self):
        try:
            with open(os.path.join(self.dir, "aegis.log"), "rb") as f:
                return f.read()[-2000:].decode(errors="replace")
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
        if self.up:
            self.up.close()

    def metrics(self):
        st, text = admin_get(self.aport, "/metrics")
        return text if st == 200 else ""

    def sighup_and_wait(self, sample, before):
        self.proc.send_signal(signal.SIGHUP)
        until = time.time() + 10
        while time.time() < until:
            v = metric(self.metrics(), sample)
            if v is not None and v > before:
                return True
            time.sleep(0.1)
        return False

    # -------------------------------------------------------------------------------------------- checks

    def run(self):
        try:
            self.crt, self.key = self.cert()
            self.up = Recorder()
            self.port, self.aport = free_port(), free_port()
            self.cfg_path = os.path.join(self.dir, "aegis.json")
            self.write_config(self.config())
            self.start()
            self.checks()
        except Exception as e:  # noqa: BLE001 - any harness error is a FAIL with its reason
            self.failures.append(f"harness: {e}")
            print(f"  FAIL harness: {e}\n{self.tail()}")
        finally:
            self.stop()
            shutil.rmtree(self.dir, ignore_errors=True)
        self.boot_checks()
        return not self.failures

    def checks(self):
        h1 = H1(self.port, self.crt)
        P = self.port
        host = f"AEGIS.test:{P}"  # canonical authority is lowercase
        auth = f"aegis.test:{P}".encode()

        # --- GET: canonical path / query / headers; framing regenerated
        n0 = self.up.count()
        st, hd, body = h1.req("GET", "/api/%7euser/%c3%a9?b=2&a=%7e1&b=3", host,
                              headers=[("X-Test", "   spaced  value  "), ("Connection", "keep-alive, X-Drop"),
                                       ("X-Drop", "hop"), ("Keep-Alive", "timeout=5")])
        r = self.up.last()
        self.check("get.status", st == 200 and body.startswith(b"upstream-ok"), f"status {st} body {body[:60]!r}")
        self.check("get.forwarded", self.up.count() == n0 + 1, "upstream did not see exactly one request")
        if r:
            self.check("get.request-line", r["head"].split(b"\r\n")[0] == b"GET /api/~user/%C3%A9?b=2&a=~1&b=3 HTTP/1.1",
                       f"upstream saw {r['head'].split(chr(13).encode())[0]!r}")
            names = [n for n, _ in r["fields"]]
            low = dict((n.lower(), v) for n, v in r["fields"])
            self.check("get.host-canonical", low.get(b"host") == auth, f"host {low.get(b'host')!r}")
            self.check("get.single-host", [n.lower() for n in names].count(b"host") == 1, f"fields {names!r}")
            self.check("get.header-canonical", (b"x-test", b"spaced  value") in r["fields"],
                       f"fields {r['fields']!r}")
            self.check("get.names-lowercase", all(n == n.lower() for n in names), f"names {names!r}")
            self.check("get.hop-by-hop-stripped",
                       not any(n.lower() in HOP or n.lower() == b"x-drop" for n in names), f"names {names!r}")
            self.check("get.no-body-framing", b"content-length" not in low and b"transfer-encoding" not in low,
                       f"fields {r['fields']!r}")

        # --- POST: chunked from the client => content-length to the upstream; body exact
        payload = b"hello, chunked world"
        st, _, _ = h1.req("POST", "/api/post", f"aegis.test:{P}", headers=[("Content-Type", "text/plain")],
                          body=payload, chunked=True)
        r = self.up.last()
        low = dict((n.lower(), v) for n, v in r["fields"]) if r else {}
        self.check("post.chunked.status", st == 200, f"status {st}")
        self.check("post.chunked.regenerated", r is not None and r["method"] == b"POST" and r["body"] == payload
                   and low.get(b"content-length") == str(len(payload)).encode() and b"transfer-encoding" not in low,
                   f"upstream saw {r and r['head']!r} body {r and r['body']!r}")
        st, _, _ = h1.req("POST", "/api/post2", f"aegis.test:{P}", body=b"abc")
        r = self.up.last()
        self.check("post.length", st == 200 and r["body"] == b"abc" and r["target"] == b"/api/post2",
                   f"status {st} upstream {r and r['head']!r}")

        # --- response hop-by-hop fields are not relayed
        st, hd, _ = h1.req("GET", "/api/hop", f"aegis.test:{P}")
        self.check("response.hop-by-hop", st == 200 and "x-hop" not in hd and "keep-alive" not in hd
                   and hd.get("x-upstream") == "rec", f"status {st} headers {hd}")

        # --- trailing slash is its own canonical form (q4-008)
        st, _, _ = h1.req("GET", "/exact", f"aegis.test:{P}")
        r = self.up.last()
        self.check("slash.exact", st == 200 and r["target"] == b"/exact", f"status {st} target {r and r['target']!r}")
        n0 = self.up.count()
        st, _, _ = h1.req("GET", "/exact/", f"aegis.test:{P}")
        self.check("slash.distinct", st == 404 and self.up.count() == n0, f"status {st}")
        st, _, _ = h1.req("GET", "/api/dir/", f"aegis.test:{P}")
        r = self.up.last()
        self.check("slash.kept", st == 200 and r["target"] == b"/api/dir/", f"status {st} target {r and r['target']!r}")

        # --- opaque query: byte order kept, never split or sorted; malformed rejected
        st, _, _ = h1.req("GET", "/api/q?z=1&a=2&z=3&%41=x", f"aegis.test:{P}")
        r = self.up.last()
        self.check("query.opaque", st == 200 and r["target"] == b"/api/q?z=1&a=2&z=3&A=x",
                   f"status {st} target {r and r['target']!r}")
        n0 = self.up.count()
        st, _, _ = h1.req("GET", "/api/q?a=%zz", f"aegis.test:{P}")
        self.check("query.malformed", st == 400 and self.up.count() == n0, f"status {st}")

        # --- // => 308 to the merged path, never forwarded
        n0 = self.up.count()
        st, hd, _ = h1.req("GET", "/api//x?q=1", f"aegis.test:{P}")
        self.check("empty-segment.308", st == 308 and hd.get("location") == "/api/x?q=1" and self.up.count() == n0,
                   f"status {st} location {hd.get('location')!r}")
        n0 = self.up.count()
        st, _, _ = h1.req("GET", "/api/a/../b", f"aegis.test:{P}")
        self.check("dot-segment.400", st == 400 and self.up.count() == n0, f"status {st}")

        # --- CANON-6: SNI aegis.test, Host other.test => 421
        n0 = self.up.count()
        st, _, _ = h1.req("GET", "/api/x", "other.test", sni="aegis.test")
        self.check("sni-host.421", st == 421 and self.up.count() == n0, f"status {st}")
        st, _, _ = h1.req("GET", "/x", "other.test", sni="other.test")
        self.check("other-vhost.ok", st == 200, f"status {st}")

        # --- INV-NONEMPTY: route without authz => 403, upstream never sees it; unknown policy => 403
        n0 = self.up.count()
        st, _, _ = h1.req("GET", "/noauthz/x", f"aegis.test:{P}")
        self.check("noauthz.403", st == 403, f"status {st}")
        st2, _, _ = h1.req("POST", "/noauthz/x", f"aegis.test:{P}", body=b"x" * 10)
        self.check("noauthz.never-forwarded", st2 == 403 and self.up.count() == n0, f"status {st2}")
        n0 = self.up.count()
        st, _, _ = h1.req("GET", "/cedar/x", f"aegis.test:{P}")
        self.check("unknown-policy.403", st == 403 and self.up.count() == n0, f"status {st}")

        # --- HTTP/2 (curl --http2)
        if curl_has_h2():
            n0 = self.up.count()
            code, ver, body = curl_h2(P, self.crt, "/api/h2%7e?x=%7e")
            r = self.up.last()
            self.check("h2.status", code == 200 and ver == "2" and body.startswith(b"upstream-ok"),
                       f"code {code} version {ver}")
            if r and self.up.count() == n0 + 1:
                low = dict((n.lower(), v) for n, v in r["fields"])
                self.check("h2.regenerated-h1", r["head"].split(b"\r\n")[0] == b"GET /api/h2~?x=~ HTTP/1.1"
                           and low.get(b"host") == auth and (b"x-h2", b"spaced value") in r["fields"],
                           f"upstream saw {r['head']!r}")
            else:
                self.check("h2.regenerated-h1", False, "upstream did not see the h2 request")
            n0 = self.up.count()
            code, _, _ = curl_h2(P, self.crt, "/api/x", host="other.test")
            self.check("h2.sni-authority.421", code == 421 and self.up.count() == n0, f"code {code}")
            code, _, _ = curl_h2(P, self.crt, "/noauthz/x")
            self.check("h2.noauthz.403", code == 403 and self.up.count() == n0, f"code {code}")
            code, _, _ = curl_h2(P, self.crt, "/api//x")
            self.check("h2.empty-segment.308", code == 308 and self.up.count() == n0, f"code {code}")
        else:
            self.notes.append("h2 not exercised (curl without HTTP2)")

        # --- admin /metrics: every golden family; counters move
        m1 = self.metrics()
        missing = [f for f in GOLDEN if f"# TYPE {f} " not in m1]
        self.check("metrics.golden-families", not missing and m1.rstrip().endswith("# EOF"), f"missing {missing}")
        st, hz = admin_get(self.aport, "/healthz")
        self.check("healthz", st == 200 and '"status":"ok"' in hz, f"{st} {hz!r}")
        d0 = metric(m1, 'aegis_budget_debits_total{scope="ip"}') or 0
        a0 = metric(m1, "aegis_proxy_authz_denied_total") or 0
        h1.req("GET", "/api/m", f"aegis.test:{P}")
        h1.req("GET", "/noauthz/m", f"aegis.test:{P}")
        m2 = self.metrics()
        self.check("metrics.counters-move", (metric(m2, 'aegis_budget_debits_total{scope="ip"}') or 0) >= d0 + 2
                   and (metric(m2, "aegis_proxy_authz_denied_total") or 0) >= a0 + 1, "debits/denied did not move")
        cert = metric(m2, 'aegis_cert_seconds_to_expiry{slot="serving"}') or 0
        self.check("metrics.cert-gauge", 20 * 86400 < cert <= 31 * 86400, f"cert gauge {cert}")

        # --- CFG-3: a bad reload keeps the old config serving and counts a last-known-good fallback
        for label, bad in [("syntax", '{"v":1, "listeners": [}'),
                           ("plan", json.dumps({**self.config(), "vhosts": [{"host": "aegis.test", "routes": [
                               {"id": 1, "path": "/api/", "to": {"static": "/srv"}, "authz": "allow-all"}]}]}))]:
            lkg0 = metric(self.metrics(), "aegis_config_lkg_fallbacks_total") or 0
            self.write_config(bad)
            moved = self.sighup_and_wait("aegis_config_lkg_fallbacks_total", lkg0)
            self.check(f"lkg.{label}.counter", moved, "aegis_config_lkg_fallbacks did not increment")
            n0 = self.up.count()
            st, _, _ = h1.req("GET", "/api/after-bad-reload", f"aegis.test:{P}")
            self.check(f"lkg.{label}.old-config-serves", st == 200 and self.up.count() == n0 + 1, f"status {st}")
            st, _, _ = h1.req("GET", "/noauthz/x", f"aegis.test:{P}")
            self.check(f"lkg.{label}.old-config-denies", st == 403, f"status {st}")

        # --- CRS C5: pooled upstream connections are reused within a config, never across a change
        h1.req("GET", "/api/pool-a", f"aegis.test:{P}")
        ca = self.up.last()["conn"]
        h1.req("GET", "/api/pool-b", f"aegis.test:{P}")
        cb = self.up.last()["conn"]
        self.check("pool.reused-within-epoch", ca == cb, f"conn {ca} then {cb}")
        r0 = metric(self.metrics(), "aegis_proxy_config_reloads_total") or 0
        self.write_config(self.config(extra_route=True))
        applied = self.sighup_and_wait("aegis_proxy_config_reloads_total", r0)
        self.check("reload.applied", applied, "good reload not applied")
        st, _, _ = h1.req("GET", "/new/route", f"aegis.test:{P}")
        cc = self.up.last()["conn"]
        self.check("reload.new-route", st == 200 and self.up.last()["target"] == b"/new/route", f"status {st}")
        self.check("pool.not-reused-across-epoch", cc != cb, f"conn {cb} reused after config change")

    def boot_checks(self):
        # --- fail-closed boot: no config / invalid config => exit 78, nothing bound
        port = free_port()
        try:
            p = subprocess.run([self.subject], capture_output=True, timeout=20, env=self.clean_env())
            self.check("boot.no-config.78", p.returncode == 78, f"exit {p.returncode}")
            d = tempfile.mkdtemp(prefix="aegis-proxy-e2e-boot-")
            try:
                bad = os.path.join(d, "bad.json")
                with open(bad, "w") as f:
                    json.dump({"v": 1, "listeners": [{"name": "pub", "bind": f"127.0.0.1:{port}",
                                                      "profile": "P-PUBLIC-WEB"}],
                               "vhosts": [{"host": "aegis.test", "routes": [
                                   {"id": 1, "path": "/", "to": {"upstream": "127.0.0.1:1"}, "bogus": 1}]}]}, f)
                pr = subprocess.Popen([self.subject, "--config", bad, "--audit-dir", d], stdout=subprocess.DEVNULL,
                                      stderr=subprocess.PIPE, env=self.clean_env())
                listened = False
                until = time.time() + 5
                while pr.poll() is None and time.time() < until:
                    s = socket.socket()
                    s.settimeout(0.05)
                    try:
                        s.connect(("127.0.0.1", port))
                        listened = True
                    except OSError:
                        pass
                    finally:
                        s.close()
                rc = pr.wait(15)
                self.check("boot.invalid-config.78", rc == 78, f"exit {rc}")
                self.check("boot.invalid-config.nothing-bound", not listened and self.can_bind(port),
                           "a socket listened on the configured port")
                missing = os.path.join(d, "absent.json")
                rc2 = subprocess.run([self.subject, "--config", missing], capture_output=True, timeout=20,
                                     env=self.clean_env()).returncode
                self.check("boot.missing-file.78", rc2 == 78, f"exit {rc2}")
            finally:
                shutil.rmtree(d, ignore_errors=True)
        except (OSError, subprocess.SubprocessError) as e:
            self.check("boot", False, str(e))

    def clean_env(self):
        env = dict(os.environ)
        env.pop("NOTIFY_SOCKET", None)
        env.pop("AEGIS_UPGRADE_DIR", None)
        env.pop("CREDENTIALS_DIRECTORY", None)
        env.update(self.env_extra)
        return env

    @staticmethod
    def can_bind(port):
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False
        finally:
            s.close()


def run_subject(subject, env_extra=None, verbose=False):
    r = Run(subject, env_extra, verbose)
    ok = r.run()
    return ok, r


def build_mutant_subject(repo):
    target = os.path.join(repo, "target", "e2e-mutants")
    binp = os.path.join(target, "release", "aegis")
    env = dict(os.environ, CARGO_TARGET_DIR=target)
    print(f"building the negative-control subject ({binp}) through ci/heavy.sh ...")
    p = subprocess.run([os.path.join(repo, "ci", "heavy.sh"), "cargo", "build", "--release", "--locked", "-p",
                        "aegis-bin", "--features", "e2e-mutants"], cwd=repo, env=env)
    if p.returncode != 0 or not os.path.exists(binp):
        return None
    return binp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--subject", default="target/release/aegis")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--mutant-subject", default=None, help="prebuilt e2e-mutants binary for --self-test")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    if not a.self_test:
        subj = os.path.abspath(a.subject)
        if not os.access(subj, os.X_OK):
            print(f"{NAME}: FAIL (subject {subj} not executable)")
            return 1
        ok, r = run_subject(subj, verbose=a.verbose)
        note = ("; " + "; ".join(r.notes)) if r.notes else ""
        if ok:
            print(f"{NAME}: PASS ({r.passed} checks{note})")
            return 0
        print(f"{NAME}: FAIL ({len(r.failures)} failed: {', '.join(r.failures[:8])}{note})")
        return 1

    subj = a.mutant_subject or os.path.join(repo, "target", "e2e-mutants", "release", "aegis")
    if not os.access(subj, os.X_OK):
        subj = build_mutant_subject(repo)
        if not subj:
            print(f"{NAME} SELF-TEST: FAIL (could not build the e2e-mutants subject)")
            return 1
    print(f"self-test subject: {subj}")
    ok, r = run_subject(subj, verbose=a.verbose)
    if not ok:
        print(f"{NAME} SELF-TEST: FAIL (the unmutated e2e-mutants build must pass first: {r.failures[:5]})")
        return 1
    print(f"  baseline (no mutant): PASS ({r.passed} checks)")
    caught = []
    for m in MUTANTS:
        ok, r = run_subject(subj, {"AEGIS_E2E_MUTANT": m}, verbose=False)
        if ok:
            print(f"{NAME} SELF-TEST: FAIL (mutant {m} was not caught)")
            return 1
        print(f"  mutant {m}: caught by {', '.join(r.failures[:6])}")
        caught.append(m)
    print(f"{NAME} SELF-TEST: PASS ({len(caught)}/{len(MUTANTS)} mutants caught: {', '.join(caught)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
