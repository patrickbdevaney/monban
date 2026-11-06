"""AEGIS oracle front-equiv (P7-oracle-uring-001): FRONT-1 and D-P7.3. Stdlib only; run as `python3 -I equiv.py`.

FRONT-1: responses and rejects are a function of the request bytes, never of the front. The same binary is started
with `--front epoll` and then `--front uring` against one deterministic upstream; every corpus case (the proxy-e2e
forwarding corpus, strict-H1 rejects, pipelining, large and streamed bodies, keep-alive / close, h2 via curl, h2 and
h1 load via h2load, SIGHUP reload, SIGTERM drain) must give byte-identical normalized responses, the same close
behaviour and the same upstream view. Each front must also be the front it claims to be (/proc evidence), the
uring front must refuse to start when io_uring is unavailable, and the hardened systemd unit must refuse io_uring
unless deploy/uring.conf is installed. See README.md.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import unitcheck  # noqa: E402
from front_ref import parse_h1_response  # noqa: E402

NAME = "FRONT-EQUIV"
FRONT_MUTANTS = ["drop-last-chunk", "reorder-pipelined", "close-after-response", "normalize-bare-lf", "no-ring",
                 "socket-in-epoll", "silent-fallback", "config-front-ignored"]
UNIT_MUTANTS = ["unit-admits", "dropin-broad", "dropin-incomplete", "dropin-relaxes-other"]
VERBOSE = False


def log(msg):
    print(msg, flush=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def pattern(n):
    return (bytes(range(251)) * (n // 251 + 1))[:n]


# ------------------------------------------------------------------------------------------------ upstream


class Upstream:
    """Deterministic HTTP/1.1 upstream: every response is a function of the (port-normalized) request it received."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(512)
        self.port = self.sock.getsockname()[1]
        self.lock = threading.Lock()
        self.reqs = []
        self.pub = b"\x00"
        threading.Thread(target=self._accept, daemon=True).start()

    def norm(self, b):
        return b.replace(b":" + self.pub, b":{P}")

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
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
                target = (lines[0].split(b" ") + [b"", b""])[1]
                low = {}
                for ln in lines[1:]:
                    n, _, v = ln.partition(b":")
                    low[n.strip().lower()] = v.strip()
                body = b""
                if b"transfer-encoding" in low:
                    body = b"<chunked upstream request: framing not regenerated>"
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
                nh = self.norm(head)
                with self.lock:
                    self.reqs.append((nh, hashlib.sha256(body).hexdigest(), len(body)))
                if not self._respond(c, target, nh, body):
                    return
        except (OSError, ValueError):
            return
        finally:
            c.close()

    def _respond(self, c, target, nh, body):
        base = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nX-Upstream: det\r\n"
        m = re.match(rb"^/api/(big|bigchunked)/(\d+)$", target)
        if m:
            n = min(int(m.group(2)), 8 << 20)
            data = pattern(n)
            if m.group(1) == b"big":
                c.sendall(base + b"Content-Length: %d\r\n\r\n" % n + data)
            else:
                c.sendall(base + b"Transfer-Encoding: chunked\r\n\r\n")
                for i in range(0, n, 16384):
                    part = data[i:i + 16384]
                    c.sendall(b"%x\r\n" % len(part) + part + b"\r\n")
                c.sendall(b"0\r\n\r\n")
            return True
        if target == b"/api/slow":
            data = pattern(3000)
            c.sendall(base + b"Content-Length: 3000\r\n\r\n" + data[:1000])
            for i in (1000, 2000):
                time.sleep(0.2)
                c.sendall(data[i:i + 1000])
            return True
        if target == b"/api/close":
            c.sendall(base + b"Connection: close\r\n\r\n" + pattern(5000))
            return False
        extra = b"Connection: x-hop\r\nX-Hop: secret\r\nKeep-Alive: timeout=5\r\n" if target.startswith(b"/api/hop") \
            else b""
        rb = b"up " + hashlib.sha256(nh + b"\n" + body).hexdigest()[:24].encode() + b" %d\n" % len(body)
        c.sendall(base + extra + b"Content-Length: %d\r\n\r\n" % len(rb) + rb)
        return True

    def mark(self):
        with self.lock:
            return len(self.reqs)

    def since(self, n):
        with self.lock:
            return list(self.reqs[n:])


# ------------------------------------------------------------------------------------------------ /proc evidence


def proc_fds(pid):
    out = {}
    try:
        for fd in os.listdir(f"/proc/{pid}/fd"):
            try:
                out[int(fd)] = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                pass
    except OSError:
        pass
    return out


def fdinfo(pid, fd):
    try:
        with open(f"/proc/{pid}/fdinfo/{fd}") as f:
            return f.read()
    except OSError:
        return ""


def ring_tails(pid):
    """{ring inode: CqTail} for every io_uring instance the process holds."""
    out = {}
    for fd, link in proc_fds(pid).items():
        if link == "anon_inode:[io_uring]":
            info = fdinfo(pid, fd)
            m = re.search(r"^CqTail:\s*(\d+)", info, re.M)
            ino = re.search(r"^ino:\s*(\d+)", info, re.M)
            if m:
                out[ino.group(1) if ino else f"fd{fd}"] = int(m.group(1))
    return out


def cq_delta(before, after):
    d = 0
    for k, v in after.items():
        d += (v - before.get(k, 0)) & 0xFFFFFFFF
    return d


def epoll_registered(pid):
    """Set of fds registered in any eventpoll instance of the process (fdinfo `tfd:` lines)."""
    regs = set()
    for fd, link in proc_fds(pid).items():
        if link == "anon_inode:[eventpoll]":
            regs |= {int(x) for x in re.findall(r"^tfd:\s*(\d+)", fdinfo(pid, fd), re.M)}
    return regs


def tcp_inode(local_port, remote_port=None, listen=False):
    # The harness only ever binds and connects on 127.0.0.1 (IPv4): match that address, not just the port.
    for path in ("/proc/net/tcp",):
        try:
            lines = open(path).read().splitlines()[1:]
        except OSError:
            continue
        for ln in lines:
            f = ln.split()
            if f[1].split(":")[0] != "0100007F":
                continue
            lp = int(f[1].rsplit(":", 1)[1], 16)
            rp = int(f[2].rsplit(":", 1)[1], 16)
            st = f[3]
            if lp != local_port:
                continue
            if listen and st == "0A":
                return f[9]
            if not listen and rp == remote_port and st == "01":
                return f[9]
    return None


def fd_of_inode(pid, inode):
    for fd, link in proc_fds(pid).items():
        if link == f"socket:[{inode}]":
            return fd
    return None


# ------------------------------------------------------------------------------------------------ clients


DATE = re.compile(rb"(?im)^date: [^\r\n]*")


class Client:
    def __init__(self, cafile):
        self.cafile = cafile

    def tls(self, port, sni="aegis.test", alpn=("http/1.1",)):
        ctx = ssl.create_default_context(cafile=self.cafile)
        ctx.set_alpn_protocols(list(alpn))
        s = socket.create_connection(("127.0.0.1", port), 10)
        s = ctx.wrap_socket(s, server_hostname=sni)
        s.settimeout(8)
        return s


def read_one(s, buf, timeout=8.0):
    """Read one HTTP/1.1 response. Returns (bytes|None, buf, state) with state in ok/eof/timeout/error."""
    s.settimeout(timeout)
    while True:
        r = parse_h1_response(buf)
        if r is not None:
            return buf[:r[0]], buf[r[0]:], "ok"
        try:
            d = s.recv(65536)
        except socket.timeout:
            return None, buf, "timeout"
        except (OSError, ssl.SSLError):
            return (buf or None), b"", "error"
        if not d:
            return (buf or None), b"", "eof"
        buf += d


def close_state(s, timeout=1.5, buf=b""):
    """Close class after the last expected response: 'open' or 'closed', plus any bytes that arrived after it
    (including bytes already buffered behind the last parsed response). Returns (class, extra_bytes)."""
    extra, until = buf, time.time() + timeout
    while True:
        left = until - time.time()
        if left <= 0:
            return "open", extra
        s.settimeout(left)
        try:
            d = s.recv(65536)
        except socket.timeout:
            return "open", extra
        except (OSError, ssl.SSLError):
            return "closed", extra
        if not d:
            return "closed", extra
        extra += d


# ------------------------------------------------------------------------------------------------ corpus


def corpus(P):
    """(name, steps, sni, reject). steps: ('send', bytes) | ('frag', bytes, n) | ('read', n) | ('sleep', s)."""
    A = f"aegis.test:{P}".encode()

    def get(path, host=A, extra=b"", conn=b""):
        return b"GET " + path + b" HTTP/1.1\r\nHost: " + host + b"\r\n" + extra + conn + b"\r\n"

    def post(path, body, extra=b""):
        return b"POST " + path + b" HTTP/1.1\r\nHost: " + A + b"\r\n" + extra + \
            b"Content-Length: %d\r\n\r\n" % len(body) + body

    chunked = b"POST /api/post HTTP/1.1\r\nHost: " + A + b"\r\nContent-Type: text/plain\r\n" \
        b"Transfer-Encoding: chunked\r\n\r\n" + b"".join(b"4\r\n" + b"hell\r\n" for _ in range(3)) + b"0\r\n\r\n"
    big_up = pattern(256 * 1024)
    C = []
    # --- forwarding (proxy-e2e corpus)
    C.append(("get.canonical", [("send", get(b"/api/%7euser/%c3%a9?b=2&a=%7e1&b=3", b"AEGIS.test:%d" % P,
                                              b"X-Test:    spaced  value  \r\nConnection: keep-alive, X-Drop\r\n"
                                              b"X-Drop: hop\r\nKeep-Alive: timeout=5\r\n")), ("read", 1)], None, False))
    C.append(("post.chunked", [("send", chunked), ("read", 1)], None, False))
    C.append(("post.length", [("send", post(b"/api/post2", b"abc")), ("read", 1)], None, False))
    C.append(("post.large-256k", [("send", post(b"/api/up", big_up)), ("read", 1)], None, False))
    C.append(("response.hop-by-hop", [("send", get(b"/api/hop")), ("read", 1)], None, False))
    C.append(("slash.exact", [("send", get(b"/exact")), ("read", 1)], None, False))
    C.append(("slash.distinct-404", [("send", get(b"/exact/")), ("read", 1)], None, False))
    C.append(("slash.kept", [("send", get(b"/api/dir/")), ("read", 1)], None, False))
    C.append(("query.opaque", [("send", get(b"/api/q?z=1&a=2&z=3&%41=x")), ("read", 1)], None, False))
    C.append(("query.malformed-400", [("send", get(b"/api/q?a=%zz")), ("read", 1)], None, False))
    C.append(("empty-segment.308", [("send", get(b"/api//x?q=1")), ("read", 1)], None, False))
    C.append(("dot-segment.400", [("send", get(b"/api/a/../b")), ("read", 1)], None, False))
    C.append(("sni-host.421", [("send", get(b"/api/x", b"other.test")), ("read", 1)], "aegis.test", False))
    C.append(("other-vhost.200", [("send", get(b"/x", b"other.test")), ("read", 1)], "other.test", False))
    C.append(("noauthz.403", [("send", get(b"/noauthz/x")), ("read", 1)], None, False))
    C.append(("noauthz.post-403", [("send", post(b"/noauthz/x", b"x" * 10)), ("read", 1)], None, False))
    C.append(("unknown-policy.403", [("send", get(b"/cedar/x")), ("read", 1)], None, False))
    # --- bodies across many writes
    C.append(("body.big-1m", [("send", get(b"/api/big/1048576")), ("read", 1)], None, False))
    C.append(("body.big-chunked-upstream", [("send", get(b"/api/bigchunked/300000")), ("read", 1)], None, False))
    C.append(("body.streamed-slow", [("send", get(b"/api/slow")), ("read", 1)], None, False))
    C.append(("body.close-delimited-upstream", [("send", get(b"/api/close")), ("read", 1)], None, False))
    C.append(("body.big-then-small", [("send", get(b"/api/big/200000")), ("read", 1),
                                      ("send", get(b"/api/after-big")), ("read", 1)], None, False))
    # --- pipelining, fragmentation, keep-alive, close
    C.append(("pipeline.3", [("send", get(b"/api/p1") + get(b"/api/p2") + get(b"/api/p3")), ("read", 3)],
              None, False))
    C.append(("pipeline.mixed", [("send", post(b"/api/pm1", b"one") + get(b"/api/big/40000") + get(b"/noauthz/p")
                                  + get(b"/api/pm4")), ("read", 4)], None, False))
    C.append(("fragmented.1-byte-writes", [("frag", get(b"/api/frag?x=1"), 1), ("read", 1)], None, False))
    C.append(("fragmented.body", [("frag", post(b"/api/fragbody", b"z" * 3000), 700), ("read", 1)], None, False))
    C.append(("keepalive.sequential", [("send", get(b"/api/k1")), ("read", 1), ("sleep", 0.3),
                                       ("send", get(b"/api/k2")), ("read", 1)], None, False))
    C.append(("close.connection-close", [("send", get(b"/api/c1", conn=b"Connection: close\r\n")), ("read", 1)],
              None, False))
    C.append(("close.http10", [("send", b"GET /api/h10 HTTP/1.0\r\nHost: " + A + b"\r\n\r\n"), ("read", 1)],
              None, False))
    C.append(("expect.100-continue", [("send", b"POST /api/e HTTP/1.1\r\nHost: " + A +
                                       b"\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n"), ("sleep", 0.5),
                                      ("send", b"hello"), ("read", 2)], None, False))
    # --- strict-H1 rejects (aegis-transport h1.rs); each must be a reject on both fronts
    R = []
    R.append(("reject.bare-lf", b"GET /api/x HTTP/1.1\nHost: " + A + b"\n\n"))
    R.append(("reject.obs-fold", get(b"/api/x", extra=b"X-A: a\r\n b\r\n")))
    R.append(("reject.cl-and-te", b"POST /api/x HTTP/1.1\r\nHost: " + A +
              b"\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"))
    R.append(("reject.duplicate-cl", b"POST /api/x HTTP/1.1\r\nHost: " + A +
              b"\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc"))
    R.append(("reject.te-not-chunked", b"POST /api/x HTTP/1.1\r\nHost: " + A +
              b"\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n"))
    R.append(("reject.space-before-colon", b"GET /api/x HTTP/1.1\r\nHost : " + A + b"\r\n\r\n"))
    R.append(("reject.absolute-form", b"GET https://aegis.test:%d/api/x HTTP/1.1\r\nHost: " % P + A + b"\r\n\r\n"))
    R.append(("reject.leading-empty-line", b"\r\n" + get(b"/api/x")))
    R.append(("reject.nul-in-value", get(b"/api/x", extra=b"X-A: a\x00b\r\n")))
    R.append(("reject.te-on-http10", b"POST /api/x HTTP/1.0\r\nHost: " + A +
              b"\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"))
    R.append(("reject.bad-chunk-size", b"POST /api/x HTTP/1.1\r\nHost: " + A +
              b"\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n0\r\n\r\n"))
    R.append(("reject.bare-lf-chunk-line", b"POST /api/x HTTP/1.1\r\nHost: " + A +
              b"\r\nTransfer-Encoding: chunked\r\n\r\n3\nabc\r\n0\r\n\r\n"))
    R.append(("reject.expect-other-417", b"POST /api/x HTTP/1.1\r\nHost: " + A +
              b"\r\nExpect: something\r\nContent-Length: 3\r\n\r\nabc"))
    # 431s stay inside one TLS record (< 16 KiB): the server then has no unread TCP bytes when it closes, so no RST
    # can race the response away (a 70 KB head lost the 431 to the RST in 1 of 15 tries through the reference front).
    R.append(("reject.too-many-fields-431", get(b"/api/x", extra=b"".join(b"X-F%d: v\r\n" % i for i in range(140)))))
    R.append(("reject.field-block-too-large-431",
              get(b"/api/x", extra=b"".join(b"X-G%d: " % i + b"a" * 140 + b"\r\n" for i in range(100)))))
    R.append(("reject.bad-request-line", b"GET  /api/x HTTP/1.1\r\nHost: " + A + b"\r\n\r\n"))
    for name, raw in R:
        C.append((name, [("send", raw), ("read", 1)], None, True))
    C.append(("reject.after-good-on-same-conn", [("send", get(b"/api/good1")), ("read", 1),
                                                  ("send", b"GET /api/x HTTP/1.1\nHost: " + A + b"\n\n"),
                                                  ("read", 1)], None, False))
    C.append(("reject.smuggle-pipelined", [("send", b"POST /api/s HTTP/1.1\r\nHost: " + A +
                                            b"\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
                                            + get(b"/noauthz/smuggled")), ("read", 2)], None, True))
    return C


def run_case(cl, port, steps, sni):
    """Run one case. A failed write (the server closed while the client was still sending, e.g. after a 431) is a
    client-side timing artifact: later writes are skipped, but the reads still run, so the reject the server sent
    before closing is observed and compared, never the write error itself."""
    s = cl.tls(port, sni or "aegis.test")
    resps, buf, state, send_failed = [], b"", "ok", False
    try:
        for st in steps:
            if state != "ok":
                break
            if st[0] in ("send", "frag") and send_failed:
                continue
            try:
                if st[0] == "send":
                    s.sendall(st[1])
                elif st[0] == "frag":
                    data, n = st[1], st[2]
                    for i in range(0, len(data), n):
                        s.sendall(data[i:i + n])
                        time.sleep(0.002)
                elif st[0] == "sleep":
                    time.sleep(st[1])
            except (OSError, ssl.SSLError):
                send_failed = True
                continue
            if st[0] == "read":
                for _ in range(st[1]):
                    r, buf, state = read_one(s, buf)
                    if r is not None:
                        resps.append(r)
                    if state != "ok":  # eof vs reset is timing (unread bytes at close): one marker for both
                        resps.append(b"<timeout>" if state == "timeout" else b"<closed>")
                        break
        if state in ("eof", "error"):
            close, extra = "closed", b""
        else:
            close, extra = close_state(s, buf=buf)
    finally:
        s.close()
    return resps, close, extra


# ------------------------------------------------------------------------------------------------ h2load


def h2load_path():
    root = os.path.join(os.environ.get("AEGIS_TOOLS") or os.path.expanduser("~/.cache/aegis-tools"),
                        "h2load-1.69.0")
    bin_, ld = os.path.join(root, "usr/bin/h2load"), os.path.join(root, "lib/ld-musl-x86_64.so.1")
    stamp = os.path.join(root, ".complete")
    if os.path.exists(stamp) and os.access(ld, os.X_OK):
        return [ld, "--library-path", f"{root}/lib:{root}/usr/lib", bin_]
    os.makedirs(root, exist_ok=True)
    rows = [ln.split("\t") for ln in open(os.path.join(HERE, "h2load.lock")).read().splitlines()
            if ln and not ln.startswith("#")]
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
    open(stamp, "w").close()
    return [ld, "--library-path", f"{root}/lib:{root}/usr/lib", bin_]


def h2load(args, port, timeout=120):
    cmd = h2load_path() + [f"--connect-to=127.0.0.1:{port}"] + args
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    out = p.stdout + p.stderr
    m = re.search(r"requests: (\d+) total, (\d+) started, (\d+) done, (\d+) succeeded, (\d+) failed, (\d+) errored, "
                  r"(\d+) timeout", out)
    s = re.search(r"status codes: (\d+) 2xx, (\d+) 3xx, (\d+) 4xx, (\d+) 5xx", out)
    if not m or not s:
        return {"error": out.strip()[-400:]}
    k = ["total", "started", "done", "succeeded", "failed", "errored", "timeout"]
    r = dict(zip(k, map(int, m.groups())))
    r.update(dict(zip(["2xx", "3xx", "4xx", "5xx"], map(int, s.groups()))))
    return r


# ------------------------------------------------------------------------------------------------ one front


class Front:
    def __init__(self, binary, front_args, up, crt, key, d, env_extra=None, cfg_front=None):
        self.binary, self.front_args, self.up, self.crt, self.key, self.d = binary, front_args, up, crt, key, d
        self.env_extra = env_extra or {}
        self.cfg_front = cfg_front
        self.port, self.aport = free_port(), free_port()
        self.cfg = os.path.join(d, f"aegis-{self.port}.json")
        self.proc = None
        self.conns = 0

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
        lst = {"name": "pub", "bind": f"127.0.0.1:{self.port}", "profile": "P-PUBLIC-WEB", "alpn": ["h2", "http/1.1"]}
        if self.cfg_front is not None:
            lst["front"] = self.cfg_front
        return {"v": 1, "listeners": [lst], "admin": {"bind": f"127.0.0.1:{self.aport}"},
                "vhosts": [{"host": "aegis.test", "routes": routes},
                           {"host": "other.test", "routes": [{"id": 1, "path": "/", "to": {"upstream": u},
                                                              "authz": "allow-all"}]}]}

    def argv(self):
        return [self.binary, "--config", self.cfg, "--cert", self.crt, "--key", self.key, "--audit-dir",
                os.path.join(self.d, f"audit-{self.port}")] + self.front_args

    def env(self):
        env = dict(os.environ)
        for k in ("NOTIFY_SOCKET", "AEGIS_UPGRADE_DIR", "AEGIS_E2E_MUTANT", "CREDENTIALS_DIRECTORY"):
            env.pop(k, None)
        env.update(self.env_extra)
        return env

    def start(self, wrap=None):
        with open(self.cfg, "w") as f:
            json.dump(self.config(), f)
        self.log = open(os.path.join(self.d, f"aegis-{self.port}.log"), "wb")
        self.proc = subprocess.Popen((wrap or []) + self.argv(), stdout=self.log, stderr=subprocess.STDOUT,
                                     env=self.env())
        until = time.time() + 20
        while time.time() < until:
            if self.proc.poll() is not None:
                raise RuntimeError(f"exited {self.proc.returncode} at start: {self.tail()[-600:]}")
            try:
                st, _ = admin_get(self.aport, "/healthz")
                if st == 200 and self.listening():
                    return
            except OSError:
                pass
            time.sleep(0.1)
        raise RuntimeError("not healthy within 20 s")

    def listening(self):
        s = socket.socket()
        s.settimeout(0.2)
        try:
            s.connect(("127.0.0.1", self.port))
            return True
        except OSError:
            return False
        finally:
            s.close()

    def tail(self):
        try:
            with open(os.path.join(self.d, f"aegis-{self.port}.log"), "rb") as f:
                return f.read()[-3000:].decode(errors="replace")
        except OSError:
            return ""

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def metric(self, sample):
        try:
            st, text = admin_get(self.aport, "/metrics")
        except OSError:
            return None
        for ln in text.splitlines():
            if ln.startswith(sample + " "):
                try:
                    return float(ln.split()[-1])
                except ValueError:
                    return None
        return None


def admin_get(port, path):
    import http.client
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        c.request("GET", path)
        r = c.getresponse()
        return r.status, r.read().decode(errors="replace")
    finally:
        c.close()


# ------------------------------------------------------------------------------------------------ the run


class Result:
    def __init__(self):
        self.failures, self.passed, self.notes = [], 0, []

    def check(self, name, ok, detail=""):
        if ok:
            self.passed += 1
            if VERBOSE:
                log(f"  ok   {name}")
        else:
            self.failures.append(name)
            log(f"  FAIL {name}: {str(detail)[:600]}")


def mint_cert(d):
    key, crt = os.path.join(d, "key.pem"), os.path.join(d, "cert.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", key, "-out", crt, "-days", "30", "-subj", "/CN=aegis.test",
                    "-addext", "subjectAltName=DNS:aegis.test,DNS:other.test"], check=True, capture_output=True,
                   timeout=30)
    return crt, key


def norm_resp(b, port):
    return DATE.sub(b"date: <D>", b.replace(b":%d" % port, b":{P}"))


def curl_h2(port, crt, path, host=None, data=None):
    cmd = ["curl", "-sS", "--http2", "--cacert", crt, "--resolve", f"aegis.test:{port}:127.0.0.1", "-D", "-",
           "-o", "-", "-H", "X-H2:  spaced value ", f"https://aegis.test:{port}{path}"]
    if host:
        cmd += ["-H", f"Host: {host}"]
    if data is not None:
        cmd += ["--data-binary", "@-"]
    p = subprocess.run(cmd, capture_output=True, timeout=30, input=data)
    return p.returncode, p.stdout


def observe_front(binary, label, front_args, up, crt, key, d, res, env_extra=None):
    """Run the whole corpus against one front. Returns the observation dict (or None if it could not start)."""
    fr = Front(binary, front_args, up, crt, key, d, env_extra)
    obs = {}
    try:
        fr.start()
    except RuntimeError as e:
        res.check(f"{label}.start", False, f"{' '.join(fr.argv()[1:])}: {e}")
        return None, None
    res.check(f"{label}.start", True)
    up.pub = str(fr.port).encode()
    pid = fr.proc.pid
    cl = Client(crt)
    ev = {"rings0": ring_tails(pid)}
    try:
        for name, steps, sni, reject in corpus(fr.port):
            n0 = up.mark()
            resps, close, extra = run_case(cl, fr.port, steps, sni)
            fr.conns += 1
            time.sleep(0.05)
            obs[name] = {"resp": [norm_resp(r, fr.port) for r in resps], "close": close,
                         "after": norm_resp(extra, fr.port), "up": up.since(n0), "reject": reject}
        # --- h2 (curl)
        if shutil.which("curl"):
            for name, path, host, data in [("h2.canonical", "/api/h2%7e?x=%7e", None, None),
                                           ("h2.sni-authority-421", "/api/x", "other.test", None),
                                           ("h2.noauthz-403", "/noauthz/x", None, None),
                                           ("h2.empty-segment-308", "/api//x", None, None),
                                           ("h2.big-1m", "/api/big/1048576", None, None),
                                           ("h2.post-256k", "/api/h2up", None, pattern(256 * 1024))]:
                n0 = up.mark()
                rc, out = curl_h2(fr.port, crt, path, host, data)
                fr.conns += 1
                obs[name] = {"resp": [b"rc=%d " % rc + norm_resp(out, fr.port)], "close": "-", "up": up.since(n0),
                             "reject": False}
        else:
            res.check(f"{label}.curl", False, "curl not found")
        # --- load (h2load): h2 stream cap, many conns, h1 conns, zero-window stall
        A = f"https://aegis.test:{fr.port}"
        # Each phase stays under aegis's per-IP admission burst (GCRA 1000/s, burst 2000, shared.rs) with a 2.5 s
        # refill pause before it, so no 429 depends on timing (a timing-dependent 429 would differ between fronts).
        for name, args, conns in [("load.h2-1conn-1000streams", ["-c", "1", "-m", "1000", "-n", "1000",
                                                                 f"{A}/api/load"], 1),
                                  ("load.h2-300conns", ["-c", "300", "-n", "1200", f"{A}/api/load"], 300),
                                  ("load.h1-50conns", ["--h1", "-c", "50", "-n", "1000", f"{A}/api/load1"], 50),
                                  ("load.h2-mixed-status", ["-c", "4", "-m", "10", "-n", "400", f"{A}/api/l",
                                                            f"{A}/noauthz/l", f"{A}/api//l", f"{A}/exact/"], 4)]:
            time.sleep(2.5)
            n0 = up.mark()
            r = h2load(args, fr.port)
            fr.conns += conns
            obs[name] = {"load": r, "upcount": len(up.since(n0))}
        t0 = time.time()
        r = h2load(["-c", "2", "-m", "10", "-w", "0", "-W", "16", "-n", "20", "-T", "30",
                    f"{A}/api/big/4194304"], fr.port, timeout=90)
        wall = time.time() - t0
        fr.conns += 2
        obs["load.h2-zero-window-stall"] = {"load": {k: r.get(k) for k in ("total", "timeout", "error")},
                                            "reaped<=13s": wall <= 13.0}
        ev["stall_wall"] = round(wall, 1)
        # --- reload (SIGHUP): new route served on the same front
        r0 = fr.metric("aegis_proxy_config_reloads_total") or 0
        with open(fr.cfg, "w") as f:
            json.dump(fr.config(extra_route=True), f)
        fr.proc.send_signal(signal.SIGHUP)
        until = time.time() + 10
        while time.time() < until and (fr.metric("aegis_proxy_config_reloads_total") or 0) <= r0:
            time.sleep(0.1)
        n0 = up.mark()
        resps, close, _ = run_case(cl, fr.port, [("send", b"GET /new/route HTTP/1.1\r\nHost: aegis.test:%d\r\n\r\n"
                                                  % fr.port), ("read", 1)], None)
        fr.conns += 1
        obs["reload.new-route"] = {"resp": [norm_resp(x, fr.port) for x in resps], "close": close,
                                   "up": up.since(n0), "reject": False}
        # --- identity evidence while a client connection is open
        s = cl.tls(fr.port)
        fr.conns += 1
        s.sendall(b"GET /api/ident HTTP/1.1\r\nHost: aegis.test:%d\r\n\r\n" % fr.port)
        read_one(s, b"")
        lport = s.getsockname()[1]
        time.sleep(0.2)
        ino = tcp_inode(fr.port, lport)
        ev["conn_fd"] = fd_of_inode(pid, ino) if ino else None
        lino = tcp_inode(fr.port, listen=True)
        ev["listen_fd"] = fd_of_inode(pid, lino) if lino else None
        ev["epoll_regs"] = epoll_registered(pid)
        ev["rings1"] = ring_tails(pid)
        ev["conns"] = fr.conns
        # --- SIGTERM: the idle keep-alive connection is closed, the process exits 0
        fr.proc.send_signal(signal.SIGTERM)
        st, _ = close_state(s, timeout=15)
        s.close()
        try:
            rc = fr.proc.wait(20)
        except subprocess.TimeoutExpired:
            rc = "timeout"
        obs["sigterm.drain"] = {"idle-conn": st, "exit": rc}
    except (OSError, ssl.SSLError, RuntimeError, subprocess.SubprocessError) as e:
        res.check(f"{label}.harness", False, f"{type(e).__name__}: {e}\n{fr.tail()[-800:]}")
    finally:
        fr.stop()
    return obs, ev


def identity_checks(label, ev, want, res):
    if ev is None or "rings1" not in ev:
        res.check(f"{label}.identity", False, "no evidence collected")
        return
    rings, delta = ev["rings1"], cq_delta(ev["rings0"], ev["rings1"])
    cfd, lfd, regs = ev["conn_fd"], ev["listen_fd"], ev["epoll_regs"]
    res.check(f"{label}.identity.conn-socket-held", cfd is not None,
              "the server side of a live client connection is not an fd of the launched process")
    if want == "uring":
        res.check(f"{label}.identity.has-io_uring", bool(rings), "no anon_inode:[io_uring] fd in the process")
        res.check(f"{label}.identity.cq-moves-with-traffic", delta >= ev["conns"],
                  f"CqTail advanced {delta} over {ev['conns']} client connections (want >= 1 per connection)")
        res.check(f"{label}.identity.conn-not-in-epoll", cfd is not None and cfd not in regs,
                  f"client connection fd {cfd} is registered in an epoll instance (connection I/O must go through "
                  f"io_uring)")
        res.check(f"{label}.identity.listener-not-in-epoll", lfd is None or lfd not in regs,
                  f"listening socket fd {lfd} is registered in an epoll instance")
    else:
        res.check(f"{label}.identity.no-io_uring", not rings, f"io_uring instances present: {sorted(rings)}")
        res.check(f"{label}.identity.conn-in-epoll", cfd is not None and cfd in regs,
                  f"client connection fd {cfd} not registered in any epoll instance")


def compare(a, b, res):
    for name in a:
        if name not in b:
            res.check(f"equiv.{name}", False, "missing on the uring front")
            continue
        oa, ob = a[name], b[name]
        if oa == ob:
            res.check(f"equiv.{name}", True)
        else:
            diff = {k: (oa.get(k), ob.get(k)) for k in set(oa) | set(ob) if oa.get(k) != ob.get(k)}
            res.check(f"equiv.{name}", False, f"epoll vs uring differ: {short(diff)}")
    for name, o in a.items():
        if o.get("reject"):
            first = o["resp"][0] if o["resp"] else b""
            m = re.match(rb"HTTP/1\.[01] (\d{3})", first)
            ok = (m is None or int(m.group(1)) >= 400) and not any(b"/smuggled" in h or b"/api/x " in h
                                                                  for h, _, _ in o["up"])
            res.check(f"corpus.{name}.is-reject", ok and (m is not None or o["close"] == "closed"),
                      f"not a reject on the epoll front: {first[:80]!r}, upstream saw {len(o['up'])}")
    for name, o in a.items():
        if "load" in o and name != "load.h2-zero-window-stall":
            r = o["load"]
            ok = "error" not in r and r.get("done", 0) == r.get("total", -1)
            if name != "load.h2-mixed-status":
                ok = ok and r.get("succeeded") == r.get("total") and o["upcount"] == r.get("total")
            res.check(f"corpus.{name}.ran", ok, f"h2load on epoll: {r}, upstream saw {o.get('upcount')}")


def shown(p):
    r = os.path.relpath(p, REPO)
    return p if r.startswith("..") else r


def short(x):
    s = repr(x)
    return s if len(s) < 500 else s[:500] + "..."


def fail_closed_checks(binary, up, crt, key, d, res, env_extra):
    """--front uring with io_uring unavailable (seccomp EPERM) refuses to start; --front epoll still starts."""
    wrap = [sys.executable, "-I", os.path.join(HERE, "noring_exec.py")]
    fr = Front(binary, ["--front", "uring"], up, crt, key, d, env_extra)
    with open(fr.cfg, "w") as f:
        json.dump(fr.config(), f)
    log_path = os.path.join(d, f"noring-{fr.port}.log")
    with open(log_path, "wb") as lf:
        p = subprocess.Popen(wrap + fr.argv(), stdout=lf, stderr=subprocess.STDOUT, env=fr.env())
        listened, until = False, time.time() + 8
        while p.poll() is None and time.time() < until:
            listened = listened or fr.listening()
            time.sleep(0.05)
        alive = p.poll() is None
        if alive:
            listened = listened or fr.listening()
            p.send_signal(signal.SIGTERM)
            try:
                p.wait(15)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
    out = open(log_path, "rb").read().decode(errors="replace")
    rc = p.returncode
    res.check("fallback.uring-refuses-without-io_uring", not alive and rc not in (0, None) and rc > 0,
              f"--front uring under an io_uring EPERM filter: {'still running after 8 s' if alive else f'exit {rc}'}"
              f"; log: {out[-300:]!r}")
    res.check("fallback.nothing-listened", not listened, "the listener accepted connections")
    res.check("fallback.message-names-io_uring", "io_uring" in out.lower() or "io-uring" in out.lower(),
              f"stderr does not name io_uring: {out[-300:]!r}")
    fe = Front(binary, ["--front", "epoll"], up, crt, key, d, env_extra)
    try:
        fe.start(wrap=wrap)
        res.check("fallback.epoll-unaffected", True)
    except RuntimeError as e:
        res.check("fallback.epoll-unaffected", False, f"--front epoll under the same filter: {e}")
    finally:
        fe.stop()


def cli_checks(binary, up, crt, key, d, res, env_extra):
    """Interface: default = epoll; listeners[].front selects; CLI overrides; bad values exit 64 / 78, nothing bound."""
    cl = Client(crt)

    def ident(label, front_args, cfg_front, want):
        fr = Front(binary, front_args, up, crt, key, d, env_extra, cfg_front=cfg_front)
        try:
            fr.start()
        except RuntimeError as e:
            res.check(f"cli.{label}.start", False, f"{' '.join(fr.argv()[1:])} (front in config: {cfg_front}): {e}")
            return
        try:
            pid = fr.proc.pid
            r0 = ring_tails(pid)
            n = 0
            for _ in range(3):
                n += 1
                run_case(cl, fr.port, [("send", b"GET /api/cli HTTP/1.1\r\nHost: aegis.test:%d\r\n"
                                        b"Connection: close\r\n\r\n" % fr.port), ("read", 1)], None)
            s = cl.tls(fr.port)
            n += 1
            s.sendall(b"GET /api/cli HTTP/1.1\r\nHost: aegis.test:%d\r\n\r\n" % fr.port)
            read_one(s, b"")
            time.sleep(0.2)
            ino = tcp_inode(fr.port, s.getsockname()[1])
            lino = tcp_inode(fr.port, listen=True)
            ev = {"rings0": r0, "rings1": ring_tails(pid), "conn_fd": fd_of_inode(pid, ino) if ino else None,
                  "listen_fd": fd_of_inode(pid, lino) if lino else None, "epoll_regs": epoll_registered(pid),
                  "conns": n}
            s.close()
            identity_checks(f"cli.{label}", ev, want, res)
        except (OSError, ssl.SSLError) as e:
            res.check(f"cli.{label}.harness", False, str(e))
        finally:
            fr.stop()

    ident("default-is-epoll", [], None, "epoll")
    ident("config-front-uring", [], "uring", "uring")
    ident("config-front-epoll", [], "epoll", "epoll")
    ident("cli-overrides-config", ["--front", "epoll"], "uring", "epoll")

    def refused(label, front_args, cfg_front, want_rc):
        fr = Front(binary, front_args, up, crt, key, d, env_extra, cfg_front=cfg_front)
        with open(fr.cfg, "w") as f:
            json.dump(fr.config(), f)
        p = subprocess.Popen(fr.argv(), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=fr.env())
        listened, until = False, time.time() + 5
        while p.poll() is None and time.time() < until:
            listened = listened or fr.listening()
            time.sleep(0.05)
        if p.poll() is None:
            p.kill()
        rc = p.wait()
        res.check(f"cli.{label}.exit-{want_rc}", rc == want_rc, f"exit {rc}")
        res.check(f"cli.{label}.nothing-bound", not listened, "the listener accepted connections")

    refused("bad-flag-value", ["--front", "kqueue"], None, 64)
    refused("bad-config-value", [], "kqueue", 78)


def run_oracle(binary, unit, dropin, env_extra=None, sections=("cli", "equiv", "fallback", "unit"), fail_fast=False):
    res = Result()
    d = tempfile.mkdtemp(prefix="aegis-front-equiv-")
    up = Upstream()
    try:
        crt, key = mint_cert(d)
        if "equiv" in sections:
            log("[equiv] --front epoll")
            a, ev_a = observe_front(binary, "epoll", ["--front", "epoll"], up, crt, key, d, res, env_extra)
            if not (fail_fast and res.failures):
                log("[equiv] --front uring")
                b, ev_b = observe_front(binary, "uring", ["--front", "uring"], up, crt, key, d, res, env_extra)
                if a is not None and b is not None:
                    compare(a, b, res)
                    identity_checks("epoll", ev_a, "epoll", res)
                    identity_checks("uring", ev_b, "uring", res)
                    if ev_a and "stall_wall" in ev_a:
                        res.notes.append(f"zero-window stall wall epoll {ev_a['stall_wall']} s / uring "
                                         f"{ev_b.get('stall_wall') if ev_b else '?'} s")
        if "cli" in sections and not (fail_fast and res.failures):
            log("[cli] front selection and refusals")
            cli_checks(binary, up, crt, key, d, res, env_extra)
        if "fallback" in sections and not (fail_fast and res.failures):
            log("[fallback] io_uring unavailable")
            fail_closed_checks(binary, up, crt, key, d, res, env_extra)
        if "unit" in sections and not (fail_fast and res.failures):
            log(f"[unit] {shown(unit)} + {shown(dropin)}")
            for name, ok, detail in unitcheck.check(unit, dropin):
                res.check(name, ok, detail)
    except Exception as e:  # noqa: BLE001 - any harness error is a FAIL with its reason
        res.check("harness", False, f"{type(e).__name__}: {e}")
    finally:
        up.sock.close()
        shutil.rmtree(d, ignore_errors=True)
    return res


# ------------------------------------------------------------------------------------------------ self-test


def ensure_default_aegis():
    p = os.path.join(REPO, "target", "release", "aegis")
    if os.access(p, os.X_OK):
        return p
    log("building the self-test backend (default aegis) through ci/heavy.sh ...")
    r = subprocess.run([os.path.join(REPO, "ci", "heavy.sh"), "cargo", "build", "--release", "--locked", "-q", "-p",
                        "aegis-bin"], cwd=REPO)
    return p if r.returncode == 0 and os.access(p, os.X_OK) else None


def unit_mutant_files(d, unit_text, dropin_text):
    good = unitcheck.fixture_good(unit_text)
    files = {}
    for name, u, dr in [
        ("good", good, dropin_text),
        ("unit-admits", unitcheck.strip_uring_deny(good), dropin_text),
        ("dropin-broad", good, dropin_text + "SystemCallFilter=io_uring_setup ptrace\n"),
        ("dropin-incomplete", good, "[Service]\nSystemCallFilter=io_uring_register\n"),
        ("dropin-relaxes-other", good, dropin_text + "NoNewPrivileges=no\n"),
    ]:
        up, dp = os.path.join(d, f"{name}.service"), os.path.join(d, f"{name}.conf")
        with open(up, "w") as f:
            f.write(u)
        with open(dp, "w") as f:
            f.write(dr)
        files[name] = (up, dp)
    return files


def self_test(unit, dropin):
    backend = ensure_default_aegis()
    if not backend:
        log(f"{NAME} SELF-TEST: FAIL (could not build target/release/aegis)")
        return 1
    ref = os.path.join(HERE, "aegis-front-ref")
    d = tempfile.mkdtemp(prefix="aegis-front-equiv-st-")
    try:
        files = unit_mutant_files(d, open(unit).read(), open(dropin).read())
        env = {"FRONT_REF_AEGIS": backend}
        log(f"self-test subject: {os.path.relpath(ref, REPO)} wrapping {backend}")
        log(f"self-test unit fixture: {os.path.relpath(unit, REPO)} + the io_uring deny line (unitcheck.fixture_good)")
        r = run_oracle(ref, *files["good"], env_extra=env)
        if r.failures:
            log(f"{NAME} SELF-TEST: FAIL (the reference front must pass first: {r.failures[:8]})")
            return 1
        log(f"  baseline (reference front, fixture unit): PASS ({r.passed} checks; {'; '.join(r.notes)})")
        caught = []
        for m in FRONT_MUTANTS:
            sections = ("fallback",) if m == "silent-fallback" else ("cli",) if m == "config-front-ignored" \
                else ("equiv",)
            r = run_oracle(ref, *files["good"], env_extra=dict(env, FRONT_REF_MUTANT=m), sections=sections,
                           fail_fast=False)
            if not r.failures:
                log(f"{NAME} SELF-TEST: FAIL (front mutant {m} was not caught)")
                return 1
            log(f"  mutant {m}: caught by {', '.join(r.failures[:6])}{' ...' if len(r.failures) > 6 else ''}")
            caught.append(m)
        for m in UNIT_MUTANTS:
            bad = [n for n, ok, _ in unitcheck.check(*files[m]) if not ok]
            if not bad:
                log(f"{NAME} SELF-TEST: FAIL (unit mutant {m} was not caught)")
                return 1
            log(f"  mutant {m}: caught by {', '.join(bad)}")
            caught.append(m)
        total = len(FRONT_MUTANTS) + len(UNIT_MUTANTS)
        log(f"{NAME} SELF-TEST: PASS ({len(caught)}/{total} mutants caught: {', '.join(caught)})")
        return 0
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------------------------------------------------ main


def build_uring():
    target = os.path.join(REPO, "target", "front-equiv")
    binp = os.path.join(target, "release", "aegis")
    log(f"building {os.path.relpath(binp, REPO)} (--features uring) through ci/heavy.sh ...")
    r = subprocess.run([os.path.join(REPO, "ci", "heavy.sh"), "cargo", "build", "--release", "--locked", "-q", "-p",
                        "aegis-bin", "--features", "uring"], cwd=REPO, env=dict(os.environ, CARGO_TARGET_DIR=target))
    return binp if r.returncode == 0 and os.access(binp, os.X_OK) else None


def main():
    global VERBOSE
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--binary", help="aegis built with --features uring")
    g.add_argument("--binary-from-build", action="store_true", help="build it first (target/front-equiv)")
    g.add_argument("--self-test", action="store_true")
    ap.add_argument("--unit", default=os.path.join(REPO, "deploy", "aegis-hardened.service"))
    ap.add_argument("--dropin", default=os.path.join(REPO, "deploy", "uring.conf"))
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    VERBOSE = a.verbose
    if a.self_test:
        return self_test(a.unit, a.dropin)
    if a.binary_from_build:
        binary = build_uring()
        if not binary:
            log(f"{NAME}: FAIL (cargo build -p aegis-bin --features uring failed)")
            return 1
    else:
        binary = os.path.abspath(a.binary)
    if not os.access(binary, os.X_OK):
        log(f"{NAME}: FAIL (binary {binary} not executable)")
        return 1
    if open("/proc/sys/kernel/io_uring_disabled").read().strip() != "0":
        log(f"{NAME}: FAIL (kernel.io_uring_disabled != 0 on this host: run on the desktop via ci/remote.sh)")
        return 1
    r = run_oracle(binary, a.unit, a.dropin)
    note = ("; " + "; ".join(r.notes)) if r.notes else ""
    if not r.failures:
        log(f"{NAME}: PASS ({r.passed} checks{note})")
        return 0
    log(f"{NAME}: FAIL ({len(r.failures)} failed: {', '.join(r.failures[:10])}{' ...' if len(r.failures) > 10 else ''}"
        f"{note})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
