"""Reference subject for the proxy-l4 oracle (self-test only; stdlib only; run as `python3 -I ref_server.py`).

Implements the subject contract in README.md with the PROXY v2 and ClientHello reference parsers: the F8 additions
`listener.proxy_protocol = {trusted = [CIDR...]}` and `listener.l4 = [{sni, upstream}]`, the F1 PROXY-1..3 and
L4-1..2 rules, the audit events `proxy.accept` / `l4.route`, admin `/healthz`, exit 78 on a refused config.
Only what the oracle drives is implemented: the HTTP side forwards `/api/*` GETs to the vhost route's upstream.

AEGIS_PROXY_L4_REF_MUTANT=<name> plants one defect (README.md "Self-test"). Never used outside the self-test.
"""

import argparse
import hashlib
import http.server
import ipaddress
import json
import os
import signal
import socket
import ssl
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import clienthello as ch  # noqa: E402
import proxyv2 as pp  # noqa: E402
from tlsbio import Pump  # noqa: E402

MUT = os.environ.get("AEGIS_PROXY_L4_REF_MUTANT", "")
PARSER_MUT = MUT if MUT in pp.MUTANTS else None
STALL_S = 5.0
LISTENER_KEYS = {"name", "bind", "profile", "alpn", "proxy_protocol", "l4", "front"}


def refuse(msg):
    print(f"ref_server: config refused: {msg}", file=sys.stderr)
    sys.exit(78)


def split_hostport(s):
    if s.startswith("["):
        host, _, port = s[1:].partition("]:")
    else:
        host, _, port = s.rpartition(":")
    if not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(f"bad host:port {s!r}")
    return host, int(port)


class Audit:
    def __init__(self, root):
        self.dir = os.path.join(root, f"{int(time.time() * 1000)}-{os.getpid()}", "tile", "entries", "000.p")
        os.makedirs(self.dir, exist_ok=True)
        self.lock = threading.Lock()
        self.leaves = []

    def event(self, action, obj, detail):
        with self.lock:
            ev = {"v": 1, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "seq": len(self.leaves),
                  "actor": {"kind": "public"}, "action": action, "object": obj, "outcome": "allow",
                  "req_id": os.urandom(16).hex(), "config_hash": "0" * 64, "fips_status": "none", "detail": detail}
            leaf = json.dumps(ev, separators=(",", ":")).encode()
            self.leaves.append(len(leaf).to_bytes(2, "big") + leaf)
            path = os.path.join(self.dir, str(len(self.leaves)))
            with open(path + ".tmp", "wb") as f:
                f.write(b"".join(self.leaves))
            os.replace(path + ".tmp", path)


class Listener:
    def __init__(self, d):
        unknown = set(d) - LISTENER_KEYS
        if unknown:
            refuse(f"unknown listener field(s) {sorted(unknown)}")
        self.name = d["name"]
        self.host, self.port = split_hostport(d["bind"])
        self.trusted = None
        if "proxy_protocol" in d:
            ppc = d["proxy_protocol"]
            if not isinstance(ppc, dict) or set(ppc) - {"trusted"} or not isinstance(ppc.get("trusted"), list):
                refuse("proxy_protocol must be {trusted = [CIDR...]}")
            try:
                self.trusted = [ipaddress.ip_network(c, strict=True) for c in ppc["trusted"]]
            except (ValueError, TypeError) as e:
                refuse(f"proxy_protocol.trusted: {e}")
        self.l4 = None
        if "l4" in d:
            if "alpn" in d:
                refuse(f"listener {self.name}: l4 and alpn (a listener is L4 or HTTP, never both)")
            self.l4 = {}
            self.l4_order = []
            for r in d["l4"]:
                if not isinstance(r, dict) or set(r) != {"sni", "upstream"}:
                    refuse("l4 entry must be {sni, upstream}")
                if not ch._valid_host(r["sni"].encode()):
                    refuse(f"l4 sni {r['sni']!r}")
                k = r["sni"].lower()
                if k in self.l4:
                    refuse(f"duplicate l4 sni {k}")
                try:
                    split_hostport(r["upstream"])
                except ValueError as e:
                    refuse(str(e))
                self.l4[k] = r["upstream"]
                self.l4_order.append(r["upstream"])
            if not self.l4:
                refuse("l4 with no routes")

    def is_trusted(self, ip):
        a = ipaddress.ip_address(ip)
        return any(a in n for n in self.trusted if a.version == n.version)


class Server:
    def __init__(self, cfg, cert, key, audit):
        self.cfg = cfg
        self.audit = audit
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ctx.load_cert_chain(cert, key)
        self.ctx.set_alpn_protocols(["http/1.1"])
        self.route_up = None
        for vh in cfg.get("vhosts", []):
            for r in vh.get("routes", []):
                if r.get("path") == "/api/" and r.get("authz") == "allow-all":
                    self.route_up = split_hostport(r["to"]["upstream"])
        self.listeners = [Listener(d) for d in cfg["listeners"]]

    # ---------------------------------------------------------------------------------------- connection

    def serve(self, lst):
        fam = socket.AF_INET6 if ":" in lst.host else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((lst.host, lst.port))
        s.listen(256)
        threading.Thread(target=self._accept, args=(s, lst), daemon=True).start()

    def _accept(self, s, lst):
        while True:
            c, addr = s.accept()
            threading.Thread(target=self._conn, args=(c, addr, lst), daemon=True).start()

    def _conn(self, c, addr, lst):
        try:
            self._handle(c, addr, lst)
        except (OSError, ValueError, ssl.SSLError, ConnectionError):
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass

    def _handle(self, c, addr, lst):
        via = addr[0]
        peer = via
        deadline = time.monotonic() + STALL_S
        buf = b""
        hdr_bytes = b""

        def more(nodeadline=False):
            if nodeadline:
                c.settimeout(None)
            else:
                left = deadline - time.monotonic()
                if left <= 0:
                    return b""
                c.settimeout(left)
            try:
                return c.recv(65536)
            except (socket.timeout, ConnectionResetError):
                return b""

        if lst.trusted is not None:
            trusted = lst.is_trusted(via)
            d = more()
            if not d:
                return
            buf += d
            if not trusted and MUT not in ("proxy-untrusted-accept", "proxy-trust-by-header"):
                if pp.looks_like_proxy(buf):
                    return  # PROXY-1: refused before any byte is read as TLS or HTTP
            elif trusted or pp.looks_like_proxy(buf):
                while True:
                    try:
                        h = pp.parse(buf, mutant=PARSER_MUT)
                        break
                    except pp.Incomplete:
                        d = more()
                        if not d:
                            return
                        buf += d
                    except pp.Reject as e:
                        if e.cls == "sig" and trusted and MUT == "proxy-autodetect":
                            h = None
                            break
                        return  # PROXY-3 / never auto-detected
                if h is not None:
                    if not h["stream_accept"]:
                        return
                    if not trusted:
                        if MUT == "proxy-trust-by-header":
                            if not (h["peer"] == "src" and lst.is_trusted(h["src"])):
                                return
                        elif MUT != "proxy-untrusted-accept":
                            return
                    hdr_bytes, buf = buf[:h["consumed"]], buf[h["consumed"]:]
                    peer = h["src"] if h["peer"] == "src" and (trusted or MUT == "proxy-trust-by-header") else via
                    self.audit.event("proxy.accept", lst.name, {"peer": peer, "via": via})
        if lst.l4 is not None:
            self._l4(c, lst, buf, hdr_bytes, peer, more)
        else:
            self._http(c, buf)

    def _l4(self, c, lst, buf, hdr_bytes, peer, more):
        nodl = MUT == "l4-no-stall-deadline"
        if not buf:
            buf = more(nodl)
            if not buf:
                return
        if MUT == "l4-http-parse" and buf[:1] != b"\x16" and buf.split(b" ", 1)[0] in (b"GET", b"POST", b"PRI",
                                                                                      b"HEAD", b"PUT"):
            c.sendall(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            return
        while True:
            try:
                pk = ch.peek(buf, allow_multi_record=(MUT == "l4-multi-record"))
                break
            except ch.PeekIncomplete:
                d = more(nodl)
                if not d:
                    return
                buf += d
            except ch.PeekError:
                return  # L4-1 / L4-2: never a default upstream, never HTTP
        sni = pk["sni"]
        up = lst.l4.get(sni.lower()) if sni else None
        if up is None:
            if MUT != "l4-default-upstream":
                return
            up = lst.l4_order[0]
        host, port = split_hostport(up)
        u = socket.create_connection((host, port), timeout=10)
        self.audit.event("l4.route", lst.name, {"sni": sni or "", "upstream": up, "peer": peer})
        u.sendall((hdr_bytes if MUT == "l4-forward-proxy-header" else b"") + buf)
        c.settimeout(None)
        u.settimeout(None)

        def pipe(a, b):
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

        t = threading.Thread(target=pipe, args=(u, c), daemon=True)
        t.start()
        pipe(c, u)
        t.join(30)
        u.close()

    def _http(self, c, buf):
        c.settimeout(10)
        t = Pump(c, self.ctx, server_side=True, pre_in=buf)
        t.handshake()
        req = b""
        while b"\r\n\r\n" not in req:
            d = t.read()
            if not d:
                return
            req += d
        line = req.split(b"\r\n", 1)[0].split(b" ")
        path = line[1] if len(line) == 3 else b""
        if not path.startswith(b"/api/") or self.route_up is None:
            t.write(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            return
        u = socket.create_connection(self.route_up, timeout=10)
        u.sendall(b"GET " + path + b" HTTP/1.1\r\nhost: monban.test\r\nconnection: close\r\n\r\n")
        resp = b""
        while True:
            d = u.recv(65536)
            if not d:
                break
            resp += d
            head, sep, body = resp.partition(b"\r\n\r\n")
            if sep:
                n = 0
                for ln in head.split(b"\r\n")[1:]:
                    k, _, v = ln.partition(b":")
                    if k.strip().lower() == b"content-length":
                        n = int(v)
                if len(body) >= n:
                    break
        u.close()
        t.write(resp)


class Admin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        code = 200 if self.path == "/healthz" else 404
        body = b'{"status":"ok"}\n' if code == 200 else b""
        self.send_response(code)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--audit-dir", required=True)
    a = ap.parse_args()
    try:
        with open(a.config) as f:
            cfg = json.load(f)
    except (OSError, ValueError) as e:
        refuse(str(e))
    try:
        srv = Server(cfg, a.cert, a.key, None)
    except (KeyError, TypeError, ValueError) as e:
        refuse(f"{type(e).__name__}: {e}")
    srv.audit = Audit(a.audit_dir)
    for lst in srv.listeners:
        srv.serve(lst)
    ah, ap_ = split_hostport(cfg["admin"]["bind"])
    adm = http.server.ThreadingHTTPServer((ah, ap_), Admin)
    threading.Thread(target=adm.serve_forever, daemon=True).start()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    print(f"ref_server: up (mutant={MUT or 'none'}, config sha256 "
          f"{hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()[:12]})", flush=True)
    stop.wait()
    sys.exit(0)


if __name__ == "__main__":
    main()
