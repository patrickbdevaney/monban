#!/usr/bin/env python3
"""bin-residuals reference subject (stdlib only). Not a model of monban internals: it follows the observable contract
in README.md so the oracle can be shown to PASS on a correct subject and to go red on each mutant.

    ref_server.py --config <f8.json> --cert <pem> --key <pem> [--audit-dir d]

- HTTP listeners that have tls.credentials candidates: reads the ClientHello record, picks the credential with the
  cred-select decision table (oracles/cred-select/ref_selector.py) and sends ServerHello + EncryptedExtensions +
  Certificate (tls13.server_flight), or the alert (49 when the client's sigalgs miss the profile's F12 sigalgs, F12
  admission step 2; else 40 = handshake_failure, SEL-3). It never completes a handshake: the oracle stops at
  Certificate.
- Other HTTP listeners: Python ssl with --cert/--key, one HTTP/1.1 exchange (oracles/proxy-e2e/oneresp.serve_h1).
- L4 listeners: peek, route by exact SNI, splice with the idle timeout (limits.idle_timeout_ms, no byte either way).

Negative controls, env AEGIS_BR_MUTANT: sel1-any-trust-anchor, sel1-prefix-match, sel2-mldsa-public,
sel3-other-listener, ta-codepoint-lenient (passed to ref_selector), idle-ignored (no idle timeout), idle-absolute
(closes idle_timeout_ms after routing whatever the traffic), two-responses (R6: two 400s for one bad request).
"""

import argparse
import base64
import json
import os
import re
import signal
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
for d in (HERE, os.path.join(REPO, "oracles", "proxy-e2e"), os.path.join(REPO, "oracles", "proxy-l4"),
          os.path.join(REPO, "oracles", "cred-select")):
    sys.path.insert(0, d)
import clienthello as ch  # noqa: E402
import oneresp  # noqa: E402
import ref_selector  # noqa: E402
import tls13  # noqa: E402

MUTANT = os.environ.get("AEGIS_BR_MUTANT", "")
SEL_MUTANT = MUTANT if MUTANT in ref_selector.MUTANTS else None
EX_CONFIG = 78
OIDS = {  # PKCS#8 algorithm (and curve) OIDs -> the TLS 1.3 SignatureScheme the key signs CertificateVerify with
    bytes.fromhex("06082a8648ce3d030107"): 0x0403,        # prime256v1 (with id-ecPublicKey)
    bytes.fromhex("06052b81040022"): 0x0503,              # secp384r1
    bytes.fromhex("0609608648016503040311"): 0x0904,      # id-ml-dsa-44
    bytes.fromhex("0609608648016503040312"): 0x0905,      # id-ml-dsa-65
    bytes.fromhex("0609608648016503040313"): 0x0906,      # id-ml-dsa-87
}


def log(m):
    print(f"bin-residuals-ref: {m}", file=sys.stderr, flush=True)


def ta_wire(dotted):
    out = b""
    for comp in (int(x) for x in dotted.split(".")):
        grp = [comp & 0x7F]
        comp >>= 7
        while comp:
            grp.append(0x80 | (comp & 0x7F))
            comp >>= 7
        out += bytes(reversed(grp))
    return out


def pem_blocks(text, label):
    return [base64.b64decode("".join(m.group(1).split()))
            for m in re.finditer(rf"-----BEGIN {label}-----(.*?)-----END {label}-----", text, re.S)]


def path_of(ref):
    if not ref.startswith("path:/"):
        raise ValueError(f"the reference reads path: credentials only, not {ref}")
    return ref[5:]


def key_scheme(path):
    with open(path) as f:
        ders = pem_blocks(f.read(), "PRIVATE KEY")
    if not ders:
        raise ValueError(f"{path}: no PKCS#8 PRIVATE KEY block")
    for oid, scheme in OIDS.items():
        if oid in ders[0][:40]:
            return scheme
    raise ValueError(f"{path}: unsupported key algorithm")


def chain_of(c):
    p = path_of(c["chain"])
    with open(p, "rb") as f:
        raw = f.read()
    blocks = pem_blocks(raw.decode(errors="replace"), "CERTIFICATE")
    if c["kind"] == "mtc":
        return blocks or [raw]
    if not blocks:
        raise ValueError(f"{p}: no CERTIFICATE block")
    return blocks


def recv_record(sock, deadline):
    buf = b""
    while len(buf) < 5 or len(buf) < 5 + int.from_bytes(buf[3:5], "big"):
        left = deadline - time.monotonic()
        if left <= 0 or len(buf) > 5 + 16384:
            return None
        sock.settimeout(left)
        try:
            d = sock.recv(65536)
        except OSError:
            return None
        if not d:
            return None
        buf += d
    return buf


class Server:
    def __init__(self, cfg, cert, key):
        self.cfg = cfg
        limits = cfg.get("limits") or {}
        self.idle = limits.get("idle_timeout_ms", 30000) / 1000
        self.stall = limits.get("stall_timeout_ms", 10000) / 1000
        self.http_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.http_ctx.load_cert_chain(cert, key)
        self.http_ctx.set_alpn_protocols(["http/1.1"])
        names = [l["name"] for l in cfg["listeners"] if "l4" not in l]
        self.pool, self.chains = [], {}
        for c in (cfg.get("tls") or {}).get("credentials", []):
            scope = c.get("listeners") or names
            scheme = key_scheme(path_of(c["key"]))
            ta = ta_wire(c["trust_anchor_id"]) if c["kind"] == "mtc" else None
            self.chains[c["id"]] = chain_of(c)
            for ln in scope:
                if ln not in names:
                    raise ValueError(f"credential {c['id']}: listener {ln} is not an HTTP listener")
                self.pool.append({"id": c["id"], "listener": ln, "kind": c["kind"], "scheme": scheme, "ta": ta})

    def listen(self, l):
        host, port = l["bind"].rsplit(":", 1)
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, int(port)))
        s.listen(128)
        # candidates as monban-config TlsBlock::candidates: scoped to the listener, minus mldsa on P-PUBLIC-WEB
        own = [c for c in self.pool if c["listener"] == l["name"]
               and not (c["kind"] == "mldsa" and l["profile"] == ref_selector.PUBLIC_WEB)]
        if "l4" in l:
            target = self.l4
        elif own:
            target = self.selector
        else:
            target = self.http
        threading.Thread(target=self.accept, args=(s, l, target), daemon=True).start()

    @staticmethod
    def accept(s, l, target):
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            threading.Thread(target=target, args=(c, l), daemon=True).start()

    # ------------------------------------------------------------ selector listeners
    def selector(self, c, l):
        try:
            rec = recv_record(c, time.monotonic() + self.stall)
            if rec is None:
                return
            req = {"case": 0, "profile": l["profile"], "listener": l["name"], "creds": self.pool, "hello": rec}
            got = ref_selector.select(req, SEL_MUTANT)
            pk = ref_selector.peek(rec)
            if pk is not None and not set(pk["sigalgs"]) & set(ref_selector.PROFILES[l["profile"]]):
                c.sendall(tls13.alert_record(49))
                return
            if got == ref_selector.HANDSHAKE_FAILURE:
                c.sendall(tls13.alert_record(40))
                return
            hello = rec[5:]
            flight = tls13.server_flight(hello, self.chains[got], tls13.client_hello_session_id(hello))
            if flight is None:
                c.sendall(tls13.alert_record(40))
                return
            c.sendall(flight)
            c.settimeout(10)
            while c.recv(65536):
                pass
        except OSError:
            return
        finally:
            c.close()

    # ------------------------------------------------------------ plain HTTP listener (R6)
    def http(self, c, l):
        try:
            t = self.http_ctx.wrap_socket(c, server_side=True)
        except (OSError, ssl.SSLError):
            c.close()
            return
        try:
            oneresp.serve_h1(t, "two-responses" if MUTANT == "two-responses" else None)
        finally:
            t.close()

    # ------------------------------------------------------------ L4
    def l4(self, c, l):
        up = None
        try:
            rec = recv_record(c, time.monotonic() + self.stall)
            if rec is None:
                return
            try:
                pk = ch.peek(rec)
            except (ch.PeekError, ch.PeekIncomplete):
                return
            sni = (pk.get("sni") or "").lower()
            route = next((r for r in l["l4"] if r["sni"].lower() == sni), None)
            if route is None:
                return
            host, port = route["upstream"].rsplit(":", 1)
            up = socket.create_connection((host, int(port)), timeout=5)
            up.sendall(rec)
            self.splice(c, up)
        except OSError:
            return
        finally:
            c.close()
            if up:
                up.close()

    def splice(self, a, b):
        import select
        t0 = last = time.monotonic()
        open_ = {a: b, b: a}
        while open_:
            if MUTANT == "idle-absolute" and time.monotonic() - t0 >= self.idle:
                break
            if MUTANT != "idle-ignored" and MUTANT != "idle-absolute" and time.monotonic() - last >= self.idle:
                break
            r, _, _ = select.select(list(open_), [], [], 0.05)
            for s in r:
                try:
                    d = s.recv(65536)
                except OSError:
                    d = b""
                if not d:
                    try:
                        open_[s].shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    del open_[s]
                    continue
                open_[s].sendall(d)
                last = time.monotonic()
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class Admin(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"ok" if self.path == "/healthz" else b"# EOF\n"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config")
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--audit-dir")
    a = ap.parse_args()
    try:
        with open(a.config) as f:
            cfg = json.load(f)
        srv = Server(cfg, a.cert, a.key)
    except (OSError, ValueError, KeyError, TypeError) as e:
        log(f"config refused: {e}")
        return EX_CONFIG
    for l in cfg["listeners"]:
        srv.listen(l)
    host, port = cfg["admin"]["bind"].rsplit(":", 1)
    adm = ThreadingHTTPServer((host, int(port)), Admin)
    threading.Thread(target=adm.serve_forever, daemon=True).start()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    log(f"serving{(' mutant ' + MUTANT) if MUTANT else ''}")
    stop.wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
