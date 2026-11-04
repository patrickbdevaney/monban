#!/usr/bin/env python3
"""kx-interop oracle (PLAN-6 D4, PREFLIGHT D-P4): AEGIS PQ key-exchange groups against independent TLS stacks.

Invoked by ./run (python3 -I, stdlib only). For every matrix cell the subject (aegis tls-subject, or the reference /
a mutant in --self-test) speaks TLS over stdin/stdout and this script bridges it to a TCP socket on which the peer
(OpenSSL 3.5.3 CLI, Go 1.27.3 crypto/tls, BoringSSL bssl) runs. The bridge parses every plaintext TLS record in both
directions, so the negotiated group and any HelloRetryRequest are observed on the wire, independently of what
either side reports. A cell passes only if wire, peer and subject all agree and application data made the round trip.
"""
import argparse
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
NAME = "KX-INTEROP"
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

# codepoint -> (OpenSSL name, BoringSSL name). Names a library does not know are still listed: the capability probe
# (not this table) decides what a peer has.
NAMES = {
    0x11ED: ("SecP384r1MLKEM1024", "SecP384r1MLKEM1024"),
    0x11EB: ("SecP256r1MLKEM768", "SecP256r1MLKEM768"),
    0x11EC: ("X25519MLKEM768", "X25519MLKEM768"),
    0x0202: ("MLKEM1024", "MLKEM1024"),
    0x001D: ("X25519", "X25519"),
    0x0017: ("secp256r1", "P-256"),
    0x0018: ("secp384r1", "P-384"),
}
PEERS = ("openssl", "go", "bssl")

# The coverage PREFLIGHT D-P4 / unit P6-oracle-interop-001 requires: (group, peer, subject role, hrr). The matrix
# file may add cells, never drop one of these; a matrix missing one is refused.
REQUIRED = {
    (0x11ED, "openssl", "server", False), (0x11ED, "openssl", "client", False), (0x11ED, "openssl", "server", True),
    (0x11ED, "go", "server", False), (0x11ED, "go", "client", False), (0x11ED, "go", "server", True),
    (0x11EB, "openssl", "server", False), (0x11EB, "openssl", "client", True),
    (0x11EB, "go", "server", False), (0x11EB, "go", "client", True),
    (0x0202, "openssl", "server", False), (0x0202, "openssl", "client", False),
    (0x0202, "bssl", "server", False), (0x0202, "bssl", "client", False),
    (0x0202, "go", "server", False), (0x0202, "go", "client", False),
    (0x11EC, "bssl", "server", False), (0x11EC, "bssl", "client", False),
}
# Negative coverage: a peer offering only X25519 must not complete against P-UNIVERSAL.
REQUIRED_REFUSE = {("P-UNIVERSAL", "openssl", (0x001D,)), ("P-UNIVERSAL", "go", (0x001D,))}

CELL_TIMEOUT = 25.0
VERBOSE = bool(os.environ.get("KX_INTEROP_VERBOSE"))
ECHO_WAIT = 8.0


def log(*a):
    print(*a, flush=True)


def hexg(g):
    return "none" if g is None else f"0x{g:04x}"


# ------------------------------------------------------------------------------------------------ wire observer

class Flow:
    """One direction of plaintext TLS records: handshake messages until encryption starts, plaintext alerts."""

    def __init__(self):
        self.buf = bytearray()
        self.hs = bytearray()
        self.msgs = []          # (type, body) of plaintext handshake messages
        self.alerts = []        # plaintext alert descriptions
        self.encrypted = 0      # count of application_data records (encrypted handshake + app data)
        self.bytes = 0

    def feed(self, data):
        self.bytes += len(data)
        self.buf += data
        while len(self.buf) >= 5:
            ct, ln = self.buf[0], int.from_bytes(self.buf[3:5], "big")
            if len(self.buf) < 5 + ln:
                break
            frag = bytes(self.buf[5:5 + ln])
            del self.buf[:5 + ln]
            if ct == 22 and not self.encrypted:
                self.hs += frag
                while len(self.hs) >= 4:
                    n = int.from_bytes(self.hs[1:4], "big")
                    if len(self.hs) < 4 + n:
                        break
                    self.msgs.append((self.hs[0], bytes(self.hs[4:4 + n])))
                    del self.hs[:4 + n]
            elif ct == 21 and not self.encrypted and len(frag) >= 2:
                self.alerts.append(frag[1])
            elif ct == 23:
                self.encrypted += 1


def exts(body, off):
    out = {}
    if off + 2 > len(body):
        return out
    end = off + 2 + int.from_bytes(body[off:off + 2], "big")
    off += 2
    while off + 4 <= min(end, len(body)):
        t, n = int.from_bytes(body[off:off + 2], "big"), int.from_bytes(body[off + 2:off + 4], "big")
        out[t] = body[off + 4:off + 4 + n]
        off += 4 + n
    return out


def parse_ch(body):
    off = 2 + 32
    off += 1 + body[off]
    off += 2 + int.from_bytes(body[off:off + 2], "big")
    off += 1 + body[off]
    e = exts(body, off)
    groups, shares = [], []
    sg = e.get(0x000A, b"")
    groups = [int.from_bytes(sg[i:i + 2], "big") for i in range(2, len(sg) - 1, 2)]
    ks = e.get(0x0033, b"")
    i = 2
    while i + 4 <= len(ks):
        g, n = int.from_bytes(ks[i:i + 2], "big"), int.from_bytes(ks[i + 2:i + 4], "big")
        shares.append((g, n))
        i += 4 + n
    return {"groups": groups, "shares": shares}


def parse_sh(body):
    hrr = body[2:34] == HRR_RANDOM
    off = 2 + 32
    off += 1 + body[off]
    off += 2 + 1
    e = exts(body, off)
    ks = e.get(0x0033, b"")
    group = int.from_bytes(ks[0:2], "big") if len(ks) >= 2 else None
    sv = e.get(0x002B, b"")
    version = int.from_bytes(sv[0:2], "big") if len(sv) >= 2 else None
    share_len = int.from_bytes(ks[2:4], "big") if (not hrr and len(ks) >= 4) else None
    return {"hrr": hrr, "group": group, "version": version, "share_len": share_len}


def summarize(c2s, s2c):
    w = {"ch": [], "hrr": None, "sh": None, "alerts_c2s": c2s.alerts, "alerts_s2c": s2c.alerts,
         "app_c2s": c2s.encrypted, "app_s2c": s2c.encrypted}
    for t, b in c2s.msgs:
        if t == 1:
            try:
                w["ch"].append(parse_ch(b))
            except IndexError:
                w["ch"].append({"groups": [], "shares": [], "malformed": True})
    for t, b in s2c.msgs:
        if t == 2:
            try:
                sh = parse_sh(b)
            except IndexError:
                continue
            if sh["hrr"] and w["hrr"] is None and w["sh"] is None:
                w["hrr"] = sh
            elif not sh["hrr"] and w["sh"] is None:
                w["sh"] = sh
    return w


# ------------------------------------------------------------------------------------------------ processes

class Proc:
    """A peer process with merged stdout/stderr collected line by line."""

    def __init__(self, argv, name=None):
        self.argv, self.docker_name = argv, name
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  bufsize=0)
        self.lines, self.lock = [], threading.Lock()
        self.t = threading.Thread(target=self._read, daemon=True)
        self.t.start()

    def _read(self):
        buf = b""
        while True:
            d = self.p.stdout.read1(65536) if hasattr(self.p.stdout, "read1") else os.read(self.p.stdout.fileno(), 65536)
            if not d:
                break
            buf += d
            *done, buf = buf.split(b"\n")
            with self.lock:
                self.lines += [x.decode("utf-8", "replace").rstrip("\r") for x in done]
        if buf:
            with self.lock:
                self.lines.append(buf.decode("utf-8", "replace"))

    def text(self):
        with self.lock:
            return list(self.lines)

    def wait_line(self, pred, timeout):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            for ln in self.text():
                if pred(ln):
                    return ln
            if self.p.poll() is not None and not self.t.is_alive():
                for ln in self.text():
                    if pred(ln):
                        return ln
                return None
            time.sleep(0.05)
        return None

    def write(self, s):
        try:
            self.p.stdin.write(s.encode())
            self.p.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            pass

    def close_stdin(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass

    def finish(self, timeout):
        self.close_stdin()
        try:
            self.p.wait(timeout)
        except subprocess.TimeoutExpired:
            self.kill()
        self.t.join(2)
        return self.p.returncode

    def kill(self):
        if self.docker_name:
            subprocess.run(["docker", "kill", self.docker_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if self.p.poll() is None:
            self.p.kill()
            try:
                self.p.wait(5)
            except subprocess.TimeoutExpired:
                pass


def bridge(sock, subj, c2s_is_sock):
    """Pump bytes between the TCP socket and the subject's stdio; feed both flows. Returns (c2s, s2c, threads)."""
    c2s, s2c = Flow(), Flow()
    from_sock, from_subj = (c2s, s2c) if c2s_is_sock else (s2c, c2s)

    def sock_to_subj():
        try:
            while True:
                d = sock.recv(65536)
                if not d:
                    break
                from_sock.feed(d)
                subj.stdin.write(d)
                subj.stdin.flush()
        except (OSError, ValueError):
            pass
        try:
            subj.stdin.close()
        except OSError:
            pass

    def subj_to_sock():
        try:
            while True:
                d = os.read(subj.stdout.fileno(), 65536)
                if not d:
                    break
                from_subj.feed(d)
                sock.sendall(d)
        except OSError:
            pass
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    ts = [threading.Thread(target=sock_to_subj, daemon=True), threading.Thread(target=subj_to_sock, daemon=True)]
    for t in ts:
        t.start()
    return c2s, s2c, ts


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def connect_retry(port, timeout):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=2)
        except OSError:
            time.sleep(0.1)
    return None


# ------------------------------------------------------------------------------------------------ peers

class Env:
    def __init__(self, a, work):
        self.openssl, self.gopeer, self.bssl_image = a.openssl, a.gopeer, a.bssl_image
        self.work = work
        self.ca = os.path.join(work, "ca.pem")
        self.leaf = os.path.join(work, "leaf.pem")
        self.key = os.path.join(work, "leaf.key")
        self.n = 0

    def docker(self, args):
        self.n += 1
        name = f"kxi-{os.getpid()}-{self.n}"
        return ["docker", "run", "-i", "--rm", "--name", name, "--network", "host", "-v", f"{self.work}:/w:ro",
                self.bssl_image] + args, name


def make_creds(env):
    o, w = env.openssl, env.work
    q = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "check": True}
    subprocess.run([o, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384", "-nodes",
                    "-keyout", f"{w}/ca.key", "-out", env.ca, "-days", "2", "-subj", "/CN=kx-interop test CA",
                    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign"], **q)
    subprocess.run([o, "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384", "-nodes", "-keyout", env.key,
                    "-out", f"{w}/leaf.csr", "-subj", "/CN=aegis.test"], **q)
    with open(f"{w}/ext", "w") as f:
        f.write("subjectAltName=DNS:aegis.test\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
    subprocess.run([o, "x509", "-req", "-in", f"{w}/leaf.csr", "-CA", env.ca, "-CAkey", f"{w}/ca.key", "-out",
                    env.leaf, "-days", "2", "-extfile", f"{w}/ext"], **q)
    for f in (env.key, f"{w}/ca.key"):
        os.chmod(f, 0o644)  # read by the bssl container (root in a throwaway image); test keys, deleted after the run


def probe(env):
    """What each peer actually implements (TLS 1.3 groups), by asking the peer, not by a table."""
    caps = {}
    out = subprocess.run([env.openssl, "list", "-tls-groups", "-tls1_3"], capture_output=True, text=True).stdout
    names = {n.lower() for n in out.strip().split(":")}
    caps["openssl"] = {g for g, (on, _) in NAMES.items() if on.lower() in names}
    out = subprocess.run([env.gopeer, "probe"], capture_output=True, text=True, timeout=60).stdout
    caps["go"] = {int(m.group(1), 16) for m in re.finditer(r"^group 0x([0-9a-f]{4}) ok$", out, re.M)}
    # bssl exits non-zero both for an unknown curve name and for the refused connection, so tell them apart by message.
    script = "; ".join(f"echo {g:04x} $(/usr/local/bin/bssl client -connect 127.0.0.1:9 -curves {bn} </dev/null 2>&1 "
                       f"| grep -c -e 'Failed setting curves' -e UNSUPPORTED_ELLIPTIC_CURVE)" for g, (_, bn) in NAMES.items())
    r = subprocess.run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "bash", env.bssl_image, "-c",
                        script], capture_output=True, text=True, timeout=120)
    caps["bssl"] = set()
    for ln in r.stdout.splitlines():
        g, bad = ln.split()
        if bad == "0":
            caps["bssl"].add(int(g, 16))
    if r.returncode != 0 or not caps["bssl"]:
        caps["bssl_error"] = r.stderr.strip()[-300:]
    return caps


def client_peer(env, peer, port, groups, nonce):
    if peer == "openssl":
        names = ":".join(NAMES[g][0] for g in groups)
        return Proc([env.openssl, "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_3", "-groups", names,
                     "-servername", "aegis.test", "-nocommands"]), True
    if peer == "bssl":
        names = ":".join(NAMES[g][1] for g in groups)
        argv, name = env.docker(["client", "-connect", f"127.0.0.1:{port}", "-curves", names, "-min-version",
                                 "tls1.3", "-max-version", "tls1.3", "-server-name", "aegis.test",
                                 # BoringSSL's default verify list has no ML-DSA; P-CNSA servers sign with ML-DSA-87.
                                 "-sigalgs", "mldsa87:ecdsa_secp384r1_sha384:ecdsa_secp256r1_sha256"])
        return Proc(argv, name), True
    return Proc([env.gopeer, "client", "-connect", f"127.0.0.1:{port}", "-groups",
                 ",".join(f"0x{g:04x}" for g in groups), "-nonce", nonce]), False


def server_peer(env, peer, port, groups):
    if peer == "openssl":
        names = ":".join(NAMES[g][0] for g in groups)
        return Proc([env.openssl, "s_server", "-accept", f"127.0.0.1:{port}", "-tls1_3", "-groups", names,
                     "-cert", env.leaf, "-key", env.key, "-naccept", "1"]), True
    if peer == "bssl":
        names = ":".join(NAMES[g][1] for g in groups)
        argv, name = env.docker(["server", "-accept", str(port), "-curves", names, "-min-version", "tls1.3",
                                 "-max-version", "tls1.3", "-cert", "/w/leaf.pem", "-key", "/w/leaf.key"])
        return Proc(argv, name), True
    return Proc([env.gopeer, "server", "-listen", f"127.0.0.1:{port}", "-groups",
                 ",".join(f"0x{g:04x}" for g in groups), "-cert", env.leaf, "-key", env.key]), False


def peer_report(peer, lines):
    """(handshake_ok, group, hrr) as the peer itself reports them (None where the tool does not say)."""
    text = "\n".join(lines)
    if peer == "go":
        m = re.search(r"HANDSHAKE ok group=0x([0-9a-f]{4}) hrr=(true|false)", text)
        return (True, int(m.group(1), 16), m.group(2) == "true") if m else (False, None, None)
    if peer == "openssl":
        m = re.search(r"^Negotiated TLS1\.3 group: (\S+)", text, re.M)
        rev = {v[0]: k for k, v in NAMES.items()}
        ok = bool(re.search(r"^New, TLSv1\.3, Cipher is TLS_", text, re.M) or re.search(r"^CIPHER is TLS_", text, re.M))
        return ok, (rev.get(m.group(1)) if m else None), None
    m = re.search(r"ECDHE group: (\S+)", text)
    rev = {v[1]: k for k, v in NAMES.items()}
    return ("Connected." in text or "Version: TLSv1.3" in text), (rev.get(m.group(1)) if m else None), None


# ------------------------------------------------------------------------------------------------ cells

def run_cell(env, subject, cell):
    nonce = "aegis-nonce-" + secrets.token_hex(12)
    role, peer, groups = cell["role"], cell["peer"], cell["peer_groups"]
    sub_argv = subject + (["interop-server", cell["profile"]] if role == "server"
                          else ["interop-client", cell["profile"], env.ca, nonce])
    obs = {"nonce_at_peer": False, "peer_echo_ok": False}
    sock = peerp = subj = None
    subj_err = []
    try:
        if role == "server":
            lst = socket.socket()
            lst.bind(("127.0.0.1", 0))
            lst.listen(1)
            lst.settimeout(15)
            peerp, interactive = client_peer(env, peer, lst.getsockname()[1], groups, nonce)
            if interactive and peer != "openssl":
                peerp.write(nonce + "\n")
            try:
                sock, _ = lst.accept()
            except OSError:
                sock = None
            lst.close()
            if sock is None:
                obs["error"] = "peer client never connected"
                return obs
        else:
            port = free_port()
            peerp, interactive = server_peer(env, peer, port, groups)
            sock = connect_retry(port, 15)
            if sock is None:
                obs["error"] = "peer server never accepted"
                return obs
        sock.settimeout(None)
        subj = subprocess.Popen(sub_argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                bufsize=0)
        et = threading.Thread(target=lambda: subj_err.extend(subj.stderr.read().decode("utf-8", "replace")
                                                             .splitlines()), daemon=True)
        et.start()
        c2s, s2c, ts = bridge(sock, subj, c2s_is_sock=(role == "server"))
        deadline = time.monotonic() + CELL_TIMEOUT
        if role == "server":
            if interactive and peer == "openssl":
                # Send once s_client has printed the handshake summary (-nocommands: a line starting "k" would
                # otherwise be taken as a KeyUpdate command, not data).
                if peerp.wait_line(lambda ln: ln.startswith("Verify return code") or ln.startswith("Negotiated TLS1.3"),
                                   ECHO_WAIT):
                    peerp.write(nonce + "\n")
            if interactive:
                got = peerp.wait_line(lambda ln: ln.strip() == nonce, ECHO_WAIT)
                obs["peer_echo_ok"] = got is not None
                peerp.close_stdin()
            else:
                peerp.wait_line(lambda ln: ln.startswith("ECHO "), ECHO_WAIT)
                obs["peer_echo_ok"] = any(ln == "ECHO ok" for ln in peerp.text())
            obs["nonce_at_peer"] = obs["peer_echo_ok"]
        else:
            if interactive:
                got = peerp.wait_line(lambda ln: ln.strip() == nonce, ECHO_WAIT)
                obs["nonce_at_peer"] = got is not None
                if got:
                    peerp.write(nonce + "\n")
            else:
                peerp.wait_line(lambda ln: ln.startswith("ECHOED ") or ln.startswith("HANDSHAKE fail"), ECHO_WAIT)
        try:
            subj.wait(max(1.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            subj.kill()
            obs["subject_timeout"] = True
        if role == "client":
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        peerp.finish(max(1.0, min(10.0, deadline - time.monotonic())))
        try:
            sock.close()
        except OSError:
            pass
        for t in ts:
            t.join(3)
        et.join(3)
        if role == "client" and not interactive:
            # Go server: it echoed what it received; it reports the byte count.
            m = [ln for ln in peerp.text() if ln.startswith("ECHOED ")]
            obs["nonce_at_peer"] = bool(m) and int(m[0].split()[1]) >= len(nonce) + 1
        obs["wire"] = summarize(c2s, s2c)
        obs["subject_rc"] = subj.returncode
        obs["subject_err"] = subj_err
        obs["peer_lines"] = peerp.text()
        obs["peer"] = peer_report(peer, peerp.text())
        return obs
    finally:
        for x in (subj,):
            if x is not None and x.poll() is None:
                x.kill()
        if peerp is not None and peerp.p.poll() is None:
            peerp.kill()
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def judge(cell, obs):
    """List of failure reasons (empty = PASS)."""
    why = []
    if "error" in obs:
        return [obs["error"]]
    w, err = obs["wire"], obs["subject_err"]
    role = cell["role"]
    if obs["subject_rc"] not in (0, None) and any("usage" in ln.lower() for ln in err):
        return [f"subject has no interop-{role} mode (README 'Subject contract'): {err[-1][:160] if err else ''}"]
    if cell["expect"] == "refuse":
        if w["sh"] is not None:
            why.append(f"handshake proceeded to ServerHello group {hexg(w['sh']['group'])} (must be refused)")
        if obs["peer"][0]:
            why.append("peer reports a completed handshake (must be refused)")
        if obs["peer_echo_ok"] or obs["nonce_at_peer"]:
            why.append("application data crossed (must be refused)")
        return why
    target = cell["group"]
    if not w["ch"]:
        why.append("no ClientHello on the wire")
    if cell["hrr"]:
        if w["ch"] and any(g == target for g, _ in w["ch"][0]["shares"]):
            why.append(f"HRR precondition: first ClientHello already has a {hexg(target)} share")
        if w["hrr"] is None:
            why.append("expected HelloRetryRequest, none on the wire")
        elif w["hrr"]["group"] != target:
            why.append(f"HelloRetryRequest selected {hexg(w['hrr']['group'])}, want {hexg(target)}")
        elif len(w["ch"]) < 2 or not any(g == target for g, _ in w["ch"][1]["shares"]):
            why.append("second ClientHello has no share for the HRR group")
    elif w["hrr"] is not None:
        why.append(f"unexpected HelloRetryRequest (selected {hexg(w['hrr']['group'])})")
    if w["sh"] is None:
        why.append("no ServerHello on the wire")
    else:
        if w["sh"]["group"] != target:
            why.append(f"ServerHello group {hexg(w['sh']['group'])}, want {hexg(target)}")
        if w["sh"]["version"] != 0x0304:
            why.append(f"ServerHello version {w['sh']['version']}")
    if w["alerts_c2s"] or w["alerts_s2c"]:
        why.append(f"plaintext alerts c2s={w['alerts_c2s']} s2c={w['alerts_s2c']}")
    ok, pg, phrr = obs["peer"]
    if not ok:
        why.append(f"peer {cell['peer']} reports no completed handshake")
    if pg is not None and pg != target:
        why.append(f"peer reports group {hexg(pg)}")
    if phrr is not None and phrr != cell["hrr"]:
        why.append(f"peer reports hrr={phrr}")
    if role == "server":
        if not obs["peer_echo_ok"]:
            why.append("application data echo not received by the peer")
    else:
        if not obs["nonce_at_peer"]:
            why.append("peer never received the subject's application data")
        if not any(ln.strip() == "interop: echo=ok" for ln in err):
            why.append("subject did not report the echo")
    m = [re.search(r"interop: handshake ok group=0x([0-9a-f]{4})", ln) for ln in err]
    m = [x for x in m if x]
    if not m:
        why.append("subject printed no 'interop: handshake ok' line")
    elif int(m[0].group(1), 16) != target:
        why.append(f"subject reports group 0x{m[0].group(1)}")
    if obs["subject_rc"] != 0:
        why.append(f"subject exit {obs['subject_rc']}{' (killed at timeout)' if obs.get('subject_timeout') else ''}"
                   f": {err[-1][:160] if err else ''}")
    return why


# ------------------------------------------------------------------------------------------------ matrix

def load_matrix(path):
    with open(path, "rb") as f:
        m = tomllib.load(f)
    cells = []
    for c in m.get("cell", []):
        cells.append({
            "id": c["id"], "group": int(c["group"], 16) if "group" in c else None, "profile": c["profile"],
            "peer": c["peer"], "role": c["role"], "hrr": bool(c.get("hrr", False)),
            "expect": c.get("expect", "complete"), "peer_groups": [int(g, 16) for g in c["peer_groups"]],
        })
    return cells


def validate(cells, caps):
    """Reasons to refuse the matrix (empty = accepted)."""
    bad, ids = [], set()
    for c in cells:
        if c["id"] in ids:
            bad.append(f"duplicate cell id {c['id']}")
        ids.add(c["id"])
        if c["peer"] not in PEERS or c["role"] not in ("server", "client") or c["expect"] not in ("complete",
                                                                                                  "refuse"):
            bad.append(f"{c['id']}: bad peer/role/expect")
            continue
        have = caps.get(c["peer"], set())
        claim = ([c["group"]] if c["group"] is not None else []) + c["peer_groups"]
        for g in claim:
            if g not in have:
                bad.append(f"{c['id']} claims {c['peer']} x {hexg(g)}, but the {c['peer']} probe says it lacks it")
        if c["expect"] == "complete" and c["group"] is None:
            bad.append(f"{c['id']}: a completing cell needs a group")
        if c["expect"] == "complete" and c["group"] not in c["peer_groups"]:
            bad.append(f"{c['id']}: peer does not offer the target group")
    have_req = {(c["group"], c["peer"], c["role"], c["hrr"]) for c in cells if c["expect"] == "complete"}
    for r in sorted(REQUIRED - have_req):
        bad.append(f"matrix lacks required cell {hexg(r[0])} x {r[1]} subject-{r[2]}{' HRR' if r[3] else ''}")
    have_ref = {(c["profile"], c["peer"], tuple(c["peer_groups"])) for c in cells if c["expect"] == "refuse"}
    for r in sorted(REQUIRED_REFUSE - have_ref):
        bad.append(f"matrix lacks required refusal cell {r[1]} offering only {[hexg(g) for g in r[2]]} vs {r[0]}")
    return bad


def run_matrix(env, subject, cells, label, only=None):
    results = {}
    for c in cells:
        if only is not None and not only(c):
            continue
        obs = run_cell(env, subject, c)
        why = judge(c, obs)
        results[c["id"]] = why
        tag = "PASS" if not why else "FAIL"
        w = obs.get("wire") or {}
        sh = (w.get("sh") or {}).get("group")
        hrr = (w.get("hrr") or {}).get("group") if w.get("hrr") else None
        log(f"[{label}] CELL {c['id']:<22} {tag}  wire: hrr={hexg(hrr)} sh={hexg(sh)}"
            + ("" if not why else "  -- " + "; ".join(why)))
        if why and VERBOSE:
            for ln in [ln for ln in obs.get("peer_lines", []) if ln.strip()][-8:]:
                log(f"    peer| {ln[:200]}")
            log(f"    wire| app records c2s={w.get('app_c2s')} s2c={w.get('app_s2c')} ch={w.get('ch')}")
            for ln in obs.get("subject_err", [])[-3:]:
                log(f"    subj| {ln[:200]}")
    return results


# ------------------------------------------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--subject", help="subject command (split on whitespace); default: target/release/tls-subject")
    ap.add_argument("--matrix", default=os.path.join(HERE, "matrix.toml"))
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--ref", help="reference subject binary (self-test)")
    ap.add_argument("--openssl", required=True)
    ap.add_argument("--gopeer", required=True)
    ap.add_argument("--bssl-image", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--only", help="regex on cell ids (diagnostics; the gate never passes it)")
    a = ap.parse_args()
    os.makedirs(a.work, exist_ok=True)
    work = tempfile.mkdtemp(prefix="run-", dir=a.work)
    os.chmod(work, 0o755)
    env = Env(a, work)
    try:
        make_creds(env)
        caps = probe(env)
        log("peers: " + "; ".join(f"{p}={','.join(hexg(g) for g in sorted(caps.get(p, ())))}" for p in PEERS))
        if "bssl_error" in caps:
            log(f"bssl probe stderr: {caps['bssl_error']}")
        cells = load_matrix(a.matrix)
        if a.self_test:
            return self_test(env, a, cells, caps)
        bad = validate(cells, caps)
        if bad:
            for b in bad:
                log("MATRIX REFUSED: " + b)
            log(f"{NAME}: FAIL (matrix refused: {len(bad)} problem(s); first: {bad[0]})")
            return 1
        if a.only:
            cells = [c for c in cells if re.search(a.only, c["id"])]
        if not a.subject:
            log(f"{NAME}: FAIL (no --subject)")
            return 1
        subject = a.subject.split()
        res = run_matrix(env, subject, cells, "run")
        failed = [k for k, v in res.items() if v]
        if failed:
            log(f"{NAME}: FAIL ({len(failed)}/{len(res)} cells failed: {', '.join(failed)})")
            return 1
        log(f"{NAME}: PASS ({len(res)} cells: groups 0x11ed 0x11eb 0x0202 0x11ec; peers OpenSSL 3.5.3, Go 1.27.3, "
            f"BoringSSL; both directions, HRR, X25519-only refusal)")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


def self_test(env, a, cells, caps):
    ST = f"{NAME} SELF-TEST"
    ref = [a.ref]
    problems, caught = [], []

    def positive(c):
        return c["expect"] == "complete"

    # M0: the matrix as shipped must be accepted, and the reference subject must pass every cell (a self-test whose
    # baseline is red proves nothing).
    bad = validate(cells, caps)
    if bad:
        log(f"{ST}: FAIL (shipped matrix refused: {bad[0]})")
        return 1
    base = run_matrix(env, ref, cells, "baseline")
    if any(base.values()):
        log(f"{ST}: FAIL (baseline reference not green: {', '.join(k for k, v in base.items() if v)})")
        return 1

    # M1 order mutant (ML-KEM secret first): every 0x11ED cell must fail; cells of other groups must still pass.
    r = run_matrix(env, ref + ["--mutant", "order"], cells, "order", only=positive)
    ed = [c["id"] for c in cells if positive(c) and c["group"] == 0x11ED]
    other = [c["id"] for c in cells if positive(c) and c["group"] != 0x11ED]
    missed = [i for i in ed if not r[i]]
    collateral = [i for i in other if r[i]]
    if missed or collateral:
        problems.append(f"order: uncaught 0x11ED cells {missed}, collateral {collateral}")
    else:
        caught.append(f"order {len(ed)}/{len(ed)} 0x11ED cells red, {len(other)} other cells green")

    # M2 X25519 fallback on P-UNIVERSAL: the X25519-only refusal cells must fail.
    r = run_matrix(env, ref + ["--mutant", "x25519-fallback"], cells, "x25519-fallback",
                   only=lambda c: c["expect"] == "refuse")
    neg = [i for i in r]
    if not neg or any(not r[i] for i in neg):
        problems.append(f"x25519-fallback: refusal cells not all red {r}")
    else:
        caught.append(f"x25519-fallback {len(neg)}/{len(neg)} refusal cells red")

    # M3 no application-data echo (server) / nonce never sent but success claimed (client): every positive cell fails.
    r = run_matrix(env, ref + ["--mutant", "no-echo"], cells, "no-echo", only=positive)
    missed = [i for i, v in r.items() if not v]
    if missed:
        problems.append(f"no-echo: uncaught {missed}")
    else:
        caught.append(f"no-echo {len(r)}/{len(r)} cells red")

    # M4 HRR liveness: make the first ClientHello carry a share for the target, so no HRR happens; each HRR cell must
    # fail. Subject-server cells: the peer client offers the target first. Subject-client cells: the reference client
    # lists P-BSI-ALT as [0x11EB, 0x11ED] (mutant bsi-11eb-first), so it shares 0x11EB up front and the group check
    # alone would still pass: only the HRR check can catch it.
    srv = []
    for c in cells:
        if c["hrr"] and positive(c) and c["role"] == "server":
            m = dict(c)
            m["peer_groups"] = [c["group"]]
            srv.append(m)
    cli = [c for c in cells if c["hrr"] and positive(c) and c["role"] == "client"]
    r = run_matrix(env, ref, srv, "hrr-precondition")
    r.update(run_matrix(env, ref + ["--mutant", "bsi-11eb-first"], cli, "hrr-bsi-11eb-first"))
    missed = [i for i, v in r.items() if not v]
    if not srv or not cli or missed:
        problems.append(f"hrr-precondition: uncaught {missed or 'missing HRR cells'}")
    else:
        caught.append(f"hrr-precondition {len(r)}/{len(r)} HRR cells red")

    # M5 a matrix claiming BoringSSL x 0x11ED must be refused (BoringSSL has no 0x11ED, PREFLIGHT D-P4).
    claim = cells + [{"id": "ED-BSSL-S", "group": 0x11ED, "profile": "P-UNIVERSAL", "peer": "bssl",
                      "role": "server", "hrr": False, "expect": "complete", "peer_groups": [0x11ED]}]
    bad = validate(claim, caps)
    if any("ED-BSSL-S claims bssl x 0x11ed" in b for b in bad):
        caught.append("matrix-bssl-11ed refused")
    else:
        problems.append(f"matrix-bssl-11ed accepted ({bad})")

    # M6 a matrix with a required cell removed (Go 0x11ED HRR) must be refused.
    dropped = [c for c in cells if not (c["group"] == 0x11ED and c["peer"] == "go" and c["hrr"])]
    if any("lacks required cell 0x11ed x go subject-server HRR" in b for b in validate(dropped, caps)):
        caught.append("matrix-missing-cell refused")
    else:
        problems.append("matrix-missing-cell accepted")

    # M7 a matrix with the X25519-only refusal cells removed must be refused.
    dropped = [c for c in cells if c["expect"] != "refuse"]
    if any("lacks required refusal cell" in b for b in validate(dropped, caps)):
        caught.append("matrix-missing-refusal refused")
    else:
        problems.append("matrix-missing-refusal accepted")

    if problems:
        log(f"{ST}: FAIL ({'; '.join(problems)})")
        return 1
    log(f"{ST}: PASS (baseline {len(base)}/{len(base)} green; {'; '.join(caught)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
