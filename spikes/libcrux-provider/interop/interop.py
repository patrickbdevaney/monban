#!/usr/bin/env python3
"""P7-libcrux-001 interop matrix: the libcrux-provider server against OpenSSL 3.5.3 s_client and Go 1.27.3 crypto/tls.

usage: python3 -I interop.py --server BIN --openssl /usr/bin/openssl --gopeer BIN --work DIR [--only REGEX]
                             [--expect-fail REGEX]
Cells: every kx (X25519MLKEM768, X25519, secp256r1) x every AEAD (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) x
{openssl, go} with an ECDSA-P256 leaf, plus every kx x {openssl, go} with an Ed25519 leaf (ChaCha20-Poly1305).
The server is pinned to one group and one suite per cell, so the negotiated values are forced; the peer offers only
the cell's group. A cell passes only if (a) the server reports the cell's group+suite and exits 0, (b) the peer reports
the same group (Go also the suite; OpenSSL the cipher name), (c) the peer verified the chain (OpenSSL: Verify return
code 0 with -verify_return_error; Go: RootCAs), and (d) a random nonce sent by the peer came back through the server.
--expect-fail REGEX inverts (a)-(d) for the matching cells (self-test mutants): those must FAIL, every other must PASS.
Last line: LCX-INTEROP: PASS (...) | LCX-INTEROP: FAIL (...).
"""
import argparse
import os
import re
import secrets
import subprocess
import sys
import threading
import time

GROUPS = {"x25519mlkem768": (0x11EC, "X25519MLKEM768"), "x25519": (0x001D, "X25519"), "secp256r1": (0x0017, "secp256r1")}
# How OpenSSL 3.5.3 s_client names the negotiated group: KEM groups get "Negotiated TLS1.3 group", (EC)DH groups get
# "Peer Temp Key" (measured on kamrui, 2026-11-06).
OSSL_GROUP_RE = {"x25519mlkem768": r"^Negotiated TLS1\.3 group: X25519MLKEM768$",
                 "x25519": r"^Peer Temp Key: X25519, 253 bits$",
                 "secp256r1": r"^Peer Temp Key: ECDH, prime256v1, 256 bits$"}
SUITES = {"aes128gcm": (0x1301, "TLS_AES_128_GCM_SHA256"), "aes256gcm": (0x1302, "TLS_AES_256_GCM_SHA384"),
          "chacha20": (0x1303, "TLS_CHACHA20_POLY1305_SHA256")}
TIMEOUT = 20.0


def cells():
    out = []
    for g in GROUPS:
        for s in SUITES:
            for peer in ("openssl", "go"):
                out.append((f"{g}-{s}-ecdsa-{peer}", g, s, "ecdsa", peer))
    for g in GROUPS:
        for peer in ("openssl", "go"):
            out.append((f"{g}-chacha20-ed25519-{peer}", g, "chacha20", "ed25519", peer))
    return out


class Proc:
    def __init__(self, argv):
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.lines, self.lock = [], threading.Lock()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for raw in iter(self.p.stdout.readline, b""):
            with self.lock:
                self.lines.append(raw.decode("utf-8", "replace").rstrip("\r\n"))

    def text(self):
        with self.lock:
            return "\n".join(self.lines)

    def wait_for(self, pat, timeout):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            m = re.search(pat, self.text(), re.M)
            if m:
                return m
            if self.p.poll() is not None:
                time.sleep(0.1)
                return re.search(pat, self.text(), re.M)
            time.sleep(0.05)
        return None

    def finish(self, timeout=TIMEOUT):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            self.p.wait(timeout)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait(5)
        time.sleep(0.05)
        return self.p.returncode


def make_creds(openssl, w):
    q = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "check": True}
    subprocess.run([openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-keyout", f"{w}/ca.key", "-out", f"{w}/ca.pem", "-days", "2", "-subj", "/CN=lcx test CA",
                    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign"], **q)
    with open(f"{w}/ext", "w") as f:
        f.write("subjectAltName=DNS:aegis.test\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n")
    for name, algo in (("ecdsa", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]),
                       ("ed25519", ["-algorithm", "ED25519"])):
        subprocess.run([openssl, "genpkey", *algo, "-out", f"{w}/{name}.key"], **q)
        subprocess.run([openssl, "req", "-new", "-key", f"{w}/{name}.key", "-out", f"{w}/{name}.csr",
                        "-subj", "/CN=aegis.test"], **q)
        subprocess.run([openssl, "x509", "-req", "-in", f"{w}/{name}.csr", "-CA", f"{w}/ca.pem", "-CAkey",
                        f"{w}/ca.key", "-out", f"{w}/{name}.leaf.pem", "-days", "2", "-extfile", f"{w}/ext"], **q)
        with open(f"{w}/{name}.chain.pem", "w") as out:
            out.write(open(f"{w}/{name}.leaf.pem").read() + open(f"{w}/ca.pem").read())


def run_cell(a, cell):
    cid, g, s, cert, peer = cell
    gid, gname = GROUPS[g]
    sid, sname = SUITES[s]
    w = a.work
    srv = Proc([a.server, "--port", "0", "--group", g, "--suite", s, "--cert", f"{w}/{cert}.chain.pem",
                "--key", f"{w}/{cert}.key", "--count", "1"])
    m = srv.wait_for(r"^listening (\d+)$", 10)
    if not m:
        srv.p.kill()
        return False, f"server did not start: {srv.text()[-300:]}"
    port = m.group(1)
    nonce = "lcxi-" + secrets.token_hex(8)
    problems = []
    if peer == "openssl":
        cli = Proc([a.openssl, "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_3", "-groups", gname,
                    "-ciphersuites", sname, "-CAfile", f"{w}/ca.pem", "-verify_return_error", "-verify_hostname",
                    "aegis.test", "-servername", "aegis.test", "-nocommands"])
        if cli.wait_for(r"^(New, TLSv1\.3, Cipher is|CIPHER is) ", TIMEOUT):
            cli.p.stdin.write((nonce + "\n").encode())
            cli.p.stdin.flush()
            cli.wait_for(rf"^{nonce}$", 8)
        cli.finish()
        out = cli.text()
        if not re.search(OSSL_GROUP_RE[g], out, re.M):
            problems.append("openssl: group not reported as " + gname)
        if not re.search(rf"^(New, TLSv1\.3, Cipher is|CIPHER is) {sname}$", out, re.M):
            problems.append("openssl: cipher not " + sname)
        if not re.search(r"Verify return code: 0 \(ok\)", out):
            problems.append("openssl: chain not verified")
        if not re.search(rf"^{nonce}$", out, re.M):
            problems.append("openssl: nonce not echoed")
    else:
        cli = Proc([a.gopeer, "-connect", f"127.0.0.1:{port}", "-group", f"0x{gid:04x}", "-ca", f"{w}/ca.pem",
                    "-nonce", nonce])
        rc = cli.finish()
        out = cli.text()
        mm = re.search(r"HANDSHAKE ok group=0x([0-9a-f]{4}) suite=0x([0-9a-f]{4})", out)
        if not mm or int(mm.group(1), 16) != gid or int(mm.group(2), 16) != sid:
            problems.append("go: handshake/group/suite: " + out.splitlines()[0][:200] if out else "go: no output")
        if rc != 0 or "ECHO ok" not in out:
            problems.append(f"go: echo failed rc={rc}")
    src = srv.finish(10)
    stext = srv.text()
    sm = re.search(r"interop: handshake ok group=0x([0-9a-f]{4}) suite=0x([0-9a-f]{4})", stext)
    if src != 0 or not sm or int(sm.group(1), 16) != gid or int(sm.group(2), 16) != sid:
        problems.append(f"server rc={src}: {stext.splitlines()[-1][:200] if stext else 'no output'}")
    with open(os.path.join(w, f"{cid}.log"), "w") as f:
        f.write(f"== server\n{stext}\n== {peer}\n{out}\n")
    return (not problems), "; ".join(problems)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--openssl", required=True)
    ap.add_argument("--gopeer", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--only")
    ap.add_argument("--expect-fail")
    a = ap.parse_args()
    os.makedirs(a.work, exist_ok=True)
    make_creds(a.openssl, a.work)
    todo = [c for c in cells() if not a.only or re.search(a.only, c[0])]
    bad, n_expected_fail = [], 0
    for c in todo:
        ok, why = run_cell(a, c)
        want_fail = bool(a.expect_fail and re.search(a.expect_fail, c[0]))
        n_expected_fail += want_fail
        verdict = "ok" if ok != want_fail else "WRONG"
        print(f"cell {c[0]}: {'pass' if ok else 'fail'}{' (expected fail)' if want_fail else ''} -> {verdict}"
              + (f" [{why}]" if why else ""), flush=True)
        if ok == want_fail:
            bad.append(c[0])
    for f in os.listdir(a.work):
        if f.endswith(".key"):
            os.remove(os.path.join(a.work, f))
    extra = f", {n_expected_fail} expected-fail cells failed" if a.expect_fail else ""
    if bad:
        print(f"LCX-INTEROP: FAIL ({len(bad)}/{len(todo)} cells wrong: {', '.join(bad[:6])})")
        sys.exit(1)
    print(f"LCX-INTEROP: PASS ({len(todo)}/{len(todo)} cells as expected{extra})")


if __name__ == "__main__":
    main()
