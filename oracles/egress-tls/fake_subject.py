#!/usr/bin/env python3
"""Self-test subjects for oracles/egress-tls: the egress-subject JSON-lines protocol answered with `openssl s_client`.

  fake_subject.py --openssl PATH --mode ref|accept-untrusted|no-hostname-check|resume|early-data|classical-first|wrong-alpn

ref: verifies the chain against the case CA and the host name, offers the profile's groups in order, no session reuse,
ALPN http/1.1 (it must PASS the oracle). Each other mode breaks one property:
  accept-untrusted   no -verify_return_error: the handshake continues past a failed chain (and name) check
  no-hostname-check  chain verified, host name not
  resume             -sess_out / -sess_in per client id: the second fetch offers pre_shared_key
  early-data         as resume, plus -early_data: the request goes out as 0-RTT
  classical-first    X25519 first in the group list (and the first key share)
  wrong-alpn         offers h2 and http/1.1
"""
import argparse, json, os, subprocess, sys, tempfile
from urllib.parse import urlsplit

NAMES = {0x11EC: "X25519MLKEM768", 0x11ED: "SecP384r1MLKEM1024", 0x11EB: "SecP256r1MLKEM768",
         0x001D: "x25519", 0x0017: "secp256r1", 0x0202: "MLKEM1024"}
PROFILES = {
    "P-PUBLIC-WEB": [0x11EC, 0x11ED, 0x11EB, 0x001D, 0x0017], "PQ-REQUIRED": [0x11EC], "P-UNIVERSAL": [0x11ED],
    "P-BSI-ALT": [0x11ED, 0x11EB], "P-CNSA": [0x0202], "FIPS-PQ-REQUIRED": [0x11EB],
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--openssl", default="openssl")
    ap.add_argument("--mode", required=True)
    a = ap.parse_args()
    sess = tempfile.mkdtemp(prefix="egress-tls-fake-")
    for line in sys.stdin:
        if not line.strip():
            continue
        c = json.loads(line)
        u = urlsplit(c["url"])
        host, port, path = u.hostname, u.port, u.path or "/"
        addr = f"{c['dns'][host][0][0]}:{port}"
        tls = c["tls"]
        groups = [NAMES[g] for g in PROFILES[tls["profile"]]]
        if a.mode == "classical-first":
            groups = ["x25519"] + [g for g in groups if g != "x25519"]
        cmd = [a.openssl, "s_client", "-connect", addr, "-servername", host, "-tls1_3", "-groups", ":".join(groups),
               "-alpn", "h2,http/1.1" if a.mode == "wrong-alpn" else "http/1.1", "-quiet", "-CAfile", tls["ca"]]
        if a.mode != "accept-untrusted":
            cmd.append("-verify_return_error")
        if a.mode not in ("accept-untrusted", "no-hostname-check"):
            cmd += ["-verify_hostname", host]
        req = f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode()
        sfile = os.path.join(sess, tls["client"].replace("/", "_") + ".sess")
        if a.mode in ("resume", "early-data"):
            if os.path.exists(sfile):
                cmd += ["-sess_in", sfile]
                if a.mode == "early-data":
                    ed = os.path.join(sess, "early.req")
                    with open(ed, "wb") as f:
                        f.write(req)
                    cmd += ["-early_data", ed]
                    req = b""
            cmd += ["-sess_out", sfile]
        try:
            r = subprocess.run(cmd, input=req, capture_output=True, timeout=20)
            out, rc = r.stdout, r.returncode
        except subprocess.TimeoutExpired:
            out, rc = b"", -1
        v = {"id": c["id"]}
        head, _, body = out.partition(b"\r\n\r\n")
        first = head.split(b"\r\n", 1)[0].split()
        if len(first) >= 2 and first[0].startswith(b"HTTP/") and first[1].isdigit():
            v.update(decision="connect", addr=addr, status=int(first[1]), body_len=len(body), body_hex=body.hex())
        else:
            v.update(reject="tls", detail=f"s_client rc={rc}")
        v.update(connects=[addr], queries={host: 1})
        print(json.dumps(v), flush=True)


if __name__ == "__main__":
    main()
