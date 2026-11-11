#!/usr/bin/env -S python3 -I
"""Audit a release key directory (stdlib only; no key is decrypted).

  keycheck.py private DIR    the ceremony's private output: root-1..5.key.enc.pem, online/ (7 keys), WHERE-TO-STORE.txt
  keycheck.py online DIR     the online keys a release uses (ci/release/pipeline.sh --keys DIR)
  keycheck.py public DIR     the public directory committed to the repo (release-keys/)
  keycheck.py partial DIR    replacement keys from ceremony.sh next-root: any of root-N.key.enc.pem, online/<7 keys>

private / online: exactly the expected files (anything else is refused, so a stray plaintext copy cannot hide), each
key one PEM block "BEGIN ENCRYPTED PRIVATE KEY" whose DER is PBES2 + PBKDF2 (hmacWithSHA256, >= 600,000 iterations)
+ AES-256-CBC, and no file anywhere holding a plaintext private key (PEM or PKCS#8 DER, via jobs/leakcheck.py's
patterns). private also requires mode 0600 files / 0700 dirs.
public: exactly the 12 public keys, KEYS.txt and N.root.json files (1..N consecutive), each .pub.pem a single
"BEGIN PUBLIC KEY" block, and no private key material at all (jobs/leakcheck.py). The TUF content of the roots
(3 of 5, signatures, chain, no test_keys) is root.py check's job.

Final line: KEYCHECK: PASS (<what>) or KEYCHECK: FAIL (<first problem>); one PROBLEM line per finding.
"""

import base64
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
LEAKCHECK = os.path.join(HERE, "..", "jobs", "leakcheck.py")
ONLINE = ("ed25519", "slh-dsa-sha2-128s", "ml-dsa-87", "attest", "targets", "snapshot", "timestamp")
ROOTS = tuple(f"root-{i}" for i in range(1, 6))
MIN_ITER = 600000
OID_PBES2 = bytes.fromhex("06092a864886f70d01050d")
OID_PBKDF2 = bytes.fromhex("06092a864886f70d01050c")
OID_HMAC_SHA256 = bytes.fromhex("06082a864886f70d0209")
OID_AES256CBC = bytes.fromhex("060960864801650304012a")
PEM_ANY = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----")
ENC_PEM = re.compile(rb"\A-----BEGIN ENCRYPTED PRIVATE KEY-----\n([A-Za-z0-9+/=\n]+)-----END ENCRYPTED PRIVATE KEY-----\n\Z")
PUB_PEM = re.compile(rb"\A-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=\n]+)-----END PUBLIC KEY-----\n\Z")
ROOT_RE = re.compile(r"\A([1-9][0-9]{0,8})\.root\.json\Z")


def der_len(b, i):
    """(length, index after the length octets) of the DER length at b[i]."""
    n = b[i]
    if n < 0x80:
        return n, i + 1
    k = n & 0x7F
    return int.from_bytes(b[i + 1:i + 1 + k], "big"), i + 1 + k


def check_encrypted(path, data):
    m = ENC_PEM.match(data)
    if not m:
        return "not a single 'BEGIN ENCRYPTED PRIVATE KEY' PEM block"
    try:
        der = base64.b64decode(m[1].replace(b"\n", b""), validate=True)
    except ValueError:
        return "PEM body is not base64"
    # EncryptedPrivateKeyInfo ::= SEQUENCE { SEQUENCE { OID PBES2, SEQUENCE { kdf SEQUENCE { OID PBKDF2,
    #   SEQUENCE { OCTET STRING salt, INTEGER iter, [keylen], SEQUENCE { OID prf } } }, SEQUENCE { OID enc, iv } } },
    #   OCTET STRING }
    if not der.startswith(b"\x30") or OID_PBES2 not in der[:24]:
        return "not PBES2"
    for oid, what in ((OID_PBKDF2, "PBKDF2"), (OID_HMAC_SHA256, "hmacWithSHA256"), (OID_AES256CBC, "AES-256-CBC")):
        if oid not in der[:128]:
            return f"encryption is not {what}"
    i = der.index(OID_PBKDF2) + len(OID_PBKDF2)
    if der[i] != 0x30:
        return "malformed PBKDF2 parameters"
    _, i = der_len(der, i + 1)
    if der[i] != 0x04:
        return "malformed PBKDF2 salt"
    n, i = der_len(der, i + 1)
    if n < 16:
        return f"PBKDF2 salt only {n} bytes"
    i += n
    if der[i] != 0x02:
        return "malformed PBKDF2 iteration count"
    n, i = der_len(der, i + 1)
    it = int.from_bytes(der[i:i + n], "big")
    if it < MIN_ITER:
        return f"PBKDF2 iterations {it} < {MIN_ITER}"
    return None


def leak(paths):
    p = subprocess.run([sys.executable, "-I", LEAKCHECK] + list(paths), capture_output=True, text=True, check=False)
    return [ln for ln in p.stdout.splitlines() if ln.startswith("LEAK ")] if p.returncode != 0 else []


def files_under(d):
    out, probs = [], []
    for dp, dns, fns in os.walk(d):
        dns.sort()
        for n in dns:
            if os.path.islink(os.path.join(dp, n)):
                probs.append(f"{os.path.join(dp, n)}: symlink")
        for fn in sorted(fns):
            p = os.path.join(dp, fn)
            if os.path.islink(p) or not os.path.isfile(p):
                probs.append(f"{p}: not a regular file")
            else:
                out.append(os.path.relpath(p, d))
    return out, probs


def plaintext_scan(d, rels):
    """Any plaintext private key PEM block, anywhere (encrypted PKCS#8 blocks are the expected content)."""
    probs = []
    for r in rels:
        with open(os.path.join(d, r), "rb") as f:
            data = f.read()
        for m in PEM_ANY.finditer(data):
            t = m[1]
            if t.endswith(b"PRIVATE KEY") and t != b"ENCRYPTED PRIVATE KEY":
                probs.append(f"{r}: plaintext private key ({t.decode()})")
    return probs


def check_keys(d, expected, extra_ok, modes):
    probs = []
    rels, p = files_under(d)
    probs += p
    have = set(rels)
    for e in expected:
        if e not in have:
            probs.append(f"{e}: missing")
    for r in sorted(have - set(expected) - set(extra_ok)):
        probs.append(f"{r}: unexpected file (only the encrypted keys belong here)")
    probs += plaintext_scan(d, rels)
    for r in sorted(have & set(expected)):
        with open(os.path.join(d, r), "rb") as f:
            why = check_encrypted(r, f.read())
        if why:
            probs.append(f"{r}: {why}")
    # DER-encoded plaintext PKCS#8 (or its base64) anywhere, outside the encrypted PEMs (whose ciphertext is random)
    others = [os.path.join(d, r) for r in sorted(have - set(expected))]
    probs += [f"{ln[5:]}" for ln in leak(others)] if others else []
    if modes:
        for dp, dns, fns in os.walk(d):
            for n in [dp] + [os.path.join(dp, x) for x in dns]:
                if os.stat(n).st_mode & 0o077:
                    probs.append(f"{n}: directory mode {oct(os.stat(n).st_mode & 0o777)} (want 0700)")
            for fn in fns:
                n = os.path.join(dp, fn)
                if os.path.isfile(n) and os.stat(n).st_mode & 0o077:
                    probs.append(f"{os.path.relpath(n, d)}: mode {oct(os.stat(n).st_mode & 0o777)} (want 0600)")
    return probs


def check_public(d):
    probs = []
    rels, p = files_under(d)
    probs += p
    pubs = {f"{n}.pub.pem" for n in ONLINE + ROOTS}
    roots = sorted(int(ROOT_RE.match(r)[1]) for r in rels if ROOT_RE.match(r))
    for e in sorted(pubs | {"KEYS.txt"}):
        if e not in rels:
            probs.append(f"{e}: missing")
    if not roots or roots != list(range(1, roots[-1] + 1)):
        probs.append(f"root versions {roots} are not 1..N")
    for r in sorted(set(rels) - pubs - {"KEYS.txt"}):
        if not ROOT_RE.match(r):
            probs.append(f"{r}: unexpected file")
    for r in sorted(set(rels) & pubs):
        with open(os.path.join(d, r), "rb") as f:
            if not PUB_PEM.match(f.read()):
                probs.append(f"{r}: not a single 'BEGIN PUBLIC KEY' PEM block")
    probs += plaintext_scan(d, rels)
    probs += [ln[5:] for ln in leak([d])]
    return probs, (roots[-1] if roots else 0)


def main(argv):
    if len(argv) != 2 or argv[0] not in ("private", "online", "public", "partial"):
        print("usage: keycheck.py private|online|public|partial DIR", file=sys.stderr)
        return 2
    kind, d = argv
    if not os.path.isdir(d):
        probs, what = [f"{d}: not a directory"], ""
    elif kind == "private":
        exp = [f"{r}.key.enc.pem" for r in ROOTS] + [f"online/{n}.key.enc.pem" for n in ONLINE]
        probs, what = check_keys(d, exp, ["WHERE-TO-STORE.txt"], True), "5 root + 7 online keys, all encrypted"
    elif kind == "partial":
        allowed = [f"{r}.key.enc.pem" for r in ROOTS] + [f"online/{n}.key.enc.pem" for n in ONLINE]
        rels, _ = files_under(d) if os.path.isdir(d) else ([], [])
        exp = [r for r in rels if r in allowed]
        probs = check_keys(d, exp, ["WHERE-TO-STORE.txt"], True)
        if not exp:
            probs.append("no replacement key")
        what = f"{len(exp)} replacement key(s), all encrypted"
    elif kind == "online":
        probs, what = check_keys(d, [f"{n}.key.enc.pem" for n in ONLINE], ["WHERE-TO-STORE.txt"], False), \
            "7 online keys, all encrypted"
    else:
        probs, n = check_public(d)
        what = f"12 public keys, roots 1..{n}, no private material"
    for p in probs:
        print(f"PROBLEM {p}")
    if probs:
        print(f"KEYCHECK: FAIL ({probs[0]})")
        return 1
    print(f"KEYCHECK: PASS ({kind} {d}: {what})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
