#!/usr/bin/env -S python3 -I
"""Private key material scanner for the release pipeline (P6-release-001; PREFLIGHT D-P2: no private key may reach
the release directory).

Usage:
  leakcheck.py [--keys KEYDIR] PATH...     scan every regular file under each PATH
  leakcheck.py --self-test

Generic checks (no key needed), on raw bytes and on their base64 renderings:
  - a PEM private key block: `-----BEGIN <anything> PRIVATE KEY-----` (PKCS#8, encrypted PKCS#8, EC, RSA, OPENSSH);
  - a PKCS#8 DER private key header for the release algorithms: Ed25519 (OID 1.3.101.112), ML-DSA-44/65/87 and
    SLH-DSA-SHA2-128s (OIDs 2.16.840.1.101.3.4.3.17/18/19/20), i.e. `INTEGER 0, SEQUENCE { OID }` (a public SPKI has
    no INTEGER 0 before its AlgorithmIdentifier, so public keys do not match).
Known-key checks (--keys KEYDIR: every *.key.pem there, read with `openssl pkey`): the key's PKCS#8 DER, its hex and
base64, each PEM body line, and for Ed25519 the 32-byte seed raw, in hex and in base64 must not occur in any file.
Symlinks and special files are refused, so nothing hides behind them.

Output: one `LEAK <path>: <what>` line per finding, then `LEAKCHECK: PASS` (exit 0) or `LEAKCHECK: FAIL (<n>
findings)` (exit 1).
"""

import base64
import binascii
import os
import re
import shutil
import subprocess
import sys
import tempfile

OPENSSL = os.environ.get("AEGIS_OPENSSL", "/usr/bin/openssl")
PEM_PRIVATE = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
# PKCS#8 OneAsymmetricKey prefix: INTEGER 0 (02 01 00) then AlgorithmIdentifier SEQUENCE { OID }.
DER_HEADERS = {
    "Ed25519 PKCS#8 DER": bytes.fromhex("020100300506032b6570"),
    "ML-DSA-44 PKCS#8 DER": bytes.fromhex("020100300b0609608648016503040311"),
    "ML-DSA-65 PKCS#8 DER": bytes.fromhex("020100300b0609608648016503040312"),
    "ML-DSA-87 PKCS#8 DER": bytes.fromhex("020100300b0609608648016503040313"),
    "SLH-DSA-SHA2-128s PKCS#8 DER": bytes.fromhex("020100300b0609608648016503040314"),
}


def b64_variants(needle):
    """base64 renderings of `needle` at the three byte alignments, with the partial edge characters cut off: any
    base64 text that encodes `needle` contains one of these."""
    out = []
    for pad in range(3):
        enc = base64.b64encode(b"\0" * pad + needle)
        start = (pad * 8 + 5) // 6  # first char made only of needle bits
        end = ((pad + len(needle)) * 8) // 6  # chars after this mix in whatever follows the needle
        frag = enc[start:end]
        if len(frag) >= 8:
            out.append(frag)
    return out


def generic_needles():
    n = []
    for what, h in DER_HEADERS.items():
        n.append((what, h))
        for v in b64_variants(h):
            n.append((what + " (base64)", v))
            n.append((what + " (base64url)", v.replace(b"+", b"-").replace(b"/", b"_")))
        n.append((what + " (hex)", binascii.hexlify(h)))
        n.append((what + " (HEX)", binascii.hexlify(h).upper()))
    return n


def key_needles(keydir):
    n = []
    for fn in sorted(os.listdir(keydir)):
        if not fn.endswith(".key.pem"):
            continue
        p = os.path.join(keydir, fn)
        der = subprocess.run([OPENSSL, "pkey", "-in", p, "-outform", "DER"], capture_output=True, check=True).stdout
        if not der:
            raise RuntimeError(f"openssl produced no DER for {fn}")
        items = [("DER", der), ("DER hex", binascii.hexlify(der)), ("DER HEX", binascii.hexlify(der).upper())]
        items += [("DER base64", v) for v in b64_variants(der)]
        with open(p, "rb") as f:
            for line in f.read().splitlines():
                line = line.strip()
                if line and not line.startswith(b"-----"):
                    items.append(("PEM body line", line))
        if der.startswith(bytes.fromhex("302e020100300506032b657004220420")) and len(der) == 48:
            seed = der[16:]
            items += [("Ed25519 seed", seed), ("Ed25519 seed hex", binascii.hexlify(seed)),
                      ("Ed25519 seed HEX", binascii.hexlify(seed).upper())]
            items += [("Ed25519 seed base64", v) for v in b64_variants(seed)]
        n += [(f"{fn} {what}", b) for what, b in items]
    return n


def scan(paths, keydir=None):
    needles = generic_needles() + (key_needles(keydir) if keydir else [])
    findings = []
    for top in paths:
        if os.path.islink(top):
            findings.append((top, "is a symlink"))
            continue
        if os.path.isfile(top):
            walk = [(os.path.dirname(top), [], [os.path.basename(top)])]
        elif os.path.isdir(top):
            walk = os.walk(top)
        else:
            findings.append((top, "missing or not a regular file/directory"))
            continue
        for dp, dns, fns in walk:
            for d in dns:
                if os.path.islink(os.path.join(dp, d)):
                    findings.append((os.path.join(dp, d), "is a symlink"))
            for fn in fns:
                p = os.path.join(dp, fn)
                if os.path.islink(p) or not os.path.isfile(p):
                    findings.append((p, "is not a regular file"))
                    continue
                with open(p, "rb") as f:
                    data = f.read()
                if PEM_PRIVATE.search(data):
                    findings.append((p, "PEM private key block"))
                for what, nd in needles:
                    if nd in data:
                        findings.append((p, what))
    return findings


def report(findings):
    for p, what in findings:
        print(f"LEAK {p}: {what}")
    if findings:
        print(f"LEAKCHECK: FAIL ({len(findings)} findings)")
        return 1
    print("LEAKCHECK: PASS")
    return 0


def self_test():
    """Clean files pass; every planted form of a private key is found (generic scan, and the known-key scan for the
    forms the generic scan cannot see: raw seed and hex seed)."""
    t = tempfile.mkdtemp(prefix="aegis-leakcheck-")
    try:
        kd = os.path.join(t, "keys")
        os.makedirs(kd, mode=0o700)
        algs = {"ed25519": "ED25519", "ml-dsa-87": "ML-DSA-87", "slh-dsa-sha2-128s": "SLH-DSA-SHA2-128s"}
        for name, alg in algs.items():
            k = os.path.join(kd, name + ".key.pem")
            subprocess.run([OPENSSL, "genpkey", "-algorithm", alg, "-out", k], check=True, capture_output=True)
            subprocess.run([OPENSSL, "pkey", "-in", k, "-pubout", "-out", os.path.join(t, name + ".pub.pem")],
                           check=True, capture_output=True)

        def der(name):
            return subprocess.run([OPENSSL, "pkey", "-in", os.path.join(kd, name + ".key.pem"), "-outform", "DER"],
                                  check=True, capture_output=True).stdout

        clean = os.path.join(t, "clean")
        os.makedirs(os.path.join(clean, "sigs"))
        for name in algs:
            shutil.copy(os.path.join(t, name + ".pub.pem"), os.path.join(clean, "sigs", name + ".pub.pem"))
            pub_der = subprocess.run([OPENSSL, "pkey", "-pubin", "-in", os.path.join(t, name + ".pub.pem"),
                                      "-outform", "DER"], check=True, capture_output=True).stdout
            with open(os.path.join(clean, "sigs", name + ".pub.der"), "wb") as f:
                f.write(pub_der)
        with open(os.path.join(clean, "notes.txt"), "wb") as f:
            f.write(b"public keys only; the word PRIVATE KEY alone is not a PEM block\n")
        seed = der("ed25519")[16:]
        plants = {
            "pem-pkcs8": (open(os.path.join(kd, "ed25519.key.pem"), "rb").read(), False),
            "pem-ml-dsa": (open(os.path.join(kd, "ml-dsa-87.key.pem"), "rb").read(), False),
            "pem-encrypted-label": (b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n", False),
            "pem-openssh-label": (b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n", False),
            "der-ed25519": (der("ed25519"), False),
            "der-slh-dsa": (der("slh-dsa-sha2-128s"), False),
            "der-ml-dsa-in-json-b64": (b'{"k":"' + base64.b64encode(der("ml-dsa-87")) + b'"}', False),
            "der-ed25519-b64-offset1": (b"x" + base64.b64encode(b"z" + der("ed25519")), False),
            "der-ed25519-b64-offset2": (base64.b64encode(b"zz" + der("ed25519")), False),
            "der-hex": (binascii.hexlify(der("ed25519")), False),
            "raw-seed": (b"prefix" + seed, True),
            "hex-seed": (binascii.hexlify(seed), True),
        }
        ok = True
        f = scan([clean])
        g = scan([clean], kd)
        if f or g:
            print(f"SELF-TEST: clean tree flagged: {f + g}")
            ok = False
        for name, (blob, needs_keys) in plants.items():
            mdir = os.path.join(t, "m-" + name)
            shutil.copytree(clean, mdir)
            with open(os.path.join(mdir, "sigs", "planted.bin"), "wb") as fh:
                fh.write(blob)
            found = scan([mdir], kd if needs_keys else None)
            if not found:
                print(f"SELF-TEST: mutant {name} NOT caught")
                ok = False
            else:
                print(f"SELF-TEST: mutant {name} caught ({found[0][1]})")
        link = os.path.join(t, "m-symlink")
        shutil.copytree(clean, link)
        os.symlink(os.path.join(kd, "ed25519.key.pem"), os.path.join(link, "sigs", "k.pem"))
        if not scan([link]):
            print("SELF-TEST: mutant symlink NOT caught")
            ok = False
        else:
            print("SELF-TEST: mutant symlink caught")
        n = len(plants) + 1
        print(f"LEAKCHECK SELF-TEST: {'PASS' if ok else 'FAIL'} (clean tree passes; {n} planted-key mutants)")
        return 0 if ok else 1
    finally:
        for dp, _dn, fns in os.walk(t):
            for fn in fns:
                if fn.endswith(".key.pem"):
                    subprocess.run(["shred", "-u", "-z", os.path.join(dp, fn)], check=False)
        shutil.rmtree(t, ignore_errors=True)


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    keydir = None
    if len(argv) >= 2 and argv[0] == "--keys":
        keydir, argv = argv[1], argv[2:]
    if not argv or any(a.startswith("--") for a in argv):
        print(__doc__.strip().splitlines()[3], file=sys.stderr)
        return 2
    return report(scan(argv, keydir))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
