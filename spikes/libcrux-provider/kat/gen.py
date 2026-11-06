#!/usr/bin/env python3
"""Regenerate the KAT files in this directory from the public source documents (P7-libcrux-001).

usage: python3 -I gen.py <dir with the sources>
Sources (sha256 pinned below; the script refuses a file whose hash differs):
  rfc7748.txt rfc8439.txt rfc5869.txt rfc4231.txt rfc8032.txt rfc5903.txt   (https://www.rfc-editor.org/rfc/rfcNNNN.txt)
  gcmtestvectors.zip  (NIST CAVP, csrc.nist.gov .../mac/gcmtestvectors.zip)
  mlkem-kg.json mlkem-ed.json  (usnistgov/ACVP-Server gen-val/json-files/ML-KEM-{keyGen,encapDecap}-FIPS203/
                                internalProjection.json)
Output format: one vector per line, `<kind> field=hex field=hex ...` (empty value = empty byte string).
"""
import hashlib, io, json, os, re, sys, zipfile

PINS = {
    "rfc7748.txt": "279ca0ecc5e92e2962e27b846986aeb74729d9dd34bd4a04a362f80dcb596ad3",
    "rfc8439.txt": "25bef70fbf7a07ff45c2fe4cb7c6ce954eac687413d8610603268b4e4415324c",
    "rfc5869.txt": "7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c",
    "rfc4231.txt": "72178527ce93500e730bc8eb182b857e583096d652b64ece0879c52ba1df973b",
    "rfc8032.txt": "ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3",
    "rfc5903.txt": "939fab548a6e6bb49a5b3c4dd24a3c5df54a46645447b2d6f4df4fd88ff2d69f",
    "gcmtestvectors.zip": "f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023",
    "mlkem-kg.json": "d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b",
    "mlkem-ed.json": "a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f",
}
HEX = re.compile(r"^[0-9a-fA-F]+$")
OUT = os.path.dirname(os.path.abspath(__file__))


def load(src, name):
    b = open(os.path.join(src, name), "rb").read()
    h = hashlib.sha256(b).hexdigest()
    if h != PINS[name]:
        sys.exit(f"gen.py: {name} sha256 {h} != pinned {PINS[name]}")
    return b


def lines_of(src, name):
    return load(src, name).decode().splitlines()


def find(L, label, start=0):
    for i in range(start, len(L)):
        if label in L[i]:
            return i
    sys.exit(f"gen.py: label not found: {label!r}")


def hex_after(L, i, stop=None):
    """Hex on the label line (after '=' or ':') and following lines, until a line that is not hex."""
    out = ""
    first = L[i]
    tail = re.split(r"[=:]", first, maxsplit=1)[1] if re.search(r"[=:]", first) else ""
    tail = tail.replace("0x", "").split("(")[0].strip().replace(" ", "")
    if tail and HEX.match(tail):
        out += tail
    for ln in L[i + 1:]:
        t = ln.split("(")[0].strip().replace(" ", "").replace(":", "")
        if stop and stop in ln:
            break
        if not t or not HEX.match(t):
            break
        out += t
    return out.lower()


def dump_after(L, i):
    """RFC 8439 style dump lines `000  4c 61 ...  ascii`."""
    out = ""
    for ln in L[i + 1:]:
        m = re.match(r"^\s*(\d{3})  ((?:[0-9a-f]{2} ){0,15}[0-9a-f]{2})", ln)
        if not m:
            if ln.strip() == "" or "[Page" in ln or ln.startswith("RFC "):
                continue
            break
        out += m.group(2).replace(" ", "")
    return out


def write(name, header, rows):
    with open(os.path.join(OUT, name), "w") as f:
        f.write(header.rstrip() + "\n")
        for kind, fields in rows:
            f.write(kind + " " + " ".join(f"{k}={v.lower()}" for k, v in fields) + "\n")
    print(f"{name}: {len(rows)} vectors")


def rfc7748(src):
    L = lines_of(src, "rfc7748.txt")
    rows, i = [], find(L, "5.2.  Test Vectors")
    for _ in range(2):
        i = find(L, "Input scalar:", i + 1)
        s = hex_after(L, i)
        u = hex_after(L, find(L, "Input u-coordinate:", i))
        o = hex_after(L, find(L, "Output u-coordinate:", i))
        rows.append(("x25519", [("scalar", s), ("u", u), ("out", o)]))
    i = find(L, "After one iteration:")
    rows.append(("x25519iter", [("n", "%08x" % 1), ("out", hex_after(L, i))]))
    rows.append(("x25519iter", [("n", "%08x" % 1000), ("out", hex_after(L, find(L, "After 1,000 iterations:", i)))]))
    i = find(L, "Alice's private key, a:")
    rows.append(("x25519dh", [("a", hex_after(L, i)), ("apub", hex_after(L, i + 2)), ("b", hex_after(L, i + 4)),
                              ("bpub", hex_after(L, i + 6)), ("k", hex_after(L, i + 8))]))
    write("rfc7748.txt", "# RFC 7748 sec 5.2 (X25519 vectors + 1 and 1000 iterations) and sec 6.1 (DH)", rows)


def rfc8439(src):
    L = lines_of(src, "rfc8439.txt")
    i = find(L, "2.8.2.  Example and Test Vector for AEAD_CHACHA20_POLY1305")
    pt = dump_after(L, find(L, "Plaintext:", i))
    aad = dump_after(L, find(L, "AAD:", i))
    key = dump_after(L, find(L, "Key:", i))
    iv = dump_after(L, find(L, "IV:", i))
    fixed = dump_after(L, find(L, "32-bit fixed-common part:", i))
    ct = dump_after(L, find(L, "Ciphertext:", i))
    tag = hex_after(L, find(L, "Tag:", find(L, "AEAD Construction for Poly1305:", i)))
    rows = [("aead", [("key", key), ("nonce", fixed + iv), ("aad", aad), ("pt", pt), ("ct", ct), ("tag", tag)])]
    i = find(L, "A.5.  ChaCha20-Poly1305 AEAD Decryption", find(L, "Appendix A."))
    i = find(L, "A.5.  ChaCha20-Poly1305 AEAD Decryption", i + 1)
    key = dump_after(L, find(L, "The ChaCha20 Key", i))
    ct = dump_after(L, find(L, "Ciphertext:", i))
    nonce = dump_after(L, find(L, "The nonce:", i))
    aad = dump_after(L, find(L, "The AAD:", i))
    tag = dump_after(L, find(L, "Received Tag:", i))
    pt = dump_after(L, find(L, "Plaintext::", i))
    rows.append(("aead", [("key", key), ("nonce", nonce), ("aad", aad), ("pt", pt), ("ct", ct), ("tag", tag)]))
    write("rfc8439.txt", "# RFC 8439 sec 2.8.2 (AEAD example) and appendix A.5 (decryption)", rows)


def rfc5869(src):
    L = lines_of(src, "rfc5869.txt")
    rows = []
    for n in (1, 2, 3):
        i = find(L, f"A.{n}.  Test Case {n}", find(L, "Appendix A."))
        f = {}
        for k in ("IKM", "salt", "info", "PRK", "OKM"):
            j = find(L, f"   {k} ", i)
            f[k] = hex_after(L, j)
        Lval = int(re.search(r"L\s+=\s+(\d+)", "\n".join(L[i:i + 30])).group(1))
        rows.append(("hkdf256", [("ikm", f["IKM"]), ("salt", f["salt"]), ("info", f["info"]), ("len", "%04x" % Lval),
                                 ("prk", f["PRK"]), ("okm", f["OKM"])]))
    write("rfc5869.txt", "# RFC 5869 appendix A.1-A.3 (HKDF-SHA-256)", rows)


def rfc4231(src):
    L = lines_of(src, "rfc4231.txt")
    rows = []
    for n, sec in ((1, "4.2"), (2, "4.3"), (3, "4.4"), (4, "4.5"), (6, "4.7"), (7, "4.8")):
        i = next(j for j, ln in enumerate(L) if ln.startswith(f"{sec}.  Test Case {n}"))
        # Test Case 3 prints "Key" without "=" (RFC 4231 typo); normalise the label line first.
        j = find(L, "   Key ", i)
        L2 = L[:j] + [re.sub(r"^   Key\s+=?", "   Key =", L[j])] + L[j + 1:]
        key = hex_after(L2, j)
        data = hex_after(L, find(L, "Data =", i))
        s256 = hex_after(L, find(L, "HMAC-SHA-256 =", i))
        s384 = hex_after(L, find(L, "HMAC-SHA-384 =", i))
        rows.append(("hmac", [("key", key), ("data", data), ("sha256", s256), ("sha384", s384)]))
    write("rfc4231.txt", "# RFC 4231 test cases 1,2,3,4,6,7 (HMAC-SHA-256/384; case 5 is truncated output)", rows)


def rfc8032(src):
    L = lines_of(src, "rfc8032.txt")
    rows, i = [], find(L, "7.1.  Test Vectors for Ed25519")
    for n in (1, 2, 3):
        i = find(L, f"-----TEST {n}", i)
        sk = hex_after(L, find(L, "SECRET KEY:", i))
        pk = hex_after(L, find(L, "PUBLIC KEY:", i))
        msg = hex_after(L, find(L, "MESSAGE (length", i))
        sig = hex_after(L, find(L, "SIGNATURE:", i))
        rows.append(("ed25519", [("sk", sk), ("pk", pk), ("msg", msg), ("sig", sig)]))
    write("rfc8032.txt", "# RFC 8032 sec 7.1 TEST 1-3 (Ed25519)", rows)


def rfc5903(src):
    L = lines_of(src, "rfc5903.txt")
    i = find(L, "8.1.  256-Bit Random ECP Group")
    f = {k: hex_after(L, find(L, k + ":", i)) for k in ("i", "gix", "giy", "r", "grx", "gry", "girx", "giry")}
    rows = [("p256dh", [(k, f[k]) for k in ("i", "gix", "giy", "r", "grx", "gry", "girx", "giry")])]
    write("rfc5903.txt", "# RFC 5903 sec 8.1 (P-256 ECDH)", rows)


def gcm(src):
    z = zipfile.ZipFile(io.BytesIO(load(src, "gcmtestvectors.zip")))
    rows = []
    for bits in (128, 256):
        for fname, kind in ((f"gcmEncryptExtIV{bits}.rsp", "gcm-enc"), (f"gcmDecrypt{bits}.rsp", "gcm-dec")):
            text = z.read(fname).decode()
            hdr, rec, take = {}, {}, {}
            for ln in text.splitlines() + [""]:
                ln = ln.strip()
                m = re.match(r"^\[(\w+) = (\d+)\]$", ln)
                if m:
                    hdr[m.group(1)] = int(m.group(2))
                    continue
                if ln == "":
                    if rec and hdr.get("IVlen") == 96 and hdr.get("Taglen") == 128 \
                            and hdr.get("PTlen") in (0, 128, 408) and hdr.get("AADlen") in (0, 128, 720):
                        key = (hdr["PTlen"], hdr["AADlen"])
                        nfail = sum(1 for r in take.get(key, []) if r.get("FAIL"))
                        nok = len(take.get(key, [])) - nfail
                        if (rec.get("FAIL") and nfail < 2) or (not rec.get("FAIL") and nok < 2):
                            take.setdefault(key, []).append(rec)
                    rec = {}
                    continue
                if ln == "FAIL":
                    rec["FAIL"] = True
                elif " = " in ln or ln.endswith(" ="):
                    k, _, v = ln.partition("=")
                    rec[k.strip()] = v.strip()
            for key in sorted(take):
                for r in take[key]:
                    f = [("key", r["Key"]), ("iv", r["IV"]), ("aad", r["AAD"]), ("pt", r.get("PT", "")),
                         ("ct", r["CT"]), ("tag", r["Tag"])]
                    if kind == "gcm-dec":
                        f.append(("fail", "01" if r.get("FAIL") else "00"))
                    rows.append((kind, f))
    write("nist-gcm.txt", "# NIST CAVP gcmtestvectors.zip: gcmEncryptExtIV{128,256}.rsp and gcmDecrypt{128,256}.rsp,\n"
          "# IVlen 96, Taglen 128, PTlen in {0,128,408}, AADlen in {0,128,720}; first 2 pass (+ first 2 FAIL) per cell", rows)


def mlkem(src):
    kg = json.loads(load(src, "mlkem-kg.json"))
    ed = json.loads(load(src, "mlkem-ed.json"))
    rows = []
    for g in kg["testGroups"]:
        if g["parameterSet"] == "ML-KEM-768":
            for t in g["tests"][:10]:
                rows.append(("keygen", [("tc", "%04x" % t["tcId"]), ("d", t["d"]), ("z", t["z"]), ("ek", t["ek"]),
                                        ("dk", t["dk"])]))
    for g in ed["testGroups"]:
        if g["parameterSet"] != "ML-KEM-768":
            continue
        fn = g["function"]
        for t in g["tests"][:10]:
            tc = ("tc", "%04x" % t["tcId"])
            if fn == "encapsulation":
                rows.append(("encap", [tc, ("ek", t["ek"]), ("m", t["m"]), ("c", t["c"]), ("k", t["k"])]))
            elif fn == "decapsulation":
                rows.append(("decap", [tc, ("dk", t["dk"]), ("c", t["c"]), ("k", t["k"])]))
            elif fn == "encapsulationKeyCheck":
                rows.append(("ekcheck", [tc, ("ek", t["ek"]), ("pass", "01" if t["testPassed"] else "00")]))
    write("acvp-mlkem768.txt", "# NIST ACVP-Server ML-KEM-768 (FIPS 203): keyGen tg2, encapDecap tg2 (encapsulation),\n"
          "# tg5 (decapsulation, incl. implicit rejection), tg10 (encapsulationKeyCheck); first 10 of each", rows)


if __name__ == "__main__":
    s = sys.argv[1]
    rfc7748(s); rfc8439(s); rfc5869(s); rfc4231(s); rfc8032(s); rfc5903(s); gcm(s); mlkem(s)
