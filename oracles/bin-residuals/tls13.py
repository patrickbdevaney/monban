"""Minimal TLS 1.3 handshake probe, stdlib only (oracle bin-residuals, unit P8-oracle-001).

Why it exists: SEL-1..3 end to end means "which credential did the server put in its Certificate message for this
ClientHello". Python's ssl module cannot send a trust_anchors extension (draft-ietf-tls-trust-anchor-ids-07,
codepoint 0xCA34) and cannot choose signature_algorithms, and the Certificate message is encrypted in TLS 1.3. So the
oracle builds the ClientHello itself (oracles/proxy-l4/clienthello.py), runs X25519 + TLS_CHACHA20_POLY1305_SHA256,
derives the server handshake traffic key (RFC 8446 section 7.1) and decrypts the server's first flight up to and
including Certificate. It never sends Finished and never verifies CertificateVerify: it judges selection only.

Also a matching minimal server side (`ServerFlight`) for the oracle's reference subject, which sends ServerHello,
EncryptedExtensions and Certificate with whatever certificate_list the reference selector chose.

Every primitive is checked against its RFC test vector at import (`_selftest`): RFC 7748 section 5.2 (X25519),
RFC 8439 sections 2.3.2 / 2.5.2 / 2.8.2 (ChaCha20 block, Poly1305, AEAD), RFC 5869 A.1 (HKDF-SHA256).
"""

import hashlib
import hmac
import os
import socket
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "oracles", "proxy-l4"))
import clienthello as ch  # noqa: E402

CHACHA = 0x1303
X25519 = 0x001D
ALERT_NAMES = {40: "handshake_failure", 49: "access_denied", 70: "protocol_version", 109: "missing_extension",
               47: "illegal_parameter", 80: "internal_error", 50: "decode_error"}

# ------------------------------------------------------------------------------------------------ X25519 (RFC 7748)
_P = 2 ** 255 - 19
_A24 = 121665


def _decode_scalar(k):
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def x25519(k, u):
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    k = _decode_scalar(k)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a, b = (x2 + z2) % _P, (x2 - z2) % _P
        aa, bb = a * a % _P, b * b % _P
        e = (aa - bb) % _P
        c, d = (x3 + z3) % _P, (x3 - z3) % _P
        da, cb = d * a % _P, c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def x25519_keypair():
    sk = os.urandom(32)
    return sk, x25519(sk, (9).to_bytes(32, "little"))


# ------------------------------------------------------------------------------------------------ ChaCha20-Poly1305
def _rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 7)


def chacha20_block(key, counter, nonce):
    st = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574] + list(struct.unpack("<8I", key)) + [counter] + \
        list(struct.unpack("<3I", nonce))
    w = st[:]
    for _ in range(10):
        _qr(w, 0, 4, 8, 12)
        _qr(w, 1, 5, 9, 13)
        _qr(w, 2, 6, 10, 14)
        _qr(w, 3, 7, 11, 15)
        _qr(w, 0, 5, 10, 15)
        _qr(w, 1, 6, 11, 12)
        _qr(w, 2, 7, 8, 13)
        _qr(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(a + b) & 0xFFFFFFFF for a, b in zip(w, st)])


def chacha20(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha20_block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], ks))
    return bytes(out)


def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p, acc = (1 << 130) - 5, 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i:i + 16] + b"\x01", "little")
        acc = (acc + n) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(b):
    return b"\x00" * (-len(b) % 16)


def _mac_data(aad, ct):
    return aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))


def aead_seal(key, nonce, pt, aad):
    otk = chacha20_block(key, 0, nonce)[:32]
    ct = chacha20(key, 1, nonce, pt)
    return ct + poly1305(otk, _mac_data(aad, ct))


def aead_open(key, nonce, data, aad):
    if len(data) < 16:
        raise ValueError("record shorter than the tag")
    ct, tag = data[:-16], data[-16:]
    otk = chacha20_block(key, 0, nonce)[:32]
    if not hmac.compare_digest(poly1305(otk, _mac_data(aad, ct)), tag):
        raise ValueError("bad record tag (wrong traffic key: transcript or shared secret differs)")
    return chacha20(key, 1, nonce, ct)


# ------------------------------------------------------------------------------------------------ HKDF / key schedule
def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def expand_label(secret, label, ctx, n):
    full = b"tls13 " + label
    return hkdf_expand(secret, struct.pack("!H", n) + bytes([len(full)]) + full + bytes([len(ctx)]) + ctx, n)


def handshake_keys(shared, transcript_hash):
    """Server and client handshake traffic (key, iv) for TLS_CHACHA20_POLY1305_SHA256 (RFC 8446 section 7.1)."""
    zero = b"\x00" * 32
    early = hkdf_extract(zero, zero)
    derived = expand_label(early, b"derived", hashlib.sha256(b"").digest(), 32)
    hs = hkdf_extract(derived, shared)
    out = {}
    for side, label in (("s", b"s hs traffic"), ("c", b"c hs traffic")):
        sec = expand_label(hs, label, transcript_hash, 32)
        out[side] = (expand_label(sec, b"key", b"", 32), expand_label(sec, b"iv", b"", 12))
    return out


def _nonce(iv, seq):
    return bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))


# ------------------------------------------------------------------------------------------------ record I/O
class Records:
    def __init__(self, sock, deadline):
        self.s, self.deadline, self.buf, self.eof = sock, deadline, b"", False

    def _fill(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("server flight timed out")
        self.s.settimeout(left)
        try:
            d = self.s.recv(65536)
        except (ConnectionResetError, BrokenPipeError):
            d = b""
        if not d:
            self.eof = True
            raise EOFError("connection closed")
        self.buf += d

    def next(self):
        while len(self.buf) < 5:
            self._fill()
        n = struct.unpack("!H", self.buf[3:5])[0]
        while len(self.buf) < 5 + n:
            self._fill()
        rec, self.buf = self.buf[:5 + n], self.buf[5 + n:]
        return rec[0], rec[:5], rec[5:]


def _hs_messages(buf):
    """Split complete handshake messages off buf: returns ([(type, full_msg)], rest)."""
    out = []
    while len(buf) >= 4:
        n = int.from_bytes(buf[1:4], "big")
        if len(buf) < 4 + n:
            break
        out.append((buf[0], buf[:4 + n]))
        buf = buf[4 + n:]
    return out, buf


def parse_server_hello(msg):
    b = msg[4:]
    o = 2 + 32
    sid_len = b[o]
    o += 1 + sid_len
    suite = struct.unpack("!H", b[o:o + 2])[0]
    o += 3
    ext_len = struct.unpack("!H", b[o:o + 2])[0]
    o += 2
    end = o + ext_len
    exts = {}
    while o < end:
        t, n = struct.unpack("!HH", b[o:o + 4])
        exts[t] = b[o + 4:o + 4 + n]
        o += 4 + n
    random = b[2:34]
    return suite, exts, random


HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")


def parse_certificate(msg):
    b = msg[4:]
    ctx_len = b[0]
    o = 1 + ctx_len
    total = int.from_bytes(b[o:o + 3], "big")
    o += 3
    end, certs = o + total, []
    while o < end:
        n = int.from_bytes(b[o:o + 3], "big")
        certs.append(bytes(b[o + 3:o + 3 + n]))
        o += 3 + n
        en = struct.unpack("!H", b[o:o + 2])[0]
        o += 2 + en
    return certs


class Outcome:
    """kind: "certificate" (certs = the certificate_list entries), "alert" (alert = description), "hrr", "closed",
    "error" (detail)."""

    def __init__(self, kind, certs=None, alert=None, detail=""):
        self.kind, self.certs, self.alert, self.detail = kind, certs or [], alert, detail

    def __repr__(self):
        if self.kind == "certificate":
            return f"<certificate {len(self.certs)} entries, leaf {len(self.certs[0]) if self.certs else 0} B>"
        if self.kind == "alert":
            return f"<alert {self.alert} {ALERT_NAMES.get(self.alert, '')}>"
        return f"<{self.kind} {self.detail}>"


def probe(host, port, sni, sigalgs, trust_anchors=None, ta_codepoint=ch.TRUST_ANCHORS_EXT, alpn=("http/1.1",),
          timeout=10.0):
    """One handshake up to the server's Certificate message. Returns an Outcome."""
    sk, pk = x25519_keypair()
    hello = ch.build(sni=sni, alpn=list(alpn) if alpn else None, sigalgs=list(sigalgs), groups=[X25519],
                     key_shares=[(X25519, pk)], trust_anchors=trust_anchors, ta_codepoint=ta_codepoint,
                     suites=[CHACHA], session_id=os.urandom(32), seed=int.from_bytes(os.urandom(4), "big"))
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return Outcome("error", detail=f"connect: {e}")
    try:
        s.sendall(ch.record(hello))
        return _client_flight(Records(s, time.monotonic() + timeout), hello, sk)
    except (EOFError, ConnectionError) as e:
        return Outcome("closed", detail=str(e))
    except TimeoutError as e:
        return Outcome("error", detail=str(e))
    except (ValueError, IndexError, struct.error) as e:
        return Outcome("error", detail=f"malformed server flight: {e}")
    finally:
        s.close()


def _client_flight(recs, hello, sk):
    ctype, _, body = recs.next()
    if ctype == 21:
        return Outcome("alert", alert=body[1] if len(body) >= 2 else None)
    if ctype != 22:
        return Outcome("error", detail=f"first record type {ctype}")
    msgs, rest = _hs_messages(body)
    while not msgs:
        ctype, _, more = recs.next()
        if ctype != 22:
            return Outcome("error", detail="ServerHello split across non-handshake records")
        msgs, rest = _hs_messages(rest + more)
    t, sh = msgs[0]
    if t != 2:
        return Outcome("error", detail=f"first handshake message type {t}")
    suite, exts, rnd = parse_server_hello(sh)
    if rnd == HRR_RANDOM:
        return Outcome("hrr")
    if suite != CHACHA or 51 not in exts:
        return Outcome("error", detail=f"suite {suite:#06x}, key_share present {51 in exts}")
    ks = exts[51]
    group, n = struct.unpack("!HH", ks[:4])
    if group != X25519 or n != 32:
        return Outcome("error", detail=f"server share group {group:#06x}")
    shared = x25519(sk, ks[4:36])
    keys = handshake_keys(shared, hashlib.sha256(hello + sh).digest())
    key, iv = keys["s"]
    seq, hs = 0, b""
    while True:
        ctype, header, body = recs.next()
        if ctype == 20:  # middlebox-compat ChangeCipherSpec
            continue
        if ctype == 21:
            return Outcome("alert", alert=body[1] if len(body) >= 2 else None, detail="plaintext alert after SH")
        if ctype != 23:
            return Outcome("error", detail=f"record type {ctype} after ServerHello")
        inner = aead_open(key, _nonce(iv, seq), body, header).rstrip(b"\x00")
        seq += 1
        itype, data = inner[-1], inner[:-1]
        if itype == 21:
            return Outcome("alert", alert=data[1] if len(data) >= 2 else None, detail="encrypted alert")
        if itype != 22:
            return Outcome("error", detail=f"inner type {itype} before Certificate")
        msgs, hs = _hs_messages(hs + data)
        for mt, m in msgs:
            if mt == 11:
                return Outcome("certificate", certs=parse_certificate(m))
            if mt == 13:
                return Outcome("error", detail="CertificateRequest (client auth) is not expected")


# ------------------------------------------------------------------------------------------------ server side
def _hs(t, body):
    return bytes([t]) + len(body).to_bytes(3, "big") + body


def server_flight(hello_msg, certs, sid):
    """Given the client's ClientHello handshake message (X25519 share, 0x1303 offered) and a certificate_list, return
    the bytes of ServerHello + CCS + encrypted EncryptedExtensions and Certificate, or None if the hello does not
    offer what this minimal server speaks."""
    body = hello_msg[4:]
    o = 2 + 32
    o += 1 + body[o]
    sn = struct.unpack("!H", body[o:o + 2])[0]
    suites = [struct.unpack("!H", body[o + 2 + i:o + 4 + i])[0] for i in range(0, sn, 2)]
    o += 2 + sn
    o += 1 + body[o]
    el = struct.unpack("!H", body[o:o + 2])[0]
    o += 2
    end, share = o + el, None
    while o < end:
        t, n = struct.unpack("!HH", body[o:o + 4])
        d = body[o + 4:o + 4 + n]
        if t == 51:
            q = 2
            while q < len(d):
                g, ln = struct.unpack("!HH", d[q:q + 4])
                if g == X25519 and ln == 32:
                    share = d[q + 4:q + 36]
                q += 4 + ln
        o += 4 + n
    if CHACHA not in suites or share is None:
        return None
    sk, pk = x25519_keypair()
    exts = ch.ext(43, b"\x03\x04") + ch.ext(51, ch.u16(X25519) + ch.vec16(pk))
    sh = _hs(2, b"\x03\x03" + os.urandom(32) + ch.vec8(sid) + ch.u16(CHACHA) + b"\x00" + ch.vec16(exts))
    keys = handshake_keys(x25519(sk, share), hashlib.sha256(hello_msg + sh).digest())
    key, iv = keys["s"]
    ee = _hs(8, ch.vec16(b""))
    lst = b"".join(len(c).to_bytes(3, "big") + c + b"\x00\x00" for c in certs)
    cert = _hs(11, b"\x00" + len(lst).to_bytes(3, "big") + lst)
    out = ch.record(sh, version=0x0303) + b"\x14\x03\x03\x00\x01\x01"
    for seq, m in enumerate((ee, cert)):
        inner = m + b"\x16"
        header = b"\x17\x03\x03" + struct.pack("!H", len(inner) + 16)
        out += header + aead_seal(key, _nonce(iv, seq), inner, header)
    return out


def alert_record(desc):
    return b"\x15\x03\x03\x00\x02\x02" + bytes([desc])


def client_hello_session_id(hello_msg):
    body = hello_msg[4:]
    n = body[34]
    return bytes(body[35:35 + n])


# ------------------------------------------------------------------------------------------------ RFC vectors
def _selftest():
    # RFC 7748 6.1 Diffie-Hellman vector (Alice/Bob)
    a_sk = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    a_pk = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    b_sk = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    b_pk = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    k_ab = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    base = (9).to_bytes(32, "little")
    assert x25519(a_sk, base) == a_pk and x25519(b_sk, base) == b_pk, "X25519 RFC 7748 6.1 public keys"
    assert x25519(a_sk, b_pk) == k_ab == x25519(b_sk, a_pk), "X25519 RFC 7748 6.1 shared secret"
    # RFC 8439 2.3.2 block function
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    blk = chacha20_block(key, 1, nonce)
    assert blk.hex().startswith("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"), "ChaCha20 2.3.2"
    # RFC 8439 2.5.2 Poly1305
    pk_ = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
    assert poly1305(pk_, b"Cryptographic Forum Research Group").hex() == "a8061dc1305136c6c22b8baf0c0127a9", \
        "Poly1305 2.5.2"
    # RFC 8439 2.8.2 AEAD
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
          b"sunscreen would be it.")
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    sealed = aead_seal(key, nonce, pt, aad)
    assert sealed[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691", "AEAD 2.8.2 tag"
    assert sealed[:16].hex() == "d31a8d34648e60db7b86afbc53ef7ec2", "AEAD 2.8.2 ciphertext"
    assert aead_open(key, nonce, sealed, aad) == pt
    # RFC 5869 A.1
    prk = hkdf_extract(bytes.fromhex("000102030405060708090a0b0c"), b"\x0b" * 22)
    assert prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", "HKDF A.1 PRK"
    okm = hkdf_expand(prk, bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865"), "HKDF A.1 OKM"


_selftest()
