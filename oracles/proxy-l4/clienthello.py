"""TLS 1.3 ClientHello builder and reference peek parser (oracle proxy-l4; stdlib only). Shared with oracles/cred-select.

Import from another oracle (scripts run with `python3 -I`, so the script dir is not on sys.path):

    sys.path.insert(0, os.path.join(REPO, "oracles", "proxy-l4"))
    import clienthello as ch
    hello = ch.build(sni="a.example", sigalgs=[0x0403], trust_anchors=[bytes.fromhex("81fd5901")])
    rec = ch.record(hello)                  # one TLS record (bytes)
    peek = ch.peek(rec)                     # dict: sni, alpn, versions, sigalgs, groups, trust_anchors, consumed

trust_anchors (draft-ietf-tls-trust-anchor-ids-07 section 5.1): extension_data in ClientHello is
`TrustAnchorID RequestedTrustAnchorList<0..2^16-1>` with `opaque TrustAnchorID<1..32>`. The draft's codepoint is TBD
and IANA has not assigned one (registry checked 2026-11-06); the deployed experimental codepoint is 0xCA34
(BoringSSL include/openssl/tls1.h `TLSEXT_TYPE_trust_anchors 0xca34`, the one Chrome's MTC experiment uses). It is a
parameter here (`TRUST_ANCHORS_EXT`, `ta_codepoint=`) so the final IANA value is a one-line change.

The peek rules are the AEGIS L4/selector ClientHello peek contract (README.md "ClientHello peek rules"): exactly one
handshake record of at most 16384 bytes holding exactly one complete ClientHello; anything else is refused.
"""

import random as _random

TRUST_ANCHORS_EXT = 0xCA34
EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_SIGNATURE_ALGORITHMS = 13
EXT_ALPN = 16
EXT_PADDING = 21
EXT_SUPPORTED_VERSIONS = 43
EXT_PSK_KEX_MODES = 45
EXT_KEY_SHARE = 51
MAX_RECORD = 16384

DEFAULT_SUITES = [0x1301, 0x1302, 0x1303]
DEFAULT_GROUPS = [0x001D, 0x0017]
DEFAULT_SIGALGS = [0x0403, 0x0804, 0x0805, 0x0806, 0x0503, 0x0603, 0x0401, 0x0501, 0x0601]
SHARE_LEN = {0x001D: 32, 0x0017: 65, 0x0018: 97, 0x11EC: 1216, 0x11EB: 1249, 0x0200: 800, 0x0201: 1184}

MUTANTS = ("ch-ta-codepoint",)


class PeekError(Exception):
    def __init__(self, cls, msg=""):
        super().__init__(f"{cls}: {msg}" if msg else cls)
        self.cls = cls


class PeekIncomplete(Exception):
    pass


# ------------------------------------------------------------------------------------------------ builder

def u8(n):
    return n.to_bytes(1, "big")


def u16(n):
    return n.to_bytes(2, "big")


def u24(n):
    return n.to_bytes(3, "big")


def vec8(b):
    return u8(len(b)) + b


def vec16(b):
    return u16(len(b)) + b


def ext(t, data):
    return u16(t) + vec16(data)


def sni_ext(names):
    """names: str or list of str / (name_type, bytes) for hostile variants."""
    if isinstance(names, (str, bytes)):
        names = [names]
    lst = b""
    for n in names:
        if isinstance(n, tuple):
            nt, nb = n
        else:
            nt, nb = 0, n.encode() if isinstance(n, str) else n
        lst += u8(nt) + vec16(nb)
    return vec16(lst)


def alpn_ext(protos):
    return vec16(b"".join(vec8(p.encode() if isinstance(p, str) else p) for p in protos))


def trust_anchors_ext(ids):
    return vec16(b"".join(vec8(i) for i in ids))


def key_share_ext(shares):
    return vec16(b"".join(u16(g) + vec16(k) for g, k in shares))


def build(sni=None, alpn=None, versions=(0x0304,), sigalgs=DEFAULT_SIGALGS, groups=DEFAULT_GROUPS, key_shares=None,
          trust_anchors=None, ta_codepoint=TRUST_ANCHORS_EXT, extra=(), order=None, suites=DEFAULT_SUITES,
          session_id=None, legacy_version=0x0303, compression=b"\x00", seed=0, padding_to=None, raw_exts=None):
    """Return a ClientHello handshake message (type 1, 3-byte length, body).

    key_shares: list of (group, bytes); default one random X25519 share (a fresh-looking public value, not a real
    key: a server will answer it, which is all an e2e check needs). trust_anchors: list of bytes IDs, [] sends an
    empty RequestedTrustAnchorList, None omits the extension. extra: list of (type, data) appended. order: list of
    extension types giving the order (others keep theirs). padding_to: add a padding extension so the handshake
    message is exactly that many bytes. raw_exts: exact extensions-block contents (overrides everything)."""
    rnd = _random.Random(seed)
    rb = lambda n: bytes(rnd.getrandbits(8) for _ in range(n))  # noqa: E731
    if key_shares is None:
        key_shares = [(groups[0], rb(SHARE_LEN.get(groups[0], 32)))] if groups else []
    exts = []
    if sni is not None:
        exts.append((EXT_SERVER_NAME, sni_ext(sni)))
    if groups is not None:
        exts.append((EXT_SUPPORTED_GROUPS, vec16(b"".join(u16(g) for g in groups))))
    if sigalgs is not None:
        exts.append((EXT_SIGNATURE_ALGORITHMS, vec16(b"".join(u16(s) for s in sigalgs))))
    if alpn is not None:
        exts.append((EXT_ALPN, alpn_ext(alpn)))
    if versions is not None:
        exts.append((EXT_SUPPORTED_VERSIONS, vec8(b"".join(u16(v) for v in versions))))
    exts.append((EXT_PSK_KEX_MODES, vec8(b"\x01")))
    exts.append((EXT_KEY_SHARE, key_share_ext(key_shares)))
    if trust_anchors is not None:
        exts.append((ta_codepoint, trust_anchors_ext(trust_anchors)))
    exts.extend(extra)
    if order:
        pos = {t: i for i, t in enumerate(order)}
        exts.sort(key=lambda e: pos.get(e[0], len(order)))
    sid = rb(32) if session_id is None else session_id
    head = u16(legacy_version) + rb(32) + vec8(sid) + vec16(b"".join(u16(s) for s in suites)) + vec8(compression)
    if raw_exts is not None:
        block = raw_exts
    else:
        block = b"".join(ext(t, d) for t, d in exts)
        if padding_to is not None:
            cur = 4 + len(head) + 2 + len(block) + 4
            pad = padding_to - cur
            if pad < 0:
                raise ValueError(f"padding_to {padding_to} smaller than the hello ({cur})")
            block += ext(EXT_PADDING, b"\x00" * pad)
    body = head + vec16(block)
    return b"\x01" + u24(len(body)) + body


def record(hs, version=0x0301, ctype=0x16, length=None):
    n = len(hs) if length is None else length
    return u8(ctype) + u16(version) + u16(n) + hs


def records(hs, split, version=0x0301):
    """Fragment a handshake message across records at the given byte offsets."""
    out, prev = b"", 0
    for s in list(split) + [len(hs)]:
        out += record(hs[prev:s], version)
        prev = s
    return out


# ------------------------------------------------------------------------------------------------ reference peek

def _valid_host(b):
    if not b or len(b) > 253 or b.endswith(b".") or b.startswith(b"."):
        return False
    for label in b.split(b"."):
        if not label or len(label) > 63 or label.startswith(b"-") or label.endswith(b"-"):
            return False
        for c in label:
            if not (48 <= c <= 57 or 65 <= c <= 90 or 97 <= c <= 122 or c == 45):
                return False
    return True


class _R:
    def __init__(self, b):
        self.b, self.o = b, 0

    def take(self, n, what):
        if self.o + n > len(self.b):
            raise PeekError("malformed", f"{what} overruns")
        v = self.b[self.o:self.o + n]
        self.o += n
        return v

    def int(self, n, what):
        return int.from_bytes(self.take(n, what), "big")

    def vec(self, lb, what):
        return self.take(self.int(lb, what + " length"), what)

    def done(self):
        return self.o == len(self.b)


def peek(buf, mutant=None, allow_multi_record=False):
    """Parse exactly one TLS record holding one complete ClientHello. Returns a dict; raises PeekIncomplete if the
    record is not all there yet, PeekError(cls) otherwise. allow_multi_record is a mutant hook (L4-1)."""
    buf = bytes(buf)
    if len(buf) < 5:
        if buf and buf[0] != 0x16:
            raise PeekError("record-type", f"content type {buf[0]:#04x}")
        raise PeekIncomplete()
    if buf[0] != 0x16:
        raise PeekError("record-type", f"content type {buf[0]:#04x}")
    rv = int.from_bytes(buf[1:3], "big")
    if rv not in (0x0301, 0x0302, 0x0303):
        raise PeekError("record-version", f"{rv:#06x}")
    n = int.from_bytes(buf[3:5], "big")
    if n == 0 or n > MAX_RECORD:
        raise PeekError("record-length", f"{n}")
    if len(buf) < 5 + n:
        raise PeekIncomplete()
    payload = buf[5:5 + n]
    consumed = 5 + n
    if len(payload) < 4:
        raise PeekError("fragmented", "handshake header split across records")
    if payload[0] != 1:
        raise PeekError("not-client-hello", f"handshake type {payload[0]}")
    hl = int.from_bytes(payload[1:4], "big")
    if hl > n - 4:
        if not allow_multi_record:
            raise PeekError("fragmented", f"ClientHello of {hl} bytes does not fit one record of {n}")
        body = payload[4:]
        off = consumed
        while len(body) < hl:
            if len(buf) < off + 5:
                raise PeekIncomplete()
            m = int.from_bytes(buf[off + 3:off + 5], "big")
            if len(buf) < off + 5 + m:
                raise PeekIncomplete()
            body += buf[off + 5:off + 5 + m]
            off += 5 + m
        consumed = off
        body = body[:hl]
    else:
        if hl < n - 4:
            raise PeekError("trailing", f"{n - 4 - hl} bytes after the ClientHello in its record")
        body = payload[4:]
    r = _R(body)
    r.take(2, "legacy_version")
    r.take(32, "random")
    sid = r.vec(1, "session_id")
    if len(sid) > 32:
        raise PeekError("malformed", "session_id longer than 32")
    cs = r.vec(2, "cipher_suites")
    if len(cs) < 2 or len(cs) % 2:
        raise PeekError("malformed", "cipher_suites length")
    comp = r.vec(1, "compression_methods")
    if len(comp) < 1:
        raise PeekError("malformed", "compression_methods empty")
    out = {"sni": None, "alpn": [], "versions": [], "sigalgs": [], "groups": [], "trust_anchors": None,
           "consumed": consumed}
    if r.done():
        return out
    block = r.vec(2, "extensions")
    if not r.done():
        raise PeekError("malformed", "bytes after the extensions block")
    er = _R(block)
    seen = set()
    ta_code = TRUST_ANCHORS_EXT + 1 if mutant == "ch-ta-codepoint" else TRUST_ANCHORS_EXT
    while not er.done():
        t = er.int(2, "extension type")
        d = er.vec(2, f"extension {t:#06x}")
        if t in seen:
            raise PeekError("duplicate-extension", f"{t:#06x}")
        seen.add(t)
        x = _R(d)
        if t == EXT_SERVER_NAME:
            lst = _R(x.vec(2, "server_name_list"))
            if not x.done() or lst.done():
                raise PeekError("malformed", "server_name_list")
            hosts = 0
            while not lst.done():
                nt = lst.int(1, "name_type")
                nm = lst.vec(2, "HostName")
                if nt != 0:
                    raise PeekError("malformed", f"name_type {nt}")
                hosts += 1
                if hosts > 1:
                    raise PeekError("malformed", "more than one host_name")
                if not _valid_host(nm):
                    raise PeekError("sni-invalid", repr(nm[:64]))
                out["sni"] = nm.decode("ascii")
        elif t == EXT_ALPN:
            lst = _R(x.vec(2, "protocol_name_list"))
            if not x.done() or lst.done():
                raise PeekError("malformed", "protocol_name_list")
            while not lst.done():
                p = lst.vec(1, "ProtocolName")
                if not p:
                    raise PeekError("malformed", "empty ProtocolName")
                out["alpn"].append(p.hex())
        elif t == EXT_SUPPORTED_VERSIONS:
            v = x.vec(1, "versions")
            if not x.done() or len(v) < 2 or len(v) % 2:
                raise PeekError("malformed", "supported_versions")
            out["versions"] = [int.from_bytes(v[i:i + 2], "big") for i in range(0, len(v), 2)]
        elif t == EXT_SIGNATURE_ALGORITHMS:
            v = x.vec(2, "supported_signature_algorithms")
            if not x.done() or len(v) < 2 or len(v) % 2:
                raise PeekError("malformed", "signature_algorithms")
            out["sigalgs"] = [int.from_bytes(v[i:i + 2], "big") for i in range(0, len(v), 2)]
        elif t == EXT_SUPPORTED_GROUPS:
            v = x.vec(2, "named_group_list")
            if not x.done() or len(v) < 2 or len(v) % 2:
                raise PeekError("malformed", "supported_groups")
            out["groups"] = [int.from_bytes(v[i:i + 2], "big") for i in range(0, len(v), 2)]
        elif t == ta_code:
            lst = _R(x.vec(2, "RequestedTrustAnchorList"))
            if not x.done():
                raise PeekError("malformed", "trust_anchors trailing bytes")
            ids = []
            while not lst.done():
                i = lst.vec(1, "TrustAnchorID")
                if not 1 <= len(i) <= 32:
                    raise PeekError("malformed", f"TrustAnchorID length {len(i)}")
                ids.append(i.hex())
            out["trust_anchors"] = ids
    return out
