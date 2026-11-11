"""PROXY protocol v2: encoder and reference parser (oracle proxy-l4; stdlib only).

Written from haproxy.org/download/3.2/doc/proxy-protocol.txt section 2.2 (sha256 in README.md). The parser is the
reference model for the Monban receiver rules in README.md ("PROXY v2 acceptance rules"), which add the PLAN-7 limits
(v1 refused, declared length <= 536) and fail-closed choices where the spec leaves the receiver free.

parse(buf) -> dict on success, raises Incomplete (need more bytes) or Reject(cls). `mutant` selects a deliberately
wrong variant for the self-test; production callers never pass it.
"""

import ipaddress

SIG = b"\r\n\r\n\x00\r\nQUIT\n"
MAX_LEN = 536
CMD_LOCAL, CMD_PROXY = 0, 1
FAM_UNSPEC, FAM_INET, FAM_INET6, FAM_UNIX = 0, 1, 2, 3
PROTO_UNSPEC, PROTO_STREAM, PROTO_DGRAM = 0, 1, 2
ADDR_LEN = {FAM_INET: 12, FAM_INET6: 36, FAM_UNIX: 216}

PP2_TYPE_ALPN = 0x01
PP2_TYPE_AUTHORITY = 0x02
PP2_TYPE_CRC32C = 0x03
PP2_TYPE_NOOP = 0x04
PP2_TYPE_UNIQUE_ID = 0x05
PP2_TYPE_SSL = 0x20
PP2_SUBTYPE_SSL_VERSION = 0x21
PP2_SUBTYPE_SSL_CN = 0x22
PP2_SUBTYPE_SSL_CIPHER = 0x23
PP2_SUBTYPE_SSL_SIG_ALG = 0x24
PP2_SUBTYPE_SSL_KEY_ALG = 0x25
PP2_TYPE_NETNS = 0x30

# Parser mutants (self-test only).
MUTANTS = ("proxy-v1-accept", "proxy-len-537", "proxy-crc-skip", "proxy-tlv-lenient", "proxy-local-header-peer")


class Reject(Exception):
    def __init__(self, cls, msg=""):
        super().__init__(f"{cls}: {msg}" if msg else cls)
        self.cls = cls


class Incomplete(Exception):
    pass


# ------------------------------------------------------------------------------------------------ CRC32C (RFC 4960 B)

def _crc_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        t.append(c)
    return t


_T = _crc_table()


def crc32c(data):
    c = 0xFFFFFFFF
    for b in data:
        c = _T[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


assert crc32c(b"123456789") == 0xE3069283  # RFC 3720 / iSCSI check value


# ------------------------------------------------------------------------------------------------ encoder

def tlv(t, value):
    """One TLV. value=None on type CRC32C means 'compute the checksum here' (encode() fills it)."""
    return (t, value)


def ssl_value(client=0x01, verify=0, subs=()):
    v = bytes([client]) + verify.to_bytes(4, "big")
    for st, sv in subs:
        v += bytes([st]) + len(sv).to_bytes(2, "big") + sv
    return v


def addr_block(fam, src, dst, sport=0, dport=0):
    if fam == FAM_INET:
        return (ipaddress.IPv4Address(src).packed + ipaddress.IPv4Address(dst).packed +
                sport.to_bytes(2, "big") + dport.to_bytes(2, "big"))
    if fam == FAM_INET6:
        return (ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed +
                sport.to_bytes(2, "big") + dport.to_bytes(2, "big"))
    if fam == FAM_UNIX:
        s, d = src.encode() if isinstance(src, str) else src, dst.encode() if isinstance(dst, str) else dst
        return s.ljust(108, b"\x00")[:108] + d.ljust(108, b"\x00")[:108]
    return b""


def encode(cmd=CMD_PROXY, fam=FAM_INET, proto=PROTO_STREAM, src="192.0.2.1", dst="192.0.2.2", sport=40000,
           dport=443, addr=None, tlvs=(), ver=2, length=None, sig=SIG, crc_bad=False, crc_unzeroed=False):
    """Build a v2 header. addr overrides the address block; length overrides the declared length (the bytes
    present stay len(addr)+len(tlvs)). A CRC32C TLV with value None is filled with the correct checksum
    (crc_bad: flipped; crc_unzeroed: computed without zeroing the field first, a classic sender bug)."""
    if addr is None:
        addr = addr_block(fam, src, dst, sport, dport) if cmd == CMD_PROXY or fam else b""
    body = bytearray(addr)
    crc_at = None
    for t, v in tlvs:
        if t == PP2_TYPE_CRC32C and v is None:
            crc_at = len(body) + 3
            v = b"\x00\x00\x00\x00"
        body += bytes([t]) + len(v).to_bytes(2, "big") + v
    n = len(body) if length is None else length
    hdr = bytearray(sig + bytes([(ver << 4) | cmd, (fam << 4) | proto]) + n.to_bytes(2, "big")) + body
    if crc_at is not None:
        off = 16 + crc_at
        if crc_unzeroed:
            hdr[off:off + 4] = b"\xde\xad\xbe\xef"
        c = crc32c(bytes(hdr))
        if crc_bad:
            c ^= 0x00000100
        hdr[off:off + 4] = c.to_bytes(4, "big")
    return bytes(hdr)


# ------------------------------------------------------------------------------------------------ reference parser

def _valid_utf8(b):
    try:
        b.decode("utf-8", errors="strict")
        return True
    except UnicodeDecodeError:
        return False


def _parse_v1(buf):
    end = buf.find(b"\r\n")
    if end < 0:
        if len(buf) >= 107:
            raise Reject("v1", "no CRLF")
        raise Incomplete()
    parts = buf[:end].split(b" ")
    out = {"consumed": end + 2, "version": 1, "command": "proxy", "family": "unspec", "proto": "unspec",
           "src": None, "dst": None, "src_port": None, "dst_port": None, "tlvs": [], "peer": "transport",
           "stream_accept": True}
    if len(parts) == 6 and parts[1] in (b"TCP4", b"TCP6"):
        out.update(family="inet" if parts[1] == b"TCP4" else "inet6", proto="stream", src=parts[2].decode(),
                   dst=parts[3].decode(), src_port=int(parts[4]), dst_port=int(parts[5]), peer="src")
    return out


def _tlvs(region, start, hdr, mutant, out):
    """Parse the TLV area region = hdr[start:16+len]."""
    off = 0
    crc_seen = False
    while off < len(region):
        if len(region) - off < 3:
            if mutant == "proxy-tlv-lenient":
                return
            raise Reject("tlv-truncated", f"{len(region) - off} trailing byte(s)")
        t = region[off]
        n = int.from_bytes(region[off + 1:off + 3], "big")
        if off + 3 + n > len(region):
            if mutant == "proxy-tlv-lenient":
                return
            raise Reject("tlv-truncated", f"type {t:#x} len {n} exceeds the header")
        v = region[off + 3:off + 3 + n]
        if t == PP2_TYPE_CRC32C:
            if n != 4:
                raise Reject("crc-length", f"len {n}")
            if crc_seen:
                raise Reject("crc-duplicate")
            crc_seen = True
            if mutant != "proxy-crc-skip":
                pos = start + off + 3
                z = bytearray(hdr)
                z[pos:pos + 4] = b"\x00\x00\x00\x00"
                if crc32c(bytes(z)) != int.from_bytes(v, "big"):
                    raise Reject("crc-mismatch")
            out["crc32c"] = True
        elif t == PP2_TYPE_UNIQUE_ID:
            if n > 128:
                raise Reject("unique-id-length", f"len {n}")
        elif t == PP2_TYPE_AUTHORITY:
            if not _valid_utf8(v):
                raise Reject("authority-utf8")
        elif t == PP2_TYPE_SSL:
            if n < 5:
                raise Reject("ssl-short", f"len {n}")
            so = 5
            subs = []
            while so < n:
                if n - so < 3:
                    raise Reject("ssl-subtlv-truncated")
                st = v[so]
                sn = int.from_bytes(v[so + 1:so + 3], "big")
                if so + 3 + sn > n:
                    raise Reject("ssl-subtlv-truncated")
                subs.append([st, v[so + 3:so + 3 + sn].hex()])
                so += 3 + sn
            out["ssl"] = {"client": v[0], "verify": int.from_bytes(v[1:5], "big"), "subs": subs}
        out["tlvs"].append([t, v.hex()])
        off += 3 + n


def parse(buf, mutant=None):
    buf = bytes(buf)
    k = min(len(buf), 12)
    if buf[:k] != SIG[:k]:
        if buf[:5] == b"PROXY" or (len(buf) < 5 and b"PROXY".startswith(buf) and buf):
            if mutant == "proxy-v1-accept":
                return _parse_v1(buf)
            raise Reject("v1", "version 1 header refused")
        raise Reject("sig", "not a PROXY v2 signature")
    if len(buf) < 16:
        raise Incomplete()
    ver, cmd = buf[12] >> 4, buf[12] & 0x0F
    fam, proto = buf[13] >> 4, buf[13] & 0x0F
    n = int.from_bytes(buf[14:16], "big")
    if ver != 2:
        raise Reject("version", f"version nibble {ver}")
    if cmd not in (CMD_LOCAL, CMD_PROXY):
        raise Reject("command", f"command nibble {cmd}")
    if fam > FAM_UNIX or proto > PROTO_DGRAM:
        raise Reject("family", f"family/protocol byte {buf[13]:#04x}")
    if n > (1024 if mutant == "proxy-len-537" else MAX_LEN):
        raise Reject("length", f"declared length {n} > {MAX_LEN}")
    if len(buf) < 16 + n:
        raise Incomplete()
    hdr = buf[:16 + n]
    block = hdr[16:]
    fname = {0: "unspec", 1: "inet", 2: "inet6", 3: "unix"}[fam]
    pname = {0: "unspec", 1: "stream", 2: "dgram"}[proto]
    out = {"consumed": 16 + n, "version": 2, "command": "local" if cmd == CMD_LOCAL else "proxy", "family": fname,
           "proto": pname, "src": None, "dst": None, "src_port": None, "dst_port": None, "tlvs": [],
           "peer": "transport", "stream_accept": True}
    if cmd == CMD_LOCAL:
        # Spec: accept, use the real endpoints, discard the protocol block including the family.
        if mutant == "proxy-local-header-peer" and fam in (FAM_INET, FAM_INET6) and n >= ADDR_LEN[fam]:
            _addrs(out, fam, block)
            out["peer"] = "src"
        return out
    if fam == FAM_UNSPEC or proto == PROTO_UNSPEC:
        # UNSPEC: address information ignored, real endpoints used; the block (incl. any TLVs) is skipped.
        return out
    need = ADDR_LEN[fam]
    if n < need:
        raise Reject("short-address", f"{fname} needs {need} address bytes, header declares {n}")
    _addrs(out, fam, block)
    _tlvs(block[need:], 16 + need, hdr, mutant, out)
    if proto == PROTO_DGRAM:
        out["stream_accept"] = False  # a datagram flow announced on a stream listener: refused by policy
    elif fam in (FAM_INET, FAM_INET6):
        out["peer"] = "src"
    return out


def fmt6(b):
    """RFC 5952 text form (section 5: IPv4-mapped addresses keep the dotted quad), as Rust's Ipv6Addr prints it;
    Python's own str() of a mapped address changed between 3.12 and 3.13."""
    a = ipaddress.IPv6Address(b)
    m = a.ipv4_mapped
    return f"::ffff:{m}" if m is not None else str(a)


def _addrs(out, fam, block):
    if fam == FAM_INET:
        out.update(src=str(ipaddress.IPv4Address(block[0:4])), dst=str(ipaddress.IPv4Address(block[4:8])),
                   src_port=int.from_bytes(block[8:10], "big"), dst_port=int.from_bytes(block[10:12], "big"))
    elif fam == FAM_INET6:
        out.update(src=fmt6(block[0:16]), dst=fmt6(block[16:32]),
                   src_port=int.from_bytes(block[32:34], "big"), dst_port=int.from_bytes(block[34:36], "big"))
    elif fam == FAM_UNIX:
        out.update(src=block[0:108].rstrip(b"\x00").hex(), dst=block[108:216].rstrip(b"\x00").hex())


def looks_like_proxy(buf):
    """True if buf could begin a PROXY header (v2 signature prefix or v1 'PROXY' prefix): used by a receiver on an
    untrusted source to refuse it (PROXY-1). Needs at least one byte."""
    k = min(len(buf), 12)
    if k and buf[:k] == SIG[:k]:
        return True
    k = min(len(buf), 5)
    return bool(k) and buf[:k] == b"PROXY"[:k]
