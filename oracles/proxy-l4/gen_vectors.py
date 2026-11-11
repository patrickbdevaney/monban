"""Generate the proxy-l4 vector sets (deterministic; stdlib only).

    python3 -I gen_vectors.py            write vectors/proxy_v2.json and vectors/client_hello.json
    python3 -I gen_vectors.py --check    regenerate in memory and diff against the committed files (exit 1 on drift)

Expectations are stated by construction (what the generator built), never by running a parser: the reference parsers
in proxyv2.py / clienthello.py are checked against these files, and so is the Rust parser (P7-wire-001).
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import clienthello as ch  # noqa: E402
import proxyv2 as pp  # noqa: E402

PP_SOURCE = "haproxy.org/download/3.2/doc/proxy-protocol.txt sec 2.2 (sha256 66be6188...c98d) + README.md rules"
CH_SOURCE = "RFC 8446 4.1.2, RFC 6066 3, RFC 7301 3.1, draft-ietf-tls-trust-anchor-ids-07 5.1 (codepoint 0xCA34)"

# ------------------------------------------------------------------------------------------------ PROXY v2


class PV:
    def __init__(self):
        self.v = []
        self.n4 = 0
        self.n6 = 0

    def src4(self):
        self.n4 += 1
        return f"203.0.113.{self.n4}"

    def src6(self):
        self.n6 += 1
        return f"2001:db8::{self.n6:x}"

    def add(self, vid, group, data, expect, cls=None, **kw):
        if any(x["id"] == vid for x in self.v):
            raise SystemExit(f"duplicate vector id {vid}")
        d = {"id": vid, "group": group, "hex": data.hex(), "expect": expect}
        if expect == "reject":
            d["class"] = cls
            d["listener"] = "close"
            d["e2e"] = "append-client-hello"
        elif expect == "incomplete":
            d["listener"] = "close"
            d["e2e"] = "half-close"
        else:
            d.update(kw)
            d["listener"] = "accept" if kw["stream_accept"] else "close"
            d["e2e"] = "append-client-hello"
        self.v.append(d)

    def ok(self, vid, group, hdr, cmd, fam, proto, src=None, dst=None, sp=None, dp=None, peer="transport",
           stream_accept=True, tlvs=(), consumed=None, data=None):
        exp = []
        off = 16 + {("proxy", "inet"): 12, ("proxy", "inet6"): 36, ("proxy", "unix"): 216}.get((cmd, fam), 0)
        if cmd == "proxy" and fam not in ("unspec",) and proto != "unspec":
            for t, v in tlvs:
                val = hdr[off + 3:off + 3 + 4] if (t == pp.PP2_TYPE_CRC32C and v is None) else v
                exp.append([t, val.hex()])
                off += 3 + len(val)
        self.add(vid, group, hdr if data is None else data, "ok", command=cmd, family=fam, proto=proto, src=src,
                 dst=dst, src_port=sp, dst_port=dp, peer=peer, stream_accept=stream_accept, tlvs=exp,
                 consumed=len(hdr) if consumed is None else consumed)


def tcp4(p, tlvs=(), **kw):
    s = p.src4()
    return s, pp.encode(src=s, dst="192.0.2.10", sport=50000 + p.n4, dport=443, tlvs=tlvs, **kw)


def tcp6(p, tlvs=(), **kw):
    s = p.src6()
    return s, pp.encode(fam=pp.FAM_INET6, src=s, dst="2001:db8:ffff::1", sport=51000 + p.n6, dport=443,
                        tlvs=tlvs, **kw)


def unix(tlvs=(), **kw):
    return pp.encode(fam=pp.FAM_UNIX, src="/run/lb.sock", dst="/run/monban.sock", tlvs=tlvs, **kw)


def ssl_all():
    return pp.ssl_value(0x07, 0, [(pp.PP2_SUBTYPE_SSL_VERSION, b"TLSv1.3"), (pp.PP2_SUBTYPE_SSL_CN, b"client.example"),
                                  (pp.PP2_SUBTYPE_SSL_CIPHER, b"TLS_AES_128_GCM_SHA256"),
                                  (pp.PP2_SUBTYPE_SSL_SIG_ALG, b"SHA256"), (pp.PP2_SUBTYPE_SSL_KEY_ALG, b"EC256")])


def proxy_vectors():
    p = PV()
    T = pp.tlv
    # ---- spec vectors (section 2.2): every address family, LOCAL, every registered TLV, CRC32C, SSL
    s, h = tcp4(p)
    p.ok("spec-tcp4", "spec", h, "proxy", "inet", "stream", s, "192.0.2.10", 50000 + p.n4, 443, "src")
    s, h = tcp6(p)
    p.ok("spec-tcp6", "spec", h, "proxy", "inet6", "stream", s, "2001:db8:ffff::1", 51000 + p.n6, 443, "src")
    h = unix()
    p.ok("spec-unix-stream", "spec", h, "proxy", "unix", "stream", "2f72756e2f6c622e736f636b",
         "2f72756e2f61656769732e736f636b")
    h = pp.encode(cmd=pp.CMD_LOCAL, fam=0, proto=0, addr=b"")
    p.ok("spec-local-empty", "spec", h, "local", "unspec", "unspec")
    h = pp.encode(cmd=pp.CMD_LOCAL, fam=pp.FAM_INET, proto=pp.PROTO_STREAM, addr=pp.addr_block(1, "198.18.0.1",
                                                                                             "198.18.0.2", 1, 2))
    p.ok("spec-local-with-inet-block", "spec", h, "local", "inet", "stream")
    h = pp.encode(cmd=pp.CMD_LOCAL, fam=0, proto=0, addr=b"\xff" * 20)
    p.ok("spec-local-unspec-garbage-block", "spec", h, "local", "unspec", "unspec")
    h = pp.encode(cmd=pp.CMD_LOCAL, fam=pp.FAM_INET, proto=pp.PROTO_STREAM,
                  addr=pp.addr_block(1, "198.18.0.1", "198.18.0.2", 1, 2) + b"\x03\x00\x04junk")
    p.ok("spec-local-block-skipped-unverified", "spec", h, "local", "inet", "stream")
    h = pp.encode(fam=0, proto=0, addr=b"")
    p.ok("spec-proxy-unspec-empty", "spec", h, "proxy", "unspec", "unspec")
    h = pp.encode(fam=0, proto=0, addr=b"\x01" * 12)
    p.ok("spec-proxy-unspec-block-ignored", "spec", h, "proxy", "unspec", "unspec")
    h = pp.encode(fam=pp.FAM_INET, proto=0, addr=b"\x02" * 12)
    p.ok("spec-proxy-inet-proto-unspec", "spec", h, "proxy", "inet", "unspec")
    for vid, tl in [
        ("spec-tlv-alpn", [T(1, b"h2")]),
        ("spec-tlv-authority", [T(2, b"a.example")]),
        ("spec-tlv-authority-empty", [T(2, b"")]),
        ("spec-tlv-authority-utf8", [T(2, "bücher.example".encode())]),
        ("spec-tlv-crc32c", [T(3, None)]),
        ("spec-tlv-noop-empty", [T(4, b"")]),
        ("spec-tlv-noop-100", [T(4, b"\x00" * 100)]),
        ("spec-tlv-unique-id-128", [T(5, bytes(range(128)))]),
        ("spec-tlv-unique-id-0", [T(5, b"")]),
        ("spec-tlv-ssl-all-subtypes", [T(0x20, ssl_all())]),
        ("spec-tlv-ssl-bare", [T(0x20, pp.ssl_value(0, 1, []))]),
        ("spec-tlv-ssl-unknown-subtype", [T(0x20, pp.ssl_value(1, 7, [(0x26, b"x"), (0x21, b"TLSv1.2")]))]),
        ("spec-tlv-netns", [T(0x30, b"ns1")]),
        ("spec-tlv-custom-e0", [T(0xE0, b"app")]),
        ("spec-tlv-experiment-f0", [T(0xF0, b"exp")]),
        ("spec-tlv-future-f8", [T(0xF8, b"fut")]),
        ("spec-tlv-unassigned-06", [T(0x06, b"\x00\x01")]),
        ("spec-tlv-crc-first-of-many", [T(3, None), T(1, b"http/1.1"), T(2, b"b.example"), T(5, b"id-42"),
                                        T(0x20, ssl_all())]),
        ("spec-tlv-crc-last-of-many", [T(4, b"\x00\x00"), T(1, b"h2"), T(0x30, b"ns"), T(3, None)]),
    ]:
        s, h = tcp4(p, tl)
        p.ok(vid, "spec", h, "proxy", "inet", "stream", s, "192.0.2.10", 50000 + p.n4, 443, "src", tlvs=tl)
    tl = [T(4, b"\x00" * (536 - 12 - 3))]
    s, h = tcp4(p, tl)
    assert len(h) == 16 + 536
    p.ok("spec-len-536-exact", "spec", h, "proxy", "inet", "stream", s, "192.0.2.10", 50000 + p.n4, 443, "src",
         tlvs=tl)
    tl = [T(3, None), T(0x20, ssl_all())]
    s, h = tcp6(p, tl)
    p.ok("spec-tcp6-crc-ssl", "spec", h, "proxy", "inet6", "stream", s, "2001:db8:ffff::1", 51000 + p.n6, 443,
         "src", tlvs=tl)
    tl = [T(3, None), T(2, b"u.example")]
    h = unix(tl)
    p.ok("spec-unix-crc-authority", "spec", h, "proxy", "unix", "stream", "2f72756e2f6c622e736f636b",
         "2f72756e2f61656769732e736f636b", tlvs=tl)
    h = pp.encode(fam=pp.FAM_INET6, src="::ffff:198.51.100.77", dst="::ffff:192.0.2.10", sport=1, dport=443)
    p.ok("spec-tcp6-v4mapped", "spec", h, "proxy", "inet6", "stream", "::ffff:198.51.100.77", "::ffff:192.0.2.10",
         1, 443, "src")
    h = pp.encode(src="198.51.100.200", dst="192.0.2.10", sport=0, dport=0)
    p.ok("spec-tcp4-port-zero", "spec", h, "proxy", "inet", "stream", "198.51.100.200", "192.0.2.10", 0, 0, "src")
    # ---- trailing bytes after the header belong to the next layer: consumed = 16 + len exactly
    tail = b"\x16\x03\x01\x00\x05"
    s, h = tcp4(p)
    p.ok("trail-tcp4-then-tls", "trailing", h, "proxy", "inet", "stream", s, "192.0.2.10", 50000 + p.n4, 443, "src",
         data=h + tail)
    h = pp.encode(cmd=pp.CMD_LOCAL, fam=0, proto=0, addr=b"")
    p.ok("trail-local-then-tls", "trailing", h, "local", "unspec", "unspec", data=h + tail)
    h = pp.encode(fam=0, proto=0, addr=b"\x00" * 4)
    p.ok("trail-unspec-then-tls", "trailing", h, "proxy", "unspec", "unspec", data=h + SIG_LIKE_TAIL)
    # ---- policy: well-formed, but a datagram flow on a stream listener is refused
    for vid, fam, src, dst in [("policy-udp4", pp.FAM_INET, "198.51.100.1", "192.0.2.10"),
                               ("policy-udp6", pp.FAM_INET6, "2001:db8::aaaa", "2001:db8:ffff::1")]:
        h = pp.encode(fam=fam, proto=pp.PROTO_DGRAM, src=src, dst=dst, sport=53, dport=53)
        p.ok(vid, "policy", h, "proxy", "inet" if fam == 1 else "inet6", "dgram", src, dst, 53, 53,
             stream_accept=False)
    h = pp.encode(fam=pp.FAM_UNIX, proto=pp.PROTO_DGRAM, src="/a", dst="/b")
    p.ok("policy-unix-dgram", "policy", h, "proxy", "unix", "dgram", b"/a".hex(), b"/b".hex(), stream_accept=False)
    tl = [T(1, b"h3")]
    h = pp.encode(proto=pp.PROTO_DGRAM, src="198.51.100.2", dst="192.0.2.10", sport=443, dport=443, tlvs=tl)
    p.ok("policy-udp4-tlv", "policy", h, "proxy", "inet", "dgram", "198.51.100.2", "192.0.2.10", 443, 443,
         stream_accept=False, tlvs=tl)

    # ---- hostile
    _, base = tcp4(p)
    for x in (0x20, 0x01):
        for i in range(12):
            b = bytearray(base)
            b[i] ^= x
            p.add(f"h-sig-byte{i}-x{x:02x}", "hostile", bytes(b), "reject", "sig")
    for vid, d in [("h-v1-tcp4", b"PROXY TCP4 192.0.2.1 192.0.2.2 1000 443\r\n"),
                   ("h-v1-tcp6", b"PROXY TCP6 2001:db8::1 2001:db8::2 1000 443\r\n"),
                   ("h-v1-unknown", b"PROXY UNKNOWN\r\n"),
                   ("h-v1-then-v2", b"PROXY TCP4 192.0.2.1 192.0.2.2 1 2\r\n" + base),
                   ("h-v1-no-crlf", b"PROXY " + b"A" * 120),
                   ("h-v1-prefix", b"PROX")]:
        p.add(vid, "hostile", d, "reject", "v1")
    for ver in [0, 1] + list(range(3, 16)):
        b = bytearray(base)
        b[12] = (ver << 4) | 1
        p.add(f"h-version-{ver}", "hostile", bytes(b), "reject", "version")
    for cmd in range(2, 16):
        b = bytearray(base)
        b[12] = 0x20 | cmd
        p.add(f"h-command-{cmd}", "hostile", bytes(b), "reject", "command")
    for fam in range(4, 16):
        b = bytearray(base)
        b[13] = (fam << 4) | 1
        p.add(f"h-family-{fam}", "hostile", bytes(b), "reject", "family")
    for proto in range(3, 16):
        b = bytearray(base)
        b[13] = 0x10 | proto
        p.add(f"h-proto-{proto}", "hostile", bytes(b), "reject", "family")
    for fp in (0x40, 0x50, 0xF0, 0x03, 0x0F):
        h = pp.encode(cmd=pp.CMD_LOCAL, addr=b"")
        b = bytearray(h)
        b[13] = fp
        p.add(f"h-local-family-{fp:02x}", "hostile", bytes(b), "reject", "family")
    for n, full in [(537, True), (538, True), (600, True), (1024, False), (4096, False), (65535, False)]:
        tl = [pp.tlv(4, b"\x00" * (n - 12 - 3))] if full else []
        _, h = tcp4(p, tl, length=n)
        p.add(f"h-len-{n}{'-full' if full else ''}", "hostile", h, "reject", "length")
    p.add("h-len-537-local", "hostile", pp.encode(cmd=pp.CMD_LOCAL, fam=0, proto=0, addr=b"\x00" * 537), "reject",
          "length")
    p.add("h-len-537-unspec", "hostile", pp.encode(fam=0, proto=0, addr=b"\x00" * 537), "reject", "length")
    blk4 = pp.addr_block(1, "198.51.100.9", "192.0.2.10", 1, 2)
    for n in range(12):
        p.add(f"h-short-tcp4-{n}", "hostile", pp.encode(addr=blk4[:n]), "reject", "short-address")
    for n in (0, 6):
        p.add(f"h-short-udp4-{n}", "hostile", pp.encode(proto=2, addr=blk4[:n]), "reject", "short-address")
    blk6 = pp.addr_block(2, "2001:db8::9", "2001:db8::a", 1, 2)
    for n in (0, 4, 12, 16, 20, 32, 35):
        p.add(f"h-short-tcp6-{n}", "hostile", pp.encode(fam=2, addr=blk6[:n]), "reject", "short-address")
    blku = pp.addr_block(3, "/x", "/y")
    for n in (0, 1, 100, 108, 215):
        p.add(f"h-short-unix-{n}", "hostile", pp.encode(fam=3, addr=blku[:n]), "reject", "short-address")
    _, h4 = tcp4(p, [pp.tlv(1, b"h2")])
    for k in (1, 5, 11, 12, 13, 15, 16, 20, 27, len(h4) - 1):
        p.add(f"h-incomplete-tcp4-at{k}", "hostile", h4[:k], "incomplete")
    _, h6 = tcp6(p)
    p.add("h-incomplete-tcp6-at40", "hostile", h6[:40], "incomplete")
    p.add("h-incomplete-unix-at200", "hostile", unix()[:200], "incomplete")
    for fname, mk in [("tcp4", lambda extra: pp.encode(addr=blk4 + extra)),
                      ("tcp6", lambda extra: pp.encode(fam=2, addr=blk6 + extra)),
                      ("unix", lambda extra: pp.encode(fam=3, addr=blku + extra))]:
        for vid, extra in [("1byte", b"\x04"), ("2bytes", b"\x04\x00"), ("len-over", b"\x04\x00\x05abcd"),
                           ("len-ffff", b"\x01\xff\xffabc"), ("second-truncated", b"\x04\x00\x01\x00\x02\x00")]:
            p.add(f"h-tlv-{vid}-{fname}", "hostile", mk(extra), "reject", "tlv-truncated")
    for fname, mk in [("tcp4", lambda tl, **k: tcp4(p, tl, **k)[1]), ("tcp6", lambda tl, **k: tcp6(p, tl, **k)[1]),
                      ("unix", lambda tl, **k: unix(tl, **k))]:
        p.add(f"h-crc-bad-{fname}", "hostile", mk([T(3, None)], crc_bad=True), "reject", "crc-mismatch")
        p.add(f"h-crc-bad-after-tlvs-{fname}", "hostile", mk([T(1, b"h2"), T(4, b"\x00"), T(3, None)], crc_bad=True),
              "reject", "crc-mismatch")
        p.add(f"h-crc-unzeroed-{fname}", "hostile", mk([T(3, None)], crc_unzeroed=True), "reject", "crc-mismatch")
    p.add("h-crc-all-zero", "hostile", tcp4(p, [T(3, b"\x00\x00\x00\x00")])[1], "reject", "crc-mismatch")
    for n in (0, 3, 5, 8):
        p.add(f"h-crc-len-{n}", "hostile", tcp4(p, [T(3, b"\x00" * n)])[1], "reject", "crc-length")
    p.add("h-crc-duplicate", "hostile", tcp4(p, [T(3, None), T(3, b"\x00\x00\x00\x00")])[1], "reject",
          "crc-duplicate")
    p.add("h-crc-duplicate-noop-between", "hostile", tcp4(p, [T(3, None), T(4, b""), T(3, b"\x00\x00\x00\x00")])[1],
          "reject", "crc-duplicate")
    for n in (129, 200, 255):
        p.add(f"h-unique-id-{n}-tcp4", "hostile", tcp4(p, [T(5, b"u" * n)])[1], "reject", "unique-id-length")
        p.add(f"h-unique-id-{n}-tcp6", "hostile", tcp6(p, [T(5, b"u" * n)])[1], "reject", "unique-id-length")
    for fname, mk in [("tcp4", lambda tl: tcp4(p, tl)[1]), ("tcp6", lambda tl: tcp6(p, tl)[1])]:
        for n in range(5):
            p.add(f"h-ssl-short-{n}-{fname}", "hostile", mk([T(0x20, b"\x01" * n)]), "reject", "ssl-short")
        for vid, sub in [("1byte", b"\x21"), ("2bytes", b"\x21\x00"), ("len-over", b"\x21\x00\x09TLSv1.3"),
                         ("len-ffff", b"\x22\xff\xffcn")]:
            p.add(f"h-ssl-sub-{vid}-{fname}", "hostile", mk([T(0x20, b"\x01\x00\x00\x00\x00" + sub)]), "reject",
                  "ssl-subtlv-truncated")
        for i, bad in enumerate([b"\xff", b"\xc3", b"a\x80b", b"\xed\xa0\x80"]):
            p.add(f"h-authority-utf8-{i}-{fname}", "hostile", mk([T(2, bad)]), "reject", "authority-utf8")
    p.add("h-len-536-truncated-tlv", "hostile", pp.encode(addr=blk4 + b"\x04\x02\x10" + b"\x00" * 509), "reject",
          "tlv-truncated")
    hello = ch.record(ch.build(sni="a.l4.test", seed=7))
    p.add("h-no-header-tls", "hostile", hello, "reject", "sig")
    p.add("h-no-header-http", "hostile", b"GET / HTTP/1.1\r\nHost: monban.test\r\n\r\n", "reject", "sig")
    return p.v


SIG_LIKE_TAIL = b"\r\n\r\n\x00"  # the next layer's bytes may even look like a signature: they are not re-parsed

# ------------------------------------------------------------------------------------------------ ClientHello

ROUTES = {"a.l4.test": "a", "b.l4.test": "b"}


def route_of(sni):
    return ROUTES.get(sni.lower(), "close") if sni else "close"


def ch_vectors():
    v = []
    seed = [100]

    def nxt():
        seed[0] += 1
        return seed[0]

    def ok(vid, group, rec, sni=None, alpn=(), versions=(0x0304,), sigalgs=ch.DEFAULT_SIGALGS,
           groups=ch.DEFAULT_GROUPS, ta=None, consumed=None, data=None):
        v.append({"id": vid, "group": group, "hex": (rec if data is None else data).hex(), "expect": "ok",
                  "sni": sni, "alpn": [a.encode().hex() for a in alpn], "versions": list(versions),
                  "sigalgs": list(sigalgs), "groups": list(groups),
                  "trust_anchors": None if ta is None else [t.hex() for t in ta],
                  "consumed": len(rec) if consumed is None else consumed, "route": route_of(sni),
                  "e2e": "send"})

    def bad(vid, data, cls):
        v.append({"id": vid, "group": "hostile", "hex": data.hex(), "expect": "reject", "class": cls,
                  "route": "close", "e2e": "send"})

    def inc(vid, data):
        v.append({"id": vid, "group": "hostile", "hex": data.hex(), "expect": "incomplete", "route": "close",
                  "e2e": "half-close"})

    R, B = ch.record, ch.build
    ok("ch-a-basic", "valid", R(B(sni="a.l4.test", seed=nxt())), "a.l4.test")
    ok("ch-b-basic", "valid", R(B(sni="b.l4.test", seed=nxt())), "b.l4.test")
    ok("ch-a-mixed-case", "valid", R(B(sni="A.L4.Test", seed=nxt())), "A.L4.Test")
    ok("ch-a-alpn", "valid", R(B(sni="a.l4.test", alpn=["h2", "http/1.1"], seed=nxt())), "a.l4.test",
       alpn=["h2", "http/1.1"])
    ta1 = [bytes.fromhex("81fd5901")]
    ta3 = [bytes.fromhex("81fd5901"), bytes.fromhex("2a8648"), bytes(range(32))]
    ok("ch-a-ta-empty", "valid", R(B(sni="a.l4.test", trust_anchors=[], seed=nxt())), "a.l4.test", ta=[])
    ok("ch-a-ta-one", "valid", R(B(sni="a.l4.test", trust_anchors=ta1, seed=nxt())), "a.l4.test", ta=ta1)
    ok("ch-b-ta-three", "valid", R(B(sni="b.l4.test", trust_anchors=ta3, seed=nxt())), "b.l4.test", ta=ta3)
    ok("ch-a-ta-wrong-codepoint-ignored", "valid",
       R(B(sni="a.l4.test", trust_anchors=ta1, ta_codepoint=0xCA35, seed=nxt())), "a.l4.test", ta=None)
    ok("ch-a-ta-first", "valid", R(B(sni="a.l4.test", trust_anchors=ta1, order=[ch.TRUST_ANCHORS_EXT], seed=nxt())),
       "a.l4.test", ta=ta1)
    sig2 = [0x0403, 0x0905]
    ok("ch-a-sigalgs-two", "valid", R(B(sni="a.l4.test", sigalgs=sig2, seed=nxt())), "a.l4.test", sigalgs=sig2)
    ok("ch-a-tls12-and-13", "valid", R(B(sni="a.l4.test", versions=(0x0304, 0x0303), seed=nxt())), "a.l4.test",
       versions=(0x0304, 0x0303))
    ok("ch-a-recver-0303", "valid", R(B(sni="a.l4.test", seed=nxt()), version=0x0303), "a.l4.test")
    ok("ch-a-recver-0302", "valid", R(B(sni="a.l4.test", seed=nxt()), version=0x0302), "a.l4.test")
    g = [0x11EC, 0x001D]
    ok("ch-a-mlkem-share", "valid", R(B(sni="a.l4.test", groups=g, seed=nxt())), "a.l4.test", groups=g)
    ok("ch-a-grease-unknown", "valid", R(B(sni="a.l4.test", extra=[(0x0A0A, b""), (0xFFFE, b"xyz")],
                                           order=[0x0A0A], seed=nxt())), "a.l4.test")
    ok("ch-a-record-16384", "valid", R(B(sni="a.l4.test", padding_to=16384, seed=nxt())), "a.l4.test")
    ok("ch-a-session-id-empty", "valid", R(B(sni="a.l4.test", session_id=b"", seed=nxt())), "a.l4.test")
    r = R(B(sni="b.l4.test", seed=nxt()))
    ok("ch-b-trailing-record", "valid", r, "b.l4.test", data=r + R(b"\x14\x00\x00\x00", ctype=0x16))
    ok("ch-unknown-sni", "valid", R(B(sni="c.l4.test", seed=nxt())), "c.l4.test")
    ok("ch-suffix-sni", "valid", R(B(sni="x.a.l4.test", seed=nxt())), "x.a.l4.test")
    ok("ch-no-sni", "valid", R(B(seed=nxt())), None)
    ok("ch-no-sni-ta", "valid", R(B(trust_anchors=ta1, seed=nxt())), None, ta=ta1)
    hs = B(sni="a.l4.test", seed=nxt())
    no_ext = hs[:4 + 2 + 32 + 1 + 32 + 2 + 6 + 2]  # through compression methods, no extensions block
    no_ext = b"\x01" + (len(no_ext) - 4).to_bytes(3, "big") + no_ext[4:]
    ok("ch-no-extensions-block", "valid", R(no_ext), None, versions=(), sigalgs=(), groups=())

    # hostile
    base = B(sni="a.l4.test", seed=nxt())
    for ct in (0x17, 0x15, 0x14, 0x80):
        bad(f"ch-h-ctype-{ct:02x}", R(base, ctype=ct), "record-type")
    bad("ch-h-http-get", b"GET / HTTP/1.1\r\nHost: a.l4.test\r\n\r\n", "record-type")
    bad("ch-h-http-post", b"POST /x HTTP/1.1\r\nHost: a.l4.test\r\nContent-Length: 0\r\n\r\n", "record-type")
    bad("ch-h-h2-preface", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "record-type")
    bad("ch-h-proxy-v2", pp.encode(src="198.51.100.1", dst="192.0.2.1") + R(base), "record-type")
    for rv in (0x0300, 0x0304, 0x0200, 0xFEFF):
        bad(f"ch-h-recver-{rv:04x}", R(base, version=rv), "record-version")
    bad("ch-h-reclen-0", R(b""), "record-length")
    bad("ch-h-reclen-16385", R(B(sni="a.l4.test", padding_to=16385, seed=nxt())), "record-length")
    bad("ch-h-reclen-ffff", R(base, length=0xFFFF) + b"\x00" * (0xFFFF - len(base)), "record-length")
    inc("ch-h-incomplete-header", R(base)[:3])
    inc("ch-h-incomplete-record", R(base)[:-1])
    bad("ch-h-hs-type-2", R(b"\x02" + base[1:]), "not-client-hello")
    bad("ch-h-hs-type-0", R(b"\x00" + base[1:]), "not-client-hello")
    bad("ch-h-fragmented-50", ch.records(base, [50]), "fragmented")
    bad("ch-h-fragmented-hdr", ch.records(base, [2]), "fragmented")
    bad("ch-h-trailing-in-record", R(base + b"\x00\x00\x00"), "trailing")

    def body_mut(fn):
        b = bytearray(base[4:])
        b = fn(b)
        return R(b"\x01" + len(b).to_bytes(3, "big") + bytes(b))

    bad("ch-h-session-id-33", R(B(sni="a.l4.test", session_id=b"\x00" * 33, seed=nxt())), "malformed")
    # body layout (32-byte session id): version 0..2, random 2..34, session_id 34..67, suites length at 67
    bad("ch-h-suites-odd", body_mut(lambda b: b[:67] + b"\x00\x03\x13\x01\x13" + b[67 + 2 + 6:]), "malformed")
    bad("ch-h-suites-empty", R(B(sni="a.l4.test", suites=[], seed=nxt())), "malformed")
    bad("ch-h-compression-empty", R(B(sni="a.l4.test", compression=b"", seed=nxt())), "malformed")
    bad("ch-h-extblock-long", body_mut(lambda b: b[:77] + (int.from_bytes(b[77:79], "big") + 9).to_bytes(2, "big") +
                                       b[79:]), "malformed")
    bad("ch-h-extblock-garbage-after", body_mut(lambda b: b + b"\x00"), "malformed")
    bad("ch-h-dup-sni", R(B(sni="a.l4.test", extra=[(0, ch.sni_ext("b.l4.test"))], seed=nxt())),
        "duplicate-extension")
    bad("ch-h-dup-key-share", R(B(sni="a.l4.test", extra=[(51, ch.key_share_ext([(0x1D, b"\x01" * 32)]))],
                                  seed=nxt())), "duplicate-extension")
    bad("ch-h-dup-trust-anchors", R(B(sni="a.l4.test", trust_anchors=ta1,
                                      extra=[(ch.TRUST_ANCHORS_EXT, ch.trust_anchors_ext(ta1))], seed=nxt())),
        "duplicate-extension")

    def sni_raw(vid, raw, cls):
        bad(vid, R(B(extra=[(0, raw)], seed=nxt())), cls)

    sni_raw("ch-h-sni-empty-list", ch.vec16(b""), "malformed")
    sni_raw("ch-h-sni-two-hosts", ch.sni_ext(["a.l4.test", "b.l4.test"]), "malformed")
    sni_raw("ch-h-sni-name-type-1", ch.sni_ext([(1, b"a.l4.test")]), "malformed")
    sni_raw("ch-h-sni-list-trailing", ch.sni_ext("a.l4.test") + b"\x00", "malformed")
    sni_raw("ch-h-sni-name-overrun", ch.vec16(b"\x00\x00\x40a.l4.test"), "malformed")
    for i, nm in enumerate([b"", b"a l4.test", b"a_l4.test", b"a.l4.test.", b".a.l4.test", b"a..l4.test",
                            b"-a.l4.test", b"a-.l4.test", b"a" * 64 + b".test", (b"a" * 63 + b".") * 4 + b"ab",
                            b"\xc3\xa4.l4.test", b"a.l4.test\x00", b"a.l4.test\x00.evil"]):
        sni_raw(f"ch-h-sni-invalid-{i}", ch.sni_ext([(0, nm)]), "sni-invalid")
    for vid, raw in [("ch-h-alpn-empty-list", ch.vec16(b"")), ("ch-h-alpn-empty-name", ch.vec16(b"\x00")),
                     ("ch-h-alpn-overrun", ch.vec16(b"\x05h2"))]:
        bad(vid, R(B(sni="a.l4.test", extra=[(16, raw)], seed=nxt())), "malformed")
    for vid, raw in [("ch-h-versions-odd", b"\x03\x03\x04\x03"), ("ch-h-versions-empty", b"\x00")]:
        bad(vid, R(B(sni="a.l4.test", versions=None, extra=[(43, raw)], seed=nxt())), "malformed")
    for vid, raw in [("ch-h-sigalgs-odd", b"\x00\x03\x04\x03\x08"), ("ch-h-sigalgs-empty", b"\x00\x00")]:
        bad(vid, R(B(sni="a.l4.test", sigalgs=None, extra=[(13, raw)], seed=nxt())), "malformed")
    for vid, raw in [("ch-h-ta-id-len-0", ch.vec16(b"\x00")),
                     ("ch-h-ta-id-len-33", ch.vec16(b"\x21" + b"\x01" * 33)),
                     ("ch-h-ta-list-overrun", b"\x00\x09\x04\x81\xfd\x59\x01"),
                     ("ch-h-ta-trailing", ch.trust_anchors_ext(ta1) + b"\x00")]:
        bad(vid, R(B(sni="a.l4.test", extra=[(ch.TRUST_ANCHORS_EXT, raw)], seed=nxt())), "malformed")
    bad("ch-h-ext-overrun", body_mut(lambda b: b + b"\x00\x2b\x00\x10\x02"), "malformed")
    return v


def render():
    out = {}
    pv = proxy_vectors()
    out["proxy_v2.json"] = {"source": PP_SOURCE, "rules": "oracles/proxy-l4/README.md#proxy-v2-acceptance-rules",
                            "count": len(pv), "hostile": sum(1 for x in pv if x["group"] in ("hostile", "policy")),
                            "vectors": pv}
    cv = ch_vectors()
    out["client_hello.json"] = {"source": CH_SOURCE, "trust_anchors_codepoint": ch.TRUST_ANCHORS_EXT,
                                "rules": "oracles/proxy-l4/README.md#clienthello-peek-rules",
                                "routes": ROUTES, "count": len(cv), "vectors": cv}
    return {k: dump(d) for k, d in out.items()}


def dump(d):
    vec = d.pop("vectors")
    head = json.dumps(d, sort_keys=True)[:-1]
    lines = ",\n".join("  " + json.dumps(x, sort_keys=True) for x in vec)
    return head + ', "vectors": [\n' + lines + "\n]}\n"


def main():
    files = render()
    vd = os.path.join(HERE, "vectors")
    if "--check" in sys.argv:
        bad = []
        for k, txt in files.items():
            try:
                with open(os.path.join(vd, k)) as f:
                    if f.read() != txt:
                        bad.append(k)
            except OSError:
                bad.append(k)
        if bad:
            print(f"vectors drifted from gen_vectors.py: {', '.join(bad)}")
            return 1
        print("vectors match gen_vectors.py")
        return 0
    os.makedirs(vd, exist_ok=True)
    for k, txt in files.items():
        with open(os.path.join(vd, k), "w") as f:
            f.write(txt)
        print(f"wrote vectors/{k} ({json.loads(txt)['count']} vectors)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
