"""SSRF-CORPUS cases. `cases()` returns the list; strings may contain {PORT} (the harness's loopback server port).

Every case: id, url, dns ({host: [answer set per query]}), allow_hosts, expect ("connect" | "reject"), optional
expect_addr, readmit, allow_ports, allow_http, max_redirects, cross_origin, redirects ({hop url: [status, location]}),
live (real loopback fetch), expect_host (Host header the loopback server must see), server_hits.
"""

PUB4 = "93.184.216.34"
PUB4B = "93.184.216.35"
PUB6 = "2606:4700:4700::1111"

FORBIDDEN_V4 = [
    "0.0.0.0", "0.1.2.3", "0.255.255.255", "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.20.1.1",
    "172.31.255.254", "192.168.0.1", "192.168.255.255", "100.64.0.1", "100.127.255.254", "100.100.100.200",
    "127.0.0.1", "127.1.2.3", "127.255.255.254", "169.254.169.254", "169.254.170.2", "169.254.0.1",
    "169.254.255.255", "192.0.0.1", "192.0.0.170", "192.0.2.1", "198.51.100.7", "203.0.113.9", "198.18.0.1",
    "198.19.255.255", "192.88.99.1", "224.0.0.1", "239.255.255.250", "240.0.0.1", "250.1.2.3",
    "255.255.255.255",
]
FORBIDDEN_V6 = [
    "::", "::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::ffff:8.8.8.8",
    "::ffff:0:7f00:1", "::127.0.0.1", "::10.0.0.1", "::8.8.8.8", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe",
    "64:ff9b::a00:1", "64:ff9b::c0a8:1", "64:ff9b::a9fe:1", "64:ff9b:1::808:808", "64:ff9b:1::7f00:1",
    "2002:7f00:1::1", "2002:a9fe:a9fe::1", "2002:a00:1::", "2002:c0a8:101::1", "2002:6440:1::1",
    "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001::1", "2001:db8::1", "3fff::1", "2001:2::1", "2001:10::1",
    "100::1", "fc00::1", "fd00::1", "fd00:ec2::254", "fe80::1", "fe80::a9fe:a9fe", "fec0::1", "ff02::1",
    "ff05::1:3", "5f00::1", "4000::1", "::ffff:100.100.100.200",
]
PUBLIC = [
    PUB4, "8.8.8.8", "1.1.1.1", "172.32.0.1", "172.15.255.254", "100.128.0.1", "100.63.255.254", "11.0.0.1",
    "169.255.0.1", "198.20.0.1", "223.255.255.254", "192.0.1.1", "192.169.0.1", PUB6, "2a00:1450:4001::1",
    "64:ff9b::808:808", "2002:808:808::1",
]


def cases():
    out = []

    def add(cid, url, expect, **kw):
        c = {"id": cid, "url": url, "expect": expect}
        c.update(kw)
        c.setdefault("dns", {})
        c.setdefault("allow_hosts", [])
        out.append(c)

    pub = {"pub.test": [[PUB4]]}

    # A. forbidden answers via DNS (v4 and v6)
    for a in FORBIDDEN_V4 + FORBIDDEN_V6:
        add("dns-forbidden:" + a, "http://evil.test/", "reject", dns={"evil.test": [[a]]}, allow_hosts=["evil.test"])
    # B. forbidden IPv4 literals (allowlisted by literal text: classification must still refuse)
    for a in ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.100.100.200",
              "0.0.0.0", "100.64.0.1", "192.0.2.1", "198.18.0.1", "224.0.0.1", "255.255.255.255", "240.0.0.1"]:
        add("lit4-forbidden:" + a, "http://%s/" % a, "reject", allow_hosts=[a])
    # C. forbidden IPv6 literals
    for a in ["::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:a9fe:a9fe", "64:ff9b::a9fe:a9fe", "2002:7f00:1::",
              "fd00:ec2::254", "fe80::1", "fc00::1", "::"]:
        add("lit6-forbidden:" + a, "http://[%s]/" % a, "reject", allow_hosts=[a])
    # D. IPv6 zone ids (any form) are rejected
    for z in ["fe80::1%25eth0", "fe80::1%eth0", "::1%251", "fe80::a9fe:a9fe%25lo"]:
        add("zone-id:" + z, "http://[%s]/" % z, "reject", allow_hosts=[z.split("%")[0]])
    # E. non-canonical IPv4 literals. The allowlist holds both the literal text and what a lenient parser makes of
    #    it, so only a strict parser refuses; a lenient one dials an address that is no DNS answer and no literal.
    lenient = {
        "0177.0.0.1": "127.0.0.1", "0x7f.0.0.1": "127.0.0.1", "0x7f000001": "127.0.0.1", "2130706433": "127.0.0.1",
        "017700000001": "127.0.0.1", "127.1": "127.0.0.1", "127.0.1": "127.0.0.1", "0": "0.0.0.0",
        "0177.1": "127.0.0.1", "0300.0250.0.1": "192.168.0.1", "3232235521": "192.168.0.1",
        "0xa9.0xfe.0xa9.0xfe": "169.254.169.254", "169.254.43518": "169.254.169.254",
        "0251.0376.0251.0376": "169.254.169.254", "127.000.000.001": "127.0.0.1", "0110.0.0.1": "72.0.0.1",
        "010.010.010.010": "8.8.8.8", "0x08.0x08.0x08.0x08": "8.8.8.8", "134744072": "8.8.8.8",
        "0x5db8d822": PUB4, "93.184.0xd822": PUB4, "01.1.1.1": "1.1.1.1",
    }
    for lit, real in lenient.items():
        add("ipv4-noncanonical:" + lit, "http://%s/" % lit, "reject", allow_hosts=[lit, real])
    add("ipv4-five-labels", "http://1.1.1.1.1/", "reject", allow_hosts=["1.1.1.1.1"])
    # F. DNS rebinding: first answer public, any later answer private. One query per hop; connect to the vetted IP.
    for second in ["127.0.0.1", "169.254.169.254", "10.0.0.1", "::1", "::ffff:127.0.0.1", "fd00:ec2::254"]:
        add("rebind:" + second, "http://rebind.test/", "connect", expect_addr=PUB4,
            dns={"rebind.test": [[PUB4], [second]]}, allow_hosts=["rebind.test"])
    add("rebind-v6", "http://rebind.test/", "connect", expect_addr=PUB6,
        dns={"rebind.test": [[PUB6], ["::1"]]}, allow_hosts=["rebind.test"])
    # every answer is vetted, in any order
    for i, s in enumerate([[PUB4, "127.0.0.1"], ["127.0.0.1", PUB4], [PUB6, "::1"], [PUB4, "::ffff:10.0.0.1"],
                           [PUB4, "64:ff9b::7f00:1"], [PUB4, "169.254.169.254"]]):
        add("mixed-answers:%d" % i, "http://mixed.test/", "reject", dns={"mixed.test": [s]},
            allow_hosts=["mixed.test"])
    add("nxdomain", "http://nx.test/", "reject", allow_hosts=["nx.test"])
    add("empty-answer", "http://empty.test/", "reject", dns={"empty.test": [[]]}, allow_hosts=["empty.test"])

    # G. redirects (simulated responses)
    base = dict(dns={"pub.test": [[PUB4]], "b.test": [[PUB4B]], "evil.test": [["10.0.0.1"]],
                     "meta.test": [["169.254.169.254"]], "map.test": [["::ffff:127.0.0.1"]],
                     "rebind2.test": [[PUB4B], ["127.0.0.1"]], "c.test": [["93.184.216.36"]]},
                allow_hosts=["pub.test", "b.test", "evil.test", "meta.test", "map.test", "rebind2.test",
                             "127.0.0.1", "169.254.169.254", "::1", "fd00:ec2::254", "::ffff:169.254.169.254",
                             "0177.0.0.1"])
    forbidden_targets = [
        "http://evil.test/", "http://127.0.0.1/", "http://[::1]/", "http://169.254.169.254/latest/meta-data/",
        "http://[fd00:ec2::254]/", "http://0177.0.0.1/", "http://meta.test/", "http://[::ffff:169.254.169.254]/",
        "//evil.test/x", "http://map.test/", "http://c.test/", "file:///etc/passwd", "gopher://evil.test:70/_x",
        "javascript:alert(1)", "http://user@pub.test/", "http://pub.test:22/", "http:evil.test", "",
        "http://evil.test\\@pub.test/",
    ]
    for t in forbidden_targets:
        for st in ([302] if t not in ("http://evil.test/", "http://169.254.169.254/latest/meta-data/")
                   else [301, 302, 303, 307, 308]):
            add("redirect-to:%d:%s" % (st, t), "http://pub.test/", "reject", cross_origin=True,
                redirects={"http://pub.test/": [st, t]}, **base)
    add("redirect-same-origin", "http://pub.test/", "connect", expect_addr=PUB4,
        redirects={"http://pub.test/": [302, "/next"]}, **base)
    add("redirect-relative", "http://pub.test/a/b", "connect", expect_addr=PUB4,
        redirects={"http://pub.test/a/b": [302, "c?d=1"]}, **base)
    add("redirect-cross-origin-denied", "http://pub.test/", "reject",
        redirects={"http://pub.test/": [302, "http://b.test/"]}, **base)
    add("redirect-cross-origin-allowed", "http://pub.test/", "connect", expect_addr=PUB4B, cross_origin=True,
        redirects={"http://pub.test/": [302, "http://b.test/"]}, **base)
    add("redirect-chain-to-evil", "http://pub.test/", "reject", cross_origin=True,
        redirects={"http://pub.test/": [302, "/a"], "http://pub.test/a": [302, "http://b.test/"],
                   "http://b.test/": [307, "http://evil.test/"]}, **base)
    add("redirect-to-rebinding-host", "http://pub.test/", "connect", expect_addr=PUB4B, cross_origin=True,
        redirects={"http://pub.test/": [302, "http://rebind2.test/"]}, **base)
    chain = {"http://pub.test/": [302, "/1"], "http://pub.test/1": [302, "/2"], "http://pub.test/2": [302, "/3"]}
    add("redirect-3-hops-max-3", "http://pub.test/", "connect", expect_addr=PUB4, max_redirects=3,
        redirects=chain, **base)
    add("redirect-4-hops-max-3", "http://pub.test/", "reject", max_redirects=3,
        redirects=dict(chain, **{"http://pub.test/3": [302, "/4"]}), **base)
    add("redirect-loop", "http://pub.test/", "reject", redirects={"http://pub.test/": [302, "/"]}, **base)
    add("redirect-max-0", "http://pub.test/", "reject", max_redirects=0,
        redirects={"http://pub.test/": [302, "/next"]}, **base)
    add("redirect-downgrade", "https://pub.test/", "reject", cross_origin=True,
        redirects={"https://pub.test/": [302, "http://pub.test/"]}, **base)
    add("redirect-downgrade-to-evil", "https://pub.test/", "reject", cross_origin=True,
        redirects={"https://pub.test/": [301, "http://evil.test/"]}, **base)
    add("redirect-upgrade", "http://pub.test/", "connect", expect_addr=PUB4, cross_origin=True,
        redirects={"http://pub.test/": [302, "https://pub.test/"]}, **base)
    add("redirect-no-location", "http://pub.test/nl", "reject", redirects={"http://pub.test/nl": [302, ""]}, **base)

    # H. userinfo and authority tricks
    for u in ["http://pub.test@evil.test/", "http://evil.test@pub.test/", "http://pub.test:80@evil.test/",
              "http://user:pass@pub.test/", "http://pub.test%40evil.test/", "http://pub.test\\@evil.test/",
              "http://@pub.test/", "http://evil.test?@pub.test/", "http://pub.test&@evil.test#@pub.test/"]:
        add("authority:" + u, u, "reject", dns={"pub.test": [[PUB4]], "evil.test": [["127.0.0.1"]]},
            allow_hosts=["pub.test", "evil.test"])
    add("authority-fragment-at", "http://pub.test#@evil.test/", "connect", expect_addr=PUB4,
        dns={"pub.test": [[PUB4]], "evil.test": [["127.0.0.1"]]}, allow_hosts=["pub.test", "evil.test"])
    # I. trailing dots, case, odd hosts
    for u in ["http://pub.test./", "http://pub.test../", "http://.pub.test/", "http://evil.test./",
              "http://pub..test/", "http://pub_test.test/", "http://pub.test%2e/", "http://pÜb.test/",
              "http://-pub.test/", "http:///pub.test/", "http:/pub.test/", "http://[pub.test]/"]:
        add("host:" + u, u, "reject", dns={"pub.test": [[PUB4]], "evil.test": [["127.0.0.1"]]},
            allow_hosts=["pub.test", "evil.test", "pub.test.", "pub_test.test"])
    for u in ["http://PUB.TEST/", "HTTP://Pub.Test/", "hTTp://pUb.tEsT/x"]:
        add("case:" + u, u, "connect", expect_addr=PUB4, dns=pub, allow_hosts=["pub.test"])
    add("case-evil", "http://EVIL.TEST/", "reject", dns={"evil.test": [["127.0.0.1"]]}, allow_hosts=["evil.test"])
    # J. ports
    add("port-default", "http://pub.test:80/", "connect", expect_addr=PUB4, dns=pub, allow_hosts=["pub.test"])
    add("port-allowed", "http://pub.test:8080/", "connect", expect_addr=PUB4, dns=pub, allow_hosts=["pub.test"],
        allow_ports=[8080])
    add("port-not-allowed", "http://pub.test:8080/", "reject", dns=pub, allow_hosts=["pub.test"])
    add("port-ssh", "http://pub.test:22/", "reject", dns=pub, allow_hosts=["pub.test"], allow_ports=[80, 443])
    for p in ["0", "65536", "080", "+80", "80:80", "", "-1", "99999", "8o", "0x50", " 80"]:
        add("port-bad:" + p, "http://pub.test:%s/" % p, "reject", dns=pub, allow_hosts=["pub.test"],
            allow_ports=[80, 8080])
    # K. allowlist
    add("allow-missing", "http://pub.test/", "reject", dns=pub, allow_hosts=["other.test"])
    add("allow-empty", "http://pub.test/", "reject", dns=pub)
    add("allow-suffix", "http://x.wild.test/", "connect", expect_addr=PUB4, dns={"x.wild.test": [[PUB4]]},
        allow_hosts=["*.wild.test"])
    add("allow-suffix-apex", "http://wild.test/", "reject", dns={"wild.test": [[PUB4]]}, allow_hosts=["*.wild.test"])
    add("allow-suffix-lookalike", "http://evilwild.test/", "reject", dns={"evilwild.test": [[PUB4]]},
        allow_hosts=["*.wild.test"])
    add("allow-suffix-private", "http://x.wild.test/", "reject", dns={"x.wild.test": [["10.1.1.1"]]},
        allow_hosts=["*.wild.test"])
    # L. schemes
    for u in ["ftp://pub.test/", "file:///etc/passwd", "file://pub.test/etc/passwd", "gopher://pub.test/",
              "dict://pub.test:11211/", "ldap://pub.test/", "javascript:alert(1)", "data:text/plain,x",
              "ws://pub.test/", "jar:http://pub.test/!/"]:
        add("scheme:" + u, u, "reject", dns=pub, allow_hosts=["pub.test"])
    add("http-not-allowed", "http://pub.test/", "reject", dns=pub, allow_hosts=["pub.test"], allow_http=False)
    add("https-only-ok", "https://pub.test/", "connect", expect_addr=PUB4, dns=pub, allow_hosts=["pub.test"],
        allow_http=False)
    # M. positive controls (simulated)
    for a in PUBLIC:
        add("public-dns:" + a, "http://ok.test/", "connect", expect_addr=a, dns={"ok.test": [[a]]},
            allow_hosts=["ok.test"])
    add("public-lit4", "http://8.8.8.8/", "connect", expect_addr="8.8.8.8", allow_hosts=["8.8.8.8"])
    add("public-lit6", "http://[%s]/" % PUB6, "connect", expect_addr=PUB6, allow_hosts=[PUB6])
    add("public-multi", "http://ok.test/", "connect", dns={"ok.test": [[PUB4, PUB6, "8.8.8.8"]]},
        allow_hosts=["ok.test"])
    add("readmit-private", "http://int.test/", "connect", expect_addr="10.0.0.5", dns={"int.test": [["10.0.0.5"]]},
        allow_hosts=["int.test"], readmit=["10.0.0.0/8"])
    add("readmit-wrong-prefix", "http://int.test/", "reject", dns={"int.test": [["10.0.0.5"]]},
        allow_hosts=["int.test"], readmit=["10.1.0.0/16"])
    add("readmit-never-metadata", "http://int.test/", "reject", dns={"int.test": [["169.254.169.254"]]},
        allow_hosts=["int.test"], readmit=["0.0.0.0/0"])
    add("readmit-never-mapped", "http://int.test/", "reject", dns={"int.test": [["::ffff:10.0.0.5"]]},
        allow_hosts=["int.test"], readmit=["10.0.0.0/8", "::/0"])
    add("readmit-never-linklocal", "http://int.test/", "reject", dns={"int.test": [["fe80::1"]]},
        allow_hosts=["int.test"], readmit=["::/0"])

    # N. live positive controls and live negatives against the harness's loopback server (127.0.0.1:{PORT})
    live = dict(live=True, allow_ports=["{PORT}"], readmit=["127.0.0.1/32"], deadline_ms=3000)
    svc = {"svc.test": [["127.0.0.1"]], "evil.test": [["10.0.0.5"]], "svc2.test": [["127.0.0.1"], ["127.0.0.2"]]}
    hosts = ["svc.test", "evil.test", "svc2.test", "127.0.0.1", "169.254.169.254"]
    add("live-ok", "http://svc.test:{PORT}/ok", "connect", expect_addr="127.0.0.1", dns=svc, allow_hosts=hosts,
        expect_host="svc.test:{PORT}", server_hits=1, **live)
    add("live-uppercase-host", "http://SVC.TEST:{PORT}/ok", "connect", expect_addr="127.0.0.1", dns=svc,
        allow_hosts=hosts, expect_host="svc.test:{PORT}", server_hits=1, **live)
    add("live-literal", "http://127.0.0.1:{PORT}/ok", "connect", expect_addr="127.0.0.1", dns=svc,
        allow_hosts=hosts, expect_host="127.0.0.1:{PORT}", server_hits=1, **live)
    add("live-rebind", "http://svc2.test:{PORT}/ok", "connect", expect_addr="127.0.0.1", dns=svc,
        allow_hosts=hosts, expect_host="svc2.test:{PORT}", server_hits=1, **live)
    add("live-redirect-same-origin", "http://svc.test:{PORT}/redir-ok", "connect", expect_addr="127.0.0.1",
        dns=svc, allow_hosts=hosts, server_hits=2, **live)
    add("live-redirect-evil", "http://svc.test:{PORT}/redir-evil", "reject", dns=svc, allow_hosts=hosts,
        cross_origin=True, server_hits=1, **live)
    add("live-redirect-metadata", "http://svc.test:{PORT}/redir-meta", "reject", dns=svc, allow_hosts=hosts,
        cross_origin=True, server_hits=1, **live)
    add("live-no-readmit", "http://svc.test:{PORT}/ok", "reject", dns=svc, allow_hosts=hosts, server_hits=0,
        **dict(live, readmit=[]))
    add("live-size-cap", "http://svc.test:{PORT}/big", "reject", dns=svc, allow_hosts=hosts, server_hits=1,
        **dict(live, max_bytes=1000))
    add("live-deadline", "http://svc.test:{PORT}/slow", "reject", dns=svc, allow_hosts=hosts, server_hits=1,
        **dict(live, deadline_ms=300))
    return out
