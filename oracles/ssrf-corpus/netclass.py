"""Independent address judgement for the SSRF-CORPUS oracle (stdlib `ipaddress`, written from the IANA special-purpose
registries, not ported from aegis-egress). `judge(ip)` returns (class, readmittable)."""
import ipaddress as ia

V4 = [  # (network, class); first match wins, most specific first
    ("169.254.169.254/32", "metadata"), ("169.254.170.2/32", "metadata"), ("100.100.100.200/32", "metadata"),
    ("0.0.0.0/32", "unspecified"), ("255.255.255.255/32", "broadcast"),
    ("0.0.0.0/8", "this-network"), ("10.0.0.0/8", "private"), ("100.64.0.0/10", "shared-address-space"),
    ("127.0.0.0/8", "loopback"), ("169.254.0.0/16", "link-local"), ("172.16.0.0/12", "private"),
    ("192.0.0.0/24", "reserved"), ("192.0.2.0/24", "documentation"), ("192.88.99.0/24", "reserved"),
    ("192.168.0.0/16", "private"), ("198.18.0.0/15", "benchmarking"), ("198.51.100.0/24", "documentation"),
    ("203.0.113.0/24", "documentation"), ("224.0.0.0/4", "multicast"), ("240.0.0.0/4", "reserved"),
]
V6 = [
    ("fd00:ec2::254/128", "metadata"), ("::/128", "unspecified"), ("::1/128", "loopback"),
    ("::ffff:0:0/96", "ipv4-mapped"), ("::/96", "ipv4-compatible"),
    ("64:ff9b::/96", "@nat64"), ("64:ff9b:1::/48", "nat64-local-use"),
    ("ff00::/8", "multicast"), ("fe80::/10", "link-local"), ("fec0::/10", "site-local"), ("fc00::/7", "unique-local"),
    ("2001::/32", "teredo"), ("2001:db8::/32", "documentation"), ("3fff::/20", "documentation"),
    ("2001:2::/48", "benchmarking"), ("2001::/23", "reserved"), ("2002::/16", "@6to4"),
]
V4N = [(ia.ip_network(n), c) for n, c in V4]
V6N = [(ia.ip_network(n), c) for n, c in V6]
GLOBAL6 = ia.ip_network("2000::/3")
READMIT = {"loopback", "private", "shared-address-space", "unique-local"}


def classify(ip):
    ip = ia.ip_address(ip) if isinstance(ip, str) else ip
    if ip.version == 4:
        for n, c in V4N:
            if ip in n:
                return c
        return "public"
    for n, c in V6N:
        if ip in n:
            if c == "@nat64":
                return "public" if classify(ia.IPv4Address(int(ip) & 0xFFFFFFFF)) == "public" else "nat64"
            if c == "@6to4":
                return "public" if classify(ia.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)) == "public" else "6to4"
            return c
    return "public" if ip in GLOBAL6 else "reserved"


def allowed(ip, readmit):
    """Connectable under a case's readmit prefixes (list of strings)."""
    ip = ia.ip_address(ip) if isinstance(ip, str) else ip
    c = classify(ip)
    if c == "public":
        return True
    if c in READMIT:
        for p in readmit:
            n = ia.ip_network(p, strict=False)
            if n.version == ip.version and ip in n:
                return True
    return False
