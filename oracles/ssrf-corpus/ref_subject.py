"""Reference subject for the SSRF-CORPUS self-test (same JSON-lines protocol as subjects/egress-subject).

    python3 -I ref_subject.py [--mutant NAME]

Without --mutant it implements the contract (strict URL, allowlist, resolve once per hop, every answer vetted,
connect to the vetted literal, redirects re-vetted, no https->http, cross-origin only if allowed). Each mutant
breaks one rule the way real fetchers do; `run --self-test` requires every mutant to FAIL the corpus:

  hostname           connect by hostname: re-resolve at connect time and dial whatever comes back
  no-mapped          classifier skips IPv4-mapped / IPv4-compatible IPv6 (treated as public)
  redirect-no-revet  follows redirects without vetting the new hop (allowlist and classification skipped)
  octal              inet_aton-style IPv4 literals (octal/hex/decimal/short forms accepted)
  first-only         vets only the first DNS answer
  no-embedded        NAT64 / 6to4 / Teredo not unwrapped (treated as public)
  downgrade          allows https -> http redirects
"""
import ipaddress as ia
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netclass  # noqa: E402

MUTANT = ""
DEFAULT_PORT = {"http": 80, "https": 443}


class Reject(Exception):
    def __init__(self, code, detail=""):
        super().__init__(code)
        self.code, self.detail = code, detail


def check_chars(s):
    if len(s) > 4096:
        raise Reject("invalid-url", "too-long")
    if any(not (0x21 <= ord(c) <= 0x7E) for c in s):
        raise Reject("invalid-url", "bad-char")
    if "\\" in s:
        raise Reject("invalid-url", "backslash")


def lenient_v4(h):
    parts = h.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    vals = []
    for p in parts:
        try:
            if p.lower().startswith("0x"):
                vals.append(int(p[2:] or "0", 16))
            elif len(p) > 1 and p.startswith("0"):
                vals.append(int(p, 8))
            else:
                vals.append(int(p, 10))
        except ValueError:
            return None
    n = 0
    for v in vals[:-1]:
        if v > 255:
            return None
        n = n * 256 + v
    last_bits = 8 * (5 - len(vals))
    if vals[-1] >= 1 << last_bits:
        return None
    n = (n << last_bits) | vals[-1]
    return str(ia.IPv4Address(n))


def check_host(h):
    if not h:
        raise Reject("invalid-url", "empty-host")
    h = h.lower()
    if h.endswith("."):
        raise Reject("invalid-url", "trailing-dot")
    labels = h.split(".")
    last = labels[-1]
    ends_num = (last.isdigit() and last.isascii()) or (
        last.startswith("0x") and all(c in "0123456789abcdef" for c in last[2:]))
    if ends_num:
        if MUTANT == "octal":
            v = lenient_v4(h)
            if v is None:
                raise Reject("invalid-url", "ipv4-noncanonical")
            return "v4", v
        ok = len(labels) == 4 and all(l.isdigit() and (l == "0" or not l.startswith("0")) and int(l) <= 255
                                      for l in labels)
        if not ok:
            raise Reject("invalid-url", "ipv4-noncanonical")
        return "v4", h
    for l in labels:
        if not (1 <= len(l) <= 63 and all(c.isalnum() and c.isascii() or c == "-" for c in l)
                and l[0] != "-" and l[-1] != "-"):
            raise Reject("invalid-url", "host")
        if l[2:4] == "--" and not l.startswith("xn--"):
            raise Reject("invalid-url", "host")
    return "name", h


def parse_port(p):
    if not p or len(p) > 5 or not p.isdigit() or p.startswith("0") or not 1 <= int(p) <= 65535:
        raise Reject("invalid-url", "port")
    return int(p)


def check_path(p):
    if p == "":
        p = "/"
    elif p.startswith("?"):
        p = "/" + p
    i = 0
    while i < len(p):
        c = p[i]
        if c == "%":
            if not all(x in "0123456789abcdefABCDEF" for x in p[i + 1:i + 3]) or len(p[i + 1:i + 3]) != 2:
                raise Reject("invalid-url", "bad-percent")
        elif not (c.isalnum() or c in "-._~!$&'()*+,;=:@/?"):
            raise Reject("invalid-url", "path-char")
        i += 1
    return p


def parse(s):
    check_chars(s)
    if "://" not in s:
        raise Reject("invalid-url", "no-scheme")
    scheme, rest = s.split("://", 1)
    scheme = scheme.lower()
    if scheme not in DEFAULT_PORT:
        raise Reject("invalid-url", "scheme")
    rest = rest.split("#", 1)[0]
    cut = min([i for i in (rest.find("/"), rest.find("?")) if i >= 0] or [len(rest)])
    auth, path = rest[:cut], rest[cut:]
    if not auth:
        raise Reject("invalid-url", "empty-host")
    if "@" in auth:
        raise Reject("invalid-url", "userinfo")
    if auth.startswith("["):
        if "]" not in auth:
            raise Reject("invalid-url", "ipv6")
        inner, after = auth[1:].split("]", 1)
        if "%" in inner:
            raise Reject("invalid-url", "zone-id")
        try:
            host = str(ia.IPv6Address(inner))
        except ValueError:
            raise Reject("invalid-url", "ipv6")
        if after and not after.startswith(":"):
            raise Reject("invalid-url", "port")
        port = parse_port(after[1:]) if after else DEFAULT_PORT[scheme]
        kind = "v6"
    else:
        if "[" in auth or "]" in auth:
            raise Reject("invalid-url", "ipv6")
        h, sep, p = auth.partition(":")
        port = parse_port(p) if sep else DEFAULT_PORT[scheme]
        if "%" in h:
            raise Reject("invalid-url", "host-percent")
        kind, host = check_host(h)
    return {"scheme": scheme, "kind": kind, "host": host, "port": port, "path": check_path(path)}


def host_text(u):
    return "[%s]" % u["host"] if u["kind"] == "v6" else u["host"]


def host_header(u):
    return host_text(u) if u["port"] == DEFAULT_PORT[u["scheme"]] else "%s:%d" % (host_text(u), u["port"])


def url_str(u):
    return "%s://%s%s" % (u["scheme"], host_header(u), u["path"])


def join(base, loc):
    if not loc:
        raise Reject("bad-redirect", "empty-location")
    check_chars(loc)
    loc = loc.split("#", 1)[0]
    cut = min([i for i in (loc.find("/"), loc.find("?")) if i >= 0] or [len(loc)])
    if loc.startswith("//"):
        return parse(base["scheme"] + ":" + loc)
    if ":" in loc[:cut]:
        return parse(loc)
    bp = base["path"].split("?", 1)[0]
    if loc.startswith("/"):
        path = loc
    elif loc.startswith("?"):
        path = bp + loc
    elif loc == "":
        path = base["path"]
    else:
        path = bp[:bp.rfind("/") + 1] + loc
    return dict(base, path=check_path(path))


def classify(ip):
    ip = ia.ip_address(ip)
    if MUTANT == "no-mapped" and ip.version == 6 and (ip in ia.ip_network("::ffff:0:0/96") or ip in ia.ip_network("::/96")) \
            and ip not in (ia.ip_address("::"), ia.ip_address("::1")):
        return "public"
    if MUTANT == "no-embedded" and ip.version == 6 and any(
            ip in ia.ip_network(n) for n in ("64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32")):
        return "public"
    return netclass.classify(ip)


def check_addr(ip, readmit):
    c = classify(ip)
    if c == "public":
        return
    if c in netclass.READMIT and any(
            ia.ip_address(ip).version == ia.ip_network(p, strict=False).version
            and ia.ip_address(ip) in ia.ip_network(p, strict=False) for p in readmit):
        return
    raise Reject("forbidden-address", "%s (%s)" % (ip, c))


class Ctx:
    def __init__(self, case):
        self.case = case
        self.queries = {}
        self.connects = []
        self.server_hits = 0

    def resolve(self, host):
        n = self.queries.get(host, 0)
        self.queries[host] = n + 1
        sets = self.case.get("dns", {}).get(host)
        if sets is None:
            raise Reject("resolve", "nxdomain")
        return list(sets[n] if n < len(sets) else sets[-1])

    def allowed_host(self, u):
        key = u["host"]
        for r in self.case.get("allow_hosts", []):
            if r.startswith("*."):
                sfx = r[2:].lower()
                if u["kind"] == "name" and key.endswith("." + sfx):
                    return True
            elif key == r.lower():
                return True
        return False

    def vet(self, u, revet=True):
        c = self.case
        if revet:
            if u["scheme"] == "http" and not c.get("allow_http", True):
                raise Reject("scheme-not-allowed")
            if not self.allowed_host(u):
                raise Reject("host-not-allowed")
            ports = c.get("allow_ports") or [DEFAULT_PORT[u["scheme"]]]
            if u["port"] not in ports:
                raise Reject("port-not-allowed")
        ips = self.resolve(u["host"]) if u["kind"] == "name" else [u["host"]]
        if not ips:
            raise Reject("resolve", "no addresses")
        if revet:
            for ip in (ips[:1] if MUTANT == "first-only" else ips):
                check_addr(ip, c.get("readmit", []))
        return ips


def sockaddr(ip, port):
    return "[%s]:%d" % (ip, port) if ":" in ip else "%s:%d" % (ip, port)


def live_exchange(ctx, ip, u, deadline):
    max_bytes = ctx.case.get("max_bytes", 1 << 20)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise Reject("timeout")
    try:
        s = socket.create_connection((ip, u["port"]), timeout=remaining)
    except socket.timeout:
        raise Reject("timeout")
    except OSError as e:
        raise Reject("connect", str(e))
    try:
        s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: aegis-egress\r\nConnection: close\r\n\r\n"
                   % (u["path"], host_header(u))).encode())
        buf = b""
        while True:
            s.settimeout(max(0.001, deadline - time.monotonic()))
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > max_bytes + 16384:
                raise Reject("response-too-large")
    except socket.timeout:
        raise Reject("timeout")
    finally:
        s.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    if len(body) > max_bytes:
        raise Reject("response-too-large")
    lines = head.decode("latin-1").split("\r\n")
    try:
        status = int(lines[0].split(" ")[1])
    except (IndexError, ValueError):
        raise Reject("bad-response", "status-line")
    loc = None
    for l in lines[1:]:
        k, _, v = l.partition(":")
        if k.strip().lower() == "location":
            loc = v.strip()
    return status, loc, len(body)


def fetch(case):
    ctx = Ctx(case)
    deadline = time.monotonic() + case.get("deadline_ms", 10000) / 1000.0
    out = {"id": case.get("id", "")}
    try:
        u = parse(case.get("url", ""))
        hops = 0
        while True:
            ips = ctx.vet(u, revet=not (MUTANT == "redirect-no-revet" and hops > 0))
            ip = ips[0]
            if MUTANT == "hostname" and u["kind"] == "name":
                ip = ctx.resolve(u["host"])[0]  # the socket layer resolves the name again
            peer = sockaddr(ip, u["port"])
            ctx.connects.append(peer)
            if case.get("live"):
                status, loc, blen = live_exchange(ctx, ip, u, deadline)
            else:
                r = case.get("redirects", {}).get(url_str(u))
                status, loc, blen = (r[0], r[1], 0) if r else (200, None, 3)
            if status not in (301, 302, 303, 307, 308):
                out.update(decision="connect", addr=peer, status=status, body_len=blen)
                break
            if hops >= case.get("max_redirects", 3):
                raise Reject("too-many-redirects")
            hops += 1
            if loc is None:
                raise Reject("bad-redirect", "no-location")
            nxt = join(u, loc)
            if u["scheme"] == "https" and nxt["scheme"] == "http" and MUTANT != "downgrade":
                raise Reject("scheme-downgrade")
            same = all(u[k] == nxt[k] for k in ("scheme", "host", "port"))
            if not same and not case.get("cross_origin", False) and MUTANT != "redirect-no-revet":
                raise Reject("cross-origin-redirect")
            u = nxt
    except Reject as e:
        out.update(reject=e.code, detail=e.detail)
    out["connects"] = ctx.connects
    out["queries"] = ctx.queries
    return out


def main():
    global MUTANT
    if len(sys.argv) == 3 and sys.argv[1] == "--mutant":
        MUTANT = sys.argv[2]
    for line in sys.stdin:
        if not line.strip():
            continue
        sys.stdout.write(json.dumps(fetch(json.loads(line))) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
