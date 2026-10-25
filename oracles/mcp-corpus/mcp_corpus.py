"""MCP-CORPUS oracle driver: MCP listener/gateway corpus (43 research cases + token-passthrough) against a gateway URL.

Invoke through ./run (python3 -I, stdlib only, 127.0.0.1 only, offline). See README.md.
Reviewed port of research round-004/06-corpus/mcp_lc_corpus.py + corpus_ext.py (httpx/h2/pyjwt/cryptography replaced
by stdlib; HS256 test-token profile instead of RS256; expected verdicts from corpus_expected.json made exact).
"""
import argparse
import base64
import concurrent.futures as cf
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
import re
import select
import socket
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
NAME = "MCP-CORPUS"


def _load(name):
    sp = importlib.util.spec_from_file_location("aegis_mcp_" + name, os.path.join(HERE, name + ".py"))
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


MOCK = _load("mock_upstream")
CORPUS = json.load(open(os.path.join(HERE, "corpus.json"), encoding="utf-8"))
PROFILE = CORPUS["profile"]
SECRET = PROFILE["auth"]["secret"].encode()
ISS = PROFILE["auth"]["iss"]
V = PROFILE["protocol_versions"]
META_PV = "io.modelcontextprotocol/protocolVersion"
META_CC = "io.modelcontextprotocol/clientCapabilities"
LOOPBACK = ("127.0.0.1", "localhost", "::1")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def mint(sub="alice", aud=None, iss=ISS, exp=3600, nbf=None, alg="HS256", omit_aud=False, secret=SECRET):
    now = int(time.time())
    claims = {"sub": sub, "iss": iss, "iat": now, "exp": now + exp}
    if nbf is not None:
        claims["nbf"] = now + nbf
    if not omit_aud:
        claims["aud"] = aud
    h = b64u(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    p = b64u(json.dumps(claims).encode())
    if alg == "none":
        return h + "." + p + "."
    dig = {"HS256": hashlib.sha256, "HS512": hashlib.sha512}[alg]
    return h + "." + p + "." + b64u(hmac.new(secret, (h + "." + p).encode(), dig).digest())


class Resp:
    def __init__(self, status=None, headers=None, body=b"", err=None):
        self.status, self.headers, self.body, self.err = status, headers or {}, body, err

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")

    def json(self):
        t = self.text
        m = re.search(r"data: (\{.*\})", t)
        try:
            return json.loads(m.group(1) if m else t)
        except Exception:
            return None

    def rpc_code(self):
        j = self.json()
        if isinstance(j, dict) and isinstance(j.get("error"), dict):
            return j["error"].get("code")
        return None

    def ev(self):
        d = {"status": self.status}
        if self.err:
            d["err"] = self.err[:120]
        c = self.rpc_code()
        if c is not None:
            d["rpc"] = c
        return d


class Ctx:
    def __init__(self, url, counter, url2=None, url_redir=None, url_multi=None, pid=None, flood_n=20000,
                 records=None):
        for u in [url, url2, url_redir, url_multi]:
            if u and urllib.parse.urlsplit(u).hostname not in LOOPBACK:
                raise SystemExit("refusing non-loopback subject %s" % u)
        self.url, self.url2, self.url_redir, self.url_multi = url, url2, url_redir, url_multi
        self.counter, self.records, self.pid, self.flood_n = counter, records, pid, flood_n
        u = urllib.parse.urlsplit(url)
        self.host, self.port, self.netloc = u.hostname, u.port, u.netloc
        self.n = 0

    # ---------------------------------------------------------------- transport
    def req(self, method, url, headers=(), body=None, timeout=30):
        u = urllib.parse.urlsplit(url)
        c = http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)
        try:
            c.putrequest(method, u.path or "/", skip_host=True, skip_accept_encoding=True)
            hs = list(headers)
            if not any(k.lower() == "host" for k, _ in hs):
                hs.insert(0, ("Host", u.netloc))
            for k, v in hs:
                if v is not None:
                    c.putheader(k, v)
            if body is not None:
                c.putheader("Content-Length", str(len(body)))
            c.endheaders(body)
            r = c.getresponse()
            data = r.read()
            hdrs = {}
            for k, v in r.getheaders():
                hdrs.setdefault(k.lower(), v)
            return Resp(r.status, hdrs, data)
        except Exception as e:
            return Resp(None, {}, b"", repr(e))
        finally:
            c.close()

    def body(self, method, params=None, era="legacy", id_=None):
        self.n += 1
        p = dict(params or {})
        if era == "modern":
            p["_meta"] = {META_PV: V["modern"], META_CC: {}}
        b = {"jsonrpc": "2.0", "method": method, "params": p}
        if not method.startswith("notifications/"):
            b["id"] = id_ if id_ is not None else self.n
        return b

    def hdr(self, method, era, name=None, sid=None, token="default", url=None, extra=()):
        h = [("Content-Type", "application/json"), ("Accept", "application/json, text/event-stream")]
        if era == "modern":
            h += [("MCP-Protocol-Version", V["modern"]), ("Mcp-Method", method)]
            if name:
                h.append(("Mcp-Name", name))
        else:
            h.append(("MCP-Protocol-Version", V["legacy"]))
            if sid:
                h.append(("Mcp-Session-Id", sid))
        if token == "default":
            token = mint(aud=url or self.url)
        if token:
            h.append(("Authorization", "Bearer " + token))
        ex = dict((k.lower(), (k, v)) for k, v in extra)
        h = [(k, v) for k, v in h if k.lower() not in ex] + [kv for kv in ex.values() if kv[1] is not None]
        return h

    def post(self, obj, headers, url=None):
        data = obj if isinstance(obj, bytes) else (obj.encode() if isinstance(obj, str) else json.dumps(obj).encode())
        return self.req("POST", url or self.url, headers, data)

    def session(self, era, token="default", url=None):
        """legacy: initialize + initialized -> session id ("" if refused). modern: None."""
        if era == "modern":
            return None
        url = url or self.url
        r = self.post(self.body("initialize", {"protocolVersion": V["legacy"], "capabilities": {},
                                               "clientInfo": {"name": "oracle", "version": "1"}}),
                      self.hdr("initialize", era, token=token, url=url), url)
        sid = r.headers.get("mcp-session-id") or ""
        if r.status == 200:
            self.post(self.body("notifications/initialized"), self.hdr("notifications/initialized", era, sid=sid,
                                                                      token=token, url=url), url)
        return sid

    def echo(self, x, era, sid=None, extra=(), id_=None, token="default", url=None):
        url = url or self.url
        return self.post(self.body("tools/call", {"name": "echo", "arguments": {"x": x}}, era, id_),
                         self.hdr("tools/call", era, "echo", sid, token, url, extra), url)

    def calls(self):
        return self.counter()

    def blocked(self, r, before):
        """A reject: HTTP 4xx (never 200 for a reject) and zero upstream handler invocations."""
        reached = self.calls() - before
        ok = reached == 0 and r.status is not None and 400 <= r.status < 500
        return ok, dict(r.ev(), handler_invocations=reached)

    def rss_kb(self):
        if not self.pid:
            return None
        try:
            with open("/proc/%d/status" % self.pid) as f:
                for ln in f:
                    if ln.startswith("VmRSS"):
                        return int(ln.split()[1])
        except OSError:
            return None
        return None


PASS, FAIL, NA = "PASS", "FAIL", "NA"
CASES = {}


def case(cid):
    def d(f):
        CASES[cid] = f
        return f
    return d


def evil_variants(c):
    P = c.port
    return {"host-only": [("Host", "evil.example")],
            "rebind(Host+Origin)": [("Host", "rebind.test:%d" % P), ("Origin", "http://rebind.test:%d" % P)],
            "origin-only": [("Origin", "http://evil.example")]}


# ====================================================================== origin / host family
@case("host-allowlist-required")
def c_host(c, era):
    sid = c.session(era)
    ev, ok = {}, True
    for k, e in evil_variants(c).items():
        b = c.calls()
        r = c.echo("x", era, sid, extra=e)
        bl, ev[k] = c.blocked(r, b)
        if k == "origin-only":
            bl = bl and r.status == 403                  # spec MUST: invalid Origin -> 403
        ok &= bl
    return (PASS if ok else FAIL), "evil Host, evil Origin (403), Host+Origin rebind -> 4xx, 0 handler calls", ev


@case("reject-text-plain-post")
def c_txt(c, era):
    ev, ok = {}, True
    for what in ("initialize", "tools/call"):
        if what == "initialize":
            body = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": V["legacy"], "capabilities": {}, "clientInfo": {"name": "x", "version": "1"}}}
        else:
            body = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "echo", "arguments": {"x": "csrf"}}}
        h = [("Content-Type", "text/plain;charset=UTF-8"), ("Accept", "*/*"), ("Origin", "http://evil.example"),
             ("Sec-Fetch-Site", "cross-site")]
        b = c.calls()
        r = c.post(json.dumps(body), h)
        bl, ev[what] = c.blocked(r, b)
        ev[what]["session_minted"] = "mcp-session-id" in r.headers
        ok &= bl and "mcp-session-id" not in r.headers
    return (PASS if ok else FAIL), "text/plain cross-site POST -> 4xx, no session minted, 0 handler calls", ev


@case("no-wildcard-cors")
def c_cors(c, era):
    ev = {}
    r = c.req("OPTIONS", c.url, [("Origin", "http://evil.example"), ("Access-Control-Request-Method", "POST"),
                                 ("Access-Control-Request-Headers", "content-type,mcp-protocol-version,mcp-method,authorization")])
    ev["preflight"] = {"status": r.status, "acao": r.headers.get("access-control-allow-origin")}
    sid = c.session(era)
    b = c.calls()
    r2 = c.echo("x", era, sid, extra=[("Origin", "http://evil.example")])
    ev["post"] = {"status": r2.status, "acao": r2.headers.get("access-control-allow-origin"),
                  "handler_invocations": c.calls() - b}
    acao = [ev["preflight"]["acao"], ev["post"]["acao"]]
    bad = any(a in ("*", "http://evil.example") for a in acao) or ev["post"]["handler_invocations"] > 0
    return (FAIL if bad else PASS), "no ACAO '*' and no reflected evil origin on preflight or POST", ev


@case("ws-origin-check")
def c_ws(c, era):
    b = c.calls()
    r = c.req("GET", c.url, [("Upgrade", "websocket"), ("Connection", "Upgrade"), ("Sec-WebSocket-Version", "13"),
                             ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="), ("Origin", "http://evil.example")])
    ev = dict(r.ev(), handler_invocations=c.calls() - b)
    ok = r.status is not None and r.status != 101 and ev["handler_invocations"] == 0
    return (PASS if ok else FAIL), "WebSocket upgrade with evil Origin never 101, 0 handler calls", ev


@case("absent-origin-fail-closed")
def c_abs(c, era):
    sid = c.session(era)
    ev, ok = {}, True
    b = c.calls()
    r = c.echo("x", era, sid, extra=[("Cookie", "session=ambient"), ("Sec-Fetch-Site", "cross-site")])
    bl, ev["bearer+cookie+cross-site"] = c.blocked(r, b)
    ok &= bl
    b = c.calls()
    r = c.echo("x", era, sid, extra=[("Cookie", "session=ambient")], token=None)
    bl, ev["cookie-only(no bearer)"] = c.blocked(r, b)
    ok &= bl
    return (PASS if ok else FAIL), "no Origin + ambient cookie (+ Sec-Fetch-Site cross-site) -> 4xx, 0 handler calls", ev


# ====================================================================== parser family
def _parse_case(c, era, variants):
    sid = c.session(era)
    ev, ok = {}, True
    for name, (content, ctype) in variants.items():
        h = c.hdr("tools/call", era, "echo", sid, extra=[("Content-Type", ctype)])
        b = c.calls()
        r = c.post(content, h)
        bl, ev[name] = c.blocked(r, b)
        ok &= bl
    return ok, ev


def _tc(c, era):
    return c.body("tools/call", {"name": "echo", "arguments": {"x": "p"}}, era)


@case("json-case-variant-reject")
def c_case(c, era):
    s = json.dumps(_tc(c, era))
    ok, ev = _parse_case(c, era, {"Method-key": (s.replace('"method"', '"Method"'), "application/json"),
                                  "TOOLS/CALL": (s.replace('"tools/call"', '"TOOLS/CALL"'), "application/json")})
    return (PASS if ok else FAIL), "'Method' key / 'TOOLS/CALL' -> 4xx, 0 handler calls", ev


@case("json-dup-nul-reject")
def c_dup(c, era):
    m = _tc(c, era)
    p = json.dumps(m["params"])
    v = {"dup-method(list,call)": ('{"jsonrpc":"2.0","id":9,"method":"tools/list","method":"tools/call","params":%s}' % p, "application/json"),
         "dup-method(call,list)": ('{"jsonrpc":"2.0","id":9,"method":"tools/call","method":"tools/list","params":%s}' % p, "application/json"),
         "NUL-key": (json.dumps(m).replace('"name"', '"na\\u0000me"', 1), "application/json")}
    ok, ev = _parse_case(c, era, v)
    return (PASS if ok else FAIL), "duplicate method key (either order) / NUL key -> 4xx, 0 handler calls", ev


@case("json-bom-reject")
def c_bom(c, era):
    ok, ev = _parse_case(c, era, {"BOM": (b"\xef\xbb\xbf" + json.dumps(_tc(c, era)).encode(), "application/json")})
    return (PASS if ok else FAIL), "BOM-prefixed body -> 4xx, 0 handler calls", ev


@case("policy-fail-closed")
def c_pol(c, era):
    m = json.dumps(_tc(c, era))
    ok, ev = _parse_case(c, era, {"name=1e1000": (m.replace('"name": "echo"', '"name": 1e1000'), "application/json"),
                                  "ctype=text/xml": (m, "text/xml"), "ctype=empty": (m, "")})
    return (PASS if ok else FAIL), "1e1000 name, non-JSON or empty content-type -> 4xx, 0 handler calls", ev


@case("amplification-bound")
def c_amp(c, era):
    sid = c.session(era)
    d = 200000
    payload = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"x":' + "[" * d + "]" * d + "}}}"
    if era == "modern":
        payload = payload.replace('"params":{', '"params":{"_meta":{"%s":"%s"},' % (META_PV, V["modern"]), 1)
    b = c.calls()
    r = c.post(payload, c.hdr("tools/call", era, "echo", sid))
    bl, ev = c.blocked(r, b)
    sid2 = c.session(era)
    alive = c.echo("alive", era, sid2)
    ev["alive_after"] = alive.status
    ok = bl and alive.status == 200
    return (PASS if ok else FAIL), "200k-deep nesting -> 4xx, 0 handler calls, gateway still serves", ev


# ====================================================================== concurrency
@case("id-collision-two-clients")
def c_idc(c, era):
    def one(k):
        sid = c.session(era, token=mint(sub="client%d" % k, aud=c.url))
        res = []
        for i in range(25):
            val = "client%d-%d" % (k, i)
            r = c.echo(val, era, sid, id_=1, token=mint(sub="client%d" % k, aud=c.url))
            t = r.text
            res.append(r.status == 200 and val in t and ("client%d-" % (1 - k)) not in t)
        return res
    with cf.ThreadPoolExecutor(2) as ex:
        flat = [x for lst in ex.map(one, [0, 1]) for x in lst]
    bad = flat.count(False)
    return (PASS if bad == 0 else FAIL), "two clients, same JSON-RPC id concurrently -> each gets its own result", \
        {"mismatches": bad, "of": len(flat)}


# ====================================================================== resource bounds
def _stream_big(c, headers, total):
    """Send headers, wait up to 1 s for an early reply, then stream the body in 1 MiB chunks, stopping as soon as
    the server answers. Returns (status or None, bytes_sent)."""
    s = socket.create_connection((c.host, c.port), timeout=30)
    head = "POST %s HTTP/1.1\r\n" % (urllib.parse.urlsplit(c.url).path or "/")
    hs = [("Host", c.netloc)] + list(headers) + [("Content-Length", str(total)), ("Connection", "close")]
    head += "".join("%s: %s\r\n" % kv for kv in hs) + "\r\n"
    sent, got = 0, b""
    pre = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"x":"'
    post = b'"}}}'
    try:
        s.sendall(head.encode())
        r, _, _ = select.select([s], [], [], 1.0)
        if not r:
            chunk = b"A" * (1 << 20)
            s.sendall(pre)
            sent = len(pre)
            while sent < total - len(post):
                r, _, _ = select.select([s], [], [], 0)
                if r:
                    break
                n = min(len(chunk), total - len(post) - sent)
                s.sendall(chunk[:n])
                sent += n
            else:
                s.sendall(post)
                sent += len(post)
        s.settimeout(60)
        while b"\r\n" not in got:
            d = s.recv(65536)
            if not d:
                break
            got += d
    except OSError:
        try:
            got += s.recv(65536)
        except OSError:
            pass
    finally:
        s.close()
    m = re.match(rb"HTTP/1\.[01] (\d{3})", got)
    return (int(m.group(1)) if m else None), sent


@case("body-cap-413")
def c_body(c, era):
    sid = c.session(era)
    b = c.calls()
    h = [kv for kv in c.hdr("tools/call", era, "echo", sid)]
    st, sent = _stream_big(c, h, 64 * 1024 * 1024)
    ev = {"status": st, "body_bytes_sent": sent, "handler_invocations": c.calls() - b}
    ok = st == 413 and ev["handler_invocations"] == 0
    return (PASS if ok else FAIL), "64 MiB body -> 413 before buffering, 0 handler calls", ev


@case("session-table-bound")
def c_sess(c, era):
    if not c.pid:
        return NA, "needs --subject-pid (RSS of the gateway process)", {}
    r0 = c.rss_kb()
    hist = {}

    def one(_):
        r = c.post(c.body("initialize", {"protocolVersion": V["legacy"], "capabilities": {},
                                         "clientInfo": {"name": "f", "version": "1"}}), c.hdr("initialize", "legacy"))
        return r.status
    with cf.ThreadPoolExecutor(50) as ex:
        for st in ex.map(one, range(c.flood_n)):
            hist[st] = hist.get(st, 0) + 1
    r1 = c.rss_kb()
    ev = {"N": c.flood_n, "status_hist": hist, "rss_kb_before": r0, "rss_kb_after": r1}
    ok = r0 is not None and r1 is not None and (r1 - r0) / 1024 < 15
    return (PASS if ok else FAIL), "N authenticated initialize -> RSS growth < 15 MB (bounded table / TTL)", ev


@case("cache-bound")
def c_cache(c, era):
    if not c.pid:
        return NA, "needs --subject-pid (RSS of the gateway process)", {}
    sid = c.session(era)
    r0 = c.rss_kb()

    def one(i):
        nm = "nosuch_%d_%s" % (i, "a" * 64)
        return c.post(c.body("tools/call", {"name": nm, "arguments": {}}, era), c.hdr("tools/call", era, nm, sid)).status
    with cf.ThreadPoolExecutor(50) as ex:
        list(ex.map(one, range(c.flood_n)))
    r1 = c.rss_kb()
    ok = r0 is not None and r1 is not None and (r1 - r0) / 1024 < 15
    return (PASS if ok else FAIL), "N unique unknown tool calls -> RSS growth < 15 MB", {"rss_kb_before": r0, "rss_kb_after": r1}


@case("unauth-listener-refused")
def c_unauth(c, era):
    b = c.calls()
    r = c.post(c.body("tools/list", {}, era), c.hdr("tools/list", era, token=None))
    bl, ev = c.blocked(r, b)
    ok = bl and r.status in (401, 403)
    return (PASS if ok else FAIL), "tools/list without credential -> 401/403 in the default build, 0 handler calls", ev


# ====================================================================== auth / gateway forwarding
@case("token-wrong-audience-401")
def c_aud(c, era):
    def attempt(tok):
        b = c.calls()
        if era == "legacy":
            r = c.post(c.body("initialize", {"protocolVersion": V["legacy"], "capabilities": {},
                                             "clientInfo": {"name": "aud", "version": "1"}}), c.hdr("initialize", era, token=tok))
        else:
            r = c.echo("aud", era, token=tok)
        return r.status, c.calls() - b
    good = mint(aud=c.url)
    tests = {"good": good, "aud=other": mint(aud="http://other.example/mcp"), "aud=omitted": mint(omit_aud=True),
             "expired": mint(aud=c.url, exp=-3600), "iss=wrong": mint(aud=c.url, iss="http://evil.example"),
             "nbf=future": mint(aud=c.url, nbf=3600), "alg=none": mint(aud=c.url, alg="none"),
             "alg=HS512": mint(aud=c.url, alg="HS512"), "wrong-key": mint(aud=c.url, secret=b"not-the-key"),
             "sig-tampered": good[:-4] + ("AAAA" if not good.endswith("AAAA") else "BBBB"), "no-token": None}
    res = {k: attempt(v) for k, v in tests.items()}
    bad = [k for k, (st, calls) in res.items() if k != "good" and (st != 401 or calls)]
    ev = {k: {"status": st, "handler_invocations": n} for k, (st, n) in res.items()}
    if res["good"][0] != 200:
        return FAIL, "good token must be accepted", ev
    ev["not_401_or_reached"] = bad
    return (PASS if not bad else FAIL), "only the audience-correct token accepted; every other token -> 401, 0 handler calls", ev


@case("session-principal-binding")
def c_spb(c, era):
    sid = c.session(era, token=mint(sub="alice", aud=c.url))
    if not sid:
        return FAIL, "legacy initialize must mint a session id", {}
    b = c.calls()
    r = c.echo("bob-uses-alice-session", era, sid, token=mint(sub="bob", aud=c.url))
    bl, ev = c.blocked(r, b)
    return (PASS if bl else FAIL), "Bob presenting Alice's session id -> 4xx, 0 handler calls", ev


@case("session-route-pin")
def c_srp(c, era):
    if not c.url2:
        return NA, "needs --subject-url2", {}
    sid = c.session(era)
    if not sid:
        return FAIL, "legacy initialize must mint a session id", {}
    b = c.calls()
    r = c.echo("cross-route", era, sid, token=mint(aud=c.url2), url=c.url2)
    bl, ev = c.blocked(r, b)
    return (PASS if bl else FAIL), "session from route 1 presented on route 2 -> 4xx, 0 handler calls", ev


@case("token-passthrough")
def c_tp(c, era):
    if c.records is None:
        return NA, "needs the in-process mock upstream (not --counter-url)", {}
    tok = mint(aud=c.url)
    start = len(c.records())
    sid = c.session(era, token=tok)
    r = c.echo("tp", era, sid, token=tok, extra=[("X-Api-Key", "client-key-xyz"), ("Cookie", "sess=abc")])
    recs = c.records()[start:]
    leaked = [k for k in ("authorization", "cookie", "x-api-key")
              if any(tok in v or "client-key-xyz" in v or "sess=abc" in v
                     for rr in recs for hk, v in rr["headers"].items() if hk == k)]
    ev = {"status": r.status, "upstream_requests": len(recs), "client_credentials_forwarded": leaked}
    if r.status != 200 or not recs:
        return FAIL, "the request itself must succeed and reach the upstream", ev
    return (FAIL if leaked else PASS), "client Authorization/Cookie/X-Api-Key never forwarded upstream", ev


@case("redirect-strip-headers")
def c_red(c, era):
    if not c.url_redir:
        return NA, "needs --subject-redir-url", {}
    if c.records is None:
        return NA, "needs the in-process mock upstream", {}
    startb = len(c.records_b())
    sid = c.session(era, url=c.url_redir)
    r = c.echo("rd", era, sid, url=c.url_redir, extra=[("X-Api-Key", "client-key-xyz")])
    B = c.records_b()[startb:]
    leak = [x for x in B if any(x["headers"].get(k) for k in ("authorization", "x-api-key", "cookie"))]
    ev = {"client_status": r.status, "origin_B_requests": len(B), "origin_B_with_credentials": len(leak)}
    note = " (followed without credentials)" if B and not leak else ""
    return (FAIL if leak else PASS), "cross-origin upstream redirect never followed with credentials" + note, ev


@case("toolname-collision")
def c_tnc(c, era):
    if not c.url_multi:
        return NA, "needs --subject-multi-url", {}
    sid = c.session(era, url=c.url_multi)
    r = c.post(c.body("tools/list", {}, era), c.hdr("tools/list", era, sid=sid, url=c.url_multi), c.url_multi)
    j = r.json() or {}
    names = [t.get("name") for t in (j.get("result") or {}).get("tools", []) if isinstance(t, dict)]
    ok = len(names) >= 2 and len(names) == len(set(names)) == len({str(n).lower() for n in names})
    return (PASS if ok else FAIL), "two upstreams exposing `echo` -> distinct, case-fold-distinct names", {"names": names}


# ====================================================================== MCP 2026-07-28 (modern) cases
def _m(c, hdr_mut=None, body_mut=None, method="tools/call", name="echo", params=None):
    p = params if params is not None else {"name": "echo", "arguments": {"x": "m"}}
    b = c.body(method, p, "modern")
    if body_mut:
        body_mut(b)
    h = dict((k, v) for k, v in c.hdr(method, "modern", name))
    if hdr_mut:
        hdr_mut(h)
    before = c.calls()
    r = c.post(b, list(h.items()))
    return r, before


def _n_reject(c, r, b, status, codes):
    bl, ev = c.blocked(r, b)
    ok = bl and r.status == status and (codes is None or r.rpc_code() in codes)
    return ok, ev


@case("N01-header-mismatch-protocol-version")
def n01(c, era):
    r, b = _m(c, hdr_mut=lambda h: h.update({"MCP-Protocol-Version": V["legacy"]}))
    ok, ev = _n_reject(c, r, b, 400, (-32020, -32001))
    return (PASS if ok else FAIL), "MCP-Protocol-Version header != _meta -> 400 HeaderMismatch(-32020), 0 handler calls", ev


@case("N02-missing-mcp-method-header")
def n02(c, era):
    r, b = _m(c, hdr_mut=lambda h: h.pop("Mcp-Method", None))
    ok, ev = _n_reject(c, r, b, 400, (-32020,))
    return (PASS if ok else FAIL), "missing Mcp-Method -> 400 -32020, 0 handler calls", ev


@case("N03-mcp-name-mismatch")
def n03(c, era):
    r, b = _m(c, hdr_mut=lambda h: h.update({"Mcp-Name": "other"}))
    ok, ev = _n_reject(c, r, b, 400, (-32020,))
    return (PASS if ok else FAIL), "Mcp-Name != params.name -> 400 -32020, 0 handler calls", ev


@case("N04-unsupported-protocol-version")
def n04(c, era):
    def hm(h):
        h["MCP-Protocol-Version"] = "2099-01-01"

    def bm(b):
        b["params"]["_meta"][META_PV] = "2099-01-01"
    r, b = _m(c, hdr_mut=hm, body_mut=bm)
    ok, ev = _n_reject(c, r, b, 400, (-32022, -32004))
    ev["lists_supported"] = V["modern"] in r.text
    ok = ok and ev["lists_supported"]
    return (PASS if ok else FAIL), "unknown version -> 400 UnsupportedProtocolVersion(-32022) listing supported, 0 handler calls", ev


@case("N05-no-session-id-issued")
def n05(c, era):
    r, b = _m(c)
    sidh = r.headers.get("mcp-session-id")
    ok = r.status == 200 and not sidh
    return (PASS if ok else FAIL), "200 and no Mcp-Session-Id header", {"status": r.status, "session_header": sidh}


@case("N06-removed-ping")
def n06(c, era):
    r, b = _m(c, method="ping", name=None, params={})
    ok, ev = _n_reject(c, r, b, 404, (-32601,))
    return (PASS if ok else FAIL), "ping -> 404 + -32601, 0 handler calls", ev


@case("N07-get-endpoint-removed")
def n07(c, era):
    h = [kv for kv in c.hdr("subscriptions/listen", "modern") if kv[0].lower() != "content-type"]
    h = [(k, ("text/event-stream" if k.lower() == "accept" else v)) for k, v in h]
    b = c.calls()
    r = c.req("GET", c.url, h)
    ev = dict(r.ev(), handler_invocations=c.calls() - b)
    ok = r.status in (405, 404, 400) and ev["handler_invocations"] == 0
    return (PASS if ok else FAIL), "GET -> 405/404 (no standalone stream), 0 handler calls", ev


@case("N08-initialize-under-modern")
def n08(c, era):
    r, b = _m(c, method="initialize", name=None, params={"protocolVersion": V["legacy"], "capabilities": {},
                                                         "clientInfo": {"name": "x", "version": "1"}})
    ok, ev = _n_reject(c, r, b, 404, (-32601,))
    ev["sid"] = r.headers.get("mcp-session-id")
    ok = ok and not ev["sid"]
    return (PASS if ok else FAIL), "initialize under 2026-07-28 -> 404 + -32601, no session, 0 handler calls", ev


@case("N09-simple-request-cannot-reach-modern")
def n09(c, era):
    body = c.body("tools/call", {"name": "echo", "arguments": {"x": "csrf"}}, "modern")
    b = c.calls()
    r = c.post(json.dumps(body), [("Content-Type", "text/plain"), ("Origin", "http://evil.example")])
    ok, ev = c.blocked(r, b)
    return (PASS if ok else FAIL), "text/plain without MCP headers -> 4xx (400/403/415), 0 handler calls", ev


@case("N10-delete-session-legacy")
def n10(c, era):
    sid = c.session(era)
    if not sid:
        return FAIL, "legacy initialize must mint a session id", {}
    h = [kv for kv in c.hdr("x", era, sid=sid) if kv[0].lower() != "content-type"]
    d = c.req("DELETE", c.url, h)
    b = c.calls()
    r2 = c.echo("x", era, sid)
    ev = {"delete": d.status, "reuse": r2.status, "handler_invocations_on_reuse": c.calls() - b}
    ok = d.status in (200, 202, 204) and r2.status == 404 and ev["handler_invocations_on_reuse"] == 0
    return (PASS if ok else FAIL), "DELETE ends the session; reuse -> 404, 0 handler calls", ev


# ====================================================================== runner
def baseline(c, era):
    sid = c.session(era)
    b = c.calls()
    r = c.echo("base", era, sid)
    ok = r.status == 200 and "base" in r.text and c.calls() > b
    return ok, dict(r.ev(), handler_invocations=c.calls() - b, sid=bool(sid))


def run_corpus(c, quiet=False):
    """Returns (ok, results, lines)."""
    lines, results = [], []
    base_ok = True
    for era in ("legacy", "modern"):
        ok, ev = baseline(c, era)
        base_ok &= ok
        lines.append("BASELINE %-6s %s %s" % (era, "PASS" if ok else "FAIL", json.dumps(ev)[:160]))
    flood_last = ("session-table-bound", "cache-bound")
    order = [x for x in CORPUS["cases"] if x["id"] not in flood_last] + \
            [x for x in CORPUS["cases"] if x["id"] in flood_last]
    for meta in order:
        cid = meta["id"]
        f = CASES.get(cid)
        for era in meta["eras"]:
            if f is None:
                v, exp, ev = NA, meta["executable"], {}
            else:
                try:
                    v, exp, ev = f(c, era)
                except Exception as e:
                    v, exp, ev = FAIL, "oracle/subject exception", {"exc": repr(e)[:200]}
            results.append({"case": cid, "era": era, "verdict": v, "set": meta["set"], "expect": exp, "evidence": ev,
                            "executable": meta["executable"]})
            lines.append("%-4s %-40s %-6s %s" % (v, cid, era, (json.dumps(ev, default=str)[:150] if v != NA else exp[:110])))
    by_case = {}
    for r in results:
        by_case.setdefault(r["case"], []).append(r["verdict"])
    fails = sorted(k for k, vs in by_case.items() if FAIL in vs)
    required_na = sorted(r["case"] for r in results if r["executable"] == "yes" and r["verdict"] == NA)
    ok = base_ok and not fails and not required_na
    if not quiet:
        print("\n".join(lines))
    return ok, results, lines, base_ok, fails, required_na


def summarize(results):
    by_case = {}
    for r in results:
        by_case.setdefault(r["case"], (r["set"], []))[1].append(r["verdict"])
    def agg(vs):
        return FAIL if FAIL in vs else (PASS if PASS in vs else NA)
    s = {"executed": 0, "pass": 0, "fail": 0, "na": 0, "adv_exec": 0, "adv_pass": 0}
    for cid, (st, vs) in by_case.items():
        a = agg(vs)
        s["na" if a == NA else "executed"] += 1
        if a == PASS:
            s["pass"] += 1
        if a == FAIL:
            s["fail"] += 1
        if st == "advisory-33" and a != NA:
            s["adv_exec"] += 1
            s["adv_pass"] += a == PASS
    s["total"] = len(by_case)
    return s


# ====================================================================== self-test
EXPECT_CATCH = {
    "no-audience-check": "token-wrong-audience-401", "wildcard-origin": "no-wildcard-cors",
    "pass-unknown-version": "N04-unsupported-protocol-version", "no-host-check": "host-allowlist-required",
    "ignore-sec-fetch-site": "absent-origin-fail-closed", "allow-unauthenticated": "unauth-listener-refused",
    "no-content-type-check": "policy-fail-closed", "no-body-cap": "body-cap-413", "json-last-wins": "json-dup-nul-reject",
    "accept-bom": "json-bom-reject", "fail-open-on-parse-error": "amplification-bound",
    "case-insensitive-keys": "json-case-variant-reject", "no-header-body-consistency": "N01-header-mismatch-protocol-version",
    "legacy-methods-under-modern": "N06-removed-ping", "unbound-sessions": "session-principal-binding",
    "forward-authorization": "token-passthrough", "follow-redirect": "redirect-strip-headers",
    "raw-merge-tool-names": "toolname-collision", "reject-everything": "BASELINE",
}


def self_test(args):
    TOY = _load("toy_gateway")
    b_up = MOCK.MockUpstream().start()
    a_up = MOCK.MockUpstream(redirect_to=b_up.url).start()
    rows, all_ok = [], True

    def run_gw(flaws):
        gw = TOY.ToyGateway(a_up.url, flaws).start()
        try:
            c = make_ctx(gw.base + "/mcp", a_up, b_up, gw.base + "/mcp2", gw.base + "/mcp-redir", gw.base + "/mcp-multi",
                         None, args.flood_n)
            return run_corpus(c, quiet=True)
        finally:
            gw.stop()
    try:
        ok, res, lines, base_ok, fails, req_na = run_gw(set())
        s = summarize(res)
        if args.verbose:
            print("\n".join(lines))
        rows.append(("strict toy gateway (must PASS)", ok, "executed=%d pass=%d fail=%d na=%d fails=%s required_na=%s"
                     % (s["executed"], s["pass"], s["fail"], s["na"], fails, req_na)))
        all_ok &= ok
        ok, res, lines, base_ok, fails, _ = run_gw(set(TOY.LENIENT))
        caught = not ok
        rows.append(("lenient toy gateway %s (must FAIL)" % "+".join(sorted(TOY.LENIENT)), caught, "failing=%s" % fails))
        all_ok &= caught
        for flaw in TOY.FLAWS:
            ok, res, lines, base_ok, fails, _ = run_gw({flaw})
            want = EXPECT_CATCH[flaw]
            hit = (not base_ok) if want == "BASELINE" else (want in fails)
            caught = (not ok) and hit
            rows.append(("flaw %s" % flaw, caught, "expected %s; failing=%s%s" % (want, fails[:6], "" if base_ok else " baseline=FAIL")))
            all_ok &= caught
    finally:
        a_up.stop()
        b_up.stop()
    for name, okk, detail in rows:
        print("  %-62s %s  %s" % (name, "ok" if okk else "MISSED", detail[:150]))
    n = sum(1 for _, okk, _ in rows if okk)
    if all_ok:
        print("%s SELF-TEST: PASS (%d/%d: strict toy passes; lenient toy and %d single-flaw toys each fail on the "
              "expected case)" % (NAME, n, len(rows), len(TOY.FLAWS)))
        return 0
    print("%s SELF-TEST: FAIL (%d/%d)" % (NAME, n, len(rows)))
    return 1


def make_ctx(url, a_up, b_up, url2, url_redir, url_multi, pid, flood_n, counter_url=None):
    if counter_url:
        def counter():
            r = http.client.HTTPConnection(urllib.parse.urlsplit(counter_url).hostname,
                                           urllib.parse.urlsplit(counter_url).port, timeout=10)
            try:
                r.request("GET", urllib.parse.urlsplit(counter_url).path or "/")
                return int(json.loads(r.getresponse().read())["count"])
            finally:
                r.close()
        c = Ctx(url, counter, url2, url_redir, url_multi, pid, flood_n, None)
        c.records_b = lambda: []
        return c
    c = Ctx(url, lambda: a_up.count() + b_up.count(), url2, url_redir, url_multi, pid, flood_n, a_up.snapshot)
    c.records_b = b_up.snapshot
    return c


def main():
    ap = argparse.ArgumentParser(prog="oracles/mcp-corpus/run", description=__doc__)
    ap.add_argument("--subject", help="gateway route URL (loopback), configured per corpus.json profile")
    ap.add_argument("--upstream-port", type=int, default=0, help="port for the mock upstream the gateway forwards to")
    ap.add_argument("--redirect-target-port", type=int, default=0, help="port for origin B (redirect target)")
    ap.add_argument("--counter-url", help="instead of the mock: GET returns {\"count\": n} handler invocations")
    ap.add_argument("--subject-url2")
    ap.add_argument("--subject-redir-url")
    ap.add_argument("--subject-multi-url")
    ap.add_argument("--subject-pid", type=int)
    ap.add_argument("--flood-n", type=int, default=20000)
    ap.add_argument("--wait", type=float, default=0.0, help="seconds to wait after starting the mock (start the gateway)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--json-out", help="write per-case results here")
    args = ap.parse_args()
    if args.self_test:
        return self_test(args)
    b_up = MOCK.MockUpstream(args.redirect_target_port).start()
    a_up = MOCK.MockUpstream(args.upstream_port, redirect_to=b_up.url).start()
    gw = None
    if not args.subject:
        # contract: until the Rust gateway exists, run against the reference model (the strict toy gateway)
        gw = _load("toy_gateway").ToyGateway(a_up.url).start()
        args.subject = gw.base + "/mcp"
        args.subject_url2, args.subject_redir_url, args.subject_multi_url = (gw.base + "/mcp2", gw.base + "/mcp-redir",
                                                                             gw.base + "/mcp-multi")
    print("mock upstream %s (redirect route: %s/redir, multiplex: %s/a %s/b); origin B %s"
          % (a_up.url, a_up.url, a_up.url, a_up.url, b_up.url), file=sys.stderr)
    if args.wait:
        time.sleep(args.wait)
    try:
        c = make_ctx(args.subject, a_up, b_up, args.subject_url2, args.subject_redir_url, args.subject_multi_url,
                     args.subject_pid, args.flood_n, args.counter_url)
        ok, res, lines, base_ok, fails, req_na = run_corpus(c)
    finally:
        a_up.stop()
        b_up.stop()
        if gw:
            gw.stop()
    s = summarize(res)
    who = "subject=strict-toy-reference" if gw else "subject=%s" % args.subject
    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(res, f, indent=1, default=str)
    detail = who + " cases=%d executed=%d pass=%d fail=%d na=%d advisory-33 executed=%d pass=%d baseline=%s" % (
        s["total"], s["executed"], s["pass"], s["fail"], s["na"], s["adv_exec"], s["adv_pass"], "ok" if base_ok else "FAIL")
    if ok:
        print("%s: PASS (%s)" % (NAME, detail))
        return 0
    print("%s: FAIL (%s failing=%s required_but_NA=%s)" % (NAME, detail, fails, req_na))
    return 1


if __name__ == "__main__":
    sys.exit(main())
