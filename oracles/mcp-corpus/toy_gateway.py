"""In-process toy MCP gateways for the mcp-corpus self-test (stdlib http.server, 127.0.0.1, ephemeral ports).

`ToyGateway(upstream_url, flaws=set())` with no flaws is the STRICT gateway: it implements the listener-gate profile of
corpus.json (ARCHITECTURE 3.9): Host and Origin allowlists, Sec-Fetch-Site / ambient-cookie rule, application/json
only, body cap, HS256 bearer with iss/aud/exp/nbf, one strict JSON parse (no BOM, no duplicate or NUL names, depth
cap, no non-finite numbers), exact JSON-RPC shape, both MCP eras (2025-11-25 sessions bound to principal+route;
2026-07-28 stateless with MCP-Protocol-Version/Mcp-Method/Mcp-Name/_meta consistency), method allowlist, namespaced
multiplexed tool names, its own upstream credential (never the client's), no redirect following. It exists to show
the oracle is satisfiable; it is not AEGIS.

Each name in FLAWS removes or weakens exactly one of those checks, so the self-test can show that every check is
observed by at least one corpus case.
"""
import base64
import hashlib
import hmac
import http.client
import http.server
import json
import threading
import time
import urllib.parse
import uuid

SECRET = b"aegis-oracle-test-secret-NOT-FOR-PRODUCTION"
ISS = "https://issuer.oracle.test"
V_LEGACY, V_MODERN = "2025-11-25", "2026-07-28"
META_PV = "io.modelcontextprotocol/protocolVersion"
BODY_CAP = 1 << 20
MAX_DEPTH = 64
UPSTREAM_CRED = "Bearer gw-upstream-credential"
LEGACY_METHODS = {"initialize", "notifications/initialized", "ping", "tools/list", "tools/call", "resources/list",
                  "prompts/list", "notifications/cancelled"}
MODERN_METHODS = {"tools/list", "tools/call", "resources/list", "prompts/list", "notifications/cancelled"}
NAMED = {"tools/call"}

FLAWS = {
    "no-audience-check": "accepts a validly signed token for any audience (or none)",
    "wildcard-origin": "no Origin validation; Access-Control-Allow-Origin: *",
    "pass-unknown-version": "forwards requests with an unsupported MCP-Protocol-Version",
    "no-host-check": "no Host allowlist",
    "ignore-sec-fetch-site": "absent Origin accepted with Sec-Fetch-Site: cross-site / ambient cookie",
    "allow-unauthenticated": "no Authorization header -> anonymous principal",
    "no-content-type-check": "any Content-Type is parsed as JSON",
    "no-body-cap": "reads and forwards bodies of any size",
    "json-last-wins": "duplicate and NUL member names accepted (last wins)",
    "accept-bom": "strips a UTF-8 BOM instead of rejecting",
    "fail-open-on-parse-error": "forwards the raw body when the strict parse fails",
    "case-insensitive-keys": "lowercases JSON-RPC member names and method",
    "no-header-body-consistency": "skips Mcp-Method/Mcp-Name/_meta vs header checks",
    "legacy-methods-under-modern": "serves initialize/ping/GET stream and issues session ids under 2026-07-28",
    "unbound-sessions": "legacy session ids not bound to principal or route",
    "forward-authorization": "forwards the client's Authorization/Cookie/X-Api-Key upstream",
    "follow-redirect": "follows upstream redirects with the same headers",
    "raw-merge-tool-names": "multiplexed tools/list merges names without namespacing",
    "reject-everything": "403 on every request (negative control for the baseline)",
}
LENIENT = {"no-audience-check", "wildcard-origin", "pass-unknown-version"}


def b64url_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class _Reject(Exception):
    def __init__(self, status, code=None, msg="", data=None, headers=()):
        super().__init__(msg)
        self.status, self.code, self.msg, self.data, self.headers = status, code, msg, data, headers


def depth_ok(s, maxd):
    d, in_str, esc = 0, False, False
    for ch in s:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            d += 1
            if d > maxd:
                return False
        elif ch in "]}":
            d -= 1
    return True


def strict_json(text, flaws):
    if text.startswith("﻿"):
        if "accept-bom" in flaws:
            text = text[1:]
        else:
            raise ValueError("BOM")
    if not depth_ok(text, MAX_DEPTH):
        raise ValueError("too deep")

    def hook(kv):
        if "json-last-wins" not in flaws:
            ks = [k for k, _ in kv]
            if len(ks) != len(set(ks)) or any("\x00" in k for k in ks):
                raise ValueError("duplicate/NUL name")
        return dict(kv)

    def pf(x):
        f = float(x)
        if f in (float("inf"), float("-inf")) or f != f:
            raise ValueError("non-finite")
        return f

    def pc(x):
        raise ValueError("constant " + x)
    return json.loads(text, object_pairs_hook=hook, parse_float=pf, parse_constant=pc)


class ToyGateway:
    def __init__(self, upstream_url, flaws=()):
        unknown = set(flaws) - set(FLAWS)
        if unknown:
            raise ValueError("unknown flaws %s" % unknown)
        self.flaws = set(flaws)
        self.upstream = upstream_url.rstrip("/")
        self.sessions = {}
        self.lock = threading.Lock()
        gw = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def handle_one_request(self):
                try:
                    super().handle_one_request()
                except (ConnectionError, OSError):
                    self.close_connection = True

            def do_POST(self):
                gw.handle(self, "POST")

            def do_GET(self):
                gw.handle(self, "GET")

            def do_DELETE(self):
                gw.handle(self, "DELETE")

            def do_OPTIONS(self):
                gw.handle(self, "OPTIONS")

            def do_PUT(self):
                gw.handle(self, "PUT")

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.base = "http://127.0.0.1:%d" % self.port
        self.routes = {"/mcp": {"up": [("", "/")]}, "/mcp2": {"up": [("", "/")]},
                       "/mcp-redir": {"up": [("", "/redir")]}, "/mcp-multi": {"up": [("a__", "/a"), ("b__", "/b")]}}
        self.allowed_hosts = {"127.0.0.1:%d" % self.port, "localhost:%d" % self.port}
        self.allowed_origins = {"http://127.0.0.1:%d" % self.port, "http://localhost:%d" % self.port}
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    # ------------------------------------------------------------ helpers
    def reply(self, h, status, obj=None, headers=(), close=False):
        data = b"" if obj is None else json.dumps(obj).encode()
        h.send_response(status)
        for k, v in headers:
            h.send_header(k, v)
        if obj is not None:
            h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(data)))
        if close:
            h.send_header("Connection", "close")
            h.close_connection = True
        h.end_headers()
        if h.command != "HEAD":
            h.wfile.write(data)

    def rpc_err(self, id_, code, msg, data=None):
        e = {"code": code, "message": msg}
        if data is not None:
            e["data"] = data
        return {"jsonrpc": "2.0", "id": id_, "error": e}

    def verify_token(self, authz, route_url):
        if not authz:
            if "allow-unauthenticated" in self.flaws:
                return "anonymous"
            raise _Reject(401, msg="no token", headers=[("WWW-Authenticate", 'Bearer resource_metadata="%s"' % route_url)])
        if not authz.startswith("Bearer "):
            raise _Reject(401, msg="scheme")
        tok = authz[7:]
        try:
            hs, ps, ss = tok.split(".")
            hdr, pay = json.loads(b64url_dec(hs)), json.loads(b64url_dec(ps))
            sig = b64url_dec(ss)
        except Exception:
            raise _Reject(401, msg="malformed token")
        if not isinstance(hdr, dict) or hdr.get("alg") != "HS256":
            raise _Reject(401, msg="alg")
        good = hmac.new(SECRET, (hs + "." + ps).encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(good, sig):
            raise _Reject(401, msg="signature")
        now = time.time()
        if not isinstance(pay, dict) or pay.get("iss") != ISS or not isinstance(pay.get("sub"), str):
            raise _Reject(401, msg="iss/sub")
        if not isinstance(pay.get("exp"), (int, float)) or pay["exp"] <= now:
            raise _Reject(401, msg="expired")
        if "nbf" in pay and (not isinstance(pay["nbf"], (int, float)) or pay["nbf"] > now):
            raise _Reject(401, msg="nbf")
        if "no-audience-check" not in self.flaws:
            aud = pay.get("aud")
            if not (aud == route_url or (isinstance(aud, list) and route_url in aud)):
                raise _Reject(401, msg="audience")
        return pay["sub"]

    def forward(self, path, body, client_headers):
        u = urllib.parse.urlsplit(self.upstream + path)
        hdrs = {"Content-Type": "application/json", "Accept": "application/json", "Authorization": UPSTREAM_CRED}
        if "forward-authorization" in self.flaws:
            for k in ("Authorization", "Cookie", "X-Api-Key"):
                if client_headers.get(k):
                    hdrs[k] = client_headers.get(k)
        for _hop in range(3):
            c = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
            try:
                c.request("POST", u.path or "/", body=body, headers=hdrs)
                r = c.getresponse()
                data = r.read()
                loc = r.getheader("Location")
                st = r.status
            finally:
                c.close()
            if 300 <= st < 400:
                if "follow-redirect" in self.flaws and loc:
                    u = urllib.parse.urlsplit(loc)
                    continue
                raise _Reject(502, -32603, "upstream redirect not followed")
            return st, data
        raise _Reject(502, -32603, "redirect loop")

    # ------------------------------------------------------------ main gate
    def handle(self, h, method):
        try:
            self._handle(h, method)
        except _Reject as e:
            body = None
            if e.code is not None:
                body = self.rpc_err(None, e.code, e.msg, e.data)
            self.reply(h, e.status, body, e.headers, close=True)

    def _handle(self, h, method):
        f = self.flaws
        hd = h.headers
        if "reject-everything" in f:
            raise _Reject(403)
        path = urllib.parse.urlsplit(h.path).path
        route = self.routes.get(path)
        if route is None:
            raise _Reject(404)
        route_url = self.base + path
        hosts = hd.get_all("Host") or []
        if "no-host-check" not in f and (len(hosts) != 1 or hosts[0].lower() not in self.allowed_hosts):
            raise _Reject(421, msg="host")
        origin = hd.get("Origin")
        cors = []
        if "wildcard-origin" in f:
            cors = [("Access-Control-Allow-Origin", "*")]
        else:
            if origin is not None and origin not in self.allowed_origins:
                raise _Reject(403, msg="origin")
            if origin is None and "ignore-sec-fetch-site" not in f:
                if (hd.get("Sec-Fetch-Site") or "").lower() == "cross-site":
                    raise _Reject(403, msg="cross-site")
                if hd.get("Cookie") and not hd.get("Authorization"):
                    raise _Reject(403, msg="ambient cookie without bearer")
            if origin is not None:
                cors = [("Access-Control-Allow-Origin", origin), ("Vary", "Origin")]
        if method == "OPTIONS":
            return self.reply(h, 204, None, cors + [("Access-Control-Allow-Methods", "POST"),
                                                    ("Access-Control-Allow-Headers", "content-type, authorization, mcp-protocol-version, mcp-method, mcp-name, mcp-session-id")])
        pv_hdr = hd.get("MCP-Protocol-Version")
        if method == "GET":
            if "legacy-methods-under-modern" in f:
                return self.reply(h, 200, {"stream": "stub"}, cors)
            raise _Reject(405, msg="no standalone stream", headers=[("Allow", "POST, DELETE")])
        if method == "DELETE":
            sub = self.verify_token(hd.get("Authorization"), route_url)
            sid = hd.get("Mcp-Session-Id")
            with self.lock:
                s = self.sessions.get(sid)
                if s and (s == (sub, path) or "unbound-sessions" in f):
                    del self.sessions[sid]
                    return self.reply(h, 204, None, cors)
            raise _Reject(404, msg="no such session")
        if method != "POST":
            raise _Reject(405)
        ctype = (hd.get("Content-Type") or "").split(";")[0].strip().lower()
        if "no-content-type-check" not in f and ctype != "application/json":
            raise _Reject(415, msg="content-type")
        if hd.get("Transfer-Encoding"):
            raise _Reject(411, msg="length required")
        try:
            n = int(hd.get("Content-Length") or "x")
        except ValueError:
            raise _Reject(411, msg="length required")
        if n > BODY_CAP and "no-body-cap" not in f:
            raise _Reject(413, msg="body too large")
        sub = self.verify_token(hd.get("Authorization"), route_url)
        raw = h.rfile.read(n)
        try:
            text = raw.decode("utf-8")
            msg = strict_json(text, f)
        except (ValueError, UnicodeDecodeError, RecursionError):
            if "fail-open-on-parse-error" in f:
                st, data = self.forward(route["up"][0][1], raw, hd)
                h.send_response(st)
                h.send_header("Content-Length", str(len(data)))
                h.end_headers()
                h.wfile.write(data)
                return
            raise _Reject(400, -32700, "parse error")
        if "case-insensitive-keys" in f and isinstance(msg, dict):
            msg = {k.lower(): v for k, v in msg.items()}
            if isinstance(msg.get("method"), str):
                msg["method"] = msg["method"].lower()
        if (not isinstance(msg, dict) or set(msg) - {"jsonrpc", "id", "method", "params"} or msg.get("jsonrpc") != "2.0"
                or not isinstance(msg.get("method"), str)
                or ("id" in msg and not isinstance(msg["id"], (str, int)))
                or not isinstance(msg.get("params", {}), dict)):
            raise _Reject(400, -32600, "invalid request")
        rid, meth, params = msg.get("id"), msg["method"], msg.get("params", {})
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        body_pv = meta.get(META_PV)
        supported = [V_LEGACY, V_MODERN]
        for v in (pv_hdr, body_pv):
            if v is not None and v not in supported and "pass-unknown-version" not in f:
                raise _Reject(400, -32022, "unsupported protocol version", {"supported": supported})
        if body_pv is not None and pv_hdr != body_pv and "no-header-body-consistency" not in f:
            raise _Reject(400, -32020, "header mismatch: MCP-Protocol-Version")
        era = "modern" if (pv_hdr == V_MODERN or (pv_hdr not in (None, V_LEGACY))) else "legacy"
        extra = list(cors)
        if era == "modern":
            if "no-header-body-consistency" not in f:
                if hd.get("Mcp-Method") != meth:
                    raise _Reject(400, -32020, "header mismatch: Mcp-Method")
                if meth in NAMED and hd.get("Mcp-Name") != params.get("name"):
                    raise _Reject(400, -32020, "header mismatch: Mcp-Name")
                if body_pv is None:
                    raise _Reject(400, -32020, "header mismatch: _meta protocolVersion missing")
            allowed = MODERN_METHODS | (LEGACY_METHODS if "legacy-methods-under-modern" in f else set())
            if meth not in allowed:
                raise _Reject(404, -32601, "method not found")
            if "legacy-methods-under-modern" in f:
                extra.append(("Mcp-Session-Id", uuid.uuid4().hex))
        else:
            if meth not in LEGACY_METHODS:
                raise _Reject(404, -32601, "method not found")
            if meth == "initialize":
                sid = uuid.uuid4().hex
                with self.lock:
                    if len(self.sessions) >= 10000:
                        raise _Reject(503, -32603, "session table full")
                    self.sessions[sid] = (sub, path)
                extra.append(("Mcp-Session-Id", sid))
            else:
                sid = hd.get("Mcp-Session-Id")
                if not sid:
                    raise _Reject(400, -32600, "missing session")
                with self.lock:
                    s = self.sessions.get(sid)
                if s is None or (s != (sub, path) and "unbound-sessions" not in f):
                    raise _Reject(404, -32600, "unknown session")
        if meth == "tools/call" and not isinstance(params.get("name"), str):
            raise _Reject(400, -32602, "invalid params")
        ups = route["up"]
        if meth == "tools/list" and len(ups) > 1:
            names = []
            for pre, up in ups:
                st, data = self.forward(up, json.dumps(msg).encode(), hd)
                for t in json.loads(data).get("result", {}).get("tools", []):
                    names.append(dict(t, name=(t["name"] if "raw-merge-tool-names" in f else pre + t["name"])))
            return self.reply(h, 200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": names}}, extra)
        target = ups[0][1]
        if meth == "tools/call" and len(ups) > 1:
            for pre, up in ups:
                if params["name"].startswith(pre):
                    target = up
                    msg = dict(msg, params=dict(params, name=params["name"][len(pre):]))
                    break
            else:
                raise _Reject(404, -32602, "unknown tool")
        st, data = self.forward(target, json.dumps(msg).encode(), hd)
        if st == 202 or not data:
            return self.reply(h, 202, None, extra)
        try:
            obj = json.loads(data)
        except ValueError:
            raise _Reject(502, -32603, "bad upstream reply")
        return self.reply(h, 200 if st == 200 else 502, obj, extra)



if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="standalone toy gateway (for exercising `run --subject URL`)")
    ap.add_argument("--upstream", required=True, help="mock upstream base URL, e.g. http://127.0.0.1:18080")
    ap.add_argument("--flaws", default="", help="comma-separated names from FLAWS")
    a = ap.parse_args()
    if not a.upstream.startswith("http://127.0.0.1:"):
        raise SystemExit("loopback upstream only")
    gw = ToyGateway(a.upstream, [x for x in a.flaws.split(",") if x]).start()
    print("LISTENING %s/mcp" % gw.base, flush=True)
    gw.thread.join()
