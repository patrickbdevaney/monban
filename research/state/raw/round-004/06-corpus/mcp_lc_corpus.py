#!/usr/bin/env python3
"""AEGIS MCP listener/gateway conformance corpus (MCP-LC), black-box, LOCAL targets only.
Cases 1..33 = keys of r2 node l5.conformance-manifest (same names); N* = added for MCP spec 2026-07-28.
Usage: mcp_lc_corpus.py targets.json out_dir [target_name ...]
Verdicts: PASS / FAIL / WARN (accepted-but-handler-not-invoked or partial) / NA (not testable black-box here) / ERR (baseline failed).
SAFETY: refuses any non-loopback target host.
"""
import json, sys, os, time, threading, subprocess, re, socket, struct, concurrent.futures as cf
import httpx

M_REJ = (400, 401, 403, 404, 405, 406, 413, 415, 421, 422)
REJECT = {400, 401, 403, 404, 405, 406, 411, 413, 415, 421, 422, 431}
ENV_LEGACY = "2025-11-25"; ENV_MODERN = "2026-07-28"
META_PV = "io.modelcontextprotocol/protocolVersion"; META_CC = "io.modelcontextprotocol/clientCapabilities"

class Ctx:
    def __init__(s, t, era, logf):
        s.t, s.era, s.logf = t, era, logf
        u = httpx.URL(t["url"]); assert u.host in ("127.0.0.1", "localhost", "::1"), "loopback only"
        s.host, s.port, s.path = u.host, u.port, u.path or "/"
        s.client = httpx.Client(timeout=httpx.Timeout(20.0), http1=True, verify=False, limits=httpx.Limits(max_connections=200))
        s.n = 0
    def log(s, kind, obj): s.logf.write(json.dumps({"k": kind, **obj}, default=str)[:6000] + "\n"); s.logf.flush()
    def calls(s):
        f = s.t.get("counter")
        if not f or not os.path.exists(f): return 0 if f else None
        return sum(1 for _ in open(f))
    # ---- body builders
    def body(s, method, params=None, id_=None, era=None):
        era = era or s.era; s.n += 1
        p = dict(params or {})
        if era == "modern": p["_meta"] = {META_PV: ENV_MODERN, META_CC: {}}
        return {"jsonrpc": "2.0", "id": id_ if id_ is not None else s.n, "method": method, "params": p}
    def hdr(s, method, name=None, era=None, extra=None, sid=None, auth=True):
        era = era or s.era
        h = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
        if era == "modern":
            h.update({"MCP-Protocol-Version": ENV_MODERN, "Mcp-Method": method})
            if name: h["Mcp-Name"] = name
        else:
            h["MCP-Protocol-Version"] = ENV_LEGACY
            if sid: h["Mcp-Session-Id"] = sid
        if auth and s.t.get("bearer"): h["Authorization"] = "Bearer " + s.t["bearer"]
        if extra: h.update({k: v for k, v in extra.items() if v is not None})
        for k, v in (extra or {}).items():
            if v is None: h.pop(k, None)
        return h
    def post(s, content, headers, url=None, tag=""):
        url = url or s.t["url"]
        try:
            r = s.client.post(url, content=content if isinstance(content, (bytes, str)) else json.dumps(content), headers=headers)
            out = {"status": r.status_code, "headers": dict(r.headers), "text": r.text[:1500]}
        except Exception as e:
            out = {"status": None, "err": repr(e)[:300], "headers": {}, "text": ""}
        s.log("req", {"tag": tag, "url": url, "h": headers, "body": (content if isinstance(content, str) else (content[:400].decode("latin1") if isinstance(content, bytes) else json.dumps(content)))[:500], "resp": out})
        return out
    def parse(s, r):
        txt = r.get("text", "")
        m = re.search(r"data: (\{.*\})", txt)
        try: return json.loads(m.group(1) if m else txt)
        except Exception: return None
    def session(s):
        """legacy: initialize + initialized; returns session id (or None for stateless). modern: None"""
        if s.era == "modern": return None
        r = s.post(s.body("initialize", {"protocolVersion": ENV_LEGACY, "capabilities": {}, "clientInfo": {"name": "lc", "version": "1"}}), s.hdr("initialize"), tag="init")
        sid = r["headers"].get("mcp-session-id")
        if r["status"] == 200:
            s.post({"jsonrpc": "2.0", "method": "notifications/initialized"}, s.hdr("notifications/initialized", sid=sid), tag="initialized")
        return sid if r["status"] == 200 else "INIT_FAIL"
    def echo(s, x, sid=None, extra=None, tag="echo", content_type=None, id_=None):
        tn, ta = s.t.get("tool", ["echo", "x"])
        b = s.body("tools/call", {"name": tn, "arguments": {ta: x}}, id_=id_)
        h = s.hdr("tools/call", tn, sid=sid, extra=extra)
        if content_type: h["content-type"] = content_type
        return s.post(b, h, tag=tag)
    def blocked(s, r, before):
        """True if the request did not reach a tool handler and was refused (4xx or JSON-RPC error)."""
        after = s.calls()
        reached = (after is not None and before is not None and after > before)
        st = r.get("status")
        j = s.parse(r)
        err = (st in REJECT) or (st is None) or (isinstance(j, dict) and "error" in j)
        return (not reached) and err, reached, st
    def rss(s):
        pid = s.t.get("pid_port") and pid_of_port(s.t["pid_port"])
        if not pid: return None
        try:
            for l in open(f"/proc/{pid}/status"):
                if l.startswith("VmRSS"): return int(l.split()[1]) // 1  # kB
        except Exception: return None

def pid_of_port(port):
    out = subprocess.run(["ss", "-ltnpH", f"sport = :{port}"], capture_output=True, text=True).stdout
    m = re.search(r"pid=(\d+)", out); return int(m.group(1)) if m else None

def bind_addr(port):
    out = subprocess.run(["ss", "-ltnH", f"sport = :{port}"], capture_output=True, text=True).stdout.split()
    return out[3] if len(out) > 3 else None

R = lambda v, expect, ev, basis: (v, expect, ev, basis)
CASES = []
def case(key, basis, eras=("legacy", "modern")):
    def d(f): CASES.append((key, basis, eras, f)); return f
    return d

# ------------------------------------------------------------------ origin/host family
@case("host-allowlist-required", "SPEC-MUST(Origin)+SDK-practice(Host)")
def c_host(c):
    sid = c.session(); ev = {}
    if sid == "INIT_FAIL": return R("ERR", "baseline", "init failed", "")
    P = c.port
    variants = {
      "host-only": {"Host": "evil.example"},
      "rebind-shape(Host+Origin same evil)": {"Host": f"rebind.test:{P}", "Origin": f"http://rebind.test:{P}"},
      "origin-only": {"Origin": "http://evil.example"},
    }
    ok = {}
    for k, e in variants.items():
        b = c.calls(); r = c.echo("x", sid=sid, extra=e, tag="host-" + k); bl, reached, st = c.blocked(r, b)
        ev[k] = {"status": st, "reached_handler": reached}; ok[k] = bl
    if all(ok.values()): return R("PASS", "all 3 -> 4xx, handler untouched", ev, "")
    if ok["origin-only"] and ok["rebind-shape(Host+Origin same evil)"]: return R("WARN", "host-only not enforced; Origin enforced", ev, "")
    return R("FAIL", "all 3 -> 4xx, handler untouched", ev, "")

@case("reject-text-plain-post", "SPEC(Origin MUST)+CSRF")
def c_txt(c):
    sid = c.session(); ev = {}
    e = {"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"}
    # a browser "simple request" can only set content-type text/plain (no custom headers)
    ok = []
    for what in ("initialize", "tools/call"):
        b = c.calls()
        if what == "initialize":
            body = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": ENV_LEGACY, "capabilities": {}, "clientInfo": {"name": "x", "version": "1"}}}
        else:
            body = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "echo", "arguments": {"x": "csrf"}}}
        h = {"content-type": "text/plain;charset=UTF-8", "accept": "*/*", **e}
        if c.t.get("bearer") is None: pass
        r = c.post(json.dumps(body), h, tag="txtplain-" + what); bl, reached, st = c.blocked(r, b)
        ev[what] = {"status": st, "reached_handler": reached, "session_minted": "mcp-session-id" in r["headers"]}; ok.append(bl)
    if all(ok): return R("PASS", "text/plain cross-site POST -> 4xx, no handler/session", ev, "")
    return R("FAIL", "text/plain cross-site POST -> 4xx, no handler/session", ev, "")

@case("no-wildcard-cors", "SPEC-implied/ADVISORY")
def c_cors(c):
    ev = {}
    h = {"Origin": "http://evil.example", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type,mcp-protocol-version,mcp-method,mcp-session-id"}
    try:
        r = c.client.options(c.t["url"], headers=h); ev["preflight"] = {"status": r.status_code, "acao": r.headers.get("access-control-allow-origin"), "acah": r.headers.get("access-control-allow-headers"), "acac": r.headers.get("access-control-allow-credentials")}
    except Exception as e: ev["preflight"] = repr(e)
    sid = c.session()
    r = c.echo("x", sid=sid, extra={"Origin": "http://evil.example"}, tag="cors-post")
    ev["post"] = {"status": r["status"], "acao": r["headers"].get("access-control-allow-origin")}
    acao = [ev["preflight"].get("acao") if isinstance(ev["preflight"], dict) else None, ev["post"]["acao"]]
    if any(a in ("*", "http://evil.example") for a in acao): return R("FAIL", "no ACAO * / reflected evil origin", ev, "")
    return R("PASS", "no ACAO * / reflected evil origin", ev, "")

@case("ws-origin-check", "ADVISORY GHSA-vj7q")
def c_ws(c):
    h = {"Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==", "Origin": "http://evil.example"}
    try: r = c.client.get(c.t["url"], headers=h); st = r.status_code
    except Exception as e: st = repr(e)
    if st == 101: return R("FAIL", "no WS upgrade with evil Origin", {"status": st}, "")
    return R("NA", "no WS surface on Streamable HTTP endpoint", {"status": st}, "")

@case("host-allowlist-required;h2-authority", "ADVISORY GHSA-89vp (#827)", eras=("legacy",))
def c_h2(c):
    import h2.connection, h2.config, h2.events
    try:
        s = socket.create_connection((c.host, c.port), timeout=5)
        cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8"); conn = h2.connection.H2Connection(cfg); conn.initiate_connection(); s.sendall(conn.data_to_send())
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": ENV_LEGACY, "capabilities": {}, "clientInfo": {"name": "x", "version": "1"}}}).encode()
        def go(auth, sid_):
            hs = [(":method", "POST"), (":path", c.path), (":scheme", "http"), (":authority", auth), ("content-type", "application/json"), ("accept", "application/json, text/event-stream"), ("content-length", str(len(body)))]
            conn.send_headers(sid_, hs); conn.send_data(sid_, body, end_stream=True); s.sendall(conn.data_to_send())
        res = {}
        go(f"evil.example", 1)
        go(f"127.0.0.1:{c.port}", 3)
        s.settimeout(5); t0 = time.time()
        while time.time() - t0 < 5 and len(res) < 2:
            try: d = s.recv(65536)
            except socket.timeout: break
            if not d: break
            for ev in conn.receive_data(d):
                if isinstance(ev, h2.events.ResponseReceived): res[ev.stream_id] = dict(ev.headers).get(":status")
            s.sendall(conn.data_to_send())
        evd = {"evil_authority_status": res.get(1), "ok_authority_status": res.get(3)}
        if res.get(3) is None: return R("NA", "server speaks no h2c prior-knowledge", evd, "")
        if res.get(1) and res[1].startswith("4"): return R("PASS", "evil :authority -> 4xx", evd, "")
        return R("FAIL", "evil :authority -> 4xx", evd, "")
    except Exception as e:
        return R("NA", "h2c unavailable", repr(e)[:200], "")

@case("absent-origin-fail-closed", "AEGIS-hardening (rule 2)")
def c_abs(c):
    sid = c.session()
    b = c.calls(); r = c.echo("x", sid=sid, extra={"Cookie": "session=ambient", "Sec-Fetch-Site": "cross-site"}, tag="absent-origin")
    bl, reached, st = c.blocked(r, b)
    return R("PASS" if bl else "FAIL", "no Origin + ambient cookie + Sec-Fetch-Site cross-site -> 4xx", {"status": st, "reached": reached}, "")

# ------------------------------------------------------------------ parser family
def _parse_case(key, basis, mk):
    @case(key, basis)
    def f(c):
        sid = c.session(); ev = {}
        out = {}
        for name, (content, ctype) in mk(c).items():
            b = c.calls(); h = c.hdr("tools/call", "echo", sid=sid); h["content-type"] = ctype
            r = c.post(content, h, tag=key + ":" + name); bl, reached, st = c.blocked(r, b)
            j = c.parse(r); ev[name] = {"status": st, "reached": reached, "jsonrpc_error": (j or {}).get("error", {}).get("code") if isinstance(j, dict) else None}
            out[name] = "reached" if reached else ("blocked" if bl else "accepted-no-call")
        if any(v == "reached" for v in out.values()): return R("FAIL", "ambiguous encodings rejected before handler", ev, "")
        if any(v == "accepted-no-call" for v in out.values()): return R("WARN", "reject (accepted-without-call = parser-differential risk)", ev, "")
        return R("PASS", "all rejected", ev, "")
    return f

def _tc(c, extra_top=None):
    m = c.body("tools/call", {"name": "echo", "arguments": {"x": "p"}}); return m

def mk_case(c):
    s = json.dumps(_tc(c)).replace('"method"', '"Method"')
    return {"Method-case": (s, "application/json"), "TOOLS/CALL": (json.dumps(_tc(c)).replace("tools/call", "TOOLS/CALL"), "application/json")}
_parse_case("json-case-variant-reject", "ADVISORY GHSA-wvj2", mk_case)

def mk_dup(c):
    m = _tc(c); base = json.dumps(m)
    dup_last_call = '{"jsonrpc":"2.0","id":9,"method":"tools/list","method":"tools/call","params":' + json.dumps(m["params"]) + '}'
    dup_first_call = '{"jsonrpc":"2.0","id":9,"method":"tools/call","method":"tools/list","params":' + json.dumps(m["params"]) + '}'
    nul = base.replace('"name"', '"na\\u0000me"', 1)
    return {"dup-method(list,call)": (dup_last_call, "application/json"), "dup-method(call,list)": (dup_first_call, "application/json"), "NUL-key": (nul, "application/json")}
_parse_case("json-dup-nul-reject", "ADVISORY GHSA-q382/hxx3", mk_dup)

def mk_bom(c):
    return {"BOM": (b"\xef\xbb\xbf" + json.dumps(_tc(c)).encode(), "application/json")}
_parse_case("json-bom-reject", "ADVISORY GHSA-9v4w", mk_bom)

def mk_pol(c):
    m = _tc(c); s = json.dumps(m).replace('"name": "echo"', '"name": 1e1000')
    t = json.dumps(m); 
    return {"name=1e1000": (s, "application/json"), "ctype=text/xml-with-json": (t, "text/xml"), "ctype=none": (t, "")}
_parse_case("policy-fail-closed", "ADVISORY GHSA-vpfq/g7gq", mk_pol)

# ------------------------------------------------------------------ concurrency / id collision
@case("id-collision-two-clients", "ADVISORY GHSA-345p/jm63")
def c_idc(c):
    bad = 0; total = 0; sids = []
    def one(k):
        cc = Ctx(c.t, c.era, c.logf); sid = cc.session(); res = []
        for i in range(25):
            val = f"client{k}-{i}"
            r = cc.echo(val, sid=sid, id_=1, tag="idc"); j = cc.parse(r)
            txt = json.dumps(j)
            res.append(val in txt and (f"client{1-k}-" not in txt))
        return res
    with cf.ThreadPoolExecutor(2) as ex: out = list(ex.map(one, [0, 1]))
    flat = [x for l in out for x in l]; bad = flat.count(False)
    return R("PASS" if bad == 0 else "FAIL", "each client gets its own echo (id=1 both)", {"mismatches": bad, "of": len(flat)}, "")

# ------------------------------------------------------------------ resource bounds
@case("session-table-bound", "ADVISORY GHSA-9pj6/84m7/2hm9", eras=("legacy",))
def c_sess(c):
    N = c.t.get("flood_n", 20000); r0 = c.rss(); hist = {}
    def one(_):
        try:
            r = c.client.post(c.t["url"], json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": ENV_LEGACY, "capabilities": {}, "clientInfo": {"name": "f", "version": "1"}}}, headers=c.hdr("initialize"), timeout=5)
            return r.status_code
        except Exception as e: return "exc"
    t0 = time.time()
    with cf.ThreadPoolExecutor(50) as ex:
        for st in ex.map(one, range(N)): hist[st] = hist.get(st, 0) + 1
    dt = time.time() - t0; r1 = c.rss(); time.sleep(20); r2 = c.rss()
    ev = {"N": N, "status_hist": hist, "secs": round(dt, 1), "rss_kb_before": r0, "rss_kb_after": r1, "rss_kb_after_20s_idle": r2, "per_session_bytes_est": (round((r1 - r0) * 1024 / max(hist.get(200, 1), 1)) if r0 and r1 else None)}
    if r0 is None: return R("NA", "no pid", ev, "")
    d = (r1 - r0) / 1024
    if d < 15: return R("PASS", "RSS growth <15 MB after N unauth initialize", ev, "")
    return R("WARN", "RSS growth <15 MB after N unauth initialize (retains per-session state; check cap/TTL)", ev, "")

@case("cache-bound", "ADVISORY GHSA-4432")
def c_cache(c):
    N = c.t.get("flood_n", 20000); sid = c.session(); r0 = c.rss()
    def one(i):
        b = c.body("tools/call", {"name": f"nosuch_{i}_" + "a" * 64, "arguments": {}}); h = c.hdr("tools/call", f"nosuch_{i}", sid=sid)
        try: return c.client.post(c.t["url"], content=json.dumps(b), headers=h, timeout=5).status_code
        except Exception: return "exc"
    hist = {}
    with cf.ThreadPoolExecutor(50) as ex:
        for st in ex.map(one, range(N)): hist[st] = hist.get(st, 0) + 1
    r1 = c.rss(); ev = {"N": N, "status_hist": hist, "rss_kb_before": r0, "rss_kb_after": r1}
    if r0 is None: return R("NA", "no pid", ev, "")
    return R("PASS" if (r1 - r0) / 1024 < 15 else "WARN", "RSS growth <15 MB after N unique unknown tool calls", ev, "")

@case("body-cap-413", "ADVISORY GHSA-fmmv/4x8c/f897")
def c_body(c):
    sid = c.session(); r0 = c.rss(); ev = {}
    big = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"x":"' + b"A" * (64 * 1024 * 1024) + b'"}}}'
    b = c.calls(); t0 = time.time(); r = c.post(big, c.hdr("tools/call", "echo", sid=sid), tag="body64MB"); dt = time.time() - t0
    r1 = c.rss(); ev = {"status": r["status"], "secs": round(dt, 2), "err": r.get("err"), "rss_peak_after_kb": r1, "rss_before_kb": r0, "handler_reached": (c.calls() or 0) > (b or 0)}
    if r["status"] == 413: return R("PASS", "64 MiB body -> 413", ev, "")
    if r["status"] in REJECT or r["status"] is None: return R("WARN", "64 MiB body -> 413 (got other reject/reset)", ev, "")
    return R("FAIL", "64 MiB body -> 413", ev, "")

@case("amplification-bound", "ADVISORY GHSA-46jr")
def c_amp(c):
    sid = c.session(); r0 = c.rss()
    depth = 200000
    payload = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"x":' + '[' * depth + ']' * depth + '}}}'
    b = c.calls(); t0 = time.time(); r = c.post(payload, c.hdr("tools/call", "echo", sid=sid), tag="deepnest"); dt = time.time() - t0
    alive = c.echo("alive", sid=sid, tag="alive-after")["status"]
    alive2 = None
    if alive != 200:
        sid2 = c.session(); alive2 = c.echo("alive", sid=sid2, tag="alive-after-newsession")["status"]
    r1 = c.rss(); ev = {"depth": depth, "status": r["status"], "secs": round(dt, 2), "alive_after": alive, "alive_new_session": alive2, "rss_before_kb": r0, "rss_after_kb": r1}
    if r["status"] is None or (alive != 200 and alive2 != 200): return R("FAIL", "survives 200k-deep nesting", ev, "")
    return R("PASS", "survives 200k-deep nesting, rejects", ev, "")

@case("unauth-listener-refused", "ADVISORY GHSA-g879 (default-config)")
def c_unauth(c):
    sid = c.session() if not c.t.get("bearer") else None
    r = c.post(c.body("tools/list"), c.hdr("tools/list", auth=False, sid=sid if sid != "INIT_FAIL" else None), tag="unauth-list")
    ba = bind_addr(c.port)
    ev = {"status": r["status"], "bind": ba}
    if r["status"] in (401, 403): return R("PASS", "unauthenticated tools/list -> 401/403 by default", ev, "")
    return R("FAIL", "unauthenticated tools/list -> 401/403 by default (note: SDKs are libraries; auth is app responsibility)", ev, "")

# ------------------------------------------------------------------ modern-only (spec 2026-07-28)
def _m(c, hdr_mut=None, body_mut=None, method="tools/call", name="echo", params=None):
    p = params if params is not None else {"name": "echo", "arguments": {"x": "m"}}
    b = c.body(method, p); 
    if body_mut: body_mut(b)
    h = c.hdr(method, name)
    if hdr_mut: hdr_mut(h)
    bb = c.calls(); r = c.post(b, h, tag="N"); return r, bb

@case("N01-header-mismatch-protocol-version", "SPEC-MUST 2026-07-28 streamable-http", eras=("modern",))
def n01(c):
    r, b = _m(c, hdr_mut=lambda h: h.update({"MCP-Protocol-Version": "2025-11-25"}))
    j = c.parse(r); code = (j or {}).get("error", {}).get("code") if isinstance(j, dict) else None
    ev = {"status": r["status"], "code": code}
    return R("PASS" if r["status"] == 400 and code in (-32020, -32001) else ("WARN" if r["status"] in M_REJ else "FAIL"), "400 + HeaderMismatch(-32020); WARN=rejected with other code/status", ev, "")
@case("N02-missing-mcp-method-header", "SPEC-MUST", eras=("modern",))
def n02(c):
    r, b = _m(c, hdr_mut=lambda h: h.pop("Mcp-Method", None)); j = c.parse(r); code = (j or {}).get("error", {}).get("code") if isinstance(j, dict) else None
    return R("PASS" if r["status"] == 400 and code == -32020 else ("WARN" if (r["status"] in M_REJ and (c.calls() or 0) == (b or 0)) else "FAIL"), "400 + -32020; WARN=rejected, other code/status", {"status": r["status"], "code": code, "reached": (c.calls() or 0) > (b or 0)}, "")
@case("N03-mcp-name-mismatch", "SPEC-MUST", eras=("modern",))
def n03(c):
    r, b = _m(c, hdr_mut=lambda h: h.update({"Mcp-Name": "other"})); j = c.parse(r); code = (j or {}).get("error", {}).get("code") if isinstance(j, dict) else None
    return R("PASS" if r["status"] == 400 and code == -32020 else ("WARN" if (r["status"] in M_REJ and (c.calls() or 0) == (b or 0)) else "FAIL"), "400 + -32020; WARN=rejected, other code/status", {"status": r["status"], "code": code, "reached": (c.calls() or 0) > (b or 0)}, "")
@case("N04-unsupported-protocol-version", "SPEC-MUST", eras=("modern",))
def n04(c):
    def hm(h): h["MCP-Protocol-Version"] = "2099-01-01"
    def bm(b): b["params"]["_meta"][META_PV] = "2099-01-01"
    r, b = _m(c, hdr_mut=hm, body_mut=bm); j = c.parse(r); code = (j or {}).get("error", {}).get("code") if isinstance(j, dict) else None
    return R("PASS" if r["status"] == 400 and code in (-32022, -32004) else "FAIL", "400 + UnsupportedProtocolVersion(-32022) listing supported", {"status": r["status"], "code": code, "text": r["text"][:200]}, "")
@case("N05-no-session-id-issued", "SPEC 2026-07-28 SEP-2567", eras=("modern",))
def n05(c):
    r, b = _m(c); sidh = r["headers"].get("mcp-session-id")
    return R("PASS" if r["status"] == 200 and not sidh else "FAIL", "200 and no Mcp-Session-Id", {"status": r["status"], "session_header": sidh}, "")
@case("N06-removed-ping", "SPEC 2026-07-28 (ping removed)", eras=("modern",))
def n06(c):
    r, b = _m(c, method="ping", name=None, params={}); j = c.parse(r); code = (j or {}).get("error", {}).get("code") if isinstance(j, dict) else None
    return R("PASS" if r["status"] == 404 and code == -32601 else "FAIL", "404 + -32601 (method not found)", {"status": r["status"], "code": code}, "")
@case("N07-get-endpoint-removed", "SPEC 2026-07-28 (HTTP GET endpoint removed)", eras=("modern",))
def n07(c):
    h = c.hdr("subscriptions/listen"); h.pop("content-type", None); h["accept"] = "text/event-stream"
    try: r = c.client.get(c.t["url"], headers=h); st = r.status_code
    except Exception as e: st = repr(e)
    return R("PASS" if st in (405, 404, 400) else "FAIL", "GET -> 405/404 (no standalone stream)", {"status": st}, "")
@case("N08-initialize-under-modern", "SPEC 2026-07-28 (initialize removed)", eras=("modern",))
def n08(c):
    r, b = _m(c, method="initialize", name=None, params={"protocolVersion": ENV_LEGACY, "capabilities": {}, "clientInfo": {"name": "x", "version": "1"}}); j = c.parse(r)
    return R("PASS" if (r["status"] == 404 and (j or {}).get("error", {}).get("code") == -32601) else "FAIL", "404 + -32601 (conformance server-stateless: removed endpoints incl. initialize)", {"status": r["status"], "sid": r["headers"].get("mcp-session-id")}, "")
@case("N09-simple-request-cannot-reach-modern", "SPEC SEP-2243 headers force preflight", eras=("modern",))
def n09(c):
    body = c.body("tools/call", {"name": "echo", "arguments": {"x": "csrf"}}); b = c.calls()
    r = c.post(json.dumps(body), {"content-type": "text/plain", "Origin": "http://evil.example"}, tag="N09"); bl, reached, st = c.blocked(r, b)
    return R("PASS" if bl else "FAIL", "text/plain w/o MCP headers -> 400/415", {"status": st, "reached": reached}, "")
@case("N10-delete-session-legacy", "SPEC 2025-11-25 session termination", eras=("legacy",))
def n10(c):
    sid = c.session()
    if not sid or sid == "INIT_FAIL": return R("NA", "stateless/no session", {}, "")
    r = c.client.delete(c.t["url"], headers=c.hdr("x", sid=sid)); r2 = c.echo("x", sid=sid)
    return R("PASS" if r.status_code in (200, 202, 204) and r2["status"] == 404 else "WARN", "DELETE ends session; reuse -> 404", {"delete": r.status_code, "reuse": r2["status"]}, "")

# ------------------------------------------------------------------ extension hooks (auth/gateway cases defined in corpus_ext.py)
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import corpus_ext; corpus_ext.register(sys.modules[__name__])
except ImportError:
    pass

NA_BLACKBOX = {
 "proxy-token-required": "Inspector-proxy specific (GHSA-7f8r); no such process in SDK/gateway targets",
 "token-not-to-app-origin": "Inspector UI specific (GHSA-6x67)",
 "task-cross-principal-404": "needs tasks-capable server + two principals; not built in this round (spike)",
 "oauth-issuer-pin": "client-side (AS mix-up); needs client SDK vs rogue AS - separate harness",
 "resource-mismatch": "client-side (PRM.resource)",
 "ssrf-resolved-address": "operator-configured egress; needs gateway with attacker-controlled target URLs (docker dynamic tools) - spike",
 "path-allowlist": "docker mcp-gateway config-driven mounts; needs docker daemon + catalog",
 "scheme-allowlist": "docker mcp-gateway server refs (file://); needs catalog",
 "verify-default-on": "read from `gateway run --help`: --verify-signatures default true (v0.44.2)",
 "argv-injection": "docker OCI label parsing; needs images",
 "oauth-state-bound": "client login CSRF; client-side",
}

def main():
    tg = json.load(open(sys.argv[1])); out = sys.argv[2]; only = set(sys.argv[3:]); os.makedirs(out, exist_ok=True)
    resf = open(os.path.join(out, "results.jsonl"), "a")
    for t in tg:
        if only and t["name"] not in only: continue
        if "corpus_ext" in sys.modules and hasattr(sys.modules["corpus_ext"], "prep"): sys.modules["corpus_ext"].prep(t)
        logf = open(os.path.join(out, re.sub(r"[^A-Za-z0-9._+-]", "_", t["name"]) + ".raw.jsonl"), "w")
        for era in t["eras"]:
            c = Ctx(t, era, logf)
            sid = c.session(); base = c.echo("base", sid=sid if sid != "INIT_FAIL" else None, tag="baseline")
            basej = c.parse(base); base_ok = base["status"] == 200 and (t.get("tool") is not None or "base" in json.dumps(basej))
            resf.write(json.dumps({"target": t["name"], "era": era, "case": "BASELINE", "verdict": "PASS" if base_ok else "ERR", "evidence": {"status": base["status"], "text": base["text"][:200]}}) + "\n")
            print(t["name"], era, "BASELINE", base_ok, base["status"], flush=True)
            if not base_ok and not t.get("run_anyway"): continue
            for key, basis, eras, f in CASES:
                if key == "session-table-bound": continue
                if era.split(":")[0] not in eras: continue
                if t.get("only_cases") and key not in t["only_cases"]: continue
                if t.get("skip_cases") and key in t["skip_cases"]: continue
                t0 = time.time()
                try: v, exp, ev, _ = f(c)
                except Exception as e: v, exp, ev = "ERR", "", repr(e)[:300]
                rec = {"target": t["name"], "era": era, "case": key, "verdict": v, "expect": exp, "basis": basis, "evidence": ev, "secs": round(time.time() - t0, 1)}
                resf.write(json.dumps(rec, default=str) + "\n"); resf.flush()
                print(t["name"], era, key, v, json.dumps(ev, default=str)[:160], flush=True)
        # flood pass LAST (leaves server saturated): legacy era only
        if "legacy" in t["eras"] and not t.get("skip_flood"):
            c = Ctx(t, "legacy", logf)
            if not t.get("only_cases") or "session-table-bound" in t["only_cases"]:
                f = [x for x in CASES if x[0] == "session-table-bound"][0]
                try: v, exp, ev, _ = f[3](c)
                except Exception as e: v, exp, ev = "ERR", "", repr(e)[:300]
                resf.write(json.dumps({"target": t["name"], "era": "legacy", "case": "session-table-bound", "verdict": v, "expect": exp, "basis": f[1], "evidence": ev}, default=str) + "\n"); resf.flush()
                print(t["name"], "legacy session-table-bound", v, json.dumps(ev, default=str)[:200], flush=True)
        logf.close()
    resf.close()

if __name__ == "__main__": main()
