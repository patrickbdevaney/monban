"""Auth / gateway-forwarding cases for mcp_lc_corpus.py (need targets with jwt{} or mock{} blocks)."""
import json, time, base64, hmac, hashlib, os
import jwt as pyjwt
from cryptography.hazmat.primitives import serialization

def _key(t): return open(t["jwt"]["key"], "rb").read()
def mint(t, sub="alice", aud=None, iss=None, exp=3600, nbf=0, alg="RS256", kid="k1", **kw):
    j = t["jwt"]; now = int(time.time())
    claims = {"sub": sub, "iss": iss or j["iss"], "iat": now, "exp": now + exp}
    if nbf: claims["nbf"] = now + nbf
    a = j["aud"] if aud == "default" or aud is None else aud
    if a != "OMIT": claims["aud"] = a
    claims.update(kw)
    if alg == "RS256": return pyjwt.encode(claims, _key(t), algorithm="RS256", headers={"kid": kid})
    if alg == "none":
        h = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT", "kid": kid}).encode()).rstrip(b"=")
        p = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=")
        return (h + b"." + p + b".").decode()
    if alg == "HS256":  # algorithm confusion: HMAC with public-key PEM bytes as secret
        pub = serialization.load_pem_private_key(_key(t), None).public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        h = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid}).encode()).rstrip(b"=")
        p = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=")
        sig = base64.urlsafe_b64encode(hmac.new(pub, h + b"." + p, hashlib.sha256).digest()).rstrip(b"=")
        return (h + b"." + p + b"." + sig).decode()
    raise ValueError(alg)

def prep(t):
    if t.get("jwt"): t["bearer"] = mint(t)

def register(M):
    case = M.case; R = M.R
    ev_ok = lambda r: r["status"]

    @case("token-wrong-audience-401", "SPEC-MUST (auth: aud validation) / ADVISORY GHSA-rvq5,w4fh", eras=("legacy",))
    def c_aud(c):
        t = c.t
        if not t.get("jwt"): return R("NA", "no token verifier in this config", {}, "")
        def attempt(tok):
            h = c.hdr("initialize", auth=False); h["Authorization"] = "Bearer " + tok
            r = c.post(c.body("initialize", {"protocolVersion": M.ENV_LEGACY, "capabilities": {}, "clientInfo": {"name": "aud", "version": "1"}}), h, tag="aud"); return r["status"]
        tests = {
          "good": mint(t), "aud=other": mint(t, aud="http://other.example/mcp"), "aud=omitted": mint(t, aud="OMIT"),
          "expired": mint(t, exp=-3600), "iss=wrong": mint(t, iss="http://evil.example"), "nbf=future": mint(t, nbf=3600),
          "alg=none": mint(t, alg="none"), "alg=HS256(pubkey-as-secret)": mint(t, alg="HS256"),
          "sig-tampered": mint(t)[:-6] + ("AAAAAA" if not mint(t).endswith("AAAAAA") else "BBBBBB"),
        }
        res = {k: attempt(v) for k, v in tests.items()}
        no_tok = c.post(c.body("initialize", {"protocolVersion": M.ENV_LEGACY, "capabilities": {}, "clientInfo": {"name": "aud", "version": "1"}}), c.hdr("initialize", auth=False), tag="aud-none")["status"]; res["no-token"] = no_tok
        bad_acc = [k for k, v in res.items() if k != "good" and v in (200, 202)]
        if res["good"] != 200: return R("ERR", "good token must pass", res, "")
        return R("PASS" if not bad_acc else "FAIL", "only 'good' token accepted; others 401", {**res, "accepted_bad": bad_acc}, "")

    @case("session-principal-binding", "ADVISORY GHSA-jpw9/hqg7", eras=("legacy",))
    def c_spb(c):
        t = c.t
        if not t.get("jwt"): return R("NA", "no principals in this config", {}, "")
        A = mint(t, sub="alice"); B = mint(t, sub="bob")
        t["bearer"] = A; sid = c.session()
        if sid in (None, "INIT_FAIL"): return R("NA", "stateless", {"sid": sid}, "")
        before = c.calls()
        h = c.hdr("tools/call", "echo", sid=sid, auth=False); h["Authorization"] = "Bearer " + B
        r = c.post(c.body("tools/call", {"name": "echo", "arguments": {"x": "bob-uses-alice-session"}}), h, tag="spb")
        bl, reached, st = c.blocked(r, before); t["bearer"] = mint(t)
        return R("PASS" if bl else "FAIL", "bob + alice's session id -> 4xx, handler untouched", {"status": st, "reached": reached, "sid_prefix": sid[:20], "sid_is_b64json": _b64json(sid)}, "")

    @case("session-route-pin", "ADVISORY GHSA-mvgg", eras=("legacy",))
    def c_srp(c):
        t = c.t
        if not t.get("url2"): return R("NA", "single-route config", {}, "")
        t["bearer"] = mint(t, aud=t["jwt"]["aud"]); sid = c.session()
        if sid in (None, "INIT_FAIL"): return R("NA", "stateless", {}, "")
        tok2 = mint(t, aud=t["jwt"]["aud2"]); h = c.hdr("tools/call", "echo", sid=sid, auth=False); h["Authorization"] = "Bearer " + tok2
        r = c.post(c.body("tools/call", {"name": "echo", "arguments": {"x": "cross-route"}}), h, url=t["url2"], tag="srp"); t["bearer"] = mint(t)
        ok = r["status"] in M.REJECT
        return R("PASS" if ok else "FAIL", "session from route 1 on route 2 -> 4xx", {"status": r["status"], "text": r["text"][:150]}, "")

    @case("token-passthrough", "SPEC-MUST-NOT (2026-07-28 authorization / security best practices)", eras=("legacy",))
    def c_tp(c):
        t = c.t; m = t.get("mock")
        if not m: return R("NA", "no recording upstream", {}, "")
        open(m["logA"], "w").close(); SECRET = "Bearer SECRET-CLIENT-TOKEN-123"
        h = c.hdr("initialize", auth=False); h["Authorization"] = SECRET; h["X-Api-Key"] = "client-key-xyz"; h["Cookie"] = "sess=abc"
        c.post(c.body("initialize", {"protocolVersion": M.ENV_LEGACY, "capabilities": {}, "clientInfo": {"name": "tp", "version": "1"}}), h, tag="tp")
        time.sleep(0.5); recs = [json.loads(l) for l in open(m["logA"])]
        fwd = [r for r in recs if r["headers"].get("authorization") == SECRET]
        others = {k: any(r["headers"].get(k) for r in recs) for k in ("x-api-key", "cookie", "origin")}
        ev = {"upstream_reqs": len(recs), "authorization_forwarded": bool(fwd), "other_headers_forwarded": others}
        if not recs: return R("ERR", "upstream saw nothing", ev, "")
        return R("FAIL" if fwd else "PASS", "client Authorization not forwarded to upstream", ev, "")

    @case("redirect-strip-headers", "ADVISORY GHSA-6prh/5h93/9g45/f6mc", eras=("legacy",))
    def c_red(c):
        t = c.t; m = t.get("mock")
        if not m: return R("NA", "no recording upstream", {}, "")
        open(m["logA"], "w").close(); open(m["logB"], "w").close()
        h = c.hdr("initialize", auth=False); h["Authorization"] = "Bearer SECRET-CLIENT-TOKEN-123"; h["X-Api-Key"] = "client-key-xyz"
        r = c.post(c.body("initialize", {"protocolVersion": M.ENV_LEGACY, "capabilities": {}, "clientInfo": {"name": "rd", "version": "1"}}), h, url=t["url_redir"], tag="redir")
        time.sleep(0.5); A = [json.loads(l) for l in open(m["logA"])]; B = [json.loads(l) for l in open(m["logB"])]
        leak = [b for b in B if b["headers"].get("authorization") or b["headers"].get("x-api-key")]
        ev = {"client_status": r["status"], "A_reqs": len(A), "B_reqs(cross-origin after 307)": len(B), "B_with_credentials": len(leak), "B_has_body": any(b["body"] for b in B)}
        if not A: return R("ERR", "A saw nothing", ev, "")
        if leak: return R("FAIL", "no cross-origin redirect following with credentials", ev, "")
        if B: return R("WARN", "follows cross-origin redirect (credentials stripped)", ev, "")
        return R("PASS", "does not follow cross-origin redirect", ev, "")

    @case("toolname-collision", "ADVISORY GHSA-qg99/m5m2", eras=("legacy",))
    def c_tnc(c):
        t = c.t
        if not t.get("multiplex"): return R("NA", "single target", {}, "")
        sid = c.session(); r = c.post(c.body("tools/list"), c.hdr("tools/list", sid=sid), tag="tnc"); j = c.parse(r)
        names = [x["name"] for x in (j or {}).get("result", {}).get("tools", [])]
        dup = len(names) != len(set(names)); fold = len(names) != len({n.lower() for n in names})
        return R("PASS" if not dup and not fold and len(names) >= 2 else "FAIL", "two targets exposing `echo` -> distinct names", {"names": names}, "")

def _b64json(s):
    try:
        pad = "=" * (-len(s) % 4); return bool(json.loads(base64.urlsafe_b64decode(s + pad)))
    except Exception: return False
