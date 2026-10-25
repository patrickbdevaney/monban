"""CANON-DIFF oracle driver (G1 property, G2 pinned differential, G3 ledger regressions, G4 lock bans, CANON-6, CANON-7).

Invoke through ./run (python3 -I, stdlib only). See README.md for the subject protocol and pass criterion.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import random
import re
import shlex
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
NAME = "CANON-DIFF"


def _load_ref():
    sp = importlib.util.spec_from_file_location("aegis_canon_ref", os.path.join(HERE, "canon_ref.py"))
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    return m


R = _load_ref()
KIND_ORDER = list(R.KINDS)
CELLS = ["ref_reject_subj_accept", "ref_accept_subj_reject", "canonical_mismatch", "reject_code_mismatch",
         "not_idempotent", "protocol_error"]


def jload(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return json.load(f)


def dumps(x):
    return json.dumps(x, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def code_of(reason):
    m = re.match(r"^(\d{3})\b", reason or "")
    return m.group(1) if m else None


# ============================================================== corpus (G2 pinned + extra)
SPECIAL = ("http://", "https://", "ws://", "wss://", "ftp://")


def build_corpus():
    """Deterministic list of (case_id, kind, input). Sources: research corpus, WPT urltestdata, IdnaTestV2, extra."""
    seen, cases = set(), []
    extra = jload("corpus/extra.json")
    vh = extra["vhosts"]

    def add(src, kind, x):
        key = (kind, dumps(x))
        if key in seen:
            return
        seen.add(key)
        cases.append(("%s:%s:%d" % (src, kind, len(cases)), kind, x))

    rc = jload("corpus/research_corpus.json")
    for kind, key in [("path", "paths"), ("host", "hosts"), ("json", "json_docs"), ("cookie", "cookies"),
                      ("ctype", "ctypes"), ("origin", "origins"), ("tenant", "tenants"), ("headers", "headers")]:
        for x in rc[key]:
            add("research", kind, x)
    for x in jload("corpus/urltestdata.json"):
        if not isinstance(x, dict) or not isinstance(x.get("input"), str):
            continue
        inp = x["input"]
        if not x.get("failure"):
            if isinstance(x.get("hostname"), str) and x["hostname"]:
                add("wpt", "host", x["hostname"])
            if isinstance(x.get("pathname"), str) and x["pathname"].startswith("/"):
                add("wpt", "path", x["pathname"])
            if isinstance(x.get("origin"), str):
                add("wpt", "origin", x["origin"])
            if isinstance(x.get("search"), str) and x["search"].startswith("?"):
                add("wpt", "query", x["search"][1:])
        low = inp.lower()
        for sp in SPECIAL:
            if low.startswith(sp):
                rest = inp[len(sp):]
                auth = re.split(r"[/?#\\]", rest, maxsplit=1)[0]
                add("wpt-raw", "host", auth)
                add("wpt-raw", "origin", inp[:len(sp)] + auth)
                tail = rest[len(auth):]
                if tail.startswith("/"):
                    add("wpt-raw", "path", re.split(r"[?#]", tail, maxsplit=1)[0])
                break
        if inp.startswith("/"):
            add("wpt-raw", "path", re.split(r"[?#]", inp, maxsplit=1)[0])
    for x in jload("corpus/IdnaTestV2.json"):
        if isinstance(x, dict):
            if isinstance(x.get("input"), str):
                add("idna", "host", x["input"])
            if isinstance(x.get("output"), str):
                add("idna", "host", x["output"])
    for kind, key in [("path", "paths"), ("host", "hosts"), ("origin", "origins"), ("cookie", "cookies"),
                      ("query", "queries"), ("json", "json_docs"), ("headers", "headers"), ("tenant", "tenants"),
                      ("ctype", "ctypes")]:
        for x in extra[key]:
            add("extra", kind, x)
    g = extra["request_grid"]
    for proto in g["proto"]:
        for scheme in g["scheme"]:
            for a in g["authority"]:
                for hl in g["host_lists"]:
                    hosts = {"none": [], "same": [a], "same-upper": [a.upper()], "other": ["api.example.com"],
                             "dup-same": [a, a], "dup-other": [a, "evil.example"], "userinfo": ["u@" + a]}[hl]
                    for sni in g["sni"]:
                        for origin in g["origin"]:
                            if proto == "h1":
                                if hl == "none":
                                    continue
                                r = {"proto": "h1", "scheme": scheme, "sni": sni, "authority": None, "host": hosts,
                                     "origin": origin, "vhosts": vh}
                            else:
                                r = {"proto": "h2", "scheme": scheme, "sni": sni, "authority": a, "host": hosts,
                                     "origin": origin, "vhosts": vh}
                            add("canon6", "request", r)
    for r in extra["request_cleartext"]:
        add("canon6", "request", dict(r, vhosts=dict(vh, **{"example.com": ["https://example.com"]})))
    return cases


def corpus_digest(cases):
    h = hashlib.sha256()
    for cid, kind, x in cases:
        h.update((cid + "\x00" + kind + "\x00" + dumps(x) + "\n").encode())
    return h.hexdigest()


def ledger_cases():
    vh = jload("corpus/extra.json")["vhosts"]
    out = []
    for row in jload("ledger.json")["rows"]:
        x = row["input"]
        if row["kind"] == "request":
            x = dict(x, vhosts=vh)
        out.append((row["id"], row["kind"], x, row["expect"]))
    return out


# ============================================================== G1 generator (attacker operators, seeded)
INS = {
    "path": ["/./", "/../", "//", "\\", ";", "%2F", "%2f", "%5C", "%5c", "%2e", "%2E%2E", "%00", "%25", "%252F", "\u00a0",
             "\u200b", "\uff0f", "%3B", "..", ".", "%41", "%7e", "%7E", "%20", "~", ":", "@", "/", "%61", "%C3%A9", "?",
             "#", "%zz", "\u212a"],
    "host": [".", "..", "-", "xn--", ":443", ":0", "%2e", "\u3002", "\uff0e", "\u212a", "\u0130", "\u00df", "\u200b",
             "0x", "0", "_", " ", "\t", "@", "[", "]", "1", "\u00ad"],
    "query": ["&", ";", "=", "+", "%26", "%3D", "%2B", "%25", "%00", "%61", "%e9", "\u00e9", "&&", "a=1", "%2F", "?"],
}
HOST_SEEDS = ["example.com", "api.example.com", "xn--fa-hia.de", "127.0.0.1", "localhost", "a.b", "xn--mnchen-3ya.de"]
PATH_SEEDS = ["/", "/admin", "/admin/x", "/public/a", "/a/b/c", "/api/v1/users"]


def _mut_str(rng, s, pool):
    for _ in range(rng.randint(1, 4)):
        op = rng.randrange(6)
        pos = rng.randint(0, len(s))
        if op <= 1:
            s = s[:pos] + rng.choice(pool) + s[pos:]
        elif op == 2 and s:
            i = rng.randrange(len(s))
            if ord(s[i]) < 128:
                s = s[:i] + (("%%%02X" if rng.random() < .5 else "%%%02x") % ord(s[i])) + s[i + 1:]
        elif op == 3 and s:
            i = rng.randrange(len(s))
            s = s[:i] + s[i].swapcase() + s[i + 1:]
        elif op == 4 and len(s) > 1:
            i = rng.randrange(len(s))
            s = s[:i] + s[i + 1:]
        else:
            s = s + rng.choice(["/", ".", "", "%2F", "/."])
    return s


def _ipv4ish(rng):
    parts = []
    for _ in range(rng.choice([1, 2, 3, 4, 4, 4, 5])):
        n = rng.randrange(0, 300)
        parts.append(rng.choice([str(n), "0" + str(n), hex(n), str(n)]))
    return ".".join(parts)


def gen(kind, rng, vh):
    if kind == "path":
        return _mut_str(rng, rng.choice(PATH_SEEDS), INS["path"])
    if kind == "host":
        return _ipv4ish(rng) if rng.random() < .2 else _mut_str(rng, rng.choice(HOST_SEEDS), INS["host"])
    if kind == "query":
        base = "&".join("%s=%s" % (rng.choice("abAB"), rng.choice(["1", "x", "", "%41"])) for _ in range(rng.randint(1, 3)))
        return _mut_str(rng, base, INS["query"])
    if kind == "origin":
        scheme = rng.choice(["https", "http", "HTTPS", "wss", "file"])
        host = gen("host", rng, vh)
        port = rng.choice(["", "", ":443", ":80", ":8443", ":0443", ":", ":99999"])
        tail = rng.choice(["", "", "", "/", "?", "#x", "@evil.example", "\\@evil.example"])
        return scheme + "://" + rng.choice(["", "", "user@"]) + host + port + tail
    if kind == "cookie":
        pairs = []
        for _ in range(rng.randint(1, 4)):
            n = rng.choice(["sid", "__Host-sid", "__host-sid", "__Secure-x", "$Version", "a%5F", "x", "SID", "y", ""])
            v = rng.choice(["1", "abc", '"q"', "a,b", "a\u00a0", "", "a=b", "a b", "a\\b"])
            pairs.append(rng.choice(["", "", " ", "\u00a0"]) + n + rng.choice(["=", "=", "=", " =", "= "]) + v)
        if rng.random() < .3:
            pairs.append(rng.choice(pairs))
        sep = rng.choice(["; ", "; ", ";", ";  ", "; \t", ";; "])
        return sep.join(pairs)
    if kind == "json":
        def val(d):
            r = rng.random()
            if d < 3 and r < .2:
                return "{" + ",".join('"%s":%s' % (rng.choice(["a", "b", "role", "Role"]), val(d + 1))
                                      for _ in range(rng.randint(0, 3))) + "}"
            if d < 3 and r < .3:
                return "[" + ",".join(val(d + 1) for _ in range(rng.randint(0, 3))) + "]"
            return rng.choice(['"user"', '"\\ud800"', '"a\\u0000"', '"\\u00e9"', "1", "-0", "1e400", "9007199254740993",
                               "0.1e-400", "1.0", "12345678901234567890.5", "-0.0", "1E2", "true", "null", "NaN"])
        keys = rng.sample(["role", "r\\u006fle", "ROLE", "amount", "name"], rng.randint(0, 3))
        if keys and rng.random() < .3:
            keys.append(keys[0])
        s = "{" + ",".join('"%s":%s' % (k, val(0)) for k in keys) + rng.choice(["}", "}", "}", ",}", "} ", "}{}"])
        if rng.random() < .05:
            s = "\ufeff" + s
        if rng.random() < .02:
            d = rng.randint(60, 80)
            s = "[" * d + "]" * d
        return s
    if kind == "ctype":
        ess = rng.choice(["application/json", "APPLICATION/JSON", "text/plain", "multipart/form-data", "*/*",
                          "application /json", "application/vnd.api+json"])
        ps = []
        for _ in range(rng.randint(0, 3)):
            ps.append(rng.choice(["charset=utf-8", "Charset=UTF-8", "boundary=a", "boundary=b", 'charset="utf-8"', "",
                                  "x", "a=b;c"]))
        return ess + "".join(rng.choice([";", "; ", " ;", ";  "]) + p for p in ps) + rng.choice(["", "", " ", "\t", ","])
    if kind == "tenant":
        return "".join(rng.choice("acmeKk-_0\u212a\u0130\u0131\u00dfAZ \u200b\uff41") for _ in range(rng.randint(1, 8)))
    if kind == "headers":
        pool = ["Host: example.com", "Host: evil.example", "host: example.com", "Host : example.com", "Content-Length: 5",
                "Content-Length: 05", "Transfer-Encoding: chunked", "Transfer-Encoding: Chunked", "Accept: */*",
                "X-Role: a", "x-role: b", " folded", "X: caf\u00e9", "X:\tv", "Authorization: Bearer a", "Host:"]
        return [rng.choice(pool) for _ in range(rng.randint(1, 5))]
    if kind == "request":
        g = jload_cached("corpus/extra.json")["request_grid"]
        proto = rng.choice(["h1", "h2"])
        a = rng.choice(g["authority"]) if rng.random() < .6 else gen("host", rng, vh) + rng.choice(["", ":443", ":8443"])
        hosts = rng.choice([[], [a], [a.upper()], [a, a], ["api.example.com"], [gen("host", rng, vh)]])
        r = {"proto": proto, "scheme": rng.choice(["https", "https", "http"]), "sni": rng.choice(g["sni"]),
             "authority": a if proto == "h2" else None, "host": hosts if proto == "h2" else (hosts or [a]),
             "origin": rng.choice(g["origin"]), "vhosts": vh}
        return r
    raise ValueError(kind)


_JC = {}


def jload_cached(name):
    if name not in _JC:
        _JC[name] = jload(name)
    return _JC[name]


def g1_cases(n, seed=20261025):
    rng = random.Random(seed)
    vh = jload("corpus/extra.json")["vhosts"]
    out = []
    for i in range(n):
        kind = KIND_ORDER[i % len(KIND_ORDER)]
        out.append(("g1:%s:%d" % (kind, i), kind, gen(kind, rng, vh)))
    return out


# ============================================================== reference self-properties (CANON-7, safe-set only)
def _safe_path(raw):
    def f(m):
        ch = chr(int(m.group(1), 16))
        return ch if ch in R.UNRES else "%" + m.group(1).upper()
    return re.sub(r"%([0-9A-Fa-f]{2})", f, raw)


def ref_property_violations(kind, x, res):
    """Properties of the reference itself (not circular w.r.t. the golden): totality, reason format, CANON-7
    idempotence, and 'only the safe set was repaired' / output-shape invariants per kind."""
    st, v = res
    if st not in (R.ACCEPT, R.REJECT):
        return "non-total result"
    if st == R.REJECT:
        return None if code_of(v) else "reject reason lacks status code"
    again = R.canon(kind, R.serialize(kind, v, x))
    if again != (R.ACCEPT, v):
        return "CANON-7 not idempotent: %r -> %r" % (v, again)
    if kind == "path":
        if v != _safe_path(x):
            return "path repaired outside the safe set"
        low = v.lower()
        if any(t in low for t in ("%2f", "%5c", "%3b", "%00", "%25", "\\", ";", "//", "/./", "/../")) or \
                v.endswith(("/.", "/..")) or not v.isascii():
            return "path output shape"
    elif kind == "host":
        if v != x.lower() or not v.isascii() or v.endswith("."):
            return "host repaired beyond ASCII lowercase"
    elif kind == "origin":
        if not re.fullmatch(r"https?://[a-z0-9.-]+(:[1-9][0-9]{0,4})?", v) or v.endswith((":443", ":80")) and \
                ((v.startswith("https:") and v.endswith(":443")) or (v.startswith("http:") and v.endswith(":80"))):
            return "origin output shape"
    elif kind == "cookie":
        names = [p.split("=", 1)[0].lower() for p in v.split("; ")]
        if len(names) != len(set(names)):
            return "cookie duplicate survived"
    elif kind == "json":
        if R.canon_json(v) != (R.ACCEPT, v):
            return "json canonical not a fixed point"
    elif kind == "tenant":
        if v != x:
            return "tenant folded"
    elif kind == "headers":
        names = [n for n, _ in v]
        if any(names.count(n) > 1 and n not in R.LIST_FIELDS for n in names):
            return "duplicate singleton survived"
    elif kind == "request":
        if v.get("vhost") not in (x.get("vhosts") or {}):
            return "request bound to unknown vhost"
    return None


# ============================================================== subject process (line-oriented JSON protocol)
class Subject:
    def __init__(self, argv, timeout):
        self.argv, self.timeout = argv, timeout

    def query(self, items):
        """items: list of (kind, input). Returns list of response dicts (or None on protocol failure)."""
        if not items:
            return []
        p = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr,
                             cwd=HERE, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))

        def writer():
            try:
                for i, (k, x) in enumerate(items):
                    p.stdin.write((dumps({"id": i, "kind": k, "input": x}) + "\n").encode("ascii"))
                p.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        t = threading.Thread(target=writer, daemon=True)
        t.start()
        out = [None] * len(items)
        deadline = time.time() + self.timeout
        timer = threading.Timer(self.timeout, p.kill)
        timer.start()
        try:
            for line in p.stdout:
                try:
                    msg = json.loads(line)
                    i = msg["id"]
                    if isinstance(i, int) and 0 <= i < len(items) and out[i] is None:
                        out[i] = msg
                except Exception:
                    continue
                if time.time() > deadline:
                    break
        finally:
            timer.cancel()
            try:
                p.kill()
            except OSError:
                pass
            p.wait()
        return out


def norm_response(msg):
    """-> (status, value) or None if malformed."""
    if not isinstance(msg, dict):
        return None
    a, r = "accept" in msg, "reject" in msg
    if a == r:
        return None
    if r:
        return (R.REJECT, msg["reject"]) if isinstance(msg["reject"], str) else None
    return (R.ACCEPT, msg["accept"])


# ============================================================== comparison
class Table:
    def __init__(self, title):
        self.title = title
        self.c = {}
        self.ex = {}
        self.n = {}

    def seen(self, kind):
        self.n[kind] = self.n.get(kind, 0) + 1

    def hit(self, kind, cell, example):
        self.c[(kind, cell)] = self.c.get((kind, cell), 0) + 1
        lst = self.ex.setdefault((kind, cell), [])
        if len(lst) < 3:
            lst.append(example)

    def nonzero(self):
        return sum(self.c.values())

    def report(self, out):
        out.append("[%s] cases=%d nonzero_cells=%d" % (self.title, sum(self.n.values()), self.nonzero()))
        for (kind, cell), cnt in sorted(self.c.items()):
            out.append("    %-8s %-24s %6d   e.g. %s" % (kind, cell, cnt, " | ".join(self.ex[(kind, cell)])[:300]))


def compare(table, cid, kind, x, ref, subj):
    table.seen(kind)
    ex = "%s %s" % (cid, ascii(dumps(x))[:80])
    if subj is None:
        table.hit(kind, "protocol_error", ex)
        return
    rs, rv = ref
    ss, sv = subj
    if rs == R.REJECT and ss == R.ACCEPT:
        table.hit(kind, "ref_reject_subj_accept", ex + " ref=%r subj=%s" % (rv, ascii(dumps(sv))[:60]))
    elif rs == R.ACCEPT and ss == R.REJECT:
        table.hit(kind, "ref_accept_subj_reject", ex + " ref=%s subj=%r" % (ascii(dumps(rv))[:60], sv))
    elif rs == R.ACCEPT and rv != sv:
        table.hit(kind, "canonical_mismatch", ex + " ref=%s subj=%s" % (ascii(dumps(rv))[:60], ascii(dumps(sv))[:60]))
    elif rs == R.REJECT and kind == "request" and code_of(rv) != code_of(sv):
        table.hit(kind, "reject_code_mismatch", ex + " ref=%r subj=%r" % (rv, sv))


def expect_to_res(e):
    if isinstance(e, dict):
        return (R.ACCEPT, e["accept"])
    if e == "reject":
        return (R.REJECT, None)
    return (R.REJECT, e.split(":", 1)[1] + " ledger")


def compare_ledger(table, cid, kind, x, expect, got):
    table.seen(kind)
    exp = expect_to_res(expect)
    if got is None:
        table.hit(kind, "protocol_error", cid)
        return
    if exp[0] != got[0]:
        table.hit(kind, "ref_reject_subj_accept" if exp[0] == R.REJECT else "ref_accept_subj_reject",
                  "%s expect=%s got=%s" % (cid, expect, ascii(dumps(got[1]))[:80]))
    elif exp[0] == R.ACCEPT and exp[1] != got[1]:
        table.hit(kind, "canonical_mismatch", "%s expect=%s got=%s" % (cid, expect, ascii(dumps(got[1]))[:80]))
    elif exp[0] == R.REJECT and exp[1] and code_of(exp[1]) != code_of(got[1]):
        table.hit(kind, "reject_code_mismatch", "%s expect=%s got=%r" % (cid, expect, got[1]))


# ============================================================== G4 lockfile bans
BANNED = {"simd-json": "first-wins duplicates + lone-surrogate bug #481", "sonic-rs": "first-wins duplicates"}
URL_PARSERS = {"url", "fluent-uri", "uriparse", "iri-string", "oxiri", "uriparser", "uris"}


def g4_check(lock_text):
    names = set(re.findall(r'^name = "([^"]+)"$', lock_text, re.M))
    bad = ["%s (%s)" % (n, BANNED[n]) for n in sorted(names & set(BANNED))]
    urls = sorted(names & URL_PARSERS)
    if len(urls) > 1:
        bad.append("more than one URL parser in the lock: " + ",".join(urls))
    return bad, len(names)


# ============================================================== run modes
def load_golden():
    try:
        return jload("expected.json")
    except FileNotFoundError:
        return None


def regen_golden():
    cases = build_corpus()
    out = {"_comment": "Frozen expected outputs of the reviewed canon_ref.py over the G2 corpus. Regenerate only with "
                       "`./run --regen-golden` after a reviewed change to canon_ref.py, and say why in the commit.",
           "corpus_sha256": corpus_digest(cases), "canon_ref_sha256": sha256_file(os.path.join(HERE, "canon_ref.py")),
           "n": len(cases), "cases": {}}
    for cid, kind, x in cases:
        st, v = R.canon(kind, x)
        out["cases"][cid] = {"kind": kind, "input_sha256": hashlib.sha256(dumps(x).encode()).hexdigest()[:16],
                             st: v}
    with open(os.path.join(HERE, "expected.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=True, indent=0, sort_keys=True)
        f.write("\n")
    print("wrote expected.json: %d cases, corpus_sha256=%s" % (len(cases), out["corpus_sha256"]))


def sha256_file(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def research_pin_check(out):
    """The reference must agree with research canon_map.json except the reviewed deviations in deviations.json."""
    cm = jload("research/canon_map.json")
    dev = jload("deviations.json")["deviations"]
    devkeys = {(d["kind"], d["input"]) for d in dev}
    bad = []
    for ckind, kind in (("paths", "path"), ("hosts", "host")):
        for x, want in cm[ckind].items():
            st, v = R.canon(kind, x)
            mine = v if st == R.ACCEPT else None
            if (mine != want) != ((kind, x) in devkeys):
                bad.append("%s %s research=%r ref=%r (%s)" % (kind, ascii(x), want, mine,
                                                              "unlisted deviation" if mine != want else "listed deviation no longer deviates"))
    out.append("[research-pin] canon_map entries=%d listed_deviations=%d mismatches=%d"
               % (len(cm["paths"]) + len(cm["hosts"]), len(dev), len(bad)))
    out.extend("    " + b for b in bad[:10])
    return len(bad)


def run_oracle(subject_argv, g1n, do_g2, do_g3, do_g4, lock_path, timeout, golden_override=None, quiet=False):
    """Returns (nonzero_total, summary_str, lines)."""
    out = []
    total = 0
    summary = []
    subj = Subject(subject_argv, timeout) if subject_argv else None
    golden = golden_override if golden_override is not None else load_golden()

    # ---- G2 pinned corpus
    if do_g2:
        cases = build_corpus()
        ref = [R.canon(k, x) for _, k, x in cases]
        t = Table("G2 reference-vs-golden")
        if golden is None or golden.get("corpus_sha256") != corpus_digest(cases):
            t.hit("*", "protocol_error", "golden missing or stale (corpus_sha256 mismatch): run --regen-golden after review")
        else:
            for (cid, kind, x), r in zip(cases, ref):
                g = golden["cases"].get(cid)
                gres = None
                if g is not None and g.get("input_sha256") == hashlib.sha256(dumps(x).encode()).hexdigest()[:16]:
                    gres = (R.ACCEPT, g["accept"]) if "accept" in g else ((R.REJECT, g["reject"]) if "reject" in g else None)
                # golden plays 'reference', current reference plays 'subject' (drift detector)
                compare(t, cid, kind, x, gres or (R.REJECT, "?"), r if gres else None)
        t.report(out)
        total += t.nonzero()
        tp = Table("CANON-7 reference properties (G2 corpus)")
        for (cid, kind, x), r in zip(cases, ref):
            tp.seen(kind)
            v = ref_property_violations(kind, x, r)
            if v:
                tp.hit(kind, "not_idempotent" if "CANON-7" in v else "protocol_error", "%s %s: %s" % (cid, ascii(dumps(x))[:60], v))
        tp.report(out)
        total += tp.nonzero()
        total += research_pin_check(out)
        if subj:
            ts = Table("G2 subject-vs-reference")
            resp = subj.query([(k, x) for _, k, x in cases])
            sres = [norm_response(m) for m in resp]
            for (cid, kind, x), r, s in zip(cases, ref, sres):
                compare(ts, cid, kind, x, r, s)
            idem_items, idem_idx = [], []
            for i, ((cid, kind, x), s) in enumerate(zip(cases, sres)):
                if s and s[0] == R.ACCEPT:
                    try:
                        idem_items.append((kind, R.serialize(kind, s[1], x)))
                        idem_idx.append(i)
                    except Exception:
                        ts.hit(kind, "protocol_error", "%s unserializable canonical %s" % (cid, ascii(dumps(s[1]))[:60]))
            back = subj.query(idem_items)
            for i, m in zip(idem_idx, back):
                cid, kind, x = cases[i]
                b = norm_response(m)
                if b != sres[i]:
                    ts.hit(kind, "not_idempotent", "%s canon=%s recanon=%s" % (cid, ascii(dumps(sres[i][1]))[:60], ascii(dumps(b))[:60]))
            ts.report(out)
            total += ts.nonzero()
        summary.append("g2=%d" % len(cases))

    # ---- G3 ledger
    if do_g3:
        lc = ledger_cases()
        t = Table("G3 ledger (reference)")
        for cid, kind, x, e in lc:
            compare_ledger(t, cid, kind, x, e, R.canon(kind, x))
        t.report(out)
        total += t.nonzero()
        if subj:
            ts = Table("G3 ledger (subject)")
            resp = subj.query([(k, x) for _, k, x, _ in lc])
            for (cid, kind, x, e), m in zip(lc, resp):
                compare_ledger(ts, cid, kind, x, e, norm_response(m))
            ts.report(out)
            total += ts.nonzero()
        summary.append("g3=%d" % len(lc))

    # ---- G1 property
    if g1n:
        gc = g1_cases(g1n)
        ref = []
        tp = Table("G1 reference properties (totality, CANON-7, safe-set-only)")
        for cid, kind, x in gc:
            tp.seen(kind)
            try:
                r = R.canon(kind, x)
            except Exception as e:  # totality violation
                tp.hit(kind, "protocol_error", "%s raised %r" % (cid, e))
                r = (R.REJECT, "500 exception")
            ref.append(r)
            v = ref_property_violations(kind, x, r)
            if v:
                tp.hit(kind, "not_idempotent" if "CANON-7" in v else "protocol_error", "%s %s: %s" % (cid, ascii(dumps(x))[:60], v))
        tp.report(out)
        total += tp.nonzero()
        if subj:
            ts = Table("G1 subject-vs-reference")
            resp = subj.query([(k, x) for _, k, x in gc])
            sres = [norm_response(m) for m in resp]
            for (cid, kind, x), r, s in zip(gc, ref, sres):
                compare(ts, cid, kind, x, r, s)
            idem_items, idem_idx = [], []
            for i, ((cid, kind, x), s) in enumerate(zip(gc, sres)):
                if s and s[0] == R.ACCEPT:
                    try:
                        idem_items.append((kind, R.serialize(kind, s[1], x)))
                        idem_idx.append(i)
                    except Exception:
                        ts.hit(kind, "protocol_error", "%s unserializable" % cid)
            for i, m in zip(idem_idx, subj.query(idem_items)):
                if norm_response(m) != sres[i]:
                    ts.hit(gc[i][1], "not_idempotent", "%s canon=%s" % (gc[i][0], ascii(dumps(sres[i][1]))[:60]))
            ts.report(out)
            total += ts.nonzero()
        summary.append("g1=%d" % g1n)

    # ---- G4 lock bans
    if do_g4:
        if os.path.exists(lock_path):
            with open(lock_path, encoding="utf-8") as f:
                bad, n = g4_check(f.read())
            out.append("[G4 lock bans] %s packages=%d violations=%d %s" % (lock_path, n, len(bad), "; ".join(bad)))
            total += len(bad)
            summary.append("g4=%s" % ("ok" if not bad else "FAIL"))
        else:
            out.append("[G4 lock bans] no lockfile at %s: FAIL (pass --g4 skip to run without it)" % lock_path)
            total += 1
            summary.append("g4=missing")
    if not quiet:
        print("\n".join(out))
    return total, " ".join(summary), out


# ============================================================== deliberately lenient mutants (self-test subjects)
def _mut_request(x, f):
    if not isinstance(x, dict):
        return x
    x = dict(x)
    return f(x) or x


def _remove_dots(p):
    out = []
    for s in p.split("/")[1:]:
        if s == "..":
            if out:
                out.pop()
        elif s not in (".", ""):
            out.append(s)
    return "/" + "/".join(out)


def _strip_userinfo(v):
    return v.rsplit("@", 1)[-1] if isinstance(v, str) else v


def m_decode_slash(kind, x):
    if kind == "path" and isinstance(x, str):
        x = re.sub("%2[fF]", "/", x)
    return R.canon(kind, x)


def m_backslash_fold(kind, x):
    if kind == "path" and isinstance(x, str):
        x = re.sub("%5[cC]", "/", x.replace("\\", "/"))
    return R.canon(kind, x)


def m_dup_host(kind, x):
    if kind == "headers" and isinstance(x, list):
        keep, seen = [], False
        for ln in x:
            if isinstance(ln, str) and ln.lower().startswith("host:"):
                if seen:
                    continue
                seen = True
            keep.append(ln)
        x = keep
    if kind == "request":
        x = _mut_request(x, lambda r: r.update(host=(r.get("host") or [])[:1]))
    return R.canon(kind, x)


def m_userinfo(kind, x):
    if kind == "request":
        def f(r):
            r["authority"] = _strip_userinfo(r.get("authority"))
            r["host"] = [_strip_userinfo(h) for h in (r.get("host") or [])]
        x = _mut_request(x, f)
    if kind == "origin" and isinstance(x, str) and "://" in x:
        s, rest = x.split("://", 1)
        x = s + "://" + _strip_userinfo(rest)
    return R.canon(kind, x)


def m_unicode_lower(kind, x):
    lo = (lambda v: v.lower() if isinstance(v, str) else v)
    if kind in ("host", "tenant", "origin"):
        x = lo(x)
    if kind == "request":
        def f(r):
            r["sni"], r["authority"] = lo(r.get("sni")), lo(r.get("authority"))
            r["host"] = [lo(h) for h in (r.get("host") or [])]
        x = _mut_request(x, f)
    return R.canon(kind, x)


def m_dot_repair(kind, x):
    if kind == "path" and isinstance(x, str) and x.startswith("/"):
        y = re.sub("%2[eE]", ".", x)
        q = re.split(r"[?#]", y, maxsplit=1)[0]
        x = _remove_dots(q) + ("/" if q.endswith("/") and q != "/" and not q.endswith("/..") else "")
        if x.endswith("/") and len(x) > 1:
            x = x[:-1]
    return R.canon(kind, x)


def m_json_last_wins(kind, x):
    if kind == "json" and isinstance(x, str):
        try:
            v = json.loads(x)
            return R.canon("json", json.dumps(v, ensure_ascii=False))
        except Exception:
            pass
    return R.canon(kind, x)


def m_cookie_unicode_trim(kind, x):
    if kind == "cookie" and isinstance(x, str):
        parts = [p.strip() for p in x.split(";") if p.strip()]
        x = "; ".join("=".join(s.strip() for s in p.split("=", 1)) for p in parts)
        x = "".join(ch for ch in x if ch.isascii())
    return R.canon(kind, x)


def m_double_decode(kind, x):
    if kind == "path" and isinstance(x, str) and "%25" in x:
        st, v = R.canon_path(x.replace("%25", "~25~"))
        if st == R.ACCEPT:
            return (R.ACCEPT, v.replace("~25~", "%"))
        return (st, v)
    return R.canon(kind, x)


def m_sni_unbound(kind, x):
    if kind == "request":
        x = _mut_request(x, lambda r: r.update(sni=None))
    return R.canon(kind, x)


def m_origin_unbound(kind, x):
    if kind == "request":
        x = _mut_request(x, lambda r: r.update(origin=None) if R.canon_origin(r.get("origin"))[0] == R.ACCEPT else None)
    return R.canon(kind, x)


def m_trailing_dot(kind, x):
    sd = (lambda v: v[:-1] if isinstance(v, str) and v.endswith(".") else v)
    if kind in ("host", "origin"):
        x = sd(x)
    if kind == "request":
        def f(r):
            r["sni"], r["authority"] = sd(r.get("sni")), sd(r.get("authority"))
            r["host"] = [sd(h) for h in (r.get("host") or [])]
        x = _mut_request(x, f)
    return R.canon(kind, x)


MUTANTS = {
    # name: (function, cell that must be nonzero)
    "decode-%2F": (m_decode_slash, "ref_reject_subj_accept"),
    "backslash-to-slash": (m_backslash_fold, "ref_reject_subj_accept"),
    "accept-duplicate-Host": (m_dup_host, "ref_reject_subj_accept"),
    "accept-userinfo": (m_userinfo, "ref_reject_subj_accept"),
    "lowercase-non-ASCII": (m_unicode_lower, "ref_reject_subj_accept"),
    "repair-dot-segments": (m_dot_repair, "ref_reject_subj_accept"),
    "json-last-wins": (m_json_last_wins, "ref_reject_subj_accept"),
    "cookie-unicode-trim": (m_cookie_unicode_trim, "ref_reject_subj_accept"),
    "double-decode-%25 (CANON-7)": (m_double_decode, "not_idempotent"),
    "ignore-SNI-binding (CANON-6)": (m_sni_unbound, "ref_reject_subj_accept"),
    "ignore-Origin-binding (CANON-6)": (m_origin_unbound, "ref_reject_subj_accept"),
    "strip-trailing-dot": (m_trailing_dot, "ref_reject_subj_accept"),
}


def serve(mutant):
    f = MUTANTS[mutant][0] if mutant else R.canon
    out = sys.stdout
    for line in sys.stdin:
        try:
            msg = json.loads(line)
            st, v = f(msg["kind"], msg["input"])
            resp = {"id": msg["id"], st: v}
        except Exception as e:
            resp = {"id": msg.get("id") if isinstance(msg, dict) else None, "reject": "500 subject exception %r" % e}
        out.write(dumps(resp) + "\n")
    out.flush()


def self_test(args):
    me = [sys.executable, "-I", os.path.abspath(__file__)]
    results, ok = [], True
    g1n = args.self_test_g1
    lock = args.lock
    # 1. unmutated reference as a subject must PASS (oracle is satisfiable)
    n, _, _ = run_oracle(me + ["--serve"], g1n, True, True, False, lock, args.timeout, quiet=True)
    results.append(("reference-as-subject (must pass)", n == 0, "nonzero_cells=%d" % n))
    ok &= n == 0
    # 2. each lenient mutant must FAIL with its characteristic cell nonzero
    for name, (_, cell) in MUTANTS.items():
        n, _, lines = run_oracle(me + ["--serve", "--mutant", name], g1n, True, True, False, lock, args.timeout,
                                 quiet=True)
        hit = any((" %s " % cell) in ln for ln in lines if ln.startswith("    "))
        caught = n > 0 and hit
        results.append(("mutant %s" % name, caught, "nonzero_cells=%d %s>0=%s" % (n, cell, hit)))
        ok &= caught
    # 3. tampered golden must be caught in reference mode
    g = load_golden()
    if g:
        g2 = json.loads(json.dumps(g))
        cid = next(k for k, v in sorted(g2["cases"].items()) if v["kind"] == "path" and "reject" in v)
        g2["cases"][cid] = {"kind": "path", "input_sha256": g2["cases"][cid]["input_sha256"], "accept": "/tampered"}
        n, _, _ = run_oracle(None, 0, True, False, False, lock, args.timeout, golden_override=g2, quiet=True)
        results.append(("tampered golden entry", n > 0, "nonzero_cells=%d" % n))
        ok &= n > 0
    else:
        results.append(("tampered golden entry", False, "no expected.json"))
        ok = False
    # 4. G4 synthetic lock with banned crates
    bad, _ = g4_check('name = "serde_json"\nname = "simd-json"\nname = "url"\nname = "fluent-uri"\n')
    results.append(("G4 synthetic lock (simd-json, 2 URL parsers)", len(bad) == 2, "violations=%d" % len(bad)))
    ok &= len(bad) == 2
    for name, c, detail in results:
        print("  %-44s %s  (%s)" % (name, "caught/ok" if c else "MISSED", detail))
    caught = sum(1 for _, c, _ in results if c)
    if ok:
        print("%s SELF-TEST: PASS (%d/%d checks: %d lenient mutants caught, reference subject passes, golden tamper and "
              "G4 ban caught)" % (NAME, caught, len(results), len(MUTANTS)))
        return 0
    print("%s SELF-TEST: FAIL (%d/%d checks)" % (NAME, caught, len(results)))
    return 1


def main():
    ap = argparse.ArgumentParser(prog="oracles/canon-diff/run", description=__doc__)
    ap.add_argument("--subject", help="command line of a subject speaking the line-oriented JSON protocol (README)")
    ap.add_argument("--g1", type=int, default=100000, help="G1 property cases (0 disables)")
    ap.add_argument("--g2", choices=["pinned", "skip"], default="pinned")
    ap.add_argument("--g3", choices=["ledger", "skip"], default="ledger")
    ap.add_argument("--g4", choices=["lock", "skip"], default="lock")
    ap.add_argument("--lock", default=os.path.normpath(os.path.join(HERE, "..", "..", "Cargo.lock")))
    ap.add_argument("--timeout", type=float, default=300.0, help="seconds per subject batch")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--self-test-g1", type=int, default=3000)
    ap.add_argument("--regen-golden", action="store_true", help="rewrite expected.json from canon_ref.py (review first)")
    ap.add_argument("--serve", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--mutant", help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.serve:
        serve(args.mutant)
        return 0
    if args.regen_golden:
        regen_golden()
        return 0
    if args.self_test:
        return self_test(args)
    argv = shlex.split(args.subject) if args.subject else None
    t0 = time.time()
    n, summary, _ = run_oracle(argv, args.g1, args.g2 == "pinned", args.g3 == "ledger", args.g4 == "lock", args.lock,
                               args.timeout)
    who = "subject=%s" % args.subject if argv else "subject=reference-vs-golden"
    if n == 0:
        print("%s: PASS (%s %s nonzero_cells=0 %.1fs)" % (NAME, who, summary, time.time() - t0))
        return 0
    print("%s: FAIL (%s %s nonzero_cells=%d)" % (NAME, who, summary, n))
    return 1


if __name__ == "__main__":
    sys.exit(main())
