"""q4-008: per-clause CANON-2 false-reject measurement on real request lines (stdlib only; python3 -I -B).

usage:
  python3 -I -B analyze.py --source NAME --format clf|cc [--static-site] --out OUT.json FILE...

  clf: Apache/NCSA common/combined log lines (gz or plain). Apache's %r escaping (\\xHH, \\", \\\\) is undone, so
       the target is the byte string the server received (bytes >= 0x80 become U+0080..U+00FF code points).
  cc : "status<TAB>url" lines written by cc_sample.py (Common Crawl URL index). Path+query and the authority are
       taken from the URL; the authority stands in for Host.

Every target is split at the first '?' into path and query; the path goes through canon_ref.canon_path, the query
through canon_ref.canon_query, the authority (cc only) through canon_ref.canon_authority. The reference verdict is
the ground truth. Independent per-clause detectors (below) mirror each rejecting rule of canon_ref so that a line
that violates several clauses is attributed to all of them; a consistency counter checks that the detectors and the
reference agree on reject/accept for every component (expected 0 disagreements).

Benign classification (documented heuristic; see README): a line is ATTACK if its request line is not HTTP/1.x
origin- or absolute-form with a standard method, if its target or User-Agent matches a signature list, or if its
client IP produced any ATTACK line in the same source (scanner session). Everything else is BENIGN.
"""
import gzip
import json
import re
import sys
from collections import Counter, defaultdict

sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__import__("os").path.abspath(__file__)),
                                              "..", "..", "oracles", "canon-diff"))
import canon_ref as R  # noqa: E402  (reference canonicalizer, imported read-only)

UNRES, PCHAR_LIT, HEXD = R.UNRES, R.PCHAR_LIT, R.HEXD
QLIT = (PCHAR_LIT - frozenset("+&=")) | frozenset("/?")
STD_METHODS = {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"}

PATH_CLAUSES = ["p.not_origin_form", "p.too_long", "p.bad_pct", "p.enc_slash", "p.enc_backslash", "p.enc_semicolon",
                "p.enc_nul", "p.enc_pct", "p.enc_ctrl", "p.enc_nonascii", "p.raw_nonascii", "p.backslash",
                "p.semicolon", "p.space", "p.fragment", "p.raw_ctrl", "p.other_forbidden_ascii", "p.dot_segment",
                "p.empty_segment"]
QUERY_CLAUSES = ["q.too_long", "q.empty_pair", "q.no_eq", "q.multi_eq", "q.empty_name", "q.bad_pct", "q.enc_amp_eq",
                 "q.enc_semicolon", "q.enc_plus", "q.enc_pct", "q.enc_nul_ctrl", "q.enc_nonascii", "q.plus",
                 "q.semicolon", "q.raw_nonascii", "q.space", "q.fragment", "q.raw_ctrl", "q.other_forbidden_ascii",
                 "q.dup_name"]
HOST_CLAUSES = ["h.userinfo", "h.ip_literal", "h.bad_port", "h.non_ascii", "h.too_long", "h.trailing_dot",
                "h.ipv4_noncanonical", "h.underscore", "h.label_not_ldh_other", "h.reserved_rldh", "h.bad_alabel"]
OK308 = "p.trailing_slash_308"
INFO = ["h.uppercase_repaired", "h.port_nondefault", "h.alabel_ok", "h.ipv4_ok", "p.enc_unreserved_repaired",
        "p.lowercase_hex_repaired"]


# ------------------------------------------------------------------ detectors (mirror canon_ref rules, never early-exit)
def _pct_scan(s, i):
    h = s[i + 1:i + 3]
    if len(h) != 2 or not all(x in HEXD for x in h):
        return None, h
    return chr(int(h, 16)), h


def detect_path(t, hits, forb):
    if not t.startswith("/"):
        hits.add("p.not_origin_form")
        return
    if len(t) > R.MAX_PATH:
        hits.add("p.too_long")
    if "#" in t:
        hits.add("p.fragment")
        t = t.split("#", 1)[0]
    out, i = [], 0
    while i < len(t):
        c = t[i]
        if c == "/":
            out.append("/")
            i += 1
            continue
        if c == "%":
            ch, h = _pct_scan(t, i)
            if ch is None:
                hits.add("p.bad_pct")
                out.append("%")
                i += 1
                continue
            if ch in UNRES:
                hits.add("p.enc_unreserved_repaired")
                out.append(ch)
            elif ch == "/":
                hits.add("p.enc_slash")
            elif ch == "\\":
                hits.add("p.enc_backslash")
            elif ch == ";":
                hits.add("p.enc_semicolon")
            elif ch == "\x00":
                hits.add("p.enc_nul")
            elif ch == "%":
                hits.add("p.enc_pct")
            elif ord(ch) < 0x20 or ord(ch) == 0x7F:
                hits.add("p.enc_ctrl")
            elif ord(ch) >= 0x80:
                hits.add("p.enc_nonascii")
            else:
                if h != h.upper():
                    hits.add("p.lowercase_hex_repaired")
                out.append("%" + h.upper())
            i += 3
            continue
        if c not in PCHAR_LIT:
            o = ord(c)
            if o >= 0x80:
                hits.add("p.raw_nonascii")
            elif c == "\\":
                hits.add("p.backslash")
            elif c == ";":
                hits.add("p.semicolon")
            elif c == " ":
                hits.add("p.space")
            elif o < 0x20 or o == 0x7F:
                hits.add("p.raw_ctrl")
            else:
                hits.add("p.other_forbidden_ascii")
                forb[c] += 1
        out.append(c)
        i += 1
    p = "".join(out)
    segs = p.split("/")[1:]
    if any(s in (".", "..") for s in segs):
        hits.add("p.dot_segment")
    if "" in segs[:-1]:
        hits.add("p.empty_segment")
    if len(p) > 1 and p.endswith("/"):
        hits.add(OK308)


def _qcomp(comp, hits, forb):
    o, i = [], 0
    while i < len(comp):
        c = comp[i]
        if c == "%":
            ch, h = _pct_scan(comp, i)
            if ch is None:
                hits.add("q.bad_pct")
                o.append("%")
                i += 1
                continue
            if ch in UNRES:
                o.append(ch)
            elif ch in "&=":
                hits.add("q.enc_amp_eq")
            elif ch == ";":
                hits.add("q.enc_semicolon")
            elif ch == "+":
                hits.add("q.enc_plus")
            elif ch == "%":
                hits.add("q.enc_pct")
            elif ord(ch) < 0x20 or ord(ch) == 0x7F:
                hits.add("q.enc_nul_ctrl")
            elif ord(ch) >= 0x80:
                hits.add("q.enc_nonascii")
            else:
                o.append("%" + h.upper())
            i += 3
            continue
        if c not in QLIT:
            n = ord(c)
            if c == "+":
                hits.add("q.plus")
            elif c == ";":
                hits.add("q.semicolon")
            elif n >= 0x80:
                hits.add("q.raw_nonascii")
            elif c == " ":
                hits.add("q.space")
            elif c == "#":
                hits.add("q.fragment")
            elif n < 0x20 or n == 0x7F:
                hits.add("q.raw_ctrl")
            else:
                hits.add("q.other_forbidden_ascii")
                forb[c] += 1
        o.append(c)
        i += 1
    return "".join(o)


def detect_query(q, hits, forb):
    if q == "":
        return
    if len(q) > R.MAX_PATH:
        hits.add("q.too_long")
    seen = set()
    for part in q.split("&"):
        if not part:
            hits.add("q.empty_pair")
            continue
        ne = part.count("=")
        if ne == 0:
            hits.add("q.no_eq")
            _qcomp(part, hits, forb)
            continue
        if ne > 1:
            hits.add("q.multi_eq")
        n, v = part.split("=", 1)
        nn = _qcomp(n, hits, forb)
        for comp in v.split("="):
            _qcomp(comp, hits, forb)
        if not n:
            hits.add("q.empty_name")
        elif nn in seen:
            hits.add("q.dup_name")
        seen.add(nn)


def detect_host(a, scheme, hits):
    if "@" in a:
        hits.add("h.userinfo")
        a = a.rsplit("@", 1)[1]
    if "[" in a or "]" in a:
        hits.add("h.ip_literal")
        return
    host = a
    if ":" in a:
        host, port = a.rsplit(":", 1)
        ps, err = R._canon_port(port, scheme)
        if err:
            hits.add("h.bad_port")
        elif ps:
            hits.add("h.port_nondefault")
    if not host.isascii():
        hits.add("h.non_ascii")
        return
    if len(host) > R.MAX_HOST:
        hits.add("h.too_long")
    if host != host.lower():
        hits.add("h.uppercase_repaired")
    h = host.lower()
    if h.endswith("."):
        hits.add("h.trailing_dot")
        h = h[:-1]
    if not h:
        hits.add("h.label_not_ldh_other")
        return
    labels = h.split(".")
    last = labels[-1]
    if last.isdigit() or (last.startswith("0x") and all(c in "0123456789abcdef" for c in last[2:])):
        if (not all(lab.isdigit() for lab in labels) or len(labels) != 4
                or any((len(lab) > 1 and lab[0] == "0") or int(lab) > 255 for lab in labels)):
            hits.add("h.ipv4_noncanonical")
        else:
            hits.add("h.ipv4_ok")
        return
    for lab in labels:
        if not R.LDH.match(lab):
            hits.add("h.underscore" if "_" in lab and R.LDH.match(lab.replace("_", "a")) else "h.label_not_ldh_other")
        elif len(lab) >= 4 and lab[2:4] == "--":
            if not lab.startswith("xn--"):
                hits.add("h.reserved_rldh")
            elif not R._alabel_ok(lab):
                hits.add("h.bad_alabel")
            else:
                hits.add("h.alabel_ok")


# ------------------------------------------------------------------ benign / attack heuristic
SIG_TARGET = re.compile("|".join([
    r"(?:\.\./.*){2,}", r"\.\.\\", r"\.\.;", r"%2e%2e", r"%252e", r"%c0%ae", r"%c0%af", r"%e0%80%ae", r"\.\.%2f",
    r"\.\.%5c", r"\.%2e/", r"%2e\./",
    r"/etc/(?:passwd|shadow|hosts)", r"win\.ini", r"boot\.ini", r"/proc/self", r"(?:^|/)\.env(?:$|[./?])",
    r"/\.git(?:/|$)", r"/\.svn", r"/\.hg/", r"\.ds_store", r"\.htaccess", r"\.htpasswd", r"wp-config", r"web\.config",
    r"id_rsa", r"/\.aws/", r"/\.ssh", r"/\.vscode", r"/\.docker", r"\.bash_history",
    r"wp-login\.php", r"xmlrpc\.php", r"/wp-admin", r"/wp-includes", r"/wp-content/plugins", r"phpmyadmin", r"/pma/",
    r"myadmin", r"/phpunit", r"eval-stdin", r"/actuator", r"/manager/html", r"/hnap1", r"/boaform", r"/goform",
    r"setup\.cgi", r"/cgi-bin/(?:.*(?:sh|bash|test-cgi|php|luci))", r"/solr/admin", r"/jmx-console", r"/invoker/",
    r"/vendor/", r"/autodiscover", r"/owa/", r"/ecp/", r"/geoserver", r"/remote/login", r"/sdk$", r"/console/",
    r"/druid/", r"/telescope", r"/_ignition", r"/\+cscoe\+", r"/dana-na", r"/global-protect", r"/mgmt/tm",
    r"/shell", r"/webshell", r"c99\.php", r"r57\.php", r"/admin/config\.php", r"/server-status", r"/config\.json$",
    r"union(?:\s|\+|%20|/\*.*?\*/)+(?:all(?:\s|\+|%20)+)?select", r"select(?:\s|\+|%20).*(?:\s|\+|%20)from",
    r"information_schema", r"sleep\(\d", r"benchmark\(", r"waitfor(?:\s|\+|%20)delay", r"(?:'|%27)(?:\s|\+|%20)*or",
    r"or(?:\s|\+|%20)+1=1", r"<script", r"%3cscript", r"javascript:", r"onerror=", r"onload=", r"alert\(",
    r"\$\{jndi", r"%24%7bjndi", r"\$\{", r"%24%7b", r"\(\)(?:\s|%20)*\{", r"/bin/(?:ba)?sh", r"cmd\.exe", r"powershell",
    r"wget(?:\s|\+|%20)", r"curl(?:\s|\+|%20)", r"base64_decode", r"eval\(", r"exec\(", r"system\(", r"passthru",
    r"allow_url_include", r"auto_prepend", r"php://", r"file://", r"data://", r"expect://", r"%00", r"\x00",
    r"/bins/", r"mozi\.", r"\.sh(?:$|\?)", r"chmod", r"/tmp/",
]), re.I | re.S)
SIG_STATIC = re.compile(r"\.(?:php\d?|asp|aspx|jsp|jspa|cgi|pl|do|action|cfm)(?:$|[/?;])", re.I)
SIG_UA = re.compile(r"nikto|sqlmap|nmap|masscan|zgrab|nuclei|acunetix|dirbuster|gobuster|wpscan|morfeus|netsparker|"
                    r"w3af|openvas|nessus|qualys|censys|shodan|expanse|internet-measurement|l9explore|l9tcpid|"
                    r"projectdiscovery|httpx|fuzz|ffuf|wfuzz|feroxbuster|jaeles|zmeu|hello, world|"
                    r"\bhello\b|scanner|scan\b|exploit|libredtail|ivre-masscan|keydrop|xfa1|"
                    r"modatscanner|odin|cortex|paloalto|stretchoid|leakix|netcraft", re.I)


def unescape_apache(s):
    if "\\" not in s:
        return s
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n == "x" and i + 3 < len(s) + 0 and all(ch in HEXD for ch in s[i + 2:i + 4]) and len(s[i + 2:i + 4]) == 2:
                out.append(chr(int(s[i + 2:i + 4], 16)))
                i += 4
                continue
            if n in "\"\\":
                out.append(n)
                i += 2
                continue
            if n in "nrtv":
                out.append({"n": "\n", "r": "\r", "t": "\t", "v": "\v"}[n])
                i += 2
                continue
        out.append(c)
        i += 1
    return "".join(out)


CLF = re.compile(r'^(\S+) \S+ \S+ \[[^\]]*\] "((?:[^"\\]|\\.)*)" (\S+) (\S+)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?')
CLF_LOOSE = re.compile(r'^(\S+) \S+ \S+ \[[^\]]*\] "(.*)" (\S+) (\S+)\s*$')


def parse_clf(line, apache_escapes):
    m = CLF.match(line) if apache_escapes else None
    if m:
        ip, rl, ua = m.group(1), unescape_apache(m.group(2)), unescape_apache(m.group(6) or "")
    else:
        m = CLF_LOOSE.match(line)
        if not m:
            return None
        ip, rl, ua = m.group(1), m.group(2), ""
    return ip, rl, ua


def split_request_line(rl):
    """-> (method, target, version, shape) with shape in ok|http09|nonhttp."""
    toks = rl.split(" ")
    if len(toks) >= 3 and re.fullmatch(r"HTTP/\d(?:\.\d)?", toks[-1]):
        return toks[0], " ".join(toks[1:-1]), toks[-1], "ok"
    if len(toks) == 2 and re.fullmatch(r"[A-Z]+", toks[0]):
        return toks[0], toks[1], "", "http09"
    return "", rl, "", "nonhttp"


def wire_ok_bytes(s):
    return all(ord(c) < 256 for c in s)


# ------------------------------------------------------------------ analysis
class Stats:
    def __init__(self):
        self.lines = 0
        self.lines_ref_reject = 0
        self.lines_ref_308 = 0
        self.any = Counter()
        self.sole = Counter()
        self.first = Counter()
        self.uniq_targets = set()
        self.uniq_any = Counter()
        self.examples = defaultdict(list)

    def add(self, target, rej_clauses, all_hits, ref_reasons, is_308):
        self.lines += 1
        new = target not in self.uniq_targets
        if new and len(self.uniq_targets) < 3_000_000:
            self.uniq_targets.add(target)
        if rej_clauses:
            self.lines_ref_reject += 1
        elif is_308:
            self.lines_ref_308 += 1
        for c in all_hits:
            self.any[c] += 1
            if new:
                self.uniq_any[c] += 1
            if len(self.examples[c]) < 6 and target not in self.examples[c]:
                self.examples[c].append(target)
        if len(rej_clauses) == 1:
            self.sole[next(iter(rej_clauses))] += 1
        for r in ref_reasons:
            self.first[r] += 1

    def dump(self):
        n = self.lines or 1
        u = len(self.uniq_targets) or 1
        clauses = {}
        for c in PATH_CLAUSES + [OK308] + QUERY_CLAUSES + HOST_CLAUSES + INFO:
            clauses[c] = {"lines": self.any[c], "pct_lines": round(100.0 * self.any[c] / n, 4),
                          "sole_cause_lines": self.sole[c], "pct_sole": round(100.0 * self.sole[c] / n, 4),
                          "unique_targets": self.uniq_any[c], "pct_unique": round(100.0 * self.uniq_any[c] / u, 4),
                          "examples": [e[:160].encode("unicode_escape").decode("ascii") for e in self.examples[c]]}
        return {"lines": self.lines, "unique_targets": len(self.uniq_targets),
                "ref_reject_lines": self.lines_ref_reject,
                "pct_ref_reject": round(100.0 * self.lines_ref_reject / n, 4),
                "ref_308_lines": self.lines_ref_308, "pct_ref_308": round(100.0 * self.lines_ref_308 / n, 4),
                "clauses": clauses, "ref_reasons_top": dict(self.first.most_common(40))}


REASON_NORM = re.compile(r"%[0-9A-F]{2}|U\+[0-9A-F]{4}|redirect to .*")


def analyze_target(target, authority, scheme, memo, consistency, forb_p, forb_q):
    key = (target, authority)
    r = memo.get(key)
    if r is not None:
        return r
    hits = set()
    reasons = []
    rej = set()
    if authority is not None:
        hh = set()
        detect_host(authority, scheme, hh)
        st, v = R.canon_authority(authority, scheme)
        hrej = {c for c in hh if c in HOST_CLAUSES}
        if (st == R.REJECT) != bool(hrej):
            consistency["host"] += 1
            if len(consistency["examples"]) < 20:
                consistency["examples"].append(["host", authority, v])
        if st == R.REJECT:
            reasons.append("host: " + v)
        hits |= hh
        rej |= hrej
    if "?" in target:
        path, query = target.split("?", 1)
    else:
        path, query = target, None
    ph = set()
    detect_path(path, ph, forb_p)
    st, v = R.canon_path(path)
    prej = {c for c in ph if c in PATH_CLAUSES}
    is308 = st == R.REJECT and v.startswith("308")
    if (st == R.REJECT and not is308) != bool(prej):
        consistency["path"] += 1
        if len(consistency["examples"]) < 20:
            consistency["examples"].append(["path", path[:200], v])
    if st == R.REJECT:
        reasons.append(REASON_NORM.sub("X", v))
    hits |= ph
    rej |= prej
    if query is not None:
        qh = set()
        detect_query(query, qh, forb_q)
        st, v = R.canon_query(query)
        qrej = {c for c in qh if c in QUERY_CLAUSES}
        if (st == R.REJECT) != bool(qrej):
            consistency["query"] += 1
            if len(consistency["examples"]) < 20:
                consistency["examples"].append(["query", query[:200], v])
        if st == R.REJECT:
            reasons.append(REASON_NORM.sub("X", v))
        hits |= qh
        rej |= qrej
    r = (frozenset(rej), frozenset(hits), tuple(reasons), is308 and not rej)
    if len(memo) < 2_000_000:
        memo[key] = r
    return r


def is_attack_target(target, static_site):
    t = target
    if SIG_TARGET.search(t):
        return True
    try:
        d = re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), t)
        d2 = re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), d)
    except ValueError:
        d = d2 = t
    if d != t and (SIG_TARGET.search(d) or SIG_TARGET.search(d2)):
        return True
    if static_site and SIG_STATIC.search(t.split("?", 1)[0]):
        return True
    return False


def open_any(fn):
    if fn.endswith(".gz"):
        return gzip.open(fn, "rt", encoding="latin-1", newline="\n")
    return open(fn, "rt", encoding="latin-1", newline="\n")


def iter_clf(files, apache_escapes, meta):
    for fn in files:
        try:
            fh = open_any(fn)
            for line in fh:
                line = line.rstrip("\r\n")
                meta["raw_lines"] += 1
                p = parse_clf(line, apache_escapes)
                if p is None:
                    meta["unparsed_log_lines"] += 1
                    continue
                yield p
        except (OSError, EOFError) as e:
            meta["file_errors"].append("%s: %s" % (fn, e))


def run(argv):
    opts = {"--source": None, "--format": None, "--out": None}
    flags = set()
    files = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in opts:
            opts[a] = argv[i + 1]
            i += 2
        elif a in ("--static-site", "--no-apache-escapes"):
            flags.add(a)
            i += 1
        else:
            files.append(a)
            i += 1
    fmt, static_site = opts["--format"], "--static-site" in flags
    apache = "--no-apache-escapes" not in flags
    meta = Counter()
    meta["file_errors"] = []
    shapes = Counter()
    methods = Counter()
    consistency = Counter()
    consistency["examples"] = []
    forb_p, forb_q = Counter(), Counter()
    memo = {}
    raw, benign = Stats(), Stats()
    attack_reasons = Counter()

    if fmt == "clf":
        # pass 1: scanner sessions (client IPs with any attack line)
        bad_ips = set()
        m1 = Counter()
        m1["file_errors"] = []
        for ip, rl, ua in iter_clf(files, apache, m1):
            method, target, ver, shape = split_request_line(rl)
            if (shape != "ok" or method not in STD_METHODS or not target.startswith("/")
                    or is_attack_target(target, static_site) or (ua and SIG_UA.search(ua))):
                bad_ips.add(ip)
        for ip, rl, ua in iter_clf(files, apache, meta):
            method, target, ver, shape = split_request_line(rl)
            shapes[shape] += 1
            methods[method if method in STD_METHODS else ("OTHER" if method else "-")] += 1
            if shape == "nonhttp":
                attack_reasons["nonhttp_request_line"] += 1
                meta["excluded_nonhttp"] += 1
                continue                                   # not an HTTP request target at all: excluded entirely
            rej, hits, reasons, is308 = analyze_target(target, None, "https", memo, consistency, forb_p, forb_q)
            raw.add(target, rej, hits, reasons, is308)
            why = None
            if shape != "ok":
                why = "http09_or_malformed"
            elif method not in STD_METHODS:
                why = "nonstandard_method"
            elif not target.startswith("/"):
                why = "absolute_or_asterisk_form"
            elif is_attack_target(target, static_site):
                why = "target_signature"
            elif ua and SIG_UA.search(ua):
                why = "scanner_user_agent"
            elif ip in bad_ips:
                why = "scanner_session_ip"
            if why:
                attack_reasons[why] += 1
                continue
            benign.add(target, rej, hits, reasons, is308)
        meta["attack_client_ips"] = len(bad_ips)
    elif fmt == "cc":
        for fn in files:
            for line in open_any(fn):
                meta["raw_lines"] += 1
                status, _, url = line.rstrip("\n").partition("\t")
                m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)(.*)$", url)
                if not m:
                    meta["unparsed_log_lines"] += 1
                    continue
                scheme, auth, rest = m.group(1).lower(), m.group(2), m.group(3)
                if scheme not in ("http", "https"):
                    meta["non_http_scheme"] += 1
                    continue
                target = rest if rest.startswith("/") else "/" + rest   # "" or "?q" -> origin-form "/" ...
                meta["status_" + status[:1]] += 1
                # cdx stores the URL as the crawler requested it; it is decoded from UTF-8, so code points
                # >= 0x80 here are raw non-ASCII (the crawler would send them as UTF-8 bytes)
                rej, hits, reasons, is308 = analyze_target(target, auth, scheme, memo, consistency, forb_p, forb_q)
                raw.add(target, rej, hits, reasons, is308)
                if is_attack_target(target, False):
                    attack_reasons["target_signature"] += 1
                    continue
                benign.add(target, rej, hits, reasons, is308)
    else:
        raise SystemExit("--format clf|cc")

    out = {"source": opts["--source"], "format": fmt, "static_site_signatures": static_site, "files": len(files),
           "meta": {k: v for k, v in meta.items()}, "request_line_shapes": dict(shapes), "methods": dict(methods),
           "attack_exclusions": dict(attack_reasons),
           "detector_vs_reference_disagreements": {k: v for k, v in consistency.items()},
           "forbidden_ascii_chars_path": {repr(k): v for k, v in forb_p.most_common(20)},
           "forbidden_ascii_chars_query": {repr(k): v for k, v in forb_q.most_common(20)},
           "raw": raw.dump(), "benign": benign.dump()}
    with open(opts["--out"], "w") as f:
        json.dump(out, f, indent=1, sort_keys=False)
    sys.stderr.write("%s: raw=%d benign=%d ref_reject raw=%.3f%% benign=%.3f%% disagreements=%s\n" % (
        opts["--source"], raw.lines, benign.lines, out["raw"]["pct_ref_reject"], out["benign"]["pct_ref_reject"],
        {k: v for k, v in consistency.items() if k != "examples"}))


if __name__ == "__main__":
    run(sys.argv[1:])
