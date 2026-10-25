"""AEGIS canon-diff reference canonicalizer (spec-by-code for SPEC_INVARIANTS D: CANON-1..8, H1(c) header rules).

Ported and reviewed from research/state/raw/round-004/07-work/canon_ref.py (see README.md for provenance and every
deliberate deviation). Python stdlib only; run under `python3 -I`. No I/O, no IDNA, no WHATWG parsing.

Every canon_* function returns ("accept", canonical) or ("reject", reason). It never raises on any input of the
documented type; the driver also checks totality on random inputs (G1).

Rules (CANON-2 "reject, don't repair"): anything with more than one plausible reading is rejected. The only repairs:
  * RFC 3986 6.2.2.1  uppercase percent-encoding hex digits; lowercase scheme and (ASCII) host;
  * RFC 3986 6.2.2.2  decode percent-encoded unreserved characters;
  * RFC 3986 6.2.3    strip the scheme's default port (authority, Origin) -- the research owner table lists it in
                      the safe set and the hyper/h2 regression (:authority A.example:443 == Host a.example) needs it;
  * ASCII-lowercasing of tokens that the governing RFC defines as case-insensitive (media type/subtype, parameter
    names, header field names, charset value). This is canonicalization of a single reading, not a repair.
6.2.2.3 (remove_dot_segments) is deliberately NOT applied: dot segments are rejected (CANON-2 overrides).

Per-clause outcomes fixed by spike q4-008 (spikes/q4-008/verdict.json; F8 `canon` block; CANON-2 text), each one
because the benign false-reject rate of the old reject exceeded 0.1%:
  * empty segments ("//")      -> 308 to the slash-merged path (a reject whose reason starts with "308"; nothing is
                                  forwarded in the non-canonical form). F8 canon.empty_segments = redirect_308.
  * trailing slash             -> accepted as its own canonical form: "/a/" != "/a", no 308. canon.trailing_slash = accept.
  * %80-%FF path escapes       -> kept as opaque uppercase-hex octets (never decoded or Unicode-normalized for
                                  matching); rejected if the percent-decoded path is not strict UTF-8 (overlong,
                                  surrogates, truncated) or not NFC. canon.encoded_non_ascii_path = accept_opaque.
  * query                      -> canon_query is the default `opaque` mode: only 6.2.2.1/6.2.2.2 are applied and
                                  the rest is forwarded byte-exact, never split or reordered. canon_query_typed is
                                  the `typed` mode (route-declared parameters): the old strict per-parameter rules.
Unchanged: dot segments, encoded / \\ ; NUL controls %25, raw \\ ; and raw non-ASCII in paths, host rules, headers.
"""
import json
import re
import unicodedata

ACCEPT, REJECT = "accept", "reject"
UNRES = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
PCHAR_LIT = UNRES | frozenset("!$&'()*+,=:@")          # ';' deliberately excluded (matrix-param confusion)
HEXD = frozenset("0123456789abcdefABCDEF")
TCHAR = frozenset("!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
COOKIE_OCTET = frozenset(chr(c) for c in [0x21] + list(range(0x23, 0x2C)) + list(range(0x2D, 0x3B))
                         + list(range(0x3C, 0x5C)) + list(range(0x5D, 0x7F)))
LDH = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")  # used with fullmatch: `$` would also match before a trailing "\n"
DEFAULT_PORT = {"http": 80, "https": 443}
MAX_PATH, MAX_HOST, MAX_JSON, MAX_JSON_DEPTH = 8192, 253, 1 << 20, 64


def _rej(reason):
    return (REJECT, reason)


def _acc(v):
    return (ACCEPT, v)


def _is_str(x):
    return isinstance(x, str)


# ---------------------------------------------------------------- route path (origin-form, no query)
def canon_path(t):
    if not _is_str(t):
        return _rej("400 path: not a string")
    if len(t) > MAX_PATH:
        return _rej("414 path: too long")
    if not t.startswith("/"):
        return _rej("400 path: not origin-form")
    if "?" in t or "#" in t:
        return _rej("400 path: query/fragment in path kind")
    out = []
    i = 0
    while i < len(t):
        c = t[i]
        if c == "/":
            out.append("/")
            i += 1
            continue
        if c == "%":
            h = t[i + 1:i + 3]
            if len(h) != 2 or not all(x in HEXD for x in h):
                return _rej("400 path: bad percent-escape")
            ch = chr(int(h, 16))
            if ch in UNRES:
                out.append(ch)                                # 6.2.2.2 decode unreserved
            elif ch in "/\\;\x00%" or ord(ch) < 0x20 or ord(ch) == 0x7F:
                return _rej("400 path: ambiguous percent-escape %" + h.upper())
            else:
                out.append("%" + h.upper())                   # 6.2.2.1 uppercase hex
            i += 3
            continue
        if c not in PCHAR_LIT:
            return _rej("400 path: forbidden character U+%04X" % ord(c))
        out.append(c)
        i += 1
    p = "".join(out)
    segs = p.split("/")[1:]
    if any(s in (".", "..") for s in segs):
        return _rej("400 path: dot segment")
    if "%" in p:                                          # %80-%FF kept opaque, but must be one strict UTF-8, NFC reading
        raw = _pct_bytes(p)
        try:
            u = raw.decode("utf-8", errors="strict")      # rejects overlong forms, surrogates, truncated sequences
        except UnicodeDecodeError:
            return _rej("400 path: encoded octets are not valid UTF-8")
        if unicodedata.normalize("NFC", u) != u:
            return _rej("400 path: encoded octets are not NFC")
    if "" in segs[:-1]:                                   # '//' anywhere (a single trailing '/' is its own form)
        return _rej("308 path: empty segment, redirect to " + _merge_slashes(p))
    return _acc(p)


def _pct_bytes(p):
    """Percent-decode an already validated path (every '%' starts a 2-hex-digit escape) to bytes."""
    b, i = bytearray(), 0
    while i < len(p):
        if p[i] == "%":
            b.append(int(p[i + 1:i + 3], 16))
            i += 3
        else:
            b.extend(p[i].encode("ascii"))
            i += 1
    return bytes(b)


def _merge_slashes(p):
    return re.sub("/{2,}", "/", p)


def redirect_target(reason):
    """The Location of a 308 reject reason, or None."""
    m = re.match(r"^308 .*, redirect to (/\S*)$", reason or "")
    return m.group(1) if m else None


# ---------------------------------------------------------------- query, opaque mode (F8 canon.query = opaque, default)
QUERY_LIT = PCHAR_LIT | frozenset(";/?")                 # RFC 3986 query = *( pchar / "/" / "?" ); pchar has ';'


def canon_query(q):
    """Opaque mode (q4-008): the query is canonicalized only by RFC 3986 6.2.2.1 (uppercase hex) and 6.2.2.2 (decode
    unreserved) and otherwise forwarded byte-exact. It is never split, reordered or de-duplicated by the core; '+',
    ';', '%26', '%3D', '%25', %80-%FF, repeated names and name-only tokens are all accepted (authz never keys on the
    query, CANON-5). Still rejected: bad percent-escape, raw non-ASCII, raw space / forbidden ASCII / '#', encoded or
    raw NUL and controls (%00-%1F, %7F), length > 8192, an empty pair ('&&', leading or trailing '&'), an empty name
    ('=v'), and %2B."""
    if not _is_str(q):
        return _rej("400 query: not a string")
    if q == "":
        return _acc("")
    if len(q) > MAX_PATH:
        return _rej("414 query: too long")
    o, i = [], 0
    while i < len(q):
        c = q[i]
        if c == "%":
            h = q[i + 1:i + 3]
            if len(h) != 2 or not all(x in HEXD for x in h):
                return _rej("400 query: bad percent-escape")
            n = int(h, 16)
            ch = chr(n)
            if ch in UNRES:
                o.append(ch)                              # 6.2.2.2
            elif n < 0x20 or n == 0x7F or ch == "+":
                return _rej("400 query: rejected percent-escape %" + h.upper())
            else:
                o.append("%" + h.upper())                 # 6.2.2.1; %80-%FF opaque octets
            i += 3
            continue
        if c not in QUERY_LIT:
            return _rej("400 query: forbidden character U+%04X" % ord(c))
        o.append(c)
        i += 1
    for part in q.split("&"):                             # lexical checks only; the output is never split
        if not part:
            return _rej("400 query: empty pair")
        if part.startswith("="):
            return _rej("400 query: empty name")
    return _acc("".join(o))


# ---------------------------------------------------------------- query, typed mode (route-declared parameters, strict)
def canon_query_typed(q):
    """Typed mode (F8 canon.query = typed, per route). '&' is the only separator (';' rejected: python-multipart CVE-2026-53538); every pair is name=value; '+' is
    rejected (space-or-plus has two readings); escapes as in paths but %26 %3D %3B %2B %25 %00 and controls are
    rejected; duplicate decoded names are rejected (no route-declared list parameters in this model)."""
    if not _is_str(q):
        return _rej("400 query: not a string")
    if q == "":
        return _acc("")
    if len(q) > MAX_PATH:
        return _rej("414 query: too long")
    pairs, seen = [], set()
    for part in q.split("&"):
        if not part:
            return _rej("400 query: empty pair")
        if part.count("=") != 1:
            return _rej("400 query: pair must be exactly name=value")
        outs = []
        for comp in part.split("="):
            o, i = [], 0
            while i < len(comp):
                c = comp[i]
                if c == "%":
                    h = comp[i + 1:i + 3]
                    if len(h) != 2 or not all(x in HEXD for x in h):
                        return _rej("400 query: bad percent-escape")
                    ch = chr(int(h, 16))
                    if ch in UNRES:
                        o.append(ch)
                    elif ch in "&=;+%\x00" or ord(ch) < 0x20 or ord(ch) >= 0x7F:
                        return _rej("400 query: ambiguous percent-escape %" + h.upper())
                    else:
                        o.append("%" + h.upper())
                    i += 3
                    continue
                if c not in (PCHAR_LIT - frozenset("+&=")) and c not in "/?":
                    return _rej("400 query: forbidden character U+%04X" % ord(c))
                o.append(c)
                i += 1
            outs.append("".join(o))
        n, v = outs
        if not n:
            return _rej("400 query: empty name")
        if n in seen:
            return _rej("400 query: duplicate name")
        seen.add(n)
        pairs.append(n + "=" + v)
    return _acc("&".join(pairs))


# ---------------------------------------------------------------- host (bare, no port): exact A-label form
def _alabel_ok(label):
    """Structural RFC 3492 check only (no IDNA mapping, no UTS-46, nothing is ever decoded for matching): the ACE
    suffix must punycode-decode to a non-ASCII string of letters/marks/digits/'-' that is NFC and lowercase, and
    re-encode to exactly the same label. The host is then matched byte-exactly as the A-label."""
    body = label[4:]
    if not body:
        return False
    try:
        u = body.encode("ascii").decode("punycode")
        if u.isascii():
            return False
        # validity filter, not a mapping: letters/marks/digits or '-', already NFC, already lowercase
        if any(not (ch == "-" or unicodedata.category(ch)[0] in "LMN") for ch in u):
            return False
        if unicodedata.normalize("NFC", u) != u or u.lower() != u:
            return False
        return u.encode("punycode").decode("ascii") == body
    except Exception:
        return False


def canon_host(h):
    if not _is_str(h):
        return _rej("400 host: not a string")
    if not h:
        return _rej("400 host: empty")
    if not h.isascii():
        return _rej("400 host: non-ASCII (A-labels only, no IDNA on ingress)")
    if len(h) > MAX_HOST:
        return _rej("400 host: too long")
    h = h.lower()                                         # ASCII-only here, so this is ASCII lowercasing
    if h.endswith("."):
        return _rej("400 host: trailing dot")
    labels = h.split(".")
    last = labels[-1]
    ends_in_number = last.isdigit() or (last.startswith("0x") and all(c in "0123456789abcdef" for c in last[2:]))
    if ends_in_number:                                    # WHATWG 'ends in a number' => canonical dotted quad only
        if not all(lab.isdigit() for lab in labels):
            return _rej("400 host: non-canonical IPv4")
        if len(labels) != 4 or any((len(lab) > 1 and lab[0] == "0") or int(lab) > 255 for lab in labels):
            return _rej("400 host: non-canonical IPv4")
        return _acc(h)
    for lab in labels:
        if not LDH.fullmatch(lab):
            return _rej("400 host: label not LDH")
        if len(lab) >= 4 and lab[2:4] == "--":
            if not lab.startswith("xn--"):
                return _rej("400 host: reserved R-LDH label")
            if not _alabel_ok(lab):
                return _rej("400 host: malformed A-label")
    return _acc(h)


def _canon_port(p, scheme):
    if p == "" or not p.isdigit() or not p.isascii() or len(p) > 5 or (len(p) > 1 and p[0] == "0"):
        return None, "bad port"
    n = int(p)
    if not 1 <= n <= 65535:
        return None, "bad port"
    return ("" if DEFAULT_PORT.get(scheme) == n else ":%d" % n), None


def canon_authority(a, scheme="https"):
    """:authority / Host value: host[:port]. userinfo and IP-literals rejected; default port stripped."""
    if not _is_str(a):
        return _rej("400 authority: not a string")
    if "@" in a:
        return _rej("400 authority: userinfo")
    if "[" in a or "]" in a:
        return _rej("400 authority: IP-literal not served")
    host, port = a, None
    if ":" in a:
        host, port = a.rsplit(":", 1)
    if port is not None:
        ps, err = _canon_port(port, scheme)
        if err:
            return _rej("400 authority: " + err)
    else:
        ps = ""
    st, hv = canon_host(host)
    if st == REJECT:
        return _rej("400 authority: " + hv.split(" ", 1)[1])
    return _acc(hv + ps)


# ---------------------------------------------------------------- Origin (serialized origin, RFC 6454)
ORIGIN_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*)://([^/?#\\]*)")  # fullmatch


def canon_origin(o):
    if not _is_str(o):
        return _rej("403 origin: not a string")
    if o == "null":
        return _rej("403 origin: opaque 'null'")
    if not o.isascii() or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in o):
        return _rej("403 origin: non-ASCII/control/space")
    m = ORIGIN_RE.fullmatch(o)
    if not m:
        return _rej("403 origin: not a serialized origin")
    scheme, auth = m.group(1).lower(), m.group(2)
    if scheme not in DEFAULT_PORT:
        return _rej("403 origin: scheme")
    if "%" in auth:
        return _rej("403 origin: percent-encoding in host")
    st, av = canon_authority(auth, scheme)
    if st == REJECT:
        return _rej("403 origin: " + av.split(" ", 1)[1])
    return _acc(scheme + "://" + av)


# ---------------------------------------------------------------- Cookie request header (RFC 6265bis, strict)
def canon_cookie(c):
    if not _is_str(c):
        return _rej("400 cookie: not a string")
    if not c.isascii():
        return _rej("400 cookie: non-ASCII (NBSP etc. never trimmed)")
    c = c.strip(" \t")                                    # field-value OWS only
    if not c:
        return _rej("400 cookie: empty")
    parts = c.split(";")
    jar, seen_ci = [], set()
    for i, part in enumerate(parts):
        if i > 0:
            part = part.lstrip(" ")                       # "; " separator (SP only)
        if not part:
            return _rej("400 cookie: empty cookie-pair")
        if "=" not in part:
            return _rej("400 cookie: nameless/valueless pair")
        k, v = part.split("=", 1)
        if not k or any(ch not in TCHAR for ch in k):
            return _rej("400 cookie: bad name")
        if k[0] == "$" or "%" in k:
            return _rej("400 cookie: legacy/percent-encoded name")
        kl = k.lower()
        if kl.startswith(("__host-", "__secure-")) and not k.startswith(("__Host-", "__Secure-")):
            return _rej("400 cookie: miscapitalized prefix")
        if kl in seen_ci:
            return _rej("400 cookie: duplicate name")
        if v.startswith('"'):
            return _rej("400 cookie: quoted value")
        if any(ch not in COOKIE_OCTET for ch in v):
            return _rej("400 cookie: bad value octet")
        seen_ci.add(kl)
        jar.append((k, v))
    return _acc("; ".join("%s=%s" % kv for kv in jar))


# ---------------------------------------------------------------- media type (Content-Type)
def canon_media_type(ct):
    if not _is_str(ct):
        return _rej("415 media-type: not a string")
    if not ct or not ct.isascii() or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in ct):
        return _rej("415 media-type: empty/non-ASCII/control")
    if ct != ct.strip(" "):
        return _rej("415 media-type: surrounding whitespace")
    parts = ct.split(";")
    ess = parts[0]
    if ess.count("/") != 1:
        return _rej("415 media-type: essence")
    t, s = ess.split("/")
    if not t or not s or any(ch not in TCHAR for ch in t + s) or "*" in (t + s):
        return _rej("415 media-type: essence")
    out = t.lower() + "/" + s.lower()
    seen = set()
    for p in parts[1:]:
        p = p.lstrip(" ")
        if not p:
            return _rej("415 media-type: empty parameter")
        if "=" not in p:
            return _rej("415 media-type: parameter without value")
        n, v = p.split("=", 1)
        if not n or any(ch not in TCHAR for ch in n):
            return _rej("415 media-type: bad parameter name")
        if v.startswith('"'):
            return _rej("415 media-type: quoted parameter value")
        if not v or any(ch not in TCHAR for ch in v):
            return _rej("415 media-type: bad parameter value")
        n = n.lower()
        if n in seen:
            return _rej("415 media-type: duplicate parameter")
        seen.add(n)
        out += "; %s=%s" % (n, v.lower() if n == "charset" else v)
    return _acc(out)


# ---------------------------------------------------------------- JSON body (I-JSON, RFC 7493, strict)
class _JErr(ValueError):
    pass


_NUM_SIG = re.compile(r"-?(\d+)(?:\.(\d+))?(?:[eE][+-]?\d+)?")  # fullmatch


def canon_json(s):
    if not _is_str(s):
        return _rej("400 json: not a string")
    if len(s) > MAX_JSON:
        return _rej("413 json: too large")
    if s.startswith("﻿"):
        return _rej("400 json: BOM")

    def hook(kv):
        keys = [k for k, _ in kv]
        if len(keys) != len(set(keys)):
            raise _JErr("duplicate name")
        if len(keys) != len(set(k.lower() if k.isascii() else k for k in keys)):
            raise _JErr("names collide under ASCII case-folding")   # Go encoding/json matches fields case-insensitively
        return dict(kv)

    def pint(x):
        if x.startswith("-") and x.strip("-0") == "":
            raise _JErr("negative zero")
        n = int(x)
        if abs(n) > 2 ** 53 - 1:
            raise _JErr("integer outside I-JSON range")
        return n

    def pfloat(x):
        m = _NUM_SIG.fullmatch(x)
        digits = ((m.group(1) or "") + (m.group(2) or "")).lstrip("0") if m else x
        f = float(x)
        if f != f or f in (float("inf"), float("-inf")):
            raise _JErr("non-finite number")
        if f == 0.0 and digits.strip("0"):
            raise _JErr("underflow")
        if f == 0.0 and x.startswith("-"):
            raise _JErr("negative zero")
        if len(digits.rstrip("0")) > 17:
            raise _JErr("precision beyond binary64")
        return f

    def pconst(x):
        raise _JErr("non-finite constant " + x)

    try:
        v = json.loads(s, object_pairs_hook=hook, parse_int=pint, parse_float=pfloat, parse_constant=pconst)
    except _JErr as e:
        return _rej("400 json: " + str(e))
    except (ValueError, RecursionError):
        return _rej("400 json: syntax")

    def chk(o, d):
        if d > MAX_JSON_DEPTH:
            raise _JErr("too deep")
        if isinstance(o, str):
            if "\x00" in o:
                raise _JErr("NUL in string")
            o.encode("utf-8")                             # lone surrogates raise UnicodeEncodeError
        elif isinstance(o, dict):
            for k, x in o.items():
                chk(k, d + 1)
                chk(x, d + 1)
        elif isinstance(o, list):
            for x in o:
                chk(x, d + 1)
    try:
        chk(v, 0)
    except _JErr as e:
        return _rej("400 json: " + str(e))
    except UnicodeEncodeError:
        return _rej("400 json: lone surrogate")
    except RecursionError:
        return _rej("400 json: too deep")
    return _acc(json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False))


# ---------------------------------------------------------------- principal / tenant id
TENANT_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def canon_tenant(t):
    if not _is_str(t):
        return _rej("400 tenant: not a string")
    return _acc(t) if TENANT_RE.fullmatch(t) else _rej("400 tenant: not an ASCII slug (no folding)")


# ---------------------------------------------------------------- HTTP/1.1 header block (H1 grammar (c), CANON-2)
LIST_FIELDS = frozenset(["accept", "accept-charset", "accept-encoding", "accept-language", "cache-control", "pragma",
                         "via", "warning", "te", "if-match", "if-none-match"])


def canon_headers(lines):
    """lines: list of raw field lines without CRLF. Every field is a singleton unless it is a declared list field."""
    if not isinstance(lines, list) or not all(_is_str(x) for x in lines):
        return _rej("400 headers: not a list of strings")
    out, seen = [], set()
    for ln in lines:
        if not ln.isascii():
            return _rej("400 headers: obs-text")
        if ln[:1] in (" ", "\t"):
            return _rej("400 headers: obs-fold")
        if any((ord(ch) < 0x20 and ch != "\t") or ord(ch) == 0x7F for ch in ln):
            return _rej("400 headers: control character")
        if ":" not in ln:
            return _rej("400 headers: no colon")
        n, v = ln.split(":", 1)
        if not n or any(ch not in TCHAR for ch in n):
            return _rej("400 headers: bad field name (whitespace before colon?)")
        n = n.lower()
        v = v.strip(" \t")
        if n in seen and n not in LIST_FIELDS:
            return _rej("400 headers: duplicate singleton field " + n)
        seen.add(n)
        out.append([n, v])
    names = [n for n, _ in out]
    if "content-length" in names and "transfer-encoding" in names:
        return _rej("400 headers: CL+TE")
    for n, v in out:
        if n == "transfer-encoding" and v != "chunked":
            return _rej("400 headers: TE not exactly 'chunked'")
        if n == "content-length" and (not v.isdigit() or (len(v) > 1 and v[0] == "0") or len(v) > 18):
            return _rej("400 headers: bad Content-Length")
        if n == "host" and not v:
            return _rej("400 headers: empty Host")
    return _acc(out)


# ---------------------------------------------------------------- CANON-6 request binding
def canon_request(r):
    """r = {proto: h1|h2, scheme: http|https, sni: str|null, authority: str|null, host: [str...], origin: str|null,
            vhosts: {canonical-authority: [allowed serialized origins...]}}
    accept -> {"vhost": key}; reject reasons start with the status: 400 / 403 / 404 / 421.
    Check order (frozen): framing of Host/:authority (400) -> userinfo (400) -> authority syntax (400) ->
    Host != :authority (400) -> vhost lookup (h2 421 / h1 404) -> SNI binding (421) -> Origin syntax (403) ->
    Origin binding (421)."""
    if not isinstance(r, dict):
        return _rej("400 request: not an object")
    proto, scheme = r.get("proto"), r.get("scheme")
    sni, auth, hosts, origin = r.get("sni"), r.get("authority"), r.get("host") or [], r.get("origin")
    vhosts = r.get("vhosts") or {}
    if proto not in ("h1", "h2") or scheme not in DEFAULT_PORT or not isinstance(hosts, list):
        return _rej("400 request: bad envelope")
    if proto == "h1":
        if auth is not None:
            return _rej("400 request: absolute-form/:authority on h1 not served")
        if len(hosts) == 0:
            return _rej("400 request: missing Host")
        if len(hosts) > 1:
            return _rej("400 request: duplicate Host")
        raw = hosts[0]
    else:
        if auth is None:
            return _rej("400 request: missing :authority")
        if len(hosts) > 1:
            return _rej("400 request: duplicate Host")
        raw = auth
    for v in [raw] + list(hosts):
        if _is_str(v) and "@" in v:
            return _rej("400 request: userinfo in authority")
    st, a = canon_authority(raw, scheme)
    if st == REJECT:
        return _rej("400 request: " + a.split(" ", 1)[1])
    if proto == "h2" and hosts:
        st2, a2 = canon_authority(hosts[0], scheme)
        if st2 == REJECT or a2 != a:
            return _rej("400 request: Host != :authority")
    if a not in vhosts:
        return _rej(("421" if proto == "h2" else "404") + " request: unknown vhost")
    if sni is not None:
        if scheme != "https":
            return _rej("400 request: SNI on cleartext")
        st3, s = canon_host(sni)
        if st3 == REJECT or s != a.rsplit(":", 1)[0]:
            return _rej("421 request: SNI not bound to vhost")
    if origin is not None:
        st4, o = canon_origin(origin)
        if st4 == REJECT:
            return _rej("403 request: Origin unparseable")
        if o not in vhosts[a]:
            return _rej("421 request: Origin not bound to vhost")
    return _acc({"vhost": a})


KINDS = {
    "path": canon_path, "query": canon_query, "query_typed": canon_query_typed, "host": canon_host,
    "origin": canon_origin, "cookie": canon_cookie, "ctype": canon_media_type, "json": canon_json, "tenant": canon_tenant, "headers": canon_headers,
    "request": canon_request,
}


def canon(kind, x):
    f = KINDS.get(kind)
    if f is None:
        return _rej("unknown kind")
    return f(x)


def serialize(kind, canonical, original=None):
    """The spec serializer used for CANON-7: canon(kind, serialize(kind, canon(kind, x))) == canon(kind, x).
    For `request`, the re-serialized exchange carries the canonical authority (h2, Host regenerated equal to it) and
    the canonical SNI/Origin of the original input."""
    if kind == "headers":
        return ["%s: %s" % (n, v) for n, v in canonical]
    if kind == "request":
        o = dict(original or {})
        o["proto"] = "h2"
        o["authority"] = canonical["vhost"]
        o["host"] = [canonical["vhost"]]
        if o.get("sni") is not None:
            o["sni"] = canon_host(o["sni"])[1]
        if o.get("origin") is not None:
            o["origin"] = canon_origin(o["origin"])[1]
        return o
    return canonical

