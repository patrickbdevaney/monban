"""Reference CredentialSelector for oracle cred-select (P7-oracle-sel-001; F1 SEL-1..3, PREFLIGHT D-P7.4).

Stdlib only. Two uses:
- imported by oracle.py: `select(req, mutant=None)` is the decision table (README.md "Decision table");
- run as a subject (`python3 -I ref_selector.py [--mutant M]`): speaks the `tls-subject select` line protocol
  (README.md "Subject protocol") on stdin/stdout, so the self-test exercises the same I/O path as the real subject.

Each mutant is a one-rule change to the reference; the self-test requires every one to diverge from it.
"""

import os
import sys
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "oracles", "proxy-l4"))  # python3 -I does not add any script dir

import clienthello as ch  # noqa: E402  (the shared ClientHello builder + reference peek, oracles/proxy-l4)

HANDSHAKE_FAILURE = "handshake_failure"
KINDS = ("x509", "mldsa", "mtc")
TIER_ORDER = ("mtc", "mldsa", "x509")  # D-P7.4: MTC on a trust-anchor match, else ML-DSA (private hops), else classical
PUBLIC_WEB = "P-PUBLIC-WEB"

# F8 listener profile name -> F12 (tls/verdicts.toml) row. FIPS-CMVP has no F12 row and no floor-build config.
F8_TO_F12 = {
    "P-PUBLIC-WEB": "P-PUBLIC-WEB",
    "P-PQ-REQUIRED": "PQ-REQUIRED",
    "P-UNIVERSAL": "P-UNIVERSAL",
    "P-BSI-ALT": "P-BSI-ALT",
    "P-CNSA": "P-CNSA",
    "FIPS-FLOOR": "FIPS",
    "FIPS-PQ-REQUIRED": "FIPS-PQ-REQUIRED",
}

MUTANTS = (
    "sel1-any-trust-anchor",     # SEL-1: MTC chosen whenever the client sent a non-empty trust_anchors list
    "sel1-ignore-trust-anchor",  # SEL-1: MTC chosen without looking at trust_anchors at all
    "sel1-prefix-match",         # SEL-1: configured ID matches if it is a prefix of an offered ID (or vice versa)
    "sel2-mldsa-public",         # SEL-2: ML-DSA credential exempt from the profile check on P-PUBLIC-WEB
    "sel3-other-listener",       # SEL-3: nothing eligible -> fall back to another listener's eligible credential
    "sel3-pool-wide",            # SEL-3: the listener filter is dropped (whole credential pool considered)
    "ta-codepoint",              # trust_anchors read from codepoint TRUST_ANCHORS_EXT+1 (clienthello ch-ta-codepoint)
    "ta-codepoint-lenient",      # trust_anchors also taken from the neighbouring codepoints TRUST_ANCHORS_EXT+-1
    "peek-fail-open",            # a refused peek falls back to the first x509 credential instead of handshake_failure
    "tier-classical-first",      # x509 preferred over ML-DSA on private hops
    "tier-mldsa-over-mtc",       # ML-DSA preferred over a matching MTC credential
    "client-sigalgs-ignored",    # credential chosen even if the client did not offer its scheme
    "profile-sigalgs-ignored",   # credential chosen even if its scheme is not in the profile's F12 sigalgs
    "tiebreak-last",             # within a tier, the last configured credential instead of the first
)


def load_profiles(path=None):
    """F8 profile name -> tuple of CertificateVerify scheme codepoints the listener may produce (F12 `sigalgs`)."""
    path = path or os.path.join(REPO, "tls", "verdicts.toml")
    with open(path, "rb") as f:
        v = tomllib.load(f)
    cp = v["codepoints"]["sigalgs"]
    out = {}
    for f8, f12 in F8_TO_F12.items():
        out[f8] = tuple(cp[s] for s in v["profiles"][f12]["sigalgs"])
    return out


PROFILES = load_profiles()


class ProtocolError(Exception):
    pass


def _name_ok(s):
    return 1 <= len(s) <= 32 and all(c.isascii() and (c.isalnum() or c in "-._") for c in s) and \
        s != HANDSHAKE_FAILURE


def parse_request(line):
    """`<case> <profile> <listener> <ncred> <cred>... <hello_hex>` -> dict. Raises ProtocolError."""
    t = line.split()
    if len(t) < 5:
        raise ProtocolError("too few fields")
    case, profile, listener, ncred = t[0], t[1], t[2], t[3]
    if not case.isdigit():
        raise ProtocolError("case is not a decimal number")
    if profile not in PROFILES:
        raise ProtocolError(f"unknown profile {profile}")
    if not _name_ok(listener):
        raise ProtocolError("bad listener name")
    if not ncred.isdigit() or len(t) != 5 + int(ncred):
        raise ProtocolError("credential count does not match the field count")
    creds, ids = [], set()
    for tok in t[4:4 + int(ncred)]:
        f = tok.split(",")
        if len(f) != 5:
            raise ProtocolError(f"credential {tok!r}: want id,listener,kind,scheme,ta")
        cid, cl, kind, scheme, ta = f
        if not _name_ok(cid) or not _name_ok(cl) or cid in ids:
            raise ProtocolError(f"credential {tok!r}: bad or duplicate id / listener")
        ids.add(cid)
        if kind not in KINDS:
            raise ProtocolError(f"credential {tok!r}: kind")
        if len(scheme) != 4:
            raise ProtocolError(f"credential {tok!r}: scheme")
        try:
            sc = int(scheme, 16)
            tab = None if ta == "-" else bytes.fromhex(ta)
        except ValueError as e:
            raise ProtocolError(f"credential {tok!r}: {e}") from None
        if (kind == "mtc") != (tab is not None) or (tab is not None and not 1 <= len(tab) <= 32):
            raise ProtocolError(f"credential {tok!r}: trust_anchor_id iff kind mtc, 1..32 bytes")
        creds.append({"id": cid, "listener": cl, "kind": kind, "scheme": sc, "ta": tab})
    try:
        hello = bytes.fromhex(t[-1])
    except ValueError:
        raise ProtocolError("client hello is not hex") from None
    return {"case": int(case), "profile": profile, "listener": listener, "creds": creds, "hello": hello}


def format_request(req):
    def cred(c):
        ta = "-" if c["ta"] is None else c["ta"].hex()
        return f"{c['id']},{c['listener']},{c['kind']},{c['scheme']:04x},{ta}"
    parts = [str(req["case"]), req["profile"], req["listener"], str(len(req["creds"]))]
    parts += [cred(c) for c in req["creds"]]
    parts.append(req["hello"].hex())
    return " ".join(parts)


PROTO_MUTANTS = ("drop-first-line", "case-off-by-one", "exit-nonzero")


def _ext_body(hello, ext_type):
    """Raw body of extension `ext_type` in a peek-valid single-record ClientHello, or None."""
    b = hello[5 + 4:]
    o = 2 + 32
    o += 1 + b[o]
    o += 2 + int.from_bytes(b[o:o + 2], "big")
    o += 1 + b[o]
    if o >= len(b):
        return None
    end = o + 2 + int.from_bytes(b[o:o + 2], "big")
    o += 2
    while o < end:
        t, n = int.from_bytes(b[o:o + 2], "big"), int.from_bytes(b[o + 2:o + 4], "big")
        if t == ext_type:
            return b[o + 4:o + 4 + n]
        o += 4 + n
    return None


def peek(hello, mutant=None):
    """The shared reference peek; None if refused (any PeekError or an incomplete record)."""
    try:
        pk = ch.peek(hello, mutant="ch-ta-codepoint" if mutant == "ta-codepoint" else None)
    except (ch.PeekError, ch.PeekIncomplete):
        return None
    if mutant == "ta-codepoint-lenient":
        for code in (ch.TRUST_ANCHORS_EXT - 1, ch.TRUST_ANCHORS_EXT + 1):
            body = _ext_body(hello, code)
            if body is None:
                continue
            ids, o, lst = [], 0, body[2:]
            while o < len(lst):
                ids.append(lst[o + 1:o + 1 + lst[o]].hex())
                o += 1 + lst[o]
            pk["trust_anchors"] = (pk["trust_anchors"] or []) + ids
    return pk


def _eligible(c, profile, pk, mutant):
    """Rows E1..E4 of the decision table for one credential (the listener filter E0 is applied by the caller)."""
    offered_sigalgs = set(pk["sigalgs"])
    offered_tas = [bytes.fromhex(x) for x in (pk["trust_anchors"] or [])]
    prof_ok = c["scheme"] in PROFILES[profile]
    sel2_ok = not (c["kind"] == "mldsa" and profile == PUBLIC_WEB)
    if mutant == "profile-sigalgs-ignored":
        prof_ok = True
    if mutant == "sel2-mldsa-public" and c["kind"] == "mldsa" and profile == PUBLIC_WEB:
        prof_ok = sel2_ok = True
    if not (prof_ok and sel2_ok):                                    # E1 profile, E2 SEL-2
        return False
    if c["scheme"] not in offered_sigalgs and mutant != "client-sigalgs-ignored":  # E3 client offers the scheme
        return False
    if c["kind"] == "mtc":                                           # E4 SEL-1
        if mutant == "sel1-ignore-trust-anchor":
            return True
        if mutant == "sel1-any-trust-anchor":
            return len(offered_tas) > 0
        if mutant == "sel1-prefix-match":
            return any(o.startswith(c["ta"]) or c["ta"].startswith(o) for o in offered_tas)
        return c["ta"] in offered_tas
    return True


def _pick(cands, mutant):
    order = TIER_ORDER
    if mutant == "tier-classical-first":
        order = ("mtc", "x509", "mldsa")
    elif mutant == "tier-mldsa-over-mtc":
        order = ("mldsa", "mtc", "x509")
    for kind in order:
        tier = [c for c in cands if c["kind"] == kind]
        if tier:
            return (tier[-1] if mutant == "tiebreak-last" else tier[0])["id"]
    return None


def select(req, mutant=None):
    """The decision table. Returns a credential id or HANDSHAKE_FAILURE."""
    pk = peek(req["hello"], mutant)
    if pk is None:                                                   # R0
        if mutant == "peek-fail-open":
            x = [c for c in req["creds"] if c["listener"] == req["listener"] and c["kind"] == "x509"]
            if x:
                return x[0]["id"]
        return HANDSHAKE_FAILURE
    pool = req["creds"]
    own = pool if mutant == "sel3-pool-wide" else [c for c in pool if c["listener"] == req["listener"]]  # E0
    cands = [c for c in own if _eligible(c, req["profile"], pk, mutant)]
    got = _pick(cands, mutant)
    if got is None and mutant == "sel3-other-listener":
        got = _pick([c for c in pool if c["listener"] != req["listener"]
                     and _eligible(c, req["profile"], pk, None)], None)
    return got if got is not None else HANDSHAKE_FAILURE              # R4 (SEL-3)


def classify(req):
    """Decision-table row the reference takes: R0 peek-refused, R1 mtc, R2 mldsa, R3 x509, R4 none."""
    pk = peek(req["hello"])
    if pk is None:
        return "R0"
    got = select(req)
    if got == HANDSHAKE_FAILURE:
        return "R4"
    kind = next(c["kind"] for c in req["creds"] if c["id"] == got)
    return {"mtc": "R1", "mldsa": "R2", "x509": "R3"}[kind]


def serve(mutant=None, proto=None, inp=sys.stdin, out=sys.stdout):
    """The `tls-subject select` line protocol, answered by the reference (or a mutant)."""
    first = True
    for line in inp:
        line = line.strip()
        if not line:
            continue
        case = line.split(" ", 1)[0]
        try:
            req = parse_request(line)
        except ProtocolError as e:
            out.write(f"{case} error {e}\n")
            out.flush()
            continue
        if proto == "drop-first-line" and first:
            first = False
            continue
        n = req["case"] + (1 if proto == "case-off-by-one" and req["case"] == 7 else 0)
        out.write(f"{n} {select(req, mutant)}\n")
        out.flush()
    return 3 if proto == "exit-nonzero" else 0


def main():
    mutant = proto = None
    a = sys.argv[1:]
    if a[:1] == ["--mutant"] and len(a) == 2 and a[1] in MUTANTS:
        mutant = a[1]
    elif a[:1] == ["--proto-mutant"] and len(a) == 2 and a[1] in PROTO_MUTANTS:
        proto = a[1]
    elif a:
        print("usage: ref_selector.py [--mutant M | --proto-mutant P]", file=sys.stderr)
        return 2
    return serve(mutant, proto)


if __name__ == "__main__":
    sys.exit(main())
