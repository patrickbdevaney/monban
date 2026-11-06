"""AEGIS oracle cred-select (P7-oracle-sel-001): the MTC CredentialSelector decision table, F1 SEL-1..3 (D-P7.4).

Stdlib only; run as `python3 -I oracle.py` (via ./run). README.md has the subject protocol, the decision table, the
generator, every check and the self-test mutants.

    run [--subject 'CMD ARGS'] [--n N] [--seed S] [-v]   subject default: the reference (ref_selector.py)
    run --self-test [--n N]
"""

import argparse
import collections
import contextlib
import io
import os
import random
import shlex
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import ref_selector as ref  # noqa: E402
from ref_selector import ch  # noqa: E402  (oracles/proxy-l4/clienthello.py, the shared builder)

NAME = "CRED-SELECT"
MIN_N = 10000
TA_CODEPOINT = 0xCA34  # draft-ietf-tls-trust-anchor-ids-07 `trust_anchors(TBD)`; BoringSSL experimental value
DECOY_CODEPOINTS = (TA_CODEPOINT + 1, TA_CODEPOINT - 1, 0x1A1A)  # 0x1A1A: a GREASE value (RFC 8701), ignored
SUBJECT_TIMEOUT_S = 900

# Schemes a credential of each kind may carry (codepoints from F12 [codepoints.sigalgs]).
KIND_SCHEMES = {
    "x509": (0x0403, 0x0503, 0x0807),
    "mldsa": (0x0904, 0x0905, 0x0906),
    "mtc": (0x0403, 0x0503, 0x0904, 0x0906),
}
# Universe of client signature_algorithms values (TLS 1.3 + legacy + ML-DSA).
CLIENT_SIGALGS = (0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0401, 0x0501, 0x0601, 0x0201,
                  0x0904, 0x0905, 0x0906)
GROUPS = [0x001D, 0x11EC, 0x0017, 0x0018, 0x11EB, 0x0202]  # one X25519 key share (first group)
LISTENERS = ("pub", "api", "int", "gov", "edge", "fips")
PROFILE_WEIGHTS = {"P-PUBLIC-WEB": 30, "P-PQ-REQUIRED": 18, "P-UNIVERSAL": 12, "P-BSI-ALT": 8, "P-CNSA": 8,
                   "FIPS-FLOOR": 12, "FIPS-PQ-REQUIRED": 12}
HOSTILE = ("ta-duplicate", "ta-empty-id", "ta-id-33", "ta-trailing", "ta-list-overrun", "fragmented",
           "record-type", "record-version", "trailing-in-record", "sni-invalid", "duplicate-sigalgs")

# Generator knobs (probabilities). The self-test's corpus mutants zero some of them.
KNOBS = {"decoy": 0.15, "own_ta": 0.40, "hostile": 0.04}

# Per 1e4 cases: the minimum number of rows each decision-table row is taken, and of cases on which each mutant
# disagrees with the reference (the corpus must be able to tell every planted bug apart).
ROW_MIN = {"R0": 150, "R1": 800, "R2": 500, "R3": 800, "R4": 800}
MUTANT_KILL_MIN = 100


# ------------------------------------------------------------------------------------------------ generator

def _ta_id(rnd):
    n = rnd.choice((1, 2, 3, 4, 4, 5, 6, 8, 12, 16, 32))
    return bytes(rnd.getrandbits(8) for _ in range(n))


def _near_miss(rnd, tid):
    """An ID that is not `tid` but close: a prefix, an extension, one flipped bit, or the same bytes reversed."""
    opts = []
    if len(tid) > 1:
        opts.append(tid[:-1])
    if len(tid) < 32:
        opts.append(tid + bytes([rnd.getrandbits(8)]))
    i = rnd.randrange(len(tid))
    opts.append(tid[:i] + bytes([tid[i] ^ (1 << rnd.randrange(8))]) + tid[i + 1:])
    if len(tid) > 1 and tid != tid[::-1]:
        opts.append(tid[::-1])
    return rnd.choice(opts)


def _cred(rnd, cid, listener, kind, profile_schemes, ta_pool):
    schemes = KIND_SCHEMES[kind]
    good = [s for s in schemes if s in profile_schemes]
    scheme = rnd.choice(good) if good and rnd.random() < 0.7 else rnd.choice(schemes)
    ta = None
    if kind == "mtc":
        ta = _ta_id(rnd)
        while ta in ta_pool:
            ta = _ta_id(rnd)
        ta_pool.add(ta)
    return {"id": cid, "listener": listener, "kind": kind, "scheme": scheme, "ta": ta}


def gen_case(rnd, case):
    profile = rnd.choices(list(PROFILE_WEIGHTS), weights=list(PROFILE_WEIGHTS.values()))[0]
    pschemes = ref.PROFILES[profile]
    names = rnd.sample(LISTENERS, rnd.randint(2, 4))
    target = names[0]
    empty_target = rnd.random() < 0.06
    creds, ta_pool, k = [], set(), 0
    for li in names:
        n = 0 if (li == target and empty_target) else rnd.choice((0, 1, 1, 2, 2, 3, 3, 4, 5)) if li != target \
            else rnd.choice((1, 1, 2, 2, 3, 3, 4, 5))
        for _ in range(n):
            kind = rnd.choices(("x509", "mldsa", "mtc"), weights=(4, 3, 3))[0]
            creds.append(_cred(rnd, f"{li}-{kind}-{k}", li, kind, pschemes, ta_pool))
            k += 1
    rnd.shuffle(creds)  # configured order is the pool order; the listener's own order is its subsequence
    own = [c for c in creds if c["listener"] == target]
    other = [c for c in creds if c["listener"] != target]

    # client signature_algorithms
    if rnd.random() < 0.04:
        sigalgs = None
    else:
        s = [x for x in CLIENT_SIGALGS if rnd.random() < 0.25]
        for c in own + other:
            if rnd.random() < 0.55 and c["scheme"] not in s:
                s.append(c["scheme"])
        if not s:
            s = [rnd.choice(CLIENT_SIGALGS)]
        rnd.shuffle(s)
        sigalgs = s

    # trust_anchors
    own_ta = [c["ta"] for c in own if c["kind"] == "mtc"]
    other_ta = [c["ta"] for c in other if c["kind"] == "mtc"]
    r = rnd.random()
    if r < 0.25:
        tas = None
    elif r < 0.30:
        tas = []
    else:
        tas = []
        for _ in range(rnd.randint(1, 4)):
            q = rnd.random()
            if own_ta and q < KNOBS["own_ta"]:
                tas.append(rnd.choice(own_ta))
            elif other_ta and q < KNOBS["own_ta"] + 0.15:
                tas.append(rnd.choice(other_ta))
            elif (own_ta or other_ta) and q < KNOBS["own_ta"] + 0.40:
                tas.append(_near_miss(rnd, rnd.choice(own_ta or other_ta)))
            else:
                tas.append(_ta_id(rnd))
        tas = list(dict.fromkeys(tas))
    extra = []
    if rnd.random() < KNOBS["decoy"]:
        decoy = list(dict.fromkeys(own_ta + other_ta)) or [_ta_id(rnd)]
        rnd.shuffle(decoy)
        extra.append((rnd.choice(DECOY_CODEPOINTS), ch.trust_anchors_ext(decoy[:4])))
        if rnd.random() < 0.6:
            tas = None

    sni = None if rnd.random() < 0.15 else f"{rnd.choice(('www', 'api', 'mtc', 'a', 'svc-1'))}.{target}.example"
    alpn = None if rnd.random() < 0.5 else rnd.choice((["h2", "http/1.1"], ["http/1.1"], ["h2"]))
    kw = dict(sni=sni, alpn=alpn, sigalgs=sigalgs, groups=GROUPS, trust_anchors=tas, ta_codepoint=TA_CODEPOINT,
              extra=extra, seed=rnd.getrandbits(32))
    if extra or tas is not None:
        order = [t for t, _ in extra] if rnd.random() < 0.3 else None  # sometimes a decoy first
        kw["order"] = order
    hostile = rnd.choice(HOSTILE) if rnd.random() < KNOBS["hostile"] else None
    hello = _hello(rnd, kw, hostile)
    req = {"case": case, "profile": profile, "listener": target, "creds": creds, "hello": hello}
    meta = {"sigalgs": sigalgs, "tas": tas, "hostile": hostile, "sni": sni, "extra": extra}
    return req, meta


def _hello(rnd, kw, hostile):
    """One TLS record. `hostile` names a peek refusal (README "Generator")."""
    ok_id = [bytes.fromhex("81fd5901")]
    if hostile is None:
        return ch.record(ch.build(**kw))
    if hostile == "ta-duplicate":
        kw = dict(kw, trust_anchors=kw["trust_anchors"] or ok_id,
                  extra=list(kw["extra"]) + [(TA_CODEPOINT, ch.trust_anchors_ext(ok_id))])
        return ch.record(ch.build(**kw))
    if hostile in ("ta-empty-id", "ta-id-33", "ta-trailing", "ta-list-overrun"):
        body = {"ta-empty-id": ch.vec16(ch.vec8(b"\x81") + b"\x00"),
                "ta-id-33": ch.vec16(ch.vec8(bytes(33))),
                "ta-trailing": ch.vec16(ch.vec8(b"\x81\xfd")) + b"\x00",
                "ta-list-overrun": ch.u16(9) + ch.vec8(b"\x81\xfd")}[hostile]
        kw = dict(kw, trust_anchors=None, extra=[e for e in kw["extra"] if e[0] != TA_CODEPOINT]
                  + [(TA_CODEPOINT, body)])
        return ch.record(ch.build(**kw))
    hs = ch.build(**kw)
    if hostile == "fragmented":
        return ch.records(hs, [rnd.randrange(8, len(hs) - 8)])
    if hostile == "record-type":
        return ch.record(hs, ctype=0x17)
    if hostile == "record-version":
        return ch.record(hs, version=0x0304)
    if hostile == "trailing-in-record":
        return ch.record(hs + b"\x00\x00")
    if hostile == "sni-invalid":
        return ch.record(ch.build(**dict(kw, sni="bad_name.example.")))
    if hostile == "duplicate-sigalgs":
        return ch.record(ch.build(**dict(kw, sigalgs=kw["sigalgs"] or [0x0403], extra=list(kw["extra"]) + [(ch.EXT_SIGNATURE_ALGORITHMS,
                                                                           ch.vec16(ch.u16(0x0403)))])))
    raise ValueError(hostile)


def directed():
    """Named cases, one per clause, each also in every run (README "Directed cases")."""
    tid, other = bytes.fromhex("81fd5901"), bytes.fromhex("81fd5902")
    mk = lambda i, li, k, s, ta=None: {"id": i, "listener": li, "kind": k, "scheme": s, "ta": ta}  # noqa: E731
    pub_set = [mk("pub-x509", "pub", "x509", 0x0403), mk("pub-mtc", "pub", "mtc", 0x0403, tid),
               mk("pub-mldsa", "pub", "mldsa", 0x0904), mk("api-mtc", "api", "mtc", 0x0403, other),
               mk("api-x509", "api", "x509", 0x0403)]
    api_set = [mk("api-x509", "api", "x509", 0x0403), mk("api-mldsa", "api", "mldsa", 0x0904),
               mk("api-mtc", "api", "mtc", 0x0403, tid), mk("pub-x509", "pub", "x509", 0x0503)]
    sig = [0x0403, 0x0503, 0x0904, 0x0906]
    H = lambda **k: ch.record(ch.build(sni="aegis.test", groups=GROUPS, **k))  # noqa: E731
    cases = [
        ("sel1.match", "P-PUBLIC-WEB", "pub", pub_set, H(sigalgs=sig, trust_anchors=[tid]), "pub-mtc"),
        ("sel1.no-extension", "P-PUBLIC-WEB", "pub", pub_set, H(sigalgs=sig), "pub-x509"),
        ("sel1.empty-list", "P-PUBLIC-WEB", "pub", pub_set, H(sigalgs=sig, trust_anchors=[]), "pub-x509"),
        ("sel1.other-id", "P-PUBLIC-WEB", "pub", pub_set, H(sigalgs=sig, trust_anchors=[other]), "pub-x509"),
        ("sel1.prefix-id", "P-PUBLIC-WEB", "pub", pub_set, H(sigalgs=sig, trust_anchors=[tid[:3]]), "pub-x509"),
        ("sel1.extended-id", "P-PUBLIC-WEB", "pub", pub_set, H(sigalgs=sig, trust_anchors=[tid + b"\x00"]),
         "pub-x509"),
        ("sel1.second-in-list", "P-PUBLIC-WEB", "pub", pub_set, H(sigalgs=sig, trust_anchors=[other, tid]),
         "pub-mtc"),
        ("sel1.scheme-not-offered", "P-PUBLIC-WEB", "pub", pub_set, H(sigalgs=[0x0503], trust_anchors=[tid]),
         ref.HANDSHAKE_FAILURE),
        ("codepoint.decoy-ca35", "P-PUBLIC-WEB", "pub", pub_set,
         H(sigalgs=sig, extra=[(TA_CODEPOINT + 1, ch.trust_anchors_ext([tid]))]), "pub-x509"),
        ("codepoint.decoy-ca33", "P-PUBLIC-WEB", "pub", pub_set,
         H(sigalgs=sig, extra=[(TA_CODEPOINT - 1, ch.trust_anchors_ext([tid]))]), "pub-x509"),
        ("codepoint.real-and-decoy", "P-PUBLIC-WEB", "pub", pub_set,
         H(sigalgs=sig, trust_anchors=[other], extra=[(TA_CODEPOINT + 1, ch.trust_anchors_ext([tid]))]),
         "pub-x509"),
        ("sel2.mldsa-offered-public", "P-PUBLIC-WEB", "pub", pub_set, H(sigalgs=[0x0904, 0x0403]), "pub-x509"),
        ("sel2.mldsa-only-public", "P-PUBLIC-WEB", "pub", pub_set, H(sigalgs=[0x0904]), ref.HANDSHAKE_FAILURE),
        ("tier.mldsa-private", "P-PQ-REQUIRED", "api", api_set, H(sigalgs=sig), "api-mldsa"),
        ("tier.mtc-private", "P-PQ-REQUIRED", "api", api_set, H(sigalgs=sig, trust_anchors=[tid]), "api-mtc"),
        ("tier.x509-private", "P-PQ-REQUIRED", "api", api_set, H(sigalgs=[0x0403]), "api-x509"),
        ("sel3.other-listener-id", "P-PUBLIC-WEB", "pub", pub_set[1:2] + pub_set[3:],
         H(sigalgs=sig, trust_anchors=[other]), ref.HANDSHAKE_FAILURE),
        ("sel3.other-listener-scheme", "P-UNIVERSAL", "api", api_set, H(sigalgs=[0x0503]),
         ref.HANDSHAKE_FAILURE),
        ("sel3.no-credentials", "P-PUBLIC-WEB", "edge", pub_set, H(sigalgs=sig, trust_anchors=[tid]),
         ref.HANDSHAKE_FAILURE),
        ("peek.duplicate-ta", "P-PUBLIC-WEB", "pub", pub_set,
         H(sigalgs=sig, trust_anchors=[other], extra=[(TA_CODEPOINT, ch.trust_anchors_ext([tid]))]),
         ref.HANDSHAKE_FAILURE),
        ("peek.no-sigalgs", "P-PUBLIC-WEB", "pub", pub_set, H(sigalgs=None, trust_anchors=[tid]),
         ref.HANDSHAKE_FAILURE),
    ]
    out = []
    for i, (name, prof, li, creds, hello, want) in enumerate(cases):
        out.append((name, {"case": i, "profile": prof, "listener": li, "creds": creds, "hello": hello}, want))
    return out


def corpus(n, seed):
    rnd = random.Random(seed)
    d = directed()
    reqs = [r for _, r, _ in d]
    names = {r["case"]: nm for nm, r, _ in d}
    metas = {}
    for i in range(len(d), len(d) + n):
        req, meta = gen_case(rnd, i)
        reqs.append(req)
        metas[i] = meta
    for r in reqs:
        r["want"] = ref.select(r)
    return reqs, names, metas, d


# ------------------------------------------------------------------------------------------------ checks

class Report:
    def __init__(self, verbose=0):
        self.fails, self.passes, self.verbose = [], 0, verbose

    def check(self, name, ok, detail=""):
        if ok:
            self.passes += 1
            if self.verbose:
                print(f"  ok   {name} {detail}")
        else:
            self.fails.append(name)
            print(f"  FAIL {name} {detail}")
        return ok


def corpus_checks(rep, reqs, names, metas, d, n):
    """Checks on the corpus itself, independent of the subject."""
    rep.check("constant.ta-codepoint", ch.TRUST_ANCHORS_EXT == TA_CODEPOINT,
              f"clienthello.TRUST_ANCHORS_EXT={ch.TRUST_ANCHORS_EXT:#06x}, oracle {TA_CODEPOINT:#06x}")
    rep.check("corpus.size", n >= MIN_N, f"{n} generated cases (+{len(d)} directed); minimum {MIN_N}")
    for name, req, want in d:
        got = ref.select(req)
        rep.check(f"directed.reference.{name}", got == want, f"reference={got} table={want}")
    # generator self-consistency: the shared peek sees what was built
    bad = []
    for req in reqs[len(d):]:
        m = metas[req["case"]]
        pk = ref.peek(req["hello"])
        if m["hostile"]:
            if pk is not None:
                bad.append((req["case"], f"hostile {m['hostile']} accepted"))
            continue
        if pk is None:
            bad.append((req["case"], "benign hello refused"))
            continue
        want_ta = None if m["tas"] is None else [t.hex() for t in m["tas"]]
        if pk["trust_anchors"] != want_ta or pk["sigalgs"] != (m["sigalgs"] or []) or pk["sni"] != m["sni"]:
            bad.append((req["case"], "peek fields differ from the generator's"))
    rep.check("corpus.peek-consistent", not bad, f"{len(bad)} inconsistent" + (f", first {bad[:3]}" if bad else ""))
    # decision-table row coverage
    rows = collections.Counter(ref.classify(r) for r in reqs[len(d):])
    scale = n / 10000
    for row, lo in ROW_MIN.items():
        rep.check(f"coverage.{row}", rows[row] >= lo * scale, f"{rows[row]} cases (minimum {int(lo * scale)})")
    # discriminating power: every planted bug must change the answer on enough cases
    for mu in ref.MUTANTS:
        k = sum(1 for r in reqs[len(d):] if ref.select(r, mu) != r["want"])
        rep.check(f"coverage.kills.{mu}", k >= MUTANT_KILL_MIN * scale,
                  f"{k} cases where the mutant differs (minimum {int(MUTANT_KILL_MIN * scale)})")
    return rows


def describe(req):
    pk = ref.peek(req["hello"])
    pks = "peek refused" if pk is None else \
        f"sigalgs={[f'{s:04x}' for s in pk['sigalgs']]} trust_anchors={pk['trust_anchors']} sni={pk['sni']}"
    creds = ", ".join(f"{c['id']}[{c['listener']},{c['kind']},{c['scheme']:04x}"
                      f"{',ta=' + c['ta'].hex() if c['ta'] else ''}]" for c in req["creds"])
    return f"profile={req['profile']} listener={req['listener']} {pks} creds: {creds}"


def drive(subject, reqs, rep, names, label="subject"):
    """Send every request line, read one answer per line; compare with the reference. Returns divergence count."""
    argv = shlex.split(subject)
    data = "".join(ref.format_request(r) + "\n" for r in reqs)
    try:
        p = subprocess.run(argv, input=data, capture_output=True, text=True, cwd=REPO, timeout=SUBJECT_TIMEOUT_S)
    except FileNotFoundError as e:
        rep.check(f"{label}.protocol", False, f"cannot start {argv[0]}: {e}")
        return len(reqs)
    except subprocess.TimeoutExpired:
        rep.check(f"{label}.protocol", False, f"no exit within {SUBJECT_TIMEOUT_S} s")
        return len(reqs)
    lines = p.stdout.splitlines()
    err_tail = " | ".join(p.stderr.strip().splitlines()[-3:])
    proto_ok = p.returncode == 0 and len(lines) == len(reqs)
    rep.check(f"{label}.protocol", proto_ok,
              f"exit {p.returncode}, {len(lines)} answer lines for {len(reqs)} requests"
              + (f"; stderr: {err_tail}" if err_tail and not proto_ok else ""))
    div, shown = 0, 0
    for i, req in enumerate(reqs):
        want = req["want"]
        got_line = lines[i] if i < len(lines) else None
        got = None
        if got_line is not None:
            f = got_line.split()
            if len(f) == 2 and f[0] == str(req["case"]):
                got = f[1]
        if got != want:
            div += 1
            if shown < 10:
                shown += 1
                nm = names.get(req["case"], "generated")
                print(f"  divergence case {req['case']} ({nm}): want {want!r}, got line {got_line!r}\n"
                      f"      {describe(req)}")
    for nm_case, nm in names.items():
        req = reqs[nm_case]
        got_line = lines[nm_case] if nm_case < len(lines) else None
        rep.check(f"{label}.directed.{nm}", got_line == f"{nm_case} {req["want"]}", f"got {got_line!r}")
    rep.check(f"{label}.divergence", div == 0, f"{div} of {len(reqs)} cases diverge from the decision table")
    return div


def run(subject, n, seed, verbose):
    rep = Report(verbose)
    reqs, names, metas, d = corpus(n, seed)
    print(f"{NAME}: {n} generated + {len(d)} directed cases, seed {seed}, trust_anchors codepoint "
          f"{TA_CODEPOINT:#06x}; subject: {subject}")
    rows = corpus_checks(rep, reqs, names, metas, d, n)
    div = drive(subject, reqs, rep, names)
    summary = f"{len(reqs)} cases, {div} divergence, rows {dict(sorted(rows.items()))}, {rep.passes} checks ok"
    if rep.fails:
        print(f"{NAME}: FAIL ({len(rep.fails)} checks failed: {', '.join(rep.fails[:6])}"
              f"{' ...' if len(rep.fails) > 6 else ''}; {summary})")
        return 1
    print(f"{NAME}: PASS ({summary})")
    return 0


REF_CMD = f"python3 -I {shlex.quote(os.path.join(HERE, 'ref_selector.py'))}"
CORPUS_MUTANTS = {"no-decoy": {"decoy": 0.0}, "no-mtc-match": {"own_ta": 0.0}, "no-hostile": {"hostile": 0.0},
                  "small-n": None}


def corpus_mutant(cm, n, seed):
    """A degraded generator (or too few cases): the corpus checks must notice."""
    if cm == "small-n":
        return corpus(MIN_N - 1, seed) + (MIN_N - 1,)
    saved = dict(KNOBS)
    try:
        KNOBS.update(CORPUS_MUTANTS[cm])
        return corpus(n, seed) + (n,)
    finally:
        KNOBS.clear()
        KNOBS.update(saved)


def self_test(n, seed):
    print(f"{NAME} SELF-TEST: reference subject (must PASS)")
    rc = run(REF_CMD, n, seed, 0)
    caught, missed = [], []
    reqs, names, _, _ = corpus(n, seed)
    print(f"{NAME} SELF-TEST: mutants (each must be red)")
    for mu in list(ref.MUTANTS) + list(ref.PROTO_MUTANTS):
        flag = "--mutant" if mu in ref.MUTANTS else "--proto-mutant"
        r = Report(0)
        with contextlib.redirect_stdout(io.StringIO()):
            div = drive(f"{REF_CMD} {flag} {mu}", reqs, r, names, label=f"mutant.{mu}")
        red = bool(r.fails)
        (caught if red else missed).append(mu)
        kind = "selector" if mu in ref.MUTANTS else "protocol"
        print(f"  {kind} mutant {mu:26s} {'caught' if red else 'MISSED'} ({div} divergent cases; red: "
              f"{', '.join(r.fails[:3])})")
    for cm in CORPUS_MUTANTS:
        r = Report(0)
        with contextlib.redirect_stdout(io.StringIO()):
            creqs, cnames, cmetas, cd, nn = corpus_mutant(cm, n, seed)
            corpus_checks(r, creqs, cnames, cmetas, cd, nn)
        red = bool(r.fails)
        (caught if red else missed).append(f"corpus:{cm}")
        print(f"  corpus mutant   {cm:26s} {'caught' if red else 'MISSED'} (red: {', '.join(r.fails[:3])})")
    total = len(ref.MUTANTS) + len(ref.PROTO_MUTANTS) + len(CORPUS_MUTANTS)
    if rc == 0 and not missed:
        print(f"{NAME} SELF-TEST: PASS (reference PASS on {n} cases; {len(caught)}/{total} mutants caught: "
              f"{len(ref.MUTANTS)} selector, {len(ref.PROTO_MUTANTS)} protocol, {len(CORPUS_MUTANTS)} corpus)")
        return 0
    print(f"{NAME} SELF-TEST: FAIL (reference rc={rc}; missed: {', '.join(missed) or 'none'})")
    return 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--subject", default=None, help="command speaking the select protocol (default: reference)")
    ap.add_argument("--n", type=int, default=MIN_N)
    ap.add_argument("--seed", type=int, default=0xC5E1)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("-v", action="count", default=0)
    a = ap.parse_args()
    if a.self_test:
        return self_test(a.n, a.seed)
    return run(a.subject or REF_CMD, a.n, a.seed, a.v)


if __name__ == "__main__":
    sys.exit(main())
