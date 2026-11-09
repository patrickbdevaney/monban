#!/usr/bin/env python3
"""FIPS-boundary gate for 0x11ED (PREFLIGHT-8 D-P8.1; PLAN-8 `fips-boundary`; unit P8-fips-001; F1 FIPS-B1).

Usage: python3 -I ci/fips-boundary.py [--root DIR] [--policy FILE]
       python3 -I ci/fips-boundary.py --self-test [--policy FILE]

Stdlib only, plus `pdftotext` (poppler) to read the policy text. Reads compliance/fips-boundary.toml under the root and
the CMVP #5314 Security Policy (140sp5314.pdf). The PDF is never vendored: with --policy it is read from FILE;
otherwise from ~/.cache/aegis-ci/fips/140sp5314.pdf (outside the repo; $AEGIS_CI_CACHE overrides ~/.cache/aegis-ci),
fetched from csrc.nist.gov with `User-Agent: aegis-ci` when the cache is missing or does not match the pin.

check fails (last line `FIPS-BOUNDARY: FAIL (<n> violation(s): <tags>)`, exit 1) on:
  toml              the record is missing, unparsable, or lacks a required key, a component id, or has a duplicate id
  cert              certificate.number is not 5314, not the static module/linkage, or #5298 is not recorded as the
                    dynamic module that this build does not cite
  policy-sha256     policy.sha256 is not 64 hex, or the policy file's sha256 differs from it
  policy-fetch      the policy file could not be read or fetched (fail closed: no hash, no pass)
  excerpt           an `excerpts` string is not in the policy text, a `policy.absent` term is in it, or pdftotext is
                    unavailable
  component         a primitive component is not state "approved", or lacks its table/row/page/cavp/reference
  tls13-kdf         the tls13-kdf component is not state "not-claimed", or claim text calls the TLS 1.3 KDF / key
                    schedule approved, validated, certified or CAVP/CVL-covered (without a preceding negation)
  combiner          combiner order is not [p384-ecdh, mlkem1024-encapdecap] (RFC 10024: ECDHE first), kdm is not hkdf,
                    or the SP 800-227 §4.6.2 / RFC 10024 references or the 80-byte secret are missing
  claim             claim.permitted lacks the D-P8.1 qualifier ("#5314-approved components", "SP 800-227 §4.6.2",
                    "NOT CLAIMED"), or itself trips a claim-text rule
  unqualified-11ed  claim text that calls 0x11ED / SecP384r1MLKEM1024 / P-UNIVERSAL FIPS-approved, -validated,
                    -certified, -compliant, -approvable, "approved key establishment" or "inside the ... boundary"
                    without a preceding negation and without the component qualifier ("component(s)" between the group
                    name and the phrase, or within 60 characters of the phrase)
  cert-5298         claim text citing #5298 without "dynamic" within 60 characters (the cmvp build is static: #5314)

Claim text scanned: every top-level *.md except CLAUDE.md (README.md, SECURITY_CLAIMS.md, SECURITY_BY_DESIGN.md,
DEVIATIONS.md), every *.md/*.txt/*.toml under compliance/ except compliance/fips-boundary.toml itself (validated
structurally instead), and every *.md/*.txt under docs/ when present. Units are table cells and sentences (paragraph
lines joined). A negation is not/never/no/nor/cannot/without/neither/isn't/aren't or "NOT CLAIMED" within the
80 characters before the phrase in the same unit.

--self-test builds a tree from ci/fixtures/fips-boundary/good/ plus the real compliance/fips-boundary.toml and the
real policy, requires it to PASS with no tag, then applies every mutant and requires exactly the expected tag set.
Last line `FIPS-BOUNDARY SELF-TEST: PASS|FAIL (...)`.
"""
import hashlib, os, re, shutil, subprocess, sys, tempfile, tomllib, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
RECORD = "compliance/fips-boundary.toml"
FIXTURE = os.path.join(HERE, "fixtures", "fips-boundary", "good")
UA = "aegis-ci"
CERT, OTHER_CERT = 5314, 5298
PRIMITIVES = ["p384-keygen", "p384-ecdh", "mlkem1024-keygen", "mlkem1024-encapdecap", "hkdf"]
TLS13 = "tls13-kdf"
ORDER = ["p384-ecdh", "mlkem1024-encapdecap"]
COMP_KEYS = ("id", "role", "algorithm", "table", "row", "page", "cavp", "reference", "state", "excerpts")
QUALIFIER = ["#5314-approved components", "SP 800-227 §4.6.2", "NOT CLAIMED"]

GROUP = re.compile(r"0x11ED\b|\bSecP384r1MLKEM1024\b|\bP-UNIVERSAL\b", re.I)
APPROVAL = re.compile(r"FIPS[\s-]*(?:140-3[\s-]*)?(?:approved|validated|certified|compliant|approvable)\b"
                      r"|\bapproved\s+key[\s-]+(?:establishment|exchange|agreement)\b"
                      r"|\b(?:inside|within|in)\s+the\s+(?:[\w.#/-]+\s+){0,4}boundary\b", re.I)
COMPONENT = re.compile(r"\bcomponents?\b", re.I)
NEG = re.compile(r"\b(?:not|never|no|nor|cannot|without|neither|isn't|aren't)\b|NOT CLAIMED", re.I)
TLS13_RE = re.compile(r"\bTLS\s*v?1\.3\b|\bTLSv1\.3\b", re.I)
KDF_RE = re.compile(r"\bKDF\b|\bkey\s+schedule\b|\bkey\s+derivation\b", re.I)
TLS_APPROVAL = re.compile(r"\b(?:approved|validated|certified|CAVP|CVL|covered)\b", re.I)
CERT5298 = re.compile(r"#\s?5298\b|\bCMVP\s+5298\b|\bcertificates?\s+5298\b|certificate/5298\b", re.I)
DYNAMIC = re.compile(r"\bdynamic\b", re.I)


# ---------------------------------------------------------------- claim text

def scan_files(root):
    out = []
    for n in sorted(os.listdir(root)):
        if n.endswith(".md") and n != "CLAUDE.md" and os.path.isfile(os.path.join(root, n)):
            out.append(n)
    for sub, exts in (("compliance", (".md", ".txt", ".toml")), ("docs", (".md", ".txt"))):
        base = os.path.join(root, sub)
        for d, dirs, files in os.walk(base):
            dirs.sort()
            for f in sorted(files):
                rel = os.path.relpath(os.path.join(d, f), root)
                if f.endswith(exts) and rel != RECORD:
                    out.append(rel)
    return out


def units(text):
    """(line, unit) pairs: table cells, and sentences of paragraphs/list items with wrapped lines joined."""
    blocks, cur, start = [], [], 0
    def flush():
        if cur:
            blocks.append((start, " ".join(cur)))
            cur.clear()
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if s.startswith("|"):
            flush()
            for cell in s.strip("|").split("|"):
                blocks.append((i, cell))
            continue
        if not s or s.startswith("#") or s.startswith("```"):
            flush()
            if s.startswith("#"):
                blocks.append((i, s.lstrip("#")))
            continue
        if re.match(r"([-*+]|\d+\.)\s", s):
            flush()
        if not cur:
            start = i
        cur.append(s)
    flush()
    for ln, b in blocks:
        for sent in re.split(r"(?<=[.;!?])\s+", b):
            if sent.strip():
                yield ln, sent


def negated(u, pos):
    return bool(NEG.search(u[max(0, pos - 80):pos]))


def text_violations(u):
    """Claim-text rule hits for one unit: list of (tag, detail)."""
    out = []
    g = GROUP.search(u)
    if g:
        for m in APPROVAL.finditer(u):
            if negated(u, m.start()):
                continue
            lo, hi = sorted((g.start(), m.start()))
            near = u[max(0, m.start() - 60):m.end() + 60]
            if COMPONENT.search(u[lo:hi]) or COMPONENT.search(near):
                continue
            out.append(("unqualified-11ed", f"{g.group(0)} ... '{m.group(0)}'"))
    if TLS13_RE.search(u) and KDF_RE.search(u):
        for m in TLS_APPROVAL.finditer(u):
            if not negated(u, m.start()):
                out.append(("tls13-kdf", f"TLS 1.3 KDF ... '{m.group(0)}'"))
                break
    for m in CERT5298.finditer(u):
        if not DYNAMIC.search(u[max(0, m.start() - 60):m.end() + 60]):
            out.append(("cert-5298", f"'{m.group(0)}' without 'dynamic'"))
    return out


def scan_claims(root):
    v = []
    for rel in scan_files(root):
        try:
            with open(os.path.join(root, rel), encoding="utf-8") as f:
                text = f.read()
        except (OSError, UnicodeDecodeError) as e:
            v.append(("toml", f"{rel}: unreadable claim file ({e})"))
            continue
        for ln, u in units(text):
            for tag, d in text_violations(u):
                v.append((tag, f"{rel}:{ln}: {d}: {u.strip()[:160]}"))
    return v


# ---------------------------------------------------------------- policy

def cache_path():
    base = os.environ.get("AEGIS_CI_CACHE") or os.path.join(os.path.expanduser("~"), ".cache", "aegis-ci")
    return os.path.join(base, "fips", "140sp5314.pdf")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 16), b""):
            h.update(b)
    return h.hexdigest()


def acquire_policy(url, pin):
    """Path of a local policy copy: the cache if it matches the pin, else a fresh fetch (cached only on match)."""
    cp = cache_path()
    if os.path.isfile(cp) and sha256(cp) == pin:
        return cp, None
    os.makedirs(os.path.dirname(cp), exist_ok=True)
    tmp = cp + ".part"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=60) as r, open(tmp, "wb") as f:
            shutil.copyfileobj(r, f)
    except Exception as e:  # network, HTTP or disk error: fail closed
        return None, f"fetch {url}: {e}"
    if sha256(tmp) == pin:
        os.replace(tmp, cp)
        return cp, None
    bad = cp + ".mismatch"
    os.replace(tmp, bad)
    return bad, None  # the hash check below reports the mismatch


def policy_text(path):
    exe = shutil.which("pdftotext")
    if not exe:
        return None, "pdftotext not found (poppler-utils): the excerpts cannot be checked"
    r = subprocess.run([exe, "-layout", path, "-"], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        return None, f"pdftotext exit {r.returncode}: {r.stderr.strip()[:200]}"
    return " ".join(r.stdout.split()), None


# ---------------------------------------------------------------- record

def check(root, policy=None):
    v = []
    rp = os.path.join(root, RECORD)
    try:
        with open(rp, "rb") as f:
            t = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        return [("toml", f"{RECORD}: {e}")] + scan_claims(root)

    def need(tbl, key, where, tag="toml"):
        if not isinstance(tbl, dict) or tbl.get(key) in (None, "", []):
            v.append((tag, f"{where}.{key} missing or empty"))
            return None
        return tbl[key]

    cert = t.get("certificate", {})
    if cert.get("number") != CERT:
        v.append(("cert", f"certificate.number = {cert.get('number')!r}, want {CERT} (static module of the cmvp build)"))
    if cert.get("linkage") != "static" or "(static)" not in str(cert.get("module", "")):
        v.append(("cert", "certificate is not the static module (linkage/module)"))
    if cert.get("module_version") != "AWS-LC FIPS 3.1.0":
        v.append(("cert", f"certificate.module_version = {cert.get('module_version')!r}, want 'AWS-LC FIPS 3.1.0'"))
    others = cert.get("not_this_build", [])
    if not any(o.get("number") == OTHER_CERT and o.get("linkage") == "dynamic" for o in others if isinstance(o, dict)):
        v.append(("cert", f"certificate.not_this_build lacks #{OTHER_CERT} as the dynamic module"))
    if any(o.get("number") == CERT for o in others if isinstance(o, dict)):
        v.append(("cert", f"#{CERT} listed under not_this_build"))

    pol = t.get("policy", {})
    pin = str(pol.get("sha256", ""))
    pin_ok = bool(re.fullmatch(r"[0-9a-f]{64}", pin))
    if not pin_ok:
        v.append(("policy-sha256", f"policy.sha256 {pin!r} is not 64 lowercase hex"))
    for k in ("url", "version", "date"):
        need(pol, k, "policy")
    if pol.get("vendored") is not False:
        v.append(("toml", "policy.vendored must be false (the PDF is not vendored)"))

    comps, ids = t.get("component", []), []
    for c in comps:
        if not isinstance(c, dict):
            v.append(("toml", "component entry is not a table"))
            continue
        cid = c.get("id", "?")
        ids.append(cid)
        for k in COMP_KEYS:
            need(c, k, f"component[{cid}]", "component" if k != "id" else "toml")
        pg = c.get("page")
        if not isinstance(pg, int) or not 1 <= pg <= int(pol.get("pages", 0) or 0):
            v.append(("component", f"component[{cid}].page {pg!r} outside 1..policy.pages"))
        if cid in PRIMITIVES and c.get("state") != "approved":
            v.append(("component", f"component[{cid}].state = {c.get('state')!r}, want 'approved'"))
        if cid == TLS13 and c.get("state") != "not-claimed":
            v.append(("tls13-kdf", f"component[{TLS13}].state = {c.get('state')!r}, want 'not-claimed' (no CAVP row)"))
        if cid not in PRIMITIVES + [TLS13]:
            v.append(("toml", f"unknown component id {cid!r}"))
    for cid in PRIMITIVES + [TLS13]:
        n = ids.count(cid)
        if n != 1:
            v.append(("toml", f"component {cid!r} appears {n} time(s), want 1"))

    comb = t.get("combiner", {})
    if comb.get("order") != ORDER:
        v.append(("combiner", f"combiner.order = {comb.get('order')!r}, want {ORDER} (RFC 10024: ECDHE first)"))
    if comb.get("kdm") != "hkdf":
        v.append(("combiner", f"combiner.kdm = {comb.get('kdm')!r}, want 'hkdf'"))
    ref = str(comb.get("reference", ""))
    if "SP 800-227" not in ref or "4.6.2" not in ref:
        v.append(("combiner", "combiner.reference lacks SP 800-227 §4.6.2"))
    if "RFC 10024" not in str(comb.get("ordering_reference", "")):
        v.append(("combiner", "combiner.ordering_reference lacks RFC 10024"))
    if comb.get("shared_secret_bytes") != 80:
        v.append(("combiner", f"combiner.shared_secret_bytes = {comb.get('shared_secret_bytes')!r}, want 80 (48 + 32)"))
    need(comb, "argument", "combiner", "combiner")

    claim = t.get("claim", {})
    permitted = str(claim.get("permitted", ""))
    for q in QUALIFIER:
        if q not in permitted:
            v.append(("claim", f"claim.permitted lacks {q!r}"))
    for _, u in units(permitted):
        for tag, d in text_violations(u):
            v.append(("claim", f"claim.permitted trips {tag}: {d}"))
    need(claim, "rung", "claim", "claim")

    # policy identity and excerpts
    if pin_ok and pol.get("url"):
        if policy:
            path, err = (policy, None) if os.path.isfile(policy) else (None, f"--policy {policy}: no such file")
        else:
            path, err = acquire_policy(pol["url"], pin)
        if err:
            v.append(("policy-fetch", err))
        else:
            got = sha256(path)
            if got != pin:
                v.append(("policy-sha256", f"{path}: sha256 {got} != pinned {pin}"))
            else:
                text, terr = policy_text(path)
                if terr:
                    v.append(("excerpt", terr))
                else:
                    groups = [("certificate", cert), ("policy", pol)] + [(f"component[{c.get('id')}]", c)
                                                                         for c in comps if isinstance(c, dict)]
                    nex = 0
                    for where, tbl in groups:
                        for e in tbl.get("excerpts", []) or []:
                            nex += 1
                            if " ".join(str(e).split()) not in text:
                                v.append(("excerpt", f"{where}: not in policy text: {e!r}"))
                    low = text.lower()
                    for a in pol.get("absent", []) or []:
                        if str(a).lower() in low:
                            v.append(("excerpt", f"policy.absent term {a!r} occurs in the policy text"))
                    check.excerpts = nex
    return v + scan_claims(root)


check.excerpts = 0


def report(v, label="FIPS-BOUNDARY"):
    for tag, msg in v:
        print(f"  [{tag}] {msg}")
    if v:
        tags = ",".join(sorted({t for t, _ in v}))
        print(f"{label}: FAIL ({len(v)} violation(s): {tags})")
        return 1
    print(f"{label}: PASS (cert #{CERT} static; policy sha256 pinned and matched; {check.excerpts} excerpts found; "
          f"{len(PRIMITIVES)} components approved, TLS 1.3 KDF not claimed; combiner SP 800-227 §4.6.2)")
    return 0


# ---------------------------------------------------------------- self-test

def sub(pat, rep):
    def f(s):
        n = re.sub(pat, rep, s, count=1, flags=re.M)
        if n == s:
            raise RuntimeError(f"mutant pattern did not apply: {pat}")
        return n
    return f


def pin_flip(s):
    m = re.search(r'^sha256 = "([0-9a-f]{64})"', s, re.M)
    if not m:
        raise RuntimeError("pin-mismatch: no sha256 line")
    h = m.group(1)
    nh = h[:-1] + ("0" if h[-1] != "0" else "1")
    return s.replace(f'sha256 = "{h}"', f'sha256 = "{nh}"', 1)


MUTANTS = [  # (name, kind, target, change, expected tags)
    ("sc-11ed-approved", "append", "SECURITY_CLAIMS.md", "\n0x11ED is FIPS-approved.\n", {"unqualified-11ed"}),
    ("sc-11ed-table-cell", "append", "SECURITY_CLAIMS.md",
     "\n| P-UNIVERSAL | 0x11ED key exchange, FIPS 140-3 validated on cmvp |\n", {"unqualified-11ed"}),
    ("readme-inside-boundary", "append", "README.md",
     "\nOn the cmvp build\nSecP384r1MLKEM1024 runs inside the AWS-LC FIPS boundary.\n", {"unqualified-11ed"}),
    ("cm-approved-kex", "append", "compliance/COMPLIANCE_MAP.md",
     "\n- 0x11ED is approved key establishment on AL2023.\n", {"unqualified-11ed"}),
    ("cra-nested-scanned", "append", "compliance/cra/notes.md", "\n0x11ED is FIPS validated.\n", {"unqualified-11ed"}),
    ("docs-scanned", "append", "docs/fips.md", "\nP-UNIVERSAL is FIPS-approvable.\n", {"unqualified-11ed"}),
    ("tls13-kdf-claimed", "append", "SECURITY_CLAIMS.md",
     "\nThe TLS 1.3 KDF is approved in #5314.\n", {"tls13-kdf"}),
    ("tls13-schedule-cavp", "append", "compliance/COMPLIANCE_MAP.md",
     "\n| kx | the TLS 1.3 key schedule is CAVP covered |\n", {"tls13-kdf"}),
    ("tls13-kdf-state", "toml", RECORD, sub(r'^state = "not-claimed"', 'state = "approved"'), {"tls13-kdf"}),
    ("cert-5298-static", "append", "SECURITY_CLAIMS.md",
     "\nThe cmvp build uses the validated module (CMVP #5298/#5314).\n", {"cert-5298"}),
    ("cert-number", "toml", RECORD, sub(r"^number = 5314$", "number = 5298"), {"cert"}),
    ("cert-linkage", "toml", RECORD, sub(r'^linkage = "static"$', 'linkage = "dynamic"'), {"cert"}),
    ("pin-mismatch", "toml", RECORD, pin_flip, {"policy-sha256"}),
    ("policy-bytes", "policy", None, None, {"policy-sha256"}),
    ("pin-malformed", "toml", RECORD, sub(r'^sha256 = "[0-9a-f]{64}"', 'sha256 = "deadbeef"'), {"policy-sha256"}),
    ("excerpt-wrong", "toml", RECORD,
     sub(r"TLS Version - v1\.0/1\.1, v1\.2 SP 800-135", "TLS Version - v1.0/1.1, v1.2, v1.3 SP 800-135"), {"excerpt"}),
    ("absent-term-present", "toml", RECORD, sub(r'^absent = \["combiner"', 'absent = ["ML-KEM-1024", "combiner"'),
     {"excerpt"}),
    ("component-dropped", "toml", RECORD, sub(r'^id = "hkdf"$', 'id = "hkdf-x"'), {"toml"}),
    ("component-not-approved", "toml", RECORD, sub(r'^state = "approved"', 'state = "not-claimed"'), {"component"}),
    ("component-no-row", "toml", RECORD, sub(r'^row = "ML-KEM KeyGen[^\n]*"$', 'row = ""'), {"component"}),
    ("combiner-order", "toml", RECORD,
     sub(r'^order = \["p384-ecdh", "mlkem1024-encapdecap"\]', 'order = ["mlkem1024-encapdecap", "p384-ecdh"]'),
     {"combiner"}),
    ("combiner-ref", "toml", RECORD, sub(r"^reference = \"SP 800-227 \(final, 2025-09\) §4\.6\.2",
                                         'reference = "SP 800-227 (final, 2025-09) §4.6.1'), {"combiner"}),
    ("claim-unqualified", "toml", RECORD,
     sub(r'^permitted = "0x11ED built only from #5314-approved components', 'permitted = "0x11ED is FIPS-approved, built from'),
     {"claim"}),
]


def build_tree(dst, record_text):
    shutil.copytree(FIXTURE, dst)
    os.makedirs(os.path.join(dst, "compliance"), exist_ok=True)
    with open(os.path.join(dst, RECORD), "w", encoding="utf-8") as f:
        f.write(record_text)


def self_test(policy_arg):
    fails = []
    with open(os.path.join(REPO, RECORD), encoding="utf-8") as f:
        record = f.read()
    t = tomllib.loads(record)
    if policy_arg:
        policy = policy_arg
    else:
        policy, err = acquire_policy(t["policy"]["url"], t["policy"]["sha256"])
        if err:
            print(f"FIPS-BOUNDARY SELF-TEST: FAIL (no policy copy: {err})")
            return 1
    with tempfile.TemporaryDirectory(prefix="fips-boundary-") as tmp:
        pol = os.path.join(tmp, "policy.pdf")
        shutil.copyfile(policy, pol)
        base = os.path.join(tmp, "base")
        build_tree(base, record)
        v = check(base, pol)
        if v:
            for tag, msg in v:
                print(f"  baseline [{tag}] {msg}")
            fails.append("baseline not PASS")
        for name, kind, target, change, want in MUTANTS:
            root = os.path.join(tmp, name)
            rec, ppath = record, pol
            try:
                if kind == "toml":
                    rec = change(record)
                build_tree(root, rec)
                if kind == "append":
                    p = os.path.join(root, target)
                    os.makedirs(os.path.dirname(p), exist_ok=True)
                    with open(p, "a", encoding="utf-8") as f:
                        f.write(change)
                elif kind == "policy":
                    ppath = os.path.join(tmp, f"{name}.pdf")
                    with open(pol, "rb") as f:
                        b = bytearray(f.read())
                    b[len(b) // 2] ^= 0x01
                    with open(ppath, "wb") as f:
                        f.write(b)
            except RuntimeError as e:
                fails.append(f"{name}: {e}")
                continue
            got = {tag for tag, _ in check(root, ppath)}
            ok = got == want
            print(f"  mutant {name}: {'red' if got else 'GREEN'} {sorted(got)} {'ok' if ok else 'WANT ' + str(sorted(want))}")
            if not ok:
                fails.append(f"{name}: got {sorted(got)} want {sorted(want)}")
    if fails:
        print(f"FIPS-BOUNDARY SELF-TEST: FAIL ({'; '.join(fails)})")
        return 1
    print(f"FIPS-BOUNDARY SELF-TEST: PASS (baseline green; {len(MUTANTS)}/{len(MUTANTS)} mutants red with exactly the "
          f"expected tag)")
    return 0


def main(argv):
    root, policy, st = REPO, None, False
    it = iter(argv)
    for a in it:
        if a == "--self-test":
            st = True
        elif a == "--root":
            root = next(it, None)
        elif a == "--policy":
            policy = next(it, None)
        else:
            print(__doc__)
            return 2
    if root is None or (policy is None and "--policy" in argv):
        print(__doc__)
        return 2
    if policy:
        policy = os.path.abspath(policy)
    if st:
        return self_test(policy)
    return report(check(os.path.abspath(root), policy))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
