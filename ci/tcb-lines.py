#!/usr/bin/env python3
"""TCB-line gate (IMPLEMENTATION_PLAN §3 Phase 7 "each off by default, own TCB line"; PLAN-7; unit P7-compliance-001).

Usage: python3 -I ci/tcb-lines.py [--root DIR]
       python3 -I ci/tcb-lines.py --self-test

Stdlib only. Reads SECURITY_CLAIMS.md, compliance/COMPLIANCE_MAP.md and gates/phase-7.toml under the root.

Each of the two files carries the same two tables:
  TCB table       SECURITY_CLAIMS "## Phase 7: one TCB line per feature" / COMPLIANCE_MAP "### 4.2 Phase-7 TCB lines";
                  columns feature | new surface | gate_id | rung | residuals, one row per Phase-7 feature
  deferred table  SECURITY_CLAIMS "### Phase 7: deferred and blocked" / COMPLIANCE_MAP "### 4.3 Phase-7 deferred ...";
                  columns item | status | evidence | gate_id | re-check

check fails (last line `TCB-LINES: FAIL (<n> violation(s): <tags>)`, exit 1) on:
  structure        a table missing, a header without the required columns, or a row whose cell count differs
  feature-missing  a Phase-7 feature (FEATURES) without a row in a file's TCB table
  feature-dup      a feature (or a deferred item) with more than one row, or a row for an unknown feature
  surface          a surface cell that does not name all three of `crates:`, `C:` and `kernel:` (value may be none)
  gate-id          a gate_id cell that is empty, not only backticked names, or names a gate not in gates/phase-7.toml
  rung             a rung cell without an R0..R4 rung
  residual         an empty residual cell, or one that drops a residual this feature must carry (REQUIRED)
  mismatch         the two files disagree on a feature's gate ids or rungs
  deferred         HTTP/3 / WebTransport row missing, not "deferred" with the 2026-11-06 evidence date and the
                   2027-03-30 re-check, or either file calling HTTP/3 / WebTransport "unsupported by design"
  blocked          the 64-core row missing, or not "blocked" on GCP quota with CPUS_ALL_REGIONS = 12
  trusted-list     SECURITY_CLAIMS "Not proven" table lacks a row for one of hyper, h2, tokio, rustls, AWS-LC C,
                   rustc, io_uring, libcrux; or the COMPLIANCE_MAP **Trusted, not verified** paragraph lacks io_uring
                   or libcrux
  proven           a table cell or sentence in either file that calls hyper, h2, tokio, rustls, AWS-LC, rustc/LLVM,
                   io_uring/io-uring, libcrux or the kernel proven/proved/verified without a negation
  pending          a `PENDING(` marker left in either file (P7-bin-001 has landed; its residuals must be filled in)

--self-test requires the real files and the fixture tree ci/fixtures/tcb-lines/good/ to PASS, then applies every
mutant to a copy of each and requires exactly the expected tag set. Last line `TCB-LINES SELF-TEST: PASS|FAIL (...)`.
"""
import os, re, shutil, sys, tempfile, tomllib

SC, CM, GATES = "SECURITY_CLAIMS.md", "compliance/COMPLIANCE_MAP.md", "gates/phase-7.toml"
FEATURES = ["proxy-protocol", "l4", "uring", "mtc", "adapter-mariadb", "adapter-crdb", "aegis-otlp", "libcrux-spike"]
TABLES = {  # (file, kind) -> heading regex
    (SC, "tcb"): r"^## Phase 7: one TCB line per feature",
    (SC, "deferred"): r"^### Phase 7: deferred and blocked",
    (CM, "tcb"): r"^### 4\.2 Phase-7 TCB lines",
    (CM, "deferred"): r"^### 4\.3 Phase-7 deferred and blocked",
}
COLS = {"tcb": ("feature", "new surface", "gate_id", "rung", "residuals"),
        "deferred": ("item", "status", "evidence", "gate_id", "re-check")}
# residuals each feature must carry (P7 reports; PLAN-7 "Residual claims to keep honest"). (label, regex)
REQUIRED = {
    "proxy-protocol": [("UNIX family not Kani-covered", r"UNIX"), ("TLV > 10 bytes bound", r"TLV[^|]*\b10 bytes"),
                       ("8 KiB bitmap", r"8 KiB"), ("bitmap only by exhaustive unit test", r"exhaustive unit test"),
                       ("trusted CIDR only", r"trusted CIDR")],
    "l4": [("ext > 12 bytes bound", r"ext[^|]*\b12 bytes"), ("8 KiB bitmap", r"8 KiB"),
           ("bitmap only by exhaustive unit test", r"exhaustive unit test"), ("idle timeout has no oracle", r"idle timeout[^|]*no oracle")],
    "uring": [("io_uring kernel surface", r"kernel attack surface[^|]*io_uring"), ("agent vet audit", r"agent review"),
              ("operator countersign", r"countersign"), ("X-19 unsafe", r"X-19")],
    "mtc": [("selection only", r"selection only"), ("codepoint 0xCA34", r"0xCA34"), ("experimental codepoint", r"experimental"),
            ("no MTC validity claim", r"no MTC validity"), ("not driven through aegis-bin", r"no gate drives")],
    "adapter-mariadb": [("not servable / boots fail closed", r"not servable"), ("no pool", r"no pool"),
                        ("no cancel", r"no cancel"), ("write forms not live-tested", r"not live-tested"),
                        ("loopback only", r"loopback only"), ("no TLS", r"no TLS"), ("no RLS", r"no RLS")],
    "adapter-crdb": [("40001 retry only unit-tested", r"40001[^|]*only unit-tested"), ("no RLS", r"no RLS"),
                     ("40001 surfaces as conflict", r"surfaces as a conflict"), ("CancelRequest untested", r"CancelRequest[^|]*untested")],
    "aegis-otlp": [("https not oracle-covered", r"https"), ("retry", r"retry"), ("backpressure", r"backpressure"),
                   ("not oracle-covered", r"not oracle-covered")],
    "libcrux-spike": [("2.5-3x slower", r"2\.5-3\s*[×x]"), ("not side-channel verified", r"not verified side-channel"),
                      ("cfg(hax) advisory", r"cfg\(hax\)"), ("accepted until 2027-02-06", r"until 2027-02-06"),
                      ("spike, not shipped", r"not a shipped")],
}
RUNG = re.compile(r"\bR[0-4]\b")
TRUSTED_SC = [("hyper", r"\bhyper\b"), ("h2", r"\bh2\b"), ("tokio", r"\btokio\b"), ("rustls", r"\brustls\b"),
              ("AWS-LC C", r"AWS-LC C"), ("rustc", r"\brustc\b"), ("io_uring", r"io_uring"), ("libcrux", r"\blibcrux\b")]
COMPONENT = re.compile(r"\b(hyper|h2|tokio|rustls|AWS-LC|aws-lc(?:-rs|-sys|-fips-sys)?|rustc|LLVM|io[_-]uring|"
                       r"libcrux[\w-]*|kernel)\b", re.I)
PROOF = re.compile(r"\b(proven|proved|formally[\s-]+verified|verified)\b", re.I)
NEG = re.compile(r"\b(not|never|no|nor|without|neither|un\w*)\b", re.I)
BY_DESIGN = re.compile(r"(unsupported|not\s+supported|never\s+supported|out\s+of\s+scope)\s+by\s+design", re.I)


def split_row(ln):
    return [c.strip() for c in ln.strip().strip("|").split("|")]


def table_after(lines, start):
    """(header, [(lineno, cells)]) of the first table after `start`, stopping at the next heading."""
    i = start + 1
    while i < len(lines) and not lines[i].startswith("|"):
        if lines[i].startswith("#"):
            return None, []
        i += 1
    if i + 1 >= len(lines):
        return None, []
    header, rows, j = split_row(lines[i]), [], i + 2
    while j < len(lines) and lines[j].startswith("|"):
        rows.append((j + 1, split_row(lines[j])))
        j += 1
    return header, rows


def gate_names(root):
    with open(os.path.join(root, GATES), "rb") as f:
        return {g["name"] for g in tomllib.load(f).get("gate", []) if "name" in g}


def units(text):
    """Table cells and sentences: the granularity at which a 'proven' wording is judged."""
    for ln in text.splitlines():
        parts = split_row(ln) if ln.startswith("|") else [ln]
        for cell in parts:
            for s in re.split(r"(?<=[.;:])\s+", cell):
                if s.strip():
                    yield s


def affirmative_proof(u):
    if not COMPONENT.search(u):
        return None
    for m in PROOF.finditer(u):
        before = u[max(0, m.start() - 40):m.start()]
        if not NEG.search(before):
            return m.group(0)
    return None


def check(root):
    errs, stats = [], {"gids": set()}
    E = lambda tag, msg: errs.append((tag, msg))
    try:
        gates = gate_names(root)
    except Exception as e:
        gates = set()
        E("gate-id", f"{GATES} unreadable: {e}")
    texts, parsed = {}, {}
    for f in (SC, CM):
        p = os.path.join(root, f)
        if not os.path.isfile(p):
            E("structure", f"{f} missing")
            texts[f] = ""
            continue
        texts[f] = open(p, encoding="utf-8").read()
    for (f, kind), rx in TABLES.items():
        lines = texts[f].splitlines()
        hs = [i for i, ln in enumerate(lines) if re.match(rx, ln)]
        if not hs:
            E("structure", f"{f}: no heading matching {rx!r}")
            continue
        header, rows = table_after(lines, hs[0])
        if not header or tuple(header) != COLS[kind]:
            E("structure", f"{f}: {kind} table header must be {' | '.join(COLS[kind])}, got {header}")
            continue
        good = {}
        for ln, cells in rows:
            if len(cells) != len(header):
                E("structure", f"{f}:{ln}: {len(cells)} cells, header has {len(header)}")
                continue
            key = re.sub(r"`", "", cells[0]).strip()
            if key in good:
                E("feature-dup", f"{f}:{ln}: second row for {key!r}")
                continue
            good[key] = (ln, dict(zip(header, cells)))
        parsed[(f, kind)] = good

    def gate_cell(f, ln, what, cell):
        ids = re.findall(r"`([^`]+)`", cell)
        rest = re.sub(r"`[^`]+`", "", cell).replace(",", "").strip()
        if not ids or rest:
            E("gate-id", f"{f}:{ln}: {what}: gate_id must be backticked gate names, got {cell!r}")
        for g in ids:
            stats["gids"].add(g)
            if g not in gates:
                E("gate-id", f"{f}:{ln}: {what}: gate {g!r} is not a gate in {GATES}")
        return set(ids)

    # TCB tables
    seen = {}
    for f in (SC, CM):
        t = parsed.get((f, "tcb"))
        if t is None:
            continue
        for key in t:
            if key not in FEATURES:
                E("feature-dup", f"{f}:{t[key][0]}: row for unknown feature {key!r} (known: {', '.join(FEATURES)})")
        for feat in FEATURES:
            if feat not in t:
                E("feature-missing", f"{f}: no TCB line for Phase-7 feature {feat!r}")
                continue
            ln, r = t[feat]
            for lab in ("crates:", "C:", "kernel:"):
                if not re.search(r"(^|[\s;(])" + re.escape(lab), r["new surface"]):
                    E("surface", f"{f}:{ln}: {feat}: surface does not name {lab!r} (write 'none' if nothing new)")
            gids = gate_cell(f, ln, feat, r["gate_id"])
            rungs = set(RUNG.findall(r["rung"]))
            if not rungs:
                E("rung", f"{f}:{ln}: {feat}: rung cell names no rung R0..R4: {r['rung'][:60]!r}")
            res = r["residuals"]
            if not res or res in ("—", "-", "none"):
                E("residual", f"{f}:{ln}: {feat}: empty residuals")
            else:
                for lab, rx in REQUIRED.get(feat, []):
                    if not re.search(rx, res, re.I):
                        E("residual", f"{f}:{ln}: {feat}: residuals drop '{lab}'")
            seen.setdefault(feat, {})[f] = (gids, rungs)
    for feat, by in seen.items():
        if len(by) == 2:
            (g1, r1), (g2, r2) = by[SC], by[CM]
            if g1 != g2:
                E("mismatch", f"{feat}: gate ids differ: {SC} {sorted(g1)} vs {CM} {sorted(g2)}")
            if r1 and r2 and r1 != r2:
                E("mismatch", f"{feat}: rungs differ: {SC} {sorted(r1)} vs {CM} {sorted(r2)}")

    # deferred / blocked tables
    for f in (SC, CM):
        t = parsed.get((f, "deferred"))
        if t is None:
            continue
        for key, (ln, r) in t.items():
            gate_cell(f, ln, key, r["gate_id"])
        for item in ("HTTP/3", "WebTransport"):
            if item not in t:
                E("deferred", f"{f}: no deferred row for {item}")
                continue
            ln, r = t[item]
            if not re.search(r"\bdeferred\b", r["status"], re.I) or "2026-11-06" not in r["status"]:
                E("deferred", f"{f}:{ln}: {item}: status must be 'deferred' with the 2026-11-06 evidence date")
            if len(r["evidence"]) < 40:
                E("deferred", f"{f}:{ln}: {item}: evidence cell is empty or too short to carry the probe results")
            if "2027-03-30" not in r["re-check"]:
                E("deferred", f"{f}:{ln}: {item}: re-check must carry 2027-03-30")
        if "HTTP/3" in t and not re.search(r"#366[^|]*#377[^|]*#378", t["HTTP/3"][1]["evidence"]):
            E("deferred", f"{f}:{t['HTTP/3'][0]}: HTTP/3 evidence must name h3 PRs #366, #377, #378")
        if "64-core scaling run" not in t:
            E("blocked", f"{f}: no row for the 64-core scaling run")
        else:
            ln, r = t["64-core scaling run"]
            if not (re.search(r"\bblocked\b", r["status"], re.I) and re.search(r"quota", r["status"], re.I)
                    and re.search(r"CPUS_ALL_REGIONS\s*=\s*12\b", r["status"])):
                E("blocked", f"{f}:{ln}: 64-core status must be 'blocked on GCP quota (CPUS_ALL_REGIONS = 12 ...)'")
    for f in (SC, CM):
        for n, ln in enumerate(texts[f].splitlines(), 1):
            if BY_DESIGN.search(ln):
                E("deferred", f"{f}:{n}: {BY_DESIGN.search(ln).group(0)!r}: HTTP/3/WebTransport are deferred, not by design")
            if "PENDING(" in ln:
                E("pending", f"{f}:{n}: unfilled PENDING marker")

    # trusted lists
    lines = texts[SC].splitlines()
    np = [i for i, ln in enumerate(lines) if ln.startswith("## Not proven")]
    if not np:
        E("trusted-list", f"{SC}: no '## Not proven' section")
    else:
        header, rows = table_after(lines, np[0])
        firsts = [c[0] for _, c in rows if c]
        for name, rx in TRUSTED_SC:
            if not any(re.search(rx, c) for c in firsts):
                E("trusted-list", f"{SC}: 'Not proven' table has no row for {name}")
    tm = re.search(r"\*\*Trusted, not verified\*\*(.*?)\n\n", texts[CM], re.S)
    for name, rx in (("io_uring", r"io_uring"), ("libcrux", r"\blibcrux\b")):
        if not tm or not re.search(rx, tm.group(1)):
            E("trusted-list", f"{CM}: **Trusted, not verified** paragraph lacks {name}")

    # proof wording
    for f in (SC, CM):
        for u in units(texts[f]):
            w = affirmative_proof(u)
            if w:
                E("proven", f"{f}: {w!r} about a trusted component: {u[:100]!r}")
    stats["gids"] = len(stats["gids"])
    return errs, stats


def run_check(root):
    errs, st = check(root)
    for tag, msg in errs:
        print(f"  {tag}: {msg}")
    if errs:
        print(f"TCB-LINES: FAIL ({len(errs)} violation(s): {', '.join(sorted({t for t, _ in errs}))})")
        return 1
    print(f"TCB-LINES: PASS ({len(FEATURES)} Phase-7 features x 2 files ({SC}, {CM}), each naming crates/C/kernel "
          f"surface, rung and residuals; {st['gids']} gate ids, all in {GATES}; HTTP/3 + WebTransport deferred "
          f"(2026-11-06, re-check 2027-03-30); 64-core run blocked on quota; no trusted component called proven)")
    return 0


# ------------------------------------------------------------------------------------------------------- self-test
def _rw(path, fn):
    s = open(path, encoding="utf-8").read()
    t = fn(s)
    if t == s:
        raise RuntimeError(f"mutant changed nothing in {path}")
    open(path, "w", encoding="utf-8").write(t)


def _row_re(key):
    return re.compile(r"(?m)^\| `?" + re.escape(key) + r"`? \|.*\n")


def drop_row(f, key):
    return lambda r: _rw(f"{r}/{f}", lambda s: _row_re(key).sub("", s, count=1))


def dup_row(f, key):
    return lambda r: _rw(f"{r}/{f}", lambda s: _row_re(key).sub(lambda m: m.group(0) * 2, s, count=1))


def set_cell(f, key, col, fn, kind="tcb"):
    idx = COLS[kind].index(col)

    def mut(r):
        def edit(s):
            def one(m):
                cells = split_row(m.group(0))
                cells[idx] = fn(cells[idx])
                return "| " + " | ".join(cells) + " |\n"
            # only the row inside the right table: rows are unique per table, and the two kinds use different keys
            return _row_re(key).sub(one, s, count=1)
        _rw(f"{r}/{f}", edit)
    return mut


def both(*muts):
    return lambda r: [m(r) for m in muts]


def sub(f, old, new):
    return lambda r: _rw(f"{r}/{f}", lambda s: s.replace(old, new, 1))


def resub(f, rx, new):
    return lambda r: _rw(f"{r}/{f}", lambda s: re.sub(rx, new, s, count=1))


def append(f, text):
    return lambda r: open(f"{r}/{f}", "a", encoding="utf-8").write(text)


def drop_gate(name):
    return lambda r: _rw(f"{r}/{GATES}", lambda s: re.sub(r'\[\[gate\]\]\nname = "' + re.escape(name) + r'"\n', "[[gate]]\nname = \"" + name + "-gone\"\n", s))


def strip(rx):
    return lambda c: re.sub(rx, "", c)


def drop_np_row(rx):
    return lambda r: _rw(f"{r}/{SC}", lambda s: re.sub(r"(?m)^\| \*\*" + rx + r".*\n", "", s, count=1))


MUTANTS = [
    # unit oracle: a Phase-7 feature without a TCB line
    ("no-uring-line-sc", {"feature-missing"}, drop_row(SC, "uring")),
    ("no-libcrux-line-cm", {"feature-missing"}, drop_row(CM, "libcrux-spike")),
    ("dup-mtc-line", {"feature-dup"}, dup_row(SC, "mtc")),
    ("table-heading-renamed", {"structure"}, sub(CM, "### 4.2 Phase-7 TCB lines", "### 4.2 Phase-7 lines")),
    # unit oracle: a TCB line without a rung
    ("mtc-no-rung", {"rung"}, set_cell(SC, "mtc", "rung", lambda c: "selection logic against the decision table")),
    ("rung-mismatch", {"mismatch"}, set_cell(SC, "adapter-crdb", "rung", lambda c: c.replace("R2", "R3"))),
    # brief: a TCB line citing a gate id that doesn't exist
    ("gate-id-unknown", {"gate-id"}, both(*(set_cell(f, "mtc", "gate_id", lambda c: c.replace("`cred-select`", "`cred-select-x`")) for f in (SC, CM)))),
    ("gate-removed-from-toml", {"gate-id"}, drop_gate("kani-wire")),
    ("gate-id-unquoted", {"gate-id"}, both(*(set_cell(f, "aegis-otlp", "gate_id", lambda c: c.replace("`otlp-export`", "otlp-export")) for f in (SC, CM)))),
    ("gate-id-empty", {"gate-id", "mismatch"}, set_cell(CM, "l4", "gate_id", lambda c: "—")),
    ("gate-id-mismatch", {"mismatch"}, set_cell(SC, "uring", "gate_id", lambda c: c + ", `tests`")),
    # surface naming
    ("uring-no-kernel", {"surface"}, set_cell(SC, "uring", "new surface", lambda c: c.replace("kernel:", "linux"))),
    ("crdb-no-C", {"surface"}, set_cell(CM, "adapter-crdb", "new surface", lambda c: c.replace("C: none new;", ""))),
    # residuals (brief list)
    ("proxy-residual-empty", {"residual"}, set_cell(SC, "proxy-protocol", "residuals", lambda c: "—")),
    ("proxy-no-unix-bound", {"residual"}, set_cell(SC, "proxy-protocol", "residuals", strip(r"the UNIX address family is not covered in a whole parse; "))),
    ("proxy-no-bitmap-test", {"residual"}, set_cell(CM, "proxy-protocol", "residuals", lambda c: c.replace("exhaustive unit test", "test"))),
    ("l4-no-ext12", {"residual"}, set_cell(SC, "l4", "residuals", lambda c: c.replace("12 bytes", "a few bytes"))),
    ("uring-no-countersign", {"residual"}, set_cell(SC, "uring", "residuals", lambda c: c.replace("countersign", "review"))),
    ("uring-no-x19", {"residual"}, set_cell(CM, "uring", "residuals", lambda c: c.replace("X-19", "the"))),
    ("uring-no-kernel-surface", {"residual"}, set_cell(SC, "uring", "residuals", lambda c: c.replace("kernel attack surface", "surface"))),
    ("mtc-validity-claim", {"residual"}, set_cell(SC, "mtc", "residuals", lambda c: c.replace("no MTC validity", "an MTC validity"))),
    ("mtc-no-codepoint", {"residual"}, set_cell(CM, "mtc", "residuals", lambda c: c.replace("0xCA34", "the codepoint"))),
    ("mariadb-tls", {"residual"}, set_cell(SC, "adapter-mariadb", "residuals", lambda c: c.replace("loopback only and no TLS", "TLS"))),
    ("mariadb-no-rls-dropped", {"residual"}, set_cell(SC, "adapter-mariadb", "residuals", lambda c: c.replace("no RLS", "RLS"))),
    ("mariadb-servable", {"residual"}, set_cell(CM, "adapter-mariadb", "residuals", lambda c: c.replace("not servable", "servable"))),
    ("crdb-40001-live", {"residual"}, set_cell(SC, "adapter-crdb", "residuals", lambda c: c.replace("only unit-tested", "live-tested"))),
    ("otlp-no-backpressure", {"residual"}, set_cell(SC, "aegis-otlp", "residuals", lambda c: c.replace("backpressure", "load"))),
    ("libcrux-side-channel", {"residual"}, set_cell(SC, "libcrux-spike", "residuals", lambda c: c.replace("not verified side-channel", "side-channel"))),
    ("libcrux-no-expiry", {"residual"}, set_cell(CM, "libcrux-spike", "residuals", lambda c: c.replace("until 2027-02-06", "indefinitely"))),
    ("libcrux-no-cost", {"residual"}, set_cell(SC, "libcrux-spike", "residuals", lambda c: c.replace("2.5-3×", "similar to"))),
    # unit oracle: HTTP/3 'unsupported by design' instead of deferred with dated evidence
    ("h3-by-design-status", {"deferred"}, set_cell(SC, "HTTP/3", "status", lambda c: "unsupported by design", kind="deferred")),
    ("h3-by-design-prose", {"deferred"}, append(CM, "\nHTTP/3 is not supported by design.\n")),
    ("h3-no-recheck", {"deferred"}, set_cell(CM, "HTTP/3", "re-check", lambda c: c.replace("2027-03-30", "later"), kind="deferred")),
    ("h3-no-date", {"deferred"}, set_cell(SC, "HTTP/3", "status", lambda c: "deferred", kind="deferred")),
    ("webtransport-row-missing", {"deferred"}, drop_row(SC, "WebTransport")),
    ("scaling-not-blocked", {"blocked"}, set_cell(CM, "64-core scaling run", "status", lambda c: "done (2026-11-06)", kind="deferred")),
    ("scaling-row-missing", {"blocked"}, drop_row(SC, "64-core scaling run")),
    # unit oracle: a claim calling io-uring / hyper / AWS-LC 'proven'
    ("hyper-proven", {"proven"}, append(SC, "\nhyper is proven correct for HTTP/1.1 framing.\n")),
    ("io-uring-verified", {"proven"}, append(CM, "\nThe io_uring kernel code is formally verified.\n")),
    ("aws-lc-proved", {"proven"}, append(SC, "\n| x | the AWS-LC C code is proved memory-safe | y |\n")),
    ("libcrux-proven", {"proven"}, append(CM, "\nlibcrux is proven side-channel free.\n")),
    ("rustc-verified", {"proven"}, append(SC, "\nThe Rust compiler (rustc) is verified.\n")),
    # trusted lists
    ("np-no-io_uring-row", {"trusted-list"}, drop_np_row(r"Linux io_uring")),
    ("np-no-libcrux-row", {"trusted-list"}, drop_np_row(r"libcrux")),
    ("cm-trusted-no-libcrux", {"trusted-list"}, resub(CM, r"\s*and libcrux \(spike only, never shipped\)", "")),
    # P7-bin-001 has landed: no unfilled marker
    ("pending-marker", {"pending"}, set_cell(SC, "uring", "rung", lambda c: c + "; PENDING(P7-bin-001)")),
]

FIXTURE = "ci/fixtures/tcb-lines/good"


def self_test(repo):
    tmp = tempfile.mkdtemp(prefix="tcb-lines-selftest-")
    bad = []
    try:
        def fresh(src):
            r = os.path.join(tmp, "t")
            shutil.rmtree(r, ignore_errors=True)
            for f in (SC, CM, GATES):
                os.makedirs(os.path.dirname(os.path.join(r, f)) or r, exist_ok=True)
                shutil.copy(os.path.join(src, f), os.path.join(r, f))
            return r
        sources = [("repo", repo), ("fixture", os.path.join(repo, FIXTURE))]
        for label, src in sources:
            errs, _ = check(fresh(src))
            if errs:
                bad.append(f"{label} baseline not clean: {sorted({t for t, _ in errs})} ({errs[0][1][:80]})")
        caught = 0
        for name, want, mut in MUTANTS:
            for label, src in sources:
                r = fresh(src)
                try:
                    mut(r)
                except Exception as e:
                    bad.append(f"{name}@{label}: mutant not applied ({e})")
                    print(f"  FAIL {name}@{label}: not applied ({e})")
                    continue
                errs, _ = check(r)
                got = {t for t, _ in errs}
                if got == want:
                    caught += 1
                    print(f"  ok   {name}@{label}: red ({', '.join(sorted(got))})")
                else:
                    bad.append(f"{name}@{label}: want {sorted(want)}, got {sorted(got) or 'PASS'}")
                    print(f"  FAIL {name}@{label}: want {sorted(want)}, got {sorted(got) or 'PASS'}")
        total = len(MUTANTS) * len(sources)
        if bad:
            print(f"TCB-LINES SELF-TEST: FAIL ({'; '.join(bad)})")
            return 1
        print(f"TCB-LINES SELF-TEST: PASS (repo and fixture baselines clean; {caught}/{total} mutant runs red with the "
              f"exact expected tag ({len(MUTANTS)} mutants x repo, fixture))")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if argv == ["--self-test"]:
        return self_test(repo)
    if not argv:
        return run_check(repo)
    if len(argv) == 2 and argv[0] == "--root":
        return run_check(os.path.abspath(argv[1]))
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
