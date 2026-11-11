#!/usr/bin/env python3
"""TCB-line gate (IMPLEMENTATION_PLAN §3 Phase 7 "each off by default, own TCB line"; PLAN-7; unit P7-compliance-001;
Phase 8 tables and residual R1-R17 table: PLAN-8 W3, unit P8-compliance-001).

Usage: python3 -I ci/tcb-lines.py [--root DIR]
       python3 -I ci/tcb-lines.py --self-test

Stdlib only. Reads SECURITY_CLAIMS.md, compliance/COMPLIANCE_MAP.md and gates/phase-8.toml (which carries every
Phase-7 gate) under the root.

Each of the two files carries the same four tables:
  TCB table       SECURITY_CLAIMS "## Phase 7: one TCB line per feature" / COMPLIANCE_MAP "### 4.2 Phase-7 TCB lines";
                  columns feature | new surface | gate_id | rung | residuals, one row per Phase-7 feature
  deferred table  SECURITY_CLAIMS "### Phase 7: deferred and blocked" / COMPLIANCE_MAP "### 4.3 Phase-7 deferred ...";
                  columns item | status | evidence | gate_id | re-check
  Phase-8 TCB     SECURITY_CLAIMS "## Phase 8: TCB changes" / COMPLIANCE_MAP "### 4.4 Phase-8 TCB changes"; same columns
                  as the TCB table, one row per Phase-8 change that adds or moves trusted surface (CHANGES)
  residual table  SECURITY_CLAIMS "## Phase 8: residuals R1-R17" / COMPLIANCE_MAP "### 4.5 Phase-8 residuals R1-R17";
                  columns # | residual | status | rung | gate_id | evidence, one row per PREFLIGHT-8 §P2 residual

check fails (last line `TCB-LINES: FAIL (<n> violation(s): <tags>)`, exit 1) on:
  structure        a table missing, a header without the required columns, or a row whose cell count differs
  feature-missing  a Phase-7 feature (FEATURES) or a Phase-8 change (CHANGES) without a row in a file's table
  feature-dup      a feature (or a deferred item) with more than one row, or a row for an unknown feature
  surface          a surface cell that does not name all three of `crates:`, `C:` and `kernel:` (value may be none)
  gate-id          a gate_id cell that is empty, not only backticked names, or names a gate not in gates/phase-8.toml
  gate-required    a row that does not name the gate whose run closed (or judges) it (GATE_REQUIRED, RES_GATES)
  stale            a Phase-7 residual cell that still states a residual Phase 8 closed (STALE)
  rung             a rung cell without an R0..R4 rung
  residual         an empty residual cell, or one that drops a residual this feature must carry (REQUIRED)
  mismatch         the two files disagree on a feature's / change's gate ids or rungs, or on a residual's status,
                   gate ids or rungs
  deferred         HTTP/3 / WebTransport row missing, not "deferred" with the 2026-11-06 evidence date and the
                   2027-03-30 re-check, or either file calling HTTP/3 / WebTransport "unsupported by design"
  blocked          the 64-core row missing, or neither (a) "running"/"queued" on the approved quota
                   (CPUS_ALL_REGIONS = 80) with the TO-FILL(64-core) placeholder in its evidence, nor (b) "measured
                   <date>" with evidence naming the 64-vCPU machine type (<family>-standard-64, e.g. the
                   n2-standard-64 that ran) called provisional and no placeholder
  residual-table   R1..R17 not each present once, a status not closed/partial/carried, no rung, a short evidence
                   cell, or a row that drops a fact it must carry (RES_REQ: D-P8.1 text for R1, the uncovered 0x11EB/
                   0x0202 client paths for R2, the cmvp config_sha256 pin for R3, the unrun 2 h quiet soak for R17,
                   ...) or claims "closed" where the evidence stops (RES_NOT_CLOSED)
  pqc4             no sentence in a file records rustls PR #3376 as closed unmerged under R-PQC-4
  trusted-list     SECURITY_CLAIMS "Not proven" table lacks a row for one of hyper, h2, tokio, rustls, AWS-LC C,
                   rustc, io_uring, libcrux; or the COMPLIANCE_MAP **Trusted, not verified** paragraph lacks io_uring
                   or libcrux
  proven           a table cell or sentence in either file that calls hyper, h2, tokio, rustls, AWS-LC, rustc/LLVM,
                   io_uring/io-uring, libcrux or the kernel proven/proved/verified without a negation
  pending          a `PENDING(` marker left in either file (P7-bin-001 has landed; its residuals must be filled in),
                   or a `TO-FILL(` marker anywhere but the evidence cell of the 64-core row

--self-test requires the real files and the fixture tree ci/fixtures/tcb-lines/good/ to PASS, then applies every
mutant to a copy of each and requires exactly the expected tag set. Last line `TCB-LINES SELF-TEST: PASS|FAIL (...)`.
"""
import os, re, shutil, sys, tempfile, tomllib

SC, CM, GATES = "SECURITY_CLAIMS.md", "compliance/COMPLIANCE_MAP.md", "gates/phase-8.toml"
FEATURES = ["proxy-protocol", "l4", "uring", "mtc", "adapter-mariadb", "adapter-crdb", "aegis-otlp", "libcrux-spike"]
# Phase-8 changes that add or move trusted surface (PLAN-8 Units; PREFLIGHT-8 §P2). MariaDB serving, crdb cancel,
# SEL-3 and OTLP retry change Phase-7 features and are judged on those rows (GATE_REQUIRED, STALE).
CHANGES = ["test-faults", "indicator", "runtime.worker_threads", "idempotency-retention", "route-path-refusal",
           "pg-adapter-hardening", "egress-tls-client", "chunked-one-response", "mldsa-cosigner"]
TABLES = {  # (file, kind) -> heading regex
    (SC, "tcb"): r"^## Phase 7: one TCB line per feature",
    (SC, "deferred"): r"^### Phase 7: deferred and blocked",
    (SC, "tcb8"): r"^## Phase 8: TCB changes",
    (SC, "res8"): r"^## Phase 8: residuals R1",
    (CM, "tcb"): r"^### 4\.2 Phase-7 TCB lines",
    (CM, "deferred"): r"^### 4\.3 Phase-7 deferred and blocked",
    (CM, "tcb8"): r"^### 4\.4 Phase-8 TCB changes",
    (CM, "res8"): r"^### 4\.5 Phase-8 residuals R1",
}
COLS = {"tcb": ("feature", "new surface", "gate_id", "rung", "residuals"),
        "tcb8": ("feature", "new surface", "gate_id", "rung", "residuals"),
        "deferred": ("item", "status", "evidence", "gate_id", "re-check"),
        "res8": ("#", "residual", "status", "rung", "gate_id", "evidence")}
# residuals each feature must carry (P7 reports; PLAN-7 "Residual claims to keep honest"). (label, regex)
REQUIRED = {
    "proxy-protocol": [("UNIX family not Kani-covered", r"UNIX"), ("TLV > 10 bytes bound", r"TLV[^|]*\b10 bytes"),
                       ("8 KiB bitmap", r"8 KiB"), ("bitmap only by exhaustive unit test", r"exhaustive unit test"),
                       ("trusted CIDR only", r"trusted CIDR")],
    "l4": [("ext > 12 bytes bound", r"ext[^|]*\b12 bytes"), ("8 KiB bitmap", r"8 KiB"),
           ("bitmap only by exhaustive unit test", r"exhaustive unit test"),
           ("idle timeout judged on one host only", r"idle timeout[^|]*bin-residuals[^|]*one host")],
    "uring": [("io_uring kernel surface", r"kernel attack surface[^|]*io_uring"), ("agent vet audit", r"agent review"),
              ("operator countersign", r"countersign"), ("X-19 unsafe", r"X-19")],
    "mtc": [("selection only", r"selection only"), ("codepoint 0xCA34", r"0xCA34"), ("experimental codepoint", r"experimental"),
            ("no MTC validity claim", r"no MTC validity"),
            ("bin-residuals probe limits", r"does not finish the handshake")],
    "adapter-mariadb": [("pool only via is_reusable", r"is_reusable"), ("kamrui only so far", r"kamrui only"),
                        ("no cancel", r"no cancel"), ("write forms not live-tested", r"not live-tested"),
                        ("loopback only", r"loopback only"), ("no TLS", r"no TLS"), ("no RLS", r"no RLS")],
    "adapter-crdb": [("no whole-transaction retry", r"no whole-transaction retry"), ("no RLS", r"no RLS"),
                     ("40001 surfaces as conflict", r"surfaces as a conflict"),
                     ("CancelRequest not told from close", r"cannot tell a CancelRequest from closing")],
    "aegis-otlp": [("Retry-After not covered", r"Retry-After"), ("drop-oldest not covered", r"drop-oldest"),
                   ("backpressure", r"backpressure"), ("not oracle-covered", r"not oracle-covered")],
    "libcrux-spike": [("2.5-3x slower", r"2\.5-3\s*[×x]"), ("not side-channel verified", r"not verified side-channel"),
                      ("cfg(hax) advisory", r"cfg\(hax\)"), ("accepted until 2027-02-06", r"until 2027-02-06"),
                      ("spike, not shipped", r"not a shipped")],
}
REQUIRED8 = {
    "test-faults": [("enabled only by acme-subject", r"acme-subject"), ("compile-time only", r"compile-time")],
    "indicator": [("never in aegis-bin", r"never in aegis-bin"), ("not a CMVP validation", r"not a CMVP validation"),
                  ("TLS 1.3 KDF no CAVP row", r"TLS 1\.3 KDF has no CAVP row"), ("one host", r"one host")],
    "runtime.worker_threads": [("absent = 2", r"absent = 2"), ("advisory", r"advisory"), ("provisional", r"provisional"),
                               ("agent runtime still 2", r"agent[^|]*2 workers")],
    "idempotency-retention": [("absent = never expire", r"absent = never expire"),
                              ("not applied by aegis-bin", r"not applied by aegis-bin")],
    "route-path-refusal": [("fails closed at load", r"fails closed at load")],
    "pg-adapter-hardening": [("no live non-ASCII PG test", r"no live PG[^|]*non-ASCII")],
    "egress-tls-client": [("one peer stack", r"one peer stack"), ("revocation not probed", r"revocation")],
    "chunked-one-response": [("h1 only", r"h1 over TLS only"), ("hyper trusted", r"hyper is trusted")],
    "mldsa-cosigner": [("floor build only", r"floor build only"), ("not interoperable", r"not interoperable"),
                       ("external witness", r"external witness")],
}
# gates a row must name: the gate whose run closed a Phase-7 residual, or the gate that judges a Phase-8 change
GATE_REQUIRED = {
    "l4": {"bin-residuals"}, "mtc": {"bin-residuals"}, "adapter-mariadb": {"native-e2e-mariadb", "allowlist-lock"},
    "adapter-crdb": {"crdb-live"}, "aegis-otlp": {"otlp-export"},
    "test-faults": {"no-test-faults"}, "indicator": {"fips-indicator", "fips-boundary", "unsafe-sites"},
    "runtime.worker_threads": {"scaling", "config-totality"}, "idempotency-retention": {"state-props"},
    "route-path-refusal": {"config-totality"}, "pg-adapter-hardening": {"fuzz"}, "egress-tls-client": {"egress-tls-e2e"},
    "chunked-one-response": {"bin-residuals"}, "mldsa-cosigner": {"tlog-mldsa-openssl"},
}
# Phase-7 residual wording that Phase 8 made false (a stale residual is a wrong claim, in either direction)
STALE = {
    "l4": [r"idle timeout[^|]*no oracle"],
    "mtc": [r"no gate drives"],
    "uring": [r"not fixed"],
    "adapter-mariadb": [r"not servable", r"no pool\b"],
    "adapter-crdb": [r"CancelRequest[^|]*untested", r"no live contention test", r"40001 retry is only unit-tested"],
    "aegis-otlp": [r"https endpoint[^|]*not oracle-covered", r"there is no retry"],
}
RESIDUALS = [f"R{i}" for i in range(1, 18)]
RES_STATUS = re.compile(r"^(closed|partial|carried)\b")
RES_GATES = {"R1": {"fips-boundary", "fips-indicator"}, "R2": {"kani-kx-client"}, "R3": {"conformance-full"},
             "R4": {"native-e2e-mariadb"}, "R5": {"scaling"}, "R6": {"bin-residuals"}, "R7": {"bin-residuals"},
             "R8": {"crdb-live"}, "R9": {"otlp-export"}, "R10": {"tlog-mldsa-openssl"}, "R11": {"no-test-faults"},
             "R12": {"state-props"}, "R13": {"config-totality"}, "R14": {"fuzz"}, "R15": {"egress-tls-e2e"},
             "R16": {"engine-pins-kamrui"}, "R17": {"soak"}}
# residuals whose evidence stops short of the PLAN-8 claim: never "closed" until the named evidence exists
RES_NOT_CLOSED = {"R2": "0x11EB / 0x0202 client paths are not Kani-covered (P8-kani-001 INFEASIBLE_REPORT)",
                  "R3": "conformance-full is red until the cmvp config_sha256 pin exists",
                  "R5": "the 64-core run is separate and advisory", "R9": "drop-oldest under backpressure is not covered",
                  "R12": "aegis-bin does not apply the F8 retention on PG, CockroachDB or MariaDB backends (refused at boot)", "R17": "the 2 h soak on quiet has not run"}
RES_REQ = {  # facts each residual row's evidence (or rung) must carry
    "R1": [("D-P8.1 component text", r"#5314-approved components"), ("combiner SP 800-227", r"SP 800-227 §4\.6\.2"),
           ("composite NOT CLAIMED", r"NOT CLAIMED"), ("#5298 dynamic not cited", r"#5298 is the dynamic module")],
    "R2": [("0x11EB not covered", r"0x11EB"), ("0x0202 only in AWS-LC C", r"0x0202[^|]*AWS-LC C"),
           ("INFEASIBLE report", r"INFEASIBLE_REPORT")],
    "R3": [("cmvp config_sha256 pin", r"config_sha256"), ("from the first release-rebuild", r"release-rebuild")],
    "R4": [("unit runs kamrui only", r"kamrui only")],
    "R5": [("64-core row", r"64-core scaling run"), ("provisional", r"provisional")],
    "R12": [("not applied by aegis-bin", r"aegis-bin does not apply")],
    "R17": [("2 h", r"\b2 h\b"), ("aegis-quiet", r"quiet"), ("not yet run", r"not\s+(?:yet\s+)?(?:been\s+)?run"),
            ("15-min substitute", r"0\.25 h|15-min"), ("no soak claim", r"no soak claim")],
}
TOFILL = "TO-FILL(64-core)"
MACHINE64 = re.compile(r"\b[a-z][a-z0-9]*-standard-64\b")  # the 64-vCPU GCP type the run used
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

    # TCB tables (Phase 7 features, Phase 8 changes)
    seen = {}
    for kind, names, required, what in (("tcb", FEATURES, REQUIRED, "Phase-7 feature"),
                                        ("tcb8", CHANGES, REQUIRED8, "Phase-8 change")):
        for f in (SC, CM):
            t = parsed.get((f, kind))
            if t is None:
                continue
            for key in t:
                if key not in names:
                    E("feature-dup", f"{f}:{t[key][0]}: row for unknown {what} {key!r} (known: {', '.join(names)})")
            for feat in names:
                if feat not in t:
                    E("feature-missing", f"{f}: no TCB line for {what} {feat!r}")
                    continue
                ln, r = t[feat]
                for lab in ("crates:", "C:", "kernel:"):
                    if not re.search(r"(^|[\s;(])" + re.escape(lab), r["new surface"]):
                        E("surface", f"{f}:{ln}: {feat}: surface does not name {lab!r} (write 'none' if nothing new)")
                gids = gate_cell(f, ln, feat, r["gate_id"])
                for g in sorted(GATE_REQUIRED.get(feat, set()) - gids):
                    E("gate-required", f"{f}:{ln}: {feat}: gate_id does not name `{g}`, the gate that judges this row")
                rungs = set(RUNG.findall(r["rung"]))
                if not rungs:
                    E("rung", f"{f}:{ln}: {feat}: rung cell names no rung R0..R4: {r['rung'][:60]!r}")
                res = r["residuals"]
                if not res or res in ("—", "-", "none"):
                    E("residual", f"{f}:{ln}: {feat}: empty residuals")
                else:
                    for lab, rx in required.get(feat, []):
                        if not re.search(rx, res, re.I):
                            E("residual", f"{f}:{ln}: {feat}: residuals drop '{lab}'")
                for rx in STALE.get(feat, []):
                    m = re.search(rx, res + " | " + r["rung"], re.I)
                    if m:
                        E("stale", f"{f}:{ln}: {feat}: still states a residual Phase 8 closed: {m.group(0)!r}")
                seen.setdefault((kind, feat), {})[f] = (gids, rungs)
    for (kind, feat), by in seen.items():
        if len(by) == 2:
            (g1, r1), (g2, r2) = by[SC], by[CM]
            if g1 != g2:
                E("mismatch", f"{feat}: gate ids differ: {SC} {sorted(g1)} vs {CM} {sorted(g2)}")
            if r1 and r2 and r1 != r2:
                E("mismatch", f"{feat}: rungs differ: {SC} {sorted(r1)} vs {CM} {sorted(r2)}")

    # Phase-8 residual table R1..R17
    rseen = {}
    for f in (SC, CM):
        t = parsed.get((f, "res8"))
        if t is None:
            continue
        for key in t:
            if key not in RESIDUALS:
                E("residual-table", f"{f}:{t[key][0]}: row {key!r} is not a PREFLIGHT-8 residual R1..R17")
        for rid in RESIDUALS:
            if rid not in t:
                E("residual-table", f"{f}: no row for residual {rid}")
                continue
            ln, r = t[rid]
            m = RES_STATUS.match(r["status"])
            if not m:
                E("residual-table", f"{f}:{ln}: {rid}: status must start with closed, partial or carried: {r['status'][:40]!r}")
            status = m.group(1) if m else None
            if status == "closed" and rid in RES_NOT_CLOSED:
                E("residual-table", f"{f}:{ln}: {rid}: 'closed' overclaims: {RES_NOT_CLOSED[rid]}")
            gids = gate_cell(f, ln, rid, r["gate_id"])
            for g in sorted(RES_GATES.get(rid, set()) - gids):
                E("gate-required", f"{f}:{ln}: {rid}: gate_id does not name `{g}`, the evidence gate")
            rungs = set(RUNG.findall(r["rung"]))
            if not rungs:
                E("residual-table", f"{f}:{ln}: {rid}: rung cell names no rung R0..R4: {r['rung'][:60]!r}")
            if len(r["evidence"]) < 40:
                E("residual-table", f"{f}:{ln}: {rid}: evidence cell is empty or too short")
            body = r["rung"] + " | " + r["evidence"]
            for lab, rx in RES_REQ.get(rid, []):
                if not re.search(rx, body):
                    E("residual-table", f"{f}:{ln}: {rid}: drops '{lab}'")
            rseen.setdefault(rid, {})[f] = (status, gids, rungs)
    for rid, by in rseen.items():
        if len(by) == 2 and by[SC] != by[CM]:
            E("mismatch", f"{rid}: status/gates/rungs differ: {SC} {by[SC][0]} {sorted(by[SC][1])} {sorted(by[SC][2])} "
                          f"vs {CM} {by[CM][0]} {sorted(by[CM][1])} {sorted(by[CM][2])}")

    # rustls #3376 under R-PQC-4 (PREFLIGHT-8 P1)
    for f in (SC, CM):
        if not any("#3376" in u and re.search(r"closed unmerged", u) and "R-PQC-4" in u for u in units(texts[f])):
            E("pqc4", f"{f}: no sentence records rustls PR #3376 as closed unmerged under R-PQC-4")

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
            st, ev = r["status"], r["evidence"]
            waiting = (re.search(r"\b(running|queued)\b", st, re.I) and re.search(r"CPUS_ALL_REGIONS\s*=\s*80\b", st)
                       and TOFILL in ev)
            measured = (re.search(r"\bmeasured\s+20\d\d-\d\d-\d\d\b", st) and MACHINE64.search(ev)
                        and re.search(r"\bprovisional\b", ev) and TOFILL not in ev)
            if not (waiting or measured):
                E("blocked", f"{f}:{ln}: 64-core row must be 'running'/'queued' on CPUS_ALL_REGIONS = 80 with the {TOFILL} "
                             f"placeholder, or 'measured <date>' with <family>-standard-64 evidence called provisional")
    for f in (SC, CM):
        for n, ln in enumerate(texts[f].splitlines(), 1):
            if BY_DESIGN.search(ln):
                E("deferred", f"{f}:{n}: {BY_DESIGN.search(ln).group(0)!r}: HTTP/3/WebTransport are deferred, not by design")
            if "PENDING(" in ln:
                E("pending", f"{f}:{n}: unfilled PENDING marker")
            if "TO-FILL(" in ln and not (ln.startswith("| 64-core scaling run |") and ln.count("TO-FILL(") == 1
                                         and len(split_row(ln)) > 2 and TOFILL in split_row(ln)[2]):
                E("pending", f"{f}:{n}: TO-FILL marker outside the 64-core row's evidence cell")

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
    print(f"TCB-LINES: PASS ({len(FEATURES)} Phase-7 features + {len(CHANGES)} Phase-8 changes x 2 files ({SC}, {CM}), "
          f"each naming crates/C/kernel surface, rung, residuals and its judging gate; residuals R1-R17 each closed/"
          f"partial/carried with rung and evidence gate; {st['gids']} gate ids, all in {GATES}; HTTP/3 + WebTransport "
          f"deferred (2026-11-06, re-check 2027-03-30); 64-core row tracked; rustls #3376 recorded; no trusted "
          f"component called proven)")
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


def edit_row(f, key, fn, kind):
    """Edit several cells of one row at once: fn({col: cell}) -> {col: cell}."""
    cols = COLS[kind]

    def mut(r):
        def one(m):
            cells = fn(dict(zip(cols, split_row(m.group(0)))))
            return "| " + " | ".join(cells[c] for c in cols) + " |\n"
        _rw(f"{r}/{f}", lambda s: _row_re(key).sub(one, s, count=1))
    return mut


def scaling_mut(f, waiting, measured):
    """A 64-core-row mutant for either state of the row: `waiting` (TO-FILL placeholder in the evidence; the fixture)
    or `measured` (the filled row, once the run is recorded). Each must make the row red in its own state."""
    return edit_row(f, "64-core scaling run", lambda c: (waiting if TOFILL in c["evidence"] else measured)(dict(c)),
                    kind="deferred")


def _cells(c, **kw):
    c.update(kw)
    return c


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
    ("gate-id-unquoted", {"gate-id", "gate-required"}, both(*(set_cell(f, "aegis-otlp", "gate_id", lambda c: c.replace("`otlp-export`", "otlp-export")) for f in (SC, CM)))),
    ("gate-id-empty", {"gate-id", "mismatch", "gate-required"}, set_cell(CM, "l4", "gate_id", lambda c: "—")),
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
    ("mariadb-no-reusable", {"residual"}, set_cell(CM, "adapter-mariadb", "residuals", lambda c: c.replace("is_reusable", "a check"))),
    ("crdb-40001-retried", {"residual"}, set_cell(SC, "adapter-crdb", "residuals", lambda c: c.replace("no whole-transaction retry", "a whole-transaction retry"))),
    ("otlp-no-backpressure", {"residual"}, set_cell(SC, "aegis-otlp", "residuals", lambda c: c.replace("backpressure", "load"))),
    ("otlp-retry-after-dropped", {"residual"}, set_cell(CM, "aegis-otlp", "residuals", lambda c: c.replace("`Retry-After`, ", ""))),
    # Phase 8: Phase-7 rows must name the gate that closed their residual, and must not keep the closed wording
    ("mariadb-no-e2e-gate", {"gate-required"}, both(*(set_cell(f, "adapter-mariadb", "gate_id", lambda c: c.replace(", `native-e2e-mariadb`", "")) for f in (SC, CM)))),
    ("crdb-no-live-gate", {"gate-required"}, both(*(set_cell(f, "adapter-crdb", "gate_id", lambda c: c.replace(", `crdb-live`", "")) for f in (SC, CM)))),
    ("mtc-no-bin-gate", {"gate-required"}, both(*(set_cell(f, "mtc", "gate_id", lambda c: c.replace(", `bin-residuals`", "")) for f in (SC, CM)))),
    ("stale-mariadb-not-servable", {"stale"}, set_cell(SC, "adapter-mariadb", "residuals", lambda c: c + "; not servable")),
    ("stale-crdb-cancel", {"stale"}, set_cell(CM, "adapter-crdb", "residuals", lambda c: c + "; the CancelRequest (discard) path is untested")),
    ("stale-l4-idle", {"stale"}, set_cell(SC, "l4", "residuals", lambda c: c + "; the idle timeout after routing has no oracle")),
    ("stale-uring-400", {"stale"}, set_cell(CM, "uring", "residuals", lambda c: c + "; the double 400 is not fixed")),
    ("stale-mtc-bin", {"stale"}, set_cell(SC, "mtc", "residuals", lambda c: c + "; no gate drives `trust_anchors` through aegis-bin")),
    ("l4-idle-one-host-dropped", {"residual"}, set_cell(SC, "l4", "residuals", lambda c: c.replace("one host", "every host"))),
    # Phase-8 TCB changes
    ("p8-indicator-line-missing", {"feature-missing"}, drop_row(CM, "indicator")),
    ("p8-unknown-change", {"feature-dup", "feature-missing"}, set_cell(SC, "mldsa-cosigner", "feature", lambda c: "`mldsa-witness`")),
    ("p8-indicator-no-gate", {"gate-required"}, both(*(set_cell(f, "indicator", "gate_id", lambda c: c.replace("`fips-indicator`, ", "")) for f in (SC, CM)))),
    ("p8-indicator-in-bin", {"residual"}, set_cell(SC, "indicator", "residuals", lambda c: c.replace("never in aegis-bin", "also in aegis-bin"))),
    ("p8-indicator-cmvp-validation", {"residual"}, set_cell(CM, "indicator", "residuals", lambda c: c.replace("not a CMVP validation", "a CMVP validation"))),
    ("p8-retention-applied", {"residual"}, set_cell(SC, "idempotency-retention", "residuals", lambda c: c.replace("not applied by aegis-bin", "applied"))),
    ("p8-workers-agent-dropped", {"residual"}, set_cell(CM, "runtime.worker_threads", "residuals", lambda c: re.sub(r";[^;]*agent[^;]*$", "", c))),
    ("p8-cosigner-cmvp", {"residual"}, set_cell(SC, "mldsa-cosigner", "residuals", lambda c: c.replace("floor build only", "every build"))),
    ("p8-change-no-kernel", {"surface"}, set_cell(SC, "egress-tls-client", "new surface", lambda c: c.replace("kernel:", "os"))),
    ("p8-change-rung-mismatch", {"mismatch"}, set_cell(CM, "egress-tls-client", "rung", lambda c: c.replace("R2", "R3", 1))),
    # Phase-8 residual table R1..R17
    ("res-r17-missing", {"residual-table"}, drop_row(SC, "R17")),
    ("res-r4-dup", {"feature-dup"}, dup_row(CM, "R4")),
    ("res-soak-closed", {"residual-table"}, both(*(set_cell(f, "R17", "status", lambda c: "closed", kind="res8") for f in (SC, CM)))),
    ("res-soak-2h-claimed-run", {"residual-table"}, set_cell(SC, "R17", "evidence", lambda c: re.sub(r"has not been run yet|not yet run", "PASSED", c), kind="res8")),
    ("res-kani-closed", {"residual-table"}, both(*(set_cell(f, "R2", "status", lambda c: "closed", kind="res8") for f in (SC, CM)))),
    ("res-kani-no-0x11eb", {"residual-table"}, set_cell(CM, "R2", "evidence", lambda c: c.replace("0x11EB", "the other hybrid"), kind="res8")),
    ("res-conformance-closed", {"residual-table"}, both(*(set_cell(f, "R3", "status", lambda c: "closed", kind="res8") for f in (SC, CM)))),
    ("res-conformance-no-pin", {"residual-table"}, set_cell(SC, "R3", "evidence", lambda c: c.replace("config_sha256", "hash"), kind="res8")),
    ("res-r1-no-combiner", {"residual-table"}, set_cell(SC, "R1", "evidence", lambda c: c.replace("SP 800-227 §4.6.2", "a combiner"), kind="res8")),
    ("res-r1-no-5314-text", {"residual-table"}, set_cell(CM, "R1", "evidence", lambda c: c.replace("#5314-approved components", "approved parts"), kind="res8")),
    ("res-retention-closed", {"residual-table"}, both(*(set_cell(f, "R12", "status", lambda c: "closed", kind="res8") for f in (SC, CM)))),
    ("res-bad-status", {"residual-table", "mismatch"}, set_cell(SC, "R10", "status", lambda c: "done", kind="res8")),
    ("res-status-mismatch", {"mismatch"}, set_cell(SC, "R13", "status", lambda c: "carried", kind="res8")),
    ("res-no-rung", {"residual-table", "mismatch"}, set_cell(CM, "R15", "rung", lambda c: "end to end", kind="res8")),
    ("res-gate-unknown", {"gate-id", "gate-required"}, both(*(set_cell(f, "R8", "gate_id", lambda c: c.replace("`crdb-live`", "`crdb-livex`"), kind="res8") for f in (SC, CM)))),
    ("res-gate-dropped", {"gate-required"}, both(*(set_cell(f, "R4", "gate_id", lambda c: c.replace("`native-e2e-mariadb`, ", ""), kind="res8") for f in (SC, CM)))),
    ("res-unknown-row", {"residual-table"}, set_cell(SC, "R16", "#", lambda c: "R18", kind="res8")),
    ("pqc4-dropped", {"pqc4"}, lambda r: [_rw(f"{r}/{f}", lambda s: s.replace("closed unmerged", "still open")) for f in (SC, CM)]),
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
    # waiting state: placeholder dropped while still running; measured state: evidence no longer called provisional
    ("scaling-placeholder-dropped", {"blocked"}, scaling_mut(SC,
        lambda c: _cells(c, evidence=c["evidence"].replace(TOFILL, "result")),
        lambda c: _cells(c, evidence=re.sub(r"\bprovisional\b", "final", c["evidence"])))),
    # waiting: "measured" with the placeholder still in; measured: "measured" without any <family>-standard-64 evidence
    ("scaling-measured-no-evidence", {"blocked"}, scaling_mut(CM,
        lambda c: _cells(c, status="measured 2026-11-07"),
        lambda c: _cells(c, status="measured 2026-11-07", evidence=MACHINE64.sub("a VM", c["evidence"])))),
    # waiting: the pre-approval quota; measured: "measured" with no date
    ("scaling-old-quota", {"blocked"}, scaling_mut(SC,
        lambda c: _cells(c, status=c["status"].replace("= 80", "= 12")),
        lambda c: _cells(c, status=re.sub(r"\bmeasured\s+20\d\d-\d\d-\d\d\b", "measured", c["status"])))),
    ("to-fill-elsewhere", {"pending"}, set_cell(CM, "uring", "rung", lambda c: c + "; " + TOFILL)),
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
