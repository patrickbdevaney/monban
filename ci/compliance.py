#!/usr/bin/env python3
"""Compliance gate (PLAN-6 D9, D11; PREFLIGHT D-P1; unit P6-compliance-001).

Usage: python3 -I ci/compliance.py check [--root DIR]
       python3 -I ci/compliance.py --self-test

Stdlib only. If `jsonschema` happens to be importable it is run as a second CSAF validator (both must accept); the
built-in validator alone is enough and is what runs on a bare python3.

check fails (last line `COMPLIANCE: FAIL (<tag>: ...; ...)`, exit 1) on:
  map-structure   compliance/COMPLIANCE_MAP.md missing, or sections 1-8 missing / out of order, or a table malformed
  gate-id         a section-4 row whose gate_id is empty, not backticked, or not a gate name in gates/phase-6.toml
  evidence-kinds  a section-4 row with fewer than 2 `;`-separated evidence kinds
  control-missing a control row of the template's section 4 is missing
  ssdf-draft      an SSDF 1.2 control (PO.6.2, PS.4.3) not labelled "(draft)"
  sa17-theorem    a section-4.1 theorem that is not a frozen `theorem` in spec/STATEMENTS.sha256, a row without an R4
                  rung or without a "does NOT cover" entry, or a required model family (Select, Combine, Token,
                  Lowering/ThreeValued) with no theorem
  trusted-list    the trusted-not-verified list (hyper, h2, tokio, rustls, the AWS-LC C code, rustc) is incomplete
  required-claim  the map does not state "ML-DSA ... not approved in AWS-LC 3.1.0", or that laptop numbers are
                  provisional
  cra-missing     a file of the steward set (COMPLIANCE_MAP section 5) is missing under compliance/cra/
  draft-header    a CRA file whose first line is not `Status: DRAFT, not published` (JSON: a document.notes entry
                  starting with it, and tracking.status == "draft"), or an unknown file type under compliance/cra/
  support-period  support-period.draft.md has no `Support period:` line
  contact-address an e-mail address in a CRA draft (D-P1: no contact channel; the contact is a placeholder)
  csaf            a CSAF file that is not JSON, fails the vendored CSAF 2.0 schema, or fails the profile checks used
                  here (category per file, product-id references, VEX product-status rules, no `scores`)
  cyclonedx       a *.cdx.json under compliance/ that is not structurally CycloneDX
  schema-pin      the vendored CSAF schema is missing or its sha256 differs from the pin
  root-file       SECURITY.md at the repo root, in .github/ or docs/ (GitHub/Forgejo treat it as live policy), or a
                  LICENSE/LICENCE/COPYING/UNLICENSE file at the root (operator: no license yet)
  wording-fedramp "FedRAMP-ready/-authorized/-certified/-compliant" anywhere under compliance/
  wording-waf     "WAF" or "web application firewall" anywhere under compliance/, or a line that puts admission and
                  firewall together (template wording rule: admission control is rate limiting)
  wording-fips    a line mentioning "approved mode" without AL2023 / Amazon Linux 2023

--self-test copies the inputs to a temp dir, requires the clean copy to PASS, then applies each mutant and requires
the exact expected tag set. Last line `COMPLIANCE SELF-TEST: PASS|FAIL (...)`.
"""
import hashlib, json, os, re, shutil, sys, tempfile, tomllib

DRAFT = "Status: DRAFT, not published"
CSAF_SCHEMA = "compliance/cra/schemas/csaf_json_schema.json"
CSAF_SCHEMA_SHA256 = "29c114b35b0a30831f1674f2ab8b3ed9b2890cfeaa63b924ac6ed9d70ef44262"
CRA_REQUIRED = {
    "SECURITY.draft.md": None,
    "PSIRT-runbook.md": None,
    "sbom-statement.draft.md": None,
    "support-period.draft.md": None,
    "eu-declaration-of-conformity.draft.md": None,
    "steward-attestation.draft.md": None,
    "csaf/advisory-template.json": "csaf_security_advisory",
    "csaf/vex-template.json": "csaf_vex",
}
CONTROLS = ["SC-13", "SC-8/8(1)", "SC-12", "SI-7/7(1)/7(15)", "CM-7", "CM-2", "AU-2/3/12", "AU-9(3)/AU-10/SI-7(7)",
            "SA-11", "SA-15(13)", "SA-17(1)", "SR-2/3/5", "SI-2 / RA-5", "PS.4.3 anti-rollback"]
SSDF_DRAFT = ("PO.6.2", "PS.4.3")
TRUSTED = [("hyper", r"\bhyper\b"), ("h2", r"\bh2\b"), ("tokio", r"\btokio\b"), ("rustls", r"\brustls\b"),
           ("the AWS-LC C code", r"AWS-LC C code"), ("rustc", r"\brustc\b")]
FAMILIES = {"Select": r"^AegisIR\.Select\.", "Combine": r"^AegisIR\.Combine\.", "Token": r"^AegisIR\.Token\.",
            "Lowering": r"^AegisIR\.(ThreeValued\.)?(lower|rows|eval3|refines)"}
FEDRAMP = re.compile(r"fed\s*ramp[\s\-_]*(ready|authori[sz]ed|certified|compliant)\b", re.I)
WAF = re.compile(r"\bWAF\b|(?i:web[\s\-]+application[\s\-]+firewall)")  # upper-case WAF; the evidence id
# `ops.cra-annex3-waf-risk` (lower case, from the template) stays allowed
EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")


# ----------------------------------------------------------------------------------------------- JSON Schema subset
ANNOTATIONS = {"title", "description", "examples", "default", "$schema", "$id", "$defs", "$comment"}
KNOWN = ANNOTATIONS | {"$ref", "type", "enum", "required", "properties", "items", "minItems", "uniqueItems",
                       "minLength", "minProperties", "maxProperties", "pattern", "format", "oneOf"}
DATETIME = re.compile(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:([0-5]\d|60)(\.\d+)?"
                      r"(Z|[+-]([01]\d|2[0-3]):[0-5]\d)$")
URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:[^\s<>\"{}|\\^`]*$")


def _type_ok(v, t):
    return {"object": isinstance(v, dict), "array": isinstance(v, list), "string": isinstance(v, str),
            "boolean": isinstance(v, bool), "null": v is None,
            "integer": isinstance(v, int) and not isinstance(v, bool),
            "number": isinstance(v, (int, float)) and not isinstance(v, bool)}.get(t, False)


def validate(root_schema, schema, inst, path="$"):
    """Errors of `inst` against `schema` (the keyword subset the CSAF 2.0 schema uses). Unknown keywords and
    non-local $refs are errors (fail closed), never ignored."""
    errs = []
    if not isinstance(schema, dict):
        return [f"{path}: schema node is not an object"]
    for k in schema:
        if k not in KNOWN:
            errs.append(f"{path}: unsupported schema keyword {k!r}")
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            return errs + [f"{path}: non-local $ref {ref} (not vendored)"]
        node = root_schema
        for part in ref[2:].split("/"):
            if not isinstance(node, dict) or part not in node:
                return errs + [f"{path}: unresolvable $ref {ref}"]
            node = node[part]
        errs += validate(root_schema, node, inst, path)
    if "type" in schema:
        ts = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(inst, t) for t in ts):
            return errs + [f"{path}: expected type {'/'.join(ts)}"]
    if "enum" in schema and inst not in schema["enum"]:
        errs.append(f"{path}: {inst!r} not in enum")
    if isinstance(inst, str):
        if "minLength" in schema and len(inst) < schema["minLength"]:
            errs.append(f"{path}: shorter than {schema['minLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], inst):
            errs.append(f"{path}: does not match pattern")
        fmt = schema.get("format")
        if fmt == "date-time" and not DATETIME.match(inst):
            errs.append(f"{path}: not an RFC 3339 date-time")
        elif fmt == "uri" and not URI.match(inst):
            errs.append(f"{path}: not a URI")
        elif fmt not in (None, "date-time", "uri"):
            errs.append(f"{path}: unsupported format {fmt}")
    if isinstance(inst, dict):
        for r in schema.get("required", []):
            if r not in inst:
                errs.append(f"{path}: missing required {r!r}")
        if "minProperties" in schema and len(inst) < schema["minProperties"]:
            errs.append(f"{path}: fewer than {schema['minProperties']} properties")
        if "maxProperties" in schema and len(inst) > schema["maxProperties"]:
            errs.append(f"{path}: more than {schema['maxProperties']} properties")
        for k, sub in schema.get("properties", {}).items():
            if k in inst:
                errs += validate(root_schema, sub, inst[k], f"{path}.{k}")
    if isinstance(inst, list):
        if "minItems" in schema and len(inst) < schema["minItems"]:
            errs.append(f"{path}: fewer than {schema['minItems']} items")
        if schema.get("uniqueItems"):
            seen = [json.dumps(x, sort_keys=True) for x in inst]
            if len(set(seen)) != len(seen):
                errs.append(f"{path}: items not unique")
        if "items" in schema:
            for i, x in enumerate(inst):
                errs += validate(root_schema, schema["items"], x, f"{path}[{i}]")
    if "oneOf" in schema:
        n = sum(1 for sub in schema["oneOf"] if not validate(root_schema, sub, inst, path))
        if n != 1:
            errs.append(f"{path}: matches {n} of oneOf (need exactly 1)")
    return errs


def _walk(x, key):
    if isinstance(x, dict):
        for k, v in x.items():
            if k == key:
                yield v
            yield from _walk(v, key)
    elif isinstance(x, list):
        for v in x:
            yield from _walk(v, key)


def csaf_profile(doc, category):
    """The CSAF 2.0 checks beyond the schema that this gate relies on (spec §4.3/§4.5, mandatory test 6.1.1)."""
    errs = []
    d = doc.get("document", {})
    if d.get("category") != category:
        errs.append(f"document.category {d.get('category')!r} != {category!r}")
    if any(True for _ in _walk(doc, "scores")):
        errs.append("`scores` used: needs the unvendored FIRST CVSS schemas")
    if "product_tree" not in doc or "vulnerabilities" not in doc:
        errs.append("product_tree and vulnerabilities are required for this profile")
    defined = set()
    for p in _walk(doc.get("product_tree", {}), "product"):
        if isinstance(p, dict) and "product_id" in p:
            defined.add(p["product_id"])
    for r in _walk(doc.get("product_tree", {}), "relationships"):
        for rel in r if isinstance(r, list) else []:
            defined.add(rel.get("full_product_name", {}).get("product_id"))
    for i, v in enumerate(doc.get("vulnerabilities", [])):
        ps = v.get("product_status", {})
        refs = [pid for lst in ps.values() for pid in lst]
        for k in ("remediations", "flags", "threats"):
            for e in v.get(k, []):
                refs += e.get("product_ids", [])
        for pid in refs:
            if pid not in defined:
                errs.append(f"vulnerabilities[{i}]: product_id {pid!r} not defined in product_tree")
        if category == "csaf_vex":
            if not any(k in ps for k in ("fixed", "known_affected", "known_not_affected", "under_investigation")):
                errs.append(f"vulnerabilities[{i}]: VEX needs a product_status")
            if not (v.get("cve") or v.get("ids")):
                errs.append(f"vulnerabilities[{i}]: VEX needs cve or ids")
            if not v.get("notes"):
                errs.append(f"vulnerabilities[{i}]: VEX needs notes")
            impact = {p for t in v.get("threats", []) if t.get("category") == "impact" for p in t.get("product_ids", [])}
            flagged = {p for f in v.get("flags", []) for p in f.get("product_ids", [])}
            for pid in ps.get("known_not_affected", []):
                if pid not in impact and pid not in flagged:
                    errs.append(f"vulnerabilities[{i}]: known_not_affected {pid!r} has no flag or impact statement")
            remediated = {p for r in v.get("remediations", []) for p in r.get("product_ids", [])}
            for pid in ps.get("known_affected", []):
                if pid not in remediated:
                    errs.append(f"vulnerabilities[{i}]: known_affected {pid!r} has no remediation")
    return errs


def jsonschema_errors(schema, doc):
    try:
        import jsonschema  # optional second validator
    except Exception:
        return None
    v = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    return [f"{'/'.join(map(str, e.path))}: {e.message}" for e in v.iter_errors(doc)]


# --------------------------------------------------------------------------------------------------------- parsing
def table_after(lines, start):
    """First markdown table at or after line index `start`: (header cells, [(lineno, cells)])."""
    i = start
    while i < len(lines) and not lines[i].startswith("|"):
        i += 1
    if i + 1 >= len(lines):
        return None, []
    split = lambda ln: [c.strip() for c in ln.strip().strip("|").split("|")]
    header = split(lines[i])
    rows = []
    j = i + 2
    while j < len(lines) and lines[j].startswith("|"):
        rows.append((j + 1, split(lines[j])))
        j += 1
    return header, rows


def gate_names(root):
    with open(os.path.join(root, "gates/phase-6.toml"), "rb") as f:
        return {g["name"] for g in tomllib.load(f).get("gate", [])}


def frozen_theorems(root):
    out = set()
    for ln in open(os.path.join(root, "spec/STATEMENTS.sha256"), encoding="utf-8"):
        parts = ln.split()
        if len(parts) == 3 and parts[1] == "theorem" and ":" in parts[2]:
            out.add(parts[2].split(":", 1)[1])
    return out


def text_files(root):
    base = os.path.join(root, "compliance")
    for dp, _, fs in os.walk(base):
        for f in sorted(fs):
            p = os.path.join(dp, f)
            if os.path.relpath(p, root) == CSAF_SCHEMA:
                continue  # third-party, pinned by hash
            yield p


# ----------------------------------------------------------------------------------------------------------- check
def check(root):
    errs, stats = [], {}
    E = lambda tag, msg: errs.append((tag, msg))
    mp = os.path.join(root, "compliance/COMPLIANCE_MAP.md")

    # root files (GitHub/Forgejo live-policy locations; license)
    for d in ("", ".github", "docs"):
        dd = os.path.join(root, d)
        if os.path.isdir(dd):
            for n in os.listdir(dd):
                if n.lower() in ("security.md", "security.rst", "security.txt", "security"):
                    E("root-file", f"{os.path.join(d, n)} exists (D-P1: no live security policy)")
    for n in os.listdir(root):
        if re.match(r"(?i)^(un)?licen[cs]e|^copying", n):
            E("root-file", f"{n} exists at the repo root (operator: no license yet)")

    # gates and statements
    try:
        gates = gate_names(root)
    except Exception as e:
        gates = set()
        E("gate-id", f"gates/phase-6.toml unreadable: {e}")
    try:
        theorems = frozen_theorems(root)
    except Exception as e:
        theorems = set()
        E("sa17-theorem", f"spec/STATEMENTS.sha256 unreadable: {e}")

    # map
    if not os.path.isfile(mp):
        E("map-structure", "compliance/COMPLIANCE_MAP.md missing")
        lines = []
    else:
        lines = open(mp, encoding="utf-8").read().splitlines()
    heads = [(i, ln) for i, ln in enumerate(lines) if re.match(r"^## \d+\. ", ln)]
    nums = [int(re.match(r"^## (\d+)\.", ln).group(1)) for _, ln in heads]
    if lines and nums != list(range(1, 9)):
        E("map-structure", f"sections are {nums}, need 1..8 in order")
    sec = {int(re.match(r"^## (\d+)\.", ln).group(1)): i for i, ln in heads}
    text = "\n".join(lines)
    if 4 in sec:
        header, rows = table_after(lines, sec[4])
        need = ("control", "evidence_kinds", "gate_id")
        if not header or any(c not in header for c in need):
            E("map-structure", f"section 4 table header lacks {need}")
            rows = []
        else:
            ic, ie, ig = (header.index(c) for c in need)
            issdf = header.index("ssdf") if "ssdf" in header else None
            seen, gids = [], set()
            for ln, cells in rows:
                if len(cells) != len(header):
                    E("map-structure", f"COMPLIANCE_MAP.md:{ln}: {len(cells)} cells, header has {len(header)}")
                    continue
                seen.append(cells[ic])
                ids = re.findall(r"`([^`]+)`", cells[ig])
                rest = re.sub(r"`[^`]+`", "", cells[ig]).replace(",", "").strip()
                if not ids or rest:
                    E("gate-id", f"COMPLIANCE_MAP.md:{ln}: {cells[ic]}: gate_id must be backticked gate names, got {cells[ig]!r}")
                for g in ids:
                    gids.add(g)
                    if g not in gates:
                        E("gate-id", f"COMPLIANCE_MAP.md:{ln}: {cells[ic]}: gate_id {g!r} is not a gate in gates/phase-6.toml")
                kinds = [k for k in cells[ie].split(";") if k.strip() and k.strip() != "—"]
                if len(kinds) < 2:
                    E("evidence-kinds", f"COMPLIANCE_MAP.md:{ln}: {cells[ic]}: {len(kinds)} evidence kind(s), need >= 2")
                if issdf is not None:
                    for c in SSDF_DRAFT:
                        if c in cells[issdf] and not re.search(re.escape(c) + r"[^,;|]*\(draft\)", cells[issdf]):
                            E("ssdf-draft", f"COMPLIANCE_MAP.md:{ln}: SSDF 1.2 control {c} not labelled (draft)")
            for c in CONTROLS:
                if c not in seen:
                    E("control-missing", f"section 4 has no {c!r} row")
            stats["rows"], stats["gids"] = len(rows), len(gids)
    # SA-17(1) theorem table
    sa = [i for i, ln in enumerate(lines) if re.match(r"^###? .*SA-17\(1\)", ln)]
    if lines and not sa:
        E("sa17-theorem", "no SA-17(1) theorem section (### ... SA-17(1) ...)")
    elif sa:
        header, rows = table_after(lines, sa[0])
        need = ("theorem", "rung", "does NOT cover")
        if not header or any(c not in header for c in need):
            E("sa17-theorem", f"SA-17(1) table header lacks {need}")
        else:
            it, ir, inc = (header.index(c) for c in need)
            names = []
            for ln, cells in rows:
                if len(cells) != len(header):
                    E("map-structure", f"COMPLIANCE_MAP.md:{ln}: {len(cells)} cells, header has {len(header)}")
                    continue
                m = re.fullmatch(r"`([^`]+)`", cells[it])
                name = m.group(1) if m else cells[it]
                names.append(name)
                if name not in theorems:
                    E("sa17-theorem", f"COMPLIANCE_MAP.md:{ln}: {name!r} is not a frozen theorem in spec/STATEMENTS.sha256")
                if not cells[ir].startswith("R4"):
                    E("sa17-theorem", f"COMPLIANCE_MAP.md:{ln}: {name}: rung {cells[ir]!r} is not R4 (model)")
                if not cells[inc] or cells[inc] == "—":
                    E("sa17-theorem", f"COMPLIANCE_MAP.md:{ln}: {name}: empty 'does NOT cover'")
            for fam, rx in FAMILIES.items():
                if not any(re.match(rx, n) for n in names):
                    E("sa17-theorem", f"SA-17(1) table has no {fam} theorem")
            stats["thm"] = len(names)
    if lines:
        tm = re.search(r"\*\*Trusted, not verified\*\*(.*?)\n\n", text, re.S)
        if not tm:
            E("trusted-list", "no **Trusted, not verified** paragraph")
        else:
            for name, rx in TRUSTED:
                if not re.search(rx, tm.group(1)):
                    E("trusted-list", f"trusted-not-verified list lacks {name}")
        if not re.search(r"ML-DSA[^\n]*not approved in AWS-LC 3\.1\.0", text):
            E("required-claim", "map does not state that ML-DSA is not approved in AWS-LC 3.1.0")
        if not re.search(r"[Ll]aptop performance numbers are provisional", text):
            E("required-claim", "map does not state that laptop performance numbers are provisional")

    # CRA set
    cra = os.path.join(root, "compliance/cra")
    for rel in CRA_REQUIRED:
        if not os.path.isfile(os.path.join(cra, rel)):
            E("cra-missing", f"compliance/cra/{rel} missing")
    sp = os.path.join(root, CSAF_SCHEMA)
    schema = None
    if not os.path.isfile(sp):
        E("schema-pin", f"{CSAF_SCHEMA} missing")
    else:
        raw = open(sp, "rb").read()
        if hashlib.sha256(raw).hexdigest() != CSAF_SCHEMA_SHA256:
            E("schema-pin", f"{CSAF_SCHEMA} sha256 differs from the pin")
        else:
            schema = json.loads(raw)
    ndraft, ncsaf, used_js = 0, 0, False
    for dp, _, fs in os.walk(cra) if os.path.isdir(cra) else []:
        for f in sorted(fs):
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, cra)
            if rel.startswith("schemas" + os.sep):
                continue
            if f.endswith((".md", ".txt")):
                body = open(p, encoding="utf-8").read()
                if body.split("\n", 1)[0].rstrip("\r") != DRAFT:
                    E("draft-header", f"compliance/cra/{rel}: first line is not {DRAFT!r}")
                else:
                    ndraft += 1
                if EMAIL.search(body):
                    E("contact-address", f"compliance/cra/{rel}: contains an e-mail address (D-P1: placeholder only)")
            elif f.endswith(".json"):
                try:
                    doc = json.load(open(p, encoding="utf-8"))
                except Exception as e:
                    E("csaf", f"compliance/cra/{rel}: not JSON: {e}")
                    continue
                d = doc.get("document", {}) if isinstance(doc, dict) else {}
                notes = d.get("notes", []) if isinstance(d.get("notes"), list) else []
                if not any(isinstance(n, dict) and str(n.get("text", "")).startswith(DRAFT) for n in notes) \
                        or d.get("tracking", {}).get("status") != "draft":
                    E("draft-header", f"compliance/cra/{rel}: needs a document.notes entry starting {DRAFT!r} and tracking.status = draft")
                else:
                    ndraft += 1
                if EMAIL.search(json.dumps(doc)):
                    E("contact-address", f"compliance/cra/{rel}: contains an e-mail address")
                if schema is None:
                    E("csaf", f"compliance/cra/{rel}: no pinned schema to validate against")
                    continue
                se = validate(schema, schema, doc)
                for m in se[:5]:
                    E("csaf", f"compliance/cra/{rel}: schema: {m}")
                js = jsonschema_errors(schema, doc)
                if js is not None:
                    used_js = True
                    if js and not se:
                        for m in js[:5]:
                            E("csaf", f"compliance/cra/{rel}: jsonschema: {m}")
                cat = CRA_REQUIRED.get(rel.replace(os.sep, "/")) or d.get("category")
                for m in csaf_profile(doc, cat):
                    E("csaf", f"compliance/cra/{rel}: {m}")
                ncsaf += 1
            else:
                E("draft-header", f"compliance/cra/{rel}: unknown file type (only .md/.txt/.json drafts)")
    spf = os.path.join(cra, "support-period.draft.md")
    if os.path.isfile(spf) and not re.search(r"(?m)^Support period: \S", open(spf, encoding="utf-8").read()):
        E("support-period", "support-period.draft.md has no 'Support period:' line")

    # CycloneDX (any SBOM sample kept under compliance/)
    ncdx = 0
    for p in text_files(root):
        if p.endswith(".cdx.json"):
            ncdx += 1
            try:
                b = json.load(open(p, encoding="utf-8"))
                ok = (b.get("bomFormat") == "CycloneDX" and b.get("specVersion") in ("1.4", "1.5", "1.6")
                      and isinstance(b.get("version"), int) and b["version"] >= 1
                      and all(isinstance(c, dict) and c.get("type") and c.get("name") for c in b.get("components", [])))
            except Exception:
                ok = False
            if not ok:
                E("cyclonedx", f"{os.path.relpath(p, root)}: not structurally CycloneDX 1.4-1.6")

    # wording rules over everything under compliance/
    for p in text_files(root):
        try:
            body = open(p, encoding="utf-8").read()
        except UnicodeDecodeError:
            continue
        rel = os.path.relpath(p, root)
        for n, ln in enumerate(body.splitlines(), 1):
            if FEDRAMP.search(ln):
                E("wording-fedramp", f"{rel}:{n}: {FEDRAMP.search(ln).group(0)!r}")
            if WAF.search(ln) or (re.search(r"(?i)admission", ln) and re.search(r"(?i)fire\s*wall", ln)):
                E("wording-waf", f"{rel}:{n}: admission control must be described as rate limiting")
            if re.search(r"(?i)approved[\s\-]+mode", ln) and not re.search(r"AL2023|Amazon Linux 2023", ln):
                E("wording-fips", f"{rel}:{n}: 'approved mode' without AL2023")

    stats.update(draft=ndraft, csaf=ncsaf, cdx=ncdx, js=used_js)
    return errs, stats


def run_check(root):
    errs, st = check(root)
    for tag, msg in errs:
        print(f"  {tag}: {msg}")
    if errs:
        tags = sorted({t for t, _ in errs})
        print(f"COMPLIANCE: FAIL ({len(errs)} violation(s): {', '.join(tags)})")
        return 1
    print(f"COMPLIANCE: PASS ({st.get('rows', 0)} control rows, {st.get('gids', 0)} gate ids in gates/phase-6.toml, "
          f"{st.get('thm', 0)} SA-17(1) theorems frozen in spec/STATEMENTS.sha256, {st['draft']} CRA drafts unpublished, "
          f"{st['csaf']} CSAF 2.0 documents schema-valid (validator: builtin{'+jsonschema' if st['js'] else ''}), "
          f"{st['cdx']} CycloneDX; no root SECURITY.md, no LICENSE)")
    return 0


# ------------------------------------------------------------------------------------------------------- self-test
def _edit(path, old, new, count=1):
    s = open(path, encoding="utf-8").read()
    if old not in s:
        raise RuntimeError(f"mutant anchor not found in {path}: {old[:60]!r}")
    open(path, "w", encoding="utf-8").write(s.replace(old, new, count))


def _json_edit(path, fn):
    d = json.load(open(path, encoding="utf-8"))
    fn(d)
    open(path, "w", encoding="utf-8").write(json.dumps(d, indent=2))


def _append(path, text):
    open(path, "a", encoding="utf-8").write(text)


MAP, CRA = "compliance/COMPLIANCE_MAP.md", "compliance/cra"
MUTANTS = [
    ("unknown-gate-id", {"gate-id"}, lambda r: _edit(f"{r}/{MAP}", "`fips-binary`, `fips-lock`", "`fips-binary-x`, `fips-lock`")),
    ("gate-id-unquoted", {"gate-id"}, lambda r: _edit(f"{r}/{MAP}", "| `audit-tlog` | needs", "| audit-tlog | needs")),
    ("evidence-kinds-1", {"evidence-kinds"}, lambda r: _edit(f"{r}/{MAP}", "| attestation; TUF metadata; repro hashes |", "| attestation |")),
    ("control-row-removed", {"control-missing"}, lambda r: _edit(f"{r}/{MAP}", "| SA-11 |", "| SA-11X |")),
    ("ssdf-draft-label", {"ssdf-draft"}, lambda r: _edit(f"{r}/{MAP}", "| PO.6.2 (draft) |", "| PO.6.2 |")),
    ("sa17-theorem-not-frozen", {"sa17-theorem"}, lambda r: _edit(f"{r}/{MAP}", "`AegisIR.Select.universal_only_11ED`", "`AegisIR.Select.universal_only_11EE`")),
    ("sa17-def-not-theorem", {"sa17-theorem"}, lambda r: _edit(f"{r}/{MAP}", "`AegisIR.Combine.combine_empty`", "`AegisIR.Combine.combine`")),
    ("sa17-rung-r2", {"sa17-theorem"}, lambda r: _edit(f"{r}/{MAP}", "| capability token | R4 model |", "| capability token | R2 |")),
    ("trusted-list-no-rustc", {"trusted-list"}, lambda r: _edit(f"{r}/{MAP}", "**the Rust compiler\n(rustc/LLVM)**", "**the Rust compiler**")),
    ("no-mldsa-statement", {"required-claim"}, lambda r: _edit(f"{r}/{MAP}", "not approved in AWS-LC 3.1.0", "pending in AWS-LC 3.1.0", count=-1)),
    ("cra-no-draft-header", {"draft-header"}, lambda r: _edit(f"{r}/{CRA}/PSIRT-runbook.md", DRAFT + "\n", "")),
    ("cra-json-final", {"draft-header"}, lambda r: _json_edit(f"{r}/{CRA}/csaf/vex-template.json", lambda d: d["document"]["tracking"].update(status="final"))),
    ("cra-file-missing", {"cra-missing"}, lambda r: os.remove(f"{r}/{CRA}/steward-attestation.draft.md")),
    ("support-period-line", {"support-period"}, lambda r: _edit(f"{r}/{CRA}/support-period.draft.md", "Support period: `", "Period: `")),
    ("contact-email", {"contact-address"}, lambda r: _edit(f"{r}/{CRA}/SECURITY.draft.md", "- Contact: `<operator to supply>`", "- Contact: psirt@example.org")),
    ("root-security-md", {"root-file"}, lambda r: _append(f"{r}/SECURITY.md", "# Security\n")),
    ("github-security-md", {"root-file"}, lambda r: (os.makedirs(f"{r}/.github", exist_ok=True), _append(f"{r}/.github/SECURITY.md", "x\n"))),
    ("root-license", {"root-file"}, lambda r: _append(f"{r}/LICENSE", "MIT\n")),
    ("fedramp-ready", {"wording-fedramp"}, lambda r: _append(f"{r}/{MAP}", "\nAEGIS is FedRAMP-ready.\n")),
    ("waf-admission", {"wording-waf"}, lambda r: _append(f"{r}/{CRA}/SECURITY.draft.md", "\nAdmission control works as a WAF.\n")),
    ("firewall-admission", {"wording-waf"}, lambda r: _append(f"{r}/{MAP}", "\nThe admission layer is a firewall.\n")),
    ("approved-mode-debian", {"wording-fips"}, lambda r: _append(f"{r}/{MAP}", "\nFIPS approved mode also on Debian.\n")),
    ("invalid-csaf-version", {"csaf"}, lambda r: _json_edit(f"{r}/{CRA}/csaf/advisory-template.json", lambda d: d["document"].update(csaf_version="2.1"))),
    ("invalid-csaf-missing-tracking-id", {"csaf"}, lambda r: _json_edit(f"{r}/{CRA}/csaf/advisory-template.json", lambda d: d["document"]["tracking"].pop("id"))),
    ("invalid-csaf-datetime", {"csaf"}, lambda r: _json_edit(f"{r}/{CRA}/csaf/vex-template.json", lambda d: d["document"]["tracking"].update(current_release_date="2026-13-01"))),
    ("invalid-csaf-json-syntax", {"csaf"}, lambda r: _edit(f"{r}/{CRA}/csaf/vex-template.json", "\"csaf_vex\",", "\"csaf_vex\"")),
    ("csaf-dangling-product-id", {"csaf"}, lambda r: _json_edit(f"{r}/{CRA}/csaf/advisory-template.json", lambda d: d["vulnerabilities"][0]["product_status"]["fixed"].append("AEGIS-NOPE"))),
    ("vex-not-affected-unjustified", {"csaf"}, lambda r: _json_edit(f"{r}/{CRA}/csaf/vex-template.json", lambda d: (d["vulnerabilities"][0].pop("flags"), d["vulnerabilities"][0].pop("threats")))),
    ("vex-wrong-category", {"csaf"}, lambda r: _json_edit(f"{r}/{CRA}/csaf/vex-template.json", lambda d: d["document"].update(category="csaf_base"))),
    ("schema-tampered", {"schema-pin", "csaf"}, lambda r: _edit(f"{r}/{CSAF_SCHEMA}", "\"2.0\"", "\"2.1\"")),
    ("bad-cyclonedx", {"cyclonedx"}, lambda r: _append(f"{r}/compliance/sample.cdx.json", '{"bomFormat": "SPDX"}')),
]


def self_test(src):
    import contextlib, io
    tmp = tempfile.mkdtemp(prefix="compliance-selftest-")
    try:
        def fresh():
            r = os.path.join(tmp, "t")
            shutil.rmtree(r, ignore_errors=True)
            os.makedirs(os.path.join(r, "gates"))
            os.makedirs(os.path.join(r, "spec"))
            shutil.copytree(os.path.join(src, "compliance"), os.path.join(r, "compliance"))
            shutil.copy(os.path.join(src, "gates/phase-6.toml"), os.path.join(r, "gates/phase-6.toml"))
            shutil.copy(os.path.join(src, "spec/STATEMENTS.sha256"), os.path.join(r, "spec/STATEMENTS.sha256"))
            return r
        bad = []
        errs, _ = check(fresh())
        if errs:
            bad.append(f"baseline not clean: {sorted({t for t, _ in errs})}")
        caught = 0
        for name, want, mut in MUTANTS:
            r = fresh()
            try:
                mut(r)
            except Exception as e:
                bad.append(f"{name}: mutant not applied ({e})")
                continue
            errs, _ = check(r)
            got = {t for t, _ in errs}
            if got == want:
                caught += 1
                print(f"  ok   {name}: red ({', '.join(sorted(got))})")
            else:
                bad.append(f"{name}: want {sorted(want)}, got {sorted(got) or 'PASS'}")
                print(f"  FAIL {name}: want {sorted(want)}, got {sorted(got) or 'PASS'}")
        if bad:
            print(f"COMPLIANCE SELF-TEST: FAIL ({'; '.join(bad)})")
            return 1
        print(f"COMPLIANCE SELF-TEST: PASS (baseline clean; {caught}/{len(MUTANTS)} mutants red with the exact expected tag)")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv):
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if argv[:1] == ["--self-test"]:
        return self_test(repo)
    if argv[:1] == ["check"]:
        root = repo
        if argv[1:2] == ["--root"] and len(argv) == 3:
            root = os.path.abspath(argv[2])
        elif len(argv) != 1:
            print(__doc__)
            return 2
        return run_check(root)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
