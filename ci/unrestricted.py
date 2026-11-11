#!/usr/bin/env python3
"""Unrestricted ledger and default-boot limit check (INV-NONEMPTY, gate unrestricted-ledger).

INV-NONEMPTY (spec/SPEC_INVARIANTS.md): an empty capability set denies; `Unrestricted` is explicit and CI-gated;
default config boot has no effective `None` limit. This script is the "CI-gated" and "default boot" half; the
property half is oracles/nonempty-props.

  python3 -I ci/unrestricted.py check [--monban '<cmd>'] [--allow FILE] [--schema FILE]
  python3 -I ci/unrestricted.py --self-test

check:
  1. In-tree configs: every git-tracked *.json outside research/ spikes/ units/ interfaces/ fuzz/ oracles/
     ci/fixtures/ supply-chain/ target/ whose top level is an object with "v", "listeners" and "vhosts". Each is run
     through `monban check-config <path> --print-effective` (default command: target/release/monban) and judged on
     its EFFECTIVE form (defaults applied), not its source text. A config the binary rejects cannot boot, so it is
     skipped and listed, except under deploy/ apps/ examples/ config/ configs/ or named *monban.json, where a
     rejection fails the check.
  2. The built-in default: ci/fixtures/unrestricted/default-boot.json (only the schema's required members, so the
     effective form is the schema defaults). It must be accepted and must contain no `unrestricted` at all; the
     ledger cannot excuse it.
  Judgement, on every effective form:
   - an `unrestricted` occurrence is a JSON string or object key equal to "unrestricted" after trimming and
     case folding. Each must be listed in ci/unrestricted.allow (<path> <json-pointer> <reason>); every ledger
     entry must match an occurrence (no stale entries) and carry a real reason.
   - no JSON null anywhere (an effective `None`).
   - `limits` is present and has every member that F8 (interfaces/F8-config.schema.json, properties.limits, $ref
     resolved) declares, each an integer within the schema's [minimum, maximum], and nothing else; every declared
     limit has a maximum and a default; every integer property named max_* anywhere in F8 has a maximum.
   - the source text has no more `unrestricted` occurrences than the effective form (the printer must not hide
     one).
Last line: `UNRESTRICTED: PASS (...)` or `UNRESTRICTED: FAIL (...)`; exit 0 only on PASS.
"""
import json
import os
import shlex
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NAME = "UNRESTRICTED"
FIX = "ci/fixtures/unrestricted"
DEFAULT_BOOT = FIX + "/default-boot.json"
EXCLUDE = ("research/", "spikes/", "units/", "interfaces/", "fuzz/", "oracles/", "ci/fixtures/", "supply-chain/",
           "target/")
REQUIRED_DIRS = ("deploy/", "apps/", "examples/", "config/", "configs/")
PLACEHOLDER = ("todo", "tbd", "fixme", "xxx")


def pointer(path):
    return "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in path)


def is_unr(s):
    return isinstance(s, str) and s.strip().casefold() == "unrestricted"


def walk(v, path, occ, nulls):
    if v is None:
        nulls.append(pointer(path))
    elif isinstance(v, dict):
        for k, x in v.items():
            if is_unr(k):
                occ.append(pointer(path + [k]))
            walk(x, path + [k], occ, nulls)
    elif isinstance(v, list):
        for i, x in enumerate(v):
            walk(x, path + [i], occ, nulls)
    elif is_unr(v):
        occ.append(pointer(path))


def resolve(schema, node):
    seen = 0
    while isinstance(node, dict) and "$ref" in node and seen < 16:
        ref = node["$ref"]
        if not ref.startswith("#/"):
            return None
        node = schema
        for part in ref[2:].split("/"):
            node = node.get(part.replace("~1", "/").replace("~0", "~")) if isinstance(node, dict) else None
        seen += 1
    return node


def schema_limits(schema, errs):
    """-> {name: (min, max)} for F8's top-level limits; records schema defects in errs."""
    lim = resolve(schema, (schema.get("properties") or {}).get("limits"))
    if not isinstance(lim, dict) or not isinstance(lim.get("properties"), dict) or not lim["properties"]:
        errs.append("schema: no properties.limits object; cannot check for absent limits")
        return {}
    if lim.get("additionalProperties") is not False:
        errs.append("schema: limits allows additional properties (an unbounded limit could appear)")
    out = {}
    for k, p in sorted(lim["properties"].items()):
        p = resolve(schema, p) or {}
        if p.get("type") != "integer" or "maximum" not in p or "default" not in p:
            errs.append("schema: limit %s lacks integer type, maximum or default (an effective None limit)" % k)
        out[k] = (p.get("minimum", 0), p.get("maximum"))

    def scan(node, path):
        if isinstance(node, dict):
            for k, x in (node.get("properties") or {}).items():
                if isinstance(k, str) and k.startswith("max_") and isinstance(x, dict) and \
                        x.get("type") == "integer" and "maximum" not in x:
                    errs.append("schema: integer %s at %s has no maximum" % (k, path))
            for k, x in node.items():
                scan(x, path + "/" + str(k))
        elif isinstance(node, list):
            for i, x in enumerate(node):
                scan(x, "%s/%d" % (path, i))
    scan(schema, "#")
    return out


def parse_allow(text, errs):
    """-> {(path, pointer): reason}"""
    out = {}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            errs.append("ledger line %d: needs <path> <json-pointer> <reason>: %r" % (n, raw))
            continue
        path, ptr, reason = parts
        if not ptr.startswith("/"):
            errs.append("ledger line %d: %r is not a JSON pointer" % (n, ptr))
            continue
        if len(reason) < 20 or any(w in reason.casefold() for w in PLACEHOLDER):
            errs.append("ledger line %d: reason %r is not a justification" % (n, reason))
            continue
        if (path, ptr) in out:
            errs.append("ledger line %d: duplicate entry %s %s" % (n, path, ptr))
            continue
        out[(path, ptr)] = reason
    return out


def judge(entries, allow_text, schema):
    """entries: [{"path", "effective", "source" (or None), "default": bool}] -> (errors, notes)."""
    errs, notes = [], []
    lims = schema_limits(schema, errs)
    allow = parse_allow(allow_text, errs)
    used = set()
    for e in entries:
        p, eff = e["path"], e["effective"]
        occ, nulls = [], []
        walk(eff, [], occ, nulls)
        for ptr in nulls:
            errs.append("%s: null at %s in the effective form (an effective None)" % (p, ptr))
        if e["default"]:
            for ptr in occ:
                errs.append("%s: built-in default carries unrestricted at %s (absent data must mean no capability)"
                            % (p, ptr))
            for (ap, aptr) in allow:
                if ap == p:
                    errs.append("ledger: the built-in default %s cannot be listed (%s)" % (p, aptr))
                    used.add((ap, aptr))
        else:
            for ptr in occ:
                if (p, ptr) in allow:
                    used.add((p, ptr))
                    notes.append("%s %s listed: %s" % (p, ptr, allow[(p, ptr)]))
                else:
                    errs.append("%s: unrestricted at %s not listed in ci/unrestricted.allow" % (p, ptr))
        if e.get("source") is not None:
            socc, _ = [], []
            walk(e["source"], [], socc, [])
            if len(socc) > len(occ):
                errs.append("%s: source has %d unrestricted, effective form shows %d (printer hides one)"
                            % (p, len(socc), len(occ)))
        l = eff.get("limits") if isinstance(eff, dict) else None
        if not isinstance(l, dict):
            errs.append("%s: effective form has no limits object (every limit absent)" % p)
            continue
        for k, (lo, hi) in lims.items():
            if k not in l:
                errs.append("%s: absent limit %s in the effective form" % (p, k))
                continue
            v = l[k]
            if v is None:
                continue  # already reported as null
            if not isinstance(v, int) or isinstance(v, bool):
                errs.append("%s: limit %s = %r is not an integer" % (p, k, v))
            elif (hi is not None and v > hi) or (lo is not None and v < lo):
                errs.append("%s: limit %s = %d outside the schema bounds [%s, %s]" % (p, k, v, lo, hi))
        for k in sorted(set(l) - set(lims)):
            errs.append("%s: limit %s is not declared (bounded) in the schema" % (p, k))
    for key in sorted(set(allow) - used):
        errs.append("ledger: stale entry %s %s (no such unrestricted in that effective form)" % key)
    return errs, notes


# ----------------------------------------------------------------------------------------------- check

def discover(root):
    p = subprocess.run(["git", "-C", root, "ls-files", "-z", "--", "*.json"], capture_output=True)
    if p.returncode != 0:
        raise RuntimeError("git ls-files failed: %s" % p.stderr.decode(errors="replace").strip())
    out = []
    for rel in sorted(x for x in p.stdout.decode().split("\0") if x):
        if rel.startswith(EXCLUDE):
            continue
        try:
            with open(os.path.join(root, rel), "rb") as f:
                doc = json.loads(f.read())
        except (OSError, ValueError):
            continue
        if isinstance(doc, dict) and {"v", "listeners", "vhosts"} <= set(doc):
            req = rel.startswith(REQUIRED_DIRS) or os.path.basename(rel).endswith("monban.json")
            out.append((rel, req))
    return out


def effective(monban, root, rel):
    """-> (doc or None, error text)"""
    argv = monban + ["check-config", os.path.join(root, rel), "--print-effective"]
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, "cannot run %s: %s" % (argv[0], e)
    if p.returncode != 0:
        return None, "rejected (exit %d): %s" % (p.returncode, p.stderr.strip()[-300:])
    lines = [l for l in p.stdout.splitlines() if l.strip()]
    try:
        return json.loads(lines[-1]), ""
    except (IndexError, ValueError):
        return None, "no effective JSON on stdout"


def pipeline(root, configs, monban, allow_text, schema, default_rel):
    """configs: [(rel, required)] -> (errors, notes)"""
    errs, notes, entries = [], [], []
    for rel, req, dflt in [(default_rel, True, True)] + [(r, q, False) for r, q in configs]:
        doc, why = effective(monban, root, rel)
        if doc is None:
            if req:
                errs.append("%s: %s" % (rel, why))
            else:
                notes.append("%s skipped: cannot boot (%s)" % (rel, why.splitlines()[0] if why else ""))
            continue
        try:
            with open(os.path.join(root, rel), "rb") as f:
                src = json.loads(f.read())
        except (OSError, ValueError):
            src = None
        entries.append({"path": rel, "effective": doc, "source": src, "default": dflt})
    e2, n2 = judge(entries, allow_text, schema)
    return errs + e2, notes + n2, len(entries)


def read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def cmd_check(args):
    monban = shlex.split(args.get("--monban") or os.environ.get("AEGIS_BIN") or
                        shlex.quote(os.path.join(ROOT, "target", "release", "monban")))
    allow_path = args.get("--allow") or os.path.join(ROOT, "ci", "unrestricted.allow")
    schema_path = args.get("--schema") or os.path.join(ROOT, "interfaces", "F8-config.schema.json")
    try:
        schema = json.loads(read(schema_path))
        allow_text = read(allow_path)
        configs = discover(ROOT)
    except (OSError, ValueError, RuntimeError) as e:
        print("%s: FAIL (%s)" % (NAME, e))
        return 1
    errs, notes, n = pipeline(ROOT, configs, monban, allow_text, schema, DEFAULT_BOOT)
    for x in notes:
        print("  note: " + x)
    for x in errs:
        print("  " + x)
    if errs:
        print("%s: FAIL (%d problems over %d effective forms)" % (NAME, len(errs), n))
        return 1
    listed = sum(1 for x in notes if " listed: " in x)
    print("%s: PASS (%d effective forms incl. built-in default; %d in-tree configs; %d listed unrestricted; "
          "default has no unrestricted, no null, all %d limits bounded)" % (
              NAME, n, len(configs), listed, len(schema_limits(schema, []))))
    return 0


# ----------------------------------------------------------------------------------------------- self-test

def self_test():
    fx = lambda name: os.path.join(ROOT, FIX, name)
    schema = json.loads(read(fx("schema.json")))
    ld = lambda name: json.loads(read(fx(name)))
    listed = read(fx("listed.allow"))
    lp = FIX + "/src-listed.json"
    dflt = {"path": DEFAULT_BOOT, "effective": ld("effective-default.json"), "source": None, "default": True}

    def cfg(name, path=lp, src=None):
        return {"path": path, "effective": ld(name), "source": src, "default": False}

    bad_schema = json.loads(json.dumps(schema))
    del bad_schema["$defs"]["limits"]["properties"]["idle_timeout_ms"]["maximum"]
    over = ld("effective-route-unrestricted.json")
    over["limits"]["max_concurrent_streams"] = 1001
    extra = ld("effective-default.json")
    extra["limits"]["max_new_thing"] = 5
    cases = [
        # (label, entries, allow text, schema, must pass?, substring every failure must contain)
        ("clean default + listed unrestricted", [dflt, cfg("effective-route-unrestricted.json")], listed, schema,
         True, None),
        ("unlisted unrestricted", [dflt, cfg("effective-route-unrestricted.json")], "", schema, False, "not listed"),
        ("null limit", [dflt, cfg("effective-null-limit.json", FIX + "/n.json")], "", schema, False, "null at"),
        ("null limit in default", [dict(dflt, effective=ld("effective-null-limit.json"))], "", schema, False,
         "null at"),
        ("absent limit", [dflt, cfg("effective-absent-limit.json", FIX + "/a.json")], "", schema, False,
         "absent limit"),
        ("default implicit unrestricted (absent data -> unrestricted)",
         [dict(dflt, effective=ld("effective-default-implicit-unrestricted.json"))], "", schema, False,
         "built-in default"),
        ("default listed in ledger", [dict(dflt, effective=ld("effective-default-implicit-unrestricted.json"))],
         "%s /vhosts/0/routes/0/data an attempt to excuse the built-in default\n" % DEFAULT_BOOT, schema, False,
         "default"),
        ("stale ledger entry", [dflt], listed, schema, False, "stale"),
        ("ledger entry without a reason", [dflt, cfg("effective-route-unrestricted.json")],
         "%s /vhosts/0/routes/0/data TODO\n" % lp, schema, False, None),
        ("printer hides a source unrestricted",
         [dflt, cfg("effective-default.json", FIX + "/h.json", ld("effective-route-unrestricted.json"))], "",
         schema, False, "hides"),
        ("limit above schema maximum", [dflt, cfg("effective-route-unrestricted.json")], listed, schema, False,
         None),
        ("undeclared limit", [dict(dflt, effective=extra)], "", schema, False, "not declared"),
        ("schema limit without maximum", [dflt], "", bad_schema, False, "schema:"),
    ]
    cases[10] = (cases[10][0], [dflt, dict(cfg("effective-route-unrestricted.json"), effective=over)], listed,
                 schema, False, "outside the schema bounds")
    ok = True
    red = 0
    for label, entries, allow, sch, want_pass, sub in cases:
        errs, _ = judge(entries, allow, sch)
        good = (not errs) if want_pass else (bool(errs) and (sub is None or any(sub in e for e in errs)))
        if not want_pass and good:
            red += 1
        ok &= good
        print("  %-60s %s%s" % (label, "ok" if good else "WRONG", (" (red: %s)" % errs[0]) if errs and good else
                                ("" if good else " errs=%s" % errs)))
    # end to end through the check-config plumbing, with a stand-in binary
    fake = [sys.executable, "-I", "-B", fx("fake-monban.py")]
    dboot = FIX + "/effective-default.json"
    e2e = [
        ("e2e: listed config passes", [(lp, True)], listed, True, None),
        ("e2e: same config unlisted fails", [(lp, True)], "", False, "not listed"),
        ("e2e: printer hiding a source unrestricted fails", [(FIX + "/src-hidden.json", True)], "", False, "hides"),
        ("e2e: required config the binary rejects fails", [(FIX + "/src-reject.json", True)], "", False, "rejected"),
    ]
    for label, configs, allow, want_pass, sub in e2e:
        errs, _, _ = pipeline(ROOT, configs, fake, allow, schema, dboot)
        good = (not errs) if want_pass else (bool(errs) and any(sub in e for e in errs))
        if not want_pass and good:
            red += 1
        ok &= good
        print("  %-60s %s%s" % (label, "ok" if good else "WRONG", (" (red: %s)" % errs[0]) if errs and good else
                                ("" if good else " errs=%s" % errs)))
    # the real schema must itself pass the schema rules (the gate would otherwise be red for a schema defect)
    serr = []
    n = len(schema_limits(json.loads(read(os.path.join(ROOT, "interfaces", "F8-config.schema.json"))), serr))
    print("  %-60s %s" % ("F8 schema: %d limits, each bounded with a default" % n, "ok" if not serr else serr))
    ok &= not serr and n > 0
    total = len(cases) + len(e2e)
    if ok:
        print("%s SELF-TEST: PASS (%d/%d fixtures judged as expected; %d negative fixtures red, incl. unlisted "
              "unrestricted, null limit, absent limit, implicit unrestricted in the default)" % (
                  NAME, total, total, red))
        return 0
    print("%s SELF-TEST: FAIL (see above)" % NAME)
    return 1


def main(argv):
    if argv == ["--self-test"]:
        return self_test()
    if argv and argv[0] == "check" and len(argv) % 2 == 1:
        opts = dict(zip(argv[1::2], argv[2::2]))
        if set(opts) <= {"--monban", "--allow", "--schema"}:
            return cmd_check(opts)
    sys.stderr.write("usage: python3 -I ci/unrestricted.py check [--monban '<cmd>'] [--allow FILE] [--schema FILE]\n"
                     "       python3 -I ci/unrestricted.py --self-test\n")
    print("%s: FAIL (usage)" % NAME)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
