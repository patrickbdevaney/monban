#!/usr/bin/env python3
"""Frozen-statement ledger for the Lean spec (F1).

A proof PR may change proofs, never what is proved. This hashes, per top-level declaration in the library roots:
  - theorem/lemma: the statement only (text before the first `:=`), so proof edits keep the hash;
  - def/abbrev/inductive/structure/instance/class: the whole declaration, because definitions ARE the meaning.
Whitespace is normalized and comments stripped before hashing.

Usage: python3 -I ci/statements.py freeze <proj>   # spec-author only: writes <proj>/STATEMENTS.sha256
       python3 -I ci/statements.py check  <proj>   # exit 1 on any added/removed/changed entry
"""
import hashlib, os, re, sys, tomllib

KW = r"(?:@\[[^\]]*\]\s*)?(?:private\s+|protected\s+|noncomputable\s+)*(theorem|lemma|def|abbrev|inductive|structure|instance|class)\s+([^\s(:{\[]+)"


def strip_comments(src: str) -> str:
    src = re.sub(r"/-.*?-/", "", src, flags=re.S)
    return re.sub(r"--[^\n]*", "", src)


def decls(proj: str):
    cfg = tomllib.load(open(os.path.join(proj, "lakefile.toml"), "rb"))
    out = {}
    for lib in cfg["lean_lib"]:
        for root in lib["roots"]:
            src = strip_comments(open(os.path.join(proj, *root.split(".")) + ".lean").read())
            ns, cur = [], None
            chunks = []
            for line in src.splitlines():
                m_ns = re.match(r"namespace\s+(\S+)", line)
                m_end = re.match(r"end\s+(\S+)", line)
                m = re.match(KW, line)
                if m_ns or m_end or m:
                    if cur: chunks.append(cur)
                    cur = None
                if m_ns: ns.append(m_ns.group(1)); continue
                if m_end and ns and ns[-1] == m_end.group(1): ns.pop(); continue
                if m:
                    cur = [m.group(1), ".".join(ns + [m.group(2)]), [line]]
                elif cur:
                    cur[2].append(line)
            if cur: chunks.append(cur)
            for kind, name, lines in chunks:
                text = " ".join(" ".join(lines).split())
                if kind in ("theorem", "lemma"):
                    text = text.split(":=", 1)[0].strip()
                out[f"{root}:{name}"] = (kind, hashlib.sha256(text.encode()).hexdigest())
    return out


def main():
    mode, proj = sys.argv[1], os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else ".")
    ledger = os.path.join(proj, "STATEMENTS.sha256")
    cur = decls(proj)
    if mode == "freeze":
        with open(ledger, "w") as f:
            for k in sorted(cur):
                f.write(f"{cur[k][1]}  {cur[k][0]:10s} {k}\n")
        print(f"froze {len(cur)} declarations -> {ledger}")
        return
    old = {}
    for line in open(ledger):
        h, kind, key = line.split()
        old[key] = (kind, h)
    bad = [f"removed: {k}" for k in old if k not in cur]
    bad += [f"added (spec-change PR required): {k}" for k in cur if k not in old]
    bad += [f"changed statement: {k}" for k in cur if k in old and cur[k][1] != old[k][1]]
    if bad:
        print("STATEMENT GATE: FAIL"); [print("  - " + b) for b in bad]; sys.exit(1)
    print(f"STATEMENT GATE: PASS ({len(cur)} frozen declarations unchanged)")


if __name__ == "__main__":
    main()
