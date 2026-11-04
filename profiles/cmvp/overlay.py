"""Apply profiles/cmvp/overlay.toml to a scratch copy of the root Cargo.toml (PLAN-6 D1).

    python3 -I profiles/cmvp/overlay.py <overlay.toml> <root Cargo.toml> <out Cargo.toml>

Fails closed: every [workspace.dependencies] key of the overlay must occur exactly once in the root's
[workspace.dependencies] section (the whole line is replaced), the root must not already have a [patch.crates-io]
section, and the overlay may only contain those two sections.
"""

import re
import sys

ALLOWED = ("workspace.dependencies", "patch.crates-io")


def sections(text):
    cur, out = None, {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.fullmatch(r"\[([^\]]+)\]", s)
        if m:
            cur = m.group(1).strip()
            if cur not in ALLOWED:
                sys.exit(f"overlay: section [{cur}] not allowed")
            out.setdefault(cur, [])
            continue
        if cur is None:
            sys.exit(f"overlay: line outside a section: {s}")
        k = s.split("=", 1)[0].strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]+", k) or "=" not in s:
            sys.exit(f"overlay: not a key line: {s}")
        out[cur].append((k, s))
    return out


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    ov = sections(open(sys.argv[1], encoding="utf-8").read())
    lines = open(sys.argv[2], encoding="utf-8").read().split("\n")
    if any(line.strip() == "[patch.crates-io]" for line in lines):
        sys.exit("overlay: root Cargo.toml already has [patch.crates-io]")
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == "[workspace.dependencies]")
    except StopIteration:
        sys.exit("overlay: root has no [workspace.dependencies]")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].strip().startswith("[")), len(lines))
    for k, new in ov.get("workspace.dependencies", []):
        hits = [i for i in range(start + 1, end) if re.match(rf"{re.escape(k)}\s*=", lines[i])]
        if len(hits) != 1:
            sys.exit(f"overlay: root [workspace.dependencies] has {len(hits)} lines for {k} (need exactly 1)")
        print(f"overlay: {k}: {lines[hits[0]].split('#')[0].strip()}  ->  {new}", file=sys.stderr)
        lines[hits[0]] = new + "   # profiles/cmvp/overlay.toml"
    patch = ov.get("patch.crates-io", [])
    if patch:
        lines += ["", "# profiles/cmvp/overlay.toml", "[patch.crates-io]"] + [s for _, s in patch]
        for k, s in patch:
            print(f"overlay: patch {s}", file=sys.stderr)
    open(sys.argv[3], "w", encoding="utf-8").write("\n".join(lines) + ("\n" if lines[-1] else ""))


main()
