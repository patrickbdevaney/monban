#!/usr/bin/env python3
"""Generate tables.rs and vectors.txt for aegis-adapter-pg SASLprep (RFC 4013 as PostgreSQL applies it).

  python3 -I crates/aegis-adapter-pg/src/saslprep/gen_tables.py        # writes tables.rs, vectors.txt next to it

Sources (Python stdlib only, recorded in the output): `unicodedata` (NFKD decompositions, canonical combining
classes, primary composites via NFC, general category Cn) at `unicodedata.unidata_version`, and `stringprep`
(RFC 3454 tables A.1, B.1, C.1.2, C.2.1, C.2.2, C.3-C.9, D.1, D.2; Unicode 3.2). The generator refuses to run on any
other Unicode version than PINNED, so a re-run reproduces the committed files byte for byte.

vectors.txt is the independent reference: each line is `input-hex verdict output-hex`, computed here with Python's
own NFKC (`unicodedata.normalize`) and the stringprep predicates, following PostgreSQL's pg_saslprep
(src/common/saslprep.c): ASCII fast path; map (C.1.2 -> U+0020, B.1 -> nothing); empty -> prohibited; NFKC; prohibit
(C.1.2, C.2.1, C.2.2, C.3-C.9, A.1); bidi (RandALCat => no LCat, first and last RandALCat). Verdicts: `ascii`,
`ok` (output = prepared), `prohibited` (libpq then uses the raw password), `ambiguous` (refused by the client: a code
point unassigned in PINNED, or a verdict that differs between checking before and after NFKC).
"""
import hashlib, os, random, stringprep, sys, unicodedata as ud

PINNED = "15.0.0"
HERE = os.path.dirname(os.path.abspath(__file__))
MAXCP = 0x110000


def cps():
    return (c for c in range(MAXCP) if not 0xD800 <= c <= 0xDFFF)


def ranges(pred):
    out, start = [], None
    for c in range(MAXCP + 1):
        ok = c < MAXCP and not (0xD800 <= c <= 0xDFFF) and pred(c)
        if ok and start is None:
            start = c
        elif not ok and start is not None:
            out.append((start, c - 1))
            start = None
    return out


def prohibited(c):
    ch = chr(c)
    return any(f(ch) for f in (stringprep.in_table_c12, stringprep.in_table_c21, stringprep.in_table_c22,
                               stringprep.in_table_c3, stringprep.in_table_c4, stringprep.in_table_c5,
                               stringprep.in_table_c6, stringprep.in_table_c7, stringprep.in_table_c8,
                               stringprep.in_table_c9))


def unassigned_now(c):
    return ud.category(chr(c)) == "Cn"


def check(chars):
    """'ok' or 'prohibited' for a code point list (steps 3 and 4)."""
    for c in chars:
        if prohibited(c) or stringprep.in_table_a1(chr(c)):
            return "prohibited"
    if any(stringprep.in_table_d1(chr(c)) for c in chars):
        if any(stringprep.in_table_d2(chr(c)) for c in chars):
            return "prohibited"
        if not (stringprep.in_table_d1(chr(chars[0])) and stringprep.in_table_d1(chr(chars[-1]))):
            return "prohibited"
    return "ok"


def reference(s):
    if all(ord(ch) < 0x80 for ch in s):
        return "ascii", s
    mapped = []
    for ch in s:
        if stringprep.in_table_c12(ch):
            mapped.append(0x20)
        elif stringprep.in_table_b1(ch):
            continue
        else:
            mapped.append(ord(ch))
    if any(unassigned_now(c) for c in mapped):
        return "ambiguous", ""
    if not mapped:
        return "prohibited", ""
    out = [ord(x) for x in ud.normalize("NFKC", "".join(map(chr, mapped)))]
    before, after = check(mapped), check(out)
    if before != after:
        return "ambiguous", ""
    return after, "".join(map(chr, out)) if after == "ok" else ""


def rs_ranges(name, rs, doc):
    lines = [f"/// {doc} ({len(rs)} ranges)", f"pub(super) static {name}: &[(u32, u32)] = &["]
    row = []
    for a, b in rs:
        row.append(f"(0x{a:X}, 0x{b:X})")
        if len(row) == 8:
            lines.append("    " + ", ".join(row) + ",")
            row = []
    if row:
        lines.append("    " + ", ".join(row) + ",")
    lines.append("];")
    return "\n".join(lines)


def main():
    if ud.unidata_version != PINNED:
        sys.exit(f"gen_tables.py: Python's unicodedata is {ud.unidata_version}, tables are pinned to {PINNED}")
    # Decompositions (full NFKD, already canonically ordered inside each entry); Hangul syllables are algorithmic.
    keys, data, idx = [], [], 0
    for c in cps():
        if 0xAC00 <= c <= 0xD7A3:
            continue
        d = ud.normalize("NFKD", chr(c))
        if d != chr(c):
            n = len(d)
            assert n < 256 and idx < (1 << 24)
            keys.append((c, (idx << 8) | n))
            data.append(d)
            idx += n
    blob = "".join(data)
    ccc = []
    for c in cps():
        k = ud.combining(chr(c))
        if k:
            if ccc and ccc[-1][1] == c - 1 and ccc[-1][2] == k:
                ccc[-1] = (ccc[-1][0], c, k)
            else:
                ccc.append((c, c, k))
    comp = []
    for c in cps():
        dec = ud.decomposition(chr(c))
        if not dec or dec.startswith("<"):
            continue
        parts = [int(x, 16) for x in dec.split()]
        if len(parts) == 2 and ud.normalize("NFC", chr(parts[0]) + chr(parts[1])) == chr(c):
            comp.append((parts[0], parts[1], c))
    comp.sort()
    # Exhaustive single code point check value: sha256 over u32be(c) || NFKC(c) as UTF-8 for every scalar value.
    h = hashlib.sha256()
    for c in cps():
        h.update(c.to_bytes(4, "big") + ud.normalize("NFKC", chr(c)).encode("utf-8"))
    out = [
        "// @generated by gen_tables.py (Python " + sys.version.split()[0] + ", unicodedata " + ud.unidata_version
        + ", stringprep = RFC 3454 / Unicode 3.2). Do not edit; re-run the generator.",
        "#![allow(clippy::unreadable_literal)]",
        "",
        f'/// Unicode version of the normalization tables.\npub(super) const UNICODE_VERSION: &str = "{ud.unidata_version}";',
        f'/// sha256 over u32be(c) || UTF-8(NFKC(c)) for every Unicode scalar value c, per Python unicodedata.\n'
        f'#[cfg(test)]\npub(super) const NFKC_SINGLE_SHA256: &str = "{h.hexdigest()}";',
        "",
        f"/// Full compatibility decompositions: (code point, offset << 8 | length) into [`DECOMP_DATA`] ({len(keys)}).",
        "pub(super) static DECOMP: &[(u32, u32)] = &[",
    ]
    for i in range(0, len(keys), 6):
        out.append("    " + ", ".join(f"(0x{c:X}, 0x{v:X})" for c, v in keys[i:i + 6]) + ",")
    out.append("];")
    out.append(f"/// Concatenated decompositions ({len(blob)} code points), indexed by [`DECOMP`] in code points.")
    out.append("pub(super) static DECOMP_DATA: &[u32] = &[")
    cl = [ord(x) for x in blob]
    for i in range(0, len(cl), 12):
        out.append("    " + ", ".join(f"0x{c:X}" for c in cl[i:i + 12]) + ",")
    out.append("];")
    out.append(f"/// Canonical combining class ranges (first, last, class) ({len(ccc)}).")
    out.append("pub(super) static CCC: &[(u32, u32, u8)] = &[")
    for i in range(0, len(ccc), 6):
        out.append("    " + ", ".join(f"(0x{a:X}, 0x{b:X}, {k})" for a, b, k in ccc[i:i + 6]) + ",")
    out.append("];")
    out.append(f"/// Primary composites (first, second, composite), sorted ({len(comp)}).")
    out.append("pub(super) static COMPOSE: &[(u32, u32, u32)] = &[")
    for i in range(0, len(comp), 5):
        out.append("    " + ", ".join(f"(0x{a:X}, 0x{b:X}, 0x{c:X})" for a, b, c in comp[i:i + 5]) + ",")
    out.append("];")
    out.append(rs_ranges("UNASSIGNED_NOW", ranges(unassigned_now), f"General category Cn in Unicode {ud.unidata_version}"))
    out.append(rs_ranges("B1", ranges(lambda c: stringprep.in_table_b1(chr(c))), "RFC 3454 B.1 (mapped to nothing)"))
    out.append(rs_ranges("C12", ranges(lambda c: stringprep.in_table_c12(chr(c))), "RFC 3454 C.1.2 (non-ASCII space)"))
    out.append(rs_ranges("PROHIBITED", ranges(prohibited), "RFC 3454 C.1.2, C.2.1, C.2.2, C.3-C.9 (RFC 4013 §2.3)"))
    out.append(rs_ranges("A1", ranges(lambda c: stringprep.in_table_a1(chr(c))), "RFC 3454 A.1 (unassigned in Unicode 3.2)"))
    out.append(rs_ranges("D1", ranges(lambda c: stringprep.in_table_d1(chr(c))), "RFC 3454 D.1 (RandALCat)"))
    out.append(rs_ranges("D2", ranges(lambda c: stringprep.in_table_d2(chr(c))), "RFC 3454 D.2 (LCat)"))
    with open(os.path.join(HERE, "tables.rs"), "w") as f:
        f.write("\n".join(out) + "\n")

    # Reference vectors: RFC 4013 §3 examples, every table's edges, and seeded random strings.
    rng = random.Random(4013)
    pool = [0x41, 0x61, 0x31, 0x20, 0x7, 0xAD, 0xA0, 0x3000, 0xAA, 0x2168, 0x627, 0x5D0, 0x5D1, 0x31, 0xFB50, 0xFEFF,
            0x200B, 0x301, 0x300, 0x323, 0x302, 0x308, 0x1100, 0x1161, 0x11A8, 0xAC00, 0xD4DB, 0xE9, 0xC5, 0x212B,
            0x1E9B, 0xFB01, 0x2460, 0x33A1, 0xFF21, 0x1D400, 0xF900, 0x2F800, 0x10FFFD, 0xE000, 0xE0001, 0x340, 0x344,
            0x958, 0x2ADC, 0x1F600, 0x30F4, 0x3099, 0x309A, 0x30AB, 0x0F73, 0x0F75, 0x0F81, 0x1D15E, 0x05B0, 0x0591,
            0x200E, 0x202A, 0x2FF0, 0xFFFD, 0x1F, 0x7F, 0x85, 0x0340, 0x0374, 0x1FEE, 0x0385, 0x3192, 0xFDFA, 0x1E0A,
            0x0DDA, 0x0DD9, 0x0DCA, 0x0B47, 0x0B3E, 0x0B56, 0x09C7, 0x09BE, 0x09D7, 0x1025, 0x102E, 0x0CC6, 0x0CC2,
            0x0CD5, 0x11131, 0x11127, 0x0627, 0x0653, 0x1100, 0x1176, 0x1E0E, 0x0307, 0x0F71, 0x0F72, 0x0F74]
    assigned = [c for c in range(0x80, 0x30000) if not 0xD800 <= c <= 0xDFFF and not unassigned_now(c)]
    pool += rng.sample(assigned, 300) + rng.sample([c for c in range(0x80, 0x30000) if unassigned_now(c)], 10)
    cases = ["I­X", "user", "USER", "ª", "Ⅸ", "\u0007", "ا1", "اب", "­",
             " ", "á", "각", "Å", "ệ"]
    for _ in range(3000):
        n = rng.randint(1, 8)
        cases.append("".join(chr(rng.choice(pool)) for _ in range(n)))
    seen, lines = set(), []
    for s in cases:
        if s in seen:
            continue
        seen.add(s)
        verdict, prepared = reference(s)
        lines.append(f"{s.encode().hex()} {verdict} {prepared.encode().hex() or '-'}")
    with open(os.path.join(HERE, "vectors.txt"), "w") as f:
        f.write(f"# @generated by gen_tables.py (unicodedata {ud.unidata_version}); input-hex verdict output-hex\n")
        f.write("\n".join(lines) + "\n")
    print(f"tables.rs: {len(keys)} decompositions ({len(blob)} cps), {len(ccc)} ccc ranges, {len(comp)} composites; "
          f"vectors.txt: {len(lines)} cases")


if __name__ == "__main__":
    main()
