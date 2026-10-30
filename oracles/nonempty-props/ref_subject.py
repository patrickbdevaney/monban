"""Reference subject for the NONEMPTY-PROPS authorize protocol (README.md "Subject protocol").

    python3 -I -B oracles/nonempty-props/ref_subject.py [--mutate <mutation>]

Reads one JSON request per line on stdin and writes exactly one JSON reply per line on stdout. Implements the F4
CapSet semantics stated in README.md: absent, null, empty or unparsable capsets deny; the exact string
"unrestricted" is the only way to grant everything; a list capset allows an op only if ONE cap covers it (same
adapter, same collection, op kind in ops, every touched column in columns). Authorization runs before render, so a
deny never reaches render.

This file is the default subject. The checker in nonempty_props.py does not import its decision logic: it judges
replies against labels fixed at generation time. MUTATIONS are deliberate bugs used by the self-test.
"""
import json
import sys

ADAPTERS = ("sqlite", "pg", "redis", "oop")
KINDS = ("select", "insert", "update", "delete", "upsert")
CAP_KEYS = frozenset(("adapter", "collection", "ops", "columns"))

MUTATIONS = (
    "empty-means-all",           # capset [] grants everything
    "missing-capset-means-all",  # capset null or absent grants everything (error -> empty principal -> all)
    "unrestricted-implicit",     # absent capset (no data block) is read as "unrestricted"
    "deny-everything",           # never allows (non-vacuity must go red)
    "render-on-deny",            # renders before authorizing
    "empty-columns-means-all",   # a cap with columns [] covers every column
    "absent-field-means-all",    # a cap missing ops / columns grants all ops / columns
    "wildcard",                  # "*" matches any adapter, collection, op, column, or the whole capset
    "cap-union",                 # ops and columns unioned across caps of one (adapter, collection)
    "name-prefix-match",         # collection matched by prefix
    "case-insensitive",          # adapter, collection and "unrestricted" compared case-insensitively
    "lenient-parse",             # malformed cap elements skipped, the rest honoured
)


class Malformed(Exception):
    pass


def _is_uint(x):
    return isinstance(x, int) and not isinstance(x, bool) and 0 <= x <= 0xFFFFFFFF


def _parse_cap(c, mut):
    """One cap object -> (adapter, collection, frozenset ops | None=all, frozenset cols | None=all)."""
    if not isinstance(c, dict):
        raise Malformed("cap not an object")
    if mut == "absent-field-means-all":
        if set(c) - CAP_KEYS or not {"adapter", "collection"} <= set(c):
            raise Malformed("cap keys")
    elif set(c) != CAP_KEYS:
        raise Malformed("cap keys")
    ad, co = c["adapter"], c["collection"]
    if not isinstance(ad, str) or not isinstance(co, str):
        raise Malformed("adapter/collection type")
    wild = mut == "wildcard"
    if "ops" not in c:
        ops = None
    else:
        o = c["ops"]
        if not isinstance(o, list):
            raise Malformed("ops type")
        if wild and "*" in o:
            ops = None
        else:
            if any((not isinstance(k, str)) or k not in KINDS for k in o):
                raise Malformed("unknown op kind")
            ops = frozenset(o)
    if "columns" not in c:
        cols = None
    else:
        v = c["columns"]
        if not isinstance(v, list):
            raise Malformed("columns type")
        if wild and "*" in v:
            cols = None
        else:
            if not all(_is_uint(x) for x in v):
                raise Malformed("column not a uint")
            cols = frozenset(v)
            if not cols and mut == "empty-columns-means-all":
                cols = None
    return (ad, co, ops, cols)


def parse_capset(msg, mut):
    """-> ("deny",) | ("all",) | ("caps", [cap...])"""
    if "capset" not in msg:
        if mut in ("missing-capset-means-all", "unrestricted-implicit"):
            return ("all",)
        return ("deny",)
    v = msg["capset"]
    if v is None:
        return ("all",) if mut == "missing-capset-means-all" else ("deny",)
    if isinstance(v, str):
        if v == "unrestricted":
            return ("all",)
        if mut == "case-insensitive" and v.lower() == "unrestricted":
            return ("all",)
        if mut == "wildcard" and v == "*":
            return ("all",)
        return ("deny",)
    if not isinstance(v, list):
        return ("deny",)
    if not v:
        return ("all",) if mut == "empty-means-all" else ("deny",)
    caps = []
    for c in v:
        try:
            caps.append(_parse_cap(c, mut))
        except Malformed:
            if mut == "lenient-parse":
                continue
            return ("deny",)
    if not caps:
        return ("deny",)
    if mut == "cap-union":
        merged = {}
        for ad, co, ops, cols in caps:
            o0, c0 = merged.get((ad, co), (frozenset(), frozenset()))
            merged[(ad, co)] = (None if ops is None or o0 is None else o0 | ops,
                                None if cols is None or c0 is None else c0 | cols)
        caps = [(ad, co, o, c) for (ad, co), (o, c) in merged.items()]
    return ("caps", caps)


def pred_reads(p, out):
    tag = p[0]
    if tag in (2, 3, 4, 5):
        out.add(p[1])
    elif tag in (6, 7):
        pred_reads(p[1], out)
        pred_reads(p[2], out)
    elif tag == 8:
        pred_reads(p[1], out)


def touched(op):
    s = set()
    pred_reads(op["filter"], s)
    s.update(f for f, _ in op["writes"])
    s.update(op["returning"])
    return s


def _name_eq(a, b, mut):
    if a == b:
        return True
    if mut == "wildcard" and a == "*":
        return True
    if mut == "case-insensitive" and a.lower() == b.lower():
        return True
    return False


def covers(cap, adapter, op, mut):
    ad, co, ops, cols = cap
    if not _name_eq(ad, adapter, mut):
        return False
    if not _name_eq(co, op["collection"], mut):
        if not (mut == "name-prefix-match" and (op["collection"].startswith(co) or co.startswith(op["collection"]))):
            return False
    if ops is not None and op["kind"] not in ops:
        return False
    if cols is not None and not touched(op) <= cols:
        return False
    return True


def authorize(msg, mut):
    if mut == "deny-everything":
        return False
    cs = parse_capset(msg, mut)
    if cs[0] == "all":
        return True
    if cs[0] == "deny":
        return False
    return any(covers(c, msg["adapter"], msg["data_op"], mut) for c in cs[1])


def render(msg):
    """Stand-in for the adapter renderer: proves the pipeline reached render (no engine text is checked here)."""
    op = msg["data_op"]
    return "%s:%s:%s:%s" % (msg["adapter"], op["kind"], op["collection"], op["tenant"])


def decide(msg, mut=None):
    """One request -> one reply (the pipeline order is authorize -> render)."""
    rendered = False
    if mut == "render-on-deny":
        render(msg)
        rendered = True
    ok = authorize(msg, mut)
    if ok and not rendered:
        render(msg)
        rendered = True
    return {"case": msg["case"], "decision": "allow" if ok else "deny", "rendered": rendered}


def main():
    mut = None
    if len(sys.argv) == 3 and sys.argv[1] == "--mutate":
        mut = sys.argv[2]
        if mut not in MUTATIONS:
            sys.stderr.write("ref_subject: unknown mutation %r\n" % mut)
            return 2
    elif len(sys.argv) != 1:
        sys.stderr.write("usage: ref_subject.py [--mutate <mutation>]\n")
        return 2
    w = sys.stdout.write
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        if msg.get("op") != "authorize":
            sys.stderr.write("ref_subject: unknown request %r\n" % msg.get("op"))
            return 2
        w(json.dumps(decide(msg, mut), separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
