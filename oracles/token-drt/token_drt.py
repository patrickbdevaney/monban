"""TOKEN-DRT: differential test of the Rust Tier-L verifier (aegis-token) against the Lean Token model.

Stdlib only; run as `python3 -I`. See README.md for the case format, the pass criterion and known limits.
"""

import argparse
import os
import random
import shlex
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
LEAN_SRC = os.path.join(HERE, "lean", "TokenDrt.lean")
BUILD = os.path.join(HERE, ".lake", "build")
LEAN_BIN = os.path.join(BUILD, "token-drt-lean")
SPEC = os.path.join(ROOT, "spec", "AegisIR", "Token.lean")
TOOLCHAIN = os.environ.get(
    "AEGIS_LEAN_TOOLCHAIN", os.path.expanduser("~/.elan/toolchains/leanprover--lean4---v4.35.0")
)
MUTANTS = ["leaf-only", "plain-prefix", "missing-arg-allow", "depth-unchecked"]

NOW = 1_800_000_000
AUDS = ["api", "apik", "a", "api.example", "é-svc"]
KIDS = [b"k1", b"k2", b"1", b"k"]  # "api" + "k1" == "apik" + "1": the unprefixed HKDF info collides on purpose
SEGS = ["t1", "t10", "t", "docs", "x", "é"]
TOOLS = ["search", "fetch", "s"]
ARGK = ["q", "n", "k"]
STRV = ["", "he", "hello", "hel", "x", "é", "éa"]
INTV = [-5, 0, 1, 5, 10, 70000, 2**63 - 1, -(2**63)]
HOLDERS = [bytes(32), bytes([1] * 32)]


def fail(msg):
    print(f"TOKEN-DRT: FAIL ({msg})")
    sys.exit(1)


# ----------------------------------------------------------------------------------------------- encoding
def es(s):
    return "s" + s.encode("utf-8").hex()


def eb(b):
    return "x" + b.hex()


def ev(v):
    return f"I {v}" if isinstance(v, int) else f"S {es(v)}"


def epred(p):
    k = p[0]
    if k == "q":
        return f"q {ev(p[1])}"
    if k == "o":
        return f"o {len(p[1])} " + " ".join(ev(v) for v in p[1])
    if k == "r":
        return f"r {p[1]} {p[2]}"
    return f"p {es(p[1])}"


def ecav(c):
    k = c[0]
    if k in "ENODT":
        return f"{k} {c[1]}"
    if k == "A":
        return f"A {es(c[1])}"
    if k == "R":
        return f"R {len(c[1])} " + " ".join(es(s) for s in c[1])
    if k == "C":
        return f"C {eb(c[1])}"
    # tool
    parts = [f"L {es(c[1])} {len(c[2])}"]
    for key, p in c[2]:
        parts.append(f"{es(key)} {epred(p)}")
    return " ".join(parts)


def elist(cs):
    return " ".join([str(len(cs))] + [ecav(c) for c in cs])


# ----------------------------------------------------------------------------------------------- generator
class Gen:
    def __init__(self, seed):
        self.r = random.Random(seed)

    def req(self):
        r = self.r
        nargs = r.randint(0, 3)
        keys = r.sample(ARGK, nargs)
        args = [(k, r.choice(INTV) if r.random() < 0.5 else r.choice(STRV)) for k in keys]
        if r.random() < 0.05 and args:  # duplicate key: first one wins (List.lookup)
            args.append((args[0][0], r.choice(INTV)))
        return {
            "aud": r.choice(AUDS),
            "ops": r.randint(0, 31) if r.random() < 0.95 else r.randint(0, 63),
            "res": [r.choice(SEGS) for _ in range(r.randint(0, 4))],
            "tenant": r.randint(1, 3),
            "holder": b"" if r.random() < 0.3 else r.choice(HOLDERS),
            "tool": "" if r.random() < 0.15 else r.choice(TOOLS),
            "args": args,
            "now": NOW + r.randint(-3, 3),
        }

    def val(self):
        return self.r.choice(INTV) if self.r.random() < 0.5 else self.r.choice(STRV)

    def pred_for(self, v, want):
        r = self.r
        if want:
            choices = ["q", "o"] + (["r"] if isinstance(v, int) else ["p"])
            k = r.choice(choices)
            if k == "q":
                return ("q", v)
            if k == "o":
                vs = [v] + [self.val() for _ in range(r.randint(0, 3))]
                r.shuffle(vs)
                return ("o", vs)
            if k == "r":
                lo = max(v - r.randint(0, 10), -(2**63))
                hi = min(v + r.randint(0, 10), 2**63 - 1)
                return ("r", lo, hi)
            return ("p", v[: r.randint(0, len(v))])
        k = r.choice(["q", "o", "r", "p"])
        if k == "q":
            return ("q", self.val())
        if k == "o":
            return ("o", [self.val() for _ in range(r.randint(1, 4))])
        if k == "r":
            a, b = r.choice(INTV), r.choice(INTV)
            return ("r", min(a, b), max(a, b)) if r.random() < 0.8 else ("r", max(a, b), min(a, b))
        return ("p", r.choice(STRV))

    def cav(self, q, want, kind=None):
        r = self.r
        kind = kind or r.choice("AENORCTLAENORCTLD")
        if kind == "A":
            return ("A", q["aud"] if want else r.choice(AUDS))
        if kind == "E":
            return ("E", q["now"] + r.randint(1, 5) if want else q["now"] - r.randint(0, 2))
        if kind == "N":
            return ("N", q["now"] - r.randint(0, 3) if want else q["now"] + r.randint(1, 3))
        if kind == "O":
            if want and q["ops"] <= 31:
                return ("O", q["ops"] | r.randint(0, 31))
            return ("O", r.randint(0, 31))
        if kind == "R":
            res = q["res"]
            if want and res:
                return ("R", res[: r.randint(1, len(res))])
            if res and r.random() < 0.5:
                # Plain-string-prefix trap: same leading segments, last one a strict string prefix or extension.
                n = r.randint(1, len(res))
                p = list(res[:n])
                last = p[-1]
                if len(last) > 1 and r.random() < 0.5:
                    p[-1] = last[: r.randint(1, len(last) - 1)]
                else:
                    p[-1] = last + r.choice(["0", "1", "x"])
                return ("R", p)
            return ("R", [r.choice(SEGS) for _ in range(r.randint(1, 3))])
        if kind == "C":
            if want and len(q["holder"]) == 32:
                return ("C", q["holder"])
            return ("C", r.choice(HOLDERS))
        if kind == "T":
            return ("T", q["tenant"] if want else r.randint(1, 3))
        if kind == "L":
            if want and q["tool"]:
                name = q["tool"]
                seen = {}
                for k, v in q["args"]:
                    seen.setdefault(k, v)
                keys = r.sample(sorted(seen), r.randint(0, len(seen)))
                cons = [(k, self.pred_for(seen[k], True)) for k in keys]
                return ("L", name, cons)
            name = q["tool"] if q["tool"] and r.random() < 0.6 else r.choice(TOOLS)
            cons = []
            for _ in range(r.randint(0, 3)):
                present = [k for k, _ in q["args"]]
                if present and r.random() < 0.5:
                    k = r.choice(present)
                    v = next(v for kk, v in q["args"] if kk == k)
                    cons.append((k, self.pred_for(v, r.random() < 0.6)))
                else:  # D4 trap: constraint on an argument the request does not carry (or a random one)
                    k = r.choice(ARGK)
                    cons.append((k, self.pred_for(self.val(), r.random() < 0.5)))
            return ("L", name, cons)
        return ("D", r.choice([0, 1, 2, 3, 5, 16, 16, 16]))

    def caveats(self, q, n, p_sat):
        return [self.cav(q, self.r.random() < p_sat) for _ in range(n)]

    def case(self, cid):
        r = self.r
        q = self.req()
        m_master = r.randint(0, 3)
        m_aud = q["aud"] if r.random() < 0.85 else r.choice(AUDS)
        m_kid = r.choice(KIDS)
        m_nonce = bytes(r.randrange(256) for _ in range(16))
        d = r.choice([0, 1, 1, 2, 2, 3, 4, 6, 16])
        if r.random() < 0.9:
            n_extra = r.randint(0, min(d, 3))
            exp = q["now"] + r.randint(1, 900) if r.random() < 0.9 else q["now"] - r.randint(0, 2)
            mint = [("A", m_aud), ("E", exp), ("D", d)] + self.caveats(q, n_extra, 0.9)
        else:  # ill-shaped prefix (the issuer path refuses it; a key holder could still chain it)
            mint = [("A", m_aud), ("E", q["now"] + 5), ("D", d)] + self.caveats(q, r.randint(0, 2), 0.9)
            r.shuffle(mint)
            if r.random() < 0.5:
                mint = mint[1:] + [self.cav(q, True)]
        budget = max(0, 3 + d - len(mint))
        n_att = r.choice([0, 1, budget, budget, r.randint(0, budget), budget + 1, budget + 2, r.randint(0, 6)])
        n_att = min(n_att, 20)
        att = self.caveats(q, n_att, 0.85)
        tamper = self.tamper(q, len(mint) + len(att))
        keys = [(m_kid, m_master)]
        x = r.random()
        if x < 0.05:
            keys = [(r.choice([k for k in KIDS if k != m_kid]), m_master)]
        elif x < 0.10:
            keys = [(m_kid, (m_master + 1) % 4)]
        elif x < 0.20:
            keys = [(r.choice([k for k in KIDS if k != m_kid]), r.randint(0, 3)), (m_kid, m_master)]
        req = " ".join(
            [
                es(q["aud"]),
                str(q["ops"]),
                str(len(q["res"])),
                *[es(s) for s in q["res"]],
                str(q["tenant"]),
                eb(q["holder"]),
                es(q["tool"]),
                str(len(q["args"])),
                *[f"{es(k)} {ev(v)}" for k, v in q["args"]],
                str(q["now"]),
            ]
        )
        line = " ".join(
            [
                str(cid),
                str(m_master),
                es(m_aud),
                eb(m_kid),
                eb(m_nonce),
                elist(mint),
                elist(att),
                tamper,
                str(len(keys)),
                *[f"{eb(k)} {m}" for k, m in keys],
                req,
            ]
        )
        return line

    def tamper(self, q, n):
        r = self.r
        x = r.random()
        if x < 0.55 or n < 2:
            return "none"
        k = r.choice(["droplast", "drop", "repl", "swap", "ins", "app", "tag", "kid", "nonce"])
        if k == "droplast":
            return k
        if k == "drop":
            return f"drop {r.randrange(n)}"
        if k == "repl":
            return f"repl {r.randrange(n)} {ecav(self.cav(q, r.random() < 0.9))}"
        if k == "swap":
            return f"swap {r.randrange(n)} {r.randrange(n)}"
        if k == "ins":
            return f"ins {r.randint(0, n)} {ecav(self.cav(q, r.random() < 0.9))}"
        if k == "app":
            return f"app {ecav(self.cav(q, r.random() < 0.9))}"
        if k == "tag":
            return k
        if k == "kid":
            return f"kid {eb(r.choice(KIDS))}"
        return f"nonce {eb(bytes(r.randrange(256) for _ in range(16)))}"


# ----------------------------------------------------------------------------------------------- plumbing
def copy_check():
    """Every non-extension line of the COPY section must occur verbatim in spec/AegisIR/Token.lean."""
    spec_lines = set(open(SPEC, encoding="utf-8").read().splitlines())
    src = open(LEAN_SRC, encoding="utf-8").read().splitlines()
    try:
        a = src.index("-- BEGIN COPY (spec/AegisIR/Token.lean)")
        b = src.index("-- END COPY")
    except ValueError:
        return ["COPY markers missing"]
    bad = []
    for ln in src[a + 1 : b]:
        if not ln.strip() or "EXTENSION X" in ln:
            continue
        if ln not in spec_lines:
            bad.append(ln)
    return bad


def build_lean():
    if os.path.exists(LEAN_BIN) and os.path.getmtime(LEAN_BIN) >= os.path.getmtime(LEAN_SRC):
        return
    lean = os.path.join(TOOLCHAIN, "bin", "lean")
    leanc = os.path.join(TOOLCHAIN, "bin", "leanc")
    if not os.path.exists(lean):
        fail(f"Lean toolchain not found at {TOOLCHAIN} (set AEGIS_LEAN_TOOLCHAIN); this oracle needs: lean")
    os.makedirs(BUILD, exist_ok=True)
    c = os.path.join(BUILD, "TokenDrt.c")
    heavy = os.path.join(ROOT, "ci", "heavy.sh")
    for cmd in ([lean, "-c", c, LEAN_SRC], [leanc, "-O2", "-o", LEAN_BIN, c]):
        p = subprocess.run([heavy] + cmd, capture_output=True, text=True)
        if p.returncode != 0:
            fail(f"lean build failed: {' '.join(cmd)}: {p.stdout[-2000:]}{p.stderr[-2000:]}")


def generate(path, n, seed):
    g = Gen(seed)
    with open(path, "w", encoding="ascii") as f:
        for i in range(n):
            f.write(g.case(i))
            f.write("\n")


def run_both(cases, subject, mutant=None):
    out_l = cases + ".lean"
    out_r = cases + ".rust"
    cmd = shlex.split(subject) + (["--mutant", mutant] if mutant else [])
    t0 = time.time()
    with open(out_l, "w") as fl, open(cases, "rb") as fin, open(out_r, "w") as fr:
        pl = subprocess.Popen([LEAN_BIN, cases], stdout=fl)
        try:
            pr = subprocess.Popen(cmd, stdin=fin, stdout=fr)
        except OSError as e:
            pl.kill()
            fail(f"cannot start subject {cmd!r}: {e}")
        rl, rr = pl.wait(), pr.wait()
    dt = time.time() - t0
    if rl != 0:
        fail(f"lean evaluator exited {rl}")
    if rr != 0:
        fail(f"subject exited {rr}")
    return out_l, out_r, dt


def compare(cases, out_l, out_r, show=5):
    div = 0
    n = 0
    stats = {"verify": 0, "denote": 0, "depth_bad": 0, "shape_bad": 0}
    shown = []
    with open(cases) as fc, open(out_l) as fl, open(out_r) as fr:
        for c, a, b in zip(fc, fl, fr, strict=False):
            n += 1
            a, b = a.strip(), b.strip()
            if "PARSE_ERROR" in a or "PARSE_ERROR" in b or a.split(" ")[0] != c.split(" ")[0]:
                div += 1
                if len(shown) < show:
                    shown.append((c.strip(), a, b))
                continue
            va = a.split(" ")[-1]
            if va != b.split(" ")[-1]:
                div += 1
                if len(shown) < show:
                    shown.append((c.strip(), a, b))
                continue
            if len(va) == 4:
                stats["verify"] += va[0] == "1"
                stats["denote"] += va[1] == "1"
                stats["depth_bad"] += va[2] == "0"
                stats["shape_bad"] += va[3] == "0"
        extra = sum(1 for _ in fc) + sum(1 for _ in fl) + sum(1 for _ in fr)
    return n, div + extra, stats, shown


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--subject", default=None)
    ap.add_argument("--cases", type=int, default=int(os.environ.get("TOKEN_DRT_CASES", "1000000")))
    ap.add_argument("--seed", type=int, default=20261026)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()

    subject = a.subject
    if subject is None:
        ds = os.path.join(HERE, "default-subject")
        subject = os.path.join(ROOT, open(ds).read().split("\n")[0].strip())
    first = shlex.split(subject)[0] if subject else ""
    if not os.path.exists(first):
        fail(f"subject binary {first!r} not found (build: cargo build --release -p token-subject)")

    bad = copy_check()
    if bad:
        fail(f"Lean copy drifted from spec/AegisIR/Token.lean: {bad[:3]}")
    build_lean()

    work = os.path.join(HERE, ".lake", "work")
    os.makedirs(work, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=work) as td:
        cases = os.path.join(td, "cases.txt")
        if a.self_test:
            n = min(a.cases, 50_000)
            generate(cases, n, a.seed + 1)
            # The real subject must agree on the same cases (otherwise "caught" means nothing).
            ol, orr, _ = run_both(cases, subject)
            _, d0, _, shown = compare(cases, ol, orr)
            if d0:
                print(f"real subject diverges on self-test cases ({d0}); first: {shown[:1]}")
                print("TOKEN-DRT SELF-TEST: FAIL (baseline diverges)")
                sys.exit(1)
            caught = []
            missed = []
            for m in MUTANTS:
                ol, orr, _ = run_both(cases, subject, m)
                _, dm, _, _ = compare(cases, ol, orr)
                print(f"mutant {m}: {dm} divergences / {n}")
                (caught if dm > 0 else missed).append(m)
            if missed:
                print(f"TOKEN-DRT SELF-TEST: FAIL (mutants not caught: {missed})")
                sys.exit(1)
            print(f"TOKEN-DRT SELF-TEST: PASS ({len(caught)}/{len(MUTANTS)} mutants caught; baseline 0 divergences)")
            return
        t0 = time.time()
        generate(cases, a.cases, a.seed)
        tg = time.time() - t0
        ol, orr, dt = run_both(cases, subject)
        n, div, stats, shown = compare(cases, ol, orr)
    print(f"cases {n} (seed {a.seed}); generate {tg:.1f}s, evaluate {dt:.1f}s")
    print(
        f"verify=1: {stats['verify']}  denote=1: {stats['denote']}  depthOk=0: {stats['depth_bad']}  "
        f"shapeOk=0: {stats['shape_bad']}"
    )
    for c, l, r in shown:
        print(f"DIVERGENCE\n  case: {c}\n  lean: {l}\n  rust: {r}")
    if n != a.cases:
        fail(f"only {n} of {a.cases} cases compared")
    if div:
        fail(f"{div} divergences in {n} cases")
    print(f"TOKEN-DRT: PASS ({n} cases, 0 divergences)")


if __name__ == "__main__":
    main()
