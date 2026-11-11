"""CT-DUDECT: dudect-style constant-time check (Reparaz, Balasch, Verbauwhede 2017) of monban-token's tag compare.

Stdlib only; run as `python3 -I`. The subject (subjects/ct-subject) times one call per measurement and returns the
raw nanosecond durations; every statistic is computed here, so the subject cannot grade itself. See README.md.

Method, per test:
  - two input classes; each measurement's class is drawn from os.urandom (randomized interleaving), and both classes
    are read from the same per-batch buffer, so the memory access pattern does not depend on the class;
  - the first batch is a discarded warm-up;
  - Welch's t-test on: the uncropped data, the data cropped at 100 percentile thresholds
    p_i = 1 - 0.5^(10 (i+1) / 100) (dudect.h), and the second-order (centered-square) test on uncropped data;
  - the test's statistic is max |t| over those (dudect's `max_test`, among tests with > 10000 measurements).
Statistics use exact integer histograms (value -> count per class), so cropping is exact and memory is bounded.
"""

import argparse
import bisect
import os
import shlex
import subprocess
import sys
import time
from array import array
from collections import Counter
from fractions import Fraction
from itertools import compress

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
THRESHOLD = 4.5  # dudect: |t| above this means a leak; never raised
MUTANT_MIN = 10.0  # self-test: the early-exit mutant must exceed this
NPCT = 100
PERCENTILES = [1 - 0.5 ** (10 * (i + 1) / NPCT) for i in range(NPCT)]
BATCH = 100_000
TAG_LEN = 32

# Tests: (name, target, class0, class1). A class is "equal", "first", "last" (tag differs from the correct tag
# only at that byte) or "random" (a fresh random tag per measurement). "verify" uses forged tags only: an accepted
# token legitimately runs more code (shape/depth/denotation), which is not a tag-dependent leak.
TESTS = [
    ("cmp:fixed-vs-random", "cmp", "last", "random"),
    ("cmp:equal-vs-first", "cmp", "equal", "first"),
    ("cmp:equal-vs-last", "cmp", "equal", "last"),
    ("cmp:first-vs-last", "cmp", "first", "last"),
    ("mac:fixed-vs-random", "mac", "last", "random"),
    ("mac:equal-vs-first", "mac", "equal", "first"),
    ("mac:equal-vs-last", "mac", "equal", "last"),
    ("mac:first-vs-last", "mac", "first", "last"),
    ("verify:fixed-vs-random", "verify", "last", "random"),
    ("verify:first-vs-last", "verify", "first", "last"),
]
# Negative control: identical classes on the real subject must stay under THRESHOLD.
CONTROLS = [
    ("control:cmp:first-vs-first", "cmp", "first", "first"),
    ("control:mac:last-vs-last", "mac", "last", "last"),
    ("control:verify:first-vs-first", "verify", "first", "first"),
]
# Self-test: the early-exit mutant must exceed MUTANT_MIN on each of these.
MUTANT_TESTS = [
    ("mutant:cmp:first-vs-last", "cmp", "first", "last"),
    ("mutant:cmp:equal-vs-first", "cmp", "equal", "first"),
    ("mutant:mac:first-vs-last", "mac", "first", "last"),
    ("mutant:verify:first-vs-last", "verify", "first", "last"),
]

BIT = bytes(b & 1 for b in range(256))
INV = bytes(1 - (b & 1) for b in range(256))


class Fail(Exception):
    pass


# ------------------------------------------------------------------------------------------- subject I/O
class Subject:
    def __init__(self, cmd, mutant, cpu):
        argv = shlex.split(cmd) + (["--mutant", "early-exit"] if mutant else [])
        pre = None
        if cpu is not None:
            pre = lambda: os.sched_setaffinity(0, {cpu})  # noqa: E731
        try:
            self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, preexec_fn=pre)
        except OSError as e:
            raise Fail(f"cannot start subject {argv[0]}: {e}")
        hello = self.p.stdout.readline().decode("ascii", "replace").split()
        if len(hello) != 3 or hello[:2] != ["CT-SUBJECT", "1"] or not hello[2].startswith("tag="):
            raise Fail(f"bad subject banner {hello!r}")
        self.tag = bytes.fromhex(hello[2][4:])
        if len(self.tag) != TAG_LEN:
            raise Fail("bad tag length in banner")

    def batch(self, target, payload, n):
        self.p.stdin.write(f"{target} {n}\n".encode() + payload)
        self.p.stdin.flush()
        want = 8 * n
        buf = bytearray()
        while len(buf) < want:
            chunk = self.p.stdout.read(want - len(buf))
            if not chunk:
                raise Fail(f"subject died during a {target} batch (rc={self.p.poll()})")
            buf += chunk
        a = array("Q")
        a.frombytes(bytes(buf))
        if sys.byteorder != "little":
            a.byteswap()
        return a

    def close(self):
        try:
            self.p.stdin.write(b"quit\n")
            self.p.stdin.close()
        except OSError:
            pass
        try:
            self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()


def class_tag(tag, kind):
    if kind == "equal":
        return tag
    if kind == "first":
        return bytes([tag[0] ^ 0x01]) + tag[1:]
    if kind == "last":
        return tag[:-1] + bytes([tag[-1] ^ 0x80])
    return None  # random


def payload_for(bits, c0, c1):
    """Concatenated tags, one per measurement: class 1 where bits[i] == 1, else class 0. None = random."""
    n = len(bits)
    if c0 is not None and c1 is not None:
        return b"".join(map((c0, c1).__getitem__, bits))
    rnd = os.urandom(TAG_LEN * n)
    fixed, rbit = (c0, 1) if c0 is not None else (c1, 0)
    if fixed is None:
        return rnd
    return b"".join(rnd[TAG_LEN * i : TAG_LEN * i + TAG_LEN] if b == rbit else fixed for i, b in enumerate(bits))


def measure(subj, target, k0, k1, total):
    c0, c1 = class_tag(subj.tag, k0), class_tag(subj.tag, k1)
    h = (Counter(), Counter())
    done = -1  # first batch: warm-up, discarded
    while done < total:
        n = BATCH if done < 0 else min(BATCH, total - done)
        bits = os.urandom(n).translate(BIT)
        times = subj.batch(target, payload_for(bits, c0, c1), n)
        if done >= 0:
            h[0].update(compress(times, bits.translate(INV)))
            h[1].update(compress(times, bits))
            done += n
        else:
            done = 0
    return h


# ------------------------------------------------------------------------------------------ statistics
class Prefix:
    """Prefix sums of count, x*count, x^2*count over sorted values of one class histogram (exact integers)."""

    def __init__(self, hist):
        self.keys = sorted(hist)
        self.n, self.s1, self.s2 = [0], [0], [0]
        for x in self.keys:
            c = hist[x]
            self.n.append(self.n[-1] + c)
            self.s1.append(self.s1[-1] + c * x)
            self.s2.append(self.s2[-1] + c * x * x)

    def upto(self, thr):
        i = bisect.bisect_right(self.keys, thr) if thr is not None else len(self.keys)
        return self.n[i], self.s1[i], self.s2[i]


def welch(a, b):
    """Welch t from exact (n, sum, sum of squares) triples."""
    (na, s1a, s2a), (nb, s1b, s2b) = a, b
    if na < 2 or nb < 2:
        return 0.0
    ma, mb = Fraction(s1a, na), Fraction(s1b, nb)
    va = Fraction(na * s2a - s1a * s1a, na * (na - 1))
    vb = Fraction(nb * s2b - s1b * s1b, nb * (nb - 1))
    den = va / na + vb / nb
    if den == 0:
        return 0.0 if ma == mb else float("inf")
    return float(ma - mb) / float(den) ** 0.5


def second_order(hist):
    """(n, sum y, sum y^2) of y = (x - mean)^2 over the uncropped class data, exactly."""
    n = sum(hist.values())
    s = [sum(c * x**k for x, c in hist.items()) for k in range(1, 5)]
    m = Fraction(s[0], n)
    sy = s[1] - 2 * m * s[0] + n * m * m
    syy = s[3] - 4 * m * s[2] + 6 * m * m * s[1] - 4 * m**3 * s[0] + n * m**4
    return n, sy, syy


def welch_frac(a, b):
    (na, sa, qa), (nb, sb, qb) = a, b
    ma, mb = Fraction(sa) / na, Fraction(sb) / nb
    va = (Fraction(qa) - Fraction(sa) ** 2 / na) / (na - 1)
    vb = (Fraction(qb) - Fraction(sb) ** 2 / nb) / (nb - 1)
    den = va / na + vb / nb
    if den == 0:
        return 0.0 if ma == mb else float("inf")
    return float(ma - mb) / float(den) ** 0.5


def analyse(h):
    """max |t| over uncropped, 100 crops and the second-order test; returns (max_t, label, n0, n1, median_ns)."""
    both = h[0] + h[1]
    keys = sorted(both)
    cum, acc = [], 0
    for x in keys:
        acc += both[x]
        cum.append(acc)
    total = acc
    pa, pb = Prefix(h[0]), Prefix(h[1])
    best = (0.0, "none")
    cands = [("uncropped", None)]
    for i, p in enumerate(PERCENTILES):
        j = min(bisect.bisect_left(cum, p * total), len(keys) - 1)
        cands.append((f"crop{i}", keys[j]))
    for label, thr in cands:
        a, b = pa.upto(thr), pb.upto(thr)
        if a[0] + b[0] <= 10_000:
            continue
        t = welch(a, b)
        if abs(t) > abs(best[0]):
            best = (t, label)
    t2 = welch_frac(second_order(h[0]), second_order(h[1]))
    if abs(t2) > abs(best[0]):
        best = (t2, "second-order")
    med = keys[min(bisect.bisect_left(cum, total / 2), len(keys) - 1)]
    return best[0], best[1], pa.n[-1], pb.n[-1], med


def run_tests(cmd, tests, total, mutant, cpu):
    subj = Subject(cmd, mutant, cpu)
    res = []
    try:
        for name, target, k0, k1 in tests:
            t0 = time.time()
            t, label, n0, n1, med = analyse(measure(subj, target, k0, k1, total))
            print(
                f"  {name:32s} max|t|={abs(t):8.3f} ({label}) n={n0}+{n1} median={med}ns [{time.time() - t0:.0f}s]",
                flush=True,
            )
            res.append((name, abs(t), n0 + n1))
    finally:
        subj.close()
    return res


def pick_cpu(arg):
    if arg == "none":
        return None
    if arg != "auto":
        return int(arg)
    try:
        return max(os.sched_getaffinity(0))
    except (AttributeError, OSError, ValueError):
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--subject", help="subject command (default: oracles/ct-dudect/default-subject)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--measurements", type=float, default=None, help="per test (gate default 1e7; self-test 2e6)")
    ap.add_argument("--cpu", default="auto", help="pin the subject to this CPU (auto = highest allowed; none)")
    a = ap.parse_args()
    subject = a.subject
    if not subject:
        with open(os.path.join(HERE, "default-subject")) as f:
            subject = os.path.join(ROOT, f.readline().strip())
    cpu = pick_cpu(a.cpu)
    try:
        if a.self_test:
            total = int(a.measurements or 2e6)
            print(f"ct-dudect self-test: subject {subject}, {total} measurements per test, cpu {cpu}")
            mut = run_tests(subject, MUTANT_TESTS, total, True, cpu)
            ctl = run_tests(subject, CONTROLS, total, False, cpu)
            weak = [n for n, t, _ in mut if t <= MUTANT_MIN]
            loud = [n for n, t, _ in ctl if t >= THRESHOLD]
            mmin = min(t for _, t, _ in mut)
            cmax = max(t for _, t, _ in ctl)
            if weak or loud:
                print(
                    f"CT-DUDECT SELF-TEST: FAIL (mutant not caught: {weak or 'none'}; "
                    f"identical-class control over {THRESHOLD}: {loud or 'none'})"
                )
                return 1
            print(
                f"CT-DUDECT SELF-TEST: PASS (early-exit mutant min |t|={mmin:.1f} > {MUTANT_MIN:g} on "
                f"{len(mut)} tests; identical-class control max |t|={cmax:.2f} < {THRESHOLD}; {total} meas/test)"
            )
            return 0
        total = int(a.measurements or 1e7)
        print(f"ct-dudect: subject {subject}, {total} measurements per test, cpu {cpu}")
        res = run_tests(subject, TESTS, total, False, cpu)
        worst = max(res, key=lambda r: r[1])
        leaks = [n for n, t, _ in res if t >= THRESHOLD]
        if leaks:
            print(f"CT-DUDECT: FAIL (|t| >= {THRESHOLD} on {', '.join(leaks)}; max |t|={worst[1]:.2f} on {worst[0]})")
            return 1
        print(
            f"CT-DUDECT: PASS (max |t|={worst[1]:.2f} on {worst[0]} < {THRESHOLD}; {len(res)} tests x {total} meas)"
        )
        return 0
    except Fail as e:
        print(f"CT-DUDECT{' SELF-TEST' if a.self_test else ''}: FAIL ({e})")
        return 1


if __name__ == "__main__":
    sys.exit(main())
