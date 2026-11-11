#!/usr/bin/env python3
"""fips-indicator: AWS-LC FIPS 3.1.0 service-indicator verdicts from the cmvp tls-subject (PREFLIGHT D-P8.2).

  oracle.py --subject 'target/cmvp/release/tls-subject indicator' [--seed N] [--module S] [--timeout S]
  oracle.py --self-test

The oracle writes a request plan to the subject's stdin and judges the answer lines (protocol: README.md
"Subject protocol"). The plan is drawn from --seed (default: fresh from os.urandom, printed): op order is shuffled,
every op is repeated, and the HKDF salts, IKMs, infos and lengths and the invalid ECDH peer point are random, so a
subject cannot answer from a recorded transcript.

Required (any miss is FAIL):
  M  `module` reports exactly --module (default `AWS-LC FIPS 3.1.0`, CMVP #5314): the indicator read is the
     certified module's.
  A1 every `ecdh-p384` (KAS-ECC-SSC P-384): indicator=approved ok=1 match=1
  A2 every `mlkem1024` (FIPS 203 ML-KEM-1024): encap=approved decap=approved match=1 (keygen reported, not judged)
  A3 every approved-parameter `hkdf` (SP 800-56C KDA HKDF): indicator=approved, okm equal to the oracle's own
     RFC 5869 HKDF (hmac stdlib), so the call really ran
  C1 every `x25519` (not an approved KAS curve, the control the acceptance names): indicator=not-approved ok=1 match=1
  C2 every `ecdh-p384-peer <random off-curve point>`: indicator=not-approved ok=0 (the service failed, nothing ran)
  C3 every `hkdf` with an empty salt or an empty info: indicator=not-approved and the okm still correct (AWS-LC 3.1.0
     `HKDF_verify_service_indicator`: `salt != NULL && salt_len == 0` or `info_len == 0` is not approved)
  C4 every `none` (empty closure between the two indicator reads): indicator=not-approved
  H  `handshake P-UNIVERSAL` (one in-memory TLS 1.3 handshake, client and server on 0x11ED only): group=0x11ed
     version=0x0304 suite in {0x1301,0x1302,0x1303} and an indicator verdict. The verdict is REPORTED, not required:
     the TLS 1.3 key schedule has no CAVP row (PREFLIGHT D-P8.1).
  K  `kx-0x11ed` (the Monban SecP384r1MLKEM1024 group alone): match=1 and three verdicts, REPORTED.
  P  exactly one answer line per request, same id and op, in order; no `error`; exit status 0.
The approved and not-approved expectations of A3/C3 are AWS-LC 3.1.0's own rule (service_indicator.c), not a table
the subject can choose. Last line `FIPS-INDICATOR: PASS (...)` or `FIPS-INDICATOR: FAIL (...)`; exit 0 only on PASS.
"""
import hashlib
import hmac
import os
import random
import shlex
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
NAME = "FIPS-INDICATOR"
MODULE = "AWS-LC FIPS 3.1.0"
VERDICTS = ("approved", "not-approved")
HASHES = ("sha256", "sha384", "sha512")
TLS13_SUITES = {"0x1301", "0x1302", "0x1303"}
HANDSHAKE_PROFILE = "P-UNIVERSAL"


def hkdf(hash_name, salt, ikm, info, length):
    """RFC 5869 HKDF (extract then expand); an empty salt is HashLen zero bytes, which HMAC pads identically."""
    h = getattr(hashlib, hash_name)
    prk = hmac.new(salt, ikm, h).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), h).digest()
        out += t
        i += 1
    return out[:length]


def hkdf_rule_approved(salt, info):
    """AWS-LC FIPS 3.1.0 HKDF_verify_service_indicator, as aws-lc-rs 1.15.3 calls HKDF() (salt pointer never NULL)."""
    return len(salt) > 0 and len(info) > 0


def plan(seed):
    """[(op, args, expectation)] for one run; `module` first, the rest shuffled."""
    rng = random.Random(seed)
    rb = lambda lo, hi: bytes(rng.randrange(256) for _ in range(rng.randint(lo, hi)))
    steps = []
    for _ in range(2):
        steps.append(("ecdh-p384", [], {}))
        steps.append(("x25519", [], {}))
        steps.append(("mlkem1024", [], {}))
        h = rng.choice(HASHES)
        salt, ikm, info, n = rb(16, 48), rb(16, 64), rb(1, 32), rng.randint(16, 80)
        steps.append(("hkdf", [h, salt.hex(), ikm.hex(), info.hex(), str(n)],
                      {"okm": hkdf(h, salt, ikm, info, n).hex(), "indicator": "approved", "kind": "A3"}))
    # Controls: empty info, empty salt (same primitive, parameters AWS-LC does not approve).
    h = rng.choice(HASHES)
    salt, ikm, n = rb(16, 48), rb(16, 64), rng.randint(16, 80)
    steps.append(("hkdf", [h, salt.hex(), ikm.hex(), "-", str(n)],
                  {"okm": hkdf(h, salt, ikm, b"", n).hex(), "indicator": "not-approved", "kind": "C3"}))
    h = rng.choice(HASHES)
    ikm, info, n = rb(16, 64), rb(1, 32), rng.randint(16, 80)
    steps.append(("hkdf", [h, "-", ikm.hex(), info.hex(), str(n)],
                  {"okm": hkdf(h, b"", ikm, info, n).hex(), "indicator": "not-approved", "kind": "C3"}))
    # An uncompressed P-384 point with random coordinates: off the curve with probability 1 - 2^-383.
    steps.append(("ecdh-p384-peer", [(b"\x04" + rb(96, 96)).hex()], {}))
    steps.append(("none", [], {}))
    steps.append(("kx-0x11ed", [], {}))
    steps.append(("handshake", [HANDSHAKE_PROFILE], {}))
    rng.shuffle(steps)
    return [("module", [], {})] + steps


def kv(tokens):
    out = {}
    for t in tokens:
        if "=" not in t:
            return None
        k, v = t.split("=", 1)
        out[k] = v
    return out


def judge_step(op, args, exp, fields, want_module):
    """(error or None, record dict) for one answered step."""
    def need(cond, msg):
        return None if cond else msg

    if op == "module":
        return need(fields.get("module") == want_module, f"module={fields.get('module')!r}, want {want_module!r}"), \
            {"module": fields.get("module")}
    if op in ("ecdh-p384", "x25519"):
        want = "approved" if op == "ecdh-p384" else "not-approved"
        e = (need(fields.get("indicator") == want, f"indicator={fields.get('indicator')}, want {want}")
             or need(fields.get("ok") == "1", f"ok={fields.get('ok')}, want 1")
             or need(fields.get("match") == "1", f"match={fields.get('match')}, want 1"))
        return e, {"indicator": fields.get("indicator")}
    if op == "ecdh-p384-peer":
        e = (need(fields.get("indicator") == "not-approved", f"indicator={fields.get('indicator')}, want not-approved")
             or need(fields.get("ok") == "0", f"ok={fields.get('ok')}, want 0 (off-curve peer accepted)"))
        return e, {"indicator": fields.get("indicator")}
    if op == "mlkem1024":
        e = (need(fields.get("keygen") in VERDICTS, f"keygen={fields.get('keygen')} not a verdict")
             or need(fields.get("encap") == "approved", f"encap={fields.get('encap')}, want approved")
             or need(fields.get("decap") == "approved", f"decap={fields.get('decap')}, want approved")
             or need(fields.get("match") == "1", f"match={fields.get('match')}, want 1"))
        return e, {k: fields.get(k) for k in ("keygen", "encap", "decap")}
    if op == "hkdf":
        e = (need(fields.get("okm") == exp["okm"], "okm differs from RFC 5869 HKDF")
             or need(fields.get("indicator") == exp["indicator"],
                     f"indicator={fields.get('indicator')}, want {exp['indicator']} ({exp['kind']}: salt "
                     f"{'empty' if args[1] == '-' else 'set'}, info {'empty' if args[3] == '-' else 'set'})"))
        return e, {"indicator": fields.get("indicator"), "kind": exp["kind"]}
    if op == "none":
        return need(fields.get("indicator") == "not-approved", f"indicator={fields.get('indicator')}, want "
                    "not-approved"), {"indicator": fields.get("indicator")}
    if op == "kx-0x11ed":
        e = need(fields.get("match") == "1", f"match={fields.get('match')}, want 1")
        for k in ("client_start", "server", "client_complete"):
            e = e or need(fields.get(k) in VERDICTS, f"{k}={fields.get(k)} not a verdict")
        return e, {k: fields.get(k) for k in ("client_start", "server", "client_complete")}
    if op == "handshake":
        e = (need(fields.get("group") == "0x11ed", f"group={fields.get('group')}, want 0x11ed")
             or need(fields.get("version") == "0x0304", f"version={fields.get('version')}, want 0x0304")
             or need(fields.get("suite") in TLS13_SUITES, f"suite={fields.get('suite')} not TLS 1.3")
             or need(fields.get("indicator") in VERDICTS, f"indicator={fields.get('indicator')} not a verdict"))
        return e, {k: fields.get(k) for k in ("indicator", "suite")}
    return f"unknown op {op}", {}


def run(subject, seed, want_module, timeout, quiet=False):
    """(ok, summary) for one subject command line."""
    steps = plan(seed)
    req = "".join(f"{i} {op}{''.join(' ' + a for a in args)}\n" for i, (op, args, _) in enumerate(steps, 1))
    try:
        p = subprocess.run(shlex.split(subject), input=req, capture_output=True, text=True, timeout=timeout)
    except (OSError, ValueError) as e:
        return False, f"subject did not start: {e}"
    except subprocess.TimeoutExpired:
        return False, f"subject timed out after {timeout}s"
    lines = [ln for ln in p.stdout.splitlines() if ln.strip()]
    errs, recs = [], []
    if len(lines) != len(steps):
        errs.append(f"{len(lines)} answer lines for {len(steps)} requests")
    for i, (op, args, exp) in enumerate(steps, 1):
        if i > len(lines):
            break
        toks = lines[i - 1].split()
        if len(toks) < 2 or toks[0] != str(i) or toks[1] != op:
            errs.append(f"line {i}: {lines[i - 1][:80]!r}, want id {i} op {op}")
            continue
        if len(toks) > 2 and toks[2] == "error":
            errs.append(f"{i} {op}: {' '.join(toks[3:])[:160]}")
            continue
        # `module=<string>` keeps its spaces (`AWS-LC FIPS 3.1.0`); every other op answers key=value tokens.
        rest = lines[i - 1].split(None, 2)[2] if len(toks) > 2 else ""
        fields = ({"module": rest[len("module="):]} if rest.startswith("module=") else None) if op == "module" \
            else kv(toks[2:])
        if fields is None:
            errs.append(f"{i} {op}: malformed fields {' '.join(toks[2:])[:80]!r}")
            continue
        e, rec = judge_step(op, args, exp, fields, want_module)
        recs.append((i, op, rec))
        if e:
            errs.append(f"{i} {op}: {e}")
    if p.returncode != 0:
        tail = (p.stderr.strip().splitlines() or [""])[-1][:160]
        errs.append(f"subject exit {p.returncode} ({tail})")
    if not quiet:
        for i, op, rec in recs:
            print(f"  {i:>2} {op:<15} " + " ".join(f"{k}={v}" for k, v in rec.items()))
    if errs:
        shown = errs if quiet else errs[:6]  # the self-test matches reasons against the full list
        return False, f"{len(errs)} problem(s): " + "; ".join(shown) + (" ..." if len(shown) < len(errs) else "")
    count = lambda op: sum(1 for _, o, _ in recs if o == op)
    hs = next(r for _, o, r in recs if o == "handshake")
    kx = next(r for _, o, r in recs if o == "kx-0x11ed")
    a3 = sum(1 for _, o, r in recs if o == "hkdf" and r["kind"] == "A3")
    c3 = sum(1 for _, o, r in recs if o == "hkdf" and r["kind"] == "C3")
    return True, (f"Approved via the module indicator: ecdh-p384 {count('ecdh-p384')}/{count('ecdh-p384')}, "
                  f"mlkem1024 encap+decap {count('mlkem1024')}/{count('mlkem1024')}, hkdf {a3}/{a3}; NotApproved "
                  f"controls: x25519 {count('x25519')}/{count('x25519')}, off-curve peer 1/1, hkdf empty salt/info "
                  f"{c3}/{c3}, none 1/1; 0x11ED handshake reported indicator={hs['indicator']} suite={hs['suite']}; "
                  f"kx-0x11ed reported client_start={kx['client_start']} server={kx['server']} "
                  f"client_complete={kx['client_complete']}; module {want_module}; seed {seed}")


# Self-test: the model subject (fake_subject.py honest) must PASS; each mutant must be red.
MUTANTS = [  # (mode, what it models, a substring the FAIL summary must contain: red for the intended reason)
    ("always-approved", "reports Approved without calling the indicator", "x25519: indicator=approved"),
    ("x25519-approved", "a non-approved primitive (X25519) reported Approved", "x25519: indicator=approved"),
    ("never-approved", "indicator never moves (no approved service seen)", "indicator=not-approved, want approved"),
    ("no-verdict", "answers without indicator fields", "indicator=None"),
    ("hkdf-rule-ignored", "empty salt/info HKDF reported Approved", "(C3: salt"),
    ("hkdf-wrong-okm", "HKDF output not computed", "okm differs"),
    ("mlkem-decap-not-approved", "ML-KEM decap NotApproved", "decap=not-approved"),
    ("mlkem-mismatch", "ML-KEM secrets differ", "mlkem1024: match=0"),
    ("badpeer-accepted", "off-curve ECDH peer accepted", "ecdh-p384-peer: indicator=approved"),
    ("none-approved", "empty closure reported Approved", "none: indicator=approved"),
    ("handshake-missing", "no handshake answer", "handshake: handshake did not complete"),
    ("handshake-wrong-group", "handshake on 0x11eb", "group=0x11eb"),
    ("handshake-no-verdict", "handshake not reported", "handshake: indicator=None"),
    ("kx-mismatch", "0x11ED kx secrets differ", "kx-0x11ed: match=0"),
    ("module-wrong", "module AWS-LC FIPS 4.2.0 (uncertified)", "module='AWS-LC FIPS 4.2.0'"),
    ("drop-line", "one answer missing", "answer lines for"),
    ("reorder", "answers out of order", ", want id 2"),
    ("exit-nonzero", "exit status 1 after correct answers", "subject exit 1"),
    ("compiled-out", "indicator mode compiled out (floor build)", "0 answer lines"),
    ("replay", "answers a fixed transcript from another seed", "line 2:"),
]


def self_test():
    fake = f"python3 -I {shlex.quote(os.path.join(HERE, 'fake_subject.py'))}"
    seed = int.from_bytes(os.urandom(4), "big")
    bad = []
    ok, why = run(f"{fake} honest", seed, MODULE, 60, quiet=True)
    print(f"  honest                     expect PASS  got {'PASS' if ok else 'FAIL'}  {'' if ok else why}")
    if not ok:
        bad.append("honest")
    for m, what, reason in MUTANTS:
        ok, why = run(f"{fake} {m}", seed, MODULE, 60, quiet=True)
        hit = not ok and reason in why
        print(f"  {m:<26} expect FAIL  got {'PASS' if ok else 'FAIL'}{'' if hit or ok else ' (wrong reason)'}  "
              f"({what}) {why[:110]}")
        if not hit:
            bad.append(m)
    ok, why = run("/nonexistent/tls-subject indicator", seed, MODULE, 10, quiet=True)
    print(f"  {'missing-binary':<26} expect FAIL  got {'PASS' if ok else 'FAIL'}")
    if ok:
        bad.append("missing-binary")
    n = len(MUTANTS) + 2
    if bad:
        print(f"{NAME} SELF-TEST: FAIL ({len(bad)}/{n} cases wrong: {', '.join(bad)})")
        return 1
    print(f"{NAME} SELF-TEST: PASS (model subject PASS; {len(MUTANTS) + 1}/{len(MUTANTS) + 1} mutants red; seed {seed})")
    return 0


def main(argv):
    subject, seed, module, timeout = None, None, MODULE, 300
    it = iter(argv)
    for a in it:
        if a == "--self-test":
            return self_test()
        if a in ("--subject", "--seed", "--module", "--timeout"):
            v = next(it, None)
            if v is None:
                print(f"{NAME}: FAIL ({a} needs a value)")
                return 2
            if a == "--subject":
                subject = v
            elif a == "--seed":
                seed = int(v)
            elif a == "--module":
                module = v
            else:
                timeout = int(v)
        else:
            print(f"{NAME}: FAIL (unknown argument {a}; see README.md)")
            return 2
    if subject is None:
        print(f"{NAME}: FAIL (no --subject: this oracle judges the cmvp tls-subject `indicator` mode only)")
        return 1
    if seed is None:
        seed = int.from_bytes(os.urandom(4), "big")
    print(f"{NAME}: subject {subject!r} seed {seed}")
    ok, why = run(subject, seed, module, timeout)
    print(f"{NAME}: {'PASS' if ok else 'FAIL'} ({why})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
