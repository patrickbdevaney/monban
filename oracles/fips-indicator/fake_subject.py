#!/usr/bin/env python3
"""Self-test subjects for oracle.py: `fake_subject.py honest` models a correct cmvp tls-subject `indicator` mode
(AWS-LC 3.1.0's indicator rule, a real RFC 5869 HKDF); every other mode is one mutation of it (oracle.py MUTANTS).
Never a real subject: it proves the oracle's checks can go red, not that any module behaves this way."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oracle  # noqa: E402  (same directory; run with python3 -I, so only this path is added)


def answer(mode, i, op, args):
    v = lambda approved: "approved" if approved else "not-approved"
    if op == "module":
        return f"module={'AWS-LC FIPS 4.2.0' if mode == 'module-wrong' else oracle.MODULE}"
    if mode == "no-verdict" and op != "module":
        return "ok=1 match=1"
    always = mode == "always-approved"
    never = mode == "never-approved"
    if op == "ecdh-p384":
        return f"indicator={v(not never)} ok=1 match=1"
    if op == "x25519":
        return f"indicator={v(always or mode == 'x25519-approved')} ok=1 match=1"
    if op == "ecdh-p384-peer":
        return f"indicator={v(always or mode == 'badpeer-accepted')} ok={1 if mode == 'badpeer-accepted' else 0}"
    if op == "mlkem1024":
        decap = not never and mode != "mlkem-decap-not-approved"
        return (f"keygen={v(not never)} encap={v(not never)} decap={v(decap)} "
                f"match={0 if mode == 'mlkem-mismatch' else 1}")
    if op == "hkdf":
        h, salt, ikm, info, n = args
        salt = b"" if salt == "-" else bytes.fromhex(salt)
        info = b"" if info == "-" else bytes.fromhex(info)
        okm = oracle.hkdf(h, salt, bytes.fromhex(ikm), info, int(n))
        if mode == "hkdf-wrong-okm":
            okm = bytes(len(okm))
        approved = oracle.hkdf_rule_approved(salt, info)
        approved = (approved and not never) or always or mode == "hkdf-rule-ignored"
        return f"indicator={v(approved)} okm={okm.hex()}"
    if op == "none":
        return f"indicator={v(always or mode == 'none-approved')}"
    if op == "kx-0x11ed":
        return (f"client_start={v(not never)} server={v(not never)} client_complete={v(not never)} "
                f"match={0 if mode == 'kx-mismatch' else 1}")
    if op == "handshake":
        if mode == "handshake-missing":
            return "error handshake did not complete"
        group = "0x11eb" if mode == "handshake-wrong-group" else "0x11ed"
        verdict = "" if mode == "handshake-no-verdict" else f" indicator={v(not never)}"
        return f"group={group} version=0x0304 suite=0x1302{verdict}"
    return f"error unknown op {op}"


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "honest"
    if mode == "compiled-out":
        print("indicator is compiled out of this build (feature `indicator` off)", file=sys.stderr)
        return 1
    reqs = [ln.split() for ln in sys.stdin.read().splitlines() if ln.strip()]
    if mode == "replay":
        # A transcript recorded under another seed: right shape, wrong random parameters.
        steps = oracle.plan(1)
        reqs = [[str(i), op] + args for i, (op, args, _) in enumerate(steps, 1)]
    out = [f"{r[0]} {r[1]} {answer(mode, r[0], r[1], r[2:])}" for r in reqs]
    if mode == "drop-line" and out:
        out.pop(len(out) // 2)
    if mode == "reorder" and len(out) > 2:
        out[1], out[2] = out[2], out[1]
    print("\n".join(out))
    return 1 if mode == "exit-nonzero" else 0


if __name__ == "__main__":
    sys.exit(main())
