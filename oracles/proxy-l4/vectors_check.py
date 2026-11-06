"""Check the reference PROXY v2 / ClientHello peek parsers against vectors/*.json (oracle proxy-l4; stdlib only).

    python3 -I vectors_check.py [--mutant NAME]
Exit 0 iff 0 divergences. P7-wire-001 runs the same JSON files from Rust tests (README.md "Vector sets").
A reject-class mismatch counts as a divergence for the reference only; for the Rust parser the class is informational.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import clienthello as ch  # noqa: E402
import proxyv2 as pp  # noqa: E402

PP_FIELDS = ("consumed", "command", "family", "proto", "src", "dst", "src_port", "dst_port", "peer", "stream_accept",
             "tlvs")
CH_FIELDS = ("sni", "alpn", "versions", "sigalgs", "groups", "trust_anchors", "consumed")


def load(name):
    with open(os.path.join(HERE, "vectors", name)) as f:
        return json.load(f)


def _judge(v, kind, got, fields, div):
    if kind != v["expect"]:
        div.append(f"{v['id']}: expected {v['expect']}{'/' + v['class'] if v.get('class') else ''}, "
                   f"got {kind}{'/' + got if kind == 'reject' else ''}")
    elif kind == "reject" and got != v["class"]:
        div.append(f"{v['id']}: reject class {got} != {v['class']}")
    elif kind == "ok":
        for f in fields:
            if got.get(f) != v[f]:
                div.append(f"{v['id']}: {f} {got.get(f)!r} != {v[f]!r}")
                break


def run_proxy(vectors, mutant=None):
    div = []
    for v in vectors:
        try:
            kind, got = "ok", pp.parse(bytes.fromhex(v["hex"]), mutant=mutant)
        except pp.Incomplete:
            kind, got = "incomplete", None
        except pp.Reject as e:
            kind, got = "reject", e.cls
        _judge(v, kind, got, PP_FIELDS, div)
    return div


def run_ch(vectors, mutant=None):
    div = []
    for v in vectors:
        try:
            kind, got = "ok", ch.peek(bytes.fromhex(v["hex"]), mutant=mutant)
        except ch.PeekIncomplete:
            kind, got = "incomplete", None
        except ch.PeekError as e:
            kind, got = "reject", e.cls
        _judge(v, kind, got, CH_FIELDS, div)
    return div


def check(mutant=None):
    pv, cv = load("proxy_v2.json"), load("client_hello.json")
    return run_proxy(pv["vectors"], mutant), run_ch(cv["vectors"], mutant), pv, cv


def main():
    mutant = sys.argv[sys.argv.index("--mutant") + 1] if "--mutant" in sys.argv else None
    dp, dc, pv, cv = check(mutant)
    for d in dp + dc:
        print("  DIVERGE", d)
    print(f"proxy_v2: {pv['count']} vectors, {len(dp)} divergences; client_hello: {cv['count']} vectors, "
          f"{len(dc)} divergences")
    return 0 if not dp and not dc else 1


if __name__ == "__main__":
    sys.exit(main())
