#!/usr/bin/env -S python3 -I
"""Production TUF root metadata for Monban releases (F1 REL-2: 5 Ed25519 root keys, threshold 3). Runs under the
hash-locked python-tuf venv (~/aegis-ci/py-tuf; $AEGIS_PY_TUF_PYTHON), like ci/release/jobs/tuf.py.

  root.py make  --pubdir DIR --signdir DIR --days N --out FILE
      Builds the next root version from the public keys in DIR (root-1..5.pub.pem, targets/snapshot/timestamp.pub.pem):
      version 1 when DIR has no N.root.json yet, else (latest N) + 1. Signs it with every root-*.key.pem in SIGNDIR
      (plaintext keys on tmpfs, decrypted by ceremony.sh). Refuses unless the new root is signed by >= 3 of its own 5
      keys and, for version > 1, by >= 3 of the previous root's keys (a TUF client checks both). Never writes a
      test_keys marker.
  root.py check --pubdir DIR [--ignore-expiry]
      Checks the committed chain DIR/1.root.json .. N.root.json: each is 5 Ed25519 root keys with threshold 3,
      consistent_snapshot false, signed by >= 3 of its own keys and >= 3 of the previous root's keys, version N in
      N.root.json, no test_keys marker anywhere in `signed`, the latest not expired, and the latest root's keys equal
      the public keys in DIR (root-1..5 as the root role, targets/snapshot/timestamp as those roles). Also refuses a
      release or attest public key equal to any TUF key.

Final line: ROOT: PASS (...) or ROOT: FAIL (<reason>).
"""

import os
import re
import sys
from datetime import datetime, timedelta, timezone

ROOTS = [f"root-{i}" for i in range(1, 6)]
ONLINE_TUF = ("targets", "snapshot", "timestamp")
OTHER_PUBS = ("ed25519", "attest")
ROOT_RE = re.compile(r"\A([1-9][0-9]{0,8})\.root\.json\Z")


class Fail(Exception):
    pass


def _pub(path):
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from securesystemslib.signer import SSlibKey

    with open(path, "rb") as f:
        return SSlibKey.from_crypto(load_pem_public_key(f.read()))


def root_files(pubdir):
    vs = sorted(int(m[1]) for m in (ROOT_RE.match(n) for n in os.listdir(pubdir)) if m)
    if vs and vs != list(range(1, vs[-1] + 1)):
        raise Fail(f"root versions {vs} in {pubdir} are not 1..N")
    return [os.path.join(pubdir, f"{v}.root.json") for v in vs]


def has_marker(obj):
    if isinstance(obj, dict):
        return "test_keys" in obj or any(has_marker(v) for v in obj.values())
    if isinstance(obj, list):
        return any(has_marker(v) for v in obj)
    return False


def policy(md, where):
    from tuf.api.metadata import Root

    r = md.signed
    if not isinstance(r, Root):
        raise Fail(f"{where} is not root metadata")
    role = r.roles["root"]
    if len(role.keyids) != 5 or role.threshold != 3:
        raise Fail(f"{where}: root role is {role.threshold} of {len(role.keyids)} (need 3 of 5)")
    for kid in role.keyids:
        k = r.keys[kid]
        if k.keytype != "ed25519" or k.scheme != "ed25519":
            raise Fail(f"{where}: root key {kid[:16]} is not Ed25519")
    if r.consistent_snapshot:
        raise Fail(f"{where}: consistent_snapshot must be false")
    if has_marker(md.signed.to_dict()):
        raise Fail(f"{where}: carries a test_keys marker (production roots never do)")
    res = r.get_verification_result(Root.type, md.signed_bytes, md.signatures)
    if len(res.signed) < 3:
        raise Fail(f"{where}: {len(res.signed)}/5 valid signatures by its own root keys (need 3)")
    return len(res.signed)


def check_chain(pubdir, now=None, ignore_expiry=False):
    """Returns (list of (filename, bytes), latest Root). Raises Fail."""
    from tuf.api.metadata import Metadata, Root

    files = root_files(pubdir)
    if not files:
        raise Fail(f"no 1.root.json in {pubdir}")
    out, prev = [], None
    for i, p in enumerate(files, 1):
        with open(p, "rb") as f:
            data = f.read()
        try:
            md = Metadata.from_bytes(data)
        except Exception as e:  # noqa: BLE001 - any parse error is a refusal
            raise Fail(f"{os.path.basename(p)}: {e}") from None
        where = os.path.basename(p)
        if md.signed.version != i:
            raise Fail(f"{where} has version {md.signed.version}")
        policy(md, where)
        if prev is not None:
            res = prev.signed.get_verification_result(Root.type, md.signed_bytes, md.signatures)
            if len(res.signed) < 3:
                raise Fail(f"{where}: only {len(res.signed)} valid signatures by version {i - 1}'s root keys (need 3)")
        out.append((where, data))
        prev = md
    root = prev.signed
    now = now or datetime.now(timezone.utc)
    if root.expires <= now and not ignore_expiry:
        raise Fail(f"latest root {len(files)}.root.json expired {root.expires.isoformat()}")
    want_root = {_pub(os.path.join(pubdir, f"{n}.pub.pem")).keyid for n in ROOTS}
    if set(root.roles["root"].keyids) != want_root:
        raise Fail("latest root's root keys differ from root-1..5.pub.pem")
    tuf_ids = set(want_root)
    for r in ONLINE_TUF:
        kid = _pub(os.path.join(pubdir, f"{r}.pub.pem")).keyid
        if root.roles[r].keyids != [kid] or root.roles[r].threshold != 1:
            raise Fail(f"latest root's {r} role is not exactly {r}.pub.pem (threshold 1)")
        tuf_ids.add(kid)
    if len(tuf_ids) != 8:
        raise Fail("TUF keys are not 8 distinct keys")
    for n in OTHER_PUBS:
        if _pub(os.path.join(pubdir, f"{n}.pub.pem")).keyid in tuf_ids:
            raise Fail(f"{n}.pub.pem is also a TUF key")
    return out, root


def make(pubdir, signdir, days, out):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from securesystemslib.signer import CryptoSigner
    from tuf.api.metadata import Metadata, Role, Root
    from tuf.api.serialization.json import JSONSerializer

    prev_files = root_files(pubdir)
    prev = None
    if prev_files:
        with open(prev_files[-1], "rb") as f:
            prev = Metadata.from_bytes(f.read())
    version = len(prev_files) + 1
    keys = {n: _pub(os.path.join(pubdir, f"{n}.pub.pem")) for n in ROOTS + list(ONLINE_TUF)}
    if len({k.keyid for k in keys.values()}) != 8:
        raise Fail("the 8 TUF public keys are not distinct")
    for n in OTHER_PUBS:
        if _pub(os.path.join(pubdir, f"{n}.pub.pem")).keyid in {k.keyid for k in keys.values()}:
            raise Fail(f"{n}.pub.pem equals a TUF key")
    signers = []
    for fn in sorted(os.listdir(signdir)):
        if fn.startswith("root-") and fn.endswith(".key.pem"):
            with open(os.path.join(signdir, fn), "rb") as f:
                signers.append(CryptoSigner(load_pem_private_key(f.read(), password=None)))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    root = Root(version=version, expires=now + timedelta(days=days), consistent_snapshot=False)
    root.roles = {r: Role([], 1) for r in ("root",) + ONLINE_TUF}
    for n in ROOTS:
        root.add_key(keys[n], "root")
    root.roles["root"].threshold = 3
    for r in ONLINE_TUF:
        root.add_key(keys[r], r)
    md = Metadata(root)
    seen = set()
    for s in signers:
        if s.public_key.keyid in seen:
            continue
        seen.add(s.public_key.keyid)
        md.sign(s, append=True)
    n_own = policy(md, f"new root v{version}")
    if prev is not None:
        res = prev.signed.get_verification_result(Root.type, md.signed_bytes, md.signatures)
        if len(res.signed) < 3:
            raise Fail(f"new root v{version}: only {len(res.signed)} valid signatures by version {version - 1}'s root "
                       "keys (need 3)")
    md.to_file(out, JSONSerializer(compact=False))
    return version, n_own


def check_pins():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "monban_tuf_job", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "jobs", "tuf.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.check_pins()  # exits non-zero on a version that is not the ci/tools.lock pin


def main(argv):
    check_pins()
    try:
        if argv[:1] == ["check"] and len(argv) in (3, 4) and argv[1] == "--pubdir" and argv[3:] in ([],
                                                                                              ["--ignore-expiry"]):
            files, root = check_chain(argv[2], ignore_expiry=argv[3:] == ["--ignore-expiry"])
            print(f"ROOT: PASS ({len(files)} root version(s), latest 3 of 5 Ed25519, expires "
                  f"{root.expires.date().isoformat()}, keys match {argv[2]}, no test_keys)")
            return 0
        if argv[:1] == ["make"]:
            a = dict(zip(argv[1::2], argv[2::2]))
            if len(argv) != 9 or set(a) != {"--pubdir", "--signdir", "--days", "--out"}:
                raise Fail("usage: root.py make --pubdir DIR --signdir DIR --days N --out FILE")
            days = int(a["--days"])
            if not 30 <= days <= 3650:
                raise Fail("--days must be 30..3650")
            v, n = make(a["--pubdir"], a["--signdir"], days, a["--out"])
            print(f"ROOT: PASS (root v{v}, 3 of 5 Ed25519, {n} of its own root keys signed, expires in {days} days)")
            return 0
        raise Fail("usage: root.py make ... | root.py check --pubdir DIR")
    except Fail as e:
        print(f"ROOT: FAIL ({e})")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
