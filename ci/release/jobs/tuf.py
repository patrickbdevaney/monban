#!/usr/bin/env -S python3 -I
"""Release job 5: TUF metadata (PLAN-6 D6, F1 REL-2, PREFLIGHT D-P2). Runs under the hash-locked python-tuf venv
(~/aegis-ci/py-tuf, versions checked against the `#py:` rows of ci/tools.lock).

  tuf.py --release DIR --keydir DIR [--expires-days N]

Generates fresh per-run test keys in its own key directory: 5 Ed25519 root keys (threshold 3) and one Ed25519 key each
for targets, snapshot and timestamp (openssl genpkey, loaded into securesystemslib CryptoSigner). Writes
DIR/tuf/1.root.json, targets.json, snapshot.json, timestamp.json, all version 1, consistent_snapshot false, with
`"test_keys": true` in every role's `signed` (D-P2). targets.json lists every file of DIR outside tuf/ with length and
sha256. The job then checks its metadata (root 3 of 5 signatures verify, every role verifies with the root's keys),
checks its output against its keys (jobs/leakcheck.py --keys) and shreds the key directory.
"""

import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from importlib import metadata as im

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS_LOCK = os.path.join(HERE, "..", "..", "tools.lock")
OPENSSL = os.environ.get("AEGIS_OPENSSL", "/usr/bin/openssl")


def die(msg):
    print(f"tuf: {msg}", file=sys.stderr)
    sys.exit(1)


def check_pins():
    pins = {}
    with open(TOOLS_LOCK, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#py:"):
                cols = line[4:].split()
                if len(cols) >= 2:
                    pins[cols[0].lower()] = cols[1]
    for req in ("tuf", "securesystemslib", "cryptography"):
        if req not in pins:
            die(f"{req} has no #py: pin in ci/tools.lock")
    for name, want in pins.items():
        try:
            have = im.version(name)
        except im.PackageNotFoundError:
            die(f"{name} {want} pinned in ci/tools.lock but not installed in {sys.prefix}")
        if have != want:
            die(f"{name} installed {have}, pinned {want} in ci/tools.lock")


def shred_dir(d):
    for dp, _dn, fns in os.walk(d):
        for fn in fns:
            subprocess.run(["shred", "-u", "-z", os.path.join(dp, fn)], check=False)


def main(argv):
    args = dict(zip(argv[0::2], argv[1::2]))
    if len(argv) % 2 or not {"--release", "--keydir"} <= set(args) or set(args) - {"--release", "--keydir",
                                                                                    "--expires-days"}:
        die("usage: tuf.py --release DIR --keydir DIR [--expires-days N]")
    rel, kd = args["--release"], args["--keydir"]
    days = int(args.get("--expires-days", "7"))
    check_pins()
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from securesystemslib.signer import CryptoSigner
    from tuf.api.metadata import Metadata, MetaFile, Role, Root, Snapshot, TargetFile, Targets, Timestamp
    from tuf.api.serialization.json import JSONSerializer

    if not os.path.isdir(kd) or os.listdir(kd):
        die("key directory must exist and be empty")
    tdir = os.path.join(rel, "tuf")
    if os.path.exists(tdir):
        die("release already has tuf/")
    try:
        def signer(name):
            p = os.path.join(kd, name + ".key.pem")
            r = subprocess.run([OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", p], capture_output=True,
                               check=False)
            if r.returncode != 0:
                die(f"openssl genpkey failed: {r.stderr.decode(errors='replace')}")
            os.chmod(p, 0o600)
            with open(p, "rb") as f:
                return CryptoSigner(load_pem_private_key(f.read(), password=None))

        roots = [signer(f"root{i}") for i in range(1, 6)]
        targets_s, snapshot_s, timestamp_s = signer("targets"), signer("snapshot"), signer("timestamp")
        now = datetime.now(timezone.utc).replace(microsecond=0)
        mark = {"test_keys": True}

        tfiles = {}
        for dp, dns, fns in os.walk(rel):
            dns.sort()
            for fn in sorted(fns):
                p = os.path.join(dp, fn)
                if os.path.islink(p) or not os.path.isfile(p):
                    die(f"{p} is not a regular file")
                r = os.path.relpath(p, rel)
                tfiles[r] = TargetFile.from_file(r, p, ["sha256"])
        if not tfiles:
            die("nothing to list in targets")

        root = Root(version=1, expires=now + timedelta(days=max(days, 30)), consistent_snapshot=False,
                    unrecognized_fields=dict(mark))
        root.roles = {r: Role([], 1) for r in ("root", "targets", "snapshot", "timestamp")}
        for s in roots:
            root.add_key(s.public_key, "root")
        root.roles["root"].threshold = 3
        root.add_key(targets_s.public_key, "targets")
        root.add_key(snapshot_s.public_key, "snapshot")
        root.add_key(timestamp_s.public_key, "timestamp")
        root_md = Metadata(root)
        for s in roots:
            root_md.sign(s, append=True)
        targets = Metadata(Targets(version=1, expires=now + timedelta(days=days), targets=tfiles,
                                   unrecognized_fields=dict(mark)))
        targets.sign(targets_s)
        snapshot = Metadata(Snapshot(version=1, expires=now + timedelta(days=days),
                                     meta={"targets.json": MetaFile(1)}, unrecognized_fields=dict(mark)))
        snapshot.sign(snapshot_s)
        timestamp = Metadata(Timestamp(version=1, expires=now + timedelta(days=1), snapshot_meta=MetaFile(1),
                                       unrecognized_fields=dict(mark)))
        timestamp.sign(timestamp_s)

        # self-check before writing: 5/5 root signatures (threshold 3) and every role verified by the root
        res = root.get_root_verification_result(None, root_md.signed_bytes, root_md.signatures)
        if not res.verified or len(res.signed) != 5 or root.roles["root"].threshold != 3:
            die("root self-check failed")
        for name, md in (("targets", targets), ("snapshot", snapshot), ("timestamp", timestamp)):
            root.verify_delegate(name, md.signed_bytes, md.signatures)

        os.makedirs(tdir)
        ser = JSONSerializer(compact=False)
        root_md.to_file(os.path.join(tdir, "1.root.json"), ser)
        targets.to_file(os.path.join(tdir, "targets.json"), ser)
        snapshot.to_file(os.path.join(tdir, "snapshot.json"), ser)
        timestamp.to_file(os.path.join(tdir, "timestamp.json"), ser)
        lc = subprocess.run([sys.executable, "-I", os.path.join(HERE, "leakcheck.py"), "--keys", kd, rel],
                            capture_output=True, text=True, check=False)
        if lc.returncode != 0:
            die("private key material in the release:\n" + lc.stdout)
    finally:
        shred_dir(kd)
    if os.listdir(kd):
        die("key directory not empty after shred")
    print(f"tuf: root v1 (3 of 5 Ed25519), targets/snapshot/timestamp v1, {len(tfiles)} targets, test_keys true; "
          "8 keys destroyed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
