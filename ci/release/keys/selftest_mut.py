#!/usr/bin/env -S python3 -I
"""Mutant builders for ci/release/keys/selftest.sh (python-tuf venv). Only ever used on throwaway self-test keys.

  selftest_mut.py strip-root IN OUT KEEP            copy root metadata keeping only its first KEEP signatures
  selftest_mut.py mark-root IN SIGNDIR OUT          same root, `"test_keys": true` added to signed, re-signed by every
                                                    root-*.key.pem in SIGNDIR (so only the marker is wrong)
  selftest_mut.py mark-release REL ONLINEDIR        add a TEST_KEYS file to a production release and re-sign
                                                    targets/snapshot/timestamp with ONLINEDIR/{targets,snapshot,
                                                    timestamp}.key.pem (so only the marker is wrong)
"""

import os
import sys

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import Metadata, MetaFile, TargetFile
from tuf.api.serialization.json import JSONSerializer

SER = JSONSerializer(compact=False)


def signer(path):
    with open(path, "rb") as f:
        return CryptoSigner(load_pem_private_key(f.read(), password=None))


def main(a):
    if a[0] == "strip-root" and len(a) == 4:
        md = Metadata.from_file(a[1])
        keep = list(md.signatures)[: int(a[3])]
        for k in list(md.signatures):
            if k not in keep:
                del md.signatures[k]
        md.to_file(a[2], SER)
    elif a[0] == "mark-root" and len(a) == 4:
        md = Metadata.from_file(a[1])
        md.signed.unrecognized_fields["test_keys"] = True
        md.signatures.clear()
        for fn in sorted(os.listdir(a[2])):
            if fn.startswith("root-") and fn.endswith(".key.pem"):
                md.sign(signer(os.path.join(a[2], fn)), append=True)
        md.to_file(a[3], SER)
    elif a[0] == "mark-release" and len(a) == 3:
        rel, kd = a[1], a[2]
        with open(os.path.join(rel, "TEST_KEYS"), "wb") as f:
            f.write(b"test_keys: true\n")
        t = Metadata.from_file(os.path.join(rel, "tuf", "targets.json"))
        t.signed.targets["TEST_KEYS"] = TargetFile.from_file("TEST_KEYS", os.path.join(rel, "TEST_KEYS"), ["sha256"])
        t.signed.version += 1
        t.sign(signer(os.path.join(kd, "targets.key.pem")))
        s = Metadata.from_file(os.path.join(rel, "tuf", "snapshot.json"))
        s.signed.meta["targets.json"] = MetaFile(t.signed.version)
        s.signed.version += 1
        s.sign(signer(os.path.join(kd, "snapshot.key.pem")))
        ts = Metadata.from_file(os.path.join(rel, "tuf", "timestamp.json"))
        ts.signed.snapshot_meta = MetaFile(s.signed.version)
        ts.signed.version += 1
        ts.sign(signer(os.path.join(kd, "timestamp.key.pem")))
        for name, md in (("targets", t), ("snapshot", s), ("timestamp", ts)):
            md.to_file(os.path.join(rel, "tuf", f"{name}.json"), SER)
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
