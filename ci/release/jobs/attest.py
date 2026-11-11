#!/usr/bin/env -S python3 -I
"""Release job 3: attest (PLAN-6 D6, PREFLIGHT D-P5). A separate process with its own key directory and its own
Ed25519 key (a fresh per-run test key, D-P2). It reads only the build job's output digest and build record and the
SBOM (never the artifact), and writes an in-toto Statement v1 with SLSA provenance v1 as a DSSE envelope.

  attest.py --subject artifacts/<name>=<sha256> [--subject ...] --sbom FILE --build-info FILE --source FILE
            --keydir DIR --out DIR [--enc-key FILE --passfile FILE --expect-pub FILE]

Writes OUT/provenance.intoto.json and OUT/attest/attest.pub.pem (release layout contract v1, ci/release/verify.py).
The provenance records what an independent rebuild (D7) must match: source commit and SOURCE_DATE_EPOCH, the build
image (base digest, Containerfile sha256, image id), rustc -vV, Go and gcc versions, RUSTFLAGS, the command, and the
sha256 of Cargo.lock and cargo-auditable.
Production mode (--enc-key, ci/release/keys/README.md): no key is generated; the encrypted attest key is decrypted
into the job's key directory (openssl pkey -passin file:PASSFILE), its public key must equal --expect-pub (the
committed release-keys/attest.pub.pem) byte for byte, and externalParameters carries no test_keys field.
Before it exits, the job checks its outputs against its key (jobs/leakcheck.py --keys) and shreds the key directory.
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
OPENSSL = os.environ.get("AEGIS_OPENSSL", "/usr/bin/openssl")
DSSE_TYPE = "application/vnd.in-toto+json"
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
ART = re.compile(r"\Aartifacts/[A-Za-z0-9._-]+\Z")


def die(msg):
    print(f"attest: {msg}", file=sys.stderr)
    sys.exit(1)


def run(args):
    p = subprocess.run(args, capture_output=True, check=False)
    if p.returncode != 0:
        die(f"{' '.join(args[:3])} failed: {p.stderr.decode(errors='replace').strip()}")
    return p.stdout


def shred_dir(d):
    for dp, _dn, fns in os.walk(d):
        for fn in fns:
            subprocess.run(["shred", "-u", "-z", os.path.join(dp, fn)], check=False)


def parse(argv):
    a = {"subject": []}
    i = 0
    while i < len(argv):
        k = argv[i]
        if k not in ("--subject", "--sbom", "--build-info", "--source", "--keydir", "--out", "--enc-key", "--passfile",
                     "--expect-pub") or i + 1 >= len(argv):
            die(f"bad argument {k!r}")
        if k == "--subject":
            a["subject"].append(argv[i + 1])
        else:
            a[k[2:].replace("-", "_")] = argv[i + 1]
        i += 2
    for k in ("sbom", "build_info", "source", "keydir", "out"):
        if k not in a:
            die(f"missing --{k.replace('_', '-')}")
    if not a["subject"]:
        die("need at least one --subject")
    prod = [k for k in ("enc_key", "passfile", "expect_pub") if k in a]
    if prod and len(prod) != 3:
        die("production mode needs --enc-key, --passfile and --expect-pub together")
    a["prod"] = bool(prod)
    return a


def main(argv):
    a = parse(argv)
    subjects = []
    for s in a["subject"]:
        name, _, digest = s.partition("=")
        if not ART.match(name) or not HEX64.match(digest):
            die(f"bad --subject {s!r}")
        subjects.append({"name": name, "digest": {"sha256": digest}})
    with open(a["sbom"], "rb") as f:
        sbom = f.read()
    with open(a["build_info"], encoding="utf-8") as f:
        bi = json.load(f)
    with open(a["source"], encoding="utf-8") as f:
        src = json.load(f)
    if {s["name"]: s["digest"]["sha256"] for s in subjects}.get(bi["artifact"]) != bi["sha256"]:
        die("the build record's digest is not among the subjects")
    kd = a["keydir"]
    if not os.path.isdir(kd) or os.listdir(kd):
        die("key directory must exist and be empty")
    try:
        key = os.path.join(kd, "attest.key.pem")
        if a["prod"]:
            os.close(os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
            r = subprocess.run([OPENSSL, "pkey", "-in", a["enc_key"], "-passin", "file:" + a["passfile"], "-out", key],
                               capture_output=True, check=False)
            if r.returncode != 0:
                die(f"cannot decrypt {a['enc_key']} (wrong passphrase or not an encrypted key)")
        else:
            run([OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", key])
        os.chmod(key, 0o600)
        pub = run([OPENSSL, "pkey", "-in", key, "-pubout"])
        if a["prod"]:
            with open(a["expect_pub"], "rb") as f:
                if f.read() != pub:
                    die(f"{a['enc_key']} is not the key of the committed {a['expect_pub']}")
        pub_der = run([OPENSSL, "pkey", "-in", key, "-pubout", "-outform", "DER"])
        keyid = hashlib.sha256(pub_der).hexdigest()
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": subjects,
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "urn:aegis:release:d6:v1",
                    "externalParameters": {
                        "profile": bi["profile"],
                        "package": "monban-bin",
                        "command": bi["command"],
                        "source": {"commit": src["commit"], "kind": src["kind"], "tree_sha256": src["tree_sha256"]},
                        "source_date_epoch": bi["source_date_epoch"],
                        **({} if a["prod"] else {"test_keys": True}),
                    },
                    "internalParameters": {
                        "rustflags": bi["rustflags"],
                        "build_image": bi["image"],
                        "rustc_vV": bi["rustc_vV"],
                        "cargo_V": bi["cargo_V"],
                        "go_version": bi["go_version"],
                        "cc_version": bi["cc_version"],
                        "paths": bi["paths"],
                    },
                    "resolvedDependencies": [
                        {"uri": f"git+monban@{src['commit']}", "digest": {"gitCommit": src["commit"]}}
                        if re.fullmatch(r"[0-9a-f]{40}", src["commit"]) else
                        {"uri": "monban-source-tree", "digest": {"sha256": src["tree_sha256"]}},
                        {"uri": f"docker-image://{bi['image']['base']}",
                         "digest": {"sha256": bi["image"]["base"].rsplit("sha256:", 1)[-1]}},
                        {"uri": f"docker-image://{bi['image']['name']}",
                         "digest": {"sha256": bi["image"]["id"].removeprefix("sha256:")},
                         "annotations": {"containerfile_sha256": bi["image"]["containerfile_sha256"]}},
                        {"uri": "file:Cargo.lock", "digest": {"sha256": bi["cargo_lock_sha256"]}},
                        {"uri": "tool:cargo-auditable", "digest": {"sha256": bi["cargo_auditable_sha256"]}},
                        {"uri": "tool:rustc", "annotations": {"version": bi["rustc_vV"]}},
                        {"uri": "tool:go", "annotations": {"version": bi["go_version"]}},
                    ],
                },
                "runDetails": {
                    "builder": {"id": "urn:aegis:ci:kamrui:release-pipeline:v1"},
                    "metadata": {"invocationId": str(uuid.uuid4()), "startedOn": now},
                    "byproducts": [{"name": "sbom.cdx.json", "digest": {"sha256": hashlib.sha256(sbom).hexdigest()}}],
                },
            },
        }
        payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
        t = DSSE_TYPE.encode()
        pae = b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)
        msg = os.path.join(kd, "pae.bin")  # -rawin needs a sized file
        with open(msg, "wb") as f:
            f.write(pae)
        sig = run([OPENSSL, "pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", msg])
        out = a["out"]
        os.makedirs(os.path.join(out, "attest"), exist_ok=True)
        env = {"payloadType": DSSE_TYPE, "payload": base64.b64encode(payload).decode(),
               "signatures": [{"keyid": keyid, "sig": base64.b64encode(sig).decode()}]}
        with open(os.path.join(out, "provenance.intoto.json"), "w", encoding="utf-8") as f:
            json.dump(env, f, indent=1)
            f.write("\n")
        pubp = os.path.join(out, "attest", "attest.pub.pem")
        with open(pubp, "wb") as f:
            f.write(pub)
        # self-check: the envelope verifies with the shipped public key
        sigp = os.path.join(kd, "sig.bin")
        with open(sigp, "wb") as f:
            f.write(sig)
        v = subprocess.run([OPENSSL, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", pubp, "-in", msg,
                            "-sigfile", sigp], capture_output=True, check=False)
        if v.returncode != 0:
            die("DSSE signature does not verify with attest.pub.pem")
        lc = subprocess.run([sys.executable, "-I", os.path.join(HERE, "leakcheck.py"), "--keys", kd, out],
                            capture_output=True, text=True, check=False)
        if lc.returncode != 0:
            die("private key material in the attest output:\n" + lc.stdout)
    finally:
        shred_dir(kd)
    if os.listdir(kd):
        die("key directory not empty after shred")
    kind = "production attest key" if a["prod"] else "attest key"
    print(f"attest: provenance for {len(subjects)} subject(s), {kind} {keyid[:16]} (destroyed)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
