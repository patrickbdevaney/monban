#!/usr/bin/env -S python3 -I
"""AEGIS release verifier (P6-oracle-release-001; PLAN-6 D6; F1 REL-1..REL-5; PREFLIGHT D-P2).

Usage:
  ci/release/verify.py [--allow-test-keys] [--trusted-root ROOT.json] [--state DIR]
                       [--expect-sha256 PATH=HEX ...] RELEASE_DIR
  ci/release/verify.py --self-test

Output: one `REASON <tag>: <detail>` line per refusal, then exactly one final line
  RELEASE-VERIFY: PASS                     (exit 0)
  RELEASE-VERIFY: FAIL (<tag>: <detail>)   (exit 1; exit 2 for usage errors)

Runtime: python3 -I, stdlib plus python-tuf (ngclient + metadata API) and securesystemslib with pyca/cryptography.
When `tuf` is not importable, the script re-executes itself with -I under $AEGIS_PY_TUF_PYTHON or
~/aegis-ci/py-tuf/bin/python (the hash-locked venv on kamrui), then checks the installed versions against the `#py:`
rows of ci/tools.lock (P6-spec-002), or against FALLBACK_PINS below while ci/tools.lock has no `#py:` rows.
Signatures are checked with the OpenSSL CLI (`openssl pkeyutl -verify -rawin`, OpenSSL >= 3.5; $AEGIS_OPENSSL or
/usr/bin/openssl).

RELEASE DIRECTORY LAYOUT CONTRACT (v1). The pipeline (ci/release/pipeline.sh, P6-release-001) writes exactly this,
and the verifier refuses anything else (no symlinks, no special files, no unlisted files):

  RELEASE_DIR/
    artifacts/<name>            >= 1 release binaries, regular files, names [A-Za-z0-9._-]+
    SHA256SUMS                  sha256sum format, one line `<64 lowercase hex>  <path>` per artifact
                                (path = artifacts/<name>) plus one line for `sbom.cdx.json`; sorted by path,
                                no duplicates, LF line ends. Must match the files byte for byte.
    sbom.cdx.json               CycloneDX JSON (bomFormat "CycloneDX", specVersion a string).
    provenance.intoto.json      DSSE envelope {payloadType: "application/vnd.in-toto+json", payload: base64,
                                signatures: [exactly one {keyid, sig: base64}]}; signature = Ed25519 over the DSSE PAE
                                ("DSSEv1 <len> <type> <len> <payload>") with the attest key. The payload is an in-toto
                                Statement v1 (`_type` https://in-toto.io/Statement/v1, predicateType
                                https://slsa.dev/provenance/v1): `subject` = one {name: artifacts/<name>,
                                digest: {sha256}} per artifact (same set as SHA256SUMS, REL-3);
                                predicate.buildDefinition.buildType a non-empty string, externalParameters an object;
                                predicate.runDetails.builder.id a non-empty string; predicate.runDetails.byproducts holds
                                exactly one {name: "sbom.cdx.json", digest: {sha256}} (REL-5).
    attest/attest.pub.pem       the attest job's Ed25519 public key (SPKI PEM). It must be a separate key: not the
                                release Ed25519 key, not any TUF key.
    sigs/<alg>.sig              raw signature bytes, alg in {ed25519, slh-dsa-sha2-128s, ml-dsa-87}
    sigs/<alg>.subject          the exact signed message: b"aegis-release-v1 sha256:" + hex(sha256(SHA256SUMS)) + b"\n"
    sigs/<alg>.pub.pem          SPKI PEM public key of that algorithm (checked by OpenSSL's key type)
                                REL-1: all three present, each valid over its subject (openssl pkeyutl -verify -rawin),
                                all three subjects naming the same digest, and that digest = sha256(SHA256SUMS).
    TEST_KEYS                   present iff signed with per-run test keys (D-P2); content "test_keys: true\n".
    tuf/1.root.json .. N.root.json   consecutive root versions; each root: 5 Ed25519 root keys, threshold 3 (REL-2),
                                consistent_snapshot false
    tuf/targets.json            lists every file above (every path outside tuf/) with length and sha256
    tuf/snapshot.json, tuf/timestamp.json
                                TUF roles carry `"test_keys": true` in `signed` when made with test keys (D-P2).

  No file anywhere in the release may contain private key material (a PEM "PRIVATE KEY" block): D-P2.

Verification order:
  A. raw scan: regular files only; no private key material (stops on failure).
  B. TUF via python-tuf ngclient against the release's tuf/ dir (a local fetcher; nothing goes to the network):
     trust anchor = --state DIR/root.json if present, else --trusted-root, else (only with --allow-test-keys, and
     only if the release turns out to be test-key marked) tuf/1.root.json as trust-on-first-use. Root chain,
     thresholds, signatures, snapshot/timestamp meta versions and expiry of every role are python-tuf's checks.
     Policy on top: every root (final and every N.root.json) is 3 of 5 Ed25519. Monotonic versions against --state:
     each role's version must be higher than the recorded one, or equal with byte-identical metadata (the same
     already-trusted metadata, e.g. an unrotated root); a lower version, or an equal version with different bytes,
     is a rollback (REL-2). Every target is fetched through ngclient (length + sha256 checked) into a private temp
     dir, and the files outside tuf/ must be exactly the TUF targets. Stops on failure: later checks read only the
     TUF-verified copies.
  C. On the verified copies: REL-4 test-key markers (TEST_KEYS file or any role's signed.test_keys) refused without
     --allow-test-keys; REL-1 triple signature; REL-3 provenance signature, separate attest key, subject digests =
     sha256 of the artifacts (and = each --expect-sha256 PATH=HEX, used by the rebuild gate for build B); REL-5 SBOM
     digest named in the provenance = sha256(sbom.cdx.json) = its SHA256SUMS line.
  On PASS with --state DIR the trusted root and the role versions/digests are recorded for the next run.

Scope: REL-3 here compares the attested digest with the shipped artifact (build A) and with any --expect-sha256
digests; comparing with an independent build B is the release-rebuild gate (D7), which passes B's digest here.

--self-test builds fixture releases with fresh throwaway keys in a temp dir (keys deleted afterwards; the generator
is ci/release/fixtures/gen_release.py, which holds no keys), checks the clean ones pass, and checks each mutant is
refused with exactly its own reason tag.
"""

import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS_LOCK = os.path.join(os.path.dirname(HERE), "tools.lock")
# Used only while ci/tools.lock has no `#py:` rows (P6-spec-002 pins them). Installed with
# pip --require-hashes --no-deps --only-binary :all: (hashes in the P6-oracle-release-001 report).
FALLBACK_PINS = {
    "tuf": "7.0.1",
    "securesystemslib": "1.6.0",
    "urllib3": "2.8.0",
    "cryptography": "50.0.2",
    "cffi": "2.1.1",
    "pycparser": "3.12",
}
REQUIRED_PY = ("tuf", "securesystemslib", "cryptography")
ALGS = ("ed25519", "slh-dsa-sha2-128s", "ml-dsa-87")
OSSL_KEYTYPE = {"ed25519": "ED25519", "slh-dsa-sha2-128s": "SLH-DSA-SHA2-128s", "ml-dsa-87": "ML-DSA-87"}
SUBJECT_RE = re.compile(rb"\Aaegis-release-v1 sha256:([0-9a-f]{64})\n\Z")
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
NAME = r"[A-Za-z0-9._-]+"
ARTIFACT_RE = re.compile(rf"\Aartifacts/{NAME}\Z")
ROOT_RE = re.compile(r"\A([1-9][0-9]{0,8})\.root\.json\Z")
DSSE_TYPE = "application/vnd.in-toto+json"
FIXED_TARGETS = {"SHA256SUMS", "sbom.cdx.json", "provenance.intoto.json", "attest/attest.pub.pem"} | {
    f"sigs/{a}.{e}" for a in ALGS for e in ("sig", "subject", "pub.pem")
}
OPTIONAL_TARGETS = {"TEST_KEYS"}
ROLES = ("root", "timestamp", "snapshot", "targets")
META_BASE = "aegis-release://metadata/"
TARGET_BASE = "aegis-release://targets/"
PRIVATE_PEM = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")


class Refuse(Exception):
    def __init__(self, tag, detail):
        super().__init__(f"{tag}: {detail}")
        self.tag, self.detail = tag, detail


# ---------------------------------------------------------------- environment


def ensure_tuf():
    try:
        import tuf  # noqa: F401
    except ImportError:
        if os.environ.get("AEGIS_RELEASE_VERIFY_REEXEC") == "1":
            raise
        py = os.environ.get("AEGIS_PY_TUF_PYTHON") or os.path.expanduser("~/aegis-ci/py-tuf/bin/python")
        if not os.access(py, os.X_OK):
            print(f"REASON D6 tool-missing: python-tuf not importable and no venv python at {py}")
            print(f"RELEASE-VERIFY: FAIL (D6 tool-missing: python-tuf not importable and no venv python at {py})")
            sys.exit(1)
        os.environ["AEGIS_RELEASE_VERIFY_REEXEC"] = "1"
        os.execv(py, [py, "-I", os.path.abspath(__file__)] + sys.argv[1:])
    from importlib import metadata as im

    pins, src = {}, "ci/tools.lock #py: rows"
    try:
        with open(TOOLS_LOCK, encoding="utf-8") as f:
            for line in f:
                if line.startswith("#py:"):
                    cols = line[4:].split()
                    if len(cols) >= 2:
                        pins[cols[0].lower()] = cols[1]
    except OSError:
        pass
    if not pins:
        pins, src = dict(FALLBACK_PINS), "verify.py FALLBACK_PINS (ci/tools.lock has no #py: rows)"
    for req in REQUIRED_PY:
        if req not in pins:
            raise Refuse("D6 tool-pin", f"{req} is not pinned in {src}")
    for name, want in pins.items():
        try:
            have = im.version(name)
        except im.PackageNotFoundError:
            raise Refuse("D6 tool-pin", f"{name} {want} pinned in {src} but not installed") from None
        if have != want:
            raise Refuse("D6 tool-pin", f"{name} installed {have}, pinned {want} in {src}")
    return src


def openssl_bin():
    exe = os.environ.get("AEGIS_OPENSSL", "/usr/bin/openssl")
    try:
        out = subprocess.run([exe, "version"], capture_output=True, check=True, text=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        raise Refuse("D6 openssl", f"{exe} not usable: {e}") from None
    m = re.match(r"OpenSSL (\d+)\.(\d+)\.(\d+)", out)
    if not m or (int(m[1]), int(m[2])) < (3, 5):
        raise Refuse("D6 openssl", f"need OpenSSL >= 3.5 for ML-DSA/SLH-DSA, got {out.strip()!r}")
    return exe


# ---------------------------------------------------------------- helpers


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def read(path):
    with open(path, "rb") as f:
        return f.read()


def _no_dup(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r}")
        d[k] = v
    return d


def strict_json(b, what, tag):
    def bad_const(c):
        raise ValueError(f"constant {c} not allowed")

    try:
        return json.loads(b.decode("utf-8"), object_pairs_hook=_no_dup, parse_constant=bad_const)
    except (UnicodeDecodeError, ValueError) as e:
        raise Refuse(tag, f"{what} is not strict JSON: {e}") from None


def b64(s, what, tag):
    if not isinstance(s, str):
        raise Refuse(tag, f"{what} is not a base64 string")
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        raise Refuse(tag, f"{what} is not valid base64") from None


def ossl_keytype(exe, pem_path):
    p = subprocess.run([exe, "pkey", "-pubin", "-in", pem_path, "-noout", "-text"], capture_output=True, text=True)
    if p.returncode != 0 or not p.stdout:
        return None
    first = p.stdout.splitlines()[0].strip()
    return first[: -len(" Public-Key:")] if first.endswith(" Public-Key:") else first


def ossl_raw_ed25519(exe, pem_path):
    p = subprocess.run([exe, "pkey", "-pubin", "-in", pem_path, "-outform", "DER"], capture_output=True)
    return p.stdout[-32:] if p.returncode == 0 and len(p.stdout) == 44 else None


def ossl_verify(exe, pub, msg_path, sig_path):
    p = subprocess.run(
        [exe, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", pub, "-in", msg_path, "-sigfile", sig_path],
        capture_output=True,
        text=True,
    )
    return p.returncode == 0 and "Signature Verified Successfully" in p.stdout


# ---------------------------------------------------------------- stage A: raw scan


def stage_a(rel):
    if not os.path.isdir(rel) or os.path.islink(rel):
        raise Refuse("D6 layout", f"{rel} is not a directory")
    files = set()
    for dp, dns, fns in os.walk(rel, followlinks=False):
        for n in dns + fns:
            p = os.path.join(dp, n)
            rp = os.path.relpath(p, rel).replace(os.sep, "/")
            if os.path.islink(p):
                raise Refuse("D6 non-regular-file", f"{rp} is a symlink")
            if n in fns:
                if not os.path.isfile(p):
                    raise Refuse("D6 non-regular-file", f"{rp} is not a regular file")
                if PRIVATE_PEM.search(read(p)):
                    raise Refuse("D-P2 private-key-material", f"{rp} contains a PEM private key block")
                files.add(rp)
    return files


# ---------------------------------------------------------------- stage B: TUF


def make_fetcher(rel):
    from tuf.api.exceptions import DownloadHTTPError
    from tuf.ngclient import FetcherInterface

    tufdir = os.path.join(rel, "tuf")
    seg = re.compile(rf"\A{NAME}\Z")

    class LocalFetcher(FetcherInterface):
        def _fetch(self, url):
            if url.startswith(META_BASE):
                name, base = url[len(META_BASE):], tufdir
                parts = [name]
            elif url.startswith(TARGET_BASE):
                name, base = url[len(TARGET_BASE):], rel
                parts = name.split("/")
                if parts[0] == "tuf":
                    raise DownloadHTTPError(f"{name}: tuf/ is not a target dir", 404)
            else:
                raise DownloadHTTPError(f"unexpected url {url}", 400)
            if not all(seg.match(s) and s not in (".", "..") for s in parts):
                raise DownloadHTTPError(f"bad path {name!r}", 400)
            p = os.path.join(base, *parts)
            if os.path.islink(p) or not os.path.isfile(p):
                raise DownloadHTTPError(f"{name} not found", 404)
            yield read(p)

    return LocalFetcher()


def check_root_policy(md, where):
    from tuf.api.metadata import Root

    root = md.signed
    if not isinstance(root, Root):
        raise Refuse("REL-2 root-policy", f"{where} is not root metadata")
    r = root.roles["root"]
    if len(r.keyids) != 5 or r.threshold != 3:
        raise Refuse("REL-2 root-policy", f"{where}: root role is {r.threshold} of {len(r.keyids)} (need 3 of 5)")
    for kid in r.keyids:
        k = root.keys.get(kid)
        if k is None or k.keytype != "ed25519" or k.scheme != "ed25519":
            raise Refuse("REL-2 root-policy", f"{where}: root key {kid[:16]} is not Ed25519")
    res = root.get_verification_result(Root.type, md.signed_bytes, md.signatures)
    if len(res.signed) < 3:
        raise Refuse("REL-2 root-threshold", f"{where}: {len(res.signed)}/5 valid root signatures (need 3)")


def tuf_error(e):
    from tuf.api import exceptions as x

    msg = f"{type(e).__name__}: {e}"
    if isinstance(e, x.UnsignedMetadataError):
        return Refuse("REL-2 root-threshold" if str(e).startswith("root ") else "REL-2 unsigned", msg)
    if isinstance(e, x.ExpiredMetadataError):
        return Refuse("REL-2 expired", msg)
    if isinstance(e, x.BadVersionNumberError):
        return Refuse("REL-2 rollback", msg)
    if isinstance(e, (x.LengthOrHashMismatchError, x.DownloadLengthMismatchError)):
        return Refuse("REL-2 target-hash", msg)
    return Refuse("REL-2 tuf-invalid", msg)


def stage_b(rel, files, args, work):
    from tuf.api import exceptions as x
    from tuf.api.metadata import Metadata
    from tuf.ngclient import Updater

    # tuf/ inventory: consecutive N.root.json plus the three top-level roles, nothing else
    tuf_files = {f[4:] for f in files if f.startswith("tuf/")}
    roots = {}
    for n in tuf_files - {"timestamp.json", "snapshot.json", "targets.json"}:
        m = ROOT_RE.match(n)
        if not m:
            raise Refuse("REL-2 unlisted-file", f"tuf/{n} is not a TUF metadata file")
        roots[int(m[1])] = n
    if not {"timestamp.json", "snapshot.json", "targets.json"} <= tuf_files:
        raise Refuse("REL-2 tuf-invalid", "tuf/ lacks timestamp.json, snapshot.json or targets.json")
    if not roots or sorted(roots) != list(range(1, max(roots) + 1)):
        raise Refuse("REL-2 tuf-invalid", f"tuf/ root versions {sorted(roots)} are not 1..N")

    # trust anchor
    state_root = os.path.join(args.state, "root.json") if args.state else None
    tofu = False
    if state_root and os.path.isfile(state_root):
        boot, anchor = read(state_root), f"state {state_root}"
    elif args.trusted_root:
        try:
            boot = read(args.trusted_root)
        except OSError as e:
            raise Refuse("REL-2 no-trust-anchor", f"--trusted-root: {e}") from None
        anchor = f"--trusted-root {args.trusted_root}"
    elif args.allow_test_keys:
        boot, anchor, tofu = read(os.path.join(rel, "tuf", "1.root.json")), "tuf/1.root.json (TOFU, test keys)", True
    else:
        raise Refuse("REL-2 no-trust-anchor", "no --trusted-root and no --state root (TOFU only with --allow-test-keys)")

    mdir, vdir = os.path.join(work, "meta"), os.path.join(work, "verified")
    os.makedirs(mdir)
    os.makedirs(vdir)
    try:
        boot_md = Metadata.from_bytes(boot)
    except (ValueError, x.RepositoryError) as e:
        raise Refuse("REL-2 tuf-invalid", f"trust anchor {anchor} is not TUF root metadata: {e}") from None
    check_root_policy(boot_md, f"trust anchor {anchor}")
    try:
        up = Updater(mdir, META_BASE, vdir, TARGET_BASE, fetcher=make_fetcher(rel), bootstrap=boot)
        up.refresh()
    except (x.RepositoryError, x.DownloadError, ValueError) as e:
        raise tuf_error(e) from None

    # policy on every root in the release and on the final trusted root
    for v in sorted(roots):
        try:
            md = Metadata.from_bytes(read(os.path.join(rel, "tuf", roots[v])))
        except (ValueError, x.RepositoryError) as e:
            raise Refuse("REL-2 tuf-invalid", f"tuf/{roots[v]}: {e}") from None
        if md.signed.version != v:
            raise Refuse("REL-2 tuf-invalid", f"tuf/{roots[v]} has version {md.signed.version}")
        check_root_policy(md, f"tuf/{roots[v]}")
    trusted = {r: read(os.path.join(mdir, f"{r}.json")) for r in ROLES}
    mds = {r: Metadata.from_bytes(b) for r, b in trusted.items()}
    check_root_policy(mds["root"], "final trusted root")

    # monotonic versions against recorded state (REL-2)
    prev = {}
    if args.state and os.path.isfile(os.path.join(args.state, "aegis-state.json")):
        prev = strict_json(read(os.path.join(args.state, "aegis-state.json")), "state", "REL-2 state-invalid")
        prev = prev.get("roles", {}) if isinstance(prev, dict) else {}
    for r in ROLES:
        p = prev.get(r)
        if not p:
            continue
        nv, ns = mds[r].signed.version, sha256(trusted[r])
        if nv < p["version"] or (nv == p["version"] and ns != p["sha256"]):
            how = "lower than" if nv < p["version"] else "equal to, with different bytes than,"
            raise Refuse("REL-2 rollback", f"{r} version {nv} is {how} the trusted version {p['version']}")

    # targets: inventory both ways, then fetch each through ngclient (length + sha256)
    tlist = set(mds["targets"].signed.targets)
    if mds["targets"].signed.delegations is not None:
        raise Refuse("REL-2 tuf-invalid", "targets delegates; the release contract has no delegations")
    outside = {f for f in files if not f.startswith("tuf/")}
    if outside - tlist:
        raise Refuse("REL-2 unlisted-file", f"not listed in targets.json: {sorted(outside - tlist)}")
    unknown = {t for t in tlist if t not in FIXED_TARGETS | OPTIONAL_TARGETS and not ARTIFACT_RE.match(t)}
    if unknown:
        raise Refuse("D6 layout", f"targets outside the release contract: {sorted(unknown)}")
    for t in sorted(tlist):
        try:
            info = up.get_targetinfo(t)
            if info is None:
                raise Refuse("REL-2 tuf-invalid", f"target {t} not resolvable")
            up.download_target(info, filepath=os.path.join(vdir, *t.split("/")))
        except (x.RepositoryError, x.DownloadError) as e:
            if isinstance(e, x.DownloadHTTPError) and e.status_code == 404 and t in FIXED_TARGETS:
                continue  # a listed-but-absent required file: reported by its own check in stage C
            raise tuf_error(e) from None
    return {"vdir": vdir, "mds": mds, "trusted": trusted, "tofu": tofu, "anchor": anchor}


# ---------------------------------------------------------------- stage C: content checks


def check_test_keys(v, mds, args):
    marks = []
    if os.path.isfile(os.path.join(v, "TEST_KEYS")):
        marks.append("TEST_KEYS file")
    for r in ROLES:
        tk = mds[r].signed.unrecognized_fields.get("test_keys")
        if tk is True:
            marks.append(f"{r}.signed.test_keys")
        elif tk not in (None, False):
            raise Refuse("REL-4 test-keys", f"{r}.signed.test_keys is {tk!r}, not a boolean")
    if marks and not args.allow_test_keys:
        raise Refuse("REL-4 test-keys", f"test-key release ({', '.join(marks)}) refused without --allow-test-keys")
    return bool(marks)


def parse_sums(v):
    p = os.path.join(v, "SHA256SUMS")
    if not os.path.isfile(p):
        raise Refuse("REL-1 sums-mismatch", "SHA256SUMS missing")
    raw = read(p)
    lines = raw.split(b"\n")
    if lines[-1] != b"" or len(lines) < 2:
        raise Refuse("REL-1 sums-mismatch", "SHA256SUMS empty or not LF-terminated")
    out, order = {}, []
    for ln in lines[:-1]:
        m = re.fullmatch(rb"([0-9a-f]{64})  (\S+)", ln)
        if not m:
            raise Refuse("REL-1 sums-mismatch", f"bad SHA256SUMS line {ln[:100]!r}")
        path = m[2].decode()
        if path in out:
            raise Refuse("REL-1 sums-mismatch", f"duplicate SHA256SUMS path {path}")
        out[path] = m[1].decode()
        order.append(path)
    if order != sorted(order):
        raise Refuse("REL-1 sums-mismatch", "SHA256SUMS not sorted by path")
    return raw, out


def check_sums(v, sums, files):
    arts = {f for f in files if ARTIFACT_RE.match(f)}
    if not arts:
        raise Refuse("D6 layout", "no artifacts/<name>")
    if set(sums) != arts | {"sbom.cdx.json"}:
        raise Refuse("REL-1 sums-mismatch", f"SHA256SUMS paths {sorted(sums)} != artifacts + sbom.cdx.json")
    for path, want in sums.items():
        fp = os.path.join(v, *path.split("/"))
        if not os.path.isfile(fp):
            raise Refuse("REL-1 sums-mismatch", f"{path} listed in SHA256SUMS but missing")
        if sha256(read(fp)) != want:
            raise Refuse("REL-1 sums-mismatch", f"{path}: sha256 differs from SHA256SUMS")
    return arts


def check_triple(v, exe, sums_raw):
    want = sha256(sums_raw)
    digests = {}
    for alg in ALGS:
        paths = {e: os.path.join(v, "sigs", f"{alg}.{e}") for e in ("sig", "subject", "pub.pem")}
        missing = [f"sigs/{alg}.{e}" for e, p in paths.items() if not os.path.isfile(p)]
        if missing:
            raise Refuse("REL-1 signature-missing", f"{', '.join(missing)} missing (all three signatures required)")
        kt = ossl_keytype(exe, paths["pub.pem"])
        if kt != OSSL_KEYTYPE[alg]:
            raise Refuse("REL-1 key-algorithm", f"sigs/{alg}.pub.pem is {kt!r}, need {OSSL_KEYTYPE[alg]}")
        m = SUBJECT_RE.match(read(paths["subject"]))
        if not m:
            raise Refuse("REL-1 digest-mismatch", f"sigs/{alg}.subject is not 'aegis-release-v1 sha256:<hex>\\n'")
        if not ossl_verify(exe, paths["pub.pem"], paths["subject"], paths["sig"]):
            raise Refuse("REL-1 signature-invalid", f"{alg} signature does not verify over sigs/{alg}.subject")
        digests[alg] = m[1].decode()
    if len(set(digests.values())) != 1:
        raise Refuse("REL-1 digest-mismatch", f"signatures are over different digests: {digests}")
    if digests["ed25519"] != want:
        raise Refuse("REL-1 digest-mismatch", f"signed digest {digests['ed25519']} != sha256(SHA256SUMS) {want}")


def check_provenance(v, exe, sums, arts, mds, args):
    tag = "REL-3 provenance-invalid"
    pp, kp = os.path.join(v, "provenance.intoto.json"), os.path.join(v, "attest", "attest.pub.pem")
    for p, n in ((pp, "provenance.intoto.json"), (kp, "attest/attest.pub.pem")):
        if not os.path.isfile(p):
            raise Refuse(tag, f"{n} missing")
    env = strict_json(read(pp), "provenance.intoto.json", tag)
    if not isinstance(env, dict) or set(env) != {"payloadType", "payload", "signatures"}:
        raise Refuse(tag, "DSSE envelope must have exactly payloadType, payload, signatures")
    if env["payloadType"] != DSSE_TYPE:
        raise Refuse(tag, f"payloadType {env['payloadType']!r} != {DSSE_TYPE}")
    sigs = env["signatures"]
    if not isinstance(sigs, list) or len(sigs) != 1 or not isinstance(sigs[0], dict):
        raise Refuse(tag, "DSSE envelope needs exactly one signature")
    payload = b64(env["payload"], "payload", tag)
    sig = b64(sigs[0].get("sig"), "signature", tag)

    # separate attest key (D6 job 3)
    if ossl_keytype(exe, kp) != "ED25519":
        raise Refuse("REL-3 attest-key-reuse", "attest/attest.pub.pem is not an Ed25519 key")
    araw = ossl_raw_ed25519(exe, kp)
    others = {"release ed25519 key": ossl_raw_ed25519(exe, os.path.join(v, "sigs", "ed25519.pub.pem"))}
    for kid, k in mds["root"].signed.keys.items():
        if k.keytype == "ed25519":
            try:
                others[f"TUF key {kid[:16]}"] = bytes.fromhex(k.keyval.get("public", ""))
            except ValueError:
                pass
    for what, raw in others.items():
        if araw is not None and raw == araw:
            raise Refuse("REL-3 attest-key-reuse", f"attest key is the {what}; the attest job needs its own key")

    t = DSSE_TYPE.encode()
    pae = b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)
    with tempfile.NamedTemporaryFile(dir=os.path.dirname(v)) as mf, tempfile.NamedTemporaryFile(
        dir=os.path.dirname(v)
    ) as sf:
        mf.write(pae)
        mf.flush()
        sf.write(sig)
        sf.flush()
        if not ossl_verify(exe, kp, mf.name, sf.name):
            raise Refuse("REL-3 attest-signature", "DSSE signature does not verify with attest/attest.pub.pem")

    st = strict_json(payload, "in-toto statement", tag)
    if not isinstance(st, dict) or st.get("_type") != "https://in-toto.io/Statement/v1":
        raise Refuse(tag, "payload is not an in-toto Statement v1")
    if st.get("predicateType") != "https://slsa.dev/provenance/v1":
        raise Refuse(tag, f"predicateType {st.get('predicateType')!r} is not SLSA provenance v1")
    pred = st.get("predicate")
    bd = pred.get("buildDefinition") if isinstance(pred, dict) else None
    rd = pred.get("runDetails") if isinstance(pred, dict) else None
    if not (isinstance(bd, dict) and isinstance(bd.get("buildType"), str) and bd["buildType"]
            and isinstance(bd.get("externalParameters"), dict)):
        raise Refuse(tag, "predicate.buildDefinition needs buildType and externalParameters")
    if not (isinstance(rd, dict) and isinstance(rd.get("builder"), dict) and isinstance(rd["builder"].get("id"), str)
            and rd["builder"]["id"]):
        raise Refuse(tag, "predicate.runDetails.builder.id missing")

    subj = st.get("subject")
    if not isinstance(subj, list) or not subj:
        raise Refuse(tag, "statement has no subject")
    attested = {}
    for s in subj:
        d = s.get("digest") if isinstance(s, dict) else None
        if not (isinstance(d, dict) and isinstance(s.get("name"), str) and isinstance(d.get("sha256"), str)
                and HEX64.match(d["sha256"])) or s["name"] in attested:
            raise Refuse(tag, f"bad or duplicate subject {s!r:.120}")
        attested[s["name"]] = d["sha256"]
    if set(attested) != arts:
        raise Refuse("REL-3 subject-mismatch", f"attested subjects {sorted(attested)} != artifacts {sorted(arts)}")
    for a in sorted(arts):
        real = sha256(read(os.path.join(v, *a.split("/"))))
        if attested[a] != real:
            raise Refuse("REL-3 subject-mismatch", f"{a}: attested {attested[a]} != sha256 {real}")
    for name, want in args.expect:
        if name not in attested:
            raise Refuse("REL-3 rebuild-mismatch", f"--expect-sha256 names {name}, which is not an attested subject")
        if attested[name] != want:
            raise Refuse("REL-3 rebuild-mismatch", f"{name}: attested {attested[name]} != rebuild {want}")

    bps = rd.get("byproducts")
    sb = [b for b in bps if isinstance(b, dict) and b.get("name") == "sbom.cdx.json"] if isinstance(bps, list) else []
    if len(sb) != 1 or not isinstance(sb[0].get("digest"), dict) or not HEX64.match(str(sb[0]["digest"].get("sha256"))):
        raise Refuse("REL-5 sbom-mismatch", "provenance must name exactly one sbom.cdx.json byproduct with sha256")
    return sb[0]["digest"]["sha256"]


def check_sbom(v, sums, attested_sbom):
    p = os.path.join(v, "sbom.cdx.json")
    if not os.path.isfile(p):
        raise Refuse("REL-5 sbom-mismatch", "sbom.cdx.json missing")
    raw = read(p)
    real = sha256(raw)
    if real != attested_sbom:
        raise Refuse("REL-5 sbom-mismatch", f"sbom.cdx.json sha256 {real} != attested {attested_sbom}")
    if sums.get("sbom.cdx.json") != real:
        raise Refuse("REL-5 sbom-mismatch", "sbom.cdx.json sha256 != its SHA256SUMS line")
    bom = strict_json(raw, "sbom.cdx.json", "REL-5 sbom-invalid")
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX" or not isinstance(bom.get("specVersion"), str):
        raise Refuse("REL-5 sbom-invalid", "sbom.cdx.json is not a CycloneDX document")


# ---------------------------------------------------------------- driver


def verify(args):
    """Returns the list of Refuse; empty = PASS."""
    exe = openssl_bin()
    rel = os.path.abspath(args.release)
    files = stage_a(rel)
    work = tempfile.mkdtemp(prefix="aegis-relverify-")
    try:
        b = stage_b(rel, files, args, work)
        v, mds = b["vdir"], b["mds"]
        vfiles = {f for f in files if not f.startswith("tuf/")}
        fails = []

        def run(fn, *a):
            try:
                return fn(*a)
            except Refuse as e:
                fails.append(e)
                return None

        marked = run(check_test_keys, v, mds, args)
        parsed = run(parse_sums, v)
        sums = parsed[1] if parsed else {}
        arts = run(check_sums, v, sums, vfiles) if parsed else None
        if parsed:
            run(check_triple, v, exe, parsed[0])
        att_sbom = run(check_provenance, v, exe, sums, arts or set(), mds, args) if arts is not None else None
        if att_sbom:
            run(check_sbom, v, sums, att_sbom)
        if b["tofu"] and marked is False:
            fails.append(Refuse("REL-2 no-trust-anchor", "TOFU on tuf/1.root.json is allowed only for test-key releases"))
        if not fails and args.state:
            os.makedirs(args.state, exist_ok=True)
            st = {"v": 1, "roles": {r: {"version": mds[r].signed.version, "sha256": sha256(b["trusted"][r])}
                                    for r in ROLES}}
            for name, data in (("root.json", b["trusted"]["root"]), ("aegis-state.json",
                                                                    json.dumps(st, indent=1).encode() + b"\n")):
                tmp = os.path.join(args.state, f".{name}.tmp")
                with open(tmp, "wb") as f:
                    f.write(data)
                os.replace(tmp, os.path.join(args.state, name))
        return fails
    finally:
        shutil.rmtree(work, ignore_errors=True)


class Args:
    def __init__(self):
        self.allow_test_keys = False
        self.trusted_root = None
        self.state = None
        self.expect = []
        self.release = None
        self.self_test = False


def parse_args(argv):
    a, i = Args(), 0
    while i < len(argv):
        x = argv[i]
        if x == "--allow-test-keys":
            a.allow_test_keys = True
        elif x == "--self-test":
            a.self_test = True
        elif x in ("--trusted-root", "--state", "--expect-sha256") and i + 1 < len(argv):
            i += 1
            if x == "--trusted-root":
                a.trusted_root = argv[i]
            elif x == "--state":
                a.state = argv[i]
            else:
                name, sep, hx = argv[i].partition("=")
                if not sep or not HEX64.match(hx) or not ARTIFACT_RE.match(name):
                    raise Refuse("D6 usage", f"--expect-sha256 wants artifacts/<name>=<64 hex>, got {argv[i]!r}")
                a.expect.append((name, hx))
        elif not x.startswith("-") and a.release is None:
            a.release = x
        else:
            raise Refuse("D6 usage", f"unexpected argument {x!r}")
        i += 1
    if a.self_test == (a.release is not None):
        raise Refuse("D6 usage", "give exactly one of RELEASE_DIR or --self-test")
    return a


def main(argv):
    try:
        args = parse_args(argv)
    except Refuse as e:
        print(f"REASON {e}")
        print(f"RELEASE-VERIFY: FAIL ({e})")
        print(__doc__.split("\n\n")[1])
        return 2
    try:
        src = ensure_tuf()
        if args.self_test:
            try:
                return self_test(src)
            except Exception as e:  # a fixture generator crash is a self-test failure, never a pass
                print(f"REASON self-test: {type(e).__name__}: {e}")
                print(f"RELEASE-VERIFY: FAIL (self-test: {type(e).__name__}: {e})")
                return 1
        fails = verify(args)
    except Refuse as e:
        fails = [e]
    for f in fails:
        print(f"REASON {f}")
    if fails:
        print(f"RELEASE-VERIFY: FAIL ({fails[0]})")
        return 1
    print("RELEASE-VERIFY: PASS")
    return 0


# ---------------------------------------------------------------- self-test

# (mutant, expected sole reason tag, verifier flags). "@root" = the run's root v1, "@self" = the mutant's own
# tuf/1.root.json, "@state" = a copy of the state recorded after the clean v1 and v2 runs.
SELF_TEST_CASES = (
    ("root-2of5", "REL-2 root-threshold", ["--allow-test-keys", "--trusted-root", "@self"]),
    ("root-rotation-2of5", "REL-2 root-threshold", ["--allow-test-keys", "--trusted-root", "@root"]),
    ("root-policy-threshold2", "REL-2 root-policy", ["--allow-test-keys", "--trusted-root", "@self"]),
    ("sig-bad-ed25519", "REL-1 signature-invalid", ["--allow-test-keys", "--trusted-root", "@root"]),
    ("sig-bad-slh-dsa-sha2-128s", "REL-1 signature-invalid", ["--allow-test-keys", "--trusted-root", "@root"]),
    ("sig-bad-ml-dsa-87", "REL-1 signature-invalid", ["--allow-test-keys", "--trusted-root", "@root"]),
    ("sig-missing-ml-dsa-87", "REL-1 signature-missing", ["--allow-test-keys", "--trusted-root", "@root"]),
    ("sig-other-digest", "REL-1 digest-mismatch", ["--allow-test-keys", "--trusted-root", "@root"]),
    ("sig-wrong-alg-key", "REL-1 key-algorithm", ["--allow-test-keys", "--trusted-root", "@root"]),
    ("sums-mismatch", "REL-1 sums-mismatch", ["--allow-test-keys", "--trusted-root", "@root"]),
    ("test-keys-no-flag", "REL-4 test-keys", ["--trusted-root", "@root"]),
    ("no-marker-file", "REL-4 test-keys", ["--trusted-root", "@root"]),
    ("rollback-targets", "REL-2 rollback", ["--allow-test-keys", "--state", "@state"]),
    ("equal-version-timestamp", "REL-2 rollback", ["--allow-test-keys", "--state", "@state"]),
    ("timestamp-expired", "REL-2 expired", ["--allow-test-keys", "--trusted-root", "@root"]),
    ("targets-expired", "REL-2 expired", ["--allow-test-keys", "--trusted-root", "@root"]),
    ("sbom-mismatch", "REL-5 sbom-mismatch", ["--allow-test-keys", "--trusted-root", "@root"]),
    ("subject-mismatch", "REL-3 subject-mismatch", ["--allow-test-keys", "--trusted-root", "@root"]),
    ("attest-sig-bad", "REL-3 attest-signature", ["--allow-test-keys", "--trusted-root", "@root"]),
    ("attest-key-reuse", "REL-3 attest-key-reuse", ["--allow-test-keys", "--trusted-root", "@root"]),
    ("rebuild-mismatch", "REL-3 rebuild-mismatch", ["--allow-test-keys", "--trusted-root", "@root",
                                                     "--expect-sha256", "artifacts/aegis-floor=" + "0" * 64]),
    ("artifact-tampered", "REL-2 target-hash", ["--allow-test-keys", "--trusted-root", "@root"]),
    ("unlisted-file", "REL-2 unlisted-file", ["--allow-test-keys", "--trusted-root", "@root"]),
    ("private-key", "D-P2 private-key-material", ["--allow-test-keys", "--trusted-root", "@root"]),
    ("tofu-without-test-keys", "REL-2 no-trust-anchor", ["--allow-test-keys"]),
    ("no-anchor", "REL-2 no-trust-anchor", []),
)


def _invoke(release, flags):
    env = dict(os.environ, AEGIS_RELEASE_VERIFY_REEXEC="1")
    p = subprocess.run([sys.executable, "-I", os.path.abspath(__file__)] + flags + [release],
                       capture_output=True, text=True, env=env)
    lines = p.stdout.splitlines()
    tags = {ln[len("REASON "):].split(":", 1)[0] for ln in lines if ln.startswith("REASON ")}
    final = lines[-1] if lines else f"(no output; stderr: {p.stderr.strip()[-300:]})"
    return p.returncode, tags, final


def self_test(pin_src):
    import importlib.util

    spec = importlib.util.spec_from_file_location("aegis_gen_release", os.path.join(HERE, "fixtures", "gen_release.py"))
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    exe = openssl_bin()
    bad = []
    tmp = tempfile.mkdtemp(prefix="aegis-relverify-selftest-")
    try:
        keys = gen.Keys(os.path.join(tmp, "keys"), exe)
        root1 = os.path.join(tmp, "root1.json")
        state = os.path.join(tmp, "state")

        def rel(name, **kw):
            return gen.build_release(os.path.join(tmp, name), keys, **kw)

        def clean(name, release, flags):
            rc, tags, final = _invoke(release, flags)
            ok = rc == 0 and not tags and final == "RELEASE-VERIFY: PASS"
            print(f"SELF-TEST clean {name}: {'ok' if ok else 'BAD'} ({final})")
            if not ok:
                bad.append(f"clean {name} not accepted: {final}")

        r1 = rel("r1")
        shutil.copyfile(os.path.join(r1, "tuf", "1.root.json"), root1)
        clean("v1 pinned root + state", r1, ["--allow-test-keys", "--trusted-root", root1, "--state", state])
        clean("v1 TOFU (test keys)", r1, ["--allow-test-keys"])
        r2 = rel("r2", versions={"targets": 2, "snapshot": 2, "timestamp": 2, "root": 2})
        clean("v2 after v1 (monotonic, root rotation 1->2)", r2, ["--allow-test-keys", "--state", state])
        clean("v2 again (identical metadata)", r2, ["--allow-test-keys", "--state", state])
        prod = rel("prod", test_keys=False)
        clean("production-shaped, pinned root, no flag", prod, ["--trusted-root", os.path.join(prod, "tuf", "1.root.json")])
        for r in (r1, r2, prod):
            for dp, _d, fs in os.walk(r):
                if any(b"PRIVATE KEY" in read(os.path.join(dp, f)) for f in fs):
                    bad.append(f"clean release {os.path.basename(r)} contains private key material")

        for mut, want, flags in SELF_TEST_CASES:
            st = os.path.join(tmp, f"state-{mut}")
            kw = {}
            if mut == "root-rotation-2of5":
                m, kw = mut, {"versions": {"root": 2}}
            elif mut in ("test-keys-no-flag", "no-anchor"):
                m = None
            elif mut == "tofu-without-test-keys":
                m, kw = None, {"test_keys": False}
            elif mut == "rollback-targets":
                m, kw = None, {"versions": {"root": 2, "targets": 1, "snapshot": 3, "timestamp": 3}}
            elif mut == "equal-version-timestamp":
                m, kw = None, {"versions": {"root": 2, "targets": 3, "snapshot": 3, "timestamp": 2}}
            elif mut == "rebuild-mismatch":
                m = None
            else:
                m = mut
            r = rel(f"m-{mut}", mut=m, **kw)
            sub = {"@root": root1, "@self": os.path.join(r, "tuf", "1.root.json"), "@state": st}
            if "@state" in flags:
                shutil.copytree(state, st)
            rc, tags, final = _invoke(r, [sub.get(f, f) for f in flags])
            ok = rc == 1 and tags == {want} and final.startswith(f"RELEASE-VERIFY: FAIL ({want}:")
            print(f"SELF-TEST mutant {mut}: {'refused' if ok else 'BAD'} (want {want}; got {sorted(tags)}; {final})")
            if not ok:
                bad.append(f"mutant {mut}: want sole reason {want}, got {sorted(tags)} / {final}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if os.path.exists(tmp):
        bad.append(f"temp dir with keys not removed: {tmp}")
    n = len(SELF_TEST_CASES)
    print(f"tool pins checked against {pin_src}")
    if bad:
        for b in bad:
            print(f"REASON self-test: {b}")
        print(f"RELEASE-VERIFY: FAIL (self-test: {bad[0]})")
        return 1
    print(f"RELEASE-VERIFY: PASS (self-test: 5 clean releases accepted; {n}/{n} mutants refused, each with its own "
          "reason; throwaway keys deleted)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
