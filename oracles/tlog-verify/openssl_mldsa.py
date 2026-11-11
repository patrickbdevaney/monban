#!/usr/bin/env python3
"""tlog-verify --openssl-mldsa (unit P8-audit-001, gate tlog-mldsa-openssl, residual R10).

Independent cryptographic check of the monban audit checkpoint cosignature: the signed-note body and the ML-DSA-87
cosignature are pulled out of a checkpoint written by monban-bin, and OpenSSL 3.5.3 verifies them with
`pkeyutl -verify -rawin` (pure ML-DSA-87, FIPS 204 Algorithm 3: empty context string, message-encoding 1, no
prehash) against the ML-DSA-87 public key monban-bin published in its `vkey` file. The Ed25519 log signature is
verified by OpenSSL the same way. No monban code and no aws-lc code is on the verify path.

    openssl_mldsa.py verify   --openssl O --vkey F --checkpoint C [--checkpoint C ...]
    openssl_mldsa.py binary   --openssl O --binary B --work D      boot monban-bin, collect checkpoints, verify
    openssl_mldsa.py selftest --openssl O --binary B --work D      controls + mutants (each must fail for its reason)

Last line: TLOG-MLDSA-OPENSSL: PASS|FAIL (...) or TLOG-MLDSA-OPENSSL SELF-TEST: PASS|FAIL (...). Exit 0 only on PASS.
Stdlib only; run with python3 -I.
"""
import base64
import hashlib
import http.client
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

NAME = "TLOG-MLDSA-OPENSSL"
MLDSA87_SIG_TYPE = b"\xffaegis-mldsa87-note-v1"
ED25519_SIG_TYPE = b"\x01"
MLDSA87_PK_LEN = 2592
MLDSA87_SIG_LEN = 4627
ED25519_PK_LEN = 32
ED25519_SIG_LEN = 64
# SubjectPublicKeyInfo prefixes (RFC 9881 id-ml-dsa-87 = 2.16.840.1.101.3.4.3.19; RFC 8410 id-Ed25519 = 1.3.101.112).
MLDSA87_SPKI_PREFIX = bytes.fromhex("30820a32300b060960864801650304031303820a2100")
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
EM_DASH = "—"


class Fail(Exception):
    """A verification failure with a category (the self-test checks the category, not just red)."""

    def __init__(self, cat, msg):
        super().__init__(f"{cat}: {msg}")
        self.cat = cat


def key_id(name, sig_type, pk):
    return hashlib.sha256(name.encode() + b"\n" + sig_type + pk).digest()[:4]


def b64d(s, what):
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as e:
        raise Fail("parse", f"{what}: bad base64 ({e})")


def parse_vkeys(text):
    """vkey lines `name+hexid+base64(type||pk)` -> {"ed25519": (name, id, pk), "mldsa87": (name, id, pk)}."""
    keys = {}
    for ln in text.splitlines():
        if not ln.strip():
            continue
        parts = ln.split("+", 2)
        if len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{8}", parts[1]):
            raise Fail("key", f"malformed vkey line {ln[:60]!r}")
        name, idhex, b64 = parts
        mat = b64d(b64, "vkey")
        if mat.startswith(MLDSA87_SIG_TYPE):
            alg, st, plen = "mldsa87", MLDSA87_SIG_TYPE, MLDSA87_PK_LEN
        elif mat.startswith(ED25519_SIG_TYPE):
            alg, st, plen = "ed25519", ED25519_SIG_TYPE, ED25519_PK_LEN
        else:
            raise Fail("key", f"vkey {name}: unknown signature type 0x{mat[:1].hex()}")
        pk = mat[len(st):]
        if len(pk) != plen:
            raise Fail("key", f"vkey {name} ({alg}): public key is {len(pk)} bytes, want {plen}")
        kid = bytes.fromhex(idhex)
        if key_id(name, st, pk) != kid:
            raise Fail("key", f"vkey {name} ({alg}): key ID {idhex} does not match SHA-256(name||0A||type||pk)[:4]")
        if alg in keys:
            raise Fail("key", f"two {alg} vkeys")
        keys[alg] = (name, kid, pk)
    return keys


def parse_note(data):
    """signed-note: text (ends in \\n, no blank line) || \\n || ("— name base64\\n")+ -> (text bytes, [(name, blob)])."""
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Fail("parse", "note is not UTF-8")
    i = s.find("\n\n")
    if i < 0 or not s.endswith("\n"):
        raise Fail("parse", "no signature block")
    text, sigblock = s[: i + 1], s[i + 2:]
    sigs = []
    for ln in sigblock[:-1].split("\n"):
        m = re.fullmatch(EM_DASH + r" ([^\s+]+) ([A-Za-z0-9+/=]+)", ln)
        if not m:
            raise Fail("parse", f"malformed signature line {ln[:60]!r}")
        sigs.append((m.group(1), b64d(m.group(2), "signature")))
    lines = text.split("\n")
    if len(lines) != 4 or lines[3] != "":
        raise Fail("parse", "checkpoint text is not exactly origin / size / root")
    if not re.fullmatch(r"0|[1-9][0-9]{0,19}", lines[1]):
        raise Fail("parse", f"size {lines[1]!r} is not canonical decimal")
    root = b64d(lines[2], "root")
    if len(root) != 32 or base64.b64encode(root).decode() != lines[2]:
        raise Fail("parse", "root is not canonical base64 of 32 bytes")
    return text.encode("utf-8"), lines[0], sigs


def find_sig(sigs, key, alg, siglen):
    name, kid, _ = key
    got = [b for n, b in sigs if n == name and b[:4] == kid]
    if not got:
        raise Fail("cosignature-missing" if alg == "mldsa87" else "signature-missing",
                   f"no {alg} signature line for {name}+{kid.hex()}")
    if len(got) > 1:
        raise Fail("parse", f"{len(got)} {alg} signature lines for one key")
    sig = got[0][4:]
    if len(sig) != siglen:
        raise Fail("parse", f"{alg} signature is {len(sig)} bytes, want {siglen}")
    return sig


def pem(der):
    b = base64.b64encode(der).decode()
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + \
        "\n-----END PUBLIC KEY-----\n"


def ossl_verify(openssl, work, tag, spki, msg, sig):
    """OpenSSL pkeyutl -verify -rawin (one-shot, no digest). True iff OpenSSL says verified and exits 0."""
    d = tempfile.mkdtemp(prefix=f"v-{tag}-", dir=work)
    kp, mp, sp = (os.path.join(d, n) for n in ("pub.pem", "msg", "sig"))
    with open(kp, "w") as f:
        f.write(pem(spki))
    with open(mp, "wb") as f:
        f.write(msg)
    with open(sp, "wb") as f:
        f.write(sig)
    r = subprocess.run([openssl, "pkeyutl", "-verify", "-pubin", "-inkey", kp, "-rawin", "-in", mp, "-sigfile", sp],
                       capture_output=True, timeout=60)
    shutil.rmtree(d, ignore_errors=True)
    out = r.stdout.decode(errors="replace")
    if r.returncode == 0 and "Signature Verified Successfully" in out:
        return True
    if r.returncode == 1 and "Signature Verification Failure" in out:
        return False
    raise Fail("openssl", f"unexpected OpenSSL result rc={r.returncode}: {out.strip()} "
                          f"{r.stderr.decode(errors='replace').strip()[:300]}")


def verify_checkpoint(openssl, work, keys, data):
    """Verify one checkpoint; raises Fail with a category on the first failed check."""
    if "mldsa87" not in keys:
        raise Fail("key", "no ML-DSA-87 vkey published (the log has no ML-DSA-87 cosigner)")
    if "ed25519" not in keys:
        raise Fail("key", "no Ed25519 log vkey published")
    text, origin, sigs = parse_note(data)
    if origin != keys["ed25519"][0]:
        raise Fail("parse", f"origin {origin!r} is not the log key name {keys['ed25519'][0]!r}")
    msig = find_sig(sigs, keys["mldsa87"], "mldsa87", MLDSA87_SIG_LEN)
    if not ossl_verify(openssl, work, "mldsa", MLDSA87_SPKI_PREFIX + keys["mldsa87"][2], text, msig):
        raise Fail("mldsa-verify", "OpenSSL ML-DSA-87 verify failed")
    esig = find_sig(sigs, keys["ed25519"], "ed25519", ED25519_SIG_LEN)
    if not ossl_verify(openssl, work, "ed", ED25519_SPKI_PREFIX + keys["ed25519"][2], text, esig):
        raise Fail("ed25519-verify", "OpenSSL Ed25519 verify failed")
    return text


def check_openssl(openssl):
    try:
        v = subprocess.run([openssl, "version"], capture_output=True, timeout=10).stdout.decode()
    except OSError as e:
        raise Fail("openssl", f"{openssl}: {e}")
    if not v.startswith("OpenSSL 3.5.3 "):
        raise Fail("openssl", f"{openssl} is {v.strip()!r}, need OpenSSL 3.5.3 (run on kamrui)")
    return v.strip()


# ---------------------------------------------------------------------------------------------- monban-bin driver


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def healthz(port):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        c.request("GET", "/healthz")
        r = c.getresponse()
        return r.status, r.read().decode(errors="replace")
    finally:
        c.close()


def run_binary(binary, openssl, work):
    """Boot monban-bin, apply one config change (SIGHUP), stop it (SIGTERM). Returns (vkey text, [checkpoint bytes])
    with every distinct checkpoint observed after boot, after the reload and after exit."""
    d = tempfile.mkdtemp(prefix="bin-", dir=work)
    key, crt = os.path.join(d, "key.pem"), os.path.join(d, "cert.pem")
    subprocess.run([openssl, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", key, "-out", crt, "-days", "2", "-subj", "/CN=monban.test",
                    "-addext", "subjectAltName=DNS:monban.test"], check=True, capture_output=True, timeout=30)
    port, aport, up = free_port(), free_port(), free_port()
    cfgp = os.path.join(d, "monban.json")

    def cfg(n):
        routes = [{"id": i, "path": f"/r{i}/", "to": {"upstream": f"127.0.0.1:{up}"}, "authz": "allow-all"}
                  for i in range(1, n + 1)]
        with open(cfgp, "w") as f:
            json.dump({"v": 1,
                       "listeners": [{"name": "pub", "bind": f"127.0.0.1:{port}", "profile": "P-PUBLIC-WEB",
                                      "alpn": ["h2", "http/1.1"]}],
                       "admin": {"bind": f"127.0.0.1:{aport}"},
                       "vhosts": [{"host": "monban.test", "routes": routes}]}, f)

    cfg(1)
    audit = os.path.join(d, "audit")
    env = {k: v for k, v in os.environ.items() if k not in ("NOTIFY_SOCKET", "AEGIS_UPGRADE_DIR", "LISTEN_FDS")}
    logf = open(os.path.join(d, "monban.log"), "wb")
    proc = subprocess.Popen([binary, "--config", cfgp, "--cert", crt, "--key", key, "--audit-dir", audit],
                            stdout=logf, stderr=subprocess.STDOUT, env=env)
    seen = []

    def tail():
        with open(os.path.join(d, "monban.log"), "rb") as f:
            return f.read()[-1500:].decode(errors="replace")

    def logdir():
        subs = [s for s in os.listdir(audit)] if os.path.isdir(audit) else []
        if len(subs) != 1:
            raise Fail("subject", f"expected one audit log directory under {audit}, found {subs}")
        return os.path.join(audit, subs[0])

    def snap():
        with open(os.path.join(logdir(), "checkpoint"), "rb") as f:
            c = f.read()
        if c not in seen:
            seen.append(c)

    def wait_health(gen=None):
        until = time.time() + 30
        while time.time() < until:
            if proc.poll() is not None:
                raise Fail("subject", f"monban-bin exited {proc.returncode}: {tail()}")
            try:
                st, body = healthz(aport)
                if st == 200 and (gen is None or json.loads(body).get("generation", 0) >= gen):
                    return json.loads(body)
            except (OSError, ValueError):
                pass
            time.sleep(0.1)
        raise Fail("subject", f"monban-bin not healthy within 30 s: {tail()}")

    try:
        h = wait_health()
        snap()
        cfg(2)
        proc.send_signal(signal.SIGHUP)
        wait_health(gen=h.get("generation", 0) + 1)
        snap()
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            raise Fail("subject", "monban-bin did not exit within 30 s of SIGTERM")
        snap()
        with open(os.path.join(logdir(), "vkey")) as f:
            vk = f.read()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        logf.close()
    return vk, seen


# ---------------------------------------------------------------------------------------------- reference signer


def ossl(openssl, *args, data=None):
    r = subprocess.run([openssl, *args], input=data, capture_output=True, timeout=60)
    if r.returncode != 0:
        raise Fail("openssl", f"openssl {' '.join(args[:3])}: {r.stderr.decode(errors='replace').strip()[:300]}")
    return r.stdout


def ref_key(openssl, work, alg, tag):
    kp = os.path.join(work, f"ref-{tag}.pem")
    ossl(openssl, "genpkey", "-algorithm", alg, "-out", kp)
    der = ossl(openssl, "pkey", "-in", kp, "-pubout", "-outform", "DER")
    prefix = MLDSA87_SPKI_PREFIX if alg == "ML-DSA-87" else ED25519_SPKI_PREFIX
    if not der.startswith(prefix) or len(der) != len(prefix) + (MLDSA87_PK_LEN if alg == "ML-DSA-87" else 32):
        raise Fail("openssl", f"{alg} SPKI from OpenSSL does not have the expected prefix/length")
    return kp, der[len(prefix):]


def ref_sign(openssl, work, kp, msg, opts=()):
    mp = os.path.join(work, "ref-msg")
    with open(mp, "wb") as f:
        f.write(msg)
    po = []
    for o in opts:
        po += ["-pkeyopt", o]
    return ossl(openssl, "pkeyutl", "-sign", "-inkey", kp, "-rawin", "-in", mp, *po)


def vkey_line(name, st, pk):
    return f"{name}+{key_id(name, st, pk).hex()}+{base64.b64encode(st + pk).decode()}"


def note(text, lines):
    return (text.decode() + "\n" + "".join(f"{EM_DASH} {n} {base64.b64encode(b).decode()}\n" for n, b in lines)).encode()


def reference(openssl, work, mopts=()):
    """A checkpoint in monban-bin's format, signed by OpenSSL-generated keys: (vkey text, note, ml-dsa key file)."""
    name = "monban.audit"
    ekp, epk = ref_key(openssl, work, "ED25519", "ed")
    mkp, mpk = ref_key(openssl, work, "ML-DSA-87", "ml")
    text = f"{name}\n7\n{base64.b64encode(hashlib.sha256(b'ref').digest()).decode()}\n".encode()
    esig = ref_sign(openssl, work, ekp, text)
    msig = ref_sign(openssl, work, mkp, text, mopts)
    vk = vkey_line(name, ED25519_SIG_TYPE, epk) + "\n" + vkey_line(name, MLDSA87_SIG_TYPE, mpk) + "\n"
    n = note(text, [(name, key_id(name, ED25519_SIG_TYPE, epk) + esig),
                    (name, key_id(name, MLDSA87_SIG_TYPE, mpk) + msig)])
    return vk, n, mpk


# ---------------------------------------------------------------------------------------------- mutations


def resign_lines(data, fn):
    """Rebuild a note with fn([(name, blob)]) -> [(name, blob)] applied to its signature lines."""
    s = data.decode()
    i = s.find("\n\n")
    text, block = s[: i + 1], s[i + 2:]
    lines = []
    for ln in block[:-1].split("\n"):
        _, n, b = ln.split(" ", 2)
        lines.append((n, base64.b64decode(b)))
    return note(text.encode(), fn(lines))


def is_ml(blob, keys):
    return blob[:4] == keys["mldsa87"][1]


def mutants(vk, data, other_mpk):
    keys = parse_vkeys(vk)
    mname, mid, mpk = keys["mldsa87"]

    def flip_ml(at):
        return lambda ls: [(n, (b[:at] + bytes([b[at] ^ 0x01]) + b[at + 1:]) if is_ml(b, keys) else b) for n, b in ls]

    def flip_ed(ls):
        return [(n, b if is_ml(b, keys) else b[:20] + bytes([b[20] ^ 0x80]) + b[21:]) for n, b in ls]

    # wrong public key: another valid ML-DSA-87 key under the same name, with the vkey ID and the note line's key ID
    # both rewritten to match it, so key lookup succeeds and only OpenSSL's verify can catch it.
    wid = key_id(mname, MLDSA87_SIG_TYPE, other_mpk)
    wrong_vk = "\n".join(vkey_line(mname, MLDSA87_SIG_TYPE, other_mpk) if ln.split("+")[0:2] == [mname, mid.hex()]
                         else ln for ln in vk.splitlines()) + "\n"
    wrong_note = resign_lines(data, lambda ls: [(n, wid + b[4:]) if is_ml(b, keys) else (n, b) for n, b in ls])
    # flipped body byte: change the root to another canonical 32-byte value (sizes and shape stay valid)
    s = data.decode()
    lines = s.split("\n")
    root = bytearray(base64.b64decode(lines[2]))
    root[0] ^= 0x01
    lines[2] = base64.b64encode(bytes(root)).decode()
    body_flip = "\n".join(lines).encode()
    no_cosig = resign_lines(data, lambda ls: [(n, b) for n, b in ls if not is_ml(b, keys)])
    bad_id = resign_lines(data, lambda ls: [(n, (bytes([b[0] ^ 0xff]) + b[1:]) if is_ml(b, keys) else b)
                                            for n, b in ls])
    trunc = resign_lines(data, lambda ls: [(n, b[:-1] if is_ml(b, keys) else b) for n, b in ls])
    pk_flip = bytearray(mpk)
    pk_flip[100] ^= 0x01
    flipped_vk_id = "\n".join(vkey_line(mname, MLDSA87_SIG_TYPE, bytes(pk_flip)) if ln.startswith(f"{mname}+{mid.hex()}+")
                              else ln for ln in vk.splitlines()) + "\n"
    flipped_pk_note = resign_lines(data, lambda ls: [
        (n, key_id(mname, MLDSA87_SIG_TYPE, bytes(pk_flip)) + b[4:]) if is_ml(b, keys) else (n, b) for n, b in ls])
    no_ml_vk = "\n".join(ln for ln in vk.splitlines() if not ln.startswith(f"{mname}+{mid.hex()}+")) + "\n"
    return [
        ("cosig-byte-flip (first sig byte)", vk, resign_lines(data, flip_ml(4)), "mldsa-verify"),
        ("cosig-byte-flip (middle)", vk, resign_lines(data, flip_ml(4 + MLDSA87_SIG_LEN // 2)), "mldsa-verify"),
        ("cosig-byte-flip (last sig byte)", vk, resign_lines(data, flip_ml(4 + MLDSA87_SIG_LEN - 1)), "mldsa-verify"),
        ("wrong-public-key", wrong_vk, wrong_note, "mldsa-verify"),
        ("public-key-bit-flip", flipped_vk_id, flipped_pk_note, "mldsa-verify"),
        ("body-byte-flip (root)", vk, body_flip, "mldsa-verify"),
        ("cosignature-line-removed", vk, no_cosig, "cosignature-missing"),
        ("cosignature-key-id-mismatch", vk, bad_id, "cosignature-missing"),
        ("cosignature-truncated", vk, trunc, "parse"),
        ("mldsa-vkey-absent", no_ml_vk, data, "key"),
        ("log-signature-byte-flip (Ed25519)", vk, resign_lines(data, flip_ed), "ed25519-verify"),
    ]


def expect(openssl, work, label, vk, data, want, log):
    try:
        verify_checkpoint(openssl, work, parse_vkeys(vk), data)
        got = "pass"
    except Fail as e:
        got = e.cat
        if e.cat == "openssl":
            raise
    ok = got == want
    log(f"  {'ok  ' if ok else 'FAIL'} {label}: {got} (want {want})")
    return ok


def main(argv):
    mode = argv[0] if argv else ""
    args = {}
    multi = {"--checkpoint": []}
    it = iter(argv[1:])
    for a in it:
        v = next(it, None)
        if a in multi:
            multi[a].append(v)
        elif a in ("--openssl", "--binary", "--work", "--vkey"):
            args[a] = v
        else:
            print(f"usage: unknown argument {a}", file=sys.stderr)
            return 2
    title = NAME + (" SELF-TEST" if mode == "selftest" else "")
    openssl = args.get("--openssl", "/usr/bin/openssl")
    work = args.get("--work") or tempfile.mkdtemp(prefix="tlog-mldsa-")

    def log(m):
        print(m, file=sys.stderr, flush=True)

    try:
        ver = check_openssl(openssl)
        if mode == "verify":
            with open(args["--vkey"]) as f:
                keys = parse_vkeys(f.read())
            for c in multi["--checkpoint"]:
                with open(c, "rb") as f:
                    verify_checkpoint(openssl, work, keys, f.read())
            print(f"{NAME}: PASS ({len(multi['--checkpoint'])} checkpoints; {ver})")
            return 0
        if mode == "binary":
            vk, cps = run_binary(args["--binary"], openssl, work)
            keys = parse_vkeys(vk)
            if len(cps) < 2:
                raise Fail("subject", f"only {len(cps)} distinct checkpoint(s) observed; want >= 2 (boot, reload)")
            sizes = []
            for c in cps:
                text = verify_checkpoint(openssl, work, keys, c)
                sizes.append(int(text.split(b"\n")[1]))
                log(f"  ok   checkpoint size {sizes[-1]}: ML-DSA-87 cosignature and Ed25519 signature verified")
            print(f"{NAME}: PASS ({len(cps)} monban-bin checkpoints (sizes {','.join(map(str, sizes))}): ML-DSA-87 "
                  f"cosignature and Ed25519 log signature verified by {ver} pkeyutl -verify -rawin against the "
                  f"published vkeys)")
            return 0
        if mode == "selftest":
            fails, n = [], 0
            # control 1: an OpenSSL-signed reference note in monban-bin's encoding verifies
            rvk, rnote, rmpk = reference(openssl, work)
            n += 1
            if not expect(openssl, work, "control: OpenSSL-signed reference note", rvk, rnote, "pass", log):
                fails.append("reference-control")
            # parameter-set mutants on the reference: a non-empty context string is a different signature input
            # (FIPS 204 M' = 0 || |ctx| || ctx || M), so verify with the empty context must refuse it.
            cvk, cnote, _ = reference(openssl, work, mopts=("context-string:monban",))
            n += 1
            if not expect(openssl, work, "reference signed with context-string 'monban'", cvk, cnote, "mldsa-verify",
                          log):
                fails.append("context-string")
            for label, vk, data, want in mutants(rvk, rnote, reference(openssl, work)[2]):
                n += 1
                if not expect(openssl, work, f"reference/{label}", vk, data, want, log):
                    fails.append(f"reference/{label}")
            # control 2 + mutants on a real monban-bin log
            bvk, cps = run_binary(args["--binary"], openssl, work)
            head = cps[-1]
            n += 1
            if not expect(openssl, work, "control: monban-bin head checkpoint", bvk, head, "pass", log):
                fails.append("monban-bin-control")
            else:
                for label, vk, data, want in mutants(bvk, head, rmpk):
                    n += 1
                    if not expect(openssl, work, f"monban-bin/{label}", vk, data, want, log):
                        fails.append(f"monban-bin/{label}")
            if fails:
                print(f"{title}: FAIL ({len(fails)}/{n} cases wrong: {', '.join(fails)})")
                return 1
            print(f"{title}: PASS (2 controls verify; {n - 2}/{n - 2} mutants refused for their intended reason, "
                  f"incl. flipped cosignature byte and wrong public key, on an OpenSSL-signed reference and on an "
                  f"monban-bin log; {ver})")
            return 0
        print(f"usage: {sys.argv[0]} verify|binary|selftest ...", file=sys.stderr)
        return 2
    except Fail as e:
        print(f"{title}: FAIL ({e})")
        return 1
    except (OSError, subprocess.SubprocessError, KeyError) as e:
        print(f"{title}: FAIL ({type(e).__name__}: {e})")
        return 1
    finally:
        if not args.get("--work"):
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
