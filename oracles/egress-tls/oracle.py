#!/usr/bin/env python3
"""EGRESS-TLS oracle (P8-hardening-001; PREFLIGHT R15, PLAN-8 gate egress-tls-e2e). Contract: oracles/README.md;
details: README.md next to this file.

  oracle.py --subject "CMD ARGS" --openssl PATH --work DIR [--only REGEX]
  oracle.py --self-test --openssl PATH --work DIR

The subject is an egress-subject built with `--features tls-client` (ssrf-corpus JSON-lines protocol plus a `tls`
case member). For every client profile the oracle starts real TLS 1.3 upstreams (OpenSSL `s_server -WWW`) behind its
own loopback relay, which parses every plaintext TLS record in both directions. The subject fetches
https://egress.test:PORT/<nonce>.txt with scripted DNS (egress.test -> 127.0.0.1, readmitted loopback only).

Checks (ids appear in the failure lines):
  E0 proto     one well-formed verdict per case, right id, subject alive; capability probe of the peer.
  E1 data      ok cases: decision connect, status 200, body = the case's random nonce (decrypted by the subject,
               served by the independent upstream).
  E2 hello     every ClientHello: supported_versions = [0x0304] only; supported_groups = the profile's F12 list
               exactly, in order; key_share[0] = the profile's first group, every share in the list; the first group
               is post-quantum (PQ-first); SNI = egress.test; ALPN offered = [http/1.1].
  E3 server    ServerHello: version 0x0304, group = the profile's first group, no HelloRetryRequest.
  E4 refuse    untrusted-CA and wrong-name upstreams: the subject rejects with code `tls`; the upstream never serves
               the nonce file; the client sends at most one encrypted record (its alert), never Finished + request.
  E5 resume    no ClientHello ever carries pre_shared_key (41) or early_data (42), including the second fetch through
               the same client after the upstream issued tickets with max_early_data (s_server -early_data).
  E6 upstream  ok cases: the upstream served the nonce file exactly once, over exactly one connection; the subject
               dialled only the relay address.

Self-test: fake_subject.py drives `openssl s_client` per case. The reference fake (verify chain + hostname, no
session reuse, profile groups) must PASS; then each mutant must go red with its id: accept-untrusted (E4),
no-hostname-check (E4), resume (E5), early-data (E5), classical-first (E2), wrong-alpn (E2).
"""
import argparse, json, os, re, secrets, shlex, shutil, socket, subprocess, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = "egress.test"
WRONG = "other.test"
PQ = {0x0200, 0x0201, 0x0202, 0x11EB, 0x11EC, 0x11ED}
OSSL_NAME = {0x11EC: "X25519MLKEM768", 0x11ED: "SecP384r1MLKEM1024", 0x11EB: "SecP256r1MLKEM768",
             0x001D: "x25519", 0x0017: "secp256r1", 0x0018: "secp384r1", 0x0202: "MLKEM1024"}
# Client profiles (F12 rows with a client definition, monban-tls `client_config`): name -> ordered kx list.
PROFILES = {
    "P-PUBLIC-WEB": [0x11EC, 0x11ED, 0x11EB, 0x001D, 0x0017],
    "PQ-REQUIRED": [0x11EC],
    "P-UNIVERSAL": [0x11ED],
    "P-BSI-ALT": [0x11ED, 0x11EB],
    "P-CNSA": [0x0202],
    "FIPS-PQ-REQUIRED": [0x11EB],
}
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
MUTANTS = [("accept-untrusted", "E4"), ("no-hostname-check", "E4"), ("resume", "E5"), ("early-data", "E5"),
           ("classical-first", "E2"), ("wrong-alpn", "E2")]


# ------------------------------------------------------------------------------------------------ TLS record parsing

def u16(b, i):
    return int.from_bytes(b[i:i + 2], "big")


def parse_exts(b):
    out, i = {}, 0
    while i + 4 <= len(b):
        t, n = u16(b, i), u16(b, i + 2)
        out.setdefault(t, b[i + 4:i + 4 + n])
        i += 4 + n
    return out


def parse_client_hello(m):
    i = 2 + 32
    i += 1 + m[i]
    i += 2 + u16(m, i)
    i += 1 + m[i]
    ext = parse_exts(m[i + 2:i + 2 + u16(m, i)])
    ch = {"ext_types": sorted(ext)}
    g = ext.get(10, b"")
    ch["groups"] = [u16(g, 2 + 2 * k) for k in range((u16(g, 0) if g else 0) // 2)]
    ks, shares = ext.get(51, b""), []
    if ks:
        j = 2
        while j + 4 <= 2 + u16(ks, 0):
            shares.append(u16(ks, j))
            j += 4 + u16(ks, j + 2)
    ch["shares"] = shares
    sv = ext.get(43, b"")
    ch["versions"] = [u16(sv, 1 + 2 * k) for k in range((sv[0] if sv else 0) // 2)]
    sn = ext.get(0, b"")
    ch["sni"] = sn[5:5 + u16(sn, 3)].decode("ascii", "replace") if len(sn) >= 5 else None
    al, alpn = ext.get(16, b""), []
    if al:
        j = 2
        while j < 2 + u16(al, 0):
            alpn.append(al[j + 1:j + 1 + al[j]].decode("ascii", "replace"))
            j += 1 + al[j]
    ch["alpn"] = alpn if 16 in ext else None
    ch["psk"], ch["early_data"] = 41 in ext, 42 in ext
    return ch


def parse_server_hello(m):
    rnd = m[2:34]
    i = 34
    i += 1 + m[i]
    i += 3
    ext = parse_exts(m[i + 2:i + 2 + u16(m, i)])
    ks, sv = ext.get(51, b""), ext.get(43, b"")
    return {"hrr": rnd == HRR_RANDOM, "group": u16(ks, 0) if len(ks) >= 2 else None,
            "version": u16(sv, 0) if len(sv) >= 2 else None}


class Dir:
    """One direction of one relayed connection: plaintext handshake messages and encrypted record counts."""

    def __init__(self, conn, client):
        self.conn, self.client, self.buf, self.hs = conn, client, b"", b""

    def feed(self, data):
        self.buf += data
        while len(self.buf) >= 5:
            typ, n = self.buf[0], u16(self.buf, 3)
            if len(self.buf) < 5 + n:
                return
            body, self.buf = self.buf[5:5 + n], self.buf[5 + n:]
            with self.conn.lock:
                if typ == 22:
                    self.hs += body
                    self.messages()
                elif typ == 23:
                    self.conn.enc[self.client] += 1
                elif typ == 21:
                    self.conn.alerts.append(("client" if self.client else "server", body.hex()))

    def messages(self):
        while len(self.hs) >= 4:
            t, n = self.hs[0], int.from_bytes(self.hs[1:4], "big")
            if len(self.hs) < 4 + n:
                return
            m, self.hs = self.hs[4:4 + n], self.hs[4 + n:]
            try:
                if t == 1 and self.client:
                    self.conn.ch.append(parse_client_hello(m))
                elif t == 2 and not self.client:
                    self.conn.sh.append(parse_server_hello(m))
            except (IndexError, ValueError) as e:
                self.conn.errors.append(f"unparseable handshake message type {t}: {e}")


class Conn:
    def __init__(self):
        self.lock = threading.Lock()
        self.ch, self.sh, self.alerts, self.errors = [], [], [], []
        self.enc = {True: 0, False: 0}


class Relay:
    """Loopback TCP relay in front of one upstream; records every connection."""

    def __init__(self, upstream_port):
        self.up = upstream_port
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.conns, self.stop = [], False
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while not self.stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            conn = Conn()
            self.conns.append(conn)
            try:
                u = socket.create_connection(("127.0.0.1", self.up), timeout=5)
            except OSError as e:
                conn.errors.append(f"upstream connect: {e}")
                c.close()
                continue
            for a, b, client in ((c, u, True), (u, c, False)):
                threading.Thread(target=self.pump, args=(a, b, Dir(conn, client)), daemon=True).start()

    @staticmethod
    def pump(a, b, d):
        try:
            while True:
                data = a.recv(65536)
                if not data:
                    break
                d.feed(data)
                b.sendall(data)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def close(self):
        self.stop = True
        self.sock.close()


# ------------------------------------------------------------------------------------------------ peers

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, **kw)


def probe(openssl):
    r = run([openssl, "version"])
    m = re.match(r"OpenSSL (\d+)\.(\d+)\.(\d+)", r.stdout)
    if not m or (int(m.group(1)), int(m.group(2))) < (3, 5):
        return f"need OpenSSL >= 3.5 (ML-KEM TLS groups), got {r.stdout.strip() or r.stderr.strip()}"
    have = set(run([openssl, "list", "-tls-groups", "-tls1_3"]).stdout.strip().split(":"))
    need = {OSSL_NAME[g] for p in PROFILES.values() for g in p}
    if need - have:
        return f"{openssl} lacks TLS groups {sorted(need - have)}"
    return None


def pki(openssl, d):
    """Trusted CA, untrusted CA; leaves: good (egress.test <- trusted), untrusted (egress.test <- untrusted),
    wrongname (other.test <- trusted). ECDSA P-384 throughout."""
    def key(name):
        r = run([openssl, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384", "-out", f"{d}/{name}.key"])
        if r.returncode:
            raise RuntimeError(f"genpkey {name}: {r.stderr}")

    def ca(name):
        key(name)
        r = run([openssl, "req", "-x509", "-new", "-key", f"{d}/{name}.key", "-out", f"{d}/{name}.pem", "-days", "2",
                 "-sha384", "-subj", f"/CN=egress-tls oracle {name}",
                 "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
        if r.returncode:
            raise RuntimeError(f"ca {name}: {r.stderr}")

    def leaf(name, cn, issuer):
        key(name)
        ext = f"{d}/{name}.ext"
        with open(ext, "w") as f:
            f.write(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                    f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{cn}\n")
        r = run([openssl, "req", "-new", "-key", f"{d}/{name}.key", "-subj", f"/CN={cn}", "-out", f"{d}/{name}.csr"])
        if r.returncode:
            raise RuntimeError(f"csr {name}: {r.stderr}")
        r = run([openssl, "x509", "-req", "-in", f"{d}/{name}.csr", "-CA", f"{d}/{issuer}.pem", "-CAkey",
                 f"{d}/{issuer}.key", "-CAcreateserial", "-days", "2", "-sha384", "-extfile", ext,
                 "-out", f"{d}/{name}.pem"])
        if r.returncode:
            raise RuntimeError(f"sign {name}: {r.stderr}")

    ca("ca")
    ca("rogue-ca")
    leaf("good", HOST, "ca")
    leaf("untrusted", HOST, "rogue-ca")
    leaf("wrongname", WRONG, "ca")
    return f"{d}/ca.pem"


class Upstream:
    """openssl s_server -WWW for one profile and one leaf, serving files from its own directory."""

    def __init__(self, openssl, d, leaf, groups, pids):
        self.dir = d
        os.makedirs(d, exist_ok=True)
        self.log = open(f"{d}/s_server.log", "w+")
        cmd = [openssl, "s_server", "-accept", "127.0.0.1:0", "-cert", os.path.abspath(f"{d}/../pki/{leaf}.pem"),
               "-key", os.path.abspath(f"{d}/../pki/{leaf}.key"), "-tls1_3", "-WWW", "-alpn", "http/1.1",
               "-groups", ":".join(OSSL_NAME[g] for g in groups), "-early_data", "-num_tickets", "2"]
        self.p = subprocess.Popen(cmd, cwd=d, stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT)
        pids.append(self.p.pid)
        self.port = None
        for _ in range(100):
            self.log.seek(0)
            m = re.search(r"ACCEPT 127\.0\.0\.1:(\d+)", self.log.read())
            if m:
                self.port = int(m.group(1))
                break
            if self.p.poll() is not None:
                break
            time.sleep(0.05)
        if self.port is None:
            self.log.seek(0)
            raise RuntimeError(f"s_server did not start: {self.log.read()[-400:]}")
        self.relay = Relay(self.port)

    def served(self, name):
        self.log.seek(0)
        return self.log.read().count(f"FILE:{name}")

    def close(self):
        self.relay.close()
        self.p.terminate()
        try:
            self.p.wait(5)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()
        self.log.close()


class Subject:
    def __init__(self, cmd, pids):
        self.p = subprocess.Popen(shlex.split(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True)
        pids.append(self.p.pid)
        self.out = []
        threading.Thread(target=self.reader, daemon=True).start()

    def reader(self):
        for line in self.p.stdout:
            self.out.append(line)

    def ask(self, case, timeout=30):
        n = len(self.out)
        try:
            self.p.stdin.write(json.dumps(case) + "\n")
            self.p.stdin.flush()
        except OSError as e:
            return None, f"subject stdin: {e}"
        t0 = time.time()
        while len(self.out) <= n:
            if self.p.poll() is not None and len(self.out) <= n:
                return None, f"subject exited ({self.p.returncode}): {self.p.stderr.read()[-300:]}"
            if time.time() - t0 > timeout:
                return None, "no verdict within 30 s"
            time.sleep(0.01)
        try:
            return json.loads(self.out[n]), None
        except ValueError:
            return None, f"malformed verdict {self.out[n][:200]!r}"

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(10)
        except (OSError, subprocess.TimeoutExpired):
            self.p.kill()
            self.p.wait()


# ------------------------------------------------------------------------------------------------ judging

def judge_hello(cid, conn, groups, v):
    for k, ch in enumerate(conn.ch):
        tag = f"{cid} ClientHello#{k + 1}"
        if ch["versions"] != [0x0304]:
            v.append(f"E2 hello: {tag} supported_versions {[hex(x) for x in ch['versions']]} != [0x0304]")
        if ch["groups"] != groups:
            v.append(f"E2 hello: {tag} supported_groups {[hex(x) for x in ch['groups']]} != profile "
                     f"{[hex(x) for x in groups]}")
        if not ch["shares"] or ch["shares"][0] != groups[0] or groups[0] not in PQ:
            v.append(f"E2 hello: {tag} not PQ-first: key_share {[hex(x) for x in ch['shares']]}, "
                     f"profile first {hex(groups[0])}")
        if any(s not in groups for s in ch["shares"]):
            v.append(f"E2 hello: {tag} key_share outside the profile: {[hex(x) for x in ch['shares']]}")
        if ch["sni"] != HOST:
            v.append(f"E2 hello: {tag} SNI {ch['sni']!r} != {HOST}")
        if ch["alpn"] != ["http/1.1"]:
            v.append(f"E2 hello: {tag} ALPN {ch['alpn']} != ['http/1.1']")
        if ch["psk"] or ch["early_data"]:
            v.append(f"E5 resume: {tag} offers {'pre_shared_key ' if ch['psk'] else ''}"
                     f"{'early_data' if ch['early_data'] else ''}".rstrip())


def judge_case(case, verdict, err, up, nonce_name, nonce, conns, groups, kind, v):
    cid = case["id"]
    if err or verdict is None:
        v.append(f"E0 proto: {cid}: {err}")
        return
    if verdict.get("id") != cid:
        v.append(f"E0 proto: {cid}: verdict id {verdict.get('id')!r}")
    for c in conns:
        for e in c.errors:
            v.append(f"E0 proto: {cid}: relay: {e}")
        judge_hello(cid, c, groups, v)
    relay_addr = f"127.0.0.1:{up.relay.port}"
    bad_dials = [a for a in verdict.get("connects", []) if a != relay_addr]
    if bad_dials:
        v.append(f"E6 upstream: {cid}: subject dialled {bad_dials} (only {relay_addr} is the upstream)")
    served = up.served(nonce_name)
    if kind == "ok":
        if verdict.get("decision") != "connect" or verdict.get("status") != 200:
            v.append(f"E1 data: {cid}: no 200 fetch: {json.dumps(verdict)[:300]}")
        elif verdict.get("body_hex") != nonce.hex():
            v.append(f"E1 data: {cid}: body {verdict.get('body_hex', '')[:64]!r} != nonce {nonce.hex()}")
        if served != 1 or len(conns) != 1:
            v.append(f"E6 upstream: {cid}: upstream served the nonce {served}x over {len(conns)} connection(s)")
        for c in conns:
            if len(c.sh) != 1 or c.sh[0]["hrr"]:
                v.append(f"E3 server: {cid}: {len(c.sh)} ServerHello(s), HRR={any(s['hrr'] for s in c.sh)}")
            for s in c.sh:
                if not s["hrr"] and (s["group"] != groups[0] or s["version"] != 0x0304):
                    v.append(f"E3 server: {cid}: ServerHello group {s['group'] and hex(s['group'])} version "
                             f"{s['version'] and hex(s['version'])} (want {hex(groups[0])}, 0x304)")
    else:
        if "reject" not in verdict or verdict.get("decision") == "connect":
            v.append(f"E4 refuse: {cid}: {kind} upstream accepted: {json.dumps(verdict)[:300]}")
        elif verdict.get("reject") != "tls":
            v.append(f"E4 refuse: {cid}: rejected with {verdict.get('reject')!r}, want 'tls'")
        if served:
            v.append(f"E4 refuse: {cid}: {kind} upstream served the nonce {served}x")
        for c in conns:
            if c.enc[True] > 1:
                v.append(f"E4 refuse: {cid}: client sent {c.enc[True]} encrypted records to a {kind} upstream "
                         f"(Finished + data)")
        if not conns:
            v.append(f"E4 refuse: {cid}: no connection reached the {kind} upstream (nothing was refused)")


def run_matrix(subject_cmd, openssl, work, only=None, quiet=False):
    """Returns (violations, stats)."""
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(f"{work}/pki")
    ca = pki(openssl, f"{work}/pki")
    pids, v, stats = [], [], {"cases": 0, "handshakes": 0}
    sub = Subject(subject_cmd, pids)
    try:
        for prof, groups in PROFILES.items():
            if only and not re.search(only, prof):
                continue
            ups = {}
            try:
                for leaf in ("good", "untrusted", "wrongname"):
                    ups[leaf] = Upstream(openssl, f"{work}/{prof}-{leaf}", leaf, groups, pids)
                plan = [("ok-1", "good", "ok"), ("ok-2", "good", "ok"), ("untrusted", "untrusted", "untrusted-CA"),
                        ("wrong-name", "wrongname", "wrong-name"), ("ok-3", "good", "ok")]
                for tag, leaf, kind in plan:
                    up = ups[leaf]
                    nonce = secrets.token_hex(16).encode()
                    name = f"{tag}-{secrets.token_hex(4)}.txt"
                    with open(f"{up.dir}/{name}", "wb") as f:
                        f.write(nonce)
                    cid = f"{prof}/{tag}"
                    case = {"id": cid, "url": f"https://{HOST}:{up.relay.port}/{name}",
                            "dns": {HOST: [["127.0.0.1"]]}, "allow_hosts": [HOST], "allow_ports": [up.relay.port],
                            "allow_http": False, "readmit": ["127.0.0.0/8"], "deadline_ms": 15000, "live": True,
                            "echo_body": True, "tls": {"profile": prof, "ca": ca, "client": prof}}
                    before = len(up.relay.conns)
                    verdict, err = sub.ask(case)
                    time.sleep(0.15)  # let the relay threads drain the last records
                    conns = up.relay.conns[before:]
                    stats["cases"] += 1
                    stats["handshakes"] += sum(1 for c in conns if c.sh)
                    n0 = len(v)
                    judge_case(case, verdict, err, up, name, nonce, conns, groups,
                               "ok" if kind == "ok" else kind, v)
                    if not quiet:
                        print(f"  {cid}: {'ok' if len(v) == n0 else 'FAIL'} "
                              f"({(verdict or {}).get('decision') or (verdict or {}).get('reject')}, "
                              f"{len(conns)} conn, groups {[hex(x) for c in conns for x in c.ch[0]['shares'][:1]] if conns and conns[0].ch else []})")
            finally:
                for u in ups.values():
                    u.close()
    finally:
        sub.close()
    return v, stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--subject")
    ap.add_argument("--openssl", default="openssl")
    ap.add_argument("--work", required=True)
    ap.add_argument("--only")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    name = "EGRESS-TLS SELF-TEST" if a.self_test else "EGRESS-TLS"
    e = probe(a.openssl)
    if e:
        print(f"{name}: FAIL (E0 proto: {e})")
        sys.exit(1)
    fake = f"python3 -I {shlex.quote(os.path.join(HERE, 'fake_subject.py'))} --openssl {shlex.quote(a.openssl)}"
    if not a.self_test:
        if not a.subject:
            print(f"{name}: FAIL (no --subject)")
            sys.exit(1)
        try:
            v, st = run_matrix(a.subject, a.openssl, a.work, a.only)
        except (RuntimeError, OSError) as ex:
            print(f"{name}: FAIL (E0 proto: {ex})")
            sys.exit(1)
        for x in v:
            print(f"  {x}")
        if v:
            print(f"{name}: FAIL ({len(v)} violations over {st['cases']} cases)")
            sys.exit(1)
        print(f"{name}: PASS ({len(PROFILES)} client profiles x 5 cases = {st['cases']} cases, {st['handshakes']} "
              f"TLS 1.3 handshakes against OpenSSL s_server; PQ-first, no PSK/early data, untrusted + wrong-name "
              f"refused)")
        return
    errs = []
    try:
        v, st = run_matrix(f"{fake} --mode ref", a.openssl, a.work, a.only, quiet=True)
        if v:
            errs.append(f"reference fake not green: {v[:5]}")
        else:
            print(f"self-test reference (s_client, verify + hostname, no reuse): PASS ({st['cases']} cases)")
        for mode, want in MUTANTS:
            v, st = run_matrix(f"{fake} --mode {mode}", a.openssl, a.work, a.only, quiet=True)
            ids = sorted({x.split(":")[0] for x in v})
            if any(i.startswith(want) for i in ids):
                print(f"self-test mutant {mode}: FAIL as expected ({want}; ids {ids}; first: {[x for x in v if x.startswith(want)][0][:160]})")
            else:
                errs.append(f"mutant {mode}: wanted {want}, got {ids or 'PASS'}")
    except (RuntimeError, OSError) as ex:
        errs.append(f"E0 proto: {ex}")
    finally:
        shutil.rmtree(a.work, ignore_errors=True)
    if errs:
        for x in errs:
            print(f"  {x}")
        print(f"{name}: FAIL ({len(errs)} problems)")
        sys.exit(1)
    print(f"{name}: PASS (reference green; {len(MUTANTS)}/{len(MUTANTS)} mutants red)")


if __name__ == "__main__":
    main()
