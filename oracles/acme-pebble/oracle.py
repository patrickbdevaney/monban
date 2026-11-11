"""Monban oracle: ACME issuance/renewal against Pebble (RFC 8555, RFC 9773 ARI) + CERT-1..4. Stdlib only.

Contract: oracles/README.md. See README.md next to this file for the subject protocol and the checks.
"""
import argparse
import json
import os
import queue
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
NAME = "ACME-PEBBLE"
# Pinned by digest (ghcr.io; docker.io/letsencrypt/pebble no longer exists). Both ~8 MB (checked < 500 MB below).
PEBBLE = "ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199"
CHALLTESTSRV = "ghcr.io/letsencrypt/pebble-challtestsrv@sha256:12ce21884def456bcf9786542113949e1f19dc7738d2c70e156c2d0c38a1405b"
MAX_IMAGE_BYTES = 500 * 1000 * 1000
DOMAIN = "acme-subject.test"
DAY = 86400


class Fail(Exception):
    pass


class ChainFail(Fail):
    """The served chain did not verify."""


def log(msg):
    print(msg, flush=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def docker(*args, check=True, capture=True):
    r = subprocess.run(["docker", *args], capture_output=capture, text=True, timeout=300)
    if check and r.returncode != 0:
        raise Fail(f"docker {' '.join(args[:2])}: {r.stderr.strip()[:300]}")
    return r


def ensure_image(ref):
    if docker("image", "inspect", ref, check=False).returncode != 0:
        docker("pull", ref)
    size = int(docker("image", "inspect", ref, "--format", "{{.Size}}").stdout.strip())
    if size >= MAX_IMAGE_BYTES:
        raise Fail(f"image {ref} is {size} bytes (>= 500 MB)")
    return size


class Pebble:
    """Pebble + challtestsrv on loopback (host network), random ports, torn down on exit."""

    def __init__(self, work):
        self.work = work
        self.tag = f"monban-acme-pebble-{os.getpid()}"
        self.acme = free_port()
        self.mgmt = free_port()
        self.http01 = free_port()
        self.dns = free_port()
        self.ctsmgmt = free_port()
        self.started = []

    def __enter__(self):
        sizes = {ref.split("@")[0]: ensure_image(ref) for ref in (PEBBLE, CHALLTESTSRV)}
        log(f"images: " + ", ".join(f"{k} {v/1e6:.1f} MB" for k, v in sizes.items()))
        cid = docker("create", PEBBLE).stdout.strip()
        try:
            docker("cp", f"{cid}:/test/certs/pebble.minica.pem", os.path.join(self.work, "minica.pem"))
        finally:
            docker("rm", cid, check=False)
        cfg = {"pebble": {
            "listenAddress": f"127.0.0.1:{self.acme}", "managementListenAddress": f"127.0.0.1:{self.mgmt}",
            "certificate": "test/certs/localhost/cert.pem", "privateKey": "test/certs/localhost/key.pem",
            "httpPort": self.http01, "tlsPort": free_port(), "ocspResponderURL": "",
            "externalAccountBindingRequired": False, "domainBlocklist": ["blocked-domain.example"],
            "retryAfter": {"authz": 1, "order": 1}, "keyAlgorithm": "ecdsa",
            "profiles": {"default": {"description": "90 d", "validityPeriod": 7776000}}}}
        cfgp = os.path.join(self.work, "pebble-config.json")
        with open(cfgp, "w") as f:
            json.dump(cfg, f)
        os.chmod(self.work, 0o755)
        os.chmod(cfgp, 0o644)
        docker("run", "-d", "--rm", "--name", self.tag + "-cts", "--network", "host", CHALLTESTSRV,
               "-dnsserver", f"127.0.0.1:{self.dns}", "-defaultIPv4", "127.0.0.1", "-defaultIPv6", "",
               "-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", "", "-management", f"127.0.0.1:{self.ctsmgmt}")
        self.started.append(self.tag + "-cts")
        docker("run", "-d", "--rm", "--name", self.tag, "--network", "host",
               "-e", "PEBBLE_VA_NOSLEEP=1", "-e", "PEBBLE_WFE_NONCEREJECT=0", "-e", "PEBBLE_AUTHZREUSE=0",
               "-v", f"{cfgp}:/cfg.json:ro", PEBBLE, "-config", "/cfg.json", "-strict",
               "-dnsserver", f"127.0.0.1:{self.dns}")
        self.started.append(self.tag)
        self.minica = os.path.join(self.work, "minica.pem")
        deadline = time.time() + 30
        while True:
            try:
                self.get(f"https://127.0.0.1:{self.acme}/dir")
                break
            except Exception as e:  # noqa: BLE001
                if time.time() > deadline:
                    raise Fail(f"pebble did not start: {e}; logs: {self.logs()[-500:]}")
                time.sleep(0.3)
        root = self.get(f"https://127.0.0.1:{self.mgmt}/roots/0").decode()
        self.root = os.path.join(self.work, "pebble-root.pem")
        with open(self.root, "w") as f:
            f.write(root)
        return self

    def __exit__(self, *exc):
        for c in self.started:
            docker("rm", "-f", c, check=False)

    def logs(self):
        return docker("logs", self.tag, check=False).stderr + docker("logs", self.tag, check=False).stdout

    def ctx(self):
        return ssl.create_default_context(cafile=self.minica)

    def get(self, url):
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "aegis-ci"}),
                                    context=self.ctx(), timeout=10) as r:
            return r.read()

    def set_renewal_info(self, leaf_pem, start, end):
        body = json.dumps({"Certificate": leaf_pem, "ARIResponse": json.dumps(
            {"suggestedWindow": {"start": start, "end": end}})}).encode()
        req = urllib.request.Request(f"https://127.0.0.1:{self.mgmt}/set-renewal-info/", data=body, method="POST",
                                     headers={"User-Agent": "aegis-ci", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, context=self.ctx(), timeout=10) as r:
            if r.status != 200:
                raise Fail(f"set-renewal-info: {r.status}")


class Subject:
    def __init__(self, cmd, peb, extra, work):
        self.https = free_port()
        self.events = []
        self.q = queue.Queue()
        self.stderr = open(os.path.join(work, f"subject-{self.https}.log"), "w")
        args = [*cmd, "--directory", f"https://127.0.0.1:{peb.acme}/dir", "--acme-ca", peb.minica,
                "--domain", DOMAIN, "--https-addr", f"127.0.0.1:{self.https}",
                "--http01-addr", f"127.0.0.1:{peb.http01}", "--ari-min-secs", "0", "--ari-max-secs", "1",
                "--poll-min-secs", "1", "--poll-max-secs", "2", "--tick-ms", "100", *extra]
        self.p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr,
                                  text=True, bufsize=1, close_fds=True)
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                ev = {"event": "garbage", "line": line[:200]}
            self.events.append(ev)
            self.q.put(ev)
        self.q.put({"event": "__eof__"})

    def wait(self, pred, timeout, what):
        deadline = time.time() + timeout
        while True:
            left = deadline - time.time()
            if left <= 0:
                raise Fail(f"timeout waiting for {what}; last events: {self.events[-4:]}")
            try:
                ev = self.q.get(timeout=left)
            except queue.Empty:
                continue
            if ev.get("event") == "__eof__":
                raise Fail(f"subject exited (rc={self.p.wait()}) while waiting for {what}; last: {self.events[-4:]}")
            if pred(ev):
                return ev

    def send(self, cmd):
        self.p.stdin.write(cmd + "\n")
        self.p.stdin.flush()

    def drain(self, secs):
        end = time.time() + secs
        while time.time() < end:
            try:
                ev = self.q.get(timeout=max(0.01, end - time.time()))
                if ev.get("event") == "__eof__":
                    self.q.put(ev)
                    return
            except queue.Empty:
                pass

    def finish(self, timeout=15):
        try:
            if self.p.poll() is None:
                self.send("quit")
        except (BrokenPipeError, OSError):
            pass
        try:
            return self.p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.p.kill()
            return self.p.wait()
        finally:
            self.stderr.close()

    def has(self, name):
        return [e for e in self.events if e.get("event") == name]


class Conn:
    """A verified TLS connection (Python's OpenSSL verifies the served chain against `cafile`)."""

    def __init__(self, port, cafile):
        ctx = ssl.create_default_context(cafile=cafile)
        try:
            raw = socket.create_connection(("127.0.0.1", port), timeout=10)
            self.s = ctx.wrap_socket(raw, server_hostname=DOMAIN)
        except ssl.SSLCertVerificationError as e:
            raise ChainFail(f"served chain does not verify against {os.path.basename(cafile)}: {e.verify_message}")
        except (OSError, ssl.SSLError) as e:
            raise Fail(f"TLS connection failed: {e}")
        self.cert = self.s.getpeercert()
        self.der = self.s.getpeercert(binary_form=True)
        self.serial = int(self.cert["serialNumber"], 16)

    def request(self):
        self.s.sendall(f"GET / HTTP/1.1\r\nHost: {DOMAIN}\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise Fail("connection closed before a response")
            buf += chunk
        head, body = buf.split(b"\r\n\r\n", 1)
        n = int([l for l in head.split(b"\r\n") if l.lower().startswith(b"content-length:")][0].split(b":")[1])
        while len(body) < n:
            chunk = self.s.recv(4096)
            if not chunk:
                raise Fail("connection closed mid-body")
            body += chunk
        if not head.startswith(b"HTTP/1.1 200"):
            raise Fail(f"bad response {head[:40]!r}")
        return json.loads(body)

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def must_not_verify(port, cafile):
    try:
        Conn(port, cafile).close()
    except ChainFail:
        return
    raise Fail("chain verified against the wrong root (verification is not real)")


def ari_past_window():
    t = time.gmtime(time.time() - 7200)
    s = time.strftime("%Y-%m-%dT%H:%M:%SZ", t)
    e = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))
    return s, e


def scenario(cmd, peb, work, extra=()):
    """Main check: issue, verify chain to Pebble's root, ARI-forced renewal with a held connection, clock-forced
    renewal, CERT-1/2 gauge. Returns a summary string; raises Fail."""
    s = Subject(cmd, peb, list(extra), work)
    held = []
    try:
        inst = s.wait(lambda e: e.get("event") in ("installed", "error", "preflight_rejected"), 90, "first install")
        if inst["event"] != "installed":
            raise Fail(f"issuance failed: {inst}")
        s.wait(lambda e: e.get("event") == "ready", 10, "ready")
        a = Conn(s.https, peb.root)  # verifies leaf -> intermediate -> Pebble root, hostname = DOMAIN
        held.append(a)
        if a.serial != int(inst["serial"], 16):
            raise Fail(f"served serial {a.serial:x} != installed {inst['serial']}")
        must_not_verify(s.https, peb.minica)
        a.request()
        st = s.wait_status()
        if not (80 * DAY < st["cert_seconds_to_expiry"] <= 90 * DAY) or st["alert"] != "ok":
            raise Fail(f"CERT-1/2 on a fresh cert: {st}")

        # ARI-forced renewal: the CA moves the suggested window into the past.
        start, end = ari_past_window()
        peb.set_renewal_info(ssl.DER_cert_to_PEM_cert(a.der), start, end)
        sw = s.wait(lambda e: e.get("event") in ("swap", "error"), 30, "ARI renewal swap")
        if sw["event"] != "swap" or sw.get("reason") != "ari":
            raise Fail(f"ARI renewal: {sw}")
        b = Conn(s.https, peb.root)
        held.append(b)
        if b.serial == a.serial or b.serial != int(sw["serial"], 16):
            raise Fail(f"after ARI swap new handshake serial {b.serial:x}, swap {sw['serial']}, old {a.serial:x}")
        r = a.request()  # the connection held across the swap still works
        if r.get("store_serial") != sw["serial"]:
            raise Fail(f"held connection response {r} (store did not swap?)")

        # Clock-forced renewal: +62 d is past the new cert's ARI window (2/3 of 90 d +- 1 d).
        s.send(f"offset {62 * DAY}")
        sw2 = s.wait(lambda e: e.get("event") in ("swap", "error"), 60, "clock renewal swap")
        s.send("offset 0")
        if sw2["event"] != "swap" or sw2.get("reason") != "clock":
            raise Fail(f"clock renewal: {sw2}")
        s.drain(2)
        st = s.wait_status()
        c = Conn(s.https, peb.root)
        held.append(c)
        if c.serial != int(st["serial"], 16) or c.serial in (a.serial, b.serial):
            raise Fail(f"after clock swap served {c.serial:x}, status {st}")
        a.request()
        b.request()
        if s.has("bad_nonce_retry"):
            raise Fail("unexpected badNonce with PEBBLE_WFE_NONCEREJECT=0")
        if s.has("preflight_rejected"):
            raise Fail("preflight rejected a Pebble chain")
        return (f"issued {a.serial:x}; ARI renewal -> {b.serial:x}; clock renewal -> {c.serial:x} "
                f"({st['renewals']} renewals); chain verified to Pebble root; held connection survived 2 swaps")
    finally:
        for c in held:
            c.close()
        s.finish()


def _wait_status(self, timeout=10):
    self.send("status")
    return self.wait(lambda e: e.get("event") == "status", timeout, "status")


Subject.wait_status = _wait_status


def expired_alerts(cmd, peb, work, extra=()):
    """CERT-4 (+400 d via the injected clock) with renewal disabled: all CERT-2 alerts fire, gauge < 0."""
    s = Subject(cmd, peb, ["--no-renew", *extra], work)
    try:
        s.wait(lambda e: e.get("event") == "ready", 90, "ready")
        s.send(f"offset {400 * DAY}")
        st = s.wait_status()
        s.drain(1)
        levels = [e["level"] for e in s.has("alert")]
        if levels != ["30d", "14d", "7d", "3d", "expired"]:
            raise Fail(f"alerts fired {levels}")
        if st["cert_seconds_to_expiry"] >= 0 or st["alert"] != "expired":
            raise Fail(f"status at +400 d: {st}")
        if s.has("renewing"):
            raise Fail("renewed although --no-renew")
        return f"+400 d: gauge {st['cert_seconds_to_expiry']} s, alerts {levels}"
    finally:
        s.finish()


def expect_issue_error(cmd, peb, work, mutation, want):
    s = Subject(cmd, peb, ["--mutate", mutation], work)
    try:
        ev = s.wait(lambda e: e.get("event") in ("error", "installed", "ready"), 90, "outcome")
        rc = s.finish()
        if ev["event"] != "error" or rc == 0:
            raise Fail(f"{mutation}: subject did not report an error (got {ev}, rc={rc})")
        if not any(w in ev.get("detail", "") for w in want):
            raise Fail(f"{mutation}: error does not show the CA's rejection: {ev}")
        return f"{mutation}: rejected ({ev['detail'][:90]})"
    finally:
        s.finish()


def self_test(cmd, peb, work):
    results = []

    def case(name, fn):
        try:
            msg = fn()
            results.append((name, True, msg))
            log(f"  caught  {name}: {msg}")
        except Fail as e:
            results.append((name, False, str(e)))
            log(f"  MISSED  {name}: {e}")

    # 1. JWS signed with a key other than the one in the header: Pebble rejects, subject reports it.
    case("wrong-jws-key", lambda: expect_issue_error(cmd, peb, work, "wrong-jws-key", ["JWS", "signature", "verif"]))

    # 2. Replayed nonce: Pebble answers badNonce; the subject retries with the fresh nonce and still issues.
    def replay():
        s = Subject(cmd, peb, ["--mutate", "replay-nonce"], work)
        try:
            ev = s.wait(lambda e: e.get("event") in ("installed", "error"), 90, "outcome")
            if not s.has("bad_nonce_retry"):
                raise Fail("no badNonce observed: the replayed nonce was accepted or never sent")
            if ev["event"] != "installed":
                raise Fail(f"badNonce not handled: {ev}")
            return f"badNonce from Pebble ({len(s.has('bad_nonce_retry'))}x), retried, issued"
        finally:
            s.finish()
    case("replay-nonce", replay)

    # 3. Tampered order: CSR names a different identifier than the order; Pebble refuses to finalize.
    case("tamper-order", lambda: expect_issue_error(cmd, peb, work, "tamper-order", ["CSR", "identifier", "name", "Order"]))

    # 4. Tampered chain: the CERT-3 preflight refuses it and nothing is served.
    def tamper_chain():
        s = Subject(cmd, peb, ["--mutate", "tamper-chain"], work)
        try:
            ev = s.wait(lambda e: e.get("event") in ("preflight_rejected", "installed", "ready"), 90, "outcome")
            rc = s.finish()
            if ev["event"] != "preflight_rejected" or rc != 3 or s.has("ready"):
                raise Fail(f"tampered chain not rejected: {ev}, rc={rc}")
            return f"preflight rejected: {ev['detail'][:80]}"
        finally:
            s.finish()
    case("tamper-chain", tamper_chain)

    # 5. Expired cert with renewal disabled (+400 d): every alert fires.
    case("expired-no-renew", lambda: expired_alerts(cmd, peb, work))

    # Negative controls: the oracle's own checks go red on a broken subject.
    def must_fail(fn, what):
        try:
            fn()
        except Fail as e:
            return f"oracle FAILed as required ({what}): {str(e)[:100]}"
        raise Fail(f"oracle passed a broken subject ({what})")

    case("ctl-skip-preflight+tamper-chain",
         lambda: must_fail(lambda: scenario(cmd, peb, work, ["--mutate", "tamper-chain", "--mutate", "skip-preflight"]),
                           "served chain must verify to the Pebble root"))
    case("ctl-no-renew", lambda: must_fail(lambda: scenario(cmd, peb, work, ["--no-renew"]), "renewal must happen"))
    case("ctl-silence-alerts",
         lambda: must_fail(lambda: expired_alerts(cmd, peb, work, ["--mutate", "silence-alerts"]), "alerts must fire"))
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--subject", default=os.path.join(REPO, "target", "release", "acme-subject"))
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    cmd = a.subject.split()
    label = f"{NAME} SELF-TEST" if a.self_test else NAME
    if not shutil.which(cmd[0]) and not os.path.exists(cmd[0]):
        log(f"{label}: FAIL (subject {cmd[0]} not found; build with ci/heavy.sh cargo build --release -p acme-subject)")
        return 1
    work = tempfile.mkdtemp(prefix="acme-pebble-")
    try:
        with Pebble(work) as peb:
            log(f"pebble: acme 127.0.0.1:{peb.acme} mgmt :{peb.mgmt} http-01 :{peb.http01} dns :{peb.dns}")
            if a.self_test:
                res = self_test(cmd, peb, work)
                missed = [n for n, ok, _ in res if not ok]
                if missed:
                    log(f"{label}: FAIL (missed: {', '.join(missed)})")
                    return 1
                log(f"{label}: PASS ({len(res)}/{len(res)} mutations caught: {', '.join(n for n, _, _ in res)})")
                return 0
            summary = scenario(cmd, peb, work)
            log(summary)
            log(expired_alerts(cmd, peb, work))
            log(f"{label}: PASS (issue + renew(ARI) + renew(clock) + ARI + atomic swap + CERT-1/2/4 alerts)")
            return 0
    except Fail as e:
        log(f"{label}: FAIL ({e})")
        return 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
