"""Monban oracle: cross-request-state (CRS) differential oracle (P4-oracle-crs-001 / P4-crs-001).

Two families, one differential idea: a response- or authz-determining piece of state carried between requests must
depend only on the scope of the request that uses it, never on an earlier request in a different scope
(SPEC_INVARIANTS CRS C2/C3/C8, and C8's Phase-4 in-process clarification).

  --family tls-resume   The nginx/CVE-2025-23419 shape. A TLS session minted while serving vhost A (a context that
                        does not verify the client certificate) must never be *Reused* when the handshake selects a
                        different scope: another vhost (cross-SNI, the CVE), a different ALPN, or a bumped epoch.
                        σ(session) must equal σ(request) (R-PQC-6: ticketer per cert-chain hash, verifier, ALPN,
                        epoch; no resumption on mTLS listeners). PASS iff no cross-scope handshake is ever Reused.

  --family data         The two-scope data differential (C5b "R2 two-scope differentials"). The same request is run
                        under scope A and then under scope B over the PG pool, the Redis connection, the
                        statement/type cache, the idempotency store and the outbox; PASS iff B's observable state
                        never depends on A (C8 for in-process engines, D7: a recycled connection carries no
                        per-connection state; C8 R-DB-5: no backend connection shared across tenants).

Stdlib only; run as `python3 -I crsdiff.py`. See README.md for the subject wire protocol and the honest-scope note
(against today's monban, tls-resume PASSES by construction: tickets are off and there is no mTLS listener, so the
gate's teeth are the self-test and the guard for the future scoped ticketer P2-tls-002).
"""

import argparse
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

NAME = "CRS-DIFF"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def line(s):
    print(s, flush=True)


# ================================================================================================== TLS-RESUME family
#
# A "server" exposes a TLS listener on 127.0.0.1 with at least two named scopes and a way to bump the epoch. The
# checker mints a session on the open scope and then tries to resume it under scopes that differ in exactly one
# coordinate of σ; any Reused handshake there is a violation. A legitimate resume (every coordinate identical) is
# allowed and is NOT a violation, so the oracle also tolerates a future scoped ticketer.


def openssl_present():
    return shutil.which("openssl") is not None


def mint_cert(d):
    key = os.path.join(d, "srv.key")
    crt = os.path.join(d, "srv.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
         "-keyout", key, "-out", crt, "-days", "2", "-subj", "/CN=a.test",
         "-addext", "subjectAltName=DNS:a.test,DNS:b.test,DNS:secure.test"],
        check=True, capture_output=True, timeout=30)
    ca_key = os.path.join(d, "ca.key")
    ca = os.path.join(d, "ca.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
         "-keyout", ca_key, "-out", ca, "-days", "2", "-subj", "/CN=crs-ca"],
        check=True, capture_output=True, timeout=30)
    return crt, key, ca


def s_client(port, sni, alpn, sess_out=None, sess_in=None, timeout=12):
    """One openssl s_client handshake. Returns 'reused' | 'new' | 'refused' (connection/handshake rejected)."""
    cmd = ["openssl", "s_client", "-connect", f"127.0.0.1:{port}", "-servername", sni, "-alpn", alpn, "-ign_eof"]
    if sess_out:
        cmd += ["-sess_out", sess_out]
    if sess_in:
        cmd += ["-sess_in", sess_in]
    try:
        r = subprocess.run(cmd, input=b"GET / HTTP/1.1\r\nHost: " + sni.encode() + b"\r\nConnection: close\r\n\r\n",
                           capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "refused"
    out = (r.stdout + r.stderr).decode(errors="replace")
    if "Reused, TLS" in out:
        return "reused"
    if "New, TLS" in out or "New, (NONE)" in out:
        return "new"
    # No clean handshake line: treat a verify/alert as a refusal (the mTLS context rejected us), not a resume.
    return "refused"


def tls_check(server, verbose=False):
    """Run the cross-scope resumption differential against a started `server`. Returns (violations, notes)."""
    viols, notes = [], []
    d = tempfile.mkdtemp(prefix="crs-tls-sess-")
    try:
        open_scope = server.open_sni      # a vhost context with no client-cert verification
        other_scope = server.other_sni    # a different vhost context (CVE-2025-23419: mTLS/verify-required)
        sess = os.path.join(d, "s1")

        mint = s_client(server.port, open_scope, "http/1.1", sess_out=sess)
        notes.append(f"mint[{open_scope},http/1.1]={mint}")
        if not os.path.exists(sess) or os.path.getsize(sess) == 0:
            # The server issued no resumable session at all (today's monban: tickets off). Nothing can be Reused.
            notes.append("no resumable session issued (tickets off) -> no cross-scope reuse possible")
            return viols, notes

        # σ coordinate = vhost / cert-chain+verifier (the CVE axis): resume under the other vhost context.
        r = s_client(server.port, other_scope, "http/1.1", sess_in=sess)
        notes.append(f"cross-vhost[{other_scope}]={r}")
        if r == "reused":
            viols.append(f"cross-vhost resume accepted: session minted on {open_scope} Reused on {other_scope} "
                         f"(CVE-2025-23419 shape: SNI-switched context accepted a foreign ticket)")

        # σ coordinate = ALPN.
        r = s_client(server.port, open_scope, "h2", sess_in=sess)
        notes.append(f"cross-alpn[h2]={r}")
        if r == "reused":
            viols.append(f"cross-ALPN resume accepted: ticket minted under http/1.1 Reused under h2 on {open_scope}")

        # σ coordinate = epoch (if the server can rotate it).
        if server.bump_epoch():
            r = s_client(server.port, open_scope, "http/1.1", sess_in=sess)
            notes.append(f"cross-epoch[{open_scope}]={r}")
            if r == "reused":
                viols.append(f"cross-epoch resume accepted: ticket from the previous epoch Reused on {open_scope} "
                             f"after a key/epoch change (C5b: buffers/keys must be empty at a key change)")
        else:
            notes.append("cross-epoch: server exposes no epoch bump (skipped)")

        # Control: a same-scope resume is legitimate and must NOT be counted as a violation.
        r = s_client(server.port, open_scope, "http/1.1", sess_in=sess)
        notes.append(f"same-scope[{open_scope},http/1.1]={r} (allowed; not a violation)")
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return viols, notes


class MonbanTlsServer:
    """The real monban binary, driven over TLS like proxy-e2e. Two vhosts a.test/b.test; SIGHUP = epoch bump."""

    open_sni = "a.test"
    other_sni = "b.test"

    def __init__(self, subject):
        self.subject = subject
        self.proc = None
        self.up = None
        self.dir = tempfile.mkdtemp(prefix="crs-tls-monban-")

    def _recorder(self):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        s.listen(64)
        self.up = s

        def loop():
            while True:
                try:
                    c, _ = s.accept()
                except OSError:
                    return
                try:
                    c.recv(65536)
                    c.sendall(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                except OSError:
                    pass
                finally:
                    c.close()

        threading.Thread(target=loop, daemon=True).start()
        return s.getsockname()[1]

    def _config(self):
        u = f"127.0.0.1:{self.up_port}"
        return {
            "v": 1,
            "listeners": [{"name": "pub", "bind": f"127.0.0.1:{self.port}", "profile": "P-PUBLIC-WEB",
                           "alpn": ["h2", "http/1.1"]}],
            "admin": {"bind": f"127.0.0.1:{self.aport}"},
            "vhosts": [
                {"host": "a.test", "routes": [{"id": 1, "path": "/", "to": {"upstream": u}, "authz": "allow-all"}]},
                {"host": "b.test", "routes": [{"id": 1, "path": "/", "to": {"upstream": u}, "authz": "allow-all"}]},
            ],
        }

    def _write_config(self):
        with open(self.cfg, "w") as f:
            json.dump(self._config(), f)

    def start(self):
        self.up_port = self._recorder()
        self.port, self.aport = free_port(), free_port()
        self.crt, self.key, _ca = mint_cert(self.dir)
        self.cfg = os.path.join(self.dir, "monban.json")
        self._write_config()
        env = dict(os.environ)
        env.pop("NOTIFY_SOCKET", None)
        env.pop("AEGIS_UPGRADE_DIR", None)
        self.log = open(os.path.join(self.dir, "monban.log"), "wb")
        self.proc = subprocess.Popen(
            [self.subject, "--config", self.cfg, "--cert", self.crt, "--key", self.key,
             "--audit-dir", os.path.join(self.dir, "audit")],
            stdout=self.log, stderr=subprocess.STDOUT, env=env)
        until = time.time() + 20
        while time.time() < until:
            if self.proc.poll() is not None:
                raise RuntimeError(f"monban exited {self.proc.returncode} at start: {self._tail()}")
            try:
                with socket.create_connection(("127.0.0.1", self.aport), timeout=0.5) as c:
                    c.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                    if b" 200 " in c.recv(256):
                        return
            except OSError:
                pass
            time.sleep(0.1)
        raise RuntimeError(f"monban did not become healthy: {self._tail()}")

    def bump_epoch(self):
        # A config reload is an epoch change for the serving config generation. monban issues no ticket, so this is
        # exercised for completeness; a scoped ticketer must not resume across it.
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGHUP)
            time.sleep(0.5)
            return True
        return False

    def _tail(self):
        try:
            with open(os.path.join(self.dir, "monban.log"), "rb") as f:
                return f.read()[-2000:].decode(errors="replace")
        except OSError:
            return ""

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.up:
            self.up.close()
        shutil.rmtree(self.dir, ignore_errors=True)


class PyReplicaServer:
    """In-oracle reference TLS server using Python ssl. `vulnerable=True` reproduces the CVE-2025-23419 shape: an
    SNI callback switches the connection to a client-cert-verifying context (secure.test) *after* the base context
    has already accepted a resumption ticket it minted on the open context (a.test), so the client-cert check is
    skipped on resumption. `vulnerable=False` is the safe control: resumption disabled, like today's monban."""

    open_sni = "a.test"
    other_sni = "secure.test"

    def __init__(self, vulnerable):
        self.vulnerable = vulnerable
        self.dir = tempfile.mkdtemp(prefix="crs-tls-replica-")
        self.ls = None
        self.stopped = False

    def start(self):
        crt, key, ca = mint_cert(self.dir)
        base = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        base.minimum_version = ssl.TLSVersion.TLSv1_3
        base.load_cert_chain(crt, key)
        base.set_alpn_protocols(["h2", "http/1.1"])
        if not self.vulnerable:
            # Safe control, like today's monban: issue no TLS 1.3 session tickets, so nothing is ever resumable.
            try:
                base.num_tickets = 0
            except (ValueError, AttributeError):
                base.options |= getattr(ssl, "OP_NO_TICKET", 0)
        secure = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        secure.minimum_version = ssl.TLSVersion.TLSv1_3
        secure.load_cert_chain(crt, key)
        secure.set_alpn_protocols(["h2", "http/1.1"])
        secure.verify_mode = ssl.CERT_REQUIRED       # mTLS: requires a client certificate
        secure.load_verify_locations(ca)

        def cb(sock, name, ctx):
            if name == "secure.test":
                sock.context = secure      # the CVE: context switched by SNI, resumption already decided on `base`

        base.sni_callback = cb
        self.base = base
        ls = socket.socket()
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind(("127.0.0.1", 0))
        ls.listen(64)
        self.ls = ls
        self.port = ls.getsockname()[1]

        def handle(c):
            try:
                s = base.wrap_socket(c, server_side=True)
                s.recv(4096)
                s.sendall(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                s.close()
            except (ssl.SSLError, OSError):
                try:
                    c.close()
                except OSError:
                    pass

        def loop():
            while not self.stopped:
                try:
                    c, _ = ls.accept()
                except OSError:
                    return
                threading.Thread(target=handle, args=(c,), daemon=True).start()

        threading.Thread(target=loop, daemon=True).start()

    def bump_epoch(self):
        return False

    def stop(self):
        self.stopped = True
        if self.ls:
            self.ls.close()
        shutil.rmtree(self.dir, ignore_errors=True)


def run_tls(subject, verbose=False):
    if not openssl_present():
        line(f"{NAME}: FAIL (openssl CLI not found; needed for the s_client resumption client)")
        return 1
    if not subject:
        line(f"{NAME}: FAIL (tls-resume needs --subject <monban binary>)")
        return 1
    srv = MonbanTlsServer(subject)
    try:
        srv.start()
        viols, notes = tls_check(srv, verbose)
    except Exception as e:  # noqa: BLE001 - any harness error is a FAIL with its reason
        line(f"{NAME}: FAIL (harness: {e})")
        return 1
    finally:
        srv.stop()
    if verbose:
        for n in notes:
            line(f"  {n}")
    if viols:
        for v in viols:
            line(f"  VIOLATION {v}")
        line(f"{NAME}: FAIL (tls-resume: {len(viols)} cross-scope resumption(s) accepted)")
        return 1
    line(f"{NAME}: PASS (tls-resume: no cross-scope session reuse; {'; '.join(notes)})")
    return 0


def selftest_tls(verbose=False):
    if not openssl_present():
        line(f"{NAME} SELF-TEST: FAIL (openssl CLI not found)")
        return 1
    # 1) The vulnerable replica (CVE-2025-23419 shape) MUST be caught (go red).
    vuln = PyReplicaServer(vulnerable=True)
    try:
        vuln.start()
        viols, notes = tls_check(vuln, verbose)
    finally:
        vuln.stop()
    if verbose:
        for n in notes:
            line(f"  vuln: {n}")
    if not viols:
        line(f"{NAME} SELF-TEST: FAIL (the CVE-2025-23419 vulnerable replica was NOT caught: {'; '.join(notes)})")
        return 1
    caught = "; ".join(viols)
    # 2) The safe control (resumption disabled, like today's monban) MUST pass (no false positive).
    safe = PyReplicaServer(vulnerable=False)
    try:
        safe.start()
        sviols, snotes = tls_check(safe, verbose)
    finally:
        safe.stop()
    if sviols:
        line(f"{NAME} SELF-TEST: FAIL (false positive on the safe control: {'; '.join(sviols)})")
        return 1
    line(f"{NAME} SELF-TEST: PASS (tls: vulnerable replica caught [{caught}]; safe control clean)")
    return 0


# ======================================================================================================= DATA family
#
# Subject wire protocol (one JSON object per line on stdin; one JSON reply per line on stdout). See README. The
# oracle only reads the observation fields below; how the subject produces them (real engines vs. reference) is the
# subject's business.
#
#   {"op":"hello"}                                   -> {"ok":true}
#   {"op":"scope","principal":P,"tenant":T,"epoch":E}-> {"ok":true}   (T is 16-hex u64, monban_data_ir::tenant_text)
#   {"op":"do","kind":"sql"}                         -> {"conn":str,"guc":{"tenant":str},"temp_residual":bool,"cache":str}
#   {"op":"do","kind":"idem","key":K,"value":V}      -> {"idem": <stored value or null>, "fresh": bool}
#   {"op":"do","kind":"outbox","entry":X}            -> {"outbox": [<entries visible under current scope>]}
#   {"op":"bye"}                                      -> (exit)
#
# A "do sql" models one data request: it acquires a pooled backend for the current scope, reports the connection
# identity, the session tenant GUC it observes, whether a residual per-connection object was present at acquire
# time (C8/D7), and the statement/type cache identity it is bound to; then it does its work and returns the backend.


class RefSubject:
    """In-oracle reference data subject. `mutants` is a set of flaw names; the empty set is the correct subject."""

    def __init__(self, mutants=frozenset()):
        self.m = set(mutants)
        self.scope = None
        self.pool = {}         # key -> {"id":str, "temp":bool, "cache":str}
        self.next_conn = 0
        self.idem = {}         # key -> value
        self.outbox = []       # list of (principal, tenant, entry)

    def _poolkey(self):
        p, t, e = self.scope
        if "shared-pool" in self.m:
            return ("*",)                 # one connection for everything
        if "pool-key-no-tenant" in self.m:
            return ("epoch", e)           # tenants of the same epoch share a backend (C8 R-DB-5 violated)
        if "pool-key-no-epoch" in self.m:
            return ("tenant", t)          # survives an epoch bump (C5 epoch revocation violated)
        return ("tenant-epoch", t, e)     # correct: per (tenant, epoch)

    def _acquire(self):
        k = self._poolkey()
        c = self.pool.get(k)
        fresh = c is None
        if fresh:
            c = {"id": f"conn-{self.next_conn}", "temp": False, "cache": f"cache-{self.next_conn}"}
            self.next_conn += 1
            self.pool[k] = c
        return c

    def do_sql(self):
        _p, t, _e = self.scope
        c = self._acquire()
        residual = c["temp"]                 # observed BEFORE this request dirties the connection
        obs = {"conn": c["id"], "guc": {"tenant": t}, "temp_residual": residual, "cache": c["cache"]}
        # This request dirties the connection (a temp object / session state), then returns it to the pool.
        c["temp"] = True
        if "no-reset-on-recycle" not in self.m:
            c["temp"] = False                # correct: recycled objects are reset on checkin (C8)
        return obs

    def do_idem(self, key, value):
        p, _t, _e = self.scope
        ik = key if "idem-key-without-principal" in self.m else (p, key)
        if ik in self.idem:
            return {"idem": self.idem[ik], "fresh": False}
        self.idem[ik] = value
        return {"idem": None, "fresh": True}

    def do_outbox(self, entry):
        p, t, _e = self.scope
        self.outbox.append((p, t, entry))
        if "outbox-no-principal" in self.m:
            vis = [x[2] for x in self.outbox]
        else:
            vis = [x[2] for x in self.outbox if x[0] == p and x[1] == t]
        return {"outbox": vis}

    def call(self, req):
        op = req.get("op")
        if op == "hello":
            return {"ok": True}
        if op == "scope":
            self.scope = (req["principal"], req["tenant"], int(req["epoch"]))
            return {"ok": True}
        if op == "do":
            k = req.get("kind")
            if k == "sql":
                return self.do_sql()
            if k == "idem":
                return self.do_idem(req["key"], req["value"])
            if k == "outbox":
                return self.do_outbox(req["entry"])
            return {"error": f"unknown kind {k}"}
        return {"error": f"unknown op {op}"}

    def close(self):
        pass


class ProcSubject:
    """A real subject process speaking the JSON-lines protocol over stdin/stdout (e.g. target/release/crs-subject)."""

    def __init__(self, argv):
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  bufsize=1, text=True)

    def call(self, req):
        if self.p.poll() is not None:
            raise RuntimeError(f"subject exited {self.p.returncode}")
        self.p.stdin.write(json.dumps(req) + "\n")
        self.p.stdin.flush()
        resp = self.p.stdout.readline()
        if not resp:
            raise RuntimeError("subject closed stdout")
        return json.loads(resp)

    def close(self):
        try:
            self.call({"op": "bye"})
        except Exception:
            pass
        try:
            self.p.stdin.close()
            self.p.wait(5)
        except Exception:
            self.p.kill()


# Two scopes used throughout the data differential (tenants are 16-hex u64, monban_data_ir::tenant_text).
TA = "000000000000000a"
TB = "000000000000000b"
PA = "principal-a"
PB = "principal-b"


def data_check(subject, verbose=False):
    """Run the two-scope data differentials against a subject. Returns (violations, notes)."""
    viols, notes = [], []

    def call(req):
        r = subject.call(req)
        if verbose:
            notes.append(f"{json.dumps(req)} -> {json.dumps(r)}")
        return r

    call({"op": "hello"})

    # --- C8 / R-DB-5: no backend connection shared across tenants; B's GUC is B's own tenant, not A's. -----------
    call({"op": "scope", "principal": PA, "tenant": TA, "epoch": 1})
    a = call({"op": "do", "kind": "sql"})
    call({"op": "scope", "principal": PB, "tenant": TB, "epoch": 1})
    b = call({"op": "do", "kind": "sql"})
    if a["conn"] == b["conn"]:
        viols.append(f"pool conn shared across tenants: {TA} and {TB} both got {a['conn']} (C8 R-DB-5)")
    if b["guc"].get("tenant") != TB:
        viols.append(f"session GUC leaked across scope: B(tenant={TB}) observed tenant GUC {b['guc'].get('tenant')}")

    # --- C5 epoch revocation: a bumped epoch must not reuse the pre-bump connection or its cache. -----------------
    call({"op": "scope", "principal": PA, "tenant": TA, "epoch": 1})
    e1 = call({"op": "do", "kind": "sql"})
    call({"op": "scope", "principal": PA, "tenant": TA, "epoch": 2})
    e2 = call({"op": "do", "kind": "sql"})
    if e1["conn"] == e2["conn"]:
        viols.append(f"epoch bump reused the connection: epoch1 and epoch2 both got {e1['conn']} (C5)")
    if e1["cache"] == e2["cache"]:
        viols.append(f"epoch bump reused the statement/type cache: {e1['cache']} (C3/C5)")

    # --- C8 / D7: a recycled connection carries no residual per-connection state. --------------------------------
    call({"op": "scope", "principal": PA, "tenant": TA, "epoch": 3})
    call({"op": "do", "kind": "sql"})                       # dirties the backend
    r2 = call({"op": "do", "kind": "sql"})                  # reuses the same pooled backend
    if r2["temp_residual"]:
        viols.append("recycled connection kept per-connection state (C8/D7: no reset on recycle)")

    # --- C6 / idempotency keyed by principal: B must not retrieve A's stored outcome under a shared key. ---------
    call({"op": "scope", "principal": PA, "tenant": TA, "epoch": 1})
    call({"op": "do", "kind": "idem", "key": "k1", "value": "VA"})
    call({"op": "scope", "principal": PB, "tenant": TB, "epoch": 1})
    ib = call({"op": "do", "kind": "idem", "key": "k1", "value": "VB"})
    if not ib["fresh"] or ib["idem"] == "VA":
        viols.append("idempotency store not keyed by principal: B retrieved A's stored outcome (C2/C6)")

    # --- outbox scoped by principal: B sees only its own entries. -----------------------------------------------
    call({"op": "scope", "principal": PA, "tenant": TA, "epoch": 1})
    call({"op": "do", "kind": "outbox", "entry": "ea"})
    call({"op": "scope", "principal": PB, "tenant": TB, "epoch": 1})
    ob = call({"op": "do", "kind": "outbox", "entry": "eb"})
    if "ea" in ob["outbox"]:
        viols.append("outbox not scoped by principal: B observed A's entry (C2/NC6)")

    return viols, notes


def data_differential(make_subject, verbose=False):
    """The overarching C5b check: B's observations must not depend on A. Run B's fixed sequence after two different
    A-prefixes and require B's observations to match. (Connection identities are allowed to differ only in their
    freshly-minted index, so we compare the scope-determined fields.)"""
    def b_run(a_variant):
        s = make_subject()
        try:
            s.call({"op": "hello"})
            # A-prefix (varied):
            s.call({"op": "scope", "principal": a_variant[0], "tenant": a_variant[1], "epoch": a_variant[2]})
            s.call({"op": "do", "kind": "sql"})
            s.call({"op": "do", "kind": "idem", "key": "shared", "value": a_variant[3]})
            s.call({"op": "do", "kind": "outbox", "entry": a_variant[4]})
            # B-sequence (fixed):
            s.call({"op": "scope", "principal": PB, "tenant": TB, "epoch": 5})
            sql = s.call({"op": "do", "kind": "sql"})
            idem = s.call({"op": "do", "kind": "idem", "key": "shared", "value": "VB"})
            ob = s.call({"op": "do", "kind": "outbox", "entry": "eb"})
            return (sql["guc"], sql["temp_residual"], idem["fresh"], idem["idem"], ob["outbox"])
        finally:
            s.close()

    r1 = b_run((PA, TA, 1, "VA1", "ea1"))
    r2 = b_run(("principal-c", "000000000000000c", 9, "VC", "ec"))
    if r1 != r2:
        return [f"B's observable state depends on A: {r1!r} != {r2!r} (C5b two-scope differential)"]
    return []


def run_data(subject_argv, verbose=False):
    if not subject_argv:
        line(f"{NAME}: FAIL (data needs --subject <crs-subject binary>)")
        return 1
    subject = ProcSubject(subject_argv)
    try:
        viols, notes = data_check(subject, verbose)
    except Exception as e:  # noqa: BLE001
        line(f"{NAME}: FAIL (data harness: {e})")
        return 1
    finally:
        subject.close()
    viols += data_differential(lambda: ProcSubject(subject_argv), verbose)
    if verbose:
        for n in notes:
            line(f"  {n}")
    if viols:
        for v in viols:
            line(f"  VIOLATION {v}")
        line(f"{NAME}: FAIL (data: {len(viols)} cross-request leak(s))")
        return 1
    line(f"{NAME}: PASS (data: B's observable state never depends on A across pool/cache/idempotency/outbox)")
    return 0


DATA_MUTANTS = ["shared-pool", "pool-key-no-tenant", "pool-key-no-epoch", "no-reset-on-recycle",
                "idem-key-without-principal", "outbox-no-principal"]


def selftest_data(verbose=False):
    # The correct reference subject must pass.
    viols, _ = data_check(RefSubject(), verbose)
    viols += data_differential(lambda: RefSubject(), verbose)
    if viols:
        line(f"{NAME} SELF-TEST: FAIL (the correct reference data subject was flagged: {'; '.join(viols)})")
        return 1
    # Each reference mutant must be caught by at least one check.
    missed = []
    for m in DATA_MUTANTS:
        v, _ = data_check(RefSubject({m}), verbose)
        v += data_differential(lambda m=m: RefSubject({m}), verbose)
        if verbose:
            line(f"  mutant {m}: {len(v)} violation(s)")
        if not v:
            missed.append(m)
    if missed:
        line(f"{NAME} SELF-TEST: FAIL (data mutants not caught: {', '.join(missed)})")
        return 1
    line(f"{NAME} SELF-TEST: PASS (data: reference clean; all {len(DATA_MUTANTS)} mutants caught "
         f"[{', '.join(DATA_MUTANTS)}])")
    return 0


# =============================================================================================================== main


def main():
    ap = argparse.ArgumentParser(description="CRS differential oracle (tls-resume + data families)")
    ap.add_argument("--family", choices=["tls-resume", "data", "all"], default=None)
    ap.add_argument("--subject", default=None, help="tls: monban binary; data: crs-subject (quoted argv allowed)")
    ap.add_argument("--self-test", action="store_true", dest="selftest")
    ap.add_argument("--pg", default=None)       # accepted and ignored here: the data subject connects to engines
    ap.add_argument("--redis", default=None)    # itself; the oracle passes these through to the subject argv.
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    subj_argv = None
    if args.subject:
        subj_argv = args.subject.split()
        for flag, val in (("--pg", args.pg), ("--redis", args.redis)):
            if val:
                subj_argv += [flag, val]

    if args.selftest:
        fams = ["tls-resume", "data"] if args.family in (None, "all") else [args.family]
        rc = 0
        for f in fams:
            rc |= (selftest_tls if f == "tls-resume" else selftest_data)(args.verbose)
        return rc

    # The ci/oracles.sh sweep passes only --subject (default-subject: the monban binary): that is the tls-resume run.
    # The data family needs engines, so it runs only as gate crs-data with an explicit --family data.
    if args.family is None and args.subject and not (args.pg or args.redis):
        args.family = "tls-resume"
    if args.family == "tls-resume":
        return run_tls(args.subject, args.verbose)
    if args.family == "data":
        return run_data(subj_argv, args.verbose)
    line(f"{NAME}: FAIL (--family all is only for --self-test; pick tls-resume or data for a subject run)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
