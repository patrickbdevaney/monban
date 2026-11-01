#!/usr/bin/env python3
"""p2-e2e reference (mock) subject: an oracle-local model of the aegis supervisor with feature `p2`.

It follows the subject contract in README.md closely enough for the oracle to PASS on it, and each mutant
(AEGIS_P2_MUTANT) breaks exactly one obligation. It is a model of supervisor behaviour, not of the product: TLS via
the stdlib, a minimal F5 Tier-L verifier, the F8 subset the oracle writes, JSON frames to ref_worker.py instead of
F14 postcard frames, and no sandbox. Never shipped, never a source of claims about aegis.

  ref_subject.py --config <f8.json> --cert <pem> --key <pem> --audit-dir <d> --runtime-dir <d> --token-keyring <f>
  ref_subject.py check-config <f8.json> [--print-effective]

Mutants: shared-cordon, fork-respawn, global-crash-budget, no-crash-budget, budget-counts-healthy, dumpable-1
(in ref_worker.py), no-reload-switch, boot-without-landlock-accepted, auto-ignores-cpus.
"""

import base64
import collections
import copy
import hashlib
import hmac
import http.server
import json
import os
import re
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.dont_write_bytecode = True  # keep the oracle directory clean
import p2wire  # noqa: E402

EX_CONFIG = 78
MUTANT = os.environ.get("AEGIS_P2_MUTANT", "")
SCHEMA = os.path.join(REPO, "interfaces", "F8-config.schema.json")


def log(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


# ------------------------------------------------------------------------------------------------ config


class ConfigError(Exception):
    pass


def _schema():
    with open(SCHEMA) as f:
        return json.load(f)


def _check_obj(obj, sch, where):
    if not isinstance(obj, dict):
        raise ConfigError(f"{where}: not an object")
    props = sch.get("properties", {})
    for k in obj:
        if k not in props:
            raise ConfigError(f"{where}: unknown field {k}")
    for k in sch.get("required", []):
        if k not in obj:
            raise ConfigError(f"{where}: missing {k}")
    for k, v in obj.items():
        p = props[k]
        t = p.get("type")
        if t == "integer":
            if not isinstance(v, int) or isinstance(v, bool) or not p["minimum"] <= v <= p["maximum"]:
                raise ConfigError(f"{where}.{k}: out of bounds")
        elif t == "string":
            if not isinstance(v, str) or ("pattern" in p and not re.fullmatch(p["pattern"], v)):
                raise ConfigError(f"{where}.{k}: bad string")
        elif t == "boolean":
            if not isinstance(v, bool):
                raise ConfigError(f"{where}.{k}: not a boolean")
        elif "enum" in p and v not in p["enum"]:
            raise ConfigError(f"{where}.{k}: not in {p['enum']}")


def validate(doc):
    """The F8 subset the oracle writes. Raises ConfigError."""
    s = _schema()
    if not isinstance(doc, dict):
        raise ConfigError("not an object")
    for k in doc:
        if k not in s["properties"]:
            raise ConfigError(f"unknown top-level field {k}")
    mods = {}
    if "p2" in doc:
        p2 = doc["p2"]
        _check_obj(p2, s["$defs"]["p2"], "p2")
        if "crash_budget" in p2:
            _check_obj(p2["crash_budget"], s["$defs"]["p2_crash_budget"], "p2.crash_budget")
        if not isinstance(p2["modules"], list) or not p2["modules"]:
            raise ConfigError("p2.modules: empty")
        for m in p2["modules"]:
            _check_obj(m, s["$defs"]["p2_module"], "p2.modules[]")
            if m["id"] in mods:
                raise ConfigError(f"p2.modules: duplicate id {m['id']}")
            mods[m["id"]] = m
    route_props = s["$defs"]["route"]["properties"]
    for vh in doc.get("vhosts", []):
        for r in vh.get("routes", []):
            for k in r:
                if k not in route_props:
                    raise ConfigError(f"route {r.get('id')}: unknown field {k}")
            to = r.get("to", {})
            if "wasm" in to:
                if set(to) != {"wasm"}:
                    raise ConfigError("route.to: unknown field")
                if to["wasm"] not in mods:
                    raise ConfigError(f"route {r.get('id')}: wasm module {to['wasm']} not declared in p2.modules")


AUTO_CORDON_BELOW = 8  # PLAN-5 D23 option (b)


def usable_cpus():
    return max(1, len(os.sched_getaffinity(0)))


def resolve(isolation, cpus):
    if isolation == "auto":
        return "cordon" if cpus < AUTO_CORDON_BELOW else "forkwasm"
    return isolation


def path_of(p2):
    """The path multi-principal modules are served on (the effective one, unless the auto-ignores-cpus mutant)."""
    if MUTANT == "auto-ignores-cpus" and p2["isolation"] == "auto":
        return "forkwasm"  # negative control: auto ignores the CPU count (the dump stays truthful)
    return p2["isolation_effective"]


def effective(doc):
    s = _schema()
    d = copy.deepcopy(doc)
    if "p2" in d:
        p2 = d["p2"]
        for k, p in s["$defs"]["p2"]["properties"].items():
            if "default" in p and k not in p2:
                p2[k] = p["default"]
        cb = p2.setdefault("crash_budget", {})
        for k, p in s["$defs"]["p2_crash_budget"]["properties"].items():
            cb.setdefault(k, p["default"])
        for m in p2["modules"]:
            m.setdefault("tenancy", "multi")
        n = usable_cpus()
        p2["isolation_effective"] = resolve(p2["isolation"], n)
        p2["usable_cpus"] = n
    return d


def boot_checks(doc):
    """Serve-time checks beyond the schema: worker present, digests, sandboxed compile (Landlock ABI >= 4)."""
    p2 = doc.get("p2")
    if not p2:
        return
    w = p2["worker"]
    if not (os.path.isfile(w) and os.access(w, os.X_OK)):
        raise ConfigError(f"p2.worker {w}: missing or not executable")
    for m in p2["modules"]:
        try:
            with open(m["path"], "rb") as f:
                dig = hashlib.sha256(f.read()).hexdigest()
        except OSError as e:
            raise ConfigError(f"module {m['id']}: {e}")
        if dig != m["sha256"]:
            raise ConfigError(f"module {m['id']}: digest mismatch")
        rc = subprocess.run([w, "compile", "--module", m["path"], "--sha256", m["sha256"]],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30).returncode
        if rc != 0:
            if MUTANT == "boot-without-landlock-accepted":
                log(f"mutant: compile of {m['id']} exited {rc}; booting anyway")
                continue
            raise ConfigError(f"module {m['id']}: sandboxed compile exited {rc}")


def load(path, serving):
    with open(path, "rb") as f:
        raw = f.read()
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise ConfigError(f"not JSON: {e}")
    validate(doc)
    eff = effective(doc)
    if serving:
        boot_checks(eff)
    return eff


# ------------------------------------------------------------------------------------------------ F5 Tier-L verify


def cbor_decode(b):
    def item(i):
        ib = b[i]
        mt, ai = ib >> 5, ib & 31
        i += 1
        if ai < 24:
            n = ai
        elif ai in (24, 25, 26, 27):
            w = 1 << (ai - 24)
            n = int.from_bytes(b[i:i + w], "big")
            i += w
        else:
            raise ValueError("cbor: unsupported")
        if mt == 0:
            return n, i
        if mt in (2, 3):
            v = b[i:i + n]
            return (v if mt == 2 else v.decode()), i + n
        if mt == 4:
            out = []
            for _ in range(n):
                v, i = item(i)
                out.append(v)
            return out, i
        raise ValueError("cbor: unsupported major type")
    v, i = item(0)
    if i != len(b):
        raise ValueError("cbor: trailing bytes")
    return v


def cbor_encode(v):
    def head(mt, n):
        if n < 24:
            return bytes([(mt << 5) | n])
        for ai, w in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * w):
                return bytes([(mt << 5) | ai]) + n.to_bytes(w, "big")
        raise ValueError(n)
    if isinstance(v, int):
        return head(0, v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    return head(4, len(v)) + b"".join(cbor_encode(x) for x in v)


def verify_token(tok, keys, aud):
    """Returns the tenant (int) or None."""
    try:
        raw = base64.urlsafe_b64decode(tok + "=" * (-len(tok) % 4))
        v, kid, nonce, cavs, tag = cbor_decode(raw)
        if v != 1 or kid not in keys:
            return None
        prk = hmac.new(b"", keys[kid], hashlib.sha256).digest()
        a = aud.encode()
        info = b"aegis-cap-v1" + struct.pack("!H", len(a)) + a + struct.pack("!H", len(kid)) + kid
        t = hmac.new(hmac.new(prk, info + b"\x01", hashlib.sha256).digest(), kid + nonce, hashlib.sha256).digest()
        for c in cavs:
            t = hmac.new(t, cbor_encode(c), hashlib.sha256).digest()
        if not hmac.compare_digest(t, tag):
            return None
        cv = {c[0]: c[1] for c in cavs}
        if cv.get(0) != aud or cv.get(1, 0) <= time.time() or 6 not in cv:
            return None
        return cv[6]
    except (ValueError, TypeError, IndexError, KeyError):
        return None


# ------------------------------------------------------------------------------------------------ P2 runtime


class Runtime:
    def __init__(self, rundir):
        self.rundir = rundir
        self.lock = threading.Lock()
        self.cfg = None
        self.zygote = None          # Popen (correct) or pid (template mutant)
        self.zsock = None
        self.template = None
        self.cordons = {}           # key -> {"proc","sock","lock"}
        self.crashes = collections.defaultdict(collections.deque)
        self.penalty = {}
        self.broken = False         # no-reload-switch mutant
        self.gen = 0

    # -------------------------------------------------------------- lifecycle
    def apply(self, cfg):
        with self.lock:
            old = self.cfg
            self.cfg = cfg
            self.gen += 1
            self.modfile = os.path.join(self.rundir, f"modules-{self.gen}.json")
            p2 = cfg.get("p2")
            if p2:
                with open(self.modfile, "w") as f:
                    json.dump([{"id": m["id"], "path": m["path"], "sha256": m["sha256"],
                                "wall_ms": m.get("wall_ms", p2["wall_ms"])} for m in p2["modules"]], f)
            if p2:
                log(f"ref_subject: p2: isolation {p2['isolation']} -> {path_of(p2)} ({p2['usable_cpus']} usable CPUs)")
            if old is not None and old.get("p2") and p2 and path_of(old["p2"]) != path_of(p2):
                if MUTANT == "no-reload-switch":
                    self.broken = True
                if path_of(p2) == "cordon":
                    self._retire_zygote()
                else:
                    self._retire_cordons()
            elif old is not None:
                self._retire_zygote()
                self._retire_cordons()

    def shutdown(self):
        with self.lock:
            self._retire_zygote()
            self._retire_cordons()
            if self.template:
                self.template[0].kill()
                self.template[0].wait()
                self.template = None

    def _worker(self):
        return self.cfg["p2"]["worker"]

    def _retire_zygote(self):
        z = self.zygote
        self.zygote = None
        if isinstance(z, subprocess.Popen):
            z.kill()
            z.wait()
        elif isinstance(z, int):
            try:
                os.kill(z, signal.SIGKILL)
            except OSError:
                pass

    def _retire_cordons(self):
        for c in self.cordons.values():
            c["proc"].kill()
            c["proc"].wait()
            c["sock"].close()
        self.cordons = {}

    def _zygote_alive(self):
        z = self.zygote
        if isinstance(z, subprocess.Popen):
            return z.poll() is None
        if isinstance(z, int):
            try:
                os.kill(z, 0)
                with open(f"/proc/{z}/stat") as f:
                    return f.read().rsplit(")", 1)[1].split()[0] != "Z"
            except OSError:
                return False
        return False

    def _ensure_zygote(self):
        if self._zygote_alive():
            return
        self._retire_zygote()
        path = os.path.join(self.rundir, f"zygote-{time.monotonic_ns()}.sock")
        ls = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        ls.bind(path)
        ls.listen(64)
        if MUTANT == "fork-respawn":
            # Negative control (D8): replacements are forked from one long-lived template process, so every zygote
            # shares the template's address-space layout.
            if self.template is None or self.template[0].poll() is not None:
                a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                p = subprocess.Popen([self._worker(), "template", "--ctl", str(b.fileno()), "--modules",
                                      self.modfile], pass_fds=[b.fileno()])
                b.close()
                self.template = (p, a)
            socket.send_fds(self.template[1], [b"spawn"], [ls.fileno()])
            self.zygote = json.loads(self.template[1].recv(4096))["zygote"]
        else:
            self.zygote = subprocess.Popen([self._worker(), "zygote", "--fd", str(ls.fileno()), "--modules",
                                            self.modfile], pass_fds=[ls.fileno()])
        ls.close()
        self.zsock = path

    def _cordon(self, key):
        c = self.cordons.get(key)
        if c and c["proc"].poll() is None:
            return c
        if c:
            c["sock"].close()
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        p = subprocess.Popen([self._worker(), "cordon", "--fd", str(b.fileno()), "--modules", self.modfile],
                             pass_fds=[b.fileno()])
        b.close()
        c = {"proc": p, "sock": a, "lock": threading.Lock()}
        self.cordons[key] = c
        return c

    # -------------------------------------------------------------- crash budget (D7)
    def _key(self, tenant):
        return "*" if MUTANT == "global-crash-budget" else tenant

    def in_penalty(self, tenant):
        with self.lock:
            return time.monotonic() < self.penalty.get(self._key(tenant), 0)

    def charge(self, tenant):
        if MUTANT == "no-crash-budget":
            return
        cb = self.cfg["p2"]["crash_budget"]
        now = time.monotonic()
        with self.lock:
            k = self._key(tenant)
            dq = self.crashes[k]
            dq.append(now)
            while dq and dq[0] < now - cb["window_s"]:
                dq.popleft()
            if len(dq) >= cb["crashes"]:
                self.penalty[k] = now + cb["penalty_s"]
                dq.clear()

    # -------------------------------------------------------------- dispatch
    def _exchange(self, sock, msg):
        sock.settimeout(10)
        sock.send(json.dumps(msg).encode())
        while True:
            d = sock.recv(1 << 20)
            if not d:
                return None
            m = json.loads(d)
            if "layout" in m:
                log("aegis-p2-layout " + json.dumps(m["layout"]))
                continue
            return m

    def serve(self, tenant, module, req_head):
        """-> (status, body)"""
        if self.in_penalty(tenant):
            return 429, b"too many crashes\n"
        if self.broken:
            return 403, b"denied\n"  # D17: Error => the Deny response
        p2 = self.cfg["p2"]
        mod = next(m for m in p2["modules"] if m["id"] == module)
        cordon = mod.get("tenancy") == "single" or path_of(p2) == "cordon"
        msg = {"module": module, "req_head": req_head.hex()}
        res = None
        try:
            if cordon:
                with self.lock:
                    c = self._cordon(0 if MUTANT == "shared-cordon" else tenant)
                with c["lock"]:
                    res = self._exchange(c["sock"], msg)
                    if res is None:
                        c["proc"].wait()
            else:
                with self.lock:
                    self._ensure_zygote()
                    path = self.zsock
                s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                try:
                    s.connect(path)
                    res = self._exchange(s, msg)
                finally:
                    s.close()
        except (OSError, ValueError) as e:
            log(f"worker exchange failed: {e!r}")
            res = None
        if res and res.get("end") == "allow":
            return 200, bytes.fromhex(res["body"])
        if res and res.get("end") == "deny":
            if MUTANT == "budget-counts-healthy":
                self.charge(tenant)
            return 403, b"denied\n"
        self.charge(tenant)  # trap, worker death, decode failure
        return 403, b"denied\n"  # D17: Error => the Deny response


# ------------------------------------------------------------------------------------------------ servers


class State:
    def __init__(self):
        self.reloads = 0


def make_handler(rt, keys, state):
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def reply(self, status, body, ctype="application/octet-stream"):
            self.send_response(status)
            self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(body)))
            self.send_header("connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def do_GET(self):
            cfg = rt.cfg
            u = urllib.parse.urlsplit(self.path)
            routes = [r for vh in cfg.get("vhosts", []) for r in vh.get("routes", [])
                      if u.path.startswith(r["path"])]
            if not routes:
                return self.reply(404, b"not found\n")
            r = max(routes, key=lambda r: len(r["path"]))
            if "wasm" not in r.get("to", {}):
                return self.reply(404, b"not found\n")
            auth = self.headers.get("authorization", "")
            tenant = verify_token(auth[7:], keys, "aegis.test") if auth.startswith("Bearer ") else None
            if tenant is None:
                return self.reply(401, b"unauthorized\n")
            hdrs = []
            for name, value in self.headers.items():
                if name.lower() in p2wire.REQ_HEADER_ALLOW:
                    hdrs.append((name.lower(), value.strip().encode("latin-1")))
            cl = self.headers.get("content-length")
            rh = p2wire.encode_req_head(self.command, u.path, u.query.encode(), hdrs,
                                        int(cl) if cl is not None else None)
            status, body = rt.serve(tenant, r["to"]["wasm"], rh)
            self.reply(status, body)

    class A(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/healthz":
                body, st = b'{"status":"ok"}', 200
            elif self.path == "/metrics":
                body, st = f"aegis_proxy_config_reloads {state.reloads}\n".encode(), 200
            else:
                body, st = b"", 404
            self.send_response(st)
            self.send_header("content-length", str(len(body)))
            self.send_header("connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

    return H, A


class TLSServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, ctx):
        self.ctx = ctx
        super().__init__(addr, handler)

    def finish_request(self, request, client_address):
        try:
            tls = self.ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        self.RequestHandlerClass(tls, client_address, self)


def hostport(s):
    h, p = s.rsplit(":", 1)
    return h, int(p)


def serve(opts):
    try:
        cfg = load(opts["--config"], serving=True)
    except (ConfigError, OSError, subprocess.SubprocessError) as e:
        log(f"ref_subject: config refused: {e}")
        return EX_CONFIG
    with open(opts["--token-keyring"]) as f:
        keys = {bytes.fromhex(k["kid"]): bytes.fromhex(k["key"]) for k in json.load(f)["keys"]}
    rundir = opts["--runtime-dir"]
    os.makedirs(rundir, exist_ok=True)
    rt = Runtime(rundir)
    rt.apply(cfg)
    state = State()
    H, A = make_handler(rt, keys, state)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(opts["--cert"], opts["--key"])
    ctx.set_alpn_protocols(["http/1.1"])
    pub = TLSServer(hostport(cfg["listeners"][0]["bind"]), H, ctx)
    adm = http.server.ThreadingHTTPServer(hostport(cfg["admin"]["bind"]), A)
    adm.daemon_threads = True
    for s in (pub, adm):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    hup, term = threading.Event(), threading.Event()
    signal.signal(signal.SIGHUP, lambda *_: hup.set())
    signal.signal(signal.SIGTERM, lambda *_: term.set())
    while not term.is_set():
        if hup.wait(0.1):
            hup.clear()
            try:
                rt.apply(load(opts["--config"], serving=True))
                state.reloads += 1
            except (ConfigError, OSError, subprocess.SubprocessError) as e:
                log(f"ref_subject: reload refused, last-known-good kept: {e}")
    rt.shutdown()
    return 0


def main():
    a = sys.argv[1:]
    if a and a[0] == "check-config":
        try:
            cfg = load(a[1], serving=False)
        except (ConfigError, OSError, IndexError) as e:
            log(f"ref_subject: check-config: {e}")
            return EX_CONFIG
        if "--print-effective" in a:
            print(json.dumps(cfg, sort_keys=True, separators=(",", ":")))
        return 0
    opts = dict(zip(a[::2], a[1::2]))
    if "--config" not in opts:
        return EX_CONFIG
    return serve(opts)


if __name__ == "__main__":
    sys.exit(main())
