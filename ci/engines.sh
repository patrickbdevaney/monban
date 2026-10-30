#!/usr/bin/env bash
# Throwaway live database engines for Phase-4 oracles (P4-engines-001). Docker only, local only (no remote; Q1).
#
#   ci/engines.sh with <name>[,<name>...] -- <cmd...>
#       Start each engine from supply-chain/engine-pins.toml as a labelled container published on a free 127.0.0.1
#       port, wait until it answers, check its reported version against the pin, then run <cmd> with every
#       "@<name>" inside an argument replaced by that engine's DSN/URL. Always tears down (also on error/SIGINT/
#       SIGTERM) and exits with <cmd>'s status. Also exported: AEGIS_ENGINES=<names>, AEGIS_ENGINE_<NAME>=<url>.
#         postgres: postgresql://postgres:<random>@127.0.0.1:<port>/postgres   (SCRAM-SHA-256)
#         valkey/redis: redis://127.0.0.1:<port>                               (default user, no password)
#   ci/engines.sh versions      (inside `with`) probe each running engine from the host over its URL, compare with
#                               the pins; prints one line per engine; non-zero on any mismatch.
#   ci/engines.sh check         validate the pins file and the local images (digest, Id, size) without starting.
#   ci/engines.sh self-test     fake-docker + fake-server fixtures: oversize image, unpinned tag, digest/Id mismatch,
#                               version below floor or not matching pin are refused; mutants of this script go red.
#   ci/engines.sh reap          remove leftover containers labelled aegis.engines=1 (crashed runs only; it never
#                               touches unlabelled containers).
# Env: ENGINES_PINS (pins file), ENGINES_DOCKER (docker binary), ENGINES_TIMEOUT (readiness seconds, default 90),
#      ENGINES_PULL=0 to refuse pulling a missing image (default: pull by digest, then size-check, remove if oversize).
# Refusals happen before any container starts: every requested image is validated first.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ENGINES_SELF="$ROOT/ci/engines.sh"
export ENGINES_PINS="${ENGINES_PINS:-$ROOT/supply-chain/engine-pins.toml}"
PY=$(cat <<'PYEOF'
import json, os, re, secrets, signal, socket, struct, subprocess, sys, tempfile, time, base64, hashlib, hmac, threading
import tomllib

MUTANT = os.environ.get("AEGIS_ENGINES_MUTANT", "")  # self-test only: proves each check is load-bearing
DOCKER = os.environ.get("ENGINES_DOCKER", "docker")
LABEL = "aegis.engines"

class Refuse(Exception):
    pass

def log(msg):
    print(f"engines: {msg}", file=sys.stderr, flush=True)

# ------------------------------------------------------------------ versions ----------------------------------------
VER_RE = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?([A-Za-z][A-Za-z0-9]*)?$")

def parse_ver(s):
    """'17.11' -> ((17,11,0), ''), '19rc1' -> ((19,0,0), 'rc1'), '17.11 (Debian ...)' -> ((17,11,0), '')."""
    tok = (s or "").strip().split(" ")[0]
    m = VER_RE.match(tok)
    if not m:
        raise Refuse(f"unparseable version {s!r}")
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0)), (m.group(4) or "")

def ver_ge(a, b):
    if MUTANT == "string-version-compare":
        return a >= b
    (ta, pa), (tb, pb) = parse_ver(a), parse_ver(b)
    if pa:  # pre-releases never satisfy a floor
        return False
    return ta >= tb

def floor_ok(e, version):
    """Return None if version satisfies the pin's floor rule, else a reason string."""
    if MUTANT == "no-floor":
        return None
    kind = e["kind"]
    if kind == "postgres":
        floor = e["floor"]
        (tv, _), (tf, _) = parse_ver(version), parse_ver(floor)
        if tv[0] != tf[0]:
            return f"major {tv[0]} != floor major {tf[0]}"
        if not ver_ge(version, floor):
            return f"{version} below floor {floor} ({e.get('advisory', '')})"
        return None
    if kind in ("valkey", "redis"):
        tv, pv = parse_ver(version)
        if pv:
            return f"pre-release {version} not accepted"
        for f in e["fixed_in"]:
            tf, _ = parse_ver(f)
            if tf[:2] == tv[:2]:
                return None if ver_ge(version, f) else f"{version} below branch fix {f} ({e.get('advisory', '')})"
        return f"branch {tv[0]}.{tv[1]} has no fixed release listed for {e.get('advisory', '')} (refused)"
    return f"unknown kind {kind}"

# ------------------------------------------------------------------ pins --------------------------------------------
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
NAME_RE = re.compile(r"^[a-z][a-z0-9]*$")

def load_pins(path=None):
    path = path or os.environ["ENGINES_PINS"]
    with open(path, "rb") as f:
        pins = tomllib.load(f)
    if pins.get("schema") != 1:
        raise Refuse(f"{path}: schema must be 1")
    limit = pins.get("max_image_bytes")
    if not isinstance(limit, int) or limit <= 0 or limit > 500_000_000:
        raise Refuse(f"{path}: max_image_bytes must be an int in (0, 500000000] (CLAUDE.md)")
    engines = pins.get("engines") or {}
    for name, e in engines.items():
        validate_pin(name, e, limit)
    return pins

def validate_pin(name, e, limit):
    where = f"engines.{name}"
    if not NAME_RE.match(name):
        raise Refuse(f"{where}: name must match {NAME_RE.pattern}")
    for k in ("kind", "image", "version", "policy", "port"):
        if k not in e:
            raise Refuse(f"{where}: missing {k}")
    if MUTANT != "no-digest-check":
        d = e.get("digest", "")
        if not DIGEST_RE.match(d or ""):
            raise Refuse(f"{where}: image {e['image']}:{e.get('tag', '?')} is not pinned by digest (digest={d!r})")
        if not DIGEST_RE.match(e.get("image_id", "") or ""):
            raise Refuse(f"{where}: image_id missing or not sha256")
        if ":" in e["image"].split("/")[-1] or "@" in e["image"]:
            raise Refuse(f"{where}: image must be a bare repository (tag/digest go in tag/digest)")
    if e["kind"] not in ("postgres", "valkey", "redis"):
        raise Refuse(f"{where}: unknown kind {e['kind']}")
    if MUTANT != "no-size-check":
        b = e.get("bytes")
        if not isinstance(b, int) or b > limit:
            raise Refuse(f"{where}: recorded bytes {b} exceeds max_image_bytes {limit}")
    parse_ver(e["version"])
    if e["policy"] == "allow":
        if e["kind"] == "postgres" and "floor" not in e:
            raise Refuse(f"{where}: policy allow needs floor")
        if e["kind"] != "postgres" and not e.get("fixed_in"):
            raise Refuse(f"{where}: policy allow needs fixed_in")
        why = floor_ok(e, e["version"])
        if why:
            raise Refuse(f"{where}: pinned version refused by its own floor: {why}")
    elif e["policy"] != "blocked":
        raise Refuse(f"{where}: policy must be allow|blocked")

# ------------------------------------------------------------------ docker ------------------------------------------
def docker(*args, check=True, capture=True, timeout=600):
    r = subprocess.run([DOCKER, *args], capture_output=capture, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise Refuse(f"docker {' '.join(args[:2])} failed: {(r.stderr or '').strip()[:300]}")
    return r

def ref(e):
    return f"{e['image']}@{e['digest']}"

def inspect(e):
    r = docker("image", "inspect", ref(e), check=False)
    if r.returncode != 0:
        return None
    data = json.loads(r.stdout)
    return data[0] if data else None

def check_image(name, e, limit, allow_pull):
    img = inspect(e)
    if img is None:
        if not allow_pull:
            raise Refuse(f"{name}: image {ref(e)} not present locally and ENGINES_PULL=0")
        log(f"{name}: pulling {ref(e)}")
        docker("pull", "-q", ref(e), timeout=1800)
        img = inspect(e)
        if img is None:
            raise Refuse(f"{name}: pull of {ref(e)} did not produce an image")
        pulled = True
    else:
        pulled = False
    size = img.get("Size")
    if MUTANT != "no-size-check" and (not isinstance(size, int) or size > limit):
        if pulled:
            docker("rmi", ref(e), check=False)
        raise Refuse(f"{name}: image {ref(e)} size {size} exceeds {limit} bytes (refused)")
    if MUTANT != "no-digest-check":
        rd = img.get("RepoDigests") or []
        if not any(x.endswith("@" + e["digest"]) and x.split("@")[0].split("/")[-1] == e["image"].split("/")[-1]
                   for x in rd):
            raise Refuse(f"{name}: local image does not carry pinned digest {e['digest']} (RepoDigests={rd})")
        if img.get("Id") != e["image_id"]:
            raise Refuse(f"{name}: image Id {img.get('Id')} != pinned image_id {e['image_id']}")
    return size

# ------------------------------------------------------------------ probes (host side, stdlib only) -----------------
def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf

def _pg_msg(s):
    t = _recv_exact(s, 1)
    (ln,) = struct.unpack("!i", _recv_exact(s, 4))
    return t, _recv_exact(s, ln - 4)

def probe_pg(host, port, user, password, db, timeout=5.0):
    """Startup + SCRAM-SHA-256 over TCP; returns server_version from ParameterStatus. Refuses cleartext/MD5."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        body = struct.pack("!i", 196608) + b"user\0" + user.encode() + b"\0database\0" + db.encode() + b"\0\0"
        s.sendall(struct.pack("!i", len(body) + 4) + body)
        params, nonce, cfb, auth_msg, salted = {}, None, None, None, None
        while True:
            t, p = _pg_msg(s)
            if t == b"E":
                raise ConnectionError("server error: " + p.decode(errors="replace")[:200])
            if t == b"R":
                (code,) = struct.unpack("!i", p[:4])
                if code == 0:
                    continue
                if code == 10:  # SASL
                    mechs = p[4:].split(b"\0")
                    if b"SCRAM-SHA-256" not in mechs:
                        raise ConnectionError("no SCRAM-SHA-256")
                    nonce = base64.b64encode(secrets.token_bytes(18)).decode()
                    cfb = f"n=,r={nonce}"
                    data = ("n,," + cfb).encode()
                    msg = b"SCRAM-SHA-256\0" + struct.pack("!i", len(data)) + data
                    s.sendall(b"p" + struct.pack("!i", len(msg) + 4) + msg)
                    continue
                if code == 11:  # SASL continue
                    sf = p[4:].decode()
                    kv = dict(x.split("=", 1) for x in sf.split(","))
                    if not kv["r"].startswith(nonce):
                        raise ConnectionError("SCRAM nonce mismatch")
                    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(kv["s"]), int(kv["i"]))
                    ck = hmac.new(salted, b"Client Key", "sha256").digest()
                    cfwp = f"c=biws,r={kv['r']}"
                    auth_msg = f"{cfb},{sf},{cfwp}".encode()
                    sig = hmac.new(hashlib.sha256(ck).digest(), auth_msg, "sha256").digest()
                    proof = base64.b64encode(bytes(a ^ b for a, b in zip(ck, sig))).decode()
                    out = f"{cfwp},p={proof}".encode()
                    s.sendall(b"p" + struct.pack("!i", len(out) + 4) + out)
                    continue
                if code == 12:  # SASL final: verify the server knows the password too
                    sk = hmac.new(salted, b"Server Key", "sha256").digest()
                    want = base64.b64encode(hmac.new(sk, auth_msg, "sha256").digest()).decode()
                    if p[4:].decode() != f"v={want}":
                        raise ConnectionError("SCRAM server signature mismatch")
                    continue
                raise ConnectionError(f"refusing auth method {code} (only SCRAM-SHA-256 / trust)")
            if t == b"S":
                k, v = p[:-1].split(b"\0", 1)  # value may be empty
                params[k.decode()] = v.decode()
            elif t == b"Z":
                s.sendall(b"X" + struct.pack("!i", 4))
                if "server_version" not in params:
                    raise ConnectionError("no server_version reported")
                return params["server_version"].split(" ")[0]

def probe_kv(kind, host, port, timeout=5.0):
    """RESP2 INFO server; Valkey reports redis_version 7.2.4 for compatibility, so read valkey_version for Valkey."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")
        f = s.makefile("rb")
        head = f.readline()
        if not head.startswith(b"$"):
            raise ConnectionError("unexpected INFO reply " + head[:80].decode(errors="replace"))
        n = int(head[1:].strip())
        if n < 0:
            raise ConnectionError("null INFO reply")
        body = f.read(n + 2).decode(errors="replace")
    info = dict(l.split(":", 1) for l in body.splitlines() if ":" in l and not l.startswith("#"))
    key = "valkey_version" if kind == "valkey" else "redis_version"
    if kind == "redis" and "valkey_version" in info:
        raise ConnectionError("engine is Valkey, pin says Redis")
    if key not in info:
        raise ConnectionError(f"INFO lacks {key}")
    return info[key].strip()

def url_for(e, port, password):
    if e["kind"] == "postgres":
        return f"postgresql://postgres:{password}@127.0.0.1:{port}/postgres"
    return f"redis://127.0.0.1:{port}"

def probe_url(kind, url):
    m = re.match(r"^(postgresql|redis)://(?:([^:@/]*)(?::([^@/]*))?@)?([0-9.]+):(\d+)(?:/(.*))?$", url)
    if not m:
        raise Refuse(f"bad url {url}")
    scheme, user, pw, host, port, db = m.groups()
    if host != "127.0.0.1":
        raise Refuse(f"engine not on loopback: {url}")
    if scheme == "postgresql":
        return probe_pg(host, int(port), user or "postgres", pw or "", db or "postgres")
    return probe_kv(kind, host, int(port))

# ------------------------------------------------------------------ with ------------------------------------------
class Run:
    def __init__(self):
        self.run_id = f"{os.getpid()}-{secrets.token_hex(4)}"
        self.started = []  # (name, container id)

    def start(self, name, e):
        password = secrets.token_hex(16)
        cname = f"aegis-eng-{name}-{self.run_id}"
        args = ["run", "-d", "--rm", "--name", cname,
                "--label", f"{LABEL}=1", "--label", f"{LABEL}.run={self.run_id}", "--label", f"{LABEL}.engine={name}",
                "-p", f"127.0.0.1::{e['port']}",
                "--memory", "1g", "--pids-limit", "512", "--security-opt", "no-new-privileges",
                "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "SETUID", "--cap-add", "SETGID",
                "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER"]
        if e.get("tmpfs"):
            args += ["--tmpfs", f"{e['tmpfs']}:rw,size=512m"]
        if e["kind"] == "postgres":
            args += ["-e", f"POSTGRES_PASSWORD={password}", "-e", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256",
                     "-e", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256", "--shm-size", "256m"]
        args.append(ref(e))
        if e["kind"] in ("valkey", "redis"):
            # explicit server flags: no persistence (throwaway), protected-mode off only because publish is loopback
            exe = "valkey-server" if e["kind"] == "valkey" else "redis-server"
            args += [exe, "--save", "", "--appendonly", "no", "--protected-mode", "no"]
        r = docker(*args)
        cid = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else cname
        self.started.append((name, cid))
        pr = docker("port", cid, f"{e['port']}/tcp")
        port = None
        for line in pr.stdout.splitlines():
            m = re.match(r"^127\.0\.0\.1:(\d+)$", line.strip())
            if m:
                port = int(m.group(1))
        if port is None:
            raise Refuse(f"{name}: no 127.0.0.1 port binding ({pr.stdout.strip()!r}); refusing non-loopback publish")
        return url_for(e, port, password)

    def wait_version(self, name, e, url, deadline):
        last = None
        while time.time() < deadline:
            try:
                return probe_url(e["kind"], url)
            except (OSError, ConnectionError, ValueError, struct.error, KeyError) as x:
                last = x
                time.sleep(0.5)
        raise Refuse(f"{name}: not ready before timeout ({last})")

    def teardown(self):
        ok = True
        for name, cid in reversed(self.started):
            r = docker("rm", "-f", "-v", cid, check=False, timeout=120)
            if r.returncode != 0 and "No such container" not in (r.stderr or ""):
                log(f"teardown {name}: {r.stderr.strip()[:200]}")
                ok = False
        self.started.clear()
        r = docker("ps", "-aq", "--filter", f"label={LABEL}.run={self.run_id}", check=False)
        left = [x for x in (r.stdout or "").split() if x]
        for cid in left:  # e.g. created but `run` errored before printing the id
            docker("rm", "-f", "-v", cid, check=False)
        r = docker("ps", "-aq", "--filter", f"label={LABEL}.run={self.run_id}", check=False)
        left = [x for x in (r.stdout or "").split() if x]
        log(f"teardown: {len(left)} container(s) left for run {self.run_id}")
        return ok and not left

def substitute(argv, urls):
    if not urls:
        return list(argv)
    names = sorted(urls, key=len, reverse=True)
    pat = re.compile(r"@(" + "|".join(map(re.escape, names)) + r")(?![A-Za-z0-9_])")
    return [pat.sub(lambda m: urls[m.group(1)], a) for a in argv]

def cmd_with(argv):
    if "--" not in argv or argv.index("--") != 1:
        raise Refuse("usage: engines.sh with <name>[,<name>...] -- <cmd...>")
    names = [n for n in argv[0].split(",") if n]
    cmd = argv[2:]
    if not names or not cmd:
        raise Refuse("usage: engines.sh with <name>[,<name>...] -- <cmd...>")
    if len(set(names)) != len(names):
        raise Refuse("duplicate engine name")
    pins = load_pins()
    limit = pins["max_image_bytes"]
    engines = pins.get("engines", {})
    for n in names:
        if n not in engines:
            raise Refuse(f"unknown engine {n!r} (pinned: {', '.join(sorted(engines))})")
    allow_pull = os.environ.get("ENGINES_PULL", "1") != "0"
    for n in names:  # validate every image before starting anything
        size = check_image(n, engines[n], limit, allow_pull)
        log(f"{n}: {ref(engines[n])} {size} bytes <= {limit}")
    run = Run()

    def on_signal(signum, frame):
        raise KeyboardInterrupt(f"signal {signum}")
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGHUP, on_signal)
    rc = 1
    try:
        urls = {}
        for n in names:
            urls[n] = run.start(n, engines[n])
        deadline = time.time() + float(os.environ.get("ENGINES_TIMEOUT", "90"))
        for n in names:
            e = engines[n]
            v = run.wait_version(n, e, urls[n], deadline)
            if v != e["version"]:
                raise Refuse(f"{n}: server reports {v}, pin says {e['version']}")
            if e["policy"] == "allow":
                why = floor_ok(e, v)
                if why:
                    raise Refuse(f"{n}: {why}")
            log(f"{n}: up, version {v} ({e['policy']}) on 127.0.0.1")
        env = dict(os.environ)
        env["AEGIS_ENGINES"] = ",".join(names)
        for n in names:
            env[f"AEGIS_ENGINE_{n.upper()}"] = urls[n]
        rc = subprocess.run(substitute(cmd, urls), env=env).returncode
    except KeyboardInterrupt as x:
        log(f"interrupted ({x}); tearing down")
        rc = 130
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        clean = run.teardown()
    if not clean:
        log("teardown incomplete")
        return rc or 1
    return rc

def cmd_versions(argv):
    names = [n for n in os.environ.get("AEGIS_ENGINES", "").split(",") if n]
    if not names:
        raise Refuse("versions: no engines in AEGIS_ENGINES (run inside `engines.sh with ... --`)")
    engines = load_pins()["engines"]
    bad = 0
    for n in names:
        e = engines[n]
        url = os.environ[f"AEGIS_ENGINE_{n.upper()}"]
        try:
            v = probe_url(e["kind"], url)
        except (OSError, ConnectionError, ValueError) as x:
            print(f"{n:8} FAIL probe: {x}")
            bad += 1
            continue
        port = url.rsplit(":", 1)[-1].split("/")[0]
        if v != e["version"]:
            print(f"{n:8} FAIL reports {v}, pin {e['version']}")
            bad += 1
            continue
        if e["policy"] == "blocked":
            print(f"{n:8} OK    {e['kind']} {v} == pin, BLOCKED by policy ({e.get('blocked_reason', '')}) 127.0.0.1:{port}")
            continue
        why = floor_ok(e, v)
        if why:
            print(f"{n:8} FAIL {why}")
            bad += 1
            continue
        rule = f"floor {e['floor']}" if e["kind"] == "postgres" else f"fixed_in {'/'.join(e['fixed_in'])}"
        print(f"{n:8} OK    {e['kind']} {v} == pin, {rule} ({e.get('advisory', '')}) 127.0.0.1:{port}")
    print(f"ENGINES VERSIONS: {'PASS' if not bad else 'FAIL'} ({len(names) - bad}/{len(names)})")
    return 1 if bad else 0

def cmd_check(argv):
    pins = load_pins()
    limit = pins["max_image_bytes"]
    for n, e in pins["engines"].items():
        size = check_image(n, e, limit, allow_pull=False)
        print(f"{n:8} {ref(e)} {size} bytes, version {e['version']} ({e['policy']})")
    print("ENGINES CHECK: PASS")
    return 0

def cmd_reap(argv):
    r = docker("ps", "-aq", "--filter", f"label={LABEL}=1")
    ids = r.stdout.split()
    for cid in ids:
        docker("rm", "-f", "-v", cid, check=False)
    print(f"reaped {len(ids)} container(s) labelled {LABEL}=1")
    return 0

# ------------------------------------------------------------------ self-test -------------------------------------
FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys
cfg = json.load(open(os.environ["FAKE_CFG"]))
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
a = sys.argv[1:]
if a[:2] == ["image", "inspect"]:
    img = cfg["images"].get(a[2])
    if img is None:
        sys.stderr.write("No such image\n"); sys.exit(1)
    print(json.dumps([img])); sys.exit(0)
if a[0] == "pull":
    sys.stderr.write("pull disabled in fixture\n"); sys.exit(1)
if a[0] == "run":
    name = a[a.index("--name") + 1]
    print("cid-" + name); sys.exit(0)
if a[0] == "port":
    eng = a[1].split("-")[3]
    print(cfg["bind"] + ":" + str(cfg["ports"][eng])); sys.exit(0)
if a[0] in ("rm", "rmi"):
    sys.exit(0)
if a[0] == "ps":
    sys.exit(0)
sys.stderr.write("fake docker: unsupported " + " ".join(a) + "\n"); sys.exit(2)
'''

class FakeServer:
    """Minimal PG (trust: AuthOk + ParameterStatus) or RESP (INFO) server reporting a configured version."""
    def __init__(self, kind, version, valkey_compat=True):
        self.kind, self.version, self.valkey_compat = kind, version, valkey_compat
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            try:
                self.serve(c)
            except OSError:
                pass
            finally:
                c.close()

    def serve(self, c):
        if self.kind == "postgres":
            (ln,) = struct.unpack("!i", _recv_exact(c, 4))
            _recv_exact(c, ln - 4)
            def m(t, p):
                return t + struct.pack("!i", len(p) + 4) + p
            c.sendall(m(b"R", struct.pack("!i", 0))
                      + m(b"S", b"server_version\0" + self.version.encode() + b"\0")
                      + m(b"Z", b"I"))
            c.recv(16)
        else:
            c.recv(1024)
            lines = ["# Server"]
            if self.kind == "valkey" and self.valkey_compat == "only":
                lines += ["redis_version:7.2.4"]
            elif self.kind == "valkey":
                lines += ["redis_version:7.2.4", f"valkey_version:{self.version}"]
            else:
                lines += [f"redis_version:{self.version}"]
            body = "\r\n".join(l for l in lines if l) + "\r\n"
            c.sendall(f"${len(body)}\r\n{body}\r\n".encode())

    def close(self):
        self.sock.close()

def fixture_pins(tmp, engines, limit=500_000_000):
    lines = [f"schema = 1", f"max_image_bytes = {limit}"]
    for n, e in engines.items():
        lines.append(f"[engines.{n}]")
        for k, v in e.items():
            lines.append(f"{k} = {json.dumps(v)}")
    p = os.path.join(tmp, "pins.toml")
    with open(p, "w") as f:
        f.write("\n".join(lines) + "\n")
    return p

D1 = "sha256:" + "a" * 64
D2 = "sha256:" + "b" * 64
ID1 = "sha256:" + "c" * 64

def base_pin(kind="postgres", version="17.11", **kw):
    e = {"kind": kind, "image": "postgres" if kind == "postgres" else kind, "tag": "t", "digest": D1,
         "image_id": ID1, "bytes": 1000, "version": version, "policy": "allow",
         "port": 5432 if kind == "postgres" else 6379}
    if kind == "postgres":
        e["floor"] = "17.11"
    else:
        e["fixed_in"] = ["8.0.7", "8.1.6", "9.0.3", "9.1.0"] if kind == "valkey" else ["8.6.1", "8.10.0"]
    e.update(kw)
    return e

def base_image(e, size=1000, digests=None, image_id=ID1):
    return {"Id": image_id, "Size": size,
            "RepoDigests": digests if digests is not None else [f"{e['image']}@{e['digest']}"]}

def run_case(tmp, case):
    """Returns (rc, stderr+stdout, docker call log)."""
    e = case["pin"]
    name = case.get("name", "eng")
    pins = fixture_pins(tmp, {name: e})
    srv = FakeServer(e["kind"], case.get("serves", e["version"]), case.get("valkey_compat", True))
    cfg = {"images": {f"{e['image']}@{e['digest']}": case.get("image", base_image(e))},
           "ports": {name: srv.port}, "bind": case.get("bind", "127.0.0.1")}
    if case.get("no_image"):
        cfg["images"] = {}
    cfgp, logp = os.path.join(tmp, "cfg.json"), os.path.join(tmp, "calls.log")
    with open(cfgp, "w") as f:
        json.dump(cfg, f)
    open(logp, "w").close()
    env = dict(os.environ, ENGINES_PINS=pins, ENGINES_DOCKER=os.path.join(tmp, "docker"), FAKE_CFG=cfgp,
               FAKE_LOG=logp, ENGINES_TIMEOUT="3", ENGINES_PULL="0")
    cmd = case.get("cmd", ["sh", "-c", 'echo "URL=$1"; exit ${2:-0}', "sh", f"@{name}", str(case.get("cmd_rc", 0))])
    r = subprocess.run([os.environ["ENGINES_SELF"], "with", name, "--", *cmd], env=env,
                       capture_output=True, text=True, timeout=60)
    srv.close()
    calls = [json.loads(l) for l in open(logp) if l.strip()]
    return r.returncode, r.stdout + r.stderr, calls

def ran(calls):
    return any(c[:1] == ["run"] for c in calls)

def removed(calls):
    return any(c[:1] == ["rm"] for c in calls)

def cases():
    pg = base_pin()
    vk = base_pin("valkey", "9.1.2")
    rd = base_pin("redis", "8.10.2")
    def refused(substr, started=False):
        def chk(rc, out, calls):
            if rc == 0:
                return "accepted"
            if substr not in out:
                return f"refused, but not for {substr!r}: {out.strip().splitlines()[-1:]}"
            if not started and ran(calls):
                return "a container was started before the refusal"
            if started and not removed(calls):
                return "started container not torn down"
            return None
        return chk
    def accepted(rc_want=0):
        def chk(rc, out, calls):
            if rc != rc_want:
                return f"rc {rc} != {rc_want}: {out.strip().splitlines()[-2:]}"
            if not re.search(r"URL=(postgresql://postgres:[0-9a-f]{32}@|redis://)127\.0\.0\.1:\d+", out):
                return "@name not substituted with a loopback URL"
            if not removed(calls):
                return "not torn down"
            return None
        return chk
    return [
        ("positive control: pg 17.11 at pin", dict(pin=pg), accepted()),
        ("positive control: valkey 9.1.2 (valkey_version, not compat redis_version 7.2.4)", dict(pin=vk), accepted()),
        ("positive control: redis 8.10.2", dict(pin=rd), accepted()),
        ("cmd exit status propagates and teardown still runs", dict(pin=pg, cmd_rc=7), accepted(7)),
        ("oversize image (inspect Size 500000001) refused before run",
         dict(pin=pg, image=base_image(pg, size=500_000_001)), refused("exceeds")),
        ("oversize recorded bytes in pins refused", dict(pin=base_pin(bytes=600_000_000)), refused("exceeds")),
        ("unpinned tag (no digest) refused", dict(pin=base_pin(digest="")), refused("not pinned by digest")),
        ("tag-as-digest refused", dict(pin=base_pin(digest="17-alpine")), refused("not pinned by digest")),
        ("local image lacks pinned digest refused",
         dict(pin=pg, image=base_image(pg, digests=[f"postgres@{D2}"])), refused("does not carry pinned digest")),
        ("image Id differs from pin refused",
         dict(pin=pg, image=base_image(pg, image_id="sha256:" + "d" * 64)), refused("image_id")),
        ("server below floor: pin 17.11, server reports 17.10 -> teardown + refuse",
         dict(pin=pg, serves="17.10"), refused("pin says", started=True)),
        ("pin below floor: '17.9' vs floor '17.11' (numeric, not string) refused",
         dict(pin=base_pin(version="17.9")), refused("below floor")),
        ("pin pre-release below floor: 17rc1 refused", dict(pin=base_pin(version="17rc1")), refused("below floor")),
        ("valkey 9.0.2 refused (advisory says fixed, release notes put it in 9.0.3)",
         dict(pin=base_pin("valkey", "9.0.2")), refused("below branch fix")),
        ("valkey 8.1.5 refused", dict(pin=base_pin("valkey", "8.1.5")), refused("below branch fix")),
        ("redis 8.8.4 refused (branch without a fix)", dict(pin=base_pin("redis", "8.8.4")), refused("no fixed release")),
        ("valkey server reporting only compat redis_version 7.2.4 refused (no fallback)",
         dict(pin=vk, valkey_compat="only"), refused("valkey_version", started=True)),
        ("non-loopback port binding refused", dict(pin=pg, bind="0.0.0.0"), refused("non-loopback", started=True)),
        ("missing image with ENGINES_PULL=0 refused", dict(pin=pg, no_image=True), refused("not present locally")),
    ]

def unit_checks():
    """Pure checks of the floor rule; returned as (label, ok)."""
    pg17 = {"kind": "postgres", "floor": "17.11", "advisory": "x"}
    pg18 = {"kind": "postgres", "floor": "18.6", "advisory": "x"}
    vk = {"kind": "valkey", "fixed_in": ["7.2.12", "8.0.7", "8.1.6", "9.0.3", "9.1.0"]}
    rd = {"kind": "redis", "fixed_in": ["7.2.13", "7.4.8", "8.0.6", "8.2.5", "8.4.2", "8.6.1", "8.10.0"]}
    want = [(pg17, "17.11", True), (pg17, "17.12", True), (pg17, "17.10", False), (pg17, "17.9", False),
            (pg17, "18.6", False), (pg18, "18.5", False), (pg18, "18.6", True), (pg18, "18.10", True),
            (pg18, "19rc1", False), (vk, "9.1.2", True), (vk, "9.0.2", False), (vk, "9.0.3", True),
            (vk, "8.1.5", False), (vk, "9.2.0", False), (rd, "8.10.2", True), (rd, "8.8.4", False),
            (rd, "8.6.0", False), (rd, "8.6.1", True), (rd, "7.4.10", True)]
    return [(f"floor {e['kind']} {e.get('floor', '')} {v} -> {'accept' if ok else 'refuse'}", (floor_ok(e, v) is None) == ok)
            for e, v, ok in want]

def selftest_suite(tmp, verbose):
    fails = []
    for label, ok in unit_checks():
        if not ok:
            fails.append(label)
        if verbose:
            print(f"  {'ok  ' if ok else 'FAIL'} {label}")
    for label, case, chk in cases():
        rc, out, calls = run_case(tmp, case)
        why = chk(rc, out, calls)
        if why:
            fails.append(f"{label}: {why}")
        if verbose:
            print(f"  {'ok  ' if not why else 'FAIL'} {label}" + (f" -- {why}" if why else ""))
    return fails

def cmd_selftest(argv):
    global MUTANT
    with tempfile.TemporaryDirectory(prefix="engines-selftest-") as tmp:
        dp = os.path.join(tmp, "docker")
        with open(dp, "w") as f:
            f.write(FAKE_DOCKER)
        os.chmod(dp, 0o755)
        print("engines self-test: fixtures (fake docker + fake PG/RESP servers)")
        fails = selftest_suite(tmp, verbose=True)
        if fails:
            print(f"ENGINES SELF-TEST: FAIL ({len(fails)} case(s))")
            return 1
        # Mutants of this script must turn the suite red (each check is load-bearing).
        red = []
        for m in ("no-size-check", "no-digest-check", "string-version-compare", "no-floor"):
            os.environ["AEGIS_ENGINES_MUTANT"] = m
            MUTANT = m
            mf = selftest_suite(tmp, verbose=False)
            os.environ.pop("AEGIS_ENGINES_MUTANT")
            MUTANT = ""
            print(f"  mutant {m:24} {'RED (' + str(len(mf)) + ' case(s) fail)' if mf else 'GREEN -- mutant survived'}")
            if not mf:
                red.append(m)
        if red:
            print(f"ENGINES SELF-TEST: FAIL (mutants survived: {', '.join(red)})")
            return 1
    print("ENGINES SELF-TEST: PASS (oversize image, unpinned tag, digest/Id mismatch, below-floor and pin-mismatch "
          "versions refused; 4/4 mutants red)")
    return 0

def main():
    a = sys.argv[1:]
    if not a:
        print(open(os.environ["ENGINES_SELF"]).read().split("set -euo")[0], file=sys.stderr)
        return 2
    sub, rest = a[0], a[1:]
    fn = {"with": cmd_with, "versions": cmd_versions, "check": cmd_check, "self-test": cmd_selftest,
          "reap": cmd_reap}.get(sub)
    if fn is None:
        log(f"unknown subcommand {sub!r}")
        return 2
    try:
        return fn(rest)
    except Refuse as x:
        print(f"engines: REFUSED: {x}", file=sys.stderr)
        return 3

sys.exit(main())
PYEOF
)
exec python3 -I -c "$PY" "$@"
