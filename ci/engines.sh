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
#         mariadb:  mysql://root:<random>@127.0.0.1:<port>/monban                (mysql_native_password; P7)
#         crdb:     postgresql://root@127.0.0.1:<port>/defaultdb              (start-single-node --insecure,
#                   in-memory store: loopback-only throwaway, never a deployment shape; P7)
#   ci/engines.sh versions      (inside `with`) probe each running engine from the host over its URL, compare with
#                               the pins; prints one line per engine; non-zero on any mismatch.
#   ci/engines.sh check         validate the pins file and the local images (digest, config digest, size) without
#                               starting anything; every pinned image must be present (ENGINES_PULL is ignored).
#   ci/engines.sh pull [<name>[,<name>...]]
#                               stage pinned images on this host (default: all): pull image@digest, then the same
#                               size/digest/config-digest checks as `check`; an oversize image is removed again.
#   ci/engines.sh self-test     fake-docker + fake-server fixtures: oversize image, unpinned tag, digest/Id mismatch,
#                               version below floor or not matching pin are refused; mutants of this script go red.
#   ci/engines.sh reap          remove leftover containers labelled monban.engines=1 (crashed runs only; it never
#                               touches unlabelled containers).
# Image size: max(docker inspect .Size, sum of `docker history` layer sizes). On a containerd-snapshotter store
# (kamrui, docker 29) .Size is the compressed content size and Id is the index digest; the history sum is the unpacked
# size there, and equals .Size on the classic store.
# Image identity (P8-spec-002, PREFLIGHT R16): every pin carries `config_digest`, the sha256 of the linux/amd64 image
# config blob, which is the same on every host. A classic store reports it as the image Id, so Id must equal it. A
# containerd store (Descriptor.digest == Id) reports the index digest as Id, so Id must equal the pinned `digest`, and
# the config is read from `docker save --platform linux/amd64` (streamed, nothing stored): its single image's config
# blob must hash to its name, equal `config_digest`, and list the inspected image's RootFS layers. `image_id` is the Id
# the pinning host saw (informational; it must be the pin's digest or config_digest).
# Env: ENGINES_PINS (pins file), ENGINES_DOCKER (docker binary), ENGINES_TIMEOUT (readiness seconds, default 90),
#      ENGINES_PULL=0 to refuse pulling a missing image (default: pull by digest, then size-check, remove if oversize).
# Refusals happen before any container starts: every requested image is validated first.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ENGINES_SELF="$ROOT/ci/engines.sh"
export ENGINES_PINS="${ENGINES_PINS:-$ROOT/supply-chain/engine-pins.toml}"
PY=$(cat <<'PYEOF'
import io, json, os, re, secrets, signal, socket, struct, subprocess, sys, tarfile, tempfile, time, base64, hashlib, hmac, threading
import tomllib

MUTANT = os.environ.get("AEGIS_ENGINES_MUTANT", "")  # self-test only: proves each check is load-bearing
DOCKER = os.environ.get("ENGINES_DOCKER", "docker")
LABEL = "monban.engines"

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
    if kind in ("mariadb", "crdb"):
        # release series = major.minor (MariaDB 11.8 LTS, CockroachDB v25.4); same series only, numeric compare
        floor = e["floor"]
        (tv, pv), (tf, _) = parse_ver(version), parse_ver(floor)
        if pv:
            return f"pre-release {version} not accepted"
        if tv[:2] != tf[:2]:
            return f"series {tv[0]}.{tv[1]} != floor series {tf[0]}.{tf[1]}"
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
KINDS = ("postgres", "valkey", "redis", "mariadb", "crdb")
FLOOR_KINDS = ("postgres", "mariadb", "crdb")
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
    if MUTANT != "no-config-digest-check":
        if not DIGEST_RE.match(e.get("config_digest", "") or ""):
            raise Refuse(f"{where}: config_digest missing or not sha256 (every pin needs its host-independent config digest)")
        if e.get("image_id") not in (e.get("digest"), e["config_digest"]):
            raise Refuse(f"{where}: image_id {e.get('image_id')} is neither the pinned digest nor config_digest")
    if e["kind"] not in KINDS:
        raise Refuse(f"{where}: unknown kind {e['kind']}")
    if "memory" in e and not re.match(r"^[1-4]g$", str(e["memory"])):
        raise Refuse(f"{where}: memory must be 1g..4g")
    if MUTANT != "no-size-check":
        b = e.get("bytes")
        if not isinstance(b, int) or b > limit:
            raise Refuse(f"{where}: recorded bytes {b} exceeds max_image_bytes {limit}")
    parse_ver(e["version"])
    if e["policy"] == "allow":
        if e["kind"] in FLOOR_KINDS and "floor" not in e:
            raise Refuse(f"{where}: policy allow needs floor")
        if e["kind"] not in FLOOR_KINDS and not e.get("fixed_in"):
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
    if isinstance(size, int):
        # containerd store: inspect .Size is the compressed content; the unpacked size is the sum of the layer sizes
        h = docker("history", "--no-trunc", "--human=false", "--format", "{{.Size}}", ref(e), check=False)
        if h.returncode == 0:
            layers = [int(x) for x in h.stdout.split() if x.isdigit()]
            size = max(size, sum(layers))
    if MUTANT != "no-size-check" and (not isinstance(size, int) or size > limit):
        if pulled:
            docker("rmi", ref(e), check=False)
        raise Refuse(f"{name}: image {ref(e)} size {size} exceeds {limit} bytes (refused)")
    if MUTANT != "no-digest-check":
        rd = img.get("RepoDigests") or []
        if not any(x.endswith("@" + e["digest"]) and x.split("@")[0].split("/")[-1] == e["image"].split("/")[-1]
                   for x in rd):
            raise Refuse(f"{name}: local image does not carry pinned digest {e['digest']} (RepoDigests={rd})")
    store = check_config_digest(name, e, img)
    return size, store

def store_of(img):
    """'containerd' when inspect's Id is the image's own index/manifest descriptor digest, else 'classic'."""
    d = img.get("Descriptor") or {}
    return "containerd" if d.get("digest") and d.get("digest") == img.get("Id") else "classic"

SMALL_BLOB = 4 << 20

def saved_config(e):
    """Stream `docker save --platform linux/amd64 image@digest` (nothing written to disk) and return
    (config digest, config json) of its single image, from the docker-compatible manifest.json. Every small blob read
    must hash to its own name."""
    p = subprocess.Popen([DOCKER, "save", "--platform", "linux/amd64", ref(e)], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    blobs, manifest, done = {}, None, False
    try:
        with tarfile.open(fileobj=p.stdout, mode="r|") as t:
            for m in t:
                if not m.isfile() or m.size > SMALL_BLOB:
                    continue  # stream mode skips the member's bytes on the next iteration
                if m.name == "manifest.json":
                    manifest = t.extractfile(m).read()
                elif m.name.startswith("blobs/sha256/"):
                    data = t.extractfile(m).read()
                    hx = m.name.rsplit("/", 1)[-1]
                    if hashlib.sha256(data).hexdigest() != hx:
                        raise Refuse(f"saved blob {m.name} does not hash to its name (corrupt store)")
                    blobs[hx] = data
        done = True
    except tarfile.TarError as x:
        raise Refuse(f"docker save {ref(e)}: unreadable stream ({x})")
    finally:
        if not done:
            p.kill()  # our own child only; never leave a writer blocked on a full pipe
        err = p.stderr.read().decode(errors="replace") if p.stderr else ""
        rc = p.wait(timeout=600)
    if rc != 0:
        raise Refuse(f"docker save {ref(e)} failed: {err.strip()[:300]}")
    if manifest is None:
        raise Refuse(f"docker save {ref(e)}: no manifest.json")
    entries = json.loads(manifest)
    if not isinstance(entries, list) or len(entries) != 1:
        raise Refuse(f"docker save {ref(e)}: expected exactly one linux/amd64 image, got {len(entries) if isinstance(entries, list) else '?'}")
    cpath = str(entries[0].get("Config", ""))
    hx = cpath.rsplit("/", 1)[-1]
    if not cpath.startswith("blobs/sha256/") or hx not in blobs:
        raise Refuse(f"docker save {ref(e)}: config blob {cpath!r} missing from the stream")
    return "sha256:" + hx, json.loads(blobs[hx])

def check_config_digest(name, e, img):
    """The host-independent identity check (module docs). Returns the store kind."""
    store = store_of(img)
    if MUTANT == "no-config-digest-check":
        return store
    want = e["config_digest"]
    if store == "classic":
        if img.get("Id") != want:
            raise Refuse(f"{name}: classic store image Id {img.get('Id')} != pinned config_digest {want}")
        return store
    if img.get("Id") != e["digest"]:
        raise Refuse(f"{name}: containerd store image Id {img.get('Id')} is not the pinned index digest {e['digest']}")
    got, cfg = saved_config(e)
    if got != want:
        raise Refuse(f"{name}: linux/amd64 config digest {got} != pinned config_digest {want}")
    diff_ids = ((cfg.get("rootfs") or {}).get("diff_ids")) or []
    if diff_ids != ((img.get("RootFS") or {}).get("Layers") or []):
        raise Refuse(f"{name}: saved config {got} does not describe the inspected image's RootFS layers")
    return store

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

def _my_read(s):
    h = _recv_exact(s, 4)
    return _recv_exact(s, int.from_bytes(h[:3], "little")), h[3]

def _my_send(s, seq, payload):
    s.sendall(len(payload).to_bytes(3, "little") + bytes([seq & 0xff]) + payload)

def _my_lenenc(b, o):
    c = b[o]
    if c < 0xfb: return c, o + 1
    if c == 0xfc: return int.from_bytes(b[o + 1:o + 3], "little"), o + 3
    if c == 0xfd: return int.from_bytes(b[o + 1:o + 4], "little"), o + 4
    return int.from_bytes(b[o + 1:o + 9], "little"), o + 9

def probe_my(host, port, user, password, db, timeout=5.0):
    """MySQL protocol: handshake v10, mysql_native_password (incl. auth switch), then `select version()`. The
    greeting's version could come from the entrypoint's temporary init server, so readiness = an authenticated query."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        g, _ = _my_read(s)
        if g[:1] == b"\xff":
            raise ConnectionError("server error in greeting: " + g[3:].decode(errors="replace")[:120])
        if g[:1] != b"\x0a":
            raise ConnectionError("not a MySQL protocol v10 greeting")
        e = g.index(b"\0", 1); o = e + 1 + 4
        salt = g[o:o + 8]; o += 9 + 2 + 1 + 2 + 2
        alen = g[o]; o += 1 + 10
        salt += g[o:o + max(13, alen - 8)].rstrip(b"\0")
        def scramble(pw, sl):
            if not pw: return b""
            h1 = hashlib.sha1(pw).digest(); h2 = hashlib.sha1(h1).digest()
            return bytes(a ^ b for a, b in zip(h1, hashlib.sha1(sl[:20] + h2).digest()))
        auth = scramble(password.encode(), salt)
        caps = 0x1 | 0x8 | 0x200 | 0x8000 | 0x80000
        _my_send(s, 1, struct.pack("<IIB", caps, 1 << 24, 45) + b"\0" * 23 + user.encode() + b"\0" + bytes([len(auth)]) + auth
                 + db.encode() + b"\0" + b"mysql_native_password\0")
        while True:
            r, seq = _my_read(s)
            if r[:1] == b"\x00": break
            if r[:1] == b"\xfe" and len(r) > 1:     # auth switch
                e = r.index(b"\0", 1)
                if r[1:e] != b"mysql_native_password":
                    raise ConnectionError(f"refusing auth plugin {r[1:e]!r}")
                _my_send(s, seq + 1, scramble(password.encode(), r[e + 1:].rstrip(b"\0"))); continue
            raise ConnectionError("auth failed: " + r[3:].decode(errors="replace")[:120])
        _my_send(s, 0, b"\x03select version()")
        r, _ = _my_read(s)
        if r[:1] == b"\xff":
            raise ConnectionError("query error: " + r[3:].decode(errors="replace")[:120])
        while True:                                   # column definitions until EOF
            r, _ = _my_read(s)
            if r[:1] == b"\xfe" and len(r) < 9: break
        r, _ = _my_read(s)
        n, o = _my_lenenc(r, 0)
        v = r[o:o + n].decode(errors="replace")
        _my_send(s, 0, b"\x01")
    v = v[len("5.5.5-"):] if v.startswith("5.5.5-") else v
    return v.split("-")[0]

def probe_crdb(host, port, user, db, timeout=5.0):
    """PG v3 startup (insecure single node: trust only, any other auth refused) + `select version()`:
    'CockroachDB CCL v25.4.19 (...)' -> '25.4.19'. server_version (13.0.0) is the PG-compat level, not the release."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        body = struct.pack("!i", 196608) + b"user\0" + user.encode() + b"\0database\0" + db.encode() + b"\0\0"
        s.sendall(struct.pack("!i", len(body) + 4) + body)
        sent, ver = False, None
        while True:
            t, p = _pg_msg(s)
            if t == b"E":
                raise ConnectionError("server error: " + p.decode(errors="replace")[:200])
            if t == b"R" and struct.unpack("!i", p[:4])[0] != 0:
                raise ConnectionError("refusing auth (insecure throwaway node expected)")
            if t == b"D":
                (ln,) = struct.unpack("!i", p[2:6]); ver = p[6:6 + ln].decode(errors="replace")
            if t == b"Z":
                if not sent:
                    q = b"select version()\0"; s.sendall(b"Q" + struct.pack("!i", len(q) + 4) + q); sent = True; continue
                s.sendall(b"X" + struct.pack("!i", 4))
                if not ver or not ver.startswith("CockroachDB"):
                    raise ConnectionError(f"not a CockroachDB server: {ver!r}")
                tok = ver.split()[2]
                return tok[1:] if tok.startswith("v") else tok

def url_for(e, port, password):
    if e["kind"] == "postgres":
        return f"postgresql://postgres:{password}@127.0.0.1:{port}/postgres"
    if e["kind"] == "mariadb":
        return f"mysql://root:{password}@127.0.0.1:{port}/monban"
    if e["kind"] == "crdb":
        return f"postgresql://root@127.0.0.1:{port}/defaultdb"
    return f"redis://127.0.0.1:{port}"

def probe_url(kind, url):
    m = re.match(r"^(postgresql|redis|mysql)://(?:([^:@/]*)(?::([^@/]*))?@)?([0-9.]+):(\d+)(?:/(.*))?$", url)
    if not m:
        raise Refuse(f"bad url {url}")
    scheme, user, pw, host, port, db = m.groups()
    if host != "127.0.0.1":
        raise Refuse(f"engine not on loopback: {url}")
    if scheme == "mysql":
        return probe_my(host, int(port), user or "root", pw or "", db or "")
    if scheme == "postgresql" and kind == "crdb":
        return probe_crdb(host, int(port), user or "root", db or "defaultdb")
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
        cname = f"monban-eng-{name}-{self.run_id}"
        args = ["run", "-d", "--rm", "--name", cname,
                "--label", f"{LABEL}=1", "--label", f"{LABEL}.run={self.run_id}", "--label", f"{LABEL}.engine={name}",
                "-p", f"127.0.0.1::{e['port']}",
                "--memory", str(e.get("memory", "1g")), "--pids-limit", "512", "--security-opt", "no-new-privileges",
                "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "SETUID", "--cap-add", "SETGID",
                "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER"]
        if e.get("tmpfs"):
            args += ["--tmpfs", f"{e['tmpfs']}:rw,size=512m"]
        if e["kind"] == "postgres":
            args += ["-e", f"POSTGRES_PASSWORD={password}", "-e", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256",
                     "-e", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256", "--shm-size", "256m"]
        if e["kind"] == "mariadb":
            args += ["-e", f"MARIADB_ROOT_PASSWORD={password}", "-e", "MARIADB_DATABASE=monban"]
        args.append(ref(e))
        if e["kind"] == "crdb":
            # in-memory store (>= 640 MiB is CockroachDB's minimum), admin UI on the container's own loopback only
            args += ["start-single-node", "--insecure", "--store=type=mem,size=640MiB", "--cache=64MiB",
                     "--max-sql-memory=768MiB", "--http-addr=127.0.0.1:8080"]
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
        size, store = check_image(n, engines[n], limit, allow_pull)
        log(f"{n}: {ref(engines[n])} {size} bytes <= {limit}, config {engines[n]['config_digest'][:19]} ({store} store)")
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
        rule = f"floor {e['floor']}" if e["kind"] in FLOOR_KINDS else f"fixed_in {'/'.join(e['fixed_in'])}"
        print(f"{n:8} OK    {e['kind']} {v} == pin, {rule} ({e.get('advisory', '')}) 127.0.0.1:{port}")
    print(f"ENGINES VERSIONS: {'PASS' if not bad else 'FAIL'} ({len(names) - bad}/{len(names)})")
    return 1 if bad else 0

def cmd_check(argv):
    pins = load_pins()
    limit = pins["max_image_bytes"]
    for n, e in pins["engines"].items():
        size, store = check_image(n, e, limit, allow_pull=False)
        print(f"{n:8} {ref(e)} {size} bytes, config {e['config_digest']} ({store} store), version {e['version']} ({e['policy']})")
    print("ENGINES CHECK: PASS")
    return 0

def cmd_pull(argv):
    pins = load_pins()
    limit = pins["max_image_bytes"]
    engines = pins["engines"]
    names = [n for n in (argv[0].split(",") if argv else engines) if n]
    for n in names:
        if n not in engines:
            raise Refuse(f"unknown engine {n!r} (pinned: {', '.join(sorted(engines))})")
    for n in names:
        size, store = check_image(n, engines[n], limit, allow_pull=True)
        print(f"{n:8} {ref(engines[n])} {size} bytes, config {engines[n]['config_digest']} ({store} store)")
    print(f"ENGINES PULL: PASS ({len(names)} image(s) staged)")
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
if a[0] == "history":
    img = cfg["images"].get(a[-1])
    if img is None:
        sys.stderr.write("No such image\n"); sys.exit(1)
    for n in img.get("_layers", [img["Size"]]): print(n)
    sys.exit(0)
if a[0] == "save":
    blob = cfg.get("saves", {}).get(a[-1])
    if blob is None:
        sys.stderr.write("No such image\n"); sys.exit(1)
    import base64
    sys.stdout.buffer.write(base64.b64decode(blob)); sys.exit(0)
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
        if self.kind == "mariadb":
            def pkt(seq, b):
                return len(b).to_bytes(3, "little") + bytes([seq]) + b
            greet = (b"\x0a" + self.version.encode() + b"-MariaDB-fake\0" + struct.pack("<I", 7) + b"12345678\0"
                     + struct.pack("<H", 0xf7ff) + b"\x2d" + struct.pack("<H", 2) + struct.pack("<H", 0x81ff) + bytes([21])
                     + b"\0" * 10 + b"123456789012\0" + b"mysql_native_password\0")
            c.sendall(pkt(0, greet))
            c.recv(4096)
            c.sendall(pkt(2, b"\x00\x00\x00\x02\x00\x00\x00"))
            c.recv(4096)
            v = (self.version + "-MariaDB-fake").encode()
            c.sendall(pkt(1, b"\x01") + pkt(2, b"\x03def\0\0\0\x09version()\0\x0c\x21\0\0\0\0\xfd\0\0\0\0\0")
                      + pkt(3, b"\xfe\0\0\x02\0") + pkt(4, bytes([len(v)]) + v) + pkt(5, b"\xfe\0\0\x02\0"))
            c.recv(16)
            return
        if self.kind == "crdb":
            (ln,) = struct.unpack("!i", _recv_exact(c, 4))
            _recv_exact(c, ln - 4)
            def m(t, p):
                return t + struct.pack("!i", len(p) + 4) + p
            c.sendall(m(b"R", struct.pack("!i", 0)) + m(b"S", b"server_version\x0013.0.0\0") + m(b"Z", b"I"))
            _recv_exact(c, 1); (ln,) = struct.unpack("!i", _recv_exact(c, 4)); _recv_exact(c, ln - 4)
            v = f"CockroachDB CCL v{self.version} (x86_64-pc-linux-gnu, fake)".encode()
            c.sendall(m(b"T", struct.pack("!h", 1) + b"version\0" + struct.pack("!ihihih", 0, 0, 25, -1, -1, 0))
                      + m(b"D", struct.pack("!h", 1) + struct.pack("!i", len(v)) + v) + m(b"C", b"SELECT 1\0") + m(b"Z", b"I"))
            c.recv(16)
            return
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
         "image_id": ID1, "config_digest": ID1, "bytes": 1000, "version": version, "policy": "allow",
         "port": {"postgres": 5432, "mariadb": 3306, "crdb": 26257}.get(kind, 6379)}
    if kind == "postgres":
        e["floor"] = "17.11"
    elif kind == "mariadb":
        e["floor"] = "11.8.9"
    elif kind == "crdb":
        e["floor"] = "25.4.18"
    else:
        e["fixed_in"] = ["8.0.7", "8.1.6", "9.0.3", "9.1.0"] if kind == "valkey" else ["8.6.1", "8.10.0"]
    e.update(kw)
    return e

def base_image(e, size=1000, digests=None, image_id=ID1, layers=None):
    img = {"Id": image_id, "Size": size,
           "RepoDigests": digests if digests is not None else [f"{e['image']}@{e['digest']}"]}
    if layers is not None:
        img["_layers"] = layers
    return img

DIFF_IDS = ["sha256:" + "1" * 64, "sha256:" + "2" * 64]
CFG_BYTES = json.dumps({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": DIFF_IDS}},
                       separators=(",", ":")).encode()
CFG_DIGEST = "sha256:" + hashlib.sha256(CFG_BYTES).hexdigest()

def save_tar(cfg_bytes=CFG_BYTES, name_hex=None, entries=1, with_manifest=True):
    """A `docker save --platform linux/amd64` OCI-layout stream: the config blob, a 5 MB layer the reader must skip,
    and the docker-compatible manifest.json (last, as docker writes it)."""
    hx = name_hex or hashlib.sha256(cfg_bytes).hexdigest()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        def add(name, data):
            ti = tarfile.TarInfo(name); ti.size = len(data); t.addfile(ti, io.BytesIO(data))
        add("blobs/sha256/" + hx, cfg_bytes)
        big = b"\0" * (5 << 20)
        add("blobs/sha256/" + hashlib.sha256(big).hexdigest(), big)
        add("oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
        if with_manifest:
            m = [{"Config": "blobs/sha256/" + hx, "RepoTags": None, "Layers": []}] * entries
            add("manifest.json", json.dumps(m).encode())
    return base64.b64encode(buf.getvalue()).decode()

def containerd_image(e, index=D1, layers=DIFF_IDS):
    """inspect output of a containerd-snapshotter store: Id = Descriptor.digest = the index digest."""
    img = base_image(e, image_id=index)
    img["Descriptor"] = {"mediaType": "application/vnd.oci.image.index.v1+json", "digest": index, "size": 1234}
    img["RootFS"] = {"Type": "layers", "Layers": list(layers)}
    return img

def run_case(tmp, case):
    """Returns (rc, stderr+stdout, docker call log)."""
    e = case["pin"]
    name = case.get("name", "eng")
    pins = fixture_pins(tmp, {name: e})
    srv = FakeServer(e["kind"], case.get("serves", e["version"]), case.get("valkey_compat", True))
    cfg = {"images": {f"{e['image']}@{e['digest']}": case.get("image", base_image(e))},
           "saves": {f"{e['image']}@{e['digest']}": case["save"]} if "save" in case else {},
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
    my = base_pin("mariadb", "11.8.9")
    cr = base_pin("crdb", "25.4.19")
    pgc = base_pin(digest=D1, image_id=D1, config_digest=CFG_DIGEST)  # one pin, valid on both stores
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
            if not re.search(r"URL=(postgresql://postgres:[0-9a-f]{32}@|redis://|mysql://root:[0-9a-f]{32}@|postgresql://root@)"
                             r"127\.0\.0\.1:\d+", out):
                return "@name not substituted with a loopback URL"
            if not removed(calls):
                return "not torn down"
            return None
        return chk
    return [
        ("positive control: pg 17.11 at pin", dict(pin=pg), accepted()),
        ("positive control: valkey 9.1.2 (valkey_version, not compat redis_version 7.2.4)", dict(pin=vk), accepted()),
        ("positive control: redis 8.10.2", dict(pin=rd), accepted()),
        ("positive control: mariadb 11.8.9 (authenticated select version())", dict(pin=my), accepted()),
        ("positive control: crdb 25.4.19 (select version(), not server_version 13.0.0)", dict(pin=cr), accepted()),
        ("mariadb server reports 11.8.8, pin 11.8.9 -> teardown + refuse", dict(pin=my, serves="11.8.8"), refused("pin says", started=True)),
        ("crdb pin below floor (25.4.17 < 25.4.18) refused", dict(pin=base_pin("crdb", "25.4.17")), refused("below floor")),
        ("mariadb pin from another series (11.4.13 vs floor 11.8.9) refused", dict(pin=base_pin("mariadb", "11.4.13")), refused("series")),
        ("containerd store: inspect Size (compressed) 200 MB but unpacked layers 600 MB refused",
         dict(pin=cr, image=base_image(cr, size=200_000_000, layers=[300_000_000, 300_000_000])), refused("exceeds")),
        ("cmd exit status propagates and teardown still runs", dict(pin=pg, cmd_rc=7), accepted(7)),
        ("oversize image (inspect Size 500000001) refused before run",
         dict(pin=pg, image=base_image(pg, size=500_000_001)), refused("exceeds")),
        ("oversize recorded bytes in pins refused", dict(pin=base_pin(bytes=600_000_000)), refused("exceeds")),
        ("unpinned tag (no digest) refused", dict(pin=base_pin(digest="")), refused("not pinned by digest")),
        ("tag-as-digest refused", dict(pin=base_pin(digest="17-alpine")), refused("not pinned by digest")),
        ("local image lacks pinned digest refused",
         dict(pin=pg, image=base_image(pg, digests=[f"postgres@{D2}"])), refused("does not carry pinned digest")),
        ("classic store: image Id differs from the pinned config_digest refused",
         dict(pin=pg, image=base_image(pg, image_id="sha256:" + "d" * 64)), refused("!= pinned config_digest")),
        ("pin without config_digest refused", dict(pin=base_pin(config_digest="")), refused("config_digest missing")),
        ("pin image_id that is neither digest nor config_digest refused",
         dict(pin=base_pin(image_id="sha256:" + "e" * 64)), refused("neither the pinned digest")),
        ("positive control: the same pin on a containerd store (Id = index digest, config via docker save)",
         dict(pin=pgc, image=containerd_image(pgc), save=save_tar()), accepted()),
        ("positive control: that pin on a classic store (Id = config digest)",
         dict(pin=pgc, image=base_image(pgc, image_id=CFG_DIGEST)), accepted()),
        ("containerd store: saved linux/amd64 config != pinned config_digest refused",
         dict(pin=base_pin(digest=D1, image_id=D1, config_digest="sha256:" + "f" * 64), image=containerd_image(pgc),
              save=save_tar()), refused("!= pinned config_digest")),
        ("containerd store: Id is an index digest other than the pin's refused",
         dict(pin=pgc, image=containerd_image(pgc, index=D2), save=save_tar()), refused("not the pinned index digest")),
        ("containerd store: config blob does not hash to its name refused",
         dict(pin=pgc, image=containerd_image(pgc), save=save_tar(name_hex="0" * 64)),
         refused("does not hash to its name")),
        ("containerd store: config's rootfs is not the inspected image's layers refused",
         dict(pin=pgc, image=containerd_image(pgc, layers=DIFF_IDS[:1]), save=save_tar()), refused("RootFS")),
        ("containerd store: save stream with two images refused",
         dict(pin=pgc, image=containerd_image(pgc), save=save_tar(entries=2)), refused("exactly one")),
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
    myk = {"kind": "mariadb", "floor": "11.8.9", "advisory": "x"}
    crk = {"kind": "crdb", "floor": "25.4.18", "advisory": "x"}
    want = [(pg17, "17.11", True), (pg17, "17.12", True), (pg17, "17.10", False), (pg17, "17.9", False),
            (pg17, "18.6", False), (pg18, "18.5", False), (pg18, "18.6", True), (pg18, "18.10", True),
            (pg18, "19rc1", False), (vk, "9.1.2", True), (vk, "9.0.2", False), (vk, "9.0.3", True),
            (vk, "8.1.5", False), (vk, "9.2.0", False), (rd, "8.10.2", True), (rd, "8.8.4", False),
            (rd, "8.6.0", False), (rd, "8.6.1", True), (rd, "7.4.10", True),
            (myk, "11.8.9", True), (myk, "11.8.10", True), (myk, "11.8.8", False), (myk, "11.4.13", False),
            (myk, "12.3.3", False), (crk, "25.4.18", True), (crk, "25.4.19", True), (crk, "25.4.9", False),
            (crk, "25.3.30", False), (crk, "26.1.0", False)]
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

MUTANTS = ("no-size-check", "no-digest-check", "no-config-digest-check", "string-version-compare", "no-floor")

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
        for m in MUTANTS:
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
    print("ENGINES SELF-TEST: PASS (oversize image, unpinned tag, digest/config-digest mismatch on classic and "
          f"containerd stores, below-floor and pin-mismatch versions refused; {len(MUTANTS)}/{len(MUTANTS)} mutants red)")
    return 0

def main():
    a = sys.argv[1:]
    if not a:
        print(open(os.environ["ENGINES_SELF"]).read().split("set -euo")[0], file=sys.stderr)
        return 2
    sub, rest = a[0], a[1:]
    fn = {"with": cmd_with, "versions": cmd_versions, "check": cmd_check, "self-test": cmd_selftest,
          "reap": cmd_reap, "pull": cmd_pull}.get(sub)
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
