"""front-equiv self-test subject: a reference implementation of the `--front` interface around today's aegis.

It accepts exactly the interface README.md defines for the real binary:

    front_ref.py --config <f> [--cert <pem>] [--key <pem>] [--audit-dir <d>] [--front epoll|uring] [...]

and resolves the front the same way (CLI flag > `listeners[].front` > epoll; `--front <other>` -> exit 64; config
`front` other than epoll/uring -> exit 78). The real aegis it wraps is $FRONT_REF_AEGIS (a default build).

* epoll: execv()s aegis (same pid, so the oracle inspects aegis itself: its sockets sit in tokio's epoll).
* uring: checks io_uring_setup first (unavailable -> message naming io_uring, exit 71, nothing bound), creates a real
  ring, binds the public listener itself and terminates TLS there (same cert/key, ALPN, SNI forwarded), and relays
  plaintext to an aegis child bound on a private loopback port. Each accepted connection submits one IORING_OP_NOP,
  so CqTail moves with traffic; connection I/O uses blocking sockets + poll(2), never an epoll instance.

$FRONT_REF_MUTANT picks a deliberately broken uring front (each must turn the oracle red):
  drop-last-chunk     withholds the last 4096 bytes of every HTTP/1.1 response whose body is >= 16 KiB
  reorder-pipelined   swaps two complete HTTP/1.1 responses that arrive within 300 ms of each other
  close-after-response closes the client connection after the first HTTP/1.1 response (ignores keep-alive)
  normalize-bare-lf   rewrites bare LF to CRLF in client bytes (a "lenient" front: strict-H1 rejects disappear)
  no-ring             never creates a ring ("uring" that is really plain sockets)
  socket-in-epoll     registers every client socket in an epoll instance
  silent-fallback     io_uring unavailable -> serves anyway without a ring instead of refusing
  config-front-ignored ignores listeners[].front (only the CLI flag selects uring)
"""

import json
import os
import re
import select
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import uring  # noqa: E402

EX_USAGE, EX_CONFIG, EX_OSERR = 64, 78, 71
MUTANT = os.environ.get("FRONT_REF_MUTANT", "")
H1_MUTANTS = {"drop-last-chunk", "reorder-pipelined", "close-after-response"}


def die(code, msg):
    print(f"front_ref: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def parse_args(argv):
    opts, front, cfg = [], None, None
    it = iter(argv)
    for a in it:
        if a == "--front":
            front = next(it, None)
            if front not in ("epoll", "uring"):
                die(EX_USAGE, f"--front must be epoll or uring, got {front!r}")
        elif a == "--config":
            cfg = next(it, None)
            opts += [a, cfg]
        else:
            opts.append(a)
    return opts, front, cfg


def strip_front(doc):
    out = json.loads(json.dumps(doc))
    for l in out.get("listeners", []):
        l.pop("front", None)
    return out


# ------------------------------------------------------------------------------------------------ h1 response parse


def parse_h1_response(buf):
    """Return (length_of_first_complete_response, body_len) or None if incomplete / close-delimited."""
    end = buf.find(b"\r\n\r\n")
    if end < 0:
        return None
    head = buf[:end].split(b"\r\n")
    try:
        status = int(head[0].split(b" ")[1])
    except (IndexError, ValueError):
        return None
    hdr = {}
    for ln in head[1:]:
        n, _, v = ln.partition(b":")
        hdr[n.strip().lower()] = v.strip()
    start = end + 4
    if 100 <= status < 200 or status in (204, 304):
        return start, 0
    if hdr.get(b"transfer-encoding", b"").lower() == b"chunked":
        i = start
        while True:
            le = buf.find(b"\r\n", i)
            if le < 0:
                return None
            try:
                size = int(buf[i:le].split(b";")[0], 16)
            except ValueError:
                return None
            i = le + 2
            if size == 0:
                te = buf.find(b"\r\n\r\n", i - 2)
                if te < 0:
                    return None
                return te + 4, te + 4 - start
            if len(buf) < i + size + 2:
                return None
            i += size + 2
    if b"content-length" in hdr:
        n = int(hdr[b"content-length"])
        return (start + n, n) if len(buf) >= start + n else None
    return None


# ------------------------------------------------------------------------------------------------ relay


def write_all(s, data):
    p = select.poll()
    p.register(s, select.POLLOUT)
    while data:
        try:
            n = s.send(data)
            data = data[n:]
        except (ssl.SSLWantWriteError, BlockingIOError):
            p.poll(1000)
        except ssl.SSLWantReadError:
            q = select.poll()
            q.register(s, select.POLLIN)
            q.poll(1000)


def drain(s):
    """Read everything currently decryptable; return (bytes, eof)."""
    out = b""
    while True:
        try:
            d = s.recv(65536)
        except (ssl.SSLWantReadError, BlockingIOError):
            return out, False
        except ssl.SSLWantWriteError:
            return out, False
        except (OSError, ssl.SSLError):
            return out, True
        if not d:
            return out, True
        out += d


def relay(client, backend, h1):
    client.setblocking(False)
    backend.setblocking(False)
    p = select.poll()
    p.register(client, select.POLLIN)
    p.register(backend, select.POLLIN)
    s2c = b""
    held, held_until, sent_one = None, 0.0, False
    use_parser = h1 and MUTANT in H1_MUTANTS
    try:
        while True:
            timeout = 30000
            if held is not None:
                timeout = max(0, int((held_until - time.monotonic()) * 1000))
            ev = p.poll(timeout) if not (client.pending() or backend.pending()) else [(client.fileno(), 1)]
            if held is not None and time.monotonic() >= held_until:
                write_all(client, held)
                held = None
            if not ev and held is None:
                continue
            d, eof_c = drain(client)
            if d:
                if h1 and MUTANT == "normalize-bare-lf":
                    d = re.sub(rb"(?<!\r)\n", b"\r\n", d)
                write_all(backend, d)
            d, eof_b = drain(backend)
            if d:
                if not use_parser:
                    write_all(client, d)
                else:
                    s2c += d
                    while True:
                        r = parse_h1_response(s2c)
                        if r is None:
                            break
                        n, body_len = r
                        resp, s2c = s2c[:n], s2c[n:]
                        if MUTANT == "drop-last-chunk" and body_len >= 16384:
                            resp = resp[:-4096]
                        if MUTANT == "reorder-pipelined":
                            if held is None:
                                held, held_until = resp, time.monotonic() + 0.3
                            else:
                                write_all(client, resp)
                                write_all(client, held)
                                held = None
                            continue
                        write_all(client, resp)
                        if MUTANT == "close-after-response" and not resp.split(b" ", 2)[1].startswith(b"1"):
                            sent_one = True
                            break
            if sent_one:
                return
            if eof_b:
                if held is not None:
                    write_all(client, held)
                if s2c:
                    write_all(client, s2c)
                return
            if eof_c:
                return
    except (OSError, ssl.SSLError):
        return
    finally:
        for s in (client, backend):
            try:
                s.close()
            except OSError:
                pass


# ------------------------------------------------------------------------------------------------ uring front


class UringFront:
    def __init__(self, bind, alpn, cert, key, backend_port, ring):
        self.backend_port = backend_port
        self.ring = ring
        self.ep = select.epoll() if MUTANT == "socket-in-epoll" else None
        self.sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.sctx.load_cert_chain(cert, key)
        self.sctx.set_alpn_protocols(alpn)
        self.sni = {}
        self.sctx.sni_callback = lambda so, name, _ctx: self.sni.__setitem__(id(so), name)
        host, _, port = bind.rpartition(":")
        self.sock = socket.socket(socket.AF_INET6 if ":" in host.strip("[]") else socket.AF_INET)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host.strip("[]"), int(port)))
        self.sock.listen(512)

    def serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            if self.ring is not None:
                self.ring.nop()
            if self.ep is not None:
                self.ep.register(c.fileno(), select.EPOLLIN)
            threading.Thread(target=self.conn, args=(c,), daemon=True).start()

    def conn(self, raw):
        raw.settimeout(15)
        try:
            c = self.sctx.wrap_socket(raw, server_side=True)
        except (OSError, ssl.SSLError):
            raw.close()
            return
        alpn = c.selected_alpn_protocol()
        sni = self.sni.pop(id(c), None)
        try:
            cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            cctx.check_hostname = False
            cctx.verify_mode = ssl.CERT_NONE
            if alpn:
                cctx.set_alpn_protocols([alpn])
            b = socket.create_connection(("127.0.0.2", self.backend_port), 10)
            b = cctx.wrap_socket(b, server_hostname=sni)
        except (OSError, ssl.SSLError):
            c.close()
            return
        relay(c, b, alpn != "h2")


def main():
    aegis = os.environ.get("FRONT_REF_AEGIS", "")
    if not os.access(aegis, os.X_OK):
        die(EX_OSERR, f"FRONT_REF_AEGIS={aegis!r} is not an executable aegis")
    opts, cli_front, cfg_path = parse_args(sys.argv[1:])
    if cfg_path is None:
        os.execv(aegis, [aegis] + opts)  # aegis decides (exit 78 bare / missing config)
    try:
        with open(cfg_path, "rb") as f:
            doc = json.loads(f.read())
    except (OSError, ValueError):
        os.execv(aegis, [aegis] + opts)  # let aegis report the unreadable / invalid file itself
    fronts = set()
    for l in doc.get("listeners", []) if isinstance(doc, dict) else []:
        if isinstance(l, dict) and "front" in l:
            if l["front"] not in ("epoll", "uring"):
                die(EX_CONFIG, f"listener {l.get('name')!r}: front must be \"epoll\" or \"uring\"")
            fronts.add(l["front"])
    cfg_front = "uring" if "uring" in fronts and MUTANT != "config-front-ignored" else "epoll"
    front = cli_front or cfg_front

    if front == "epoll":
        if fronts:
            stripped = cfg_path + ".front-ref.json"
            with open(stripped, "w") as f:
                json.dump(strip_front(doc), f)
            opts = [stripped if o == cfg_path else o for o in opts]
        os.execv(aegis, [aegis] + opts)

    # ---- uring: fail closed before anything is bound
    ring = None
    if MUTANT != "no-ring":
        try:
            ring = uring.Ring()
        except OSError as e:
            if MUTANT != "silent-fallback":
                die(EX_OSERR, f"--front uring: io_uring unavailable ({e}); refusing to start (no epoll fallback)")
    listeners = doc.get("listeners", [])
    if len(listeners) != 1:
        die(EX_CONFIG, "front_ref supports exactly one listener")
    l0 = listeners[0]
    cert = opts[opts.index("--cert") + 1] if "--cert" in opts else None
    key = opts[opts.index("--key") + 1] if "--key" in opts else None
    # The aegis child listens on the same port on 127.0.0.2, so the authority the client sends (aegis.test:<port>)
    # still matches its listener; the reference front itself owns 127.0.0.1:<port>.
    inner = strip_front(doc)
    pub_bind = l0["bind"]
    bport = int(pub_bind.rpartition(":")[2])
    inner["listeners"][0]["bind"] = f"127.0.0.2:{bport}"
    inner_path = cfg_path + ".front-ref-inner.json"

    def write_inner():
        try:
            with open(cfg_path, "rb") as f:
                d = json.loads(f.read())
            d = strip_front(d)
            for l in d.get("listeners", []):
                l["bind"] = f"127.0.0.2:{bport}"
        except (OSError, ValueError, AttributeError, TypeError):
            with open(cfg_path, "rb") as f:
                raw = f.read()
            with open(inner_path, "wb") as f:  # pass the broken bytes through: aegis keeps its last-known-good
                f.write(raw)
            return
        with open(inner_path, "w") as f:
            json.dump(d, f)

    with open(inner_path, "w") as f:
        json.dump(inner, f)
    front_srv = UringFront(pub_bind, l0.get("alpn", ["h2", "http/1.1"]), cert, key, bport, ring)
    child = subprocess.Popen([aegis] + [inner_path if o == cfg_path else o for o in opts])

    def on_hup(_s, _f):
        write_inner()
        child.send_signal(signal.SIGHUP)

    def on_term(_s, _f):
        child.send_signal(signal.SIGTERM)

    signal.signal(signal.SIGHUP, on_hup)
    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    threading.Thread(target=front_srv.serve, daemon=True).start()
    while True:
        try:
            rc = child.wait(0.2)
            break
        except subprocess.TimeoutExpired:
            continue
    front_srv.sock.close()
    time.sleep(0.2)  # let relays observe the backend EOFs and close their clients
    sys.exit(rc if rc >= 0 else 128 - rc)


if __name__ == "__main__":
    main()
