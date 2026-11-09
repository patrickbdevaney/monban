"""One request, one response on malformed chunked framing (PREFLIGHT R6; unit P8-oracle-001). Stdlib only.

Shared by oracles/proxy-e2e (gate reverse-proxy-e2e, the default aegis build) and oracles/bin-residuals (gate
bin-residuals, aegis built with --features mtc,l4).

Finding being closed (units/phase-7/reports/P7-oracle-uring-001.md finding 2): one bad chunk-size line, or a bare LF
in a chunk line, makes aegis send two 400 responses on one connection (hyper's, with a `date` field, then the strict
filter's, without one) before it closes. RFC 9112 section 7.1 makes the chunk-size line `chunk-size [ chunk-ext ]
CRLF` with `chunk-size = 1*HEXDIG`; a recipient that cannot parse the framing cannot find the end of the message and
must close after its response (RFC 9112 section 9.6 / 11.2). One request produces exactly one response (RFC 9110
section 3.3: a server sends one final response per request).

The check, per case:
- `<case>.one-response`: the bytes the client receives until the server closes (5 s cap) parse as exactly one
  HTTP/1.1 response, with nothing after it.
- `<case>.status-400`: that response is a 400.
- `<case>.closed`: the server closed the connection within 5 s of the request (the framing is lost).
- `<case>.not-forwarded`: the upstream saw no request (when the caller passes an upstream counter).
The positive control `chunk.valid` sends a well-formed chunked POST and needs exactly one 200.

`judge_selftest()` proves the judge itself goes red: a reference TLS server that answers one 400 must pass, and
mutants that answer two 400s (the R6 behaviour), none, or one 400 and then keep the connection open must fail.
"""

import socket
import ssl
import threading
import time

READ_CAP_S = 5.0

CASES = {
    # name -> body bytes after the head (head adds Transfer-Encoding: chunked)
    "chunk.bad-size": b"zz\r\nhello\r\n0\r\n\r\n",
    "chunk.bare-lf": b"5\nhello\r\n0\r\n\r\n",
}
VALID = b"5\r\nhello\r\n0\r\n\r\n"


def request(host, path, body):
    return (f"POST {path} HTTP/1.1\r\nhost: {host}\r\ntransfer-encoding: chunked\r\n"
            f"content-type: text/plain\r\n\r\n").encode() + body


def exchange(port, sni, cafile, payload, cap=READ_CAP_S):
    """Send payload over TLS (ALPN http/1.1), read until close or cap. Returns (bytes, closed, seconds)."""
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.set_alpn_protocols(["http/1.1"])
    raw = socket.create_connection(("127.0.0.1", port), timeout=cap)
    s = ctx.wrap_socket(raw, server_hostname=sni)
    t0 = time.monotonic()
    data, closed = b"", False
    try:
        s.sendall(payload)
        while True:
            left = cap - (time.monotonic() - t0)
            if left <= 0:
                break
            s.settimeout(left)
            try:
                d = s.recv(65536)
            except (socket.timeout, TimeoutError):
                break
            except (ConnectionResetError, ssl.SSLError, OSError):
                closed = True
                break
            if not d:
                closed = True
                break
            data += d
    finally:
        try:
            s.close()
        except OSError:
            pass
    return data, closed, time.monotonic() - t0


def parse_responses(data):
    """Split HTTP/1.1 responses. Returns (list of (status, headers dict), leftover bytes, error or None)."""
    out = []
    while data:
        if b"\r\n\r\n" not in data:
            return out, data, "incomplete head"
        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        parts = lines[0].split(b" ", 2)
        if len(parts) < 2 or not parts[0].startswith(b"HTTP/1.") or not parts[1].isdigit():
            return out, data, f"not a status line: {lines[0][:60]!r}"
        hdrs = {}
        for ln in lines[1:]:
            n, _, v = ln.partition(b":")
            hdrs[n.strip().lower()] = v.strip()
        status = int(parts[1])
        if b"transfer-encoding" in hdrs:
            body_end = rest.find(b"0\r\n\r\n")
            if body_end < 0:
                return out + [(status, hdrs)], b"", None
            rest = rest[body_end + 5:]
        elif b"content-length" in hdrs:
            try:
                n = int(hdrs[b"content-length"])
            except ValueError:
                return out, data, "bad content-length"
            if len(rest) < n:
                return out + [(status, hdrs)], b"", "short body"
            rest = rest[n:]
        else:
            # no framing: the body runs to close, so nothing after it can be a second response
            out.append((status, hdrs))
            return out, b"", None
        out.append((status, hdrs))
        data = rest
    return out, b"", None


def run_cases(check, port, sni, cafile, host, path, upstream_count=None, prefix=""):
    """Run every case; `check(name, ok, detail)` records. Returns nothing."""
    for name, body in CASES.items():
        n0 = upstream_count() if upstream_count else None
        data, closed, secs = exchange(port, sni, cafile, request(host, path, body))
        resps, left, err = parse_responses(data)
        statuses = [s for s, _ in resps]
        check(f"{prefix}{name}.one-response", len(resps) == 1 and not left and err is None,
              f"{len(resps)} responses {statuses}, {len(left)} trailing bytes, {err or 'ok'}: {data[:300]!r}")
        check(f"{prefix}{name}.status-400", statuses[:1] == [400], f"statuses {statuses}")
        check(f"{prefix}{name}.closed", closed, f"connection still open {secs:.1f} s after the request")
        if upstream_count:
            time.sleep(0.2)
            check(f"{prefix}{name}.not-forwarded", upstream_count() == n0, "the upstream saw the malformed request")
    data, closed, _ = exchange(port, sni, cafile, request(host, path, VALID) .replace(
        b"content-type: text/plain\r\n", b"content-type: text/plain\r\nconnection: close\r\n"))
    resps, left, err = parse_responses(data)
    check(f"{prefix}chunk.valid.one-200", [s for s, _ in resps] == [200] and not left,
          f"{[s for s, _ in resps]} {err or ''}: {data[:200]!r}")


# ------------------------------------------------------------------------------------------------ reference server
def _strict_chunked(buf):
    """Parse a chunked body strictly. Returns ("ok", consumed) | ("bad", None) | ("more", None)."""
    o = 0
    while True:
        i = buf.find(b"\n", o)
        if i < 0:
            return ("more", None)
        if i == o or buf[i - 1:i] != b"\r":
            return ("bad", None)
        line = buf[o:i - 1].split(b";", 1)[0]
        if not line or any(c not in b"0123456789abcdefABCDEF" for c in line):
            return ("bad", None)
        n = int(line, 16)
        o = i + 1
        if n == 0:
            if buf[o:o + 2] == b"\r\n":
                return ("ok", o + 2)
            return ("more", None) if len(buf) < o + 2 else ("bad", None)
        if len(buf) < o + n + 2:
            return ("more", None)
        if buf[o + n:o + n + 2] != b"\r\n":
            return ("bad", None)
        o += n + 2


BAD = b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
BAD2 = b"HTTP/1.1 400 Bad Request\r\ncontent-length: 11\r\n\r\nbad request"
OK = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok"


def serve_h1(conn, mutant=None, on_valid=None):
    """Answer one HTTP/1.1 request on an established (TLS) socket the way the contract demands. mutant:
    "two-responses" (R6: two 400s), "no-response" (close silently), "keep-open" (one 400, never close)."""
    buf = b""
    conn.settimeout(10)
    try:
        while b"\r\n\r\n" not in buf:
            d = conn.recv(65536)
            if not d:
                return
            buf += d
        head, _, rest = buf.partition(b"\r\n\r\n")
        chunked = b"transfer-encoding: chunked" in head.lower()
        state = ("ok", 0)
        if chunked:
            while True:
                state = _strict_chunked(rest)
                if state[0] != "more":
                    break
                d = conn.recv(65536)
                if not d:
                    return
                rest += d
        if state[0] == "bad":
            if mutant == "no-response":
                return
            if mutant == "two-responses":
                conn.sendall(BAD2 + BAD)
            else:
                conn.sendall(BAD)
            if mutant == "keep-open":
                time.sleep(READ_CAP_S + 1)
            return
        if on_valid:
            on_valid()
        conn.sendall(OK)
    except OSError:
        return


class RefServer:
    def __init__(self, cert, key, mutant=None):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert, key)
        self.ctx.set_alpn_protocols(["http/1.1"])
        self.mutant = mutant
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c):
        try:
            t = self.ctx.wrap_socket(c, server_side=True)
        except (OSError, ssl.SSLError):
            c.close()
            return
        try:
            serve_h1(t, self.mutant)
        finally:
            t.close()

    def close(self):
        self.sock.close()


JUDGE_MUTANTS = ("two-responses", "no-response", "keep-open")


def judge_selftest(cert, key, sni, log=print):
    """Returns (ok, summary). The reference must pass every case; each mutant must fail at least one."""
    def run(mutant):
        fails = []
        srv = RefServer(cert, key, mutant)
        try:
            run_cases(lambda n, ok, d="": ok or fails.append(n), srv.port, sni, cert, sni, "/api/x")
        finally:
            srv.close()
        return fails
    base = run(None)
    if base:
        return False, f"reference one-response server failed {base}"
    caught = []
    for m in JUDGE_MUTANTS:
        f = run(m)
        if not f:
            return False, f"one-response judge mutant {m} not caught"
        log(f"  one-response judge mutant {m}: caught by {', '.join(f[:4])}")
        caught.append(m)
    return True, f"one-response judge {len(caught)}/{len(JUDGE_MUTANTS)} mutants caught"
