"""Self-test fakes for oracles/soak (stdlib only; never a production subject).

    fakes.py subject <admin-port> <dir>   admin HTTP (/healthz, /metrics, /load/start, /load/stop, /once) whose
                                          leaks are visible in /proc; writes <dir>/audit.state on SIGTERM
    fakes.py otlp <endpoint> <interval-s> POSTs {} to <endpoint>v1/metrics every interval until SIGTERM
    fakes.py h2load <admin-port> -c C -m M -D S [--rps R]
                                          brackets S seconds with /load/start and /load/stop and prints an h2load
                                          summary (req/s = C x R with --rps, else 20000)
    fakes.py verify <dir>                 exit 0 iff <dir>/audit.state says the log verifies

Mutants (env SOAK_FAKE_MUTANT; SOAK_FAKE_SCALE = virtual seconds per real second):
  rss-leak      2 MiB per virtual hour of load, written pages kept
  fd-leak       10 of the fds opened per load bracket are never closed
  task-leak     the 6 threads started per load bracket never exit
  one-error     exactly one failed request in the whole run
  audit-bad     the audit log does not verify
  otlp-dead     the sidecar never exports
  exit-nonzero  exit 1 on SIGTERM
  slow-load     every --rps run reports 70% of the asked rate
"""
import json
import os
import signal
import socket
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MUTANT = os.environ.get("SOAK_FAKE_MUTANT", "")
SCALE = float(os.environ.get("SOAK_FAKE_SCALE", "1"))
MIB = 1 << 20


def subject(port, d):
    state = {"load": False, "fds": [], "stops": [], "leak": [], "once": 1}
    lock = threading.Lock()

    def leaker():
        per_tick = int(2 * MIB * SCALE * 0.05 / 3600.0)   # 2 MiB per virtual hour, in 50 ms real ticks
        while True:
            time.sleep(0.05)
            if MUTANT == "rss-leak" and state["load"]:
                state["leak"].append(bytearray(b"\x5a") * per_tick)

    def start():
        with lock:
            state["load"] = True
            for _ in range(20):
                state["fds"].append(os.open("/dev/null", os.O_RDONLY))
            ev = threading.Event()
            state["stops"].append(ev)
            for _ in range(6):
                threading.Thread(target=ev.wait, daemon=True).start()

    def stop():
        with lock:
            state["load"] = False
            keep = 10 if MUTANT == "fd-leak" else 0
            fds, state["fds"] = state["fds"], []
            for fd in fds[keep:]:
                os.close(fd)
            state.setdefault("leaked", []).extend(fds[:keep])
            if MUTANT != "task-leak":
                for ev in state["stops"]:
                    ev.set()
                state["stops"] = []

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def reply(self, body):
            b = body.encode()
            self.send_response(200)
            self.send_header("content-length", str(len(b)))
            self.send_header("connection", "close")
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            if self.path == "/healthz":
                self.reply("{}")
            elif self.path == "/metrics":
                self.reply("# TYPE aegis_admission_rejects counter\naegis_admission_rejects_total 0\n"
                           "# TYPE aegis_proxy_upstream_errors counter\naegis_proxy_upstream_errors_total 0\n# EOF\n")
            elif self.path == "/load/start":
                start()
                self.reply("ok")
            elif self.path == "/load/stop":
                stop()
                self.reply("ok")
            elif self.path == "/once":
                with lock:
                    n, state["once"] = state["once"], 0
                self.reply(str(n))
            else:
                self.send_error(404)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    srv.daemon_threads = True

    def term(*_):
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, term)
    threading.Thread(target=leaker, daemon=True).start()
    srv.serve_forever()
    with open(os.path.join(d, "audit.state"), "w") as f:
        f.write("tampered" if MUTANT == "audit-bad" else "verifies")
    return 1 if MUTANT == "exit-nonzero" else 0


def otlp(endpoint, interval):
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    while not stop.wait(interval):
        if MUTANT == "otlp-dead":
            continue
        try:
            req = urllib.request.Request(endpoint + "v1/metrics", data=b"{}", method="POST",
                                         headers={"content-type": "application/json", "User-Agent": "aegis-ci"})
            urllib.request.urlopen(req, timeout=5).read()
        except OSError:
            pass
    return 0


def get(port, path):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as c:
        c.sendall(f"GET {path} HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n".encode())
        buf = b""
        while True:
            b = c.recv(4096)
            if not b:
                break
            buf += b
    return buf.partition(b"\r\n\r\n")[2].decode()


def h2load(port, argv):
    opts = dict(zip(argv[::2], argv[1::2]))
    c, dur = int(opts["-c"]), float(opts["-D"])
    rps = opts.get("--rps")
    get(port, "/load/start")
    time.sleep(dur)
    get(port, "/load/stop")
    failed = 0
    if rps and MUTANT == "one-error" and get(port, "/once") == "1":
        failed = 1
    req_s = c * int(rps) if rps else 20000
    if rps and MUTANT == "slow-load":
        req_s = int(req_s * 0.7)
    n = max(1, int(req_s * dur))
    ok = n - failed
    print(f"finished in {dur:.2f}s, {req_s:.2f} req/s, 1.00MB/s\n"
          f"requests: {n} total, {n} started, {n} done, {ok} succeeded, {failed} failed, 0 errored, 0 timeout\n"
          f"status codes: {ok} 2xx, 0 3xx, 0 4xx, {failed} 5xx")
    return 0


def verify(d):
    try:
        with open(os.path.join(d, "audit.state")) as f:
            st = f.read().strip()
    except OSError:
        st = "missing"
    print(json.dumps({"audit": st}))
    return 0 if st == "verifies" else 1


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "subject":
        sys.exit(subject(int(sys.argv[2]), sys.argv[3]))
    if cmd == "otlp":
        sys.exit(otlp(sys.argv[2], float(sys.argv[3])))
    if cmd == "h2load":
        sys.exit(h2load(int(sys.argv[2]), sys.argv[3:]))
    if cmd == "verify":
        sys.exit(verify(sys.argv[2]))
    sys.exit(2)
