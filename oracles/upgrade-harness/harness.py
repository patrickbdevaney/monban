#!/usr/bin/env python3
"""AEGIS oracle: upgrade harness (UP-1..7 under load). Contract: oracles/README.md.

Opens new TCP connections at a steady rate, one HTTP/1.1 request each, while triggering N reloads of the subject
at a fixed interval. Counts connections refused, connections reset (RST), requests dropped before the drain
deadline (EOF or no answer), reloads that did not complete, and old processes still alive after the deadline.
PASS iff all are zero over N completed reloads.

Subject CLI contract (see README):  <subject> --listen 127.0.0.1:<port> [--listen ...] --pidfile <file> --drain-ms <D>
  (--listen repeats once per listener with --listeners N; the load is spread round-robin over all of them)
  SIGHUP = upgrade; the process owning the listeners after a completed upgrade rewrites <file> with its pid;
  SIGTERM = drain and exit.

stdlib only; run as python3 -I.
"""
import argparse
import errno
import os
import resource
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

NAME = "UPGRADE-HARNESS"
REQUEST = b"GET / HTTP/1.1\r\nHost: upgrade-harness\r\nConnection: close\r\n\r\n"


# ----------------------------------------------------------------------------------------------- load generator

class Stats:
    def __init__(self):
        self.ok = 0
        self.refused = 0
        self.rst = 0
        self.dropped_eof = 0
        self.dropped_timeout = 0
        self.client_err = 0
        self.client_err_kinds = {}
        self.opened = 0
        self.ok_per_port = {}

    @property
    def dropped(self):
        return self.dropped_eof + self.dropped_timeout


def _response_complete(buf):
    end = buf.find(b"\r\n\r\n")
    if end < 0:
        return False
    head = buf[:end].decode("latin-1").lower()
    if not head.startswith("http/1.1 200"):
        return False
    clen = 0
    for line in head.split("\r\n")[1:]:
        if line.startswith("content-length:"):
            try:
                clen = int(line.split(":", 1)[1].strip())
            except ValueError:
                return False
    return len(buf) - (end + 4) >= clen


class LoadGen(threading.Thread):
    """Single-threaded epoll client: opens `rate` connections per second until stopped, then lets in-flight ones
    finish (each has a hard timeout)."""

    def __init__(self, ports, rate, conn_timeout):
        super().__init__(daemon=True)
        self.addrs = [("127.0.0.1", p) for p in ports]
        self.next_addr = 0
        self.rate = rate
        self.conn_timeout = conn_timeout
        self.stats = Stats()
        self.stop_flag = threading.Event()
        self.sel = selectors.DefaultSelector()
        self.conns = {}  # sock -> [start, phase, buf]

    def _err(self, kind):
        s = self.stats
        s.client_err += 1
        s.client_err_kinds[kind] = s.client_err_kinds.get(kind, 0) + 1

    def _classify(self, code):
        s = self.stats
        if code == errno.ECONNREFUSED:
            s.refused += 1
        elif code in (errno.ECONNRESET, errno.EPIPE):
            s.rst += 1
        else:
            self._err(errno.errorcode.get(code, str(code)))

    def _close(self, sock):
        try:
            self.sel.unregister(sock)
        except (KeyError, ValueError):
            pass
        self.conns.pop(sock, None)
        sock.close()

    def _open(self):
        self.stats.opened += 1
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        addr = self.addrs[self.next_addr]
        self.next_addr = (self.next_addr + 1) % len(self.addrs)
        code = sock.connect_ex(addr)
        if code not in (0, errno.EINPROGRESS):
            sock.close()
            self._classify(code)
            return
        self.conns[sock] = [time.monotonic(), "connect", b"", addr[1]]
        self.sel.register(sock, selectors.EVENT_WRITE)

    def _on_event(self, sock, mask):
        st = self.conns.get(sock)
        if st is None:
            return
        if st[1] == "connect":
            code = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if code != 0:
                self._close(sock)
                self._classify(code)
                return
            try:
                n = sock.send(REQUEST)
            except OSError as e:
                self._close(sock)
                self._classify(e.errno)
                return
            if n != len(REQUEST):
                self._close(sock)
                self._err("short-send")
                return
            st[1] = "read"
            self.sel.modify(sock, selectors.EVENT_READ)
            return
        try:
            data = sock.recv(65536)
        except BlockingIOError:
            return
        except OSError as e:
            self._close(sock)
            self._classify(e.errno)
            return
        if not data:
            self._close(sock)
            self.stats.dropped_eof += 1
            return
        st[2] += data
        if _response_complete(st[2]):
            self._close(sock)
            self.stats.ok += 1
            self.stats.ok_per_port[st[3]] = self.stats.ok_per_port.get(st[3], 0) + 1

    def _expire(self, now):
        for sock, st in list(self.conns.items()):
            if now - st[0] > self.conn_timeout:
                self._close(sock)
                self.stats.dropped_timeout += 1

    def run(self):
        t0 = time.monotonic()
        sent = 0
        last_expire = t0
        while True:
            now = time.monotonic()
            if not self.stop_flag.is_set():
                due = int((now - t0) * self.rate)
                burst = 0
                while sent < due and burst < 500:
                    self._open()
                    sent += 1
                    burst += 1
                wait = max(0.0005, min(0.01, (sent + 1) / self.rate - (now - t0)))
            else:
                if not self.conns:
                    return
                wait = 0.01
            for key, mask in self.sel.select(timeout=wait):
                self._on_event(key.fileobj, mask)
            if now - last_expire > 0.1:
                self._expire(now)
                last_expire = now


# ----------------------------------------------------------------------------------------------- subject control

def free_ports(n):
    """n distinct free ports (all probe sockets held open together so none repeats)."""
    socks = []
    for _ in range(n):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        socks.append(s)
    ports = [s.getsockname()[1] for s in socks]
    for s in socks:
        s.close()
    return ports


def read_pid(path):
    try:
        with open(path) as f:
            return int(f.read().strip() or "0")
    except (OSError, ValueError):
        return 0


def alive(pid):
    """True if pid exists and is not a zombie."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            stat = f.read()
    except OSError:
        return False
    try:
        return stat.rsplit(")", 1)[1].split()[0] != "Z"
    except IndexError:
        return False


def wait_until(pred, timeout, step=0.002):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(step)
    return pred()


def connectable(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
        return True
    except OSError:
        return False


def run_once(cmd, label, reloads, interval, rate, drain_ms, work, log, listeners=1):
    """Start the subject, load it, reload it `reloads` times, return a result dict."""
    ports = free_ports(listeners)
    pidfile = os.path.join(work, f"{label}.pid")
    full = list(cmd)
    for port in ports:
        full += ["--listen", f"127.0.0.1:{port}"]
    full += ["--pidfile", pidfile, "--drain-ms", str(drain_ms)]
    proc = subprocess.Popen(full, stdin=subprocess.DEVNULL, stdout=log, stderr=log, close_fds=True,
                            start_new_session=True)
    res = {"label": label, "reloads_requested": reloads, "reloads_done": 0, "old_alive": 0, "start_fail": False,
           "ports": ports}
    if not wait_until(lambda: read_pid(pidfile) > 0 and all(connectable(p) for p in ports), 10):
        res["start_fail"] = True
        proc.kill()
        proc.wait()
        return res, Stats()
    gen = LoadGen(ports, rate, conn_timeout=drain_ms / 1000.0 + 3.0)
    gen.start()
    time.sleep(0.5)  # steady state before the first reload
    old_pids = []
    reload_ms = []
    t_next = time.monotonic()
    for i in range(reloads):
        pid = read_pid(pidfile)
        t = time.monotonic()
        try:
            os.kill(pid, signal.SIGHUP)
        except OSError:
            break
        if not wait_until(lambda: read_pid(pidfile) not in (0, pid), 10):
            break
        reload_ms.append((time.monotonic() - t) * 1000)
        old_pids.append(pid)
        res["reloads_done"] += 1
        t_next += interval
        time.sleep(max(0.0, t_next - time.monotonic()))
    time.sleep(0.5)  # steady state after the last reload
    gen.stop_flag.set()
    gen.join(timeout=drain_ms / 1000.0 + 10)
    # UP-4: every old process must be gone once the drain deadline (plus slack) has passed.
    time.sleep(drain_ms / 1000.0 + 1.0)
    proc.poll()
    res["old_alive"] = sum(1 for p in old_pids if alive(p))
    cur = read_pid(pidfile)
    for p in set([cur] + old_pids):
        try:
            os.kill(p, signal.SIGTERM)
        except OSError:
            pass
    wait_until(lambda: not alive(cur), drain_ms / 1000.0 + 5)
    try:
        os.killpg(proc.pid, signal.SIGKILL)  # anything left in the session
    except OSError:
        pass
    proc.wait()
    if reload_ms:
        reload_ms.sort()
        res["reload_ms_p50"] = round(reload_ms[len(reload_ms) // 2], 1)
        res["reload_ms_max"] = round(reload_ms[-1], 1)
    return res, gen.stats


def summarize(res, st):
    return (f"reloads={res['reloads_done']}/{res['reloads_requested']} conns={st.opened} ok={st.ok} "
            f"refused={st.refused} rst={st.rst} dropped_before_D={st.dropped} "
            f"(eof={st.dropped_eof} timeout={st.dropped_timeout}) client_err={st.client_err}"
            f"{' ' + str(st.client_err_kinds) if st.client_err_kinds else ''} old_alive={res['old_alive']}"
            f"{' reload_ms_p50=' + str(res.get('reload_ms_p50')) + ' max=' + str(res.get('reload_ms_max')) if 'reload_ms_p50' in res else ''}"
            f" listeners={len(res['ports'])} ok_per_listener={[st.ok_per_port.get(p, 0) for p in res['ports']]}")


def verdict(res, st):
    # Every listener must have served traffic: a subject that hands over only some of them cannot pass.
    every_port = all(st.ok_per_port.get(p, 0) > 0 for p in res["ports"])
    return (not res["start_fail"] and res["reloads_done"] == res["reloads_requested"] and st.refused == 0
            and st.rst == 0 and st.dropped == 0 and st.client_err == 0 and res["old_alive"] == 0 and st.ok > 0
            and every_port)


# ----------------------------------------------------------------------------------------------- naive subjects

def naive_subject(argv):
    """Reference *bad* upgraders (negative controls), speaking the same CLI as a real subject.

    reuseport     the new process binds the same port with SO_REUSEPORT; once it listens, the old process closes
                  its listener (ARCHITECTURE §3.11: RSTs the connections queued on the old socket)
    close-rebind  the old process closes its listener first, then the new process binds (refused in the gap)
    deaf          ignores SIGHUP (a reload never completes)
    """
    ap = argparse.ArgumentParser()
    ap.add_argument("--naive-subject", required=True)
    ap.add_argument("--listen", required=True, action="append")
    ap.add_argument("--pidfile", required=True)
    ap.add_argument("--drain-ms", type=int, default=2000)
    a = ap.parse_args(argv)
    mode = a.naive_subject
    # Handlers before the pidfile appears: the harness signals as soon as it sees the pidfile.
    hup = threading.Event()
    term = threading.Event()
    if mode == "deaf":
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
    else:
        signal.signal(signal.SIGHUP, lambda *_: hup.set())
    signal.signal(signal.SIGTERM, lambda *_: term.set())
    lss = []
    for spec in a.listen:
        host, port = spec.rsplit(":", 1)
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if mode == "reuseport":
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        for _ in range(200):
            try:
                ls.bind((host, int(port)))
                break
            except OSError:
                time.sleep(0.005)
        ls.listen(4096)
        ls.setblocking(False)
        lss.append(ls)
    tmp = f"{a.pidfile}.tmp{os.getpid()}"
    with open(tmp, "w") as f:
        f.write(f"{os.getpid()}\n")
    os.rename(tmp, a.pidfile)

    stop = threading.Event()
    workers = []

    def handle(c):
        try:
            c.settimeout(5)
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = c.recv(4096)
                if not d:
                    return
                buf += d
            body = f"ok {os.getpid()}\n".encode()
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body))
        except OSError:
            pass
        finally:
            c.close()

    def accept_loop():
        sel = selectors.DefaultSelector()
        for ls in lss:
            sel.register(ls, selectors.EVENT_READ)
        while not stop.is_set():
            for key, _ in sel.select(timeout=0.01):
                accept_ready(key.fileobj)
        sel.close()

    def accept_ready(ls):
        while True:
            try:
                c, _ = ls.accept()
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                break
            c.setblocking(True)
            t = threading.Thread(target=handle, args=(c,), daemon=True)
            t.start()
            workers.append(t)

    acc = threading.Thread(target=accept_loop, daemon=True)
    acc.start()
    while not (hup.is_set() or term.is_set()):
        time.sleep(0.01)

    def finish():
        end = time.monotonic() + a.drain_ms / 1000.0
        for t in workers:
            t.join(timeout=max(0.0, end - time.monotonic()))
        os._exit(0)

    me = os.getpid()
    child_cmd = [sys.executable, "-I", os.path.abspath(__file__)] + argv
    if term.is_set():
        stop.set()
        acc.join()
        for ls in lss:
            ls.close()
        finish()
    if mode == "reuseport":
        subprocess.Popen(child_cmd, stdin=subprocess.DEVNULL, close_fds=True)
        wait_until(lambda: read_pid(a.pidfile) not in (0, me), 10)  # new process is listening
        stop.set()
        acc.join()
        for ls in lss:
            ls.close()  # connections queued on this socket are reset here
        finish()
    if mode == "close-rebind":
        stop.set()
        acc.join()
        for ls in lss:
            ls.close()
        subprocess.Popen(child_cmd, stdin=subprocess.DEVNULL, close_fds=True)
        finish()
    finish()


# ----------------------------------------------------------------------------------------------- main

def main():
    if "--naive-subject" in sys.argv:
        naive_subject(sys.argv[1:])
        return 0
    ap = argparse.ArgumentParser(prog="oracles/upgrade-harness/run")
    ap.add_argument("--subject", help="path of the subject binary (CLI contract in README)")
    ap.add_argument("--reloads", type=int, default=100)
    ap.add_argument("--interval", type=float, default=0.2, help="seconds between reloads (default 0.2 = 5/s)")
    ap.add_argument("--rate", type=int, default=2000, help="new connections per second (default 2000)")
    ap.add_argument("--drain-ms", type=int, default=2000)
    ap.add_argument("--listeners", type=int, default=1, help="listeners per subject; load spread across all")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if not 1 <= a.listeners <= 64:
        print(f"{NAME}: FAIL (--listeners must be 1..64)")
        return 1
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 65536), hard))
    except (ValueError, OSError):
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    work = tempfile.mkdtemp(prefix="upgrade-harness-")
    logpath = os.path.join(here, ".work", "subject.log")
    os.makedirs(os.path.dirname(logpath), exist_ok=True)
    try:
        with open(logpath, "w") as log:
            return run_main(a, work, log, logpath)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run_main(a, work, log, logpath):
    if a.self_test:
        return self_test(a, work, log)
    if not a.subject:
        print(f"{NAME}: FAIL (--subject required)")
        return 1
    cmd = [os.path.abspath(a.subject)]
    print(f"[{NAME}] subject={a.subject} reloads={a.reloads} interval={a.interval}s rate={a.rate}/s "
          f"drain_ms={a.drain_ms} listeners={a.listeners}", flush=True)
    res, st = run_once(cmd, "subject", a.reloads, a.interval, a.rate, a.drain_ms, work, log, a.listeners)
    print(f"[{NAME}] {summarize(res, st)}", flush=True)
    if verdict(res, st):
        print(f"{NAME}: PASS dropped_before_D=0 refused=0 rst=0 (reloads={res['reloads_done']} "
              f"listeners={a.listeners} conns={st.opened} ok={st.ok} client_err=0 old_alive=0)")
        return 0
    print(f"{NAME}: FAIL (dropped_before_D={st.dropped} refused={st.refused} rst={st.rst} "
          f"reloads={res['reloads_done']}/{a.reloads} client_err={st.client_err} old_alive={res['old_alive']}"
          f" ok_per_listener={[st.ok_per_port.get(p, 0) for p in res['ports']]}"
          f"{' start_fail' if res['start_fail'] else ''}; log {logpath})")
    return 1


def self_test(a, work, log):
    naive = [sys.executable, "-I", os.path.abspath(__file__), "--naive-subject"]
    caught = []
    notes = []

    # 1. The REUSEPORT control, same run parameters as the real gate; escalate (documented) only if it stays green.
    plan = [(a.rate, a.reloads), (a.rate * 2, a.reloads * 2), (a.rate * 2, a.reloads * 4)]
    hit = False
    for rate, reloads in plan:
        res, st = run_once(naive + ["reuseport"], "naive-reuseport", reloads, a.interval, rate, a.drain_ms, work, log,
                           a.listeners)
        print(f"[{NAME} SELF-TEST] reuseport rate={rate}/s: {summarize(res, st)}", flush=True)
        if st.rst + st.dropped + st.refused > 0:
            hit = True
            if (rate, reloads) != plan[0]:
                notes.append(f"reuseport control needed rate={rate}/s reloads={reloads}")
            break
    caught.append(("reuseport", hit))

    # 2. close-then-rebind: refusals in the gap.
    res, st = run_once(naive + ["close-rebind"], "naive-close-rebind", 20, a.interval, a.rate, a.drain_ms, work, log,
                       a.listeners)
    print(f"[{NAME} SELF-TEST] close-rebind: {summarize(res, st)}", flush=True)
    caught.append(("close-rebind", not verdict(res, st)))

    # 3. deaf: ignores the reload signal; must FAIL on reload completion, not pass vacuously.
    res, st = run_once(naive + ["deaf"], "naive-deaf", 2, a.interval, 200, a.drain_ms, work, log)
    print(f"[{NAME} SELF-TEST] deaf: {summarize(res, st)}", flush=True)
    caught.append(("deaf", not verdict(res, st) and res["reloads_done"] < res["reloads_requested"]))

    detail = ", ".join(f"{k}={'caught' if v else 'MISSED'}" for k, v in caught)
    if notes:
        detail += "; " + "; ".join(notes)
    if all(v for _, v in caught):
        print(f"{NAME} SELF-TEST: PASS (naive REUSEPORT control shows drops; {detail})")
        return 0
    print(f"{NAME} SELF-TEST: FAIL ({detail})")
    return 1


if __name__ == "__main__":
    sys.exit(main())
