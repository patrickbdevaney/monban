"""SSRF-CORPUS oracle harness (stdlib only; run as python3 -I).

  run [--subject CMD]      judge CMD (default: the reference subject ref_subject.py) over the corpus
  run --self-test          the reference must PASS and every mutant subject must FAIL
  run --list               print the materialized corpus as JSON lines

PASS iff (1) no subject connect goes to an address the independent judge (netclass.py) forbids for that case,
(2) every connect goes to a derivable address: a first-query DNS answer of some case host or a strict literal in
the case's URLs (so a lenient literal parser or a re-resolving dialer is caught), (3) at most one DNS query per hop
(total queries <= connects, +1 when the fetch ended in a reject), (4) every "connect" case (positive control)
connects, to expect_addr when given, and every "reject" case does not, (5) live cases: the loopback server saw
exactly server_hits requests and the expected Host header.
"""
import ipaddress as ia
import json
import os
import re
import selectors
import shlex
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import corpus  # noqa: E402
import netclass  # noqa: E402

NAME = "SSRF-CORPUS"
MUTANTS = ["hostname", "no-mapped", "redirect-no-revet", "octal", "first-only", "no-embedded", "downgrade"]
MIN_CASES = 150
REPLY_TIMEOUT = 20.0


class Server:
    def __init__(self):
        self.hits = []
        self.lock = threading.Lock()
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *a):
                pass

            def do_GET(self):
                with outer.lock:
                    outer.hits.append((self.path, self.headers.get("Host")))
                port = outer.port
                routes = {
                    "/redir-ok": (302, {"Location": "/ok"}, b""),
                    "/redir-evil": (302, {"Location": "http://evil.test:%d/" % port}, b""),
                    "/redir-meta": (302, {"Location": "http://169.254.169.254:%d/" % port}, b""),
                    "/big": (200, {}, b"x" * 200000),
                }
                if self.path == "/slow":
                    time.sleep(2.0)
                status, hdrs, body = routes.get(self.path, (200, {}, b"ok"))
                try:
                    self.send_response(status)
                    for k, v in hdrs.items():
                        self.send_header(k, v)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except OSError:
                    pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def snapshot(self):
        with self.lock:
            return list(self.hits)

    def close(self):
        self.httpd.shutdown()


def materialize(port):
    raw = json.dumps(corpus.cases()).replace("{PORT}", str(port))
    cases = json.loads(raw)
    for c in cases:
        if "allow_ports" in c:
            c["allow_ports"] = [int(p) for p in c["allow_ports"]]
    return cases


DQ = re.compile(r"(?<![0-9a-zA-Z.])((?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})(?![0-9a-zA-Z.])")
BR = re.compile(r"\[([0-9a-fA-F:.]+)\]")


def strict_literals(s):
    out = set()
    auth = re.findall(r"//([^/?#]*)", s)
    for a in auth:
        for m in DQ.findall(a):
            out.add(ia.ip_address(m))
        for m in BR.findall(a):
            try:
                out.add(ia.ip_address(m))
            except ValueError:
                pass
    return out


def derivable(case, port):
    d = set()
    for host, sets in case.get("dns", {}).items():
        for a in (sets[0] if sets else []):
            d.add(ia.ip_address(a))
    texts = [case.get("url", "")] + [v[1] for v in case.get("redirects", {}).values()]
    if case.get("live"):
        texts += ["http://evil.test:%d/" % port, "http://169.254.169.254:%d/" % port]
    for t in texts:
        d |= strict_literals(t)
    return d


def split_sockaddr(s):
    if s.startswith("["):
        host, _, port = s[1:].partition("]:")
    else:
        host, _, port = s.rpartition(":")
    return ia.ip_address(host), int(port)


def judge(case, reply, hits, port):
    safety, expect = [], []
    if "error" in reply:
        expect.append("subject error: %s" % reply["error"])
    connects = list(reply.get("connects", []))
    decided = "decision" in reply and reply.get("decision") == "connect"
    if decided and reply.get("addr") and reply["addr"] not in connects:
        connects.append(reply["addr"])
    der = derivable(case, port)
    for c in connects:
        try:
            ip, _ = split_sockaddr(c)
        except ValueError:
            safety.append("unparsable connect %r" % c)
            continue
        if not netclass.allowed(ip, case.get("readmit", [])):
            safety.append("CONNECT TO FORBIDDEN %s (%s)" % (c, netclass.classify(ip)))
        if ip not in der:
            safety.append("connect to non-derivable %s (not a first DNS answer nor a strict literal)" % c)
    q = sum(reply.get("queries", {}).values())
    if q > len(connects) + (0 if decided else 1):
        safety.append("%d DNS queries for %d connects: resolved more than once per hop" % (q, len(connects)))
    if case["expect"] == "connect":
        if not decided:
            expect.append("positive control did not connect (reject=%s %s)" % (reply.get("reject"),
                                                                              reply.get("detail", "")))
        elif case.get("expect_addr") and split_sockaddr(reply["addr"])[0] != ia.ip_address(case["expect_addr"]):
            expect.append("connected to %s, expected %s" % (reply["addr"], case["expect_addr"]))
        elif case.get("live") and reply.get("status") != 200:
            expect.append("live status %s" % reply.get("status"))
    elif decided:
        expect.append("expected reject, subject connected to %s" % reply.get("addr"))
    if case.get("live"):
        if "server_hits" in case and len(hits) != case["server_hits"]:
            expect.append("loopback server saw %d requests, expected %d" % (len(hits), case["server_hits"]))
        if case.get("expect_host") and case["expect_host"] not in [h for _, h in hits]:
            expect.append("Host header %r not seen (saw %r)" % (case["expect_host"], [h for _, h in hits]))
    return safety, expect


class Subject:
    def __init__(self, cmd):
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  text=True, bufsize=1)
        self.sel = selectors.DefaultSelector()
        self.sel.register(self.p.stdout, selectors.EVENT_READ)

    def ask(self, case):
        self.p.stdin.write(json.dumps(case) + "\n")
        self.p.stdin.flush()
        if not self.sel.select(REPLY_TIMEOUT):
            raise RuntimeError("subject did not answer within %.0fs" % REPLY_TIMEOUT)
        line = self.p.stdout.readline()
        if not line:
            raise RuntimeError("subject exited")
        return json.loads(line)

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=5)
        except Exception:
            self.p.kill()


def run_corpus(cmd, verbose=True):
    srv = Server()
    cases = materialize(srv.port)
    subj = Subject(cmd)
    n_safety = n_expect = n_connects = pos = pos_ok = 0
    lines = []
    try:
        for c in cases:
            before = len(srv.snapshot())
            try:
                reply = subj.ask(c)
            except (RuntimeError, ValueError, BrokenPipeError) as e:
                return False, ["%s: subject failure: %s" % (c["id"], e)], "subject failure at %s" % c["id"]
            if c.get("live"):
                time.sleep(0.05)
            hits = srv.snapshot()[before:]
            safety, expect = judge(c, reply, hits, srv.port)
            n_connects += len(reply.get("connects", []))
            if c["expect"] == "connect":
                pos += 1
                pos_ok += not expect and not safety
            n_safety += len(safety)
            n_expect += len(expect)
            for m in safety + expect:
                lines.append("  %s: %s" % (c["id"], m))
    finally:
        subj.close()
        srv.close()
    ok = n_safety == 0 and n_expect == 0 and len(cases) >= MIN_CASES
    summary = "%d cases, %d connects, %d safety violations, %d expectation failures, %d/%d positive controls" % (
        len(cases), n_connects, n_safety, n_expect, pos_ok, pos)
    if len(cases) < MIN_CASES:
        summary += ", corpus below %d cases" % MIN_CASES
    return ok, lines, summary


def ref_cmd(mutant=None):
    cmd = [sys.executable, "-I", "-B", os.path.join(HERE, "ref_subject.py")]
    return cmd + (["--mutant", mutant] if mutant else [])


def main(argv):
    if argv[:1] == ["--list"]:
        for c in materialize(0):
            print(json.dumps(c))
        return 0
    if argv[:1] == ["--self-test"]:
        bad = []
        ok, lines, summary = run_corpus(ref_cmd())
        print("reference: %s (%s)" % ("PASS" if ok else "FAIL", summary))
        for l in lines[:20]:
            print(l)
        if not ok:
            bad.append("reference failed")
        for m in MUTANTS:
            ok, lines, summary = run_corpus(ref_cmd(m))
            print("mutant %-18s %s (%s)" % (m, "caught" if not ok else "NOT CAUGHT", summary))
            for l in lines[:3]:
                print("  " + l.strip())
            if ok:
                bad.append("mutant %s not caught" % m)
        if bad:
            print("%s SELF-TEST: FAIL (%s)" % (NAME, "; ".join(bad)))
            return 1
        print("%s SELF-TEST: PASS (reference passes; %d/%d mutants caught: %s)" % (
            NAME, len(MUTANTS), len(MUTANTS), ", ".join(MUTANTS)))
        return 0
    if argv[:1] == ["--subject"] and len(argv) == 2:
        cmd = shlex.split(argv[1])
        if not (os.path.exists(cmd[0]) or "/" not in cmd[0]):
            print("%s: FAIL (subject not found: %s)" % (NAME, cmd[0]))
            return 1
    elif not argv:
        cmd = ref_cmd()
    else:
        print("usage: run [--subject CMD] | --self-test | --list")
        return 2
    ok, lines, summary = run_corpus(cmd)
    for l in lines:
        print(l)
    print("%s: %s (%s)" % (NAME, "PASS" if ok else "FAIL", summary))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
