#!/usr/bin/env python3
"""Reference monban-otlp exporter (oracle-only, stdlib). It implements the CLI contract in README.md so that the
oracle can show it is satisfiable, and it carries the negative controls the self-test turns on through
AEGIS_OTLP_REF_MUTANT (that variable is not part of the contract; the real exporter ignores it).

  ref_exporter.py --scrape <http://host:port/path | unix:/path/to.sock> --endpoint <http(s)://host:port[/prefix]>
                  --service-name S [--interval-ms N] [--resource-attr k=v]... [--once] [--ca-file roots.pem]

P8-oracle-001 (R9): https through --ca-file only; 429/502/503/504 and transport errors retried with exponential
backoff (100, 200, 400, 800 ms: 5 attempts), then the request is dropped and its records counted in
monban_otlp_dropped_log_records / monban_otlp_dropped_metric_points. Logs and metrics are posted from separate threads
in interval mode, so a failing signal never stalls the other.
"""
import argparse
import base64
import calendar
import collections
import http.client
import json
import os
import re
import signal
import socket
import ssl
import sys
import threading
import time
import urllib.parse

MUTANT = os.environ.get("AEGIS_OTLP_REF_MUTANT", "")
START_NS = time.time_ns()
MAX_SCRAPE = 4 * 1024 * 1024
MAX_LINE = 65536
MAX_SERIES = 10000
QUEUE_CAP = 10000
SEV = {"TRACE": 1, "DEBUG": 5, "INFO": 9, "WARN": 13, "ERROR": 17, "FATAL": 21}
SEV_NAMES = {1: "SEVERITY_NUMBER_TRACE", 5: "SEVERITY_NUMBER_DEBUG", 9: "SEVERITY_NUMBER_INFO",
             13: "SEVERITY_NUMBER_WARN", 17: "SEVERITY_NUMBER_ERROR", 21: "SEVERITY_NUMBER_FATAL"}
RESERVED = ("ts", "level", "msg", "trace_id", "span_id")
TS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$")
INT_RE = re.compile(r"^-?[0-9]+$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


class ParseError(Exception):
    pass


# ---------------------------------------------------------------- OpenMetrics text (bounded)
def _unescape(s):
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            out.append({"n": "\n", "\\": "\\", '"': '"'}.get(n, "\\" + n))
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _labels(s, i):
    """Parses `{k="v",...}` starting at s[i] == '{'. Returns (pairs, index after '}')."""
    pairs, i = [], i + 1
    while True:
        if i >= len(s):
            raise ParseError("unterminated label set")
        if s[i] == "}":
            return pairs, i + 1
        j = s.find("=", i)
        if j < 0 or s[j + 1:j + 2] != '"':
            raise ParseError("bad label")
        key, k, val = s[i:j], j + 2, []
        while True:
            if k >= len(s):
                raise ParseError("unterminated label value")
            if s[k] == "\\":
                val.append(s[k:k + 2])
                k += 2
            elif s[k] == '"':
                break
            else:
                val.append(s[k])
                k += 1
        pairs.append((key, _unescape("".join(val))))
        i = k + 1
        if i < len(s) and s[i] == ",":
            i += 1


def parse_openmetrics(text):
    if len(text) > MAX_SCRAPE:
        raise ParseError("exposition too large")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if MUTANT != "accept-truncated" and (not lines or lines[-1] != "# EOF"):
        raise ParseError("no terminating # EOF")
    fams, order, nseries = {}, [], 0
    for line in lines:
        if len(line) > MAX_LINE:
            raise ParseError("line too long")
        if line == "# EOF":
            break
        if line.startswith("# "):
            parts = line.split(" ", 3)
            if len(parts) < 4 or parts[1] not in ("TYPE", "UNIT", "HELP"):
                continue
            f = fams.get(parts[2])
            if f is None:
                f = fams[parts[2]] = {"type": "unknown", "unit": "", "help": "", "samples": []}
                order.append(parts[2])
            if parts[1] == "TYPE":
                f["type"] = parts[3]
            elif parts[1] == "UNIT":
                f["unit"] = parts[3]
            else:
                f["help"] = _unescape(parts[3])
            continue
        if not line:
            raise ParseError("empty line")
        m = re.match(r"[a-zA-Z_:][a-zA-Z0-9_:]*", line)
        if not m:
            raise ParseError("bad sample name")
        sname, i = m.group(0), m.end()
        pairs = []
        if i < len(line) and line[i] == "{":
            pairs, i = _labels(line, i)
        rest = line[i:].split(" ")
        if len(rest) < 2 or rest[0] != "":
            raise ParseError("bad sample")
        value = rest[1]
        try:
            float(value)
        except ValueError:
            raise ParseError("bad value") from None
        fam = None
        for cand in (sname, re.sub(r"_(total|created|bucket|count|sum)$", "", sname)):
            if cand in fams:
                fam = cand
                break
        if fam is None:
            raise ParseError(f"sample {sname} outside a family")
        nseries += 1
        if nseries > MAX_SERIES:
            raise ParseError("too many series")
        fams[fam]["samples"].append((sname, pairs, value))
    return [(n, fams[n]) for n in order]


# ---------------------------------------------------------------- OTLP JSON building
def anyvalue(v):
    if isinstance(v, bool):
        return {"boolValue": v}
    if isinstance(v, int):
        return {"intValue": str(v)}
    if isinstance(v, float):
        return {"doubleValue": v}
    if isinstance(v, str):
        return {"stringValue": v}
    if isinstance(v, list):
        return {"arrayValue": {"values": [anyvalue(x) for x in v if x is not None]}}
    if isinstance(v, dict):
        return {"kvlistValue": {"values": [{"key": k, "value": anyvalue(x)} for k, x in v.items() if x is not None]}}
    return {"stringValue": json.dumps(v)}


def kv(k, v):
    return {"key": k, "value": {"stringValue": v}}


def number(token):
    if INT_RE.match(token) and -(2 ** 63) <= int(token) < 2 ** 63 and MUTANT != "int-as-double":
        return {"asInt": str(int(token))}
    f = float(token)
    if f != f:
        return {"asDouble": "NaN"}
    if f in (float("inf"), float("-inf")):
        return {"asDouble": "Infinity" if f > 0 else "-Infinity"}
    return {"asDouble": f}


def created_ns(token):
    whole, _, frac = token.partition(".")
    return int(whole) * 1_000_000_000 + int((frac + "000000000")[:9] or 0)


def attrs(pairs):
    return [] if MUTANT == "drop-attributes" else [kv(k, v) for k, v in pairs]


def temporality():
    if MUTANT == "enum-names":
        return "AGGREGATION_TEMPORALITY_CUMULATIVE"
    return 1 if MUTANT == "delta-temporality" else 2


def build_metrics(fams, now, extra):
    out = []
    for name, f in fams:
        typ, base = f["type"], {"name": name, "description": f["help"]}
        if f["unit"]:
            base["unit"] = f["unit"]
        if typ == "counter":
            created = {tuple(p): created_ns(v) for s, p, v in f["samples"] if s == name + "_created"}
            pts = []
            for s, p, v in f["samples"]:
                if s != name + "_total":
                    continue
                start = created.get(tuple(p), now if MUTANT == "start-time-moves" else START_NS)
                pts.append({"attributes": attrs(p), "startTimeUnixNano": str(start), "timeUnixNano": str(now),
                            **number(v)})
            if MUTANT == "keep-total-suffix":
                base["name"] = name + "_total"
            if MUTANT == "counter-as-gauge":
                base["gauge"] = {"dataPoints": pts}
            else:
                base["sum"] = {"dataPoints": pts, "aggregationTemporality": temporality(), "isMonotonic": True}
        elif typ in ("gauge", "unknown"):
            pts = [{"attributes": attrs(p), "timeUnixNano": str(now), **number(v)}
                   for s, p, v in f["samples"] if s == name]
            base["gauge"] = {"dataPoints": pts}
        elif typ == "histogram":
            series = collections.OrderedDict()
            for s, p, v in f["samples"]:
                key = tuple((k, x) for k, x in p if k != "le")
                d = series.setdefault(key, {"buckets": [], "count": "0", "sum": None, "created": None})
                if s == name + "_bucket":
                    le = dict(p).get("le", "+Inf")
                    d["buckets"].append((float(le), int(float(v))))
                elif s == name + "_count":
                    d["count"] = str(int(float(v)))
                elif s == name + "_sum":
                    d["sum"] = float(v)
                elif s == name + "_created":
                    d["created"] = created_ns(v)
            pts = []
            for key, d in series.items():
                b = sorted(d["buckets"])
                bounds = [le for le, _ in b if le != float("inf")]
                cum = [c for _, c in b]
                per = cum if MUTANT == "cumulative-buckets" else [c - (cum[i - 1] if i else 0) for i, c in enumerate(cum)]
                start = d["created"] if d["created"] is not None else (now if MUTANT == "start-time-moves" else START_NS)
                pt = {"attributes": attrs(key), "startTimeUnixNano": str(start), "timeUnixNano": str(now),
                      "count": d["count"], "bucketCounts": [str(c) for c in per], "explicitBounds": bounds}
                if d["sum"] is not None:
                    pt["sum"] = d["sum"]
                pts.append(pt)
            base["histogram"] = {"dataPoints": pts, "aggregationTemporality": temporality()}
        else:
            continue
        out.append(base)
    out.extend(extra)
    return out


def resource(args):
    a = [] if MUTANT == "drop-service-name" else [kv("service.name", args.service_name)]
    for item in args.resource_attr:
        k, _, v = item.partition("=")
        a.append(kv(k, v))
    return {"attributes": a}


SCOPE = {"name": "monban-otlp", "version": "0.0.0-reference"}


def parse_ts(s):
    m = TS_RE.match(s) if isinstance(s, str) else None
    if not m:
        return None
    y, mo, d, h, mi, se, frac, tz = m.groups()
    secs = calendar.timegm((int(y), int(mo), int(d), int(h), int(mi), int(se)))
    if tz != "Z":
        off = int(tz[1:3]) * 3600 + int(tz[4:6]) * 60
        secs -= off if tz[0] == "+" else -off
    return secs * 1_000_000_000 + int(((frac or "") + "000000000")[:9])


def log_record(raw, observed, truncated=False):
    rec = {"observedTimeUnixNano": str(observed)}
    text = raw.decode("utf-8", "ignore" if truncated else "replace")
    obj = None
    if not truncated:
        try:
            obj = json.loads(text)
        except ValueError:
            obj = None
    if not isinstance(obj, dict):
        rec["body"] = {"stringValue": text}
        return rec
    t = parse_ts(obj.get("ts"))
    if t is not None:
        rec["timeUnixNano"] = str(observed if MUTANT == "ignore-log-ts" else t)
    lvl = obj.get("level")
    if isinstance(lvl, str):
        n = SEV.get(lvl.upper(), 0)
        if MUTANT == "severity-wrong" and n:
            n += 1
        if n:
            rec["severityNumber"] = SEV_NAMES.get(n, n) if MUTANT == "enum-names" else n
        rec["severityText"] = lvl
    if obj.get("msg") is not None:
        rec["body"] = anyvalue(obj["msg"])
    for key, field, width in (("trace_id", "traceId", 32), ("span_id", "spanId", 16)):
        v = obj.get(key)
        if isinstance(v, str) and len(v) == width and HEX_RE.match(v):
            rec[field] = base64.b64encode(bytes.fromhex(v)).decode() if MUTANT == "base64-trace-id" else v.lower()
    a = [{"key": k, "value": anyvalue(v)} for k, v in obj.items() if k not in RESERVED and v is not None]
    if a:
        rec["attributes"] = a
    return rec


def snake(o):
    if isinstance(o, dict):
        return {re.sub(r"([A-Z])", lambda m: "_" + m.group(1).lower(), k): snake(v) for k, v in o.items()}
    if isinstance(o, list):
        return [snake(x) for x in o]
    return o


# ---------------------------------------------------------------- transport
def scrape(target):
    if target.startswith("unix:"):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(target[5:])
        path = "/metrics"
    else:
        u = urllib.parse.urlsplit(target)
        if u.scheme != "http":
            raise ParseError("scrape scheme must be http or unix")
        s = socket.create_connection((u.hostname, u.port or 80), timeout=10)
        path = u.path or "/metrics"
    with s:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
        buf = b""
        while len(buf) <= MAX_SCRAPE + 65536:
            c = s.recv(65536)
            if not c:
                break
            buf += c
    head, sep, body = buf.partition(b"\r\n\r\n")
    if not sep or not head.startswith(b"HTTP/1.1 200"):
        raise ParseError("scrape failed")
    return body.decode("utf-8")


RETRYABLE = (429, 502, 503, 504)
BACKOFF_S = (0.1, 0.2, 0.4, 0.8)   # waits before attempts 2..5


class Poster:
    def __init__(self, endpoint, ca_file=None):
        u = urllib.parse.urlsplit(endpoint)
        if u.scheme not in ("http", "https"):
            raise SystemExit("monban-otlp(ref): endpoint must be http:// or https://")
        self.https = u.scheme == "https"
        self.skip = self.https and MUTANT == "https-skipped"
        self.ctx = None
        if self.https and not self.skip:
            if not ca_file:
                raise SystemExit("monban-otlp(ref): https --endpoint needs --ca-file")
            self.ctx = ssl.create_default_context(cafile=ca_file)
            self.ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            if MUTANT == "https-no-verify":
                self.ctx.check_hostname = False
                self.ctx.verify_mode = ssl.CERT_NONE
        self.host, self.port = u.hostname, u.port or (443 if self.https else 80)
        self.prefix = u.path.rstrip("/")
        self.ok = True
        self.lock = threading.Lock()
        self.dropped = {"logs": 0, "metrics": 0}

    def _attempt(self, path, body, ct):
        try:
            if self.https:
                c = http.client.HTTPSConnection(self.host, self.port, timeout=10, context=self.ctx)
            else:
                c = http.client.HTTPConnection(self.host, self.port, timeout=10)
            c.request("POST", self.prefix + path, body=body, headers={"Content-Type": ct})
            r = c.getresponse()
            r.read()
            c.close()
            return r.status
        except (OSError, http.client.HTTPException):
            return None   # transport failure (refused, reset, TLS): retryable

    def post(self, signal_path, obj, records=0):
        if self.skip:
            return True   # mutant: an https endpoint silently skipped
        if MUTANT == "snake-case-keys":
            obj = snake(obj)
        body = json.dumps(obj, separators=(",", ":")).encode()
        ct = "application/x-protobuf" if MUTANT == "protobuf-content-type" else "application/json"
        waits = (() if MUTANT == "no-retry" else (0.0,) * 4 if MUTANT == "retry-no-backoff"
                 else (0.12,) * 19 if MUTANT == "retry-unbounded" else BACKOFF_S)
        status = self._attempt(signal_path, body, ct)
        for w in waits:
            if status is not None and 200 <= status < 300:
                break
            if status is not None and status not in RETRYABLE and MUTANT != "retry-on-400":
                break
            time.sleep(w)
            status = self._attempt(signal_path, body, ct)
        good = status is not None and 200 <= status < 300
        with self.lock:
            self.ok = self.ok and good
            if not good and MUTANT != "drop-uncounted":
                self.dropped["logs" if signal_path == "/v1/logs" else "metrics"] += records
        return good


# ---------------------------------------------------------------- main
def read_line(stream):
    """One stdin line, bounded: returns (bytes without newline, truncated) or None at EOF."""
    line = stream.readline(MAX_LINE + 1)
    if not line:
        return None
    if line.endswith(b"\n"):
        return line[:-1].rstrip(b"\r"), False
    if len(line) <= MAX_LINE:
        return line, False
    rest = line
    while rest and not rest.endswith(b"\n"):
        rest = stream.readline(MAX_LINE)
    return line[:MAX_LINE], True


def main():
    ap = argparse.ArgumentParser(prog="monban-otlp")
    ap.add_argument("--scrape", required=True)
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--service-name", required=True)
    ap.add_argument("--interval-ms", type=int, default=10000)
    ap.add_argument("--resource-attr", action="append", default=[])
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--ca-file")
    ap.add_argument("--tls-profile", default="P-PUBLIC-WEB")
    args = ap.parse_args()
    poster = Poster(args.endpoint, args.ca_file)
    dropped = [0]

    def counter(name, desc, v, now):
        return {"name": name, "description": desc,
                "sum": {"dataPoints": [{"startTimeUnixNano": str(START_NS), "timeUnixNano": str(now), "asInt": str(v)}],
                        "aggregationTemporality": temporality(), "isMonotonic": True}}

    def self_metrics(now):
        with poster.lock:
            dl, dm = poster.dropped["logs"], poster.dropped["metrics"]
        return [counter("monban_otlp_dropped_log_records", "Log records dropped (queue full or retries exhausted).",
                        dropped[0] + dl, now),
                counter("monban_otlp_dropped_metric_points", "Metric points dropped (retries exhausted).", dm, now)]

    def export_metrics():
        now = time.time_ns()
        try:
            fams = parse_openmetrics(scrape(args.scrape))
        except (OSError, ParseError, UnicodeDecodeError) as e:
            print(f"monban-otlp(ref): scrape: {e}", file=sys.stderr)
            return False
        ms = build_metrics(fams, now, self_metrics(now))
        npts = sum(len((m.get("sum") or m.get("gauge") or m.get("histogram") or {}).get("dataPoints", [])) for m in ms)
        return poster.post("/v1/metrics", {"resourceMetrics": [
            {"resource": resource(args), "scopeMetrics": [{"scope": SCOPE, "metrics": ms}]}]}, npts)

    def export_logs(recs):
        for i in range(0, len(recs), 512):
            poster.post("/v1/logs", {"resourceLogs": [
                {"resource": resource(args), "scopeLogs": [{"scope": SCOPE, "logRecords": recs[i:i + 512]}]}]},
                len(recs[i:i + 512]))

    stdin = sys.stdin.buffer
    if args.once:
        recs = []
        while (got := read_line(stdin)) is not None:
            raw, trunc = got
            if raw:
                recs.append(log_record(raw, time.time_ns(), trunc))
        ok = export_metrics()
        if recs:
            export_logs(recs)
        sys.exit(0 if ok and poster.ok else 1)

    queue, lock, stop, eof = collections.deque(), threading.Lock(), threading.Event(), threading.Event()

    def reader():
        while (got := read_line(stdin)) is not None:
            raw, trunc = got
            if raw:
                with lock:
                    if len(queue) >= QUEUE_CAP:
                        queue.popleft()
                        dropped[0] += 1
                    queue.append(log_record(raw, time.time_ns(), trunc))
        eof.set()

    threading.Thread(target=reader, daemon=True).start()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    interval = max(args.interval_ms, 50) / 1000.0
    log_every = min(interval, 1.0)

    def log_loop():
        last_l = 0.0
        while not stop.is_set():
            t = time.monotonic()
            hold = MUTANT == "logs-at-eof-only" and not eof.is_set()
            if t - last_l >= log_every and not hold:
                last_l = t
                with lock:
                    recs = list(queue)
                    queue.clear()
                if recs:
                    export_logs(recs)
            stop.wait(0.05)

    lt = threading.Thread(target=log_loop, daemon=True)
    lt.start()
    last_m = 0.0
    while not stop.is_set():
        t = time.monotonic()
        if t - last_m >= interval:
            last_m = t
            export_metrics()
        stop.wait(0.05)
    lt.join(2.0)
    with lock:
        recs = list(queue)
        queue.clear()
    if recs:
        export_logs(recs)
    sys.stderr.flush()
    # os._exit: the stdin reader thread is blocked in a buffered read, which makes interpreter shutdown abort.
    os._exit(0)


if __name__ == "__main__":
    main()
