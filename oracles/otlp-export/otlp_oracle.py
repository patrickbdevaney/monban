#!/usr/bin/env python3
"""AEGIS oracle otlp-export (unit P7-oracle-otlp-001, PREFLIGHT D-P7.6). Contract: oracles/README.md; exporter CLI
contract and mapping rules: README.md next to this file.

A loopback OTLP/HTTP collector validates every request against the opentelemetry-proto JSON mapping
(docs/specification.md "JSON Protobuf Encoding" + metrics/logs/common/resource .proto, excerpts in
proto-excerpts.txt), while a fake aegis admin listener (TCP and unix socket, same wire shape as
crates/aegis-bin/src/admin.rs) serves recorded aegis /metrics text and the exporter reads recorded aegis log lines
on stdin.

  run                          against the reference exporter (ref_exporter.py)
  run --exporter <path>        against a real exporter binary (gate: target/release/aegis-otlp)
  run --self-test              reference must PASS; every mutant, a stub and an absent binary must FAIL
"""
import argparse
import calendar
import gzip
import hashlib
import json
import math
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
NAME = "OTLP-EXPORT"
SERVICE = "aegis-oracle-svc"
MAX_LOG_LINE = 65536
MAX_BODY = 32 * 1024 * 1024
EXTRA_PREFIX = "aegis_otlp_"  # exporter self-metrics are the only metrics it may add
SEV = {"TRACE": 1, "DEBUG": 5, "INFO": 9, "WARN": 13, "ERROR": 17, "FATAL": 21}
RESERVED = ("ts", "level", "msg", "trace_id", "span_id")
TS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$")
INT_RE = re.compile(r"^-?[0-9]+$")
UINT_RE = re.compile(r"^[0-9]+$")
HEX_RE = re.compile(r"^[0-9a-fA-F]*$")
MUTANTS = [
    "counter-as-gauge", "drop-service-name", "protobuf-content-type", "severity-wrong",
    "delta-temporality", "cumulative-buckets", "enum-names", "snake-case-keys", "keep-total-suffix",
    "base64-trace-id", "start-time-moves", "accept-truncated", "logs-at-eof-only", "drop-attributes",
    "int-as-double", "ignore-log-ts",
    # P8-oracle-001 (PREFLIGHT R9): https endpoint, bounded retry with backoff, drop-and-count
    "https-skipped", "https-no-verify", "no-retry", "retry-no-backoff", "retry-unbounded", "retry-on-400",
    "drop-uncounted",
]
RETRYABLE = (429, 502, 503, 504)   # OTLP/HTTP specification "Failures": the retryable status codes
RETRY_MIN_ATTEMPTS = 2             # an exhausted request was tried at least twice (one retry)
RETRY_MAX_ATTEMPTS = 8             # ... and at most this often (bounded)
RETRY_MIN_GAP_S = 0.1              # every retry waits at least this long after the previous attempt
RETRY_GROWTH = 0.8                 # each gap >= 0.8 x the previous one (backoff never shrinks; 20 % jitter room)
RETRY_BUDGET_S = 30.0              # all attempts of one request within this
DROPPED_LOGS = "aegis_otlp_dropped_log_records"
DROPPED_POINTS = "aegis_otlp_dropped_metric_points"

# ---------------------------------------------------------------- opentelemetry-proto JSON schema (lowerCamelCase)
# Types: string bool uint32 fixed32 enum int64 fixed64 double bytes trace16 span8 ANY, a message name, or [type].
SCHEMA = {
    "MetricsReq": {"resourceMetrics": ["ResourceMetrics"]},
    "LogsReq": {"resourceLogs": ["ResourceLogs"]},
    "ResourceMetrics": {"resource": "Resource", "scopeMetrics": ["ScopeMetrics"], "schemaUrl": "string"},
    "ResourceLogs": {"resource": "Resource", "scopeLogs": ["ScopeLogs"], "schemaUrl": "string"},
    "Resource": {"attributes": ["KeyValue"], "droppedAttributesCount": "uint32", "entityRefs": ["ANY"]},
    "ScopeMetrics": {"scope": "Scope", "metrics": ["Metric"], "schemaUrl": "string"},
    "ScopeLogs": {"scope": "Scope", "logRecords": ["LogRecord"], "schemaUrl": "string"},
    "Scope": {"name": "string", "version": "string", "attributes": ["KeyValue"], "droppedAttributesCount": "uint32"},
    "Metric": {"name": "string", "description": "string", "unit": "string", "gauge": "Gauge", "sum": "Sum",
               "histogram": "Histogram", "exponentialHistogram": "ANY", "summary": "ANY", "metadata": ["KeyValue"]},
    "Gauge": {"dataPoints": ["NumberDataPoint"]},
    "Sum": {"dataPoints": ["NumberDataPoint"], "aggregationTemporality": "enum", "isMonotonic": "bool"},
    "Histogram": {"dataPoints": ["HistogramDataPoint"], "aggregationTemporality": "enum"},
    "NumberDataPoint": {"attributes": ["KeyValue"], "startTimeUnixNano": "fixed64", "timeUnixNano": "fixed64",
                        "asDouble": "double", "asInt": "int64", "exemplars": ["ANY"], "flags": "uint32"},
    "HistogramDataPoint": {"attributes": ["KeyValue"], "startTimeUnixNano": "fixed64", "timeUnixNano": "fixed64",
                           "count": "fixed64", "sum": "double", "bucketCounts": ["fixed64"],
                           "explicitBounds": ["double"], "exemplars": ["ANY"], "flags": "uint32", "min": "double",
                           "max": "double"},
    "KeyValue": {"key": "string", "value": "AnyValue"},
    "AnyValue": {"stringValue": "string", "boolValue": "bool", "intValue": "int64", "doubleValue": "double",
                 "arrayValue": "ArrayValue", "kvlistValue": "KeyValueList", "bytesValue": "bytes"},
    "ArrayValue": {"values": ["AnyValue"]},
    "KeyValueList": {"values": ["KeyValue"]},
    "LogRecord": {"timeUnixNano": "fixed64", "observedTimeUnixNano": "fixed64", "severityNumber": "enum",
                  "severityText": "string", "body": "AnyValue", "attributes": ["KeyValue"],
                  "droppedAttributesCount": "uint32", "flags": "fixed32", "traceId": "trace16", "spanId": "span8",
                  "eventName": "string"},
}
ONEOF = {"Metric": (("gauge", "sum", "histogram", "exponentialHistogram", "summary"), True),
         "NumberDataPoint": (("asDouble", "asInt"), True),
         "AnyValue": (tuple(SCHEMA["AnyValue"]), False)}


def camel(k):
    return re.sub(r"_([a-z0-9])", lambda m: m.group(1).upper(), k)


def check_scalar(t, v):
    """Returns an error string or None. proto3 JSON: 64-bit ints as decimal strings (numbers accepted on decode);
    OTLP deviation: enums only as integers; traceId/spanId as hex."""
    if t == "string":
        return None if isinstance(v, str) else "not a string"
    if t == "bool":
        return None if isinstance(v, bool) else "not a bool"
    if t in ("uint32", "fixed32", "enum"):
        if t == "enum" and isinstance(v, str):
            return f"enum given as string {v!r} (OTLP JSON allows integer enum values only)"
        if isinstance(v, bool) or not (isinstance(v, int) or (isinstance(v, str) and UINT_RE.match(v))):
            return "not an integer"
        return None if 0 <= int(v) < 2 ** 32 else "out of 32-bit range"
    if t in ("int64", "fixed64"):
        if isinstance(v, bool):
            return "bool where 64-bit integer expected"
        if isinstance(v, int) or (isinstance(v, str) and INT_RE.match(v)):
            n = int(v)
            lo, hi = (0, 2 ** 64) if t == "fixed64" else (-(2 ** 63), 2 ** 63)
            return None if lo <= n < hi else "out of 64-bit range"
        return "not a 64-bit integer (decimal string or number)"
    if t == "double":
        if isinstance(v, bool):
            return "bool where double expected"
        if isinstance(v, (int, float)) or v in ("NaN", "Infinity", "-Infinity"):
            return None
        if isinstance(v, str):
            try:
                float(v)
                return None
            except ValueError:
                pass
        return "not a double"
    if t == "bytes":
        return None if isinstance(v, str) and re.match(r"^[A-Za-z0-9+/_-]*=*$", v) else "not base64"
    if t in ("trace16", "span8"):
        width = 32 if t == "trace16" else 16
        if not isinstance(v, str) or not HEX_RE.match(v) or len(v) not in (0, width):
            return f"not a {width}-char hex string (OTLP JSON encodes trace/span ids as hex, not base64)"
        return None
    return None


def validate(obj, msg, path, errs):
    if not isinstance(obj, dict):
        errs.append(f"{path}: {msg} is not a JSON object")
        return
    fields = SCHEMA[msg]
    for k, v in obj.items():
        if k not in fields:
            if "_" in k and camel(k) in fields:
                errs.append(f"{path}.{k}: snake_case key (OTLP JSON keys are lowerCamelCase: {camel(k)})")
            continue  # unknown fields MUST be ignored by receivers
        if v is None:
            continue
        t, p = fields[k], f"{path}.{k}"
        if isinstance(t, list):
            if not isinstance(v, list):
                errs.append(f"{p}: repeated field is not an array")
                continue
            for i, x in enumerate(v):
                validate_one(t[0], x, f"{p}[{i}]", errs)
        else:
            validate_one(t, v, p, errs)
    if msg in ONEOF:
        names, required = ONEOF[msg]
        present = [n for n in names if obj.get(n) is not None]
        if len(present) > 1:
            errs.append(f"{path}: oneof has several members {present}")
        elif required and not present:
            errs.append(f"{path}: {msg} has none of {list(names)}")


def validate_one(t, v, p, errs):
    if t == "ANY":
        return
    if t in SCHEMA:
        validate(v, t, p, errs)
        return
    e = check_scalar(t, v)
    if e:
        errs.append(f"{p}: {e}: {json.dumps(v)[:80]}")


def dec_any(v):
    """AnyValue JSON -> typed python value (('s', str) / ('i', int) / ('d', float) / ('b', bool) / lists / dicts)."""
    if not isinstance(v, dict):
        return None
    if v.get("stringValue") is not None:
        return ("s", v["stringValue"])
    if v.get("boolValue") is not None:
        return ("b", v["boolValue"])
    if v.get("intValue") is not None:
        return ("i", int(v["intValue"]))
    if v.get("doubleValue") is not None:
        return ("d", to_float(v["doubleValue"]))
    if v.get("arrayValue") is not None:
        return ("a", tuple(dec_any(x) for x in (v["arrayValue"].get("values") or [])))
    if v.get("kvlistValue") is not None:
        return ("kv", tuple(sorted((x.get("key"), dec_any(x.get("value"))) for x in (v["kvlistValue"].get("values") or []))))
    if v.get("bytesValue") is not None:
        return ("y", v["bytesValue"])
    return None


def py_any(v):
    """Expected AnyValue for a JSON log field value (contract: README 'Log line mapping')."""
    if isinstance(v, bool):
        return ("b", v)
    if isinstance(v, int):
        return ("i", v)
    if isinstance(v, float):
        return ("d", v)
    if isinstance(v, str):
        return ("s", v)
    if isinstance(v, list):
        return ("a", tuple(py_any(x) for x in v if x is not None))
    if isinstance(v, dict):
        return ("kv", tuple(sorted((k, py_any(x)) for k, x in v.items() if x is not None)))
    return None


def to_float(v):
    if v in ("NaN", "Infinity", "-Infinity"):
        return float(v.replace("inity", ""))
    return float(v)


def dec_attrs(lst):
    out = {}
    for a in lst or []:
        out[a.get("key")] = dec_any(a.get("value"))
    return out


# ---------------------------------------------------------------- OpenMetrics (oracle's own parser, for expectations)
def om_unescape(s):
    return re.sub(r"\\(.)", lambda m: {"n": "\n"}.get(m.group(1), m.group(1)), s)


LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')
SAMPLE_RE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})? (\S+)$")


def expected_series(text):
    """Expected OTLP points from an exposition: list of dicts keyed (name, attrs)."""
    fams, order = {}, []
    for line in text.split("\n"):
        if line in ("", "# EOF"):
            continue
        if line.startswith("# "):
            kind, name, rest = line[2:].split(" ", 2)
            f = fams.setdefault(name, {"type": None, "unit": "", "help": "", "samples": []})
            if name not in order:
                order.append(name)
            f[{"TYPE": "type", "UNIT": "unit", "HELP": "help"}[kind]] = om_unescape(rest) if kind == "HELP" else rest
            continue
        m = SAMPLE_RE.match(line)
        sname, labels = m.group(1), tuple((k, om_unescape(v)) for k, v in LABEL_RE.findall(m.group(3) or ""))
        fam = sname if sname in fams else re.sub(r"_(total|created|bucket|count|sum)$", "", sname)
        fams[fam]["samples"].append((sname[len(fam):], labels, m.group(4)))
    out = []
    for name in order:
        f = fams[name]
        common = {"name": name, "desc": f["help"], "unit": f["unit"]}
        if f["type"] == "counter":
            created = {lab: v for suf, lab, v in f["samples"] if suf == "_created"}
            for suf, lab, v in f["samples"]:
                if suf == "_total":
                    out.append({**common, "kind": "sum", "attrs": lab, "value": v, "created": created.get(lab)})
        elif f["type"] == "gauge":
            for suf, lab, v in f["samples"]:
                out.append({**common, "kind": "gauge", "attrs": lab, "value": v, "created": None})
        elif f["type"] == "histogram":
            series = {}
            for suf, lab, v in f["samples"]:
                key = tuple(x for x in lab if x[0] != "le")
                d = series.setdefault(key, {"b": [], "count": None, "sum": None, "created": None})
                if suf == "_bucket":
                    d["b"].append((float(dict(lab)["le"]), int(v)))
                else:
                    d[suf[1:]] = v
            for key, d in series.items():
                b = sorted(d["b"])
                cum = [c for _, c in b]
                out.append({**common, "kind": "histogram", "attrs": key, "created": d["created"],
                            "bounds": [le for le, _ in b if le != math.inf],
                            "buckets": [c - (cum[i - 1] if i else 0) for i, c in enumerate(cum)],
                            "count": int(d["count"]), "sum": float(d["sum"])})
    return out


def created_ns(token):
    whole, _, frac = token.partition(".")
    return int(whole) * 1_000_000_000 + int((frac + "000000000")[:9])


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


def expected_logs(data):
    out = []
    for raw in data.split(b"\n"):
        raw = raw.rstrip(b"\r")
        if not raw:
            continue
        if len(raw) > MAX_LOG_LINE:
            out.append({"oversize": raw})
            continue
        text = raw.decode("utf-8", "replace")
        try:
            obj = json.loads(text)
        except ValueError:
            obj = None
        if not isinstance(obj, dict):
            out.append({"body": ("s", text), "sev": 0, "text": None, "time": None, "attrs": {}, "trace": None,
                        "span": None, "line": text})
            continue
        lvl = obj.get("level")
        ids = {}
        for key, width in (("trace_id", 32), ("span_id", 16)):
            v = obj.get(key)
            ids[key] = v.lower() if isinstance(v, str) and len(v) == width and HEX_RE.match(v) else None
        out.append({"body": py_any(obj["msg"]) if obj.get("msg") is not None else None,
                    "sev": SEV.get(lvl.upper(), 0) if isinstance(lvl, str) else 0,
                    "text": lvl if isinstance(lvl, str) else None, "time": parse_ts(obj.get("ts")),
                    "attrs": {k: py_any(v) for k, v in obj.items() if k not in RESERVED and v is not None},
                    "trace": ids["trace_id"], "span": ids["span_id"], "line": text})
    return out


# ---------------------------------------------------------------- loopback collector
class Collector:
    """plan(path, n) -> HTTP status for the n-th (0-based) POST on that path (default: always 200). tls: an
    ssl.SSLContext (server side) to serve https instead of http."""

    def __init__(self, prefix="", tls=None, plan=None):
        self.reqs, self.lock, self.prefix = [], threading.Lock(), prefix.rstrip("/")
        self.plan, self.per_path = plan, {}
        col = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _body(self):
                if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
                    out = b""
                    while True:
                        n = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                        if n == 0:
                            while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                                pass
                            return out
                        out += self.rfile.read(n)
                        self.rfile.readline()
                        if len(out) > MAX_BODY:
                            raise ValueError("body too large")
                n = int(self.headers.get("Content-Length") or 0)
                if n > MAX_BODY:
                    raise ValueError("body too large")
                return self.rfile.read(n)

            def _done(self, code, ct, body):
                self.send_response(code)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                try:
                    body = self._body()
                    if (self.headers.get("Content-Encoding") or "").lower() == "gzip":
                        body = gzip.decompress(body)
                except (ValueError, OSError) as e:
                    col.add("POST", self.path, self.headers, b"", f"unreadable body: {e}")
                    self._done(400, "text/plain", b"bad body\n")
                    self.close_connection = True
                    return
                status = col.status_for(self.path)
                col.add("POST", self.path, self.headers, body, None, status)
                if status != 200:
                    self._done(status, "application/json", b'{"code":14,"message":"oracle: failing on purpose"}')
                    return
                ct = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
                self._done(200, "application/json" if ct == "application/json" else ct or "text/plain",
                           b"{}" if ct == "application/json" else b"")

            def do_GET(self):
                col.add("GET", self.path, self.headers, b"", None)
                self._done(405, "text/plain", b"POST only\n")

            do_PUT = do_GET

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        self.handshake_errors = 0
        if tls is not None:
            raw_get = self.srv.get_request

            def get_request():
                c, a = raw_get()
                c.settimeout(10)
                try:
                    return tls.wrap_socket(c, server_side=True), a
                except (OSError, ssl.SSLError):
                    with self.lock:
                        self.handshake_errors += 1
                    c.close()
                    raise
            self.srv.get_request = get_request
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        scheme = "https" if tls is not None else "http"
        self.url = f"{scheme}://127.0.0.1:{self.srv.server_address[1]}{prefix}"

    def status_for(self, path):
        with self.lock:
            n = self.per_path.get(path, 0)
            self.per_path[path] = n + 1
        return self.plan(path, n) if self.plan else 200

    def add(self, method, path, headers, body, err, status=200):
        with self.lock:
            self.reqs.append({"method": method, "path": path, "ct": headers.get("Content-Type"), "body": body,
                              "err": err, "t": time.time_ns(), "status": status})

    def snapshot(self):
        with self.lock:
            return list(self.reqs)

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


# ---------------------------------------------------------------- fake aegis admin listener (admin.rs wire shape)
class Admin:
    CT = "application/openmetrics-text; version=1.0.0; charset=utf-8"

    def __init__(self, provider, unix_path=None):
        self.provider, self.paths, self.lock = provider, [], threading.Lock()
        if unix_path:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind(unix_path)
            self.target = f"unix:{unix_path}"
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind(("127.0.0.1", 0))
            self.target = f"http://127.0.0.1:{self.sock.getsockname()[1]}/metrics"
        self.sock.listen(16)
        self.alive = True
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while self.alive:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c):
        with c:
            c.settimeout(5)
            buf = b""
            try:
                while b"\r\n\r\n" not in buf and len(buf) <= 8192:
                    chunk = c.recv(2048)
                    if not chunk:
                        return
                    buf += chunk
            except OSError:
                return
            parts = buf.split(b"\r\n", 1)[0].split(b" ")
            method, path = (parts + [b"", b""])[:2]
            path = path.split(b"?")[0]
            with self.lock:
                self.paths.append((method.decode(errors="replace"), path.decode(errors="replace")))
            if method == b"GET" and path == b"/metrics":
                status, ct, body = "200 OK", self.CT, self.provider().encode()
            elif method == b"GET":
                status, ct, body = "404 Not Found", "text/plain", b"not found\n"
            else:
                status, ct, body = "405 Method Not Allowed", "text/plain", b"method not allowed\n"
            head = f"HTTP/1.1 {status}\r\ncontent-type: {ct}\r\ncontent-length: {len(body)}\r\nconnection: close\r\n\r\n"
            try:
                c.sendall(head.encode() + body)
            except OSError:
                pass

    def scrapes(self):
        with self.lock:
            return list(self.paths)

    def close(self):
        self.alive = False
        self.sock.close()


# ---------------------------------------------------------------- checking
class Run:
    def __init__(self, verbose, quiet=False):
        self.passed, self.failures, self.details, self.verbose, self.quiet = 0, [], [], verbose, quiet

    def check(self, name, ok, detail=""):
        if ok:
            self.passed += 1
            if self.verbose:
                print(f"  ok   {name}")
        else:
            self.failures.append(name)
            self.details.append(detail)
            if not self.quiet:
                print(f"  FAIL {name}: {detail}"[:600])
        return ok


def decode_requests(r, case, reqs, prefix):
    """Transport + schema checks on every request. Returns (metric entries, log entries) in arrival order."""
    metrics, logs, errs = [], [], []
    for i, q in enumerate(reqs):
        where = f"req#{i} {q['method']} {q['path']}"
        if q["err"]:
            errs.append(f"{where}: {q['err']}")
            continue
        if q["method"] != "POST" or q["path"] not in (prefix + "/v1/metrics", prefix + "/v1/logs"):
            errs.append(f"{where}: expected POST {prefix}/v1/metrics or {prefix}/v1/logs")
            continue
        ct = (q["ct"] or "").split(";")[0].strip().lower()
        if ct != "application/json":
            errs.append(f"{where}: Content-Type {q['ct']!r}, expected application/json (OTLP/HTTP JSON)")
            continue
        try:
            obj = json.loads(q["body"].decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as e:
            errs.append(f"{where}: body is not JSON: {e}")
            continue
        sig = "metrics" if q["path"].endswith("/v1/metrics") else "logs"
        verrs = []
        validate(obj, "MetricsReq" if sig == "metrics" else "LogsReq", sig, verrs)
        if verrs:
            errs.extend(f"{where}: {e}" for e in verrs[:5])
            continue
        for rk, sk, ik in ((("resourceMetrics", "scopeMetrics", "metrics"),) if sig == "metrics"
                           else (("resourceLogs", "scopeLogs", "logRecords"),)):
            for res in obj.get(rk) or []:
                rattrs = dec_attrs((res.get("resource") or {}).get("attributes"))
                for sc in res.get(sk) or []:
                    scope = sc.get("scope") or {}
                    for item in sc.get(ik) or []:
                        (metrics if sig == "metrics" else logs).append(
                            {"req": i, "t": q["t"], "res": rattrs, "scope": scope, "item": item})
    r.check(f"{case}.wire+schema", not errs, "; ".join(errs[:6]))
    return metrics, logs


def check_resources(r, case, entries):
    bad = [e["res"] for e in entries if e["res"].get("service.name") != ("s", SERVICE)]
    r.check(f"{case}.resource.service.name", not bad,
            f"{len(bad)} entries lack resource attribute service.name={SERVICE!r} (got {bad[:1]})")
    bad = [e["scope"] for e in entries if not isinstance(e["scope"].get("name"), str) or not e["scope"]["name"]]
    r.check(f"{case}.scope.name", not bad, f"{len(bad)} entries without an InstrumentationScope name")


def flatten_points(metrics):
    pts = []
    for e in metrics:
        m = e["item"]
        kind = next(k for k in ("gauge", "sum", "histogram", "exponentialHistogram", "summary") if m.get(k) is not None)
        body = m[kind]
        for p in body.get("dataPoints") or []:
            pts.append({"name": m.get("name", ""), "desc": m.get("description", "") or "", "unit": m.get("unit", "") or "",
                        "kind": kind, "temp": body.get("aggregationTemporality"), "mono": body.get("isMonotonic"),
                        "attrs": tuple(sorted(dec_attrs(p.get("attributes")).items())), "p": p, "req": e["req"],
                        "t": e["t"]})
    return pts


def series_key(name, attrs):
    return (name, tuple(sorted((k, ("s", v)) for k, v in attrs)))


def point_errors(exp, o, window, check_value=True):
    errs, p = [], o["p"]
    if o["kind"] != exp["kind"]:
        errs.append(f"type {o['kind']}, expected {exp['kind']} (OpenMetrics {'counter' if exp['kind'] == 'sum' else exp['kind']})")
        return errs
    if o["desc"] != exp["desc"]:
        errs.append(f"description {o['desc']!r} != HELP {exp['desc']!r}")
    if o["unit"] != exp["unit"]:
        errs.append(f"unit {o['unit']!r} != UNIT {exp['unit']!r}")
    if exp["kind"] in ("sum", "histogram") and o["temp"] != 2:
        errs.append(f"aggregationTemporality {o['temp']!r}, expected 2 (CUMULATIVE)")
    if exp["kind"] == "sum" and o["mono"] is not True:
        errs.append(f"isMonotonic {o['mono']!r}, expected true")
    t = int(p.get("timeUnixNano") or 0)
    if not window[0] <= t <= window[1]:
        errs.append(f"timeUnixNano {t} outside the run window {window}")
    if exp["kind"] in ("sum", "histogram"):
        s = int(p.get("startTimeUnixNano") or 0)
        if not 0 < s <= t:
            errs.append(f"startTimeUnixNano {s} not in (0, timeUnixNano={t}] (cumulative needs a start)")
        if exp["created"] is not None and abs(s - created_ns(exp["created"])) > 1000:
            errs.append(f"startTimeUnixNano {s} != _created {exp['created']}")
    if exp["kind"] == "histogram":
        if [to_float(x) for x in p.get("explicitBounds") or []] != exp["bounds"]:
            errs.append(f"explicitBounds {p.get('explicitBounds')} != {exp['bounds']}")
        if [int(x) for x in p.get("bucketCounts") or []] != exp["buckets"]:
            errs.append(f"bucketCounts {p.get('bucketCounts')} != per-bucket {exp['buckets']} (OpenMetrics le buckets are cumulative)")
        if int(p.get("count") or 0) != exp["count"]:
            errs.append(f"count {p.get('count')} != {exp['count']}")
        if p.get("sum") is None or to_float(p["sum"]) != exp["sum"]:
            errs.append(f"sum {p.get('sum')} != {exp['sum']}")
    elif check_value:
        v = exp["value"]
        if INT_RE.match(v) and -(2 ** 63) <= int(v) < 2 ** 63:
            if p.get("asInt") is None or int(p["asInt"]) != int(v):
                errs.append(f"asInt {p.get('asInt')!r} (asDouble {p.get('asDouble')!r}), expected asInt {v}")
        elif p.get("asDouble") is None or to_float(p["asDouble"]) != float(v):
            errs.append(f"asDouble {p.get('asDouble')!r}, expected {float(v)}")
    return errs


def check_metrics_once(r, case, pts, text, window, spots):
    exp = expected_series(text)
    by_key = {}
    for o in pts:
        by_key.setdefault((o["name"], o["attrs"]), []).append(o)
    missing, dup, errs = [], [], []
    for e in exp:
        k = series_key(e["name"], e["attrs"])
        got = by_key.get(k, [])
        if not got:
            missing.append(k)
            continue
        if len(got) > 1:
            dup.append(k)
        for msg in point_errors(e, got[0], window):
            errs.append(f"{e['name']}{dict(e['attrs'])}: {msg}")
    expected_keys = {series_key(e["name"], e["attrs"]) for e in exp}
    extra = sorted({k[0] for k in by_key if k not in expected_keys and not k[0].startswith(EXTRA_PREFIX)})
    r.check(f"{case}.metrics.all-series", not missing,
            f"{len(missing)}/{len(exp)} series missing, e.g. {missing[:3]}")
    r.check(f"{case}.metrics.no-invented", not extra, f"metrics not in the exposition: {extra[:5]}")
    r.check(f"{case}.metrics.one-scrape-one-point", not dup, f"series exported more than once: {dup[:3]}")
    r.check(f"{case}.metrics.mapping", not errs, "; ".join(errs[:4]))
    for label, name, attrs, pred in spots:
        got = by_key.get(series_key(name, attrs), [])
        r.check(f"{case}.spot.{label}", bool(got) and pred(got[0]), f"{name}{dict(attrs)} -> {got[0]['p'] if got else 'absent'}")


def log_view(e):
    it = e["item"]
    return {"body": dec_any(it.get("body")), "sev": int(it.get("severityNumber") or 0),
            "text": it.get("severityText") or None, "time": int(it.get("timeUnixNano") or 0) or None,
            "obs": int(it.get("observedTimeUnixNano") or 0), "attrs": dec_attrs(it.get("attributes")),
            "trace": (it.get("traceId") or "").lower() or None, "span": (it.get("spanId") or "").lower() or None}


def check_logs(r, case, logs, data, window):
    exp, obs = expected_logs(data), [log_view(e) for e in logs]
    errs, j = [], 0
    for n, e in enumerate(exp):
        if "oversize" in e:
            if j < len(obs) and isinstance(obs[j]["body"], tuple) and obs[j]["body"][0] == "s" \
                    and e["oversize"].decode("utf-8", "ignore").startswith(obs[j]["body"][1][:64]) and obs[j]["body"][1]:
                if len(obs[j]["body"][1].encode()) > MAX_LOG_LINE:
                    errs.append(f"line {n}: oversize line exported with {len(obs[j]['body'][1].encode())} bytes (> {MAX_LOG_LINE})")
                j += 1
            continue
        if j >= len(obs):
            errs.append(f"line {n}: missing record for {e['line'][:60]!r}")
            continue
        o, j = obs[j], j + 1
        why = []
        if o["body"] != e["body"]:
            why.append(f"body {o['body']!r:.80} != {e['body']!r:.80}")
        if o["sev"] != e["sev"]:
            why.append(f"severityNumber {o['sev']} != {e['sev']} (level {e['text']!r})")
        if o["text"] != e["text"]:
            why.append(f"severityText {o['text']!r} != {e['text']!r}")
        if o["time"] != e["time"]:
            why.append(f"timeUnixNano {o['time']} != {e['time']} (from ts)")
        if not window[0] <= o["obs"] <= window[1]:
            why.append(f"observedTimeUnixNano {o['obs']} outside the run window")
        if o["attrs"] != e["attrs"]:
            why.append(f"attributes {o['attrs']!r:.120} != {e['attrs']!r:.120}")
        if o["trace"] != e["trace"] or o["span"] != e["span"]:
            why.append(f"traceId/spanId {o['trace']}/{o['span']} != {e['trace']}/{e['span']} (hex)")
        if why:
            errs.append(f"line {n} {e['line'][:50]!r}: " + "; ".join(why))
    if j < len(obs):
        errs.append(f"{len(obs) - j} extra log records, first {obs[j]['body']!r:.80}")
    r.check(f"{case}.logs.mapping", not errs, " | ".join(errs[:4]))
    return obs


# ---------------------------------------------------------------- cases
def read_fixture(name, mode="r"):
    with open(os.path.join(FIX, name), mode) as f:
        return f.read()


def run_exporter(cmd, args, env, stdin_bytes, timeout=30):
    with tempfile.TemporaryFile() as out:
        try:
            p = subprocess.run(cmd + args, input=stdin_bytes, stdout=out, stderr=subprocess.STDOUT, env=env,
                               timeout=timeout)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            rc = "timeout"
        except OSError as e:
            return f"spawn failed: {e}", ""
        out.seek(0)
        return rc, out.read()[-1500:].decode(errors="replace")


def case_once(r, name, cmd, env, text, stdin_bytes, unix_dir, spots, expect_metrics=True):
    col = Collector()
    adm = Admin(lambda: text, os.path.join(unix_dir, f"{name}.sock") if unix_dir else None)
    t0 = time.time_ns() - 2_000_000_000
    try:
        rc, tail = run_exporter(cmd, ["--scrape", adm.target, "--endpoint", col.url, "--service-name", SERVICE,
                                      "--interval-ms", "1000", "--once"], env, stdin_bytes)
        time.sleep(0.1)
        window = (t0, time.time_ns() + 2_000_000_000)
        reqs, scrapes = col.snapshot(), adm.scrapes()
    finally:
        col.close()
        adm.close()
    if expect_metrics:
        r.check(f"{name}.exit-0", rc == 0, f"--once exited {rc}; output tail: {tail[-400:]!r}")
    else:
        r.check(f"{name}.exit-nonzero", rc not in (0, "timeout") and not str(rc).startswith("spawn"),
                f"--once on a truncated exposition exited {rc} (must be nonzero: no # EOF -> reject the scrape)")
    r.check(f"{name}.scraped-once", scrapes == [("GET", "/metrics")], f"admin saw {scrapes}")
    metrics, logs = decode_requests(r, name, reqs, "")
    check_resources(r, name, metrics + logs)
    pts = flatten_points(metrics)
    if expect_metrics:
        check_metrics_once(r, name, pts, text, window, spots)
    else:
        leaked = [o["name"] for o in pts if not o["name"].startswith(EXTRA_PREFIX)]
        r.check(f"{name}.metrics.truncated-rejected", not leaked,
                f"exported {len(leaked)} points from an exposition without # EOF: {leaked[:3]}")
    check_logs(r, name, logs, stdin_bytes, window)


def case_daemon(r, cmd, env, real_text):
    """Interval mode: cumulative semantics across exports, streaming logs, clean SIGTERM, endpoint path prefix."""
    name, served, lock = "daemon", [], threading.Lock()

    def provider():
        with lock:
            n = 100 + len(served)
            served.append(n)
        return real_text.replace("aegis_proxy_requests_total 4\n", f"aegis_proxy_requests_total {n}\n")

    col, adm = Collector("/collector/"), Admin(provider)
    t0 = time.time_ns() - 2_000_000_000
    l1 = b'{"ts":"2026-11-06T12:30:00.000000042Z","level":"ERROR","msg":"streamed while running","n":1}\n'
    l2 = b"aegis[4242]: plain stderr line streamed while running\n"
    try:
        p = subprocess.Popen(cmd + ["--scrape", adm.target, "--endpoint", col.url, "--service-name", SERVICE,
                                    "--interval-ms", "250"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, env=env)
    except OSError as e:
        r.check(f"{name}.spawn", False, str(e))
        col.close()
        adm.close()
        return
    lat = {}
    try:
        def logs_seen():
            _, lg = decode_requests(Run(False, quiet=True), name, col.snapshot(), "/collector")
            return [log_view(e)["body"] for e in lg]

        def wait(pred, secs):
            until = time.time() + secs
            while time.time() < until:
                if pred():
                    return True
                if p.poll() is not None:
                    return pred()
                time.sleep(0.05)
            return False

        time.sleep(0.6)
        for key, line, body in (("l1", l1, ("s", "streamed while running")), ("l2", l2, ("s", l2.decode().rstrip("\n")))):
            ts = time.time()
            try:
                p.stdin.write(line)
                p.stdin.flush()
            except OSError:
                pass
            ok = wait(lambda: body in logs_seen(), 3.0)
            lat[key] = round(time.time() - ts, 2) if ok else None
        wait(lambda: len([q for q in col.snapshot() if q["path"].endswith("/v1/metrics")]) >= 3, 4.0)
        alive = p.poll() is None
        p.send_signal(15)
        try:
            rc = p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            rc = "no exit within 5 s of SIGTERM"
        time.sleep(0.1)
        window = (t0, time.time_ns() + 2_000_000_000)
        reqs = col.snapshot()
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
        col.close()
        adm.close()
    r.check(f"{name}.stays-running", alive, "exporter exited before SIGTERM in interval mode")
    r.check(f"{name}.logs-streamed", lat.get("l1") is not None and lat.get("l2") is not None,
            f"stdin lines must be exported while running (<= 3 s at --interval-ms 250, stdin still open); latency {lat}")
    r.check(f"{name}.sigterm-exit-0", rc == 0, f"exit {rc}")
    metrics, logs = decode_requests(r, name, reqs, "/collector")
    check_resources(r, name, metrics + logs)
    pts = flatten_points(metrics)
    exp = {series_key(e["name"], e["attrs"]): e for e in expected_series(real_text)}
    errs, req_pts = [], []
    for o in pts:
        e = exp.get((o["name"], o["attrs"]))
        if e is None:
            if not o["name"].startswith(EXTRA_PREFIX):
                errs.append(f"invented metric {o['name']}")
            continue
        dyn = o["name"] == "aegis_proxy_requests"
        errs.extend(f"{o['name']}: {m}" for m in point_errors(e, o, window, check_value=not dyn))
        if dyn:
            req_pts.append(o)
    r.check(f"{name}.metrics.mapping", not errs, "; ".join(errs[:4]))
    vals = [int(o["p"].get("asInt") or -1) for o in req_pts]
    times = [int(o["p"].get("timeUnixNano") or 0) for o in req_pts]
    starts = {o["p"].get("startTimeUnixNano") for o in req_pts}
    with lock:
        served_set = set(served)
    r.check(f"{name}.interval-exports", len(req_pts) >= 3, f"{len(req_pts)} exports of aegis_proxy_requests in ~5 s at 250 ms")
    r.check(f"{name}.values-scraped", bool(vals) and all(v in served_set for v in vals) and vals == sorted(vals),
            f"exported {vals}, served {sorted(served_set)[:12]}")
    r.check(f"{name}.time-advances", all(b > a for a, b in zip(times, times[1:])), f"timeUnixNano {times}")
    r.check(f"{name}.cumulative-start-fixed", len(starts) == 1,
            f"startTimeUnixNano must stay fixed across exports of a cumulative series; got {sorted(starts)[:4]}")
    obs = [log_view(e) for e in logs]
    want = [x for x in expected_logs(l1 + l2)]
    got = [(o["body"], o["sev"], o["time"], o["attrs"]) for o in obs]
    exp_l = [(w["body"], w["sev"], w["time"], w["attrs"]) for w in want]
    r.check(f"{name}.logs.mapping", got == exp_l, f"got {got!r:.300} expected {exp_l!r:.300}")


# ---------------------------------------------------------------- P8-oracle-001: https, retry, drop-and-count (R9)
def tls_material(d):
    """A throwaway CA and a P-256 leaf for 127.0.0.1 (the aegis-tls P-PUBLIC-WEB client verifies
    ecdsa_secp256r1_sha256 only, and webpki refuses a CA certificate used as the end entity), plus an unrelated CA.
    Returns (server ssl.SSLContext, ca.pem, other-ca.pem)."""
    if not shutil.which("openssl"):
        raise RuntimeError("openssl CLI not found (needed for the https collector)")

    def ossl(*a):
        subprocess.run(["openssl", *a], check=True, capture_output=True, timeout=60)
    ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]
    j = lambda n: os.path.join(d, n)  # noqa: E731
    for ca in ("ca", "other-ca"):
        ossl("req", "-x509", *ec, "-keyout", j(f"{ca}.key"), "-out", j(f"{ca}.pem"), "-days", "2",
             "-subj", f"/CN=aegis oracle {ca}", "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign")
    ossl("req", "-new", *ec, "-keyout", j("leaf.key"), "-out", j("leaf.csr"), "-subj", "/CN=127.0.0.1")
    with open(j("leaf.ext"), "w") as f:
        f.write("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                "extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n")
    ossl("x509", "-req", "-in", j("leaf.csr"), "-CA", j("ca.pem"), "-CAkey", j("ca.key"), "-CAcreateserial",
         "-out", j("leaf.pem"), "-days", "2", "-extfile", j("leaf.ext"))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(j("leaf.pem"), j("leaf.key"))
    return ctx, j("ca.pem"), j("other-ca.pem")


def attempts_by_path(reqs):
    out = {}
    for q in reqs:
        if q["method"] == "POST":
            out.setdefault(q["path"], []).append(q)
    return out


def gap_errors(attempts):
    """Backoff rule on one request's attempts (arrival times at the collector)."""
    ts = [q["t"] / 1e9 for q in attempts]
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    errs = []
    for i, g in enumerate(gaps):
        if g < RETRY_MIN_GAP_S:
            errs.append(f"retry {i + 1} came {g * 1000:.0f} ms after the previous attempt (< {RETRY_MIN_GAP_S * 1000:.0f} ms)")
        if i and g < RETRY_GROWTH * gaps[i - 1]:
            errs.append(f"gap {i + 1} {g:.3f} s shrank below {RETRY_GROWTH} x gap {i} {gaps[i - 1]:.3f} s")
    if ts and ts[-1] - ts[0] > RETRY_BUDGET_S:
        errs.append(f"attempts span {ts[-1] - ts[0]:.1f} s > {RETRY_BUDGET_S} s")
    return errs


def accepted(reqs):
    return [q for q in reqs if q.get("status", 200) == 200]


def once_args(adm, col, extra=()):
    return ["--scrape", adm.target, "--endpoint", col.url, "--service-name", SERVICE, "--interval-ms", "1000",
            "--once", *extra]


def case_https(r, cmd, env, real, logs, d):
    """https endpoint through --ca-file: delivered and mapped; an untrusted chain gets nothing."""
    ctx, ca, other = tls_material(d)
    for name, cafile in (("https-once", ca), ("https-untrusted", other)):
        col, adm = Collector(tls=ctx), Admin(lambda: real)
        t0 = time.time_ns() - 2_000_000_000
        try:
            rc, tail = run_exporter(cmd, once_args(adm, col, ["--ca-file", cafile]), env, logs, timeout=60)
            time.sleep(0.1)
            window = (t0, time.time_ns() + 2_000_000_000)
            reqs, hs_err = col.snapshot(), col.handshake_errors
        finally:
            col.close()
            adm.close()
        if name == "https-once":
            r.check(f"{name}.exit-0", rc == 0, f"--once to an https collector exited {rc}; tail {tail[-300:]!r}")
            r.check(f"{name}.delivered-over-tls", any(q["path"] == "/v1/metrics" for q in reqs),
                    f"no POST /v1/metrics reached the TLS collector ({hs_err} failed handshakes)")
            metrics, lg = decode_requests(r, name, reqs, "")
            check_resources(r, name, metrics + lg)
            check_metrics_once(r, name, flatten_points(metrics), real, window, spots_real()[:2])
            check_logs(r, name, lg, logs, window)
        else:
            r.check(f"{name}.exit-nonzero", rc not in (0, "timeout") and not str(rc).startswith("spawn"),
                    f"--once against a collector whose chain is not in --ca-file exited {rc}")
            r.check(f"{name}.nothing-delivered", not reqs,
                    f"{len(reqs)} requests reached a collector the exporter must not trust")


def case_retry_recover(r, cmd, env, real, logs):
    """503 twice per path, then 200: retried with backoff, delivered exactly once, exit 0."""
    name = "retry-recover"
    col = Collector(plan=lambda path, n: 503 if n < 2 else 200)
    adm = Admin(lambda: real)
    t0 = time.time_ns() - 2_000_000_000
    try:
        rc, tail = run_exporter(cmd, once_args(adm, col), env, logs, timeout=60)
        time.sleep(0.1)
        window = (t0, time.time_ns() + 2_000_000_000)
        reqs, scrapes = col.snapshot(), adm.scrapes()
    finally:
        col.close()
        adm.close()
    r.check(f"{name}.exit-0", rc == 0, f"--once with a collector that recovers after two 503s exited {rc}; "
            f"tail {tail[-300:]!r}")
    r.check(f"{name}.scraped-once", scrapes == [("GET", "/metrics")], f"a retry must resend, not re-scrape: {scrapes}")
    by = attempts_by_path(reqs)
    for path in ("/v1/metrics", "/v1/logs"):
        att = by.get(path, [])
        r.check(f"{name}.{path[4:]}.retried-until-accepted", [q["status"] for q in att] == [503, 503, 200],
                f"statuses seen on {path}: {[q['status'] for q in att]} (want 503, 503, 200: retried, then nothing "
                f"after the accepted attempt)")
        r.check(f"{name}.{path[4:]}.backoff", not gap_errors(att), "; ".join(gap_errors(att)[:3]))
    metrics, lg = decode_requests(r, name, accepted(reqs), "")
    check_metrics_once(r, name, flatten_points(metrics), real, window, spots_real()[:1])
    check_logs(r, name, lg, logs, window)


def case_retry_exhaust(r, cmd, env, real, logs):
    """Always 503: bounded attempts with backoff, then give up (exit nonzero)."""
    name = "retry-exhaust"
    col, adm = Collector(plan=lambda path, n: 503), Admin(lambda: real)
    t = time.monotonic()
    try:
        rc, tail = run_exporter(cmd, once_args(adm, col), env, logs, timeout=2 * RETRY_BUDGET_S + 10)
        secs = time.monotonic() - t
        reqs = col.snapshot()
    finally:
        col.close()
        adm.close()
    r.check(f"{name}.exit-nonzero", rc not in (0, "timeout") and not str(rc).startswith("spawn"),
            f"--once whose every POST got 503 exited {rc} after {secs:.1f} s (must give up and exit nonzero)")
    by = attempts_by_path(reqs)
    for path in ("/v1/metrics", "/v1/logs"):
        att = by.get(path, [])
        r.check(f"{name}.{path[4:]}.bounded", RETRY_MIN_ATTEMPTS <= len(att) <= RETRY_MAX_ATTEMPTS,
                f"{len(att)} attempts on {path} (want {RETRY_MIN_ATTEMPTS}..{RETRY_MAX_ATTEMPTS})")
        r.check(f"{name}.{path[4:]}.backoff", not gap_errors(att), "; ".join(gap_errors(att)[:3]))
        bodies = {hashlib.sha256(q["body"]).hexdigest() for q in att}
        r.check(f"{name}.{path[4:]}.same-payload", len(bodies) <= 1, f"{len(bodies)} different bodies retried")


def case_no_retry_400(r, cmd, env, real, logs):
    """400 is not retryable: exactly one attempt per request."""
    name = "no-retry-400"
    col, adm = Collector(plan=lambda path, n: 400), Admin(lambda: real)
    try:
        rc, _ = run_exporter(cmd, once_args(adm, col), env, logs, timeout=60)
        reqs = col.snapshot()
    finally:
        col.close()
        adm.close()
    r.check(f"{name}.exit-nonzero", rc not in (0, "timeout"), f"--once whose POSTs got 400 exited {rc}")
    by = attempts_by_path(reqs)
    for path in ("/v1/metrics", "/v1/logs"):
        att = by.get(path, [])
        r.check(f"{name}.{path[4:]}.one-attempt", len(att) == 1, f"{len(att)} attempts on {path} (400 is final)")


def case_daemon_drop(r, cmd, env, real):
    """Interval mode with /v1/logs always 503: metrics keep flowing, the log records are dropped after the retries
    and counted in aegis_otlp_dropped_log_records, SIGTERM still exits 0 within 5 s."""
    name = "daemon-drop"
    col = Collector(plan=lambda path, n: 503 if path.endswith("/v1/logs") else 200)
    adm = Admin(lambda: real)
    lines = b"".join(b'{"level":"WARN","msg":"dropped while the collector fails %d"}\n' % i for i in range(3))
    try:
        p = subprocess.Popen(cmd + ["--scrape", adm.target, "--endpoint", col.url, "--service-name", SERVICE,
                                    "--interval-ms", "250"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, env=env)
    except OSError as e:
        r.check(f"{name}.spawn", False, str(e))
        col.close()
        adm.close()
        return
    seen_drop, t_write = None, None
    try:
        time.sleep(0.5)
        t_write = time.time_ns()
        try:
            p.stdin.write(lines)
            p.stdin.flush()
        except OSError:
            pass
        time.sleep(5.0)
        early = [q for q in accepted(col.snapshot()) if q["path"].endswith("/v1/metrics") and q["t"] > t_write]
        until = time.time() + RETRY_BUDGET_S + 15
        while time.time() < until and p.poll() is None:
            ms, _ = decode_requests(Run(False, quiet=True), name, accepted(col.snapshot()), "")
            vals = [int(o["p"].get("asInt") or 0) for o in flatten_points(ms) if o["name"] == DROPPED_LOGS]
            if vals and max(vals) >= 3:
                seen_drop = max(vals)
                break
            time.sleep(0.25)
        alive = p.poll() is None
        p.send_signal(15)
        try:
            rc = p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            rc = "no exit within 5 s of SIGTERM"
        reqs = col.snapshot()
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()
        col.close()
        adm.close()
    r.check(f"{name}.stays-running", alive, "the exporter exited while a collector path kept failing")
    r.check(f"{name}.metrics-flow-during-log-outage", len(early) >= 3,
            f"{len(early)} metrics exports accepted in the 5 s after the logs started failing (want >= 3: a failing "
            f"signal must not stall the other)")
    logs_att = attempts_by_path(reqs).get("/v1/logs", [])
    r.check(f"{name}.logs-retried", len(logs_att) >= RETRY_MIN_ATTEMPTS, f"{len(logs_att)} attempts on /v1/logs")
    r.check(f"{name}.drop-counted", seen_drop is not None,
            f"no accepted metrics export showed {DROPPED_LOGS} >= 3 within {RETRY_BUDGET_S + 15:.0f} s "
            f"(3 log records were dropped after their retries)")
    r.check(f"{name}.sigterm-exit-0", rc == 0, f"exit {rc}")


def spots_real():
    def asint(v):
        return lambda o: o["kind"] in ("sum", "gauge") and o["p"].get("asInt") is not None and int(o["p"]["asInt"]) == v
    return [
        ("budget-ip-sum-4", "aegis_budget_debits", (("scope", "ip"),), lambda o: o["kind"] == "sum" and asint(4)(o)),
        ("cert-serving-gauge", "aegis_cert_seconds_to_expiry", (("slot", "serving"),),
         lambda o: o["kind"] == "gauge" and asint(2592000)(o)),
        ("config-hash-exact", "aegis_config_generation_hash", (), asint(14283538101851)),
        ("proxy-requests-sum-4", "aegis_proxy_requests", (), lambda o: o["kind"] == "sum" and o["mono"] is True and asint(4)(o)),
        ("upstream-errors-2", "aegis_proxy_upstream_errors", (), asint(2)),
    ]


def spots_synth():
    h = ("aegis_synth_request_duration_seconds", (("route", "api"),))
    return [
        ("hist-buckets", *h, lambda o: o["kind"] == "histogram" and [int(x) for x in o["p"].get("bucketCounts", [])] == [2, 3, 4, 1]),
        ("hist-bounds", *h, lambda o: [float(x) for x in o["p"].get("explicitBounds", [])] == [0.005, 0.05, 0.5]),
        ("hist-count-sum", *h, lambda o: int(o["p"].get("count", 0)) == 10 and float(o["p"].get("sum", 0)) == 1.875),
        ("hist-created", *h, lambda o: abs(int(o["p"].get("startTimeUnixNano", 0)) - 1793900000500000000) <= 1000),
        ("hist-unit", *h, lambda o: o["unit"] == "seconds"),
        ("counter-2^53+1-exact", "aegis_synth_events", (("kind", 'a"b'), ("path", "c\\d\ne")),
         lambda o: o["p"].get("asInt") is not None and int(o["p"]["asInt"]) == 9007199254740993),
        ("counter-help-unescaped", "aegis_synth_events", (("kind", "plain"), ("path", "/")),
         lambda o: o["desc"] == 'Synthetic counter with "escapes", a back\\slash\nand a second line.'),
        ("gauge-float", "aegis_synth_ratio", (("shard", "1"),),
         lambda o: o["kind"] == "gauge" and o["p"].get("asDouble") is not None and to_float(o["p"]["asDouble"]) == -1500.0),
        ("gauge-negative-int", "aegis_synth_ratio", (("shard", "2"),), lambda o: str(o["p"].get("asInt")) == "-42"),
    ]


def run_all(cmd, env, verbose, stop_early=False):
    r = Run(verbose, quiet=stop_early)
    real = read_fixture("aegis-metrics.txt")
    synth = read_fixture("synthetic-metrics.txt")
    logs_a = read_fixture("aegis-stderr.log", "rb") + read_fixture("json-logs.jsonl", "rb")
    logs_b = b"x" * (100 * 1024) + b"\n" + b'{"ts":"2026-11-06T12:00:09Z","level":"INFO","msg":"after an oversize line"}\n'
    trunc = real[: real.rindex("# EOF")]
    logs_r9 = b'{"ts":"2026-11-06T12:00:00Z","level":"INFO","msg":"r9 line","n":1}\naegis: plain r9 line\n'
    with tempfile.TemporaryDirectory(prefix="otlp-oracle-") as d:
        steps = [
            lambda: case_once(r, "once-tcp-real", cmd, env, real, logs_a, None, spots_real()),
            lambda: case_once(r, "once-unix-synthetic", cmd, env, synth, logs_b, d, spots_synth()),
            lambda: case_once(r, "once-truncated", cmd, env, trunc,
                              b'{"level":"INFO","msg":"logs still flow when the scrape is rejected"}\n', None, [],
                              expect_metrics=False),
            lambda: case_daemon(r, cmd, env, real),
            # P8-oracle-001 (R9)
            lambda: case_https(r, cmd, env, real, logs_r9, d),
            lambda: case_retry_recover(r, cmd, env, real, logs_r9),
            lambda: case_retry_exhaust(r, cmd, env, real, logs_r9),
            lambda: case_no_retry_400(r, cmd, env, real, logs_r9),
            lambda: case_daemon_drop(r, cmd, env, real),
        ]
        for s in steps:
            s()
            if stop_early and r.failures:
                break
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exporter", "--subject", dest="exporter", help="exporter binary (default: reference)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    ref = [sys.executable, "-I", os.path.join(HERE, "ref_exporter.py")]
    env = {k: v for k, v in os.environ.items() if k != "AEGIS_OTLP_REF_MUTANT"}
    if not a.self_test:
        if a.exporter:
            path = os.path.abspath(a.exporter)
            if not (os.path.isfile(path) and os.access(path, os.X_OK)):
                print(f"{NAME}: FAIL (exporter {a.exporter} is absent or not executable)")
                return 1
            cmd, label = [path], a.exporter
        else:
            cmd, label = ref, "reference ref_exporter.py"
        print(f"otlp-export: subject {label}")
        r = run_all(cmd, env, a.verbose)
        if r.failures:
            print(f"{NAME}: FAIL ({len(r.failures)} failed, {r.passed} passed: {', '.join(r.failures[:8])})")
            return 1
        print(f"{NAME}: PASS ({r.passed} checks, subject {label})")
        return 0

    print("otlp-export self-test: reference exporter must PASS")
    r = run_all(ref, env, a.verbose)
    if r.failures:
        print(f"{NAME} SELF-TEST: FAIL (reference exporter fails: {', '.join(r.failures[:6])})")
        return 1
    print(f"  reference: PASS ({r.passed} checks)")
    survived = []
    for m in MUTANTS:
        r = run_all(ref, {**env, "AEGIS_OTLP_REF_MUTANT": m}, False, stop_early=True)
        caught = f"RED by {r.failures[0]}: {r.details[0]}"[:200] if r.failures else "GREEN (survived)"
        print(f"  mutant {m}: {caught}")
        if not r.failures:
            survived.append(m)
    with tempfile.TemporaryDirectory(prefix="otlp-stub-") as d:
        stub = os.path.join(d, "aegis-otlp")
        with open(stub, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(stub, 0o755)
        r = run_all([stub], env, False, stop_early=True)
        print(f"  stub (exit 0, sends nothing): {'RED by ' + r.failures[0] if r.failures else 'GREEN (survived)'}")
        if not r.failures:
            survived.append("stub")
        rc = subprocess.run([sys.executable, "-I", os.path.abspath(__file__), "--exporter", os.path.join(d, "absent")],
                            capture_output=True, text=True).returncode
        print(f"  absent binary: {'RED' if rc != 0 else 'GREEN (survived)'}")
        if rc == 0:
            survived.append("absent")
    if survived:
        print(f"{NAME} SELF-TEST: FAIL (survived: {', '.join(survived)})")
        return 1
    print(f"{NAME} SELF-TEST: PASS (reference green; {len(MUTANTS)}/{len(MUTANTS)} mutants red; stub and absent binary red)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
