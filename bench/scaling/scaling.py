"""AEGIS multi-core scaling harness (unit P7-scaling-001, PREFLIGHT D-P7.7). stdlib only; run through ./run.

Per core count N it starts the default-build `aegis` in reverse-proxy mode in front of a static HTTP/1.1 upstream
(bench/scaling/upstream.rs), pins aegis to N CPUs and the upstream and h2load (the approved public load tool,
nghttp2) to their own CPUs with `taskset -c`, all three sets disjoint, and records per point: req/s, p50/p99
latency (from h2load's per-request --log-file), errors, and the CPU count aegis itself computes (crates/aegis-bin/
src/cpus.rs, read back through `aegis check-config --print-effective` under the same taskset: `p2.usable_cpus`).

The gate (`scaling`, advisory, record_only) passes when every requested core count ran with 0 errors and the report
<out>/<host>-<date>.json was written. Numbers are provisional: the desktop is shared and the run is niced.

    run --cores 1,2,4,8,16,24 --record bench/scaling/out [--duration S] [--warmup S] [--client-cpus C]
        [--upstream-cpus U] [--conns K] [--streams M] [--aegis BIN] [--h2load BIN]
    run --gcp <machine-type> [--region R]   quota preflight for the large-VM run (see README); never creates a VM here
    run --self-test                          judge + parser negative controls on a fake h2load (no aegis needed)
"""
import argparse
import datetime
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
TAG = "SCALING"


# ------------------------------------------------------------------------------------------------ cpu topology

def cpu_list(cpus):
    return ",".join(str(c) for c in sorted(cpus))


def cpu_order():
    """CPUs this process may use, ordered so the first k land on k distinct physical cores while possible
    (SMT siblings come after every core has one CPU in use)."""
    allowed = sorted(os.sched_getaffinity(0))
    seen = {}
    keyed = []
    for c in allowed:
        base = f"/sys/devices/system/cpu/cpu{c}/topology/"
        try:
            core = (int(open(base + "physical_package_id").read()), int(open(base + "core_id").read()))
        except (OSError, ValueError):
            core = (0, c)
        nth = seen.get(core, 0)
        seen[core] = nth + 1
        keyed.append(((nth, core), c))
    return [c for _, c in sorted(keyed)]


def allocate(order, n, client, upstream):
    """Disjoint sets: aegis takes the first n of `order`, h2load the last `client`, the upstream the `upstream`
    before those. None when they do not fit (the point is refused: never overlap the client with the subject)."""
    if n < 1 or n + client + upstream > len(order):
        return None
    tail = order[len(order) - client - upstream:]
    return {"aegis": order[:n], "upstream": tail[:upstream], "h2load": tail[upstream:]}


# ------------------------------------------------------------------------------------------------ h2load

SUMMARY_RE = re.compile(r"requests: (\d+) total, (\d+) started, (\d+) done, (\d+) succeeded, (\d+) failed, "
                        r"(\d+) errored, (\d+) timeout")
STATUS_RE = re.compile(r"status codes: (\d+) 2xx, (\d+) 3xx, (\d+) 4xx, (\d+) 5xx")
FINISHED_RE = re.compile(r"finished in ([0-9.]+)(m?s), ([0-9.]+) req/s")


def parse_h2load(text, log_path):
    """Parse an h2load run. errors = max(failed + errored + timeout, non-2xx statuses): h2load already counts a
    completed non-2xx stream as `failed`, so the max avoids counting it twice while still catching a non-2xx that
    is not in `failed`. The upstream only answers 200, so any non-2xx is the subject refusing or breaking.
    Latency percentiles come from --log-file."""
    s, st, fin = SUMMARY_RE.search(text), STATUS_RE.search(text), FINISHED_RE.search(text)
    if not (s and st and fin):
        raise ValueError("h2load output not understood: " + text[-400:].replace("\n", " | "))
    total, started, done, ok, failed, errored, timeout = (int(x) for x in s.groups())
    s2, s3, s4, s5 = (int(x) for x in st.groups())
    lat = []
    try:
        with open(log_path) as f:
            for line in f:
                parts = line.split("\t")
                if len(parts) >= 3:
                    lat.append(int(parts[2]))
    except OSError:
        pass
    lat.sort()

    def pct(p):
        if not lat:
            return None
        return round(lat[min(len(lat) - 1, int(p * len(lat)))] / 1000.0, 3)

    secs = float(fin.group(1)) / (1000.0 if fin.group(2) == "ms" else 1.0)
    # req/s counts 2xx only: h2load's own figure counts every response, refusals (429) included.
    return {"req_s": round(s2 / secs, 1) if secs > 0 else 0.0, "h2load_req_s": float(fin.group(3)),
            "measured_s": secs, "requests_done": done, "succeeded": ok, "status_2xx": s2,
            "status_3xx": s3, "status_4xx": s4, "status_5xx": s5, "failed": failed, "errored": errored,
            "timeout": timeout, "errors": max(failed + errored + timeout, s3 + s4 + s5),
            "h2load_summary": [m.group(0) for m in (fin, s, st)],
            "p50_ms": pct(0.50), "p99_ms": pct(0.99), "latency_samples": len(lat)}


def run_h2load(h2load, cpus, url, args, workdir, env=None):
    log = os.path.join(workdir, "h2load.log")
    cmd = ["taskset", "-c", cpu_list(cpus), h2load, "-t", str(len(cpus)), "-c", str(args.conns),
           "-m", str(args.streams), "-D", str(args.duration), "--warm-up-time", str(args.warmup),
           "--log-file", log, url]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=args.duration + args.warmup + 60,
                       env=env)
    out = p.stdout + p.stderr
    if p.returncode != 0 and not SUMMARY_RE.search(out):
        raise RuntimeError(f"h2load exit {p.returncode}: {out[-400:]}")
    r = parse_h2load(out, log)
    try:
        os.remove(log)
    except OSError:
        pass
    return r


# ------------------------------------------------------------------------------------------------ subject

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def admin_get(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
        return r.status, r.read().decode(errors="replace")


def metric_samples(text, family):
    """{label-set: value} of a counter family's `_total` samples in OpenMetrics text."""
    out = {}
    pre = family + "_total"
    for line in text.splitlines():
        if line.startswith(pre) and line[len(pre):len(pre) + 1] in ("{", " "):
            try:
                name, val = line.rsplit(" ", 1)
                out[name[len(pre):] or "-"] = float(val)
            except ValueError:
                pass
    return out


def metric_delta(m0, m1, family):
    a, b = metric_samples(m0, family), metric_samples(m1, family)
    return {k: int(v - a.get(k, 0)) for k, v in b.items() if v - a.get(k, 0)}


def config_doc(port, aport, up_port):
    return {"v": 1,
            "listeners": [{"name": "pub", "bind": f"127.0.0.1:{port}", "profile": "P-PUBLIC-WEB",
                           "alpn": ["h2", "http/1.1"]}],
            "admin": {"bind": f"127.0.0.1:{aport}"},
            # One client IP (127.0.0.1) drives every point: lift the S1 per-IP GCRA (F8 admission, P7-spec-001) and the
            # per-connection stream cap (h2load does not reconnect after 32 conns x 10,000 streams; P7-bin-001).
            "admission": {"per_ip": {"rate_per_s": 1000000, "burst": 10000000}},
            "limits": {"max_streams_per_conn": 100000},
            "vhosts": [{"host": "localhost", "routes": [
                {"id": 1, "path": "/", "to": {"upstream": f"127.0.0.1:{up_port}"}, "authz": "allow-all"}]}]}


def aegis_usable_cpus(aegis, cpus, cfg):
    """The CPU count aegis's own cpus.rs computes under this affinity (p2.usable_cpus of the effective dump).

    The dump prints `usable_cpus` only inside a `p2` block, so the probe checks a copy of the served config with a
    placeholder p2 block added (check-config validates config only; it never opens the module or starts a worker).
    The served config itself has no p2 block."""
    with open(cfg) as f:
        doc = json.load(f)
    doc["p2"] = {"worker": "/usr/libexec/aegis-p2", "modules": [
        {"id": "probe", "path": "/nonexistent/probe.wasm", "sha256": "0" * 64}]}
    probe = cfg + ".cpus-probe.json"
    with open(probe, "w") as f:
        json.dump(doc, f)
    p = subprocess.run(["taskset", "-c", cpu_list(cpus), aegis, "check-config", probe, "--print-effective"],
                       capture_output=True, text=True, timeout=30)
    if p.returncode != 0:
        raise RuntimeError(f"check-config exit {p.returncode}: {p.stderr[-300:]}")
    m = re.search(r'"usable_cpus":(\d+)', p.stdout)
    if not m:
        raise RuntimeError("check-config --print-effective has no p2.usable_cpus")
    return int(m.group(1))


class Proc:
    """A child we started; stopped by its own PID only (never by pattern)."""

    def __init__(self, cmd, log):
        self.log = open(log, "wb")
        env = {k: v for k, v in os.environ.items() if k not in ("NOTIFY_SOCKET", "AEGIS_UPGRADE_DIR",
                                                                  "AEGIS_E2E_MUTANT")}
        self.p = subprocess.Popen(cmd, stdout=self.log, stderr=subprocess.STDOUT, env=env)

    def stop(self):
        if self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(10)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait(5)
        self.log.close()


def run_point(n, sets, args, aegis, upstream_bin, h2load, work):
    d = tempfile.mkdtemp(prefix=f"p{n}-", dir=work)
    crt, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-keyout", key, "-out", crt, "-days", "30", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost"], check=True, capture_output=True)
    port, aport, up_port = free_port(), free_port(), free_port()
    cfg = os.path.join(d, "aegis.json")
    with open(cfg, "w") as f:
        json.dump(config_doc(port, aport, up_port), f)
    point = {"cores": n, "cpus": {k: cpu_list(v) for k, v in sets.items()}, "disjoint": True}
    point["usable_cpus"] = aegis_usable_cpus(aegis, sets["aegis"], cfg)
    procs = []
    try:
        procs.append(Proc(["taskset", "-c", cpu_list(sets["upstream"]), upstream_bin, str(up_port)],
                          os.path.join(d, "upstream.log")))
        a = Proc(["taskset", "-c", cpu_list(sets["aegis"]), aegis, "--config", cfg, "--cert", crt, "--key", key,
                  "--audit-dir", os.path.join(d, "audit")], os.path.join(d, "aegis.log"))
        procs.append(a)
        until = time.time() + 20
        while True:
            if a.p.poll() is not None:
                raise RuntimeError(f"aegis exited {a.p.returncode} at start: {tail(os.path.join(d, 'aegis.log'))}")
            try:
                if admin_get(aport, "/healthz")[0] == 200:
                    break
            except OSError:
                pass
            if time.time() > until:
                raise RuntimeError("aegis not healthy within 20 s")
            time.sleep(0.1)
        _, m0 = admin_get(aport, "/metrics")
        point.update(run_h2load(h2load, sets["h2load"], f"https://localhost:{port}/", args, d))
        _, m1 = admin_get(aport, "/metrics")
        # Over warm-up + measurement (h2load's counts cover the measurement window only).
        by_stage = metric_delta(m0, m1, "aegis_admission_rejects")
        point["aegis_admission_rejects_by_stage"] = by_stage
        point["aegis_admission_rejects"] = sum(by_stage.values())
        if a.p.poll() is not None:
            raise RuntimeError(f"aegis died during the run: {tail(os.path.join(d, 'aegis.log'))}")
    finally:
        for p in reversed(procs):
            p.stop()
        shutil.rmtree(d, ignore_errors=True)
    return point


def tail(path):
    try:
        with open(path, "rb") as f:
            return f.read()[-600:].decode(errors="replace")
    except OSError:
        return ""


# ------------------------------------------------------------------------------------------------ judge + report

def judge(report_path, cores):
    """Gate verdict from the written report alone: [] = PASS, else the reasons."""
    if not os.path.isfile(report_path):
        return [f"report not written ({report_path})"]
    try:
        with open(report_path) as f:
            rep = json.load(f)
    except (OSError, ValueError) as e:
        return [f"report unreadable: {e}"]
    pts = {p.get("cores"): p for p in rep.get("points", [])}
    bad = []
    for n in cores:
        p = pts.get(n)
        if p is None:
            bad.append(f"{n} cores: point missing")
        elif p.get("error"):
            bad.append(f"{n} cores: {p['error']}")
        elif p.get("errors") != 0 or p.get("aegis_admission_rejects") != 0:
            bad.append(f"{n} cores: {p.get('errors')} errors (4xx {p.get('status_4xx')}, 5xx {p.get('status_5xx')}, "
                       f"admission rejects {p.get('aegis_admission_rejects')})")
        elif not (p.get("req_s", 0) > 0 and p.get("status_2xx", 0) > 0):
            bad.append(f"{n} cores: no successful requests")
        elif p.get("usable_cpus") != n:
            bad.append(f"{n} cores: aegis cpus.rs counted {p.get('usable_cpus')}")
        elif not p.get("disjoint"):
            bad.append(f"{n} cores: cpusets not disjoint")
    return bad


def table(rep):
    rows = ["| cores | aegis cpus | usable_cpus (cpus.rs) | 2xx req/s | all responses/s | p50 ms | p99 ms | errors | "
            "admission rejects |", "|---:|---|---:|---:|---:|---:|---:|---:|---:|"]
    for p in rep["points"]:
        if p.get("error"):
            rows.append(f"| {p['cores']} | {p.get('cpus', {}).get('aegis', '-')} | - | - | - | - | - | - | "
                        f"{p['error'][:80]} |")
        else:
            rows.append(f"| {p['cores']} | {p['cpus']['aegis']} | {p['usable_cpus']} | {p['req_s']:.0f} | "
                        f"{p['h2load_req_s']:.0f} | "
                        f"{p['p50_ms']} | {p['p99_ms']} | {p['errors']} | {p['aegis_admission_rejects']} |")
    return "\n".join(rows)


def tool_version(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return (p.stdout + p.stderr).strip().splitlines()[0]
    except (OSError, IndexError, subprocess.TimeoutExpired):
        return "unknown"


def write_report(path, rep):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rep, f, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def build(args):
    """Default-feature release build of aegis and the std-only upstream (through ci/heavy.sh)."""
    heavy = os.path.join(REPO, "ci", "heavy.sh")
    if not args.aegis:
        subprocess.run([heavy, "cargo", "build", "--release", "--locked", "-q", "-p", "aegis-bin", "--bin", "aegis"],
                       cwd=REPO, check=True)
        args.aegis = os.path.join(REPO, "target", "release", "aegis")
    out = os.path.join(REPO, "target", "scaling")
    os.makedirs(out, exist_ok=True)
    up = os.path.join(out, "scaling-upstream")
    subprocess.run([heavy, "rustc", "-O", "--edition", "2021", "-o", up, os.path.join(HERE, "upstream.rs")],
                   cwd=REPO, check=True)
    return up


def cmd_run(args):
    cores = [int(x) for x in args.cores.split(",") if x.strip()]
    h2load = args.h2load or shutil.which("h2load")
    if not h2load:
        print(f"{TAG}: FAIL (h2load not found: not on PATH; install it with bench/scaling/provision-h2load)")
        return 1
    up = build(args)
    order = cpu_order()
    host = socket.gethostname().split(".")[0]
    rep = {"unit": "P7-scaling-001", "host": host, "date": datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="seconds"), "provisional": True,
           "note": "advisory record_only (PREFLIGHT D-P7.7); shared host, run at nice 15 under the ci lock",
           "host_cpus": len(order), "cpu_order": ",".join(map(str, order)),
           "kernel": os.uname().release, "h2load": tool_version([h2load, "--version"]),
           "aegis": {"binary": args.aegis, "build": "default features, --release --locked"},
           "load": {"duration_s": args.duration, "warmup_s": args.warmup, "conns": args.conns,
                    "streams": args.streams, "client_cpus": args.client_cpus, "upstream_cpus": args.upstream_cpus,
                    "url": "https://localhost:<port>/ (TLS 1.3, h2, P-PUBLIC-WEB)", "upstream": "bench/scaling/upstream.rs"},
           "points": []}
    work = tempfile.mkdtemp(prefix="aegis-scaling-")
    try:
        for n in cores:
            sets = allocate(order, n, args.client_cpus, args.upstream_cpus)
            if sets is None:
                rep["points"].append({"cores": n, "error": f"does not fit disjointly: {n} aegis + {args.client_cpus} "
                                      f"h2load + {args.upstream_cpus} upstream > {len(order)} CPUs"})
                print(f"{TAG}: {n} cores refused (no disjoint cpusets on {len(order)} CPUs)", flush=True)
                continue
            try:
                p = run_point(n, sets, args, args.aegis, up, h2load, work)
            except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as e:
                p = {"cores": n, "cpus": {k: cpu_list(v) for k, v in sets.items()}, "error": str(e)[:600]}
            rep["points"].append(p)
            print(f"{TAG}: {n} cores: " + (p.get("error") or
                  f"{p['req_s']:.0f} 2xx req/s ({p['h2load_req_s']:.0f} responses/s) p50 {p['p50_ms']} ms p99 {p['p99_ms']} ms errors {p['errors']} "
                  f"(admission rejects {p['aegis_admission_rejects']})"), flush=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    path = os.path.join(args.record, f"{host}-{rep['date'][:10]}.json")
    write_report(path, rep)
    print(table(rep))
    bad = judge(path, cores)
    if bad:
        if any(p.get("aegis_admission_rejects") for p in rep["points"]):
            bad.append("aegis admission refused load (hard-coded S1 per-IP GCRA 1000/s burst 2000, "
                       "crates/aegis-bin/src/shared.rs; see bench/scaling/INFEASIBLE_REPORT.md)")
        print(f"{TAG}: FAIL ({'; '.join(bad)}; report {path})")
        return 1
    print(f"{TAG}: PASS ({len(cores)} points, 0 errors, report {path}; advisory, provisional numbers)")
    return 0


# ------------------------------------------------------------------------------------------------ --gcp preflight

def machine_cores(mt):
    m = re.fullmatch(r"[a-z0-9]+-(?:standard|highcpu|highmem)-(\d+)", mt)
    return int(m.group(1)) if m else None


def quota_free(doc, metric):
    for q in doc.get("quotas", []):
        if q.get("metric") == metric:
            return int(q.get("limit", 0) - q.get("usage", 0)), int(q.get("limit", 0))
    return None, None


def gcp_preflight(mt, project_doc, region_doc, region):
    """(ok, message). Refuses when CPUS_ALL_REGIONS (or the family's regional quota) has fewer free vCPUs than the
    machine type needs. No retry: a quota is raised by the operator, not by waiting."""
    n = machine_cores(mt)
    if n is None:
        return False, f"unknown machine type shape {mt!r} (expected <family>-standard|highcpu|highmem-<vcpus>)"
    free, limit = quota_free(project_doc, "CPUS_ALL_REGIONS")
    if free is None:
        return False, "CPUS_ALL_REGIONS quota not reported by gcloud"
    if free < n:
        return False, (f"CPUS_ALL_REGIONS limit {limit} (free {free}) < {n} vCPUs for {mt}; operator step: raise the "
                       f"quota in the Cloud console (IAM & Admin -> Quotas), PREFLIGHT P4.1")
    fam = mt.split("-")[0].upper() + "_CPUS"
    rfree, rlimit = quota_free(region_doc, fam)
    if rfree is not None and rfree < n:
        return False, f"{fam} in {region} limit {rlimit} (free {rfree}) < {n}; operator step: raise it (PREFLIGHT P4.1)"
    return True, f"quota ok: CPUS_ALL_REGIONS free {free}, {fam} in {region} free {rfree} >= {n}"


def gcloud_json(argv):
    p = subprocess.run(["gcloud"] + argv + ["--format=json"], capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        raise RuntimeError(f"gcloud {' '.join(argv)}: exit {p.returncode}")
    return json.loads(p.stdout)


def cmd_gcp(args):
    try:
        proj = gcloud_json(["compute", "project-info", "describe"])
        reg = gcloud_json(["compute", "regions", "describe", args.region])
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as e:
        print(f"{TAG} GCP: REFUSED (cannot read quotas: {e})")
        return 3
    ok, msg = gcp_preflight(args.gcp, proj, reg, args.region)
    if not ok:
        print(f"{TAG} GCP: REFUSED ({msg})")
        return 3
    print(f"{TAG} GCP: {msg}. VM creation is not automated in P7-scaling-001: follow bench/scaling/README.md "
          f"(--gcp) to create, run on and delete the {args.gcp} VM.")
    return 4


# ------------------------------------------------------------------------------------------------ self-test

FAKE_H2LOAD = r'''#!/usr/bin/env python3
import os, sys
a = sys.argv
log = a[a.index("--log-file") + 1]
fail = int(os.environ.get("FAKE_H2LOAD_FAILED", "0"))
done = 10000
with open(log, "w") as f:
    for i in range(done):
        f.write("%d\t%d\t%d\n" % (1700000000000000 + i, 200, 500 + (i % 100) * 10))
print("finished in 8.00s, %.2f req/s, 1.00MB/s" % (done / 8.0))
print("requests: %d total, %d started, %d done, %d succeeded, %d failed, 0 errored, 0 timeout"
      % (done, done, done, done - fail, fail))
r429 = int(os.environ.get("FAKE_H2LOAD_429", "0"))
print("status codes: %d 2xx, 0 3xx, %d 4xx, 0 5xx" % (done - fail - r429, r429))
'''


def cmd_self_test(_args):
    cores = [1, 2, 4, 8, 16, 24]
    work = tempfile.mkdtemp(prefix="aegis-scaling-st-")
    caught, problems = [], []
    try:
        fake = os.path.join(work, "h2load")
        with open(fake, "w") as f:
            f.write(FAKE_H2LOAD)
        os.chmod(fake, 0o755)
        la = argparse.Namespace(conns=4, streams=4, duration=1, warmup=0)
        order = list(range(32))

        def report(variant):
            pts = []
            for n in cores:
                if variant == "missing-point" and n == 4:
                    continue
                env = dict(os.environ)
                if variant == "error-at-8" and n == 8:
                    env["FAKE_H2LOAD_FAILED"] = "1"
                if variant == "429-not-in-failed" and n == 16:
                    env["FAKE_H2LOAD_429"] = "1"
                sets = allocate(order, n, 4, 2)
                p = {"cores": n, "cpus": {k: cpu_list(v) for k, v in sets.items()}, "disjoint": True,
                     "usable_cpus": n, "aegis_admission_rejects": 0}
                p.update(run_h2load(fake, [0], "https://localhost:1/", la, work, env=env))
                if variant == "admission-rejects-unseen-by-h2load" and n == 2:
                    p["aegis_admission_rejects"] = 5
                pts.append(p)
            path = os.path.join(work, variant, "host-date.json")
            if variant != "no-report":
                write_report(path, {"points": pts})
            return path

        base = judge(report("baseline"), cores)
        if base:
            problems.append(f"unmutated run judged red: {base}")
        for variant in ("error-at-8", "429-not-in-failed", "admission-rejects-unseen-by-h2load", "missing-point",
                        "no-report"):
            r = judge(report(variant), cores)
            (caught if r else problems).append(variant if r else f"mutant {variant} judged PASS")
        # Disjointness: a point that does not fit is refused, never overlapped.
        if allocate(list(range(24)), 24, 4, 2) is not None:
            problems.append("24 aegis cpus + client on 24 CPUs was not refused")
        s = allocate(list(range(24)), 16, 4, 2)
        if not s or set(s["aegis"]) & (set(s["h2load"]) | set(s["upstream"])) or set(s["h2load"]) & set(s["upstream"]):
            problems.append("allocation not disjoint at 16 of 24")
        # --gcp preflight: refuse below quota (today's 12), pass at 100; no retry path exists.
        proj = lambda lim: {"quotas": [{"metric": "CPUS_ALL_REGIONS", "limit": float(lim), "usage": 0.0}]}
        reg = {"quotas": [{"metric": "C2D_CPUS", "limit": 100.0, "usage": 0.0}]}
        if gcp_preflight("c2d-standard-64", proj(12), reg, "us-central1")[0]:
            problems.append("--gcp accepted CPUS_ALL_REGIONS 12 < 64")
        else:
            caught.append("gcp-quota-12")
        if not gcp_preflight("c2d-standard-64", proj(100), reg, "us-central1")[0]:
            problems.append("--gcp refused with sufficient quota")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if problems:
        print(f"{TAG} SELF-TEST: FAIL ({'; '.join(problems)})")
        return 1
    print(f"{TAG} SELF-TEST: PASS (unmutated green; {len(caught)}/{len(caught)} mutants red: {', '.join(caught)})")
    return 0


def main():
    ap = argparse.ArgumentParser(prog="bench/scaling/run")
    ap.add_argument("--cores", default="1,2,4,8,16,24")
    ap.add_argument("--record", default=os.path.join(HERE, "out"))
    ap.add_argument("--duration", type=int, default=10)
    # Default 0: h2load does not count requests made during its warm-up, so a refusal there would be invisible to it
    # (the judge also reads aegis's own admission-reject counter, which covers warm-up).
    ap.add_argument("--warmup", type=int, default=0)
    ap.add_argument("--client-cpus", type=int, default=4)
    ap.add_argument("--upstream-cpus", type=int, default=2)
    ap.add_argument("--conns", type=int, default=32)
    ap.add_argument("--streams", type=int, default=16)
    ap.add_argument("--aegis")
    ap.add_argument("--h2load")
    ap.add_argument("--gcp", metavar="MACHINE_TYPE")
    ap.add_argument("--region", default="us-central1")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return cmd_self_test(args)
    if args.gcp:
        return cmd_gcp(args)
    return cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
