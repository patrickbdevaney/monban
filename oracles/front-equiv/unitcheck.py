"""front-equiv: the systemd half (D-P7.3). The hardened unit refuses io_uring unless the uring.conf drop-in is installed.

check(unit_path, dropin_path) -> list of (name, ok, detail):
  unit.denies-io_uring          effective SystemCallFilter of the unit alone denies io_uring_setup/_enter/_register
  dropin.admits-io_uring        unit + drop-in admits io_uring_setup and io_uring_enter
  dropin.only-io_uring          the drop-in has only a [Service] section with SystemCallFilter= lines naming
                                io_uring_* syscalls (no groups, no "~", no reset, no other directive), and the
                                unit+drop-in allowed set minus the unit's is a subset of the three io_uring syscalls
  dropin.exposure               systemd-analyze security --offline=yes on unit+drop-in <= 2.0 (systemd-hardening bar)
  runtime.unit-denies           a transient `systemd-run --user` service with the unit's SystemCallFilter lines (in
                                order) + SystemCallErrorNumber=EPERM: io_uring_setup fails with EPERM
  runtime.dropin-admits         the same plus the drop-in's lines: io_uring_setup succeeds
The effective set is computed with systemd.exec semantics (first assignment picks allow- or deny-list mode, later
"~" lines remove from an allow list, an empty assignment resets) over `systemd-analyze syscall-filter` group
expansion (recursive). The runtime pair is the authoritative cross-check of that expansion.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
URING = {"io_uring_setup", "io_uring_enter", "io_uring_register"}
_groups = {}
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _env():
    return dict(os.environ, SYSTEMD_COLORS="0", SYSTEMD_PAGER="", NO_COLOR="1")


def expand(tok):
    if not tok.startswith("@"):
        return {tok}
    if tok in _groups:
        return _groups[tok]
    out = subprocess.run(["systemd-analyze", "syscall-filter", "--no-pager", tok], capture_output=True, text=True,
                         timeout=30, env=_env())
    if out.returncode != 0:
        raise RuntimeError(f"systemd-analyze syscall-filter {tok}: {out.stderr.strip()}")
    names = set()
    _groups[tok] = names  # recursion guard
    for ln in out.stdout.splitlines()[1:]:
        ln = ANSI.sub("", ln).strip()
        if not ln or ln.startswith("#"):
            continue
        names |= expand(ln)
    return names


def service_lines(text):
    """(key, value) pairs of the [Service] section, in order; also returns other sections' names."""
    sec, out, others = None, [], []
    for raw in text.splitlines():
        ln = raw.strip()
        if not ln or ln.startswith("#") or ln.startswith(";"):
            continue
        m = re.match(r"^\[(.+)\]$", ln)
        if m:
            sec = m.group(1)
            if sec != "Service":
                others.append(sec)
            continue
        k, _, v = ln.partition("=")
        out.append((sec, k.strip(), v.strip()))
    return out, others


def filter_lines(text):
    lines, _ = service_lines(text)
    return [v for sec, k, v in lines if sec == "Service" and k == "SystemCallFilter"]


def effective(values):
    mode, s = None, set()
    for v in values:
        if v == "":
            mode, s = None, set()
            continue
        neg = v.startswith("~")
        names = set()
        for t in v.lstrip("~").split():
            names |= expand(t)
        if mode is None:
            mode, s = ("deny" if neg else "allow"), set(names)
        elif mode == "allow":
            s = (s - names) if neg else (s | names)
        else:
            s = (s | names) if neg else (s - names)
    if mode is None:
        return lambda n: True
    return (lambda n: n in s) if mode == "allow" else (lambda n: n not in s)


def allowed_set(values, universe):
    f = effective(values)
    return {n for n in universe if f(n)}


def universe():
    u = set()
    for g in subprocess.run(["systemd-analyze", "syscall-filter", "--no-pager"], capture_output=True, text=True,
                            timeout=30, env=_env()).stdout.splitlines():
        g = ANSI.sub("", g)
        if g.startswith("@"):
            u |= expand(g.strip())
    return u | URING


def exposure(text):
    with tempfile.TemporaryDirectory(prefix="front-equiv-unit-") as d:
        p = os.path.join(d, "aegis.service")
        with open(p, "w") as f:
            f.write(text)
        out = subprocess.run(["systemd-analyze", "security", "--offline=yes", p], capture_output=True, text=True,
                             timeout=60)
        m = re.search(r"Overall exposure level for .*: ([0-9.]+)", out.stdout + out.stderr)
        return float(m.group(1)) if m else None


def runtime_probe(values):
    """io_uring_setup result inside a transient user service carrying exactly these SystemCallFilter lines."""
    if not shutil.which("systemd-run"):
        return "no systemd-run"
    cmd = ["systemd-run", "--user", "--wait", "--pipe", "--quiet", "--collect", "-p", "NoNewPrivileges=yes",
           "-p", "SystemCallArchitectures=native", "-p", "SystemCallErrorNumber=EPERM"]
    for v in values:
        cmd += ["-p", f"SystemCallFilter={v}"]
    cmd += [sys.executable, "-I", os.path.join(HERE, "uring.py"), "probe"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as e:
        return f"systemd-run failed: {e}"
    m = re.search(r"io_uring_setup: (ok|errno \d+)", p.stdout)
    return m.group(1) if m else f"no probe output (rc {p.returncode}: {(p.stderr or p.stdout).strip()[:200]})"


def check(unit_path, dropin_path):
    res = []
    try:
        unit = open(unit_path).read()
        dropin = open(dropin_path).read()
    except OSError as e:
        return [("unit.read", False, str(e))]
    try:
        u = universe()
        f_unit = filter_lines(unit)
        f_drop = filter_lines(dropin)
        a_unit = allowed_set(f_unit, u)
        a_both = allowed_set(f_unit + f_drop, u)
    except (RuntimeError, OSError, subprocess.SubprocessError) as e:
        return [("unit.expand", False, str(e))]
    leaked = sorted(URING & a_unit)
    res.append(("unit.denies-io_uring", not leaked,
                f"{os.path.basename(unit_path)} alone admits {leaked} (SystemCallFilter=@system-service includes "
                f"@aio; add SystemCallFilter=~io_uring_setup io_uring_enter io_uring_register)"))
    need = {"io_uring_setup", "io_uring_enter"}
    res.append(("dropin.admits-io_uring", need <= a_both, f"unit+drop-in still denies {sorted(need - a_both)}"))
    lines, others = service_lines(dropin)
    bad = [f"[{s}]" for s in others]
    for sec, k, v in lines:
        if sec != "Service" or k != "SystemCallFilter":
            bad.append(f"{k}={v}")
        elif v == "" or v.startswith("~") or not set(v.split()) <= URING:
            bad.append(f"{k}={v}")
    widened = sorted((a_both - a_unit) - URING)
    narrowed = sorted(a_unit - a_both)
    res.append(("dropin.only-io_uring", not bad and not widened and not narrowed and bool(f_drop),
                f"directives {bad}, widened {widened[:8]}, narrowed {narrowed[:8]}"))
    ex = exposure(unit.rstrip("\n") + "\n\n# --- drop-in ---\n" + dropin)
    res.append(("dropin.exposure", ex is not None and ex <= 2.0, f"exposure {ex}"))
    r1 = runtime_probe(f_unit)
    res.append(("runtime.unit-denies", r1 == "errno 1", f"io_uring_setup under the unit's filter: {r1}"))
    r2 = runtime_probe(f_unit + f_drop)
    res.append(("runtime.dropin-admits", r2 == "ok", f"io_uring_setup under unit+drop-in: {r2}"))
    return res


def fixture_good(unit_text):
    """The real unit with the io_uring deny line it needs (appended after its last SystemCallFilter line)."""
    lines = unit_text.splitlines()
    if any(l.strip().startswith("SystemCallFilter=~") and URING & set(l.split("=", 1)[1].lstrip("~").split())
           for l in lines):
        return unit_text
    last = max(i for i, l in enumerate(lines) if l.strip().startswith("SystemCallFilter="))
    lines.insert(last + 1, "SystemCallFilter=~io_uring_setup io_uring_enter io_uring_register")
    return "\n".join(lines) + "\n"


def strip_uring_deny(unit_text):
    """Mutant: the same unit without any io_uring / @aio deny (what stock @system-service admits)."""
    out = []
    for l in unit_text.splitlines():
        s = l.strip()
        if s.startswith("SystemCallFilter=~"):
            toks = [t for t in s.split("=", 1)[1].lstrip("~").split() if t not in URING and t != "@aio"]
            if not toks:
                continue
            l = "SystemCallFilter=~" + " ".join(toks)
        out.append(l)
    return "\n".join(out) + "\n"
