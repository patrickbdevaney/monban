#!/usr/bin/env python3
"""Run a wall-clock-sensitive command only while the host is quiet, and void the result if it was not.

  ci/quiet.py <command...>          (under ci/heavy.sh or ci/remote.sh, which give the job its own systemd scope)

Foreign load = host CPU busy time (/proc/stat) minus this job's own cgroup usage (cpu.stat usage_usec), in cores.
1. Wait until foreign load stays <= QUIET_MAX_CORES for QUIET_SETTLE_S (gives up after QUIET_WAIT_S: exit 75).
2. Run the command while sampling foreign load every QUIET_WINDOW_S.
3. If any window exceeded QUIET_MAX_CORES, the attempt is INVALID whatever the command printed (a noisy PASS is
   no more trustworthy than a noisy FAIL: dudect noise can hide a leak). Invalid attempts are re-run, up to
   QUIET_ATTEMPTS; if none is valid, exit 75. A valid attempt's exit status is final: a valid FAIL is never retried.
The command's output is printed for every attempt; the last line is the command's own (oracle contract), and a
`quiet.py:` line before it records the load evidence.
"""
import os, subprocess, sys, tempfile, threading, time

MAX_CORES = float(os.environ.get("QUIET_MAX_CORES", "2.0"))
WINDOW = float(os.environ.get("QUIET_WINDOW_S", "5"))
SETTLE = float(os.environ.get("QUIET_SETTLE_S", "30"))
WAIT = float(os.environ.get("QUIET_WAIT_S", "10800"))
ATTEMPTS = int(os.environ.get("QUIET_ATTEMPTS", "3"))
TICK = os.sysconf("SC_CLK_TCK")


def own_cgroup():
    path = open("/proc/self/cgroup").read().strip().split("::", 1)[-1]
    if not path.endswith(".scope") or "/run-" not in path:
        sys.exit("quiet.py: not in a dedicated systemd scope; run under ci/heavy.sh or ci/remote.sh")
    return f"/sys/fs/cgroup{path}/cpu.stat"


def host_busy_s():
    f = open("/proc/stat").readline().split()[1:]
    v = list(map(int, f))
    idle = v[3] + v[4]  # idle + iowait
    return (sum(v[:8]) - idle) / TICK  # user..steal; guest is already counted in user


def own_s(stat):
    for line in open(stat):
        k, val = line.split()
        if k == "usage_usec":
            return int(val) / 1e6
    raise RuntimeError("no usage_usec")


class Sampler:
    def __init__(self, stat):
        self.stat, self.samples, self.stop = stat, [], threading.Event()
        self.prev = (time.monotonic(), host_busy_s(), own_s(stat))

    def sample(self):
        now = (time.monotonic(), host_busy_s(), own_s(self.stat))
        dt = now[0] - self.prev[0]
        foreign = max(0.0, ((now[1] - self.prev[1]) - (now[2] - self.prev[2])) / dt) if dt > 0 else 0.0
        self.prev = now
        self.samples.append(foreign)
        return foreign

    def run(self):
        while not self.stop.wait(WINDOW):
            self.sample()


def settle(stat):
    s, quiet_for, waited = Sampler(stat), 0.0, 0.0
    while quiet_for < SETTLE:
        if waited >= WAIT:
            return False
        time.sleep(WINDOW)
        waited += WINDOW
        quiet_for = quiet_for + WINDOW if s.sample() <= MAX_CORES else 0.0
    return True


def main():
    cmd = sys.argv[1:]
    if not cmd:
        sys.exit("usage: ci/quiet.py <command...>")
    stat = own_cgroup()
    for attempt in range(1, ATTEMPTS + 1):
        t0 = time.monotonic()
        if not settle(stat):
            print(f"quiet.py: host never quiet (foreign load > {MAX_CORES} cores for {WAIT:.0f} s); run INVALID")
            return 75
        waited = time.monotonic() - t0
        s = Sampler(stat)
        th = threading.Thread(target=s.run, daemon=True)
        th.start()
        with tempfile.TemporaryFile() as out:
            rc = subprocess.call(cmd, stdout=out, stderr=subprocess.STDOUT)
            s.stop.set()
            th.join()
            s.sample()
            out.seek(0)
            text = out.read().decode(errors="replace").rstrip("\n")
        peak = max(s.samples)
        mean = sum(s.samples) / len(s.samples)
        valid = peak <= MAX_CORES
        lines = text.split("\n")
        print("\n".join(lines[:-1]))
        print(f"quiet.py: attempt {attempt}/{ATTEMPTS} {'VALID' if valid else 'INVALID'}: foreign load mean "
              f"{mean:.2f} peak {peak:.2f} cores (limit {MAX_CORES}) over {len(s.samples)} x {WINDOW:.0f} s; "
              f"settled after {waited:.0f} s; exit {rc}")
        if valid:
            print(lines[-1])
            return rc
        print(f"(invalid attempt's last line, not a verdict: {lines[-1]})")
    print(f"quiet.py: no valid attempt in {ATTEMPTS}; run INVALID")
    return 75


if __name__ == "__main__":
    sys.exit(main())
