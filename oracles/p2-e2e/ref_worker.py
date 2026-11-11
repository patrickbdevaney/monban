#!/usr/bin/env python3
"""p2-e2e reference (mock) worker: stands in for monban-p2 behind ref_subject.py. Oracle-local; never shipped.

It does not execute Wasm: each module is a stub carrying its behaviour kind in a custom section (p2wire.stub_module),
and the worker plays that kind. What it does model is the process structure the oracle judges: an exec-spawned
zygote that forks one child per connection, an exec-spawned cordon per principal, PR_SET_DUMPABLE=0, refusal below
Landlock ABI 4 (exit 78), and, in a test-hooks build (env AEGIS_REF_TEST_HOOKS=1, set by the oracle's test wrapper),
the F14 layout report and the AEGIS_P2_TEST_LANDLOCK_ABI override. Landlock and seccomp themselves are not installed
(oracles/syscall-negative judges them).

Subcommands:
  compile --module <path> --sha256 <hex>
  zygote  --fd <listening SOCK_SEQPACKET fd> --modules <json>
  cordon  --fd <connected SOCK_SEQPACKET fd> --modules <json>
  template --ctl <fd> --modules <json>      (mutant fork-respawn only: forks zygotes from one template process)
Frames (mock only, JSON per message): s2w {"module","req_head"(hex)}; w2s {"layout":{"pid","load_base"}} first when
hooks are on, then {"end":"allow","status":200,"body":hex} | {"end":"deny"} | {"end":"trap","trap":n}.
"""

import ctypes
import hashlib
import json
import os
import signal
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.dont_write_bytecode = True  # keep the oracle directory clean
import p2wire  # noqa: E402

EX_CONFIG = 78
HOOKS = os.environ.get("AEGIS_REF_TEST_HOOKS") == "1"
MUTANT = os.environ.get("AEGIS_P2_MUTANT", "")
LIBC = ctypes.CDLL(None, use_errno=True)
PR_SET_DUMPABLE = 4
SYS_landlock_create_ruleset = 444
LANDLOCK_CREATE_RULESET_VERSION = 1


def die(msg):
    sys.stderr.write(f"ref_worker: {msg}\n")
    sys.stderr.flush()
    os._exit(EX_CONFIG)


def landlock_abi():
    if HOOKS and os.environ.get("AEGIS_P2_TEST_LANDLOCK_ABI"):
        return int(os.environ["AEGIS_P2_TEST_LANDLOCK_ABI"])
    r = LIBC.syscall(SYS_landlock_create_ruleset, None, 0, LANDLOCK_CREATE_RULESET_VERSION)
    return r if r > 0 else 0


def sandbox():
    abi = landlock_abi()
    if abi < 4:
        die(f"landlock ABI {abi} < 4: refusing (fail closed)")
    if MUTANT != "dumpable-1":
        if LIBC.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            die("prctl(PR_SET_DUMPABLE, 0) failed")


def load_base():
    # An address inside libc: randomized per execve (mmap ASLR), inherited unchanged by fork. The interpreter
    # binary itself may be non-PIE, so its own base would not move.
    return ctypes.cast(LIBC.prctl, ctypes.c_void_p).value


def load_module(path, sha):
    with open(path, "rb") as f:
        b = f.read()
    if hashlib.sha256(b).hexdigest() != sha:
        die(f"module {path}: digest mismatch")
    kind = p2wire.stub_kind(b)
    if kind is None:
        die(f"module {path}: not a reference stub")
    if kind == "abort" and not HOOKS:
        die(f"module {path}: imports env.host_fault, which only a test-hooks build defines")
    return kind


def load_modules(spec):
    with open(spec) as f:
        mods = json.load(f)
    return {m["id"]: (load_module(m["path"], m["sha256"]), m.get("wall_ms", 100)) for m in mods}


def send(conn, obj):
    conn.send(json.dumps(obj).encode())


def serve_one(conn, mods, msg):
    req = json.loads(msg)
    kind, wall_ms = mods.get(req["module"], (None, 0))
    if kind in ("echo_a", "echo_b"):
        body = (b"A" if kind == "echo_a" else b"B") + bytes.fromhex(req["req_head"])
        send(conn, {"end": "allow", "status": 200, "body": body.hex()})
    elif kind == "deny":
        send(conn, {"end": "deny"})
    elif kind == "spin":
        time.sleep(min(wall_ms, 300) / 1000.0)
        send(conn, {"end": "trap", "trap": 2})
    elif kind == "abort":
        os.abort()
    else:  # trap, or an unknown module id
        send(conn, {"end": "trap", "trap": 4})


def layout(conn):
    if HOOKS:
        send(conn, {"layout": {"pid": os.getpid(), "load_base": load_base()}})


def zygote_loop(lsock, mods):
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)  # children are reaped by the kernel
    while True:
        conn, _ = lsock.accept()
        pid = os.fork()
        if pid == 0:
            try:
                lsock.close()
                layout(conn)
                msg = conn.recv(1 << 20)
                if msg:
                    serve_one(conn, mods, msg)
            finally:
                os._exit(0)
        conn.close()


def main():
    a = sys.argv[1:]
    if not a:
        die("no subcommand")
    cmd, opts = a[0], dict(zip(a[1::2], a[2::2]))
    if cmd == "compile":
        if landlock_abi() < 4:
            die("landlock ABI < 4: refusing to compile (fail closed)")
        load_module(opts["--module"], opts["--sha256"])
        return 0
    sandbox()
    mods = load_modules(opts["--modules"])
    if cmd == "zygote":
        zygote_loop(socket.socket(fileno=int(opts["--fd"])), mods)
    elif cmd == "cordon":
        conn = socket.socket(fileno=int(opts["--fd"]))
        layout(conn)
        while True:
            msg = conn.recv(1 << 20)
            if not msg:
                return 0
            serve_one(conn, mods, msg)
    elif cmd == "template":
        ctl = socket.socket(fileno=int(opts["--ctl"]))
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        while True:
            msg, fds, _, _ = socket.recv_fds(ctl, 64, 1)
            if not msg or not fds:
                return 0
            pid = os.fork()
            if pid == 0:
                ctl.close()
                zygote_loop(socket.socket(fileno=fds[0]), mods)
                os._exit(0)
            os.close(fds[0])
            ctl.send(json.dumps({"zygote": pid}).encode())
    else:
        die(f"unknown subcommand {cmd}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
