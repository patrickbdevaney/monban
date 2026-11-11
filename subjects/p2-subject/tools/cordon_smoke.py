"""Manual smoke test of `monban-p2 cordon` over F14 frames (not a gate; P5-iso-003 development aid).

usage: python3 -I subjects/p2-subject/tools/cordon_smoke.py <path to monban-p2>

Compiles two hand-assembled import-free modules with `monban-p2 compile` (one returns 0, one loops), starts a cordon
on a SOCK_SEQPACKET listener at fd 3, and on two connections checks the ready frame's digest and prints the resp-end
of three sequential requests per connection (fuel and wall-bound traps for the loop module).
"""
import hashlib, os, shutil, socket, subprocess, sys, tempfile, time

B = os.path.abspath(sys.argv[1])
d = tempfile.mkdtemp(prefix="cordon-smoke-")

def mod(body):
    hdr = bytes.fromhex("0061736d01000000")
    typ = bytes.fromhex("0105016000017f")
    fn = bytes.fromhex("03020100")
    mem = bytes.fromhex("0503010001")
    exp = bytes([7, 19, 2, 6]) + b"memory" + bytes([2, 0, 6]) + b"handle" + bytes([0, 0])
    code_body = bytes([len(body)]) + body
    code = bytes([10, len(code_body) + 1, 1]) + code_body
    return hdr + typ + fn + mem + exp + code

OK = mod(bytes.fromhex("0041000b"))            # return 0
LOOP = mod(bytes.fromhex("000340" "0c000b" "41000b"))  # loop forever

def u(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)

def bs(b):
    return u(len(b)) + b

def request(rid, fuel, wall):
    lim = [fuel, wall, 16, 10000, 64, 4194304, 1048576, 65536]
    head = bs(b"GET") + bs(b"/x") + u(0) + bs(b"") + u(0) + u(0)
    return u(0) + u(rid) + b"".join(u(x) for x in lim) + head

def chunk(rid):
    return u(1) + u(rid) + bs(b"") + b"\x01"

def run(name, wasm, reqs):
    w = os.path.join(d, name + ".wasm"); c = os.path.join(d, name + ".cwasm")
    open(w, "wb").write(wasm)
    r = subprocess.run([B, "compile", "--in", w, "--out", c], capture_output=True)
    print(name, "compile rc", r.returncode, r.stderr.decode()[-300:])
    if r.returncode:
        return
    h = hashlib.sha256(open(c, "rb").read()).hexdigest()
    sp = os.path.join(d, name + ".sock")
    l = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET); l.bind(sp); l.listen(16)
    lfd = l.fileno()

    def fd3():
        # in the child, before exec: the listener at fd 3, inheritable
        if lfd != 3:
            os.dup2(lfd, 3)
        os.set_inheritable(3, True)

    p = subprocess.Popen([B, "cordon", "--module", c, "--sha256", h, "--threads", "4"], pass_fds=(lfd,),
                         preexec_fn=fd3, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    l.close()
    try:
        talk(name, sp, h, reqs, p)
    finally:
        p.kill()
        err = p.communicate()[1].decode()
        print(name, "stderr:", err[-400:])


def talk(name, sp, h, reqs, p):
    time.sleep(0.5)
    for conn_i in range(2):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET); s.connect(sp); s.settimeout(5)
        ready = s.recv(70000)
        print(name, "conn", conn_i, "ready", ready[:4].hex(), "digest ok", ready[4:] == bytes.fromhex(h))
        for rid, fuel, wall in reqs:
            t = time.time()
            s.send(request(rid, fuel, wall)); s.send(chunk(rid))
            try:
                end = s.recv(70000)
                print(name, "rid", rid, "resp", end.hex(), "%.1f ms" % ((time.time() - t) * 1e3))
            except Exception as e:
                print(name, "rid", rid, "ERR", e)
        s.close()
    print(name, "cordon alive", p.poll() is None)

try:
    run("ok", OK, [(1, 15000000, 100), (2, 15000000, 100), (3, 15000000, 100)])
    run("loop", LOOP, [(1, 15000000, 100), (2, 1000000000, 50), (3, 1000000000, 1000)])
finally:
    shutil.rmtree(d, ignore_errors=True)
