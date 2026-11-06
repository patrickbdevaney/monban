"""exec a command with io_uring unavailable: `python3 -I noring_exec.py <cmd> [args...]`.

Sets PR_SET_NO_NEW_PRIVS and installs a seccomp filter that makes io_uring_setup, io_uring_enter and
io_uring_register fail with EPERM (what `kernel.io_uring_disabled=2`, or a SystemCallFilter without them under
SystemCallErrorNumber=EPERM, gives a process). Everything else is allowed. Then execv()s the command (same pid).
No privileges needed. Used by the front-equiv fail-closed check (FRONT fallback: `--front uring` must refuse).
"""

import ctypes
import os
import struct
import sys

PR_SET_NO_NEW_PRIVS, PR_SET_SECCOMP, SECCOMP_MODE_FILTER = 38, 22, 2
RET_ALLOW, RET_ERRNO_EPERM = 0x7FFF0000, 0x00050000 | 1
AUDIT_ARCH = (0xC000003E, 0xC00000B7)  # x86_64, aarch64: io_uring syscalls are 425..427 on both
LD_W_ABS, JEQ_K, RET_K = 0x20, 0x15, 0x06


def ins(code, jt, jf, k):
    return struct.pack("<HBBI", code, jt, jf, k)


def program():
    # Jump offsets are relative to the next instruction.
    p = [ins(LD_W_ABS, 0, 0, 4),                     # 0 arch
         ins(JEQ_K, 1, 0, AUDIT_ARCH[0]),             # 1 x86_64 -> 3
         ins(JEQ_K, 0, 5, AUDIT_ARCH[1]),             # 2 aarch64 -> 3 ; other -> 8
         ins(LD_W_ABS, 0, 0, 0),                     # 3 nr
         ins(JEQ_K, 4, 0, 425),                      # 4 -> 9
         ins(JEQ_K, 3, 0, 426),                      # 5 -> 9
         ins(JEQ_K, 2, 0, 427),                      # 6 -> 9
         ins(RET_K, 0, 0, RET_ALLOW),                # 7
         ins(RET_K, 0, 0, RET_ALLOW),                # 8 (other arch)
         ins(RET_K, 0, 0, RET_ERRNO_EPERM)]          # 9
    return b"".join(p), len(p)


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def main():
    if len(sys.argv) < 2:
        print("usage: noring_exec.py <cmd> [args...]", file=sys.stderr)
        return 2
    libc = ctypes.CDLL(None, use_errno=True)
    code, n = program()
    buf = ctypes.create_string_buffer(code, len(code))
    prog = SockFprog(n, ctypes.addressof(buf))
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        print(f"noring_exec: PR_SET_NO_NEW_PRIVS: {os.strerror(ctypes.get_errno())}", file=sys.stderr)
        return 70
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0) != 0:
        print(f"noring_exec: PR_SET_SECCOMP: {os.strerror(ctypes.get_errno())}", file=sys.stderr)
        return 70
    os.execv(sys.argv[1], sys.argv[1:])
    return 70


if __name__ == "__main__":
    sys.exit(main())
