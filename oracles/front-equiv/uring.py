"""Minimal io_uring access from stdlib Python (ctypes + mmap), x86_64 / aarch64 syscall numbers.

Used by the front-equiv oracle in two places, never by monban:
  * front_ref.py (the self-test reference "uring" front) owns a real ring and submits one IORING_OP_NOP per accepted
    connection, so its /proc/<pid>/fdinfo shows an `anon_inode:[io_uring]` whose CqTail moves with traffic;
  * systemd_probe(): `python3 -I uring.py probe` prints `io_uring_setup: ok` or `io_uring_setup: errno N`, run under a
    transient systemd unit carrying the hardened unit's SystemCallFilter lines.
"""

import ctypes
import mmap
import os
import struct
import sys
import threading

NR_SETUP, NR_ENTER, NR_REGISTER = 425, 426, 427  # identical on x86_64 and aarch64 (asm-generic numbering)
IORING_OFF_SQ_RING, IORING_OFF_CQ_RING, IORING_OFF_SQES = 0, 0x8000000, 0x10000000
IORING_FEAT_SINGLE_MMAP = 1
IORING_ENTER_GETEVENTS = 1

_libc = ctypes.CDLL(None, use_errno=True)
_syscall = _libc.syscall
_syscall.restype = ctypes.c_long


class _SqOff(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint32) for n in ("head", "tail", "ring_mask", "ring_entries", "flags", "dropped",
                                                "array", "resv1")] + [("user_addr", ctypes.c_uint64)]


class _CqOff(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint32) for n in ("head", "tail", "ring_mask", "ring_entries", "overflow", "cqes",
                                                "flags", "resv1")] + [("user_addr", ctypes.c_uint64)]


class _Params(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint32) for n in ("sq_entries", "cq_entries", "flags", "sq_thread_cpu",
                                                "sq_thread_idle", "features", "wq_fd")] + [
        ("resv", ctypes.c_uint32 * 3), ("sq_off", _SqOff), ("cq_off", _CqOff)]


def setup_errno(entries=4):
    """Try io_uring_setup once; return 0 on success (the ring is closed again) or the errno."""
    p = _Params()
    fd = _syscall(NR_SETUP, ctypes.c_uint(entries), ctypes.byref(p))
    if fd < 0:
        return ctypes.get_errno()
    os.close(fd)
    return 0


class Ring:
    """One io_uring instance; nop() submits one IORING_OP_NOP and reaps its completion (thread-safe)."""

    def __init__(self, entries=8):
        p = _Params()
        fd = _syscall(NR_SETUP, ctypes.c_uint(entries), ctypes.byref(p))
        if fd < 0:
            e = ctypes.get_errno()
            raise OSError(e, f"io_uring_setup: {os.strerror(e)}")
        self.fd, self.p = fd, p
        sq_sz = p.sq_off.array + p.sq_entries * 4
        cq_sz = p.cq_off.cqes + p.cq_entries * 16
        if p.features & IORING_FEAT_SINGLE_MMAP:
            sq_sz = cq_sz = max(sq_sz, cq_sz)
        self.sq = mmap.mmap(fd, sq_sz, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=IORING_OFF_SQ_RING)
        self.cq = self.sq if p.features & IORING_FEAT_SINGLE_MMAP else mmap.mmap(
            fd, cq_sz, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=IORING_OFF_CQ_RING)
        self.sqes = mmap.mmap(fd, p.sq_entries * 64, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE,
                              offset=IORING_OFF_SQES)
        self.lock = threading.Lock()
        self.n = 0

    def _u32(self, m, off):
        return struct.unpack_from("<I", m, off)[0]

    def nop(self):
        with self.lock:
            p = self.p
            tail = self._u32(self.sq, p.sq_off.tail)
            mask = self._u32(self.sq, p.sq_off.ring_mask)
            idx = tail & mask
            self.n += 1
            sqe = bytearray(64)  # opcode 0 = IORING_OP_NOP; user_data at offset 32
            struct.pack_into("<Q", sqe, 32, self.n)
            self.sqes[idx * 64:(idx + 1) * 64] = bytes(sqe)
            struct.pack_into("<I", self.sq, p.sq_off.array + idx * 4, idx)
            struct.pack_into("<I", self.sq, p.sq_off.tail, (tail + 1) & 0xFFFFFFFF)
            r = _syscall(NR_ENTER, ctypes.c_uint(self.fd), ctypes.c_uint(1), ctypes.c_uint(1),
                         ctypes.c_uint(IORING_ENTER_GETEVENTS), None, ctypes.c_size_t(0))
            if r < 0:
                e = ctypes.get_errno()
                raise OSError(e, f"io_uring_enter: {os.strerror(e)}")
            struct.pack_into("<I", self.cq, p.cq_off.head, self._u32(self.cq, p.cq_off.tail))


def main():
    if sys.argv[1:] == ["probe"]:
        e = setup_errno()
        print("io_uring_setup: ok" if e == 0 else f"io_uring_setup: errno {e}")
        return 0
    print("usage: uring.py probe")
    return 2


if __name__ == "__main__":
    sys.exit(main())
