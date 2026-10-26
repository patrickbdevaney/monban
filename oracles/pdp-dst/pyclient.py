#!/usr/bin/env python3
"""Reference PDP-1 client for the pdp-dst self-test, with deliberate mutants. Same stdin/stdout contract as
aegis-pdp-probe: one hex request body per line in, `<decision> <combined>` per line out.

  --mutant none             correct: exact 12-byte reply, magic/version/kind, matching id, decision in 0..2;
                            timeout/EOF/garbage => ERROR, connection reset after every fault
  --mutant timeout-allow    a timeout is read as ALLOW
  --mutant ignore-id        the request id in the reply is not checked
  --mutant accept-oversize  a packet longer than 12 bytes is judged on its first 12 bytes
  --mutant no-reset         the connection is kept after a fault
"""
import argparse
import socket
import sys

MAGIC, VERSION, K_REQ, K_REP, REPLY_LEN = 0xCD, 1, 0, 1, 12


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--connect", required=True)
    ap.add_argument("--deadline-ms", type=int, default=300)
    ap.add_argument("--mutant", default="none")
    a = ap.parse_args()
    m = a.mutant
    conn, rid = None, 0
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        body = bytes.fromhex(line)
        rid += 1
        d = "ERROR"
        try:
            if conn is None:
                conn = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                conn.settimeout(a.deadline_ms / 1000.0)
                conn.connect(a.connect)
            conn.send(bytes([MAGIC, VERSION, K_REQ]) + rid.to_bytes(8, "big") + body)
            data, _, flags, _ = conn.recvmsg(4 * REPLY_LEN)
            oversized = bool(flags & socket.MSG_TRUNC) or len(data) > REPLY_LEN
            if oversized and m == "accept-oversize":
                data, oversized = data[:REPLY_LEN], False
            if (not oversized and len(data) == REPLY_LEN and data[0] == MAGIC and data[1] == VERSION
                    and data[2] == K_REP and (m == "ignore-id" or int.from_bytes(data[3:11], "big") == rid)
                    and data[11] in (0, 1, 2)):
                d = {0: "ALLOW", 1: "DENY", 2: "ERROR"}[data[11]]
        except socket.timeout:
            d = "ALLOW" if m == "timeout-allow" else "ERROR"
        except OSError:
            d = "ERROR"
        if d == "ERROR" and m != "no-reset" and conn is not None:
            conn.close()
            conn = None
        print(d, "ALLOW" if d == "ALLOW" else "DENY", flush=True)


if __name__ == "__main__":
    main()
