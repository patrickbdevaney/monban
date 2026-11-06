"""TLS over a plain socket through ssl.MemoryBIO (oracle proxy-l4; stdlib only).

Lets the oracle (a) put bytes in front of the ClientHello in the same send (a PROXY header coalesced with the hello),
(b) record every raw byte sent and received (L4 passthrough must be byte-exact), and lets the reference server feed
bytes it already read while peeking into its TLS server.
"""

import socket
import ssl


class Pump:
    def __init__(self, sock, ctx, server_side=False, server_hostname=None, prefix=b"", pre_in=b""):
        self.sock = sock
        self.inc, self.out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.obj = ctx.wrap_bio(self.inc, self.out, server_side=server_side, server_hostname=server_hostname)
        self.prefix = prefix
        self.sent = bytearray()
        self.recvd = bytearray()
        if pre_in:
            self.recvd += pre_in
            self.inc.write(pre_in)

    def _flush(self):
        data = self.out.read()
        if self.prefix:
            data, self.prefix = self.prefix + data, b""
        if data:
            self.sock.sendall(data)
            self.sent += data

    def _fill(self):
        try:
            d = self.sock.recv(65536)
        except (ConnectionResetError, socket.timeout):
            d = b""
        if not d:
            self.inc.write_eof()
            return False
        self.recvd += d
        self.inc.write(d)
        return True

    def handshake(self):
        while True:
            try:
                self.obj.do_handshake()
                self._flush()
                return
            except ssl.SSLWantReadError:
                self._flush()
                if not self._fill():
                    raise ConnectionError("EOF during the TLS handshake")

    def write(self, data):
        self.obj.write(data)
        self._flush()

    def read(self):
        while True:
            try:
                return self.obj.read(65536)
            except ssl.SSLWantReadError:
                self._flush()
                if not self._fill():
                    return b""
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                return b""

    def read_all(self, limit=1 << 20):
        buf = b""
        while len(buf) < limit:
            d = self.read()
            if not d:
                break
            buf += d
        return buf
