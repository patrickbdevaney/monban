#!/usr/bin/env python3
"""Dummy OTLP/HTTP collector: 200 to every POST, logs path and byte count to stdout. usage: collector.py <port>"""
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); self.rfile.read(n)
        print(f"POST {self.path} {n} {self.headers.get('Content-Type')}", flush=True)
        self.send_response(200); self.send_header("Content-Type", "application/x-protobuf")
        self.send_header("Content-Length", "0"); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
