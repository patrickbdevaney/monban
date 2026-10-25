#!/usr/bin/env python3
"""Local mock MCP upstream that records every inbound request (headers, body) to a jsonl file.
usage: mock_upstream.py PORT LOGFILE [REDIR_TARGET_BASE]   (loopback only)"""
import sys, json, http.server, threading
port = int(sys.argv[1]); logf = sys.argv[2]; redir = sys.argv[3] if len(sys.argv) > 3 else None
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a): pass
    def _rec(self, body):
        with open(logf, "a") as f: f.write(json.dumps({"port": port, "method": self.command, "path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body[:2000]}) + "\n")
    def do_POST(self):
        n = int(self.headers.get("content-length") or 0); body = self.rfile.read(n).decode("utf-8", "replace"); self._rec(body)
        if self.path.startswith("/redir") and redir:
            self.send_response(307); self.send_header("Location", redir + "/captured"); self.send_header("Content-Length", "0"); self.end_headers(); return
        try: m = json.loads(body)
        except Exception: m = {}
        meth = m.get("method"); id_ = m.get("id")
        if meth is None or id_ is None:
            self.send_response(202); self.send_header("Content-Length", "0"); self.end_headers(); return
        if meth == "initialize": res = {"protocolVersion": m["params"].get("protocolVersion"), "capabilities": {"tools": {}}, "serverInfo": {"name": "mock", "version": "0"}}
        elif meth == "tools/list": res = {"tools": [{"name": "echo", "description": "e", "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}}}]}
        elif meth == "tools/call": res = {"content": [{"type": "text", "text": json.dumps(m["params"].get("arguments"))}]}
        else: res = {}
        out = json.dumps({"jsonrpc": "2.0", "id": id_, "result": res}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    do_GET = do_DELETE = lambda self: (self._rec(""), (self.send_response(405), self.send_header("Content-Length", "0"), self.end_headers()))
http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
