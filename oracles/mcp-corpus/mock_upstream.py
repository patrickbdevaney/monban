"""Stdlib mock MCP upstream for the mcp-corpus oracle. Binds 127.0.0.1 only; counts and records every request.

Reviewed port of research round-004/06-corpus/mock_upstream.py (recording + 307 redirect); differences: in-process
(thread) instead of a separate process, an exact invocation counter, and a second instance used as the redirect
target ("origin B"). Every HTTP request received, whatever its method, counts as one handler invocation.
"""
import http.server
import json
import threading


class MockUpstream:
    def __init__(self, port=0, redirect_to=None):
        self.records = []
        self.lock = threading.Lock()
        self.redirect_to = redirect_to          # base URL of origin B for POST /redir
        up = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _rec(self, body):
                with up.lock:
                    up.records.append({"method": self.command, "path": self.path,
                                       "headers": {k.lower(): v for k, v in self.headers.items()},
                                       "body": body[:4000]})

            def _send(self, code, obj=None, extra=()):
                data = b"" if obj is None else json.dumps(obj).encode()
                self.send_response(code)
                for k, v in extra:
                    self.send_header(k, v)
                if obj is not None:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                n = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(n).decode("utf-8", "replace")
                self._rec(body)
                if self.path.startswith("/redir") and up.redirect_to:
                    return self._send(307, None, [("Location", up.redirect_to + "/captured")])
                try:
                    m = json.loads(body)
                except Exception:
                    m = {}
                if not isinstance(m, dict):
                    m = {}
                meth, id_ = m.get("method"), m.get("id")
                if meth is None or id_ is None:
                    return self._send(202)
                p = m.get("params") if isinstance(m.get("params"), dict) else {}
                if meth == "initialize":
                    res = {"protocolVersion": p.get("protocolVersion"), "capabilities": {"tools": {}},
                           "serverInfo": {"name": "mock", "version": "0"}}
                elif meth == "tools/list":
                    res = {"tools": [{"name": "echo", "description": "e",
                                      "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}}}]}
                elif meth == "tools/call":
                    res = {"content": [{"type": "text", "text": json.dumps(p.get("arguments"))}]}
                else:
                    res = {}
                self._send(200, {"jsonrpc": "2.0", "id": id_, "result": res})

            def do_GET(self):
                self._rec("")
                self._send(405)

            do_DELETE = do_PUT = do_OPTIONS = do_GET

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.url = "http://127.0.0.1:%d" % self.port
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def count(self):
        with self.lock:
            return len(self.records)

    def snapshot(self):
        with self.lock:
            return list(self.records)
