#!/usr/bin/env python3
"""Sidecar for requests Google rejects from reqwest (Waa/jnn-pa, googlevideo).
urllib/openssl fingerprint is accepted; reqwest's is not.
Listens on 127.0.0.1:8090. Protocol:
  POST /f  JSON {"method","url","headers":{}, "body_b64":""}
  -> response: status, headers (dict), body (raw bytes)
"""
import http.server, json, urllib.request, urllib.error, base64, socketserver

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        if self.path != "/f":
            self.send_error(404); return
        try:
            ln = int(self.headers.get("content-length", 0))
            req = json.loads(self.rfile.read(ln) or b"{}")
            url = req["url"]
            method = req.get("method", "GET")
            headers = {k: v for k, v in req.get("headers", {}).items()}
            headers.setdefault("user-agent", DEFAULT_UA)
            body = base64.b64decode(req.get("body_b64", "")) if req.get("body_b64") else None
            r = urllib.request.Request(url, data=body, method=method, headers=headers)
            resp = urllib.request.urlopen(r, timeout=120)
            data = resp.read()
            out = {"status": resp.status,
                   "headers": {k: v for k, v in resp.headers.items() if k.lower() not in ("transfer-encoding", "connection")},
                   "body_b64": base64.b64encode(data).decode()}
        except urllib.error.HTTPError as e:
            out = {"status": e.code, "headers": {"content-type": e.headers.get("content-type", "text/plain")},
                   "body_b64": base64.b64encode(e.read()).decode()}
        except Exception as e:
            out = {"status": 502, "headers": {}, "body_b64": base64.b64encode(str(e).encode()).decode()}
        payload = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a): pass

class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

if __name__ == "__main__":
    S(("127.0.0.1", 8090), H).serve_forever()
