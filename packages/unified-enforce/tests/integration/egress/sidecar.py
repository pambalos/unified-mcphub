"""A stand-in for the Envoy sidecar: answers everything with SIDECAR.

Envoy itself is tested elsewhere. What matters here is only *where the agent's
packets end up*, so this needs to be distinguishable from the upstream and
nothing more. It listens on the port the iptables REDIRECT targets.
"""

import http.server
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"SIDECAR"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
    http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
