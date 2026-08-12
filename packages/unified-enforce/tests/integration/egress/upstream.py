"""The "tool" the agent must not be able to reach directly.

Answers TCP with UPSTREAM and echoes UDP with pong, on whatever ports it is
given. Two protocols because the egress lock treats them differently: TCP is
redirected into the sidecar, UDP is dropped outright except for DNS.
"""

import http.server
import socket
import sys
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"UPSTREAM"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def udp_echo(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    while True:
        data, addr = sock.recvfrom(1024)
        if data:
            sock.sendto(b"pong", addr)


if __name__ == "__main__":
    tcp_port = int(sys.argv[1])
    # 53 stands in for DNS (allowed), 443 for QUIC (must be rejected), and one
    # arbitrary port for everything else (must be dropped).
    for udp_port in (53, 443, 9999):
        threading.Thread(target=udp_echo, args=(udp_port,), daemon=True).start()
    http.server.ThreadingHTTPServer(("0.0.0.0", tcp_port), Handler).serve_forever()
