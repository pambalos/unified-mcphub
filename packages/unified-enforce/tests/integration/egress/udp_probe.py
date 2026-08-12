"""Ask one question: did a UDP datagram reach the upstream?

Reachability is the signal, deliberately. Distinguishing REJECT from DROP by
error code is fiddly and kernel-dependent — ICMP port-unreachable surfaces as
ECONNREFUSED only on a later syscall, and not always — whereas "did the echo
come back" is unambiguous and is the property the guarantee is actually about.

Prints REACHED or BLOCKED. Usage: udp_probe.py <host> <port>
"""

import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
try:
    sock.sendto(b"ping", (host, port))
    data, _ = sock.recvfrom(1024)
    print("REACHED" if data == b"pong" else f"UNEXPECTED:{data!r}")
except OSError:
    # Timeout (DROP) or ECONNREFUSED from an ICMP unreachable (REJECT). Both
    # mean the datagram did not get through, which is the whole question.
    print("BLOCKED")
finally:
    sock.close()
