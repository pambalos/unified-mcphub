# A stand-in for an agent host: the agent and its Envoy sidecar as two uids on
# one machine, which is the topology deploy/egress/iptables-sidecar.sh locks
# down. Needs NET_ADMIN at run time to install the rules.
FROM alpine:3.20

# iptables + the owner match the script depends on; su-exec to run processes as
# a specific uid; python3 for the sidecar and the UDP probes (busybox nc has
# awkward UDP semantics and would make the assertions about the wrong thing).
RUN apk add --no-cache iptables ip6tables curl su-exec python3 bash

# The two identities the whole owner-match design turns on.
RUN adduser -D -u 1001 agent && adduser -D -u 1337 proxy

COPY sidecar.py /opt/sidecar.py
COPY udp_probe.py /opt/udp_probe.py

CMD ["sleep", "infinity"]
