#!/usr/bin/env bash
# VM / bare-metal / air-gapped egress lock — unified-enforce E3.
#
# Model: the agent process runs as AGENT_UID, the Envoy sidecar as PROXY_UID.
# Only PROXY_UID may open outbound connections; the agent's traffic is
# redirected into Envoy, and anything it tries to send directly is dropped.
# This is the owner-match pattern used by service meshes, minus the mesh.
#
#   sudo AGENT_UID=1001 PROXY_UID=1337 ./iptables-sidecar.sh
#
# Idempotent: the UNIFIED_OUTPUT chain is flushed and rebuilt on each run.
# Removing the lock: iptables -t nat -F UNIFIED_OUTPUT && iptables -F UNIFIED_EGRESS
set -euo pipefail

: "${AGENT_UID:?set AGENT_UID (the uid the agent runs as)}"
: "${PROXY_UID:?set PROXY_UID (the uid Envoy runs as)}"
PROXY_PORT="${PROXY_PORT:-10000}"
DNS_SERVER="${DNS_SERVER:-}"   # optional: pin resolution to one resolver

# --- redirect the agent's TCP egress into Envoy -------------------------------
iptables -t nat -N UNIFIED_OUTPUT 2>/dev/null || iptables -t nat -F UNIFIED_OUTPUT
iptables -t nat -C OUTPUT -j UNIFIED_OUTPUT 2>/dev/null \
  || iptables -t nat -A OUTPUT -j UNIFIED_OUTPUT

# Envoy's own traffic must not be redirected back into itself.
iptables -t nat -A UNIFIED_OUTPUT -m owner --uid-owner "$PROXY_UID" -j RETURN
# Loopback stays local (the agent talking to its own sidecar/health endpoints).
iptables -t nat -A UNIFIED_OUTPUT -o lo -j RETURN
# Everything else the agent sends goes to Envoy.
iptables -t nat -A UNIFIED_OUTPUT -p tcp -m owner --uid-owner "$AGENT_UID" \
  -j REDIRECT --to-port "$PROXY_PORT"

# --- drop anything that escapes the redirect ----------------------------------
# Redirect only covers TCP; UDP/QUIC/raw sockets would otherwise bypass the
# plane entirely. This chain is what makes enforcement mandatory.
iptables -N UNIFIED_EGRESS 2>/dev/null || iptables -F UNIFIED_EGRESS
iptables -C OUTPUT -j UNIFIED_EGRESS 2>/dev/null \
  || iptables -A OUTPUT -j UNIFIED_EGRESS

iptables -A UNIFIED_EGRESS -o lo -j RETURN
# The redirected traffic has to survive this chain, and `-o lo` does not catch
# it: REDIRECT rewrites the destination to 127.0.0.1, but the packet arrives
# here still carrying its ORIGINAL output interface, so the rule above matches
# nothing and the catch-all DROP at the bottom eats every redirected
# connection. The agent could then reach neither the upstream nor its own
# sidecar — fail-closed, but completely non-functional. Match on the
# destination instead, which is what the REDIRECT actually changed. This grants
# nothing new: loopback-destined traffic cannot leave the host, which is
# exactly what `-o lo` above already intends to allow.
iptables -A UNIFIED_EGRESS -d 127.0.0.0/8 -j RETURN
iptables -A UNIFIED_EGRESS -m owner --uid-owner "$PROXY_UID" -j RETURN
if [ -n "$DNS_SERVER" ]; then
  iptables -A UNIFIED_EGRESS -m owner --uid-owner "$AGENT_UID" \
    -p udp --dport 53 -d "$DNS_SERVER" -j RETURN
else
  iptables -A UNIFIED_EGRESS -m owner --uid-owner "$AGENT_UID" \
    -p udp --dport 53 -j RETURN
fi
# QUIC/HTTP3 must be blocked explicitly: it is UDP, so REDIRECT never saw it,
# and a client that silently upgrades would leave the plane behind.
iptables -A UNIFIED_EGRESS -m owner --uid-owner "$AGENT_UID" \
  -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
iptables -A UNIFIED_EGRESS -m owner --uid-owner "$AGENT_UID" -j DROP

echo "egress lock installed: uid $AGENT_UID -> envoy :$PROXY_PORT (uid $PROXY_UID)"
echo "verify: sudo -u '#${AGENT_UID}' curl -sS --max-time 5 https://example.com  # must NOT connect directly"
