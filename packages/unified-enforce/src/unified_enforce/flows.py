"""Flow export — `flow.v1` from the gateway's own view (build-14 S-2).

The control plane's network sensor needs egress flows: who connected, to
what name and port, how much, and what the boundary did. The ext_authz
gateway already sees every connection and every request it decides on, so it
is the cheapest exporter there is — no log tailing, no second agent. Each
check emits one record; a second `EvidenceShipper`, pointed at
`/api/v1/evidence/flows`, spools and ships them exactly as decisions are.

Facts only. A record carries the source, the destination name (the SNI the
client claimed, or the address) and port, the protocol, the verdict, and a
time. Never a payload, never a header, never a path — the control plane
refuses those by name, and this module never builds them.

The digest is deterministic over the tuple and the second, so a retried
batch and a connection that produced two checks in the same second collapse
to one record at the receiver.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from .evidence import EvidenceShipper, HttpSink
from .policy import Decision, Verdict

if TYPE_CHECKING:
    from .extauthz import CheckInput, ConnInput

FLOWS_PATH = "/api/v1/evidence/flows"
FLOWS_FIELD = "flows"


def flow_shipper(
    base_url: str, credential: str, *, channel: Any = None, **kwargs: Any
) -> EvidenceShipper:
    """A shipper for flows: the decisions shipper's sink, on the flows path."""
    sink = HttpSink(base_url, credential, path=FLOWS_PATH, field=FLOWS_FIELD, channel=channel)
    return EvidenceShipper(sink, **kwargs)


def _verdict(decision: Decision) -> str:
    return "allowed" if decision.verdict is Verdict.ALLOW else "denied"


def _digest(*parts: object) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()


def from_connection(
    conn: ConnInput, decision: Decision, *, now: datetime | None = None
) -> dict[str, Any]:
    """One L4 connection as a flow. The destination name is the SNI when the
    client claimed one — the control plane's endpoint list is keyed on names —
    and the literal address otherwise."""
    at = (now or datetime.now(UTC)).replace(microsecond=0)
    source = conn.source_address or conn.principal_id
    dst_host = conn.sni or conn.destination_address
    return {
        "digest": _digest(
            "tcp", source, dst_host, conn.destination_port, conn.principal_id, at.isoformat()
        ),
        "source": source,
        "dst_host": dst_host,
        "dst_port": conn.destination_port,
        "protocol": "tcp",
        "bytes": 0,
        "verdict": _verdict(decision),
        "seen_at": at.isoformat(),
    }


def _authority(authority: str, *, default: int) -> tuple[str, int]:
    """`host[:port]`, including the bracketed IPv6 form (`[::1]:8080`), which
    a split on the first colon turns into a host of `[`."""
    try:
        parts = urlsplit(f"//{authority}")
        host, port = parts.hostname or "", parts.port
    except ValueError:
        return authority.lower(), default
    return host.lower(), port if port is not None else default


def from_request(
    req: CheckInput, decision: Decision, *, now: datetime | None = None
) -> dict[str, Any]:
    """One HTTP request as a flow: the authority and the scheme's port. The
    path and headers are deliberately not here."""
    at = (now or datetime.now(UTC)).replace(microsecond=0)
    host, port = _authority(req.host or "", default=443 if req.scheme == "https" else 80)
    source = req.headers.get("x-forwarded-for", "").split(",")[0].strip() or req.principal_id
    return {
        "digest": _digest("http", source, host, port, req.principal_id, at.isoformat()),
        "source": source,
        "dst_host": host,
        "dst_port": port,
        "protocol": "tcp",
        "bytes": int(req.body_size or 0),
        "verdict": _verdict(decision),
        "seen_at": at.isoformat(),
    }
