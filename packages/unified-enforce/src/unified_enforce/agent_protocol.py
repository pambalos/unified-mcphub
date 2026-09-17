"""Agent-protocol ingress — build-14 S-5.

Inbound traffic to the customer's own MCP servers, agent endpoints and
model-serving APIs has a recognisable shape: a JSON-RPC body with an MCP
method, an A2A well-known path, an OpenAI-compatible completions route. When
that shape arrives from a peer that established no identity — the gateway's
deployment default, not an mTLS SAN, not a verified bearer — something nobody
enrolled is speaking agent to the fleet's agents.

This module names the shape. It never decides: policy still allows or
denies the request as it would have; what changes is that the gateway also
records a structural finding (`source="agent_protocol_unenrolled"`, the
protocol id as the resource) so the control plane can list it under
unauthorized agents and raise on it.
"""

from __future__ import annotations

import json
from typing import Any

MCP_METHODS = frozenset(
    {
        "initialize",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/read",
        "prompts/list",
        "prompts/get",
        "notifications/initialized",
        "ping",
    }
)
A2A_METHODS = frozenset(
    {"tasks/send", "tasks/get", "tasks/cancel", "message/send", "message/stream"}
)
A2A_PATHS = ("/.well-known/agent.json", "/.well-known/agent-card.json", "/a2a")
MODEL_PATHS = (
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/responses",
    "/v1/messages",
    "/v1/embeddings",
    "/api/generate",
    "/api/chat",
)


def _method_of(body: bytes | None, params: dict[str, Any]) -> str | None:
    if isinstance(params.get("method"), str) and params.get("jsonrpc"):
        return params["method"]
    if not body:
        return None
    try:
        doc = json.loads(body[:4096].decode("utf-8", "replace"))
    except (ValueError, TypeError):
        return None
    if isinstance(doc, dict) and doc.get("jsonrpc") and isinstance(doc.get("method"), str):
        return doc["method"]
    return None


def fingerprint(
    *, method: str, path: str, headers: dict[str, str], body: bytes | None, params: dict[str, Any]
) -> str | None:
    """`mcp`, `a2a`, `model-api`, or None."""
    p = path.split("?", 1)[0].rstrip("/") or "/"
    rpc = _method_of(body, params)
    if rpc in MCP_METHODS or "mcp-session-id" in headers or p.endswith(("/mcp", "/sse")):
        return "mcp"
    if rpc in A2A_METHODS or p in A2A_PATHS or p.endswith("/a2a"):
        return "a2a"
    if method.upper() == "POST" and any(p.endswith(m) for m in MODEL_PATHS):
        return "model-api"
    return None
