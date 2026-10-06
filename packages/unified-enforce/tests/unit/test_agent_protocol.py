"""S-5: agent-protocol ingress from peers nobody enrolled — build-14."""

from __future__ import annotations

import json

from unified_enforce import CheckInput, Enforcer, ExtAuthzCore, PolicyEngine, agent_protocol

POLICY = """
version: 1
rules:
  - id: mcp-open
    match: {tool: "https://tools.acme.internal/**"}
    effect: allow
counters:
  - id: calls
"""


class Collecting:
    def __init__(self) -> None:
        self.records: list[tuple] = []
        self.on_receipt = None

    def record(self, action, decision, *, entry=None) -> None:
        self.records.append((action, decision))


def core(evidence, **kw):
    return ExtAuthzCore(
        Enforcer(PolicyEngine.from_yaml(POLICY), evidence=evidence),
        default_principal="agent:unknown",
        **kw,
    )


def rpc(method: str) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}).encode()


def fp(**kw):
    base = {"method": "POST", "path": "/", "headers": {}, "body": None, "params": {}}
    base.update(kw)
    return agent_protocol.fingerprint(**base)


# --- the fingerprint ------------------------------------------------------------


def test_mcp_by_method_header_or_path():
    assert fp(body=rpc("initialize")) == "mcp"
    assert fp(body=rpc("tools/call")) == "mcp"
    assert fp(headers={"mcp-session-id": "x"}) == "mcp"
    assert fp(path="/servers/files/mcp", method="GET") == "mcp"
    assert fp(path="/events/sse", method="GET") == "mcp"
    assert fp(params={"jsonrpc": "2.0", "method": "tools/list"}) == "mcp"


def test_a2a_and_model_api():
    assert fp(path="/.well-known/agent.json", method="GET") == "a2a"
    assert fp(body=rpc("tasks/send")) == "a2a"
    assert fp(path="/v1/chat/completions") == "model-api"
    assert fp(path="/v1/messages?beta=1") == "model-api"
    assert fp(path="/v1/messages", method="GET") is None, "a GET is not a completion"


def test_ordinary_traffic_is_none():
    assert fp(path="/api/orders", body=b'{"id": 3}') is None
    assert fp(body=b"not json") is None
    assert fp(body=rpc("orders/create")) is None, "JSON-RPC that is not an agent method"


# --- the finding -------------------------------------------------------------------


def _req(principal="agent:unknown", **kw):
    base = {
        "principal_id": principal,
        "method": "POST",
        "host": "tools.acme.internal",
        "path": "/mcp",
        "headers": {},
        "body": rpc("tools/call"),
    }
    base.update(kw)
    return CheckInput(**base)


def test_an_unenrolled_peer_speaking_mcp_is_a_finding_beside_the_verdict():
    ev = Collecting()
    result = core(ev).check(_req())
    assert result.allowed, "policy allowed it; the finding is not a deny"
    findings = [(a, d) for a, d in ev.records if d.source == "agent_protocol_unenrolled"]
    assert len(findings) == 1
    action, decision = findings[0]
    assert action.principal.id == "agent:unknown"
    assert action.verb == "ingress" and action.resource == "mcp"
    assert action.tool == "https://tools.acme.internal/mcp"
    assert decision.verdict.value == "allow"
    assert "no identity" in (decision.reason or "")
    assert result.action.context.extra["agent_protocol"] == "mcp"


def test_an_enrolled_peer_is_not_a_finding():
    ev = Collecting()
    core(ev).check(_req(principal="agent:crew-1", attestation="derived"))
    assert not [d for _, d in ev.records if d.source == "agent_protocol_unenrolled"]


def test_a_failed_credential_speaking_a2a_is_a_finding_too():
    ev = Collecting()
    result = core(ev).check(
        _req(path="/a2a", body=rpc("message/send"), identity_problem="token expired")
    )
    assert not result.allowed, "a failed credential is a structural deny, as before"
    sources = [d.source for _, d in ev.records]
    assert "identity_invalid" in sources and "agent_protocol_unenrolled" in sources
    (finding,) = [a for a, d in ev.records if d.source == "agent_protocol_unenrolled"]
    assert finding.resource == "a2a"


def test_ordinary_unenrolled_traffic_records_no_protocol_finding():
    ev = Collecting()
    core(ev).check(_req(path="/api/orders", body=b'{"id": 1}'))
    assert not [d for _, d in ev.records if d.source == "agent_protocol_unenrolled"]


def test_the_finding_is_not_charged_to_the_counters():
    """The request was counted when it was decided. The finding beside it,
    with the default `tool: *` / `verb: *` counter match, must not count it
    again — or a rate floor trips at half its rate for unenrolled traffic."""
    ev = Collecting()
    c = core(ev)
    c.check(_req())
    assert c._enforcer.counters.snapshot("agent:unknown", ["calls"])["calls"]["day"] == 1.0


# --- the method comes from the prefix, not from a parse ------------------------------


def test_the_method_is_read_from_a_body_larger_than_the_prefix():
    """A `tools/call` with real arguments is far past 4 KiB. A prefix never
    parses as a document, so parsing missed every such body."""
    big = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "write", "arguments": {"content": "x" * 20_000}},
    }
    assert fp(body=json.dumps(big).encode(), path="/rpc") == "mcp"
    a2a = {"jsonrpc": "2.0", "id": 1, "method": "tasks/send", "params": {"text": "y" * 20_000}}
    assert fp(body=json.dumps(a2a).encode(), path="/agent") == "a2a"


def test_a_method_without_jsonrpc_is_not_a_protocol():
    assert fp(body=b'{"method": "tools/call"}', path="/rpc") is None
    assert fp(body=b'{"jsonrpc": "1.0", "method": "tools/call"}', path="/rpc") is None
    assert fp(body=b"jsonrpc 2.0 method tools/call", path="/rpc") is None
