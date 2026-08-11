"""E3 scaffold: ext_authz core mapping + Envoy HTTP-service transport."""

import pytest
from fastapi.testclient import TestClient

from unified_enforce import (
    AuditChain,
    CheckInput,
    Enforcer,
    ExtAuthzCore,
    PolicyEngine,
    create_http_service,
)

POLICY = """
version: 1
rules:
  - id: api-reads-ok
    match: {principal: "agent:crew-*", tool: "https://api.internal/**", verb: get}
    effect: allow
  - id: payouts-need-human
    match: {tool: "https://payments.internal/v1/payouts**", verb: post}
    effect: defer
"""


def core(chain=None):
    return ExtAuthzCore(Enforcer(PolicyEngine.from_yaml(POLICY), chain=chain))


def check(
    c, method="GET", host="api.internal", path="/v1/users", principal="agent:crew-1", headers=None
):
    return c.check(
        CheckInput(
            principal_id=principal,
            method=method,
            host=host,
            path=path,
            headers=headers or {},
        )
    )


# --- core mapping ---


def test_allow_maps_to_200_with_headers():
    r = check(core())
    assert r.allowed and r.status_code == 200
    assert r.headers["x-unified-verdict"] == "allow"
    assert r.headers["x-unified-rule"] == "api-reads-ok"
    assert len(r.headers["x-unified-action-digest"]) == 64
    assert r.action.tool == "https://api.internal/v1/users"
    assert r.action.verb == "get"
    assert r.action.context.origin == "gateway"


def test_default_deny_maps_to_403():
    r = check(core(), host="evil.example", path="/exfil")
    assert not r.allowed and r.status_code == 403
    assert r.headers["x-unified-verdict"] == "deny"
    assert r.headers["x-unified-source"] == "default"
    assert "x-unified-rule" not in r.headers


def test_defer_fails_closed_to_403():
    r = check(core(), method="POST", host="payments.internal", path="/v1/payouts")
    assert not r.allowed and r.status_code == 403
    assert r.headers["x-unified-verdict"] == "defer"
    assert r.headers["x-unified-rule"] == "payouts-need-human"


def test_traceparent_propagates_into_action_context():
    tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
    r = check(core(), headers={"traceparent": tp})
    assert r.action.context.trace_id == "0af7651916cd43dd8448eb211c80319c"
    assert r.action.context.span_id == "b7ad6b7169203331"
    malformed = check(core(), headers={"traceparent": "junk"})
    assert malformed.action.context.trace_id is None


def test_decisions_land_in_the_chain(tmp_path):
    chain = AuditChain(tmp_path / "audit")
    chain.start()
    try:
        check(core(chain))
        check(core(chain), host="evil.example", path="/exfil")
    finally:
        chain.stop()
    assert AuditChain.verify(tmp_path / "audit").ok
    import json

    entries = [
        json.loads(line)
        for p in sorted((tmp_path / "audit").glob("*.jsonl"))
        for line in p.read_text().splitlines()
    ]
    assert [e["payload"]["verdict"] for e in entries] == ["allow", "deny"]
    assert entries[0]["payload"]["action"]["context"]["origin"] == "gateway"


# --- HTTP transport (Envoy http_service protocol) ---


@pytest.fixture
def client():
    return TestClient(create_http_service(core()), raise_server_exceptions=True)


def test_http_allow(client):
    resp = client.get(
        "/v1/users",
        headers={"host": "api.internal", "x-unified-principal": "agent:crew-1"},
    )
    assert resp.status_code == 200
    assert resp.headers["x-unified-verdict"] == "allow"


def test_http_deny_carries_reason_headers(client):
    resp = client.post(
        "/v1/payouts",
        headers={"host": "payments.internal", "x-unified-principal": "agent:crew-1"},
    )
    assert resp.status_code == 403
    assert resp.headers["x-unified-verdict"] == "defer"
    assert "unified-enforce" in resp.text


def test_http_missing_principal_is_unknown_and_denied(client):
    # No x-unified-principal → agent:unknown → outside agent:crew-* → default deny.
    resp = client.get("/v1/users", headers={"host": "api.internal"})
    assert resp.status_code == 403
    assert resp.headers["x-unified-source"] == "default"


def test_http_forwarded_host_wins(client):
    resp = client.get(
        "/v1/users",
        headers={
            "host": "sidecar-internal:9002",
            "x-forwarded-host": "api.internal",
            "x-unified-principal": "agent:crew-1",
        },
    )
    assert resp.status_code == 200
