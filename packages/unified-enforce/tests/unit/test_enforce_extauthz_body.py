"""E3 §8: opt-in request-body inspection at the gateway.

This is what lets network-level policy say "no refund over $5,000" instead of
only "no POST to /v1/refunds". The interesting cases are the failures: a body
the engine cannot read must not quietly become an allow.
"""

import json

import pytest

from unified_enforce import (
    AuditChain,
    BodyInspection,
    CheckInput,
    Enforcer,
    ExtAuthzCore,
    PolicyEngine,
)
from unified_enforce.extauthz_grpc import check as grpc_check
from unified_enforce.protos import ext_authz_pb2 as pb

POLICY = """
version: 1
rules:
  - id: small-refunds
    match:
      principal: "agent:crew-*"
      tool: "https://payments.internal/v1/refunds"
      verb: post
    when: 'double(params.amount) <= 5000.0'
    effect: allow
  - id: reads-ok
    match: {tool: "https://api.internal/**", verb: get}
    effect: allow
"""

JSON = {"content-type": "application/json", "x-unified-principal": "agent:crew-1"}


def make_core(*, chain=None, inspection=BodyInspection(), **kwargs):
    return ExtAuthzCore(
        Enforcer(PolicyEngine.from_yaml(POLICY), chain=chain),
        body_inspection=inspection,
        **kwargs,
    )


def refund(body, *, headers=None, body_size=None):
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return CheckInput(
        principal_id="agent:crew-1",
        method="POST",
        host="payments.internal",
        path="/v1/refunds",
        headers=dict(headers if headers is not None else JSON),
        body=raw,
        body_size=body_size,
    )


# --- the capability itself ---


def test_body_populates_params_and_policy_decides_on_them():
    core = make_core()
    assert core.check(refund({"amount": 100})).allowed
    assert core.check(refund({"amount": 100})).action.params == {"amount": 100}


def test_policy_denies_on_a_value_inside_the_body():
    result = make_core().check(refund({"amount": 8000}))
    assert not result.allowed
    assert result.status_code == 403


def test_decimals_survive_as_exact_strings():
    """Floats break strict canonicalization (their repr is not portable), so
    the parser keeps the literal text. The digest must still compute."""
    result = make_core().check(refund({"amount": "4999.99"}))
    assert result.action.params["amount"] == "4999.99"
    assert len(result.action.digest()) == 64  # strict mode, would raise on a float


def test_a_decimal_amount_is_still_compared_numerically():
    assert make_core().check(refund({"amount": 4999.99})).allowed
    assert not make_core().check(refund({"amount": 5000.01})).allowed


def test_inspection_off_leaves_params_empty():
    """Default behaviour is unchanged: no buffering, no params, header rules only."""
    core = ExtAuthzCore(Enforcer(PolicyEngine.from_yaml(POLICY)))
    result = core.check(refund({"amount": 100}))
    assert result.action.params == {}
    assert not result.allowed  # the amount rule can't match without params


def test_a_request_with_no_body_is_not_a_failure():
    core = make_core()
    result = core.check(
        CheckInput(
            principal_id="agent:crew-1",
            method="GET",
            host="api.internal",
            path="/v1/users",
            headers={"x-unified-principal": "agent:crew-1"},
        )
    )
    assert result.allowed
    assert "body" not in result.action.context.extra


# --- unreadable bodies must fail closed ---


@pytest.mark.parametrize(
    "case,kwargs",
    [
        ("oversize", {"body": {"amount": 1, "pad": "x" * 200}}),
        ("unparseable", {"body": b"{not json"}),
        ("not_an_object", {"body": [1, 2, 3]}),
        (
            "unsupported_content_type",
            {"body": {"amount": 1}, "headers": {**JSON, "content-type": "application/xml"}},
        ),
        ("truncated", {"body": {"amount": 1}, "body_size": 10_000}),
    ],
)
def test_unreadable_body_denies_by_default(case, kwargs):
    core = make_core(inspection=BodyInspection(max_bytes=128))
    result = core.check(refund(**kwargs))
    assert not result.allowed, f"{case} should not be allowed"
    assert result.headers["x-unified-source"] == "body_unreadable"
    assert result.action.context.extra["body"] == case


def test_truncation_is_caught_even_when_the_prefix_parses():
    """A truncated body can still be valid JSON by luck — `{"amount": 1}` cut
    out of a larger document. Envoy's declared size is the only reliable tell,
    and without this check the request would be judged on a partial payload."""
    result = make_core().check(refund({"amount": 1}, body_size=9_999))
    assert not result.allowed
    assert result.action.context.extra["body"] == "truncated"


def test_ignore_mode_still_fails_closed_on_body_dependent_rules():
    """`ignore` does not mean "unsafe" — it means "let the policy engine decide".

    With no params, a rule whose CEL reads `params.amount` errors, and the
    engine's existing fail-closed rule turns that into a deny (condition_error)
    rather than skipping the rule. So the two modes differ in *which* layer
    refuses, not in whether one does: `deny` refuses structurally before the
    engine runs, `ignore` lets the condition fail.
    """
    core = make_core(inspection=BodyInspection(on_unreadable="ignore"))
    result = core.check(refund(b"{not json"))
    assert not result.allowed
    assert result.headers["x-unified-source"] == "condition_error"
    assert result.action.context.extra["body"] == "unparseable"


def test_ignore_mode_still_allows_what_header_rules_permit():
    core = make_core(inspection=BodyInspection(on_unreadable="ignore"))
    result = core.check(
        CheckInput(
            principal_id="agent:crew-1",
            method="GET",
            host="api.internal",
            path="/v1/users",
            headers={"content-type": "application/xml"},
            body=b"<x/>",
        )
    )
    assert result.allowed


def test_body_denials_are_chained_into_the_audit_log(tmp_path):
    """A structural deny is still evidence — it must not bypass the chain just
    because the policy engine never ran."""
    chain = AuditChain(tmp_path / "audit")
    chain.start()
    try:
        make_core(chain=chain).check(refund(b"{not json"))
    finally:
        chain.stop()
    payload = json.loads(next((tmp_path / "audit").glob("*.jsonl")).read_text().splitlines()[0])[
        "payload"
    ]
    assert payload["verdict"] == "deny"
    assert payload["source"] == "body_unreadable"
    assert payload["reason"] == "request body unparseable"
    assert payload["action"]["context"]["extra"]["body"] == "unparseable"


# --- transport wiring ---


def test_grpc_transport_carries_body_and_declared_size():
    req = pb.CheckRequest()
    http = req.attributes.request.http
    http.method, http.host, http.path, http.scheme = (
        "POST",
        "payments.internal",
        "/v1/refunds",
        "https",
    )
    http.headers["content-type"] = "application/json"
    http.headers["x-unified-principal"] = "agent:crew-1"
    http.body = json.dumps({"amount": 100}).encode().decode()
    http.size = len(http.body)
    assert grpc_check(make_core(), req).status.code == 0


def test_grpc_transport_reads_raw_body_when_packed_as_bytes():
    """Envoy uses raw_body instead of body when pack_as_bytes is set."""
    req = pb.CheckRequest()
    http = req.attributes.request.http
    http.method, http.host, http.path, http.scheme = (
        "POST",
        "payments.internal",
        "/v1/refunds",
        "https",
    )
    http.headers["content-type"] = "application/json"
    http.headers["x-unified-principal"] = "agent:crew-1"
    http.raw_body = json.dumps({"amount": 100}).encode()
    http.size = len(http.raw_body)
    assert grpc_check(make_core(), req).status.code == 0


def test_grpc_transport_detects_envoy_truncation():
    req = pb.CheckRequest()
    http = req.attributes.request.http
    http.method, http.host, http.path, http.scheme = (
        "POST",
        "payments.internal",
        "/v1/refunds",
        "https",
    )
    http.headers["content-type"] = "application/json"
    http.headers["x-unified-principal"] = "agent:crew-1"
    http.raw_body = json.dumps({"amount": 100}).encode()
    http.size = 50_000  # Envoy saw a much larger request than it forwarded
    resp = grpc_check(make_core(), req)
    assert resp.status.code == 7  # PERMISSION_DENIED


def test_http_transport_reads_the_body():
    from fastapi.testclient import TestClient

    from unified_enforce import create_http_service

    client = TestClient(create_http_service(make_core()))
    ok = client.post(
        "/v1/refunds",
        json={"amount": 100},
        headers={"host": "payments.internal", "x-unified-principal": "agent:crew-1"},
    )
    assert ok.status_code == 200
    too_big = client.post(
        "/v1/refunds",
        json={"amount": 9000},
        headers={"host": "payments.internal", "x-unified-principal": "agent:crew-1"},
    )
    assert too_big.status_code == 403
