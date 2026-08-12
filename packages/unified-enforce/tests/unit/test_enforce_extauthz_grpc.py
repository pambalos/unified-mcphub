"""E3: Envoy ext_authz gRPC transport (envoy.service.auth.v3.Authorization)."""

import json

import grpc
import pytest

from unified_enforce import AuditChain, Enforcer, ExtAuthzCore, PolicyEngine
from unified_enforce.extauthz_grpc import SERVICE_NAME, check, create_grpc_server
from unified_enforce.protos import ext_authz_pb2 as pb

OK = 0  # google.rpc.Code.OK
PERMISSION_DENIED = 7

POLICY = """
version: 1
rules:
  - id: api-reads-ok
    match: {principal: "agent:crew-*", tool: "https://api.internal/**", verb: get}
    effect: allow
  - id: spiffe-writes-ok
    match:
      principal: "spiffe://cluster.local/ns/prod/sa/*"
      tool: "https://api.internal/**"
      verb: post
    effect: allow
  - id: payouts-need-human
    match: {tool: "https://payments.internal/v1/payouts**", verb: post}
    effect: defer
"""


def make_core(chain=None, **kwargs):
    return ExtAuthzCore(Enforcer(PolicyEngine.from_yaml(POLICY), chain=chain), **kwargs)


def request(method="GET", host="api.internal", path="/v1/users", headers=None, mtls=None):
    req = pb.CheckRequest()
    http = req.attributes.request.http
    http.method = method
    http.host = host
    http.path = path
    http.scheme = "https"
    for k, v in (headers or {"x-unified-principal": "agent:crew-1"}).items():
        http.headers[k] = v
    if mtls:
        req.attributes.source.principal = mtls
    return req


def headers_of(resp, denied: bool):
    block = resp.denied_response if denied else resp.ok_response
    return {h.header.key: h.header.value for h in block.headers}


# --- decision mapping ---


def test_allow_returns_ok_status_and_headers():
    resp = check(make_core(), request())
    assert resp.status.code == OK
    assert resp.HasField("ok_response")
    h = headers_of(resp, denied=False)
    assert h["x-unified-verdict"] == "allow"
    assert h["x-unified-rule"] == "api-reads-ok"
    assert len(h["x-unified-action-digest"]) == 64


def test_deny_returns_permission_denied_and_403():
    resp = check(make_core(), request(host="evil.example", path="/exfil"))
    assert resp.status.code == PERMISSION_DENIED
    assert resp.denied_response.status.code == 403
    assert headers_of(resp, denied=True)["x-unified-source"] == "default"
    assert "unified-enforce" in resp.denied_response.body


def test_defer_fails_closed_at_the_gateway():
    resp = check(make_core(), request(method="POST", host="payments.internal", path="/v1/payouts"))
    assert resp.status.code == PERMISSION_DENIED
    assert headers_of(resp, denied=True)["x-unified-verdict"] == "defer"


# --- principal trust (spec §3) ---


def test_mtls_san_outranks_header():
    # Header claims a different identity; the SPIFFE SAN wins and policy matches it.
    resp = check(
        make_core(),
        request(
            method="POST",
            headers={"x-unified-principal": "agent:crew-1"},
            mtls="spiffe://cluster.local/ns/prod/sa/writer",
        ),
    )
    assert resp.status.code == OK
    assert headers_of(resp, denied=False)["x-unified-rule"] == "spiffe-writes-ok"


def test_untrusted_header_falls_back_to_default_principal():
    # Sidecar mode: header ignored, identity is the configured default.
    core = make_core(default_principal="agent:crew-9", trust_principal_header=False)
    resp = check(core, request(headers={"x-unified-principal": "agent:admin"}))
    assert resp.status.code == OK  # agent:crew-9 matches agent:crew-*
    assert headers_of(resp, denied=False)["x-unified-rule"] == "api-reads-ok"


def test_spoofed_header_cannot_impersonate_when_untrusted():
    core = make_core(default_principal="agent:nobody", trust_principal_header=False)
    resp = check(core, request(headers={"x-unified-principal": "agent:crew-1"}))
    assert resp.status.code == PERMISSION_DENIED


def test_traceparent_reaches_the_action_via_grpc(tmp_path):
    chain = AuditChain(tmp_path / "audit")
    chain.start()
    try:
        check(
            make_core(chain),
            request(
                headers={
                    "x-unified-principal": "agent:crew-1",
                    "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
                }
            ),
        )
    finally:
        chain.stop()
    entry = json.loads(next((tmp_path / "audit").glob("*.jsonl")).read_text().splitlines()[0])
    ctx = entry["payload"]["action"]["context"]
    assert ctx["origin"] == "gateway"
    assert ctx["trace_id"] == "0af7651916cd43dd8448eb211c80319c"


# --- real server round trip over the exact path Envoy dials ---


@pytest.fixture
def grpc_channel():
    server = create_grpc_server(make_core(), "127.0.0.1:0")
    server.start()
    channel = grpc.insecure_channel(f"127.0.0.1:{server.bound_port}")
    yield channel
    channel.close()
    server.stop(None)


def test_end_to_end_over_the_envoy_method_path(grpc_channel):
    # Dial the literal path Envoy uses. If the service name ever drifts from
    # envoy.service.auth.v3.Authorization, Envoy gets UNIMPLEMENTED and (with
    # failure_mode_allow: false) every request dies — so pin it here.
    rpc = grpc_channel.unary_unary(
        f"/{SERVICE_NAME}/Check",
        request_serializer=pb.CheckRequest.SerializeToString,
        response_deserializer=pb.CheckResponse.FromString,
    )
    assert SERVICE_NAME == "envoy.service.auth.v3.Authorization"

    allowed = rpc(request(), timeout=5)
    assert allowed.status.code == OK

    denied = rpc(request(host="evil.example", path="/exfil"), timeout=5)
    assert denied.status.code == PERMISSION_DENIED
    assert denied.denied_response.status.code == 403


def test_unknown_method_is_unimplemented(grpc_channel):
    rpc = grpc_channel.unary_unary(
        "/envoy.service.auth.v3.Authorization/Nope",
        request_serializer=pb.CheckRequest.SerializeToString,
        response_deserializer=pb.CheckResponse.FromString,
    )
    with pytest.raises(grpc.RpcError) as exc:
        rpc(request(), timeout=5)
    assert exc.value.code() is grpc.StatusCode.UNIMPLEMENTED
