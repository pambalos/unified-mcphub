"""E3.5: connection-level (L4) ext_authz — the network filter's half of the
gateway. Same RPC as the HTTP filter, distinguished on the wire by an absent
`attributes.request.http`; same core, so a verdict cannot differ by transport.
"""

from unified_enforce import ConnInput, Enforcer, ExtAuthzCore, PolicyEngine
from unified_enforce.extauthz_grpc import check
from unified_enforce.protos import ext_authz_pb2 as pb

OK = 0
PERMISSION_DENIED = 7

POLICY = """
version: 1
rules:
  - id: postgres-ok
    match: {principal: "agent:crew-*", tool: "tcp://10.0.5.10:5432", verb: connect}
    effect: allow
  - id: vault-by-sni
    match: {principal: "agent:crew-*", tool: "tcp://10.0.9.*:443", verb: connect}
    when: 'params.sni == "vault.internal"'
    effect: allow
"""


def make_core(**kwargs):
    return ExtAuthzCore(Enforcer(PolicyEngine.from_yaml(POLICY)), **kwargs)


def conn_request(dest="10.0.5.10", port=5432, source="10.0.1.7", mtls=None, sni=None):
    req = pb.CheckRequest()
    d = req.attributes.destination.address.socket_address
    d.address = dest
    d.port_value = port
    s = req.attributes.source.address.socket_address
    s.address = source
    if mtls:
        req.attributes.source.principal = mtls
    if sni:
        req.attributes.tls_session.sni = sni
    return req


def headers_of(resp, denied: bool):
    block = resp.denied_response if denied else resp.ok_response
    return {h.header.key: h.header.value for h in block.headers}


# --- verdict mapping over the wire shape the network filter sends ---


def test_allowed_connection(tmp_path):
    resp = check(make_core(default_principal="agent:crew-1"), conn_request())
    assert resp.status.code == OK
    h = headers_of(resp, denied=False)
    assert h["x-unified-verdict"] == "allow"
    assert h["x-unified-rule"] == "postgres-ok"
    assert len(h["x-unified-action-digest"]) == 64


def test_unlisted_destination_is_denied():
    resp = check(make_core(default_principal="agent:crew-1"), conn_request(port=6379))
    assert resp.status.code == PERMISSION_DENIED
    assert headers_of(resp, denied=True)["x-unified-source"] == "default"


def test_default_principal_is_the_identity_at_l4():
    # No header exists at L4 to fall back on: an unconfigured sidecar is
    # agent:unknown, which matches no rule — deny by default, not by accident.
    resp = check(make_core(), conn_request())
    assert resp.status.code == PERMISSION_DENIED


def test_mtls_san_outranks_the_default():
    core = make_core(default_principal="agent:crew-1")
    resp = check(core, conn_request(mtls="spiffe://cluster.local/ns/dev/sa/other"))
    assert resp.status.code == PERMISSION_DENIED, (
        "the SAN identity must win, and it matches nothing"
    )


def test_sni_is_matchable_but_does_not_rename_the_tool():
    core = make_core(default_principal="agent:crew-1")
    allowed = check(core, conn_request(dest="10.0.9.3", port=443, sni="vault.internal"))
    assert allowed.status.code == OK
    assert headers_of(allowed, denied=False)["x-unified-rule"] == "vault-by-sni"

    spoofless = check(core, conn_request(dest="10.0.9.3", port=443))
    assert spoofless.status.code == PERMISSION_DENIED, "no SNI, no params.sni, no match"

    wrong = check(core, conn_request(dest="10.0.9.3", port=443, sni="other.internal"))
    assert wrong.status.code == PERMISSION_DENIED


def test_missing_destination_is_denied_by_construction():
    req = pb.CheckRequest()  # neither http nor destination: nothing to decide about
    resp = check(make_core(default_principal="agent:crew-1"), req)
    assert resp.status.code == PERMISSION_DENIED


def test_l4_action_shape_cannot_collide_with_l7_rules():
    core = make_core(default_principal="agent:crew-1")
    result = core.check_connection(
        ConnInput(
            principal_id="agent:crew-1", destination_address="10.0.5.10", destination_port=5432
        )
    )
    assert result.action.tool == "tcp://10.0.5.10:5432"
    assert result.action.verb == "connect"
