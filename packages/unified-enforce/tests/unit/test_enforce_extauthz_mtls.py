"""E3 §8: mTLS between Envoy and the engine.

Real certificates, a real TLS handshake, and a real gRPC server — the security
property here is entirely about what the transport refuses, so a mocked
handshake would test nothing. The throwaway PKI comes from `tests/conftest.py`,
shared with the real-Envoy integration suite.
"""

import grpc
import pytest

from unified_enforce import Enforcer, ExtAuthzCore, PolicyEngine
from unified_enforce.extauthz_grpc import SERVICE_NAME, ServerTLS, create_grpc_server
from unified_enforce.protos import ext_authz_pb2 as pb

OK = 0
POLICY = """
version: 1
rules:
  - id: reads-ok
    match: {principal: "agent:crew-*", tool: "https://api.internal/**", verb: get}
    effect: allow
"""


def request(host="api.internal", path="/v1/users"):
    req = pb.CheckRequest()
    http = req.attributes.request.http
    http.method = "GET"
    http.host = host
    http.path = path
    http.scheme = "https"
    http.headers["x-unified-principal"] = "agent:crew-1"
    return req


def core():
    return ExtAuthzCore(Enforcer(PolicyEngine.from_yaml(POLICY)))


def rpc_on(channel):
    return channel.unary_unary(
        f"/{SERVICE_NAME}/Check",
        request_serializer=pb.CheckRequest.SerializeToString,
        response_deserializer=pb.CheckResponse.FromString,
    )


@pytest.fixture
def mtls_server(pki):
    server_key, server_cert = pki["server"]
    server = create_grpc_server(
        core(),
        "127.0.0.1:0",
        tls=ServerTLS(
            certificate_chain=server_cert,
            private_key=server_key,
            client_ca=pki["ca"],
            require_client_auth=True,
        ),
    )
    server.start()
    yield server
    server.stop(None)


# --- configuration guardrails ---


def test_require_client_auth_without_a_ca_is_refused():
    # grpc would silently accept unauthenticated clients here, so the mistake
    # has to fail loudly at construction rather than at the first handshake.
    with pytest.raises(ValueError, match="client_ca"):
        ServerTLS(certificate_chain=b"cert", private_key=b"key", require_client_auth=True)


def test_server_only_tls_is_allowed_when_explicit():
    tls = ServerTLS(certificate_chain=b"cert", private_key=b"key", require_client_auth=False)
    assert tls.client_ca is None


def test_from_files_reads_pem_material(tmp_path, pki):
    server_key, server_cert = pki["server"]
    (tmp_path / "tls.crt").write_bytes(server_cert)
    (tmp_path / "tls.key").write_bytes(server_key)
    (tmp_path / "ca.crt").write_bytes(pki["ca"])
    tls = ServerTLS.from_files(
        tmp_path / "tls.crt", tmp_path / "tls.key", client_ca=tmp_path / "ca.crt"
    )
    assert tls.certificate_chain == server_cert
    assert tls.client_ca == pki["ca"]


# --- the handshake itself ---


def test_client_with_a_trusted_cert_gets_a_verdict(mtls_server, pki):
    client_key, client_cert = pki["client"]
    creds = grpc.ssl_channel_credentials(
        root_certificates=pki["ca"], private_key=client_key, certificate_chain=client_cert
    )
    with grpc.secure_channel(f"localhost:{mtls_server.bound_port}", creds) as channel:
        assert rpc_on(channel)(request(), timeout=10).status.code == OK


def test_client_without_a_cert_is_rejected(mtls_server, pki):
    """The point of mutual TLS: a local process that is not the sidecar cannot
    ask for verdicts, even though it can reach the socket."""
    creds = grpc.ssl_channel_credentials(root_certificates=pki["ca"])
    with grpc.secure_channel(f"localhost:{mtls_server.bound_port}", creds) as channel:
        with pytest.raises(grpc.RpcError):
            rpc_on(channel)(request(), timeout=10)


def test_client_with_an_untrusted_cert_is_rejected(mtls_server, pki):
    rogue_key, rogue_cert = pki["rogue"]
    creds = grpc.ssl_channel_credentials(
        root_certificates=pki["ca"], private_key=rogue_key, certificate_chain=rogue_cert
    )
    with grpc.secure_channel(f"localhost:{mtls_server.bound_port}", creds) as channel:
        with pytest.raises(grpc.RpcError):
            rpc_on(channel)(request(), timeout=10)


def test_plaintext_client_cannot_reach_a_tls_listener(mtls_server):
    with grpc.insecure_channel(f"127.0.0.1:{mtls_server.bound_port}") as channel:
        with pytest.raises(grpc.RpcError):
            rpc_on(channel)(request(), timeout=10)


def test_insecure_server_still_works_without_tls():
    """TLS is opt-in; the loopback sidecar deployment must not need certs."""
    server = create_grpc_server(core(), "127.0.0.1:0")
    server.start()
    try:
        with grpc.insecure_channel(f"127.0.0.1:{server.bound_port}") as channel:
            assert rpc_on(channel)(request(), timeout=10).status.code == OK
    finally:
        server.stop(None)
