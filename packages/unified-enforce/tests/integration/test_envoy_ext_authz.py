"""End-to-end: real Envoy enforcing our ext_authz verdicts. E3, spec §1/§4/§8.

This is the test that proves the vendored minimal protos are wire-compatible
with Envoy — we no longer link Envoy's generated stubs, so nothing else does.
It also proves the shipped templates parse against Envoy's schema, that
`failure_mode_allow: false` really denies when the engine dies, and that the
mTLS listener actually interoperates with Envoy's TLS client.

Requires Docker (skipped otherwise) and pulls envoyproxy/envoy on first run:

    uv run pytest packages/unified-enforce/tests/integration -m integration
"""

from __future__ import annotations

import http.server
import json
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from unified_enforce import BodyInspection, Enforcer, ExtAuthzCore, PolicyEngine
from unified_enforce.extauthz_grpc import ServerTLS, create_grpc_server

pytestmark = pytest.mark.integration

ENVOY_IMAGE = "envoyproxy/envoy:v1.31-latest"
DEPLOY = Path(__file__).resolve().parents[2] / "deploy"

POLICY = """
version: 1
rules:
  - id: api-reads-ok
    match: {principal: "agent:crew-*", tool: "http://*/v1/users**", verb: get}
    effect: allow
  - id: small-refunds
    match: {principal: "agent:crew-*", tool: "http://*/v1/refunds", verb: post}
    when: 'double(params.amount) <= 5000.0'
    effect: allow
  - id: payouts-need-a-human
    match: {tool: "http://*/v1/payouts", verb: get}
    effect: defer
"""


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True, timeout=60).returncode == 0


requires_docker = pytest.mark.skipif(not _docker_ok(), reason="docker daemon not available")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _wait_for(url: str, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2)
            return
        except urllib.error.HTTPError:
            return  # any HTTP status means the listener is up
        except Exception as exc:  # connection refused while Envoy boots
            last = exc
            time.sleep(0.5)
    raise TimeoutError(f"{url} never came up: {last}")


def _call(
    url: str, headers: dict[str, str], data: bytes | None = None
) -> tuple[int, dict[str, str], str]:
    req = urllib.request.Request(url, headers=headers, data=data)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return (
                resp.status,
                {k.lower(): v for k, v in resp.headers.items()},
                resp.read().decode(),
            )
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read().decode()


class _Upstream(http.server.BaseHTTPRequestHandler):
    """Echoes the x-unified-* headers it received, so tests can assert what the
    engine injected into the *upstream request* on an allow."""

    def _respond(self):
        injected = {
            k.lower(): v for k, v in self.headers.items() if k.lower().startswith("x-unified-")
        }
        body = json.dumps(injected).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _respond  # noqa: N815

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("content-length", 0))
        if length:
            self.rfile.read(length)
        self._respond()

    def log_message(self, *args):  # silence
        pass


@pytest.fixture(scope="module")
def upstream():
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), _Upstream)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()


def _core() -> ExtAuthzCore:
    return ExtAuthzCore(
        Enforcer(PolicyEngine.from_yaml(POLICY)),
        # Enabled so this suite exercises the body/raw_body/size field numbers
        # against real Envoy — nothing else pins them to Envoy's wire format.
        body_inspection=BodyInspection(max_bytes=4096),
    )


@pytest.fixture(scope="module")
def engine_server():
    server = create_grpc_server(_core(), "0.0.0.0:0")  # container must reach it
    server.start()
    yield server
    server.stop(None)


@pytest.fixture(scope="module")
def http_engine_server():
    """`create_http_service()` behind a real uvicorn, for Envoy's http_service.

    Runs in a thread rather than a subprocess only because nothing here needs
    isolation — unlike the latency harness, this measures behaviour, not time.
    """
    import uvicorn

    from unified_enforce import create_http_service

    port = _free_port()
    config = uvicorn.Config(
        create_http_service(_core()), host="0.0.0.0", port=port, log_level="warning"
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    _wait_for(f"http://127.0.0.1:{port}/health-probe")
    yield port
    server.should_exit = True
    thread.join(timeout=10)


@pytest.fixture(scope="module", params=["grpc", "http"])
def gateway(request, tmp_path_factory, engine_server, http_engine_server, upstream):
    """Envoy in front of the engine, once per transport.

    Both transports share one `ExtAuthzCore`, so a verdict cannot differ
    between them by construction — but *reaching* that core differs a lot
    (HTTP/2 vs HTTP/1.1, header allowlists, how a denial is rendered), and
    until now only gRPC had ever been driven by real Envoy.
    """
    transport = request.param
    engine_port = engine_server.bound_port if transport == "grpc" else http_engine_server
    cfg_dir = tmp_path_factory.mktemp(f"envoy-{transport}")
    (cfg_dir / "envoy.yaml").write_text(_envoy_config(engine_port, upstream, transport=transport))
    port, name = _run_envoy(cfg_dir)
    try:
        _wait_for(f"http://127.0.0.1:{port}/v1/users")
        yield port
    finally:
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        print(f"--- envoy ({transport}) ---\n{logs.stderr[-1500:]}")
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


# Envoy's default c-ares resolver ignores /etc/hosts, so --add-host's
# host.docker.internal entry is invisible to it. getaddrinfo goes through libc
# and sees it. Test-harness only: real sidecars address 127.0.0.1.
_GETADDRINFO = """
      typed_dns_resolver_config:
        name: envoy.network.dns_resolver.getaddrinfo
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.network.dns_resolver.getaddrinfo.v3.GetAddrInfoDnsResolverConfig
"""


def _ext_authz_stanza(transport: str, engine_port: int) -> str:
    """The one part of the sidecar config that differs by transport."""
    if transport == "grpc":
        return """
                      grpc_service:
                        envoy_grpc: { cluster_name: unified_enforce }
                        timeout: 2s"""
    # `http_service` speaks plain HTTP to create_http_service(). This allowlist
    # mirrors the shipped template exactly, and it is load-bearing in a way that
    # is easy to miss: anything not listed never reaches the engine. Writing it
    # from memory here (without host/x-forwarded-*) made every request
    # default-deny, because the engine reconstructs the tool URI from those
    # headers and got `https://` + an empty host instead of the real target.
    # Trimming this list in a deployment fails closed, but it fails *everything*.
    return f"""
                      http_service:
                        server_uri:
                          uri: http://host.docker.internal:{engine_port}
                          cluster: unified_enforce
                          timeout: 2s
                        authorization_request:
                          allowed_headers:
                            patterns:
                              - exact: x-unified-principal
                              - exact: x-unified-action
                              - exact: content-type
                              - exact: traceparent
                              - exact: host
                              - exact: x-forwarded-host
                              - exact: x-forwarded-proto
                        authorization_response:
                          allowed_upstream_headers:
                            patterns:
                              - prefix: x-unified-
                          allowed_client_headers:
                            patterns:
                              - prefix: x-unified-"""


def _envoy_config(
    grpc_port: int,
    upstream_port: int,
    *,
    tls: bool = False,
    strip_principal: bool = False,
    transport: str = "grpc",
) -> str:
    # Exactly what the shipped sidecar templates place ahead of ext_authz.
    mutation = (
        """
                  - name: envoy.filters.http.header_mutation
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.header_mutation.v3.HeaderMutation
                      mutations:
                        request_mutations:
                          - remove: "x-unified-principal"
"""
        if strip_principal
        else ""
    )
    # gRPC needs HTTP/2; the http_service transport must not have it, or Envoy
    # speaks h2 to a server expecting HTTP/1.1 and every check fails.
    http2 = """
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config: { http2_protocol_options: {} }"""
    transport_socket = (
        """
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          sni: unified-enforce
          common_tls_context:
            tls_certificates:
              - certificate_chain: { filename: /tls/envoy.crt }
                private_key: { filename: /tls/envoy.key }
            validation_context:
              trusted_ca: { filename: /tls/ca.crt }
              match_typed_subject_alt_names:
                - san_type: DNS
                  matcher: { exact: "unified-enforce" }
"""
        if tls
        else ""
    )
    return f"""
static_resources:
  listeners:
    - name: egress
      address: {{ socket_address: {{ address: 0.0.0.0, port_value: 10000 }} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: egress
                route_config:
                  name: all
                  virtual_hosts:
                    - name: upstream
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          route: {{ cluster: upstream }}
                http_filters:{mutation}
                  - name: envoy.filters.http.ext_authz
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
                      transport_api_version: V3
                      failure_mode_allow: false
                      with_request_body:
                        max_request_bytes: 4096
                        allow_partial_message: false
                        pack_as_bytes: true
{_ext_authz_stanza(transport, grpc_port)}
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: unified_enforce
      type: STRICT_DNS
      connect_timeout: 2s
{_GETADDRINFO}{transport_socket}
{http2 if transport == "grpc" else ""}
      load_assignment:
        cluster_name: unified_enforce
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: host.docker.internal, port_value: {grpc_port} }}
    - name: upstream
      type: STRICT_DNS
      connect_timeout: 2s
{_GETADDRINFO}
      load_assignment:
        cluster_name: upstream
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: host.docker.internal, port_value: {upstream_port} }}
"""


def _run_envoy(cfg_dir: Path, extra_mounts: dict[Path, str] | None = None):
    """Start Envoy in a container; yields the published listener port."""
    port = _free_port()
    name = f"unified-envoy-test-{port}"
    mounts: list[str] = ["-v", f"{cfg_dir}:/cfg:ro"]
    for host_path, container_path in (extra_mounts or {}).items():
        mounts += ["-v", f"{host_path}:{container_path}:ro"]
    proc = subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", name,
         "--add-host=host.docker.internal:host-gateway", "-p", f"{port}:10000",
         *mounts, ENVOY_IMAGE, "envoy", "-c", "/cfg/envoy.yaml"],
        capture_output=True, text=True, timeout=600,
    )  # fmt: skip
    if proc.returncode != 0:
        pytest.fail(f"docker run failed: {proc.stderr}")
    return port, name


@pytest.fixture(scope="module")
def envoy(tmp_path_factory, engine_server, upstream):
    cfg_dir = tmp_path_factory.mktemp("envoy")
    (cfg_dir / "envoy.yaml").write_text(_envoy_config(engine_server.bound_port, upstream))
    port, name = _run_envoy(cfg_dir)
    try:
        _wait_for(f"http://127.0.0.1:{port}/v1/users")
        yield port
    finally:
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        print(logs.stderr[-2000:])
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


@pytest.fixture(scope="module")
def tls_dir(tmp_path_factory, pki) -> Path:
    """PEM material laid out the way the shipped mTLS template expects."""
    d = tmp_path_factory.mktemp("tls")
    (d / "ca.crt").write_bytes(pki["ca"])
    (d / "server.key").write_bytes(pki["server"][0])
    (d / "server.crt").write_bytes(pki["server"][1])
    (d / "envoy.key").write_bytes(pki["client"][0])
    (d / "envoy.crt").write_bytes(pki["client"][1])
    return d


# --- the tests ---


@requires_docker
@pytest.mark.parametrize("template", ["ext_authz-grpc.yaml", "ext_authz-http.yaml"])
def test_shipped_templates_pass_envoy_validation(template):
    """The templates we ship must parse against Envoy's real schema."""
    proc = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{DEPLOY / 'envoy'}:/cfg:ro",
         ENVOY_IMAGE, "envoy", "--mode", "validate", "-c", f"/cfg/{template}"],
        capture_output=True, text=True, timeout=600,
    )  # fmt: skip
    assert proc.returncode == 0, f"{template} failed validation:\n{proc.stderr}"


@requires_docker
def test_mtls_template_passes_envoy_validation(tls_dir):
    """The mTLS template names certificate paths, and Envoy reads them at load
    time — so validating it without real files would only prove the YAML parses.
    Mounting a live chain at the documented path checks both together."""
    proc = subprocess.run(
        ["docker", "run", "--rm",
         "-v", f"{DEPLOY / 'envoy'}:/cfg:ro", "-v", f"{tls_dir}:/etc/unified/tls:ro",
         ENVOY_IMAGE, "envoy", "--mode", "validate", "-c", "/cfg/ext_authz-grpc-mtls.yaml"],
        capture_output=True, text=True, timeout=600,
    )  # fmt: skip
    assert proc.returncode == 0, f"mTLS template failed validation:\n{proc.stderr}"


@requires_docker
def test_allowed_request_reaches_upstream(gateway):
    status, _, body = _call(
        f"http://127.0.0.1:{gateway}/v1/users",
        {"x-unified-principal": "agent:crew-1"},
    )
    assert status == 200
    # On ALLOW, Envoy injects OkHttpResponse.headers into the *upstream request*
    # (client-visible headers are the denial path). The upstream echoes them, so
    # this asserts the provenance the upstream actually receives.
    injected = json.loads(body)
    assert injected["x-unified-verdict"] == "allow"
    assert injected["x-unified-rule"] == "api-reads-ok"
    assert len(injected["x-unified-action-digest"]) == 64


@requires_docker
def test_denied_request_is_blocked_by_envoy(gateway):
    status, headers, _ = _call(
        f"http://127.0.0.1:{gateway}/admin/secrets",
        {"x-unified-principal": "agent:crew-1"},
    )
    assert status == 403
    assert headers.get("x-unified-verdict") == "deny"
    assert headers.get("x-unified-source") == "default"


@requires_docker
def test_unknown_principal_is_denied(gateway):
    status, _, _ = _call(f"http://127.0.0.1:{gateway}/v1/users", {})
    assert status == 403


# --- body inspection against real Envoy (spec §8) ---


@requires_docker
def test_body_value_decides_the_verdict(gateway):
    """The whole point of body inspection: same method, same path, same
    principal — only the amount inside the payload differs.

    This is also what pins the vendored proto's raw_body/size field numbers to
    Envoy's, since Envoy is the only thing that fills them.
    """
    headers = {"x-unified-principal": "agent:crew-1", "content-type": "application/json"}
    url = f"http://127.0.0.1:{gateway}/v1/refunds"

    small, _, _ = _call(url, headers, data=json.dumps({"amount": 100}).encode())
    assert small == 200, "a small refund should be allowed"

    large, hdrs, _ = _call(url, headers, data=json.dumps({"amount": 9000}).encode())
    assert large == 403, "a refund over the limit should be denied"
    assert hdrs.get("x-unified-verdict") == "deny"


@requires_docker
def test_unreadable_body_is_denied_through_envoy(gateway):
    status, headers, _ = _call(
        f"http://127.0.0.1:{gateway}/v1/refunds",
        {"x-unified-principal": "agent:crew-1", "content-type": "application/json"},
        data=b"{not json",
    )
    assert status == 403
    assert headers.get("x-unified-source") == "body_unreadable"


@requires_docker
def test_defer_fails_closed_at_the_gateway(gateway):
    """A deferred action cannot wait for a human on a synchronous hop.

    The spec commits to 403 + `x-unified-verdict: defer` rather than holding
    the connection, because blocking here would pin an Envoy worker until an
    operator answered. It was unit-tested at the core but Envoy had never
    actually produced the response — and the two transports render a denial by
    different mechanisms, so this is exactly the kind of claim that could be
    true for one and not the other.
    """
    status, headers, _ = _call(
        f"http://127.0.0.1:{gateway}/v1/payouts",
        {"x-unified-principal": "agent:crew-1"},
    )
    assert status == 403
    assert headers.get("x-unified-verdict") == "defer"
    assert headers.get("x-unified-rule") == "payouts-need-a-human"


# --- principal spoofing (spec §4) ---


@requires_docker
def test_route_level_removal_does_not_protect_the_engine(envoy):
    """Documents the ordering that made the original template's comment wrong.

    `route_config.request_headers_to_remove` runs when the request is
    FORWARDED — after ext_authz has already decided. So it keeps internal
    headers off the wire to third parties, but it does NOT stop an agent from
    naming its own principal. This fixture has no header_mutation filter, and
    the client-supplied principal reaches the engine and matches a rule.
    """
    status, _, _ = _call(
        f"http://127.0.0.1:{envoy}/v1/users", {"x-unified-principal": "agent:crew-1"}
    )
    assert status == 200, "without header_mutation, a client-set principal is honoured"


@requires_docker
def test_header_mutation_stops_an_agent_naming_its_own_principal(
    tmp_path_factory, engine_server, upstream
):
    """The actual protection, as now shipped in the templates: a filter ordered
    ahead of ext_authz deletes the header before the engine ever sees it, so
    identity falls back to the sidecar's configured default."""
    cfg_dir = tmp_path_factory.mktemp("envoy-strip")
    (cfg_dir / "envoy.yaml").write_text(
        _envoy_config(engine_server.bound_port, upstream, strip_principal=True)
    )
    port, name = _run_envoy(cfg_dir)
    try:
        _wait_for(f"http://127.0.0.1:{port}/v1/users")
        status, headers, _ = _call(
            f"http://127.0.0.1:{port}/v1/users", {"x-unified-principal": "agent:crew-1"}
        )
        assert status == 403, "a spoofed principal must not reach the engine"
        assert headers.get("x-unified-verdict") == "deny"
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


# --- mTLS between Envoy and the engine (spec §8) ---


@requires_docker
def test_envoy_reaches_the_engine_over_mtls(tmp_path_factory, tls_dir, pki, upstream):
    """Envoy's TLS client against ServerTLS — the interop that unit tests can't
    cover, since they use grpc's own client on both ends."""
    server_key, server_cert = pki["server"]
    server = create_grpc_server(
        _core(),
        "0.0.0.0:0",
        tls=ServerTLS(
            certificate_chain=server_cert,
            private_key=server_key,
            client_ca=pki["ca"],
            require_client_auth=True,
        ),
    )
    server.start()
    cfg_dir = tmp_path_factory.mktemp("envoy-mtls")
    (cfg_dir / "envoy.yaml").write_text(_envoy_config(server.bound_port, upstream, tls=True))
    port, name = _run_envoy(cfg_dir, extra_mounts={tls_dir: "/tls"})
    try:
        _wait_for(f"http://127.0.0.1:{port}/v1/users")
        status, _, body = _call(
            f"http://127.0.0.1:{port}/v1/users", {"x-unified-principal": "agent:crew-1"}
        )
        assert status == 200, "mTLS handshake should succeed and the verdict should pass through"
        assert json.loads(body)["x-unified-verdict"] == "allow"
    finally:
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        print(logs.stderr[-2000:])
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        server.stop(None)


# --- keep last: this fixture's engine stays stopped afterwards ---


@requires_docker
def test_engine_down_fails_closed(envoy, engine_server):
    """failure_mode_allow: false — killing the engine must deny, never pass."""
    engine_server.stop(None)
    time.sleep(1)
    status, _, _ = _call(
        f"http://127.0.0.1:{envoy}/v1/users",
        {"x-unified-principal": "agent:crew-1"},
    )
    assert status != 200, "traffic passed with the engine down — NOT fail-closed"
    assert status in (403, 500, 503), f"unexpected status {status}"
