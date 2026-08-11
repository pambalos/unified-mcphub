"""End-to-end: real Envoy enforcing our ext_authz verdicts. E3, spec §1/§4.

This is the test that proves the vendored minimal protos are wire-compatible
with Envoy — we no longer link Envoy's generated stubs, so nothing else does.
It also proves the shipped templates parse against Envoy's schema and that
`failure_mode_allow: false` really denies when the engine dies.

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

from unified_enforce import Enforcer, ExtAuthzCore, PolicyEngine
from unified_enforce.extauthz_grpc import create_grpc_server

pytestmark = pytest.mark.integration

ENVOY_IMAGE = "envoyproxy/envoy:v1.31-latest"
DEPLOY = Path(__file__).resolve().parents[2] / "deploy"

POLICY = """
version: 1
rules:
  - id: api-reads-ok
    match: {principal: "agent:crew-*", tool: "http://*/v1/users**", verb: get}
    effect: allow
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


def _get(url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], str]:
    req = urllib.request.Request(url, headers=headers)
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

    def do_GET(self):  # noqa: N802
        injected = {
            k.lower(): v for k, v in self.headers.items() if k.lower().startswith("x-unified-")
        }
        body = json.dumps(injected).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence
        pass


@pytest.fixture(scope="module")
def upstream():
    server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), _Upstream)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()


@pytest.fixture(scope="module")
def engine_server():
    core = ExtAuthzCore(Enforcer(PolicyEngine.from_yaml(POLICY)))
    server = create_grpc_server(core, "0.0.0.0:0")  # container must reach it
    server.start()
    yield server
    server.stop(None)


def _envoy_config(grpc_port: int, upstream_port: int) -> str:
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
                http_filters:
                  - name: envoy.filters.http.ext_authz
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
                      transport_api_version: V3
                      failure_mode_allow: false
                      grpc_service:
                        envoy_grpc: {{ cluster_name: unified_enforce }}
                        timeout: 2s
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: unified_enforce
      type: STRICT_DNS
      connect_timeout: 2s
      # Envoy's default c-ares resolver ignores /etc/hosts, so --add-host's
      # host.docker.internal entry is invisible to it. getaddrinfo goes through
      # libc and sees it. Test-harness only: real sidecars use 127.0.0.1.
      typed_dns_resolver_config:
        name: envoy.network.dns_resolver.getaddrinfo
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.network.dns_resolver.getaddrinfo.v3.GetAddrInfoDnsResolverConfig
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config: {{ http2_protocol_options: {{}} }}
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
      # Envoy's default c-ares resolver ignores /etc/hosts, so --add-host's
      # host.docker.internal entry is invisible to it. getaddrinfo goes through
      # libc and sees it. Test-harness only: real sidecars use 127.0.0.1.
      typed_dns_resolver_config:
        name: envoy.network.dns_resolver.getaddrinfo
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.network.dns_resolver.getaddrinfo.v3.GetAddrInfoDnsResolverConfig
      load_assignment:
        cluster_name: upstream
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: host.docker.internal, port_value: {upstream_port} }}
"""


@pytest.fixture(scope="module")
def envoy(tmp_path_factory, engine_server, upstream):
    cfg_dir = tmp_path_factory.mktemp("envoy")
    (cfg_dir / "envoy.yaml").write_text(_envoy_config(engine_server.bound_port, upstream))
    port = _free_port()
    name = f"unified-envoy-test-{port}"
    proc = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            name,
            "--add-host=host.docker.internal:host-gateway",
            "-p",
            f"{port}:10000",
            "-v",
            f"{cfg_dir}:/cfg:ro",
            ENVOY_IMAGE,
            "envoy",
            "-c",
            "/cfg/envoy.yaml",
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0:
        pytest.fail(f"docker run failed: {proc.stderr}")
    try:
        _wait_for(f"http://127.0.0.1:{port}/v1/users")
        yield port
    finally:
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        print(logs.stderr[-2000:])
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


# --- the tests ---


@requires_docker
def test_shipped_templates_pass_envoy_validation():
    """The templates we ship must parse against Envoy's real schema."""
    for template in ["ext_authz-grpc.yaml", "ext_authz-http.yaml"]:
        proc = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{DEPLOY / 'envoy'}:/cfg:ro",
                ENVOY_IMAGE,
                "envoy",
                "--mode",
                "validate",
                "-c",
                f"/cfg/{template}",
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
        assert proc.returncode == 0, f"{template} failed validation:\n{proc.stderr}"


@requires_docker
def test_allowed_request_reaches_upstream(envoy):
    status, _, body = _get(
        f"http://127.0.0.1:{envoy}/v1/users",
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
def test_denied_request_is_blocked_by_envoy(envoy):
    status, headers, _ = _get(
        f"http://127.0.0.1:{envoy}/admin/secrets",
        {"x-unified-principal": "agent:crew-1"},
    )
    assert status == 403
    assert headers.get("x-unified-verdict") == "deny"
    assert headers.get("x-unified-source") == "default"


@requires_docker
def test_unknown_principal_is_denied(envoy):
    status, _, _ = _get(f"http://127.0.0.1:{envoy}/v1/users", {})
    assert status == 403


@requires_docker
def test_engine_down_fails_closed(envoy, engine_server):
    """failure_mode_allow: false — killing the engine must deny, never pass."""
    engine_server.stop(None)
    time.sleep(1)
    try:
        status, _, _ = _get(
            f"http://127.0.0.1:{envoy}/v1/users",
            {"x-unified-principal": "agent:crew-1"},
        )
        assert status != 200, "traffic passed with the engine down — NOT fail-closed"
        assert status in (403, 500, 503), f"unexpected status {status}"
    finally:
        pass  # module-scoped server intentionally left stopped; last test in file
