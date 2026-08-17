"""End-to-end: real Envoy's network (L4) ext_authz filter enforcing our
connection verdicts. E3.5.

What only this test can prove: that the vendored Peer.address / destination
socket-address field numbers match Envoy's wire format (Envoy is the only
thing that fills them), and what the filter's guarantee actually IS — which
running it revealed to be narrower than the obvious reading. Envoy's network
ext_authz deliberately defers the check to the first *downstream* byte (its
source comments: waiting until onData gives the CheckRequest more to say),
and returns Continue from onNewConnection. tcp_proxy therefore establishes
the upstream connection before any verdict exists, and a server-first
protocol's banner reaches a client that will be denied.

So the enforced claim, stated exactly: **no client byte crosses without an
ALLOW, and a denied connection closes at the first client write.** The
upstream still observes a TCP open/close, and greeting bytes still leak
downstream — both pinned below as documentation, so an Envoy release that
tightens this shows up as a test to update rather than silent slack.

Requires Docker (skipped otherwise):

    uv run pytest packages/unified-enforce/tests/integration -m integration
"""

from __future__ import annotations

import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

from unified_enforce import Enforcer, ExtAuthzCore, PolicyEngine
from unified_enforce.extauthz_grpc import create_grpc_server

pytestmark = pytest.mark.integration

ENVOY_IMAGE = "envoyproxy/envoy:v1.31-latest"
DEPLOY = Path(__file__).resolve().parents[2] / "deploy"


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True, timeout=60).returncode == 0


requires_docker = pytest.mark.skipif(not _docker_ok(), reason="docker daemon not available")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _readable_by_container(path: Path) -> Path:
    """See test_envoy_ext_authz._readable_by_container — same reason, and the
    tests directory is not a package, so no relative import to share it."""
    for parent in [path, *path.parents]:
        try:
            parent.chmod(parent.stat().st_mode | 0o055)
        except PermissionError:  # pragma: no cover - outside our tmp tree
            break
        if parent == Path(tempfile.gettempdir()):
            break
    for child in path.rglob("*"):
        child.chmod(child.stat().st_mode | 0o044)
    return path


# The destination the engine sees is the listener's local address — inside the
# container that is an unknowable IP, so the rule pins what IS stable: the
# port. Listener 10001 is the allowed path; 10002 matches nothing.
POLICY = """
version: 1
rules:
  - id: tcp-upstream-ok
    match: {principal: "agent:crew-1", tool: "tcp://*:10001", verb: connect}
    effect: allow
"""

BANNER = b"unified-tcp-upstream\n"


class _EchoUpstream(socketserver.ThreadingTCPServer):
    """Server-first echo upstream that records every client byte it received,
    so a test can assert not just what the client saw but what crossed."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client_bytes: list[bytes] = []
        self.connections = 0


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.connections += 1
        self.request.sendall(BANNER)
        try:
            data = self.request.recv(1024)
        except OSError:
            return
        if data:
            self.server.client_bytes.append(data)
            self.request.sendall(b"echo:" + data)


@pytest.fixture(scope="module")
def tcp_upstream():
    server = _EchoUpstream(("0.0.0.0", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()


@pytest.fixture(scope="module")
def engine_server():
    core = ExtAuthzCore(Enforcer(PolicyEngine.from_yaml(POLICY)), default_principal="agent:crew-1")
    server = create_grpc_server(core, "0.0.0.0:0")
    server.start()
    yield server
    server.stop(None)


def _tcp_envoy_config(engine_port: int, upstream_port: int) -> str:
    # Two TCP listeners that differ only in port: policy allows *:10001 and
    # says nothing about *:10002, so one connection carries bytes and the
    # other dies at establish — the L4 twin of allow/deny-by-default.
    def listener(name: str, port: int) -> str:
        return f"""
    - name: {name}
      address: {{ socket_address: {{ address: 0.0.0.0, port_value: {port} }} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.ext_authz
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.ext_authz.v3.ExtAuthz
                stat_prefix: tcp_authz_{port}
                transport_api_version: V3
                failure_mode_allow: false
                grpc_service:
                  envoy_grpc: {{ cluster_name: unified_enforce }}
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: tcp_egress_{port}
                cluster: tcp_upstream"""

    return f"""
static_resources:
  listeners:{listener("allowed", 10001)}{listener("denied", 10002)}
  clusters:
    - name: unified_enforce
      type: STRICT_DNS
      connect_timeout: 2s
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
                    socket_address: {{ address: host.docker.internal, port_value: {engine_port} }}
    - name: tcp_upstream
      type: STRICT_DNS
      connect_timeout: 2s
      typed_dns_resolver_config:
        name: envoy.network.dns_resolver.getaddrinfo
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.network.dns_resolver.getaddrinfo.v3.GetAddrInfoDnsResolverConfig
      load_assignment:
        cluster_name: tcp_upstream
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: host.docker.internal, port_value: {upstream_port} }}
"""


def _run_tcp_envoy(cfg_dir: Path):
    """Like test_envoy_ext_authz._run_envoy but publishing both TCP ports."""
    _readable_by_container(cfg_dir)
    allowed, denied = _free_port(), _free_port()
    name = f"unified-envoy-l4-test-{allowed}"
    proc = subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", name,
         "--add-host=host.docker.internal:host-gateway",
         "-p", f"{allowed}:10001", "-p", f"{denied}:10002",
         "-v", f"{cfg_dir}:/cfg:ro", ENVOY_IMAGE, "envoy", "-c", "/cfg/envoy.yaml"],
        capture_output=True, text=True, timeout=600,
    )  # fmt: skip
    if proc.returncode != 0:
        pytest.fail(f"docker run failed: {proc.stderr}")
    return allowed, denied, name


def _exchange(port: int, payload: bytes, timeout: float = 5.0) -> tuple[bytes, bytes]:
    """Connect, read whatever greets us, write payload, read the reply.

    Returns (greeting, reply). Either may be b"" if the connection closed.
    """
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.settimeout(timeout)
        try:
            greeting = s.recv(1024)
        except (TimeoutError, ConnectionResetError):
            greeting = b""
        try:
            s.sendall(payload)
            reply = s.recv(1024)
        except (TimeoutError, ConnectionResetError, BrokenPipeError):
            reply = b""
        return greeting, reply


@pytest.fixture(scope="module")
def tcp_gateway(tmp_path_factory, engine_server, tcp_upstream):
    cfg_dir = tmp_path_factory.mktemp("envoy-l4")
    (cfg_dir / "envoy.yaml").write_text(
        _tcp_envoy_config(engine_server.bound_port, tcp_upstream.server_address[1])
    )
    allowed, denied, name = _run_tcp_envoy(cfg_dir)
    # Readiness must prove a completed ALLOW round-trip, not banner arrival —
    # the banner flows before any verdict exists (see module docstring).
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            if _exchange(allowed, b"ready?")[1] == b"echo:ready?":
                break
        except OSError:
            pass
        time.sleep(0.5)
    else:
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        pytest.fail(f"allowed TCP path never came up:\n{logs.stderr[-1500:]}")
    try:
        yield allowed, denied
    finally:
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        print(f"--- envoy (l4) ---\n{logs.stderr[-1500:]}")
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


# --- the tests ---


@requires_docker
def test_shipped_tcp_template_passes_envoy_validation():
    proc = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{DEPLOY / 'envoy'}:/cfg:ro",
         ENVOY_IMAGE, "envoy", "--mode", "validate", "-c", "/cfg/ext_authz-tcp.yaml"],
        capture_output=True, text=True, timeout=600,
    )  # fmt: skip
    assert proc.returncode == 0, f"ext_authz-tcp.yaml failed validation:\n{proc.stderr}"


@requires_docker
def test_allowed_connection_carries_bytes_both_ways(tcp_gateway):
    allowed, _ = tcp_gateway
    greeting, reply = _exchange(allowed, b"ping")
    assert greeting == BANNER
    assert reply == b"echo:ping"


@requires_docker
def test_denied_client_data_never_reaches_the_upstream(tcp_gateway, tcp_upstream):
    """The guarantee: the check fires on the first client byte, the verdict is
    DENY, the connection closes, and the byte that triggered it never crosses."""
    _, denied = tcp_gateway
    payload = b"SELECT * FROM secrets"
    _, reply = _exchange(denied, payload)
    assert reply == b"", "a denied connection must close, not echo"
    time.sleep(1)  # were Envoy to flush the buffered client data, it has by now
    crossed = b"".join(tcp_upstream.client_bytes)
    assert payload not in crossed, "client data crossed to the upstream on a DENY"


@requires_docker
def test_the_upstream_connection_itself_predates_the_verdict(tcp_gateway):
    """Documentation, not aspiration: Envoy's network ext_authz checks on the
    first downstream byte, so tcp_proxy has already opened the upstream and a
    server-first greeting reaches even a client that will be denied. If an
    Envoy upgrade ever moves the check to connection establish, this fails —
    update the module docstring and the template's stated guarantee with it."""
    _, denied = tcp_gateway
    greeting, _ = _exchange(denied, b"x")
    assert greeting == BANNER, "expected the pre-verdict banner leak Envoy currently has"
