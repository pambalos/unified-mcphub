"""Configurable TCP port + friendly bind error — specs/mcphub/NEXT-PR-port-config.md.

`--port` / `--no-tcp` override the loaded config (precedence CLI > config.yaml >
default 7712); a port collision surfaces as a one-line message, not a traceback.
The unix socket stays the primary, 0600-mode transport throughout.
"""

from __future__ import annotations

import socket
from pathlib import Path

import httpx
import pytest

from unified_mcphub.config import ListenConfig, load_config
from unified_mcphub.hub import Hub
from unified_mcphub.transports import PortInUseError, TransportServer, build_app


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.asyncio
async def test_port_override_binds_chosen_port_and_socket(hub_home, enable_tcp):
    port = _free_port()
    enable_tcp(f"127.0.0.1:{port}")  # stands in for `start --port <port>`
    config = load_config()
    hub = Hub(config)
    await hub.start()
    try:
        # TCP is up on the chosen port (/status is unauthenticated).
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", timeout=10) as c:
            assert (await c.get("/status")).status_code == 200
        # The unix socket is still bound at mode 0600.
        sock = Path(config.hub.listen.unix_socket)
        assert sock.exists()
        transport = httpx.AsyncHTTPTransport(uds=str(sock))
        async with httpx.AsyncClient(transport=transport, base_url="http://hub", timeout=10) as c:
            assert (await c.get("/status")).status_code == 200
    finally:
        await hub.stop()


@pytest.mark.asyncio
async def test_no_tcp_serves_unix_socket_only(hub_home):
    # The default fixture config has tcp_enabled: false (the `--no-tcp` shape).
    config = load_config()
    assert config.hub.listen.tcp_address is None
    hub = Hub(config)
    await hub.start()
    try:
        assert "http" not in hub._listen_dict()  # no TCP listener advertised
        sock = Path(config.hub.listen.unix_socket)
        transport = httpx.AsyncHTTPTransport(uds=str(sock))
        async with httpx.AsyncClient(transport=transport, base_url="http://hub", timeout=10) as c:
            assert (await c.get("/status")).status_code == 200
    finally:
        await hub.stop()


@pytest.mark.asyncio
async def test_port_in_use_raises_friendly_error(hub_home):
    # Occupy a port, then a hub configured for it must fail fast with a clean
    # PortInUseError (no uvicorn traceback, no started-poll timeout).
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen()
    port = blocker.getsockname()[1]
    try:
        listen = ListenConfig(unix_socket="", tcp_enabled=True, host="127.0.0.1", port=port)
        server = TransportServer(build_app(object()), listen)
        with pytest.raises(PortInUseError) as exc:
            await server.start()
        assert str(port) in str(exc.value)
        assert "--port" in str(exc.value)
    finally:
        blocker.close()
        await server.stop()
