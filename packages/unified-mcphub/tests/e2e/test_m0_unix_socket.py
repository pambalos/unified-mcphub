"""MCP-HUB-1 gating e2e — Unix socket transport (spec §3.1, §16).

Socket is bound at mode 0600 (filesystem-permission auth boundary) and a
same-user client can connect and drive the MCP surface over it.
"""

from __future__ import annotations

import stat
from pathlib import Path

import httpx
import pytest

from unified_mcphub.config import load_config
from unified_mcphub.hub import Hub


@pytest.mark.asyncio
async def test_unix_socket_mode_0600_and_usable(hub_home):
    config = load_config()
    hub = Hub(config)
    await hub.start()
    sock = Path(config.hub.listen.unix_socket)
    try:
        assert sock.exists()
        assert stat.S_ISSOCK(sock.stat().st_mode), "expected a socket file"
        assert stat.S_IMODE(sock.stat().st_mode) == 0o600

        transport = httpx.AsyncHTTPTransport(uds=str(sock))
        async with httpx.AsyncClient(transport=transport, base_url="http://hub", timeout=10) as c:
            r = await c.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                headers={"X-Caller-Id": "claude-code"},
            )
            assert r.status_code == 200
            assert r.json()["result"] == {}

            # notifications carry no id -> the surface returns 202 with no body.
            notify = await c.post(
                "/mcp",
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                headers={"X-Caller-Id": "claude-code"},
            )
            assert notify.status_code == 202

            status = await c.get("/status")
            assert status.json()["workspace"] == "default"
    finally:
        await hub.stop()

    # graceful drain removes the socket file.
    assert not sock.exists()
