"""The operator interdict endpoint — build-04.

`POST /interdict {"principal": ...}` cancels that principal's calls in flight
over the hub's real unix-socket transport, and the caller of the interrupted
call gets `-32004 interdicted` rather than a hang or a crash.
"""

from __future__ import annotations

import asyncio
import sys
import textwrap
from pathlib import Path

import httpx
import pytest

from unified_mcphub.config import load_config
from unified_mcphub.hub import Hub

FAKE_SERVER = Path(__file__).parent.parent / "fixtures" / "fake_mcp_server.py"


def _permissive_workspace(hub_home):
    (hub_home / "workspaces" / "default.yaml").write_text(
        textwrap.dedent(
            f"""
            servers:
              filesystem:
                upstream:
                  command: {sys.executable}
                  args: ["{FAKE_SERVER}"]
            authz:
              rules:
                - tool: "mcp://*/*"
                  effect: allow
            """
        ).strip()
        + "\n"
    )


def _client(sock: Path) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.AsyncHTTPTransport(uds=str(sock)), base_url="http://hub", timeout=20
    )


@pytest.mark.asyncio
async def test_interdict_over_the_socket(hub_home):
    _permissive_workspace(hub_home)
    config = load_config()
    config.hub.listen.tcp_enabled = False
    hub = Hub(config)
    await hub.start()
    release = asyncio.Event()

    async def slow(server_name, tool, args):
        await release.wait()
        return {"content": [{"type": "text", "text": "late"}]}

    hub._forward = slow  # type: ignore[method-assign]
    sock = Path(config.hub.listen.unix_socket)
    try:
        async with _client(sock) as c:
            call = asyncio.create_task(
                c.post(
                    "/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "filesystem__read_file", "arguments": {"path": "x"}},
                    },
                    headers={"X-Caller-Id": "claude-code"},
                )
            )
            for _ in range(200):
                await asyncio.sleep(0.01)
                if hub.in_flight():
                    break
            status = (await c.get("/status")).json()
            assert len(status["in_flight"]) == 1
            assert status["in_flight"][0]["principal"] == "agent:claude-code"
            assert status["fleet"] is None  # standalone hub

            bad = await c.post("/interdict", json={}, headers={"X-Caller-Id": "operator"})
            assert bad.status_code == 400

            r = await c.post(
                "/interdict",
                json={"principal": "agent:claude-code", "reason": "operator stop"},
                headers={"X-Caller-Id": "alice"},
            )
            assert r.status_code == 200
            interrupted = r.json()["interdicted"]
            assert len(interrupted) == 1

            body = (await call).json()
            assert body["error"]["code"] == -32004
            assert "operator stop" in body["error"]["message"]
            assert (await c.get("/status")).json()["in_flight"] == []
    finally:
        release.set()
        await hub.stop()
