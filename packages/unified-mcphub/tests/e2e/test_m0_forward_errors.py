"""Hot-path error branches — unknown server/built-in and malformed tool names.

A permissive workspace lets the calls pass authz so they reach `_forward`,
exercising the error handling + `completed` audit on failure (spec §10).
"""

from __future__ import annotations

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


async def _call(hub_home, tool_name):
    _permissive_workspace(hub_home)
    config = load_config()
    hub = Hub(config)
    await hub.start()
    sock = Path(config.hub.listen.unix_socket)
    try:
        transport = httpx.AsyncHTTPTransport(uds=str(sock))
        async with httpx.AsyncClient(transport=transport, base_url="http://hub", timeout=15) as c:
            r = await c.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": {}},
                },
                headers={"X-Caller-Id": "claude-code"},
            )
            return r.json()
    finally:
        await hub.stop()


@pytest.mark.asyncio
async def test_unknown_server_returns_error(hub_home):
    body = await _call(hub_home, "ghost__do_thing")
    assert "error" in body
    assert "unknown server" in body["error"]["message"]


@pytest.mark.asyncio
async def test_unknown_builtin_returns_error(hub_home):
    body = await _call(hub_home, "built-in__nope")
    assert "error" in body
    assert "unknown built-in" in body["error"]["message"]


@pytest.mark.asyncio
async def test_missing_separator_returns_error(hub_home):
    body = await _call(hub_home, "noseparator")
    assert "error" in body
    assert "<server>__<tool>" in body["error"]["message"]
