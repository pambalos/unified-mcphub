"""MCP-HUB-1 gating e2e — workspaces (spec §2.3, §16).

active_workspace selection + `--workspace` override change which servers/rules
load, so the same call is gated differently per workspace. (CLI `workspace
list/show/use` is MCP-HUB-6; here we cover the loader + override the hub uses.)
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


def _seed_permissive_workspace(hub_home):
    """A 'personal' workspace with the same server but an allow-everything rule."""
    (hub_home / "workspaces" / "personal.yaml").write_text(
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


def test_active_workspace_is_default(hub_home):
    assert load_config().workspace_name == "default"


def test_override_selects_workspace_and_rules(hub_home):
    _seed_permissive_workspace(hub_home)
    cfg = load_config("personal")
    assert cfg.workspace_name == "personal"
    assert cfg.workspace.authz.rules[0].tool == "mcp://*/*"


async def _call_read_file(hub_home, workspace):
    hub = Hub(load_config(workspace))
    await hub.start()
    sock = Path(load_config(workspace).hub.listen.unix_socket)
    try:
        transport = httpx.AsyncHTTPTransport(uds=str(sock))
        async with httpx.AsyncClient(transport=transport, base_url="http://hub", timeout=15) as c:
            r = await c.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "filesystem__read_file", "arguments": {"path": "x"}},
                },
                headers={"X-Caller-Id": "claude-code"},
            )
            return r.json()
    finally:
        await hub.stop()


@pytest.mark.asyncio
async def test_default_workspace_denies_read_file(hub_home):
    # default only allows mcp://*/list_* -> read_file is denied.
    body = await _call_read_file(hub_home, None)
    assert "error" in body
    assert "denied by policy" in body["error"]["message"]


@pytest.mark.asyncio
async def test_personal_workspace_allows_read_file(hub_home):
    _seed_permissive_workspace(hub_home)
    body = await _call_read_file(hub_home, "personal")
    assert "result" in body, body
    assert body["result"]["isError"] is False
    assert "contents of x" in str(body["result"]["content"])
