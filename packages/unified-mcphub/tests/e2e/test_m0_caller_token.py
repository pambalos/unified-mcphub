"""TCP bearer-token auth — spec §3.1, §3.2, §16 (SEC-MCP-2).

Unix socket = filesystem perms (no token). TCP loopback requires a valid bearer
mapped to a caller; a bad/absent token is rejected; rotation invalidates old.
"""

from __future__ import annotations

import json
import socket
from datetime import datetime, timezone

import httpx
import pytest

from unified_mcphub.config import audit_dir, load_config, mcphub_home
from unified_mcphub.hub import Hub
from unified_mcphub.tokens import TokenStore


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _call(client, headers):
    return client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        headers=headers,
    )


@pytest.mark.asyncio
async def test_tcp_requires_valid_bearer(hub_home, enable_tcp):
    port = _free_port()
    enable_tcp(f"127.0.0.1:{port}")
    token = TokenStore(mcphub_home() / "caller-tokens").mint("claude-code")

    hub = Hub(load_config())
    await hub.start()
    try:
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", timeout=10) as c:
            assert (await _call(c, {"Authorization": f"Bearer {token}"})).status_code == 200
            assert (await _call(c, {})).status_code == 401                      # no token
            assert (await _call(c, {"Authorization": "Bearer wrong"})).status_code == 401
    finally:
        await hub.stop()


@pytest.mark.asyncio
async def test_tcp_call_logs_caller_token_id(hub_home, enable_tcp):
    port = _free_port()
    enable_tcp(f"127.0.0.1:{port}")
    token = TokenStore(mcphub_home() / "caller-tokens").mint("claude-code")

    hub = Hub(load_config())
    await hub.start()
    try:
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", timeout=10) as c:
            await c.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "built-in__ping", "arguments": {}}},
                headers={"Authorization": f"Bearer {token}"},
            )
    finally:
        await hub.stop()

    date = datetime.now(timezone.utc).date().isoformat()
    entries = [json.loads(line) for line in (audit_dir() / f"{date}.jsonl").read_text().splitlines()]
    received = [e for e in entries if e["phase"] == "received"][-1]
    assert received["caller_id"] == "claude-code"
    assert received["caller_token_id"] == TokenStore.caller_token_id(token)


@pytest.mark.asyncio
async def test_rotation_invalidates_old_token(hub_home, enable_tcp):
    port = _free_port()
    enable_tcp(f"127.0.0.1:{port}")
    store = TokenStore(mcphub_home() / "caller-tokens")
    old = store.mint("claude-code")
    new = store.mint("claude-code")  # rotate before start

    hub = Hub(load_config())
    await hub.start()
    try:
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", timeout=10) as c:
            assert (await _call(c, {"Authorization": f"Bearer {new}"})).status_code == 200
            assert (await _call(c, {"Authorization": f"Bearer {old}"})).status_code == 401
    finally:
        await hub.stop()
