"""M0 first-run e2e — spec §14, §16. Acceptance for MCP-HUB-1.

install -> register a server -> call a tool as caller "claude-code" ->
see received + completed audit entries paired by request_id with
authz_decision == "allow".
"""

from __future__ import annotations

import json
import stat
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from unified_mcphub.config import load_config
from unified_mcphub.hub import Hub


def _rpc(method: str, req_id: int, params: dict | None = None) -> dict:
    msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


@pytest.mark.asyncio
async def test_install_and_first_audited_call(hub_home):
    # 1. start the hub on the Unix socket with the seeded starter workspace.
    config = load_config()
    hub = Hub(config)
    await hub.start()

    sock = Path(config.hub.listen.unix_socket)
    assert sock.exists(), "Unix socket not bound"
    assert stat.S_IMODE(sock.stat().st_mode) == 0o600, "socket must be mode 0600"

    try:
        transport = httpx.AsyncHTTPTransport(uds=str(sock))
        async with httpx.AsyncClient(
            transport=transport, base_url="http://hub", timeout=30
        ) as client:
            headers = {"X-Caller-Id": "claude-code"}

            r = await client.post(
                "/mcp",
                json=_rpc(
                    "initialize",
                    1,
                    {"protocolVersion": "2024-11-05", "capabilities": {},
                     "clientInfo": {"name": "test", "version": "0"}},
                ),
                headers=headers,
            )
            assert r.status_code == 200 and "result" in r.json()

            # 2. the registered filesystem server's tool is aggregated + namespaced.
            r = await client.post("/mcp", json=_rpc("tools/list", 2), headers=headers)
            names = [t["name"] for t in r.json()["result"]["tools"]]
            assert "filesystem__list_files" in names
            assert "built-in__ping" in names  # aggregation includes built-ins

            # 3. issue a tool call as caller "claude-code".
            r = await client.post(
                "/mcp",
                json=_rpc(
                    "tools/call", 3,
                    {"name": "filesystem__list_files", "arguments": {"path": "."}},
                ),
                headers=headers,
            )
            body = r.json()
            assert "result" in body, body
            assert body["result"]["isError"] is False
            assert "alpha.txt" in json.dumps(body["result"]["content"])
    finally:
        await hub.stop()

    # 4. audit/<UTC-date>.jsonl has a received + completed pair, matched by
    #    request_id, with authz_decision == "allow".
    date = datetime.now(timezone.utc).date().isoformat()
    audit_file = hub_home / "audit" / f"{date}.jsonl"
    entries = [json.loads(line) for line in audit_file.read_text().splitlines()]

    received = [e for e in entries if e["phase"] == "received"]
    completed = [e for e in entries if e["phase"] == "completed"]
    assert received and completed, entries

    rec, comp = received[-1], completed[-1]
    assert rec["request_id"] == comp["request_id"]
    assert rec["caller_id"] == "claude-code"
    assert rec["mcp_server"] == "filesystem"
    assert rec["tool"] == "list_files"
    assert rec["authz_decision"] == "allow"
    assert comp["result_status"] == "ok"
