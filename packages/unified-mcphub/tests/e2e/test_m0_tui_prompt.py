"""Prompt path + allow_always persistence — spec §5, ADR-0018/0024/0025.

A `prompt`-effect call blocks on the in-process approval; an `allow_always`
(command-scoped, key `c`) keypress writes a precedence-1 exact rule scoped to the
call's primary argument, to the machine-managed `.local.yaml` (ADR-0024/0025),
and the call proceeds. Audit records `prompt_allowed`.
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from unified_mcphub.approval import TerminalChannel
from unified_mcphub.config import load_config
from unified_mcphub.hub import Hub


def _add_prompt_rule(hub_home):
    wf = hub_home / "workspaces" / "default.yaml"
    wf.write_text(wf.read_text() + '    - tool: "mcp://*/read_*"\n      effect: prompt\n')


@pytest.mark.asyncio
async def test_prompt_allow_always_persists_exact_rule(hub_home, monkeypatch):
    _add_prompt_rule(hub_home)
    monkeypatch.setattr("sys.stdin", io.StringIO("c\n"))  # allow_always (this command)

    config = load_config()
    hub = Hub(config)
    hub.approval.channel = TerminalChannel()  # force the TUI path (isatty() is False under pytest)
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
                    "params": {"name": "filesystem__read_file", "arguments": {"path": "x"}},
                },
                headers={"X-Caller-Id": "claude-code"},
            )
            body = r.json()
            assert "result" in body, body
            assert body["result"]["isError"] is False
    finally:
        await hub.stop()

    date = datetime.now(timezone.utc).date().isoformat()
    entries = [
        json.loads(line) for line in (hub_home / "audit" / f"{date}.jsonl").read_text().splitlines()
    ]
    received = [e for e in entries if e["phase"] == "received"][-1]
    assert received["authz_decision"] == "prompt_allowed"

    # allow_always wrote a precedence-1 exact rule, scoped to the call's primary
    # arg, to the machine-managed .local.yaml (ADR-0024/0025) — never into the
    # hand-curated workspace file.
    import yaml

    workspaces = hub_home / "workspaces"
    learned = yaml.safe_load((workspaces / "default.local.yaml").read_text())
    assert learned[0]["tool"] == "mcp://filesystem/read_file"
    assert learned[0]["args_filter"] == {"path": {"equals": ["x"]}}
    assert "mcp://filesystem/read_file" not in (workspaces / "default.yaml").read_text()


@pytest.mark.asyncio
async def test_background_prompt_denies_no_channel(hub_home):
    _add_prompt_rule(hub_home)
    config = load_config()
    hub = Hub(config)
    hub.approval.channel = None  # detached hub -> no TUI / no approval channel
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
                    "params": {"name": "filesystem__read_file", "arguments": {"path": "x"}},
                },
                headers={"X-Caller-Id": "claude-code"},
            )
            assert "error" in r.json()
    finally:
        await hub.stop()

    date = datetime.now(timezone.utc).date().isoformat()
    entries = [
        json.loads(line) for line in (hub_home / "audit" / f"{date}.jsonl").read_text().splitlines()
    ]
    rec = [e for e in entries if e["phase"] == "received"][-1]
    assert rec["authz_decision"] == "prompt_denied"
    assert rec["reason"] == "no_approval_channel"
    assert not [e for e in entries if e["phase"] == "completed"]  # denied -> received only
