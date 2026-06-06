"""Remote approval over the control API — UAI-107 / UAI-109.

A headless hub with `approval.remote` enabled blocks a `prompt`-effect call until
an out-of-process client resolves it over the control API (the surface the TUI
and the Discord bridge both use). Covers: the allow/deny round-trip end to end,
the SSE pending stream, and first-responder-wins on the decision endpoint.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from unified_mcphub.config import load_config
from unified_mcphub.hub import Hub

CALL = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "filesystem__read_file", "arguments": {"path": "x"}},
}


def _add_prompt_rule(hub_home):
    wf = hub_home / "workspaces" / "default.yaml"
    wf.write_text(wf.read_text() + '    - tool: "mcp://*/read_*"\n      effect: prompt\n')


def _remote_hub(hub_home) -> tuple[Hub, Path]:
    _add_prompt_rule(hub_home)
    config = load_config()
    config.hub.approval.remote = True
    config.hub.approval.remote_timeout_s = 15
    hub = Hub(config)
    return hub, Path(config.hub.listen.unix_socket)


def _client(sock: Path) -> httpx.AsyncClient:
    transport = httpx.AsyncHTTPTransport(uds=str(sock))
    return httpx.AsyncClient(transport=transport, base_url="http://hub", timeout=20)


async def _await_pending(c: httpx.AsyncClient) -> str:
    for _ in range(200):
        await asyncio.sleep(0.05)
        items = (await c.get("/approvals/pending", headers={"X-Caller-Id": "operator"})).json()[
            "pending"
        ]
        if items:
            return items[0]["pending_id"]
    raise AssertionError("no pending surfaced over the control API")


def _last_received(hub_home) -> dict:
    date = datetime.now(timezone.utc).date().isoformat()
    entries = [
        json.loads(line) for line in (hub_home / "audit" / f"{date}.jsonl").read_text().splitlines()
    ]
    return [e for e in entries if e["phase"] == "received"][-1]


@pytest.mark.asyncio
async def test_remote_prompt_allow_round_trip(hub_home):
    hub, sock = _remote_hub(hub_home)
    await hub.start()
    try:
        async with _client(sock) as c:
            call = asyncio.create_task(
                c.post("/mcp", json=CALL, headers={"X-Caller-Id": "claude-code"})
            )
            pending_id = await _await_pending(c)

            decision = await c.post(
                "/approvals/decision",
                json={"pending_id": pending_id, "kind": "allow"},
                headers={"X-Caller-Id": "operator"},
            )
            assert decision.json()["result"] == "accepted"

            body = (await call).json()
            assert "result" in body, body
            assert body["result"]["isError"] is False
    finally:
        await hub.stop()

    assert _last_received(hub_home)["authz_decision"] == "prompt_allowed"


@pytest.mark.asyncio
async def test_remote_prompt_deny_round_trip(hub_home):
    hub, sock = _remote_hub(hub_home)
    await hub.start()
    try:
        async with _client(sock) as c:
            call = asyncio.create_task(
                c.post("/mcp", json=CALL, headers={"X-Caller-Id": "claude-code"})
            )
            pending_id = await _await_pending(c)
            await c.post(
                "/approvals/decision",
                json={"pending_id": pending_id, "kind": "deny"},
                headers={"X-Caller-Id": "operator"},
            )
            assert "error" in (await call).json()
    finally:
        await hub.stop()

    assert _last_received(hub_home)["authz_decision"] == "prompt_denied"


@pytest.mark.asyncio
async def test_remote_decision_first_wins(hub_home):
    hub, sock = _remote_hub(hub_home)
    await hub.start()
    try:
        async with _client(sock) as c:
            call = asyncio.create_task(
                c.post("/mcp", json=CALL, headers={"X-Caller-Id": "claude-code"})
            )
            pending_id = await _await_pending(c)

            first = await c.post(
                "/approvals/decision",
                json={"pending_id": pending_id, "kind": "allow"},
                headers={"X-Caller-Id": "tui"},
            )
            second = await c.post(
                "/approvals/decision",
                json={"pending_id": pending_id, "kind": "deny"},
                headers={"X-Caller-Id": "discord"},
            )
            assert first.json()["result"] == "accepted"
            assert second.json()["result"] == "already_resolved"
            assert (await call).json()["result"]["isError"] is False
    finally:
        await hub.stop()


@pytest.mark.asyncio
async def test_remote_sse_stream_emits_pending_created(hub_home):
    hub, sock = _remote_hub(hub_home)
    await hub.start()
    try:
        async with _client(sock) as c:
            call = asyncio.create_task(
                c.post("/mcp", json=CALL, headers={"X-Caller-Id": "claude-code"})
            )
            saw_created = False
            async with c.stream(
                "GET", "/approvals/stream", headers={"X-Caller-Id": "operator"}
            ) as stream:
                async for line in stream.aiter_lines():
                    if line.startswith("event: pending.created"):
                        saw_created = True
                        break
            assert saw_created

            # Resolve so the blocked call unwinds cleanly.
            pending_id = await _await_pending(c)
            await c.post(
                "/approvals/decision",
                json={"pending_id": pending_id, "kind": "deny"},
                headers={"X-Caller-Id": "operator"},
            )
            await call
    finally:
        await hub.stop()


@pytest.mark.asyncio
async def test_remote_decision_rejects_unknown_kind(hub_home):
    hub, sock = _remote_hub(hub_home)
    await hub.start()
    try:
        async with _client(sock) as c:
            r = await c.post(
                "/approvals/decision",
                json={"pending_id": "whatever", "kind": "maybe"},
                headers={"X-Caller-Id": "operator"},
            )
            assert r.status_code == 400
    finally:
        await hub.stop()
