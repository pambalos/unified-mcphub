"""The operator reload endpoint — apply on-disk config without a restart (UAI-216).

In a `locked` deployment, file-watch never auto-applies a policy change under
`manual`/`approval`; `POST /reload` is the explicit operator apply. These start a
real hub over its unix socket (TCP disabled, so nothing collides with a hub that
may already be running) and drive the endpoint the way the CLI does.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from unified_mcphub.config import load_config
from unified_mcphub.hub import Hub


def _client(sock: Path) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.AsyncHTTPTransport(uds=str(sock)), base_url="http://hub", timeout=20
    )


async def _started_hub(hub_home):
    config = load_config()
    config.hub.listen.tcp_enabled = False  # unix socket only — no port collision
    hub = Hub(config)
    await hub.start()
    return hub, Path(config.hub.listen.unix_socket)


def _append_rule(hub_home) -> None:
    wf = hub_home / "workspaces" / "default.yaml"
    wf.write_text(wf.read_text() + '    - tool: "mcp://nothing/x"\n      effect: deny\n')


@pytest.mark.asyncio
async def test_reload_applies_a_changed_workspace(hub_home):
    hub, sock = await _started_hub(hub_home)
    try:
        before = len(hub.config.workspace.authz.rules)
        _append_rule(hub_home)
        async with _client(sock) as c:
            resp = await c.post("/reload", headers={"X-Caller-Id": "cli"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["applied"] is True
        assert body["changed"] is True
        # The new rule is live without a restart.
        assert len(hub.config.workspace.authz.rules) == before + 1
    finally:
        await hub.stop()


@pytest.mark.asyncio
async def test_reload_with_no_change_reports_unchanged(hub_home):
    hub, sock = await _started_hub(hub_home)
    try:
        async with _client(sock) as c:
            resp = await c.post("/reload", headers={"X-Caller-Id": "cli"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["applied"] is True
        assert body["changed"] is False
    finally:
        await hub.stop()


@pytest.mark.asyncio
async def test_reload_applies_even_under_manual_mode(hub_home):
    """The whole point: `manual` reload does not auto-apply on file change, but
    an explicit reload does. Confirms the endpoint is the human-in-the-loop path,
    not blocked by the same gate that stops the file-watcher."""
    config = load_config()
    config.hub.listen.tcp_enabled = False
    config.hub.deployment.reload_mode = "manual"
    hub = Hub(config)
    await hub.start()
    try:
        before = len(hub.config.workspace.authz.rules)
        _append_rule(hub_home)
        async with _client(Path(config.hub.listen.unix_socket)) as c:
            body = (await c.post("/reload", headers={"X-Caller-Id": "cli"})).json()
        assert body["applied"] is True and body["changed"] is True
        assert len(hub.config.workspace.authz.rules) == before + 1
    finally:
        await hub.stop()


def _append_allow(hub_home) -> None:
    wf = hub_home / "workspaces" / "default.yaml"
    wf.write_text(wf.read_text() + '    - tool: "mcp://anything/danger"\n      effect: allow\n')


@pytest.mark.asyncio
async def test_reload_surfaces_a_broadening_change(hub_home):
    """A reload that adds an allow rule reports it, so the operator applying it
    sees exactly what was granted (Enh B5)."""
    hub, sock = await _started_hub(hub_home)
    try:
        _append_allow(hub_home)
        async with _client(sock) as c:
            body = (await c.post("/reload", headers={"X-Caller-Id": "cli"})).json()
        assert body["applied"] is True
        broadening = body["broadening"]
        assert len(broadening) == 1
        assert broadening[0]["tool"] == "mcp://anything/danger"
        assert broadening[0]["note"] == "new allow rule"
    finally:
        await hub.stop()


@pytest.mark.asyncio
async def test_a_benign_reload_reports_no_broadening(hub_home):
    hub, sock = await _started_hub(hub_home)
    try:
        _append_rule(hub_home)  # a deny rule — narrows, does not broaden
        async with _client(sock) as c:
            body = (await c.post("/reload", headers={"X-Caller-Id": "cli"})).json()
        assert body["broadening"] == []
    finally:
        await hub.stop()
