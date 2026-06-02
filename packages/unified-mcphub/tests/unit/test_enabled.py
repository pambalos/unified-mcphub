"""`enabled: false` must keep a server's config but never start it (spec §"per-server enable/disable")."""

from __future__ import annotations

import pytest

from unified_mcphub.config import ServerSpec, Upstream, load_config
from unified_mcphub.hub import Hub


def _spec(name: str, *, enabled: bool) -> ServerSpec:
    return ServerSpec(
        upstream=Upstream(command="python", args=["-m", f"unified_mcp_servers.{name}"]),
        enabled=enabled,
    )


@pytest.mark.asyncio
async def test_disabled_server_is_not_started(hub_home, monkeypatch):
    hub = Hub(load_config())
    added: list[str] = []

    async def fake_add(name, spec):
        added.append(name)

    monkeypatch.setattr(hub, "_add_server", fake_add)

    await hub._apply_server_diff({
        "filesystem": _spec("filesystem", enabled=True),
        "shell": _spec("shell", enabled=False),
    })

    assert added == ["filesystem"]  # disabled 'shell' skipped


@pytest.mark.asyncio
async def test_flipping_to_disabled_tears_down_running_server(hub_home, monkeypatch):
    hub = Hub(load_config())

    class FakeRunning:
        def __init__(self):
            self.stopped = False

        async def stop(self):
            self.stopped = True

    running = FakeRunning()
    hub.servers["shell"] = running  # pretend it's already up
    monkeypatch.setattr(hub, "_add_server", lambda *a: None)

    # Reload where 'shell' is now disabled -> treated as absent -> stopped.
    await hub._apply_server_diff({"shell": _spec("shell", enabled=False)})

    assert running.stopped is True
    assert "shell" not in hub.servers
