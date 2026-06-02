"""File-watch config reload — spec §8. Reload re-validates and applies a server
+ rule diff to the running hub (the watcher trigger is exercised via _reload()).
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

from unified_mcphub.authz import Effect
from unified_mcphub.config import load_config
from unified_mcphub.hub import Hub

FAKE_SERVER = Path(__file__).parent.parent / "fixtures" / "fake_mcp_server.py"


@pytest.mark.asyncio
async def test_reload_applies_rule_and_server_diff(hub_home):
    hub = Hub(load_config())
    await hub.start()
    try:
        # default: only list_* allowed; the filesystem server is connected.
        assert hub.authz.resolve("mcp://filesystem/read_file", {}, "claude-code").effect is Effect.DENY
        assert "filesystem" in hub.servers

        (hub_home / "workspaces" / "default.yaml").write_text(
            textwrap.dedent(
                """
                servers: {}
                authz:
                  rules:
                    - tool: "mcp://*/*"
                      effect: allow
                """
            ).strip()
            + "\n"
        )
        await hub._reload()

        assert hub.authz.resolve("mcp://filesystem/read_file", {}, "claude-code").effect is Effect.ALLOW
        assert "filesystem" not in hub.servers  # server removed by the diff
    finally:
        await hub.stop()


@pytest.mark.asyncio
async def test_reload_restarts_changed_server(hub_home):
    hub = Hub(load_config())
    await hub.start()
    try:
        await hub.servers["filesystem"].wait_ready(timeout=15)
        before = id(hub.servers["filesystem"])

        # Same server name, changed upstream args -> spec differs -> restart.
        (hub_home / "workspaces" / "default.yaml").write_text(
            textwrap.dedent(
                f"""
                servers:
                  filesystem:
                    upstream:
                      command: {sys.executable}
                      args: ["{FAKE_SERVER}", "ignored-extra-arg"]
                authz:
                  rules:
                    - tool: "mcp://*/list_*"
                      effect: allow
                """
            ).strip()
            + "\n"
        )
        await hub._reload()

        assert "filesystem" in hub.servers
        assert id(hub.servers["filesystem"]) != before  # restarted (fresh supervisor)
        await hub.servers["filesystem"].wait_ready(timeout=15)
    finally:
        await hub.stop()


@pytest.mark.asyncio
async def test_reload_keeps_prior_config_on_invalid_yaml(hub_home):
    hub = Hub(load_config())
    await hub.start()
    try:
        before = hub.config.workspace.authz.rules
        (hub_home / "workspaces" / "default.yaml").write_text("authz: [this is not a mapping]\n")
        await hub._reload()  # must not raise; keeps prior config
        assert hub.config.workspace.authz.rules == before
    finally:
        await hub.stop()
