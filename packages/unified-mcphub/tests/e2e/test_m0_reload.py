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
        assert (
            hub.authz.resolve("mcp://filesystem/read_file", {}, "claude-code").effect is Effect.DENY
        )
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

        assert (
            hub.authz.resolve("mcp://filesystem/read_file", {}, "claude-code").effect
            is Effect.ALLOW
        )
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


def test_watch_covers_workspaces_dir_for_late_created_local(hub_home):
    # The learned-rules <name>.local.yaml may not exist at hub startup. Watching
    # the whole workspaces directory (not the individual files) means a .local.yaml
    # created/edited/removed mid-session still triggers a hot-reload (ADR-0024) —
    # awatch can't watch a path that is absent when the watch starts.
    paths = Hub(load_config())._watch_paths()
    assert str(hub_home / "config.yaml") in paths
    assert str(hub_home / "workspaces") in paths
    # The not-yet-existing local file must NOT be watched directly (would raise).
    assert str(hub_home / "workspaces" / "default.local.yaml") not in paths


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


@pytest.mark.asyncio
async def test_reload_does_not_change_the_deployment_profile(hub_home):
    """The deployment security profile is fixed at boot (UAI-216).

    It describes how this process was deployed, not what the config file
    currently says. Re-reading it would let the one control that protects
    policy from tampering be switched off by editing the very file it
    protects, so `locked` -> `open` must not survive a reload.
    """
    config = hub_home / "config.yaml"
    config.write_text(
        textwrap.dedent(
            """
            deployment:
              policy_protection: locked
            """
        ).strip()
        + "\n"
    )
    hub = Hub(load_config())
    await hub.start()
    try:
        assert hub.config.hub.deployment.is_locked
        policy_file = str(hub_home / "config.yaml")
        assert (
            hub.authz.resolve(
                "mcp://filesystem/edit_file", {"path": policy_file}, "claude-code"
            ).effect
            is Effect.DENY
        )

        # An agent (or anyone) edits the profile back to open and a reload runs.
        config.write_text(
            textwrap.dedent(
                """
                deployment:
                  policy_protection: open
                """
            ).strip()
            + "\n"
        )
        await hub._reload()

        # Still locked, and the config dir is still not agent-writable.
        assert hub.config.hub.deployment.is_locked
        assert (
            hub.authz.resolve(
                "mcp://filesystem/edit_file", {"path": policy_file}, "claude-code"
            ).effect
            is Effect.DENY
        )
    finally:
        await hub.stop()
