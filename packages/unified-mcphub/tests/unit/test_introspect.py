"""Unit tests for introspection CLIs — spec §13 (MCP-HUB-6)."""

from __future__ import annotations

import textwrap

import pytest

from unified_mcphub import introspect
from unified_mcphub.config import load_hub_config


def test_list_and_active_workspace(hub_home):
    assert introspect.list_workspaces() == ["default"]
    assert introspect.active_workspace() == "default"


def test_show_workspace(hub_home):
    shown = introspect.show_workspace()
    assert shown["name"] == "default"
    assert "filesystem" in shown["servers"]


def test_use_workspace_switches_active(hub_home):
    (hub_home / "workspaces" / "personal.yaml").write_text(
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
    introspect.use_workspace("personal")
    assert load_hub_config().active_workspace == "personal"


def test_use_unknown_workspace_raises(hub_home):
    with pytest.raises(FileNotFoundError):
        introspect.use_workspace("ghost")


def test_list_servers(hub_home):
    servers = introspect.list_servers()
    assert servers == [{"name": "filesystem", "kind": "process"}]


def test_list_packs_empty_by_default(hub_home):
    assert introspect.list_packs() == []


def test_list_tools_falls_back_to_builtins_when_hub_down(hub_home):
    result = introspect.list_tools()
    assert result["source"].startswith("builtins")
    assert "built-in__ping" in result["tools"]
