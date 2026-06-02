"""install opencode — CLI path + config-merge fallback; idempotent (spec §11, §16)."""

from __future__ import annotations

import json
from pathlib import Path

from unified_mcphub import installers
from unified_mcphub.installers import _common



def _config():
    return Path.home() / ".config" / "opencode" / "opencode.json"


def test_config_merge_fallback_idempotent(hub_home, enable_tcp, monkeypatch):
    enable_tcp()
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: False)

    installers.dispatch_install("opencode")
    entry = json.loads(_config().read_text())["mcp"]["unified-hub"]
    assert entry["type"] == "remote"
    assert entry["enabled"] is True
    assert entry["url"] == "http://127.0.0.1:7712/mcp"
    assert entry["headers"]["X-Caller-Id"] == "opencode"

    installers.dispatch_install("opencode")
    assert list(json.loads(_config().read_text())["mcp"]) == ["unified-hub"]


def test_cli_path_invokes_opencode(hub_home, enable_tcp, monkeypatch):
    enable_tcp()
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: True)
    captured: dict = {}
    monkeypatch.setattr(_common.subprocess, "run",
                        lambda cmd, **kw: captured.setdefault("cmd", cmd))

    installers.dispatch_install("opencode")
    assert captured["cmd"][:4] == ["opencode", "mcp", "add", "unified-hub"]
    assert "http://127.0.0.1:7712/mcp" in captured["cmd"]


def test_uninstall_removes_entry(hub_home, enable_tcp, monkeypatch):
    enable_tcp()
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: False)
    installers.dispatch_install("opencode")
    installers.dispatch_uninstall("opencode")
    assert "unified-hub" not in json.loads(_config().read_text()).get("mcp", {})


def test_append_instructions(hub_home, enable_tcp, monkeypatch, tmp_path):
    enable_tcp()
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: False)
    guide = tmp_path / "AGENTS.md"
    guide.write_text("# agents\n")
    installers.dispatch_install("opencode", append_instructions=str(guide))
    assert "MCP hub guidance" in guide.read_text()
