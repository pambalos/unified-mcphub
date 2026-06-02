"""install claude-code — CLI path + JSON-merge fallback; idempotent (spec §11, §16)."""

from __future__ import annotations

import json
from pathlib import Path

from unified_mcphub import installers
from unified_mcphub.installers import _common



def test_json_merge_fallback_idempotent(hub_home, enable_tcp, monkeypatch):
    enable_tcp()
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: False)

    installers.dispatch_install("claude-code")
    config = Path.home() / ".claude.json"
    entry = json.loads(config.read_text())["mcpServers"]["unified-hub"]
    assert entry["type"] == "http"
    assert entry["url"] == "http://127.0.0.1:7712/mcp"
    assert entry["headers"]["X-Caller-Id"] == "claude-code"
    assert entry["headers"]["Authorization"].startswith("Bearer ")

    installers.dispatch_install("claude-code")  # idempotent + backs up
    assert list(json.loads(config.read_text())["mcpServers"]) == ["unified-hub"]
    assert list(config.parent.glob(".claude.json.backup-*"))


def test_cli_path_invokes_claude(hub_home, enable_tcp, monkeypatch):
    enable_tcp()
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: True)
    captured: dict = {}
    monkeypatch.setattr(_common.subprocess, "run",
                        lambda cmd, **kw: captured.setdefault("cmd", cmd))

    installers.dispatch_install("claude-code")
    cmd = captured["cmd"]
    assert cmd[:4] == ["claude", "mcp", "add", "unified-hub"]
    assert "http://127.0.0.1:7712/mcp" in cmd
    assert any("X-Caller-Id: claude-code" in part for part in cmd)


def test_uninstall_removes_entry(hub_home, enable_tcp, monkeypatch):
    enable_tcp()
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: False)
    installers.dispatch_install("claude-code")
    installers.dispatch_uninstall("claude-code")
    config = Path.home() / ".claude.json"
    assert "unified-hub" not in json.loads(config.read_text()).get("mcpServers", {})
