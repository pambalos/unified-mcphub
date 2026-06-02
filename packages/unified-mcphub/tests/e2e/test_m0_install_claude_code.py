"""install claude-code — CLI path + JSON-merge fallback; idempotent (spec §11, §16)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from unified_mcphub import installers
from unified_mcphub.installers import _common



def _local_node(config: Path) -> dict:
    """The local-scope mcpServers node: ~/.claude.json projects[<cwd>].mcpServers."""
    return (
        json.loads(config.read_text())
        .get("projects", {})
        .get(str(Path.cwd()), {})
        .get("mcpServers", {})
    )


def test_json_merge_fallback_idempotent(hub_home, enable_tcp, monkeypatch):
    enable_tcp()
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: False)

    installers.dispatch_install("claude-code")  # default scope = local
    config = Path.home() / ".claude.json"
    entry = _local_node(config)["unified-hub"]
    assert entry["type"] == "http"
    assert entry["url"] == "http://127.0.0.1:7712/mcp"
    assert entry["headers"]["X-Caller-Id"] == "claude-code"
    assert entry["headers"]["Authorization"].startswith("Bearer ")
    # local scope must NOT leak into the global top-level mcpServers.
    assert "unified-hub" not in json.loads(config.read_text()).get("mcpServers", {})

    installers.dispatch_install("claude-code")  # idempotent + backs up
    assert list(_local_node(config)) == ["unified-hub"]
    assert list(config.parent.glob(".claude.json.backup-*"))


def test_user_scope_writes_top_level(hub_home, enable_tcp, monkeypatch):
    enable_tcp()
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: False)

    installers.dispatch_install("claude-code", scope="user")
    config = Path.home() / ".claude.json"
    top = json.loads(config.read_text())["mcpServers"]
    assert top["unified-hub"]["url"] == "http://127.0.0.1:7712/mcp"
    # user scope is global — it must not be nested under a project.
    assert "unified-hub" not in _local_node(config)


def _fake_run(captured: dict):
    def run(cmd, **kw):
        captured["cmd"] = cmd
        return SimpleNamespace(stdout="", stderr="", returncode=0)
    return run


def test_cli_path_invokes_claude(hub_home, enable_tcp, monkeypatch):
    enable_tcp()
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: True)
    captured: dict = {}
    monkeypatch.setattr(_common.subprocess, "run", _fake_run(captured))

    installers.dispatch_install("claude-code", scope="user")
    cmd = captured["cmd"]
    assert cmd[:4] == ["claude", "mcp", "add", "unified-hub"]
    assert "http://127.0.0.1:7712/mcp" in cmd
    assert any("X-Caller-Id: claude-code" in part for part in cmd)
    assert cmd[cmd.index("--scope") + 1] == "user"


def test_run_cli_redacts_token_in_output(monkeypatch, capsys):
    token = "a" * 64
    monkeypatch.setattr(
        _common.subprocess, "run",
        lambda cmd, **kw: SimpleNamespace(
            stdout=f"Headers: Authorization: Bearer {token}\n", stderr="", returncode=0
        ),
    )
    _common.run_cli(["claude", "mcp", "add"], dry_run=False)
    out = capsys.readouterr().out
    assert token not in out
    assert "Bearer [REDACTED]" in out


def test_redaction_hook_installed_and_removed(hub_home, enable_tcp, monkeypatch):
    enable_tcp()
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: True)
    monkeypatch.setattr(_common.subprocess, "run", _fake_run({}))

    installers.dispatch_install("claude-code", scope="user", with_redaction_hook=True)
    settings = json.loads((Path.home() / ".claude" / "settings.json").read_text())
    groups = settings["hooks"]["PreToolUse"]
    cmds = [h["command"] for g in groups for h in g["hooks"]]
    assert any("#RDCT_HOOK" in c for c in cmds)
    assert all(g["hooks"][0]["if"] == "Bash(claude mcp *)" for g in groups)

    # idempotent: a second install doesn't duplicate the hook group
    installers.dispatch_install("claude-code", scope="user", with_redaction_hook=True)
    groups = json.loads((Path.home() / ".claude" / "settings.json").read_text())["hooks"]["PreToolUse"]
    assert sum("#RDCT_HOOK" in h["command"] for g in groups for h in g["hooks"]) == 1

    installers.dispatch_uninstall("claude-code", scope="user")
    groups = json.loads((Path.home() / ".claude" / "settings.json").read_text())["hooks"]["PreToolUse"]
    assert not any("#RDCT_HOOK" in h["command"] for g in groups for h in g["hooks"])


def test_uninstall_removes_entry(hub_home, enable_tcp, monkeypatch):
    enable_tcp()
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: False)
    installers.dispatch_install("claude-code")
    installers.dispatch_uninstall("claude-code")
    config = Path.home() / ".claude.json"
    assert "unified-hub" not in _local_node(config)
