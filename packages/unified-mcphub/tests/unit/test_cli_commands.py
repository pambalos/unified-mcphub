"""CLI command handlers (non-interactive) — spec §13. Exercised via main() under hub_home."""

from __future__ import annotations

import json

import pytest

from unified_mcphub.cli import main
from unified_mcphub.config import audit_dir
from unified_mcphub.installers import _common


def test_workspace_list_marks_active(hub_home, capsys):
    assert main(["workspace", "list"]) == 0
    assert "* default" in capsys.readouterr().out


def test_workspace_show(hub_home, capsys):
    assert main(["workspace", "show"]) == 0
    assert "filesystem" in capsys.readouterr().out


def test_workspace_use(hub_home, capsys):
    (hub_home / "workspaces" / "personal.yaml").write_text("servers: {}\nauthz:\n  rules: []\n")
    assert main(["workspace", "use", "personal"]) == 0
    assert "personal" in capsys.readouterr().out


def test_list_servers_and_packs(hub_home, capsys):
    assert main(["list-servers"]) == 0
    assert "filesystem" in capsys.readouterr().out
    assert main(["list-packs"]) == 0  # empty floor


def test_list_tools_fallback(hub_home, capsys):
    assert main(["list-tools"]) == 0
    assert "built-in__ping" in capsys.readouterr().out


def test_secrets_set_list_remove(hub_home, fake_keyring, monkeypatch, capsys):
    monkeypatch.setattr("getpass.getpass", lambda *a, **k: "sekret")

    assert main(["secrets", "set", "mykey"]) == 0
    assert main(["secrets", "list"]) == 0
    assert "mykey" in capsys.readouterr().out
    assert main(["secrets", "remove", "mykey"]) == 0


def test_install_via_main(hub_home, enable_tcp, monkeypatch):
    enable_tcp()
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: False)
    assert main(["install", "claude-code"]) == 0
    assert main(["uninstall", "claude-code"]) == 0


def test_auth_revoke(hub_home, fake_keyring):
    assert main(["auth", "revoke", "github"]) == 0


def test_auth_login_without_oauth_config_errors(hub_home):
    # the seeded `filesystem` server has no `oauth:` block.
    with pytest.raises(SystemExit):
        main(["auth", "login", "filesystem"])


def test_audit_commands(hub_home, capsys):
    directory = audit_dir()
    directory.mkdir(parents=True)
    (directory / "2026-01-01.jsonl").write_text(
        json.dumps({"phase": "received", "request_id": "r1", "authz_decision": "deny",
                    "ts": "2026-01-01T00:00:00+00:00", "caller_id": "claude-code"}) + "\n"
    )
    assert main(["audit", "show", "r1"]) == 0
    assert main(["audit", "pair", "r1"]) == 0
    assert main(["audit", "search", "--caller", "claude-code"]) == 0
    assert main(["audit", "tail"]) == 0
    assert main(["audit", "lint"]) == 0
    assert main(["audit", "prune"]) == 0
