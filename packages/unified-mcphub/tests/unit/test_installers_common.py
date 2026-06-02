"""Unit tests for shared install mechanics — spec §11."""

from __future__ import annotations

import json

import pytest

from unified_mcphub import endpoints, installers
from unified_mcphub.installers import _common


def test_http_url_none_when_tcp_disabled(hub_home):
    assert endpoints.http_url() is None  # default fixture config has tcp_enabled: false


def test_install_errors_without_tcp(hub_home, monkeypatch):
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: False)
    with pytest.raises(SystemExit):
        installers.dispatch_install("claude-code")


def test_append_guidance_writes(tmp_path):
    guide = tmp_path / "CLAUDE.md"
    guide.write_text("# project\n")
    _common.append_guidance(guide, dry_run=False)
    assert "MCP hub guidance" in guide.read_text()


def test_append_guidance_dry_run(tmp_path, capsys):
    guide = tmp_path / "CLAUDE.md"
    _common.append_guidance(guide, dry_run=True)
    assert "[dry-run]" in capsys.readouterr().out
    assert not guide.exists()


def test_remove_json_noop_when_file_missing(tmp_path):
    _common.remove_json(tmp_path / "absent.json", ["mcpServers"], "x", dry_run=False)  # no raise


def test_remove_json_noop_when_key_absent(tmp_path):
    path = tmp_path / "c.json"
    path.write_text('{"other": {}}')
    _common.remove_json(path, ["mcpServers"], "x", dry_run=False)
    assert json.loads(path.read_text()) == {"other": {}}
