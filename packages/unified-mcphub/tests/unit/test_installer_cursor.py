"""Unit tests for the Cursor installer — spec §11 (M1 adapter)."""

from __future__ import annotations

import json

import pytest

from unified_mcphub import installers
from unified_mcphub.installers import cursor
from unified_mcphub.tokens import TokenStore

URL = "http://127.0.0.1:8765/mcp"


def test_cursor_is_registered():
    assert "cursor" in installers.list_harnesses()


def test_install_merges_http_entry_with_cursor_caller(hub_home, tmp_path, monkeypatch):
    cfg = tmp_path / "mcp.json"
    monkeypatch.setattr(cursor, "_config_path", lambda scope: cfg)
    monkeypatch.setattr(cursor.endpoints, "http_url", lambda *a, **k: URL)

    cursor.install(dry_run=False)

    entry = json.loads(cfg.read_text())["mcpServers"]["unified-hub"]
    assert entry["url"] == URL
    assert entry["headers"]["X-Caller-Id"] == "cursor"
    assert entry["headers"]["Authorization"].startswith("Bearer ")
    # A dedicated cursor token is minted — identity is the token, not the header.
    assert (hub_home / "caller-tokens" / "cursor.token").exists()


def test_install_errors_without_tcp(hub_home, monkeypatch):
    monkeypatch.setattr(cursor.endpoints, "http_url", lambda *a, **k: None)
    with pytest.raises(SystemExit):
        cursor.install(dry_run=False)


def test_project_scope_writes_project_file(hub_home, tmp_path, monkeypatch):
    monkeypatch.setattr(cursor.endpoints, "http_url", lambda *a, **k: URL)
    monkeypatch.chdir(tmp_path)

    cursor.install(dry_run=False, scope="project")

    proj = tmp_path / ".cursor" / "mcp.json"
    assert "unified-hub" in json.loads(proj.read_text())["mcpServers"]


def test_uninstall_removes_only_the_hub_entry_and_revokes(hub_home, tmp_path, monkeypatch):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"unified-hub": {"url": "x"}, "other": {}}}))
    monkeypatch.setattr(cursor, "_config_path", lambda scope: cfg)
    TokenStore().mint("cursor")

    cursor.uninstall(dry_run=False)

    servers = json.loads(cfg.read_text())["mcpServers"]
    assert "unified-hub" not in servers
    assert "other" in servers
    assert not (hub_home / "caller-tokens" / "cursor.token").exists()


def test_dispatch_install_routes_to_cursor(hub_home, tmp_path, monkeypatch):
    cfg = tmp_path / "mcp.json"
    monkeypatch.setattr(cursor, "_config_path", lambda scope: cfg)
    monkeypatch.setattr(cursor.endpoints, "http_url", lambda *a, **k: URL)

    installers.dispatch_install("cursor")

    assert "unified-hub" in json.loads(cfg.read_text())["mcpServers"]
