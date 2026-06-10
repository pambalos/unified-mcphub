"""Unit tests for the OpenClaw installer — spec §11 (UAI-108)."""

from __future__ import annotations

import json

import pytest

from unified_mcphub import installers
from unified_mcphub.installers import _common, openclaw

URL = "http://127.0.0.1:8765/mcp"


def test_openclaw_is_registered():
    assert "openclaw" in installers.list_harnesses()


def test_install_merges_streamable_http_entry(hub_home, tmp_path, monkeypatch):
    cfg = tmp_path / "openclaw.json"
    monkeypatch.setattr(openclaw, "_config_path", lambda: cfg)
    monkeypatch.setattr(openclaw.endpoints, "http_url", lambda *a, **k: URL)
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: False)

    openclaw.install(dry_run=False)

    entry = json.loads(cfg.read_text())["mcp"]["servers"]["unified-hub"]
    assert entry["url"] == URL
    assert entry["transport"] == "streamable-http"
    assert entry["enabled"] is True
    assert entry["headers"]["X-Caller-Id"] == "openclaw"
    assert entry["headers"]["Authorization"].startswith("Bearer ")


def test_install_errors_without_tcp(hub_home, monkeypatch):
    monkeypatch.setattr(openclaw.endpoints, "http_url", lambda *a, **k: None)
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: False)
    with pytest.raises(SystemExit):
        openclaw.install(dry_run=False)


def test_uninstall_removes_only_the_hub_entry(hub_home, tmp_path, monkeypatch):
    cfg = tmp_path / "openclaw.json"
    cfg.write_text(json.dumps({"mcp": {"servers": {"unified-hub": {"url": "x"}, "other": {}}}}))
    monkeypatch.setattr(openclaw, "_config_path", lambda: cfg)

    openclaw.uninstall(dry_run=False)

    servers = json.loads(cfg.read_text())["mcp"]["servers"]
    assert "unified-hub" not in servers
    assert "other" in servers


def test_dispatch_install_routes_to_openclaw(hub_home, tmp_path, monkeypatch):
    cfg = tmp_path / "openclaw.json"
    monkeypatch.setattr(openclaw, "_config_path", lambda: cfg)
    monkeypatch.setattr(openclaw.endpoints, "http_url", lambda *a, **k: URL)
    monkeypatch.setattr(_common, "harness_cli_present", lambda binary: False)

    installers.dispatch_install("openclaw")

    assert "unified-hub" in json.loads(cfg.read_text())["mcp"]["servers"]
