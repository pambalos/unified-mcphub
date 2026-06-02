"""Unit tests for the discovery file writer — spec §12, ADR-0013."""

from __future__ import annotations

import json
import stat

from unified_mcphub import discovery
from unified_mcphub.config import discovery_path


def test_publish_refresh_remove_roundtrip(hub_home):
    discovery.publish(
        listen={"unix_socket": "/tmp/x.sock"},
        servers=["filesystem", "github"],
        config_hash="sha256:abc123",
        started_at="2026-01-01T00:00:00Z",
    )
    entry = json.loads(discovery_path().read_text())["daemons"]["unified-mcphub"]
    assert entry["servers"] == ["filesystem", "github"]
    assert entry["pid"] > 0
    assert entry["config_hash"] == "sha256:abc123"

    discovery.refresh()  # liveness heartbeat; entry stays
    assert "unified-mcphub" in json.loads(discovery_path().read_text())["daemons"]

    discovery.remove()  # graceful shutdown
    assert "unified-mcphub" not in json.loads(discovery_path().read_text())["daemons"]


def test_publish_creates_dir_with_0600(hub_home):
    discovery.publish(listen={}, servers=[], config_hash="x", started_at="t")
    assert stat.S_IMODE(discovery_path().stat().st_mode) == 0o600
