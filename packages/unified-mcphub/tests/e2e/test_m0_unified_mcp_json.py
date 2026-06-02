"""Canonical truth file + discovery entry on start — spec §11.1, §12, §16."""

from __future__ import annotations

import json
import stat

import pytest

from unified_mcphub.config import canonical_truth_path, discovery_path, load_config
from unified_mcphub.hub import Hub


@pytest.mark.asyncio
async def test_canonical_truth_and_discovery_written_on_start(hub_home):
    hub = Hub(load_config())
    await hub.start()
    try:
        truth = json.loads(canonical_truth_path().read_text())
        assert truth["name"] == "unified-hub"
        assert truth["active_workspace"] == "default"
        assert truth["transports"]["unix_socket"]["preferred"] is True
        assert stat.S_IMODE(canonical_truth_path().stat().st_mode) == 0o600

        daemons = json.loads(discovery_path().read_text())["daemons"]
        assert "filesystem" in daemons["unified-mcphub"]["servers"]
    finally:
        await hub.stop()

    # graceful shutdown removes our discovery entry (ADR-0013).
    daemons = json.loads(discovery_path().read_text())["daemons"]
    assert "unified-mcphub" not in daemons
