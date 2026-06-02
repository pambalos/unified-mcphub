"""introspect.list_tools queries the running hub over its Unix socket (spec §13)."""

from __future__ import annotations

import asyncio

import pytest

from unified_mcphub import introspect
from unified_mcphub.config import load_config
from unified_mcphub.hub import Hub


@pytest.mark.asyncio
async def test_list_tools_queries_running_hub(hub_home):
    hub = Hub(load_config())
    await hub.start()
    try:
        await hub.servers["filesystem"].wait_ready(timeout=15)
        # list_tools() uses asyncio.run internally, so run it off the test's loop.
        result = await asyncio.to_thread(introspect.list_tools)
        assert result["source"] == "hub"
        assert "filesystem__list_files" in result["tools"]
    finally:
        await hub.stop()
