"""End-to-end: `add-server` probes a real stdio server, writes rules, and the
hub picks the server up and serves its tools."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from unified_mcphub import introspect, servers
from unified_mcphub.config import load_config, load_workspace
from unified_mcphub.hub import Hub

FAKE_SERVER = Path(__file__).resolve().parent.parent / "fixtures" / "fake_mcp_server.py"


@pytest.mark.asyncio
async def test_add_server_probes_and_hub_serves(hub_home):
    # add-server runs a probe via asyncio.run internally → run it off the test loop.
    await asyncio.to_thread(
        servers.add_server,
        "fakefs",
        command=sys.executable,
        args=[str(FAKE_SERVER)],
        assume_yes=True,
        no_preflight=False,
    )

    # Rules were proposed from the probe: both fake tools are reads -> allow.
    ws = load_workspace("default")
    assert "fakefs" in ws.servers
    scoped = {
        r.tool: r.effect for r in ws.authz.rules if servers.is_server_scoped(r.tool, "fakefs")
    }
    assert scoped == {"mcp://fakefs/list_files": "allow", "mcp://fakefs/read_file": "allow"}

    # The hub stands the server up and aggregates its tools.
    hub = Hub(load_config())
    await hub.start()
    try:
        await hub.servers["fakefs"].wait_ready(timeout=15)
        result = await asyncio.to_thread(introspect.list_tools)
        assert result["source"] == "hub"
        assert "fakefs__list_files" in result["tools"]
        assert "fakefs__read_file" in result["tools"]
    finally:
        await hub.stop()


@pytest.mark.asyncio
async def test_add_server_unpinned_npx_refused(hub_home):
    with pytest.raises(SystemExit, match="unpinned"):
        await asyncio.to_thread(
            servers.add_server, "mem", npx="@modelcontextprotocol/server-memory", no_probe=True
        )
