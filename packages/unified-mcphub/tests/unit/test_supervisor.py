"""Supervisor tests — spec §8. Connect/list/call happy path + failure handling."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from unified_mcphub.config import ServerSpec, Upstream
from unified_mcphub.supervisor import SupervisedServer

FAKE_SERVER = Path(__file__).parent.parent / "fixtures" / "fake_mcp_server.py"


def test_http_upstream_injects_bearer_from_secret():
    # auth_secret_ref must reach the HTTP connection's headers (the A1 seam).
    spec = ServerSpec(upstream=Upstream(url="https://mcp.example/mcp"), auth_secret_ref="gh-token")
    server = SupervisedServer(
        "github", spec, secret_resolver=lambda name: "SEKRET" if name == "gh-token" else None
    )
    conn = server._make_connection()
    assert conn._resolve_headers() == {"Authorization": "Bearer SEKRET"}


def test_http_upstream_without_secret_has_no_auth_header():
    spec = ServerSpec(upstream=Upstream(url="https://mcp.example/mcp"))
    server = SupervisedServer("x", spec, secret_resolver=lambda name: None)
    assert server._make_connection()._resolve_headers() == {}


@pytest.mark.asyncio
async def test_connect_list_and_call():
    spec = ServerSpec(upstream=Upstream(command=sys.executable, args=[str(FAKE_SERVER)]))
    server = SupervisedServer("fs", spec)
    await server.start()
    try:
        await server.wait_ready(timeout=30)
        assert server.healthy
        assert any(t.name == "list_files" for t in server.tools)
        result = await server.call("list_files", {"path": "."})
        assert "alpha.txt" in str(result.content)
    finally:
        await server.stop()


def test_python_command_resolves_to_hub_interpreter():
    # A bare `python`/`python3` upstream must spawn under the hub's own
    # interpreter (which has the bundled unified_mcp_servers package).
    for cmd in ("python", "python3"):
        spec = ServerSpec(upstream=Upstream(command=cmd, args=["-m", "unified_mcp_servers.shell"]))
        conn = SupervisedServer("fetch", spec)._make_connection()
        assert conn._params.command == sys.executable


def test_other_commands_left_untouched():
    spec = ServerSpec(upstream=Upstream(command="npx", args=["-y", "x"]))
    conn = SupervisedServer("ext", spec)._make_connection()
    assert conn._params.command == "npx"


@pytest.mark.asyncio
async def test_bundled_server_boots_via_python_resolution():
    # End-to-end: `command: python` resolution lets a bundled server connect.
    spec = ServerSpec(
        upstream=Upstream(command="python", args=["-m", "unified_mcp_servers.python"])
    )
    server = SupervisedServer("python", spec)
    await server.start()
    try:
        await server.wait_ready(timeout=30)
        assert any(t.name == "check_syntax" for t in server.tools)
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_bad_command_never_ready_and_records_error():
    spec = ServerSpec(upstream=Upstream(command="unified-mcphub-no-such-binary-xyz"))
    server = SupervisedServer("bad", spec)
    await server.start()
    try:
        with pytest.raises(asyncio.TimeoutError):
            await server.wait_ready(timeout=3)
        assert server.last_error is not None
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_container_upstream_unsupported_at_m0():
    spec = ServerSpec(upstream=Upstream(image="ghcr.io/unified-ai/mcp-fs@sha256:abc"))
    server = SupervisedServer("c", spec)
    await server.start()
    try:
        with pytest.raises(asyncio.TimeoutError):
            await server.wait_ready(timeout=2)
        assert "M0.5" in (server.last_error or "")
    finally:
        await server.stop()
