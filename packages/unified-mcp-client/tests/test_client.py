"""Integration tests for the async MCP client against a stdio fake server."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from unified_mcp_client import StdioConnection, types

FAKE_SERVER = Path(__file__).parent / "fake_server.py"


@pytest.mark.asyncio
async def test_stdio_connect_list_call():
    async with StdioConnection(sys.executable, [str(FAKE_SERVER)]) as conn:
        tools = await conn.list_tools()
        assert all(isinstance(t, types.Tool) for t in tools)
        assert any(t.name == "echo" for t in tools)

        result = await conn.call_tool("echo", {"text": "hi"})
        assert isinstance(result, types.CallToolResult)
        assert "echo: hi" in str(result.content)


@pytest.mark.asyncio
async def test_connect_close_explicit():
    conn = StdioConnection(sys.executable, [str(FAKE_SERVER)])
    await conn.connect()
    try:
        assert any(t.name == "echo" for t in await conn.list_tools())
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_call_before_connect_raises():
    conn = StdioConnection(sys.executable, [str(FAKE_SERVER)])
    with pytest.raises(RuntimeError):
        await conn.call_tool("echo", {"text": "x"})
