"""Async connection to a single upstream MCP server.

Built on the official `mcp` SDK. `StdioConnection` spawns a stdio MCP server
subprocess; `HttpConnection` speaks streamable-HTTP. Both reuse `mcp.types`
as the wire/interchange types (ADR-0023).

anyio constraint: a connection's enter and exit must happen in the same task.
Use `async with conn:` (natural), or call `connect()`/`close()` from one task.
"""

from __future__ import annotations

import contextlib
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamablehttp_client

HeadersProvider = Callable[[], Mapping[str, str]]


class MCPConnection(ABC):
    """One live MCP session. Subclasses provide the transport streams."""

    def __init__(self) -> None:
        self._session: ClientSession | None = None
        self._stack: contextlib.AsyncExitStack | None = None

    @abstractmethod
    def _streams_cm(self) -> Any:
        """Return the SDK transport context manager yielding (read, write, ...)."""

    async def connect(self) -> "MCPConnection":
        stack = contextlib.AsyncExitStack()
        try:
            streams = await stack.enter_async_context(self._streams_cm())
            read, write = streams[0], streams[1]
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
        except BaseException:
            await stack.aclose()
            raise
        self._stack = stack
        self._session = session
        return self

    async def close(self) -> None:
        stack, self._stack, self._session = self._stack, None, None
        if stack is not None:
            await stack.aclose()

    async def __aenter__(self) -> "MCPConnection":
        return await self.connect()

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def list_tools(self) -> list[types.Tool]:
        return (await self._require().list_tools()).tools

    async def call_tool(self, name: str, arguments: Mapping[str, Any]) -> types.CallToolResult:
        return await self._require().call_tool(name, dict(arguments))

    def _require(self) -> ClientSession:
        if self._session is None:
            raise RuntimeError("MCP connection is not established")
        return self._session


class StdioConnection(MCPConnection):
    def __init__(
        self,
        command: str,
        args: Sequence[str] | None = None,
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
    ) -> None:
        super().__init__()
        self._params = StdioServerParameters(
            command=command,
            args=list(args or []),
            env=dict(env) if env else None,
            cwd=cwd,
        )

    def _streams_cm(self) -> Any:
        return stdio_client(self._params)


class HttpConnection(MCPConnection):
    def __init__(
        self,
        url: str,
        headers: Mapping[str, str] | None = None,
        headers_provider: HeadersProvider | None = None,
    ) -> None:
        super().__init__()
        self._url = url
        self._headers = dict(headers) if headers else {}
        self._headers_provider = headers_provider

    def _streams_cm(self) -> Any:
        return streamablehttp_client(self._url, headers=self._resolve_headers())

    def _resolve_headers(self) -> dict[str, str]:
        headers = dict(self._headers)
        if self._headers_provider is not None:
            headers.update(self._headers_provider())
        return headers
