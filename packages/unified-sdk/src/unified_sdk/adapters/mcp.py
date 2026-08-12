"""MCP adapter — enforce an MCP client's tool calls.

The hub already proves this shape end to end (intercept `tools/call`, decide,
chain, forward), so this is extraction rather than new design. The difference
is which side of the wire it runs on: the hub enforces as a *server* fronting
upstreams, this enforces in a *client* that talks to MCP servers directly —
useful when an agent speaks MCP without a hub in front of it.

Tool identity deliberately matches the hub's: `mcp://<server>/<tool>`. MCP is
the one ecosystem here with a real namespace — the server is part of what a
tool *is*, and two servers can legitimately both expose `read_file`. Keeping
the convention also means a policy written for the hub applies unchanged.
"""

from __future__ import annotations

from typing import Any

from ..client import UnifiedAI
from .core import ToolGuard

ORIGIN = "mcp"


def mcp_guard(client: UnifiedAI, **kwargs: Any) -> ToolGuard:
    """A ToolGuard producing `mcp://server/tool` identities."""
    kwargs.setdefault("scheme", "mcp")
    kwargs.setdefault("origin", ORIGIN)
    return ToolGuard(client, **kwargs)


class GuardedSession:
    """Wraps an MCP client session so every `call_tool` is enforced.

        session = GuardedSession(raw_session, mcp_guard(ua), server="files")
        await session.call_tool("read_file", {"path": "/etc/passwd"})  # -> Denied

    Everything other than `call_tool` is forwarded untouched, so this drops in
    wherever a session is already used. Duck-typed rather than subclassed: the
    MCP SDK's session type has moved more than once, and an adapter that only
    needs one method should not depend on the rest of the class.
    """

    def __init__(self, session: Any, guard: ToolGuard, *, server: str) -> None:
        self._session = session
        self._guard = guard
        self._server = server

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        acting = await self._guard.check_async(
            f"{self._server}/{name}",
            arguments or {},
            summary=f"{self._server}: {name}",
        )
        acting.raise_for_verdict()
        return await self._session.call_tool(name, arguments)
