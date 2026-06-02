"""Per-server supervisor — spec §8.

Each configured external MCP server gets a supervising task that connects (via
the shared `unified-mcp-client` package), lists tools, and holds the connection
open. On failure it reconnects with exponential backoff (1,2,4,8,16,32,60s); 5
crashes in <60s marks it unhealthy.

The connection open/close happen in the supervisor task (anyio requires same
task); tool calls come from request-handler tasks (safe across tasks).
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from collections import deque
from collections.abc import Callable

from unified_mcp_client import HttpConnection, MCPConnection, StdioConnection, types

from .config import ServerSpec

logger = logging.getLogger(__name__)

_BACKOFF = [1, 2, 4, 8, 16, 32, 60]

SecretResolver = Callable[[str], str | None]


class SupervisedServer:
    def __init__(
        self, name: str, spec: ServerSpec, secret_resolver: SecretResolver | None = None
    ) -> None:
        self.name = name
        self.spec = spec
        self.healthy = True
        self.last_error: str | None = None
        self._secret_resolver = secret_resolver
        self._tools: list[types.Tool] = []
        self._conn: MCPConnection | None = None
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._attempt = 0

    def _auth_headers(self) -> dict[str, str]:
        # Resolved at connect time so credential rotation is picked up.
        ref = self.spec.auth_secret_ref
        if not ref or self._secret_resolver is None:
            return {}
        secret = self._secret_resolver(ref)
        return {"Authorization": f"Bearer {secret}"} if secret else {}

    def _make_connection(self) -> MCPConnection:
        up = self.spec.upstream
        if up.command:
            # Resolve a bare `python`/`python3` to the hub's own interpreter, so
            # bundled first-party servers (unified_mcp_servers.*) run in the venv
            # that actually has the package — no PATH/activation assumptions.
            command = sys.executable if up.command in ("python", "python3") else up.command
            return StdioConnection(command, up.args, up.env or None)
        if up.url:
            return HttpConnection(up.url, headers_provider=self._auth_headers)
        if up.image:
            raise ValueError(
                f"server '{self.name}': container upstreams arrive at M0.5 (SEC-MCP-5)"
            )
        raise ValueError(f"server '{self.name}': upstream needs one of command/url/image")

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name=f"supervise:{self.name}")

    async def _run(self) -> None:
        crashes: deque[float] = deque()
        while not self._stop.is_set():
            try:
                async with self._make_connection() as conn:
                    self._tools = await conn.list_tools()
                    self._conn = conn
                    self._attempt = 0
                    self.last_error = None
                    self._ready.set()
                    logger.info("server '%s' connected (%d tools)", self.name, len(self._tools))
                    await self._stop.wait()
                    return
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - supervise everything
                self.last_error = str(exc)
                logger.warning("server '%s' connection failed: %s", self.name, exc)
                now = time.monotonic()
                crashes.append(now)
                while crashes and now - crashes[0] > 60:
                    crashes.popleft()
                if len(crashes) >= 5:
                    self.healthy = False
                delay = _BACKOFF[min(self._attempt, len(_BACKOFF) - 1)]
                self._attempt += 1
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=delay)
                    return
                except asyncio.TimeoutError:
                    pass
            finally:
                self._ready.clear()
                self._conn = None

    async def wait_ready(self, timeout: float = 30) -> None:
        await asyncio.wait_for(self._ready.wait(), timeout)

    @property
    def tools(self) -> list[types.Tool]:
        return self._tools

    async def call(self, tool: str, args: dict) -> types.CallToolResult:
        if not self._ready.is_set():
            await self.wait_ready()
        assert self._conn is not None
        return await self._conn.call_tool(tool, args)

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=12)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
