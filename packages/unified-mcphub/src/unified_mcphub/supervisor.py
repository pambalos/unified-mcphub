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

from unified_mcp_client import HttpConnection, MCPConnection, StdioConnection, types

from . import oauth
from .config import ServerSpec

logger = logging.getLogger(__name__)

_BACKOFF = [1, 2, 4, 8, 16, 32, 60]


def _static_auth_header(spec: ServerSpec, token_store: oauth.TokenStore | None) -> dict[str, str]:
    """`auth_secret_ref` → an auth header. `Authorization: Bearer <secret>` by
    default; a custom `auth_header` with `auth_scheme: null` sends the raw secret
    (API-key style, e.g. `X-API-Key: <key>`)."""
    ref = spec.auth_secret_ref
    if not ref or token_store is None:
        return {}
    secret = token_store.get(ref)
    if not secret:
        return {}
    value = f"{spec.auth_scheme} {secret}" if spec.auth_scheme else secret
    return {spec.auth_header: value}


async def resolve_auth_headers(
    spec: ServerSpec, token_store: oauth.TokenStore | None, *, name: str = ""
) -> dict[str, str]:
    """Auth headers for an HTTP upstream, computed at connect time.

    OAuth takes precedence over a static `auth_secret_ref`: if the server has an
    `oauth:` block AND we hold a refresh token (i.e. `auth login` was run), refresh
    it to a fresh access token and send `Authorization: Bearer <token>`. Refreshing
    on each (re)connect means an expired token self-heals on the supervisor's next
    reconnect. We never trigger discovery/registration before login (no refresh
    token → fall through), so a probe of an un-authed OAuth server stays side-effect
    free. Any failure degrades to no auth (the upstream 401s and is marked unhealthy
    with a clear `auth login` hint)."""
    if spec.oauth is not None and token_store is not None:
        if token_store.get(f"{name}-oauth-refresh"):
            try:
                flow = await oauth.build_flow(
                    name,
                    token_store,
                    authorize_url=spec.oauth.authorize_url,
                    token_url=spec.oauth.token_url,
                    client_id=spec.oauth.client_id,
                    issuer=spec.oauth.issuer,
                    registration_url=spec.oauth.registration_url,
                    scopes=spec.oauth.scopes,
                )
                tokens = await flow.refresh()
                access = tokens.get("access_token")
                if access:
                    return {"Authorization": f"Bearer {access}"}
                logger.warning("server '%s': OAuth refresh returned no access_token", name)
            except Exception as exc:  # noqa: BLE001 - degrade to no-auth, supervisor surfaces it
                logger.warning("server '%s': OAuth token refresh failed: %s", name, exc)
            return {}
        logger.warning(
            "server '%s': OAuth configured but not logged in — run `unified-mcphub auth login %s`",
            name,
            name,
        )
        return {}
    return _static_auth_header(spec, token_store)


def build_connection(
    spec: ServerSpec, *, auth_headers: dict[str, str] | None = None, name: str = ""
) -> MCPConnection:
    """Build a client connection from a server spec — the single source of truth
    for connection semantics, shared by the live supervisor and the `add-server`
    probe (so a server probes exactly the way the hub will later run it).

    A bare `python`/`python3` resolves to the hub's own interpreter, so bundled
    first-party servers run in the venv that actually has the package. HTTP auth
    headers are computed by the caller (see `resolve_auth_headers`) and passed in.
    """
    up = spec.upstream
    if up.command:
        command = sys.executable if up.command in ("python", "python3") else up.command
        return StdioConnection(command, up.args, up.env or None)
    if up.url:
        return HttpConnection(up.url, headers=dict(auth_headers or {}))
    if up.image:
        raise ValueError(f"server '{name}': container upstreams arrive at M0.5 (SEC-MCP-5)")
    raise ValueError(f"server '{name}': upstream needs one of command/url/image")


class SupervisedServer:
    def __init__(
        self, name: str, spec: ServerSpec, token_store: oauth.TokenStore | None = None
    ) -> None:
        self.name = name
        self.spec = spec
        self.healthy = True
        self.last_error: str | None = None
        self._token_store = token_store
        self._tools: list[types.Tool] = []
        self._conn: MCPConnection | None = None
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._attempt = 0

    async def _make_connection(self) -> MCPConnection:
        # Auth resolved per (re)connect: OAuth tokens refresh, static secrets rotate.
        headers = await resolve_auth_headers(self.spec, self._token_store, name=self.name)
        return build_connection(self.spec, auth_headers=headers, name=self.name)

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name=f"supervise:{self.name}")

    async def _run(self) -> None:
        crashes: deque[float] = deque()
        while not self._stop.is_set():
            try:
                async with await self._make_connection() as conn:
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
