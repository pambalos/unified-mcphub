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

from collections.abc import Callable
from typing import Any

from unified_enforce import AttachmentProvider
from unified_enforce.staging import (
    RESERVED_SERVER,
    TOOL_SPECS,
    AttachmentTools,
    RecordedResults,
    channel_attach,
)

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


# --- reserved attachment tools (approval-attachments.v1 §4.2, A2) ---------------------

#: Arguments that are evidence, not policy input. Kept out of the Action the
#: tool call is decided on: the content is hashed into the staged item, and a
#: 10 MiB base64 string in the audit chain's params would record the document
#: on every staging, whether or not anyone is ever asked about it.
_CONTENT_ARGS = frozenset({"content", "content_base64"})


def _register_take(ua: UnifiedAI, session_id: str) -> None:
    """Make `ua`'s deferred checks consume what was staged in `session_id`.

    A provider over every tool (`*`): staging already scoped each item to a
    tool glob, a `match` and a principal, and `take` applies all three.
    Registered once per (client, session), however many servers call this.
    """
    registered = ua.__dict__.setdefault("_staging_sessions", set())
    if session_id in registered:
        return
    registered.add(session_id)
    staging = ua.staging

    def staged_attachments(action):
        return list(staging.take(action, session_id))

    ua._attachment_providers.append(AttachmentProvider.build("*", staged_attachments))


def attachment_tools(
    ua: UnifiedAI,
    *,
    session_id: str = "stdio",
    recorded: RecordedResults | None = None,
) -> list[tuple[str, Callable[..., Any], str]]:
    """The reserved `unified__*` tools as `(name, async fn, description)`.

    The same four tools, arguments and descriptions as the hub (the logic is
    `unified_enforce.staging.AttachmentTools`), for an MCP server built on
    `mcp_guard`. Each call is decided by policy first, as
    `mcp://unified/<tool>` -- the hub's URI, so one rule covers both -- and
    a deny stops it before anything is staged.

    The principal is `ua`'s, never an argument. `session_id` scopes staged
    items: a stdio server is one agent session, so the default is fine; a
    server multiplexing sessions should build one set per session.
    `recorded` is where `from_call` looks for results this server relayed;
    without it every `from_call` gives an `unavailable` entry, never content.

    Also registers the provider that makes `ua`'s deferred checks consume
    staged items, so nothing else needs wiring.
    """
    _register_take(ua, session_id)
    guard = mcp_guard(ua)
    tools = AttachmentTools(
        ua.staging,
        recorded=recorded,
        attach=channel_attach(lambda: getattr(ua._enforcer.approvals, "channel", None)),
    )
    principal = ua._principal.id

    async def run(name: str, args: dict[str, Any]) -> dict[str, Any]:
        policy_args = {k: v for k, v in args.items() if k not in _CONTENT_ARGS}
        acting = await guard.check_async(
            f"{RESERVED_SERVER}/{name}", policy_args, summary=f"unified: {name}"
        )
        acting.raise_for_verdict()
        return await tools.call(name, args, principal, session_id)

    def given(**kwargs: Any) -> dict[str, Any]:
        return {k: v for k, v in kwargs.items() if v is not None}

    async def stage_attachment(
        for_tool: str,
        label: str,
        content: str | None = None,
        content_base64: str | None = None,
        from_call: str | None = None,
        media_type: str | None = None,
        match: dict[str, Any] | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        return await run(
            "stage_attachment",
            given(
                for_tool=for_tool,
                label=label,
                content=content,
                content_base64=content_base64,
                from_call=from_call,
                media_type=media_type,
                match=match,
                note=note,
            ),
        )

    async def list_staged() -> dict[str, Any]:
        return await run("list_staged", {})

    async def discard_staged(staged_id: str) -> dict[str, Any]:
        return await run("discard_staged", {"staged_id": staged_id})

    async def attach_to_approval(
        approval_ref: str,
        label: str,
        content: str | None = None,
        content_base64: str | None = None,
        from_call: str | None = None,
        media_type: str | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        return await run(
            "attach_to_approval",
            given(
                approval_ref=approval_ref,
                label=label,
                content=content,
                content_base64=content_base64,
                from_call=from_call,
                media_type=media_type,
                note=note,
            ),
        )

    fns: dict[str, Callable[..., Any]] = {
        "stage_attachment": stage_attachment,
        "list_staged": list_staged,
        "discard_staged": discard_staged,
        "attach_to_approval": attach_to_approval,
    }
    return [(f"{RESERVED_SERVER}__{name}", fns[name], TOOL_SPECS[name][0]) for name in fns]


def register_attachment_tools(
    server: Any,
    ua: UnifiedAI,
    *,
    session_id: str = "stdio",
    recorded: RecordedResults | None = None,
) -> None:
    """Add the reserved attachment tools to a FastMCP `server` (see
    `attachment_tools`). Raises ImportError when FastMCP is not installed:
    this helper is for FastMCP servers, and a duck-typed guess at some other
    framework's registration API is how a tool silently fails to appear."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - exercised only without `mcp`
        raise ImportError(
            "register_attachment_tools needs FastMCP (`pip install mcp`); for another "
            "framework, register the tuples from attachment_tools() yourself"
        ) from exc
    if not isinstance(server, FastMCP):
        raise TypeError(f"expected a FastMCP server, got {type(server).__name__}")
    for name, fn, description in attachment_tools(ua, session_id=session_id, recorded=recorded):
        server.add_tool(fn, name=name, description=description)
