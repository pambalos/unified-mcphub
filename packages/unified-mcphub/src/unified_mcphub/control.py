"""Control plane for out-of-process approvals — UAI-107 / UAI-109.

The hub owns the authoritative registry of pending `prompt` decisions so a
decision can arrive from an out-of-process client (TUI, Discord bridge, web UI)
over the local control API instead of the hub's own terminal.

First-responder-wins lives here and is naturally atomic: asyncio is
single-threaded, so the first `submit()` to run completes the pending's future
and removes it; any later submission — another channel, a duplicate, a late
Discord reaction — finds it gone and returns `already_resolved`. `pending_id` is
opaque and single-use, which is also the anti-replay property.

Fail-closed: a pending that times out, or that is still outstanding when the
registry shuts down, resolves to deny. The SSE transport (UAI-107) subscribes to
`pending.created` / `pending.resolved` via the `publish` sink; that wiring lands
with the endpoints, so the registry stays transport-agnostic.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from ulid import ULID

from .approval import DecisionKind

DecisionResult = tuple[DecisionKind, dict | None]
SubmitResult = Literal["accepted", "already_resolved"]
EventSink = Callable[[str, dict], None]


@dataclass
class PendingApproval:
    pending_id: str  # opaque, single-use
    tool_uri: str
    caller: str
    summary: str
    args: dict
    floored: bool = False

    def created_event(self) -> dict:
        return {
            "pending_id": self.pending_id,
            "tool_uri": self.tool_uri,
            "caller": self.caller,
            "args_summary": self.summary,
            "floored": self.floored,
        }


@dataclass
class _Entry:
    info: PendingApproval
    future: asyncio.Future[DecisionResult]


class PendingRegistry:
    """Authoritative store of outstanding `prompt` decisions (UAI-107).

    `publish` (optional) receives `(event_name, data)` for every state change so
    the control-API SSE stream can fan it out to subscribers.
    """

    def __init__(self, publish: EventSink | None = None) -> None:
        self._entries: dict[str, _Entry] = {}
        self._publish = publish

    def register(self, info: PendingApproval) -> asyncio.Future[DecisionResult]:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[DecisionResult] = loop.create_future()
        self._entries[info.pending_id] = _Entry(info, future)
        self._emit("pending.created", info.created_event())
        return future

    def list_pending(self) -> list[PendingApproval]:
        return [entry.info for entry in self._entries.values()]

    def submit(
        self,
        pending_id: str,
        kind: DecisionKind,
        *,
        decided_by: str,
        args_filter: dict | None = None,
    ) -> SubmitResult:
        """Resolve a pending decision. First-wins; later calls -> already_resolved."""
        entry = self._entries.pop(pending_id, None)
        if entry is None or entry.future.done():
            return "already_resolved"
        entry.future.set_result((kind, args_filter))
        self._emit(
            "pending.resolved",
            {"pending_id": pending_id, "kind": kind.value, "decided_by": decided_by},
        )
        return "accepted"

    def expire(self, pending_id: str, *, reason: str) -> None:
        """Drop a pending the waiter has abandoned (timeout / disconnect).

        The waiter is already returning deny; this cleans up the entry and lets
        subscribers retract their cards. No-op if it was already resolved.
        """
        entry = self._entries.pop(pending_id, None)
        if entry is None:
            return
        self._emit(
            "pending.resolved",
            {"pending_id": pending_id, "kind": DecisionKind.DENY.value, "decided_by": reason},
        )

    def shutdown(self) -> None:
        """Fail-closed: deny every outstanding pending on teardown."""
        for pending_id, entry in list(self._entries.items()):
            if not entry.future.done():
                entry.future.set_result((DecisionKind.DENY, None))
            self._entries.pop(pending_id, None)

    def _emit(self, event: str, data: dict) -> None:
        if self._publish is not None:
            self._publish(event, data)


class ControlApiChannel:
    """ApprovalChannel that sources decisions from the control-API registry.

    Publishes a pending over the registry (→ SSE for TUI / Discord / web), waits
    for an out-of-process decision, and fails closed to deny on timeout. Selected
    by the hub when it has no terminal (the headless path).
    """

    def __init__(self, registry: PendingRegistry, *, timeout_s: float) -> None:
        self._registry = registry
        self._timeout_s = timeout_s

    async def ask(
        self, tool_uri: str, caller: str, summary: str, args: dict, floored: bool
    ) -> DecisionResult:
        info = PendingApproval(
            pending_id=str(ULID()),
            tool_uri=tool_uri,
            caller=caller,
            summary=summary,
            args=args,
            floored=floored,
        )
        future = self._registry.register(info)
        try:
            return await asyncio.wait_for(future, self._timeout_s)
        except asyncio.TimeoutError:
            self._registry.expire(info.pending_id, reason="timeout")
            return DecisionKind.DENY, None
        except asyncio.CancelledError:
            self._registry.expire(info.pending_id, reason="cancelled")
            raise
