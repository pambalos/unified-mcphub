"""Raw tool-calling loop adapter — no framework at all.

The case the framework list keeps missing: a team building directly on the
Anthropic or OpenAI SDK, dispatching `tool_use` blocks themselves. That is
common in exactly the regulated environments this product targets, where a
framework dependency is itself a review item. There is nothing to adapt *to*,
so this supplies the missing piece — a registry that enforces on dispatch.

    box = Toolbox(toolloop_guard(ua))

    @box.tool
    def issue_refund(customer_id: str, amount: str) -> str: ...

    # in the loop, for each tool_use block the model emits:
    result = box.dispatch(block.name, block.input)

`denial_result()` turns a refusal into a tool result the model can read, which
matters more here than elsewhere: the loop is hand-written, so nothing else
will translate the exception into something the agent can reason about.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from ..client import UnifiedAI
from ..errors import EnforcementError
from .core import ToolGuard

ORIGIN = "toolloop"


def toolloop_guard(client: UnifiedAI, **kwargs: Any) -> ToolGuard:
    kwargs.setdefault("origin", ORIGIN)
    return ToolGuard(client, **kwargs)


class Toolbox:
    """A name -> callable registry that decides before it dispatches."""

    def __init__(self, guard: ToolGuard) -> None:
        self._guard = guard
        self._tools: dict[str, Callable] = {}

    def register(self, name: str, fn: Callable) -> None:
        self._tools[name] = fn

    def tool(self, fn: Callable | None = None, *, name: str | None = None):
        """Register a function as a tool, by decorator."""

        def register(target: Callable) -> Callable:
            self.register(name or target.__name__, target)
            return target  # returned unwrapped: enforcement happens at dispatch

        return register(fn) if fn is not None else register

    @property
    def names(self) -> list[str]:
        return sorted(self._tools)

    def _lookup(self, name: str) -> Callable:
        try:
            return self._tools[name]
        except KeyError:
            # A model can hallucinate a tool name. That is not a policy
            # question, and reporting it as one would put a misleading denial
            # in the audit chain.
            raise KeyError(f"unknown tool {name!r}; registered: {self.names}") from None

    def dispatch(self, name: str, args: dict[str, Any] | None = None) -> Any:
        fn = self._lookup(name)
        self._guard.check(name, args or {}).raise_for_verdict()
        return fn(**(args or {}))

    async def dispatch_async(self, name: str, args: dict[str, Any] | None = None) -> Any:
        """Dispatch with approvals available — a DEFER can reach a human here."""
        fn = self._lookup(name)
        acting = await self._guard.check_async(name, args or {}, summary=f"tool: {name}")
        acting.raise_for_verdict()
        result = fn(**(args or {}))
        return await result if inspect.isawaitable(result) else result


def denial_result(exc: EnforcementError, tool_use_id: str | None = None) -> dict[str, Any]:
    """A refusal shaped as a tool result the model can read and act on.

    Deliberately says the call was *blocked by policy* and names the rule. A
    bare "error" invites the model to retry the identical call — often several
    times — which burns tokens and fills the audit log with identical denials.
    Telling it the refusal is a policy decision lets it choose another route or
    surface the block to the user.
    """
    result: dict[str, Any] = {
        "type": "tool_result",
        "is_error": True,
        "content": (
            f"Blocked by policy ({exc.decision.rule_id or exc.decision.source}). "
            "This is a policy decision, not a transient failure — retrying the "
            "same call will be blocked again. Choose a different approach or "
            "tell the user this action requires authorization."
        ),
    }
    if tool_use_id is not None:
        result["tool_use_id"] = tool_use_id
    return result
