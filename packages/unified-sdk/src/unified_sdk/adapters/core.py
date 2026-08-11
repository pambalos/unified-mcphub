"""The shared core every framework adapter is built from — UAI-132.

Agent frameworks look different and converge on the same thing: **a named
callable invoked with a dict of arguments**. That is the entire surface an
adapter needs, so the framework-specific code should be a shape translation of
twenty or thirty lines, and anything larger is doing something it shouldn't.

Two rules the adapters in this package follow, both learned the hard way:

**Wrap, never hook.** Several frameworks offer callbacks that fire around tool
execution (LangChain's `on_tool_start`, for one). They are *observational*.
Raising from them happens to abort in some versions, which makes a
callback-based adapter look like it enforces while being one upgrade away from
silently passing everything. The enforcement point is always the callable
itself.

**Identity is framework-agnostic by default.** A tool is `tool://send_email`,
not `langchain://send_email`, and the framework goes in `context.origin`. The
product promise is framework-agnostic policy; a security team should not have
to rewrite rules because a squad migrated from CrewAI to LangChain. Adapters
for ecosystems that already have a real namespace — MCP's `mcp://server/tool` —
keep it, because there the server *is* part of the tool's identity.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Sequence
from typing import Any

from ..client import Acting, UnifiedAI


class ToolGuard:
    """Turns "a tool was called" into an enforced, audited Action.

        guard = ToolGuard(ua, origin="langchain")
        guard.check("send_email", {"to": "x@y.z"}).raise_for_verdict()

    `capture` narrows which arguments reach the Action. Left unset, every
    argument is captured — which is the right default here even though the
    `@action` decorator makes capture explicit, because an adapter cannot ask
    the developer per-tool what matters. The safety net is the audit capture
    level, which scrubs secret-shaped values before anything is written; set
    `capture` when a tool takes an argument that should never be recorded at
    all, since that is stronger than relying on the scrubber to recognise it.
    """

    def __init__(
        self,
        client: UnifiedAI,
        *,
        origin: str,
        scheme: str = "tool",
        verb: str = "call",
        resource: str = "*",
        capture: Sequence[str] | None = None,
    ) -> None:
        self._client = client
        self._origin = origin
        self._scheme = scheme
        self._verb = verb
        self._resource = resource
        self._capture = tuple(capture) if capture is not None else None

    # --- identity ---

    def tool_uri(self, name: str) -> str:
        """`send_email` -> `tool://send_email`. Already-qualified names pass
        through, so an adapter can hand over `mcp://files/read` unchanged."""
        return name if "://" in name else f"{self._scheme}://{name}"

    def _params(self, args: dict[str, Any]) -> dict[str, Any]:
        if self._capture is None:
            return dict(args)
        return {k: v for k, v in args.items() if k in self._capture}

    def _extra(self) -> dict[str, Any]:
        return {"framework": self._origin}

    # --- deciding ---

    def check(self, name: str, args: dict[str, Any] | None = None) -> Acting:
        """Decide without raising. Synchronous and non-blocking."""
        return self._client.check(
            self.tool_uri(name),
            verb=self._verb,
            resource=self._resource,
            params=self._params(args or {}),
            extra=self._extra(),
        )

    async def check_async(
        self, name: str, args: dict[str, Any] | None = None, *, summary: str = ""
    ) -> Acting:
        """Decide, taking a DEFER to a human when approvals are configured.

        Async tool execution is the only place in an agent loop where waiting
        for an approval is affordable, which is why the async wrappers below
        route through here and the sync ones cannot.
        """
        return await self._client.check_async(
            self.tool_uri(name),
            verb=self._verb,
            resource=self._resource,
            params=self._params(args or {}),
            extra=self._extra(),
            summary=summary or f"{self._origin}: {name}",
        )

    # --- wrapping ---

    def wrap(self, fn: Callable, *, name: str | None = None) -> Callable:
        """Guard a callable, preserving whether it is sync or async.

        The wrapper decides *before* delegating, so a denied tool never runs.
        An async function gets an async wrapper: a sync one would decide and
        then hand back a coroutine that executes after the guard had already
        returned — authorized, but at a misleading moment.
        """
        tool_name = name or getattr(fn, "__name__", None) or repr(fn)

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                (await self.check_async(tool_name, _as_args(fn, args, kwargs))).raise_for_verdict()
                return await fn(*args, **kwargs)

            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            self.check(tool_name, _as_args(fn, args, kwargs)).raise_for_verdict()
            return fn(*args, **kwargs)

        return wrapper


def _as_args(fn: Callable, args: tuple, kwargs: dict) -> dict[str, Any]:
    """Positional and keyword arguments as one flat name->value mapping.

    Policy is written against argument *names*, so a tool invoked positionally
    has to produce the same params as the same tool invoked by keyword —
    otherwise a rule matches or misses depending on the caller's style.

    `**kwargs` is flattened rather than left nested. `bind_partial` collects it
    under the parameter's own name, so a tool declared `def tool(**kwargs)` —
    which is how a great many wrapped tools are written — would otherwise
    produce `params={"kwargs": {"amount": 9000}}` and no `params.amount` rule
    would ever match it. Silently unmatchable is the worst possible failure for
    a policy engine, so the names the caller actually supplied are lifted to
    the top level.

    `*args` are kept under their parameter name as a list: unlike keywords they
    have no names of their own to match on, but dropping them would hide real
    arguments from the audit record.

    Builtins and C functions have no inspectable signature; those fall back to
    keywords alone.
    """
    try:
        signature = inspect.signature(fn)
        bound = signature.bind_partial(*args, **kwargs)
        bound.apply_defaults()
    except (TypeError, ValueError):
        return dict(kwargs)

    flat: dict[str, Any] = {}
    for name, value in bound.arguments.items():
        kind = signature.parameters[name].kind
        if kind is inspect.Parameter.VAR_KEYWORD:
            flat.update(value)
        elif kind is inspect.Parameter.VAR_POSITIONAL:
            flat[name] = list(value)
        else:
            flat[name] = value
    return flat
