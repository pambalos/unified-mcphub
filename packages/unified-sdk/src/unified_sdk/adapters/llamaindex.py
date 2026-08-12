"""LlamaIndex adapter — enforce an agent's tools.

Same principle as the others: hand the agent *replacement* tools, so the
guarded callable is the only one it can reach.

LlamaIndex is the friendliest of the three to wrap. `FunctionTool.from_defaults`
takes both a sync `fn` and an async `async_fn`, and carries the schema in
`tool_metadata`, so a replacement is built entirely from public constructor
arguments — no subclassing, no patching, and the agent sees an identical tool.

The one wrinkle is that a tool call arrives as `**kwargs` but `call()` accepts
`*args` too, so positional invocations are bound against the original function's
signature (`ToolGuard.wrap` handles that) rather than assumed to be keywords.

Needs `llama-index-core`: `pip install 'unified-sdk[llamaindex]'`.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from ..client import UnifiedAI
from .core import ToolGuard

ORIGIN = "llamaindex"

_INSTALL_HINT = "llama-index-core is not installed — pip install 'unified-sdk[llamaindex]'"


def llamaindex_guard(client: UnifiedAI, **kwargs: Any) -> ToolGuard:
    kwargs.setdefault("origin", ORIGIN)
    return ToolGuard(client, **kwargs)


def guard_tool(tool: Any, guard: ToolGuard) -> Any:
    """An enforced replacement for one LlamaIndex tool.

    Both the sync and async paths are wired, because an agent picks between
    `call` and `acall` on its own — guarding only one would leave a route
    through which nothing is enforced.
    """
    try:
        from llama_index.core.tools import FunctionTool
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(_INSTALL_HINT) from exc

    name = tool.metadata.name

    def run(*args: Any, **kwargs: Any) -> Any:
        guard.check(name, kwargs).raise_for_verdict()
        return tool.call(*args, **kwargs)

    async def arun(*args: Any, **kwargs: Any) -> Any:
        acting = await guard.check_async(name, kwargs, summary=f"llamaindex: {name}")
        acting.raise_for_verdict()
        return await tool.acall(*args, **kwargs)

    return FunctionTool.from_defaults(
        fn=run,
        async_fn=arun,
        name=name,
        description=tool.metadata.description,
        # Carry the original schema so the model's prompt is unchanged; without
        # it LlamaIndex would infer one from `run(*args, **kwargs)` and the
        # agent would lose every argument name.
        fn_schema=getattr(tool.metadata, "fn_schema", None),
    )


def guard_tools(tools: Iterable[Any], guard: ToolGuard) -> Sequence[Any]:
    """Enforced replacements for a whole toolset."""
    return [guard_tool(tool, guard) for tool in tools]
