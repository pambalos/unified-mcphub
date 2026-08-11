"""LangChain adapter — enforce a LangChain agent's tools.

`guard_tools()` returns replacement tools. Hand those to the agent instead of
the originals and every invocation is decided first.

**Why replacement rather than a callback handler.** LangChain's callbacks
(`on_tool_start`) are an observability surface. Raising from one aborts the
call in some versions, which is exactly the trap: a callback-based adapter
passes its own tests, ships, and then silently stops enforcing after a minor
upgrade — with no error, because nothing was ever contractually blocking. A
replacement tool is the only thing the agent can reach, so enforcement cannot
be bypassed by a change in callback semantics.

**Why a new tool rather than patching the original.** `BaseTool` is a Pydantic
model; assigning over `_run` on an instance is fragile across Pydantic and
LangChain versions, and mutating a caller's object is rude besides. Building a
`StructuredTool` around `invoke`/`ainvoke` uses only the stable public surface.

Needs `langchain-core`: `pip install 'unified-sdk[langchain]'`.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from ..client import UnifiedAI
from .core import ToolGuard

ORIGIN = "langchain"

_INSTALL_HINT = "langchain-core is not installed — pip install 'unified-sdk[langchain]'"


def langchain_guard(client: UnifiedAI, **kwargs: Any) -> ToolGuard:
    kwargs.setdefault("origin", ORIGIN)
    return ToolGuard(client, **kwargs)


def guard_tool(tool: Any, guard: ToolGuard) -> Any:
    """One enforced replacement for `tool`, same name, description and schema.

    The agent sees an identical tool; the model's prompt does not change, so
    behaviour is unaffected until policy actually denies something.
    """
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(_INSTALL_HINT) from exc

    name = tool.name

    def run(**kwargs: Any) -> Any:
        guard.check(name, kwargs).raise_for_verdict()
        return tool.invoke(kwargs)

    async def arun(**kwargs: Any) -> Any:
        (await guard.check_async(name, kwargs, summary=f"langchain: {name}")).raise_for_verdict()
        return await tool.ainvoke(kwargs)

    return StructuredTool(
        name=name,
        description=tool.description,
        args_schema=tool.args_schema,
        func=run,
        coroutine=arun,
        # A denial is the agent's business: let it surface so the model can
        # read the refusal and choose another route, rather than LangChain
        # swallowing it into a generic tool error.
        handle_tool_error=False,
    )


def guard_tools(tools: Iterable[Any], guard: ToolGuard) -> Sequence[Any]:
    """Enforced replacements for a whole toolbelt."""
    return [guard_tool(tool, guard) for tool in tools]
