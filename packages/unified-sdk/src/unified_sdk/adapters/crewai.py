"""CrewAI adapter — enforce a crew's tools.

Same principle as the LangChain adapter: hand the agent *replacement* tools, so
the guarded callable is the only one it can reach. CrewAI's `BaseTool` is a
Pydantic model, so the replacement is a small subclass built at call time
rather than a patched instance.

CrewAI also accepts LangChain tools directly. If that is what a crew is using,
reach for `adapters.langchain.guard_tools` instead — this module is for
`crewai.tools.BaseTool`.

Needs `crewai`: `pip install 'unified-sdk[crewai]'`.

⚠️ Verified structurally, not against the real package. `crewai` cannot be
installed on this machine (it depends on `lancedb`, which publishes no wheel
for macOS x86_64), so the conformance driver runs against a stub that mirrors
`BaseTool`'s contract: `name`, `description`, `args_schema`, and `_run`. That
covers our logic and the shape we depend on, but not CrewAI's real runtime —
run the suite on Linux or an arm64 Mac to close the gap. Tracked in
specs/enforce/adapters.v1.md §7.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from ..client import UnifiedAI
from .core import ToolGuard

ORIGIN = "crewai"

_INSTALL_HINT = "crewai is not installed — pip install 'unified-sdk[crewai]'"


def crewai_guard(client: UnifiedAI, **kwargs: Any) -> ToolGuard:
    kwargs.setdefault("origin", ORIGIN)
    return ToolGuard(client, **kwargs)


def guard_tool(tool: Any, guard: ToolGuard) -> Any:
    """An enforced replacement for one CrewAI tool.

    Keeps the name, description and args schema, so the agent's prompt is
    unchanged and behaviour only differs once policy actually refuses.
    """
    try:
        from crewai.tools import BaseTool
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(_INSTALL_HINT) from exc

    name = tool.name

    class Guarded(BaseTool):  # type: ignore[misc, valid-type]
        # Declared as Pydantic field defaults; CrewAI reads them off the model.
        name: str = tool.name
        description: str = tool.description
        args_schema: Any = getattr(tool, "args_schema", None)

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            guard.check(name, kwargs).raise_for_verdict()
            return tool._run(*args, **kwargs)

    return Guarded()


def guard_tools(tools: Iterable[Any], guard: ToolGuard) -> Sequence[Any]:
    """Enforced replacements for a crew's whole toolset."""
    return [guard_tool(tool, guard) for tool in tools]
