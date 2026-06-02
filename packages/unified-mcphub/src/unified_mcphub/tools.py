"""Built-in tools — spec §10, §10.1.

Hub-native + user-defined tools, registered via the `@tool` decorator and
surfaced as `mcp://built-in/<tool>`. The decorator emits an `mcp.types.Tool`
(the narrow-waist interchange type, ADR-0023) — no parallel tool model.

User tools in ~/.unified-ai/mcphub/tools/*.py are auto-discovered (full
hot-reload is MCP-HUB-2; this loads them once at startup).
"""

from __future__ import annotations

import importlib.util
import inspect
import typing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from mcp import types

_PY_TO_JSON = {str: "string", int: "integer", float: "number", bool: "boolean"}


def _schema_from_signature(fn: Callable) -> dict[str, Any]:
    # Resolve annotations to real types (handles `from __future__ import annotations`,
    # which makes them strings via PEP 563). Unresolvable forward refs fall back to raw.
    try:
        hints = typing.get_type_hints(fn)
    except (NameError, TypeError):
        hints = {}
    props: dict[str, Any] = {}
    required: list[str] = []
    for name, param in inspect.signature(fn).parameters.items():
        if name in ("self", "agent_state"):
            continue
        annotation = hints.get(name, param.annotation)
        props[name] = {"type": _PY_TO_JSON.get(annotation, "string")}
        if param.default is inspect.Parameter.empty:
            required.append(name)
    return {"type": "object", "properties": props, "required": required}


@dataclass
class Builtin:
    tool: types.Tool
    handler: Callable[..., Any]


# Module-level registry populated by @tool at import time.
_REGISTRY: dict[str, Builtin] = {}


def tool(*, name: str, description: str = "") -> Callable[[Callable], Callable]:
    def deco(fn: Callable) -> Callable:
        _REGISTRY[name] = Builtin(
            tool=types.Tool(
                name=name,
                description=description or (fn.__doc__ or "").strip(),
                inputSchema=_schema_from_signature(fn),
            ),
            handler=fn,
        )
        return fn

    return deco


@tool(name="ping", description="Liveness check; returns 'pong'.")
def _ping() -> str:
    return "pong"


class BuiltinRegistry:
    """Aggregates hub-native + user-defined built-ins under `mcp://built-in/*`."""

    def __init__(self) -> None:
        self._tools: dict[str, Builtin] = dict(_REGISTRY)

    def load_user_tools(self, tools_dir: Path) -> None:
        if not tools_dir.is_dir():
            return
        for path in sorted(tools_dir.glob("*.py")):
            spec = importlib.util.spec_from_file_location(f"mcphub_user_tool_{path.stem}", path)
            if spec and spec.loader:
                spec.loader.exec_module(importlib.util.module_from_spec(spec))
        self._tools = dict(_REGISTRY)  # decorators registered on import

    def list_tools(self) -> list[types.Tool]:
        return [b.tool for b in self._tools.values()]

    def has(self, name: str) -> bool:
        return name in self._tools

    def call(self, name: str, args: dict[str, Any]) -> Any:
        return self._tools[name].handler(**args)
