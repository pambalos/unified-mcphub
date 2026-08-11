"""Framework adapters — UAI-132. Spec: specs/enforce/adapters.v1.md.

Every adapter is a shape translation over `ToolGuard`; the enforcement logic
lives there and in the engine, never in the framework-specific code.

Framework modules import their framework lazily, so `unified_sdk.adapters` is
safe to import with none of them installed.

    from unified_sdk.adapters import ToolGuard
    from unified_sdk.adapters.langchain import guard_tools, langchain_guard
    from unified_sdk.adapters.mcp import GuardedSession, mcp_guard
    from unified_sdk.adapters.toolloop import Toolbox, denial_result, toolloop_guard
"""

from .core import ToolGuard

__all__ = ["ToolGuard"]
