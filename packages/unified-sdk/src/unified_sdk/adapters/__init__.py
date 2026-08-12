"""Framework adapters — UAI-132. Spec: specs/enforce/adapters.v1.md.

Every adapter is a shape translation over `ToolGuard`; the enforcement logic
lives there and in the engine, never in the framework-specific code.

Framework modules import their framework lazily, so `unified_sdk.adapters` is
safe to import with none of them installed.

    from unified_sdk.adapters import ToolGuard
    from unified_sdk.adapters.langchain import guard_tools, langchain_guard
    from unified_sdk.adapters.llamaindex import guard_tools, llamaindex_guard
    from unified_sdk.adapters.crewai import guard_tools, crewai_guard
    from unified_sdk.adapters.mcp import GuardedSession, mcp_guard
    from unified_sdk.adapters.toolloop import Toolbox, denial_result, toolloop_guard

`providers` is the odd one out and deliberately so: OpenAI, OpenRouter, Bedrock
and Anthropic are inference APIs, not frameworks, so there is nothing to adapt
— only four spellings of the same tool call to normalize, and four dialects a
denial has to be written back in.

    from unified_sdk.adapters.providers import tool_calls, denial_message
"""

from .core import ToolGuard

__all__ = ["ToolGuard"]
