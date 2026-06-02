"""First-party light/safe MCP servers — the unified-mcphub default tier.

Each submodule is a standalone stdio MCP server runnable as
``python -m unified_mcp_servers.<name>``. Logic is stdlib-only; the only
dependency is the official ``mcp`` SDK (ADR-0023). The hub is the security
layer (ADR-0006/0018) — these servers keep only a slim ``is_path_safe`` check.
"""

__all__ = ["filesystem", "shell", "fetch", "python", "documents"]
