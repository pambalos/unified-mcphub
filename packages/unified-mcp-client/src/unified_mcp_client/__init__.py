"""Async MCP client (stdio + streamable-HTTP) on the official mcp SDK. See ADR-0023.

The interchange type is `mcp.types.Tool`; this package defines no parallel tool model.
"""

from __future__ import annotations

from mcp import types

from .client import HttpConnection, MCPConnection, StdioConnection

__all__ = ["MCPConnection", "StdioConnection", "HttpConnection", "types"]
