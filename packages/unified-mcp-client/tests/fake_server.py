"""Minimal stdio MCP server for unified-mcp-client tests."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fake")


@mcp.tool()
def echo(text: str) -> str:
    """Echo the input text back."""
    return f"echo: {text}"


if __name__ == "__main__":
    mcp.run()
