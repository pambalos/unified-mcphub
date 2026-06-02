"""A tiny stdio MCP server used as a fake upstream in e2e tests.

Runs under the same interpreter as the test (so the `mcp` SDK is available).
Exposes a `list_files` tool (matches the `mcp://*/list_*` allow rule) and a
`read_file` tool.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fake-fs")


@mcp.tool()
def list_files(path: str = ".") -> str:
    """List files at a path."""
    return "alpha.txt\nbeta.txt\ngamma.txt"


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file's contents."""
    return f"contents of {path}"


if __name__ == "__main__":
    mcp.run()  # stdio transport by default
