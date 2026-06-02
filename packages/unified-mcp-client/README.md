# unified-mcp-client

Async MCP client for talking OUT to MCP servers, built on the official `mcp` SDK.

Shared platform substrate (see [ADR-0023](../../docs/adrs/0023-mcp-client-shared-package.md)):
- `unified-mcphub` uses it now (M0) to proxy external servers.
- `adapter-base.self.mcp` reuses it at M1 with a traceparent `headers_provider`.

The interchange type is `mcp.types.Tool` — this package defines **no** parallel tool model.
Lifecycle (process supervision / backoff) is the consumer's job; this package is a connection.

```python
from unified_mcp_client import StdioConnection, HttpConnection

async with StdioConnection("python", ["-m", "my_server"]) as conn:
    tools = await conn.list_tools()                 # list[mcp.types.Tool]
    result = await conn.call_tool("read_file", {"path": "x"})

async with HttpConnection("https://mcp.example/mcp",
                          headers_provider=lambda: {"traceparent": current_traceparent()}) as conn:
    ...
```

`connect()`/`close()` and `__aenter__`/`__aexit__` must run in the same task (anyio constraint).
