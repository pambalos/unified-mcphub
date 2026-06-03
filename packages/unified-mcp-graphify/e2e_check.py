"""End-to-end smoke test: stand up the real stdio MCP server, run a real
graphify build over the wire, and poll build_status to completion.

Uses a code-only repo so extraction skips the LLM backend (no API key needed).
Run with the package venv: `uv run python e2e_check.py`.
"""

import asyncio
import json
import sys
import tempfile
import time
from pathlib import Path

from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client

SAMPLE = """\
from dataclasses import dataclass


@dataclass
class Order:
    item: str
    qty: int

    def total(self, price: float) -> float:
        return self.qty * price


def make_order(item: str, qty: int) -> Order:
    return Order(item=item, qty=qty)
"""


def _payload(result: types.CallToolResult) -> dict:
    """Tools return a dict; the SDK delivers it as text content (and/or structured)."""
    if result.structuredContent:
        sc = result.structuredContent
        return sc.get("result", sc) if isinstance(sc, dict) else sc
    return json.loads(result.content[0].text)


async def main() -> int:
    server = StdioServerParameters(
        command=sys.executable, args=["-m", "unified_mcp_graphify.server"]
    )
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / "orders.py").write_text(SAMPLE)

        async with stdio_client(server) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                tools = {t.name for t in (await session.list_tools()).tools}
                print("tools:", sorted(tools))
                assert {"build_graph", "build_status"} <= tools, "new tools not exposed!"

                # 1) idle before any build
                idle = _payload(await session.call_tool("build_status", {"path": str(repo)}))
                print("idle status:", idle)
                assert idle["state"] == "idle", idle

                # 2) start build -> must return immediately as running
                t0 = time.monotonic()
                started = _payload(await session.call_tool("build_graph", {"path": str(repo)}))
                dt = time.monotonic() - t0
                print(f"build_graph returned in {dt:.2f}s:", started)
                assert started["ok"] and started["state"] == "running", started
                assert dt < 5, f"build_graph should return immediately, took {dt:.1f}s"

                # 3) poll build_status until done
                deadline = time.monotonic() + 120
                final = None
                while time.monotonic() < deadline:
                    st = _payload(await session.call_tool("build_status", {"path": str(repo)}))
                    print("  poll:", st["state"], st.get("elapsed_s"))
                    if st["state"] in ("done", "failed"):
                        final = st
                        break
                    await asyncio.sleep(0.5)

                assert final is not None, "build never finished within 120s"
                print("final status:", json.dumps(final, indent=2))
                assert final["state"] == "done", final
                assert final["ok"] is True, final
                assert final["nodes"] > 0 and final["edges"] >= 0, final
                assert Path(final["graph_json"]).exists(), "graph.json not written"

                # 4) a real query over the freshly built graph
                stats = (
                    (await session.call_tool("graph_stats", {"path": str(repo)})).content[0].text
                )
                print("graph_stats:\n", stats)
                assert "Nodes:" in stats

    print("\nE2E PASSED ✅")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
