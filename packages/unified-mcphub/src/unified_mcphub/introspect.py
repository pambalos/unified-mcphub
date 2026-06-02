"""Introspection for the read-only CLIs — spec §13 (MCP-HUB-6).

`workspace list/show/use` and `list-servers/list-tools/list-packs`. These read
config + workspace files; `list-tools` queries the running hub over its Unix
socket when up, else falls back to locally-known built-ins.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import yaml

from . import endpoints
from .config import (
    config_path,
    load_dangerous_commands,
    load_hub_config,
    load_workspace,
    mcphub_home,
)
from .tools import BuiltinRegistry


def list_workspaces() -> list[str]:
    workspaces = mcphub_home() / "workspaces"
    if not workspaces.is_dir():
        return []
    return sorted(p.stem for p in workspaces.glob("*.yaml"))


def active_workspace() -> str:
    return load_hub_config().active_workspace


def show_workspace(name: str | None = None) -> dict:
    name = name or active_workspace()
    return {"name": name, **load_workspace(name).model_dump()}


def use_workspace(name: str) -> None:
    if name not in list_workspaces():
        raise FileNotFoundError(f"workspace '{name}' not found in {mcphub_home() / 'workspaces'}")
    path = config_path()
    data = (yaml.safe_load(path.read_text()) if path.exists() else {}) or {}
    data["active_workspace"] = name
    path.write_text(yaml.safe_dump(data, sort_keys=False))


def list_servers(name: str | None = None) -> list[dict]:
    name = name or active_workspace()
    servers = []
    for server_name, spec in load_workspace(name).servers.items():
        upstream = spec.upstream
        kind = (
            "process"
            if upstream.command
            else "http"
            if upstream.url
            else "container"
            if upstream.image
            else "unknown"
        )
        servers.append({"name": server_name, "kind": kind})
    return servers


def list_packs() -> list[str]:
    # The only rule "pack" at M0 is the dangerous-commands safety floor.
    return load_dangerous_commands().require_approval


async def _query_hub_tools(socket: Path) -> list[str]:
    transport = httpx.AsyncHTTPTransport(uds=str(socket))
    async with httpx.AsyncClient(transport=transport, base_url="http://hub", timeout=5) as client:
        response = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"X-Caller-Id": "cli"},
        )
        return [tool["name"] for tool in response.json()["result"]["tools"]]


def list_tools() -> dict:
    """Aggregated tools from the running hub, else locally-known built-ins."""
    socket = endpoints.socket_path()
    if socket and socket.exists():
        return {"source": "hub", "tools": asyncio.run(_query_hub_tools(socket))}
    registry = BuiltinRegistry()
    registry.load_user_tools(mcphub_home() / "tools")
    return {
        "source": "builtins-only (hub not running)",
        "tools": [f"built-in__{tool.name}" for tool in registry.list_tools()],
    }
