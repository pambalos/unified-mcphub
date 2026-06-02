"""Connection-info derivation — spec §3.1, §11.1.

Single source for the hub's reachable addresses + the `unified-mcp.json`
canonical-truth shape. The hub (on start), the installers (when wiring a
harness), and the CLI introspection all derive from here so the URL/socket
forms are defined exactly once.
"""

from __future__ import annotations

from pathlib import Path

from .config import HubConfig, load_hub_config


def http_url(hub: HubConfig | None = None) -> str | None:
    hub = hub or load_hub_config()
    return f"http://{hub.listen.tcp}/mcp" if hub.listen.tcp else None


def socket_path(hub: HubConfig | None = None) -> Path | None:
    hub = hub or load_hub_config()
    return Path(hub.listen.unix_socket).expanduser() if hub.listen.unix_socket else None


def canonical_truth(workspace_name: str, hub: HubConfig | None = None) -> dict:
    hub = hub or load_hub_config()
    transports: dict = {}
    sock = socket_path(hub)
    if sock:
        transports["unix_socket"] = {"path": str(sock), "preferred": True}
    if hub.listen.tcp:
        transports["tcp"] = {"url": http_url(hub)}
    return {"name": "unified-hub", "transports": transports, "active_workspace": workspace_name}
