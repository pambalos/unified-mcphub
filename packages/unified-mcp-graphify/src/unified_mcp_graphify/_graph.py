"""Per-call graph resolution + caching for arbitrary repos.

Every wrapper tool takes a ``path`` (a repo root) and operates on the graphify
graph at the NATIVE location ``<path>/graphify-out/graph.json`` (the location
``graphify extract`` writes to — see the spec / Part A notes). Graphs are loaded
lazily and cached by (resolved path, mtime), so repeated queries against an
unchanged graph don't re-parse it.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import networkx as nx
from networkx.readwrite import json_graph

from graphify.security import check_graph_file_size_cap
from graphify.serve import _communities_from_graph


class GraphNotBuiltError(FileNotFoundError):
    """No graph exists for the path yet — the caller should run ``build_graph``."""


def graph_json_path(path: str) -> Path:
    """Resolve the native graph location for a repo ``path``."""
    return Path(path).expanduser().resolve() / "graphify-out" / "graph.json"


# (resolved graph.json path) -> (mtime, graph, communities)
_cache: dict[str, tuple[float, nx.Graph, dict[int, list[str]]]] = {}
_lock = threading.Lock()


def _read_graph(gp: Path) -> nx.Graph:
    """Load a node-link ``graph.json`` into a directed NetworkX graph.

    Mirrors ``graphify.serve._load_graph`` but **raises** instead of calling
    ``sys.exit`` (that helper is a CLI; we're a long-lived server, so a bad path
    must not kill the process).
    """
    if gp.suffix != ".json":
        raise ValueError(f"graph path must be a .json file: {gp}")
    if not gp.exists():
        raise GraphNotBuiltError(f"no graph at {gp} — run build_graph first")
    check_graph_file_size_cap(gp)  # raises ValueError if oversized
    data = json.loads(gp.read_text(encoding="utf-8"))
    if "links" not in data and "edges" in data:
        data = dict(data, links=data["edges"])
    data = {**data, "directed": True}
    try:
        return json_graph.node_link_graph(data, edges="links")
    except TypeError:  # older networkx signature
        return json_graph.node_link_graph(data)


def load(path: str) -> tuple[nx.Graph, dict[int, list[str]]]:
    """Return ``(graph, communities)`` for a repo ``path``, cached by mtime.

    Raises ``GraphNotBuiltError`` if the graph doesn't exist yet.
    """
    gp = graph_json_path(path)
    if not gp.exists():
        raise GraphNotBuiltError(
            f"no graph for {Path(path).expanduser().resolve()} "
            f"(expected {gp}) — run build_graph first"
        )
    mtime = gp.stat().st_mtime
    key = str(gp)
    with _lock:
        cached = _cache.get(key)
        if cached and cached[0] == mtime:
            return cached[1], cached[2]
    graph = _read_graph(gp)
    communities = _communities_from_graph(graph)
    with _lock:
        _cache[key] = (mtime, graph, communities)
    return graph, communities


def clear_cache() -> None:
    """Drop all cached graphs (used by tests)."""
    with _lock:
        _cache.clear()
