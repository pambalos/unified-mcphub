import shutil
from pathlib import Path

import pytest

from unified_mcp_graphify import _graph

FIXTURE = Path(__file__).parent / "fixtures" / "sample_graph.json"


def test_graph_json_path_is_native_location():
    p = _graph.graph_json_path("/some/repo")
    assert p.name == "graph.json"
    assert p.parent.name == "graphify-out"


def _make_repo(tmp_path: Path) -> str:
    out = tmp_path / "graphify-out"
    out.mkdir()
    shutil.copy(FIXTURE, out / "graph.json")
    _graph.clear_cache()
    return str(tmp_path)


def test_load_returns_graph_and_communities(tmp_path):
    graph, communities = _graph.load(_make_repo(tmp_path))
    assert graph.number_of_nodes() > 0
    assert isinstance(communities, dict)


def test_load_is_cached_by_mtime(tmp_path):
    repo = _make_repo(tmp_path)
    g1, _ = _graph.load(repo)
    g2, _ = _graph.load(repo)
    assert g1 is g2  # same object → served from cache


def test_missing_graph_raises(tmp_path):
    _graph.clear_cache()
    with pytest.raises(_graph.GraphNotBuiltError):
        _graph.load(str(tmp_path))
