import shutil
from pathlib import Path

import pytest

from unified_mcp_graphify import _graph, server

FIXTURE = Path(__file__).parent / "fixtures" / "sample_graph.json"


@pytest.fixture
def repo(tmp_path):
    """A repo dir whose graphify-out/graph.json is the sample (orders.py) graph."""
    out = tmp_path / "graphify-out"
    out.mkdir()
    shutil.copy(FIXTURE, out / "graph.json")
    _graph.clear_cache()
    return str(tmp_path)


def test_graph_stats(repo):
    out = server.graph_stats(repo)
    assert "Nodes:" in out and "Edges:" in out and "EXTRACTED:" in out


def test_query_graph_finds_known_node(repo):
    out = server.query_graph(repo, "Order")
    assert "Order" in out


def test_get_node(repo):
    out = server.get_node(repo, "Order")
    assert out.startswith("Node:")
    assert "Degree:" in out


def test_get_node_missing(repo):
    assert "No node matching" in server.get_node(repo, "zzz_does_not_exist")


def test_get_neighbors(repo):
    out = server.get_neighbors(repo, "Order")
    assert out.startswith("Neighbors of")


def test_god_nodes(repo):
    out = server.god_nodes(repo, top_n=3)
    assert out.startswith("God nodes")


def test_get_community(repo):
    out = server.get_community(repo, 0)
    assert "Community 0" in out


def test_shortest_path_returns_string(repo):
    out = server.shortest_path(repo, "Order", "Decimal")
    assert isinstance(out, str) and out


def test_tools_report_missing_graph(tmp_path):
    _graph.clear_cache()
    out = server.query_graph(str(tmp_path), "anything")
    assert "build_graph" in out
