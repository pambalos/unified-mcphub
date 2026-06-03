import shutil
import time
from pathlib import Path

import pytest

from unified_mcp_graphify import _graph, build, server

FIXTURE = Path(__file__).parent / "fixtures" / "sample_graph.json"


@pytest.fixture
def repo(tmp_path):
    """A repo dir whose graphify-out/graph.json is the sample (orders.py) graph."""
    out = tmp_path / "graphify-out"
    out.mkdir()
    shutil.copy(FIXTURE, out / "graph.json")
    _graph.clear_cache()
    return str(tmp_path)


@pytest.fixture(autouse=True)
def _clear_jobs():
    with build._jobs_lock:
        build._jobs.clear()
    yield
    with build._jobs_lock:
        build._jobs.clear()


def _wait_for(predicate, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if value := predicate():
            return value
        time.sleep(0.01)
    raise AssertionError("condition not met within timeout")


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


# --- async build_graph / build_status ---------------------------------------


def test_build_status_idle_without_graph(tmp_path):
    r = server.build_status(str(tmp_path))
    assert r["state"] == "idle"
    assert r["graph_exists"] is False


def test_build_status_idle_falls_back_to_disk(repo):
    r = server.build_status(repo)
    assert r["state"] == "idle"
    assert r["graph_exists"] is True  # on-disk graph from a prior run


def test_build_graph_returns_running_immediately(tmp_path, monkeypatch):
    monkeypatch.setattr(build, "build_graph", lambda *a, **k: {"ok": True, "nodes": 1})
    r = server.build_graph(str(tmp_path))
    assert r["ok"] is True and r["state"] == "running"


def test_build_status_reports_completion(tmp_path, monkeypatch):
    monkeypatch.setattr(
        build, "build_graph", lambda *a, **k: {"ok": True, "nodes": 9, "edges": 4, "communities": 1}
    )
    server.build_graph(str(tmp_path), backend="claude-cli")
    done = _wait_for(lambda: (s := server.build_status(str(tmp_path)))["state"] == "done" and s)
    assert done["nodes"] == 9
    assert done["backend"] == "claude-cli"
    assert done["ok"] is True
    assert isinstance(done["elapsed_s"], float)
