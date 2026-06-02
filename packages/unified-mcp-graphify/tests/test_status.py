import shutil
from pathlib import Path

from unified_mcp_graphify import status

FIXTURE = Path(__file__).parent / "fixtures" / "sample_graph.json"


def test_no_graph(tmp_path):
    r = status.graph_status(str(tmp_path))
    assert r["graph_exists"] is False
    assert "hint" in r


def test_with_graph(tmp_path):
    out = tmp_path / "graphify-out"
    out.mkdir()
    shutil.copy(FIXTURE, out / "graph.json")
    r = status.graph_status(str(tmp_path))
    assert r["graph_exists"] is True
    assert "built_at" in r
    assert r["size_bytes"] > 0
