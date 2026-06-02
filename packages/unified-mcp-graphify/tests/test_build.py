import subprocess

from unified_mcp_graphify import build


class _Proc:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_not_a_directory(tmp_path):
    f = tmp_path / "afile"
    f.write_text("x")
    r = build.build_graph(str(f))
    assert r["ok"] is False
    assert "not a directory" in r["error"]


def test_success_parses_summary(tmp_path, monkeypatch):
    out = "[graphify extract] wrote /x/graphify-out/graph.json: 8 nodes, 14 edges, 3 communities"
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Proc(0, stdout=out))
    r = build.build_graph(str(tmp_path), backend="claude-cli")
    assert r["ok"] is True
    assert (r["nodes"], r["edges"], r["communities"]) == (8, 14, 3)
    assert r["graph_json"].endswith("graphify-out/graph.json")
    assert r["backend"] == "claude-cli"


def test_nonzero_exit_is_error(tmp_path, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Proc(1, stderr="boom"))
    r = build.build_graph(str(tmp_path))
    assert r["ok"] is False
    assert "failed" in r["error"]
    assert "boom" in r["detail"]


def test_timeout_is_handled(tmp_path, monkeypatch):
    def _raise(*a, **k):
        raise subprocess.TimeoutExpired(cmd="graphify", timeout=1)

    monkeypatch.setattr(subprocess, "run", _raise)
    r = build.build_graph(str(tmp_path), timeout=1)
    assert r["ok"] is False
    assert "timed out" in r["error"]
