import subprocess
import threading
import time

import pytest

from unified_mcp_graphify import build


class _Proc:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture(autouse=True)
def _clear_jobs():
    """Keep the in-process job registry from leaking across tests."""
    with build._jobs_lock:
        build._jobs.clear()
    yield
    with build._jobs_lock:
        build._jobs.clear()


def _wait_for(predicate, timeout=5.0):
    """Poll ``predicate`` until truthy; return its value or fail on timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.01)
    raise AssertionError("condition not met within timeout")


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


# --- async job model --------------------------------------------------------


def test_start_build_rejects_non_directory(tmp_path):
    f = tmp_path / "afile"
    f.write_text("x")
    r = build.start_build(str(f))
    assert r["ok"] is False
    assert "not a directory" in r["error"]
    assert build.build_state(str(f)) is None  # nothing registered


def test_build_state_none_when_unknown(tmp_path):
    assert build.build_state(str(tmp_path)) is None


def test_start_build_returns_running_then_done(tmp_path, monkeypatch):
    monkeypatch.setattr(
        build, "build_graph", lambda *a, **k: {"ok": True, "nodes": 5, "edges": 7, "communities": 2}
    )
    r = build.start_build(str(tmp_path), backend="claude-cli")
    assert r["ok"] is True and r["state"] == "running"
    assert r["path"] == str(tmp_path.resolve())

    job = _wait_for(lambda: (j := build.build_state(str(tmp_path))) and j["state"] == "done" and j)
    assert job["result"]["nodes"] == 5
    assert job["finished_at"] is not None


def test_failed_build_marks_state_failed(tmp_path, monkeypatch):
    monkeypatch.setattr(build, "build_graph", lambda *a, **k: {"ok": False, "error": "boom"})
    build.start_build(str(tmp_path))
    job = _wait_for(
        lambda: (j := build.build_state(str(tmp_path))) and j["state"] != "running" and j
    )
    assert job["state"] == "failed"
    assert job["result"]["error"] == "boom"


def test_crash_in_worker_marks_failed(tmp_path, monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(build, "build_graph", _boom)
    build.start_build(str(tmp_path))
    job = _wait_for(
        lambda: (j := build.build_state(str(tmp_path))) and j["state"] != "running" and j
    )
    assert job["state"] == "failed"
    assert "kaboom" in job["result"]["error"]


def test_concurrent_build_is_deduped(tmp_path, monkeypatch):
    release = threading.Event()

    def _block(*a, **k):
        release.wait(timeout=5)
        return {"ok": True}

    monkeypatch.setattr(build, "build_graph", _block)
    first = build.start_build(str(tmp_path))
    assert first["state"] == "running" and "note" not in first

    # second call while the first is still blocked → not duplicated
    second = build.start_build(str(tmp_path))
    assert second["state"] == "running"
    assert "already in progress" in second["note"]
    assert second["started_at"] == build.build_state(str(tmp_path))["started_at"]

    release.set()
    _wait_for(lambda: build.build_state(str(tmp_path))["state"] == "done")
