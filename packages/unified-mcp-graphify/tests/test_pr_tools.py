"""PR tools (list_prs / get_pr_impact / triage_prs) — graphify.prs is mocked so
these run offline; a live `gh` smoke test is in the Part-B notes."""

import datetime as dt
import shutil
from pathlib import Path

import graphify.prs as prs
import pytest

from unified_mcp_graphify import _graph, server

FIXTURE = Path(__file__).parent / "fixtures" / "sample_graph.json"


def _pr(number=8, base="main", status_inputs=None):
    return prs.PRInfo(
        number=number,
        title=f"PR {number}",
        branch=f"feat/{number}",
        base_branch=base,
        author="me",
        is_draft=False,
        review_decision="",
        ci_status="SUCCESS",
        updated_at=dt.datetime.now(dt.timezone.utc),
        expected_base=base,
    )


@pytest.fixture
def repo(tmp_path):
    out = tmp_path / "graphify-out"
    out.mkdir()
    shutil.copy(FIXTURE, out / "graph.json")
    _graph.clear_cache()
    return str(tmp_path)


def test_list_prs(monkeypatch, tmp_path):
    monkeypatch.setattr(prs, "_detect_default_branch", lambda repo=None: "main")
    monkeypatch.setattr(prs, "fetch_prs", lambda repo=None, base=None: [_pr(8)])
    monkeypatch.setattr(prs, "fetch_worktrees", lambda: {})
    monkeypatch.setattr(prs, "format_prs_text", lambda prs_, base: f"{len(prs_)} PR(s) on {base}")
    out = server.list_prs(str(tmp_path))
    assert "1 PR(s) on main" in out


def test_get_pr_impact(monkeypatch, repo):
    monkeypatch.setattr(
        prs,
        "_gh",
        lambda *a: {
            "title": "Title",
            "baseRefName": "main",
            "author": {"login": "me"},
            "statusCheckRollup": [],
            "reviewDecision": None,
        },
    )
    monkeypatch.setattr(prs, "fetch_pr_files", lambda n, r=None: ["src/orders.py"])
    monkeypatch.setattr(prs, "compute_pr_impact", lambda files, g: ([0], 3))
    monkeypatch.setattr(prs, "_parse_ci", lambda rollup: "NONE")
    out = server.get_pr_impact(repo, 8)
    assert "PR #8: Title" in out
    assert "Graph impact: 3 nodes across 1 communities" in out
    assert "src/orders.py" in out


def test_get_pr_impact_no_graph(tmp_path):
    _graph.clear_cache()
    out = server.get_pr_impact(str(tmp_path), 1)
    assert "build_graph" in out


def test_triage_prs(monkeypatch, repo):
    monkeypatch.setattr(prs, "_detect_default_branch", lambda repo=None: "main")
    monkeypatch.setattr(prs, "fetch_prs", lambda repo=None, base=None: [_pr(8), _pr(9)])
    monkeypatch.setattr(prs, "fetch_worktrees", lambda: {})
    monkeypatch.setattr(prs, "fetch_pr_files", lambda n, r=None: ["src/orders.py"])
    monkeypatch.setattr(prs, "compute_pr_impact", lambda files, g: ([0], 2))
    out = server.triage_prs(repo)
    assert "Actionable PRs targeting main: 2" in out
    assert "PR #8" in out and "PR #9" in out


def test_triage_no_graph(tmp_path):
    _graph.clear_cache()
    out = server.triage_prs(str(tmp_path))
    assert "build_graph" in out
