"""Unit tests for the fetch server — SSRF block list + backend selection.

No real network: we exercise the block decision and backend routing, which are
the security-relevant parts.
"""

from __future__ import annotations

import unified_mcp_servers.fetch as ft


def test_blocked_host_literal(monkeypatch):
    monkeypatch.setattr(ft.CONFIG, "blocked_hosts", ["169.254.169.254"])
    assert ft._host_blocked("169.254.169.254") is True
    assert ft._host_blocked("example.com") is False


def test_blocked_host_cidr(monkeypatch):
    monkeypatch.setattr(ft.CONFIG, "blocked_hosts", ["169.254.0.0/16"])
    assert ft._host_blocked("169.254.169.254") is True


def test_empty_blocklist_allows_everything(monkeypatch):
    monkeypatch.setattr(ft.CONFIG, "blocked_hosts", [])
    assert ft._host_blocked("169.254.169.254") is False  # guard off by default


def test_fetch_refuses_blocked_without_override(monkeypatch):
    monkeypatch.setattr(ft.CONFIG, "blocked_hosts", ["169.254.169.254"])
    res = ft.fetch_webpage("http://169.254.169.254/latest/meta-data/")
    assert res["success"] is False and res["error"] == "blocked_host"


def test_fetch_rejects_non_http():
    assert ft.fetch_webpage("file:///etc/passwd")["success"] is False


def test_backend_auto_selection(monkeypatch):
    monkeypatch.setattr(ft.CONFIG, "search_backend", "auto")
    monkeypatch.delenv("BRAVE_API_KEY", raising=False)
    assert ft._resolve_backend() == "duckduckgo"
    monkeypatch.setenv("BRAVE_API_KEY", "k")
    assert ft._resolve_backend() == "brave"


def test_search_none_disabled(monkeypatch):
    monkeypatch.setattr(ft.CONFIG, "search_backend", "none")
    assert ft.search_internet("q")["success"] is False


def test_ddg_parser_extracts_lite_results():
    body = (
        '<a rel="nofollow" class="result-link" href="https://a.example/x">First Result</a>'
        '<a rel="nofollow" class="result-link" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fb.example">Second</a>'
    )
    p = ft._DDGLiteParser()
    p.feed(body)
    assert [r["title"] for r in p.results] == ["First Result", "Second"]
    assert p.results[0]["url"] == "https://a.example/x"
    assert p.results[1]["url"] == "https://b.example"  # uddg-unwrapped


def test_ddg_blocked_reports_failure_not_empty_success(monkeypatch):
    # When DDG serves an anomaly/captcha page (no result-link), we must NOT
    # report success with 0 results — surface a clear, honest failure.
    monkeypatch.setattr(ft.CONFIG, "search_backend", "duckduckgo")

    class _Resp:
        def read(self):
            return b"<html>unusual traffic detected, please solve the captcha</html>"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(ft.urllib.request, "urlopen", lambda *a, **k: _Resp())
    r = ft.search_internet("anything")
    assert r["success"] is False and r["result_count"] == 0
    assert "BRAVE_API_KEY" in r["error"] and "blocked" in r["error"]
