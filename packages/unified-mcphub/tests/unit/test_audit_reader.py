"""Unit tests for the audit reader — spec §6.5 (SEC-MCP-3)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from unified_mcphub import audit_reader


def _write(audit_dir, date_str, entries):
    audit_dir.mkdir(parents=True, exist_ok=True)
    (audit_dir / f"{date_str}.jsonl").write_text(
        "\n".join(json.dumps(e) if isinstance(e, dict) else e for e in entries) + "\n"
    )


def _received(rid, **over):
    base = {"phase": "received", "request_id": rid, "ts": "2026-01-01T00:00:00+00:00",
            "caller_id": "claude-code", "tool": "list_files", "mcp_server": "fs",
            "authz_decision": "allow"}
    base.update(over)
    return base


def _completed(rid, **over):
    base = {"phase": "completed", "request_id": rid, "ts": "2026-01-01T00:00:01+00:00",
            "result_status": "ok"}
    base.update(over)
    return base


def test_pair(tmp_path):
    d = tmp_path / "audit"
    _write(d, "2026-01-01", [_received("r1"), _completed("r1")])
    result = audit_reader.pair(d, "r1")
    assert result["received"]["request_id"] == "r1"
    assert result["completed"]["result_status"] == "ok"


def test_search_filters(tmp_path):
    d = tmp_path / "audit"
    _write(d, "2026-01-01", [
        _received("r1", caller_id="claude-code", tool="list_files"),
        _received("r2", caller_id="opencode", tool="read_file"),
    ])
    assert [e["request_id"] for e in audit_reader.search(d, caller="claude-code")] == ["r1"]
    assert [e["request_id"] for e in audit_reader.search(d, tool="read_file")] == ["r2"]
    assert audit_reader.search(d, phase="completed") == []
    assert len(audit_reader.search(d, limit=1)) == 1


def test_read_day(tmp_path):
    d = tmp_path / "audit"
    _write(d, "2026-01-01", [_received("r1")])
    assert len(audit_reader.read_day(d, "2026-01-01")) == 1
    assert audit_reader.read_day(d, "2099-01-01") == []


def test_search_remaining_filters(tmp_path):
    d = tmp_path / "audit"
    _write(d, "2026-01-01", [
        _received("r1", mcp_server="fs", ts="2026-01-01T01:00:00+00:00"),
        _completed("r1", result_status="ok"),
        _received("r2", mcp_server="github", authz_decision="deny",
                  ts="2026-01-02T01:00:00+00:00"),
    ])
    assert [e["request_id"] for e in audit_reader.search(d, server="github")] == ["r2"]
    assert [e["request_id"] for e in audit_reader.search(d, decision="deny")] == ["r2"]
    assert [e["request_id"] for e in audit_reader.search(d, status="ok")] == ["r1"]
    assert [e["request_id"] for e in audit_reader.search(d, since="2026-01-02T00:00:00+00:00")] == ["r2"]
    assert "r2" not in [e["request_id"] for e in audit_reader.search(d, until="2026-01-01T23:59:59+00:00")]


def test_tail_order(tmp_path):
    d = tmp_path / "audit"
    _write(d, "2026-01-01", [_received(f"r{i}") for i in range(5)])
    tail = audit_reader.tail(d, n=2)
    assert [e["request_id"] for e in tail] == ["r3", "r4"]


def test_lint_catches_malformed_and_unpaired(tmp_path):
    d = tmp_path / "audit"
    _write(d, "2026-01-01", [
        _received("r1", authz_decision="allow"),   # allowed but no completed -> flagged
        "{ this is not json",                        # malformed -> flagged
        _completed("orphan"),                        # completed with no received -> flagged
        _received("r2", authz_decision="deny"),      # deny: received-only is fine
    ])
    problems = audit_reader.lint(d)
    assert any("malformed" in p for p in problems)
    assert any("r1" in p and "no completed" in p for p in problems)
    assert any("orphan" in p and "no received" in p for p in problems)
    assert not any("r2" in p for p in problems)


def test_prune_removes_only_old(tmp_path):
    d = tmp_path / "audit"
    today = datetime.now(timezone.utc).date()
    old = (today - timedelta(days=400)).isoformat()
    recent = (today - timedelta(days=2)).isoformat()
    _write(d, old, [_received("a")])
    _write(d, recent, [_received("b")])
    removed = audit_reader.prune(d, retention_days=365)
    assert removed == [f"{old}.jsonl"]
    assert (d / f"{recent}.jsonl").exists()
    assert not (d / f"{old}.jsonl").exists()
