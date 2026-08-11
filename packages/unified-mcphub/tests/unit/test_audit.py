"""Unit tests for the two-phase audit writer — spec §6, ADR-0009 (SEC-MCP-3 logic)."""

from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timezone

import pytest

import unified_mcphub.audit as audit_mod
from unified_mcphub.audit import AuditLog


def _received(log: AuditLog, request_id: str, **over):
    kw = dict(
        request_id=request_id,
        trace_id="t",
        span_id="s",
        caller_id="claude-code",
        caller_token_id=None,
        mcp_server="fs",
        tool="list_files",
        args={"path": "."},
        authz_decision="allow",
        authz_rule="mcp://*/list_*",
        audit_level="standard",
    )
    kw.update(over)
    log.write_received(**kw)


def _read(audit_dir):
    files = list(audit_dir.glob("*.jsonl"))
    assert len(files) == 1, files
    return [json.loads(line) for line in files[0].read_text().splitlines()]


def test_two_phase_pair(tmp_path):
    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        _received(log, "r1")
        log.write_completed(
            request_id="r1",
            duration_ms=1.2,
            result={"content": []},
            result_status="ok",
            audit_level="standard",
        )
    finally:
        log.stop()

    entries = _read(tmp_path / "audit")
    assert [e["phase"] for e in entries] == ["received", "completed"]
    assert entries[0]["request_id"] == entries[1]["request_id"] == "r1"
    assert entries[0]["seq"] < entries[1]["seq"]
    assert entries[1]["result_status"] == "ok"


def test_deny_writes_received_only(tmp_path):
    # caller logic writes received only on deny; the writer just records what it's given.
    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        _received(log, "d1", authz_decision="deny", authz_rule=None, reason="default_deny")
    finally:
        log.stop()
    entries = _read(tmp_path / "audit")
    assert len(entries) == 1 and entries[0]["phase"] == "received"
    assert entries[0]["authz_decision"] == "deny"


def test_standard_level_scrubs_secrets(tmp_path):
    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        _received(log, "r1", args={"token": "sk-ABCDEFGHIJKLMNOPQRSTUVWX"}, audit_level="standard")
    finally:
        log.stop()
    entry = _read(tmp_path / "audit")[0]
    assert "sk-ABCDEF" not in json.dumps(entry["args"])
    assert "redacted" in json.dumps(entry["args"])


def test_minimal_level_nulls_payload(tmp_path):
    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        _received(log, "r1", args={"secret": "x"}, audit_level="minimal")
    finally:
        log.stop()
    assert _read(tmp_path / "audit")[0]["args"] is None


def test_lock_blocks_second_writer(tmp_path):
    log1 = AuditLog(tmp_path / "audit")
    log1.start()
    log2 = AuditLog(tmp_path / "audit")
    try:
        with pytest.raises(RuntimeError):
            log2.start()
    finally:
        log1.stop()


def test_audit_file_mode_0600(tmp_path):
    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        _received(log, "r1")
    finally:
        log.stop()
    f = next((tmp_path / "audit").glob("*.jsonl"))
    assert stat.S_IMODE(f.stat().st_mode) == 0o600


def test_detailed_level_keeps_raw(tmp_path):
    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        _received(log, "r1", args={"token": "sk-ABCDEFGHIJKLMNOPQRSTUVWX"}, audit_level="detailed")
    finally:
        log.stop()
    # detailed captures raw, no scrubbing.
    assert _read(tmp_path / "audit")[0]["args"]["token"] == "sk-ABCDEFGHIJKLMNOPQRSTUVWX"


def test_full_level_keeps_raw(tmp_path):
    # `full` captures raw like `detailed` — the spec's "4KB stdout tail" is N/A for
    # routed MCP calls (no per-call stdout stream exists at M0).
    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        _received(log, "r1", args={"token": "sk-ABCDEFGHIJKLMNOPQRSTUVWX"}, audit_level="full")
    finally:
        log.stop()
    assert _read(tmp_path / "audit")[0]["args"]["token"] == "sk-ABCDEFGHIJKLMNOPQRSTUVWX"


def test_write_failure_raises_audit_error(tmp_path):
    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        os.close(log._fd)  # simulate an I/O failure on the audit fd
        with pytest.raises(RuntimeError, match="audit_error"):
            _received(log, "r1", audit_level="minimal")
    finally:
        log._fd = None  # already closed — don't double-close in stop()
        log.stop()


def test_entries_are_hash_chained(tmp_path):
    # Post unified-enforce migration: flat two-phase entries carry the chain.
    from unified_mcphub import audit_reader

    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        _received(log, "r1")
        _received(log, "r2")
    finally:
        log.stop()
    entries = _read(tmp_path / "audit")
    assert entries[0]["prev_hash"] == "0" * 64
    assert entries[1]["prev_hash"] == entries[0]["hash"]
    assert entries[0]["phase"] == "received"  # flat shape preserved
    result = audit_reader.verify(tmp_path / "audit")
    assert result.ok and result.entries == 2


def test_tampered_entry_fails_verify(tmp_path):
    import json as json_mod

    from unified_mcphub import audit_reader

    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        _received(log, "r1")
    finally:
        log.stop()
    path = next((tmp_path / "audit").glob("*.jsonl"))
    entry = json_mod.loads(path.read_text())
    entry["authz_decision"] = "allow-actually-it-was-deny"
    path.write_text(json_mod.dumps(entry) + "\n")
    result = audit_reader.verify(tmp_path / "audit")
    assert not result.ok and "hash mismatch" in result.error


def test_chain_resumes_across_restarts(tmp_path):
    from unified_mcphub import audit_reader

    log1 = AuditLog(tmp_path / "audit")
    log1.start()
    try:
        _received(log1, "r1")
    finally:
        log1.stop()
    log2 = AuditLog(tmp_path / "audit")
    log2.start()
    try:
        _received(log2, "r2")
    finally:
        log2.stop()
    entries = _read(tmp_path / "audit")
    assert entries[1]["prev_hash"] == entries[0]["hash"]
    assert entries[1]["seq"] == 2  # seq now survives restarts too
    assert audit_reader.verify(tmp_path / "audit").ok


def test_float_args_are_recorded_not_rejected(tmp_path):
    # Hub args are free-form JSON (strict=False chaining) — floats must not raise.
    from unified_mcphub import audit_reader

    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        _received(log, "r1", args={"amount": 1.5}, audit_level="detailed")
    finally:
        log.stop()
    assert _read(tmp_path / "audit")[0]["args"]["amount"] == 1.5
    assert audit_reader.verify(tmp_path / "audit").ok


def test_action_digest_recorded_when_given(tmp_path):
    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        _received(log, "r1", action_digest="ab" * 32)
    finally:
        log.stop()
    assert _read(tmp_path / "audit")[0]["action_digest"] == "ab" * 32


def test_daily_utc_rotation(tmp_path, monkeypatch):
    clock = {"now": datetime(2026, 1, 1, tzinfo=timezone.utc)}
    monkeypatch.setattr(audit_mod, "utcnow", lambda: clock["now"])
    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        _received(log, "r1", audit_level="minimal")
        clock["now"] = datetime(2026, 1, 2, tzinfo=timezone.utc)
        _received(log, "r2", audit_level="minimal")
    finally:
        log.stop()
    names = sorted(p.name for p in (tmp_path / "audit").glob("*.jsonl"))
    assert names == ["2026-01-01.jsonl", "2026-01-02.jsonl"]
