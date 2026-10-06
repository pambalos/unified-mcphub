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


SECRET = "sk-ABCDEFGHIJKLMNOPQRSTUVWX"


@pytest.mark.parametrize("level", ["minimal", "standard", "detailed", "full"])
def test_args_and_result_are_recorded_raw_at_every_level(tmp_path, level):
    """The record holds exactly what was sent and what came back; audit_level
    is recorded beside it as the default view, not applied to it."""
    from unified_mcphub import audit_reader

    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        _received(log, "r1", args={"token": SECRET}, audit_level=level)
        log.write_completed(
            request_id="r1",
            duration_ms=1.0,
            result={"content": [{"type": "text", "text": SECRET}]},
            result_status="ok",
            audit_level=level,
        )
    finally:
        log.stop()
    received, completed = _read(tmp_path / "audit")
    assert received["args"] == {"token": SECRET}
    assert completed["result"]["content"][0]["text"] == SECRET
    assert received["audit_level"] == completed["audit_level"] == level
    assert set(received["detached"]) == {"args"} and set(completed["detached"]) == {"result"}
    assert "redactions_applied" not in completed, "described a write-time scrub that is gone"
    result = audit_reader.verify(tmp_path / "audit")
    assert result.ok and result.payloads_verified == 2


def test_display_applies_the_recorded_level(tmp_path):
    from unified_mcphub import audit_reader

    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        _received(log, "std", args={"token": SECRET}, audit_level="standard")
        _received(log, "min", args={"token": SECRET}, audit_level="minimal")
        _received(log, "raw", args={"token": SECRET}, audit_level="detailed")
    finally:
        log.stop()
    std, mini, raw = (audit_reader.view(e) for e in _read(tmp_path / "audit"))
    assert "sk-ABCDEF" not in json.dumps(std["args"]) and "redacted" in json.dumps(std["args"])
    assert mini["args"] is None
    assert raw["args"]["token"] == SECRET
    assert all("salts" not in e for e in (std, mini, raw)), "salts are never printed"


def test_cli_prints_the_view_unless_raw(tmp_path, monkeypatch, capsys):
    from unified_mcphub import cli

    monkeypatch.setattr(cli, "audit_dir", lambda: tmp_path / "audit")
    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        _received(log, "r1", args={"token": SECRET}, audit_level="standard")
    finally:
        log.stop()
    cli.main(["audit", "tail"])
    assert SECRET not in capsys.readouterr().out
    cli.main(["audit", "show", "r1", "--raw"])
    assert SECRET in capsys.readouterr().out


def test_edited_args_fail_verify_even_though_the_hash_does_not_cover_them(tmp_path):
    from unified_mcphub import audit_reader

    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        _received(log, "r1", args={"path": "/etc/passwd"})
    finally:
        log.stop()
    path = next((tmp_path / "audit").glob("*.jsonl"))
    path.write_text(path.read_text().replace("/etc/passwd", "/tmp/harmless"))
    result = audit_reader.verify(tmp_path / "audit")
    assert not result.ok and "does not match its digest" in result.error


def test_record_payloads_off_keeps_digests_not_content_and_says_so(tmp_path, caplog):
    import logging

    from unified_mcphub import audit_reader

    log = AuditLog(tmp_path / "audit", record_payloads=False)
    with caplog.at_level(logging.WARNING):
        log.start()
    try:
        _received(log, "r1", args={"token": SECRET})
        log.write_completed(
            request_id="r1",
            duration_ms=1.0,
            result={"content": [{"type": "text", "text": SECRET}]},
            result_status="ok",
            audit_level="standard",
        )
    finally:
        log.stop()
    assert any(
        r.levelno == logging.WARNING and "record_payloads is OFF" in r.getMessage()
        for r in caplog.records
    )
    raw = next((tmp_path / "audit").glob("*.jsonl")).read_text()
    assert SECRET not in raw
    received, completed = _read(tmp_path / "audit")
    assert "args" not in received and received["unrecorded"] == ["args"]
    assert "result" not in completed and completed["unrecorded"] == ["result"]
    assert audit_reader.view(received)["args"] == audit_reader.NOT_RECORDED
    result = audit_reader.verify(tmp_path / "audit")
    assert result.ok and result.payloads_unrecorded == 2 and result.payloads_verified == 0


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


def test_received_records_the_policy_digest_when_given(tmp_path):
    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        _received(log, "p1", policy_digest="ab" * 32)
        _received(log, "p2")
    finally:
        log.stop()
    with_digest, without = _read(tmp_path / "audit")
    assert with_digest["policy_digest"] == "ab" * 32
    assert "policy_digest" not in without, "absent, not null, when no policy decided"


def test_a_hub_chain_exports_digests_only_and_still_verifies(tmp_path):
    """The hub's args and results withheld from an evidence pack: no content
    in the pack, every link intact, the pack's own verifier satisfied."""
    import subprocess
    import sys
    from datetime import timedelta

    from unified_enforce.evidence_pack import ChainSource, build

    log = AuditLog(tmp_path / "audit")
    log.start()
    try:
        _received(log, "r1", args={"token": SECRET})
        log.write_completed(
            request_id="r1",
            duration_ms=1.0,
            result={"content": [{"type": "text", "text": SECRET}]},
            result_status="ok",
            audit_level="standard",
        )
    finally:
        log.stop()
    pack = build(
        out=tmp_path / "pack",
        title="hub",
        fleet_id="f",
        start=datetime(2000, 1, 1, tzinfo=timezone.utc),
        end=datetime.now(timezone.utc) + timedelta(days=1),
        csv_path=None,
        chains=[ChainSource(name="hub", directory=tmp_path / "audit")],
        policies=[],
        root_key=None,
        keyset_path=None,
        payloads="digests-only",
    )
    assert SECRET not in (pack / "chains" / "hub" / "chain.jsonl").read_text()
    result = subprocess.run(
        [sys.executable, "-I", str(pack / "verify" / "verify.py")],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "0 verified against their digests, 2 withheld" in result.stdout
