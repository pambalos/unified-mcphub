"""Audit-log reader — spec §6.5 (SEC-MCP-3 CLI half).

Pure read-side functions over an audit directory of <UTC-date>.jsonl files
written by audit.py. Backs `audit show | pair | search | tail | lint | prune |
verify`.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from unified_enforce.audit import HashChainWriter, VerifyResult

_ALLOWED_DECISIONS = {"allow", "prompt_allowed", "approval_disabled"}


def _day_files(audit_dir: Path) -> list[Path]:
    if not audit_dir.is_dir():
        return []
    return sorted(audit_dir.glob("*.jsonl"))


def _iter_entries(audit_dir: Path):
    for path in _day_files(audit_dir):
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            if not line.strip():
                continue
            try:
                yield path.name, lineno, json.loads(line)
            except json.JSONDecodeError:
                yield path.name, lineno, None  # malformed; lint reports, others skip


def read_day(audit_dir: Path, date_str: str) -> list[dict]:
    path = audit_dir / f"{date_str}.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def pair(audit_dir: Path, request_id: str) -> dict:
    result: dict = {"received": None, "completed": None}
    for _, _, entry in _iter_entries(audit_dir):
        if entry and entry.get("request_id") == request_id:
            result[entry.get("phase")] = entry
    return result


def search(
    audit_dir: Path,
    *,
    caller: str | None = None,
    tool: str | None = None,
    server: str | None = None,
    decision: str | None = None,
    status: str | None = None,
    since: str | None = None,
    until: str | None = None,
    phase: str | None = None,
    limit: int | None = None,
) -> list[dict]:
    matches: list[dict] = []
    for _, _, entry in _iter_entries(audit_dir):
        if entry is None:
            continue
        if phase and entry.get("phase") != phase:
            continue
        if caller and entry.get("caller_id") != caller:
            continue
        if tool and entry.get("tool") != tool:
            continue
        if server and entry.get("mcp_server") != server:
            continue
        if decision and entry.get("authz_decision") != decision:
            continue
        if status and entry.get("result_status") != status:
            continue
        ts = entry.get("ts", "")
        if since and ts < since:
            continue
        if until and ts > until:
            continue
        matches.append(entry)
    return matches[:limit] if limit else matches


def tail(audit_dir: Path, n: int = 20) -> list[dict]:
    files = _day_files(audit_dir)
    if not files:
        return []
    lines = [line for line in files[-1].read_text().splitlines() if line.strip()]
    return [json.loads(line) for line in lines[-n:]]


def lint(audit_dir: Path) -> list[str]:
    problems: list[str] = []
    received: dict[str, str] = {}  # request_id -> decision
    completed: set[str] = set()
    for filename, lineno, entry in _iter_entries(audit_dir):
        if entry is None:
            problems.append(f"{filename}:{lineno}: malformed JSON")
            continue
        phase = entry.get("phase")
        rid = entry.get("request_id")
        if phase == "received":
            received[rid] = entry.get("authz_decision", "")
        elif phase == "completed":
            completed.add(rid)
        else:
            problems.append(f"{filename}:{lineno}: unknown phase {phase!r}")
    for rid, dec in received.items():
        if dec in _ALLOWED_DECISIONS and rid not in completed:
            problems.append(f"request {rid}: '{dec}' received with no completed entry")
    for rid in completed - set(received):
        problems.append(f"request {rid}: completed with no received entry")
    return problems


def verify(audit_dir: Path) -> VerifyResult:
    """Replay the hash chain offline: any edited or deleted entry breaks it."""
    return HashChainWriter.verify(audit_dir)


def prune(audit_dir: Path, retention_days: int) -> list[str]:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).date()
    removed: list[str] = []
    for path in _day_files(audit_dir):
        try:
            file_date = datetime.strptime(path.stem, "%Y-%m-%d").date()
        except ValueError:
            continue  # not a dated audit file; leave it
        if file_date < cutoff:
            path.unlink()
            removed.append(path.name)
    return removed
