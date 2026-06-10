"""Two-phase append-only audit log — spec §6, ADR-0009.

- File: audit/<UTC-date>.jsonl, opened O_APPEND|O_WRONLY|O_CREAT (0600).
- fcntl exclusive lock on audit/.lock at startup (single writer).
- Two entries per call paired by request_id: `received` (before forward) +
  `completed` (on resolve). Denied calls write `received` only.
- Sync os.write append into the page cache — immediately readable and
  crash-surviving; fsync on daily rotation + shutdown. audit_level controls
  payload capture (minimal/standard/detailed/full).

Writes come only from the single asyncio event-loop thread (sync, no await in
the write path), so no locking is needed.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any

from .util import utcnow

# Secret-shape redaction for `standard` level (defense-in-depth, leaky by design).
_SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{16,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT
]
_REDACTED = "«redacted»"


def _scrub(value: Any) -> Any:
    if isinstance(value, str):
        out = value
        for pat in _SECRET_PATTERNS:
            out = pat.sub(_REDACTED, out)
        return out
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


def _capture(payload: Any, audit_level: str) -> Any:
    if audit_level == "minimal":
        return None
    if audit_level == "standard":
        return _scrub(payload)
    return payload  # detailed / full -> raw


def new_trace_id() -> str:
    return secrets.token_hex(16)


def new_span_id() -> str:
    return secrets.token_hex(8)


class AuditLog:
    def __init__(self, audit_dir: Path) -> None:
        self._dir = audit_dir
        self._fd: int | None = None
        self._lock_fd: int | None = None
        self._date: str | None = None
        self._seq = 0

    # --- lifecycle ---

    def start(self) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self._dir, 0o700)
        self._lock_fd = os.open(self._dir / ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            # Another hub holds the single-writer lock — translate to a clear error.
            os.close(self._lock_fd)
            self._lock_fd = None
            raise RuntimeError(f"audit log is locked by another hub: {exc}") from exc
        self._open_for_today()

    def stop(self) -> None:
        if self._fd is not None:
            os.fsync(self._fd)
            os.close(self._fd)
            self._fd = None
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None

    # --- writers ---

    def write_received(
        self,
        *,
        request_id: str,
        trace_id: str,
        span_id: str,
        caller_id: str,
        caller_token_id: str | None,
        mcp_server: str,
        tool: str,
        args: dict[str, Any],
        authz_decision: str,
        authz_rule: str | None,
        audit_level: str,
        reason: str | None = None,
        decided_by: str | None = None,
    ) -> None:
        entry = {
            "phase": "received",
            "request_id": request_id,
            "trace_id": trace_id,
            "span_id": span_id,
            "ts": utcnow().isoformat(),
            "seq": self._next_seq(),
            "caller_id": caller_id,
            "caller_token_id": caller_token_id,
            "mcp_server": mcp_server,
            "tool": tool,
            "args": _capture(args, audit_level),
            "args_size_bytes": len(json.dumps(args, default=str)),
            "authz_decision": authz_decision,
            "authz_rule": authz_rule,
            "audit_level": audit_level,
        }
        if reason:
            entry["reason"] = reason
        if decided_by:
            entry["decided_by"] = decided_by
        self._write(entry)

    def write_completed(
        self,
        *,
        request_id: str,
        duration_ms: float,
        result: Any,
        result_status: str,
        audit_level: str,
        prompt_response_ms: float | None = None,
        upstream_request_id: str | None = None,
    ) -> None:
        result_json = json.dumps(result, default=str) if result is not None else ""
        entry = {
            "phase": "completed",
            "request_id": request_id,
            "ts": utcnow().isoformat(),
            "seq": self._next_seq(),
            "duration_ms": round(duration_ms, 3),
            "result": _capture(result, audit_level),
            "result_status": result_status,
            "result_size_bytes": len(result_json),
            "prompt_response_ms": prompt_response_ms,
            "upstream_request_id": upstream_request_id,
            "redactions_applied": audit_level == "standard",
        }
        self._write(entry)

    # --- internals ---

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _open_for_today(self) -> None:
        date = utcnow().date().isoformat()
        path = self._dir / f"{date}.jsonl"
        self._fd = os.open(path, os.O_APPEND | os.O_WRONLY | os.O_CREAT, 0o600)
        self._date = date

    def _write(self, entry: dict[str, Any]) -> None:
        line = (json.dumps(entry, default=str) + "\n").encode()
        if self._date != utcnow().date().isoformat():
            if self._fd is not None:
                os.fsync(self._fd)  # flush at the day boundary
                os.close(self._fd)
            self._open_for_today()
        try:
            os.write(self._fd, line)  # O_APPEND => atomic per write
        except OSError as exc:
            raise RuntimeError(f"audit_error: {exc}") from exc
