"""Two-phase append-only audit log — spec §6, ADR-0009; chained per E2.

The hub is integration #1 of the enforcement engine: since the unified-enforce
migration, the file mechanics (single-writer fcntl lock, O_APPEND daily JSONL,
0600/0700, fsync on rotation + shutdown) and the tamper-evident hash chain live
in `unified_enforce.audit.HashChainWriter`. This module keeps the hub's entry
shape and capture semantics exactly as before — flat `received`/`completed`
entries paired by request_id — which now additionally carry `prev_hash`/`hash`
(strict=False chaining: hub args/results are pre-existing free-form JSON).
`unified-mcphub audit verify` replays the chain offline.

Denied calls write `received` only. audit_level controls payload capture
(minimal/standard/detailed/full); secret-shape scrubbing at `standard` comes
from `unified_enforce.redaction` (same patterns the engine uses).

Writes come only from the single asyncio event-loop thread (sync, no await in
the write path), so no locking is needed.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

from unified_enforce.audit import HashChainWriter
from unified_enforce.redaction import scrub as _scrub

from .util import utcnow


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
        # utcnow resolved late so tests can monkeypatch this module's clock.
        self._writer = HashChainWriter(audit_dir, strict=False, clock=lambda: utcnow())
        self._seq = 0

    # The write-failure test injects errors by closing the raw fd directly.
    @property
    def _fd(self) -> int | None:
        return self._writer._fd

    @_fd.setter
    def _fd(self, value: int | None) -> None:
        self._writer._fd = value

    # --- lifecycle ---

    def start(self) -> None:
        try:
            self._writer.start()
        except RuntimeError as exc:
            raise RuntimeError(f"audit log is locked by another hub: {exc}") from exc
        last = self._writer.last_entry
        self._seq = int(last.get("seq", 0)) if last else 0

    def stop(self) -> None:
        self._writer.stop()

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
        action_digest: str | None = None,
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
        if action_digest:
            entry["action_digest"] = action_digest
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

    def write_interdicted(
        self,
        *,
        request_id: str,
        duration_ms: float,
        interdicted_by: str,
        reason: str,
        prompt_response_ms: float | None = None,
    ) -> None:
        """The third phase (build-04). Closes a bracket whose forward was
        cancelled while in flight because the principal became contained.

        Distinct from `completed` with an error on purpose: a reader must be
        able to tell "the upstream failed" from "the plane stopped this call"
        without parsing an error string — today an interrupted call and a
        crashed one look the same, and that ambiguity is what this removes.
        No result is recorded because none was accepted: whatever the upstream
        returned after cancellation was dropped, never audited, never returned.
        """
        self._write(
            {
                "phase": "interdicted",
                "request_id": request_id,
                "ts": utcnow().isoformat(),
                "seq": self._next_seq(),
                "duration_ms": round(duration_ms, 3),
                "result": None,
                "result_status": "interdicted",
                "interdicted_by": interdicted_by,
                "reason": reason,
                "prompt_response_ms": prompt_response_ms,
            }
        )

    # --- internals ---

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _write(self, entry: dict[str, Any]) -> None:
        try:
            self._writer.append(entry)
        except RuntimeError:
            raise
        except Exception as exc:  # canonicalization surprises must not kill the hub silently
            raise RuntimeError(f"audit_error: {exc}") from exc
