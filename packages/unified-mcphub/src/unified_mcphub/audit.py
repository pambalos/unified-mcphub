"""Two-phase append-only audit log — spec §6, ADR-0009; chained per E2.

The hub is integration #1 of the enforcement engine: since the unified-enforce
migration, the file mechanics (single-writer fcntl lock, O_APPEND daily JSONL,
0600/0700, fsync on rotation + shutdown) and the tamper-evident hash chain live
in `unified_enforce.audit.HashChainWriter`. This module keeps the hub's entry
shape and capture semantics exactly as before — flat `received`/`completed`
entries paired by request_id — which now additionally carry `prev_hash`/`hash`
(strict=False chaining: hub args/results are pre-existing free-form JSON).
`unified-mcphub audit verify` replays the chain offline.

Denied calls write `received` only.

**Arguments and results are recorded raw, whatever the rule's audit_level.**
`args` (received) and `result` (completed) are *detached*
(`unified_enforce.detach`): the entry hash covers a salted digest of each, and
the value sits inline beside it. So the chain always holds exactly what the
agent sent and what came back — the one thing an investigation cannot do
without — and an export can still withhold it (a digests-only evidence pack)
without breaking a link or a signature.

`audit_level` (minimal/standard/detailed/full) is still recorded on both
phases, but as the default *view*: `audit show/pair/tail/search` apply it when
they print (`audit_reader.view`; `--raw` to see the record as written).
Shaping at write time — `minimal` stored `null`, `standard` scrubbed
secret-shaped strings — made the record itself lossy, and could not be undone
for the one reader who needed the original. `completed` entries no longer carry
`redactions_applied`: it described that write-time scrub, which no longer
happens, and the display-time equivalent is a property of how an entry is
printed, not of the entry. (The workspace `redact:` filter, spec §10.2, is a
different thing and unchanged: it rewrites the result *before it reaches the
agent*, so the recorded result is still exactly what came back to the agent.)

`audit.record_payloads: false` is the loud escape hatch: digests and salts are
kept, values are not, and each entry says so under `unrecorded`.

Writes come only from the single asyncio event-loop thread (sync, no await in
the write path), so no locking is needed.

Signed when the hub has a signing key (signing.py): `set_signer` attaches it
after start — the lock is taken first, the secrets store unlocked after — and
the first entry it signs is reported once through `on_first_signed`, which is
how `signing.json` learns where signing began. The writers return the entry as
written, `hash` and `seq` included, because that is what a joined hub's
evidence record points at (`chain_seq`/`chain_hash`).
"""

from __future__ import annotations

import json
import logging
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Any

from unified_enforce.audit import HashChainWriter
from unified_enforce.redaction import scrub as _scrub

from .util import utcnow

logger = logging.getLogger(__name__)


#: The content-bearing fields of a hub entry, by phase. Everything else in an
#: entry (who, which tool, the decision, timings, sizes) is the skeleton an
#: auditor needs to read the log at all, and stays hashed directly.
RECEIVED_PAYLOADS = ("args",)
COMPLETED_PAYLOADS = ("result",)


def capture(payload: Any, audit_level: str) -> Any:
    """Apply an audit level to a payload for *display* (see module docstring)."""
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
    def __init__(self, audit_dir: Path, *, record_payloads: bool = True) -> None:
        # utcnow resolved late so tests can monkeypatch this module's clock.
        self._writer = HashChainWriter(
            audit_dir, strict=False, clock=lambda: utcnow(), record_payloads=record_payloads
        )
        self._seq = 0
        #: Called once with the seq of the first entry the current signer
        #: signs; cleared when it succeeds (retried on the next write if not).
        self._on_first_signed: Callable[[int], object] | None = None

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

    def set_signer(
        self, signer: Any, *, on_first_signed: Callable[[int], object] | None = None
    ) -> None:
        """Sign every entry written from now on (see module docstring).

        Called by the hub once its secrets store is unlocked, which is after
        `start()` and before the transport accepts a call — so in practice no
        entry of a run is unsigned when a key exists. `on_first_signed` is
        given the first signed entry's seq; a failure there is logged and
        retried on the next write, never raised into the call being audited,
        because a missing record degrades `audit verify` to hash-only for the
        range rather than making anything unverifiable.
        """
        self._writer.signer = signer
        self._on_first_signed = on_first_signed if signer is not None else None

    @property
    def signer(self) -> Any:
        return self._writer.signer

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
        policy_digest: str | None = None,
        approver: dict[str, Any] | None = None,
        attestation: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """`approver` and `attestation` are set when a console approver
        resolved a `prompt` (control_plane.approvals: console): who, as the
        control plane's signature attests it, and the signature itself. Kept
        here rather than only at the control plane because its approvals table
        is a queue and this chain is the evidence — it lives with the hub, it
        is hash-chained (and signed, when the hub signs), and the attestation
        in it can be re-verified against the fleet's key set by somebody who
        does not trust whoever operates the control plane. A terminal answer
        leaves both absent: nobody authenticated, and the entry should not
        imply otherwise with an empty object."""
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
            "args": args,
            "args_size_bytes": len(json.dumps(args, default=str)),
            "authz_decision": authz_decision,
            "authz_rule": authz_rule,
            "audit_level": audit_level,
        }
        if action_digest:
            entry["action_digest"] = action_digest
        if policy_digest:
            entry["policy_digest"] = policy_digest
        if reason:
            entry["reason"] = reason
        if decided_by:
            entry["decided_by"] = decided_by
        if approver:
            entry["approver"] = approver
        if attestation:
            entry["attestation"] = attestation
        return self._write(entry, detach=RECEIVED_PAYLOADS)

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
        injection: list[str] | None = None,
    ) -> dict[str, Any]:
        """`audit_level` is recorded (the received entry's, carried over) so
        the completed half can be shown at the same level without a join."""
        result_json = json.dumps(result, default=str) if result is not None else ""
        entry = {
            "phase": "completed",
            "request_id": request_id,
            "ts": utcnow().isoformat(),
            "seq": self._next_seq(),
            "duration_ms": round(duration_ms, 3),
            "result": result,
            "result_status": result_status,
            "result_size_bytes": len(result_json),
            "prompt_response_ms": prompt_response_ms,
            "upstream_request_id": upstream_request_id,
            "audit_level": audit_level,
        }
        if injection:
            # D-12: the shapes found in the result, by id. The reader sees
            # that this result carried instructions without re-reading them.
            entry["injection"] = list(injection)
        return self._write(entry, detach=COMPLETED_PAYLOADS)

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

    def _write(self, entry: dict[str, Any], *, detach: tuple[str, ...] = ()) -> dict[str, Any]:
        try:
            written = self._writer.append(entry, detach=detach)
        except RuntimeError:
            raise
        except Exception as exc:  # canonicalization surprises must not kill the hub silently
            raise RuntimeError(f"audit_error: {exc}") from exc
        if self._on_first_signed is not None and "sig" in written:
            try:
                self._on_first_signed(int(written["seq"]))
                self._on_first_signed = None
            except Exception:  # noqa: BLE001 - see set_signer
                logger.exception("audit: could not record where signing began; will retry")
        return written
