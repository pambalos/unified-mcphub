"""Hash-chained append-only audit log — spec §5 (specs/enforce/e1.v1.md).

Evolves the hub's two-phase JSONL writer (audit.py, ADR-0009) into a
tamper-evident chain:

- entry.hash = SHA-256 over the canonical bytes of the entry minus its `hash`
  field; entry.prev_hash links to the previous entry (GENESIS_HASH for the first)
- one chain across daily files: day N+1's first entry links to day N's last
- single writer (fcntl lock), O_APPEND, 0600 files; page-cache writes, fsync on
  rotation and shutdown — same durability posture as the hub
- `verify()` replays every file offline and reports the first break

Entries must be canonicalizable (no floats — see canonical.py); durations are
recorded as integer microseconds.
"""

from __future__ import annotations

import fcntl
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .action import Action
from .canonical import GENESIS_HASH, canonical_bytes, sha256_hex
from .policy import Decision


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    error: str | None = None  # "<file>:<line>: <what broke>"


class AuditChain:
    def __init__(self, audit_dir: str | Path) -> None:
        self._dir = Path(audit_dir)
        self._fd: int | None = None
        self._lock_fd: int | None = None
        self._date: str | None = None
        self._seq = 0
        self._head = GENESIS_HASH

    # --- lifecycle ---

    def start(self) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self._dir, 0o700)
        self._lock_fd = os.open(self._dir / ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(self._lock_fd)
            self._lock_fd = None
            raise RuntimeError(f"audit chain is locked by another writer: {exc}") from exc
        self._recover_head()
        self._open_for_today()

    def stop(self) -> None:
        if self._fd is not None:
            os.fsync(self._fd)
            os.close(self._fd)
            self._fd = None
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None

    @property
    def head(self) -> str:
        return self._head

    # --- writers ---

    def append(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Append one chained entry. Returns the entry as written (with hash)."""
        if self._fd is None:
            raise RuntimeError("AuditChain not started")
        self._seq += 1
        body: dict[str, Any] = {
            "kind": kind,
            "seq": self._seq,
            "ts": datetime.now(UTC).isoformat(timespec="microseconds"),
            "prev_hash": self._head,
            "payload": payload,
        }
        entry_hash = sha256_hex(canonical_bytes(body))
        entry = {**body, "hash": entry_hash}
        line = (json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self._rotate_if_needed()
        try:
            os.write(self._fd, line)  # O_APPEND => atomic per write
        except OSError as exc:
            raise RuntimeError(f"audit_error: {exc}") from exc
        self._head = entry_hash
        return entry

    def append_decision(self, action: Action, decision: Decision) -> dict[str, Any]:
        """The standard record: what was attempted, what was decided, and why.

        The digest always covers the full action; the stored copy is shaped by
        the rule's audit_level (see redaction.py)."""
        from .redaction import capture_action

        stored, redacted = capture_action(action.model_dump(mode="json"), decision.audit_level)
        return self.append(
            "decision",
            {
                "action_digest": action.digest(),
                "action": stored,
                "verdict": decision.verdict.value,
                "rule_id": decision.rule_id,
                "source": decision.source,
                "audit_level": decision.audit_level,
                "redacted": redacted,
                "reason": decision.reason,
                "elapsed_us": int(decision.elapsed_ms * 1000),
            },
        )

    # --- verification (offline, no lock needed) ---

    @classmethod
    def verify(cls, audit_dir: str | Path) -> VerifyResult:
        files = sorted(Path(audit_dir).glob("*.jsonl"))
        prev = GENESIS_HASH
        count = 0
        for path in files:
            with path.open("rb") as fh:
                for lineno, raw in enumerate(fh, start=1):
                    raw = raw.strip()
                    if not raw:
                        continue
                    where = f"{path.name}:{lineno}"
                    try:
                        entry = json.loads(raw)
                    except json.JSONDecodeError as exc:
                        return VerifyResult(False, count, f"{where}: unparseable: {exc}")
                    claimed = entry.pop("hash", None)
                    if entry.get("prev_hash") != prev:
                        return VerifyResult(False, count, f"{where}: chain break (prev_hash)")
                    if sha256_hex(canonical_bytes(entry)) != claimed:
                        return VerifyResult(False, count, f"{where}: hash mismatch (tampered)")
                    prev = claimed
                    count += 1
        return VerifyResult(True, count)

    # --- internals ---

    def _recover_head(self) -> None:
        """Resume the chain from the last entry on disk (crash-safe restart)."""
        files = sorted(self._dir.glob("*.jsonl"))
        if not files:
            return
        last_line: bytes | None = None
        with files[-1].open("rb") as fh:
            for raw in fh:
                if raw.strip():
                    last_line = raw
        if last_line is None:
            return
        entry = json.loads(last_line)
        self._head = entry["hash"]
        self._seq = entry["seq"]

    def _today(self) -> str:
        return datetime.now(UTC).date().isoformat()

    def _open_for_today(self) -> None:
        date = self._today()
        self._fd = os.open(
            self._dir / f"{date}.jsonl", os.O_APPEND | os.O_WRONLY | os.O_CREAT, 0o600
        )
        self._date = date

    def _rotate_if_needed(self) -> None:
        if self._date != self._today():
            if self._fd is not None:
                os.fsync(self._fd)
                os.close(self._fd)
            self._open_for_today()
