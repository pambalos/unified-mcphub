"""Hash-chained append-only audit log — spec §5 (specs/enforce/e1.v1.md).

Two layers:

- `HashChainWriter` — the reusable chaining primitive. Takes FLAT dict entries,
  stamps each with `prev_hash` + `hash` (SHA-256 over the canonical bytes of the
  entry minus `hash`), and appends them to daily JSONL files. Single writer
  (fcntl lock), O_APPEND, 0600 files; page-cache writes, fsync on rotation and
  shutdown. One chain spans daily files; restart resumes from the last entry on
  disk. Integrations with their own entry shape (the MCP hub's two-phase log)
  build on this layer directly with `strict=False` (see canonical.py).
- `AuditChain` — the engine's record format on top: `{kind, seq, ts, payload}`,
  strict canonical payloads (no floats; durations are integer microseconds).

`verify()` replays every file offline and reports the first break. It works on
anything a HashChainWriter wrote, whichever layer shaped the entries.
"""

from __future__ import annotations

import fcntl
import json
import os
from collections.abc import Callable
from dataclasses import asdict, dataclass
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
    anchor: str | None = None  # prev_hash of the first verified entry; GENESIS_HASH
    # unless retention pruning truncated the chain head. Head truncation is
    # indistinguishable from pruning by design — pin the anchor out-of-band
    # (control plane, C2 evidence) when that distinction matters.


class HashChainWriter:
    def __init__(
        self,
        audit_dir: str | Path,
        *,
        strict: bool = True,
        clock: Callable[[], datetime] | None = None,  # UTC now; injectable for rotation tests
    ) -> None:
        self._dir = Path(audit_dir)
        self._strict = strict
        self._clock = clock or (lambda: datetime.now(UTC))
        self._fd: int | None = None
        self._lock_fd: int | None = None
        self._date: str | None = None
        self._head = GENESIS_HASH
        self._last_entry: dict[str, Any] | None = None

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
        self._recover()
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

    @property
    def last_entry(self) -> dict[str, Any] | None:
        """The most recent entry on disk (recovered at start, tracked after)."""
        return self._last_entry

    # --- writing ---

    def append(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Chain and write one flat entry. `hash`/`prev_hash` are stamped here
        and must not be present on the way in."""
        if self._fd is None:
            raise RuntimeError("HashChainWriter not started")
        if "hash" in entry or "prev_hash" in entry:
            raise ValueError("entry must not pre-set hash/prev_hash")
        body = {**entry, "prev_hash": self._head}
        entry_hash = sha256_hex(canonical_bytes(body, strict=self._strict))
        full = {**body, "hash": entry_hash}
        line = (
            json.dumps(full, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
            + "\n"
        ).encode("utf-8")
        self._rotate_if_needed()
        try:
            os.write(self._fd, line)  # O_APPEND => atomic per write
        except OSError as exc:
            raise RuntimeError(f"audit_error: {exc}") from exc
        self._head = entry_hash
        self._last_entry = full
        return full

    # --- verification (offline, no lock needed) ---

    @classmethod
    def verify(cls, audit_dir: str | Path) -> VerifyResult:
        """Re-serialization of parsed JSON is deterministic without the strict
        type checks, so one verifier covers strict and lenient chains alike."""
        files = sorted(Path(audit_dir).glob("*.jsonl"))
        anchor: str | None = None
        prev: str | None = None
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
                        return VerifyResult(False, count, f"{where}: unparseable: {exc}", anchor)
                    claimed = entry.pop("hash", None)
                    if prev is None:
                        # First retained entry is the trust anchor (GENESIS unless
                        # retention pruning removed older day-files).
                        anchor = prev = entry.get("prev_hash")
                    if entry.get("prev_hash") != prev:
                        return VerifyResult(
                            False, count, f"{where}: chain break (prev_hash)", anchor
                        )
                    if sha256_hex(canonical_bytes(entry, strict=False)) != claimed:
                        return VerifyResult(
                            False, count, f"{where}: hash mismatch (tampered)", anchor
                        )
                    prev = claimed
                    count += 1
        return VerifyResult(True, count, None, anchor)

    # --- internals ---

    def _recover(self) -> None:
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
        self._last_entry = entry

    def _today(self) -> str:
        return self._clock().date().isoformat()

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


class AuditChain:
    def __init__(self, audit_dir: str | Path) -> None:
        self._dir = Path(audit_dir)
        self._writer = HashChainWriter(audit_dir, strict=True)
        self._seq = 0

    # --- lifecycle ---

    def start(self) -> None:
        self._writer.start()
        last = self._writer.last_entry
        self._seq = int(last.get("seq", 0)) if last else 0

    def stop(self) -> None:
        self._writer.stop()

    @property
    def head(self) -> str:
        return self._writer.head

    # --- writers ---

    def append(self, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Append one chained entry. Returns the entry as written (with hash)."""
        self._seq += 1
        try:
            return self._writer.append(
                {
                    "kind": kind,
                    "seq": self._seq,
                    "ts": datetime.now(UTC).isoformat(timespec="microseconds"),
                    "payload": payload,
                }
            )
        except Exception:
            self._seq -= 1  # nothing was written; keep seq contiguous
            raise

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

    def append_approval(self, recorded: Any) -> dict[str, Any]:
        """Record how a deferred action was resolved (see approval.py).

        A separate entry rather than a rewrite of the DEFER: that review was
        demanded, and that a named human resolved it, are two events. An
        evidence log that collapses them cannot answer "who approved this?" —
        and the chain is append-only anyway, so the earlier entry stands.

        `action_digest` is the join back to the decision entry.
        """
        return self.append("approval", asdict(recorded))

    # --- verification ---

    @classmethod
    def verify(cls, audit_dir: str | Path) -> VerifyResult:
        return HashChainWriter.verify(audit_dir)
