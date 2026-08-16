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
import logging
import os
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .action import Action
from .canonical import GENESIS_HASH, canonical_bytes, sha256_hex
from .policy import Decision


log = logging.getLogger("unified_enforce.audit")


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
        signer: Any = None,  # unified_enforce.Signer; signs each entry hash
    ) -> None:
        self._dir = Path(audit_dir)
        self._strict = strict
        self._signer = signer
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
        if self._signer is not None:
            # Sign the entry hash, which already covers the payload and the
            # whole preceding chain via prev_hash — so one signature per entry
            # authenticates everything before it, and a rewritten history needs
            # the key rather than just write access to the file.
            full["sig"] = self._signer.sign_bytes(entry_hash.encode("ascii"))
            full["key_id"] = self._signer.key_id
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
    def verify(cls, audit_dir: str | Path, *, public_key: bytes | None = None) -> VerifyResult:
        """Re-serialization of parsed JSON is deterministic without the strict
        type checks, so one verifier covers strict and lenient chains alike.

        Pass `public_key` to also check signatures. Without it, signed chains
        verify exactly as before — the hash chain alone is still meaningful,
        and an auditor who has not been given the key can still detect
        tampering *within* what they hold. What the key adds is proof of *who*
        wrote it, which is the part a hash chain cannot give you: an attacker
        with write access can rewrite an unsigned chain end to end and it will
        verify perfectly.
        """
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
                    signature = entry.pop("sig", None)
                    key_id = entry.pop("key_id", None)
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
                    if public_key is not None:
                        from .signing import verify_bytes

                        if signature is None:
                            return VerifyResult(False, count, f"{where}: entry is unsigned", anchor)
                        if not verify_bytes(public_key, signature, claimed.encode("ascii")):
                            return VerifyResult(
                                False, count, f"{where}: bad signature (key_id={key_id})", anchor
                            )
                    prev = claimed
                    count += 1
        return VerifyResult(True, count, None, anchor)

    # --- internals ---

    def _recover(self) -> None:
        """Pick up the chain head from the last entry that parses.

        Trailing garbage is skipped rather than raised on. `O_APPEND` makes each
        write atomic, but a machine losing power mid-write still leaves a
        partial final line -- and this used to raise, which meant an unclean
        shutdown turned into a sidecar that could not start. Refusing to run
        because the last line is half-written fails closed in the least useful
        possible way: the agent is not protected, it is stopped, and so is
        everything else it was doing.

        Skipping it is not a way to hide a tampered chain. `verify()` reads
        every line and reports the first unparseable one, so the damage stays
        visible to an auditor; what changes is that it no longer takes the
        service down before anyone can look. Logged at error level, because a
        line that failed to parse is either a crash or somebody editing the
        file, and both want attention.

        A parseable last entry with no `hash` is different: the directory
        predates the chain (logs written before the unified-enforce migration
        are flat JSONL with no `prev_hash`/`hash`). That history cannot anchor
        a chain, and leaving it in place would make `verify()` report it as
        tampering forever, so it is moved whole into `legacy/` — nothing is
        deleted — and the chain starts fresh from GENESIS.
        """
        files = sorted(self._dir.glob("*.jsonl"))
        if not files:
            return
        lines = [raw for raw in files[-1].read_bytes().splitlines() if raw.strip()]
        for offset, raw in enumerate(reversed(lines)):
            try:
                entry = json.loads(raw)
            except ValueError:
                continue
            if "hash" not in entry:
                self._quarantine_legacy(files)
                return
            if offset:
                log.error(
                    "%s: skipped %d unparseable trailing line(s) recovering the chain head. "
                    "Run `AuditChain.verify` -- this is a crash or an edit, and the "
                    "difference matters.",
                    files[-1].name,
                    offset,
                )
            self._head = entry["hash"]
            self._last_entry = entry
            return

    def _quarantine_legacy(self, files: list[Path]) -> None:
        legacy = self._dir / "legacy"
        legacy.mkdir(mode=0o700, exist_ok=True)
        for path in files:
            path.rename(legacy / path.name)
        log.error(
            "moved %d pre-chain audit file(s) to %s: they predate hash chaining "
            "and cannot anchor a chain. They are preserved verbatim but no longer "
            "tamper-checked; the chain restarts from GENESIS.",
            len(files),
            legacy,
        )

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
    def __init__(self, audit_dir: str | Path, *, signer: Any = None) -> None:
        """`signer` upgrades the chain from tamper-*evident* to
        tamper-evident-and-*attributable*.

        Without it the chain proves internal consistency, which an attacker who
        controls the writer defeats by rewriting the whole history — every hash
        recomputes and `verify()` is perfectly happy. With it, that rewrite also
        needs the private key. Still not a defence against a compromised *live*
        writer (it holds the key), which is what external anchoring is for.
        """
        self._dir = Path(audit_dir)
        self._writer = HashChainWriter(audit_dir, strict=True, signer=signer)
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

    def entries(self, *, days: int = 2) -> Iterator[dict[str, Any]]:
        """Read back what was written, newest files last. Off the hot path.

        Two days by default rather than one: the longest counter window is a
        day, and a day-long window at 00:05 spans two files. Reading only
        today's would silently halve a budget every midnight -- once a day,
        for five minutes, in a way that looks like the budget working.

        Malformed lines are skipped rather than raised on. This is used to
        recover state after a restart, and a chain with one truncated final
        line -- which is what an unclean shutdown produces -- must not stop a
        sidecar from starting.
        """
        files = sorted(self._dir.glob("*.jsonl"))[-days:]
        for path in files:
            try:
                with path.open(encoding="utf-8") as handle:
                    for line in handle:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            yield json.loads(line)
                        except ValueError:
                            continue
            except OSError:
                continue

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

    def append_decision(
        self,
        action: Action,
        decision: Decision,
        *,
        counters: dict[str, float] | None = None,
    ) -> dict[str, Any]:
        """The standard record: what was attempted, what was decided, and why.

        The digest always covers the full action; the stored copy is shaped by
        the rule's audit_level (see redaction.py).

        `counters` values are stored as **strings**, like every other number
        that crosses this boundary: canonical bytes refuse floats, because a
        float's serialisation is not portable and the digest has to be
        reproducible in another language. `Counters.replay` parses them back.

        `counters` is what this action added to each cumulative total (UAI-147),
        written down rather than left to be recomputed. Recomputing it would
        mean re-reading `params` from the *stored* action, which redaction may
        have removed -- so a payments policy that redacts amounts would rebuild
        a budget of zero from a chain that recorded every spend correctly. It is
        also the honest record: the entry says what this action cost.
        """
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
                # Omitted entirely when nothing was counted, so the common
                # entry does not grow a `"counters": {}` that every reader has
                # to learn to ignore.
                **({"counters": {k: repr(v) for k, v in counters.items()}} if counters else {}),
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
    def verify(cls, audit_dir: str | Path, *, public_key: bytes | None = None) -> VerifyResult:
        return HashChainWriter.verify(audit_dir, public_key=public_key)
