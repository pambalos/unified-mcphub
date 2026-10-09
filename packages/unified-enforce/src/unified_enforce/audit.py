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

**Content is recorded raw and detached** (detach.py). Both layers can name
content-bearing fields — the engine's `payload.action.params` and
`payload.action.context.extra`, the hub's `args` and `result` — which are then
committed to by a salted digest inside the hashed body while the value stays
inline. The chain therefore always holds exactly what was sent and returned,
and an export can still withhold it (`detach.redact`) without breaking a link
or a signature. Entries without detached fields hash exactly as they always
have, so chains written before this keep verifying unchanged.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
from collections.abc import Callable, Iterable, Iterator
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from . import detach as _detach
from .action import Action
from .canonical import GENESIS_HASH, _check, canonical_bytes, sha256_hex
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
    #: Detached values present and matching their digest (detach.py).
    payloads_verified: int = 0
    #: Detached values absent. A writer's own chain should report none: content
    #: is only withheld from exports. A local chain with withheld values has had
    #: content deleted — not altered, which would fail — and that is worth a look.
    payloads_withheld: int = 0
    #: Detached values the writer was configured not to store
    #: (`record_payloads=False`), as the signed entries themselves say.
    payloads_unrecorded: int = 0


class HashChainWriter:
    def __init__(
        self,
        audit_dir: str | Path,
        *,
        strict: bool = True,
        clock: Callable[[], datetime] | None = None,  # UTC now; injectable for rotation tests
        signer: Any = None,  # unified_enforce.Signer; signs each entry hash
        record_payloads: bool = True,
    ) -> None:
        """`record_payloads=False` is the explicit escape hatch for deployments
        that must not keep content at all: detached values are digested (with a
        salt kept locally) and then dropped, and each entry says so under
        `unrecorded`. The chain then proves *that* a call happened and *which*
        content it carried — a copy held elsewhere can be checked against it —
        but cannot by itself say what that content was. Logged loudly at start,
        because a deployment that turned this on by accident has quietly lost
        the ability to reconstruct what its agents did."""
        self._dir = Path(audit_dir)
        self._strict = strict
        self._signer = signer
        self._record_payloads = record_payloads
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
        if not self._record_payloads:
            log.warning(
                "%s: record_payloads is OFF — tool inputs and outputs are committed to by "
                "salted digest but NOT stored. This chain will prove that a call happened and "
                "which content it carried, but cannot show what that content was; an "
                "investigation will need a copy held elsewhere. (Hub: audit.record_payloads; "
                "engine: AuditChain(record_payloads=...).) To keep content out of an export "
                "instead, record it and build a digests-only evidence pack.",
                self._dir,
            )

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

    @property
    def signer(self) -> Any:
        return self._signer

    @signer.setter
    def signer(self, value: Any) -> None:
        """Attach (or replace) the signer after `start()`.

        For a host whose key is not available when the chain opens. The MCP hub
        takes the chain's lock first — so a second hub fails before it touches
        anything else — and only then unlocks the secrets store its signing key
        lives in. Constructing the writer late instead would move the
        single-writer check behind a keychain prompt.

        Only entries appended after this carry a signature. A chain that gains
        a key mid-life is therefore unsigned up to some seq and signed after
        it; `verify(signed_from_seq=...)` is how that shape is checked, and the
        host is responsible for recording where signing began.
        """
        self._signer = value

    @property
    def record_payloads(self) -> bool:
        return self._record_payloads

    # --- writing ---

    def append(self, entry: dict[str, Any], *, detach: Iterable[str] = ()) -> dict[str, Any]:
        """Chain and write one flat entry. `hash`/`prev_hash` are stamped here
        and must not be present on the way in.

        `detach` names the content-bearing fields (dotted paths) to commit to by
        salted digest rather than directly (see detach.py): recorded raw and
        inline, but removable from an export without breaking the chain.

        A strict chain checks the *whole* entry, detached values included,
        before anything is digested: detaching a value takes it out of the
        hashed bytes, and must not take it out of the engine's no-floats rule
        with it.
        """
        if self._fd is None:
            raise RuntimeError("HashChainWriter not started")
        if "hash" in entry or "prev_hash" in entry:
            raise ValueError("entry must not pre-set hash/prev_hash")
        if _detach.DETACHED in entry or _detach.SALTS in entry or _detach.UNRECORDED in entry:
            raise ValueError("entry must not pre-set detached/salts/unrecorded; pass detach=")
        body = {**entry, "prev_hash": self._head}
        if self._strict:
            _check(body, "$")
        if detach:
            body = _detach.detach(body, detach, record=self._record_payloads)
        entry_hash = sha256_hex(canonical_bytes(_detach.hashable_body(body), strict=False))
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
    def verify(
        cls,
        audit_dir: str | Path,
        *,
        public_key: bytes | None = None,
        signed_from_seq: int | None = None,
    ) -> VerifyResult:
        """Re-serialization of parsed JSON is deterministic without the strict
        type checks, so one verifier covers strict and lenient chains alike.

        Pass `public_key` to also check signatures. Without it, signed chains
        verify exactly as before — the hash chain alone is still meaningful,
        and an auditor who has not been given the key can still detect
        tampering *within* what they hold. What the key adds is proof of *who*
        wrote it, which is the part a hash chain cannot give you: an attacker
        with write access can rewrite an unsigned chain end to end and it will
        verify perfectly.

        `signed_from_seq` is for a chain that *started* unsigned and was given
        a key later — a hub that ran for months before joining a fleet. Entries
        with `seq` below it may be unsigned; from the first entry at or above
        it, every entry must carry a valid signature, **including any later
        entry whose `seq` claims to be lower** (the requirement latches, so
        renumbering a tail entry is not a way to shed its signature). And at
        least one entry at or above it must exist: a chain that recorded
        signing from seq N and now ends before N has had its signed tail
        removed, which is the one edit that would leave the unsigned prefix
        rewritable, so it is reported rather than passed.

        Why the unsigned prefix is still protected by the signatures after it:
        each signed entry's signature covers its `hash`, and that hash covers
        its `prev_hash` — the hash of the entry before, which covers *its*
        `prev_hash`, and so on back to the anchor. Rewriting any entry before N
        changes the hash the first signed entry must point at; making the link
        line up again means changing that entry's `prev_hash`, which changes its
        hash, which its signature no longer matches. So one valid signature at
        N attests the whole history up to N, exactly as `append` says of every
        signed entry — what the prefix lacks is only a per-entry signature, and
        it never needed one.

        Detached content (detach.py) is checked after the hash: the hash covers
        each value's digest, and `detach.check` recomputes the digest of every
        value present. A present value that does not match is tampering; an
        absent one is counted (`payloads_withheld`) rather than failed, because
        withholding content is what an export is allowed to do.
        """
        if signed_from_seq is not None and public_key is None:
            raise ValueError("signed_from_seq needs public_key: there is nothing to check from it")
        files = sorted(Path(audit_dir).glob("*.jsonl"))
        anchor: str | None = None
        prev: str | None = None
        count = 0
        verified = withheld = unrecorded = 0
        #: Whether signatures are required from here on. Latches True at the
        #: first entry at/after `signed_from_seq` (and from the start when no
        #: start point was given): see the docstring for why it never unlatches.
        must_sign = public_key is not None and signed_from_seq is None

        def _fail(where: str, what: str) -> VerifyResult:
            return VerifyResult(
                False, count, f"{where}: {what}", anchor, verified, withheld, unrecorded
            )

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
                    signature = entry.get("sig")
                    key_id = entry.get("key_id")
                    claimed = entry.get("hash")
                    if prev is None:
                        # First retained entry is the trust anchor (GENESIS unless
                        # retention pruning removed older day-files).
                        anchor = prev = entry.get("prev_hash")
                    if entry.get("prev_hash") != prev:
                        return _fail(where, "chain break (prev_hash)")
                    body = _detach.hashable_body(entry)
                    if sha256_hex(canonical_bytes(body, strict=False)) != claimed:
                        return _fail(where, "hash mismatch (tampered)")
                    checked = _detach.check(entry)
                    if not checked.ok:
                        return _fail(where, f"detached content: {checked.problem}")
                    verified += checked.present
                    withheld += checked.withheld
                    unrecorded += checked.unrecorded
                    if public_key is not None and not must_sign:
                        seq = entry.get("seq")
                        # An entry with no usable seq cannot be shown to sit
                        # before the start point, so it is held to the stricter
                        # rule rather than given the benefit of the doubt.
                        if not isinstance(seq, int) or seq >= cast(int, signed_from_seq):
                            must_sign = True
                    if must_sign:
                        from .signing import verify_bytes

                        assert public_key is not None
                        if signature is None:
                            return _fail(where, "entry is unsigned")
                        if not verify_bytes(public_key, signature, claimed.encode("ascii")):
                            return _fail(where, f"bad signature (key_id={key_id})")
                    prev = claimed
                    count += 1
        if signed_from_seq is not None and not must_sign:
            return VerifyResult(
                False,
                count,
                f"signing began at seq {signed_from_seq} but the chain holds no entry at or "
                "after it: the signed tail is missing, which would leave the unsigned "
                "history before it rewritable",
                anchor,
                verified,
                withheld,
                unrecorded,
            )
        return VerifyResult(True, count, None, anchor, verified, withheld, unrecorded)

    # --- internals ---

    def _recover(self) -> None:
        """Pick up the chain head from the last entry that parses, in whichever
        day file holds it (empty or wholly unparseable trailing files are
        passed over).

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
        # Newest file first, and on to older ones until an entry parses. The
        # newest file alone is not enough: a writer that starts and stops
        # without appending leaves today's file empty, and a restart that
        # read only that file resumed from GENESIS -- a chain break at the
        # next entry, `seq` restarting at 1 below where signing began, and
        # every checkpoint after it refused.
        # Per file, because the skipped lines may sit in newer files than the
        # one the head is finally recovered from -- and the log must point at
        # the damage, not at the file that was fine.
        skipped: dict[str, int] = {}

        def report_skipped() -> None:
            if skipped:
                log.error(
                    "skipped %d unparseable trailing line(s) recovering the chain head (%s). "
                    "Run `AuditChain.verify` -- this is a crash or an edit, and the "
                    "difference matters.",
                    sum(skipped.values()),
                    ", ".join(f"{name}: {n}" for name, n in skipped.items()),
                )

        for path in reversed(files):
            lines = [raw for raw in path.read_bytes().splitlines() if raw.strip()]
            for raw in reversed(lines):
                try:
                    entry = json.loads(raw)
                except ValueError:
                    skipped[path.name] = skipped.get(path.name, 0) + 1
                    continue
                if not isinstance(entry, dict) or "hash" not in entry:
                    self._quarantine_legacy(files)
                    return
                report_skipped()
                self._head = entry["hash"]
                self._last_entry = entry
                return
        report_skipped()

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


#: The content-bearing fields of an engine decision entry: what the agent asked
#: to do with, and the free-form context its integration attached. Everything
#: else in the entry (tool, verb, resource, principal, verdict, rule) is the
#: skeleton an auditor needs to read the log at all, and stays hashed directly.
DECISION_PAYLOADS = ("payload.action.params", "payload.action.context.extra")


class AuditChain:
    def __init__(
        self, audit_dir: str | Path, *, signer: Any = None, record_payloads: bool = True
    ) -> None:
        """`signer` upgrades the chain from tamper-*evident* to
        tamper-evident-and-*attributable*.

        Without it the chain proves internal consistency, which an attacker who
        controls the writer defeats by rewriting the whole history — every hash
        recomputes and `verify()` is perfectly happy. With it, that rewrite also
        needs the private key. Still not a defence against a compromised *live*
        writer (it holds the key), which is what external anchoring is for.

        `record_payloads=False` keeps a digest of each action's `params` and
        `context.extra` but not the values (see `HashChainWriter`). Off by
        default; nothing that only wants a smaller *export* should use it —
        that is what `detach.redact` and a digests-only evidence pack are for.
        """
        self._dir = Path(audit_dir)
        self._writer = HashChainWriter(
            audit_dir, strict=True, signer=signer, record_payloads=record_payloads
        )
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

    def append(
        self, kind: str, payload: dict[str, Any], *, detach: Iterable[str] = ()
    ) -> dict[str, Any]:
        """Append one chained entry. Returns the entry as written (with hash).

        `detach` paths are relative to the entry (`payload.action.params`)."""
        self._seq += 1
        try:
            return self._writer.append(
                {
                    "kind": kind,
                    "seq": self._seq,
                    "ts": datetime.now(UTC).isoformat(timespec="microseconds"),
                    "payload": payload,
                },
                detach=detach,
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

        The action is stored **raw**: its `params` and `context.extra` are
        detached (detach.py) — committed to by salted digest inside the hashed
        body, with the values inline beside them. The rule's `audit_level` is
        still recorded, but it no longer shapes what is written: it is the
        default *view* (what a reader shows) and the default *export* level.
        Shaping at write time made the record itself lossy — `minimal` kept no
        parameters at all, so neither an investigation nor a replay could ever
        see what the agent asked for — and gained nothing an export cannot do
        without touching the chain. `redacted` is therefore always false on new
        entries; it stays in the shape because entries written before this
        carry `true` where their stored copy was scrubbed, and replay reads it.

        `counters` values are stored as **strings**, like every other number
        that crosses this boundary: canonical bytes refuse floats, because a
        float's serialisation is not portable and the digest has to be
        reproducible in another language. `Counters.replay` parses them back.

        `counters` is what this action added to each cumulative total (UAI-147),
        written down rather than left to be recomputed. Recomputing it would
        mean re-reading `params` from the *stored* action, which may not be
        there -- withheld from an export, never recorded (`record_payloads`),
        or scrubbed by a pre-detach `minimal` rule -- so a payments policy
        would rebuild a budget of zero from a chain that recorded every spend
        correctly. It is also the honest record: the entry says what this
        action cost.
        """
        return self.append(
            "decision",
            {
                "action_digest": action.digest(),
                "action": action.model_dump(mode="json"),
                "verdict": decision.verdict.value,
                "rule_id": decision.rule_id,
                "source": decision.source,
                "audit_level": decision.audit_level,
                "redacted": False,
                "reason": decision.reason,
                "elapsed_us": int(decision.elapsed_ms * 1000),
                # Omitted for structural verdicts, which no policy made.
                **({"policy_digest": decision.policy_digest} if decision.policy_digest else {}),
                # Omitted entirely when nothing was counted, so the common
                # entry does not grow a `"counters": {}` that every reader has
                # to learn to ignore.
                **({"counters": {k: repr(v) for k, v in counters.items()}} if counters else {}),
                # Structured detail the reason string cannot carry — today the
                # offending hop of a chain that failed an attestation floor.
                # Written into the chain rather than left in-process, because a
                # `why` naming which link failed is worth nothing to an
                # investigator reading the log a week later. Omitted when
                # absent, like `counters`, so the common entry does not grow a
                # key every reader has to learn to ignore.
                **({"context": decision.context} if decision.context else {}),
            },
            detach=DECISION_PAYLOADS,
        )

    def append_approval(self, recorded: Any) -> dict[str, Any]:
        """Record how a deferred action was resolved (see approval.py).

        A separate entry rather than a rewrite of the DEFER: that review was
        demanded, and that a named human resolved it, are two events. An
        evidence log that collapses them cannot answer "who approved this?" —
        and the chain is append-only anyway, so the earlier entry stands.

        `action_digest` is the join back to the decision entry.

        Nothing here is detached. The one field that can echo the action's
        content is `scope` (an `*_always` persistence filter), and it is part
        of what the control plane signed: an export that withheld it could no
        longer have its approval signature checked, which is the point of
        exporting an approval at all.

        `attachments_digest` is omitted when None rather than written as null:
        an approval for a request without attachments then records exactly
        the entry it did before attachments existed, and a reader that has
        never heard of them sees nothing new.
        """
        payload = asdict(recorded)
        if payload.get("attachments_digest", "absent") is None:
            del payload["attachments_digest"]
        return self.append("approval", payload)

    # --- verification ---

    @classmethod
    def verify(
        cls,
        audit_dir: str | Path,
        *,
        public_key: bytes | None = None,
        signed_from_seq: int | None = None,
    ) -> VerifyResult:
        return HashChainWriter.verify(
            audit_dir, public_key=public_key, signed_from_seq=signed_from_seq
        )
