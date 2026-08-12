"""Shipping decision metadata to a control plane, without ever mattering.

**This is not in the decision path and must never become so.** The engine
decides, writes its chain, and hands a summary to this module as a side effect.
If the control plane is slow, unreachable, hostile or absent, the agent's
verdict is unchanged and the evidence is already durable — it is in the chain,
which is the actual record. This module only makes a *copy* queryable somewhere
else.

That single property dictates everything else here:

- `record()` never raises, never blocks, and never waits on a network. It puts
  a small dict on a bounded queue and returns.
- The queue is bounded, so a control plane that stops accepting cannot grow a
  sidecar's memory until something else dies.
- Shipping happens on a background thread. Failures are retried; nothing is
  dropped because a send failed.

**What is shipped is metadata, and that is enforced here rather than trusted to
the receiver.** The control plane rejects `params` (it should), but a sidecar
that sends content and is refused has still put it on a wire and possibly in a
log at the far end. The payload is built by naming the fields to include, not
by removing the ones to exclude — an allowlist survives a new field being added
to `Action`; a denylist does not.

**Loss is counted and reported, never silent.** A dashboard built on evidence
that quietly went missing is worse than one that admits a gap: the first is
believed. `dropped` is exposed for exactly that, and `chain_seq` travels with
every record so the receiver can see a hole rather than infer a quiet agent.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol

from .action import Action
from .policy import Decision

log = logging.getLogger("unified_enforce.evidence")

#: How many records to hold when the receiver is unavailable. At a few hundred
#: bytes each this is single-digit megabytes — small enough that a sidecar
#: cannot be starved by an outage it did not cause, large enough to ride out
#: the kind of interruption that happens during a deploy.
DEFAULT_CAPACITY = 10_000

#: Records per request. Bounded so one flush after a long outage does not
#: arrive as a single enormous body.
DEFAULT_BATCH = 200


class Sink(Protocol):
    """Where records go. Raises on failure; the shipper handles that."""

    def send(self, batch: list[dict[str, Any]]) -> None: ...


@dataclass
class SpoolStats:
    queued: int = 0
    shipped: int = 0
    #: Records discarded because the spool was full. Surfaced, never silent —
    #: this number is the difference between a dashboard with a known gap and a
    #: dashboard that is quietly wrong.
    dropped: int = 0
    failures: int = 0


@dataclass
class EvidenceSpool:
    """A bounded, thread-safe queue of pending records.

    **Drops the oldest.** Two defensible policies exist and the choice matters:
    dropping the newest preserves an unbroken run from a known point, dropping
    the oldest keeps the most recent picture. Oldest wins here because during an
    outage the recent decisions are the ones an operator is about to ask about,
    and because `chain_seq` makes the resulting hole visible — the receiver can
    see records 400–900 are missing rather than guessing whether the agent went
    quiet. A gap you can see is survivable; a plausible-looking recent history
    that is silently truncated is not.
    """

    capacity: int = DEFAULT_CAPACITY
    _items: deque[dict[str, Any]] = field(default_factory=deque, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    stats: SpoolStats = field(default_factory=SpoolStats, init=False)

    def add(self, record: dict[str, Any]) -> None:
        with self._lock:
            if len(self._items) >= self.capacity:
                self._items.popleft()
                self.stats.dropped += 1
                if self.stats.dropped == 1 or self.stats.dropped % 1000 == 0:
                    log.warning(
                        "evidence spool full (capacity=%d); %d record(s) dropped",
                        self.capacity,
                        self.stats.dropped,
                    )
            self._items.append(record)
            self.stats.queued = len(self._items)

    def take(self, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            batch = [self._items.popleft() for _ in range(min(limit, len(self._items)))]
            self.stats.queued = len(self._items)
            return batch

    def put_back(self, batch: Iterable[dict[str, Any]]) -> None:
        """Return an unshipped batch to the front of the queue.

        A send that failed must not lose its records — that would make an
        unreachable control plane indistinguishable from a quiet agent, which
        is the confusion this whole module is built to avoid. If the spool has
        filled meanwhile, the usual drop-oldest rule applies to the combined
        queue rather than preferring either.
        """
        with self._lock:
            for record in reversed(list(batch)):
                if len(self._items) >= self.capacity:
                    self.stats.dropped += 1
                    continue
                self._items.appendleft(record)
            self.stats.queued = len(self._items)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


def summarise(
    action: Action,
    decision: Decision,
    *,
    entry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The wire record: metadata only, by allowlist.

    Fields are named in rather than filtered out. A denylist would silently
    start shipping whatever gets added to `Action` next — and the field most
    likely to be added is another one carrying content.

    `entry` is the chain entry this decision produced, when there is one. Its
    `seq` and `hash` are what let a receiver notice a missing range instead of
    assuming an agent was idle.
    """
    verdict = decision.verdict
    return {
        "action_digest": action.digest(),
        "principal_id": action.principal.id,
        "tool": action.tool,
        "verb": action.verb,
        "resource": action.resource,
        "verdict": verdict.value if hasattr(verdict, "value") else str(verdict),
        "rule_id": decision.rule_id,
        "source": decision.source,
        "chain_seq": (entry or {}).get("seq"),
        "chain_hash": (entry or {}).get("hash"),
        "decided_at": action.ts,
    }


class EvidenceShipper:
    """Collects records and ships them in the background.

    The host owns the lifecycle: `start()` for a long-running sidecar,
    `flush()` where the caller would rather ship synchronously (tests, and
    short-lived processes that would otherwise exit with a full spool).
    """

    def __init__(
        self,
        sink: Sink,
        *,
        capacity: int = DEFAULT_CAPACITY,
        batch_size: int = DEFAULT_BATCH,
        interval_seconds: float = 5.0,
    ) -> None:
        self._sink = sink
        self._batch_size = batch_size
        self._interval = interval_seconds
        self.spool = EvidenceSpool(capacity=capacity)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # --- the decision path's only entry point --------------------------------

    def record(
        self, action: Action, decision: Decision, *, entry: dict[str, Any] | None = None
    ) -> None:
        """Queue one decision. Cannot raise, by construction and by test.

        Wrapped because a bug in summarisation must not become a failed
        enforcement. The engine has already decided and already written its
        chain by the time this is called; nothing here is worth losing that
        over, and an exception escaping would turn a telemetry defect into an
        outage.
        """
        try:
            self.spool.add(summarise(action, decision, entry=entry))
        except Exception:
            log.exception("could not queue evidence; the decision is unaffected")

    # --- shipping -------------------------------------------------------------

    def flush(self) -> int:
        """Ship what is queued. Returns how many records were accepted."""
        shipped = 0
        while True:
            batch = self.spool.take(self._batch_size)
            if not batch:
                return shipped
            try:
                self._sink.send(batch)
            except Exception as exc:
                # Put it back and stop. Retrying immediately against a
                # receiver that just failed would spin; the next tick is soon
                # enough for something nobody is waiting on.
                self.spool.put_back(batch)
                self.spool.stats.failures += 1
                log.debug("evidence send failed, %d record(s) requeued: %s", len(batch), exc)
                return shipped
            shipped += len(batch)
            self.spool.stats.shipped += len(batch)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="unified-evidence", daemon=True)
        self._thread.start()

    def stop(self, *, timeout: float = 5.0) -> None:
        """Stop shipping, with one last attempt only when it is safe to make.

        A shutdown that hangs waiting on an unreachable control plane is a
        worse failure than losing the tail of a spool — and the tail is in the
        chain regardless, so nothing is actually lost.

        `timeout` is the whole budget, not just the thread join. An earlier
        version bounded only the join, and a second attempt bounded only the
        case where the worker was stuck mid-send — both missed the ordinary
        one, where the worker exits cleanly and the *final* flush then blocks on
        the same unreachable sink.

        So the final flush runs on its own daemon thread and is abandoned if it
        outlives the budget. Abandoning it is safe: the records are already in
        the audit chain, which is the record — this only ships a copy.

        A caller that never started a worker is managing `flush()` itself and
        can bound it as it likes.
        """
        deadline = time.monotonic() + timeout
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is None:
            return

        thread.join(timeout=timeout)
        if thread.is_alive():
            log.warning(
                "evidence worker still shipping at shutdown; %d record(s) remain "
                "queued and are already in the audit chain.",
                len(self.spool),
            )
            return

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return

        final = threading.Thread(
            target=self._flush_quietly, name="unified-evidence-final", daemon=True
        )
        final.start()
        final.join(timeout=remaining)
        if final.is_alive():
            log.warning(
                "final evidence flush did not complete within the shutdown budget; "
                "%d record(s) remain queued and are already in the audit chain.",
                len(self.spool),
            )

    def _flush_quietly(self) -> None:
        try:
            self.flush()
        except Exception:
            log.debug("final evidence flush failed", exc_info=True)

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self.flush()
            except Exception:
                # A flush that raises must not kill the thread, or evidence
                # stops for the life of the process and nothing says so.
                log.exception("evidence flush raised")
