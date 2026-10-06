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

**Content travels only on its own stream, and only when asked for**
(payload-evidence.v1, `PayloadShipper`). A self-hosted control plane may want
the arguments and results too; those go to a different endpoint, in records
built from the chain entry that committed to them, signed, and only after the
control plane's receipt has said it accepts them. Decision records stay
metadata whatever that stream does.

**Loss is counted and reported, never silent.** A dashboard built on evidence
that quietly went missing is worse than one that admits a gap: the first is
believed. `dropped` is exposed for exactly that, and `chain_seq` travels with
every record so the receiver can see a hole rather than infer a quiet agent.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from . import detach as _detach
from .action import Action
from .attest import sign_evidence, sign_payload_evidence
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


class PermanentRejection(Exception):
    """The receiver will never accept this batch, however many times it is sent.

    Distinguished from an ordinary failure because the responses are opposite.
    A transient failure — connection refused, 5xx, a timeout — must requeue, or
    an outage becomes silent data loss. A permanent one must *not*: a batch the
    receiver refuses on its merits (malformed, a field it will not store) would
    otherwise be retried forever at the head of the queue, blocking every record
    behind it. One poison record would stop all evidence for the life of the
    process, and the spool would fill and start dropping while the cause sat at
    the front, unlogged.
    """


class PayloadTooLarge(PermanentRejection):
    """The receiver refused the batch for its size (HTTP 413).

    Permanent for *this* batch, not for its records: half as many may well
    fit. The shipper splits and resends rather than discarding the lot, and
    only a single record the receiver will not take on its own is dropped
    (and counted). A subclass, so a sink or handler that only knows
    `PermanentRejection` keeps its old meaning.
    """


class Sink(Protocol):
    """Where records go.

    Raises on failure; the shipper handles that. Raise `PermanentRejection` when
    retrying cannot help — see above for why that distinction is load-bearing.

    May return the receiver's receipt (a mapping) or nothing. The shipper hands
    a receipt to `on_receipt`; a sink that returns `None` is fine, which is what
    every sink written before receipts existed does.
    """

    def send(self, batch: list[dict[str, Any]]) -> Any: ...


@dataclass
class SpoolStats:
    queued: int = 0
    shipped: int = 0
    #: Batches the receiver refused on their merits. Counted separately from
    #: `dropped` because the causes differ: dropped means we were too slow or
    #: too full, rejected means we sent something it will not store, and only
    #: one of those is fixed by a bigger spool.
    rejected: int = 0
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
    #: An optional second bound, in whatever unit `weigh` returns. Decision
    #: records are a few hundred bytes each and a count bounds them well
    #: enough; payload records carry raw arguments and results, where ten
    #: thousand of them could be gigabytes. Unset, the spool behaves exactly
    #: as it always has.
    max_bytes: int | None = None
    weigh: Callable[[dict[str, Any]], int] | None = None
    _items: deque[dict[str, Any]] = field(default_factory=deque, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _bytes: int = field(default=0, init=False)
    stats: SpoolStats = field(default_factory=SpoolStats, init=False)

    def _weight(self, record: dict[str, Any]) -> int:
        return self.weigh(record) if self.weigh is not None else 0

    def _full(self, incoming: int) -> bool:
        if len(self._items) >= self.capacity:
            return True
        return self.max_bytes is not None and self._bytes + incoming > self.max_bytes

    def add(self, record: dict[str, Any]) -> bool:
        """Queue `record`, dropping the oldest to make room. False if it was refused.

        A single record heavier than `max_bytes` is refused outright and
        counted as dropped. Admitting it would first evict *everything* queued
        to make room and then hold more than the bound anyway -- one oversized
        value trading a whole spool for a breach of the limit it was meant to
        respect.
        """
        weight = self._weight(record)
        with self._lock:
            if self.max_bytes is not None and weight > self.max_bytes:
                self.stats.dropped += 1
                log.warning(
                    "evidence record of %d bytes exceeds the spool bound (%d); dropped",
                    weight,
                    self.max_bytes,
                )
                return False
            while self._items and self._full(weight):
                self._bytes -= self._weight(self._items.popleft())
                self.stats.dropped += 1
                if self.stats.dropped == 1 or self.stats.dropped % 1000 == 0:
                    log.warning(
                        "evidence spool full (capacity=%d); %d record(s) dropped",
                        self.capacity,
                        self.stats.dropped,
                    )
            self._items.append(record)
            self._bytes += weight
            self.stats.queued = len(self._items)
            return True

    def take(self, limit: int, *, max_bytes: int | None = None) -> list[dict[str, Any]]:
        """Up to `limit` records from the front, and no more than `max_bytes` of them.

        Always at least one record when any are queued, whatever it weighs: a
        byte cap that could return nothing would park a heavy record at the
        head of the queue for good. (The payload shipper screens a record too
        large to send before this matters.)
        """
        with self._lock:
            batch: list[dict[str, Any]] = []
            total = 0
            while self._items and len(batch) < limit:
                weight = self._weight(self._items[0])
                if batch and max_bytes is not None and total + weight > max_bytes:
                    break
                batch.append(self._items.popleft())
                total += weight
            self._bytes -= total
            self.stats.queued = len(self._items)
            return batch

    def discard(self, predicate: Callable[[dict[str, Any]], bool]) -> int:
        """Remove every queued record `predicate` selects. Returns how many.

        Not counted as `dropped`: the caller is discarding on purpose (a
        receiver that has stopped accepting what is queued) and counts it under
        its own name, so `dropped` keeps meaning "we were too full".
        """
        with self._lock:
            kept = deque(r for r in self._items if not predicate(r))
            removed = len(self._items) - len(kept)
            self._items = kept
            self._bytes = sum(self._weight(r) for r in kept)
            self.stats.queued = len(self._items)
            return removed

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
                weight = self._weight(record)
                if self._items and self._full(weight):
                    self.stats.dropped += 1
                    continue
                self._items.appendleft(record)
                self._bytes += weight
            self.stats.queued = len(self._items)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


def summarise(
    action: Action,
    decision: Decision,
    *,
    entry: dict[str, Any] | None = None,
    signer: Any = None,
    action_digest: str | None = None,
) -> dict[str, Any]:
    """The wire record: metadata only, by allowlist.

    Fields are named in rather than filtered out. A denylist would silently
    start shipping whatever gets added to `Action` next — and the field most
    likely to be added is another one carrying content.

    `entry` is the chain entry this decision produced, when there is one. Its
    `seq` and `hash` are what let a receiver notice a missing range instead of
    assuming an agent was idle.

    `signer` attests the record. Note what is signed: **this summary**, not the
    chain entry. The chain signs an entry hash covering content that
    deliberately never leaves the customer's environment, so a receiver holding
    a summary could verify that signature and still have no reason to believe
    the summary beside it describes that entry. Signing the summary means the
    receiver's stored copy is checkable by anyone with the reporter's public
    key — including against the receiver.

    `action_digest` is the digest the cited entry actually recorded, when the
    caller's chain computes it differently from the strict default. The hub
    records `action.digest(strict=False)`, because MCP arguments are free-form
    JSON and may hold floats -- and the strict digest *raises* on a float. So
    without this every hub call with a float argument lost its decision row
    (silently: `record()` swallows the error), and its payloads, attached to
    that digest, had no row to belong to. With it the row carries the same
    digest as the entry it points at, which is the only digest a reader can
    check it against. Unset, the strict digest, exactly as before: the engine
    chain records that one.
    """
    verdict = decision.verdict
    record = {
        "action_digest": action_digest if action_digest is not None else action.digest(),
        "principal_id": action.principal.id,
        "tool": action.tool,
        "verb": action.verb,
        "resource": action.resource,
        "verdict": verdict.value if hasattr(verdict, "value") else str(verdict),
        "rule_id": decision.rule_id,
        "source": decision.source,
        # Which policy decided. Outside EVIDENCE_FIELDS, so not covered by the
        # signature below: adding it to the signable form changes the bytes an
        # existing verifier expects, which wants a versioned payload rather than
        # a quiet edit. The signed copy is the chain entry this row points at.
        "policy_digest": getattr(decision, "policy_digest", None),
        "chain_seq": (entry or {}).get("seq"),
        "chain_hash": (entry or {}).get("hash"),
        # How the identity every rule keys on was established, and what spawned
        # it. Shipped because a receiver counting denies per principal is
        # counting something whose meaning depends on this -- "agent:crew-1 was
        # denied nine times" is a different fact when that name was a header a
        # gateway stamped than when it was proven.
        # The CHAIN's grade, not the leaf's. This field answers "how was the
        # identity every rule keys on established", and once delegation exists
        # the leaf's own grade is the wrong answer: an `attested` sidecar
        # acting behind an `assigned` hop is an `assigned` chain (build-01 §4).
        # Shipping the leaf value re-introduced, on the receiver side, exactly
        # the laundering the minimum-grade rule prevents on the decision side —
        # a receiver counting denials per principal scored an unproven chain as
        # proven.
        #
        # EVIDENCE_VERSION is deliberately NOT bumped: the signed field set and
        # the canonical bytes are unchanged, so producer and verifier cannot
        # drift over this. What changed is the value's truthfulness, and
        # consumers that *interpret* the field (the control plane's analytics)
        # need telling that it is now chain-aware.
        "attestation": action.principal.chain_grade(),
        "parent_id": action.principal.parent_id,
        "decided_at": action.ts,
    }
    return sign_evidence(record, signer) if signer is not None else record


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
        signer: Any = None,
        on_receipt: Any = None,
        payloads: PayloadShipper | None = None,
    ) -> None:
        #: The payload stream, when this reporter may ship arguments and
        #: results (payload-evidence.v1). A separate shipper with its own spool
        #: and thread, never a second field in this one's batches: the receiver
        #: validates the two kinds at different endpoints, a payload batch can
        #: be orders of magnitude larger, and nothing about one failing may
        #: hold up decisions. It lives here only because the *gate* does: the
        #: control plane says whether it accepts payloads in the receipt for
        #: decision evidence, and this is where that receipt arrives.
        self.payloads = payloads
        #: Called with each receipt the sink returns, on the shipping thread.
        #: The control plane's receipt carries `revocations_version`, and a
        #: sidecar that sees it move can refresh containment at once rather than
        #: at its next poll -- which is what lets a containment triggered by the
        #: batch just shipped land at that agent's *next* action. Public and
        #: settable so `Enforcer` can wire it without every deployment having to
        #: remember to. A failing callback never fails shipping.
        self.on_receipt = on_receipt
        #: The audit chain's signer, when this sidecar keeps a signed chain.
        #:
        #: Optional, and the gradient matters. A reporter without one is a
        #: weaker deployment, not a hostile one, and refusing its evidence
        #: would push people towards shipping none — but a receiver that has
        #: been told this reporter signs must refuse unsigned records from it,
        #: or an attacker holding a stolen credential simply stops signing.
        #: That downgrade is closed at the receiver, against the key registered
        #: at enrolment, rather than here.
        self._signer = signer
        self._sink = sink
        self._batch_size = batch_size
        self._interval = interval_seconds
        self.spool = EvidenceSpool(capacity=capacity)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def signer(self) -> Any:
        return self._signer

    @signer.setter
    def signer(self, value: Any) -> None:
        """Attach the signer after construction, before the first `record()`.

        Same reason as `HashChainWriter.signer`: a host may have to build the
        shipper before the store holding its key is unlocked. Records are
        signed when summarised, on the decision path, so whatever is set here
        when a decision is recorded is what signs it.
        """
        self._signer = value

    # --- the decision path's only entry point --------------------------------

    def submit(self, record: dict[str, Any]) -> bool:
        """Queue an already-shaped record. Cannot raise. True if it was queued.

        The generic form. `record()` builds a decision summary and calls this;
        shadow divergences arrive here directly, through a shipper of their own
        pointed at a different endpoint. Two shippers rather than one mixed
        spool: the receiver validates each kind separately, and a batch
        containing both shapes would be refused wholesale — one divergence
        would then block every decision behind it.
        """
        try:
            return self.spool.add(record)
        except Exception:
            log.exception("could not queue evidence; the decision is unaffected")
            return False

    def record(
        self,
        action: Action,
        decision: Decision,
        *,
        entry: dict[str, Any] | None = None,
        action_digest: str | None = None,
    ) -> bool:
        """Queue one decision. Cannot raise, by construction and by test.

        Wrapped because a bug in summarisation must not become a failed
        enforcement. The engine has already decided and already written its
        chain by the time this is called; nothing here is worth losing that
        over, and an exception escaping would turn a telemetry defect into an
        outage.

        Returns whether the row was queued. Payloads are offered only when it
        was: a payload hangs off its decision row, and one shipped for a row
        that never left is a value the console cannot place. `action_digest`:
        see `summarise`.
        """
        try:
            return self.submit(
                summarise(
                    action, decision, entry=entry, signer=self._signer, action_digest=action_digest
                )
            )
        except Exception:
            log.exception("could not summarise evidence; the decision is unaffected")
            return False

    def record_payload(
        self, entry: Mapping[str, Any], path: str, *, action_digest: str | None = None
    ) -> None:
        """Offer the value detached at `path` in a written chain entry. Cannot raise.

        Signed with this shipper's signer -- the key the receiver registered for
        this reporter's decision evidence, which is the one it will check the
        payload against. A no-op without a payload stream; whether anything is
        actually queued is `PayloadShipper.record_payload`'s decision.
        """
        if self.payloads is None:
            return
        try:
            self.payloads.record_payload(
                entry, path, signer=self._signer, action_digest=action_digest
            )
        except Exception:
            log.exception("could not queue payload evidence; the decision is unaffected")

    # --- shipping -------------------------------------------------------------

    #: A byte bound per batch, over the spool's weights. None for decision
    #: evidence, whose records are small enough that the count bounds them.
    _batch_bytes: int | None = None

    def flush(self) -> int:
        """Ship what is queued. Returns how many records were accepted."""
        shipped = 0
        while True:
            batch = self.spool.take(self._batch_size, max_bytes=self._batch_bytes)
            if not batch:
                return shipped
            # Screened per batch, not once per flush: a flush can run for many
            # batches, and what may be sent can change between them (the
            # payload gate closing on a receipt that arrived meanwhile).
            admitted = self._admit(batch)
            if admitted is None:
                return shipped
            if not admitted:
                continue
            sent, unsent = self._deliver(admitted)
            shipped += sent
            if unsent:
                # Put it back and stop. Retrying immediately against a
                # receiver that just failed would spin; the next tick is soon
                # enough for something nobody is waiting on.
                self.spool.put_back(unsent)
                return shipped

    def _admit(self, batch: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
        """What of a batch just taken may be sent. None: stop this flush.

        Decision evidence sends everything. The payload shipper re-reads its
        gate here (see `PayloadShipper._admit`). A hook returning None has put
        back whatever it wants kept; records it leaves out of a list it
        returns are its to count.
        """
        return batch

    def _deliver(self, batch: list[dict[str, Any]]) -> tuple[int, list[dict[str, Any]]]:
        """Send one batch. Returns (records accepted, records to requeue).

        A non-empty second element means a transient failure: the caller puts
        those back, in order, and stops.
        """
        try:
            receipt = self._sink.send(batch)
        except PayloadTooLarge as exc:
            if len(batch) == 1:
                self._too_large(batch[0], exc)
                return 0, []
            # Split and resend rather than discard: the receiver refused the
            # body's size, not these records, and half of it may well fit.
            # Recursion depth is log2 of the batch size.
            middle = len(batch) // 2
            first, unsent = self._deliver(batch[:middle])
            if unsent:
                return first, unsent + batch[middle:]
            # The first half's receipt may have changed what may be sent.
            rest = self._admit(batch[middle:])
            if not rest:
                return first, []
            second, unsent = self._deliver(rest)
            return first + second, unsent
        except PermanentRejection as exc:
            # Dropped deliberately, and loudly. Requeueing would park it at
            # the head of the queue forever and take every later record with
            # it.
            self.spool.stats.rejected += len(batch)
            log.error(
                "control plane permanently refused %d %s record(s); discarding them: %s",
                len(batch),
                self._stream,
                exc,
            )
            return 0, []
        except Exception as exc:
            self.spool.stats.failures += 1
            log.debug("%s send failed, %d record(s) requeued: %s", self._stream, len(batch), exc)
            return 0, batch
        self.spool.stats.shipped += len(batch)
        if self.payloads is not None:
            # Before `on_receipt`, and guarded on its own: a payload gate
            # that cannot read the receipt must not stop containment from
            # refreshing off it, and the reverse. Called even for a send that
            # returned no receipt, which the gate counts: a receiver that
            # never answers cannot leave payloads held forever.
            try:
                self.payloads.observe(receipt)
            except Exception:
                log.exception("payload gate could not read the evidence receipt")
        if receipt and self.on_receipt is not None:
            try:
                self.on_receipt(receipt)
            except Exception:
                # The receipt is a courtesy; the records are already
                # accepted. A refresh that blows up must not look like a
                # shipping failure, or the batch would be requeued and sent
                # twice.
                log.exception("evidence receipt handler raised")
        return len(batch), []

    def _too_large(self, record: dict[str, Any], exc: Exception) -> None:
        """A single record the receiver refused for size, even on its own."""
        self.spool.stats.rejected += 1
        log.error(
            "control plane refused a %s record as too large; discarding it: %s", self._stream, exc
        )

    #: The worker thread's name; the payload shipper sets its own so a stack
    #: dump says which stream is stuck.
    _thread_name = "unified-evidence"
    #: What this stream is called in logs, so an operator reading a shutdown
    #: warning knows which copy is still queued.
    _stream = "evidence"

    #: The least the payload stream gets to stop in, even when the decision
    #: stream used the whole shutdown budget. Joining with no time at all
    #: reported a worker that was merely waking from its sleep as "still
    #: shipping" -- a warning on every ordinary shutdown, which teaches people
    #: to ignore the one that matters.
    _PAYLOAD_STOP_FLOOR = 0.1

    def start(self) -> None:
        if self.payloads is not None:
            self.payloads.start()
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name=self._thread_name, daemon=True)
        self._thread.start()

    def stop(self, *, timeout: float = 5.0) -> None:
        """Stop this stream, then the payload stream with whatever budget is left.

        Decisions first: they are what the console's rows are made of, and a
        payload that arrives with no row to attach to is the less useful half.
        `timeout` stays the budget for the whole shutdown, both streams, plus
        at most `_PAYLOAD_STOP_FLOOR` for the payload stream to notice it has
        been stopped.
        """
        deadline = time.monotonic() + timeout
        self._stop_shipping(timeout=timeout)
        if self.payloads is not None:
            remaining = max(self._PAYLOAD_STOP_FLOOR, deadline - time.monotonic())
            self.payloads.stop(timeout=remaining)

    def _stop_shipping(self, *, timeout: float) -> None:
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
                "%s worker still shipping at shutdown; %d record(s) remain "
                "queued and are already in the audit chain.",
                self._stream,
                len(self.spool),
            )
            return

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return

        final = threading.Thread(
            target=self._flush_quietly, name=f"{self._thread_name}-final", daemon=True
        )
        final.start()
        final.join(timeout=remaining)
        if final.is_alive():
            log.warning(
                "final %s flush did not complete within the shutdown budget; "
                "%d record(s) remain queued and are already in the audit chain.",
                self._stream,
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


#: Where payload evidence goes, and the key its batch travels under
#: (payload-evidence.v1).
PAYLOADS_PATH = "/api/v1/evidence/payloads"
PAYLOADS_FIELD = "payloads"

#: Payload records held while the receiver is unavailable (or before it has
#: said whether it accepts any). Far fewer than decisions: each one carries an
#: argument or a result, not a summary.
DEFAULT_PAYLOAD_CAPACITY = 1_000

#: And a byte bound over the same spool, counted in `size_bytes`. The count
#: alone would let a run of large results hold a gigabyte in a sidecar's
#: memory; this keeps the worst case to a known figure whatever the receiver
#: says its per-value limit is.
DEFAULT_PAYLOAD_SPOOL_BYTES = 64 * 1024 * 1024

#: Records per payload request. Small, because each may be as large as the
#: receiver's `max_payload_bytes`.
DEFAULT_PAYLOAD_BATCH = 20

#: And bytes per payload request, summed over `size_bytes`. The count alone
#: lets twenty values at a generous `max_payload_bytes` make one enormous body
#: -- the request a proxy in front of the control plane is most likely to turn
#: away. A single value larger than this still goes, alone (`EvidenceSpool.take`).
DEFAULT_PAYLOAD_BATCH_BYTES = 8 * 1024 * 1024

#: The largest value held while no receipt has said what the receiver takes.
#: Until then there is no limit to apply, and holding a few huge results for
#: a control plane that may refuse them all is pure cost. Conservative on
#: purpose: a value over it is counted oversize, and the chain still has it.
DEFAULT_PENDING_MAX_BYTES = 1024 * 1024

#: Decision batches shipped with no receipt at all before the gate settles to
#: refuse. A sink that returns nothing (a receiver that answers 202 with an
#: empty body, or a custom sink written before receipts) would otherwise
#: leave values held for the life of the process, waiting on an answer that
#: is never coming.
PENDING_SILENT_RECEIPTS = 3

#: Hosts where plain http is acceptable for the payload stream: this machine.
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def payload_transport_ok(base_url: str | None) -> bool:
    """Whether arguments and results may be sent to `base_url` at all.

    https, or plain http to this machine only. Decision evidence is metadata
    and digests; this stream is the customer's actual content -- file paths,
    queries, whatever a tool returned -- and the request proof that protects
    the decision stream's integrity does nothing for its confidentiality.
    Loopback is excepted because a control plane on the same host (the
    self-hosted quickstart, a test) never puts it on a network.
    """
    from urllib.parse import urlsplit

    if not isinstance(base_url, str):
        return False
    try:
        parts = urlsplit(base_url.strip())
        host = (parts.hostname or "").lower()
    except ValueError:
        return False
    if parts.scheme == "https":
        return bool(host)
    return parts.scheme == "http" and host in _LOOPBACK_HOSTS


@dataclass
class PayloadStats:
    """Why values were not shipped, by cause. All counted, none silent.

    Each of these is a value the console will show as "held only in the
    customer's chain", and an operator asking why deserves a number per reason
    rather than a single total that mixes "the plane said no" with "this hub
    has no key".
    """

    #: The receiver had not accepted payloads (or had stopped): never queued,
    #: or discarded from the queue when it said so.
    declined: int = 0
    #: Larger than the receiver's `max_payload_bytes` (or, before any receipt,
    #: than `DEFAULT_PENDING_MAX_BYTES`), or refused for size on its own.
    oversize: int = 0
    #: No signer. The receiver refuses unsigned payloads, so sending one would
    #: put content on the wire to be thrown away.
    unsigned: int = 0
    #: The entry holds no value to send at that path: written with
    #: `record_payloads=False`, withheld, or never detached.
    unrecorded: int = 0
    #: Records the receiver refused individually (`refused` in its response).
    refused: int = 0


class PayloadShipper(EvidenceShipper):
    """Ships detached argument and result values (payload-evidence.v1).

    The same machinery as decision evidence -- bounded spool, background
    thread, requeue on failure, discard on permanent refusal -- because every
    reason behind that machinery applies here too. What is added is a **gate**,
    and the gate is the point of this class:

    - **Nothing is sent until the control plane has said it accepts.** The
      answer arrives in a receipt (`"payloads": "accept"`, plus
      `max_payload_bytes`), first on decision evidence and then on every
      payload response. Before any receipt, values are *held* in the spool --
      never sent, and none larger than `DEFAULT_PENDING_MAX_BYTES` -- so the
      calls a sidecar makes in the seconds after a restart are not lost to the
      race with its first decision batch. The first receipt settles it either
      way, and a refusal discards what was held.
    - **Any receipt that does not say `accept` means refuse**, and so, after
      `PENDING_SILENT_RECEIPTS` batches, does no receipt at all. A control
      plane that predates payloads says nothing about them; silence is not
      consent to receive somebody's tool arguments.
    - **The gate is re-read before every batch**, not once per flush: a
      refusal or a lower limit arriving mid-flush (on this stream's own
      responses, or on the decision thread's) stops what follows.
    - **A larger value than the receiver will take is not sent**, checked when
      offered and again when shipped, because the limit can move between the
      two.
    - **Unsigned or unrecorded values are never queued.** See `PayloadStats`.

    The local decision -- `control_plane.payloads: off` -- is made by not
    building one of these at all, so no code path exists that could send.

    A payload failure costs a payload and nothing else: this has its own spool
    and its own thread, and `EvidenceShipper.record_payload` swallows anything
    that escapes from here.
    """

    _thread_name = "unified-evidence-payloads"
    _stream = "payload evidence"

    def __init__(
        self,
        sink: Sink,
        *,
        capacity: int = DEFAULT_PAYLOAD_CAPACITY,
        max_spool_bytes: int = DEFAULT_PAYLOAD_SPOOL_BYTES,
        batch_size: int = DEFAULT_PAYLOAD_BATCH,
        batch_bytes: int = DEFAULT_PAYLOAD_BATCH_BYTES,
        pending_max_bytes: int = DEFAULT_PENDING_MAX_BYTES,
        interval_seconds: float = 5.0,
        signer: Any = None,
    ) -> None:
        super().__init__(
            sink,
            capacity=capacity,
            batch_size=batch_size,
            interval_seconds=interval_seconds,
            signer=signer,
            on_receipt=self._payload_receipt,
        )
        self.spool = EvidenceSpool(
            capacity=capacity,
            max_bytes=max_spool_bytes,
            weigh=lambda record: int(record.get("size_bytes") or 0),
        )
        self._batch_bytes = batch_bytes
        self.pending_max_bytes = pending_max_bytes
        self.payload_stats = PayloadStats()
        #: `mode` and `max_payload_bytes` are written by whichever thread got
        #: a receipt (decision or payload) and read on the caller's thread and
        #: this one. Changed and read together under this lock, so nobody sees
        #: "accept" beside the previous limit -- a refusal's 0, or a larger
        #: limit the receiver has just lowered.
        self._gate_lock = threading.Lock()
        #: None until a receipt has said anything; then "accept" or "refuse".
        self.mode: str | None = None
        #: The receiver's per-value limit, from the same receipt. Meaningless
        #: unless `mode` is "accept".
        self.max_payload_bytes: int = 0
        #: Decision batches shipped with no receipt while still pending.
        self._silent = 0

    @property
    def accepting(self) -> bool:
        return self.mode == "accept"

    # --- the gate --------------------------------------------------------------

    def _gate(self) -> tuple[str | None, int]:
        with self._gate_lock:
            return self.mode, self.max_payload_bytes

    def _set_gate(self, mode: str, limit: int) -> str | None:
        with self._gate_lock:
            before = self.mode
            # The limit first: an unlocked reader that checks `mode` and then
            # the limit must never pair "accept" with a stale one.
            self.max_payload_bytes = limit
            self.mode = mode
            return before

    def observe(self, receipt: Any) -> None:
        """Read the gate from a receipt. Any receipt settles it.

        The receipt is trusted for one thing only: whether to *withhold*
        content. A forged "refuse" costs copies; a forged "accept" sends a
        signed copy of what the reporter's own chain recorded to the control
        plane it is already authenticated to -- which is where the receipt
        came from. Neither can alter a decision or the chain.

        No receipt at all (None, or an empty body) is counted rather than
        read: one silent batch says nothing, but `PENDING_SILENT_RECEIPTS` of
        them while still pending means nobody is going to answer.
        """
        if not isinstance(receipt, Mapping) or not receipt:
            with self._gate_lock:
                if self.mode is not None:
                    return
                self._silent += 1
                if self._silent < PENDING_SILENT_RECEIPTS:
                    return
            log.warning(
                "control plane sent no receipt for %d evidence batch(es); assuming it does "
                "not accept payload evidence and discarding held values",
                PENDING_SILENT_RECEIPTS,
            )
            self._set_gate("refuse", 0)
            return
        limit = receipt.get("max_payload_bytes")
        usable = isinstance(limit, int) and not isinstance(limit, bool) and limit > 0
        if receipt.get("payloads") == "accept" and usable:
            assert isinstance(limit, int)
            if self._set_gate("accept", limit) != "accept":
                log.info("control plane accepts payload evidence (max %d bytes)", limit)
            return
        if receipt.get("payloads") == "accept":
            # Accepting with no limit we can apply is not something to guess
            # at: a value the receiver turns away for size has still crossed
            # the wire. Treated as a refusal, and said so.
            log.warning(
                "control plane accepts payloads but sent no usable max_payload_bytes (%r); "
                "not shipping payloads",
                limit,
            )
        if self._set_gate("refuse", 0) == "accept":
            log.info("control plane no longer accepts payload evidence")

    def _payload_receipt(self, receipt: Mapping[str, Any]) -> None:
        refused = receipt.get("refused") if isinstance(receipt, Mapping) else None
        if isinstance(refused, list) and refused:
            self.payload_stats.refused += len(refused)
            # Not retried: the receiver judged these records on their merits
            # (a digest that does not match, a signature it cannot check), and
            # it would judge them the same way again.
            log.warning(
                "control plane refused %d payload record(s): %s",
                len(refused),
                "; ".join(str(r.get("reason")) for r in refused[:3] if isinstance(r, Mapping)),
            )
        self.observe(receipt)

    # --- offering a value ------------------------------------------------------

    def record_payload(
        self,
        entry: Mapping[str, Any],
        path: str,
        *,
        signer: Any = None,
        action_digest: str | None = None,
    ) -> None:
        """Queue the value detached at `path` in a written chain entry. Cannot raise.

        Built from the entry *as written* -- its `seq`, `hash`, `detached[path]`
        and `salts[path]` -- rather than from the caller's copy of the value,
        so the record names exactly the bytes the signed chain committed to.
        A value that drifted between the call and the write would otherwise be
        shipped with a digest it does not match, and refused.

        `action_digest` defaults to the entry's own (a hub `received` entry
        carries it at the top level, an engine decision entry under
        `payload`); a hub `completed` entry has none, so the hub passes the
        received entry's.
        """
        try:
            self._record_payload(entry, path, signer=signer, action_digest=action_digest)
        except Exception:
            log.exception("could not queue payload evidence; nothing else is affected")

    def _record_payload(
        self,
        entry: Mapping[str, Any],
        path: str,
        *,
        signer: Any,
        action_digest: str | None,
    ) -> None:
        # Cheapest refusals first: this runs on the caller's thread, and a
        # control plane that does not want payloads should cost the hot path a
        # comparison, not a canonicalisation of the result.
        mode, limit = self._gate()
        if mode == "refuse":
            self.payload_stats.declined += 1
            return
        signer = signer if signer is not None else self.signer
        if signer is None:
            self.payload_stats.unsigned += 1
            return

        detached = entry.get(_detach.DETACHED) or {}
        salts = entry.get(_detach.SALTS) or {}
        unrecorded = entry.get(_detach.UNRECORDED) or ()
        found, value = _detach.get(dict(entry), path)
        # `unrecorded` is checked by name, not only by absence: with
        # record_payloads=False the salt is still kept locally (detach.py), so
        # "has a salt" is not "has a value", and the signed entry saying the
        # content was never stored is the authority.
        if (
            path in unrecorded
            or not found
            or not isinstance(detached.get(path), str)
            or not isinstance(salts.get(path), str)
        ):
            self.payload_stats.unrecorded += 1
            return

        digest = action_digest or entry.get("action_digest")
        if not digest and isinstance(entry.get("payload"), Mapping):
            digest = entry["payload"].get("action_digest")
        if not isinstance(digest, str) or not digest:
            # Without it the receiver cannot attach the value to an action,
            # and would refuse it. Counted with the values it cannot use.
            self.payload_stats.unrecorded += 1
            return

        body = _detach.canonical(value)
        size = len(body)
        # Before any receipt there is no receiver limit to apply, so a
        # conservative one of our own: see DEFAULT_PENDING_MAX_BYTES.
        cap = limit if mode == "accept" else self.pending_max_bytes
        if size > cap:
            self.payload_stats.oversize += 1
            return

        self.submit(
            sign_payload_evidence(
                {
                    "action_digest": digest,
                    "chain_seq": entry.get("seq"),
                    "chain_hash": entry.get("hash"),
                    "path": path,
                    "digest": detached[path],
                    "size_bytes": size,
                    "salt": salts[path],
                    # The exact bytes the digest was computed over, parsed
                    # back -- not the in-memory value. The chain's canonical
                    # form stringifies what JSON cannot carry (a date, a
                    # Decimal, bytes); shipping the original object instead
                    # made the sink's `json.dumps` raise, and a batch that
                    # cannot be serialised was requeued forever at the head
                    # of the stream. This is always JSON, and is what was
                    # hashed, so it is what the receiver will verify.
                    "value": json.loads(body),
                },
                signer,
            )
        )

    # --- shipping ----------------------------------------------------------------

    def flush(self) -> int:
        """Ship what is queued -- only if, and only what, the receiver accepts."""
        mode, _ = self._gate()
        if mode is None:
            return 0  # held: nothing has said yes or no yet
        if mode != "accept":
            self._decline_queued()
            return 0
        return super().flush()

    def _decline_queued(self, extra: int = 0) -> None:
        declined = self.spool.discard(lambda _record: True) + extra
        if declined:
            self.payload_stats.declined += declined
            log.info(
                "discarded %d held payload record(s): the control plane does not accept "
                "payloads (they remain in the audit chain)",
                declined,
            )

    def _admit(self, batch: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
        """Re-read the gate for this batch.

        A refusal that arrived since the last batch -- on a payload response
        just handled, or a decision receipt on the other thread -- discards
        this batch and everything still queued. A limit lowered meanwhile
        drops the values now over it.
        """
        mode, limit = self._gate()
        if mode is None:
            self.spool.put_back(batch)
            return None
        if mode != "accept":
            self._decline_queued(extra=len(batch))
            return None
        kept = [r for r in batch if int(r.get("size_bytes") or 0) <= limit]
        self.payload_stats.oversize += len(batch) - len(kept)
        return kept

    def _too_large(self, record: dict[str, Any], exc: Exception) -> None:
        self.payload_stats.oversize += 1
        log.warning("control plane refused a payload record as too large on its own: %s", exc)


class HttpSink:
    """Posts batches to a control plane's evidence endpoint.

    Standard library only, on purpose: the core package stays import-light for
    the in-process decision path, and this runs in every sidecar.

    **Always has a timeout.** It runs on the background thread, so a stuck
    socket cannot delay a decision — but it can stall shipping indefinitely,
    which turns a slow receiver into silent staleness. A bounded wait makes it a
    visible failure instead.
    """

    def __init__(
        self,
        base_url: str,
        credential: str,
        *,
        timeout_seconds: float = 10.0,
        path: str = "/api/v1/evidence",
        field: str = "decisions",
        channel: Any = None,
        ensure_ascii: bool = True,
    ) -> None:
        #: Binds each post to the key this sidecar registered, so a stolen
        #: bearer token cannot report evidence in its name. Optional: a
        #: deployment that has not enrolled a channel key still ships, and the
        #: receiver refuses the downgrade only for credentials that registered
        #: one.
        self._channel = channel
        self._path = path
        self._url = base_url.rstrip("/") + path
        self._credential = credential
        self._timeout = timeout_seconds
        #: The key the receiver expects. Divergences go to a different endpoint
        #: under a different name; everything else about shipping them is the
        #: same, which is why this is a parameter and not a second class.
        self._field = field
        #: False for the payload stream: values are mostly text, often not
        #: ASCII, and `\uXXXX` escaping can make a body up to six times the
        #: `size_bytes` the batch bound was computed from. Decision evidence
        #: keeps the default; its bytes are what existing receivers have seen.
        self._ensure_ascii = ensure_ascii

    def send(self, batch: list[dict[str, Any]]) -> dict[str, Any] | None:
        import json as _json
        import urllib.error
        import urllib.request

        try:
            body = _json.dumps({self._field: batch}, ensure_ascii=self._ensure_ascii).encode(
                "utf-8"
            )
        except (TypeError, ValueError) as exc:
            # A batch that cannot be serialised now cannot be later either.
            # Raised as a transient failure it was put back at the head of the
            # queue and retried forever, and nothing behind it ever shipped.
            raise PermanentRejection(f"batch is not serialisable as JSON: {exc}") from exc
        headers = {
            "content-type": "application/json",
            "authorization": f"Bearer {self._credential}",
        }
        if self._channel is not None:
            headers.update(self._channel.headers("POST", self._path, body))

        request = urllib.request.Request(self._url, data=body, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                if response.status >= 300:
                    raise RuntimeError(f"unexpected status {response.status}")
                raw = response.read()
        except urllib.error.HTTPError as exc:
            # 4xx means the receiver has judged the batch and will judge it the
            # same way next time — except 429, which is explicitly "try later".
            # 5xx is the receiver's problem and worth retrying. 413 is about
            # the body, not its records: the shipper splits and resends.
            if exc.code == 413:
                raise PayloadTooLarge(f"HTTP 413: {exc.reason}") from exc
            if 400 <= exc.code < 500 and exc.code != 429:
                raise PermanentRejection(f"HTTP {exc.code}: {exc.reason}") from exc
            raise

        # The receipt. Accepted is accepted whatever the body says: a receiver
        # that answered 202 with something unparseable has still taken the
        # records, so this returns None rather than raising and causing a
        # resend.
        try:
            receipt = _json.loads(raw) if raw else None
        except ValueError:
            return None
        return receipt if isinstance(receipt, dict) else None


def payload_shipper(
    base_url: str, credential: str, *, channel: Any = None, **kwargs: Any
) -> PayloadShipper:
    """A payload stream: the decisions sink, on the payloads path, gated.

    Hand the result to the decision shipper (`EvidenceShipper(...,
    payloads=...)`), whose receipts open the gate. Same credential and request
    proof as decision evidence, which is what the receiver checks.

    Refuses a `base_url` that is not https (loopback excepted; see
    `payload_transport_ok`). At construction, so the mistake surfaces when the
    sidecar is configured -- never on the decision path, and never by sending.
    """
    if not payload_transport_ok(base_url):
        raise ValueError(
            f"payload evidence needs an https control plane (or loopback), not {base_url!r}"
        )
    sink = HttpSink(
        base_url,
        credential,
        path=PAYLOADS_PATH,
        field=PAYLOADS_FIELD,
        channel=channel,
        ensure_ascii=False,
    )
    return PayloadShipper(sink, **kwargs)
