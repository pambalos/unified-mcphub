"""Windowed totals per principal, so a budget can be cumulative. UAI-147.

A per-action cap denies one oversized refund. It does not deny a thousand
refunds of $499, and every one of those is individually compliant — the gap the
OWASP pack has carried as a deliberately *passing* test since the pack was
written.

Closing it looks like it requires state on the decision path, which is exactly
what the <10 ms budget and the fail-closed story depend on not having. It does
not. See `docs/adr-0026-cumulative-counters.md`; the short version is that a
pure function can be handed a number:

    engine.decide(action, counters=totals)    # totals computed by the caller

So `PolicyEngine` still performs no I/O and holds nothing. This module is where
the number comes from, and it lives with the `Enforcer`, which already does I/O.

**Minute buckets, three windows.** One structure answers minute, hour and day:
a day is 1440 minute buckets, an hour is the last 60 of them, a minute is the
last one. Bounded per key regardless of traffic — a hot principal costs the same
1440 floats as a quiet one, which is what keeps a decision path allocation-free
under load.

**Restart is an attack, not just an inconvenience.** A total that lives only in
memory is a budget an agent resets by crashing its own sidecar, and an agent
that can spend the daily limit once per restart has no daily limit. So the
totals are rebuilt from the audit chain at start-up — signed, append-only, and
already recording every decision. Read once, at boot, off the decision path.

**Local, and honest about it.** These totals are what *this* sidecar saw. Ten
sidecars enforcing a $5,000 day will, worst case, permit $50,000 before the
control plane's fleet view catches up and contains the principal (UAI-165, on a
measured 30-second bound). That window is stated in the docs and in the ADR
rather than implied away — a customer who needs a hard fleet-wide cap needs to
know which number they are looking at.
"""

from __future__ import annotations

import logging
import math
import time
from collections import OrderedDict
from typing import Any

log = logging.getLogger("unified_enforce.counters")

#: Minute buckets in the longest window. A day, because that is the period every
#: real spend limit is written against.
DAY_BUCKETS = 1440

#: Window name to bucket count. `decide()` sees exactly these three, and adding
#: a fourth is a policy-language change rather than a storage change.
WINDOWS = {"minute": 1, "hour": 60, "day": DAY_BUCKETS}

#: How many (principal, counter) series to hold before evicting the least
#: recently used.
#:
#: Eviction resets a total, which is a fail-open, so the cap is set far above
#: what any real deployment reaches: a sidecar fronts a handful of agents and a
#: policy declares a handful of counters. Reaching it requires an agent minting
#: unbounded distinct principal ids, which is what attested identity (UAI-178)
#: stops it doing. An eviction is logged at error level because if one ever
#: happens, one of those two assumptions was wrong and somebody needs to know
#: which.
MAX_SERIES = 10_000


class _Series:
    """Minute buckets for one (principal, counter), oldest dropped on write."""

    __slots__ = ("_buckets",)

    def __init__(self) -> None:
        #: bucket index (epoch minutes) -> total. Ordered, so pruning is from
        #: the front and the common case touches one entry.
        self._buckets: OrderedDict[int, float] = OrderedDict()

    def add(self, minute: int, value: float) -> None:
        self._buckets[minute] = self._buckets.get(minute, 0.0) + value
        self._buckets.move_to_end(minute)
        self._prune(minute)

    def sum(self, minute: int, buckets: int) -> float:
        oldest = minute - buckets + 1
        return math.fsum(v for m, v in self._buckets.items() if m >= oldest)

    def _prune(self, minute: int) -> None:
        oldest = minute - DAY_BUCKETS + 1
        # Not a comprehension rebuilding the dict: pruning runs on the write
        # path, and the usual case removes nothing.
        while self._buckets:
            first = next(iter(self._buckets))
            if first >= oldest:
                break
            del self._buckets[first]

    def empty(self) -> bool:
        return not self._buckets


class Counters:
    """Windowed totals, keyed by principal and counter id.

    Not thread-safe by design, and that is worth being explicit about: the
    sidecar decides on one path, and adding a lock here would put contention on
    the hot path to protect against a concurrency model this component does not
    have. A deployment that grows one must own the store, not this class.
    """

    def __init__(self, *, max_series: int = MAX_SERIES) -> None:
        self._series: OrderedDict[tuple[str, str], _Series] = OrderedDict()
        self._max = max_series
        #: Counted, not just logged: a dashboard that shows this above zero is
        #: showing a fleet whose budgets are not what the policy says.
        self.evictions = 0

    @staticmethod
    def minute_of(now: float | None = None) -> int:
        return int((now if now is not None else time.time()) // 60)

    def add(
        self, principal: str, counter_id: str, value: float, *, now: float | None = None
    ) -> None:
        if value == 0.0:
            return
        key = (principal, counter_id)
        series = self._series.get(key)
        if series is None:
            series = _Series()
            self._series[key] = series
            self._evict_if_needed()
        self._series.move_to_end(key)
        series.add(self.minute_of(now), value)

    def snapshot(
        self, principal: str, counter_ids: list[str], *, now: float | None = None
    ) -> dict[str, dict[str, float]]:
        """Totals for every declared counter, including the ones at zero.

        A declared counter that resolved to *nothing* would make the CEL
        expression referencing it raise, which `decide()` turns into a deny —
        the safe direction, and a terrible one to debug. So every id a policy
        declares always resolves to a number.
        """
        minute = self.minute_of(now)
        out: dict[str, dict[str, float]] = {}
        for counter_id in counter_ids:
            series = self._series.get((principal, counter_id))
            out[counter_id] = {
                name: (series.sum(minute, buckets) if series is not None else 0.0)
                for name, buckets in WINDOWS.items()
            }
        return out

    def _evict_if_needed(self) -> None:
        while len(self._series) > self._max:
            key, _ = self._series.popitem(last=False)
            self.evictions += 1
            log.error(
                "counter series evicted for principal=%s counter=%s: over %d series. "
                "Its cumulative total is now zero, which permits spending a budget "
                "again. Either a policy declares far more counters than expected, or "
                "something is minting principal ids.",
                key[0],
                key[1],
                self._max,
            )

    # --- rebuilding after a restart ------------------------------------------

    def replay(self, entries: Any, *, now: float | None = None) -> int:
        """Re-apply the counter deltas recorded in audit entries.

        Reads the deltas the entry *recorded*, rather than recomputing them from
        the stored action. The stored action is shaped by the rule's audit
        level, so a policy that redacts `params` — which a payments policy
        plausibly does — would otherwise recover a budget of zero from a chain
        that faithfully recorded every spend. The number is written down at the
        time precisely so recovery does not have to depend on what redaction
        left behind.

        Entries older than the longest window are skipped rather than clamped
        into the current one, which would credit yesterday's spend to today.
        """
        from datetime import datetime

        floor = self.minute_of(now) - DAY_BUCKETS + 1
        applied = 0
        for entry in entries:
            payload = entry.get("payload") or {}
            deltas = payload.get("counters")
            if not deltas:
                continue
            action = payload.get("action") or {}
            principal = (action.get("principal") or {}).get("id")
            if not principal:
                continue
            try:
                stamped = datetime.fromisoformat(entry["ts"]).timestamp()
            except (KeyError, ValueError):
                continue
            minute = self.minute_of(stamped)
            if minute < floor:
                continue
            for counter_id, value in deltas.items():
                series = self._series.setdefault((principal, counter_id), _Series())
                series.add(minute, float(value))
                applied += 1
        self._evict_if_needed()
        return applied
