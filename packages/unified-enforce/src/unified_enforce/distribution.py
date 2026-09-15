"""Fetching, verifying and applying signed policy — the sidecar's side.

`attest.py` decides whether an artifact is trustworthy. This decides what to do
about the answer, which is a separate question and the one with the sharper
edges: almost every wrong behaviour here is a *fail-open*, and the tempting
default is usually the wrong one.

The rule everything below follows:

    a distribution failure may cost freshness; it may never grant permission.

Concretely (spec §5):

| situation                    | behaviour                                     |
|------------------------------|-----------------------------------------------|
| cannot reach the source      | keep the last verified bundle, no alarm       |
| signature does not verify    | keep the last, alarm                          |
| bundle for another fleet     | reject, alarm                                 |
| version older than current   | reject, alarm — this is an attack             |
| a file's hash does not match | reject the *whole* bundle                     |
| bundle expired               | keep enforcing, alarm; `on_stale` may escalate|
| **no valid bundle at all**   | **deny everything**                           |
| revocation list expired      | escalate; never assume nobody is contained    |

Three of those are worth saying out loud because the opposite is what someone
reaches for under pressure.

**"Cannot reach the source" is not an alarm.** Brief unreachability is normal.
Alerting on it trains an operator to ignore the alert that matters, and expiry
is already the signal that something is actually wrong.

**A fresh sidecar with no policy denies.** This is the one place a permissive
default is tempting, because denying at startup looks like an outage. It would
mean an attacker who can block a single fetch gets an unprotected agent. If a
customer cannot tolerate that, the answer is a bundle baked into the deployment
image, not a permissive default.

**Stale policy keeps enforcing; a stale revocation list escalates.** The
asymmetry is deliberate. Old rules are still rules. But a revocation list we
cannot verify means we do not know whether an agent has been contained, and
assuming it has not is precisely the fail-open a kill switch exists to prevent.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from .action import Action
from .attest import (
    BundleState,
    Reason,
    VerificationKey,
    accept_manifest,
    accept_revocations,
    load_key_set,
    unb64u,
    verify_files,
)
from .policy import Decision, Verdict

log = logging.getLogger("unified_enforce.distribution")


class Health(StrEnum):
    """What the sidecar can currently prove about its policy."""

    #: Verified and inside its expiry.
    FRESH = "fresh"
    #: Verified once, now past expiry. Still enforced; loudly stale.
    STALE = "stale"
    #: Nothing has ever verified. Everything is denied.
    UNPROVISIONED = "unprovisioned"


class StaleAction(StrEnum):
    """What to do when policy is past its expiry. Spec §5.1.

    The same axis as containment modes, deliberately — an operator should not
    have to learn two vocabularies for "what happens when we are unsure".
    """

    #: Carry on with the stale rules. The default: a network partition should
    #: not take down a customer's agents.
    KEEP = "keep"
    #: Send everything to a human. High-assurance, and needs the approval queue
    #: to be able to absorb the volume.
    DEFER = "defer"
    #: Refuse everything. Available, never the default.
    DENY = "deny"


@dataclass(frozen=True)
class Containment:
    """An agent the control plane has told us to contain."""

    principal_id: str
    #: `defer`, `deny`, or `deny_except`.
    mode: str
    allow: tuple[str, ...] = ()


@dataclass
class Snapshot:
    """Everything a decision needs to know about distribution state."""

    health: Health = Health.UNPROVISIONED
    version: int | None = None
    expires_at_ms: int | None = None
    files: dict[str, bytes] = field(default_factory=dict)

    #: Containment, keyed by principal.
    containment: dict[str, Containment] = field(default_factory=dict)
    #: Separate from `health`: a revocation list can be stale while policy is
    #: fresh, and the two failures call for opposite responses.
    revocations_health: Health = Health.UNPROVISIONED
    revocations_version: int | None = None

    #: A candidate bundle to evaluate, never to enforce (spec §8). Held in
    #: entirely separate fields from the enforcing bundle rather than as a flag
    #: on it, because the one thing that must never happen is a candidate being
    #: mistaken for policy — and a boolean beside the files is one wrong
    #: condition away from exactly that.
    shadow_version: int | None = None
    shadow_files: dict[str, bytes] = field(default_factory=dict)

    def is_usable(self) -> bool:
        return self.health in (Health.FRESH, Health.STALE)


class Source(Protocol):
    """Where artifacts come from.

    A protocol rather than an HTTP client, because a verified artifact does not
    care how it arrived. The same bytes verify identically whether they came
    from the control plane, an object store, a mounted ConfigMap, or a file
    carried into an air-gapped facility — which is why air gap is the same
    guarantee here rather than a documented exception.

    Every method may raise; unreachability is expected and handled.
    """

    def fetch_keyset(self) -> Any: ...
    def fetch_bundle(self) -> Any: ...
    def fetch_revocations(self) -> Any: ...


class DirectorySource:
    """Artifacts from a directory — air-gapped transfer, or a mounted volume."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)

    def _read(self, name: str) -> Any:
        return json.loads((self._root / name).read_text())

    def fetch_keyset(self) -> Any:
        return self._read("keyset.json")

    def fetch_bundle(self) -> Any:
        return self._read("bundle.json")

    def fetch_revocations(self) -> Any:
        return self._read("revocations.json")


class ControlPlaneSource:
    """The three artifacts, over HTTP, from a control plane.

    The counterpart to `DirectorySource`, and the reason containment has a
    number attached to it at all: until something fetched on a schedule, "an
    operator contains an agent and it stops" had no elapsed time — only a
    `gate()` that would have denied had anything told it to.

    **Unverified bytes.** Everything this returns goes through `attest`, which
    checks a root-signed chain of signatures. So a hostile response is a refused
    refresh, not a compromised sidecar, and that is what makes it acceptable to
    fetch policy over a channel this class does not authenticate. TLS narrows
    who can answer; the signature is what decides whether the answer counts.

    **`channel` binds each request to the key this sidecar registered**, same as
    the approval client. Without it a stolen bearer token reads another fleet's
    policy — less serious than forging it, and still not something to leave
    open.

    Raising is the contract: `Distribution.refresh` catches, reports
    unreachable, and keeps the last verified snapshot.
    """

    def __init__(
        self,
        base_url: str,
        credential: str,
        *,
        channel: Any = None,
        http_timeout: float = 10.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._credential = credential
        self._channel = channel
        self._timeout = http_timeout

    def fetch_keyset(self) -> Any:
        return self._get("/api/v1/policy/keyset")

    def fetch_bundle(self) -> Any:
        return self._get("/api/v1/policy/bundle")

    def fetch_revocations(self) -> Any:
        # Returned as served, wrapper and all. `_apply_revocations` unwraps,
        # and doing it here as well produced a sidecar that refused every
        # revocation list it was handed — which, because an unusable list
        # escalates rather than assuming nobody is contained, presented as
        # everything being denied instead of as a broken fetch. Unwrapping
        # belongs in one place; this is not it.
        return self._get("/api/v1/policy/revocations")

    def _get(self, path: str) -> Any:
        import urllib.error
        import urllib.request

        headers = {"authorization": f"Bearer {self._credential}"}
        if self._channel is not None:
            headers.update(self._channel.headers("GET", path, None))

        request = urllib.request.Request(self._base + path, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            raise SourceUnavailable(f"HTTP {exc.code} for {path}: {exc.reason}") from exc
        except urllib.error.URLError as exc:
            raise SourceUnavailable(f"cannot reach {self._base}: {exc.reason}") from exc
        except ValueError as exc:
            raise SourceUnavailable(f"{path} returned invalid JSON") from exc
        except OSError as exc:
            # A read that times out mid-response arrives as a bare
            # `TimeoutError`, not a `URLError` — urllib only wraps what fails
            # while connecting. Left uncaught it escapes as a type callers do
            # not expect, and the one place that must never be surprised is the
            # poll loop.
            raise SourceUnavailable(f"cannot read from {self._base}: {exc}") from exc


class SourceUnavailable(Exception):
    """A fetch failed. Ordinary, and handled by keeping the last snapshot."""


#: How long an operator waits between pressing the kill switch and the last
#: sidecar honouring it. This is the entire containment bound, so it is a
#: constant with a justification rather than a parameter with a default.
#:
#: Thirty seconds, not five minutes: the actions worth a kill switch — a loop
#: burning spend, an agent walking a filesystem — are ones where minutes are
#: many more operations. Not one second either; that is a request per sidecar
#: per second, forever, against a document that changes about twice a year, and
#: the cost is paid by every customer to shorten an event most never have.
#:
#: The revocation list's expiry is what makes this safe to get wrong. A sidecar
#: that cannot reach the control plane for longer than that expiry escalates
#: rather than assuming nobody is contained, so a missed poll degrades towards
#: stricter, not towards stale.
DEFAULT_POLL_SECONDS = 30.0


class Poller:
    """Calls `refresh()` forever, on an interval, without letting it die.

    Small, and load-bearing. A poller that stops on the first exception turns a
    transient control-plane blip into a sidecar that never learns anything
    again — containment included — while every health check stays green,
    because `gate()` keeps working perfectly against a snapshot from Tuesday.
    That is the failure this class exists to not have.

    `refresh()` already promises not to raise; this catches anyway. The promise
    is one edit away from being untrue, and the cost of being wrong is silent.
    """

    def __init__(
        self,
        distribution: "Distribution",
        *,
        interval_seconds: float = DEFAULT_POLL_SECONDS,
        on_report: Any = None,
    ) -> None:
        self._distribution = distribution
        self._interval = interval_seconds
        self._on_report = on_report
        self._task: Any = None
        #: Set after each completed poll, so a caller — a test measuring the
        #: bound, or a readiness probe — can wait for one rather than sleep.
        self.polled: Any = None

    async def start(self) -> None:
        import asyncio

        if self._task is not None:
            return
        self.polled = asyncio.Event()
        self._task = asyncio.create_task(self._run(), name="unified-distribution-poll")

    async def stop(self) -> None:
        import asyncio

        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    async def _run(self) -> None:
        import asyncio

        while True:
            try:
                report = await asyncio.to_thread(self._distribution.refresh)
                if self._on_report is not None:
                    self._on_report(report)
            except asyncio.CancelledError:
                raise
            except Exception:
                # Deliberately swallowed. See the class docstring: the only
                # thing worse than a failed poll is a poller that stopped.
                log.exception("policy refresh raised; continuing to poll")
            if self.polled is not None:
                self.polled.set()
            await asyncio.sleep(self._interval)


@dataclass
class RefreshReport:
    """What happened on one poll. Returned rather than only logged so a caller
    can surface it — an operator needs to see *why* a fleet went stale."""

    applied_bundle: bool = False
    applied_shadow: bool = False
    applied_revocations: bool = False
    unreachable: bool = False
    #: Refusals worth alarming on. Unreachability is deliberately absent.
    problems: list[tuple[str, Reason, str]] = field(default_factory=list)

    def alarming(self) -> bool:
        return bool(self.problems)


#: The principal id that means "every principal in this fleet".
#:
#: Not a pattern language. A kill switch is pressed by somebody having a bad
#: day, and the failure mode of a glob is containing more or less than intended
#: while believing otherwise. One literal, one meaning.
FLEET_WIDE = "*"

#: Strictness order, tightest first. Composition takes the strictest of the
#: rules that apply, because a kill switch a narrower rule can weaken is not a
#: kill switch: a fleet-wide `deny` must not be softened to `defer` by a
#: per-principal entry somebody set last week and forgot.
_STRICTNESS = ("deny", "deny_except", "defer")


def _strictest(*candidates: "Containment | None") -> "Containment | None":
    present = [c for c in candidates if c is not None]
    if not present:
        return None
    return min(present, key=lambda c: _STRICTNESS.index(c.mode) if c.mode in _STRICTNESS else 99)


class Distribution:
    """Holds the verified snapshot and refreshes it from a source.

    Persists the last verified artifacts so a restart does not become an
    `UNPROVISIONED` outage. That matters more than it sounds: restarts happen
    during deploys and incidents, which is exactly when an agent losing all
    policy is least acceptable — and, not coincidentally, when an attacker
    would choose to block a fetch.
    """

    def __init__(
        self,
        source: Source,
        *,
        fleet_id: str,
        root_public_key: str,
        cache_dir: Path | None = None,
        on_stale: StaleAction = StaleAction.KEEP,
        required_kids: set[str] | None = None,
        now: datetime | None = None,
        on_containment: Any = None,
    ) -> None:
        self._source = source
        self._fleet = fleet_id
        self._root_key = root_public_key
        self._cache = Path(cache_dir) if cache_dir else None
        self._on_stale = on_stale
        self._required_kids = required_kids
        #: Called as `on_containment(added, removed)` -- two frozensets of
        #: principal ids -- after a verified revocation list changes who is
        #: contained (or how strictly). `gate()` already stops a contained
        #: principal's *next* action; this is for the enforcement point that
        #: can also stop the one in progress. Fired on the refreshing thread,
        #: never on hydration from cache (nothing is in flight at start-up),
        #: and a handler that raises does not fail the refresh: the list is
        #: applied first, the announcement second.
        self.on_containment = on_containment
        #: `refresh` is called from the poller's worker thread and, since
        #: receipts, from the evidence shipper's thread. Serialised, so two
        #: refreshes cannot interleave their snapshot writes.
        self._refresh_lock = threading.Lock()
        self.snapshot = Snapshot()
        #: The keys from the last key set that verified. Retained so anything
        #: else needing to check a control-plane signature -- the approval
        #: channel, today -- uses the same rotating set rather than pinning a
        #: key of its own at enrolment. A second pinning point would be a second
        #: thing to rotate, which in practice means one that never is.
        self._verification_keys: dict[str, VerificationKey] = {}
        if self._cache is not None:
            self._load_cache(now=now)

    def verification_keys(self) -> Mapping[str, VerificationKey]:
        """The currently trusted keys, by kid. Empty until a key set verifies.

        A callable rather than an attribute because callers hold it across
        refreshes: `RemoteApprovals(..., keys=distribution.verification_keys)`
        picks up a rotation on the next poll, where a snapshot taken at
        construction would pin the fleet to whatever was valid at start-up.
        """
        return self._verification_keys

    # --- refresh --------------------------------------------------------------

    def refresh(self, *, now: datetime | None = None) -> RefreshReport:
        """One poll. Never raises; the report says what happened."""
        with self._refresh_lock:
            return self._refresh(now=now)

    def on_receipt(
        self, receipt: Mapping[str, Any], *, now: datetime | None = None
    ) -> RefreshReport | None:
        """An evidence receipt says the fleet's revocation list moved: refresh now.

        The reporting sidecar is the one running the agent whose batch just
        raised an incident, so it is the one that most needs the new list --
        and the one that would otherwise wait up to a full poll interval for
        it. This makes "contained at its next action" true for that sidecar.

        The receipt is a cue, not a source. Nothing in it is trusted: it only
        decides *whether* to run the same verified refresh the poller runs, and
        that refresh still checks every signature against the pinned root and
        still refuses a version older than the one held. A forged receipt can
        therefore cost one extra fetch and nothing else -- it cannot downgrade,
        cannot contain, and cannot release.
        """
        version = receipt.get("revocations_version")
        if not isinstance(version, int):
            return None
        held = self.snapshot.revocations_version
        if held is not None and version <= held:
            return None
        return self.refresh(now=now)

    def _refresh(self, *, now: datetime | None = None) -> RefreshReport:
        now_ms = _ms(now or datetime.now(UTC))
        report = RefreshReport()

        try:
            keyset_doc = self._source.fetch_keyset()
            bundle_doc = self._source.fetch_bundle()
            revocations_doc = self._source.fetch_revocations()
        except Exception as exc:
            # Not a problem, on purpose. Brief unreachability is ordinary, and
            # alarming on it trains an operator to ignore the alarm that means
            # something. Expiry is the signal.
            log.debug("distribution source unreachable: %s", exc)
            report.unreachable = True
            self._reassess(now_ms)
            return report

        verdict, keys = load_key_set(keyset_doc, root_public_key=self._root_key, now_ms=now_ms)
        if not verdict:
            # The previous keys are dropped, not kept. A key set that no longer
            # verifies -- expired, or signed by something other than the pinned
            # root -- is exactly when continuing to trust what it used to say is
            # wrong, and the consequence is that approvals stop being honoured
            # rather than being honoured on stale authority.
            self._verification_keys = {}
            self._refuse(report, "keyset", verdict.reason, verdict.detail)
            self._reassess(now_ms)
            return report

        self._verification_keys = dict(keys)
        self._apply_bundle(bundle_doc, keys, now_ms, report)
        self._apply_shadow(bundle_doc, keys, now_ms, report)
        self._apply_revocations(revocations_doc, keys, now_ms, report)
        self._reassess(now_ms)
        return report

    def _apply_bundle(
        self,
        doc: Any,
        keys: Mapping[str, VerificationKey],
        now_ms: int,
        report: RefreshReport,
        *,
        hydrating: bool = False,
    ) -> None:
        held = (
            BundleState(self.snapshot.version, self.snapshot.expires_at_ms or 0)
            if self.snapshot.version is not None
            else None
        )
        envelope = doc.get("manifest") if isinstance(doc, dict) else doc

        verdict = accept_manifest(
            envelope,
            keys,
            fleet_id=self._fleet,
            current=held,
            now_ms=now_ms,
            required_kids=self._required_kids,
            ignore_expiry=hydrating,
        )
        if not verdict:
            self._refuse(report, "bundle", verdict.reason, verdict.detail)
            return

        files = {
            path: content.encode() if isinstance(content, str) else content
            for path, content in (doc.get("files") or {}).items()
        }
        # All or nothing. A partially applied bundle is a policy nobody wrote
        # and nobody reviewed — worse than keeping the previous one, which at
        # least someone approved.
        file_verdict = verify_files(verdict.payload, files)
        if not file_verdict:
            self._refuse(report, "files", file_verdict.reason, file_verdict.detail)
            return

        self.snapshot.version = verdict.payload["version"]
        self.snapshot.expires_at_ms = verdict.payload["expires_at_ms"]
        self.snapshot.files = files
        report.applied_bundle = True
        self._write_cache("bundle.json", doc)

    def _apply_shadow(
        self,
        doc: Any,
        keys: Mapping[str, VerificationKey],
        now_ms: int,
        report: RefreshReport,
        *,
        hydrating: bool = False,
    ) -> None:
        """Accept a candidate for evaluation. It can never become policy.

        Verified exactly like the enforcing bundle — same signature, same fleet
        binding, same rollback rule — because a candidate that could be forged
        would let an attacker choose what the divergence report says, and a
        divergence report is what an operator reads before promoting.

        It has its own freshness line, and the reason is narrower than it first
        appears. Promotion works either way — accepting a candidate never
        advances the enforcing pointer — so the line is not about that. What it
        buys is rollback protection *for the candidate*: with a shared
        baseline, a candidate at v6 compared against an enforcing v5 accepts a
        replayed v6 carrying an earlier expiry, because 6 > 5 passes before the
        equal-version refresh rule is ever reached. An attacker could then pin
        the divergence report to a stale proposal, which is what an operator
        reads before promoting.

        (An earlier version of this comment claimed a shared line would block
        promotion. It would not; mutation testing said so.)
        """
        if not isinstance(doc, dict):
            return
        shadow = doc.get("shadow")
        if not shadow:
            # No candidate, or one that has been promoted or superseded. Drop
            # what we were holding rather than keep reporting divergences
            # against a question nobody is asking any more.
            self.snapshot.shadow_version = None
            self.snapshot.shadow_files = {}
            self._shadow_expire_at = None
            return

        # The real expiry, not a zero. Passing 0 here makes the equal-version
        # refresh rule compare against nothing, so any replayed artifact at the
        # same version passes — which defeats the whole point of tracking a
        # freshness line for the candidate.
        held = (
            BundleState(self.snapshot.shadow_version, self._shadow_expire_at or 0)
            if self.snapshot.shadow_version is not None
            else None
        )
        verdict = accept_manifest(
            shadow.get("manifest"),
            keys,
            fleet_id=self._fleet,
            current=held,
            now_ms=now_ms,
            required_kids=self._required_kids,
            ignore_expiry=hydrating,
        )
        if not verdict:
            self._refuse(report, "shadow", verdict.reason, verdict.detail)
            return

        if verdict.payload.get("mode") != "shadow":
            # A bundle offered as a candidate that does not say so inside its
            # own signature. Refused rather than evaluated: the mismatch means
            # either a bug or an attempt to have a signed enforcing bundle
            # treated as a proposal, and neither should be quietly tolerated.
            self._refuse(report, "shadow", Reason.WRONG_SCHEMA, "manifest mode is not shadow")
            return

        files = {
            path: content.encode() if isinstance(content, str) else content
            for path, content in (shadow.get("files") or {}).items()
        }
        file_verdict = verify_files(verdict.payload, files)
        if not file_verdict:
            self._refuse(report, "shadow_files", file_verdict.reason, file_verdict.detail)
            return

        self.snapshot.shadow_version = verdict.payload["version"]
        self.snapshot.shadow_files = files
        self._shadow_expire_at = verdict.payload["expires_at_ms"]
        report.applied_shadow = True

    def _apply_revocations(
        self,
        doc: Any,
        keys: Mapping[str, VerificationKey],
        now_ms: int,
        report: RefreshReport,
        *,
        hydrating: bool = False,
    ) -> None:
        held = (
            BundleState(self.snapshot.revocations_version, self._revocations_expire_at or 0)
            if self.snapshot.revocations_version is not None
            else None
        )
        envelope = doc.get("revocations") if isinstance(doc, dict) else doc

        verdict = accept_revocations(
            envelope,
            keys,
            fleet_id=self._fleet,
            current=held,
            now_ms=now_ms,
            required_kids=self._required_kids,
            ignore_expiry=hydrating,
        )
        if not verdict:
            self._refuse(report, "revocations", verdict.reason, verdict.detail)
            return

        before = self.snapshot.containment
        self.snapshot.containment = {
            entry["principal_id"]: Containment(
                principal_id=entry["principal_id"],
                mode=entry.get("mode", "defer"),
                allow=tuple(entry.get("allow") or ()),
            )
            for entry in verdict.payload.get("revocations", [])
        }
        self.snapshot.revocations_version = verdict.payload["version"]
        self._revocations_expire_at = verdict.payload["expires_at_ms"]
        report.applied_revocations = True
        self._write_cache("revocations.json", doc)
        if not hydrating:
            self._announce_containment(before, self.snapshot.containment)

    def _announce_containment(
        self, before: Mapping[str, Containment], after: Mapping[str, Containment]
    ) -> None:
        if self.on_containment is None:
            return
        # "Added" is anyone newly contained *or* contained differently: a
        # principal moved from `defer` to `deny` is news to a call in flight.
        added = frozenset(p for p, c in after.items() if before.get(p) != c)
        removed = frozenset(p for p in before if p not in after)
        if not added and not removed:
            return
        try:
            self.on_containment(added, removed)
        except Exception:
            log.exception("containment change handler raised")

    _revocations_expire_at: int | None = None
    _shadow_expire_at: int | None = None

    def _refuse(self, report: RefreshReport, what: str, reason: Reason | None, detail: str) -> None:
        # Everything that reaches here is worth an operator's attention: a
        # signature that does not verify, a bundle for another fleet, a
        # rollback. None of them are ordinary, and a rollback in particular is
        # an attack rather than a mistake.
        log.warning("refused %s: %s (%s)", what, reason, detail)
        report.problems.append((what, reason or Reason.MALFORMED, detail))

    def _reassess(self, now_ms: int) -> None:
        """Recompute health from what is held, independent of this poll."""
        if self.snapshot.version is None:
            self.snapshot.health = Health.UNPROVISIONED
        elif (self.snapshot.expires_at_ms or 0) <= now_ms:
            self.snapshot.health = Health.STALE
        else:
            self.snapshot.health = Health.FRESH

        if self.snapshot.revocations_version is None:
            self.snapshot.revocations_health = Health.UNPROVISIONED
        elif (self._revocations_expire_at or 0) <= now_ms:
            self.snapshot.revocations_health = Health.STALE
        else:
            self.snapshot.revocations_health = Health.FRESH

    # --- the decision hook ----------------------------------------------------

    def gate(self, action: Action) -> Decision | None:
        """The verdict distribution state forces, or None to let policy decide.

        Called *before* the policy engine. Returning `None` is the ordinary
        case; everything else is a decision the engine is not entitled to
        override, because it concerns whether we can trust the engine's rules
        at all.
        """
        principal = action.principal.id

        # Containment first. A contained agent is contained whatever the rules
        # say — that is the entire point of a kill switch, and a policy that
        # allowed the action would otherwise quietly win.
        contained = _strictest(
            self.snapshot.containment.get(principal),
            # `*` is the whole fleet: the button an incident responder presses
            # when they do not yet know which agent is the problem.
            self.snapshot.containment.get(FLEET_WIDE),
        )
        if contained is not None:
            forced = _containment_decision(contained, action)
            if forced is not None:
                return forced

        if self.snapshot.health is Health.UNPROVISIONED:
            # Checked before revocation staleness, because with nothing
            # provisioned both conditions hold and `deny` is the stricter of
            # the two. Ordered the other way round, a sidecar that had never
            # fetched anything would *defer* every action -- sending an
            # operator a queue item per call instead of refusing, which reads
            # as "waiting for approval" rather than "this agent has no policy".
            #
            # Denying at startup looks like an outage; allowing would hand an
            # unprotected agent to anyone able to block one fetch.
            return Decision(
                verdict=Verdict.DENY,
                rule_id=None,
                source="distribution",
                reason="no verified policy bundle; refusing every action",
            )

        if self.snapshot.revocations_health is not Health.FRESH:
            # We cannot tell whether this agent is contained. Assuming it is
            # not is the fail-open a kill switch exists to prevent.
            return Decision(
                verdict=Verdict.DEFER,
                rule_id=None,
                source="distribution",
                reason=(
                    "revocation list is "
                    f"{self.snapshot.revocations_health.value}; cannot confirm "
                    "whether this principal is contained"
                ),
            )

        if self.snapshot.health is Health.STALE:
            if self._on_stale is StaleAction.DENY:
                return Decision(
                    verdict=Verdict.DENY,
                    rule_id=None,
                    source="distribution",
                    reason="policy bundle expired and on_stale=deny",
                )
            if self._on_stale is StaleAction.DEFER:
                return Decision(
                    verdict=Verdict.DEFER,
                    rule_id=None,
                    source="distribution",
                    reason="policy bundle expired and on_stale=defer",
                )
            # KEEP: old rules are still rules. The alarm is the operator's
            # signal, not a change in what agents may do.

        return None

    # --- cache ----------------------------------------------------------------

    def _write_cache(self, name: str, doc: Any) -> None:
        if self._cache is None:
            return
        try:
            self._cache.mkdir(parents=True, exist_ok=True)
            (self._cache / name).write_text(json.dumps(doc))
        except OSError as exc:
            # A cache we cannot write is a slower restart, not a security
            # problem. It must never stop us enforcing what we just verified.
            log.warning("could not cache %s: %s", name, exc)

    def _load_cache(self, *, now: datetime | None = None) -> None:
        """Re-verify cached artifacts on the way in.

        Deliberately not trusted just because we wrote it: the file sits on
        disk in the customer's environment, and reloading it without checking
        the signature would make the cache a way to install policy.

        Expiry is the one check relaxed here, and only to recover *contents*.
        A restart that discarded an expired cached revocation list would forget
        which agents are contained — downgrading a hard `deny` to whatever we
        do about an unknown list, at exactly the moment (a restart, mid-
        incident) when that matters most. `_reassess` immediately marks
        anything past its expiry as stale, so remembered is never mistaken for
        current.
        """
        assert self._cache is not None
        try:
            keyset_doc = json.loads((self._cache / "keyset.json").read_text())
        except (OSError, ValueError):
            return

        now_ms = _ms(now or datetime.now(UTC))
        verdict, keys = load_key_set(keyset_doc, root_public_key=self._root_key, now_ms=now_ms)
        if not verdict:
            log.warning("cached key set no longer verifies: %s", verdict.reason)
            return

        report = RefreshReport()
        for name, apply in (
            ("bundle.json", self._apply_bundle),
            ("revocations.json", self._apply_revocations),
        ):
            try:
                doc = json.loads((self._cache / name).read_text())
            except (OSError, ValueError):
                continue
            apply(doc, keys, now_ms, report, hydrating=True)
        self._reassess(now_ms)

    def cache_keyset(self, doc: Any) -> None:
        """Store the key set so a restart can re-verify what it cached."""
        self._write_cache("keyset.json", doc)


def _containment_decision(contained: Containment, action: Action) -> Decision | None:
    """What a containment mode does to one action."""
    if contained.mode == "deny":
        return Decision(
            verdict=Verdict.DENY,
            rule_id=None,
            source="containment",
            reason=f"{contained.principal_id} is contained (deny)",
        )
    if contained.mode == "deny_except":
        if _matches_any(action.tool, contained.allow):
            return None
        return Decision(
            verdict=Verdict.DENY,
            rule_id=None,
            source="containment",
            reason=f"{contained.principal_id} is contained (deny_except)",
        )
    # defer
    return Decision(
        verdict=Verdict.DEFER,
        rule_id=None,
        source="containment",
        reason=f"{contained.principal_id} is contained (defer)",
    )


def _matches_any(tool: str, patterns: tuple[str, ...]) -> bool:
    """Prefix-glob match for containment allowlists.

    Deliberately simpler than the policy engine's segment-aware globs: an
    allowlist written during an incident should do the obvious thing, and a
    surprising match here fails open for a contained agent.
    """
    for pattern in patterns:
        if pattern == tool:
            return True
        if pattern.endswith("*") and tool.startswith(pattern[:-1]):
            return True
    return False


def _ms(value: datetime) -> int:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return int(value.astimezone(UTC).timestamp() * 1000)


def manifest_of(envelope: Mapping[str, Any]) -> dict[str, Any]:
    """The decoded payload of a JWS envelope, for logging and diagnostics.

    Never for decisions — `accept_*` is what decides, and reading a payload
    without verifying it is how an unverified value ends up load-bearing.
    """
    return json.loads(unb64u(envelope["payload"]))
